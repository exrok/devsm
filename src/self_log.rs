use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    thread::Thread,
};

use kvlog::collector::{LogBuffer, LoggerGuard};
use slab::Slab;

#[cfg(not(test))]
const RING_BUFFER_SIZE: usize = 128 * 1024;
#[cfg(test)]
const RING_BUFFER_SIZE: usize = 1024;

pub struct LogRingBuffer {
    data: Box<[u8; RING_BUFFER_SIZE]>,
    write_pos: usize,
    len: usize,
}

impl LogRingBuffer {
    fn new() -> Self {
        Self { data: Box::new([0u8; RING_BUFFER_SIZE]), write_pos: 0, len: 0 }
    }

    fn push(&mut self, entry: &[u8]) {
        if entry.len() > RING_BUFFER_SIZE {
            return;
        }

        while self.len + entry.len() > RING_BUFFER_SIZE {
            let Some(oldest_len) = self.entry_len_at_start() else {
                self.len = 0;
                self.write_pos = 0;
                break;
            };
            self.len -= oldest_len;
        }

        let start = self.write_pos;
        let end = start + entry.len();

        if end <= RING_BUFFER_SIZE {
            self.data[start..end].copy_from_slice(entry);
        } else {
            let first_part = RING_BUFFER_SIZE - start;
            self.data[start..].copy_from_slice(&entry[..first_part]);
            self.data[..entry.len() - first_part].copy_from_slice(&entry[first_part..]);
        }

        self.write_pos = end % RING_BUFFER_SIZE;
        self.len += entry.len();
    }

    fn entry_len_at_start(&self) -> Option<usize> {
        if self.len < 4 {
            return None;
        }

        let read_start = (self.write_pos + RING_BUFFER_SIZE - self.len) % RING_BUFFER_SIZE;
        let mut header_bytes = [0u8; 4];

        for (i, byte) in header_bytes.iter_mut().enumerate() {
            *byte = self.data[(read_start + i) % RING_BUFFER_SIZE];
        }

        kvlog::encoding::log_len(&header_bytes)
    }

    fn snapshot(&self) -> Vec<u8> {
        if self.len == 0 {
            return Vec::new();
        }

        let read_start = (self.write_pos + RING_BUFFER_SIZE - self.len) % RING_BUFFER_SIZE;
        let mut result = Vec::with_capacity(self.len);

        if read_start + self.len <= RING_BUFFER_SIZE {
            result.extend_from_slice(&self.data[read_start..read_start + self.len]);
        } else {
            result.extend_from_slice(&self.data[read_start..]);
            result.extend_from_slice(&self.data[..self.write_pos]);
        }

        result
    }

    fn last_n_entries(&self, n: usize) -> Vec<Vec<u8>> {
        let snapshot = self.snapshot();
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset < snapshot.len() {
            let Some(len) = kvlog::encoding::log_len(&snapshot[offset..]) else {
                break;
            };
            if offset + len > snapshot.len() {
                break;
            }
            entries.push(snapshot[offset..offset + len].to_vec());
            offset += len;
        }

        let start = entries.len().saturating_sub(n);
        entries.into_iter().skip(start).collect()
    }
}

static CLIENT_LOGS: OnceLock<Arc<Mutex<LogRingBuffer>>> = OnceLock::new();
static DAEMON_LOGS: OnceLock<Arc<Mutex<DaemonLogState>>> = OnceLock::new();

pub struct DaemonLogState {
    buffer: LogRingBuffer,
    offset: u64,
    followers: Slab<Thread>,
}

impl DaemonLogState {
    fn new() -> Self {
        Self { buffer: LogRingBuffer::new(), offset: 0, followers: Slab::new() }
    }

    fn push(&mut self, entry: &[u8]) {
        self.buffer.push(entry);
        self.offset += entry.len() as u64;
        for (_, thread) in &self.followers {
            thread.unpark();
        }
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.buffer.snapshot()
    }

    pub fn snapshot_from(&self, from_offset: u64, out: &mut Vec<u8>) -> u64 {
        out.clear();
        let current_offset = self.offset;
        let buffer_start_offset = current_offset.saturating_sub(self.buffer.len as u64);

        if from_offset <= buffer_start_offset {
            *out = self.buffer.snapshot();
            return current_offset;
        }

        if from_offset >= current_offset {
            return current_offset;
        }

        let skip_bytes = (from_offset - buffer_start_offset) as usize;
        let snapshot = self.buffer.snapshot();
        out.extend_from_slice(&snapshot[skip_bytes..]);

        current_offset
    }

    pub fn register_follower(&mut self, thread: Thread) -> usize {
        self.followers.insert(thread)
    }

    pub fn unregister_follower(&mut self, index: usize) {
        self.followers.try_remove(index);
    }
}

pub fn init_client_logging() -> LoggerGuard {
    let ring = Arc::new(Mutex::new(LogRingBuffer::new()));
    CLIENT_LOGS.set(ring.clone()).ok();

    let ring_for_panic = ring.clone();
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        original_hook(info);

        if let Ok(buffer) = ring_for_panic.lock() {
            let entries = buffer.last_n_entries(30);
            if !entries.is_empty() {
                eprintln!("\n=== Last {} log entries ===", entries.len());
                let mut fmt_buf = Vec::new();
                let mut parents = kvlog::collector::ParentSpanSuffixCache::new_boxed();
                for entry in entries {
                    for (ts, level, span, fields) in kvlog::encoding::decode(&entry).flatten() {
                        kvlog::collector::format_statement_with_colors(
                            &mut fmt_buf,
                            &mut parents,
                            ts,
                            level,
                            span,
                            fields,
                        );
                    }
                }
                eprint!("{}", String::from_utf8_lossy(&fmt_buf));
            }
        }
    }));

    let ring_for_collector = ring;
    kvlog::collector::init_closure_logger(move |log_buffer: &mut LogBuffer| {
        let bytes = log_buffer.as_bytes();
        if let Ok(mut buffer) = ring_for_collector.lock() {
            let mut offset = 0;
            while offset < bytes.len() {
                let Some(len) = kvlog::encoding::log_len(&bytes[offset..]) else {
                    break;
                };
                if offset + len > bytes.len() {
                    break;
                }
                buffer.push(&bytes[offset..offset + len]);
                offset += len;
            }
        }
        log_buffer.clear();
    })
}

pub fn init_daemon_logging() -> LoggerGuard {
    let state = Arc::new(Mutex::new(DaemonLogState::new()));
    DAEMON_LOGS.set(state.clone()).ok();

    let state_for_collector = state;
    kvlog::collector::init_closure_logger(move |log_buffer: &mut LogBuffer| {
        let bytes = log_buffer.as_bytes();
        if let Ok(mut state) = state_for_collector.lock() {
            let mut offset = 0;
            while offset < bytes.len() {
                let Some(len) = kvlog::encoding::log_len(&bytes[offset..]) else {
                    break;
                };
                if offset + len > bytes.len() {
                    break;
                }
                state.push(&bytes[offset..offset + len]);
                offset += len;
            }
        }
        log_buffer.clear();
    })
}

pub fn get_daemon_logs() -> Option<Vec<u8>> {
    DAEMON_LOGS.get().and_then(|state| state.lock().ok().map(|s| s.snapshot()))
}

pub fn daemon_log_state() -> Option<&'static Arc<Mutex<DaemonLogState>>> {
    DAEMON_LOGS.get()
}

static CRASH_REPORT_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Path to the daemon crash-report file.
///
/// Resolved identically by daemon and client so the client can point the user
/// at the file the daemon would have written, without any RPC interchange.
/// Uses `DEVSM_CRASH_REPORT` if set, otherwise the per-user state directory
/// (`$XDG_STATE_HOME/devsm` or `$HOME/.local/state/devsm`), falling back to
/// `/tmp/devsm-<uid>.crash.log`.
pub fn crash_report_path() -> &'static Path {
    CRASH_REPORT_PATH.get_or_init(|| {
        resolve_crash_report_path(
            std::env::var("DEVSM_CRASH_REPORT").ok(),
            std::env::var("XDG_STATE_HOME").ok(),
            std::env::var("HOME").ok(),
            unsafe { libc::getuid() },
        )
    })
}

fn resolve_crash_report_path(
    override_path: Option<String>,
    xdg_state_home: Option<String>,
    home: Option<String>,
    uid: u32,
) -> PathBuf {
    if let Some(path) = override_path {
        return PathBuf::from(path);
    }
    if let Some(state_home) = xdg_state_home.filter(|s| !s.is_empty()) {
        return PathBuf::from(state_home).join("devsm/crash.log");
    }
    if let Some(home) = home.filter(|s| !s.is_empty()) {
        return PathBuf::from(home).join(".local/state/devsm/crash.log");
    }
    PathBuf::from(format!("/tmp/devsm-{uid}.crash.log"))
}

/// Decodes binary kvlog entries into plain (ANSI-stripped) UTF-8 text.
///
/// kvlog only exposes a colored formatter, so this formats with colors and then
/// strips the escape codes — yielding text the user can read and prune before
/// attaching it to a bug report.
pub fn decode_self_log_entries_to_plain_text(binary: &[u8], out: &mut String) {
    let mut colored = Vec::new();
    let mut parents = kvlog::collector::ParentSpanSuffixCache::new_boxed();
    for (ts, level, span, fields) in kvlog::encoding::decode(binary).flatten() {
        kvlog::collector::format_statement_with_colors(&mut colored, &mut parents, ts, level, span, fields);
    }
    let mut plain = Vec::new();
    crate::line_width::strip_ansi_to_buffer_preserve_case(&String::from_utf8_lossy(&colored), &mut plain);
    out.push_str(&String::from_utf8_lossy(&plain));
}

/// Installs a chained panic hook that writes a daemon crash report to
/// [`crash_report_path`].
///
/// Installed unconditionally for the daemon process (even when self-logging is
/// disabled via `DEVSM_LOG_STDOUT`), so a panic always leaves a report behind.
pub fn install_daemon_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        original(info);
        write_daemon_crash_report(info);
    }));
}

fn panic_payload_str<'a>(info: &'a std::panic::PanicHookInfo<'_>) -> &'a str {
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        s
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.as_str()
    } else {
        "<non-string panic payload>"
    }
}

/// Writes a human-readable crash report. Best-effort: every step ignores its own
/// IO error and the function never panics, since it runs from inside a panic.
fn write_daemon_crash_report(info: &std::panic::PanicHookInfo) {
    let path = crash_report_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = std::fs::File::create(path) else {
        return;
    };

    let _ = writeln!(file, "=== devsm daemon crash report ===");
    let _ = writeln!(file, "version: {}", env!("CARGO_PKG_VERSION"));
    if let Ok(since_epoch) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        let _ = writeln!(file, "time: {} (unix seconds)", since_epoch.as_secs());
    }
    let _ = writeln!(file, "panic: {}", panic_payload_str(info));
    if let Some(location) = info.location() {
        let _ = writeln!(file, "location: {location}");
    }
    let _ = writeln!(file, "\nbacktrace:\n{}", std::backtrace::Backtrace::force_capture());

    let _ = writeln!(file, "\n--- recent daemon logs ---");
    let Some(state) = daemon_log_state() else {
        let _ = writeln!(file, "<daemon log ring buffer not initialized>");
        return;
    };
    // try_lock, not lock: the panicking thread may already hold this mutex (a
    // panic during push/snapshot), and lock() would self-deadlock the dying
    // process. A poisoned guard still carries readable data, so recover it.
    let snapshot = match state.try_lock() {
        Ok(guard) => guard.snapshot(),
        Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner().snapshot(),
        Err(std::sync::TryLockError::WouldBlock) => {
            let _ = writeln!(file, "<self-log buffer was locked; recent entries unavailable>");
            return;
        }
    };
    let mut text = String::new();
    decode_self_log_entries_to_plain_text(&snapshot, &mut text);
    let _ = file.write_all(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(payload: &[u8]) -> Vec<u8> {
        let header = (kvlog::encoding::MAGIC_BYTE) << 24 | (payload.len() as u32);
        let mut entry = header.to_le_bytes().to_vec();
        entry.extend_from_slice(payload);
        entry
    }

    fn extract_payloads(snapshot: &[u8]) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        let mut offset = 0;
        while offset < snapshot.len() {
            let Some(len) = kvlog::encoding::log_len(&snapshot[offset..]) else {
                break;
            };
            if offset + len > snapshot.len() {
                break;
            }
            payloads.push(snapshot[offset + 4..offset + len].to_vec());
            offset += len;
        }
        payloads
    }

    #[test]
    fn empty_buffer() {
        let buffer = LogRingBuffer::new();
        assert_eq!(buffer.write_pos, 0);
        assert_eq!(buffer.len, 0);
        assert_eq!(buffer.snapshot(), Vec::<u8>::new());
        assert_eq!(buffer.last_n_entries(10), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn single_entry() {
        let mut buffer = LogRingBuffer::new();
        buffer.push(&make_entry(b"hello"));

        assert_eq!(buffer.write_pos, 9);
        assert_eq!(buffer.len, 9);

        let payloads = extract_payloads(&buffer.snapshot());
        assert_eq!(payloads, vec![b"hello".to_vec()]);
    }

    #[test]
    fn multiple_entries_no_wrap() {
        let mut buffer = LogRingBuffer::new();
        buffer.push(&make_entry(b"first"));
        buffer.push(&make_entry(b"second"));
        buffer.push(&make_entry(b"third"));

        assert_eq!(buffer.write_pos, 9 + 10 + 9);
        assert_eq!(buffer.len, 28);

        let payloads = extract_payloads(&buffer.snapshot());
        assert_eq!(payloads, vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]);
    }

    #[test]
    fn wrapping_evicts_oldest_entries() {
        let mut buffer = LogRingBuffer::new();

        for i in 0..100u8 {
            buffer.push(&make_entry(&[i; 20]));
        }

        let payloads = extract_payloads(&buffer.snapshot());

        assert_eq!(payloads.len(), 42);
        assert_eq!(payloads[0], vec![58u8; 20]);
        assert_eq!(payloads[41], vec![99u8; 20]);

        for (i, payload) in payloads.iter().enumerate() {
            assert_eq!(payload.len(), 20);
            assert!(payload.iter().all(|&b| b == payload[0]));
            assert_eq!(payload[0], 58 + i as u8);
        }
    }

    #[test]
    fn last_n_entries() {
        let mut buffer = LogRingBuffer::new();
        buffer.push(&make_entry(b"one"));
        buffer.push(&make_entry(b"two"));
        buffer.push(&make_entry(b"three"));
        buffer.push(&make_entry(b"four"));
        buffer.push(&make_entry(b"five"));

        let last_0 = buffer.last_n_entries(0);
        assert_eq!(last_0, Vec::<Vec<u8>>::new());

        let last_2 = buffer.last_n_entries(2);
        assert_eq!(last_2.len(), 2);
        assert_eq!(&last_2[0][4..], b"four");
        assert_eq!(&last_2[1][4..], b"five");

        let last_5 = buffer.last_n_entries(5);
        assert_eq!(last_5.len(), 5);
        assert_eq!(&last_5[0][4..], b"one");
        assert_eq!(&last_5[4][4..], b"five");

        let last_100 = buffer.last_n_entries(100);
        assert_eq!(last_100.len(), 5);
    }

    #[test]
    fn entry_data_spans_buffer_boundary() {
        let mut buffer = LogRingBuffer::new();

        buffer.push(&make_entry(&[0xAA; 900]));
        assert_eq!(buffer.write_pos, 904);
        assert_eq!(buffer.len, 904);

        buffer.push(&make_entry(&[0xBB; 200]));
        assert_eq!(buffer.write_pos, (904 + 204) % RING_BUFFER_SIZE);
        assert_eq!(buffer.len, 204);

        let payloads = extract_payloads(&buffer.snapshot());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].len(), 200);
        assert!(payloads[0].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn entry_header_spans_buffer_boundary() {
        let mut buffer = LogRingBuffer::new();

        buffer.push(&make_entry(&[0xCC; 1018]));
        assert_eq!(buffer.write_pos, 1022);
        assert_eq!(buffer.len, 1022);

        buffer.push(&make_entry(&[0xDD; 50]));
        assert_eq!(buffer.write_pos, (1022 + 54) % RING_BUFFER_SIZE);
        assert_eq!(buffer.len, 54);

        let payloads = extract_payloads(&buffer.snapshot());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].len(), 50);
        assert!(payloads[0].iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn entry_too_large_is_ignored() {
        let mut buffer = LogRingBuffer::new();

        buffer.push(&make_entry(b"keep"));
        assert_eq!(buffer.len, 8);

        buffer.push(&make_entry(&[0xFF; RING_BUFFER_SIZE]));
        assert_eq!(buffer.len, 8);

        buffer.push(&make_entry(&[0xEE; RING_BUFFER_SIZE - 3]));
        assert_eq!(buffer.len, 8);

        let payloads = extract_payloads(&buffer.snapshot());
        assert_eq!(payloads, vec![b"keep".to_vec()]);
    }

    #[test]
    fn multiple_wraps() {
        let mut buffer = LogRingBuffer::new();

        for round in 0..5u8 {
            for i in 0..50u8 {
                buffer.push(&make_entry(&[round * 50 + i; 30]));
            }
        }

        let payloads = extract_payloads(&buffer.snapshot());
        assert_eq!(payloads.len(), 30);

        for (i, payload) in payloads.iter().enumerate() {
            let expected_value = 220 + i as u8;
            assert_eq!(payload.len(), 30);
            assert!(payload.iter().all(|&b| b == expected_value), "payload {i} should be all {expected_value}");
        }
    }

    #[test]
    fn exact_fit_no_eviction() {
        let mut buffer = LogRingBuffer::new();

        buffer.push(&make_entry(&[0x11; 508]));
        buffer.push(&make_entry(&[0x22; 508]));

        assert_eq!(buffer.len, 1024);
        assert_eq!(buffer.write_pos, 0);

        let payloads = extract_payloads(&buffer.snapshot());
        assert_eq!(payloads.len(), 2);
        assert!(payloads[0].iter().all(|&b| b == 0x11));
        assert!(payloads[1].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn one_byte_over_causes_eviction() {
        let mut buffer = LogRingBuffer::new();

        buffer.push(&make_entry(&[0x11; 508]));
        buffer.push(&make_entry(&[0x22; 509]));

        assert_eq!(buffer.len, 513);

        let payloads = extract_payloads(&buffer.snapshot());
        assert_eq!(payloads.len(), 1);
        assert!(payloads[0].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn daemon_log_state_snapshot_from_basic() {
        let mut state = DaemonLogState::new();

        let entry1 = make_entry(b"first");
        let entry2 = make_entry(b"second");
        let entry3 = make_entry(b"third");

        state.push(&entry1);
        let offset_after_first = state.offset;
        state.push(&entry2);
        let offset_after_second = state.offset;
        state.push(&entry3);
        let offset_after_third = state.offset;

        let mut out = Vec::new();

        let new_offset = state.snapshot_from(0, &mut out);
        assert_eq!(new_offset, offset_after_third);
        let payloads = extract_payloads(&out);
        assert_eq!(payloads, vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]);

        let new_offset = state.snapshot_from(offset_after_first, &mut out);
        assert_eq!(new_offset, offset_after_third);
        let payloads = extract_payloads(&out);
        assert_eq!(payloads, vec![b"second".to_vec(), b"third".to_vec()]);

        let new_offset = state.snapshot_from(offset_after_second, &mut out);
        assert_eq!(new_offset, offset_after_third);
        let payloads = extract_payloads(&out);
        assert_eq!(payloads, vec![b"third".to_vec()]);

        let new_offset = state.snapshot_from(offset_after_third, &mut out);
        assert_eq!(new_offset, offset_after_third);
        assert!(out.is_empty());
    }

    #[test]
    fn daemon_log_state_snapshot_from_after_wrap() {
        let mut state = DaemonLogState::new();

        for i in 0..100u8 {
            state.push(&make_entry(&[i; 20]));
        }

        let total_offset = state.offset;
        assert_eq!(total_offset, 100 * 24);

        let mut out = Vec::new();
        let new_offset = state.snapshot_from(0, &mut out);
        assert_eq!(new_offset, total_offset);

        let payloads = extract_payloads(&out);
        assert_eq!(payloads.len(), 42);
        assert_eq!(payloads[0], vec![58u8; 20]);
        assert_eq!(payloads[41], vec![99u8; 20]);
    }

    #[test]
    fn daemon_log_state_snapshot_from_partial_after_wrap() {
        let mut state = DaemonLogState::new();

        for i in 0..50u8 {
            state.push(&make_entry(&[i; 20]));
        }
        let offset_mid = state.offset;

        for i in 50..100u8 {
            state.push(&make_entry(&[i; 20]));
        }

        let mut out = Vec::new();
        let new_offset = state.snapshot_from(offset_mid, &mut out);
        assert_eq!(new_offset, 100 * 24);

        let payloads = extract_payloads(&out);
        assert_eq!(payloads.len(), 42);

        for (i, payload) in payloads.iter().enumerate() {
            assert_eq!(payload.len(), 20);
            assert_eq!(payload[0], 58 + i as u8);
        }
    }

    #[test]
    fn daemon_log_state_offset_never_resets() {
        let mut state = DaemonLogState::new();

        for _ in 0..10 {
            for i in 0..50u8 {
                state.push(&make_entry(&[i; 30]));
            }
        }

        assert_eq!(state.offset, 10 * 50 * 34);

        let mut out = Vec::new();
        let new_offset = state.snapshot_from(state.offset - 100, &mut out);
        assert_eq!(new_offset, state.offset);
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn daemon_log_state_snapshot_from_future_offset() {
        let mut state = DaemonLogState::new();
        state.push(&make_entry(b"test"));

        let mut out = Vec::new();
        let new_offset = state.snapshot_from(9999, &mut out);
        assert_eq!(new_offset, 8);
        assert!(out.is_empty());
    }

    #[test]
    fn resolve_crash_report_path_resolution_order() {
        assert_eq!(
            resolve_crash_report_path(Some("/custom/crash.log".into()), Some("/state".into()), Some("/h".into()), 7),
            PathBuf::from("/custom/crash.log")
        );
        assert_eq!(
            resolve_crash_report_path(None, Some("/state".into()), Some("/h".into()), 7),
            PathBuf::from("/state/devsm/crash.log")
        );
        assert_eq!(
            resolve_crash_report_path(None, Some(String::new()), Some("/h".into()), 7),
            PathBuf::from("/h/.local/state/devsm/crash.log")
        );
        assert_eq!(resolve_crash_report_path(None, None, None, 7), PathBuf::from("/tmp/devsm-7.crash.log"));
    }

    fn encoded_log_entry(message: &str) -> Vec<u8> {
        let mut encoder = kvlog::encoding::Encoder::new();
        encoder.append(kvlog::LogLevel::Info, 0).key("msg").value_via_display(&message);
        encoder.bytes().to_vec()
    }

    #[test]
    fn decode_self_log_entries_to_plain_text_is_readable_and_ansi_free() {
        let mut binary = encoded_log_entry("hello from the daemon");
        binary.extend_from_slice(&encoded_log_entry("second line"));

        let mut out = String::new();
        decode_self_log_entries_to_plain_text(&binary, &mut out);

        assert!(out.contains("hello from the daemon"), "decoded text was: {out:?}");
        assert!(out.contains("second line"), "decoded text was: {out:?}");
        assert!(!out.contains('\x1b'), "decoded text still contained ANSI escapes: {out:?}");
    }

    #[test]
    fn decode_self_log_entries_to_plain_text_empty_input() {
        let mut out = String::new();
        decode_self_log_entries_to_plain_text(&[], &mut out);
        assert!(out.is_empty());
    }
}
