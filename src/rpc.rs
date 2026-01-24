#![allow(dead_code, reason = "it is used but only from testing harness")]
//! Bidirectional RPC protocol for devsm client-daemon communication.
//!
//! Currently this is just a module, but in the future may be extracted into owns crate.
//! I just don't want to worry about publishing one and maintaining semver version this
//! early.

use jsony::Jsony;

pub(crate) mod unix_path {
    use jsony::{BytesWriter, FromBinary, ToBinary};
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};
    pub fn encode_binary(value: &Path, output: &mut BytesWriter) {
        value.as_os_str().as_bytes().encode_binary(output);
    }
    pub fn decode_binary<'a>(decoder: &mut jsony::binary::Decoder<'a>) -> &'a Path {
        Path::new(OsStr::from_bytes(<&'a [u8]>::decode_binary(decoder)))
    }
}

/// Protocol magic number identifying devsm RPC messages.
pub const MAGIC: u32 = 0xDE75_0001;

/// Size of the message header in bytes.
pub const HEAD_SIZE: usize = 12;

/// Default maximum payload size (64KB).
pub const DEFAULT_MAX_PAYLOAD: usize = 64 * 1024;

/// Flag bit in correlation field indicating one-shot mode.
///
/// When set, the command executes synchronously without mio registration,
/// and the socket closes immediately after the response.
pub const ONE_SHOT_FLAG: u16 = 1 << 15;

/// Mask for extracting correlation ID (bits 0-14).
pub const CORRELATION_MASK: u16 = 0x7FFF;

/// Message header for the RPC protocol.
///
/// The header is 12 bytes in little-endian format and precedes every message.
///
/// The correlation field uses bit 15 as a one-shot flag:
/// - Bit 15 = 1: One-shot mode (fast path, no mio registration)
/// - Bits 0-14: Correlation ID (0-32767)
///
/// # Examples
///
/// ```ignore
/// let head = Head {
///     magic: MAGIC,
///     kind: RpcMessageKind::Resize as u16,
///     one_shot: false,
///     correlation: 1,
///     len: 4,
/// };
/// let bytes = head.to_bytes();
/// let parsed = Head::from_bytes(&bytes)?;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub magic: u32,
    pub kind: u16,
    pub one_shot: bool,
    pub correlation: u16,
    pub len: u32,
}

impl Head {
    /// Parses a header from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidMagic`] if the magic number is incorrect.
    pub fn from_bytes(bytes: &[u8; HEAD_SIZE]) -> Result<Self, ProtocolError> {
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != MAGIC {
            return Err(ProtocolError::InvalidMagic(magic));
        }
        let flags_correlation = u16::from_le_bytes([bytes[6], bytes[7]]);
        Ok(Self {
            magic,
            kind: u16::from_le_bytes([bytes[4], bytes[5]]),
            one_shot: (flags_correlation & ONE_SHOT_FLAG) != 0,
            correlation: flags_correlation & CORRELATION_MASK,
            len: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }

    /// Serializes the header to raw bytes.
    pub fn to_bytes(&self) -> [u8; HEAD_SIZE] {
        let mut buf = [0u8; HEAD_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.kind.to_le_bytes());
        let flags_correlation = self.correlation | if self.one_shot { ONE_SHOT_FLAG } else { 0 };
        buf[6..8].copy_from_slice(&flags_correlation.to_le_bytes());
        buf[8..12].copy_from_slice(&self.len.to_le_bytes());
        buf
    }
}

/// Message type discriminant for the RPC protocol.
///
/// Discriminants are explicitly assigned for wire stability:
/// - `0x01xx`: Client to server messages
/// - `0x02xx`: Server to client responses
/// - `0x03xx`: Server to client events
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RpcMessageKind {
    // Legacy (kept for backward compat during migration)
    OpenWorkspace = 0x0100,
    Subscribe = 0x0101,
    RunTask = 0x0103,
    Resize = 0x0120,
    Terminate = 0x0121,

    // Commands (0x01xx) - new unified protocol
    RestartTask = 0x0110,
    KillTask = 0x0111,
    RerunTests = 0x0112,
    CallFunction = 0x0113,
    AttachTui = 0x0114,
    AttachRun = 0x0115,
    AttachTests = 0x0116,
    AttachLogs = 0x0117,
    GetSelfLogs = 0x0118,
    RestartSelected = 0x0119,
    GetLoggedRustPanics = 0x011A,

    // Legacy responses
    OpenWorkspaceAck = 0x0200,
    SubscribeAck = 0x0201,
    RunTaskAck = 0x0203,
    ErrorResponse = 0x02FF,
    TerminateAck = 0x0220,

    // Responses (0x02xx) - new unified protocol
    CommandAck = 0x0210,

    // Events (0x03xx)
    JobStatus = 0x0301,
    JobExited = 0x0302,
    Disconnect = 0x03FF,
}

impl RpcMessageKind {
    /// Converts a raw u16 to a message kind.
    ///
    /// Returns [`None`] if the value does not match a known message kind.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0100 => Some(Self::OpenWorkspace),
            0x0101 => Some(Self::Subscribe),
            0x0103 => Some(Self::RunTask),
            0x0120 => Some(Self::Resize),
            0x0121 => Some(Self::Terminate),
            0x0110 => Some(Self::RestartTask),
            0x0111 => Some(Self::KillTask),
            0x0112 => Some(Self::RerunTests),
            0x0113 => Some(Self::CallFunction),
            0x0114 => Some(Self::AttachTui),
            0x0115 => Some(Self::AttachRun),
            0x0116 => Some(Self::AttachTests),
            0x0117 => Some(Self::AttachLogs),
            0x0118 => Some(Self::GetSelfLogs),
            0x0119 => Some(Self::RestartSelected),
            0x011A => Some(Self::GetLoggedRustPanics),
            0x0200 => Some(Self::OpenWorkspaceAck),
            0x0201 => Some(Self::SubscribeAck),
            0x0203 => Some(Self::RunTaskAck),
            0x02FF => Some(Self::ErrorResponse),
            0x0220 => Some(Self::TerminateAck),
            0x0210 => Some(Self::CommandAck),
            0x0301 => Some(Self::JobStatus),
            0x0302 => Some(Self::JobExited),
            0x03FF => Some(Self::Disconnect),
            _ => None,
        }
    }

    /// Returns true if this message kind supports one-shot mode.
    pub fn is_one_shot_capable(&self) -> bool {
        matches!(
            self,
            Self::RestartTask
                | Self::KillTask
                | Self::RerunTests
                | Self::CallFunction
                | Self::RestartSelected
                | Self::GetLoggedRustPanics
        )
    }
}

/// Errors that can occur during protocol encoding or decoding.
#[derive(Debug)]
pub enum ProtocolError {
    InvalidMagic(u32),
    UnknownMessageKind(u16),
    PayloadTooLarge(u32),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic(m) => write!(f, "invalid magic: {m:#x}"),
            Self::UnknownMessageKind(k) => write!(f, "unknown message kind: {k:#x}"),
            Self::PayloadTooLarge(len) => write!(f, "payload too large: {len} bytes"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Zero-copy decoder state for RPC messages.
///
/// Tracks the read position within an external buffer. The buffer is owned
/// by the caller, allowing zero-copy reads directly into buffer capacity.
///
/// # Examples
///
/// ```ignore
/// let mut state = DecodingState::default();
/// let mut buffer = Vec::new();
///
/// loop {
///     match state.decode(&buffer) {
///         DecodeResult::Message { kind, correlation, payload } => {
///             process(kind, payload);
///         }
///         DecodeResult::MissingData { additional } => {
///             // Read more data
///             buffer.reserve(additional);
///             let n = read_into_spare_capacity(&mut buffer)?;
///             if n == 0 { break; }
///         }
///         DecodeResult::Empty => {
///             buffer.clear();
///             break;
///         }
///         DecodeResult::Error(e) => return Err(e),
///     }
/// }
/// state.compact(&mut buffer, 4096);
/// ```
pub struct DecodingState {
    offset: usize,
    max_payload_size: usize,
}

impl Default for DecodingState {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of attempting to decode a message.
pub enum DecodeResult<'a> {
    /// A complete message was decoded.
    Message { correlation: u16, one_shot: bool, kind: RpcMessageKind, payload: &'a [u8] },
    /// More data is needed to complete the message.
    MissingData {
        /// Minimum additional bytes needed.
        additional: usize,
    },
    /// Buffer has been fully consumed and can be cleared.
    Empty,
    /// Protocol error; stream should be closed.
    Error(ProtocolError),
}

impl DecodingState {
    /// Creates a new decoding state with default max payload size.
    pub fn new() -> Self {
        Self { offset: 0, max_payload_size: DEFAULT_MAX_PAYLOAD }
    }

    /// Decodes the next message from the buffer.
    ///
    /// The buffer must not be truncated between calls; only append new data.
    /// After processing a [`DecodeResult::Message`], call this again to get
    /// the next message. The state automatically advances past decoded messages.
    ///
    /// Returns [`DecodeResult::Empty`] when all data has been consumed and
    /// the buffer can safely be cleared.
    pub fn decode<'a>(&mut self, bytes: &'a [u8]) -> DecodeResult<'a> {
        let remaining = &bytes[self.offset..];

        if remaining.is_empty() {
            self.offset = 0;
            return DecodeResult::Empty;
        }

        if remaining.len() < HEAD_SIZE {
            return DecodeResult::MissingData { additional: HEAD_SIZE - remaining.len() };
        }

        let header_bytes: &[u8; HEAD_SIZE] = remaining[..HEAD_SIZE].try_into().unwrap();
        let head = match Head::from_bytes(header_bytes) {
            Ok(h) => h,
            Err(e) => return DecodeResult::Error(e),
        };

        let Some(kind) = RpcMessageKind::from_u16(head.kind) else {
            return DecodeResult::Error(ProtocolError::UnknownMessageKind(head.kind));
        };

        if head.len as usize > self.max_payload_size {
            return DecodeResult::Error(ProtocolError::PayloadTooLarge(head.len));
        }

        let total_size = HEAD_SIZE + head.len as usize;
        if remaining.len() < total_size {
            return DecodeResult::MissingData { additional: total_size - remaining.len() };
        }

        let payload = &remaining[HEAD_SIZE..total_size];
        self.offset += total_size;

        DecodeResult::Message { correlation: head.correlation, one_shot: head.one_shot, kind, payload }
    }

    /// Compacts the buffer by removing already-processed bytes.
    ///
    /// If the number of processed bytes exceeds `threshold`, copies the
    /// unread portion to the start of the buffer and resets the offset.
    /// If the buffer is fully consumed, just clears it.
    pub fn compact(&mut self, buffer: &mut Vec<u8>, threshold: usize) {
        if self.offset == 0 {
            return;
        }

        if self.offset >= buffer.len() {
            buffer.clear();
            self.offset = 0;
            return;
        }

        if self.offset >= threshold {
            buffer.copy_within(self.offset.., 0);
            buffer.truncate(buffer.len() - self.offset);
            self.offset = 0;
        }
    }
}

/// Sans-IO encoder for RPC messages.
///
/// The encoder writes messages to an internal buffer. It does not perform any
/// I/O directly; the caller retrieves bytes and sends them.
///
/// # Examples
///
/// ```ignore
/// let mut encoder = Encoder::new();
/// encoder.encode_push(RpcMessageKind::JobStatus, &event);
/// socket.write_all(encoder.output())?;
/// encoder.clear();
/// ```
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Creates a new encoder.
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(4096) }
    }

    /// Returns the output buffer containing encoded messages.
    pub fn output(&self) -> &[u8] {
        &self.buf
    }

    /// Clears the output buffer after sending.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Encodes a response message with the given correlation ID.
    pub fn encode_response<T: jsony::ToBinary>(&mut self, kind: RpcMessageKind, correlation: u16, payload: &T) {
        self.encode_with_correlation(kind, correlation, payload);
    }

    /// Encodes a subscription push message (correlation = 0).
    pub fn encode_push<T: jsony::ToBinary>(&mut self, kind: RpcMessageKind, payload: &T) {
        self.encode_with_correlation(kind, 0, payload);
    }

    /// Encodes a message with no payload.
    pub fn encode_empty(&mut self, kind: RpcMessageKind, correlation: u16) {
        let head = Head { magic: MAGIC, kind: kind as u16, one_shot: false, correlation, len: 0 };
        self.buf.extend_from_slice(&head.to_bytes());
    }

    /// Encodes a one-shot message with no payload.
    pub fn encode_empty_one_shot(&mut self, kind: RpcMessageKind, correlation: u16) {
        let head = Head { magic: MAGIC, kind: kind as u16, one_shot: true, correlation, len: 0 };
        self.buf.extend_from_slice(&head.to_bytes());
    }

    fn encode_with_correlation<T: jsony::ToBinary>(&mut self, kind: RpcMessageKind, correlation: u16, payload: &T) {
        self.encode_internal(kind, correlation, false, payload);
    }

    /// Encodes a one-shot request message.
    pub fn encode_one_shot<T: jsony::ToBinary>(&mut self, kind: RpcMessageKind, correlation: u16, payload: &T) {
        self.encode_internal(kind, correlation, true, payload);
    }

    fn encode_internal<T: jsony::ToBinary>(
        &mut self,
        kind: RpcMessageKind,
        correlation: u16,
        one_shot: bool,
        payload: &T,
    ) {
        let header_start = self.buf.len();
        self.buf.extend_from_slice(&[0u8; HEAD_SIZE]);

        let payload_start = self.buf.len();
        jsony::to_binary_into(payload, &mut self.buf);
        let payload_len = self.buf.len() - payload_start;

        let head = Head { magic: MAGIC, kind: kind as u16, one_shot, correlation, len: payload_len as u32 };
        self.buf[header_start..header_start + HEAD_SIZE].copy_from_slice(&head.to_bytes());
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct ResizeNotification {
    pub width: u16,
    pub height: u16,
}

#[derive(Jsony, Debug, Clone, Copy)]
#[jsony(Binary)]
#[repr(u8)]
pub enum JobStatusKind {
    Scheduled = 0,
    Starting = 1,
    Running = 2,
    Restarting = 3,
    Waiting = 4,
}

#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct JobStatusEvent {
    pub job_index: u32,
    pub status: JobStatusKind,
}

#[derive(Jsony, Debug, Clone, Copy)]
#[jsony(Binary)]
#[repr(u8)]
pub enum ExitCause {
    Unknown = 0,
    Killed = 1,
    Restarted = 2,
    SpawnFailed = 3,
    ProfileConflict = 4,
}

#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct JobExitedEvent {
    pub job_index: u32,
    pub exit_code: i32,
    pub cause: ExitCause,
}

/// Request to open a workspace by config path.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct OpenWorkspaceRequest<'a> {
    pub config_path: &'a str,
    pub subscribe: bool,
}

/// Response to an [`OpenWorkspaceRequest`].
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct OpenWorkspaceResponse {
    pub success: bool,
    pub error: Option<Box<str>>,
}

/// Filters for event subscriptions.
#[derive(Jsony, Debug, Default)]
#[jsony(Binary)]
pub struct SubscriptionFilter {
    pub job_status: bool,
    pub job_exits: bool,
}

/// Response confirming subscription filter update.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct SubscribeAck {
    pub success: bool,
}

/// Request to run a task by name.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct RunTaskRequest<'a> {
    pub task_name: &'a str,
    pub profile: &'a str,
    pub params: &'a [u8],
}

/// Response to a [`RunTaskRequest`].
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct RunTaskResponse {
    pub success: bool,
    pub job_index: Option<u32>,
    pub error: Option<Box<str>>,
}

/// Generic error response for failed requests.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct ErrorResponsePayload {
    pub code: u32,
    pub message: Box<str>,
}

/// Workspace reference for RPC commands.
///
/// Commands can reference workspaces either by ID (efficient for repeated calls)
/// or by config path (for first-time setup).
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub enum WorkspaceRef<'a> {
    Id(u32),
    Path {
        #[jsony(with = unix_path)]
        config: &'a std::path::Path,
    },
}

/// Request to restart a task.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct RestartTaskRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
    pub task_name: &'a str,
    pub profile: &'a str,
    pub params: &'a [u8],
    pub as_test: bool,
}

/// Request to kill a task.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct KillTaskRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
    pub task_name: &'a str,
}

/// Request to rerun tests.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct RerunTestsRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
    pub only_failed: bool,
}

/// Request to call a function.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct CallFunctionRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
    pub function_name: &'a str,
}

/// Request to attach a TUI client.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct AttachTuiRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
}

/// Request to attach a run client.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct AttachRunRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
    pub task_name: &'a str,
    pub params: &'a [u8],
    pub as_test: bool,
}

/// Filters for test selection (serializable for IPC).
#[derive(Jsony, Debug, Clone, Default)]
#[jsony(Binary)]
pub struct TestFilters<'a> {
    pub include_tags: Vec<&'a str>,
    pub exclude_tags: Vec<&'a str>,
    pub include_names: Vec<&'a str>,
}

/// Request to attach a test run client.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct AttachTestsRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
    pub filters: TestFilters<'a>,
}

/// Task filter for log queries.
#[derive(Jsony, Debug, Clone)]
#[jsony(Binary)]
pub struct TaskFilter<'a> {
    pub name: &'a str,
    pub latest: bool,
}

/// Kind filter for log queries.
#[derive(Jsony, Debug, Clone)]
#[jsony(Binary)]
pub struct KindFilter<'a> {
    pub kind: &'a str,
    pub latest: bool,
}

/// Query parameters for the logs command.
#[derive(Jsony, Debug, Clone, Default)]
#[jsony(Binary)]
pub struct LogsQuery<'a> {
    pub max_age_secs: Option<u32>,
    pub task_filters: Vec<TaskFilter<'a>>,
    pub job_index: Option<u32>,
    pub kind_filters: Vec<KindFilter<'a>>,
    pub pattern: &'a str,
    pub follow: bool,
    pub retry: bool,
    pub oldest: Option<u32>,
    pub newest: Option<u32>,
    pub without_taskname: bool,
    pub is_tty: bool,
}

/// Request to attach a logs client.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct AttachLogsRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
    pub query: LogsQuery<'a>,
}

/// Request to get daemon self-logs.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct GetSelfLogsRequest {
    pub follow: bool,
}

/// Request to restart the currently selected task in TUI.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct RestartSelectedRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
}

/// Request to get logged Rust panics.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct GetLoggedRustPanicsRequest<'a> {
    pub workspace: WorkspaceRef<'a>,
}

/// Body of a command response.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub enum CommandBody {
    /// Success with no additional information.
    Empty,
    /// Success with an informational message.
    Message(Box<str>),
    /// Failure with an error message.
    Error(Box<str>),
}

/// Generic response for commands.
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct CommandResponse {
    pub workspace_id: u32,
    pub body: CommandBody,
}

/// Client-side protocol with encoder and decoder state.
///
/// # Examples
///
/// ```ignore
/// let mut protocol = ClientProtocol::new();
/// let mut read_buf = Vec::new();
///
/// // Send a message
/// protocol.send_notify(RpcMessageKind::Resize, &ResizeNotification { width: 80, height: 24 });
/// socket.write_all(protocol.output())?;
/// protocol.clear_output();
///
/// // Read and decode
/// read_buf.extend_from_slice(&received_data);
/// loop {
///     match protocol.decode(&read_buf) {
///         DecodeResult::Message { kind, payload, .. } => {
///             handle(kind, payload);
///         }
///         DecodeResult::MissingData { .. } | DecodeResult::Empty => break,
///         DecodeResult::Error(e) => return Err(e),
///     }
/// }
/// protocol.compact(&mut read_buf, 4096);
/// ```
pub struct ClientProtocol {
    encoder: Encoder,
    state: DecodingState,
    next_correlation: u16,
}

impl ClientProtocol {
    /// Creates a new client protocol handler.
    pub fn new() -> Self {
        Self { encoder: Encoder::new(), state: DecodingState::new(), next_correlation: 1 }
    }

    /// Returns the next correlation ID and advances the counter.
    ///
    /// IDs cycle through 1..=u16::MAX, skipping 0 which is reserved for push messages.
    pub fn next_correlation(&mut self) -> u16 {
        let id = self.next_correlation;
        self.next_correlation = if id == u16::MAX { 1 } else { id + 1 };
        id
    }

    /// Queues a request message with a correlation ID for response pairing.
    ///
    /// Returns the correlation ID used, which will appear in the response.
    pub fn send_request<T: jsony::ToBinary>(&mut self, kind: RpcMessageKind, payload: &T) -> u16 {
        let correlation = self.next_correlation();
        self.encoder.encode_response(kind, correlation, payload);
        correlation
    }

    /// Queues a fire-and-forget message (no response expected).
    pub fn send_notify<T: jsony::ToBinary>(&mut self, kind: RpcMessageKind, payload: &T) {
        self.encoder.encode_response(kind, 0, payload);
    }

    /// Queues an empty message (no payload).
    pub fn send_empty(&mut self, kind: RpcMessageKind, correlation: u16) {
        self.encoder.encode_empty(kind, correlation);
    }

    /// Returns the output buffer containing encoded messages.
    pub fn output(&self) -> &[u8] {
        self.encoder.output()
    }

    /// Clears the output buffer after sending.
    pub fn clear_output(&mut self) {
        self.encoder.clear();
    }

    /// Decodes the next message from the buffer.
    ///
    /// Call in a loop until [`DecodeResult::MissingData`] or [`DecodeResult::Empty`].
    pub fn decode<'a>(&mut self, buffer: &'a [u8]) -> DecodeResult<'a> {
        self.state.decode(buffer)
    }

    /// Compacts the read buffer by removing processed bytes.
    pub fn compact(&mut self, buffer: &mut Vec<u8>, threshold: usize) {
        self.state.compact(buffer, threshold);
    }
}

impl Default for ClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes an AttachRpc request message in jsony binary format.
///
/// The format matches the daemon's RequestMessage struct:
/// - cwd: length-prefixed byte string (path)
/// - request: enum discriminant (4 for AttachRpc) + variant fields
///   - config: length-prefixed byte string (path)
///   - subscribe: bool as u8
///
/// # Examples
///
/// ```ignore
/// let msg = encode_attach_rpc(&cwd, &config_path, true);
/// socket.write_all(&msg)?;
/// ```
pub fn encode_attach_rpc(cwd: &std::path::Path, config: &std::path::Path, subscribe: bool) -> Vec<u8> {
    use jsony::ToBinary;
    use std::os::unix::ffi::OsStrExt;

    let mut out = jsony::BytesWriter::new();

    // Encode cwd path (length-prefixed bytes)
    let cwd_bytes = cwd.as_os_str().as_bytes();
    cwd_bytes.encode_binary(&mut out);

    // Encode Request enum discriminant (AttachRpc = variant index 3)
    // Note: variant indices are: AttachTui=0, AttachRun=1, AttachTests=2, AttachRpc=3, AttachLogs=4, GetSelfLogs=5
    out.push(3);

    // Encode AttachRpc fields:
    // - config path (length-prefixed bytes)
    let config_bytes = config.as_os_str().as_bytes();
    config_bytes.encode_binary(&mut out);

    // - subscribe bool
    subscribe.encode_binary(&mut out);

    out.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_round_trip() {
        let head =
            Head { magic: MAGIC, kind: RpcMessageKind::Resize as u16, one_shot: false, correlation: 42, len: 100 };
        let bytes = head.to_bytes();
        let parsed = Head::from_bytes(&bytes).unwrap();
        assert_eq!(head, parsed);
    }

    #[test]
    fn head_one_shot_flag() {
        let head =
            Head { magic: MAGIC, kind: RpcMessageKind::RestartTask as u16, one_shot: true, correlation: 123, len: 0 };
        let bytes = head.to_bytes();
        let parsed = Head::from_bytes(&bytes).unwrap();
        assert!(parsed.one_shot);
        assert_eq!(parsed.correlation, 123);
        assert_eq!(head, parsed);
    }

    #[test]
    fn head_invalid_magic() {
        let mut bytes = [0u8; HEAD_SIZE];
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let result = Head::from_bytes(&bytes);
        assert!(matches!(result, Err(ProtocolError::InvalidMagic(0xDEADBEEF))));
    }

    #[test]
    fn encoder_decoder_round_trip() {
        let mut encoder = Encoder::new();
        let payload = ResizeNotification { width: 120, height: 40 };
        encoder.encode_push(RpcMessageKind::Resize, &payload);
        let data = encoder.output().to_vec();

        let mut state = DecodingState::new();
        let DecodeResult::Message { correlation, kind, payload: msg_payload, .. } = state.decode(&data) else {
            panic!("expected message");
        };
        assert_eq!(kind, RpcMessageKind::Resize);
        assert_eq!(correlation, 0);

        let decoded: ResizeNotification = jsony::from_binary(msg_payload).unwrap();
        assert_eq!(decoded.width, 120);
        assert_eq!(decoded.height, 40);
    }

    #[test]
    fn decoder_partial_data() {
        let mut encoder = Encoder::new();
        encoder.encode_push(RpcMessageKind::Resize, &ResizeNotification { width: 80, height: 24 });
        let data = encoder.output().to_vec();

        let mut state = DecodingState::new();

        // Only header partial
        assert!(matches!(state.decode(&data[..5]), DecodeResult::MissingData { .. }));

        // Full header but no payload
        assert!(matches!(state.decode(&data[..HEAD_SIZE]), DecodeResult::MissingData { .. }));

        // Full message
        assert!(matches!(state.decode(&data), DecodeResult::Message { .. }));
    }

    #[test]
    fn decoder_empty_payload() {
        let mut encoder = Encoder::new();
        encoder.encode_empty(RpcMessageKind::Terminate, 5);
        let data = encoder.output().to_vec();

        let mut state = DecodingState::new();
        let DecodeResult::Message { kind, correlation, payload, .. } = state.decode(&data) else {
            panic!("expected message");
        };
        assert_eq!(kind, RpcMessageKind::Terminate);
        assert_eq!(correlation, 5);
        assert!(payload.is_empty());
    }

    #[test]
    fn decoder_multiple_messages() {
        let mut encoder = Encoder::new();
        encoder
            .encode_push(RpcMessageKind::JobStatus, &JobStatusEvent { job_index: 1, status: JobStatusKind::Running });
        encoder
            .encode_push(RpcMessageKind::JobStatus, &JobStatusEvent { job_index: 2, status: JobStatusKind::Waiting });
        let data = encoder.output().to_vec();

        let mut state = DecodingState::new();

        let DecodeResult::Message { payload, .. } = state.decode(&data) else {
            panic!("expected first message");
        };
        let event1: JobStatusEvent = jsony::from_binary(payload).unwrap();
        assert_eq!(event1.job_index, 1);

        let DecodeResult::Message { payload, .. } = state.decode(&data) else {
            panic!("expected second message");
        };
        let event2: JobStatusEvent = jsony::from_binary(payload).unwrap();
        assert_eq!(event2.job_index, 2);

        assert!(matches!(state.decode(&data), DecodeResult::Empty));
    }

    #[test]
    fn decoder_compact() {
        let mut encoder = Encoder::new();
        encoder.encode_empty(RpcMessageKind::Terminate, 0);
        encoder.encode_empty(RpcMessageKind::TerminateAck, 0);
        let mut buffer = encoder.output().to_vec();
        let original_len = buffer.len();

        let mut state = DecodingState::new();

        // Decode first message
        assert!(matches!(state.decode(&buffer), DecodeResult::Message { .. }));

        // Compact with high threshold - should not compact
        state.compact(&mut buffer, 1024);
        assert_eq!(buffer.len(), original_len);

        // Compact with low threshold - should compact
        state.compact(&mut buffer, 1);
        assert_eq!(buffer.len(), HEAD_SIZE);

        // Can still decode second message
        assert!(matches!(state.decode(&buffer), DecodeResult::Message { kind: RpcMessageKind::TerminateAck, .. }));
    }
}
