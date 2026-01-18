use std::{
    marker::PhantomData,
    ops::ControlFlow,
    ptr::NonNull,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use unicode_width::UnicodeWidthStr;
use vtui::Style;

#[derive(Clone, Copy)]
enum LineFilter {
    None,
}

impl<'a> LineTableView<'a> {
    pub fn contains(&self, line: &Line) -> bool {
        true
    }
}
#[derive(Clone, Copy)]
pub struct LineTableView<'a> {
    pub(crate) table: &'a LineTable,
    pub(crate) tail: LineId,
    pub(crate) filter: LineFilter,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JobId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Default)]
pub struct LineId(pub usize);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Line {
    pub job_id: JobId,
    start: u32,
    len: u32,
    pub width: u32,
    pub style: Style,
}
impl Line {
    /// Safety: The Line must be from the providd LineBuffer and
    /// the LineBuffer must not have been mutated since the Line
    /// was taking from said buffer.
    pub unsafe fn text(&self, buf: &LineTable) -> &str {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(
            buf.buffer.add(self.start as usize).as_ptr(),
            self.len as usize,
        ))
    }
}

#[cfg(not(test))]
const MAX_LINES: usize = 16 * 4096;
#[cfg(not(test))]
const MAX_CAPACITY: usize = 16 * 1024;

// NOTE: Modified for effective testing
#[cfg(test)]
const MAX_LINES: usize = 16;
#[cfg(test)]
const MAX_CAPACITY: usize = 256;

unsafe impl Send for LineTable {}
unsafe impl Sync for LineTable {}

impl Drop for LineTable {
    fn drop(&mut self) {
        unsafe {
            let layout = std::alloc::Layout::from_size_align(MAX_CAPACITY, 1).unwrap();
            std::alloc::dealloc(self.buffer.as_ptr(), layout);
            let layout = std::alloc::Layout::array::<Line>(MAX_LINES).unwrap();
            std::alloc::dealloc(self.line_entires.as_ptr() as *mut u8, layout);
        }
    }
}

struct WrappingBufferRange {
    start: u32,
    len: u32,
}

pub struct LineTable {
    buffer: NonNull<u8>,
    line_entires: NonNull<Line>,
    // This MUST be atomic as it's modified under a read lock.
    line_count: AtomicUsize,
    /// The absolute, ever-increasing LineId of the first line in the buffer.
    /// This is only ever modified under a write lock, so it does not need to be atomic.
    start_line_id: usize,
}

pub struct LineIndexer<'a> {
    buffer: NonNull<Line>,
    end: usize,
    start: usize,
    _marker: PhantomData<&'a ()>,
}

impl std::ops::Index<LineId> for LineIndexer<'_> {
    type Output = Line;
    fn index(&self, id: LineId) -> &Self::Output {
        if id.0 < self.start && id.0 >= self.end {
            panic!("LineId out of bounds");
        }
        unsafe { &*self.buffer.as_ptr().add(id.0 % MAX_LINES) }
    }
}

impl LineTable {
    pub fn view_all(&self) -> LineTableView<'_> {
        LineTableView {
            table: self,
            tail: self.tail(),
            filter: LineFilter::None,
        }
    }
    pub fn indexer(&self) -> LineIndexer<'_> {
        let len = self.line_count.load(Ordering::Acquire);
        LineIndexer {
            buffer: self.line_entires,
            start: self.start_line_id,
            end: self.start_line_id + len,
            _marker: PhantomData,
        }
    }
    fn index_start(&self) -> usize {
        self.start_line_id & (MAX_LINES - 1)
    }
    pub fn head(&self) -> LineId {
        LineId(self.start_line_id)
    }
    pub fn tail(&self) -> LineId {
        let len = self.line_count.load(Ordering::Acquire);
        LineId(self.start_line_id + len)
    }

    pub fn slices(&self) -> (&[Line], &[Line]) {
        let len = self.line_count.load(Ordering::Acquire);
        let start = self.index_start();
        if start + len <= MAX_LINES {
            unsafe {
                let slice = std::slice::from_raw_parts(self.line_entires.as_ptr().add(start), len);
                return (slice, &[]);
            }
        }
        let first_len = MAX_LINES - start;
        unsafe {
            let a = std::slice::from_raw_parts(self.line_entires.as_ptr().add(start), first_len);
            let b = std::slice::from_raw_parts(self.line_entires.as_ptr(), len - first_len);
            return (a, b);
        }
    }

    pub fn slices_range(&self, min: LineId, max: LineId) -> (&[Line], &[Line]) {
        if min.0 > max.0 {
            return (&[], &[]);
        }

        let first_id = self.start_line_id;
        let len = self.line_count.load(Ordering::Acquire);

        if len == 0 {
            return (&[], &[]);
        }

        let last_id = first_id + len - 1;

        let start_id = min.0.max(first_id);
        let end_id = max.0.min(last_id);

        if start_id > end_id {
            return (&[], &[]);
        }

        let count = end_id - start_id + 1;

        let start_offset = start_id - first_id;
        let physical_start = (self.index_start() + start_offset) & (MAX_LINES - 1);

        if physical_start + count <= MAX_LINES {
            unsafe {
                let slice = std::slice::from_raw_parts(
                    self.line_entires.as_ptr().add(physical_start),
                    count,
                );
                (slice, &[])
            }
        } else {
            let first_len = MAX_LINES - physical_start;
            let second_len = count - first_len;
            unsafe {
                let a = std::slice::from_raw_parts(
                    self.line_entires.as_ptr().add(physical_start),
                    first_len,
                );
                let b = std::slice::from_raw_parts(self.line_entires.as_ptr(), second_len);
                (a, b)
            }
        }
    }

    pub fn slices_from(&self, start_id: LineId) -> (&[Line], &[Line], LineId) {
        let first_id = self.start_line_id;
        let len = self.line_count.load(Ordering::Acquire);

        let end_line_id = first_id + len;
        if len == 0 {
            return (&[], &[], LineId(end_line_id)); // Buffer is empty, try again from the same spot later.
        }

        let start_logical_offset = start_id.0.saturating_sub(first_id);

        if start_logical_offset >= len {
            // The requested start_id is past the end of our buffer.
            // The next valid ID to request is the one after our last line.
            return (&[], &[], LineId(end_line_id));
        }

        let physical_start_index = (first_id + start_logical_offset) & (MAX_LINES - 1);
        let num_lines_to_iterate = len - start_logical_offset;

        let (a, b) = if physical_start_index + num_lines_to_iterate <= MAX_LINES {
            unsafe {
                (
                    std::slice::from_raw_parts(
                        self.line_entires.as_ptr().add(physical_start_index),
                        num_lines_to_iterate,
                    ),
                    &[][..],
                )
            }
        } else {
            let first_slice_len = MAX_LINES - physical_start_index;
            unsafe {
                (
                    std::slice::from_raw_parts(
                        self.line_entires.as_ptr().add(physical_start_index),
                        first_slice_len,
                    ),
                    std::slice::from_raw_parts(
                        self.line_entires.as_ptr(),
                        num_lines_to_iterate - first_slice_len,
                    ),
                )
            }
        };
        (a, b, LineId(end_line_id))
    }

    pub fn for_each(&self, mut func: impl FnMut(LineId, JobId, &str, u32) -> ControlFlow<(), ()>) {
        let (a, b) = self.slices();
        let first_id = self.start_line_id;
        let mut logical_index = 0;
        for array in [a, b] {
            for entry in array.iter() {
                let data = unsafe {
                    std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                        self.buffer.add(entry.start as usize).as_ptr(),
                        entry.len as usize,
                    ))
                };
                match func(
                    LineId(first_id + logical_index),
                    entry.job_id,
                    data,
                    entry.width,
                ) {
                    ControlFlow::Continue(_) => (),
                    ControlFlow::Break(_) => return,
                }
                logical_index += 1;
            }
        }
    }

    pub fn for_each_from(
        &self,
        start_id: LineId,
        mut func: impl FnMut(LineId, JobId, &str, u32) -> ControlFlow<(), ()>,
    ) -> LineId {
        let first_id = self.start_line_id;
        let len = self.line_count.load(Ordering::Acquire);

        if len == 0 {
            return start_id; // Buffer is empty, try again from the same spot later.
        }

        let end_line_id = first_id + len;
        let start_logical_offset = start_id.0.saturating_sub(first_id);

        if start_logical_offset >= len {
            // The requested start_id is past the end of our buffer.
            // The next valid ID to request is the one after our last line.
            return LineId(end_line_id);
        }

        let physical_start_index = (first_id + start_logical_offset) & (MAX_LINES - 1);
        let num_lines_to_iterate = len - start_logical_offset;

        let (a, b) = if physical_start_index + num_lines_to_iterate <= MAX_LINES {
            unsafe {
                (
                    std::slice::from_raw_parts(
                        self.line_entires.as_ptr().add(physical_start_index),
                        num_lines_to_iterate,
                    ),
                    &[][..],
                )
            }
        } else {
            let first_slice_len = MAX_LINES - physical_start_index;
            unsafe {
                (
                    std::slice::from_raw_parts(
                        self.line_entires.as_ptr().add(physical_start_index),
                        first_slice_len,
                    ),
                    std::slice::from_raw_parts(
                        self.line_entires.as_ptr(),
                        num_lines_to_iterate - first_slice_len,
                    ),
                )
            }
        };

        let mut current_logical_offset = start_logical_offset;
        for array in [a, b] {
            for entry in array.iter() {
                let data = unsafe {
                    std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                        self.buffer.add(entry.start as usize).as_ptr(),
                        entry.len as usize,
                    ))
                };
                let current_line_id = LineId(first_id + current_logical_offset);
                match func(current_line_id, entry.job_id, data, entry.width) {
                    ControlFlow::Continue(_) => (),
                    ControlFlow::Break(_) => {
                        // Iteration was stopped early. The next ID to start from
                        // is the one after the line we just processed.
                        return LineId(current_line_id.0 + 1);
                    }
                }
                current_logical_offset += 1;
            }
        }

        // If we finished the whole loop, the next ID to start from is
        // the one after the very last line in the buffer.
        LineId(end_line_id)
    }

    fn free_lines(&mut self, amount: usize) -> WrappingBufferRange {
        let curr = *self.line_count.get_mut();
        let amount = curr.min(amount);
        let index_start = self.index_start();

        if amount == 0 {
            if curr == 0 {
                return WrappingBufferRange {
                    start: 0,
                    len: MAX_CAPACITY as u32,
                };
            }
            let last_line_idx = (index_start + curr - 1) & (MAX_LINES - 1);
            let end_of_used_buffer = unsafe {
                let value = self.line_entires.add(last_line_idx).read();
                value.start + value.len
            };
            if curr == MAX_LINES {
                return WrappingBufferRange {
                    start: end_of_used_buffer,
                    len: 0,
                };
            }
            let start_of_used_buffer = unsafe {
                let value = self.line_entires.add(index_start).read();
                value.start
            };
            return WrappingBufferRange {
                start: end_of_used_buffer,
                len: (start_of_used_buffer + MAX_CAPACITY as u32 - end_of_used_buffer)
                    % MAX_CAPACITY as u32,
            };
        }

        let last_line_index_before_free = (index_start + curr - 1) & (MAX_LINES - 1);
        let end_of_used_buffer = unsafe {
            let value = self.line_entires.add(last_line_index_before_free).read();
            value.start + value.len
        };

        self.start_line_id += amount;
        self.line_count.store(curr - amount, Ordering::Release);

        let new_line_count = curr - amount;
        if new_line_count > 0 {
            let new_index_start = self.index_start();
            let start_of_used_buffer =
                unsafe { self.line_entires.add(new_index_start).read().start };
            WrappingBufferRange {
                start: end_of_used_buffer,
                len: (start_of_used_buffer + MAX_CAPACITY as u32 - end_of_used_buffer)
                    % MAX_CAPACITY as u32,
            }
        } else {
            WrappingBufferRange {
                start: 0,
                len: MAX_CAPACITY as u32,
            }
        }
    }
}

impl WrappingBufferRange {
    fn munch(&mut self, len: usize) -> Option<u32> {
        if len > self.len as usize {
            return None;
        }
        let end = self.start + len as u32;
        if end > MAX_CAPACITY as u32 {
            let wasted = MAX_CAPACITY - self.start as usize;
            if self.len as usize - wasted < len {
                return None;
            }
            self.start = len as u32;
            self.len -= wasted as u32;
            self.len -= len as u32;
            Some(0)
        } else {
            let start = self.start;
            self.start = end;
            self.len -= len as u32;
            Some(start)
        }
    }
}

pub struct LineTableWriter {
    buffer: Arc<RwLock<LineTable>>,
    range: WrappingBufferRange,
    remaining: usize,
}

fn write_line_unchecked(
    buf: &LineTable,
    start: u32,
    line: &str,
    width: u32,
    job_id: JobId,
    style: Style,
) {
    let index_start = buf.index_start();
    let line_count = buf.line_count.load(Ordering::Acquire);
    let next = (line_count + index_start) & (MAX_LINES - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            line.as_ptr(),
            buf.buffer.add(start as usize).as_ptr(),
            line.len(),
        );
        buf.line_entires.add(next).write(Line {
            job_id,
            start,
            len: line.len() as u32,
            width,
            style,
        });
        buf.line_count.fetch_add(1, Ordering::Release);
    }
}

impl LineTableWriter {
    pub fn new() -> LineTableWriter {
        let buffer = {
            let layout = std::alloc::Layout::from_size_align(MAX_CAPACITY, 1).unwrap();
            let ptr = unsafe { std::alloc::alloc(layout) };
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            NonNull::new(ptr).unwrap()
        };
        let line_entries = {
            let layout = std::alloc::Layout::array::<Line>(MAX_LINES).unwrap();
            let ptr = unsafe { std::alloc::alloc(layout) };
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            NonNull::new(ptr as *mut Line).unwrap()
        };
        let line_buffer = LineTable {
            buffer,
            line_entires: line_entries,
            line_count: AtomicUsize::new(0),
            start_line_id: 0,
        };
        LineTableWriter {
            buffer: Arc::new(RwLock::new(line_buffer)),
            remaining: MAX_LINES,
            range: WrappingBufferRange {
                start: 0,
                len: MAX_CAPACITY as u32,
            },
        }
    }

    pub fn reader(&self) -> Arc<RwLock<LineTable>> {
        self.buffer.clone()
    }

    pub fn push(&mut self, line: &str) {
        self.push_line(line, line.width() as u32, JobId(1), Style::DEFAULT);
    }
    pub fn push_line(&mut self, line: &str, width: u32, job_id: JobId, style: Style) {
        let offset = if let Some(offset) = self.range.munch(line.len())
            && self.remaining > 0
        {
            offset
        } else {
            let mut lock = self.buffer.write().unwrap();
            let count = (lock.line_count.load(Ordering::Acquire) as usize + 1) / 2;
            self.range = lock.free_lines(count);
            self.remaining = MAX_LINES - *lock.line_count.get_mut();
            if let Some(offset) = self.range.munch(line.len())
                && self.remaining > 0
            {
                offset
            } else {
                panic!("Line is too long to fit in the freed buffer space");
            }
        };

        let buf = self.buffer.read().unwrap();
        self.remaining -= 1;
        write_line_unchecked(&buf, offset, line, width, job_id, style);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::ControlFlow;

    // Helper to collect all lines from the buffer for easy assertion.
    fn collect_lines(reader: &Arc<RwLock<LineTable>>) -> Vec<(LineId, JobId, String, u32)> {
        let mut lines = Vec::new();
        let buffer = reader.read().unwrap();
        buffer.for_each(|id, job, data, width| {
            lines.push((id, job, data.to_string(), width));
            ControlFlow::Continue(())
        });
        lines
    }

    // Helper to collect lines from a specific starting ID.
    fn collect_lines_from(
        reader: &Arc<RwLock<LineTable>>,
        start_id: LineId,
    ) -> Vec<(LineId, JobId, String, u32)> {
        let mut lines = Vec::new();
        let buffer = reader.read().unwrap();
        buffer.for_each_from(start_id, |id, job, data, width| {
            lines.push((id, job, data.to_string(), width));
            ControlFlow::Continue(())
        });
        lines
    }

    #[test]
    fn test_basic_push_and_read() {
        let mut writer = LineTableWriter::new();
        let reader = writer.reader();

        for i in 0..5 {
            writer.push_line(&format!("Line {}", i), 10, JobId(1), Style::DEFAULT);
        }

        let lines = collect_lines(&reader);
        assert_eq!(lines.len(), 5);
        for i in 0..5 {
            assert_eq!(lines[i].0, LineId(i));
            assert_eq!(lines[i].1, JobId(1));
            assert_eq!(lines[i].2, format!("Line {}", i));
            assert_eq!(lines[i].3, 10);
        }
    }

    #[test]
    fn test_rotation_on_max_lines() {
        let mut writer = LineTableWriter::new();
        let reader = writer.reader();

        // Push MAX_LINES + 1 lines to trigger a rotation.
        for i in 0..=MAX_LINES {
            writer.push_line(
                &format!("line_{}", i),
                i as u32,
                JobId(i as u32),
                Style::DEFAULT,
            );
        }

        // On the (MAX_LINES+1)th push, a rotation is triggered.
        // It frees (MAX_LINES + 1) / 2 = (16+1)/2 = 8 lines.
        // The buffer should now contain lines 8 through 16.
        // Total lines = 16 - 8 + 1 = 9.
        // The start_line_id should now be 8.

        let lock = reader.read().unwrap();
        assert_eq!(lock.start_line_id, 8);
        assert_eq!(lock.line_count.load(Ordering::Acquire), 9);
        drop(lock);

        let lines = collect_lines(&reader);
        assert_eq!(lines.len(), 9);
        assert_eq!(lines[0].0, LineId(8));
        assert_eq!(lines[0].2, "line_8");
        assert_eq!(lines[8].0, LineId(16));
        assert_eq!(lines[8].2, "line_16");
    }

    #[test]
    fn test_rotation_on_max_capacity() {
        let mut writer = LineTableWriter::new();
        let reader = writer.reader();

        // MAX_CAPACITY is 256. Push 5 lines of 60 bytes each. 4 will fit, 5th triggers rotation.
        let line_data = "A".repeat(60);
        for i in 0..4 {
            writer.push_line(&line_data, 60, JobId(i), Style::DEFAULT);
        }
        // Buffer used: 4 * 60 = 240 bytes. Remaining capacity: 16 bytes.
        assert_eq!(collect_lines(&reader).len(), 4);

        // This push will fail to find space and trigger a rotation.
        writer.push_line(&line_data, 60, JobId(4), Style::DEFAULT);

        // Rotation frees (4+1)/2 = 2 lines. 2 * 60 = 120 bytes of space freed.
        // The buffer should now contain original lines 2, 3 and the new line 4.
        // Total lines = 4 - 2 + 1 = 3.
        // start_line_id should be 2.
        let lock = reader.read().unwrap();
        assert_eq!(lock.start_line_id, 2);
        assert_eq!(lock.line_count.load(Ordering::Acquire), 3);
        drop(lock);

        let lines = collect_lines(&reader);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].0, LineId(2)); // Original 3rd line
        assert_eq!(lines[1].0, LineId(3)); // Original 4th line
        assert_eq!(lines[2].0, LineId(4)); // The new line
        assert!(lines.iter().all(|l| l.2 == line_data));
    }

    #[test]
    fn test_byte_buffer_wrapping_and_data_integrity() {
        let mut writer = LineTableWriter::new();
        let reader = writer.reader();

        // 1. Push a line that fills most of the buffer. Capacity is 256.
        let line_a = "A".repeat(200);
        writer.push_line(&line_a, 200, JobId(0), Style::DEFAULT); // Uses [0..200)

        // 2. Push a second line that fits in the remaining space.
        let line_b = "B".repeat(50);
        writer.push_line(&line_b, 50, JobId(1), Style::DEFAULT); // Uses [200..250)

        // 3. Push a third line that is too big, triggering rotation.
        let line_c = "C".repeat(100);
        writer.push_line(&line_c, 100, JobId(2), Style::DEFAULT);

        // Rotation frees (2+1)/2 = 1 line (line_a).
        // Line_b at [200..250) remains. start_line_id becomes 1.
        // The newly freed space wraps around. The new line_c should be placed at the start [0..100).

        let lines = collect_lines(&reader);
        assert_eq!(lines.len(), 2);

        // Check that the remaining line (line_b) and the new line (line_c) are correct.
        assert_eq!(lines[0].0, LineId(1));
        assert_eq!(lines[0].2, line_b);
        assert_eq!(lines[0].1, JobId(1));

        assert_eq!(lines[1].0, LineId(2));
        assert_eq!(lines[1].2, line_c);
        assert_eq!(lines[1].1, JobId(2));
    }

    #[test]
    fn test_for_each_from_after_rotation() {
        let mut writer = LineTableWriter::new();
        let reader = writer.reader();

        // Push 20 lines to trigger one rotation and populate the buffer.
        for i in 0..20 {
            writer.push_line(&format!("line_{}", i), 10, JobId(i as u32), Style::DEFAULT);
        }

        // After 16 lines, a rotation happens on the 17th. 8 lines are freed.
        // The buffer will contain lines 8..=19. start_line_id is 8. Count is 12.
        let lock = reader.read().unwrap();
        assert_eq!(lock.start_line_id, 8);
        assert_eq!(lock.line_count.load(Ordering::Acquire), 12);
        drop(lock);

        // Case 1: Start ID is before the first available line. Should start from the beginning.
        let lines_from_5 = collect_lines_from(&reader, LineId(5));
        assert_eq!(lines_from_5.len(), 12);
        assert_eq!(lines_from_5[0].0, LineId(8)); // Starts from the first available line
        assert_eq!(lines_from_5[11].0, LineId(19));

        // Case 2: Start ID is in the middle of the available lines.
        let lines_from_15 = collect_lines_from(&reader, LineId(15));
        assert_eq!(lines_from_15.len(), 5); // Lines 15, 16, 17, 18, 19
        assert_eq!(lines_from_15[0].0, LineId(15));
        assert_eq!(lines_from_15[4].0, LineId(19));

        // Case 3: Start ID is after the last available line.
        let lines_from_25 = collect_lines_from(&reader, LineId(25));
        assert_eq!(lines_from_25.len(), 0);

        // Case 4: Start ID is exactly the first line.
        let lines_from_8 = collect_lines_from(&reader, LineId(8));
        assert_eq!(lines_from_8.len(), 12);
        assert_eq!(lines_from_8[0].0, LineId(8));
    }

    #[test]
    #[should_panic(expected = "Line is too long to fit in the freed buffer space")]
    fn test_line_too_long_panics() {
        let mut writer = LineTableWriter::new();

        // Fill both MAX_LINES and MAX_CAPACITY.
        // 16 lines * 16 bytes/line = 256 bytes.
        for i in 0..MAX_LINES {
            writer.push_line(&"A".repeat(16), 16, JobId(i as u32), Style::DEFAULT);
        }

        // Now, try to push a line that is too large to fit even after rotation.
        // Rotation will free (16+1)/2 = 8 lines, freeing 8 * 16 = 128 bytes.
        // A 150-byte line will not fit in the 128 bytes of freed space.
        writer.push_line(&"B".repeat(150), 150, JobId(99), Style::DEFAULT);
    }
}
