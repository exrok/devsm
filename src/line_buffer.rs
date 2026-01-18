use std::{
    ops::ControlFlow,
    ptr::NonNull,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::JobId;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LineId(usize);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Line {
    job_id: JobId,
    start: u32,
    len: u32,
    width: u32,
}

const MAX_LINES: usize = 4 * 1024;
const MAX_CAPACITY: usize = 64 * 1024 * 1024;

unsafe impl Send for LineBuffer {}
unsafe impl Sync for LineBuffer {}

//todo fix line Index.
pub struct LineBuffer {
    buffer: NonNull<u8>,
    line_entires: NonNull<Line>,
    line_count: AtomicUsize,
    index_start: usize,
}
impl Drop for LineBuffer {
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

impl LineBuffer {
    pub fn slices(&self) -> (&[Line], &[Line]) {
        let len = self.line_count.load(Ordering::Acquire);
        let start = self.index_start;
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
    pub fn for_each(&self, mut func: impl FnMut(LineId, JobId, &str, u32) -> ControlFlow<(), ()>) {
        let (a, b) = self.slices();
        let mut offset = self.index_start;
        for array in [a, b] {
            for (i, entry) in array.iter().enumerate() {
                let data = unsafe {
                    std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                        self.buffer.add(entry.start as usize).as_ptr(),
                        entry.len as usize,
                    ))
                };
                match func(LineId(offset + i), entry.job_id, data, entry.width) {
                    ControlFlow::Continue(_) => continue,
                    ControlFlow::Break(_) => return,
                }
            }
            offset += array.len();
        }
    }
    fn free_lines(&mut self, amount: usize) -> WrappingBufferRange {
        let curr = *self.line_count.get_mut();
        let amount = curr.min(amount);
        if amount == curr {
            self.index_start = 0;
            self.line_count.store(0, Ordering::Release);
            return WrappingBufferRange {
                start: 0,
                len: MAX_CAPACITY as u32,
            };
        }
        if amount == 0 {
            if curr == 0 {
                return WrappingBufferRange {
                    start: 0,
                    len: MAX_CAPACITY as u32,
                };
            }
            let last_line_idx = (self.index_start + curr - 1) % MAX_LINES;
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
                let value = self.line_entires.add(self.index_start).read();
                value.start
            };
            return WrappingBufferRange {
                start: end_of_used_buffer,
                len: (start_of_used_buffer + (MAX_CAPACITY as u32) - end_of_used_buffer)
                    % (MAX_CAPACITY as u32),
            };
        }

        let last_line_index_before_free = (self.index_start + curr - 1) % MAX_LINES;
        let end_of_used_buffer = unsafe {
            let value = self.line_entires.add(last_line_index_before_free).read();
            value.start + value.len
        };

        self.index_start = (self.index_start + amount) % MAX_LINES;
        self.line_count.store(curr - amount, Ordering::Release);

        let start_of_used_buffer = unsafe {
            let value = self.line_entires.add(self.index_start).read();
            value.start
        };

        return WrappingBufferRange {
            start: end_of_used_buffer,
            len: (start_of_used_buffer + (MAX_CAPACITY as u32) - end_of_used_buffer)
                % (MAX_CAPACITY as u32),
        };
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
            if self.len as usize - wasted > len {
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

// MAX Thresholds before we perform rotation

pub struct LineBufferWriter {
    buffer: Arc<RwLock<LineBuffer>>,
    range: WrappingBufferRange,
    remaining: usize,
}

fn write_line_unchecked(buf: &LineBuffer, start: u32, line: &str, width: u32, job_id: JobId) {
    unsafe {
        let next = (buf.line_count.load(Ordering::Acquire) + buf.index_start) % MAX_LINES;
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
        });
        buf.line_count.fetch_add(1, Ordering::Release);
    }
}

impl LineBufferWriter {
    // allocates empty line buffer within linewriter
    pub fn new() -> LineBufferWriter {
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
        let line_buffer = LineBuffer {
            buffer,
            line_entires: line_entries,
            line_count: AtomicUsize::new(0),
            index_start: 0,
        };
        LineBufferWriter {
            buffer: Arc::new(RwLock::new(line_buffer)),
            remaining: MAX_LINES,
            range: WrappingBufferRange {
                start: 0,
                len: MAX_CAPACITY as u32,
            },
        }
    }
    pub fn reader(&self) -> Arc<RwLock<LineBuffer>> {
        self.buffer.clone()
    }
    pub fn push_line(&mut self, line: &str, width: u32, job_id: JobId) {
        let offset = if let Some(offset) = self.range.munch(line.len())
            && self.remaining > 0
        {
            offset
        } else {
            let mut lock = self.buffer.write().unwrap();
            self.range = lock.free_lines(MAX_LINES / 2);
            self.remaining = MAX_LINES - *lock.line_count.get_mut();
            if let Some(offset) = self.range.munch(line.len())
                && self.remaining > 0
            {
                offset
            } else {
                panic!();
            }
        };

        let buf = self.buffer.read().unwrap();
        self.remaining -= 1;
        write_line_unchecked(&buf, offset, line, width, job_id);
        return;
    }
}
