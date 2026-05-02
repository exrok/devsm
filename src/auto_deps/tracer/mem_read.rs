use std::io;
use std::os::raw::{c_int, c_void};

#[repr(C)]
struct IoVec {
    iov_base: *mut c_void,
    iov_len: usize,
}

unsafe extern "C" {
    fn process_vm_readv(
        pid: c_int,
        local_iov: *const IoVec,
        liovcnt: usize,
        remote_iov: *const IoVec,
        riovcnt: usize,
        flags: usize,
    ) -> isize;
}

const PATH_MAX: usize = 4096;

/// Read a NUL-terminated path string from a tracee's address space at `addr`.
///
/// Returns the bytes up to (but not including) the first NUL, or an error if
/// the read fails. Reads in chunks because `process_vm_readv` will fail with
/// EFAULT if any byte of the requested range is unmapped — we don't know
/// where the page boundary is, so start with a small read and grow.
pub fn read_cstr(pid: i32, addr: u64) -> io::Result<Vec<u8>> {
    if addr == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "null path pointer"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(256);
    let mut offset: usize = 0;
    let mut chunk: usize = 256;
    loop {
        if offset + chunk > PATH_MAX {
            chunk = PATH_MAX - offset;
            if chunk == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "path exceeds PATH_MAX"));
            }
        }
        let mut buf = vec![0u8; chunk];
        let local = IoVec { iov_base: buf.as_mut_ptr() as *mut c_void, iov_len: chunk };
        let remote = IoVec { iov_base: (addr as usize + offset) as *mut c_void, iov_len: chunk };
        let n = unsafe { process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            // Page boundary: shrink and retry. EFAULT can mean "the *next* page
            // is unmapped" even if the first byte is mapped.
            if chunk > 1 && err.raw_os_error() == Some(libc::EFAULT) {
                chunk /= 2;
                continue;
            }
            return Err(err);
        }
        let read = n as usize;
        if let Some(nul_idx) = buf[..read].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..nul_idx]);
            return Ok(out);
        }
        out.extend_from_slice(&buf[..read]);
        if read < chunk {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no NUL terminator"));
        }
        offset += read;
        if offset >= PATH_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "path exceeds PATH_MAX"));
        }
    }
}

