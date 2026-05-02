//! Build and install seccomp-BPF filters that escalate selected syscalls to
//! the tracer via `SECCOMP_RET_TRACE`. The point is to skip the kernel's
//! per-syscall ENTRY stop entirely on the (vast majority of) syscalls we
//! don't classify, so the tracer only wakes up for the ~25 fs syscalls in
//! [`crate::auto_deps::tracer::syscalls::classify`].
//!
//! Only built for `target_arch = "x86_64"` for now — the BPF program is
//! written against the x86_64 syscall ABI, and the arch-check in the filter
//! refuses anything else (a 32-bit compat exec would otherwise bypass the
//! filter entirely).
//!
//! The filter is generated once per [`install_seccomp_filter`] call (cheap —
//! ~30 instructions, no syscalls) and captured by move into the pre-exec
//! closure so the closure body never allocates after `fork`.
#![cfg(target_arch = "x86_64")]

use std::io;
use std::mem::offset_of;
use syscalls::Sysno;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `SECCOMP_RET_TRACE` lets the tracer observe the syscall via
/// `PTRACE_EVENT_SECCOMP`. The low 16 bits are user data — we don't need
/// any, so leave them zero.
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Build a sock_filter program that returns `SECCOMP_RET_TRACE` for any
/// syscall in `syscalls` and `SECCOMP_RET_ALLOW` for everything else.
///
/// Layout:
///   0:   ld   [arch]
///   1:   jeq  AUDIT_ARCH_X86_64, jt=1, jf=0      (skip the kill on match)
///   2:   ret  SECCOMP_RET_KILL_PROCESS
///   3:   ld   [nr]
///   4..N-2: jeq sysno, jt=<offset to RET TRACE>, jf=0  (one per syscall)
///   N-1: ret  SECCOMP_RET_ALLOW
///   N:   ret  SECCOMP_RET_TRACE
pub fn build_filter(syscalls: &[Sysno]) -> Vec<libc::sock_filter> {
    let mut prog = Vec::with_capacity(5 + syscalls.len());

    let arch_off = offset_of!(libc::seccomp_data, arch) as u32;
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, arch_off));
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    let nr_off = offset_of!(libc::seccomp_data, nr) as u32;
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, nr_off));

    let trace_idx = 4 + syscalls.len() + 1;
    for (i, &nr) in syscalls.iter().enumerate() {
        let cur = 4 + i;
        let jt = trace_idx - cur - 1;
        debug_assert!(jt <= u8::MAX as usize, "BPF jt overflow — too many syscalls in filter");
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr.id() as u32, jt as u8, 0));
    }
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_TRACE));

    prog
}

/// Install `prog` as a seccomp filter on the current task. Calls
/// `prctl(PR_SET_NO_NEW_PRIVS)` first (required for an unprivileged
/// `PR_SET_SECCOMP`).
///
/// Safe to call from inside `Command::pre_exec`: only does syscalls, no
/// allocation. `prog` must remain alive for the duration of the call.
pub fn install(prog: &[libc::sock_filter]) -> io::Result<()> {
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let r = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &fprog as *const libc::sock_fprog as usize,
            0,
            0,
        )
    };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
