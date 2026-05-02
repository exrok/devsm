use crate::auto_deps::event::PathEventKind;
use syscalls::Sysno;

/// Position of a path argument inside a syscall's six-register frame.
#[derive(Debug, Clone, Copy)]
pub struct PathArg {
    /// Index of a `dirfd`-style argument, if this syscall is `*at`-flavored.
    /// `None` means the path is interpreted relative to cwd.
    pub dirfd: Option<u8>,
    /// Index of the path-pointer argument.
    pub path: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum Effect {
    Read,
    Stat,
    ReadLink,
    Exec,
    Unlink,
    Mkdir,
    /// open-family: read/write determined from the flags arg.
    Open { flags_arg: u8 },
    /// getdents-family: dirfd is in `arg.path` slot (it's an fd, not a path).
    ListDir { fd_arg: u8 },
    /// chdir / fchdir: update tracee cwd, no event emitted.
    Chdir,
    Fchdir { fd_arg: u8 },
    /// rename-family: a single event is emitted on the source (Unlink) plus
    /// a Write on the destination.
    Rename { dst_dirfd: Option<u8>, dst_path: u8 },
}

#[derive(Debug, Clone, Copy)]
pub struct SyscallShape {
    pub effect: Effect,
    pub path: Option<PathArg>,
}

/// Mapping `Sysno` -> the syscall's effect + path-arg layout.
///
/// Returns `None` for syscalls we don't track. Linux-only; the `Sysno` enum is
/// already arch-specific via the `syscalls` crate's conditional re-export.
pub fn classify(nr: Sysno) -> Option<SyscallShape> {
    let s = |effect, path| Some(SyscallShape { effect, path });
    match nr {
        Sysno::openat => s(Effect::Open { flags_arg: 2 }, Some(PathArg { dirfd: Some(0), path: 1 })),
        #[cfg(target_arch = "x86_64")]
        Sysno::open => s(Effect::Open { flags_arg: 1 }, Some(PathArg { dirfd: None, path: 0 })),
        #[cfg(target_arch = "x86_64")]
        Sysno::creat => s(Effect::Open { flags_arg: 1 }, Some(PathArg { dirfd: None, path: 0 })),

        #[cfg(target_arch = "x86_64")]
        Sysno::stat => s(Effect::Stat, Some(PathArg { dirfd: None, path: 0 })),
        #[cfg(target_arch = "x86_64")]
        Sysno::lstat => s(Effect::Stat, Some(PathArg { dirfd: None, path: 0 })),
        Sysno::newfstatat => s(Effect::Stat, Some(PathArg { dirfd: Some(0), path: 1 })),
        Sysno::statx => s(Effect::Stat, Some(PathArg { dirfd: Some(0), path: 1 })),
        #[cfg(target_arch = "x86_64")]
        Sysno::access => s(Effect::Stat, Some(PathArg { dirfd: None, path: 0 })),
        Sysno::faccessat => s(Effect::Stat, Some(PathArg { dirfd: Some(0), path: 1 })),
        Sysno::faccessat2 => s(Effect::Stat, Some(PathArg { dirfd: Some(0), path: 1 })),

        #[cfg(target_arch = "x86_64")]
        Sysno::readlink => s(Effect::ReadLink, Some(PathArg { dirfd: None, path: 0 })),
        Sysno::readlinkat => s(Effect::ReadLink, Some(PathArg { dirfd: Some(0), path: 1 })),

        Sysno::execve => s(Effect::Exec, Some(PathArg { dirfd: None, path: 0 })),
        Sysno::execveat => s(Effect::Exec, Some(PathArg { dirfd: Some(0), path: 1 })),

        #[cfg(target_arch = "x86_64")]
        Sysno::unlink => s(Effect::Unlink, Some(PathArg { dirfd: None, path: 0 })),
        Sysno::unlinkat => s(Effect::Unlink, Some(PathArg { dirfd: Some(0), path: 1 })),

        #[cfg(target_arch = "x86_64")]
        Sysno::mkdir => s(Effect::Mkdir, Some(PathArg { dirfd: None, path: 0 })),
        Sysno::mkdirat => s(Effect::Mkdir, Some(PathArg { dirfd: Some(0), path: 1 })),

        Sysno::getdents64 => s(Effect::ListDir { fd_arg: 0 }, None),
        #[cfg(target_arch = "x86_64")]
        Sysno::getdents => s(Effect::ListDir { fd_arg: 0 }, None),

        Sysno::chdir => s(Effect::Chdir, Some(PathArg { dirfd: None, path: 0 })),
        Sysno::fchdir => s(Effect::Fchdir { fd_arg: 0 }, None),

        #[cfg(target_arch = "x86_64")]
        Sysno::rename => s(
            Effect::Rename { dst_dirfd: None, dst_path: 1 },
            Some(PathArg { dirfd: None, path: 0 }),
        ),
        Sysno::renameat => s(
            Effect::Rename { dst_dirfd: Some(2), dst_path: 3 },
            Some(PathArg { dirfd: Some(0), path: 1 }),
        ),
        Sysno::renameat2 => s(
            Effect::Rename { dst_dirfd: Some(2), dst_path: 3 },
            Some(PathArg { dirfd: Some(0), path: 1 }),
        ),

        _ => None,
    }
}

pub fn effect_to_event_kind(effect: Effect, opened_write: bool) -> Option<PathEventKind> {
    Some(match effect {
        Effect::Read => PathEventKind::Read,
        Effect::Stat => PathEventKind::Stat,
        Effect::ReadLink => PathEventKind::ReadLink,
        Effect::Exec => PathEventKind::Exec,
        Effect::Unlink => PathEventKind::Unlink,
        Effect::Mkdir => PathEventKind::Mkdir,
        Effect::Open { .. } => {
            if opened_write { PathEventKind::Write } else { PathEventKind::Read }
        }
        Effect::ListDir { .. } => PathEventKind::ListDir,
        Effect::Chdir | Effect::Fchdir { .. } | Effect::Rename { .. } => return None,
    })
}

/// Extract O_WRONLY / O_RDWR / O_CREAT|O_TRUNC|O_APPEND from the flags arg of
/// an open-family syscall. Returns true when the open is a write-side open.
pub fn open_flags_is_write(flags: u64) -> bool {
    let f = flags as i32;
    let access = f & libc::O_ACCMODE;
    if access == libc::O_WRONLY || access == libc::O_RDWR {
        return true;
    }
    f & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0
}

pub fn open_flags_is_cloexec(flags: u64) -> bool {
    (flags as i32) & libc::O_CLOEXEC != 0
}
