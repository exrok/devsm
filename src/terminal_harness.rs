//! Client-side owner for `managed = "terminal"` children.
//!
//! The daemon owns scheduler state; this process owns only the real terminal
//! and child process group. No stdio descriptor is ever sent across the socket.

use crate::daemon;
use crate::rpc::{ClientProtocol, DecodeResult, RpcMessageKind};
use anyhow::{Context, bail};
use jsony_value::ValueMap;
use std::ffi::OsStr;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static IDLE_INTERRUPT: AtomicBool = AtomicBool::new(false);
static TERMINATION_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn idle_interrupt_handler(_: i32) {
    IDLE_INTERRUPT.store(true, Ordering::Relaxed);
}

extern "C" fn termination_handler(_: i32) {
    TERMINATION_REQUESTED.store(true, Ordering::Relaxed);
}

struct TerminalGuard {
    fd: i32,
    wrapper_pgrp: libc::pid_t,
    original: libc::termios,
    child_pgrp: Option<libc::pid_t>,
}

impl TerminalGuard {
    fn acquire() -> anyhow::Result<Self> {
        let fd = libc::STDIN_FILENO;
        if unsafe { libc::isatty(fd) } != 1 {
            bail!("terminal tasks require stdin to be a terminal");
        }
        let wrapper_pgrp = unsafe { libc::getpgrp() };
        let foreground = unsafe { libc::tcgetpgrp(fd) };
        if foreground < 0 {
            return Err(std::io::Error::last_os_error()).context("stdin is not a usable controlling terminal");
        }
        if foreground != wrapper_pgrp {
            bail!("terminal wrapper is not the foreground process group");
        }
        let mut original = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(std::io::Error::last_os_error()).context("failed to snapshot terminal settings");
        }
        Ok(Self { fd, wrapper_pgrp, original, child_pgrp: None })
    }

    fn set_foreground(&self, pgrp: libc::pid_t) -> std::io::Result<()> {
        // Blocking these job-control signals makes tcsetpgrp safe even during
        // the small handoff window in which the caller is not foreground.
        let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut old = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTTOU);
            libc::sigaddset(&mut set, libc::SIGTTIN);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        }
        let result = unsafe { libc::tcsetpgrp(self.fd, pgrp) };
        let error = (result != 0).then(std::io::Error::last_os_error);
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        }
        error.map_or(Ok(()), Err)
    }

    fn give_to_child(&mut self, pid: libc::pid_t) -> anyhow::Result<()> {
        self.set_foreground(pid).context("failed to give terminal to child")?;
        self.child_pgrp = Some(pid);
        Ok(())
    }

    fn is_wrapper_foreground(&self) -> bool {
        unsafe { libc::tcgetpgrp(self.fd) == self.wrapper_pgrp }
    }

    fn force_reclaim(&mut self) {
        let _ = self.set_foreground(self.wrapper_pgrp);
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSADRAIN, &self.original);
        }
        self.child_pgrp = None;
    }

    fn reclaim(&mut self) {
        let foreground = unsafe { libc::tcgetpgrp(self.fd) };
        if foreground == self.wrapper_pgrp || self.child_pgrp == Some(foreground) {
            self.force_reclaim();
        } else {
            // Another shell job owns the terminal. This happens when the
            // daemon resumes a suspended wrapper solely to stop its child; do
            // not steal foreground ownership back from that job.
            self.child_pgrp = None;
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.child_pgrp {
            kill_and_reap(pid);
        }
        self.reclaim();
    }
}

enum Incoming {
    Attached,
    Waiting(Vec<String>),
    Start(crate::rpc::TerminalStartEvent),
    Stop(crate::rpc::TerminalStopEvent),
    Error(String),
    Detached,
}

fn drain_messages(
    socket: &mut UnixStream,
    protocol: &mut ClientProtocol,
    buffer: &mut Vec<u8>,
) -> anyhow::Result<Vec<Incoming>> {
    loop {
        let mut chunk = [0u8; 8192];
        match socket.read(&mut chunk) {
            Ok(0) if buffer.is_empty() => bail!("daemon disconnected"),
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("terminal harness socket read failed"),
        }
    }

    let mut incoming = Vec::new();
    loop {
        match protocol.decode(buffer) {
            DecodeResult::Message { kind, payload, .. } => match kind {
                RpcMessageKind::TerminalAttached => incoming.push(Incoming::Attached),
                RpcMessageKind::TerminalWaiting => {
                    let event: crate::rpc::TerminalWaitingEvent = jsony::from_binary(payload)
                        .map_err(|_| anyhow::anyhow!("invalid TerminalWaiting payload"))?;
                    incoming.push(Incoming::Waiting(event.tasks));
                }
                RpcMessageKind::TerminalStart => incoming.push(Incoming::Start(
                    jsony::from_binary(payload).map_err(|_| anyhow::anyhow!("invalid TerminalStart payload"))?,
                )),
                RpcMessageKind::TerminalStop => incoming.push(Incoming::Stop(
                    jsony::from_binary(payload).map_err(|_| anyhow::anyhow!("invalid TerminalStop payload"))?,
                )),
                RpcMessageKind::TerminalError => {
                    let event: crate::rpc::TerminalErrorEvent =
                        jsony::from_binary(payload).map_err(|_| anyhow::anyhow!("invalid TerminalError payload"))?;
                    incoming.push(Incoming::Error(event.message.into()));
                }
                RpcMessageKind::TerminalDetached | RpcMessageKind::Disconnect => incoming.push(Incoming::Detached),
                RpcMessageKind::JobStatus | RpcMessageKind::JobExited => {}
                _ => bail!("unexpected terminal harness message: {kind:?}"),
            },
            DecodeResult::MissingData { .. } | DecodeResult::Empty => break,
            DecodeResult::Error(error) => bail!("terminal harness protocol error: {error:?}"),
        }
    }
    protocol.compact(buffer, 4096);
    Ok(incoming)
}

fn send<T: jsony::ToBinary>(socket: &mut UnixStream, kind: RpcMessageKind, event: &T) -> anyhow::Result<()> {
    let mut encoder = crate::rpc::Encoder::new();
    encoder.encode_push(kind, event);
    socket.write_all(encoder.output()).context("failed to acknowledge terminal lifecycle")
}

fn send_detach(socket: &mut UnixStream) -> anyhow::Result<()> {
    let mut encoder = crate::rpc::Encoder::new();
    encoder.encode_empty(RpcMessageKind::TerminalDetach, 0);
    socket.write_all(encoder.output()).context("failed to detach terminal wrapper")
}

fn foreground_child_before_exec(fd: i32) -> std::io::Result<()> {
    // Command::spawn does not return until the exec error pipe closes, so a
    // parent-side tcsetpgrp leaves a window in which an interactive child can
    // read as a background process group and be stopped by SIGTTIN. Perform
    // both operations in the child before exec instead.
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut old = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTTOU);
        libc::sigaddset(&mut set, libc::SIGTTIN);
    }
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = unsafe { libc::tcsetpgrp(fd, libc::getpid()) };
    let error = (result != 0).then(std::io::Error::last_os_error);
    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
    }
    error.map_or(Ok(()), Err)
}

fn command_from_start(start: &crate::rpc::TerminalStartEvent) -> anyhow::Result<Command> {
    let mut command = match &start.command {
        crate::rpc::TerminalCommand::Cmd(args) => {
            let Some((program, args)) = args.split_first() else { bail!("resolved terminal command is empty") };
            let mut command = Command::new(&**program);
            command.args(args.iter().map(|arg| &**arg));
            command
        }
        crate::rpc::TerminalCommand::Sh { script, args } => {
            let mut command = Command::new("/bin/sh");
            command.arg("-c").arg(&**script);
            if !args.is_empty() {
                command.arg("devsm").args(args.iter().map(|arg| &**arg));
            }
            command
        }
    };
    command
        .current_dir(PathBuf::from(OsStr::from_bytes(&start.pwd)))
        .envs(start.env.iter().map(|(key, value)| (&**key, &**value)))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(|| foreground_child_before_exec(libc::STDIN_FILENO));
    }
    Ok(command)
}

enum ChildWait {
    Running,
    Stopped,
    Exited(i32),
}

fn wait_status(pid: libc::pid_t) -> std::io::Result<ChildWait> {
    let mut status = 0;
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if result == 0 || libc::WIFCONTINUED(status) {
        return Ok(ChildWait::Running);
    }
    if libc::WIFEXITED(status) {
        return Ok(ChildWait::Exited(libc::WEXITSTATUS(status)));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(ChildWait::Exited(128 + libc::WTERMSIG(status)));
    }
    if libc::WIFSTOPPED(status) {
        return Ok(ChildWait::Stopped);
    }
    Ok(ChildWait::Running)
}

fn kill_and_reap(pid: libc::pid_t) {
    unsafe { libc::kill(-pid, libc::SIGTERM) };
    let deadline = Instant::now() + crate::event_loop::PROCESS_KILL_ESCALATION;
    loop {
        if matches!(wait_status(pid), Ok(ChildWait::Exited(_)) | Err(_)) {
            return;
        }
        if Instant::now() >= deadline {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn apply_stop_messages(
    messages: Vec<Incoming>,
    run_token: crate::workspace::RunToken,
    pid: libc::pid_t,
    replacement_pending: &mut bool,
    stop_sent_at: &mut Option<Instant>,
) -> bool {
    let mut matched = false;
    for message in messages {
        if let Incoming::Stop(stop) = message
            && stop.run_token == run_token
            && stop_sent_at.is_none()
        {
            *replacement_pending = stop.replacement_pending;
            unsafe { libc::kill(-pid, libc::SIGTERM) };
            *stop_sent_at = Some(Instant::now());
            matched = true;
        }
    }
    matched
}

fn run_child(
    socket: &mut UnixStream,
    protocol: &mut ClientProtocol,
    buffer: &mut Vec<u8>,
    terminal: &mut TerminalGuard,
    start: crate::rpc::TerminalStartEvent,
    initial_stop: Option<bool>,
) -> anyhow::Result<(i32, bool)> {
    let mut command = command_from_start(&start)?;
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            // The child foregrounds its process group in pre_exec. If exec
            // itself failed, that group is already gone and the wrapper must
            // explicitly take the terminal back.
            terminal.force_reclaim();
            send(
                socket,
                RpcMessageKind::TerminalSpawnFailed,
                &crate::rpc::TerminalSpawnFailedEvent { run_token: start.run_token, message: error.to_string().into() },
            )?;
            return Ok((127, false));
        }
    };
    let pid = child.id() as libc::pid_t;
    if let Err(error) = terminal.give_to_child(pid) {
        kill_and_reap(pid);
        terminal.reclaim();
        send(
            socket,
            RpcMessageKind::TerminalSpawnFailed,
            &crate::rpc::TerminalSpawnFailedEvent {
                run_token: start.run_token,
                message: format!("failed to attach child to terminal: {error:#}").into(),
            },
        )?;
        return Ok((127, false));
    }
    send(
        socket,
        RpcMessageKind::TerminalStarted,
        &crate::rpc::TerminalRunEvent {
            run_token: start.run_token,
            process_group: pid,
        },
    )?;

    let mut replacement_pending = initial_stop.unwrap_or(false);
    let mut stop_sent_at = initial_stop.map(|_| {
        unsafe { libc::kill(-pid, libc::SIGTERM) };
        Instant::now()
    });
    loop {
        if TERMINATION_REQUESTED.load(Ordering::Relaxed) {
            bail!("terminal wrapper was terminated");
        }
        match wait_status(pid)? {
            ChildWait::Exited(code) => {
                terminal.reclaim();
                send(
                    socket,
                    RpcMessageKind::TerminalExited,
                    &crate::rpc::TerminalExitedEvent { run_token: start.run_token, exit_code: code },
                )?;
                return Ok((code, replacement_pending));
            }
            ChildWait::Stopped => {
                // Mirror a shell's job-control sequence: reclaim the terminal,
                // suspend the wrapper so its parent shell can foreground it
                // again, then return ownership and continue the child group.
                terminal.reclaim();
                // Keep ownership recorded while neither group is foreground so
                // unwinding still terminates the stopped child.
                terminal.child_pgrp = Some(pid);

                let messages = drain_messages(socket, protocol, buffer)
                    .map_err(|error| error.context("daemon disappeared while terminal child was stopped"))?;
                apply_stop_messages(
                    messages,
                    start.run_token,
                    pid,
                    &mut replacement_pending,
                    &mut stop_sent_at,
                );

                if stop_sent_at.is_some() {
                    // SIGTERM remains pending for a job-control-stopped group;
                    // continue it without granting terminal ownership so the
                    // signal can be acted on while the caller's shell stays in
                    // the foreground.
                    unsafe { libc::kill(-pid, libc::SIGCONT) };
                } else {
                    loop {
                        unsafe { libc::raise(libc::SIGTSTP) };
                        if TERMINATION_REQUESTED.load(Ordering::Relaxed) {
                            bail!("terminal wrapper was terminated");
                        }

                        let messages = drain_messages(socket, protocol, buffer)
                            .map_err(|error| error.context("daemon disappeared while terminal child was stopped"))?;
                        apply_stop_messages(
                            messages,
                            start.run_token,
                            pid,
                            &mut replacement_pending,
                            &mut stop_sent_at,
                        );
                        if stop_sent_at.is_some() {
                            unsafe { libc::kill(-pid, libc::SIGCONT) };
                            break;
                        }
                        if terminal.is_wrapper_foreground() {
                            terminal.give_to_child(pid)?;
                            unsafe { libc::kill(-pid, libc::SIGCONT) };
                            break;
                        }
                        // A background SIGCONT without a daemon control frame
                        // must not steal the terminal from another shell job.
                    }
                }
            }
            ChildWait::Running => {}
        }

        match drain_messages(socket, protocol, buffer) {
            Ok(messages) => {
                apply_stop_messages(
                    messages,
                    start.run_token,
                    pid,
                    &mut replacement_pending,
                    &mut stop_sent_at,
                );
            }
            Err(error) => {
                kill_and_reap(pid);
                terminal.reclaim();
                return Err(error.context("daemon disappeared while terminal child was running"));
            }
        }
        if stop_sent_at.is_some_and(|sent| sent.elapsed() >= crate::event_loop::PROCESS_KILL_ESCALATION) {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            stop_sent_at = None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub fn terminal_run_client(
    config: &Path,
    cwd: &Path,
    name: &str,
    params: ValueMap<'_>,
    sticky: bool,
) -> anyhow::Result<i32> {
    let mut terminal = TerminalGuard::acquire()?;
    unsafe {
        let mut action = std::mem::zeroed::<libc::sigaction>();
        action.sa_sigaction = idle_interrupt_handler as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error()).context("failed to install terminal interrupt handler");
        }
        action.sa_sigaction = termination_handler as *const () as usize;
        for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error()).context("failed to install terminal termination handler");
            }
        }
    }

    let mut socket = super::connect_or_spawn_daemon()?;
    socket.write_all(&jsony::to_binary(&daemon::RequestMessage {
        cwd,
        request: daemon::Request::AttachTerminal {
            config,
            name: name.into(),
            params,
            sticky,
            wrapper_process_group: terminal.wrapper_pgrp,
        },
    }))?;
    socket.set_nonblocking(true)?;

    let mut protocol = ClientProtocol::new();
    let mut buffer = Vec::new();
    let mut last_exit = 0;
    loop {
        if TERMINATION_REQUESTED.load(Ordering::Relaxed) {
            bail!("terminal wrapper was terminated");
        }
        match drain_messages(&mut socket, &mut protocol, &mut buffer) {
            Ok(messages) => {
                let mut pending_stops = hashbrown::HashMap::new();
                for message in &messages {
                    if let Incoming::Stop(stop) = message {
                        pending_stops.insert(stop.run_token, stop.replacement_pending);
                    }
                }
                for message in messages {
                    match message {
                        Incoming::Start(start) => {
                            if IDLE_INTERRUPT.swap(false, Ordering::Relaxed) {
                                send_detach(&mut socket)?;
                                return Ok(last_exit);
                            }
                            let initial_stop = pending_stops.remove(&start.run_token);
                            let (code, replacement_pending) =
                                run_child(&mut socket, &mut protocol, &mut buffer, &mut terminal, start, initial_stop)?;
                            last_exit = code;
                            if sticky {
                                eprintln!(
                                    "Terminal task is idle. Run `devsm start {name}` to start it again; press Ctrl-C to close this wrapper."
                                );
                            } else if !replacement_pending {
                                // The daemon closes us only after consuming the
                                // final exit acknowledgement.
                            }
                        }
                        Incoming::Error(message) => bail!("{message}"),
                        Incoming::Waiting(tasks) => {
                            if tasks.is_empty() {
                                eprintln!("Waiting for scheduler requirements...");
                            } else {
                                eprintln!("Waiting for: {}", tasks.join(", "));
                            }
                        }
                        Incoming::Detached => return Ok(last_exit),
                        Incoming::Attached | Incoming::Stop(_) => {}
                    }
                }
            }
            Err(error) => return Err(error),
        }
        if IDLE_INTERRUPT.swap(false, Ordering::Relaxed) {
            send_detach(&mut socket)?;
            return Ok(last_exit);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
