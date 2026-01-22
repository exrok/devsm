use std::{
    io::{ErrorKind, Read, Write},
    os::unix::{net::UnixStream, process::CommandExt},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use anyhow::bail;
use sendfd::SendWithFd;

use crate::daemon::{WorkspaceCommand, socket_path};
use crate::rpc::{
    ClientProtocol, DecodeResult, JobExitedEvent, JobStatusEvent, JobStatusKind, ResizeNotification, RpcMessageKind,
};

mod cli;
mod collection;
mod config;
pub mod daemon;
mod diagnostic;
mod function;
mod keybinds;
mod line_width;
mod log_fowarder_ui;
mod log_storage;
mod process_manager;
mod rpc;
mod scroll_view;
mod searcher;
mod self_log;
mod test_summary_ui;
mod tui;
mod user_config;
mod validate;
mod welcome_message;
mod workspace;

fn main() {
    let mut args = std::env::args();
    args.next();
    let args = args.collect::<Vec<_>>();
    let (_config, command) = match cli::parse(&args) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("error: {}", err);
            std::process::exit(1);
        }
    };
    match command {
        cli::Command::Help => {
            print_help();
        }
        cli::Command::Tui => {
            let _log_guard = self_log::init_client_logging();
            if let Err(err) = client() {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Server => {
            let _log_guard = if std::env::var("DEVSM_LOG_STDOUT").as_deref() == Ok("1") {
                None
            } else {
                Some(self_log::init_daemon_logging())
            };
            if let Err(err) = daemon::worker() {
                kvlog::error!("Daemon terminated with error", ?err);
            }
        }
        cli::Command::RestartSelected => {
            if let Err(err) = restart_selected_command() {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Restart { job, value_map } => {
            if let Err(err) = workspace_command(WorkspaceCommand::Run { name: job.into(), params: value_map }) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Exec { job, value_map } => {
            if let Err(err) = exec_task(job, value_map) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Run { job, value_map } => {
            let _log_guard = self_log::init_client_logging();
            if let Err(err) = run_client(job, value_map) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Test { filters } => {
            let _log_guard = self_log::init_client_logging();
            if let Err(err) = test_client(filters) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Validate { path, skip_path_checks } => {
            let config_path = match path {
                Some(p) => std::path::PathBuf::from(p),
                None => {
                    let cwd = std::env::current_dir().unwrap_or_else(|err| {
                        eprintln!("error: failed to get current directory: {}", err);
                        std::process::exit(1);
                    });
                    match config::find_config_path_from(&cwd) {
                        Some(p) => p,
                        None => {
                            eprintln!("error: cannot find devsm.toml in current or parent directories");
                            std::process::exit(1);
                        }
                    }
                }
            };
            let options = validate::ValidateOptions { skip_path_checks };
            match validate::validate_config(&config_path, &options) {
                Ok(true) => std::process::exit(0),
                Ok(false) => std::process::exit(1),
                Err(err) => {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
            }
        }
        cli::Command::Get { resource } => match resource {
            cli::GetResource::SelfLogs => {
                if let Err(err) = get_self_logs() {
                    eprintln!("error: failed to get logs: {}", err);
                    std::process::exit(1);
                }
            }
            cli::GetResource::WorkspaceConfigPath => {
                let cwd = std::env::current_dir().unwrap_or_else(|err| {
                    eprintln!("error: failed to get current directory: {}", err);
                    std::process::exit(1);
                });
                match config::find_config_path_from(&cwd) {
                    Some(path) => println!("{}", path.display()),
                    None => {
                        eprintln!("error: cannot find devsm.toml in current or parent directories");
                        std::process::exit(1);
                    }
                }
            }
            cli::GetResource::DefaultUserConfig => {
                print!("{}", user_config::default_user_config_toml());
            }
        },
        cli::Command::FunctionCall { name } => {
            if let Err(err) = workspace_command(WorkspaceCommand::CallFunction { name: name.into() }) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
    }
}

fn test_client(filters: Vec<cli::TestFilter>) -> anyhow::Result<()> {
    reset_terminal_to_canonical();

    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    setup_signal_handler(libc::SIGTERM, term_handler)?;
    setup_signal_handler(libc::SIGINT, term_handler)?;

    let mut socket = connect_or_spawn_daemon()?;

    let mut include_tags = Vec::new();
    let mut exclude_tags = Vec::new();
    let mut include_names = Vec::new();
    for filter in &filters {
        match filter {
            cli::TestFilter::IncludeTag(tag) => include_tags.push(*tag),
            cli::TestFilter::ExcludeTag(tag) => exclude_tags.push(*tag),
            cli::TestFilter::IncludeName(name) => include_names.push(*name),
        }
    }

    let test_filters = daemon::TestFilters { include_tags, exclude_tags, include_names };

    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::AttachTests { config: &config, filters: test_filters },
        }),
        &[0, 1],
    )?;

    let mut protocol = ClientProtocol::new();
    let mut read_buf = Vec::with_capacity(1024);

    loop {
        let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);

        if flags & TERMINATION_FLAG != 0 {
            protocol.send_empty(RpcMessageKind::Terminate, 0);
            socket.write_all(protocol.output())?;
            protocol.clear_output();
        }

        read_buf.reserve(1024);
        let spare = read_buf.spare_capacity_mut();
        let read_slice = unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };

        match socket.read(read_slice) {
            Ok(0) => {
                // Socket closed without TerminateAck - server encountered an error
                bail!("Test run failed");
            }
            Ok(n) => {
                unsafe { read_buf.set_len(read_buf.len() + n) };
                loop {
                    match protocol.decode(&read_buf) {
                        DecodeResult::Message { kind, .. } => match kind {
                            RpcMessageKind::TerminateAck | RpcMessageKind::Disconnect => {
                                return Ok(());
                            }
                            _ => {}
                        },
                        DecodeResult::MissingData { .. } => break,
                        DecodeResult::Empty => {
                            read_buf.clear();
                            break;
                        }
                        DecodeResult::Error(_) => return Ok(()),
                    }
                }
                protocol.compact(&mut read_buf, 4096);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => bail!("Socket read failed: {}", e),
        }
    }
}

// Bit 0 is for termination, Bit 1 is for resize
const TERMINATION_FLAG: u64 = 1 << 0;
const RESIZE_FLAG: u64 = 1 << 1;

static SIGNAL_FLAGS: AtomicU64 = AtomicU64::new(0);

extern "C" fn term_handler(_sig: i32) {
    SIGNAL_FLAGS.fetch_or(TERMINATION_FLAG, Ordering::Relaxed);
}

extern "C" fn winch_handler(_sig: i32) {
    SIGNAL_FLAGS.fetch_or(RESIZE_FLAG, Ordering::Relaxed);
}

fn setup_signal_handler(sig: i32, handler: unsafe extern "C" fn(i32)) -> anyhow::Result<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as libc::sighandler_t;
        // Do not set SA_RESTART, so that system calls are interrupted
        sa.sa_flags = 0;
        // Block all signals while the handler is running
        libc::sigfillset(&mut sa.sa_mask);

        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            bail!("Failed to set signal handler for signal {}: {}", sig, std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn default_connect_timeout_ms() -> u64 {
    std::env::var("DEVSM_CONNECT_TIMEOUT_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(1000)
}

fn connect_with_retry(timeout_ms: u64) -> std::io::Result<UnixStream> {
    let socket = socket_path();
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(e) if e.kind() == ErrorKind::ConnectionRefused || e.kind() == ErrorKind::NotFound => {
                if start.elapsed() >= timeout {
                    return Err(std::io::Error::new(ErrorKind::TimedOut, "Connection timed out"));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
}

fn connect_or_spawn_daemon() -> std::io::Result<UnixStream> {
    let socket = socket_path();
    if let Ok(stream) = UnixStream::connect(socket) {
        return Ok(stream);
    }

    if std::env::var("DEVSM_NO_AUTO_SPAWN").as_deref() == Ok("1") {
        return Err(std::io::Error::new(ErrorKind::ConnectionRefused, "Daemon not running and auto-spawn disabled"));
    }

    let current_exe = std::env::current_exe()?;
    let mut command = std::process::Command::new(current_exe);
    command.arg("server");
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    command.spawn()?;
    connect_with_retry(default_connect_timeout_ms())
}

fn workspace_command(command: WorkspaceCommand) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let mut socket = connect_or_spawn_daemon()?;
    socket.write_all(&jsony::to_binary(&daemon::RequestMessage {
        cwd: &cwd,
        request: daemon::Request::WorkspaceCommand { config: &config, command },
    }))?;
    std::io::copy(&mut socket, &mut std::io::stdout())?;
    Ok(())
}

fn restart_selected_command() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let mut socket = connect_or_spawn_daemon()?;
    socket.write_all(&jsony::to_binary(&daemon::RequestMessage {
        cwd: &cwd,
        request: daemon::Request::WorkspaceCommand { config: &config, command: WorkspaceCommand::RestartSelected },
    }))?;

    let mut response = String::new();
    socket.read_to_string(&mut response)?;

    #[derive(jsony::Jsony)]
    struct Response<'a> {
        #[jsony(default)]
        error: Option<&'a str>,
    }

    let parsed: Response = jsony::from_json(&response)?;
    if let Some(err) = parsed.error {
        bail!("{err}");
    }
    Ok(())
}

fn client() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    setup_signal_handler(libc::SIGTERM, term_handler)?;
    setup_signal_handler(libc::SIGINT, term_handler)?;
    setup_signal_handler(libc::SIGWINCH, winch_handler)?;

    let mut socket = connect_or_spawn_daemon()?;

    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::AttachTui { config: &config },
        }),
        &[0, 1],
    )?;

    let mut protocol = ClientProtocol::new();
    let mut read_buf = Vec::with_capacity(1024);

    loop {
        let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);

        if flags & TERMINATION_FLAG != 0 {
            protocol.send_empty(RpcMessageKind::Terminate, 0);
            socket.write_all(protocol.output())?;
            protocol.clear_output();
            return Ok(());
        }

        if flags & RESIZE_FLAG != 0 {
            protocol.send_notify(RpcMessageKind::Resize, &ResizeNotification { width: 0, height: 0 });
            socket.write_all(protocol.output())?;
            protocol.clear_output();
        }

        read_buf.reserve(1024);
        let spare = read_buf.spare_capacity_mut();
        let read_slice = unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };

        match socket.read(read_slice) {
            Ok(0) => break,
            Ok(n) => {
                unsafe { read_buf.set_len(read_buf.len() + n) };
                loop {
                    match protocol.decode(&read_buf) {
                        DecodeResult::Message { kind, .. } => match kind {
                            RpcMessageKind::TerminateAck | RpcMessageKind::Disconnect => {
                                return Ok(());
                            }
                            _ => {}
                        },
                        DecodeResult::MissingData { .. } => break,
                        DecodeResult::Empty => {
                            read_buf.clear();
                            break;
                        }
                        DecodeResult::Error(_) => return Ok(()),
                    }
                }
                protocol.compact(&mut read_buf, 4096);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                kvlog::info!("Interrupted")
            }
            Err(e) => {
                bail!("Socket read failed: {}", e);
            }
        }
    }

    Ok(())
}

fn reset_terminal_to_canonical() {
    unsafe {
        let mut termios: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut termios) == 0 {
            termios.c_lflag |= libc::ICANON | libc::ECHO | libc::ISIG;
            termios.c_iflag |= libc::ICRNL;
            libc::tcsetattr(0, libc::TCSANOW, &termios);
        }
    }
}

fn run_client(job: &str, params: jsony_value::ValueMap) -> anyhow::Result<()> {
    reset_terminal_to_canonical();

    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let workspace_config = config::load_from_env()?;
    let (name, _profile) = job.rsplit_once(':').unwrap_or((job, "default"));
    if name != "~cargo" {
        if let Some((_, expr)) = workspace_config.tasks.iter().find(|(n, _)| *n == name) {
            if expr.managed == Some(false) {
                bail!(
                    "Task '{}' has managed = false and must be run with exec.\n\
                     Use 'devsm exec {}' instead.",
                    name,
                    job
                );
            }
        }
    }

    setup_signal_handler(libc::SIGTERM, term_handler)?;
    setup_signal_handler(libc::SIGINT, term_handler)?;

    let mut socket = connect_or_spawn_daemon()?;

    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::AttachRun { config: &config, name: job.into(), params },
        }),
        &[0, 1],
    )?;

    let mut protocol = ClientProtocol::new();
    let mut read_buf = Vec::with_capacity(1024);
    let mut exit_status: Option<i32> = None;
    let mut terminated_by_user = false;

    loop {
        let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);

        if flags & TERMINATION_FLAG != 0 {
            terminated_by_user = true;
            protocol.send_empty(RpcMessageKind::Terminate, 0);
            socket.write_all(protocol.output())?;
            protocol.clear_output();
        }

        read_buf.reserve(1024);
        let spare = read_buf.spare_capacity_mut();
        let read_slice = unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };

        match socket.read(read_slice) {
            Ok(0) => break,
            Ok(n) => {
                unsafe { read_buf.set_len(read_buf.len() + n) };
                loop {
                    match protocol.decode(&read_buf) {
                        DecodeResult::Message { kind, payload, .. } => match kind {
                            RpcMessageKind::TerminateAck | RpcMessageKind::Disconnect => {
                                if terminated_by_user {
                                    if let Some(status) = exit_status {
                                        eprintln!("Task terminated (exit code {})", status);
                                    } else {
                                        eprintln!("Task terminated");
                                    }
                                } else if let Some(status) = exit_status {
                                    eprintln!("Task exited (code {})", status);
                                }
                                return Ok(());
                            }
                            RpcMessageKind::JobStatus => {
                                if let Ok(event) = jsony::from_binary::<JobStatusEvent>(payload) {
                                    match event.status {
                                        JobStatusKind::Restarting => eprintln!("Terminating previous run..."),
                                        JobStatusKind::Waiting => eprintln!("Waiting for dependencies..."),
                                        JobStatusKind::Running => eprintln!("Task started"),
                                        _ => {}
                                    }
                                }
                            }
                            RpcMessageKind::JobExited => {
                                if let Ok(event) = jsony::from_binary::<JobExitedEvent>(payload) {
                                    exit_status = Some(event.exit_code);
                                }
                            }
                            _ => {}
                        },
                        DecodeResult::MissingData { .. } => break,
                        DecodeResult::Empty => {
                            read_buf.clear();
                            break;
                        }
                        DecodeResult::Error(_) => break,
                    }
                }
                protocol.compact(&mut read_buf, 4096);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => bail!("Socket read failed: {}", e),
        }
    }

    Ok(())
}

/// Executes a task directly, bypassing the daemon and ignoring dependencies.
fn exec_task(job: &str, params: jsony_value::ValueMap) -> anyhow::Result<()> {
    let workspace_config = config::load_from_env()?;
    let (name, profile) = job.rsplit_once(':').unwrap_or((job, "default"));

    let task_expr = if name == "~cargo" {
        &config::CARGO_AUTO_EXPR
    } else {
        let Some((_, expr)) = workspace_config.tasks.iter().find(|(n, _)| *n == name) else {
            bail!("Task not found: {}", name);
        };
        expr
    };

    if task_expr.managed == Some(true) {
        bail!(
            "Task '{}' has managed = true and must be run through the daemon.\n\
             Use 'devsm run {}' instead.",
            name,
            job
        );
    }

    let env = config::Environment { profile, param: params, vars: task_expr.vars };
    let task = task_expr.eval(&env).map_err(|e| anyhow::anyhow!("Failed to evaluate task: {:?}", e))?;
    let tc = task.config();

    let path = workspace_config.base_path.join(tc.pwd);

    let (mut command, sh_script) = match &tc.command {
        config::Command::Sh(script) => (std::process::Command::new("/bin/sh"), Some(*script)),
        config::Command::Cmd(cmd_args) => {
            if cmd_args.is_empty() {
                bail!("Command must not be empty");
            }
            let [cmd, args @ ..] = *cmd_args else {
                bail!("Command must not be empty");
            };
            let mut cmd = std::process::Command::new(cmd);
            cmd.args(args);
            (cmd, None)
        }
    };

    command.current_dir(path).envs(tc.envvar.iter().copied());

    if let Some(script) = sh_script {
        command.arg("-c").arg(script);
    }

    let err = command.exec();
    bail!("exec failed: {}", err);
}

fn get_self_logs() -> anyhow::Result<()> {
    let mut socket = connect_or_spawn_daemon()?;
    socket.write_all(&jsony::to_binary(&daemon::RequestMessage {
        cwd: &std::env::current_dir()?,
        request: daemon::Request::GetSelfLogs,
    }))?;

    let mut logs = Vec::new();
    socket.read_to_end(&mut logs)?;

    let mut fmt_buf = Vec::new();
    let mut parents = kvlog::collector::ParentSpanSuffixCache::new_boxed();
    for log in kvlog::encoding::decode(&logs) {
        if let Ok((ts, level, span, fields)) = log {
            kvlog::collector::format_statement_with_colors(&mut fmt_buf, &mut parents, ts, level, span, fields);
        }
    }
    print!("{}", String::from_utf8_lossy(&fmt_buf));
    Ok(())
}

fn print_help() {
    print!(
        "\
devsm - TUI development service manager

Usage: devsm [OPTIONS] [COMMAND]

Commands:
  (default)         Launch the TUI interface
  run <job>         Run a job and display its output
  exec <job>        Execute a task directly, bypassing the daemon
  restart <job>     Restart a job via the daemon
  test [filters]    Run tests with optional filters
  validate [path]   Validate a config file
  get <resource>    Get information from the daemon
  server            Start the daemon process (internal)

Options:
  -h, --help        Print this help message

Job Arguments:
  Jobs accept parameters as --key=value flags or a JSON object:
    devsm run build --profile=release
    devsm run build '{{\"profile\":\"release\"}}'

Test Filters:
  +tag              Include tests with this tag
  -tag              Exclude tests with this tag
  name              Include tests matching this name

Get Resources:
  self-logs              Retrieve daemon logs
  workspace config-path  Get config file path
  default-user-config    Print default user config (keybindings)

Environment Variables:
  DEVSM_SOCKET           Custom socket path
  DEVSM_NO_AUTO_SPAWN    Disable daemon auto-spawn (set to 1)
  DEVSM_LOG_STDOUT       Log daemon to stdout (set to 1)
"
    );
}
