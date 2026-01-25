use std::{
    io::{ErrorKind, Read, Write},
    os::unix::{net::UnixStream, process::CommandExt},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use anyhow::bail;
use sendfd::SendWithFd;

use crate::daemon::socket_path;
use crate::rpc::{
    ClientProtocol, CommandBody, CommandResponse, DecodeResult, Encoder, JobExitedEvent, JobStatusEvent, JobStatusKind,
    ONE_SHOT_FLAG, ResizeNotification, RpcMessageKind, WorkspaceRef,
};

mod cache_key;
mod cli;
mod collection;
mod config;
mod daemon;
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
        cli::Command::Restart { job, value_map, as_test } => {
            if let Err(err) = restart_task_command(job, value_map, as_test) {
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
        cli::Command::Run { job, value_map, as_test } => {
            let _log_guard = self_log::init_client_logging();
            if let Err(err) = run_client(job, value_map, as_test) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Kill { job } => {
            if let Err(err) = kill_task_command(job) {
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
        cli::Command::RerunTests { only_failed } => {
            if let Err(err) = rerun_tests_command(only_failed) {
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
            cli::GetResource::SelfLogs { follow } => {
                if let Err(err) = get_self_logs(follow) {
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
            cli::GetResource::LoggedRustPanics => {
                if let Err(err) = get_logged_rust_panics_command() {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
            }
        },
        cli::Command::FunctionCall { name } => {
            if let Err(err) = call_function_command(name) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Logs { options } => {
            let _log_guard = self_log::init_client_logging();
            if let Err(err) = logs_client(options) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Complete { context } => {
            if !print_completions(context) {
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

fn rpc_command<T: jsony::ToBinary>(kind: RpcMessageKind, payload: &T) -> anyhow::Result<CommandResponse> {
    let mut socket = connect_or_spawn_daemon()?;

    let mut encoder = Encoder::new();
    encoder.encode_one_shot(kind, 1 | ONE_SHOT_FLAG, payload);
    socket.write_all(encoder.output())?;

    let mut protocol = ClientProtocol::new();
    let mut read_buf = Vec::with_capacity(1024);

    loop {
        read_buf.reserve(1024);
        let spare = read_buf.spare_capacity_mut();
        let read_slice = unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };

        match socket.read(read_slice) {
            Ok(0) => bail!("Connection closed unexpectedly"),
            Ok(n) => {
                unsafe { read_buf.set_len(read_buf.len() + n) };
                match protocol.decode(&read_buf) {
                    DecodeResult::Message { kind: RpcMessageKind::CommandAck, payload, .. } => {
                        let response: CommandResponse = jsony::from_binary(payload)?;
                        return Ok(response);
                    }
                    DecodeResult::Message { kind, .. } => {
                        bail!("Unexpected response kind: {:?}", kind);
                    }
                    DecodeResult::MissingData { .. } => continue,
                    DecodeResult::Empty => continue,
                    DecodeResult::Error(e) => bail!("RPC error: {:?}", e),
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => bail!("Socket read failed: {}", e),
        }
    }
}

fn restart_selected_command() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let req = rpc::RestartSelectedRequest { workspace: WorkspaceRef::Path { config: &config } };
    let response = rpc_command(RpcMessageKind::RestartSelected, &req)?;

    if let CommandBody::Error(err) = response.body {
        bail!("{err}");
    }
    Ok(())
}

fn restart_task_command(job: &str, value_map: jsony_value::ValueMap, as_test: bool) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let (task_name, profile) = job.rsplit_once(':').unwrap_or((job, ""));
    let params_bytes = jsony::to_binary(&value_map);

    let req = rpc::RestartTaskRequest {
        workspace: WorkspaceRef::Path { config: &config },
        task_name,
        profile,
        params: &params_bytes,
        as_test,
    };
    let response = rpc_command(RpcMessageKind::RestartTask, &req)?;
    handle_command_response(response)
}

fn kill_task_command(job: &str) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let req = rpc::KillTaskRequest { workspace: WorkspaceRef::Path { config: &config }, task_name: job };
    let response = rpc_command(RpcMessageKind::KillTask, &req)?;
    handle_command_response(response)
}

fn rerun_tests_command(only_failed: bool) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let req = rpc::RerunTestsRequest { workspace: WorkspaceRef::Path { config: &config }, only_failed };
    let response = rpc_command(RpcMessageKind::RerunTests, &req)?;
    handle_command_response(response)
}

fn call_function_command(name: &str) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let req = rpc::CallFunctionRequest { workspace: WorkspaceRef::Path { config: &config }, function_name: name };
    let response = rpc_command(RpcMessageKind::CallFunction, &req)?;
    handle_command_response(response)
}

fn get_logged_rust_panics_command() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let req = rpc::GetLoggedRustPanicsRequest { workspace: WorkspaceRef::Path { config: &config } };
    let response = rpc_command(RpcMessageKind::GetLoggedRustPanics, &req)?;
    handle_command_response(response)
}

fn handle_command_response(response: CommandResponse) -> anyhow::Result<()> {
    match response.body {
        CommandBody::Empty => Ok(()),
        CommandBody::Message(msg) => {
            println!("{}", msg);
            Ok(())
        }
        CommandBody::Error(err) => bail!("{err}"),
    }
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

fn run_client(job: &str, params: jsony_value::ValueMap, as_test: bool) -> anyhow::Result<()> {
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
            request: daemon::Request::AttachRun { config: &config, name: job.into(), params, as_test },
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

fn logs_client(options: cli::LogsOptions) -> anyhow::Result<()> {
    reset_terminal_to_canonical();

    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    if options.follow {
        setup_signal_handler(libc::SIGTERM, term_handler)?;
        setup_signal_handler(libc::SIGINT, term_handler)?;
    }

    let mut socket = connect_or_spawn_daemon()?;

    let is_tty = unsafe { libc::isatty(1) == 1 };

    let query = daemon::LogsQuery {
        max_age_secs: options.max_age.and_then(|s| parse_duration(s).ok()),
        task_filters: options.tasks.iter().map(|t| daemon::TaskFilter { name: t.name, latest: t.latest }).collect(),
        job_index: options.job,
        kind_filters: options.kinds.iter().map(|k| daemon::KindFilter { kind: k.kind, latest: k.latest }).collect(),
        pattern: options.pattern.unwrap_or(""),
        follow: options.follow,
        retry: options.retry,
        oldest: options.oldest.map(|n| n as u32),
        newest: options.newest.map(|n| n as u32),
        without_taskname: options.without_taskname,
        is_tty,
    };

    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::AttachLogs { config: &config, query },
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

fn parse_duration(s: &str) -> anyhow::Result<u32> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        let ms: u32 = num.trim().parse()?;
        return Ok(ms / 1000);
    }
    if let Some(num) = s.strip_suffix('s') {
        return Ok(num.trim().parse()?);
    }
    if let Some(num) = s.strip_suffix('m') {
        let mins: u32 = num.trim().parse()?;
        return Ok(mins * 60);
    }
    if let Some(num) = s.strip_suffix('h') {
        let hours: u32 = num.trim().parse()?;
        return Ok(hours * 3600);
    }
    s.parse().map_err(Into::into)
}

fn get_self_logs(follow: bool) -> anyhow::Result<()> {
    let mut socket = connect_or_spawn_daemon()?;

    if follow {
        setup_signal_handler(libc::SIGTERM, term_handler)?;
        setup_signal_handler(libc::SIGINT, term_handler)?;

        socket.send_with_fd(
            &jsony::to_binary(&daemon::RequestMessage {
                cwd: &std::env::current_dir()?,
                request: daemon::Request::GetSelfLogs { follow: true },
            }),
            &[1],
        )?;

        let mut read_buf = [0u8; 64];
        loop {
            let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);
            if flags & TERMINATION_FLAG != 0 {
                break;
            }

            match socket.read(&mut read_buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    } else {
        socket.write_all(&jsony::to_binary(&daemon::RequestMessage {
            cwd: &std::env::current_dir()?,
            request: daemon::Request::GetSelfLogs { follow: false },
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
    }
    Ok(())
}

fn print_completions(context: cli::CompleteContext) -> bool {
    match context {
        cli::CompleteContext::Commands => {
            println!("run\tRun a task and display output");
            println!("exec\tExecute task directly, bypassing daemon");
            println!("restart\tRestart a task via daemon");
            println!("restart-selected\tRestart selected task in TUI");
            println!("kill\tTerminate a running task");
            println!("test\tRun tests with optional filters");
            println!("logs\tView and stream logs");
            println!("validate\tValidate config file");
            println!("get\tGet information from daemon");
            println!("function\tCall a saved function");
            println!("server\tStart daemon process");
            println!("complete\tOutput completions for shell");
            true
        }
        cli::CompleteContext::Tasks => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            for (name, expr) in workspace.tasks {
                let preview = expr.command_preview();
                if preview.is_empty() {
                    println!("{name}");
                } else {
                    println!("{name}\t{preview}");
                }
                if expr.profiles.len() > 1 {
                    for profile in expr.profiles {
                        if preview.is_empty() {
                            println!("{name}:{profile}");
                        } else {
                            println!("{name}:{profile}\t{preview}");
                        }
                    }
                }
            }
            true
        }
        cli::CompleteContext::Tests => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            for (name, variants) in workspace.tests {
                let info = variants.first().map(|v| v.info).unwrap_or("");
                if info.is_empty() {
                    println!("{name}");
                } else {
                    println!("{name}\t{info}");
                }
            }
            true
        }
        cli::CompleteContext::Profiles { task } => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            let Some((_, expr)) = workspace.tasks.iter().find(|(n, _)| *n == task) else {
                return false;
            };
            for profile in expr.profiles {
                println!("{task}:{profile}");
            }
            true
        }
        cli::CompleteContext::Vars { task, exclude } => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            let Some((_, expr)) = workspace.tasks.iter().find(|(n, _)| *n == task) else {
                return false;
            };
            for (name, meta) in expr.vars {
                if exclude.contains(name) {
                    continue;
                }
                if let Some(desc) = meta.description {
                    println!("{name}\t{desc}");
                } else {
                    println!("{name}");
                }
            }
            for var in expr.collect_variables() {
                if exclude.contains(&var) {
                    continue;
                }
                if !expr.vars.iter().any(|(n, _)| *n == var) {
                    println!("{var}");
                }
            }
            true
        }
        cli::CompleteContext::Groups => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            for (name, _) in workspace.groups {
                println!("{name}");
            }
            true
        }
        cli::CompleteContext::Functions => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            for func in workspace.functions {
                println!("{}", func.name);
            }
            true
        }
        cli::CompleteContext::Tags => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            let mut tags = std::collections::HashSet::new();
            for (_, expr) in workspace.tasks {
                for tag in expr.tags {
                    tags.insert(*tag);
                }
            }
            for (_, variants) in workspace.tests {
                for variant in *variants {
                    for tag in variant.tags {
                        tags.insert(*tag);
                    }
                }
            }
            for tag in tags {
                println!("{tag}");
            }
            true
        }
        cli::CompleteContext::GetResources => {
            println!("self-logs\tRetrieve daemon logs");
            println!("workspace\tWorkspace resources");
            println!("default-user-config\tPrint default user config");
            println!("logged-rust-panics\tShow logged Rust panics");
            true
        }
        cli::CompleteContext::Kinds => {
            println!("service\tLong-running services");
            println!("action\tOne-shot actions");
            println!("test\tTest tasks");
            true
        }
    }
}

fn print_help() {
    print!(
        "\
devsm - TUI development service manager

Usage: devsm [OPTIONS] [COMMAND]

Commands:
  (default)          Launch the TUI interface
  run <job>          Run a job and display its output
  exec <job>         Execute a task directly, bypassing the daemon
  restart <job>      Restart a job via the daemon
  restart-selected   Restart the currently selected task in TUI
  kill <task>        Terminate a running task (by name or index)
  test [filters]     Run tests with optional filters
  logs [options]     View and stream logs from tasks
  validate [path]    Validate a config file
  get <resource>     Get information from the daemon
  function call <n>  Call a function defined in config
  complete <context> Output completion data for shell scripts
  server             Start the daemon process (internal)

Options:
  -h, --help        Print this help message
  --from=DIR        Run from DIR instead of current directory

Job Arguments:
  Jobs accept parameters as --key=value flags or a JSON object:
    devsm run build --profile=release
    devsm run build '{{\"profile\":\"release\"}}'

Test Filters:
  +tag              Include tests with this tag
  -tag              Exclude tests with this tag
  name              Include tests matching this name

Validate Options:
  --skip-path-checks     Skip validation of pwd paths

Logs Options:
  --max-age=DURATION     Show logs since DURATION ago (5s, 10m, 1h)
  --task=NAME[@latest]   Filter by task name (repeatable)
  --kind=KIND[@latest]   Filter by kind: service, action, test (repeatable)
  --job=INDEX            Filter by job index
  --follow, -f           Stream new logs
  --retry                With @latest, wait for next job
  --oldest=N             Show oldest N lines
  --newest=N             Show newest N lines
  --without-taskname     Omit task name prefixes
  PATTERN                Search pattern (case-insensitive if all lowercase)

Get Resources:
  self-logs [-f]         Retrieve daemon logs (-f/--follow to tail)
  workspace config-path  Get config file path
  default-user-config    Print default user config (keybindings)
  logged-rust-panics     Show logged Rust panics from daemon

Complete Contexts:
  commands               List available commands
  tasks                  List tasks from config
  tests                  List tests from config
  profiles --task=NAME   List profiles for a task
  vars --task=NAME       List variables for a task
  groups                 List groups from config
  functions              List functions from config
  tags                   List all tags
  get-resources          List get subcommands
  kinds                  List task kinds (service, action, test)

Environment Variables:
  DEVSM_SOCKET           Custom socket path
  DEVSM_NO_AUTO_SPAWN    Disable daemon auto-spawn (set to 1)
  DEVSM_LOG_STDOUT       Log daemon to stdout (set to 1)
"
    );
}
