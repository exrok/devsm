use crate::daemon::socket_path;
use crate::rpc::{
    ClientProtocol, CommandBody, CommandResponse, DecodeResult, Encoder, JobExitedEvent, JobStatusEvent, JobStatusKind,
    JobTraceReportEvent, ONE_SHOT_FLAG, ResizeNotification, RpcMessageKind, WorkspaceRef,
};
use anyhow::bail;
use kvlog::collector::UninitializedLogPolicy;
use sendfd::SendWithFd;
use std::{
    io::{ErrorKind, Read, Write},
    os::unix::{io::AsRawFd, net::UnixStream, process::CommandExt},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(test)]
mod alloc_report;
mod auto_deps;
mod cache_key;
mod cli;
mod clipboard;
mod clock;
mod collection;
mod completion;
mod config;
mod daemon;
mod db;
mod diagnostic;
mod event_loop;
mod function;
#[cfg(feature = "fuzz")]
mod fuzz_server;
mod global_tui;
mod keybinds;
mod line_width;
mod log_fowarder_ui;
mod log_storage;
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
    // Don't emit logs until decide where we are going to send them.
    kvlog::collector::set_uninitialized_log_policy(UninitializedLogPolicy::Buffer { max_bytes: 1024 * 1024 });

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
        cli::Command::Help(topic) => {
            print_help_topic(topic);
        }
        cli::Command::Tui => {
            let _log_guard = self_log::init_client_logging();
            let cwd = std::env::current_dir().unwrap_or_else(|err| {
                eprintln!("error: failed to get current directory: {}", err);
                std::process::exit(1);
            });
            if config::find_config_path_from(&cwd).is_some() {
                if let Err(err) = client() {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
            } else if let Err(err) = global_client() {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Global => {
            let _log_guard = self_log::init_client_logging();
            if let Err(err) = global_client() {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Server => {
            self_log::install_daemon_panic_hook();
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
        cli::Command::Start { job, value_map, as_test, cached } => {
            if let Err(err) = start_task_command(job, value_map, as_test, cached) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Restart { job, value_map, as_test, cached } => {
            if let Err(err) = restart_task_command(job, value_map, as_test, cached) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Exec { job, value_map, trailing_args } => {
            if let Err(err) = exec_task(job, value_map, trailing_args) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Run { job, value_map, trailing_args, as_test, derive_cache_key } => {
            let log_guard = self_log::init_client_logging();
            match run_client(job, value_map, trailing_args, as_test, derive_cache_key) {
                Ok(code) => {
                    drop(log_guard);
                    std::process::exit(code);
                }
                Err(err) => {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
            }
        }
        cli::Command::Auto { job, value_map, trailing_args } => {
            match auto_task_command(job, value_map, trailing_args) {
                Ok(code) => std::process::exit(code),
                Err(err) => {
                    eprintln!("error: {}", err);
                    std::process::exit(1);
                }
            }
        }
        cli::Command::Stop { job } => {
            if let Err(err) = kill_task_command(job) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Status { name } => {
            if let Err(err) = status_command(name) {
                eprintln!("error: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Test { filters, force } => {
            let _log_guard = self_log::init_client_logging();
            if let Err(err) = test_client(filters, force) {
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
            cli::GetResource::Workspaces { json } => {
                if let Err(err) = get_workspaces_command(json) {
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
        cli::Command::Completions { shell } => {
            print_completion_script(shell);
        }
    }
}

const BASH_SCRIPT: &str = include_str!("../completions/devsm.bash");
const FISH_SCRIPT: &str = include_str!("../completions/devsm.fish");
const ZSH_SCRIPT: &str = include_str!("../completions/devsm.zsh");

fn print_completion_script(shell: cli::CompletionShell) {
    let script = match shell {
        cli::CompletionShell::Bash => BASH_SCRIPT,
        cli::CompletionShell::Fish => FISH_SCRIPT,
        cli::CompletionShell::Zsh => ZSH_SCRIPT,
    };
    use std::io::Write;
    let _ = std::io::stdout().write_all(script.as_bytes());
}

fn test_client(filters: Vec<cli::TestFilter>, force: bool) -> anyhow::Result<()> {
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
            cli::TestFilter::IncludeTag(tag) => include_tags.push(tag.as_ref()),
            cli::TestFilter::ExcludeTag(tag) => exclude_tags.push(tag.as_ref()),
            cli::TestFilter::IncludeName(name) => include_names.push(name.as_ref()),
        }
    }

    let test_filters = daemon::TestFilters { include_tags, exclude_tags, include_names, force };

    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::AttachTests { config: &config, filters: test_filters },
        }),
        &[0, 1],
    )?;

    let mut protocol = ClientProtocol::new();
    let mut read_buf = Vec::with_capacity(1024);
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
            Ok(0) if terminated_by_user => return Ok(()),
            Ok(0) => report_daemon_disconnect(),
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
            Err(_) if terminated_by_user => return Ok(()),
            Err(_) => report_daemon_disconnect(),
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

fn build_task_params<'a>(
    task_expr: &config::TaskConfigExpr<'static>,
    mut params: jsony_value::ValueMap<'a>,
    trailing_args: &'a [String],
    run_flags: Option<(&mut bool, &mut bool)>,
) -> anyhow::Result<jsony_value::ValueMap<'a>> {
    if task_expr.cli.forward_arguments {
        if params.get("args").is_some() {
            bail!("Task uses cli.forward-arguments, so --args cannot be provided explicitly");
        }
        let args_value: jsony_value::Value<'a> = trailing_args.iter().map(|arg| arg.as_str()).collect();
        params.insert("args".into(), args_value);
        return Ok(params);
    }

    let trailing_params = if let Some((as_test, derive_cache_key)) = run_flags {
        cli::parse_run_trailing_params(trailing_args, as_test, derive_cache_key)?
    } else {
        cli::parse_task_params(trailing_args)?
    };
    for (key, value) in trailing_params.entries() {
        params.insert(key.clone(), value.clone());
    }
    Ok(params)
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
    command.arg("self").arg("server");
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

/// Clear `FD_CLOEXEC` so the daemon socket survives into the unmanaged process
/// after `exec`. The daemon holds the task's requirements active until this
/// socket EOFs, which it does when the last process holding the fd exits.
///
/// This is best-effort: a process that sanitizes its inherited fds (`closefrom`,
/// many daemonizers) closes the socket early, so the daemon releases the held
/// requirements while the process is still running. Resources held by an
/// unmanaged exec are only guaranteed for processes that leave inherited fds
/// open.
fn clear_cloexec(fd: &impl AsRawFd) -> std::io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFD);
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn rpc_ws_command<T: jsony::ToBinary>(
    kind: RpcMessageKind,
    workspace: &WorkspaceRef<'_>,
    payload: &T,
) -> anyhow::Result<CommandResponse> {
    let mut socket = connect_or_spawn_daemon()?;

    let mut encoder = Encoder::new();
    encoder.encode_one_shot_ws(kind, 1 | ONE_SHOT_FLAG, workspace, payload);
    socket.write_all(encoder.output())?;

    rpc_read_response(&mut socket)
}

fn rpc_read_response(socket: &mut UnixStream) -> anyhow::Result<CommandResponse> {
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

    let workspace = WorkspaceRef::Path { config: &config };
    let req = rpc::RestartSelectedRequest {};
    let response = rpc_ws_command(RpcMessageKind::RestartSelected, &workspace, &req)?;

    if let CommandBody::Error(err) = response.body {
        bail!("{err}");
    }
    Ok(())
}

fn start_task_command(job: &str, value_map: jsony_value::ValueMap, as_test: bool, cached: bool) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let (task_name, profile) = job.rsplit_once(':').unwrap_or((job, ""));
    let params_bytes = jsony::to_binary(&value_map);

    let workspace = WorkspaceRef::Path { config: &config };
    let req = rpc::SpawnTaskRequest { task_name, profile, params: &params_bytes, as_test, cached };
    let response = rpc_ws_command(RpcMessageKind::StartTask, &workspace, &req)?;
    handle_command_response(response)
}

fn restart_task_command(
    job: &str,
    value_map: jsony_value::ValueMap,
    as_test: bool,
    cached: bool,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let (task_name, profile) = job.rsplit_once(':').unwrap_or((job, ""));
    let params_bytes = jsony::to_binary(&value_map);

    let workspace = WorkspaceRef::Path { config: &config };
    let req = rpc::SpawnTaskRequest { task_name, profile, params: &params_bytes, as_test, cached };
    let response = rpc_ws_command(RpcMessageKind::RestartTask, &workspace, &req)?;
    handle_command_response(response)
}

fn kill_task_command(job: &str) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let workspace = WorkspaceRef::Path { config: &config };
    let req = rpc::KillTaskRequest { task_name: job };
    let response = rpc_ws_command(RpcMessageKind::KillTask, &workspace, &req)?;
    handle_command_response(response)
}

fn status_command(name: Option<&str>) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let workspace = WorkspaceRef::Path { config: &config };
    let req = rpc::GetStatusRequest { name: name.unwrap_or("") };
    let response = rpc_ws_command(RpcMessageKind::GetStatus, &workspace, &req)?;

    match response.body {
        CommandBody::Error(err) if name.is_none() && err.as_ref() == "'' is not a known task or group" => {
            status_command_legacy_global_fallback(&config)
        }
        CommandBody::Error(err) => bail!("{err}"),
        CommandBody::Empty => bail!("empty status response"),
        CommandBody::Message(msg) => {
            let parsed: rpc::StatusResponse =
                jsony::from_json(&msg).map_err(|e| anyhow::anyhow!("Failed to decode status response: {e:?}"))?;
            print_status_response(&parsed);
            Ok(())
        }
    }
}

fn status_command_legacy_global_fallback(config_path: &Path) -> anyhow::Result<()> {
    let base_path = config_path.parent().unwrap_or_else(|| Path::new("."));
    let content = std::fs::read_to_string(config_path)?.leak();
    let workspace_config = config::load_workspace_config_from_path(base_path, config_path, content)?;
    let workspace = WorkspaceRef::Path { config: config_path };

    let mut names = Vec::new();
    for (name, expr) in workspace_config.tasks {
        names.push(format!("{}.{}", expr.kind.as_str(), name));
    }
    for (name, _) in workspace_config.tests {
        names.push(format!("test.{name}"));
    }

    let mut runnables = Vec::new();
    for query_name in &names {
        let req = rpc::GetStatusRequest { name: query_name };
        let response = rpc_ws_command(RpcMessageKind::GetStatus, &workspace, &req)?;
        match response.body {
            CommandBody::Message(msg) => {
                let parsed: rpc::StatusResponse =
                    jsony::from_json(&msg).map_err(|e| anyhow::anyhow!("Failed to decode status response: {e:?}"))?;
                if let rpc::StatusResponse::Task(r) = parsed
                    && is_active_runnable(&r)
                {
                    runnables.push(r);
                }
            }
            CommandBody::Empty => {}
            CommandBody::Error(err) => bail!("{err}"),
        }
    }

    runnables.sort_by_key(|r| r.last_job_id.unwrap_or(u32::MAX));
    print_status_response(&rpc::StatusResponse::Global(rpc::GlobalStatus { runnables }));
    Ok(())
}

fn is_active_runnable(r: &rpc::RunnableStatus) -> bool {
    let state = r.state.as_ref();
    state == "scheduled" || state == "starting" || state.starts_with("running")
}

fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let secs = ms / 1000;
    let rem_ms = ms % 1000;
    if secs < 60 {
        return format!("{secs}.{:03}s", rem_ms);
    }
    let m = secs / 60;
    let s = secs % 60;
    if m < 60 {
        return format!("{m}m {s}s");
    }
    let h = m / 60;
    let m = m % 60;
    format!("{h}h {m}m {s}s")
}

fn format_age_secs(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s ago");
    }
    let m = secs / 60;
    let s = secs % 60;
    if m < 60 {
        return format!("{m}m {s}s ago");
    }
    let h = m / 60;
    let m = m % 60;
    if h < 24 {
        return format!("{h}h {m}m ago");
    }
    let d = h / 24;
    let h = h % 24;
    format!("{d}d {h}h ago")
}

fn print_runnable_summary(prefix: &str, r: &rpc::RunnableStatus) {
    println!("{prefix}{}.{}: {}", r.kind, r.name, r.state);
    if let Some(id) = r.last_job_id {
        println!("{prefix}  Last job: #{id}");
    }
    if let Some(secs) = r.last_run_started_secs_ago {
        println!("{prefix}  Started:  {}", format_age_secs(secs));
    }
    if let Some(ms) = r.last_run_duration_ms {
        println!("{prefix}  Duration: {}", format_duration_ms(ms));
    }
    if let Some(code) = r.exit_code {
        let cause = r.exit_cause.as_deref().unwrap_or("");
        if cause.is_empty() {
            println!("{prefix}  Exit:     code {code}");
        } else {
            println!("{prefix}  Exit:     code {code} ({cause})");
        }
    } else if let Some(cause) = r.exit_cause.as_deref() {
        println!("{prefix}  Exit:     {cause}");
    }
    if let Some(ready) = r.ready {
        println!("{prefix}  Ready:    {}", if ready { "yes" } else { "no" });
    }
    if !r.blocked_on.is_empty() {
        println!("{prefix}  Blocked on:");
        for dep in &r.blocked_on {
            println!("{prefix}    - {dep}");
        }
    }
    if let Some(profile) = r.profile.as_deref() {
        println!("{prefix}  Profile:  {profile}");
    }
    if let Some(params) = r.spawn_params.as_deref() {
        println!("{prefix}  Params:   {params}");
    }
    if let Some(gen_id) = r.config_generation_id {
        let marker = if r.config_is_current { "current" } else { "stale (config reloaded since)" };
        println!("{prefix}  Config:   generation {gen_id} — {marker}");
    }
}

fn print_runnable_detail(r: &rpc::RunnableStatus) {
    print_runnable_summary("", r);
    if let Some(pwd) = r.pwd.as_deref() {
        println!("  Pwd:      {pwd}");
    }
    if let Some(cmd) = r.command.as_deref() {
        println!("  Command:  {cmd}");
    }
    if !r.envvars.is_empty() {
        println!("  Env:");
        for e in &r.envvars {
            println!("    {e}");
        }
    }
    if !r.require.is_empty() {
        println!("  Require:");
        for req in &r.require {
            println!("    - {req}");
        }
    }
}

fn print_status_response(resp: &rpc::StatusResponse) {
    match resp {
        rpc::StatusResponse::Task(r) => {
            print_runnable_detail(r);
        }
        rpc::StatusResponse::Group(g) => {
            println!("group.{}: {}", g.name, g.overall);
            println!("  {} runnable(s)", g.runnables.len());
            for r in &g.runnables {
                println!();
                print_runnable_summary("  ", r);
            }
        }
        rpc::StatusResponse::Global(g) => {
            if g.runnables.is_empty() {
                println!("No active tasks.");
                return;
            }
            println!("{} active task(s)", g.runnables.len());
            for r in &g.runnables {
                println!();
                print_runnable_summary("  ", r);
            }
        }
    }
}

fn rerun_tests_command(only_failed: bool) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let workspace = WorkspaceRef::Path { config: &config };
    let req = rpc::RerunTestsRequest { only_failed };
    let response = rpc_ws_command(RpcMessageKind::RerunTests, &workspace, &req)?;
    handle_command_response(response)
}

fn call_function_command(name: &str) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let workspace = WorkspaceRef::Path { config: &config };
    let req = rpc::CallFunctionRequest { function_name: name };
    let response = rpc_ws_command(RpcMessageKind::CallFunction, &workspace, &req)?;
    handle_command_response(response)
}

fn get_logged_rust_panics_command() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let workspace = WorkspaceRef::Path { config: &config };
    let req = rpc::GetLoggedRustPanicsRequest {};
    let response = rpc_ws_command(RpcMessageKind::GetLoggedRustPanics, &workspace, &req)?;
    handle_command_response(response)
}

fn get_workspaces_command(json: bool) -> anyhow::Result<()> {
    let mut socket = connect_or_spawn_daemon()?;

    let mut encoder = rpc::Encoder::new();
    encoder.encode_one_shot(RpcMessageKind::GetWorkspaces, 1 | ONE_SHOT_FLAG, &rpc::GetWorkspacesRequest {});
    socket.write_all(encoder.output())?;

    let response = rpc_read_response(&mut socket)?;
    if json {
        return handle_command_response(response);
    }
    match response.body {
        CommandBody::Empty => Ok(()),
        CommandBody::Message(msg) => {
            let Ok(resp) = jsony::from_json::<rpc::GetWorkspacesResponse>(&msg) else {
                println!("{msg}");
                return Ok(());
            };
            for ws in &resp.workspaces {
                let status = if ws.currently_loaded { "LIVE" } else { "DEAD" };
                let path = ws.config_path.strip_suffix("/devsm.toml").unwrap_or(&ws.config_path);
                println!("{status} {path}");
            }
            Ok(())
        }
        CommandBody::Error(err) => bail!("{err}"),
    }
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

fn global_client() -> anyhow::Result<()> {
    let stdin = std::fs::File::open("/dev/tty")?;
    let stdout = std::fs::OpenOptions::new().write(true).open("/dev/tty")?;
    match global_tui::run(stdin, stdout)? {
        global_tui::Selection::Quit => Ok(()),
        global_tui::Selection::Workspace(config_path) => {
            let cwd = config_path.parent().unwrap_or(&config_path).to_path_buf();
            client_with_config(&cwd, &config_path)
        }
    }
}

fn client() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;
    client_with_config(&cwd, &config)
}

fn client_with_config(cwd: &std::path::Path, config: &std::path::Path) -> anyhow::Result<()> {
    setup_signal_handler(libc::SIGTERM, term_handler)?;
    setup_signal_handler(libc::SIGINT, term_handler)?;
    setup_signal_handler(libc::SIGWINCH, winch_handler)?;

    let mut socket = connect_or_spawn_daemon()?;

    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage { cwd, request: daemon::Request::AttachTui { config } }),
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
            Ok(0) => report_daemon_disconnect(),
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
            Err(_) => report_daemon_disconnect(),
        }
    }
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

/// Restores the terminal after the daemon — which put it in raw mode on our
/// passed-through stdout fd — died without running its own cleanup.
///
/// Emits the disable sequences (each a no-op if that mode was never enabled, so
/// this is safe for both the full-screen sessions and the plain log forwarders)
/// and restores cooked mode. Does nothing when output is not a terminal.
fn restore_terminal_on_crash() {
    use std::os::fd::FromRawFd;

    let mut seq = Vec::new();
    seq.extend_from_slice(extui::vt::DISABLE_ALT_SCREEN);
    seq.extend_from_slice(extui::vt::SHOW_CURSOR);
    seq.extend_from_slice(extui::vt::DISABLE_NON_MOTION_MOUSE_EVENTS);
    seq.extend_from_slice(extui::vt::DISABLE_BRACKETED_PASTE);
    seq.extend_from_slice(extui::vt::POP_KEYBOARD_ENABLEMENT);

    if unsafe { libc::isatty(1) } == 1 {
        let mut stdout = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
        let _ = stdout.write_all(&seq);
    } else if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = tty.write_all(&seq);
    }

    reset_terminal_to_canonical();
}

/// Cleans up the terminal and prints a diagnostic when the daemon connection
/// drops unexpectedly (i.e. without a clean `TerminateAck`/`Disconnect`), then
/// exits non-zero. Exiting here avoids the generic `error: {}` handler in
/// `main` printing a second, less helpful line.
fn report_daemon_disconnect() -> ! {
    restore_terminal_on_crash();

    let crash_path = self_log::crash_report_path();
    eprintln!();
    eprintln!("error: the devsm daemon became unreachable (connection closed unexpectedly).");
    eprintln!("       The background daemon may have crashed.");
    eprintln!();
    if crash_path.exists() {
        eprintln!("A crash report was written to:");
    } else {
        eprintln!("If the daemon crashed, a report may be found at:");
    }
    eprintln!("    {}", crash_path.display());
    eprintln!("Recent daemon logs can also be viewed with: devsm self logs");
    eprintln!();
    eprintln!("Please review it for any private information, then report the issue at:");
    eprintln!("    https://github.com/exrok/devsm/issues");

    std::process::exit(1);
}

fn run_client(
    job: &str,
    params: jsony_value::ValueMap,
    trailing_args: &[String],
    mut as_test: bool,
    mut derive_cache_key: bool,
) -> anyhow::Result<i32> {
    reset_terminal_to_canonical();

    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let workspace_config = config::load_from_env()?;
    let (name, profile) = job.rsplit_once(':').unwrap_or((job, ""));
    let bare_task_name = name.split_once('.').map_or(name, |(_, rest)| rest).to_string();

    let resolved =
        if is_explicit_group_reference(name) { None } else { resolve_name_in_config(&workspace_config, name) };
    let group = if resolved.is_none() { resolve_group_in_config(&workspace_config, name) } else { None };
    if let Some(group_name) = group {
        if !profile.is_empty() || !params.entries().is_empty() || !trailing_args.is_empty() {
            bail!("Group '{}' does not support profiles, parameters, or trailing arguments", group_name);
        }
        if as_test {
            bail!("Group '{}' cannot be run with --as-test", group_name);
        }
        if derive_cache_key {
            bail!("Group '{}' cannot be run with --derive-cache-key", group_name);
        }
    }

    let task_expr = match resolved {
        Some((_, expr)) => expr,
        None if name == "~cargo" => &config::CARGO_AUTO_EXPR,
        None if group.is_some() => &config::CARGO_AUTO_EXPR,
        None if is_explicit_group_reference(name) => {
            bail!("Group not found: {}", name.strip_prefix("group.").unwrap_or(name))
        }
        None => bail!("Task not found: {}", name),
    };
    let params = if group.is_some() {
        params
    } else {
        build_task_params(task_expr, params, trailing_args, Some((&mut as_test, &mut derive_cache_key)))?
    };
    let as_test = match resolved {
        Some((kind, _)) => as_test || kind == config::TaskKind::Test,
        None => as_test,
    };
    let job = job.to_owned();

    if name != "~cargo"
        && !as_test
        && let Some((_, expr)) = resolved
        && expr.managed == Some(false)
    {
        bail!(
            "Task '{}' has managed = false and must be run with exec.\n\
                     Use 'devsm exec {}' instead.",
            name,
            &job
        );
    }

    setup_signal_handler(libc::SIGTERM, term_handler)?;
    setup_signal_handler(libc::SIGINT, term_handler)?;

    let mut socket = connect_or_spawn_daemon()?;

    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::AttachRun {
                config: &config,
                name: (&*job).into(),
                params,
                as_test,
                derive_cache_key,
            },
        }),
        &[0, 1],
    )?;

    let mut protocol = ClientProtocol::new();
    let mut read_buf = Vec::with_capacity(1024);
    let mut exit_status: Option<i32> = None;
    let mut terminated_by_user = false;
    let mut trace_report: Option<JobTraceReportEvent> = None;

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
            Ok(0) if terminated_by_user => break,
            Ok(0) => report_daemon_disconnect(),
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
                                }
                                if derive_cache_key {
                                    apply_trace_report(&bare_task_name, &config, trace_report.take(), exit_status);
                                }
                                return Ok(if group.is_none() { exit_status.unwrap_or(0) } else { 0 });
                            }
                            RpcMessageKind::JobStatus => {
                                if let Ok(event) = jsony::from_binary::<JobStatusEvent>(payload) {
                                    match event.status {
                                        JobStatusKind::Restarting => eprintln!("Terminating previous run..."),
                                        JobStatusKind::Waiting => eprintln!("Waiting for dependencies..."),
                                        _ => {}
                                    }
                                }
                            }
                            RpcMessageKind::JobExited => {
                                if let Ok(event) = jsony::from_binary::<JobExitedEvent>(payload) {
                                    exit_status = Some(event.exit_code);
                                }
                            }
                            RpcMessageKind::JobTraceReport => {
                                if let Ok(event) = jsony::from_binary::<JobTraceReportEvent>(payload) {
                                    trace_report = Some(event);
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
            Err(_) if terminated_by_user => break,
            Err(_) => report_daemon_disconnect(),
        }
    }

    Ok(if group.is_none() { exit_status.unwrap_or(0) } else { 0 })
}

fn auto_task_command(job: &str, params: jsony_value::ValueMap, trailing_args: &[String]) -> anyhow::Result<i32> {
    let workspace_config = config::load_from_env()?;
    let (name, _) = job.rsplit_once(':').unwrap_or((job, ""));

    if name != "~cargo"
        && !is_explicit_group_reference(name)
        && let Some((_, expr)) = resolve_name_in_config(&workspace_config, name)
        && expr.managed == Some(false)
    {
        return exec_task(job, params, trailing_args).map(|()| 0);
    }

    run_client(job, params, trailing_args, false, false)
}

/// Apply an inferred-deps report received from the daemon to the user's
/// `devsm.toml`, replacing the named task's `cache.key` field.
///
/// Refuses to write when the task exited non-zero or the trace was
/// truncated — both produce unreliable dep sets.
fn apply_trace_report(
    bare_task_name: &str,
    toml_path: &std::path::Path,
    report: Option<JobTraceReportEvent>,
    exit_status: Option<i32>,
) {
    let Some(report) = report else {
        eprintln!(
            "warning: --derive-cache-key requested but no trace report was received from the daemon. \
             devsm.toml was not modified."
        );
        return;
    };

    let exit_code = exit_status.unwrap_or(report.exit_code);
    if exit_code != 0 {
        eprintln!(
            "warning: traced task exited with code {} — refusing to write cache.key from a failed run",
            exit_code
        );
        return;
    }
    if report.truncated {
        eprintln!("warning: trace exceeded the 1M event cap and is incomplete — refusing to write a partial cache.key");
        return;
    }
    if report.paths.is_empty() {
        eprintln!("warning: trace observed no in-project file accesses — devsm.toml was not modified");
        return;
    }

    match auto_deps::update_cache_key(toml_path, bare_task_name, &report.paths, &report.ignore_per_path) {
        Ok(outcome) => {
            if let Some(prev) = outcome.previous_cache_key {
                eprintln!("Replaced existing cache.key:\n  {}", prev);
            }
            let signal_summary = if report.framework_signals.is_empty() {
                String::new()
            } else {
                format!(" (signals: {})", report.framework_signals.join(", "))
            };
            eprintln!(
                "Wrote cache.key for `{}` with {} path(s) into {}{}",
                bare_task_name,
                report.paths.len(),
                toml_path.display(),
                signal_summary,
            );
        }
        Err(err) => {
            eprintln!("error: failed to update {}: {:?}", toml_path.display(), err);
        }
    }
}

/// Resolves a user-typed name (with optional `kind.` prefix) to its `TaskKind`
/// and `TaskConfigExpr` from a parsed config. Implements the same priority
/// rules as the daemon's `base_index_by_name`: bare names prefer the
/// action/service of that name over a test of the same short name.
fn resolve_name_in_config(
    config: &config::WorkspaceConfig<'static>,
    name: &str,
) -> Option<(config::TaskKind, &'static config::TaskConfigExpr<'static>)> {
    use config::TaskKind;
    let (kind_filter, short) = match name.split_once('.') {
        Some(("service", rest)) => (Some(TaskKind::Service), rest),
        Some(("action", rest)) => (Some(TaskKind::Action), rest),
        Some(("test", rest)) => (Some(TaskKind::Test), rest),
        Some(("group", _)) => return None,
        _ => (None, name),
    };

    if kind_filter == Some(TaskKind::Test) {
        let (_, test) = config.tests.iter().find(|(n, _)| *n == short)?;
        return Some((TaskKind::Test, test.to_task_config_expr()));
    }

    if let Some((_, expr)) =
        config.tasks.iter().find(|(n, expr)| *n == short && kind_filter.map(|k| k == expr.kind).unwrap_or(true))
    {
        return Some((expr.kind, expr));
    }

    if kind_filter.is_none()
        && let Some((_, test)) = config.tests.iter().find(|(n, _)| *n == short)
    {
        return Some((TaskKind::Test, test.to_task_config_expr()));
    }

    None
}

fn group_lookup_short_name(name: &str) -> Option<&str> {
    match name.split_once('.') {
        Some(("group", rest)) => Some(rest),
        Some(("service" | "action" | "test", _)) => None,
        _ => Some(name),
    }
}

fn is_explicit_group_reference(name: &str) -> bool {
    name.split_once('.').is_some_and(|(namespace, _)| namespace == "group")
}

fn resolve_group_in_config(config: &config::WorkspaceConfig<'static>, name: &str) -> Option<&'static str> {
    let short = group_lookup_short_name(name)?;
    config.groups.iter().find(|(group, _)| *group == short).map(|(group, _)| *group)
}

/// Executes a task directly, bypassing the daemon and ignoring dependencies.
fn exec_task(job: &str, params: jsony_value::ValueMap, trailing_args: &[String]) -> anyhow::Result<()> {
    let workspace_config = config::load_from_env()?;
    let (name, profile) = job.rsplit_once(':').unwrap_or((job, ""));

    let task_expr = if name == "~cargo" {
        &config::CARGO_AUTO_EXPR
    } else {
        let resolved =
            if is_explicit_group_reference(name) { None } else { resolve_name_in_config(&workspace_config, name) };
        match resolved {
            Some((_, expr)) => expr,
            None if resolve_group_in_config(&workspace_config, name).is_some() => {
                bail!("exec is not supported for groups");
            }
            None if is_explicit_group_reference(name) => {
                bail!("Group not found: {}", name.strip_prefix("group.").unwrap_or(name));
            }
            None => bail!("Task not found: {}", name),
        }
    };

    if task_expr.managed == Some(true) {
        bail!(
            "Task '{}' has managed = true and must be run through the daemon.\n\
             Use 'devsm run {}' instead.",
            name,
            job
        );
    }

    let params = build_task_params(task_expr, params, trailing_args, None)?;
    let profile = if profile.is_empty() { task_expr.profiles.first().copied().unwrap_or("") } else { profile };
    let daemon_params = params.clone();
    let env = config::Environment { profile, param: params, vars: task_expr.vars };
    let task = task_expr.eval(&env).map_err(|e| anyhow::anyhow!("Failed to evaluate task: {:?}", e))?;
    let tc = task.config();

    let path = workspace_config.base_path.join(tc.pwd);

    let (mut command, sh_command) = match &tc.command {
        config::Command::Sh { script, args } => (std::process::Command::new("/bin/sh"), Some((*script, *args))),
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

    if let Some((script, args)) = sh_command {
        command.arg("-c").arg(script);
        if !args.is_empty() {
            command.arg("devsm").args(args);
        }
    }

    // Tasks without requirements exec directly, with zero daemon involvement.
    // When a task does have `require`, the daemon runs those dependencies and
    // gates this exec until they are satisfied.
    let _exec_gate = if !tc.require.is_empty() {
        let socket = await_exec_requirements(job, daemon_params)?;
        clear_cloexec(&socket)?;
        Some(socket)
    } else {
        None
    };

    let err = command.exec();
    bail!("exec failed: {}", err);
}

/// Block until the daemon reports that `job`'s `require` dependencies are
/// satisfied. Returns the daemon socket to hold open across `exec`, or an error
/// if a dependency can never be met.
fn await_exec_requirements(job: &str, params: jsony_value::ValueMap) -> anyhow::Result<UnixStream> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let mut socket = connect_or_spawn_daemon()?;
    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::ExecAwait { config: &config, name: job.into(), params },
        }),
        &[],
    )?;

    let mut protocol = ClientProtocol::new();
    let mut read_buf = Vec::with_capacity(256);
    loop {
        read_buf.reserve(256);
        let spare = read_buf.spare_capacity_mut();
        let read_slice = unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };

        match socket.read(read_slice) {
            Ok(0) => bail!("daemon closed connection before requirements were satisfied"),
            Ok(n) => {
                unsafe { read_buf.set_len(read_buf.len() + n) };
                loop {
                    match protocol.decode(&read_buf) {
                        DecodeResult::Message { kind, payload, .. } => match kind {
                            RpcMessageKind::ExecProceed => return Ok(socket),
                            RpcMessageKind::ExecWaiting => {
                                if let Ok(event) = jsony::from_binary::<crate::rpc::ExecWaitingEvent>(payload) {
                                    if event.tasks.is_empty() {
                                        eprintln!("Waiting for dependencies...");
                                    } else {
                                        eprintln!("Waiting for: {}", event.tasks.join(", "));
                                    }
                                }
                            }
                            RpcMessageKind::ExecError => {
                                let message = jsony::from_binary::<crate::rpc::ExecErrorEvent>(payload)
                                    .map(|e| e.message)
                                    .unwrap_or_else(|_| "requirements could not be satisfied".to_string());
                                bail!("{}", message);
                            }
                            RpcMessageKind::Disconnect => {
                                bail!("daemon disconnected before requirements were satisfied");
                            }
                            _ => {}
                        },
                        DecodeResult::MissingData { .. } => break,
                        DecodeResult::Empty => {
                            read_buf.clear();
                            break;
                        }
                        DecodeResult::Error(e) => bail!("daemon sent invalid exec gating response: {:?}", e),
                    }
                }
                protocol.compact(&mut read_buf, 4096);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
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
        max_age_secs: options.max_age.and_then(|s| config::parse_duration(s).ok().map(|f| f as u32)),
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
            Ok(0) if terminated_by_user => break,
            Ok(0) => report_daemon_disconnect(),
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
            Err(_) if terminated_by_user => break,
            Err(_) => report_daemon_disconnect(),
        }
    }

    Ok(())
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
        for (ts, level, span, fields) in kvlog::encoding::decode(&logs).flatten() {
            kvlog::collector::format_statement_with_colors(&mut fmt_buf, &mut parents, ts, level, span, fields);
        }
        print!("{}", String::from_utf8_lossy(&fmt_buf));
    }
    Ok(())
}

fn print_completion(candidate: &str, description: Option<&str>) {
    if let Some(description) = description {
        let description = completion_description(description);
        if !description.is_empty() {
            println!("{candidate}\t{description}");
            return;
        }
    }
    println!("{candidate}");
}

fn completion_description(description: &str) -> String {
    let mut out = String::with_capacity(description.len());
    let mut pending_space = false;

    for ch in description.trim().chars() {
        if ch.is_whitespace() || ch.is_control() {
            if !out.is_empty() {
                pending_space = true;
            }
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(ch);
        }
    }

    out
}

#[cfg(test)]
mod completion_tests {
    use super::*;

    #[test]
    fn completion_description_collapses_multiline_text() {
        assert_eq!(
            completion_description("  COMMAND=\"cargo run\"\nif true; then\n\tcargo test  "),
            "COMMAND=\"cargo run\" if true; then cargo test"
        );
    }

    #[test]
    fn completion_description_removes_empty_whitespace() {
        assert_eq!(completion_description("\n\t  \r\n"), "");
    }
}

fn is_builtin_command_name(name: &str) -> bool {
    matches!(
        name,
        "global"
            | "run"
            | "exec"
            | "start"
            | "restart"
            | "restart-selected"
            | "stop"
            | "status"
            | "test"
            | "rerun-tests"
            | "logs"
            | "get"
            | "function"
            | "self"
            | "completions"
    )
}

fn print_task_completions(workspace: &config::WorkspaceConfig<'static>) {
    for (name, expr) in workspace.tasks {
        let preview = expr.command_preview();
        let kind = expr.kind.as_str();
        let bare_visible = !is_builtin_command_name(name);
        if bare_visible {
            print_completion(name, Some(preview));
        }
        print_completion(&format!("{kind}.{name}"), Some(preview));
        if expr.profiles.len() > 1 {
            for profile in expr.profiles {
                if bare_visible {
                    print_completion(&format!("{name}:{profile}"), Some(preview));
                }
                print_completion(&format!("{kind}.{name}:{profile}"), Some(preview));
            }
        }
    }
}

fn group_description(calls: &[config::TaskCall<'_>]) -> String {
    let n = calls.len();
    let suffix = if n == 1 { "" } else { "s" };
    let mut shown: Vec<&str> = calls.iter().take(3).map(|c| &*c.name).collect();
    if n > 3 {
        shown.push("…");
    }
    format!("group: {n} runnable{suffix} ({})", shown.join(", "))
}

fn function_description(action: &config::FunctionDefAction<'_>) -> String {
    match action {
        config::FunctionDefAction::Restart { task } => format!("restart {task}"),
        config::FunctionDefAction::Kill { task } => format!("kill {task}"),
        config::FunctionDefAction::RestartSelected => "restart-selected".to_string(),
        config::FunctionDefAction::Spawn { tasks } => match tasks.len() {
            0 => "spawn (empty)".to_string(),
            1 => format!("spawn {}", &*tasks[0].name),
            n => format!("spawn {n} tasks"),
        },
    }
}

fn tag_description(tasks: u32, tests: u32) -> String {
    match (tasks, tests) {
        (0, n) => format!("{n} test{}", if n == 1 { "" } else { "s" }),
        (n, 0) => format!("{n} task{}", if n == 1 { "" } else { "s" }),
        (a, b) => format!("{a} task{}, {b} test{}", if a == 1 { "" } else { "s" }, if b == 1 { "" } else { "s" }),
    }
}

fn print_task_var_completions(expr: &config::TaskConfigExpr<'static>, exclude: &[&str]) {
    for (name, meta) in expr.vars {
        if exclude.contains(name) {
            continue;
        }
        print_completion(name, meta.description);
    }
    for var in expr.collect_variables() {
        if exclude.contains(&var) {
            continue;
        }
        if !expr.vars.iter().any(|(n, _)| *n == var) {
            println!("{var}");
        }
    }
}

fn resolve_completion_task_expr<'a>(
    workspace: &config::WorkspaceConfig<'static>,
    task: &'a str,
) -> Option<(&'static config::TaskConfigExpr<'static>, &'a str)> {
    let (name, profile) = task.rsplit_once(':').unwrap_or((task, ""));
    let expr = if name == "~cargo" {
        &config::CARGO_AUTO_EXPR
    } else {
        resolve_name_in_config(workspace, name).map(|(_, expr)| expr)?
    };
    Some((expr, profile))
}

fn forward_completion_spec(
    workspace: &config::WorkspaceConfig<'static>,
    task: &str,
) -> Option<(std::path::PathBuf, Vec<&'static str>)> {
    let (expr, profile) = resolve_completion_task_expr(workspace, task)?;
    let prefix = expr.autocomplete_forward_prefix()?;
    let profile = if profile.is_empty() { expr.profiles.first().copied().unwrap_or("") } else { profile };
    let env = config::Environment { profile, param: jsony_value::ValueMap::new(), vars: expr.vars };
    let pwd = expr.eval_pwd(&env).ok()?;
    Some((workspace.base_path.join(pwd), prefix))
}

fn print_completions(context: cli::CompleteContext) -> bool {
    match context {
        cli::CompleteContext::Commands => {
            println!("global\tOpen global workspace selector");
            println!("run\tRun a task and display output");
            println!("exec\tExecute task directly, bypassing daemon");
            println!("start\tStart a task via daemon");
            println!("restart\tRestart a task via daemon");
            println!("restart-selected\tRestart selected task in TUI");
            println!("stop\tTerminate a running task");
            println!("status\tShow active tasks or task/group status");
            println!("test\tRun tests with optional filters");
            println!("logs\tView and stream logs");
            println!("self\tRun devsm self-management commands");
            println!("get\tGet information from daemon");
            println!("function\tCall a saved function");
            println!("completions\tPrint shell completion script");
            true
        }
        cli::CompleteContext::Tasks => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            print_task_completions(&workspace);
            true
        }
        cli::CompleteContext::Runnables => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            print_task_completions(&workspace);
            for (name, calls) in workspace.groups {
                let desc = group_description(calls);
                let task_with_same_name = workspace.tasks.iter().any(|(n, _)| n == name);
                let bare_visible = !is_builtin_command_name(name) && !task_with_same_name;
                if bare_visible {
                    print_completion(name, Some(&desc));
                }
                print_completion(&format!("group.{name}"), Some(&desc));
            }
            true
        }
        cli::CompleteContext::Tests => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            for (name, test) in workspace.tests {
                let info = test.info;
                print_completion(name, Some(info));
            }
            true
        }
        cli::CompleteContext::Profiles { task } => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            let short = match task.split_once('.') {
                Some(("service" | "action" | "test", rest)) => rest,
                _ => task,
            };
            let Some((_, expr)) = workspace.tasks.iter().find(|(n, _)| *n == short) else {
                return false;
            };
            let preview = expr.command_preview();
            for profile in expr.profiles {
                print_completion(&format!("{task}:{profile}"), Some(preview));
            }
            true
        }
        cli::CompleteContext::Vars { task, exclude } => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            let short = match task.split_once('.') {
                Some(("service" | "action" | "test", rest)) => rest,
                _ => task,
            };
            let Some((_, expr)) = workspace.tasks.iter().find(|(n, _)| *n == short) else {
                return false;
            };
            print_task_var_completions(expr, &exclude);
            true
        }
        cli::CompleteContext::ForwardPrefix { task } => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            let Some((expr, _)) = resolve_completion_task_expr(&workspace, task) else {
                return false;
            };
            if let Some(prefix) = expr.autocomplete_forward_prefix() {
                for arg in prefix {
                    println!("{arg}");
                }
            }
            true
        }
        cli::CompleteContext::TaskArgs { task, exclude, args } => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            if let Some((cwd, prefix)) = forward_completion_spec(&workspace, task) {
                println!("forward");
                println!("{}", cwd.display());
                for arg in prefix {
                    println!("{arg}");
                }
                return true;
            }

            let Some((expr, _)) = resolve_completion_task_expr(&workspace, task) else {
                return false;
            };
            let (_, profile) = task.rsplit_once(':').unwrap_or((task, ""));
            if let Some(items) = completion::complete_schema_task(&workspace, expr, task, profile, args) {
                println!("items");
                for item in items {
                    print_completion(&item.value, item.description.as_deref());
                }
                return true;
            }
            if matches!(expr.cli.autocomplete, config::CliAutocomplete::Forward) {
                return true;
            }
            println!("vars");
            print_task_var_completions(expr, &exclude);
            true
        }
        cli::CompleteContext::Groups => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            for (name, calls) in workspace.groups {
                let desc = group_description(calls);
                let task_with_same_name = workspace.tasks.iter().any(|(n, _)| n == name);
                if !task_with_same_name && !is_builtin_command_name(name) {
                    print_completion(name, Some(&desc));
                }
                print_completion(&format!("group.{name}"), Some(&desc));
            }
            true
        }
        cli::CompleteContext::Functions => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            for func in workspace.functions {
                print_completion(func.name, Some(&function_description(&func.action)));
            }
            true
        }
        cli::CompleteContext::Tags => {
            let Ok(workspace) = config::load_from_env() else {
                return false;
            };
            let mut counts: hashbrown::HashMap<&str, (u32, u32)> = hashbrown::HashMap::default();
            for (_, expr) in workspace.tasks {
                for tag in expr.tags {
                    counts.entry(tag).or_default().0 += 1;
                }
            }
            for (_, test) in workspace.tests {
                for tag in test.tags {
                    counts.entry(tag).or_default().1 += 1;
                }
            }
            for (tag, (tasks, tests)) in counts {
                print_completion(tag, Some(&tag_description(tasks, tests)));
            }
            true
        }
        cli::CompleteContext::GetResources => {
            println!("workspace\tWorkspace resources");
            println!("workspaces\tList known workspaces");
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

fn print_help_topic(topic: cli::HelpTopic) {
    match topic {
        cli::HelpTopic::General => print_help(),
        cli::HelpTopic::Global => print!(
            "\
Usage: devsm global

Open the global workspace selector.
"
        ),
        cli::HelpTopic::Run => print!(
            "\
Usage: devsm run [OPTIONS] <job> [args]

Run a job and display its output.

Options:
  --as-test             Run the job as part of a test group
  --derive-cache-key    Trace and write cache.key into devsm.toml
  -h, --help            Print this help message

Job parameters may be passed before <job> as --key=value flags or JSON.
Arguments after <job> are passed through to the task.
"
        ),
        cli::HelpTopic::Exec => print!(
            "\
Usage: devsm exec <job> [args]

Execute a task directly, bypassing the daemon.

Options:
  -h, --help            Print this help message
"
        ),
        cli::HelpTopic::Start => print!(
            "\
Usage: devsm start [OPTIONS] <job> [params]

Start a job via the daemon without restarting an active matching job.

Options:
  --as-test             Run the job as part of a test group
  --cached              Skip start if cache support says the job is current
  -h, --help            Print this help message
"
        ),
        cli::HelpTopic::Restart => print!(
            "\
Usage: devsm restart [OPTIONS] <job> [params]

Restart a job via the daemon.

Options:
  --as-test             Run the job as part of a test group
  --cached              Skip restart if cache support says the job is current
  -h, --help            Print this help message
"
        ),
        cli::HelpTopic::RestartSelected => print!(
            "\
Usage: devsm restart-selected

Restart the currently selected task in an active TUI session.
"
        ),
        cli::HelpTopic::Stop => print!(
            "\
Usage: devsm stop <task>

Terminate a running task by name or job index.

Options:
  -h, --help            Print this help message
"
        ),
        cli::HelpTopic::Status => print!(
            "\
Usage: devsm status [name]

Show active tasks when no name is provided. With a name, show status for a task
or group.

Options:
  -h, --help            Print this help message
"
        ),
        cli::HelpTopic::Test => print!(
            "\
Usage: devsm test [OPTIONS] [filters]

Run tests with optional filters.

Filters:
  +tag                  Include tests with this tag
  -tag                  Exclude tests with this tag
  name                  Include tests matching this name

Options:
  --force, --no-cache   Run matching tests even when cache would skip them
  -h, --help            Print this help message
"
        ),
        cli::HelpTopic::RerunTests => print!(
            "\
Usage: devsm rerun-tests [OPTIONS]

Rerun the previous test group.

Options:
  --only-failed         Only rerun failed tests
  -h, --help            Print this help message
"
        ),
        cli::HelpTopic::Logs => print!(
            "\
Usage: devsm logs [OPTIONS] [PATTERN]

View and stream logs from tasks.

Options:
  --max-age=DURATION     Show logs since DURATION ago (5s, 10m, 1h)
  --task=NAME[@latest]   Filter by task name (repeatable)
  --kind=KIND[@latest]   Filter by kind: service, action, test (repeatable)
  --job=INDEX            Filter by job index
  --follow, -f           Stream new logs
  --retry                With @latest, wait for next job
  --oldest=N             Show oldest N lines
  --newest=N             Show newest N lines
  --without-taskname     Omit task name prefixes
  -h, --help             Print this help message
"
        ),
        cli::HelpTopic::Get => print!(
            "\
Usage: devsm get <resource>

Resources:
  workspace config-path  Get config file path
  workspaces [--json]    List known workspaces
  default-user-config    Print default user config
  logged-rust-panics     Show logged Rust panics from daemon
"
        ),
        cli::HelpTopic::GetWorkspace => print!(
            "\
Usage: devsm get workspace <resource>

Resources:
  config-path            Get config file path
"
        ),
        cli::HelpTopic::GetWorkspaceConfigPath => print!(
            "\
Usage: devsm get workspace config-path

Print the current workspace devsm.toml path.
"
        ),
        cli::HelpTopic::GetWorkspaces => print!(
            "\
Usage: devsm get workspaces [OPTIONS]

List known workspaces, sorted by last loaded.

Options:
  --json                 Output JSON
  -h, --help             Print this help message
"
        ),
        cli::HelpTopic::GetDefaultUserConfig => print!(
            "\
Usage: devsm get default-user-config

Print the default user config.
"
        ),
        cli::HelpTopic::GetLoggedRustPanics => print!(
            "\
Usage: devsm get logged-rust-panics

Show logged Rust panics from the daemon.
"
        ),
        cli::HelpTopic::Function => print!(
            "\
Usage: devsm function <command>

Commands:
  call <name>            Call a function defined in config
"
        ),
        cli::HelpTopic::FunctionCall => print!(
            "\
Usage: devsm function call <name>

Call a function defined in config.
"
        ),
        cli::HelpTopic::Completions => print!(
            "\
Usage: devsm completions <shell>

Print a shell completion script.

Shells:
  bash
  fish
  zsh
"
        ),
        cli::HelpTopic::SelfCommand => print!(
            "\
Usage: devsm self <command>

Commands:
  server                 Start the daemon process
  validate [path]        Validate a config file
  logs [-f]              Retrieve daemon logs
  complete <ctx>         Output completion data for shell scripts
"
        ),
        cli::HelpTopic::SelfServer => print!(
            "\
Usage: devsm self server

Start the daemon process.
"
        ),
        cli::HelpTopic::SelfValidate => print!(
            "\
Usage: devsm self validate [OPTIONS] [path]

Validate a config file.

Options:
  --skip-path-checks     Skip validation of pwd paths
  -h, --help             Print this help message
"
        ),
        cli::HelpTopic::SelfLogs => print!(
            "\
Usage: devsm self logs [OPTIONS]

Retrieve daemon logs.

Options:
  --follow, -f           Stream new logs
  -h, --help             Print this help message
"
        ),
        cli::HelpTopic::SelfComplete => print!(
            "\
Usage: devsm self complete <context> [OPTIONS]

Output completion data for shell scripts.

Contexts:
  commands, tasks, runnables, tests, profiles, vars, forward-prefix,
  task-args, groups, functions, tags, get-resources, kinds
"
        ),
    }
}

fn print_help() {
    print!(
        "\
devsm - TUI development service manager

Usage: devsm [OPTIONS] [COMMAND]

Commands:
  (default)          Launch the TUI interface (or workspace selector if not in a workspace)
  <task> [args]      Run a task by name; uses exec automatically for managed = false
  global             Open global workspace selector
  run <job>          Run a job and display its output
                     --derive-cache-key: trace and write cache.key into devsm.toml
  exec <job>         Execute a task directly, bypassing the daemon
  start <job>        Start a job via the daemon without restarting an active matching job
  restart <job>      Restart a job via the daemon
  restart-selected   Restart the currently selected task in TUI
  stop <task>        Terminate a running task (by name or index)
  status [name]      Show active tasks, or status of a task/group
  test [options] [filters]
                     Run tests with optional filters
  logs [options]     View and stream logs from tasks
  get <resource>     Get information from the daemon
  function call <n>  Call a function defined in config
  completions <shell> Print shell completion script (bash | fish | zsh)
  self <command>     Run devsm self-management commands

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

Test Options:
  --force, --no-cache  Run matching tests even when cache would skip them

Validate Options:
  --skip-path-checks     Skip validation of pwd paths

Start/Restart Options:
  --cached               Skip restart if task has cache support and cache key matches

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
  workspace config-path  Get config file path
  workspaces [--json]    List known workspaces (sorted by last loaded)
  default-user-config    Print default user config (keybindings)
  logged-rust-panics     Show logged Rust panics from daemon

Self Commands:
  self server            Start the daemon process (internal)
  self validate [path]   Validate a config file
  self logs [-f]         Retrieve daemon logs (-f/--follow to tail)
  self complete <ctx>    Output completion data for shell scripts

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
