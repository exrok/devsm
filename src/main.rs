use std::{
    io::{ErrorKind, Read, Write},
    os::unix::{net::UnixStream, process::CommandExt},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::bail;
use sendfd::SendWithFd;

use crate::daemon::{GLOBAL_SOCKET, WorkspaceCommand};

mod cli;
mod collection;
mod config;
mod daemon;
mod keybinds;
mod line_width;
mod log_fowarder_ui;
mod log_storage;
mod process_manager;
mod scroll_view;
mod searcher;
mod test_summary_ui;
mod tui;
mod user_config;
mod workspace;

fn main() {
    let mut args = std::env::args();
    args.next();
    let args = args.collect::<Vec<_>>();
    let (_config, command) = cli::parse(&args).unwrap();
    match command {
        cli::Command::Cli => {
            let _log_guard = kvlog::collector::init_file_logger("/tmp/.client.devsm.log");
            client().unwrap();
            return;
        }
        cli::Command::Server => {
            let _log_guard = kvlog::collector::init_file_logger("/tmp/.devsm.log");
            if let Err(err) = daemon::worker() {
                kvlog::error!("Daemon terminated with error", ?err);
            }
        }
        cli::Command::RestartSelected => {
            workspace_command(WorkspaceCommand::RestartSelected).unwrap();
        }
        cli::Command::Restart { job, value_map } => {
            workspace_command(WorkspaceCommand::Run { name: job.into(), params: value_map }).unwrap()
        }
        cli::Command::Exec { job, value_map } => {
            if let Err(err) = exec_task(job, value_map) {
                eprintln!("exec failed: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Run { job, value_map } => {
            let _log_guard = kvlog::collector::init_file_logger("/tmp/.client.devsm.log");
            if let Err(err) = run_client(job, value_map) {
                eprintln!("run failed: {}", err);
                std::process::exit(1);
            }
        }
        cli::Command::Test { filters } => {
            let _log_guard = kvlog::collector::init_file_logger("/tmp/.client.devsm.log");
            if let Err(err) = test_client(filters) {
                eprintln!("test failed: {}", err);
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

    // Convert filters to TestFilters for IPC
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

    let mut buf = [0u8; 4];

    loop {
        let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);

        if flags & TERMINATION_FLAG != 0 {
            socket.write_all(&TERMINATION_CODE.to_ne_bytes())?;
        }

        match socket.read(&mut buf) {
            Ok(0) => break,
            Ok(4) => {
                let code = u32::from_ne_bytes(buf);
                if code == TERMINATION_CODE {
                    break;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => bail!("Socket read failed: {}", e),
        }
    }

    Ok(())
}

const RESIZE_CODE: u32 = 0x85_06_09_44;
const TERMINATION_CODE: u32 = 0xcf_04_43_58;

const STATUS_RESTARTING: u32 = 0x01_52_53_54;
const STATUS_WAITING: u32 = 0x02_57_41_54;
const STATUS_RUNNING: u32 = 0x03_52_55_4e;
const STATUS_EXITED: u32 = 0x04_45_58_54;

// Bit 0 is for termination, Bit 1 is for resize
const TERMINATION_FLAG: u64 = 1 << 0;
const RESIZE_FLAG: u64 = 1 << 1;

static SIGNAL_FLAGS: AtomicU64 = AtomicU64::new(0);

// Signal handler for termination signals (SIGINT, SIGTERM)
extern "C" fn term_handler(_sig: i32) {
    SIGNAL_FLAGS.fetch_or(TERMINATION_FLAG, Ordering::Relaxed);
}

// Signal handler for window resize signal (SIGWINCH)
extern "C" fn winch_handler(_sig: i32) {
    SIGNAL_FLAGS.fetch_or(RESIZE_FLAG, Ordering::Relaxed);
}

// Helper function to set up a signal handler using libc::sigaction
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

fn connect_or_spawn_daemon() -> std::io::Result<UnixStream> {
    if let Ok(socket) = UnixStream::connect(GLOBAL_SOCKET) {
        return Ok(socket);
    }
    let current_exe = std::env::current_exe()?;
    let mut command = std::process::Command::new(current_exe);
    command.arg("server");
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(|| {
            // setsid() creates a new session and detaches the process from
            // the controlling terminal of the parent (the client).
            // This prevents SIGTTOU when the daemon tries to configure the
            // client's TTY later.
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    command.spawn()?;
    for _ in 0..1000 {
        std::thread::sleep(Duration::from_millis(1));
        if let Ok(socket) = UnixStream::connect(GLOBAL_SOCKET) {
            return Ok(socket);
        }
    }
    Err(std::io::Error::new(ErrorKind::TimedOut, "Failed to connect to daemon"))
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

fn client() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    // Register the signal handlers using libc directly
    setup_signal_handler(libc::SIGTERM, term_handler)?;
    setup_signal_handler(libc::SIGINT, term_handler)?;
    setup_signal_handler(libc::SIGWINCH, winch_handler)?;

    let mut socket = connect_or_spawn_daemon()?;

    // socket.write_all()?;
    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::AttachTui { config: &config },
        }),
        &[0, 1],
    )?;

    let mut buf = [0; 4];

    loop {
        let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);

        if flags & TERMINATION_FLAG != 0 {
            socket.write_all(&TERMINATION_CODE.to_ne_bytes())?;
            return Ok(());
        }

        if flags & RESIZE_FLAG != 0 {
            socket.write_all(&RESIZE_CODE.to_ne_bytes())?;
        }
        match socket.read(&mut buf) {
            Ok(amount) => {
                if amount == 0 {
                    break;
                }
                let received_code = u32::from_ne_bytes(buf);
                if received_code == TERMINATION_CODE {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                kvlog::info!("Interuped")
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
            // Enable canonical mode and echo
            termios.c_lflag |= libc::ICANON | libc::ECHO | libc::ISIG;
            // Restore input processing
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

    let mut buf = [0u8; 4];
    let mut exit_status: Option<i32> = None;
    let mut terminated_by_user = false;

    loop {
        let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);

        if flags & TERMINATION_FLAG != 0 {
            terminated_by_user = true;
            socket.write_all(&TERMINATION_CODE.to_ne_bytes())?;
        }

        match socket.read(&mut buf) {
            Ok(0) => break,
            Ok(4) => {
                let code = u32::from_ne_bytes(buf);
                match code {
                    TERMINATION_CODE => {
                        if terminated_by_user {
                            if let Some(status) = exit_status {
                                eprintln!("Task terminated (exit code {})", status);
                            } else {
                                eprintln!("Task terminated");
                            }
                        } else if let Some(status) = exit_status {
                            eprintln!("Task exited (code {})", status);
                        }
                        break;
                    }
                    STATUS_RESTARTING => eprintln!("Terminating previous run..."),
                    STATUS_WAITING => eprintln!("Waiting for dependencies..."),
                    STATUS_RUNNING => eprintln!("Task started"),
                    STATUS_EXITED => {
                        let mut exit_buf = [0u8; 4];
                        if let Ok(4) = socket.read(&mut exit_buf) {
                            exit_status = Some(i32::from_ne_bytes(exit_buf));
                        }
                    }
                    _ => {}
                }
            }
            Ok(_) => {}
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

    let env = config::Enviroment { profile, param: params };
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
