use std::os::unix::process::CommandExt;
use std::process::Command;
use vtui::event::polling::GlobalWakerConfig;
use vtui::event::{Event, KeyCode, KeyModifiers};
use vtui::vt::BufferWrite;
use vtui::{Color, Rect, Style, TerminalFlags, vt};

use crate::config::{BumpEval, TaskConfig, WorkspaceConfig, load_from_env};
use crate::log_storage::{JobId, LogFilter};
use crate::scroll_view::LogWidget;

mod config;
mod line_width;
mod log_storage;
mod process_manager;
mod scroll_view;

fn unmanaged_exec(ws: &WorkspaceConfig, task: &TaskConfig) {
    let [cmd, args @ ..] = task.cmd else {
        panic!("Expected atleast one command")
    };
    let path = ws.base_path.join(task.pwd);
    println!("in {:?}", path);
    let _ = std::process::Command::new(cmd)
        .args(args)
        .current_dir(path)
        .envs(task.envvar.iter().copied())
        .exec();
    panic!()
}

fn main() {
    let config = load_from_env().unwrap();
    let mut args = std::env::args();
    args.next();
    let arg = args.next().expect("Arg");
    let (task, profile) = arg.rsplit_once(":").unwrap_or((&arg, ""));
    let task = config.task_by_name(task).expect("Unknown task");
    let bump = bumpalo::Bump::new();
    let task = task.eval(&config::Enviroment { profile }, &bump).unwrap();
    unmanaged_exec(&config, &task);
}
fn main2() -> anyhow::Result<()> {
    let _log_guard = kvlog::collector::init_file_logger("/tmp/.dfj.log");
    let waker = vtui::event::polling::initialze_global_waker(GlobalWakerConfig {
        resize: true,
        termination: true,
    })?;
    let manager = process_manager::ProcessManagerHandle::spawn(waker)?;

    let mut comm = Command::new("ls");
    // comm.arg("run")
    // .args([
    //     "--",
    //     "--config",
    //     "../libra.sim.config.js",
    //     "--config",
    //     "../libra.config.js",
    // ])
    comm.current_dir("/home/user/am/libra/backend")
        .env("CARGO_TERM_COLOR", "always");
    manager
        .request
        .send(process_manager::ProcessRequest::Spawn {
            command: Box::new(comm),
            job_id: JobId(1),
        });
    // let mut comm = Command::new("cargo");
    // comm.arg("run")
    //     .current_dir("/home/user/am/libra/projects/libra_simulation/sim_server")
    //     .env("CARGO_TERM_COLOR", "always");
    // manager
    //     .request
    //     .send(process_manager::ProcessRequest::Spawn {
    //         command: Box::new(comm),
    //         job_id: JobId(2),
    //     });
    // let mut comm = Command::new("cargo");
    // comm.arg("run")
    //     .current_dir("/home/user/am/libra/projects/video_gateway/server")
    //     .env("CARGO_TERM_COLOR", "always");
    // manager
    //     .request
    //     .send(process_manager::ProcessRequest::Spawn {
    //         command: Box::new(comm),
    //         job_id: JobId(3),
    //     });
    // let mut comm = Command::new("./run.prisons.sh");
    // comm.current_dir("/home/user/am/libra/frontend/app")
    //     .env("FORCE_COLOR", "2");

    // manager
    //     .request
    //     .send(process_manager::ProcessRequest::Spawn {
    //         command: Box::new(comm),
    //         job_id: JobId(4),
    // });

    let mode = TerminalFlags::RAW_MODE
        | TerminalFlags::ALT_SCREEN
        | TerminalFlags::HIDE_CURSOR
        | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
    let mut terminal = vtui::Terminal::open(mode).expect("Valid TTY");
    let mut events = vtui::event::parse::Events::default();
    use std::io::Write;
    let mut buf = Vec::new();
    vt::move_cursor_to_origin(&mut buf);
    buf.extend_from_slice(vt::CLEAR_BELOW);
    terminal.write_all(&buf)?;
    let stdin = std::io::stdin();
    let mut log_widget = LogWidget::default();
    let mut scroll_request: Option<i32> = None;
    let mut show_job = 0;
    let (w, h) = terminal.size()?;
    let mut render_frame = vtui::DoubleBuffer::new(w, 20);
    render_frame.y_offset = h - 20;
    loop {
        let filter = if show_job > 0 {
            LogFilter::Job(JobId(show_job))
        } else {
            LogFilter::All
        };
        let logs = manager.logs.read().unwrap();
        // start = lines.for_each_from(start, |_, j, text, _| std::ops::ControlFlow::Continue(()));
        let (w, h) = terminal.size()?;
        buf.clear();
        Style::DEFAULT.delta().write_to_buffer(&mut buf);
        let dest = Rect {
            x: 0,
            y: 0,
            width: w,
            height: h - 20,
        };
        if let Some(scroll_request) = scroll_request.take() {
            if scroll_request < 0 {
                log_widget.scroll_down(-scroll_request as u32, &mut buf, dest, logs.view(filter));
            } else if scroll_request > 0 {
                log_widget.scroll_up(scroll_request as u32, &mut buf, dest, logs.view(filter));
            }
        }
        {
            if let LogWidget::Tail(tail) = &mut log_widget {
                tail.render(&mut buf, dest, logs.view(filter));
            }
        }
        drop(logs);
        terminal.write_all(&buf)?;
        let mut bot = Rect {
            x: 0,
            y: 0,
            width: w,
            height: 20,
        };

        bot.take_top(1)
            .with(Color(2).with_fg(Color(236)))
            .fill(&mut render_frame)
            .skip(1)
            .text(
                &mut render_frame,
                match show_job {
                    1 => "Libra Webserver",
                    2 => "VGS",
                    3 => "Sim",
                    4 => "Frontend",
                    _ => "ALL",
                },
            );
        render_frame.render(&mut terminal);

        match vtui::event::poll_with_custom_waker(&stdin, Some(waker), None)? {
            vtui::event::Polled::ReadReady => {
                events.read_from(&stdin)?;
            }
            vtui::event::Polled::Woken => {}
            vtui::event::Polled::TimedOut => {}
        }
        if vtui::event::polling::termination_requested() {
            return Ok(());
        }

        while let Some(event) = events.next(terminal.is_raw()) {
            match event {
                Event::Key(key_event) => {
                    use KeyCode::*;
                    const CTRL: KeyModifiers = KeyModifiers::CONTROL;
                    // const NORM: KeyModifiers = KeyModifiers::empty();
                    match (key_event.modifiers, key_event.code) {
                        (CTRL, Char('c')) => return Ok(()),
                        (_, Char('k')) => {
                            if let Some(value) = scroll_request {
                                scroll_request = Some(value + 1);
                            } else {
                                scroll_request = Some(1);
                            }
                        }
                        (_, Char('j')) => {
                            if let Some(value) = scroll_request {
                                scroll_request = Some(value - 1);
                            } else {
                                scroll_request = Some(-1);
                            }
                        }
                        (_, Char('n')) => {
                            show_job = (show_job + 1) % 5;
                            log_widget = LogWidget::default()
                        }
                        _ => (),
                    }
                }
                Event::Resized => (),
                _ => (),
            }
        }
    }

    Ok(())
}
