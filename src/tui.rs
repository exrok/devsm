use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;
use std::sync::Arc;

use vtui::event::polling::GlobalWakerConfig;
use vtui::event::{Event, KeyCode, KeyModifiers};
use vtui::vt::BufferWrite;
use vtui::{Color, Rect, Style, TerminalFlags, vt};

use crate::log_storage::{JobId, LogFilter};
use crate::process_manager::{self, VtuiChannel};
use crate::scroll_view::{LogStyle, LogWidget};
use crate::workspace::Workspace;

pub fn run(
    stdin: OwnedFd,
    stdout: OwnedFd,
    workspace: Arc<Workspace>,
    vtui_channel: Arc<VtuiChannel>,
) -> anyhow::Result<()> {
    let mode = TerminalFlags::RAW_MODE
        | TerminalFlags::ALT_SCREEN
        | TerminalFlags::HIDE_CURSOR
        | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
    let mut terminal = vtui::Terminal::new(stdout.as_raw_fd(), mode)?;
    let mut events = vtui::event::parse::Events::default();
    use std::io::Write;
    let mut buf = Vec::new();
    vt::move_cursor_to_origin(&mut buf);
    buf.extend_from_slice(vt::CLEAR_BELOW);
    terminal.write_all(&buf)?;
    let mut log_widget = LogWidget::default();
    let mut scroll_request: Option<i32> = None;
    let mut show_job = 0;
    let (w, h) = terminal.size()?;
    let mut render_frame = vtui::DoubleBuffer::new(w, 20);
    render_frame.y_offset = h - 20;
    let mut base_task_selected = 0;
    let style = LogStyle::default();
    loop {
        let filter = if show_job > 0 {
            LogFilter::Job(JobId(show_job))
        } else {
            LogFilter::All
        };
        let logs = workspace.logs.read().unwrap();
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
                log_widget.scroll_down(
                    -scroll_request as u32,
                    &mut buf,
                    dest,
                    logs.view(filter),
                    &style,
                );
            } else if scroll_request > 0 {
                log_widget.scroll_up(
                    scroll_request as u32,
                    &mut buf,
                    dest,
                    logs.view(filter),
                    &style,
                );
            }
        }
        {
            if let LogWidget::Tail(tail) = &mut log_widget {
                tail.render(&mut buf, dest, logs.view(filter), &style);
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
        {
            let state = workspace.state();
            for (i, task) in state.base_tasks.iter().enumerate() {
                bot.take_top(1)
                    .with(if i == base_task_selected {
                        Color(3).with_fg(Color(236))
                    } else {
                        Color(248).as_fg()
                    })
                    .fill(&mut render_frame)
                    .text(&mut render_frame, &task.name);
            }
        }

        render_frame.render(&mut terminal);

        match vtui::event::poll_with_custom_waker(&stdin, Some(&vtui_channel.waker), None)? {
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
                        (_, Char('r')) => {
                            workspace.spawn_task_simple_from_base_task(base_task_selected);
                        }
                        (CTRL, Char('k')) => {
                            if let Some(value) = scroll_request {
                                scroll_request = Some(value + 1);
                            } else {
                                scroll_request = Some(1);
                            }
                        }
                        (CTRL, Char('j')) => {
                            if let Some(value) = scroll_request {
                                scroll_request = Some(value - 1);
                            } else {
                                scroll_request = Some(-1);
                            }
                        }
                        (_, Char('k')) => {
                            base_task_selected = base_task_selected.saturating_sub(1);
                        }
                        (_, Char('j')) => {
                            base_task_selected = (base_task_selected + 1)
                                .min(workspace.state().base_tasks.len() - 1);
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
