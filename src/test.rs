// fn main() -> anyhow::Result<()> {
//     let _log_guard = kvlog::collector::init_file_logger("/tmp/.dfj.log");
//     let resp = Arc::new(CrosstermChannel {
//         waker: vtui::event::polling::resize_waker().unwrap(),
//         events: Mutex::new(Vec::new()),
//     });
//     let mode = TerminalFlags::RAW_MODE
//         | TerminalFlags::MOUSE_CAPTURE
//         | TerminalFlags::ALT_SCREEN
//         | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
//     let mut terminal = vtui::Terminal::open(mode).expect("Valid TTY");
//     let mut events = vtui::event::parse::Events::default();
//     use std::io::Write;
//     let mut buf = Vec::new();
//     vt::move_cursor_to_origin(&mut buf);
//     buf.extend_from_slice(vt::CLEAR_BELOW);

//     terminal.write_all(&buf)?;
//     let stdin = std::io::stdin();
//     let mut line_buffer = log_storage::LogWriter::new();
//     let mut view = LogWidget::Tail(LogTailWidget::default());
//     for i in 0..10 {
//         let text = format!("Initial line number {}", i);
//         line_buffer.push_line(&text, text.len() as u32, JobId(1), Style::DEFAULT);
//     }
//     let reader = line_buffer.reader();
//     let mut add_next = false;
//     let mut scroll_request: Option<i32> = None;
//     let (w, h) = terminal.size()?;
//     let mut render_frame = DoubleBuffer::new(w, 20);
//     render_frame.y_offset = h - 20;
//     let mut last_event = String::new();
//     loop {
//         let (w, h) = terminal.size()?;
//         let dest = Rect {
//             x: 0,
//             y: 5,
//             width: w,
//             height: 5,
//         };
//         vt::move_cursor(&mut buf, 0, dest.y - 1);
//         Style::DEFAULT.delta().write_to_buffer(&mut buf);
//         for i in 0..w {
//             buf.push(b'=');
//         }
//         vt::move_cursor(&mut buf, 0, dest.y + dest.height);
//         for i in 0..w {
//             buf.push(b'=');
//         }
//         if let Some(scroll_request) = scroll_request.take() {
//             let reader = reader.read().unwrap();
//             if scroll_request < 0 {
//                 view.scroll_down(-scroll_request as u32, &mut buf, dest, reader.view_all());
//             } else if scroll_request > 0 {
//                 view.scroll_up(scroll_request as u32, &mut buf, dest, reader.view_all());
//             }
//         }
//         {
//             let reader = reader.read().unwrap();
//             if let LogWidget::Tail(tail) = &mut view {
//                 tail.render(&mut buf, dest, reader.view_all());
//             }
//         }
//         terminal.write_all(&buf)?;
//         render_frame.set_stringn(5, 10, "hellosadfkk", 6, Color(33).as_fg());
//         render_frame.set_string(5, 11, &last_event, Color(35).as_fg());
//         render_frame.render(&mut terminal);
//         buf.clear();
//         match vtui::event::poll(&stdin, None)? {
//             vtui::event::Polled::ReadReady => {
//                 events.read_from(&stdin)?;
//             }
//             vtui::event::Polled::Woken => {
//                 // resize event
//             }
//             vtui::event::Polled::TimedOut => {}
//         }
//         while let Some(event) = events.next(terminal.is_raw()) {
//             last_event = format!("{:?}", event);
//             if add_next {
//                 add_next = false;
//                 line_buffer.push_line(
//                     &last_event,
//                     last_event.len() as u32,
//                     JobId(3),
//                     Style::DEFAULT,
//                 );
//             }
//             match event {
//                 Event::Key(key_event) => {
//                     use KeyCode::*;
//                     const CTRL: KeyModifiers = KeyModifiers::CONTROL;
//                     // const NORM: KeyModifiers = KeyModifiers::empty();

//                     match (key_event.modifiers, key_event.code) {
//                         (CTRL, Char('c')) => return Ok(()),
//                         (_, Char('n')) => add_next = true,
//                         (_, Char('k')) => {
//                             if let Some(value) = scroll_request {
//                                 scroll_request = Some(value + 1);
//                             } else {
//                                 scroll_request = Some(1);
//                             }
//                         }
//                         (_, Char('j')) => {
//                             if let Some(value) = scroll_request {
//                                 scroll_request = Some(value - 1);
//                             } else {
//                                 scroll_request = Some(-1);
//                             }
//                         }
//                         _ => (),
//                     }
//                 }
//                 Event::Resized => (),
//                 _ => (),
//             }
//         }
//     }

//     Ok(())
// }
