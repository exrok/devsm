use super::*;

use crate::log_storage::LogView;

use extui::Rect;

use crate::log_storage::LogId;

#[derive(Debug)]
pub struct LogTailWidget {
    /// The last LineId that has been processed in ids.
    pub(crate) tail: LogId,
    pub(crate) next_screen_offset: u16,
    /// The last rectangle that has been rendered, zero height rects will not rendering anything,
    /// to force a full rerender set the previous to an Empty rectangle
    pub(crate) previous: Rect,
    /// Last skip_rect (log-overlay cutout) honored by this widget. A change
    /// forces a full reset and hardware-scroll deltas are disabled while
    /// skip_rect is active so the overlay cells aren't shifted.
    pub(crate) last_skip_rect: Option<Rect>,
    /// Last full-line log selection rendered by this widget.
    pub(crate) last_selection: Option<LogSelection>,
}

impl Default for LogTailWidget {
    fn default() -> Self {
        Self {
            tail: Default::default(),
            next_screen_offset: Default::default(),
            previous: Rect::EMPTY,
            last_skip_rect: None,
            last_selection: None,
        }
    }
}

impl LogTailWidget {
    pub fn render(&mut self, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        if rect != self.previous || self.last_skip_rect != style.skip_rect || self.last_selection != style.selection {
            self.previous = rect;
            self.last_skip_rect = style.skip_rect;
            self.last_selection = style.selection.clone();
            self.next_screen_offset = render_buffer_tail_reset(buf, rect, view, style);
            self.tail = view.tail;
            return;
        }
        if rect.h == 0 || self.tail >= view.tail {
            self.tail = view.tail;
            return;
        }
        if style.skip_rect.is_some() {
            self.next_screen_offset = render_buffer_tail_reset(buf, rect, view, style);
            self.tail = view.tail;
            return;
        }
        vt::ScrollRegion(rect.y + 1, rect.y + rect.h).write_to_buffer(buf);

        let mut first = false;
        if rect.y + self.next_screen_offset == 0 {
            vt::MoveCursor(rect.x, 0).write_to_buffer(buf);
            first = true;
        } else {
            vt::MoveCursor(rect.x, rect.y + self.next_screen_offset - 1).write_to_buffer(buf);
        }
        let mut offset = self.next_screen_offset as u32;
        view.for_each_forward(self.tail, &mut |_log_id, entry| {
            offset += get_entry_height(entry, style, rect.w as u32);
            if first {
                first = false
            } else {
                buf.extend_from_slice(b"\n\r");
            }

            let prefix = style.prefix(entry.log_group);
            let prefix_width = prefix.map(|p| p.width).unwrap_or(0);
            let prefix_bytes = prefix.map(|p| p.bytes.as_bytes()).unwrap_or(b"");

            let text = unsafe { entry.text(view.logs) };

            if entry.width as usize + prefix_width <= rect.w as usize {
                if !prefix_bytes.is_empty() {
                    buf.extend_from_slice(prefix_bytes);
                }
                entry.style.write_to_buffer(buf);
                buf.extend_from_slice(text.as_bytes());
                vt::CLEAR_STYLE.write_to_buffer(buf);
                if !style.assume_blank {
                    buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
                }
            } else {
                let limit = (rect.w as usize).saturating_sub(prefix_width);
                let mut splitter = line_width::naive_line_splitting(text, entry.style, limit);
                let mut first_line_len = 0;

                if let Some((line, l_style)) = splitter.next() {
                    first_line_len = line.len();
                    if !prefix_bytes.is_empty() {
                        buf.extend_from_slice(prefix_bytes);
                    }
                    l_style.write_to_buffer(buf);
                    buf.extend_from_slice(line.as_bytes());
                    if !style.assume_blank {
                        buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
                    }
                }

                if first_line_len < text.len() {
                    let rest = &text[first_line_len..];
                    for (line, _) in line_width::naive_line_splitting(rest, entry.style, rect.w.into()) {
                        buf.extend_from_slice(b"\r\n");
                        buf.extend_from_slice(line.as_bytes());
                        if !style.assume_blank {
                            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
                        }
                    }
                }
                vt::CLEAR_STYLE.write_to_buffer(buf);
            }
            std::ops::ControlFlow::Continue(())
        });

        vt::ScrollRegion::RESET.write_to_buffer(buf);
        if offset > rect.h as u32 {
            offset = rect.h as u32
        }
        self.next_screen_offset = offset as u16;
        self.tail = view.tail;
    }

    pub fn log_id_at_row(&self, view: &LogView, style: &LogStyle, rect: Rect, row: u16) -> Option<LogId> {
        if rect.w == 0 || row >= rect.h {
            return None;
        }

        let mut displayed: Vec<(LogId, LogEntry)> = Vec::new();
        let mut remaining_v_space = rect.h as i32;

        view.for_each_rev(view.logs.head(), &mut |log_id, entry| {
            remaining_v_space -= get_entry_height(entry, style, rect.w as u32) as i32;
            displayed.push((log_id, *entry));
            if remaining_v_space <= 0 { std::ops::ControlFlow::Break(()) } else { std::ops::ControlFlow::Continue(()) }
        });

        let mut current_row = 0u16;
        let mut entries = displayed.iter().rev();

        if remaining_v_space < 0
            && let Some((log_id, entry)) = entries.next()
        {
            let skip = (-remaining_v_space) as u16;
            let visible = (get_entry_height(entry, style, rect.w as u32) as u16)
                .saturating_sub(skip)
                .min(rect.h.saturating_sub(current_row));
            if row < current_row + visible {
                return Some(*log_id);
            }
            current_row += visible;
        }

        for (log_id, entry) in entries {
            if current_row >= rect.h {
                return None;
            }
            let visible = (get_entry_height(entry, style, rect.w as u32) as u16).min(rect.h - current_row);
            if row < current_row + visible {
                return Some(*log_id);
            }
            current_row += visible;
        }

        None
    }
}
