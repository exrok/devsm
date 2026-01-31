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
}

impl Default for LogTailWidget {
    fn default() -> Self {
        Self { tail: Default::default(), next_screen_offset: Default::default(), previous: Rect::EMPTY }
    }
}

impl LogTailWidget {
    pub fn render(&mut self, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        if rect != self.previous {
            self.previous = rect;
            self.next_screen_offset = render_buffer_tail_reset(buf, rect, view, style);
            self.tail = view.tail;
            return;
        }
        if rect.h == 0 || self.tail >= view.tail {
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
}
