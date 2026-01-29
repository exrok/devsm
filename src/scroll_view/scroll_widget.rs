use super::*;
use crate::line_width::MatchHighlight;
use crate::log_storage::LogEntry;
use crate::log_storage::LogId;
use crate::log_storage::LogView;
use extui::Rect;

#[derive(Debug)]
pub struct LogScrollWidget {
    /// The index in `ids` that has the LineId of the element at the top of the list
    pub(crate) top_index: usize,
    /// The minimum index in `ids` to be considered (lower ids are no longer in the logs)
    pub(crate) min_index: usize,
    /// The LineId's the make up the list (currently can be assumed in sorted order)
    pub(crate) ids: Vec<LogId>,
    /// The number of lines of the top element that has been scrolled up off screen
    pub(crate) scroll_shift_up: u16,
    /// The last rectangle that has been rendered, zero height rects will not render anything
    /// To force a full re-render, set this to an Empty rectangle
    pub(crate) previous: Rect,
    /// The last LineId that has been processed in ids
    pub(crate) tail: LogId,
    /// The last highlight state that was rendered
    pub(crate) last_highlight: Option<LogHighlight>,
}

impl LogScrollWidget {
    pub(crate) fn render_content(
        &self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        lines_to_render: u16,
        style: &LogStyle,
    ) -> u16 {
        let logs = view.logs.indexer();
        let mut entries = self.ids[self.top_index..].iter().map(|&id| (id, logs[id]));
        let mut remaining_height = lines_to_render;

        if let Some((log_id, entry)) = entries.next() {
            if remaining_height == 0 {
                return 0;
            }
            let rendered = render_single_entry(
                buf,
                view.logs,
                rect.w,
                &entry,
                log_id,
                self.scroll_shift_up,
                remaining_height,
                style,
                style.highlight,
            );
            remaining_height = remaining_height.saturating_sub(rendered);
        }

        for (log_id, entry) in entries {
            if remaining_height == 0 {
                break;
            }
            let rendered = render_single_entry(
                buf,
                view.logs,
                rect.w,
                &entry,
                log_id,
                0,
                remaining_height,
                style,
                style.highlight,
            );
            remaining_height = remaining_height.saturating_sub(rendered);
        }
        remaining_height
    }

    /// Renders with delta optimization when possible.
    /// Handles highlight-only changes efficiently by only re-rendering affected entries.
    pub fn render_reset_if_needed(&mut self, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        if rect == self.previous && style.highlight == self.last_highlight {
            return;
        }

        if rect == self.previous {
            self.delta_highlight_only(buf, rect, view, style);
        } else {
            self.render_reset(buf, rect, view, style);
        }
    }

    pub fn render_reset(&mut self, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        self.previous = rect;
        self.last_highlight = style.highlight;
        self.tail = view.tail;

        while let Some(id) = self.ids.get(self.top_index) {
            if *id < view.logs.head() {
                self.top_index += 1;
                self.min_index = self.top_index;
                self.scroll_shift_up = 0;
            } else {
                break;
            }
        }

        let use_batch_clear = rect.y == 0 && !style.assume_blank;

        if use_batch_clear {
            vt::MoveCursor(rect.x + rect.w, rect.y + rect.h - 1).write_to_buffer(buf);
            buf.extend_from_slice(vt::CLEAR_ABOVE);
        }

        vt::MoveCursor(rect.x, rect.y).write_to_buffer(buf);
        let remaining_height = self.render_content(buf, rect, view, rect.h, style);

        if !use_batch_clear && !style.assume_blank {
            for _ in 0..remaining_height {
                buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
                buf.extend_from_slice(b"\r\n");
            }
        }
    }

    pub(crate) fn render_top_lines(
        &self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        line_count: u16,
        style: &LogStyle,
    ) {
        vt::MoveCursor(rect.x, rect.y).write_to_buffer(buf);
        self.render_content(buf, rect, view, line_count, style);
    }

    pub(crate) fn render_bottom_lines(
        &self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        scrolled_lines: u16,
        style: &LogStyle,
    ) {
        let logs = view.logs.indexer();
        let mut entries = self.ids[self.top_index..].iter().map(|&id| (id, logs[id]));
        let mut lines_to_skip = rect.h.saturating_sub(scrolled_lines);

        let mut start_entry: Option<(LogId, LogEntry)> = None;
        let mut sub_line_skip = 0;

        if let Some((log_id, entry)) = entries.next() {
            let total_height = get_entry_height(&entry, style, rect.w as u32) as u16;
            let visible_height = total_height.saturating_sub(self.scroll_shift_up);
            if lines_to_skip < visible_height {
                start_entry = Some((log_id, entry));
                sub_line_skip = self.scroll_shift_up + lines_to_skip;
                lines_to_skip = 0;
            } else {
                lines_to_skip -= visible_height;
            }
        }

        if lines_to_skip > 0 {
            for (log_id, entry) in entries.by_ref() {
                let height = get_entry_height(&entry, style, rect.w as u32) as u16;
                if lines_to_skip < height {
                    start_entry = Some((log_id, entry));
                    sub_line_skip = lines_to_skip;
                    break;
                } else {
                    lines_to_skip -= height;
                }
            }
        }

        vt::MoveCursor(rect.x, rect.y + rect.h - scrolled_lines).write_to_buffer(buf);
        let mut remaining_height = scrolled_lines;

        if let Some((log_id, entry)) = start_entry {
            if remaining_height == 0 {
                return;
            }
            let rendered = render_single_entry(
                buf,
                view.logs,
                rect.w,
                &entry,
                log_id,
                sub_line_skip,
                remaining_height,
                style,
                style.highlight,
            );
            remaining_height = remaining_height.saturating_sub(rendered);
        }

        for (log_id, entry) in entries {
            if remaining_height == 0 {
                break;
            }
            let rendered = render_single_entry(
                buf,
                view.logs,
                rect.w,
                &entry,
                log_id,
                0,
                remaining_height,
                style,
                style.highlight,
            );
            remaining_height = remaining_height.saturating_sub(rendered);
        }
    }

    pub(crate) fn delta_scroll_up(
        &mut self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        lines: u16,
        style: &LogStyle,
    ) {
        vt::ScrollRegion(rect.y + 1, rect.y + rect.h).write_to_buffer(buf);
        extui::splat!(buf, vt::ScrollBufferDown(lines), vt::ScrollRegion::RESET);
        self.render_top_lines(buf, rect, view, lines, style);
        self.previous = rect;
    }

    pub(crate) fn delta_scroll_down(
        &mut self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        lines: u16,
        style: &LogStyle,
    ) {
        vt::ScrollRegion(rect.y + 1, rect.y + rect.h).write_to_buffer(buf);
        extui::splat!(buf, vt::ScrollBufferUp(lines), vt::ScrollRegion::RESET);
        self.render_bottom_lines(buf, rect, view, lines, style);
        self.previous = rect;
    }

    pub(crate) fn entry_screen_position(
        &self,
        view: &LogView,
        style: &LogStyle,
        rect: Rect,
        log_id: LogId,
    ) -> Option<(u16, u16)> {
        let logs = view.logs.indexer();
        let mut y_pos: u16 = 0;

        let first_id = *self.ids.get(self.top_index)?;
        let first_entry = logs[first_id];
        let first_height = get_entry_height(&first_entry, style, rect.w as u32) as u16;
        let first_visible = first_height.saturating_sub(self.scroll_shift_up);

        if first_id == log_id {
            let start = 0;
            let end = first_visible.min(rect.h);
            return Some((start, end));
        }
        y_pos += first_visible;

        for &id in &self.ids[self.top_index + 1..] {
            if y_pos >= rect.h {
                return None;
            }
            let entry = logs[id];
            let height = get_entry_height(&entry, style, rect.w as u32) as u16;

            if id == log_id {
                let start = y_pos;
                let end = (y_pos + height).min(rect.h);
                return Some((start, end));
            }
            y_pos += height;
        }
        None
    }

    pub(crate) fn render_entry_in_place(
        &self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        log_id: LogId,
        style: &LogStyle,
        highlight: Option<LogHighlight>,
    ) {
        let Some((entry_screen_start, entry_screen_end)) = self.entry_screen_position(view, style, rect, log_id) else {
            return;
        };

        let logs = view.logs.indexer();
        let entry = logs[log_id];
        let entry_height = get_entry_height(&entry, style, rect.w as u32) as u16;

        let skip_lines = if self.ids.get(self.top_index) == Some(&log_id) { self.scroll_shift_up } else { 0 };

        let visible_lines = entry_screen_end - entry_screen_start;
        let max_lines = visible_lines.min(entry_height.saturating_sub(skip_lines));

        vt::MoveCursor(rect.x, rect.y + entry_screen_start).write_to_buffer(buf);
        render_single_entry(buf, view.logs, rect.w, &entry, log_id, skip_lines, max_lines, style, highlight);
    }

    /// Render only the highlighted region of an entry.
    pub(crate) fn render_highlight_region(
        &self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        log_id: LogId,
        highlight: MatchHighlight,
        apply_highlight: bool,
        style: &LogStyle,
    ) {
        let Some((entry_screen_start, _)) = self.entry_screen_position(view, style, rect, log_id) else {
            return;
        };

        let logs = view.logs.indexer();
        let entry = logs[log_id];
        let text = unsafe { entry.text(view.logs) };

        let base_skip = if self.ids.get(self.top_index) == Some(&log_id) { self.scroll_shift_up } else { 0 };

        let positions = highlight_screen_positions(&entry, view.logs, style, rect.w, highlight);

        let hl_start = highlight.start as usize;
        let hl_end = hl_start + highlight.len as usize;

        let highlight_style = extui::Color::Grey[25].with_fg(extui::Color::Black);

        for pos in positions {
            if pos.line < base_skip {
                continue;
            }
            let screen_line = pos.line - base_skip;
            if screen_line >= rect.h {
                break;
            }

            let screen_y = entry_screen_start + screen_line;

            vt::MoveCursor(rect.x + pos.start_col, rect.y + screen_y).write_to_buffer(buf);

            let hl_text = extract_highlight_text(text, hl_start, hl_end, pos.line, &entry, style, rect.w);

            if apply_highlight {
                highlight_style.write_to_buffer(buf);
            } else {
                pos.accumulated_style.write_to_buffer(buf);
            }
            buf.extend_from_slice(hl_text.as_bytes());
            vt::CLEAR_STYLE.write_to_buffer(buf);
        }
    }

    pub(crate) fn delta_highlight_only(&mut self, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        let old_highlight = self.last_highlight;
        let new_highlight = style.highlight;

        if old_highlight == new_highlight {
            return;
        }

        match (old_highlight, new_highlight) {
            (Some(old_hl), None) => {
                self.render_highlight_region(buf, rect, view, old_hl.log_id, old_hl.match_info, false, style);
            }
            (Some(old_hl), Some(new_hl)) if old_hl.log_id != new_hl.log_id => {
                self.render_highlight_region(buf, rect, view, old_hl.log_id, old_hl.match_info, false, style);
                self.render_highlight_region(buf, rect, view, new_hl.log_id, new_hl.match_info, true, style);
            }
            (Some(old_hl), Some(new_hl)) => {
                let old_start = old_hl.match_info.start;
                let old_end = old_start + old_hl.match_info.len;
                let new_start = new_hl.match_info.start;
                let new_end = new_start + new_hl.match_info.len;

                if old_start < new_start {
                    let prefix = MatchHighlight { start: old_start, len: new_start - old_start };
                    self.render_highlight_region(buf, rect, view, old_hl.log_id, prefix, false, style);
                }
                if old_end > new_end {
                    let suffix = MatchHighlight { start: new_end, len: old_end - new_end };
                    self.render_highlight_region(buf, rect, view, old_hl.log_id, suffix, false, style);
                }

                self.render_highlight_region(buf, rect, view, new_hl.log_id, new_hl.match_info, true, style);
            }
            (None, Some(new_hl)) => {
                self.render_highlight_region(buf, rect, view, new_hl.log_id, new_hl.match_info, true, style);
            }
            (None, None) => {}
        }

        self.last_highlight = new_highlight;
    }

    pub(super) fn delta_scroll_with_highlight(
        &mut self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        scrolled_lines: u16,
        direction: ScrollDirection,
        style: &LogStyle,
    ) {
        let old_highlight = self.last_highlight;
        let new_highlight = style.highlight;

        if let Some(old_hl) = old_highlight
            && let Some((new_start, new_end)) = self.entry_screen_position(view, style, rect, old_hl.log_id)
        {
            let (old_start, old_end) = match direction {
                ScrollDirection::Up => {
                    (new_start.saturating_sub(scrolled_lines), new_end.saturating_sub(scrolled_lines))
                }
                ScrollDirection::Down => {
                    (new_start.saturating_add(scrolled_lines), new_end.saturating_add(scrolled_lines))
                }
            };

            if old_start < rect.h {
                let clamped_end = old_end.min(rect.h);
                self.render_entry_at_screen_pos(buf, rect, view, old_hl.log_id, old_start, clamped_end, style, None);
            }
        }

        match direction {
            ScrollDirection::Up => self.delta_scroll_up(buf, rect, view, scrolled_lines, style),
            ScrollDirection::Down => self.delta_scroll_down(buf, rect, view, scrolled_lines, style),
        }

        if let Some(new_hl) = new_highlight
            && let Some((start, end)) = self.entry_screen_position(view, style, rect, new_hl.log_id)
        {
            let newly_rendered = match direction {
                ScrollDirection::Up => (0, scrolled_lines),
                ScrollDirection::Down => (rect.h.saturating_sub(scrolled_lines), rect.h),
            };
            let is_fully_contained = start >= newly_rendered.0 && end <= newly_rendered.1;
            if !is_fully_contained {
                self.render_entry_in_place(buf, rect, view, new_hl.log_id, style, style.highlight);
            }
        }
    }

    pub(crate) fn render_entry_at_screen_pos(
        &self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: &LogView,
        log_id: LogId,
        screen_start: u16,
        screen_end: u16,
        style: &LogStyle,
        highlight: Option<LogHighlight>,
    ) {
        let logs = view.logs.indexer();
        let entry = logs[log_id];
        let entry_height = get_entry_height(&entry, style, rect.w as u32) as u16;

        let skip_lines = if self.ids.get(self.top_index) == Some(&log_id) { self.scroll_shift_up } else { 0 };

        let visible_lines = screen_end.saturating_sub(screen_start);
        let max_lines = visible_lines.min(entry_height.saturating_sub(skip_lines));

        if max_lines > 0 {
            vt::MoveCursor(rect.x, rect.y + screen_start).write_to_buffer(buf);
            render_single_entry(buf, view.logs, rect.w, &entry, log_id, skip_lines, max_lines, style, highlight);
        }
    }
}
