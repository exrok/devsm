use vtui::{
    Rect,
    vt::{self, BufferWrite},
};

use crate::{
    line_width::{self, MatchHighlight, Segment},
    log_storage::{LogEntry, LogGroup, LogId, LogView, Logs},
};

fn get_entry_height(entry: &LogEntry, style: &LogStyle, width: u32) -> u32 {
    let prefix_width = style.prefix(entry.log_group).map(|p| p.width).unwrap_or(0) as u32;

    let first_line_width = width.saturating_sub(prefix_width);

    if entry.width == 0 {
        1
    } else if entry.width <= first_line_width {
        1
    } else {
        1 + (entry.width - first_line_width).div_ceil(width)
    }
}

fn render_single_entry(
    buf: &mut Vec<u8>,
    logs: &Logs,
    width: u16,
    entry: &LogEntry,
    log_id: LogId,
    skip_lines: u16,
    max_lines: u16,
    style: &LogStyle,
) -> u16 {
    use vtui::Color;

    if max_lines == 0 {
        return 0;
    }

    let highlight_info = style.highlight.filter(|h| h.log_id == log_id);
    let highlight_style = Color::DarkOrange.as_bg();

    let prefix = style.prefix(entry.log_group);
    let prefix_width = prefix.map(|p| p.width).unwrap_or(0) as u16;
    let prefix_bytes = prefix.map(|p| p.bytes.as_bytes()).unwrap_or(b"");

    let total_height = get_entry_height(entry, style, width as u32) as u16;
    if skip_lines >= total_height {
        return 0;
    }

    let text = unsafe { entry.text(logs) };

    // Optimization: If we are rendering the whole entry from the start and it fits on a single line.
    if skip_lines == 0 && max_lines >= total_height && total_height == 1 {
        if !prefix_bytes.is_empty() {
            buf.extend_from_slice(prefix_bytes);
        }

        if let Some(hl) = highlight_info {
            render_text_with_highlight(buf, text, entry.style, hl.match_info, highlight_style);
        } else {
            entry.style.write_to_buffer(buf);
            buf.extend_from_slice(text.as_bytes());
        }

        vt::clear_style(buf);
        if !style.assume_blank {
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        }
        buf.extend_from_slice(b"\r\n");
        return 1;
    }

    let mut current_skip = skip_lines;
    let mut lines_rendered = 0;
    let mut text_slice = text;

    let first_line_capacity = width.saturating_sub(prefix_width);
    let mut first_line_len = 0;
    if entry.width > 0 {
        let mut splitter = line_width::naive_line_splitting(text_slice, entry.style, first_line_capacity.into());

        if let Some((line_text, line_style)) = splitter.next() {
            first_line_len = line_text.len();

            if current_skip == 0 {
                if !prefix_bytes.is_empty() {
                    buf.extend_from_slice(prefix_bytes);
                }

                if let Some(hl) = highlight_info {
                    render_text_with_highlight(buf, line_text, line_style, hl.match_info, highlight_style);
                } else {
                    line_style.write_to_buffer(buf);
                    buf.extend_from_slice(line_text.as_bytes());
                }

                if !style.assume_blank {
                    buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
                }
                buf.extend_from_slice(b"\r\n");

                lines_rendered += 1;
                if lines_rendered == max_lines {
                    vt::clear_style(buf);
                    return lines_rendered;
                }
            } else {
                current_skip -= 1;
            }
        }
    } else if current_skip == 0 {
        if !prefix_bytes.is_empty() {
            buf.extend_from_slice(prefix_bytes);
        }
        vt::clear_style(buf);
        if !style.assume_blank {
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        }
        buf.extend_from_slice(b"\r\n");
        return 1;
    }

    if first_line_len < text_slice.len() {
        text_slice = &text_slice[first_line_len..];

        let stripped_offset =
            if highlight_info.is_some() { calculate_stripped_len(&text[..first_line_len]) } else { 0 };

        let lines = line_width::naive_line_splitting(text_slice, entry.style, width.into())
            .skip(current_skip as usize)
            .take((max_lines - lines_rendered) as usize);

        let mut current_stripped_offset = stripped_offset;

        // We only set the style if we are just starting to render visible lines (i.e. we skipped some).
        // If we just rendered the first line, the style is technically active, but usually splitters reset.
        // The naive splitter returns style for every line.
        for (line, line_style) in lines {
            if let Some(hl) = highlight_info {
                let line_stripped_len = calculate_stripped_len(line);
                let line_start = current_stripped_offset;
                let line_end = current_stripped_offset + line_stripped_len;
                let hl_start = hl.match_info.start as usize;
                let hl_end = hl_start + hl.match_info.len as usize;

                let adjusted_hl = if hl_start < line_end && hl_end > line_start {
                    let overlap_start = hl_start.saturating_sub(line_start);
                    let overlap_end = hl_end.saturating_sub(line_start).min(line_stripped_len);
                    MatchHighlight { start: overlap_start as u32, len: (overlap_end - overlap_start) as u32 }
                } else {
                    MatchHighlight { start: 0, len: 0 }
                };

                render_text_with_highlight(buf, line, line_style, adjusted_hl, highlight_style);
                current_stripped_offset += line_stripped_len;
            } else {
                line_style.write_to_buffer(buf);
                buf.extend_from_slice(line.as_bytes());
            }

            if !style.assume_blank {
                buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
            }
            buf.extend_from_slice(b"\r\n");
            lines_rendered += 1;
        }
    }

    vt::clear_style(buf);
    lines_rendered
}

/// Calculate the stripped (ANSI-free) length of text for offset tracking.
fn calculate_stripped_len(text: &str) -> usize {
    let mut len = 0;
    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) => len += s.len(),
            Segment::Utf8(s) => {
                for ch in s.chars() {
                    len += ch.to_lowercase().map(|c| c.len_utf8()).sum::<usize>();
                }
            }
            Segment::AnsiEscapes(_) => {}
        }
    }
    len
}

/// Render text with substring highlighting to a raw buffer.
fn render_text_with_highlight(
    buf: &mut Vec<u8>,
    text: &str,
    base_style: vtui::Style,
    highlight: MatchHighlight,
    highlight_style: vtui::Style,
) {
    let match_start = highlight.start as usize;
    let match_end = match_start + highlight.len as usize;
    let has_highlight = highlight.len > 0;

    let mut stripped_pos = 0usize;
    let mut current_style = base_style;
    current_style.write_to_buffer(buf);

    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) => {
                let seg_start = stripped_pos;
                let seg_end = stripped_pos + s.len();

                if has_highlight && seg_start < match_end && seg_end > match_start {
                    let hl_start_in_seg = match_start.saturating_sub(seg_start);
                    let hl_end_in_seg = (match_end - seg_start).min(s.len());

                    if hl_start_in_seg > 0 {
                        buf.extend_from_slice(s[..hl_start_in_seg].as_bytes());
                    }
                    highlight_style.write_to_buffer(buf);
                    buf.extend_from_slice(s[hl_start_in_seg..hl_end_in_seg].as_bytes());
                    vt::clear_style(buf);
                    current_style.write_to_buffer(buf);
                    if hl_end_in_seg < s.len() {
                        buf.extend_from_slice(s[hl_end_in_seg..].as_bytes());
                    }
                } else {
                    buf.extend_from_slice(s.as_bytes());
                }
                stripped_pos = seg_end;
            }
            Segment::Utf8(s) => {
                // For UTF-8 segments, we process char-by-char because
                // lowercasing can change byte lengths
                for ch in s.chars() {
                    let ch_stripped_len: usize = ch.to_lowercase().map(|c| c.len_utf8()).sum();
                    let ch_start = stripped_pos;
                    let ch_end = stripped_pos + ch_stripped_len;

                    let in_highlight = has_highlight && ch_start < match_end && ch_end > match_start;

                    if in_highlight {
                        highlight_style.write_to_buffer(buf);
                        let mut char_buf = [0u8; 4];
                        let encoded = ch.encode_utf8(&mut char_buf);
                        buf.extend_from_slice(encoded.as_bytes());
                        vt::clear_style(buf);
                        current_style.write_to_buffer(buf);
                    } else {
                        let mut char_buf = [0u8; 4];
                        let encoded = ch.encode_utf8(&mut char_buf);
                        buf.extend_from_slice(encoded.as_bytes());
                    }

                    stripped_pos = ch_end;
                }
            }
            Segment::AnsiEscapes(escape) => {
                line_width::apply_raw_display_mode_vt_to_style(&mut current_style, escape);
                buf.extend_from_slice(b"\x1b[");
                buf.extend_from_slice(escape.as_bytes());
                buf.extend_from_slice(b"m");
            }
        }
    }
}

#[derive(Clone)]
pub struct Prefix {
    pub bytes: Box<str>,
    pub width: usize,
}

/// Highlight information for a specific log entry.
#[derive(Clone, Copy, Default)]
pub struct LogHighlight {
    /// The LogId to highlight.
    pub log_id: LogId,
    /// Position and length of match in stripped text.
    pub match_info: MatchHighlight,
}

#[derive(Default)]
pub struct LogStyle {
    pub prefixes: Vec<Prefix>,
    pub assume_blank: bool,
    /// Log entry to highlight when rendering. Used for search result highlighting.
    pub highlight: Option<LogHighlight>,
}

impl LogStyle {
    pub fn prefix(&self, job: LogGroup) -> Option<&Prefix> {
        self.prefixes.get(job.base_task_index().idx())
    }
}

#[derive(Debug)]
pub struct LogScrollWidget {
    /// The index in `ids` that has the LineId of the element at the top of the list
    top_index: usize,
    /// The minimum index in `ids` to be considered (lower ids are no longer in the logs)
    min_index: usize,
    /// The LineId's the make up the list (currently can be assumed in sorted order)
    ids: Vec<LogId>,
    /// The number of lines of the top element that has been scrolled up off screen
    scroll_shift_up: u16,
    /// The last rectangle that has been rendered, zero height rects will not rendering anything,
    /// to force a full rerender set the previous to an Empty rectangle
    previous: Rect,
    /// The last LineId that has been processed in ids.
    tail: LogId,
}

#[derive(Debug)]
pub struct LogTailWidget {
    /// The last LineId that has been processed in ids.
    tail: LogId,
    next_screen_offset: u16,
    /// The last rectangle that has been rendered, zero height rects will not rendering anything,
    /// to force a full rerender set the previous to an Empty rectangle
    previous: Rect,
}

impl Default for LogTailWidget {
    fn default() -> Self {
        Self { tail: Default::default(), next_screen_offset: Default::default(), previous: Rect::EMPTY }
    }
}

pub enum LogWidget {
    Scroll(LogScrollWidget),
    Tail(LogTailWidget),
}

impl Default for LogWidget {
    fn default() -> Self {
        LogWidget::Tail(LogTailWidget::default())
    }
}

impl LogWidget {
    pub fn reset(&mut self) {
        // todo optimize
        *self = LogWidget::default();
    }
    /// Transitions the view from `Tail` mode to `Scroll` mode if it isn't already.
    pub fn scrollify(&mut self, view: &LogView, style: &LogStyle) -> &mut LogScrollWidget {
        if let LogWidget::Tail(tail) = self {
            let mut ids = Vec::new();
            let mut line_id = view.logs.head();
            let (a, b) = view.logs.slices_range(LogId(0), view.tail);
            for slice in [a, b] {
                for entry in slice {
                    if view.contains(entry) {
                        ids.push(line_id);
                    }
                    line_id.0 += 1;
                }
            }

            let logs = view.logs.indexer();
            let mut remaining_height = tail.previous.h as i32;
            let top_index = 'index: {
                for (i, id) in ids.iter().enumerate().rev() {
                    let entry = logs[*id];
                    if tail.previous.w == 0 {
                        break 'index i;
                    }
                    let line_count = get_entry_height(&entry, style, tail.previous.w as u32);
                    remaining_height -= line_count as i32;
                    if remaining_height <= 0 {
                        break 'index i;
                    }
                }
                0
            };

            let scroll_view = LogScrollWidget {
                top_index,
                min_index: 0,
                ids,
                scroll_shift_up: if remaining_height < 0 { (-remaining_height) as u16 } else { 0 },
                tail: LogId(line_id.0),
                previous: Rect { x: tail.previous.x, y: tail.previous.y, w: tail.previous.w, h: tail.previous.h },
            };

            *self = LogWidget::Scroll(scroll_view)
        }
        match self {
            LogWidget::Scroll(scroll_view) => {
                if scroll_view.tail < view.tail {
                    let mut start = view.logs.head().max(LogId(scroll_view.tail.0));
                    kvlog::info!("more: {}", x = view.tail.0, start = start.0);

                    let (a, b) = view.logs.slices_range(start, view.tail);
                    kvlog::info!("added", ?a, ?b);
                    for slice in [a, b] {
                        for entry in slice {
                            if view.contains(entry) {
                                scroll_view.ids.push(start);
                            }
                            start.0 += 1;
                        }
                    }
                    scroll_view.tail = view.tail;
                }
                scroll_view
            }
            LogWidget::Tail(_) => unreachable!(),
        }
    }

    pub fn render(&mut self, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        match self {
            LogWidget::Scroll(scroll_view) => scroll_view.render_reset(buf, rect, view, style),
            LogWidget::Tail(tail_view) => tail_view.render(buf, rect, view, style),
        }
    }

    /// Scrolls the view to show a specific LogId, centering it if possible.
    ///
    /// This method is smart about scrolling:
    /// 1. If the target is already visible, no scrolling occurs
    /// 2. When scrolling is needed, the target is centered in the view
    /// 3. Centering is clamped to avoid scrolling past start or end
    pub fn scroll_to_log_id(&mut self, target: LogId, view: &LogView, style: &LogStyle) {
        let scroll_view = self.scrollify(view, style);
        let logs = view.logs.indexer();

        if scroll_view.ids.is_empty() {
            return;
        }

        let target_idx = scroll_view.ids.iter().position(|&id| id >= target).unwrap_or(scroll_view.ids.len());
        let target_idx = target_idx.min(scroll_view.ids.len().saturating_sub(1));

        let screen_height = scroll_view.previous.h as u32;
        let width = scroll_view.previous.w as u32;

        if screen_height == 0 || width == 0 {
            scroll_view.top_index = target_idx;
            scroll_view.scroll_shift_up = 0;
            scroll_view.previous = Rect::EMPTY;
            return;
        }

        let mut accumulated_height = 0u32;
        let mut found_visible = false;

        if let Some(&first_id) = scroll_view.ids.get(scroll_view.top_index) {
            let entry = logs[first_id];
            let entry_height = get_entry_height(&entry, style, width);
            let visible_height = entry_height.saturating_sub(scroll_view.scroll_shift_up as u32);

            if scroll_view.top_index == target_idx && scroll_view.scroll_shift_up == 0 {
                found_visible = true;
            }
            accumulated_height += visible_height;
        }

        if !found_visible {
            for idx in (scroll_view.top_index + 1)..scroll_view.ids.len() {
                if accumulated_height >= screen_height {
                    break;
                }
                if idx == target_idx {
                    found_visible = true;
                    break;
                }
                let entry = logs[scroll_view.ids[idx]];
                accumulated_height += get_entry_height(&entry, style, width);
            }
        }

        if found_visible {
            return;
        }

        let target_entry = logs[scroll_view.ids[target_idx]];
        let target_height = get_entry_height(&target_entry, style, width);

        let lines_above_target = (screen_height.saturating_sub(target_height)) / 2;

        let mut lines_accumulated = 0u32;
        let mut new_top_index = target_idx;
        let mut new_scroll_shift = 0u16;

        for idx in (scroll_view.min_index..target_idx).rev() {
            let entry = logs[scroll_view.ids[idx]];
            let entry_height = get_entry_height(&entry, style, width);

            if lines_accumulated + entry_height <= lines_above_target {
                lines_accumulated += entry_height;
                new_top_index = idx;
            } else {
                let remaining = lines_above_target - lines_accumulated;
                if remaining > 0 {
                    new_top_index = idx;
                    new_scroll_shift = (entry_height - remaining) as u16;
                }
                break;
            }
        }

        let mut total_visible = 0u32;
        if new_top_index < scroll_view.ids.len() {
            let first_entry = logs[scroll_view.ids[new_top_index]];
            let first_height = get_entry_height(&first_entry, style, width);
            total_visible += first_height.saturating_sub(new_scroll_shift as u32);
        }
        for idx in (new_top_index + 1)..scroll_view.ids.len() {
            let entry = logs[scroll_view.ids[idx]];
            total_visible += get_entry_height(&entry, style, width);
        }

        if total_visible < screen_height && new_top_index > scroll_view.min_index {
            let deficit = screen_height - total_visible;
            let mut extra_lines = 0u32;

            for idx in (scroll_view.min_index..new_top_index).rev() {
                let entry = logs[scroll_view.ids[idx]];
                let entry_height = get_entry_height(&entry, style, width);
                extra_lines += entry_height;
                new_top_index = idx;
                new_scroll_shift = 0;

                if extra_lines >= deficit {
                    if extra_lines > deficit {
                        new_scroll_shift = (extra_lines - deficit) as u16;
                    }
                    break;
                }
            }
        }

        scroll_view.top_index = new_top_index;
        scroll_view.scroll_shift_up = new_scroll_shift;
        scroll_view.previous = Rect::EMPTY; // Force full re-render
    }

    pub fn scrollable_render(&mut self, scroll: i32, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        if scroll == 0 {
            self.render(buf, rect, view, style);
        } else if scroll > 0 {
            self.scroll_up(scroll as u32, buf, rect, view, style);
        } else if scroll < 0 {
            self.scroll_down(scroll.unsigned_abs(), buf, rect, view, style);
        }
    }

    pub fn scroll_up(&mut self, amount: u32, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        let scroll_view = self.scrollify(view, style);
        let logs = view.logs.indexer();
        let mut scrolled_lines = 0;

        for _ in 0..amount {
            if scroll_view.scroll_shift_up > 0 {
                scroll_view.scroll_shift_up -= 1;
                scrolled_lines += 1;
            } else if scroll_view.min_index < scroll_view.top_index {
                scroll_view.top_index -= 1;
                let entry = logs[scroll_view.ids[scroll_view.top_index]];
                let line_count = get_entry_height(&entry, style, rect.w as u32);
                scroll_view.scroll_shift_up = (line_count as u16).saturating_sub(1);
                scrolled_lines += 1;
            } else {
                break;
            }
        }

        if scrolled_lines > 0 {
            handle_scroll_render(scroll_view, buf, rect, view, scrolled_lines, ScrollDirection::Up, style);
        }
    }

    pub fn scroll_down(&mut self, amount: u32, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        let at_bottom = {
            let scroll_view = self.scrollify(view, style);
            let logs = view.logs.indexer();
            let mut scrolled_lines = 0;

            for _ in 0..amount {
                if scroll_view.top_index >= scroll_view.ids.len() {
                    break;
                }
                let entry = logs[scroll_view.ids[scroll_view.top_index]];
                let line_count = get_entry_height(&entry, style, rect.w as u32);
                if scroll_view.scroll_shift_up + 1 < line_count as u16 {
                    scroll_view.scroll_shift_up += 1;
                    scrolled_lines += 1;
                } else if scroll_view.top_index + 1 < scroll_view.ids.len() {
                    scroll_view.top_index += 1;
                    scroll_view.scroll_shift_up = 0;
                    scrolled_lines += 1;
                } else {
                    break;
                }
            }

            // Determine if the scroll view is now at the very bottom of the logs.
            // This happens if the height of all logs from top_index to the end fits within the screen height.
            // This also covers the case where there are not enough lines to fill the screen (ineffective scrolling).
            let mut height_accum = 0;
            let limit = rect.h as u32;
            let mut is_at_bottom = true;

            if let Some(&id) = scroll_view.ids.get(scroll_view.top_index) {
                let entry = logs[id];
                let full_height = get_entry_height(&entry, style, rect.w as u32);
                let visible_height = full_height.saturating_sub(scroll_view.scroll_shift_up as u32);
                height_accum += visible_height;

                if height_accum > limit {
                    is_at_bottom = false;
                } else {
                    for &next_id in &scroll_view.ids[scroll_view.top_index + 1..] {
                        let entry = logs[next_id];
                        let h = get_entry_height(&entry, style, rect.w as u32);
                        height_accum += h;
                        if height_accum > limit {
                            is_at_bottom = false;
                            break;
                        }
                    }
                }
            } else {
                is_at_bottom = true;
            }

            if !is_at_bottom && scrolled_lines > 0 {
                handle_scroll_render(scroll_view, buf, rect, view, scrolled_lines, ScrollDirection::Down, style);
            }

            is_at_bottom
        };

        if at_bottom {
            *self = LogWidget::Tail(LogTailWidget::default());
            self.render(buf, rect, view, style);
        }
    }
}

enum ScrollDirection {
    Up,
    Down,
}

fn handle_scroll_render(
    scroll_view: &mut LogScrollWidget,
    buf: &mut Vec<u8>,
    rect: Rect,
    view: &LogView,
    scrolled_lines: u32,
    direction: ScrollDirection,
    style: &LogStyle,
) {
    let scrolled_lines = scrolled_lines as u16;
    if scrolled_lines < rect.h && scroll_view.previous == rect {
        let scroll_region = vt::ScrollRegion(rect.y + 1, rect.y + rect.h);
        scroll_region.write_to_buffer(buf);

        match direction {
            ScrollDirection::Up => {
                vt::scroll_buffer_down(buf, scrolled_lines);
                vt::ScrollRegion::RESET.write_to_buffer(buf);
                scroll_view.render_top_lines(buf, rect, view, scrolled_lines, style);
            }
            ScrollDirection::Down => {
                vt::scroll_buffer_up(buf, scrolled_lines);
                vt::ScrollRegion::RESET.write_to_buffer(buf);
                scroll_view.render_bottom_lines(buf, rect, view, scrolled_lines, style);
            }
        }
        scroll_view.previous = rect;
    } else {
        scroll_view.render_reset(buf, rect, view, style);
    }
}

impl LogScrollWidget {
    fn render_content(
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
            );
            remaining_height = remaining_height.saturating_sub(rendered);
        }

        for (log_id, entry) in entries {
            if remaining_height == 0 {
                break;
            }
            let rendered = render_single_entry(buf, view.logs, rect.w, &entry, log_id, 0, remaining_height, style);
            remaining_height = remaining_height.saturating_sub(rendered);
        }
        remaining_height
    }

    pub fn render_reset(&mut self, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        self.previous = rect;
        while let Some(id) = self.ids.get(self.top_index) {
            if *id < view.logs.head() {
                self.top_index += 1;
                self.min_index = self.top_index;
                self.scroll_shift_up = 0;
            } else {
                break;
            }
        }

        vt::move_cursor(buf, rect.x, rect.y);
        let remaining_height = self.render_content(buf, rect, view, rect.h, style);

        for _ in 0..remaining_height {
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
            buf.extend_from_slice(b"\r\n");
        }
    }

    fn render_top_lines(&self, buf: &mut Vec<u8>, rect: Rect, view: &LogView, line_count: u16, style: &LogStyle) {
        vt::move_cursor(buf, rect.x, rect.y);
        self.render_content(buf, rect, view, line_count, style);
    }

    fn render_bottom_lines(
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

        vt::move_cursor(buf, rect.x, rect.y + rect.h - scrolled_lines);
        let mut remaining_height = scrolled_lines;

        if let Some((log_id, entry)) = start_entry {
            if remaining_height == 0 {
                return;
            }
            let rendered =
                render_single_entry(buf, view.logs, rect.w, &entry, log_id, sub_line_skip, remaining_height, style);
            remaining_height = remaining_height.saturating_sub(rendered);
        }

        for (log_id, entry) in entries {
            if remaining_height == 0 {
                break;
            }
            let rendered = render_single_entry(buf, view.logs, rect.w, &entry, log_id, 0, remaining_height, style);
            remaining_height = remaining_height.saturating_sub(rendered);
        }
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
        let (a, b) = view.logs.slices_range(self.tail, view.tail);

        if rect.h == 0 || (a.is_empty() && b.is_empty()) {
            self.tail = view.tail;
            return;
        }
        vt::ScrollRegion(rect.y + 1, rect.y + rect.h).write_to_buffer(buf);

        let mut first = false;
        if rect.y + self.next_screen_offset == 0 {
            vt::move_cursor(buf, rect.x, 0);
            first = true;
        } else {
            vt::move_cursor(buf, rect.x, rect.y + self.next_screen_offset - 1);
        }
        let mut offset = self.next_screen_offset as u32;
        for entry in a.iter().chain(b.iter()) {
            if !view.contains(entry) {
                continue;
            }
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
                vt::clear_style(buf);
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
                vt::clear_style(buf);
            }
        }

        vt::ScrollRegion::RESET.write_to_buffer(buf);
        if offset > rect.h as u32 {
            offset = rect.h as u32
        }
        self.next_screen_offset = offset as u16;
        self.tail = view.tail;
    }
}

/// Renders the view in "tail" mode from scratch.
fn render_buffer_tail_reset(buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) -> u16 {
    let mut displayed: Vec<(LogId, LogEntry)> = Vec::new();
    let (a, b) = view.logs.slices();
    let head = view.logs.head();
    let mut remaining_v_space = rect.h as i32;

    // Iterate in reverse (newest first). Slice b comes after a in the logical order.
    // Compute LogIds: entries in a have LogIds from head to head+a.len()-1
    //                 entries in b have LogIds from head+a.len() to head+a.len()+b.len()-1
    let a_len = a.len();

    'outer: for (slice, base_offset) in [(b, a_len), (a, 0)] {
        for (rev_idx, entry) in slice.iter().rev().enumerate() {
            if !view.contains(entry) {
                continue;
            }
            let line_count = get_entry_height(entry, style, rect.w as u32);
            remaining_v_space -= line_count as i32;
            let log_id = LogId(head.0 + base_offset + (slice.len() - 1 - rev_idx));
            displayed.push((log_id, *entry));
            if remaining_v_space <= 0 {
                break 'outer;
            }
        }
    }

    vt::move_cursor(buf, rect.x, rect.y);
    let mut screen_lines_left = rect.h;
    let mut entries_to_render = displayed.iter().rev();

    if remaining_v_space < 0
        && let Some((log_id, entry)) = entries_to_render.next() {
            let skip = (-remaining_v_space) as u16;
            let rendered = render_single_entry(buf, view.logs, rect.w, entry, *log_id, skip, screen_lines_left, style);
            screen_lines_left = screen_lines_left.saturating_sub(rendered);
        }

    for (log_id, entry) in entries_to_render {
        if screen_lines_left == 0 {
            break;
        }
        let rendered = render_single_entry(buf, view.logs, rect.w, entry, *log_id, 0, screen_lines_left, style);
        screen_lines_left = screen_lines_left.saturating_sub(rendered);
    }

    if !style.assume_blank {
        for _ in 0..screen_lines_left {
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
            buf.extend_from_slice(b"\r\n");
        }
    }

    rect.h.saturating_sub(screen_lines_left)
}

#[cfg(test)]
mod test {

    use vtui::{Rect, vt};

    use crate::{
        log_storage::LogWriter,
        scroll_view::{LogStyle, LogWidget, Prefix},
    };

    #[track_caller]
    fn expect(parser: &vt100::Parser, content: &[&str]) {
        for (i, (row, expected)) in parser.screen().rows(0, 8).zip(content).enumerate() {
            let expected = expected.trim_ascii_end();
            if row == *expected {
                continue;
            }
            println!("{}", parser.screen().contents());
            panic!("Row {} did not match expected content. \nExpected: {:?} \n   Found: {:?}", i, expected, row);
        }
    }

    fn estimate_byte_cost(buf: &[u8]) -> usize {
        std::str::from_utf8(buf).unwrap().split("Line").count().saturating_sub(1) * 60 + buf.len()
    }

    #[test]
    fn scroll_insanity() {
        let mut parser = vt100::Parser::new(6, 8, 0);
        let mut total_written = 0;
        let mut buf = Vec::new();
        macro_rules! assert_scrollview {
            ($($tt:tt)*) => {
                parser.process(&buf);
                total_written += estimate_byte_cost(&buf);
                buf.clear();
                expect(&parser, &["12345678",$($tt),*,"12345678"]);
            };
        }

        vt::move_cursor(&mut buf, 0, 0);
        for _ in 0..6 {
            buf.extend_from_slice(b"12345678");
        }
        assert_scrollview! {
            "12345678"
            "12345678"
            "12345678"
            "12345678"
        }

        let rect = Rect { x: 0, y: 1, w: 8, h: 4 };
        let mut writer = LogWriter::new();
        let logs = writer.reader();
        let mut view = LogWidget::default();
        let style = LogStyle::default();
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "        "
            "        "
            "        "
            "        "
        }
        writer.push("Line 0");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 0  "
            "        "
            "        "
            "        "
        }
        writer.push("Line 1");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "        "
            "        "
        }
        writer.push("Line 2");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "        "
        }
        writer.push("Line 3");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        writer.push("Line 4");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        writer.push("Line 5");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 2  "
            "Line 3  "
            "Line 4  "
            "Line 5  "
        }
        writer.push("head1234Line 6");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 4  "
            "Line 5  "
            "head1234"
            "Line 6  "
        }
        view.scroll_up(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 3  "
            "Line 4  "
            "Line 5  "
            "head1234"
        }
        view.scroll_up(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 2  "
            "Line 3  "
            "Line 4  "
            "Line 5  "
        }
        view.scroll_up(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        view.scroll_up(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        view.scroll_up(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        view.scroll_down(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        view.scroll_down(2, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 3  "
            "Line 4  "
            "Line 5  "
            "head1234"
        }
        view.scroll_down(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 4  "
            "Line 5  "
            "head1234"
            "Line 6  "
        }
        kvlog::info!("hello");
        writer.push("Line 7");
        assert_scrollview! {
            "Line 4  "
            "Line 5  "
            "head1234"
            "Line 6  "
        }
        view.scroll_down(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
        assert_scrollview! {
            "Line 5  "
            "head1234"
            "Line 6  "
            "Line 7  "
        }
        println!("VT {} bytes written", total_written);
    }

    #[test]
    fn prefix_wrapping() {
        #[track_caller]
        fn expect(parser: &vt100::Parser, content: &[&str]) {
            for (i, (row, expected)) in parser.screen().rows(0, 10).zip(content).enumerate() {
                let expected = expected.trim_ascii_end();
                if row == *expected {
                    continue;
                }
                println!("{}", parser.screen().contents());
                panic!("Row {} did not match expected content. \nExpected: {:?} \n   Found: {:?}", i, expected, row);
            }
        }
        let mut parser = vt100::Parser::new(5, 10, 0);
        let mut buf = Vec::new();
        let rect = Rect { x: 0, y: 0, w: 10, h: 4 };

        let mut writer = LogWriter::new();
        let logs = writer.reader();
        let mut view = LogWidget::default();

        // Setup style with a prefix for Job 0
        let prefix = Prefix { bytes: "P: ".into(), width: 3 };
        let style = LogStyle { prefixes: vec![prefix.clone(), prefix], assume_blank: false, highlight: None };

        writer.push("Short");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        parser.process(&buf);
        buf.clear();

        expect(&parser, &["P: Short  ", "          ", "          ", "          "]);

        writer.push("1234567");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        parser.process(&buf);
        buf.clear();

        expect(&parser, &["P: Short  ", "P: 1234567", "          ", "          "]);

        writer.push("12345678");
        view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
        parser.process(&buf);
        buf.clear();
        expect(&parser, &["P: Short  ", "P: 1234567", "P: 1234567", "8         "]);
    }
}
