use extui::{
    Rect,
    vt::{self, BufferWrite},
};
use unicode_width::UnicodeWidthStr;

use crate::{
    line_width::{self, MatchHighlight, Segment},
    log_storage::{LogEntry, LogGroup, LogId, LogView, Logs},
};

mod scroll_widget;
mod tail_widget;
#[cfg(test)]
mod test;

#[inline]
fn lowercase_byte_len(ch: char) -> usize {
    if ch.is_ascii() { 1 } else { ch.to_lowercase().map(|c| c.len_utf8()).sum() }
}

struct HighlightScreenPos {
    line: u16,
    start_col: u16,
    accumulated_style: extui::Style,
}

fn get_entry_height(entry: &LogEntry, style: &LogStyle, width: u32) -> u32 {
    let prefix_width = style.prefix(entry.log_group).map(|p| p.width).unwrap_or(0) as u32;
    let first_line_width = width.saturating_sub(prefix_width);

    if entry.width == 0 || entry.width <= first_line_width {
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
    highlight: Option<LogHighlight>,
) -> u16 {
    use extui::Color;

    if max_lines == 0 {
        return 0;
    }

    let highlight_info = highlight.filter(|h| h.log_id == log_id);
    let highlight_style = Color::Grey[25].with_fg(Color::Black);

    let prefix = style.prefix(entry.log_group);
    let prefix_width = prefix.map(|p| p.width).unwrap_or(0) as u16;
    let prefix_bytes = prefix.map(|p| p.bytes.as_bytes()).unwrap_or(b"");

    let total_height = get_entry_height(entry, style, width as u32) as u16;
    if skip_lines >= total_height {
        return 0;
    }

    let text = unsafe { entry.text(logs) };

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

        buf.extend_from_slice(vt::CLEAR_STYLE);

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
                    vt::CLEAR_STYLE.write_to_buffer(buf);
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
        vt::CLEAR_STYLE.write_to_buffer(buf);
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

    buf.extend_from_slice(vt::CLEAR_STYLE);

    lines_rendered
}

fn calculate_stripped_len(text: &str) -> usize {
    let mut len = 0;
    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) => len += s.len(),
            Segment::Utf8(s) => {
                for ch in s.chars() {
                    len += lowercase_byte_len(ch);
                }
            }
            Segment::AnsiEscapes(_) => {}
        }
    }
    len
}

fn highlight_screen_positions(
    entry: &LogEntry,
    logs: &Logs,
    style: &LogStyle,
    width: u16,
    highlight: MatchHighlight,
) -> Vec<HighlightScreenPos> {
    if highlight.len == 0 {
        return Vec::new();
    }

    let text = unsafe { entry.text(logs) };
    let prefix = style.prefix(entry.log_group);
    let prefix_width = prefix.map(|p| p.width).unwrap_or(0) as u16;

    let hl_start = highlight.start as usize;
    let hl_end = hl_start + highlight.len as usize;

    let mut positions = Vec::new();
    let mut current_stripped_offset = 0usize;
    let mut line_num = 0u16;

    let first_line_capacity = width.saturating_sub(prefix_width);
    let mut text_slice = text;

    if entry.width > 0 {
        let mut splitter = line_width::naive_line_splitting(text_slice, entry.style, first_line_capacity.into());
        if let Some((line_text, line_style)) = splitter.next() {
            let line_stripped_len = calculate_stripped_len(line_text);
            let line_end = current_stripped_offset + line_stripped_len;

            if hl_start < line_end && hl_end > current_stripped_offset {
                let hl_start_in_line = hl_start.saturating_sub(current_stripped_offset);
                let (start_col, accumulated_style) =
                    calc_highlight_position(line_text, line_style, hl_start_in_line, prefix_width);
                positions.push(HighlightScreenPos { line: line_num, start_col, accumulated_style });
            }

            current_stripped_offset = line_end;
            text_slice = &text_slice[line_text.len()..];
            line_num += 1;
        }
    } else {
        return positions;
    }

    for (line, line_style) in line_width::naive_line_splitting(text_slice, entry.style, width.into()) {
        let line_stripped_len = calculate_stripped_len(line);
        let line_end = current_stripped_offset + line_stripped_len;

        if hl_start < line_end && hl_end > current_stripped_offset {
            let hl_start_in_line = hl_start.saturating_sub(current_stripped_offset);
            let (start_col, accumulated_style) = calc_highlight_position(line, line_style, hl_start_in_line, 0);
            positions.push(HighlightScreenPos { line: line_num, start_col, accumulated_style });
        }

        current_stripped_offset = line_end;
        line_num += 1;

        if current_stripped_offset >= hl_end {
            break;
        }
    }

    positions
}

fn calc_highlight_position(
    line_text: &str,
    base_style: extui::Style,
    hl_start_in_line: usize,
    prefix_width: u16,
) -> (u16, extui::Style) {
    let mut col = prefix_width;
    let mut stripped_pos = 0usize;
    let mut current_style = base_style;

    for segment in Segment::iterator(line_text) {
        match segment {
            Segment::Ascii(s) => {
                for _ in s.chars() {
                    if stripped_pos == hl_start_in_line {
                        return (col, current_style);
                    }
                    col += 1;
                    stripped_pos += 1;
                }
            }
            Segment::Utf8(s) => {
                for ch in s.chars() {
                    if stripped_pos == hl_start_in_line {
                        return (col, current_style);
                    }
                    let char_width = UnicodeWidthStr::width(ch.to_string().as_str()) as u16;
                    col += char_width;
                    stripped_pos += lowercase_byte_len(ch);
                }
            }
            Segment::AnsiEscapes(escape) => {
                line_width::apply_raw_display_mode_vt_to_style(&mut current_style, escape);
            }
        }
    }

    (col, current_style)
}

fn extract_highlight_text(
    text: &str,
    hl_start: usize,
    hl_end: usize,
    target_line: u16,
    entry: &LogEntry,
    style: &LogStyle,
    width: u16,
) -> String {
    let prefix_width = style.prefix(entry.log_group).map(|p| p.width).unwrap_or(0) as u16;
    let first_line_capacity = width.saturating_sub(prefix_width);

    let mut current_stripped_offset = 0usize;
    let mut line_num = 0u16;
    let mut text_slice = text;

    if entry.width > 0 {
        let mut splitter = line_width::naive_line_splitting(text_slice, entry.style, first_line_capacity.into());
        if let Some((line_text, _)) = splitter.next() {
            let line_stripped_len = calculate_stripped_len(line_text);

            if line_num == target_line {
                return extract_from_line(line_text, hl_start, hl_end, current_stripped_offset);
            }

            current_stripped_offset += line_stripped_len;
            text_slice = &text_slice[line_text.len()..];
            line_num += 1;
        }
    }

    for (line, _) in line_width::naive_line_splitting(text_slice, entry.style, width.into()) {
        if line_num == target_line {
            return extract_from_line(line, hl_start, hl_end, current_stripped_offset);
        }

        let line_stripped_len = calculate_stripped_len(line);
        current_stripped_offset += line_stripped_len;
        line_num += 1;
    }

    String::new()
}

fn extract_from_line(line_text: &str, hl_start: usize, hl_end: usize, line_start_offset: usize) -> String {
    let hl_start_in_line = hl_start.saturating_sub(line_start_offset);
    let hl_end_in_line = hl_end.saturating_sub(line_start_offset);

    let mut result = String::new();
    let mut stripped_pos = 0usize;

    for segment in Segment::iterator(line_text) {
        match segment {
            Segment::Ascii(s) => {
                for ch in s.chars() {
                    if stripped_pos >= hl_start_in_line && stripped_pos < hl_end_in_line {
                        result.push(ch);
                    }
                    stripped_pos += 1;
                    if stripped_pos >= hl_end_in_line {
                        return result;
                    }
                }
            }
            Segment::Utf8(s) => {
                for ch in s.chars() {
                    if stripped_pos >= hl_start_in_line && stripped_pos < hl_end_in_line {
                        result.push(ch);
                    }
                    stripped_pos += lowercase_byte_len(ch);
                    if stripped_pos >= hl_end_in_line {
                        return result;
                    }
                }
            }
            Segment::AnsiEscapes(_) => {}
        }
    }

    result
}

fn render_text_with_highlight(
    buf: &mut Vec<u8>,
    text: &str,
    base_style: extui::Style,
    highlight: MatchHighlight,
    highlight_style: extui::Style,
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
                        buf.extend_from_slice(&s.as_bytes()[..hl_start_in_seg]);
                    }
                    extui::splat!(
                        buf,
                        highlight_style,
                        s[hl_start_in_seg..hl_end_in_seg],
                        vt::CLEAR_STYLE,
                        current_style,
                    );

                    if hl_end_in_seg < s.len() {
                        buf.extend_from_slice(&s.as_bytes()[hl_end_in_seg..]);
                    }
                } else {
                    buf.extend_from_slice(s.as_bytes());
                }
                stripped_pos = seg_end;
            }
            Segment::Utf8(s) => {
                for ch in s.chars() {
                    let ch_stripped_len = lowercase_byte_len(ch);
                    let ch_start = stripped_pos;
                    let ch_end = stripped_pos + ch_stripped_len;

                    let in_highlight = has_highlight && ch_start < match_end && ch_end > match_start;

                    let mut char_buf = [0u8; 4];
                    let encoded = ch.encode_utf8(&mut char_buf);
                    if in_highlight {
                        extui::splat!(buf, highlight_style, encoded, vt::CLEAR_STYLE, current_style,)
                    } else {
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogHighlight {
    pub log_id: LogId,
    pub match_info: MatchHighlight,
}

#[derive(Default, Clone)]
pub struct LogStyle {
    pub prefixes: Vec<Prefix>,
    pub assume_blank: bool,
    pub highlight: Option<LogHighlight>,
}

impl LogStyle {
    pub fn prefix(&self, job: LogGroup) -> Option<&Prefix> {
        self.prefixes.get(job.base_task_index().idx())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScrollState {
    pub is_scrolled: bool,
    pub can_scroll_up: bool,
}

pub enum LogWidget {
    Scroll(scroll_widget::LogScrollWidget),
    Tail(tail_widget::LogTailWidget),
}

impl Default for LogWidget {
    fn default() -> Self {
        LogWidget::Tail(tail_widget::LogTailWidget::default())
    }
}

impl LogWidget {
    pub fn reset(&mut self) {
        *self = LogWidget::default();
    }

    pub fn scroll_state(&self, view: &LogView, style: &LogStyle) -> ScrollState {
        match self {
            LogWidget::Scroll(_) => ScrollState { is_scrolled: true, can_scroll_up: true },
            LogWidget::Tail(tail) => {
                ScrollState { is_scrolled: false, can_scroll_up: self.can_scroll(view, style, tail.previous) }
            }
        }
    }

    fn can_scroll(&self, view: &LogView, style: &LogStyle, rect: Rect) -> bool {
        if rect.h == 0 || rect.w == 0 {
            return false;
        }
        let (a, b) = view.logs.slices();
        let mut total_height = 0u32;
        let limit = rect.h as u32;

        for slice in [a, b] {
            for entry in slice {
                if !view.contains(entry) {
                    continue;
                }
                total_height += get_entry_height(entry, style, rect.w as u32);
                if total_height > limit {
                    return true;
                }
            }
        }
        false
    }

    pub fn check_resize_revert_to_tail(&mut self, view: &LogView, style: &LogStyle, rect: Rect) -> bool {
        if let LogWidget::Scroll(_) = self
            && !self.can_scroll(view, style, rect)
        {
            *self = LogWidget::Tail(tail_widget::LogTailWidget::default());
            return true;
        }
        false
    }

    pub fn scrollify(&mut self, view: &LogView, style: &LogStyle) -> &mut scroll_widget::LogScrollWidget {
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

            let scroll_view = scroll_widget::LogScrollWidget {
                top_index,
                min_index: 0,
                ids,
                scroll_shift_up: if remaining_height < 0 { (-remaining_height) as u16 } else { 0 },
                tail: LogId(line_id.0),
                previous: Rect { x: tail.previous.x, y: tail.previous.y, w: tail.previous.w, h: tail.previous.h },
                last_highlight: None,
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
            LogWidget::Scroll(scroll_view) => scroll_view.render_reset_if_needed(buf, rect, view, style),
            LogWidget::Tail(tail_view) => tail_view.render(buf, rect, view, style),
        }
    }

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
        scroll_view.previous = Rect::EMPTY;
    }

    pub fn jump_to_oldest(&mut self, view: &LogView, style: &LogStyle) {
        let scroll_view = self.scrollify(view, style);
        scroll_view.top_index = scroll_view.min_index;
        scroll_view.scroll_shift_up = 0;
        scroll_view.previous = Rect::EMPTY;
    }

    pub fn scrollable_render(&mut self, scroll: i32, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        if scroll == 0 {
            if let LogWidget::Scroll(_) = self {
                self.scroll_down(0, buf, rect, view, style);
            } else {
                self.render(buf, rect, view, style);
            }
        } else if scroll > 0 {
            self.scroll_up(scroll as u32, buf, rect, view, style);
        } else if scroll < 0 {
            self.scroll_down(scroll.unsigned_abs(), buf, rect, view, style);
        }
    }

    pub fn scroll_up(&mut self, amount: u32, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        if let LogWidget::Tail(_) = self
            && !self.can_scroll(view, style, rect)
        {
            self.render(buf, rect, view, style);
            return;
        }
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
        } else if scroll_view.previous != rect {
            scroll_view.render_reset(buf, rect, view, style);
        } else if style.highlight != scroll_view.last_highlight {
            scroll_view.delta_highlight_only(buf, rect, view, style);
        }
    }

    pub fn scroll_down(&mut self, amount: u32, buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) {
        if let LogWidget::Tail(tail) = self {
            tail.render(buf, rect, view, style);
            return;
        }

        let at_bottom = {
            let scroll_view = self.scrollify(view, style);
            let logs = view.logs.indexer();

            let check_at_bottom = |sv: &scroll_widget::LogScrollWidget| -> bool {
                let mut height_accum = 0u32;
                let limit = rect.h as u32;
                if let Some(&id) = sv.ids.get(sv.top_index) {
                    let entry = logs[id];
                    let full_height = get_entry_height(&entry, style, rect.w as u32);
                    let visible_height = full_height.saturating_sub(sv.scroll_shift_up as u32);
                    height_accum += visible_height;
                    if height_accum > limit {
                        return false;
                    }
                    for &next_id in &sv.ids[sv.top_index + 1..] {
                        let entry = logs[next_id];
                        height_accum += get_entry_height(&entry, style, rect.w as u32);
                        if height_accum > limit {
                            return false;
                        }
                    }
                }
                true
            };

            let was_at_bottom = check_at_bottom(scroll_view);

            let mut scrolled_lines = 0u32;
            if !(was_at_bottom && style.highlight.is_some()) {
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
            }

            let is_at_bottom = check_at_bottom(scroll_view);

            if is_at_bottom && style.highlight.is_some() && scroll_view.previous == rect {
                let mut current_height = 0u32;
                if let Some(&id) = scroll_view.ids.get(scroll_view.top_index) {
                    let entry = logs[id];
                    let full_h = get_entry_height(&entry, style, rect.w as u32);
                    current_height += full_h.saturating_sub(scroll_view.scroll_shift_up as u32);
                }
                for &id in &scroll_view.ids[scroll_view.top_index + 1..] {
                    let entry = logs[id];
                    current_height += get_entry_height(&entry, style, rect.w as u32);
                }

                let gap = (rect.h as u32).saturating_sub(current_height);
                if gap > 0 {
                    let old_top = scroll_view.top_index;
                    let old_shift = scroll_view.scroll_shift_up;

                    let mut lines_to_fill = gap;
                    while lines_to_fill > 0 {
                        if scroll_view.scroll_shift_up > 0 {
                            scroll_view.scroll_shift_up -= 1;
                            lines_to_fill -= 1;
                        } else if scroll_view.top_index > 0 {
                            scroll_view.top_index -= 1;
                            let entry = logs[scroll_view.ids[scroll_view.top_index]];
                            let h = get_entry_height(&entry, style, rect.w as u32);
                            if h <= lines_to_fill {
                                lines_to_fill -= h;
                            } else {
                                scroll_view.scroll_shift_up = (h - lines_to_fill) as u16;
                                lines_to_fill = 0;
                            }
                        } else {
                            break;
                        }
                    }

                    if scroll_view.top_index != old_top || scroll_view.scroll_shift_up != old_shift {
                        let filled = gap - lines_to_fill;
                        scroll_view.delta_scroll_up(buf, rect, view, filled as u16, style);
                    }
                }
            }

            let stay_in_scroll = !is_at_bottom || style.highlight.is_some();
            if stay_in_scroll && scrolled_lines > 0 {
                handle_scroll_render(scroll_view, buf, rect, view, scrolled_lines, ScrollDirection::Down, style);
            } else if stay_in_scroll && scroll_view.previous != rect {
                scroll_view.render_reset(buf, rect, view, style);
            } else if stay_in_scroll && style.highlight != scroll_view.last_highlight {
                scroll_view.delta_highlight_only(buf, rect, view, style);
            }

            is_at_bottom
        };

        if at_bottom && style.highlight.is_none() {
            *self = LogWidget::Tail(tail_widget::LogTailWidget::default());
            self.render(buf, rect, view, style);
        }
    }
}

#[derive(Clone, Copy)]
enum ScrollDirection {
    Up,
    Down,
}

fn handle_scroll_render(
    scroll_view: &mut scroll_widget::LogScrollWidget,
    buf: &mut Vec<u8>,
    rect: Rect,
    view: &LogView,
    scrolled_lines: u32,
    direction: ScrollDirection,
    style: &LogStyle,
) {
    let scrolled_lines = scrolled_lines as u16;
    if scrolled_lines >= rect.h || scroll_view.previous != rect {
        scroll_view.render_reset(buf, rect, view, style);
        return;
    }

    let highlight_changed = style.highlight != scroll_view.last_highlight;

    if highlight_changed {
        if scrolled_lines as f32 / rect.h as f32 > 0.4 {
            scroll_view.render_reset(buf, rect, view, style);
            return;
        }
        scroll_view.delta_scroll_with_highlight(buf, rect, view, scrolled_lines, direction, style);
    } else {
        match direction {
            ScrollDirection::Up => scroll_view.delta_scroll_up(buf, rect, view, scrolled_lines, style),
            ScrollDirection::Down => scroll_view.delta_scroll_down(buf, rect, view, scrolled_lines, style),
        }
    }

    scroll_view.last_highlight = style.highlight;
}

fn render_buffer_tail_reset(buf: &mut Vec<u8>, rect: Rect, view: &LogView, style: &LogStyle) -> u16 {
    let mut displayed: Vec<(LogId, LogEntry)> = Vec::new();
    let (a, b) = view.logs.slices();
    let head = view.logs.head();
    let mut remaining_v_space = rect.h as i32;

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

    let use_batch_clear = rect.y == 0 && !style.assume_blank;

    if use_batch_clear {
        vt::MoveCursor(rect.x + rect.w, rect.y + rect.h - 1).write_to_buffer(buf);
        buf.extend_from_slice(vt::CLEAR_ABOVE);
    }

    vt::MoveCursor(rect.x, rect.y).write_to_buffer(buf);

    let mut screen_lines_left = rect.h;
    let mut entries_to_render = displayed.iter().rev();

    if remaining_v_space < 0
        && let Some((log_id, entry)) = entries_to_render.next()
    {
        let skip = (-remaining_v_space) as u16;
        let rendered = render_single_entry(
            buf,
            view.logs,
            rect.w,
            entry,
            *log_id,
            skip,
            screen_lines_left,
            style,
            style.highlight,
        );
        screen_lines_left = screen_lines_left.saturating_sub(rendered);
    }

    for (log_id, entry) in entries_to_render {
        if screen_lines_left == 0 {
            break;
        }
        let rendered =
            render_single_entry(buf, view.logs, rect.w, entry, *log_id, 0, screen_lines_left, style, style.highlight);
        screen_lines_left = screen_lines_left.saturating_sub(rendered);
    }

    if !use_batch_clear && !style.assume_blank {
        for _ in 0..screen_lines_left {
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
            buf.extend_from_slice(b"\r\n");
        }
    }

    rect.h.saturating_sub(screen_lines_left)
}
