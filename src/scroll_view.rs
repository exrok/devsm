use vtui::{
    Rect,
    vt::{self, BufferWrite},
};

use crate::{
    line_width,
    log_storage::{LogEntry, LogId, LogView, Logs},
};

/// Calculates the number of vertical lines an entry will occupy when wrapped.
fn get_entry_height(entry: &LogEntry, width: u32) -> u32 {
    if entry.width == 0 {
        1
    } else {
        entry.width.div_ceil(width)
    }
}

/// Renders a single `Line` entry to the buffer, handling wrapping and partial visibility.
///
/// This function is the core of the rendering logic, designed to be called in a loop
/// to draw the contents of a viewport. It includes an optimization to render the entire
/// line's text at once if it fits completely, otherwise it falls back to splitting the
/// line into multiple physical lines.
///
/// # Returns
/// The number of physical lines that were actually rendered to the buffer.
fn render_single_entry(
    buf: &mut Vec<u8>,
    logs: &Logs,
    width: u16,
    entry: &LogEntry,
    skip_lines: u16,
    max_lines: u16,
) -> u16 {
    if max_lines == 0 {
        return 0;
    }

    let total_height = get_entry_height(entry, width as u32) as u16;
    if skip_lines >= total_height {
        return 0;
    }

    let text = unsafe { entry.text(logs) };

    // Optimization: If we are rendering the whole entry from the start and it fits.
    if skip_lines == 0 && max_lines >= total_height {
        entry.style.write_to_buffer(buf);
        buf.extend_from_slice(text.as_bytes());
        vt::clear_style(buf);
        buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        buf.extend_from_slice(b"\r\n");
        return total_height;
    }

    // Fallback to line splitting for partial rendering.
    let lines_to_render = (total_height - skip_lines).min(max_lines);
    let mut lines = line_width::naive_line_splitting(text, entry.style, width.into())
        .skip(skip_lines as usize)
        .take(lines_to_render as usize);

    if let Some((line, style)) = lines.next() {
        // Set style once for the first visible part of the line.
        style.write_to_buffer(buf);
        buf.extend_from_slice(line.as_bytes());
        buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        buf.extend_from_slice(b"\r\n");

        // Render subsequent lines without re-emitting style codes.
        for (line, _) in lines {
            buf.extend_from_slice(line.as_bytes());
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
            buf.extend_from_slice(b"\r\n");
        }
        // Clear the style at the end.
        vt::clear_style(buf);
    }

    lines_to_render
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
        Self {
            tail: Default::default(),
            next_screen_offset: Default::default(),
            previous: Rect::EMPTY,
        }
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
    /// Transitions the view from `Tail` mode to `Scroll` mode if it isn't already.
    ///
    /// This is called when a user action, like scrolling up, requires a persistent
    /// scrollback history. It populates a vector of line IDs and calculates the
    /// initial scroll position to provide a seamless transition from the tail view.
    fn scrollify(&mut self, view: LogView) -> &mut LogScrollWidget {
        if let LogWidget::Tail(tail) = self {
            // 1. Collect all valid line IDs into a vector for scrollback.
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

            // 2. Calculate the initial `top_index` and `scroll_shift_up` to match
            //    what was previously visible in the tail view.
            let logs = view.logs.indexer();
            let mut remaining_height = tail.previous.height as i32;
            let top_index = 'index: {
                for (i, id) in ids.iter().enumerate().rev() {
                    let entry = logs[*id];
                    let line_count = get_entry_height(&entry, tail.previous.width as u32);
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
                scroll_shift_up: if remaining_height < 0 {
                    (-remaining_height) as u16
                } else {
                    0
                },
                tail: LogId(line_id.0),
                previous: Rect {
                    x: tail.previous.x,
                    y: tail.previous.y,
                    width: tail.previous.width,
                    height: tail.previous.height,
                },
            };

            *self = LogWidget::Scroll(scroll_view)
        }
        // This match is a workaround for borrow-checker limitations (NLL).
        // We know from above that MultiView will always be a Scroll variant now.
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

    pub fn render(&mut self, buf: &mut Vec<u8>, rect: Rect, view: LogView) {
        match self {
            LogWidget::Scroll(scroll_view) => scroll_view.render_reset(buf, rect, view),
            LogWidget::Tail(tail_view) => tail_view.render(buf, rect, view),
        }
    }

    pub fn scroll_up(&mut self, amount: u32, buf: &mut Vec<u8>, rect: Rect, view: LogView) {
        let scroll_view = self.scrollify(view);
        let logs = view.logs.indexer();
        let mut scrolled_lines = 0;

        for _ in 0..amount {
            if scroll_view.scroll_shift_up > 0 {
                scroll_view.scroll_shift_up -= 1;
                scrolled_lines += 1;
            } else if scroll_view.min_index < scroll_view.top_index {
                scroll_view.top_index -= 1;
                let entry = logs[scroll_view.ids[scroll_view.top_index]];
                let line_count = get_entry_height(&entry, rect.width as u32);
                scroll_view.scroll_shift_up = (line_count as u16).saturating_sub(1);
                scrolled_lines += 1;
            } else {
                break;
            }
        }

        if scrolled_lines > 0 {
            handle_scroll_render(
                scroll_view,
                buf,
                rect,
                view,
                scrolled_lines,
                ScrollDirection::Up,
            );
        }
    }

    pub fn scroll_down(&mut self, amount: u32, buf: &mut Vec<u8>, rect: Rect, view: LogView) {
        let scroll_view = self.scrollify(view);
        let logs = view.logs.indexer();
        let mut scrolled_lines = 0;

        for _ in 0..amount {
            if scroll_view.top_index >= scroll_view.ids.len() {
                break;
            }
            let entry = logs[scroll_view.ids[scroll_view.top_index]];
            let line_count = get_entry_height(&entry, rect.width as u32);
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

        if scrolled_lines > 0 {
            handle_scroll_render(
                scroll_view,
                buf,
                rect,
                view,
                scrolled_lines,
                ScrollDirection::Down,
            );
        }
    }
}

enum ScrollDirection {
    Up,
    Down,
}

/// Handles the rendering logic after a scroll action.
/// It decides whether to perform an efficient incremental scroll using terminal
/// capabilities or to do a full redraw of the view.
fn handle_scroll_render(
    scroll_view: &mut LogScrollWidget,
    buf: &mut Vec<u8>,
    rect: Rect,
    view: LogView,
    scrolled_lines: u32,
    direction: ScrollDirection,
) {
    let scrolled_lines = scrolled_lines as u16;
    if scrolled_lines < rect.height && scroll_view.previous == rect {
        // Efficient path: use terminal scrolling and only draw the new lines.
        let scroll_region = vt::ScrollRegion(rect.y + 1, rect.y + rect.height);
        scroll_region.write_to_buffer(buf);

        match direction {
            ScrollDirection::Up => {
                vt::scroll_buffer_down(buf, scrolled_lines);
                vt::ScrollRegion::RESET.write_to_buffer(buf);
                scroll_view.render_top_lines(buf, rect, view, scrolled_lines);
            }
            ScrollDirection::Down => {
                vt::scroll_buffer_up(buf, scrolled_lines);
                vt::ScrollRegion::RESET.write_to_buffer(buf);
                scroll_view.render_bottom_lines(buf, rect, view, scrolled_lines);
            }
        }
        scroll_view.previous = rect;
    } else {
        // Fallback: redraw the entire view.
        scroll_view.render_reset(buf, rect, view);
    }
}

impl LogScrollWidget {
    /// Renders the visible content of the scroll view.
    ///
    /// # Returns
    /// The number of screen lines remaining in the render area.
    fn render_content(
        &self,
        buf: &mut Vec<u8>,
        rect: Rect, // Used for width
        view: LogView,
        lines_to_render: u16,
    ) -> u16 {
        let logs = view.logs.indexer();
        let mut entries = self.ids[self.top_index..].iter().map(|id| logs[*id]);
        let mut remaining_height = lines_to_render;

        // Render first entry, which might be partially scrolled due to `scroll_shift_up`.
        if let Some(entry) = entries.next() {
            if remaining_height == 0 {
                return 0;
            }
            let rendered = render_single_entry(
                buf,
                view.logs,
                rect.width,
                &entry,
                self.scroll_shift_up,
                remaining_height,
            );
            remaining_height = remaining_height.saturating_sub(rendered);
        }

        // Render subsequent entries until the requested height is filled.
        for entry in entries {
            if remaining_height == 0 {
                break;
            }
            let rendered =
                render_single_entry(buf, view.logs, rect.width, &entry, 0, remaining_height);
            remaining_height = remaining_height.saturating_sub(rendered);
        }
        remaining_height
    }

    pub fn render_reset(&mut self, buf: &mut Vec<u8>, rect: Rect, view: LogView) {
        self.previous = rect;
        // Prune IDs that have been scrolled out of the buffer's history.
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
        let remaining_height = self.render_content(buf, rect, view, rect.height);

        // Clear any remaining lines at the bottom of the rect.
        for _ in 0..remaining_height {
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
            buf.extend_from_slice(b"\r\n");
        }
    }

    fn render_top_lines(&self, buf: &mut Vec<u8>, rect: Rect, view: LogView, line_count: u16) {
        vt::move_cursor(buf, rect.x, rect.y);
        self.render_content(buf, rect, view, line_count);
    }

    fn render_bottom_lines(
        &self,
        buf: &mut Vec<u8>,
        rect: Rect,
        view: LogView,
        scrolled_lines: u16,
    ) {
        let logs = view.logs.indexer();
        let mut entries = self.ids[self.top_index..].iter().map(|id| logs[*id]);
        let mut lines_to_skip = rect.height.saturating_sub(scrolled_lines);

        // --- Find the starting entry and sub-line to render ---
        let mut start_entry = None;
        let mut sub_line_skip = 0;

        // Account for the first visible entry, which may be partially scrolled.
        if let Some(entry) = entries.next() {
            let total_height = get_entry_height(&entry, rect.width as u32) as u16;
            let visible_height = total_height.saturating_sub(self.scroll_shift_up);
            if lines_to_skip < visible_height {
                start_entry = Some(entry);
                sub_line_skip = self.scroll_shift_up + lines_to_skip;
                lines_to_skip = 0; // Found start, stop skipping.
            } else {
                lines_to_skip -= visible_height;
            }
        }

        // Iterate through subsequent entries to find the start point.
        if lines_to_skip > 0 {
            for entry in entries.by_ref() {
                let height = get_entry_height(&entry, rect.width as u32) as u16;
                if lines_to_skip < height {
                    start_entry = Some(entry);
                    sub_line_skip = lines_to_skip;
                    break;
                } else {
                    lines_to_skip -= height;
                }
            }
        }

        vt::move_cursor(buf, rect.x, rect.y + rect.height - scrolled_lines);
        let mut remaining_height = scrolled_lines;

        // --- Render content from the identified start point ---
        if let Some(entry) = start_entry {
            if remaining_height == 0 {
                return;
            }
            let rendered = render_single_entry(
                buf,
                view.logs,
                rect.width,
                &entry,
                sub_line_skip,
                remaining_height,
            );
            remaining_height = remaining_height.saturating_sub(rendered);
        }

        // Render subsequent full entries.
        for entry in entries {
            if remaining_height == 0 {
                break;
            }
            let rendered =
                render_single_entry(buf, view.logs, rect.width, &entry, 0, remaining_height);
            remaining_height = remaining_height.saturating_sub(rendered);
        }
    }
}

impl LogTailWidget {
    pub fn render(&mut self, buf: &mut Vec<u8>, rect: Rect, view: LogView) {
        if rect != self.previous {
            self.previous = rect;
            self.next_screen_offset = render_buffer_tail_reset(buf, rect, view);
            self.tail = view.tail;
            return;
        }
        let (a, b) = view.logs.slices_range(self.tail, view.tail);

        if rect.height == 0 || (a.is_empty() && b.is_empty()) {
            self.tail = view.tail;
            return;
        }
        vt::ScrollRegion(rect.y + 1, rect.y + rect.height).write_to_buffer(buf);

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
            // todo handle empty line
            offset += get_entry_height(entry, rect.width as u32);
            if first {
                first = false
            } else {
                buf.extend_from_slice(b"\n\r");
            }
            let text = unsafe { entry.text(&view.logs) };
            entry.style.write_to_buffer(buf);
            buf.extend_from_slice(text.as_bytes());
            vt::clear_style(buf);
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        }

        vt::ScrollRegion::RESET.write_to_buffer(buf);
        if offset > rect.height as u32 {
            offset = rect.height as u32
        }
        self.next_screen_offset = offset as u16;
        self.tail = view.tail;
    }
}

/// Renders the view in "tail" mode from scratch.
/// It works backwards from the most recent line to fill the screen.
fn render_buffer_tail_reset(buf: &mut Vec<u8>, rect: Rect, view: LogView) -> u16 {
    // 1. Collect visible lines from the tail of the buffer, going backwards.
    // This temporary allocation is acceptable as it only happens on a full reset.
    let mut displayed: Vec<LogEntry> = Vec::new();
    let (a, b) = view.logs.slices();
    let mut remaining_v_space = rect.height as i32;
    'outer: for slice in [b, a] {
        for entry in slice.iter().rev() {
            if !view.contains(entry) {
                continue;
            }
            let line_count = get_entry_height(entry, rect.width as u32);
            remaining_v_space -= line_count as i32;
            displayed.push(*entry);
            if remaining_v_space <= 0 {
                break 'outer;
            }
        }
    }

    // 2. Render the collected lines, from top to bottom.
    vt::move_cursor(buf, rect.x, rect.y);
    let mut screen_lines_left = rect.height;
    let mut entries_to_render = displayed.iter().rev();

    // The first chronological entry might be partially visible at the top.
    if remaining_v_space < 0 {
        if let Some(entry) = entries_to_render.next() {
            let skip = (-remaining_v_space) as u16;
            let rendered =
                render_single_entry(buf, view.logs, rect.width, entry, skip, screen_lines_left);
            screen_lines_left = screen_lines_left.saturating_sub(rendered);
        }
    }

    // Render the rest of the entries that fit fully.
    for entry in entries_to_render {
        if screen_lines_left == 0 {
            break;
        }
        let rendered = render_single_entry(buf, view.logs, rect.width, entry, 0, screen_lines_left);
        screen_lines_left = screen_lines_left.saturating_sub(rendered);
    }

    // 3. Clear any unused space at the bottom of the rect.
    for _ in 0..screen_lines_left {
        buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        buf.extend_from_slice(b"\r\n");
    }

    // Return the number of lines occupied by content.
    rect.height.saturating_sub(screen_lines_left)
}

#[cfg(test)]
mod test {
    // ... tests remain unchanged ...
    use std::{
        io::{LineWriter, Write},
        os::unix::process,
    };

    use vtui::{Rect, Style, vt};

    use crate::{
        log_storage::{JobId, LogWriter, Logs},
        scroll_view::{LogTailWidget, LogWidget},
    };

    #[track_caller]
    fn expect(parser: &vt100::Parser, content: &[&str]) {
        for (i, (row, expected)) in parser.screen().rows(0, 8).zip(content).enumerate() {
            let expected = expected.trim_ascii_end();
            if row == *expected {
                continue;
            }
            println!("{}", parser.screen().contents());
            panic!(
                "Row {} did not match expected content. \nExpected: {:?} \n   Found: {:?}",
                i, expected, row
            );
        }
    }

    fn estimate_byte_cost(buf: &[u8]) -> usize {
        std::str::from_utf8(buf)
            .unwrap()
            .split("Line")
            .count()
            .saturating_sub(1)
            * 60
            + buf.len()
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

        let rect = Rect {
            x: 0,
            y: 1,
            width: 8,
            height: 4,
        };
        let mut writer = LogWriter::new();
        let logs = writer.reader();
        let mut view = LogWidget::default();
        view.render(&mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "        "
            "        "
            "        "
            "        "
        }
        writer.push("Line 0");
        view.render(&mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "        "
            "        "
            "        "
        }
        writer.push("Line 1");
        view.render(&mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "        "
            "        "
        }
        writer.push("Line 2");
        view.render(&mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "        "
        }
        writer.push("Line 3");
        view.render(&mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        writer.push("Line 4");
        view.render(&mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        writer.push("Line 5");
        view.render(&mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 2  "
            "Line 3  "
            "Line 4  "
            "Line 5  "
        }
        writer.push("head1234Line 6");
        view.render(&mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 4  "
            "Line 5  "
            "head1234"
            "Line 6  "
        }
        view.scroll_up(1, &mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 3  "
            "Line 4  "
            "Line 5  "
            "head1234"
        }
        view.scroll_up(1, &mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 2  "
            "Line 3  "
            "Line 4  "
            "Line 5  "
        }
        view.scroll_up(1, &mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        view.scroll_up(1, &mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        view.scroll_up(1, &mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        view.scroll_down(1, &mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        view.scroll_down(2, &mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 3  "
            "Line 4  "
            "Line 5  "
            "head1234"
        }
        view.scroll_down(1, &mut buf, rect, logs.read().unwrap().view_all());
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
        view.scroll_down(1, &mut buf, rect, logs.read().unwrap().view_all());
        assert_scrollview! {
            "Line 5  "
            "head1234"
            "Line 6  "
            "Line 7  "
        }
        println!("VT {} bytes written", total_written);
    }
}
