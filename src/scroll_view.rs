use vtui::{
    Rect,
    vt::{self, BufferWrite},
};

use crate::{
    line_buffer::{Line, LineId, LineTable, LineTableView},
    line_width, scroll_view,
};

#[derive(Debug)]
pub struct ScrollView {
    top_index: usize,
    min_index: usize,
    ids: Vec<LineId>,
    scroll_shift_up: u16,
    tail: LineId,
    previous: Rect,
}

impl Default for MultiView {
    fn default() -> Self {
        MultiView::Tail(TailView::default())
    }
}
pub enum MultiView {
    Scroll(ScrollView),
    Tail(TailView),
}

impl MultiView {
    fn scrollify(&mut self, view: LineTableView) -> &mut ScrollView {
        if let MultiView::Tail(tail) = self {
            let mut ids = Vec::new();
            let mut line_id = view.table.head();
            let (a, b) = view.table.slices_range(LineId(0), view.tail);
            for slice in [a, b] {
                for entry in slice {
                    if view.contains(entry) {
                        ids.push(line_id);
                    }
                    line_id.0 += 1;
                }
            }
            let table = view.table.indexer();
            let mut remaining_height = tail.previous.height as i32;
            let top_index = 'index: {
                for (i, id) in ids.iter().enumerate().rev() {
                    let entry = table[*id];
                    let line_count = if entry.width == 0 {
                        1
                    } else {
                        entry.width.div_ceil(tail.previous.width as u32)
                    };
                    remaining_height -= line_count as i32;
                    if remaining_height <= 0 {
                        break 'index i;
                    }
                }
                0
            };
            let scroll_view = ScrollView {
                top_index,
                min_index: 0,
                ids,
                scroll_shift_up: if remaining_height < 0 {
                    (-remaining_height) as u16
                } else {
                    0
                },
                tail: LineId(line_id.0.saturating_sub(1)),
                previous: Rect {
                    x: 0,
                    y: 0,
                    width: 0,
                    height: 0,
                },
            };

            *self = MultiView::Scroll(scroll_view)
        }
        // workout for NL limitiation
        match self {
            MultiView::Scroll(scroll_view) => scroll_view,
            MultiView::Tail(_) => unreachable!(),
        }
    }
    pub fn render(&mut self, buf: &mut Vec<u8>, rect: Rect, view: LineTableView) {
        match self {
            MultiView::Scroll(scroll_view) => {
                scroll_view.render_reset(buf, rect, view);
            }
            MultiView::Tail(tail_view) => {
                tail_view.render(buf, rect, view);
            }
        }
    }
    pub fn scroll_up(&mut self, amount: u32, buf: &mut Vec<u8>, rect: Rect, view: LineTableView) {
        let scroll_view = self.scrollify(view);
        if scroll_view.scroll_shift_up == 0 {
            if scroll_view.min_index < scroll_view.top_index {
                scroll_view.top_index -= 1;
                // should comute scroll_shift up
            }
        }
        scroll_view.render_reset(buf, rect, view);
    }
    pub fn scroll_down(&mut self, amount: u32, buf: &mut Vec<u8>, rect: Rect, view: LineTableView) {
        let scroll_view = self.scrollify(view);
        scroll_view.top_index += 1;

        scroll_view.render_reset(buf, rect, view);
    }
}

impl ScrollView {
    pub fn render_reset(&mut self, buf: &mut Vec<u8>, rect: Rect, view: LineTableView) {
        self.previous = rect;
        let ids = {
            let mut ids = self.ids.get(self.top_index..).unwrap_or_default();
            while let [id, rest @ ..] = ids {
                if *id < view.table.head() {
                    self.top_index += 1;
                    // optimize not setting these repeatingly
                    self.min_index = self.top_index;
                    self.scroll_shift_up = 0;
                    ids = rest;
                } else {
                    break;
                }
            }
            ids
        };
        let table = view.table.indexer();
        vt::move_cursor(buf, rect.x, rect.y);
        let mut entries = ids.iter().map(|id| table[*id]);
        let mut remaining_height = rect.height as i32;
        if self.scroll_shift_up > 0 {
            if let Some(entry) = entries.next() {
                let text = unsafe { entry.text(&view.table) };
                let mut first = true;
                for (line, style) in
                    line_width::naive_line_splitting(text, entry.style, rect.width.into())
                        .skip(self.scroll_shift_up as usize)
                {
                    // todo need to handle fun
                    if first {
                        style.write_to_buffer(buf);
                        first = false;
                    }
                    buf.extend_from_slice(line.as_bytes());
                    buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
                    buf.extend_from_slice(b"\r\n");
                    remaining_height -= 1;
                    if remaining_height <= 0 {
                        break;
                    }
                }
            }
        }
        for entry in entries {
            if remaining_height <= 0 {
                break;
            }
            let text = unsafe { entry.text(view.table) };
            kvlog::info!("scroll_view {:?}", text);
            let height = if entry.width == 0 {
                1
            } else {
                entry.width.div_ceil(rect.width as u32)
            };
            if height as i32 > remaining_height {
                let mut first = true;
                for (line, style) in
                    line_width::naive_line_splitting(text, entry.style, rect.width.into())
                        .take(remaining_height as usize)
                {
                    // todo need to handle fun
                    if first {
                        style.write_to_buffer(buf);
                        first = false;
                    }
                    buf.extend_from_slice(line.as_bytes());
                    buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
                    buf.extend_from_slice(b"\r\n");
                }
                remaining_height = 0;
                break;
            }
            remaining_height -= height as i32;
            entry.style.write_to_buffer(buf);
            buf.extend_from_slice(text.as_bytes());
            vt::clear_style(buf);
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
            buf.extend_from_slice(b"\r\n");
        }
        while remaining_height > 0 {
            buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
            buf.extend_from_slice(b"\r\n");
            remaining_height -= 1;
        }
    }
}

struct LineSearch {
    ids: Vec<LineId>,
}
impl Default for TailView {
    fn default() -> Self {
        Self {
            tail: Default::default(),
            next_screen_offset: Default::default(),
            previous: Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
        }
    }
}

// pub struct LineSet {
//     tail: LineId,
//     table:
// }

pub struct TailView {
    tail: LineId,
    next_screen_offset: u16,
    previous: Rect,
}

impl TailView {
    pub fn render(&mut self, buf: &mut Vec<u8>, rect: Rect, view: LineTableView) {
        kvlog::info!("screen_offset", screen_offset = self.next_screen_offset);
        if rect != self.previous {
            self.previous = rect;
            self.next_screen_offset = render_buffer_tail_reset(buf, rect, view);
            self.tail = view.tail;
            return;
        }
        let (a, b) = view.table.slices_range(self.tail, view.tail);

        if rect.height == 0 || (a.is_empty() && b.is_empty()) {
            self.tail = view.tail;
            return;
        }
        vt::ScrollRegion(rect.y + 1, rect.y + rect.height).write_to_buffer(buf);

        vt::move_cursor(buf, rect.x, rect.y + self.next_screen_offset - 1);
        let mut offset = self.next_screen_offset as u32;
        for entry in a.iter().chain(b.iter()) {
            if !view.contains(entry) {
                continue;
            }
            // todo handle empty line
            offset += entry.width.div_ceil(rect.width as u32);
            buf.extend_from_slice(b"\n\r");
            let text = unsafe { entry.text(&view.table) };
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

fn render_buffer_tail_push(
    buf: &mut Vec<u8>,
    rect: Rect,
    screen_offset: u16,
    min_id: LineId,
    lines: &LineTable,
    mut filter: impl FnMut(&Line) -> bool,
) -> (u16, LineId) {
    let (a, b, end) = lines.slices_from(min_id);
    if rect.height == 0 {
        return (0, end);
    }
    // todo only enabled when needed

    vt::ScrollRegion(rect.y + 1, rect.y + rect.height).write_to_buffer(buf);

    vt::move_cursor(buf, rect.x, rect.y + screen_offset - 1);
    let mut offset = screen_offset as u32;
    for entry in a.iter().chain(b.iter()) {
        if !filter(entry) {
            continue;
        }
        // todo handle empty line
        offset += entry.width.div_ceil(rect.width as u32);
        buf.extend_from_slice(b"\n\r");
        let text = unsafe { entry.text(lines) };
        entry.style.write_to_buffer(buf);
        buf.extend_from_slice(text.as_bytes());
        vt::clear_style(buf);
        buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
    }

    vt::ScrollRegion::RESET.write_to_buffer(buf);
    if offset > rect.height as u32 {
        offset = rect.height as u32
    }
    (offset as u16, end)
}

// not filter yet
fn render_buffer_tail_reset(buf: &mut Vec<u8>, rect: Rect, view: LineTableView) -> u16 {
    let mut displayed: Vec<Line> = Vec::new();
    let (a, b) = view.table.slices();
    let mut remaining_height = rect.height as i32;
    'outer: for slice in [b, a] {
        for entry in slice.iter().rev() {
            if !view.contains(entry) {
                continue;
            }
            let line_count = if entry.width == 0 {
                1
            } else {
                entry.width.div_ceil(rect.width as u32)
            };
            remaining_height -= line_count as i32;
            displayed.push(*entry);
            if remaining_height <= 0 {
                break 'outer;
            }
        }
    }
    render_buffer_tail_reset_inner(buf, rect, view.table, &displayed, remaining_height)
}

fn render_buffer_tail_reset_inner(
    buf: &mut Vec<u8>,
    rect: Rect,
    table: &LineTable,
    displayed: &[Line],
    mut remaining_height: i32,
) -> u16 {
    vt::move_cursor(buf, rect.x, rect.y);
    let mut entries = displayed.iter().rev();
    if remaining_height < 0 {
        if let Some(entry) = entries.next() {
            let text = unsafe { entry.text(table) };
            let mut first = true;
            for (line, style) in
                line_width::naive_line_splitting(text, entry.style, rect.width.into())
                    .skip(-remaining_height as usize)
            {
                if first {
                    style.write_to_buffer(buf);
                    first = false;
                }
                buf.extend_from_slice(line.as_bytes());
                buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
                buf.extend_from_slice(b"\r\n");
            }
        }
    }
    for entries in entries {
        let text = unsafe { entries.text(table) };
        entries.style.write_to_buffer(buf);
        buf.extend_from_slice(text.as_bytes());
        vt::clear_style(buf);
        buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        buf.extend_from_slice(b"\r\n");
    }
    let offset = rect.height as i32 - remaining_height;
    while remaining_height > 0 {
        buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        buf.extend_from_slice(b"\r\n");
        remaining_height -= 1;
    }
    (offset as u16).min(rect.height)
}

#[cfg(test)]
mod test {
    use std::{
        io::{LineWriter, Write},
        os::unix::process,
    };

    use vtui::{Rect, Style, vt};

    use crate::{
        line_buffer::{JobId, LineTable, LineTableWriter},
        scroll_view::{MultiView, TailView},
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
        let mut writer = LineTableWriter::new();
        let table = writer.reader();
        let mut view = MultiView::default();
        view.render(&mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "        "
            "        "
            "        "
            "        "
        }
        writer.push("Line 0");
        view.render(&mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "        "
            "        "
            "        "
        }
        writer.push("Line 1");
        view.render(&mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "        "
            "        "
        }
        writer.push("Line 2");
        view.render(&mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "        "
        }
        writer.push("Line 3");
        view.render(&mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        writer.push("Line 4");
        view.render(&mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        writer.push("Line 5");
        view.render(&mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 2  "
            "Line 3  "
            "Line 4  "
            "Line 5  "
        }
        writer.push("padd1234Line 6");
        view.render(&mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 4  "
            "Line 5  "
            "padd1234"
            "Line 6  "
        }
        view.scroll_up(1, &mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 3  "
            "Line 4  "
            "Line 5  "
            "padd1234"
        }
        view.scroll_up(1, &mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 2  "
            "Line 3  "
            "Line 4  "
            "Line 5  "
        }
        view.scroll_up(1, &mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        view.scroll_up(1, &mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        view.scroll_up(1, &mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 0  "
            "Line 1  "
            "Line 2  "
            "Line 3  "
        }
        view.scroll_down(1, &mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 1  "
            "Line 2  "
            "Line 3  "
            "Line 4  "
        }
        view.scroll_down(1, &mut buf, rect, table.read().unwrap().view_all());
        view.scroll_down(1, &mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 3  "
            "Line 4  "
            "Line 5  "
            "padd1234"
        }
        view.scroll_down(1, &mut buf, rect, table.read().unwrap().view_all());
        assert_scrollview! {
            "Line 4  "
            "Line 5  "
            "padd1234"
            "Line 6  "
        }
        println!("VT {} bytes written", total_written);
    }
}
