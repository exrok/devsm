use extui::{Rect, vt, vt::BufferWrite};

use crate::{
    line_width::MatchHighlight,
    log_storage::{LogId, LogWriter},
    scroll_view::{LogHighlight, LogStyle, LogWidget, Prefix, get_entry_height},
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

    vt::MoveCursor(0, 0).write_to_buffer(&mut buf);
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
    let style = LogStyle {
        prefixes: vec![prefix.clone(), prefix],
        assume_blank: false,
        highlight: None,
        skip_rect: None,
    };

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

#[test]
fn batch_clear_optimization_at_y_zero() {
    let mut parser = vt100::Parser::new(10, 20, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 0, w: 20, h: 10 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();
    let style = LogStyle::default();

    for i in 0..3 {
        writer.push(&format!("Line {}", i));
    }

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);

    let byte_count_optimized = buf.len();
    buf.clear();

    assert!(
        byte_count_optimized < 150,
        "Byte count {} should be reduced with CLEAR_ABOVE optimization",
        byte_count_optimized
    );

    for (i, row) in parser.screen().rows(0, 20).enumerate() {
        if i < 3 {
            assert!(row.starts_with("Line"), "Row {} should have content", i);
        } else if i < 10 {
            assert!(row.trim().is_empty(), "Row {} should be blank", i);
        }
    }
}

#[test]
fn no_batch_clear_when_y_nonzero() {
    let mut parser = vt100::Parser::new(12, 20, 0);
    let mut buf = Vec::new();

    vt::MoveCursor(0, 0).write_to_buffer(&mut buf);
    buf.extend_from_slice(b"HEADER LINE         ");
    parser.process(&buf);
    buf.clear();

    let rect = Rect { x: 0, y: 1, w: 20, h: 10 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();
    let style = LogStyle::default();

    for i in 0..3 {
        writer.push(&format!("Line {}", i));
    }

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let first_row = parser.screen().rows(0, 20).next().unwrap();
    assert_eq!(first_row.trim(), "HEADER LINE", "Header should be preserved when rect.y != 0");

    for (i, row) in parser.screen().rows(0, 20).skip(1).enumerate() {
        if i < 3 {
            assert!(row.starts_with("Line"), "Row {} should have content", i + 1);
        }
    }
}

#[test]
fn reset_uses_batch_clear_at_y_zero() {
    let mut parser = vt100::Parser::new(10, 20, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 0, w: 20, h: 10 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();
    let style = LogStyle::default();

    for i in 0..5 {
        writer.push(&format!("Line {}", i));
    }
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    let initial_len = buf.len();
    buf.clear();

    view.scroll_up(2, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view = LogWidget::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    let reset_len = buf.len();
    buf.clear();

    assert!(
        reset_len <= initial_len + 50,
        "Reset render ({} bytes) should be similar to initial ({} bytes)",
        reset_len,
        initial_len
    );

    for (i, row) in parser.screen().rows(0, 20).enumerate() {
        if i < 5 {
            assert!(row.starts_with("Line"), "Row {} should have content", i);
        } else if i < 10 {
            assert!(row.trim().is_empty(), "Row {} should be blank", i);
        }
    }
}

#[test]
fn highlight_delta_scroll_up() {
    let mut parser = vt100::Parser::new(6, 10, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 10, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..8 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(3, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let mut style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(2), match_info: MatchHighlight { start: 5, len: 1 } }),
        ..Default::default()
    };

    view.scroll_up(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);
    buf.clear();

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 0"), "Should show Line 0 after scroll up: '{}'", screen_content);

    style_hl.highlight = Some(LogHighlight { log_id: LogId(1), match_info: MatchHighlight { start: 5, len: 1 } });

    view.scroll_up(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 0"), "Should still show Line 0 after second scroll up: '{}'", screen_content);
}

#[test]
fn highlight_delta_scroll_down() {
    let mut parser = vt100::Parser::new(6, 10, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 10, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..8 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(4, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 0"), "After scroll_up(4): '{}'", screen_content);

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(2), match_info: MatchHighlight { start: 5, len: 1 } }),
        ..Default::default()
    };

    view.scroll_down(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);

    let screen_content = parser.screen().contents();
    assert!(
        screen_content.contains("Line 1") && screen_content.contains("Line 4"),
        "After scroll_down(1) with highlight: '{}'",
        screen_content
    );
}

#[test]
fn highlight_delta_multiline_entry() {
    let mut parser = vt100::Parser::new(10, 8, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 0, w: 8, h: 8 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..3 {
        writer.push(&format!("Line {}", i));
    }
    writer.push("LongLine");
    for i in 4..10 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(2, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(3), match_info: MatchHighlight { start: 0, len: 4 } }),
        ..Default::default()
    };

    view.scroll_up(1, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("LongLine"), "Should show multiline entry");
}

#[test]
fn highlight_delta_threshold() {
    let mut parser = vt100::Parser::new(10, 10, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 0, w: 10, h: 10 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..15 {
        writer.push(&format!("Line {:02}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(5, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(5), match_info: MatchHighlight { start: 5, len: 2 } }),
        ..Default::default()
    };

    view.scroll_up(5, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 00"), "Large scroll should render Line 00");
}

#[test]
fn highlight_delta_offscreen() {
    let mut parser = vt100::Parser::new(6, 10, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 10, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..10 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(6, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(0), match_info: MatchHighlight { start: 5, len: 1 } }),
        ..Default::default()
    };

    view.scroll_down(2, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);

    let screen_content = parser.screen().contents();
    assert!(
        screen_content.contains("Line 2"),
        "Should render correctly when old highlight is offscreen: '{}'",
        screen_content
    );
}

#[test]
fn highlight_delta_byte_efficiency() {
    let rect = Rect { x: 0, y: 1, w: 20, h: 8 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();

    for i in 0..12 {
        writer.push(&format!("Line {:02}", i));
    }

    let style = LogStyle::default();
    let mut view_delta = LogWidget::default();
    let mut buf_delta = Vec::new();
    view_delta.render(&mut buf_delta, rect, &logs.read().unwrap().view_all(), &style);
    buf_delta.clear();

    view_delta.scroll_up(2, &mut buf_delta, rect, &logs.read().unwrap().view_all(), &style);
    buf_delta.clear();

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(3), match_info: MatchHighlight { start: 5, len: 2 } }),
        ..Default::default()
    };
    view_delta.scroll_down(1, &mut buf_delta, rect, &logs.read().unwrap().view_all(), &style_hl);
    let delta_bytes = buf_delta.len();

    let mut view_reset = LogWidget::default();
    let mut buf_reset = Vec::new();
    view_reset.render(&mut buf_reset, rect, &logs.read().unwrap().view_all(), &style);
    buf_reset.clear();

    view_reset.scroll_up(1, &mut buf_reset, rect, &logs.read().unwrap().view_all(), &style);
    buf_reset.clear();

    if let LogWidget::Scroll(scroll_view) = &mut view_reset {
        scroll_view.render_reset(&mut buf_reset, rect, &logs.read().unwrap().view_all(), &style_hl);
    }
    let reset_bytes = buf_reset.len();

    assert!(
        delta_bytes > 0 && reset_bytes > 0,
        "Both methods should write bytes (delta={}, reset={})",
        delta_bytes,
        reset_bytes
    );

    assert!(
        delta_bytes < reset_bytes,
        "Delta scroll with highlight ({} bytes) should be more efficient than full reset ({} bytes)",
        delta_bytes,
        reset_bytes
    );
}

#[test]
fn highlight_only_change_no_scroll() {
    let mut parser = vt100::Parser::new(6, 10, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 10, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..8 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(4, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl1 = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(1), match_info: MatchHighlight { start: 5, len: 1 } }),
        ..Default::default()
    };

    view.scroll_up(0, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl1);
    parser.process(&buf);
    let first_hl_bytes = buf.len();
    buf.clear();

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 0"), "Should still show Line 0: '{}'", screen_content);

    let style_hl2 = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(2), match_info: MatchHighlight { start: 5, len: 1 } }),
        ..Default::default()
    };

    view.scroll_up(0, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl2);
    parser.process(&buf);
    let change_hl_bytes = buf.len();
    buf.clear();

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 0"), "Should still show Line 0: '{}'", screen_content);

    assert!(first_hl_bytes > 0, "Adding highlight should write bytes");
    assert!(change_hl_bytes > 0, "Changing highlight should write bytes");
}

#[test]
fn highlight_only_change_via_render() {
    let mut parser = vt100::Parser::new(6, 10, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 10, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..8 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(4, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(2), match_info: MatchHighlight { start: 5, len: 1 } }),
        ..Default::default()
    };

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);
    let delta_bytes = buf.len();
    buf.clear();

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 0"), "Should still show Line 0: '{}'", screen_content);

    let mut view_reset = LogWidget::default();
    let mut buf_reset = Vec::new();
    view_reset.render(&mut buf_reset, rect, &logs.read().unwrap().view_all(), &style);
    buf_reset.clear();

    view_reset.scroll_up(4, &mut buf_reset, rect, &logs.read().unwrap().view_all(), &style);
    buf_reset.clear();

    if let LogWidget::Scroll(scroll_view) = &mut view_reset {
        scroll_view.render_reset(&mut buf_reset, rect, &logs.read().unwrap().view_all(), &style_hl);
    }
    let reset_bytes = buf_reset.len();

    assert!(delta_bytes > 0, "Delta highlight should write bytes: {}", delta_bytes);
    assert!(
        delta_bytes < reset_bytes,
        "Delta highlight ({} bytes) should be more efficient than full reset ({} bytes)",
        delta_bytes,
        reset_bytes
    );
}

#[test]
fn highlight_remove_optimization() {
    let mut parser = vt100::Parser::new(6, 10, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 10, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..8 {
        writer.push(&format!("Line {}", i));
    }

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(2), match_info: MatchHighlight { start: 5, len: 1 } }),
        ..Default::default()
    };
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(4, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);
    buf.clear();

    let style_no_hl = LogStyle::default();

    view.scroll_up(0, &mut buf, rect, &logs.read().unwrap().view_all(), &style_no_hl);
    parser.process(&buf);
    let remove_bytes = buf.len();

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 0"), "Should still show Line 0: '{}'", screen_content);
    assert!(remove_bytes > 0, "Removing highlight should write bytes: {}", remove_bytes);
}

#[test]
fn highlight_same_entry_different_match() {
    let mut parser = vt100::Parser::new(6, 10, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 10, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..8 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(4, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl1 = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(2), match_info: MatchHighlight { start: 0, len: 4 } }),
        ..Default::default()
    };

    view.scroll_up(0, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl1);
    parser.process(&buf);
    buf.clear();

    let style_hl2 = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(2), match_info: MatchHighlight { start: 5, len: 1 } }),
        ..Default::default()
    };

    view.scroll_up(0, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl2);
    parser.process(&buf);
    let change_match_bytes = buf.len();

    let screen_content = parser.screen().contents();
    assert!(screen_content.contains("Line 0"), "Should still show Line 0: '{}'", screen_content);
    assert!(change_match_bytes > 0, "Changing match position on same entry should write bytes: {}", change_match_bytes);
}

#[test]
fn highlight_styling_applied() {
    let mut parser = vt100::Parser::new(6, 20, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 20, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    writer.push("Hello World");
    writer.push("Test Line");

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(0), match_info: MatchHighlight { start: 6, len: 5 } }),
        ..Default::default()
    };
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);

    let screen = parser.screen();

    let cell_before_hl = screen.cell(1, 5).unwrap();
    assert!(
        cell_before_hl.bgcolor() == vt100::Color::Default,
        "Cell before highlight should have default background, got {:?}",
        cell_before_hl.bgcolor()
    );

    let cell_in_hl = screen.cell(1, 6).unwrap();
    assert!(
        cell_in_hl.bgcolor() != vt100::Color::Default,
        "Highlighted cell should have non-default background, got {:?}",
        cell_in_hl.bgcolor()
    );

    let cell_after_hl = screen.cell(1, 11).unwrap();
    assert!(
        cell_after_hl.bgcolor() == vt100::Color::Default,
        "Cell after highlight should have default background, got {:?}",
        cell_after_hl.bgcolor()
    );
}

#[test]
fn highlight_only_renders_affected_lines() {
    let mut parser = vt100::Parser::new(12, 20, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 20, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..10 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(5, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(2), match_info: MatchHighlight { start: 0, len: 4 } }),
        ..Default::default()
    };

    view.scroll_up(0, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);
    let hl_bytes = buf.len();

    assert!(hl_bytes > 0, "Highlight delta should write bytes: {}", hl_bytes);

    let screen = parser.screen();
    let cell_hl = screen.cell(2, 0).unwrap();
    assert!(
        cell_hl.bgcolor() != vt100::Color::Default,
        "Highlighted cell at 'Line' should have non-default background, got {:?}",
        cell_hl.bgcolor()
    );
}

#[test]
fn search_mode_no_scroll_past_end() {
    let mut parser = vt100::Parser::new(8, 20, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 20, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..6 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(2, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(4), match_info: MatchHighlight { start: 0, len: 4 } }),
        ..Default::default()
    };

    view.scroll_down(10, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl);
    parser.process(&buf);

    assert!(matches!(view, LogWidget::Scroll(_)), "Should stay in scroll mode when searching");

    if let LogWidget::Scroll(sv) = &view {
        let logs_indexer = logs.read().unwrap();
        let log_view = logs_indexer.view_all();
        let indexer = log_view.logs.indexer();

        let mut height = 0u32;
        if let Some(&id) = sv.ids.get(sv.top_index) {
            let entry = indexer[id];
            let full_h = get_entry_height(&entry, &style_hl, rect.w as u32);
            height += full_h.saturating_sub(sv.scroll_shift_up as u32);
        }
        for &id in &sv.ids[sv.top_index + 1..] {
            let entry = indexer[id];
            height += get_entry_height(&entry, &style_hl, rect.w as u32);
        }

        assert!(
            height <= rect.h as u32,
            "When searching, should not scroll past where all content is visible. Height {} > rect.h {}",
            height,
            rect.h
        );
    }

    let screen = parser.screen();
    let screen_content = screen.contents();
    assert!(screen_content.contains("Line 5"), "Should show last entry: {}", screen_content);
}

#[test]
fn highlight_shrink_unhighlights_suffix() {
    let mut parser = vt100::Parser::new(6, 20, 0);
    let mut buf = Vec::new();
    let rect = Rect { x: 0, y: 1, w: 20, h: 4 };

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..6 {
        writer.push(&format!("Line {}", i));
    }

    let style = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    view.scroll_up(2, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let style_hl_long = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(1), match_info: MatchHighlight { start: 0, len: 4 } }),
        ..Default::default()
    };
    view.scroll_up(0, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl_long);
    parser.process(&buf);
    buf.clear();

    let screen = parser.screen();
    let cell_at_3 = screen.cell(2, 3).unwrap();
    assert!(
        cell_at_3.bgcolor() != vt100::Color::Default,
        "Cell at position 3 ('e' in 'Line') should be highlighted before shrink, got {:?}",
        cell_at_3.bgcolor()
    );

    let style_hl_short = LogStyle {
        highlight: Some(LogHighlight { log_id: LogId(1), match_info: MatchHighlight { start: 0, len: 2 } }),
        ..Default::default()
    };
    view.scroll_up(0, &mut buf, rect, &logs.read().unwrap().view_all(), &style_hl_short);
    parser.process(&buf);

    let screen = parser.screen();

    let cell_at_0 = screen.cell(2, 0).unwrap();
    assert!(
        cell_at_0.bgcolor() != vt100::Color::Default,
        "Cell at position 0 ('L') should still be highlighted, got {:?}",
        cell_at_0.bgcolor()
    );

    let cell_at_1 = screen.cell(2, 1).unwrap();
    assert!(
        cell_at_1.bgcolor() != vt100::Color::Default,
        "Cell at position 1 ('i') should still be highlighted, got {:?}",
        cell_at_1.bgcolor()
    );

    let cell_at_2 = screen.cell(2, 2).unwrap();
    assert!(
        cell_at_2.bgcolor() == vt100::Color::Default,
        "Cell at position 2 ('n') should be un-highlighted after shrink, got {:?}",
        cell_at_2.bgcolor()
    );

    let cell_at_3 = screen.cell(2, 3).unwrap();
    assert!(
        cell_at_3.bgcolor() == vt100::Color::Default,
        "Cell at position 3 ('e') should be un-highlighted after shrink, got {:?}",
        cell_at_3.bgcolor()
    );
}

/// Setting `skip_rect` on a tail-mode render should leave the band untouched —
/// rows inside the rect must keep whatever was on screen before the render.
#[test]
fn skip_rect_tail_reset_preserves_band() {
    let mut parser = vt100::Parser::new(12, 10, 0);
    let mut buf = Vec::new();

    let mut seed = Vec::new();
    vt::MoveCursor(0, 2).write_to_buffer(&mut seed);
    seed.extend_from_slice(b"OVERLAY_A");
    vt::MoveCursor(0, 3).write_to_buffer(&mut seed);
    seed.extend_from_slice(b"OVERLAY_B");
    vt::MoveCursor(0, 4).write_to_buffer(&mut seed);
    seed.extend_from_slice(b"OVERLAY_C");
    parser.process(&seed);

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..6 {
        writer.push(&format!("L{}", i));
    }

    let rect = Rect { x: 0, y: 0, w: 10, h: 6 };
    let style = LogStyle { skip_rect: Some(Rect { x: 0, y: 2, w: 10, h: 3 }), ..Default::default() };

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let rows: Vec<String> = parser.screen().rows(0, 10).take(7).collect();
    assert!(rows[2].starts_with("OVERLAY_A"), "row 2 overlay preserved, got {:?}", rows[2]);
    assert!(rows[3].starts_with("OVERLAY_B"), "row 3 overlay preserved, got {:?}", rows[3]);
    assert!(rows[4].starts_with("OVERLAY_C"), "row 4 overlay preserved, got {:?}", rows[4]);

    assert!(
        rows[0].starts_with("L0") || rows[0].starts_with('L'),
        "rows above skip band should show log content, got {:?}",
        rows[0]
    );
    assert!(rows[1].starts_with("L1") || rows[1].starts_with('L'), "row 1 should show log, got {:?}", rows[1]);
    assert!(rows[5].starts_with('L'), "rows below skip band should show log content, got {:?}", rows[5]);
}

/// After the overlay closes (skip_rect transitions from Some to None), the
/// next render must fully repaint the area the overlay was covering.
#[test]
fn skip_rect_close_repaints_band() {
    let mut parser = vt100::Parser::new(6, 10, 0);
    let mut buf = Vec::new();

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..8 {
        writer.push(&format!("line{}", i));
    }

    let rect = Rect { x: 0, y: 0, w: 10, h: 8 };

    let style_with_skip = LogStyle {
        skip_rect: Some(Rect { x: 0, y: 2, w: 10, h: 3 }),
        ..Default::default()
    };
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style_with_skip);
    parser.process(&buf);
    buf.clear();

    let mut seed = Vec::new();
    vt::MoveCursor(0, 2).write_to_buffer(&mut seed);
    seed.extend_from_slice(b"PALETTE");
    vt::MoveCursor(0, 3).write_to_buffer(&mut seed);
    seed.extend_from_slice(b"STATE");
    parser.process(&seed);

    let style_without_skip = LogStyle::default();
    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style_without_skip);
    parser.process(&buf);
    buf.clear();

    let rows: Vec<String> = parser.screen().rows(0, 10).take(8).collect();
    for (i, row) in rows.iter().enumerate() {
        assert!(
            !row.contains("PALETTE") && !row.contains("STATE"),
            "row {} should not contain overlay leftovers, got {:?}",
            i,
            row
        );
    }
    let has_log_content = rows.iter().any(|r| r.contains("line"));
    assert!(has_log_content, "after skip_rect cleared, log content should repaint: {:?}", rows);
}

/// A narrow `skip_rect` (cutout smaller than the log rect) must leave the
/// cells inside the skip untouched while still rendering log content in
/// the left and right side columns of the rows it covers — the command
/// palette depends on both halves being honored.
#[test]
fn skip_rect_narrow_renders_side_columns() {
    let mut parser = vt100::Parser::new(12, 20, 0);
    let mut buf = Vec::new();

    let mut seed = Vec::new();
    for row in 2..5 {
        vt::MoveCursor(5, row).write_to_buffer(&mut seed);
        seed.extend_from_slice(b"[PAL]");
    }
    parser.process(&seed);

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..8 {
        writer.push(&format!("LL{:02}_mmmm_RRRRRRR_", i));
    }

    let rect = Rect { x: 0, y: 0, w: 20, h: 8 };
    let style = LogStyle {
        skip_rect: Some(Rect { x: 5, y: 2, w: 5, h: 3 }),
        ..Default::default()
    };

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let rows: Vec<String> = parser.screen().rows(0, 20).take(8).collect();

    for (i, row) in rows.iter().enumerate() {
        assert!(row.contains("LL"), "row {} should contain log content, got {:?}", i, row);
    }

    for row in 2u16..5 {
        let cell_inside = parser.screen().cell(row, 5).unwrap();
        assert_eq!(
            cell_inside.contents(),
            "[",
            "row {} col 5 (inside skip) should still be '[' from seed, got {:?}",
            row,
            cell_inside.contents()
        );
        let cell_inside_end = parser.screen().cell(row, 9).unwrap();
        assert_eq!(
            cell_inside_end.contents(),
            "]",
            "row {} col 9 (inside skip) should still be ']' from seed, got {:?}",
            row,
            cell_inside_end.contents()
        );

        let row_text = &rows[row as usize];
        let prefix: String = row_text.chars().take(5).collect();
        assert!(
            prefix.contains("LL"),
            "row {} left side (cols 0..5) should contain log content, got {:?}",
            row,
            prefix
        );
        let suffix: String = row_text.chars().skip(10).collect();
        assert!(
            suffix.contains("RRR"),
            "row {} right side (cols 10+) should contain log content, got {:?}",
            row,
            suffix
        );
    }
}

/// When a log line is shorter than the clipping range, the cells that
/// fall inside the side columns but beyond the line's text must be
/// cleared on each full reset — otherwise stale content from before a
/// resize (or from the previous overlay layout) hangs around next to the
/// palette edges.
#[test]
fn skip_rect_narrow_short_line_clears_side_padding() {
    let mut parser = vt100::Parser::new(12, 30, 0);
    let mut buf = Vec::new();

    let mut seed = Vec::new();
    for row in 0..6 {
        vt::MoveCursor(0, row).write_to_buffer(&mut seed);
        seed.extend_from_slice(b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    }
    parser.process(&seed);

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for _ in 0..6 {
        writer.push("ab");
    }

    let rect = Rect { x: 0, y: 0, w: 30, h: 6 };
    let style = LogStyle {
        skip_rect: Some(Rect { x: 10, y: 2, w: 10, h: 2 }),
        ..Default::default()
    };

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let screen = parser.screen();

    for row in 2u16..4 {
        for col in 2u16..10 {
            let cell = screen.cell(row, col).unwrap();
            assert_ne!(
                cell.contents(),
                "X",
                "row {} col {} should no longer contain the stale 'X' from seed, got {:?}",
                row,
                col,
                cell.contents()
            );
        }
        for col in 20u16..30 {
            let cell = screen.cell(row, col).unwrap();
            assert_ne!(
                cell.contents(),
                "X",
                "row {} col {} (right side of skip) should no longer contain the stale 'X', got {:?}",
                row,
                col,
                cell.contents()
            );
        }
    }
}

/// Log lines that carry SGR escapes must still render with the right
/// colors when they share a row with the command palette. Both the left
/// half (style from the line start) and the right half (style active at
/// the rejoin column) need to pick up foreground color changes, and
/// subsequent escapes after the skip cutout must keep working. Regression
/// for styles being dropped after [`Style::write_to_buffer`] was used as
/// an absolute setter when it is really additive.
#[test]
fn skip_rect_narrow_preserves_styles_across_cut() {
    let mut parser = vt100::Parser::new(12, 20, 0);
    let mut buf = Vec::new();

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    writer.push("AA\x1b[31mRR\x1b[0mBB\x1b[32mGGGGGGGG\x1b[0mCC\x1b[34mBB");

    let rect = Rect { x: 0, y: 0, w: 20, h: 4 };
    let style = LogStyle {
        skip_rect: Some(Rect { x: 6, y: 0, w: 8, h: 1 }),
        ..Default::default()
    };

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let screen = parser.screen();

    let red_cell = screen.cell(0, 2).unwrap();
    assert_eq!(
        red_cell.contents(),
        "R",
        "left side col 2 should render 'R' from the red run"
    );
    assert_eq!(
        red_cell.fgcolor(),
        vt100::Color::Idx(1),
        "left side col 2 should be red, got {:?}",
        red_cell.fgcolor()
    );

    let black_cell = screen.cell(0, 4).unwrap();
    assert_eq!(black_cell.contents(), "B", "left side col 4 should render 'B' from the reset run");
    assert_eq!(
        black_cell.fgcolor(),
        vt100::Color::Default,
        "left side col 4 should be default after the reset, got {:?}",
        black_cell.fgcolor()
    );

    let right_green = screen.cell(0, 14).unwrap();
    assert_eq!(right_green.contents(), "C", "right side col 14 should render 'C' from after the green run");
    assert_eq!(
        right_green.fgcolor(),
        vt100::Color::Default,
        "right side col 14 should be default (the green run was reset mid-line), got {:?}",
        right_green.fgcolor()
    );

    let right_blue = screen.cell(0, 16).unwrap();
    assert_eq!(right_blue.contents(), "B", "right side col 16 should render 'B' after the blue escape");
    assert_eq!(
        right_blue.fgcolor(),
        vt100::Color::Idx(4),
        "right side col 16 should be blue (escape after the cut is honoured), got {:?}",
        right_blue.fgcolor()
    );
}

/// With a narrow `skip_rect` in place, pushing new log lines after the
/// overlay is already open must propagate to the side columns of the skip
/// band on the next render — the user needs to see fresh log activity
/// beside the palette box as tasks keep running.
#[test]
fn skip_rect_narrow_new_logs_update_sides() {
    let mut parser = vt100::Parser::new(12, 30, 0);
    let mut buf = Vec::new();

    let mut seed = Vec::new();
    for row in 2..5 {
        vt::MoveCursor(10, row).write_to_buffer(&mut seed);
        seed.extend_from_slice(b"<PAL>");
    }
    parser.process(&seed);

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..4 {
        writer.push(&format!("before-{}", i));
    }

    let rect = Rect { x: 0, y: 0, w: 30, h: 8 };
    let style = LogStyle {
        skip_rect: Some(Rect { x: 10, y: 2, w: 5, h: 3 }),
        ..Default::default()
    };

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    for i in 0..4 {
        writer.push(&format!("after-{}", i));
    }

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    parser.process(&buf);
    buf.clear();

    let rows: Vec<String> = parser.screen().rows(0, 30).take(8).collect();
    let all_text = rows.join("\n");

    assert!(all_text.contains("after-0"), "fresh logs should appear after re-render: {:?}", rows);
    assert!(all_text.contains("after-3"), "fresh logs should appear after re-render: {:?}", rows);

    for row in 2u16..5 {
        let cell_inside = parser.screen().cell(row, 10).unwrap();
        assert_eq!(
            cell_inside.contents(),
            "<",
            "row {} col 10 (inside skip) should still be '<' from seed after log update, got {:?}",
            row,
            cell_inside.contents()
        );
    }

    let side_has_fresh_content = (2..5).any(|row| {
        let row_text = &rows[row as usize];
        let left: String = row_text.chars().take(10).collect();
        let right: String = row_text.chars().skip(15).collect();
        left.contains("after") || right.contains("after")
    });
    assert!(
        side_has_fresh_content,
        "fresh logs should be visible in the side columns of skip rows: {:?}",
        rows
    );
}

/// When skip_rect is set, scroll_widget must not use hardware scroll deltas
/// (ScrollRegion + ScrollBufferUp/Down). Those would shift the overlay band.
#[test]
fn skip_rect_disables_hardware_scroll() {
    let mut buf = Vec::new();

    let mut writer = LogWriter::new();
    let logs = writer.reader();
    let mut view = LogWidget::default();

    for i in 0..10 {
        writer.push(&format!("line{}", i));
    }

    let rect = Rect { x: 0, y: 0, w: 20, h: 8 };
    let style = LogStyle { skip_rect: Some(Rect { x: 0, y: 2, w: 20, h: 3 }), ..Default::default() };

    view.render(&mut buf, rect, &logs.read().unwrap().view_all(), &style);
    buf.clear();

    view.scroll_up(2, &mut buf, rect, &logs.read().unwrap().view_all(), &style);

    let out = std::str::from_utf8(&buf).unwrap();
    assert!(
        !out.contains("\x1b[1;8r") && !out.contains("\x1b[1;9r"),
        "scroll_up with skip_rect must not emit ScrollRegion/ScrollBuffer: {:?}",
        out
    );

    buf.clear();
    view.scroll_down(2, &mut buf, rect, &logs.read().unwrap().view_all(), &style);
    let out = std::str::from_utf8(&buf).unwrap();
    assert!(
        !out.contains("\x1b[1;8r") && !out.contains("\x1b[1;9r"),
        "scroll_down with skip_rect must not emit ScrollRegion/ScrollBuffer: {:?}",
        out
    );
}
