use extui::{AnsiColor, Style, vt::Modifier};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// A segment of a string, classified for width calculation.
#[derive(Debug, PartialEq, Eq)]
pub enum Segment<'a> {
    /// A segment containing only printable ASCII characters.
    Ascii(&'a str),
    /// A segment representing an ANSI SGR escape code (`\x1b[...m`) or an OSC sequence.
    AnsiEscapes(&'a str),
    /// A printable segment containing non-ASCII Unicode characters.
    Utf8(&'a str),
}

/// An iterator that partitions a string into `Segment`s in a single pass.
///
/// Non-SGR CSI sequences (cursor moves, screen clears, etc.) and bare ESC + char
/// sequences are dropped from the iteration — the corresponding bytes are skipped
/// and never yielded. After iterating, `stripped` reports whether any such bytes
/// were dropped, so the caller can fall back to a sanitized copy of the input.
pub struct SegmentIterator<'a> {
    remaining: &'a str,
    /// `true` once an unsafe escape has been skipped. Never written on the safe path.
    pub stripped: bool,
}

fn numericalize_unchecked_iter(text: &str) -> impl Iterator<Item = u8> {
    let mut bytes = text.as_bytes().iter();
    std::iter::from_fn(move || {
        let mut num = bytes.next()?.wrapping_sub(b'0');
        for &ch in bytes.by_ref() {
            if ch == b';' {
                return Some(num);
            }
            num = num.wrapping_mul(10).wrapping_add(ch.wrapping_sub(b'0'));
        }
        Some(num)
    })
}

impl<'a> Iterator for SegmentIterator<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.remaining.is_empty() {
                return None;
            }

            let bytes = self.remaining.as_bytes();
            let first_byte = bytes[0];

            if first_byte == b'\x1b' {
                if bytes.get(1) == Some(&b'[') {
                    // CSI sequence: `\x1b[` params (0x30..0x3F) intermediates (0x20..0x2F) final (0x40..0x7E).
                    // Scan for the first byte >= 0x40 (the final byte). For SGR this is `m` and
                    // costs the same single-byte comparison as the prior `position(==b'm')`.
                    let mut j = 2;
                    while j < bytes.len() && bytes[j] < 0x40 {
                        j += 1;
                    }
                    if j < bytes.len() {
                        let final_byte = bytes[j];
                        if final_byte < 0x80 {
                            let segment_len = j + 1;
                            let body = unsafe { std::str::from_utf8_unchecked(&bytes[2..j]) };
                            self.remaining = unsafe { std::str::from_utf8_unchecked(&bytes[segment_len..]) };
                            if final_byte == b'm' {
                                return Some(Segment::AnsiEscapes(body));
                            }
                            self.stripped = true;
                            continue;
                        }
                        // Malformed CSI: bytes[j] is a UTF-8 multibyte byte. Strip just
                        // the ESC[…prefix and resume parsing at this char boundary (the
                        // prior `\x1b[` are both ASCII, so position j is on a boundary).
                        self.remaining = unsafe { std::str::from_utf8_unchecked(&bytes[j..]) };
                        self.stripped = true;
                        continue;
                    }
                    self.stripped = true;
                    self.remaining = "";
                    continue;
                }
                if bytes.get(1) == Some(&b']') {
                    // OSC sequence: \x1b]...ST where ST is \x1b\\ or BEL (\x07).
                    // OSC 8 hyperlinks and benign OSC (title, palette) all pass through.
                    let segment_len = bytes
                        .windows(2)
                        .position(|w| w == b"\x1b\\")
                        .map(|pos| pos + 2)
                        .or_else(|| bytes.iter().position(|&b| b == b'\x07').map(|pos| pos + 1))
                        .unwrap_or(bytes.len());
                    self.remaining = unsafe { std::str::from_utf8_unchecked(&bytes[segment_len..]) };
                    return Some(Segment::AnsiEscapes(""));
                }
                // Other escape sequence - skip ESC and the following char.
                // Advance by full char so we never split inside a multibyte UTF-8 sequence.
                let mut chars = self.remaining.chars();
                chars.next();
                chars.next();
                self.remaining = chars.as_str();
                self.stripped = true;
                continue;
            }
            if first_byte.is_ascii() {
                let segment_len = bytes.iter().position(|&b| !b.is_ascii() || b == b'\x1b').unwrap_or(bytes.len());
                let (segment_str, next_remaining) = self.remaining.split_at(segment_len);
                self.remaining = next_remaining;
                return Some(Segment::Ascii(segment_str));
            }
            let segment_len = bytes.iter().position(|&b| b.is_ascii() || b == b'\x1b').unwrap_or(bytes.len());
            let (segment_str, next_remaining) = self.remaining.split_at(segment_len);
            self.remaining = next_remaining;
            return Some(Segment::Utf8(segment_str));
        }
    }
}

impl<'a> Segment<'a> {
    /// Returns an iterator over the segments of a string.
    ///
    /// Yields `Ascii`, `Utf8`, and `AnsiEscapes` segments in a single pass. CSI
    /// sequences whose final byte is not `m` (cursor moves, clears, mode sets,
    /// scroll, etc.) and bare ESC + char sequences are skipped silently and
    /// `SegmentIterator::stripped` is set so the caller can sanitize storage.
    ///
    /// # Assumptions
    /// The input `text` contains no control characters (`\t`, `\n`, etc.).
    pub fn iterator(text: &'a str) -> SegmentIterator<'a> {
        SegmentIterator { remaining: text, stripped: false }
    }
}

/// Returns `(end_byte_offset, keep)` for the escape sequence starting at `start`
/// (a `\x1b` byte). `keep == true` means the bytes `start..end` must be preserved
/// when copying the line into storage.
///
/// Shared between `SegmentIterator` and `write_kept_bytes` so classification has
/// one source of truth.
fn classify_escape_at(bytes: &[u8], start: usize) -> (usize, bool) {
    match bytes.get(start + 1) {
        Some(&b'[') => {
            let mut j = start + 2;
            while j < bytes.len() && bytes[j] < 0x40 {
                j += 1;
            }
            if j < bytes.len() {
                if bytes[j] < 0x80 {
                    (j + 1, bytes[j] == b'm')
                } else {
                    // Malformed CSI - strip only up to the multibyte byte, leaving
                    // it for the next pass to interpret as a UTF-8 char.
                    (j, false)
                }
            } else {
                (bytes.len(), false)
            }
        }
        Some(&b']') => {
            let mut j = start + 2;
            while j + 1 < bytes.len() {
                if bytes[j] == b'\x1b' && bytes[j + 1] == b'\\' {
                    return (j + 2, true);
                }
                if bytes[j] == b'\x07' {
                    return (j + 1, true);
                }
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'\x07' {
                return (j + 1, true);
            }
            (bytes.len(), true)
        }
        Some(_) => {
            // ESC + one char. Advance by full UTF-8 char so we never split inside a multibyte sequence.
            let tail = unsafe { std::str::from_utf8_unchecked(&bytes[start + 1..]) };
            let next_char_len = tail.chars().next().map_or(0, |c| c.len_utf8());
            (start + 1 + next_char_len, false)
        }
        None => (start + 1, false),
    }
}

/// Copies the safe bytes of `text` into `dst`, returning the number of bytes
/// written. Skips non-SGR CSI sequences and bare ESC + char sequences; passes
/// SGR (`\x1b[...m`) and OSC (including OSC 8 hyperlinks) through verbatim.
///
/// Caller must ensure `dst.len() >= text.len()`. Only invoked on the rare slow
/// path where `SegmentIterator::stripped` indicates the line contains an unsafe
/// escape — never on safe lines.
pub fn write_kept_bytes(text: &str, dst: &mut [u8]) -> usize {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut written = 0;
    while i < bytes.len() {
        let next_esc = bytes[i..].iter().position(|&b| b == b'\x1b').map_or(bytes.len(), |p| i + p);
        if next_esc > i {
            let span = &bytes[i..next_esc];
            dst[written..written + span.len()].copy_from_slice(span);
            written += span.len();
        }
        if next_esc == bytes.len() {
            break;
        }
        let (end, keep) = classify_escape_at(bytes, next_esc);
        if keep {
            let span = &bytes[next_esc..end];
            dst[written..written + span.len()].copy_from_slice(span);
            written += span.len();
        }
        i = end;
    }
    written
}

/// Strips ANSI escape codes and checks if text contains needle (case-sensitive).
///
/// Used for checking ready conditions where ANSI codes should be ignored.
pub fn strip_ansi_and_contains(text: &str, needle: &str) -> bool {
    let mut buffer = Vec::new();
    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) | Segment::Utf8(s) => buffer.extend(s.bytes()),
            Segment::AnsiEscapes(_) => {}
        }
    }
    std::str::from_utf8(&buffer).is_ok_and(|s| s.contains(needle))
}

/// Strips ANSI escape codes from text and appends lowercase content to buffer.
///
/// Used for building search indices where case-insensitive matching is needed
/// and ANSI codes should be ignored.
pub fn strip_ansi_to_buffer(text: &str, buffer: &mut Vec<u8>) {
    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) => {
                buffer.extend(s.bytes().map(|b| b.to_ascii_lowercase()));
            }
            Segment::Utf8(s) => {
                for c in s.chars().flat_map(|c| c.to_lowercase()) {
                    let mut buf = [0u8; 4];
                    let encoded = c.encode_utf8(&mut buf);
                    buffer.extend_from_slice(encoded.as_bytes());
                }
            }
            Segment::AnsiEscapes(_) => {}
        }
    }
}

/// Strips ANSI escape codes from text and appends content to buffer preserving case.
///
/// Used for building search indices where case-sensitive matching is needed.
pub fn strip_ansi_to_buffer_preserve_case(text: &str, buffer: &mut Vec<u8>) {
    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) => {
                buffer.extend_from_slice(s.as_bytes());
            }
            Segment::Utf8(s) => {
                buffer.extend_from_slice(s.as_bytes());
            }
            Segment::AnsiEscapes(_) => {}
        }
    }
}

/// Calculates display width of text, ignoring ANSI escape codes.
///
/// Uses unicode_width for accurate display width of Unicode characters.
pub fn display_width(text: &str) -> usize {
    let mut width = 0;
    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) => width += s.len(),
            Segment::Utf8(s) => width += s.width(),
            Segment::AnsiEscapes(_) => {}
        }
    }
    width
}

/// Match highlight information for rendering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MatchHighlight {
    /// Byte offset in stripped (ANSI-free, lowercased) text where match starts.
    pub start: u32,
    /// Length of match in stripped text bytes.
    pub len: u32,
}

pub fn apply_raw_display_mode_vt_to_style(style: &mut Style, escape: &str) {
    if escape.is_empty() {
        *style = Style::DEFAULT;
        return;
    }
    let mut digits = numericalize_unchecked_iter(escape);
    macro_rules! next {
        () => {
            if let Some(digit) = digits.next() {
                digit
            } else {
                return;
            }
        };
    }

    while let Some(digit) = digits.next() {
        *style = match digit {
            0 => Style::DEFAULT,
            1 => style.with_modifier(Modifier::BOLD),
            2 => style.with_modifier(Modifier::DIM),
            3 => style.with_modifier(Modifier::ITALIC),
            4 => style.with_modifier(Modifier::UNDERLINED),
            5 => style.with_modifier(Modifier::UNDERLINED),
            7 => style.with_modifier(Modifier::REVERSED),
            8 => style.with_modifier(Modifier::HIDDEN),
            9 => style.with_modifier(Modifier::CROSSED_OUT),
            21 => style.without_modifier(Modifier::BOLD),
            22 => style.without_modifier(Modifier::DIM),
            23 => style.without_modifier(Modifier::ITALIC),
            24 => style.without_modifier(Modifier::UNDERLINED),
            25 => style.without_modifier(Modifier::UNDERLINED),
            27 => style.without_modifier(Modifier::REVERSED),
            28 => style.without_modifier(Modifier::HIDDEN),
            29 => style.without_modifier(Modifier::CROSSED_OUT),
            fg @ 30..=37 => style.with_fg(extui::AnsiColor(fg - 30)),
            38 => match next!() {
                5 => style.with_fg(AnsiColor(next!())),
                _ => return,
            },
            39 => style.without_fg(),
            fg @ 90..=97 => style.with_fg(extui::AnsiColor(fg - 90 + 8)),
            bg @ 40..=47 => style.with_bg(extui::AnsiColor(bg - 40)),
            bg @ 100..=107 => style.with_bg(extui::AnsiColor(bg - 100 + 8)),
            49 => style.without_bg(),
            48 => match next!() {
                5 => style.with_bg(AnsiColor(next!())),
                _ => return,
            },
            _ => return,
        }
    }
}

/// # Assumptions
/// The function assumes the input `text` contains no control characters (`\t`, `\n`, etc.)
/// and that the only VT escape codes present are SGR display mode codes (`\x1b[...m`).
fn naive_line_splitting_inner(
    text: &str,
    mut style: Style,
    max_line_length: usize,
) -> impl Iterator<Item = (*const u8, Style, u32)> {
    let mut used = 0;
    let mut segments = Segment::iterator(text);
    let mut current_segment = Segment::AnsiEscapes("");
    std::iter::from_fn(move || {
        loop {
            match current_segment {
                Segment::Ascii(text) => {
                    if text.len() + used > max_line_length {
                        let take = max_line_length - used;
                        let rem = &text[take..];
                        if rem.is_empty() {
                            panic!()
                        }
                        let ret = rem.as_ptr();
                        // println!("REM: {:?} {:p}", rem, ret);
                        current_segment = Segment::Ascii(rem);
                        let w = used;
                        used = 0;
                        return Some((ret, style, w as u32));
                    } else {
                        used += text.len();
                    }
                }
                Segment::AnsiEscapes(escape) => {
                    apply_raw_display_mode_vt_to_style(&mut style, escape);
                }
                Segment::Utf8(text) => {
                    let mut iter = text.graphemes(true);
                    while let Some(cluster) = iter.next() {
                        let width = UnicodeWidthStr::width(cluster);
                        if used + width > max_line_length {
                            current_segment = Segment::Utf8(iter.as_str());
                            // could cause over flow if width > max_line_length
                            let w = used;
                            used = width;
                            return Some((cluster.as_ptr(), style, w as u32));
                        } else {
                            used += width;
                        }
                    }
                }
            }
            if let Some(segment) = segments.next() {
                current_segment = segment
            } else {
                current_segment = Segment::AnsiEscapes("");
                return None;
            }
        }
    })
}

pub fn naive_line_splitting(
    text: &str,
    mut style: Style,
    max_line_length: usize,
) -> impl Iterator<Item = (&str, Style)> {
    let mut start = 0;
    let mut ptr_splits = naive_line_splitting_inner(text, style, max_line_length);
    std::iter::from_fn(move || {
        if let Some((next_ptr, end_style, _)) = ptr_splits.next() {
            let end = unsafe { next_ptr.offset_from(text.as_ptr()) as usize };
            let slice = &text[start..end];
            start = end;
            let start_style = style;
            style = end_style;
            return Some((slice, start_style));
        }
        if start != text.len() {
            let slice = &text[start..];
            start = text.len();
            Some((slice, style))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_segment_iterator() {
        let text = "hello \x1b[31mworld\x1b[0m! これはASCIIではありません\x1b[0mりません";
        let segments: Vec<_> = Segment::iterator(text).collect();
        assert_eq!(
            segments,
            vec![
                Segment::Ascii("hello "),
                Segment::AnsiEscapes("31"),
                Segment::Ascii("world"),
                Segment::AnsiEscapes("0"),
                Segment::Ascii("! "),
                Segment::Utf8("これは"),
                Segment::Ascii("ASCII"),
                Segment::Utf8("ではありません"),
                Segment::AnsiEscapes("0"),
                Segment::Utf8("りません"),
            ]
        );
    }

    #[test]
    fn test_adjacent_escapes() {
        let text = "\x1b[1m\x1b[31mbold red\x1b[0m";
        let segments: Vec<_> = Segment::iterator(text).collect();
        assert_eq!(
            segments,
            vec![
                Segment::AnsiEscapes("1"),
                Segment::AnsiEscapes("31"),
                Segment::Ascii("bold red"),
                Segment::AnsiEscapes("0"),
            ]
        );
    }

    #[test]
    fn test_standard_background_sgr_updates_background() {
        let mut style = Style::DEFAULT;
        apply_raw_display_mode_vt_to_style(&mut style, "41");
        assert_eq!(style.fg(), None);
        assert_eq!(style.bg().map(|color| color.to_ansi()), Some(AnsiColor(1)));
    }

    #[test]
    fn test_osc8_hyperlink() {
        // OSC 8 hyperlink: \x1b]8;params;uri\x1b\\text\x1b]8;;\x1b\\
        // This is what cargo outputs in gnome-terminal for clickable links
        let text = "\x1b[1m\x1b[92m    Finished\x1b[0m \x1b]8;;https://doc.rust-lang.org/cargo/reference/profiles.html\x1b\\`dev` profile\x1b]8;;\x1b\\ in 0.13s";
        let segments: Vec<_> = Segment::iterator(text).collect();
        assert_eq!(
            segments,
            vec![
                Segment::AnsiEscapes("1"),
                Segment::AnsiEscapes("92"),
                Segment::Ascii("    Finished"),
                Segment::AnsiEscapes("0"),
                Segment::Ascii(" "),
                Segment::AnsiEscapes(""), // OSC 8 start hyperlink
                Segment::Ascii("`dev` profile"),
                Segment::AnsiEscapes(""), // OSC 8 end hyperlink
                Segment::Ascii(" in 0.13s"),
            ]
        );

        // Verify width calculation ignores the OSC sequences
        // "    Finished" (12) + " " (1) + "`dev` profile" (13) + " in 0.13s" (9) = 35
        assert_eq!(display_width(text), 35);
    }

    #[test]
    fn test_osc8_hyperlink_with_bel_terminator() {
        // Some terminals use BEL (\x07) instead of ST (\x1b\\) as OSC terminator
        let text = "Click \x1b]8;;https://example.com\x07here\x1b]8;;\x07 for more";
        let segments: Vec<_> = Segment::iterator(text).collect();
        assert_eq!(
            segments,
            vec![
                Segment::Ascii("Click "),
                Segment::AnsiEscapes(""), // OSC 8 start
                Segment::Ascii("here"),
                Segment::AnsiEscapes(""), // OSC 8 end
                Segment::Ascii(" for more"),
            ]
        );
        // "Click " (6) + "here" (4) + " for more" (9) = 19
        assert_eq!(display_width(text), 19);
    }
    //字👍 <-- Double width characters I can actually see
    //〇
    #[test]
    fn test_width_calculation() {
        // Simple ASCII
        assert_eq!(width_ignoring_vt_ansi_color("hello world"), 11);

        // ASCII with ANSI codes
        let text_with_color = "hello \x1b[31mworld\x1b[0m!";
        assert_eq!(width_ignoring_vt_ansi_color(text_with_color), 12); // "hello world!"

        // Mixed ASCII and Unicode
        // 'ｈｅｌｌｏ' are full-width characters (2 cells each)
        // 'ｗｏｒｌｄ' are full-width characters (2 cells each)
        // '!' is a half-width character (1 cell)
        let text_with_unicode = "ｈｅｌｌｏ, ｗｏｒｌｄ!";
        assert_eq!(width_ignoring_vt_ansi_color(text_with_unicode), 23); // 5*2 + 1 + 1 + 5*2 + 1

        // All features combined
        let complex_text = "foo \x1b[1;34mbar\x1b[0m baz 日本語";
        // "foo bar baz 日本語"
        // 3 + 1 + 3 + 1 + 3 + 1 + (3 * 2) = 12 + 6 = 18
        assert_eq!(width_ignoring_vt_ansi_color(complex_text), 18);

        // Empty string
        assert_eq!(width_ignoring_vt_ansi_color(""), 0);

        // String with only ANSI codes
        assert_eq!(width_ignoring_vt_ansi_color("\x1b[1m\x1b[31m\x1b[0m"), 0);

        // Malformed ANSI code (no 'm')
        assert_eq!(width_ignoring_vt_ansi_color("test\x1b[1;34"), 4); // "test"
    }

    #[test]
    fn test_utf8_then_ascii() {
        let text = "日本語abc";
        let segments: Vec<_> = Segment::iterator(text).collect();
        assert_eq!(segments, vec![Segment::Utf8("日本語"), Segment::Ascii("abc"),]);
    }

    #[test]
    fn test_escape_followed_by_multibyte_utf8() {
        // ESC followed by a non-`[`/`]` multibyte char must not split inside the
        // multibyte sequence. The iterator now skips ESC + char entirely and sets `stripped`.
        let text = "\x1bé hello";
        let mut iter = Segment::iterator(text);
        let segments: Vec<_> = iter.by_ref().collect();
        assert_eq!(segments, vec![Segment::Ascii(" hello")]);
        assert!(iter.stripped);
        assert_eq!(display_width(text), " hello".len());
    }

    #[test]
    fn test_csi_with_multibyte_tail() {
        // Malformed CSI - the multibyte char is NOT consumed; the ESC[…prefix is
        // stripped and parsing resumes on the char boundary so the char shows up
        // as a UTF-8 segment.
        let text = "\x1b[31é";
        let mut iter = Segment::iterator(text);
        let segments: Vec<_> = iter.by_ref().collect();
        assert_eq!(segments, vec![Segment::Utf8("é")]);
        assert!(iter.stripped);
        assert_eq!(display_width(text), UnicodeWidthStr::width("é"));
    }

    fn assert_stripped_to(text: &str, expected: &str) {
        let mut iter = Segment::iterator(text);
        for _ in iter.by_ref() {}
        assert!(iter.stripped, "expected stripped=true for {text:?}");
        let mut buf = vec![0u8; text.len()];
        let n = write_kept_bytes(text, &mut buf);
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), expected);
    }

    fn assert_not_stripped(text: &str) {
        let mut iter = Segment::iterator(text);
        for _ in iter.by_ref() {}
        assert!(!iter.stripped, "expected stripped=false for {text:?}");
    }

    #[test]
    fn test_iterator_not_stripped_for_safe_lines() {
        assert_not_stripped("hello world");
        assert_not_stripped("\x1b[1m\x1b[31mbold red\x1b[0m");
        assert_not_stripped("\x1b]8;;https://example.com\x1b\\link\x1b]8;;\x1b\\");
        assert_not_stripped("\x1b]0;window title\x07visible");
    }

    #[test]
    fn test_iterator_strips_screen_clear() {
        assert_stripped_to("before\x1b[2Jafter", "beforeafter");
    }

    #[test]
    fn test_iterator_strips_cursor_position() {
        assert_stripped_to("row1\x1b[10;20Hrow2\x1b[Hhome", "row1row2home");
    }

    #[test]
    fn test_iterator_strips_dec_private_modes() {
        assert_stripped_to("\x1b[?25lhidden\x1b[?25h", "hidden");
    }

    #[test]
    fn test_iterator_strips_other_escape() {
        assert_stripped_to("before\x1bcafter", "beforeafter");
    }

    #[test]
    fn test_iterator_strips_truncated_csi() {
        assert_stripped_to("\x1b[31", "");
    }

    #[test]
    fn test_iterator_keeps_sgr_around_clear() {
        assert_stripped_to("\x1b[31mred\x1b[2J\x1b[0mreset", "\x1b[31mred\x1b[0mreset");
    }

    #[test]
    fn test_write_kept_bytes_safe_passthrough() {
        let text = "\x1b[31mhello\x1b[0m world";
        let mut buf = vec![0u8; text.len()];
        let n = write_kept_bytes(text, &mut buf);
        assert_eq!(&buf[..n], text.as_bytes());
    }

    /// Computes the terminal display width of a string, ignoring ANSI SGR color codes.
    ///
    /// This function is optimized for performance by:
    /// 1. Treating pure ASCII segments separately, where width is simply the byte length.
    /// 2. Skipping over ANSI SGR escape codes (`\x1b[...m`) without processing their contents.
    /// 3. Using `unicode_width` only for segments that contain non-ASCII characters.
    ///
    /// # Assumptions
    /// The function assumes the input `text` contains no control characters (`\t`, `\n`, etc.)
    /// and that the only VT escape codes present are SGR display mode codes (`\x1b[...m`).
    fn width_ignoring_vt_ansi_color(text: &str) -> usize {
        let mut width = 0;
        // SAFETY for from_utf8_unchecked: The SegmentIterator is carefully designed to only split
        // on ASCII boundaries (`m`, `\x1b`, or the transition between ASCII/non-ASCII chars).
        // Since the original `&str` is valid UTF-8, any split on an ASCII boundary will
        // also result in valid UTF-8 slices.
        for segment in Segment::iterator(text) {
            match segment {
                // For pure ASCII, width is equivalent to byte length. This is a fast path.
                Segment::Ascii(s) => width += s.len(),
                // For segments with unicode, we use the unicode-width crate.
                Segment::Utf8(s) => width += s.width(),
                // ANSI escape codes have zero display width.
                Segment::AnsiEscapes(_) => continue,
            }
        }
        width
    }
}
