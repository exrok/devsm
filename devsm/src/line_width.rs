use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;
use vtui::{Color, Style, vt::Modifier};

/// A segment of a string, classified for width calculation.
#[derive(Debug, PartialEq, Eq)]
pub enum Segment<'a> {
    /// A segment containing only printable ASCII characters.
    Ascii(&'a str),
    /// A segment representing an ANSI SGR escape code (`\x1b[...m`).
    AnsiEscapes(&'a str),
    /// A printable segment containing non-ASCII Unicode characters.
    Utf8(&'a str),
}

/// An iterator that partitions a string into `Segment`s in a single pass.
///
/// This iterator is optimized to process strings containing ANSI escape codes efficiently.
/// It determines the type of the next segment by looking at the first byte of the
/// remaining string and consumes just that segment, ensuring O(n) linear time complexity.
struct SegmentIterator<'a> {
    remaining: &'a str,
}

// given the string after the [b']

fn numericalize_unchecked_iter(text: &str) -> impl Iterator<Item = u8> {
    let mut bytes = text.as_bytes().iter();
    std::iter::from_fn(move || {
        let mut num = bytes.next()?.wrapping_sub(b'0');
        while let Some(&ch) = bytes.next() {
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
        if self.remaining.is_empty() {
            return None;
        }

        let bytes = self.remaining.as_bytes();
        let first_byte = bytes[0];

        if first_byte == b'\x1b' && bytes.get(1) == Some(&b'[') {
            let segment_len = bytes.iter().skip(2).position(|&b| b == b'm').map(|pos| pos + 3).unwrap_or(bytes.len());
            self.remaining = unsafe { std::str::from_utf8_unchecked(&bytes[segment_len..]) };

            Some(Segment::AnsiEscapes(unsafe { std::str::from_utf8_unchecked(&bytes[2..segment_len - 1]) }))
        } else if first_byte.is_ascii() {
            let segment_len = bytes.iter().position(|&b| !b.is_ascii() || b == b'\x1b').unwrap_or(bytes.len());
            let (segment_str, next_remaining) = self.remaining.split_at(segment_len);
            self.remaining = next_remaining;

            Some(Segment::Ascii(segment_str))
        } else {
            let segment_len = bytes.iter().position(|&b| b.is_ascii() || b == b'\x1b').unwrap_or(bytes.len());
            let (segment_str, next_remaining) = self.remaining.split_at(segment_len);
            self.remaining = next_remaining;

            Some(Segment::Utf8(segment_str))
        }
    }
}

impl<'a> Segment<'a> {
    /// Returns an iterator over the segments of a string.
    ///
    /// The iterator efficiently splits the text into `Ascii`, `Utf8`, and `AnsiEscapes`
    /// segments in a single pass, allowing for optimized width calculation.
    ///
    /// # Assumptions
    /// The function assumes the input `text` contains no control characters (`\t`, `\n`, etc.)
    /// and that the only VT escape codes present are SGR display mode codes (`\x1b[...m`).
    pub fn iterator(text: &'a str) -> impl Iterator<Item = Segment<'a>> {
        SegmentIterator { remaining: text }
    }
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

/// Match highlight information for rendering.
#[derive(Clone, Copy, Default)]
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
            fg @ 30..=37 => style.with_fg(vtui::Color(fg - 30)),
            38 => match next!() {
                5 => style.with_fg(Color(next!())),
                _ => return,
            },
            39 => style.without_fg(),
            fg @ 90..=97 => style.with_fg(vtui::Color(fg - 90 + 8)),
            bg @ 40..=47 => style.with_fg(vtui::Color(bg - 30)),
            bg @ 100..=107 => style.with_bg(vtui::Color(bg - 100 + 8)),
            49 => style.without_bg(),
            48 => match next!() {
                5 => style.with_bg(Color(next!())),
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
