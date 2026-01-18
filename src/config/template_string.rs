use std::mem::MaybeUninit;

use bumpalo::Bump;
use jsony::json::DecodeError;

#[derive(PartialEq, Eq, Debug)]
pub enum TemplatePart<'a> {
    Lit(&'a str),
    Var(&'a str),
}

static EOF_ERROR: DecodeError = DecodeError { message: "EOF while parsing string" };
static CONTROL_CHAR_ERROR: DecodeError = DecodeError { message: "Control character detected" };
static INVALID_ESCAPE_ERROR: DecodeError = DecodeError { message: "Invalid escape sequence" };
static EXPECTED_DOLLAR_ERROR: DecodeError = DecodeError { message: "Expected $ after ${ in template" };
static UNCLOSED_VAR_ERROR: DecodeError = DecodeError { message: "Unclosed variable substitution" };

// Given a string, immediately following an open backtick parse a JS style template string, on success
// returning the number of bytes consumed.
//
// The current format only supports simple expressions in the form `${$VAR}`.
pub fn munch_template_literal<'a>(
    content: &'a str,
    alloc: &'a Bump,
) -> Result<(&'a [TemplatePart<'a>], usize), &'static DecodeError> {
    let data = content.as_bytes();
    let len = data.len();
    let mut parts = bumpalo::collections::Vec::new_in(alloc);
    let mut at = 0;

    loop {
        let start = at;

        // Fast scan for the next interesting character (`, $, \, or control char < 0x20)
        let mut end = skip_to_template_special(at, data);

        // Analyze the character that stopped the scan
        loop {
            if end >= len {
                return Err(&EOF_ERROR);
            }

            let ch = data[end];

            if ch == b'`' {
                // End of template literal
                if end > start {
                    parts.push(TemplatePart::Lit(&content[start..end]));
                }
                return Ok((parts.into_bump_slice(), end + 1));
            } else if ch == b'$' {
                if end + 1 < len && data[end + 1] == b'{' {
                    // Found Variable Start `${`
                    // 1. Push preceding literal if any
                    if end > start {
                        parts.push(TemplatePart::Lit(&content[start..end]));
                    }

                    // 2. Validate format `${$VAR}`
                    // We are at `$`.
                    let var_dollar_idx = end + 2;
                    if var_dollar_idx >= len || data[var_dollar_idx] != b'$' {
                        return Err(&EXPECTED_DOLLAR_ERROR);
                    }

                    // 3. Find end of variable `}`
                    let var_name_start = var_dollar_idx + 1;
                    let mut var_end = var_name_start;
                    while var_end < len && data[var_end] != b'}' {
                        var_end += 1;
                    }

                    if var_end >= len {
                        return Err(&UNCLOSED_VAR_ERROR);
                    }

                    // 4. Push Variable
                    // SAFETY: `content` is valid UTF-8, so slice is valid UTF-8.
                    parts.push(TemplatePart::Var(&content[var_name_start..var_end]));

                    // 5. Advance `at` and continue outer loop
                    at = var_end + 1;
                    break;
                } else {
                    // Literal `$`.
                    // Since we are in the "clean" slice path, we just skip over it.
                    // Effectively, we extend the current literal segment.
                    end += 1;
                    end = skip_to_template_special(end, data);
                    continue;
                }
            } else if ch == b'\\' {
                // Escape sequence detected.
                // We must switch to allocating mode to construct the decoded string.

                let mut buf = bumpalo::collections::Vec::new_in(alloc);
                // Push everything we've scanned so far in this segment
                buf.extend_from_slice(&data[start..end]);

                at = end;

                // Enter "Complex" Loop
                loop {
                    if at >= len {
                        return Err(&EOF_ERROR);
                    }

                    let b = data[at];

                    if b == b'`' {
                        // End of string
                        if !buf.is_empty() {
                            // SAFETY: Source is UTF-8, escapes produce UTF-8.
                            let s = unsafe { std::str::from_utf8_unchecked(buf.into_bump_slice()) };
                            parts.push(TemplatePart::Lit(s));
                        }
                        return Ok((parts.into_bump_slice(), at + 1));
                    } else if b == b'$' {
                        if at + 1 < len && data[at + 1] == b'{' {
                            // Variable start inside complex string
                            if !buf.is_empty() {
                                let s = unsafe { std::str::from_utf8_unchecked(buf.into_bump_slice()) };
                                parts.push(TemplatePart::Lit(s));
                            }

                            // Handle Variable (duplicate logic for speed to avoid closure/fn overhead)
                            let var_dollar_idx = at + 2;
                            if var_dollar_idx >= len || data[var_dollar_idx] != b'$' {
                                return Err(&EXPECTED_DOLLAR_ERROR);
                            }
                            let var_name_start = var_dollar_idx + 1;
                            let mut var_end = var_name_start;
                            while var_end < len && data[var_end] != b'}' {
                                var_end += 1;
                            }
                            if var_end >= len {
                                return Err(&UNCLOSED_VAR_ERROR);
                            }
                            parts.push(TemplatePart::Var(&content[var_name_start..var_end]));

                            at = var_end + 1;
                            break; // Break inner loop, continue outer loop
                        } else {
                            // Literal $
                            buf.push(b'$');
                            at += 1;
                            // Fast forward
                            let next = skip_to_template_special(at, data);
                            buf.extend_from_slice(&data[at..next]);
                            at = next;
                        }
                    } else if b == b'\\' {
                        let mut scratch = [MaybeUninit::uninit(); 4];
                        match parse_escape_inner(at + 1, data, &mut scratch) {
                            Ok((new_idx, written)) => {
                                // Copy decoded bytes to buf
                                let decoded: &[u8] =
                                    unsafe { std::slice::from_raw_parts(scratch.as_ptr() as *const u8, written) };
                                buf.extend_from_slice(decoded);
                                at = new_idx;
                            }
                            Err(_) => return Err(&INVALID_ESCAPE_ERROR),
                        }

                        // Fast forward after escape
                        let next = skip_to_template_special(at, data);
                        buf.extend_from_slice(&data[at..next]);
                        at = next;
                    } else if b == b'\n' || b == b'\r' {
                        // Literal newline in complex string
                        buf.push(b);
                        at += 1;
                        // Fast forward
                        let next = skip_to_template_special(at, data);
                        buf.extend_from_slice(&data[at..next]);
                        at = next;
                    } else if b < 0x20 {
                        return Err(&CONTROL_CHAR_ERROR);
                    } else {
                        // Should be unreachable given skip_to_template_special logic
                        // but acts as safety fallback
                        buf.push(b);
                        at += 1;
                    }
                }

                // If we broke out of the complex loop (due to finding a variable),
                // `at` is now after the variable. break inner loop to resume outer `start` reset.
                break;
            } else if ch == b'\n' || ch == b'\r' {
                end += 1;
                end = skip_to_template_special(end, data);
                continue;
            } else {
                return Err(&CONTROL_CHAR_ERROR);
            }
        }
    }
}

fn is_template_special(ch: u8) -> bool {
    ch == b'`' || ch == b'\\' || ch == b'$' || ch < 0x20
}

fn skip_to_template_special(mut at: usize, data: &[u8]) -> usize {
    if at == data.len() || is_template_special(data[at]) {
        return at;
    }
    at += 1;

    let rest = &data[at..];
    type Chunk = u64;
    const STEP: usize = size_of::<Chunk>();
    const ONE_BYTES: Chunk = Chunk::MAX / 255;

    for chunk in rest.chunks_exact(STEP) {
        let chars = Chunk::from_le_bytes(chunk.try_into().unwrap());
        let contains_ctrl = chars.wrapping_sub(ONE_BYTES * 0x20) & !chars;
        let chars_backtick = chars ^ (ONE_BYTES * Chunk::from(b'`'));
        let contains_backtick = chars_backtick.wrapping_sub(ONE_BYTES) & !chars_backtick;
        let chars_backslash = chars ^ (ONE_BYTES * Chunk::from(b'\\'));
        let contains_backslash = chars_backslash.wrapping_sub(ONE_BYTES) & !chars_backslash;
        let chars_dollar = chars ^ (ONE_BYTES * Chunk::from(b'$'));
        let contains_dollar = chars_dollar.wrapping_sub(ONE_BYTES) & !chars_dollar;
        let masked = (contains_ctrl | contains_backtick | contains_backslash | contains_dollar) & (ONE_BYTES << 7);
        if masked != 0 {
            return unsafe { chunk.as_ptr().offset_from(data.as_ptr()) } as usize
                + masked.trailing_zeros() as usize / 8;
        }
    }

    at += rest.len() / STEP * STEP;
    skip_to_template_slow(at, data)
}

#[cold]
#[inline(never)]
fn skip_to_template_slow(mut at: usize, data: &[u8]) -> usize {
    while at < data.len() && !is_template_special(data[at]) {
        at += 1;
    }
    at
}

pub(crate) fn parse_escape_inner(
    mut index: usize,
    read: &[u8],
    scratch: &mut [MaybeUninit<u8>; 4],
) -> Result<(usize, usize), ()> {
    let Some(ch) = read.get(index) else {
        return Err(());
    };
    index += 1;

    let unescaped = match ch {
        b'`' => b'`',
        b'\\' => b'\\',
        b'/' => b'/',
        b'b' => b'\x08',
        b'f' => b'\x0c',
        b'n' => b'\n',
        b'r' => b'\r',
        b'$' => b'$',
        b't' => b'\t',
        b'u' => {
            return parse_unicode_escape(index, read, scratch);
        }
        b'\n' => {
            return Ok((index, 0));
        }
        _ => {
            return Err(());
        }
    };
    scratch[0].write(unescaped);

    Ok((index, 1))
}

#[cold]
fn parse_unicode_escape(
    mut index: usize,
    read: &[u8],
    scratch: &mut [MaybeUninit<u8>; 4],
) -> Result<(usize, usize), ()> {
    let n = match read.get(index..index + 4) {
        Some([a, b, c, d]) => {
            index += 4;
            match decode_four_hex_digits(*a, *b, *c, *d) {
                Some(val) => val,
                None => return Err(()),
            }
        }
        _ => return Err(()),
    };

    if !(0xD800..=0xDBFF).contains(&n) {
        return Ok((index, push_wtf8_codepoint(n as u32, scratch)));
    }

    let n1 = n;

    if read.get(index..index + 2) != Some(b"\\u") {
        return Err(());
    }
    index += 2;

    let n2 = match read.get(index..index + 4) {
        Some([a, b, c, d]) => {
            index += 4;
            match decode_four_hex_digits(*a, *b, *c, *d) {
                Some(val) => val,
                None => return Err(()),
            }
        }
        _ => return Err(()),
    };

    if !(0xDC00..=0xDFFF).contains(&n2) {
        return Err(());
    }

    let n = ((((n1 - 0xD800) as u32) << 10) | (n2 - 0xDC00) as u32) + 0x1_0000;
    Ok((index, push_wtf8_codepoint(n, scratch)))
}

#[inline]
fn push_wtf8_codepoint(n: u32, scratch: &mut [MaybeUninit<u8>; 4]) -> usize {
    if n < 0x80 {
        scratch[0].write(n as u8);
        return 1;
    }

    unsafe {
        let ptr = scratch.as_mut_ptr() as *mut u8;

        let encoded_len = match n {
            0..=0x7F => unreachable!(),
            0x80..=0x7FF => {
                ptr.write(((n >> 6) & 0b0001_1111) as u8 | 0b1100_0000);
                2
            }
            0x800..=0xFFFF => {
                ptr.write(((n >> 12) & 0b0000_1111) as u8 | 0b1110_0000);
                ptr.add(1).write(((n >> 6) & 0b0011_1111) as u8 | 0b1000_0000);
                3
            }
            0x1_0000..=0x10_FFFF => {
                ptr.write(((n >> 18) & 0b0000_0111) as u8 | 0b1111_0000);
                ptr.add(1).write(((n >> 12) & 0b0011_1111) as u8 | 0b1000_0000);
                ptr.add(2).write(((n >> 6) & 0b0011_1111) as u8 | 0b1000_0000);
                4
            }
            0x11_0000.. => unreachable!(),
        };
        ptr.add(encoded_len - 1).write((n & 0b0011_1111) as u8 | 0b1000_0000);

        encoded_len
    }
}

const fn decode_hex_val_slow(val: u8) -> Option<u8> {
    match val {
        b'0'..=b'9' => Some(val - b'0'),
        b'A'..=b'F' => Some(val - b'A' + 10),
        b'a'..=b'f' => Some(val - b'a' + 10),
        _ => None,
    }
}

const fn build_hex_table() -> [i8; 256] {
    let mut table = [0; 256];
    let mut ch = 0;
    while ch < 256 {
        table[ch] = match decode_hex_val_slow(ch as u8) {
            Some(val) => val as i8,
            None => -1,
        };
        ch += 1;
    }
    table
}

static HEX: [i8; 256] = build_hex_table();

fn decode_four_hex_digits(a: u8, b: u8, c: u8, d: u8) -> Option<u16> {
    let a = HEX[a as usize] as i32;
    let b = HEX[b as usize] as i32;
    let c = HEX[c as usize] as i32;
    let d = HEX[d as usize] as i32;

    let codepoint = (a << 12) | (b << 8) | (c << 4) | d;
    if codepoint >= 0 { Some(codepoint as u16) } else { None }
}

#[cfg(test)]
mod test {
    use super::*;
    use TemplatePart::*;

    fn fmt(tp: &[TemplatePart]) -> String {
        let mut buf = String::new();
        buf.push('`');
        for t in tp {
            match t {
                Lit(lit) => {
                    let as_json = jsony::to_json(&lit);
                    // Get inner string content. jsony produces "string" with escaped chars.
                    // Slice 1..len-1 to strip quotes.
                    let content = &as_json[1..as_json.len() - 1];

                    // jsony escapes " and \, but NOT `.
                    // We must escape ` for template literals.
                    // We also escape ${ so it isn't parsed as a variable.
                    let escaped = content
                        .replace("`", "\\`")
                        .replace("${", "\\${")
                        // Restore literal newlines for testing
                        .replace("\\n", "\n")
                        .replace("\\r", "\r");

                    buf.push_str(&escaped);
                }
                Var(text) => {
                    buf.push_str("${$");
                    buf.push_str(text);
                    buf.push('}');
                }
            }
        }
        buf.push('`');
        buf
    }

    #[test]
    fn template_format() {
        assert_eq!(fmt(&[]), "``");
        assert_eq!(fmt(&[Lit("hello")]), "`hello`");
        assert_eq!(fmt(&[Var("var")]), "`${$var}`");
        assert_eq!(fmt(&[Lit("$")]), "`$`");
        // Check escaping
        assert_eq!(fmt(&[Lit("${$esp}")]), "`\\${$esp}`");
        assert_eq!(fmt(&[Lit("foo ` bar")]), "`foo \\` bar`");
        assert_eq!(fmt(&[Lit("alpha"), Var("x"), Lit("beta")]), "`alpha${$x}beta`");
        // Check newlines
        assert_eq!(fmt(&[Lit("a\nb")]), "`a\nb`");
    }

    #[track_caller]
    fn assert_round_trip(tp: &[TemplatePart]) {
        let alloc = Bump::new();
        let mut s = fmt(tp);
        s.push_str("123456789");
        let after = &s[1..];
        let len_to_end = after.len() - 9;

        for (kind, extra) in &[("EOF", 0), ("SINGLE", 1), ("MANY", 9)] {
            match munch_template_literal(&after[..len_to_end + extra], &alloc) {
                Ok(value) => {
                    assert_eq!(value.0, tp, "Mismatched parse result\n input: {tp:?}\n kind: {kind}\n fmt: {after}");
                    assert_eq!(
                        value.1, len_to_end,
                        "Mismatched parse length\n input: {tp:?}\n kind: {kind}\n fmt: {after}"
                    );
                }
                Err(err) => {
                    panic!("Unexpected error: {err:?}\n input: {tp:?}\n kind: {kind}\n fmt: {after}")
                }
            }
        }
    }

    #[test]
    fn basic_literals() {
        assert_round_trip(&[]);
        assert_round_trip(&[Lit("hello world")]);
        // Note: The parser merges adjacent literals.
        // We do not test split literals here as the AST will optimize them into one.
    }

    #[test]
    fn simple_variables() {
        assert_round_trip(&[Var("foo")]);
        assert_round_trip(&[Lit("x="), Var("x")]);
        assert_round_trip(&[Var("x"), Lit("=y")]);
        assert_round_trip(&[Var("x"), Var("y")]);
        assert_round_trip(&[Lit("A"), Var("A"), Lit("B"), Var("B")]);
    }

    #[test]
    fn literals_with_specials() {
        assert_round_trip(&[Lit("foo $ bar")]); // Literal $
        assert_round_trip(&[Lit("foo ` bar")]); // Escaped backtick inside content
        assert_round_trip(&[Lit("line\nbreak")]); // Literal newline
        assert_round_trip(&[Lit("line\rbreak")]); // Literal CR
        assert_round_trip(&[Lit("line\r\nbreak")]); // Literal CRLF
        assert_round_trip(&[Lit("unicode \u{00A9}")]);
        // Escaped interpolation start
        assert_round_trip(&[Lit("${")]);
        assert_round_trip(&[Lit("${$var}")]);
    }

    #[test]
    fn escaped_chars() {
        let alloc = Bump::new();

        // Escaped newline (line continuation) - removes newline
        let (parts, len) = munch_template_literal("foo\\\nbar`", &alloc).unwrap();
        assert_eq!(parts, &[Lit("foobar")]);
        assert_eq!(len, 9);

        // Manual check for literal newline just to be absolutely sure without `fmt` logic
        let (parts, _) = munch_template_literal("foo\nbar`", &alloc).unwrap();
        assert_eq!(parts, &[Lit("foo\nbar")]);

        // Escaped backtick
        let (parts, _) = munch_template_literal("foo\\`bar`", &alloc).unwrap();
        assert_eq!(parts, &[Lit("foo`bar")]);

        // Escaped backslash
        let (parts, _) = munch_template_literal("foo\\\\bar`", &alloc).unwrap();
        assert_eq!(parts, &[Lit("foo\\bar")]);

        // Escaped $ (not standard JSON, but needed for literal ${)
        let (parts, _) = munch_template_literal("foo\\$bar`", &alloc).unwrap();
        assert_eq!(parts, &[Lit("foo$bar")]);
    }

    #[test]
    fn complex_variables() {
        // Variable after escape
        assert_round_trip(&[Lit("\t"), Var("x")]);
        // Variable between escapes and newlines
        assert_round_trip(&[Lit("\n"), Var("x"), Lit("\r")]);
    }

    #[test]
    fn failures() {
        let alloc = Bump::new();

        #[track_caller]
        fn expect_error(input: &str, error: &DecodeError, alloc: &Bump) {
            match munch_template_literal(input, alloc) {
                Ok(value) => panic!("Expected failure but succeeded with {:?} \n input: {}", value, input),
                Err(err) => {
                    if !std::ptr::addr_eq(err, error) {
                        panic!("Expected error {:?} but got {:?} \n input: {}", error, err, input);
                    }
                }
            }
        }
        // assert!(matches!(munch_template_literal("unclosed", &alloc), Err(&EOF_ERROR)));
        expect_error("unclosed", &EOF_ERROR, &alloc);

        // Bad variable format
        expect_error("${var}`", &EXPECTED_DOLLAR_ERROR, &alloc);
        expect_error("${$var`", &UNCLOSED_VAR_ERROR, &alloc);
        expect_error("${$`", &UNCLOSED_VAR_ERROR, &alloc);

        // Bad escapes
        expect_error("\\z`", &INVALID_ESCAPE_ERROR, &alloc);

        // Control chars (other than \n, \r)
        //assert!(matches!(munch_template_literal("raw \x00 null`", &alloc), Err(&CONTROL_CHAR_ERROR)));
        expect_error("raw \x00 null`", &CONTROL_CHAR_ERROR, &alloc);
    }
}
