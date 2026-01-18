use unicode_width::UnicodeWidthStr;
use vtui::{
    Color, DoubleBuffer, Rect, Style,
    event::{KeyCode, KeyEvent},
};

use crate::{
    keybinds::{Command, InputEvent, Keybinds, Mode},
    line_width::{MatchHighlight, Segment, strip_ansi_to_buffer},
    log_storage::{LogEntry, LogFilter, LogId, Logs},
    tui::constrain_scroll_offset,
};

/// A match found in the log search.
#[derive(Clone, Copy, Debug)]
pub struct LogMatch {
    /// The LogId of the entry containing the match.
    pub log_id: LogId,
    /// Byte offset within the stripped text where match starts.
    pub match_start: u32,
}

/// Flat buffer search index for efficient substring searching.
///
/// This struct accumulates stripped (ANSI-free) and lowercased log text into
/// a contiguous buffer for cache-coherent searching. Each entry is separated
/// by a 0xFF sentinel byte (invalid in UTF-8).
pub struct LogSearchIndex {
    /// Flat buffer of stripped text with 0xFF separators.
    buffer: Vec<u8>,
    /// Maps each entry to its buffer offset and LogId.
    offsets: Vec<(usize, LogId)>,
    /// The LogId up to which the index has been built.
    indexed_tail: LogId,
}

impl LogSearchIndex {
    /// Builds a search index from filtered logs.
    pub fn build(logs: &Logs, filter: &LogFilter) -> Self {
        let mut buffer = Vec::with_capacity(64 * 1024);
        let mut offsets = Vec::new();

        let (a, b) = logs.slices();
        let mut current_id = logs.head();

        for slice in [a, b] {
            for entry in slice {
                if !filter_contains(filter, entry) {
                    current_id.0 += 1;
                    continue;
                }

                let text = unsafe { entry.text(logs) };
                let buffer_start = buffer.len();

                strip_ansi_to_buffer(text, &mut buffer);
                offsets.push((buffer_start, current_id));
                buffer.push(0xFF);

                current_id.0 += 1;
            }
        }

        LogSearchIndex { buffer, offsets, indexed_tail: logs.tail() }
    }

    /// Searches for pattern in indexed logs.
    ///
    /// Matches are returned in temporal order (oldest first). Only the first
    /// match per log entry is included to avoid duplicates.
    pub fn search(&self, pattern: &str, matches: &mut Vec<LogMatch>) {
        matches.clear();

        if pattern.is_empty() {
            return;
        }

        let pattern_lower = pattern.to_lowercase();
        let finder = memchr::memmem::Finder::new(pattern_lower.as_bytes());

        let mut search_pos = 0;
        let mut offset_idx = 0;
        let mut last_matched_log_id: Option<LogId> = None;

        while let Some(match_pos) = finder.find(&self.buffer[search_pos..]) {
            let abs_pos = search_pos + match_pos;

            // Find which log entry this belongs to
            while offset_idx + 1 < self.offsets.len() && self.offsets[offset_idx + 1].0 <= abs_pos {
                offset_idx += 1;
            }

            let (entry_start, log_id) = self.offsets[offset_idx];

            // Only add one match per log entry
            if last_matched_log_id != Some(log_id) {
                let match_offset_in_entry = abs_pos - entry_start;
                matches.push(LogMatch { log_id, match_start: match_offset_in_entry as u32 });
                last_matched_log_id = Some(log_id);
            }

            // Move past this match to find next
            search_pos = abs_pos + 1;
        }
    }
}

/// Action returned from search input processing.
pub enum SearchAction {
    /// User cancelled search.
    Cancel,
    /// User confirmed selection.
    Confirm(LogId),
    /// Continue searching.
    None,
}

/// Main state for interactive log search mode.
pub struct LogSearchState {
    /// Current search pattern.
    pub pattern: String,
    /// Length of pattern in lowercased form (for highlighting).
    pattern_lower_len: usize,
    /// Cursor position within pattern.
    cursor: usize,
    /// Whether pattern has been updated since last search.
    pattern_updated: bool,
    /// Search index containing stripped log text.
    index: LogSearchIndex,
    /// List of matches found.
    pub matches: Vec<LogMatch>,
    /// Currently selected match index.
    selected: usize,
    /// Scroll offset for match list display.
    scroll_offset: usize,
    /// The filter used to build the index.
    filter: LogFilter,
    /// Initial view position to select nearest match.
    initial_view_pos: LogId,
}

impl LogSearchState {
    /// Creates a new search state for the given logs and filter.
    pub fn new(logs: &Logs, filter: LogFilter, initial_view_pos: LogId) -> Self {
        let index = LogSearchIndex::build(logs, &filter);
        LogSearchState {
            pattern: String::new(),
            pattern_lower_len: 0,
            cursor: 0,
            pattern_updated: false,
            index,
            matches: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            filter,
            initial_view_pos,
        }
    }

    /// Returns the currently selected LogId, if any.
    pub fn selected_log_id(&self) -> Option<LogId> {
        self.matches.get(self.selected).map(|m| m.log_id)
    }

    /// Updates the search index with new log entries.
    pub fn update_index(&mut self, logs: &Logs) {
        if logs.tail() <= self.index.indexed_tail {
            return;
        }

        let (a, b) = logs.slices_range(self.index.indexed_tail, logs.tail());
        let mut current_id = self.index.indexed_tail;

        for slice in [a, b] {
            for entry in slice {
                if !filter_contains(&self.filter, entry) {
                    current_id.0 += 1;
                    continue;
                }

                let text = unsafe { entry.text(logs) };
                let buffer_start = self.index.buffer.len();

                strip_ansi_to_buffer(text, &mut self.index.buffer);
                self.index.offsets.push((buffer_start, current_id));
                self.index.buffer.push(0xFF);

                current_id.0 += 1;
            }
        }
        self.index.indexed_tail = logs.tail();

        // Re-run search if pattern exists
        if self.pattern_updated || !self.pattern.is_empty() {
            self.pattern_updated = true;
        }
    }

    /// Flushes pending search if pattern was updated.
    pub fn flush(&mut self) {
        if self.pattern_updated {
            // Preserve current selection by LogId if possible
            let current_log_id = self.selected_log_id();

            // Store lowercased pattern length for highlighting
            self.pattern_lower_len = self.pattern.to_lowercase().len();

            self.index.search(&self.pattern, &mut self.matches);
            self.scroll_offset = 0;

            // Try to restore selection to the same LogId, or nearest to it
            let target = current_log_id.unwrap_or(self.initial_view_pos);
            self.select_nearest_to(target);

            self.pattern_updated = false;
        }
    }

    /// Selects the match closest to the given LogId.
    fn select_nearest_to(&mut self, target: LogId) {
        if self.matches.is_empty() {
            self.selected = 0;
            return;
        }

        // Binary search for closest match
        let pos = self
            .matches
            .binary_search_by_key(&target, |m| m.log_id)
            .unwrap_or_else(|pos| pos.saturating_sub(1).min(self.matches.len() - 1));

        self.selected = pos;
    }

    /// Processes keyboard input.
    pub fn process_input(&mut self, key: KeyEvent, keybinds: &Keybinds) -> SearchAction {
        let input = InputEvent::from(key);

        // Check keybindings first
        if let Some(cmd) = keybinds.lookup_mode_only(Mode::LogSearch, input) {
            match cmd {
                Command::SelectPrev => {
                    self.flush();
                    self.selected = self.selected.saturating_sub(1);
                    return SearchAction::None;
                }
                Command::SelectNext => {
                    self.flush();
                    if self.selected + 1 < self.matches.len() {
                        self.selected += 1;
                    }
                    return SearchAction::None;
                }
                Command::OverlayCancel => {
                    return SearchAction::Cancel;
                }
                Command::OverlayConfirm => {
                    self.flush();
                    if let Some(log_id) = self.selected_log_id() {
                        return SearchAction::Confirm(log_id);
                    } else {
                        return SearchAction::Cancel;
                    }
                }
                _ => {}
            }
        }

        // Handle text input
        match key.code {
            KeyCode::Backspace => {
                if self.cursor != 0 {
                    self.pattern.remove(self.cursor - 1);
                    self.cursor -= 1;
                }
                self.pattern_updated = true;
            }
            KeyCode::Char(ch) => {
                let len = self.pattern.len();
                self.pattern.insert(self.cursor, ch);
                let len2 = self.pattern.len();
                self.cursor += len2 - len;
                self.pattern_updated = true;
            }
            _ => {}
        }
        SearchAction::None
    }

    /// Renders the search UI.
    pub fn render(&mut self, out: &mut DoubleBuffer, mut rect: Rect, logs: &Logs) {
        self.flush();

        // Input box at top
        let input_rect = rect.take_top(1);
        input_rect.with(Color::Grey[16].as_fg()).text(out, "/").with(Style::DEFAULT).text(out, &self.pattern);

        // Cursor rendering
        let cursor_rect = Rect { x: input_rect.x + 1 + self.pattern[..self.cursor].width() as u16, w: 1, ..input_rect };
        cursor_rect.with(Color::Grey[28].with_fg(Color::Grey[2])).fill(out);

        // Status line
        let status_rect = rect.take_top(1);
        status_rect.with(Color::Grey[8].as_fg()).fmt(out, format_args!("{} matches", self.matches.len()));

        if self.matches.is_empty() {
            return;
        }

        // Constrain selection and scroll
        self.selected = self.selected.min(self.matches.len().saturating_sub(1));
        self.scroll_offset = constrain_scroll_offset(rect.h as usize, self.selected, self.scroll_offset);

        let indexer = logs.indexer();

        for (i, log_match) in self.matches.iter().enumerate().skip(self.scroll_offset) {
            let entry_rect = rect.take_top(1);
            if entry_rect.is_empty() {
                break;
            }

            let is_selected = i == self.selected;

            // Try to get the entry text, handling the case where it may have rotated out
            let entry = indexer[log_match.log_id];
            let text = unsafe { entry.text(logs) };

            let base_style = if is_selected { Color::LightSkyBlue1.with_fg(Color::Black) } else { Style::DEFAULT };
            let highlight_style = Color::DarkOrange.with_fg(Color::Black);

            if is_selected {
                entry_rect.with(base_style).fill(out);
            }

            // Render with ANSI stripped and match highlighted
            let highlight = MatchHighlight { start: log_match.match_start, len: self.pattern_lower_len as u32 };

            render_stripped_with_highlight(entry_rect, out, text, base_style, highlight_style, highlight);
        }
    }

    /// Returns the current match info for the selected entry (for log buffer highlighting).
    pub fn selected_match(&self) -> Option<&LogMatch> {
        self.matches.get(self.selected)
    }

    /// Returns the pattern length in lowercased form.
    pub fn pattern_len(&self) -> usize {
        self.pattern_lower_len
    }
}

/// Checks if an entry passes the filter.
fn filter_contains(filter: &LogFilter, entry: &LogEntry) -> bool {
    match filter {
        LogFilter::All => true,
        LogFilter::IsGroup(log_group) => entry.log_group == *log_group,
        LogFilter::NotGroup(log_group) => entry.log_group != *log_group,
        LogFilter::IsBaseTask(base_task) => entry.log_group.base_task_index() == *base_task,
        LogFilter::NotBaseTask(base_task) => entry.log_group.base_task_index() != *base_task,
        LogFilter::IsInSet(set) => set.contains(entry.log_group.base_task_index()),
    }
}

/// Renders text with ANSI codes stripped and optional substring highlighting.
///
/// Uses vtui's chaining API to render each segment with appropriate styling.
fn render_stripped_with_highlight(
    rect: Rect,
    out: &mut DoubleBuffer,
    text: &str,
    base_style: Style,
    highlight_style: Style,
    highlight: MatchHighlight,
) {
    use vtui::DisplayRect;

    let match_start = highlight.start as usize;
    let match_end = match_start + highlight.len as usize;
    let has_highlight = highlight.len > 0;

    let mut stripped_pos = 0usize;
    let mut styled: DisplayRect = rect.with(base_style);

    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) => {
                let seg_start = stripped_pos;
                let seg_end = stripped_pos + s.len();

                if has_highlight && seg_start < match_end && seg_end > match_start {
                    // This segment overlaps with highlight region
                    let hl_start_in_seg = match_start.saturating_sub(seg_start);
                    let hl_end_in_seg = (match_end - seg_start).min(s.len());

                    // Before highlight
                    if hl_start_in_seg > 0 {
                        styled = styled.text(out, &s[..hl_start_in_seg]);
                    }
                    // Highlighted portion
                    styled = styled.with(highlight_style).text(out, &s[hl_start_in_seg..hl_end_in_seg]);
                    // After highlight - always reset to base_style
                    if hl_end_in_seg < s.len() {
                        styled = styled.with(base_style).text(out, &s[hl_end_in_seg..]);
                    } else {
                        // Reset style even when highlight ends at segment boundary
                        styled = styled.with(base_style);
                    }
                } else {
                    styled = styled.text(out, s);
                }
                stripped_pos = seg_end;
            }
            Segment::Utf8(s) => {
                // For UTF-8 segments, we process char-by-char because
                // lowercasing can change byte lengths, but we batch consecutive
                // chars with the same highlighting state for efficiency
                let mut current_in_highlight = false;
                let mut batch_start = 0usize;

                for (byte_idx, ch) in s.char_indices() {
                    let ch_stripped_len: usize = ch.to_lowercase().map(|c| c.len_utf8()).sum();
                    let ch_start = stripped_pos;
                    let ch_end = stripped_pos + ch_stripped_len;

                    let in_highlight = has_highlight && ch_start < match_end && ch_end > match_start;

                    if byte_idx == 0 {
                        current_in_highlight = in_highlight;
                    } else if in_highlight != current_in_highlight {
                        // Flush the batch
                        let batch = &s[batch_start..byte_idx];
                        if current_in_highlight {
                            styled = styled.with(highlight_style).text(out, batch);
                        } else {
                            styled = styled.with(base_style).text(out, batch);
                        }
                        batch_start = byte_idx;
                        current_in_highlight = in_highlight;
                    }

                    stripped_pos = ch_end;
                }

                // Flush remaining batch
                if batch_start < s.len() {
                    let batch = &s[batch_start..];
                    if current_in_highlight {
                        styled = styled.with(highlight_style).text(out, batch).with(base_style);
                    } else {
                        styled = styled.with(base_style).text(out, batch);
                    }
                }
            }
            Segment::AnsiEscapes(_) => {
                // Skip ANSI escapes - they don't contribute to stripped position
            }
        }
    }
}
