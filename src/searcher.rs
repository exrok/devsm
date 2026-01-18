#[derive(Default)]
pub struct FatSearch {
    buffer: Vec<u8>,
    indices: Vec<usize>,
}
// todo optimize
fn normalize(text: &str) -> String {
    let norm = text.to_lowercase();
    norm.replace("_", " ")
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Entry(u64);

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry").field("score", &self.score()).field("index", &self.index()).finish()
    }
}

impl Entry {
    pub fn score(self) -> u32 {
        (self.0 >> 32) as u32
    }
    pub fn index(self) -> usize {
        (self.0 & 0xffff_ffff) as usize
    }
    pub fn new(score: u16, index: usize) -> Entry {
        Entry((((!score) as u64) << 32) | (index as u64))
    }
}

impl FatSearch {
    pub fn insert(&mut self, text: &str) {
        let offset = self.buffer.len();
        self.buffer.extend_from_slice(normalize(text).as_bytes());
        self.buffer.push(255);
        self.indices.push(offset)
    }

    fn query_single(&self, pattern: &str, output: &mut Vec<Entry>) {
        let finder = memchr::memmem::Finder::new(pattern);
        let mut offset = 0;
        let mut foof = self.indices.iter().enumerate();
        let mut last_entry_index = if let Some((id, _)) = foof.next() {
            id
        } else {
            return;
        };
        'cont: while let Some(next) = finder.find(&self.buffer[offset..]) {
            let bytes = &self.buffer[offset..];
            offset += next;
            for (id, start) in foof.by_ref() {
                if offset < *start {
                    output.push(Entry::new(single_score(bytes, next), last_entry_index));
                    last_entry_index = id;
                    offset = *start;
                    continue 'cont;
                }
                last_entry_index = id;
            }
            output.push(Entry::new(single_score(bytes, next), last_entry_index));
            break;
        }
    }

    fn query_double(&self, pattern: &str, second: &str, rem: &[&str], output: &mut Vec<Entry>) {
        let finder = memchr::memmem::Finder::new(pattern);
        let finder2 = memchr::memmem::Finder::new(second);
        let mut offset = 0;
        let mut foof = self.indices.iter().enumerate();
        let mut last_entry_index = if let Some((id, _)) = foof.next() {
            id
        } else {
            return;
        };
        'cont: while let Some(next) = finder.find(&self.buffer[offset..]) {
            let ot = offset;
            offset += next;
            let (end, index) = 'blk: {
                for (id, start) in foof.by_ref() {
                    if offset < *start {
                        let index = last_entry_index;
                        last_entry_index = id;
                        offset = *start;
                        break 'blk (offset - 1, index);
                    }
                    last_entry_index = id;
                }
                offset = self.buffer.len();
                (self.buffer.len() - 1, last_entry_index)
            };
            let bytes = &self.buffer[ot..end];
            let Some(sec_start) = finder2.find(&bytes[next + pattern.len()..]) else {
                continue 'cont;
            };
            let mut score = 0;
            if !rem.is_empty() {
                let mut rest = &bytes[next + pattern.len() + sec_start..];
                for r in rem {
                    let Some(offset) = memchr::memmem::find(rest, r.as_bytes()) else {
                        continue 'cont;
                    };
                    if offset != 0 && rest[offset - 1] == b' ' {
                        score += 1;
                    }
                    rest = &rest[offset + r.len()..];
                }
            }
            score += double_score(bytes, next, pattern.len(), next + pattern.len() + sec_start);
            output.push(Entry::new(score, index))
        }
    }

    pub fn query(&self, pattern: &str, output: &mut Vec<Entry>) {
        output.clear();
        if pattern.is_empty() {
            output.extend((0..self.indices.len()).map(|i| Entry::new(0, i)));
            return;
        }
        let normed = normalize(pattern);
        let mut terms = normed.split_ascii_whitespace();
        let Some(first) = terms.next() else { return };
        if let Some(second) = terms.next() {
            let rest: Vec<_> = terms.collect();
            self.query_double(first, second, &rest, output);
        } else {
            self.query_single(first, output);
        }
        output.sort_unstable();
    }
}

fn single_score(bytes: &[u8], i: usize) -> u16 {
    if i == 0 {
        3
    } else if bytes[i - 1] == b' ' {
        2
    } else {
        1
    }
}

#[inline]
fn double_score(bytes: &[u8], ai: usize, len: usize, bi: usize) -> u16 {
    let mut score = 0;
    if ai == 0 {
        score += 2;
    } else if bytes[ai - 1] == b' ' {
        score += 1;
    }
    if bytes[bi - 1] == b' ' {
        score += 1;
        if ai + len + 1 == bi {
            score += 1;
        }
    }
    score
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple() {
        let mut searcher = FatSearch::default();
        searcher.insert("die");
        searcher.insert("info");
        searcher.insert("ping");
        searcher.insert("cargo_tree");
        let mut output = Vec::new();
        searcher.query("c t", &mut output);
        assert!(output.len() == 1);
        assert!(output[0].index() == 3);
    }
}
