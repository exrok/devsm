use crate::workspace::JobIndex;

/// Ordered job index storing a list of job indices tracking 3 main states
/// (Terminal | Running | Scheduled) in that order, with tasks which transitioned
/// to there current state earlier appearing eariler in the list.
///
/// This JobIndexList is optimized around the ideas:
/// - For specific base task there is rarely more then 1 task either running
/// or scheduled.
/// - A linear search of u32's is quite fast.
/// - "append only", jobs enter this list and then never removed.
#[derive(Default)]
pub struct JobIndexList {
    jobs: Vec<JobIndex>,
    terminal: u32,
    active: u32,
}

impl<'a> IntoIterator for &'a JobIndexList {
    type Item = &'a JobIndex;
    type IntoIter = std::slice::Iter<'a, JobIndex>;
    fn into_iter(self) -> Self::IntoIter {
        self.jobs.as_slice().into_iter()
    }
}

impl JobIndexList {
    pub fn clear(&mut self) {
        self.jobs.clear();
        self.terminal = 0;
        self.active = 0;
    }
    pub fn len(&self) -> usize {
        self.jobs.len()
    }
    pub fn push_terminated(&mut self, job: JobIndex) {
        self.jobs.insert(self.terminal as usize, job);
        self.terminal += 1;
    }
    pub fn push_active(&mut self, job: JobIndex) {
        self.jobs.insert((self.terminal + self.active) as usize, job);
        self.active += 1;
    }
    pub fn push_scheduled(&mut self, job: JobIndex) {
        self.jobs.push(job);
    }
    // doesn't affect running tasks
    pub fn terminate_scheduled(&mut self) -> &[JobIndex] {
        let og_terminated = self.terminal;
        if self.active == 0 {
            self.terminal = self.jobs.len() as u32;
            return &self.jobs[og_terminated as usize..];
        };
        let scheduled = self.jobs.len() - (self.active as usize + self.terminal as usize);
        if scheduled == 0 {
            return &[];
        }
        self.jobs[self.terminal as usize..].rotate_right(scheduled);
        self.terminal += scheduled as u32;
        &self.jobs[og_terminated as usize..self.terminal as usize]
    }
    pub fn terminate_all(&mut self) -> &[JobIndex] {
        let terminated = &self.jobs[self.terminal as usize..];
        self.terminal = self.jobs.len() as u32;
        self.active = 0;
        terminated
    }
    pub fn all(&self) -> &[JobIndex] {
        &self.jobs
    }
    pub fn set_active(&mut self, job: JobIndex) {
        for (i, j) in self.scheduled().iter().enumerate() {
            if *j != job {
                continue;
            }
            if i != 0 {
                // FIXED: offset is terminal + running
                let start = (self.terminal + self.active) as usize;
                let end = start + i + 1;
                self.jobs[start..end].rotate_right(1);
            }
            self.active += 1;
            return;
        }
        debug_assert!(false, "JobIndexList::run called on non-scheduled job: {:?}", job.0);
    }
    pub fn set_terminal(&mut self, job: JobIndex) {
        for (i, j) in self.non_terminal().iter().enumerate() {
            if *j != job {
                continue;
            }
            if i < self.active as usize {
                self.active -= 1;
            }
            if i != 0 {
                // FIXED: offset is terminal
                let start = self.terminal as usize;
                let end = start + i + 1;
                self.jobs[start..end].rotate_right(1);
            }
            self.terminal += 1;
            return;
        }
        debug_assert!(false, "JobIndexList::terminate called on non-running job: {:?}", job.0);
    }
    pub fn terminal(&self) -> &[JobIndex] {
        &self.jobs[..self.terminal as usize]
    }
    pub fn non_terminal(&self) -> &[JobIndex] {
        &self.jobs[self.terminal as usize..]
    }
    pub fn running(&self) -> &[JobIndex] {
        &self.jobs[self.terminal as usize..][..self.active as usize]
    }
    pub fn scheduled(&self) -> &[JobIndex] {
        &self.jobs[(self.terminal + self.active) as usize..]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn simple() {
        use JobIndex as J;
        let mut list = JobIndexList::default();
        macro_rules! assert_state {
            ([$($term: literal),*] [$($run: literal),*] [$($sched: literal),*]) => {
                assert_eq!(list.terminal(), &[$(J($term)),*]);
                assert_eq!(list.running(), &[$(J($run)),*]);
                assert_eq!(list.scheduled(), &[$(J($sched)),*]);
            };
        }
        assert_state!([][][]);
        assert!(list.non_terminal().is_empty());

        list.push_scheduled(J(1));
        assert_state!([][][1]);
        assert_eq!(list.non_terminal(), &[J(1)]);

        list.push_active(J(2));
        assert_state!([][2][1]);
        assert_eq!(list.non_terminal(), &[J(2), J(1)]);

        list.push_active(J(3));
        assert_state!([][2,3][1]);

        list.push_scheduled(J(4));
        assert_state!([][2,3][1,4]);

        list.set_terminal(J(3));
        assert_state!([3][2][1,4]);

        list.set_terminal(J(1));
        assert_state!([3, 1][2][4]);

        assert_eq!(list.non_terminal(), &[J(2), J(4)]);
        assert_eq!(list.terminate_all(), &[J(2), J(4)]);
        assert_state!([3, 1, 2, 4][][]);
    }
}
