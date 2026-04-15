use crate::workspace::Job;

/// Dense, generational slab of `Job` metadata.
///
/// Slots live in a single `Vec<Slot>`; removing a job makes its slot
/// immediately reusable via an intrinsic free-list. Each slot carries its
/// own generation counter, so a stale [`JobIndex`] pointing at a since-reused
/// slot cannot silently resolve to the new tenant — [`JobStore::get`] checks
/// the generation and returns `None` on mismatch.
///
/// A separate monotonic `public_id: u32` is assigned on insert and stored
/// alongside the `Job` in the slot. The public id is what the CLI and RPC
/// wire format expose (where a stable, human-friendly number is expected);
/// the internal [`JobIndex`] stays private to the daemon.
pub struct JobStore {
    slots: Vec<Slot>,
    free_head: u32,
    live: u32,
    next_public_id: u32,
    public_index: hashbrown::HashMap<u32, JobIndex>,
}

const NO_FREE: u32 = u32::MAX;

struct Slot {
    generation: u32,
    next_free: u32,
    public_id: u32,
    job: Option<Job>,
}

/// Handle into a [`JobStore`]. Combines a slot index with the generation at
/// the time of insertion — a stale handle whose slot has since been reused
/// fails the generation check on lookup.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(C)]
pub struct JobIndex {
    slot: u32,
    generation: u32,
}

impl JobIndex {
    /// Raw slot offset. Use this for display, debugging, or `kvlog` output —
    /// never as an identifier handed to a user, and never as an index into
    /// anything other than the [`JobStore`] that minted it.
    pub fn slot(self) -> u32 {
        self.slot
    }

    pub fn generation(self) -> u32 {
        self.generation
    }

    /// Slot index as `usize`. Internal use only — intended for hash keys and
    /// debug formatting. Never use this as a user-facing identifier or as an
    /// index into a parallel array keyed by `JobIndex`; the slot is not
    /// unique across a slot's lifetime.
    pub fn idx(self) -> usize {
        self.slot as usize
    }

    /// Construct a handle with generation 0 from a slot index. Intended for
    /// unit tests that use `JobIndex` as an opaque token and never actually
    /// resolve it against a [`JobStore`].
    pub fn from_usize(idx: usize) -> Self {
        Self { slot: idx as u32, generation: 0 }
    }
}

impl kvlog::Encode for JobIndex {
    fn encode_log_value_into(&self, output: kvlog::ValueEncoder<'_>) {
        self.slot.encode_log_value_into(output);
    }
}

impl Default for JobStore {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free_head: NO_FREE,
            live: 0,
            // Start at 0 to match the historical `JobIndex(u32)` identifier
            // that CLI users and tests already depend on — `--job=0` must
            // still refer to the first job a workspace spawns.
            next_public_id: 0,
            public_index: hashbrown::HashMap::new(),
        }
    }
}

impl JobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.live as usize
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Insert a job. The store assigns the next monotonic public id and
    /// returns the [`JobIndex`] handle for internal wiring.
    pub fn insert(&mut self, job: Job) -> JobIndex {
        let public_id = self.next_public_id;
        self.next_public_id = self.next_public_id.wrapping_add(1);

        let slot_idx = if self.free_head != NO_FREE {
            let idx = self.free_head;
            let slot = &mut self.slots[idx as usize];
            self.free_head = slot.next_free;
            slot.job = Some(job);
            slot.next_free = NO_FREE;
            slot.public_id = public_id;
            idx
        } else {
            let idx = u32::try_from(self.slots.len()).expect("job slot count overflow");
            self.slots.push(Slot { generation: 0, next_free: NO_FREE, public_id, job: Some(job) });
            idx
        };
        self.live += 1;
        let generation = self.slots[slot_idx as usize].generation;
        let ji = JobIndex { slot: slot_idx, generation };
        self.public_index.insert(public_id, ji);
        ji
    }

    pub fn remove(&mut self, ji: JobIndex) -> Option<Job> {
        let slot = self.slots.get_mut(ji.slot as usize)?;
        if slot.generation != ji.generation {
            return None;
        }
        let job = slot.job.take()?;
        let public_id = slot.public_id;
        slot.generation = slot.generation.wrapping_add(1);
        slot.next_free = self.free_head;
        self.free_head = ji.slot;
        self.live -= 1;
        self.public_index.remove(&public_id);
        Some(job)
    }

    pub fn get(&self, ji: JobIndex) -> Option<&Job> {
        let slot = self.slots.get(ji.slot as usize)?;
        if slot.generation != ji.generation {
            return None;
        }
        slot.job.as_ref()
    }

    pub fn get_mut(&mut self, ji: JobIndex) -> Option<&mut Job> {
        let slot = self.slots.get_mut(ji.slot as usize)?;
        if slot.generation != ji.generation {
            return None;
        }
        slot.job.as_mut()
    }

    #[allow(dead_code)]
    pub fn contains(&self, ji: JobIndex) -> bool {
        let Some(slot) = self.slots.get(ji.slot as usize) else { return false };
        slot.generation == ji.generation && slot.job.is_some()
    }

    /// Public id for a live job, or `None` if the handle is stale.
    pub fn public_id_of(&self, ji: JobIndex) -> Option<u32> {
        let slot = self.slots.get(ji.slot as usize)?;
        if slot.generation != ji.generation || slot.job.is_none() {
            return None;
        }
        Some(slot.public_id)
    }

    /// Resolve a public job id (as seen on the wire / in CLI args) to an
    /// internal [`JobIndex`]. Returns `None` once the job has been evicted.
    pub fn by_public_id(&self, public_id: u32) -> Option<JobIndex> {
        self.public_index.get(&public_id).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (JobIndex, &Job)> {
        self.slots.iter().enumerate().filter_map(|(i, slot)| {
            let job = slot.job.as_ref()?;
            Some((JobIndex { slot: i as u32, generation: slot.generation }, job))
        })
    }

    #[allow(dead_code)]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (JobIndex, &mut Job)> {
        self.slots.iter_mut().enumerate().filter_map(|(i, slot)| {
            let generation = slot.generation;
            let job = slot.job.as_mut()?;
            Some((JobIndex { slot: i as u32, generation }, job))
        })
    }
}

impl std::ops::Index<JobIndex> for JobStore {
    type Output = Job;
    #[track_caller]
    fn index(&self, ji: JobIndex) -> &Job {
        match self.get(ji) {
            Some(job) => job,
            None => panic!("JobStore indexed with evicted or stale JobIndex {:?}", ji),
        }
    }
}

impl std::ops::IndexMut<JobIndex> for JobStore {
    #[track_caller]
    fn index_mut(&mut self, ji: JobIndex) -> &mut Job {
        match self.get_mut(ji) {
            Some(job) => job,
            None => panic!("JobStore indexed with evicted or stale JobIndex {:?}", ji),
        }
    }
}
