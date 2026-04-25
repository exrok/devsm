use crate::workspace::JobIndex;

/// Stable handle for a named external resource (an `{ resource = "x" }`
/// requirement). Allocated on first interning into [`ResourceSlab`] and reused
/// for the daemon's lifetime, so in-flight `ScheduleRequirement::Resource`
/// values stay valid across config reloads.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ResourceIndex(u32);

impl ResourceIndex {
    fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Daemon-lifetime intern table for resource names plus the current holder of
/// each resource. Hot-path operations are `Vec` index lookups.
#[derive(Default)]
pub struct ResourceSlab {
    names: Vec<Box<str>>,
    held_by: Vec<Option<JobIndex>>,
    by_name: hashbrown::HashMap<Box<str>, ResourceIndex>,
}

impl ResourceSlab {
    pub fn intern(&mut self, name: &str) -> ResourceIndex {
        if let Some(&id) = self.by_name.get(name) {
            return id;
        }
        let id = ResourceIndex(self.names.len() as u32);
        let owned: Box<str> = name.into();
        self.names.push(owned.clone());
        self.held_by.push(None);
        self.by_name.insert(owned, id);
        id
    }

    pub fn is_free(&self, id: ResourceIndex) -> bool {
        self.held_by[id.idx()].is_none()
    }

    pub fn acquire(&mut self, id: ResourceIndex, ji: JobIndex) {
        let slot = &mut self.held_by[id.idx()];
        debug_assert!(slot.is_none(), "resource '{}' already held", &self.names[id.idx()]);
        *slot = Some(ji);
    }

    pub fn release(&mut self, id: ResourceIndex) {
        let slot = &mut self.held_by[id.idx()];
        debug_assert!(slot.is_some(), "release of free resource '{}'", &self.names[id.idx()]);
        *slot = None;
    }
}
