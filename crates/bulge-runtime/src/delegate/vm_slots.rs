//! VM slots for sub-agents: a bounded pool, leased per child.

use std::sync::Arc;

/// Which VM workspace slots are in use. Shared by every child of a session.
pub struct VmSlots {
    used: std::sync::Mutex<Vec<bool>>,
}

impl VmSlots {
    /// A pool of `count` slots, all free.
    pub fn new(count: usize) -> Arc<Self> {
        Arc::new(Self {
            used: std::sync::Mutex::new(vec![false; count]),
        })
    }

    /// Lease a free slot. `None` means the pool is exhausted.
    pub fn lease(self: &Arc<Self>) -> Option<SlotLease> {
        let mut used = self.used.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = used.iter().position(|in_use| !in_use)?;
        used[index] = true;
        Some(SlotLease {
            slots: self.clone(),
            index: index as u8,
        })
    }
}

/// One leased VM workspace slot; frees its index when dropped.
pub struct SlotLease {
    slots: Arc<VmSlots>,
    index: u8,
}

impl SlotLease {
    pub fn index(&self) -> u8 {
        self.index
    }
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        let mut used = self.slots.used.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(in_use) = used.get_mut(self.index as usize) {
            *in_use = false;
        }
    }
}
