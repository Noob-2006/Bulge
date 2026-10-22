//! One budget tree shared by a parent agent and its sub-agents. Each node
//! charges its own spend to every ancestor, clamps its limit to what the
//! ancestors have left, and inherits the earliest wall-clock deadline. A pool
//! shared by the tree caps how many sub-agents run at once, so one top-level
//! budget bounds the whole agent tree.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Default cap on how many agents one goal may spawn, ever.
pub const DEFAULT_TOTAL_AGENTS: usize = 100;

/// Hard upper bound for [`Ledger::root_with_total`].
pub const HARD_TOTAL_AGENTS: usize = 1_000;

/// One node of a budget tree. Cheap to share (`Arc<Ledger>`); all methods take `&self`.
#[derive(Debug)]
pub struct Ledger {
    token_limit: u64,
    spent: AtomicU64,
    deadline: Option<Instant>,
    parent: Option<Arc<Ledger>>,
    slots: Arc<SlotPool>,
    window: Option<(Instant, Duration)>,
}

/// Caps how many sub-agents of one tree run at the same time. Shared by every node of a tree.
#[derive(Debug)]
pub struct SlotPool {
    max: usize,
    used: AtomicUsize,
    /// Make checking/updating both counters one atomic step.
    lock: Mutex<()>,
    total_max: usize,
    total_spawned: AtomicUsize,
}

/// Holding one slot; releases it on drop.
#[derive(Debug)]
pub struct SlotGuard {
    pool: Arc<SlotPool>,
}

impl Ledger {
    /// The root of a tree: `token_limit` tokens, `wall_secs` of wall clock from now
    /// (`None` = no deadline), at most `max_concurrent` sub-agents at once (min 1).
    pub fn root(token_limit: u64, wall_secs: Option<u64>, max_concurrent: usize) -> Arc<Ledger> {
        Self::root_with_total(token_limit, wall_secs, max_concurrent, DEFAULT_TOTAL_AGENTS)
    }

    /// Like [`Ledger::root`], but with an explicit per-goal total-agent cap.
    /// `total_max` is clamped to `1..=HARD_TOTAL_AGENTS`.
    pub fn root_with_total(
        token_limit: u64,
        wall_secs: Option<u64>,
        max_concurrent: usize,
        total_max: usize,
    ) -> Arc<Ledger> {
        let now = Instant::now();
        let window = wall_secs.map(|secs| (now, Duration::from_secs(secs)));
        let deadline = window.and_then(|(start, len)| start.checked_add(len));
        Arc::new(Ledger {
            token_limit,
            spent: AtomicU64::new(0),
            deadline,
            parent: None,
            slots: Arc::new(SlotPool {
                max: max_concurrent.max(1),
                used: AtomicUsize::new(0),
                lock: Mutex::new(()),
                total_max: total_max.clamp(1, HARD_TOTAL_AGENTS),
                total_spawned: AtomicUsize::new(0),
            }),
            window,
        })
    }

    /// A child node. Its token limit is `min(token_limit, self.remaining())` and its deadline is
    /// the earlier of `now + wall_secs` (if given) and every ancestor deadline. Shares the
    /// tree's slot pool.
    pub fn child(self: &Arc<Self>, token_limit: u64, wall_secs: Option<u64>) -> Arc<Ledger> {
        let now = Instant::now();
        let own_deadline = wall_secs.and_then(|secs| now.checked_add(Duration::from_secs(secs)));
        let deadline = earlier(own_deadline, self.effective_deadline());
        let window = deadline.map(|deadline| (now, deadline.saturating_duration_since(now)));
        Arc::new(Ledger {
            token_limit: token_limit.min(self.remaining()),
            spent: AtomicU64::new(0),
            deadline,
            parent: Some(Arc::clone(self)),
            slots: Arc::clone(&self.slots),
            window,
        })
    }

    /// Add `tokens` to this node and every ancestor (saturating).
    pub fn charge(&self, tokens: u64) {
        let mut node = Some(self);
        while let Some(current) = node {
            current.add_spent(tokens);
            node = current.parent.as_deref();
        }
    }

    /// Tokens charged to this node (including everything charged by its descendants).
    pub fn spent(&self) -> u64 {
        self.spent.load(Ordering::SeqCst)
    }

    /// This node's token limit (after clamping at creation).
    pub fn token_limit(&self) -> u64 {
        self.token_limit
    }

    /// Tokens still available here: the minimum over this node and all ancestors of
    /// `limit - spent` (saturating at 0).
    pub fn remaining(&self) -> u64 {
        let mut left = u64::MAX;
        let mut node = Some(self);
        while let Some(current) = node {
            let here = current.token_limit.saturating_sub(current.spent.load(Ordering::SeqCst));
            left = left.min(here);
            node = current.parent.as_deref();
        }
        left
    }

    /// Seconds until the effective deadline (min over the chain), `None` if no deadline,
    /// `Some(0)` once passed.
    pub fn remaining_secs(&self) -> Option<u64> {
        self.effective_deadline()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()).as_secs())
    }

    /// True when `remaining() == 0` or the effective deadline has passed.
    pub fn exhausted(&self) -> bool {
        self.remaining() == 0
            || self.effective_deadline().is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Highest spent fraction over the chain: max over nodes of `spent / limit`
    /// (a limit of 0 counts as 1.0), and for the deadline the elapsed fraction of the
    /// node's own window (store the window start to compute it; a node without a
    /// deadline contributes 0.0). Used for wind-down.
    pub fn pressure(&self) -> f64 {
        self.token_pressure().max(self.deadline_pressure())
    }

    /// Try to take one sub-agent slot from the tree's pool; `None` when all are
    /// taken or the per-goal total-agent cap is reached. Taking a slot counts
    /// toward the total even after the slot is released.
    pub fn try_acquire_slot(&self) -> Option<SlotGuard> {
        let _lock = self.slots.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let used = self.slots.used.load(Ordering::SeqCst);
        if used >= self.slots.max {
            return None;
        }
        let spawned = self.slots.total_spawned.load(Ordering::SeqCst);
        if spawned >= self.slots.total_max {
            return None;
        }
        self.slots.used.store(used + 1, Ordering::SeqCst);
        self.slots.total_spawned.store(spawned + 1, Ordering::SeqCst);
        Some(SlotGuard { pool: Arc::clone(&self.slots) })
    }

    /// `(used, max)` of the tree's slot pool.
    pub fn slots(&self) -> (usize, usize) {
        (self.slots.used.load(Ordering::SeqCst), self.slots.max)
    }

    /// `(spawned, total_max)` for the tree's per-goal total-agent cap.
    pub fn spawned(&self) -> (usize, usize) {
        (
            self.slots.total_spawned.load(Ordering::SeqCst),
            self.slots.total_max,
        )
    }

    fn add_spent(&self, tokens: u64) {
        let mut current = self.spent.load(Ordering::SeqCst);
        loop {
            let next = current.saturating_add(tokens);
            match self.spent.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn effective_deadline(&self) -> Option<Instant> {
        let mut earliest = None;
        let mut node = Some(self);
        while let Some(current) = node {
            earliest = earlier(earliest, current.deadline);
            node = current.parent.as_deref();
        }
        earliest
    }

    pub(crate) fn token_pressure(&self) -> f64 {
        let mut pressure = 0.0_f64;
        let mut node = Some(self);
        while let Some(current) = node {
            pressure = pressure.max(current.token_fraction());
            node = current.parent.as_deref();
        }
        pressure
    }

    pub(crate) fn deadline_pressure(&self) -> f64 {
        let mut pressure = 0.0_f64;
        let mut node = Some(self);
        while let Some(current) = node {
            pressure = pressure.max(current.window_fraction());
            node = current.parent.as_deref();
        }
        pressure
    }

    fn token_fraction(&self) -> f64 {
        if self.token_limit == 0 {
            1.0
        } else {
            self.spent.load(Ordering::SeqCst) as f64 / self.token_limit as f64
        }
    }

    fn window_fraction(&self) -> f64 {
        match self.window {
            Some((start, len)) if !len.is_zero() => {
                start.elapsed().as_secs_f64() / len.as_secs_f64()
            }
            Some(_) => 1.0,
            None => 0.0,
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let _lock = self.pool.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.pool.used.fetch_sub(1, Ordering::SeqCst);
    }
}

fn earlier(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_propagates_to_every_ancestor() {
        let root = Ledger::root(1000, None, 2);
        let child = root.child(500, None);
        let grandchild = child.child(100, None);

        grandchild.charge(30);

        assert_eq!(grandchild.spent(), 30);
        assert_eq!(child.spent(), 30);
        assert_eq!(root.spent(), 30);
    }

    #[test]
    fn child_limit_is_clamped_to_what_ancestors_have_left() {
        let root = Ledger::root(1000, None, 2);
        root.charge(700);

        let child = root.child(500, None);

        assert_eq!(child.token_limit(), 300);
    }

    #[test]
    fn a_sibling_spending_exhausts_the_other_branch() {
        let root = Ledger::root(1000, None, 2);
        let a = root.child(1000, None);
        let b = root.child(1000, None);

        a.charge(1000);

        assert!(b.exhausted());
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn slot_pool_caps_concurrency_and_releases_on_drop() {
        let root = Ledger::root(1000, None, 2);
        let first = root.try_acquire_slot().expect("first slot");
        let second = root.try_acquire_slot().expect("second slot");
        assert!(root.try_acquire_slot().is_none());
        assert_eq!(root.slots(), (2, 2));

        drop(first);
        assert_eq!(root.slots(), (1, 2));
        let third = root.try_acquire_slot().expect("released slot");
        assert_eq!(root.slots(), (2, 2));

        let child = root.child(100, None);
        assert!(child.try_acquire_slot().is_none());

        drop(second);
        drop(third);
        let child_slot = child.try_acquire_slot().expect("child shares the pool");
        assert_eq!(child.slots(), (1, 2));
        drop(child_slot);
        assert_eq!(child.slots(), (0, 2));
    }

    #[test]
    fn total_cap_is_reached_even_after_slots_are_released() {
        let root = Ledger::root_with_total(1000, None, 2, 2);
        let first = root.try_acquire_slot().expect("first slot");
        let second = root.try_acquire_slot().expect("second slot");
        assert_eq!(root.spawned(), (2, 2));
        assert!(root.try_acquire_slot().is_none());

        drop(first);
        drop(second);
        assert_eq!(root.slots(), (0, 2));
        assert_eq!(root.spawned(), (2, 2), "releasing does not decrement the total");
        assert!(root.try_acquire_slot().is_none(), "total cap still applies");
    }

    #[test]
    fn total_cap_does_not_disable_the_concurrency_cap() {
        let root = Ledger::root_with_total(1000, None, 1, 5);
        let first = root.try_acquire_slot().expect("first slot");
        assert!(root.try_acquire_slot().is_none(), "concurrency cap applies first");
        drop(first);
        let second = root.try_acquire_slot().expect("slot after release");
        assert_eq!(root.spawned(), (2, 5));
        drop(second);
    }

    #[test]
    fn total_cap_is_clamped_to_the_hard_range() {
        let low = Ledger::root_with_total(1000, None, 1, 0);
        assert_eq!(low.spawned(), (0, 1));
        let high = Ledger::root_with_total(1000, None, 1, usize::MAX);
        assert_eq!(high.spawned(), (0, HARD_TOTAL_AGENTS));
        let default = Ledger::root(1000, None, 1);
        assert_eq!(default.spawned(), (0, DEFAULT_TOTAL_AGENTS));
    }

    #[test]
    fn deadline_is_inherited_and_passes() {
        let passed = Ledger::root(1000, Some(0), 2);
        assert!(passed.exhausted());

        let root = Ledger::root(1000, Some(3600), 2);
        let child = root.child(1000, Some(7200));
        assert!(matches!(child.remaining_secs(), Some(secs) if secs <= 3600));
    }

    #[test]
    fn pressure_is_the_max_over_the_chain() {
        let root = Ledger::root(100, None, 2);
        let child = root.child(50, None);
        let sibling = root.child(50, None);

        child.charge(10);
        sibling.charge(80);

        assert!(root.pressure() >= 0.9);
        assert!(child.pressure() >= 0.9);
    }
}
