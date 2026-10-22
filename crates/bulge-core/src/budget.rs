//! Hard limits on a job: steps, tokens, wall-clock. At the wind-down ratio the
//! loop is told to start finishing; at the limit it takes one final tool-less
//! step and stops.

use std::sync::Arc;
use std::time::Instant;

use bulge_store::Budget;

use crate::ledger::Ledger;

/// Fraction of any limit at which the loop enters wind-down.
pub const WIND_DOWN_RATIO: f64 = 0.8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetState {
    Ok,
    /// At least one resource is past `WIND_DOWN_RATIO`: keep tools, but the loop
    /// injects a reminder to deliver what exists before the limit.
    WindDown,
    /// At least one resource is spent: one final tool-less step, then stop.
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Steps,
    Tokens,
    WallClock,
}

#[derive(Debug)]
pub struct BudgetTracker {
    limit: Budget,
    steps: u64,
    tokens: u64,
    started: Instant,
    ledger: Option<Arc<Ledger>>,
}

impl BudgetTracker {
    pub fn new(limit: Budget) -> Self {
        Self { limit, steps: 0, tokens: 0, started: Instant::now(), ledger: None }
    }

    /// Resume with counters already spent (from the replayed log).
    pub fn with_spent(limit: Budget, steps: u64, tokens: u64) -> Self {
        Self { limit, steps, tokens, started: Instant::now(), ledger: None }
    }

    /// Also charge every recorded token to `ledger` (this agent's node of a shared
    /// budget tree) and treat the tree's exhaustion as this tracker's own.
    pub fn with_ledger(mut self, ledger: Arc<Ledger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// The shared ledger node, if one is attached.
    pub fn ledger(&self) -> Option<&Arc<Ledger>> {
        self.ledger.as_ref()
    }

    pub fn record_step(&mut self) {
        self.steps += 1;
    }

    pub fn record_tokens(&mut self, tokens: u64) {
        self.tokens = self.tokens.saturating_add(tokens);
        if let Some(ledger) = &self.ledger {
            ledger.charge(tokens);
        }
    }

    fn wall_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// The most-spent resource as a fraction of its limit (0.0..), for display.
    pub fn pressure(&self) -> f64 {
        let ratios = [
            ratio(self.steps, self.limit.max_steps),
            ratio(self.tokens, self.limit.max_tokens),
            ratio(self.wall_secs(), self.limit.max_wall_secs),
        ];
        let own = ratios.into_iter().fold(0.0, f64::max);
        match &self.ledger {
            Some(ledger) => own.max(ledger.pressure()),
            None => own,
        }
    }

    /// First resource that is exhausted, else first in wind-down.
    pub fn strained(&self) -> Option<Resource> {
        let items = [
            (Resource::Steps, self.steps, self.limit.max_steps),
            (Resource::Tokens, self.tokens, self.limit.max_tokens),
            (Resource::WallClock, self.wall_secs(), self.limit.max_wall_secs),
        ];
        if let Some(resource) = items
            .iter()
            .find(|(_, used, max)| *used >= *max)
            .or_else(|| items.iter().find(|(_, used, max)| ratio(*used, *max) >= WIND_DOWN_RATIO))
            .map(|(r, _, _)| *r)
        {
            return Some(resource);
        }
        let ledger = self.ledger.as_ref()?;
        if !ledger.exhausted() && ledger.pressure() < WIND_DOWN_RATIO {
            return None;
        }
        if ledger.remaining() == 0 || ledger.token_pressure() >= ledger.deadline_pressure() {
            Some(Resource::Tokens)
        } else {
            Some(Resource::WallClock)
        }
    }

    pub fn state(&self) -> BudgetState {
        let spent = |used: u64, max: u64| used >= max;
        if spent(self.steps, self.limit.max_steps)
            || spent(self.tokens, self.limit.max_tokens)
            || spent(self.wall_secs(), self.limit.max_wall_secs)
            || self.ledger.as_ref().is_some_and(|ledger| ledger.exhausted())
        {
            BudgetState::Exhausted
        } else if self.pressure() >= WIND_DOWN_RATIO {
            BudgetState::WindDown
        } else {
            BudgetState::Ok
        }
    }

    pub fn snapshot(&self) -> (u64, u64, u64) {
        (self.steps, self.tokens, self.wall_secs())
    }
}

fn ratio(used: u64, max: u64) -> f64 {
    if max == 0 { 1.0 } else { used as f64 / max as f64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> Budget {
        Budget { max_steps: 10, max_tokens: 1000, max_wall_secs: 3600 }
    }

    #[test]
    fn transitions_ok_winddown_exhausted() {
        let mut b = BudgetTracker::new(budget());
        assert_eq!(b.state(), BudgetState::Ok);
        for _ in 0..8 {
            b.record_step();
        }
        assert_eq!(b.state(), BudgetState::WindDown);
        assert_eq!(b.strained(), Some(Resource::Steps));
        for _ in 0..2 {
            b.record_step();
        }
        assert_eq!(b.state(), BudgetState::Exhausted);
    }

    #[test]
    fn tokens_trigger_independently() {
        let mut b = BudgetTracker::new(budget());
        b.record_tokens(950);
        assert_eq!(b.state(), BudgetState::WindDown);
        b.record_tokens(60);
        assert_eq!(b.state(), BudgetState::Exhausted);
        assert_eq!(b.strained(), Some(Resource::Tokens));
    }

    #[test]
    fn resume_counts_prior_spend() {
        let b = BudgetTracker::with_spent(budget(), 10, 0);
        assert_eq!(b.state(), BudgetState::Exhausted);
    }

    #[test]
    fn ledger_exhaustion_exhausts_the_tracker() {
        let root = Ledger::root(100, None, 2);
        let child = root.child(100, None);
        let sibling = root.child(100, None);
        sibling.charge(100);

        let tracker = BudgetTracker::new(budget()).with_ledger(child);

        assert_eq!(tracker.state(), BudgetState::Exhausted);
        assert_eq!(tracker.strained(), Some(Resource::Tokens));
    }

    #[test]
    fn recorded_tokens_are_charged_to_the_ledger() {
        let root = Ledger::root(1000, None, 2);
        let child = root.child(500, None);
        let mut tracker = BudgetTracker::new(budget()).with_ledger(Arc::clone(&child));

        tracker.record_tokens(40);

        assert_eq!(tracker.ledger().map(|ledger| ledger.spent()), Some(40));
        assert_eq!(child.spent(), 40);
        assert_eq!(root.spent(), 40);
    }
}
