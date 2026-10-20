//! Hard limits on a job: steps, tokens, wall-clock. At the wind-down ratio the
//! loop is told to start finishing; at the limit it takes one final tool-less
//! step and stops.

use std::time::Instant;

use bulge_store::Budget;

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
}

impl BudgetTracker {
    pub fn new(limit: Budget) -> Self {
        Self { limit, steps: 0, tokens: 0, started: Instant::now() }
    }

    /// Resume with counters already spent (from the replayed log).
    pub fn with_spent(limit: Budget, steps: u64, tokens: u64) -> Self {
        Self { limit, steps, tokens, started: Instant::now() }
    }

    pub fn record_step(&mut self) {
        self.steps += 1;
    }

    pub fn record_tokens(&mut self, tokens: u64) {
        self.tokens = self.tokens.saturating_add(tokens);
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
        ratios.into_iter().fold(0.0, f64::max)
    }

    /// First resource that is exhausted, else first in wind-down.
    pub fn strained(&self) -> Option<Resource> {
        let items = [
            (Resource::Steps, self.steps, self.limit.max_steps),
            (Resource::Tokens, self.tokens, self.limit.max_tokens),
            (Resource::WallClock, self.wall_secs(), self.limit.max_wall_secs),
        ];
        items
            .iter()
            .find(|(_, used, max)| *used >= *max)
            .or_else(|| items.iter().find(|(_, used, max)| ratio(*used, *max) >= WIND_DOWN_RATIO))
            .map(|(r, _, _)| *r)
    }

    pub fn state(&self) -> BudgetState {
        let spent = |used: u64, max: u64| used >= max;
        if spent(self.steps, self.limit.max_steps) || spent(self.tokens, self.limit.max_tokens) || spent(self.wall_secs(), self.limit.max_wall_secs) {
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
}
