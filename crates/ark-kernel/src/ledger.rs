//! Budget ledger. Enforced by the kernel, shared down the agent tree: a child
//! charges itself and every ancestor, so a sub-agent can never outspend its parent.

use ark_core::Usage;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Budget {
    /// Total (input + output) tokens. Cached input counts at `cache_weight`.
    pub max_tokens: Option<u64>,
    pub max_steps: Option<u64>,
    pub max_cost_usd: Option<f64>,
    pub max_wall_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Price {
    /// USD per million tokens.
    pub input: f64,
    pub output: f64,
    #[serde(default)]
    pub cache_read: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Exceeded {
    Tokens { used: u64, max: u64 },
    Steps { used: u64, max: u64 },
    Cost { used: f64, max: f64 },
    Wall { secs: u64, max: u64 },
}

impl std::fmt::Display for Exceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Exceeded::Tokens { used, max } => write!(f, "token budget exhausted ({used}/{max})"),
            Exceeded::Steps { used, max } => write!(f, "step budget exhausted ({used}/{max})"),
            Exceeded::Cost { used, max } => write!(f, "cost budget exhausted (${used:.4}/${max:.4})"),
            Exceeded::Wall { secs, max } => write!(f, "time budget exhausted ({secs}s/{max}s)"),
        }
    }
}

#[derive(Debug)]
struct State {
    budget: Budget,
    tokens: u64,
    steps: u64,
    cost: f64,
    started: Instant,
}

#[derive(Debug, Clone)]
pub struct Ledger {
    state: Arc<Mutex<State>>,
    parent: Option<Box<Ledger>>,
}

/// Cached reads are ~10x cheaper on every major provider; count them at 10%.
const CACHE_WEIGHT: f64 = 0.1;

impl Ledger {
    pub fn new(budget: Budget) -> Self {
        Ledger { state: Arc::new(Mutex::new(State { budget, tokens: 0, steps: 0, cost: 0.0, started: Instant::now() })), parent: None }
    }
    pub fn child(&self, budget: Budget) -> Self {
        let mut c = Ledger::new(budget);
        c.parent = Some(Box::new(self.clone()));
        c
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Check before starting a step. Checks the whole ancestor chain.
    pub fn check(&self) -> Result<(), Exceeded> {
        {
            let s = self.lock();
            let b = &s.budget;
            if let Some(max) = b.max_tokens {
                if s.tokens >= max {
                    return Err(Exceeded::Tokens { used: s.tokens, max });
                }
            }
            if let Some(max) = b.max_steps {
                if s.steps >= max {
                    return Err(Exceeded::Steps { used: s.steps, max });
                }
            }
            if let Some(max) = b.max_cost_usd {
                if s.cost >= max {
                    return Err(Exceeded::Cost { used: s.cost, max });
                }
            }
            if let Some(max) = b.max_wall_secs {
                let secs = s.started.elapsed().as_secs();
                if secs >= max {
                    return Err(Exceeded::Wall { secs, max });
                }
            }
        }
        match &self.parent {
            Some(p) => p.check(),
            None => Ok(()),
        }
    }

    pub fn charge(&self, usage: &Usage, price: Option<Price>) {
        let weighted = usage.input_tokens + usage.output_tokens + usage.cache_write_tokens + (usage.cache_read_tokens as f64 * CACHE_WEIGHT) as u64;
        let cost = price
            .map(|p| {
                (usage.input_tokens + usage.cache_write_tokens) as f64 * p.input / 1e6
                    + usage.output_tokens as f64 * p.output / 1e6
                    + usage.cache_read_tokens as f64 * if p.cache_read > 0.0 { p.cache_read } else { p.input * CACHE_WEIGHT } / 1e6
            })
            .unwrap_or(0.0);
        {
            let mut s = self.lock();
            s.tokens += weighted;
            s.cost += cost;
            s.steps += 1;
        }
        if let Some(p) = &self.parent {
            p.charge(usage, price);
        }
    }

    pub fn snapshot(&self) -> (u64, u64, f64) {
        let s = self.lock();
        (s.tokens, s.steps, s.cost)
    }

    /// Fraction of the tightest budget used (for "running low" notices).
    pub fn pressure(&self) -> f64 {
        let s = self.lock();
        let b = &s.budget;
        let mut p: f64 = 0.0;
        if let Some(m) = b.max_tokens.filter(|m| *m > 0) {
            p = p.max(s.tokens as f64 / m as f64);
        }
        if let Some(m) = b.max_steps.filter(|m| *m > 0) {
            p = p.max(s.steps as f64 / m as f64);
        }
        if let Some(m) = b.max_cost_usd.filter(|m| *m > 0.0) {
            p = p.max(s.cost / m);
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(i: u64, o: u64) -> Usage {
        Usage { input_tokens: i, output_tokens: o, ..Default::default() }
    }

    #[test]
    fn tokens_and_steps_enforced() {
        let l = Ledger::new(Budget { max_tokens: Some(100), max_steps: Some(10), ..Default::default() });
        l.check().unwrap();
        l.charge(&u(60, 30), None);
        l.check().unwrap();
        l.charge(&u(5, 5), None);
        assert!(matches!(l.check(), Err(Exceeded::Tokens { used: 100, max: 100 })));
    }

    #[test]
    fn child_charges_parent_and_parent_limit_stops_child() {
        let p = Ledger::new(Budget { max_steps: Some(2), ..Default::default() });
        let c = p.child(Budget::default());
        c.charge(&u(1, 1), None);
        c.charge(&u(1, 1), None);
        assert!(matches!(c.check(), Err(Exceeded::Steps { .. })), "parent budget binds child");
        assert_eq!(p.snapshot().1, 2);
    }

    #[test]
    fn cached_tokens_are_discounted_and_cost_computed() {
        let l = Ledger::new(Budget { max_cost_usd: Some(1.0), ..Default::default() });
        let usage = Usage { input_tokens: 0, output_tokens: 0, cache_read_tokens: 1000, ..Default::default() };
        l.charge(&usage, Some(Price { input: 3.0, output: 15.0, cache_read: 0.3 }));
        let (tok, _, cost) = l.snapshot();
        assert_eq!(tok, 100);
        assert!((cost - 0.0003).abs() < 1e-9);
        l.charge(&u(0, 100_000), Some(Price { input: 3.0, output: 15.0, cache_read: 0.0 }));
        assert!(matches!(l.check(), Err(Exceeded::Cost { .. })));
    }

    #[test]
    fn wall_clock_budget() {
        let l = Ledger::new(Budget { max_wall_secs: Some(0), ..Default::default() });
        assert!(matches!(l.check(), Err(Exceeded::Wall { .. })));
    }

    #[test]
    fn no_budget_never_blocks_and_pressure_tracks() {
        let l = Ledger::new(Budget::default());
        for _ in 0..1000 {
            l.charge(&u(1000, 1000), None);
        }
        l.check().unwrap();
        assert_eq!(l.pressure(), 0.0);
        let l2 = Ledger::new(Budget { max_steps: Some(4), ..Default::default() });
        l2.charge(&u(1, 1), None);
        assert!((l2.pressure() - 0.25).abs() < 1e-9);
    }
}
