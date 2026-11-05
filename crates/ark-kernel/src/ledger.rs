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
    /// 0 = same as `input`.
    #[serde(default)]
    pub cache_write: f64,
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
    /// Wall-clock time excluded from `max_wall_secs` (blocked on a human approval).
    paused: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct Ledger {
    state: Arc<Mutex<State>>,
    parent: Option<Box<Ledger>>,
}

type PriceFn = dyn Fn(&str) -> Option<Price> + Send + Sync;

fn price_source() -> &'static std::sync::RwLock<Option<Box<PriceFn>>> {
    static S: std::sync::OnceLock<std::sync::RwLock<Option<Box<PriceFn>>>> = std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::RwLock::new(None))
}

/// Built-in price table (`provider/model` → USD per million) used when `[prices]` has no entry.
pub fn set_price_source(f: Box<PriceFn>) {
    *price_source().write().unwrap() = Some(f);
}

pub fn fallback_price(model: &str) -> Option<Price> {
    price_source().read().unwrap().as_ref().and_then(|f| f(model))
}

thread_local! {
    static CURRENT: std::cell::RefCell<Option<Ledger>> = const { std::cell::RefCell::new(None) };
}

impl Ledger {
    /// Make this ledger the one auxiliary calls on this thread are charged to.
    pub fn enter(&self) -> LedgerGuard {
        let prev = CURRENT.with(|c| c.replace(Some(self.clone())));
        LedgerGuard(prev)
    }
    /// Charge an auxiliary call (compaction, review…) to the ledger of the running turn, if any.
    pub fn charge_current(usage: &Usage, price: Option<Price>) -> bool {
        CURRENT.with(|c| c.borrow().as_ref().map(|l| l.charge_tokens(usage, price)).is_some())
    }
}

pub struct LedgerGuard(Option<Ledger>);

impl Drop for LedgerGuard {
    fn drop(&mut self) {
        let prev = self.0.take();
        CURRENT.with(|c| *c.borrow_mut() = prev);
    }
}

/// Cached reads are ~10x cheaper on every major provider; count them at 10%.
const CACHE_WEIGHT: f64 = 0.1;

impl Ledger {
    pub fn new(budget: Budget) -> Self {
        Ledger { state: Arc::new(Mutex::new(State { budget, tokens: 0, steps: 0, cost: 0.0, started: Instant::now(), paused: std::time::Duration::ZERO })), parent: None }
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
                let secs = s.started.elapsed().saturating_sub(s.paused).as_secs();
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

    /// Charge tokens and cost without counting a step (auxiliary calls).
    pub fn charge_tokens(&self, usage: &Usage, price: Option<Price>) {
        self.charge_inner(usage, price, false)
    }

    /// Exclude `d` (time spent waiting on a human) from the wall-clock budget, up the chain.
    pub fn pause(&self, d: std::time::Duration) {
        if d.is_zero() {
            return;
        }
        self.lock().paused += d;
        if let Some(p) = &self.parent {
            p.pause(d);
        }
    }

    pub fn charge(&self, usage: &Usage, price: Option<Price>) {
        self.charge_inner(usage, price, true)
    }

    fn charge_inner(&self, usage: &Usage, price: Option<Price>, step: bool) {
        let weighted = usage.input_tokens + usage.output_tokens + usage.cache_write_tokens + (usage.cache_read_tokens as f64 * CACHE_WEIGHT) as u64;
        let cost = price
            .map(|p| {
                usage.input_tokens as f64 * p.input / 1e6
                    + usage.cache_write_tokens as f64 * if p.cache_write > 0.0 { p.cache_write } else { p.input } / 1e6
                    + usage.output_tokens as f64 * p.output / 1e6
                    + usage.cache_read_tokens as f64 * if p.cache_read > 0.0 { p.cache_read } else { p.input * CACHE_WEIGHT } / 1e6
            })
            .unwrap_or(0.0);
        {
            let mut s = self.lock();
            s.tokens += weighted;
            s.cost += cost;
            if step {
                s.steps += 1;
            }
        }
        if let Some(p) = &self.parent {
            p.charge_inner(usage, price, step);
        }
    }

    /// Whether this ledger or an ancestor caps spend in USD.
    pub fn has_cost_cap(&self) -> bool {
        self.lock().budget.max_cost_usd.is_some_and(|m| m > 0.0) || self.parent.as_ref().is_some_and(|p| p.has_cost_cap())
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
    fn cache_writes_use_their_own_rate() {
        let l = Ledger::new(Budget::default());
        let p = Price { input: 4.0, output: 20.0, cache_read: 0.2, cache_write: 5.0 };
        l.charge(&Usage { input_tokens: 1_000_000, output_tokens: 1_000_000, cache_read_tokens: 1_000_000, cache_write_tokens: 1_000_000, ..Default::default() }, Some(p));
        assert!((l.snapshot().2 - 29.2).abs() < 1e-9);
        assert!(!l.has_cost_cap());
        assert!(Ledger::new(Budget::default()).child(Budget { max_cost_usd: Some(1.0), ..Default::default() }).has_cost_cap());
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
        l.charge(&usage, Some(Price { input: 3.0, output: 15.0, cache_read: 0.3, cache_write: 0.0 }));
        let (tok, _, cost) = l.snapshot();
        assert_eq!(tok, 100);
        assert!((cost - 0.0003).abs() < 1e-9);
        l.charge(&u(0, 100_000), Some(Price { input: 3.0, output: 15.0, cache_read: 0.0, cache_write: 0.0 }));
        assert!(matches!(l.check(), Err(Exceeded::Cost { .. })));
    }

    #[test]
    fn aux_calls_charge_the_running_ledger_without_steps() {
        let l = Ledger::new(Budget::default());
        assert!(!Ledger::charge_current(&u(5, 5), None), "no turn running");
        {
            let _g = l.enter();
            assert!(Ledger::charge_current(&u(5, 5), Some(Price { input: 1e6, output: 0.0, cache_read: 0.0, cache_write: 0.0 })));
        }
        assert!(!Ledger::charge_current(&u(5, 5), None), "guard restores");
        let (tok, steps, cost) = l.snapshot();
        assert_eq!((tok, steps), (10, 0));
        assert!((cost - 5.0).abs() < 1e-9);
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
