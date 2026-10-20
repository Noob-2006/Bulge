//! Rule-based permissions, last-match-wins (opencode model).
//!
//! An action (e.g. `edit`, `shell`, `net`) over one or more resources (paths,
//! commands, domains) resolves to allow / deny / ask. Across all rulesets the
//! last matching rule wins; the default is `ask`. For several resources: any
//! `deny` denies; otherwise any `ask` asks; otherwise allow.

use serde::{Deserialize, Serialize};

use crate::wildcard::matches;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub action: String,
    pub resource: String,
    pub effect: Effect,
}

impl Rule {
    pub fn new(action: impl Into<String>, resource: impl Into<String>, effect: Effect) -> Self {
        Self { action: action.into(), resource: resource.into(), effect }
    }
}

pub type Ruleset = Vec<Rule>;

/// Effect for one action+resource. Later rulesets override earlier ones; within
/// a ruleset a later rule overrides an earlier one. No match → `Ask`.
pub fn evaluate(action: &str, resource: &str, rulesets: &[&Ruleset]) -> Effect {
    rulesets
        .iter()
        .rev()
        .flat_map(|rs| rs.iter().rev())
        .find(|rule| matches(action, &rule.action) && matches(resource, &rule.resource))
        .map_or(Effect::Ask, |rule| rule.effect)
}

/// Effect for an action over several resources: deny beats ask beats allow.
pub fn evaluate_resources(action: &str, resources: &[String], rulesets: &[&Ruleset]) -> Effect {
    let mut result = Effect::Allow;
    for resource in resources {
        match evaluate(action, resource, rulesets) {
            Effect::Deny => return Effect::Deny,
            Effect::Ask => result = Effect::Ask,
            Effect::Allow => {}
        }
    }
    if resources.is_empty() { Effect::Ask } else { result }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(rules: &[(&str, &str, Effect)]) -> Ruleset {
        rules.iter().map(|(a, r, e)| Rule::new(*a, *r, *e)).collect()
    }

    #[test]
    fn default_is_ask() {
        assert_eq!(evaluate("edit", "x", &[]), Effect::Ask);
    }

    #[test]
    fn last_match_wins_across_rulesets() {
        let base = rs(&[("*", "*", Effect::Allow)]);
        let session = rs(&[("shell", "*", Effect::Ask), ("shell", "git *", Effect::Allow)]);
        assert_eq!(evaluate("shell", "git status", &[&base, &session]), Effect::Allow);
        assert_eq!(evaluate("shell", "rm -rf /", &[&base, &session]), Effect::Ask);
        assert_eq!(evaluate("read", "any", &[&base, &session]), Effect::Allow);
    }

    #[test]
    fn env_reads_can_be_gated() {
        let base = rs(&[("read", "*", Effect::Allow), ("read", "*.env", Effect::Ask)]);
        assert_eq!(evaluate("read", "a.txt", &[&base]), Effect::Allow);
        assert_eq!(evaluate("read", "secrets.env", &[&base]), Effect::Ask);
    }

    #[test]
    fn multi_resource_deny_wins() {
        let base = rs(&[("edit", "*", Effect::Allow), ("edit", "locked/*", Effect::Deny)]);
        let paths = vec!["a.txt".to_string(), "locked/b.txt".to_string()];
        assert_eq!(evaluate_resources("edit", &paths, &[&base]), Effect::Deny);
    }
}
