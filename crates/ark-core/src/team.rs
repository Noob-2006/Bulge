//! The team a model call is made for (ent-086): the kernel sets it around a turn from the
//! session's owner (`ark users team`), and the provider resolver uses it to pick that team's
//! own model keys before the shared ones. Thread-local and scoped, so concurrent sessions of
//! different teams never see each other's choice.

use std::cell::RefCell;

thread_local! {
    static TEAM: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// The team of the call being made on this thread (`None` = no team / shared keys).
pub fn current() -> Option<String> {
    TEAM.with(|t| t.borrow().clone())
}

/// Set the team until the guard drops (an empty name clears it).
pub fn scope(team: &str) -> Scope {
    let t = team.trim();
    let prev = TEAM.with(|c| c.replace((!t.is_empty()).then(|| t.to_string())));
    Scope(prev)
}

pub struct Scope(Option<String>);

impl Drop for Scope {
    fn drop(&mut self) {
        let prev = self.0.take();
        TEAM.with(|c| *c.borrow_mut() = prev);
    }
}

/// `eng-platform` → `ENG_PLATFORM`: the suffix of a team's secret names
/// (`OPENAI_API_KEY__ENG_PLATFORM`).
pub fn secret_suffix(team: &str) -> String {
    team.trim().chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_nest_and_restore() {
        assert_eq!(current(), None);
        {
            let _a = scope("eng");
            assert_eq!(current().as_deref(), Some("eng"));
            {
                let _b = scope("");
                assert_eq!(current(), None);
            }
            assert_eq!(current().as_deref(), Some("eng"));
        }
        assert_eq!(current(), None);
        assert_eq!(secret_suffix("eng-platform"), "ENG_PLATFORM");
    }
}
