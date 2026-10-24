use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use super::*;

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(label: &str) -> TempDir {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bulge-org-role-{label}-{}-{sequence}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create temp dir");
    TempDir(path)
}

const FULL: &str = r#"---
# a comment
name: backend-implementer
kind: worker
purpose: "implement backend work: safely"
domain: ["src/server/**", "tests/server/**"]
accountabilities: [ship tested code, report evidence]
act: [edit_in_domain, run_tests]
recommend: [api_shape]
decide: []
tools: [read, write, edit]
model: deepseek-flash
reasoning_effort: high
budget_share: 0.15
kpis: [acceptance_rate, "rework, rate"]
---
Do the work.
Verify it.
"#;

fn tool(name: &str) -> ToolSchema {
    ToolSchema {
        name: name.to_string(),
        description: String::new(),
        parameters: json!({"type": "object"}),
        defer_loading: false,
    }
}

#[test]
fn parses_a_full_charter() {
    let charter = parse_charter(FULL).expect("parse");
    assert_eq!(charter.name, "backend-implementer");
    assert_eq!(charter.kind, RoleKind::Worker);
    assert_eq!(charter.purpose, "implement backend work: safely");
    assert_eq!(charter.domain, ["src/server/**", "tests/server/**"]);
    assert_eq!(
        charter.accountabilities,
        ["ship tested code", "report evidence"]
    );
    assert_eq!(charter.act, ["edit_in_domain", "run_tests"]);
    assert_eq!(charter.recommend, ["api_shape"]);
    assert!(charter.decide.is_empty());
    assert_eq!(charter.tools, ["read", "write", "edit"]);
    assert_eq!(charter.model.as_deref(), Some("deepseek-flash"));
    assert_eq!(charter.reasoning_effort.as_deref(), Some("high"));
    assert!((charter.budget_share - 0.15).abs() < f64::EPSILON);
    assert_eq!(charter.kpis, ["acceptance_rate", "rework, rate"]);
    assert_eq!(charter.body, "Do the work.\nVerify it.");
}

#[test]
fn scalar_list_and_quoted_comma_values() {
    let source =
        "---\nname: analyst\npurpose: analyze\ntools: [read]\ndomain: [\"a, b\", c]\n---\n";
    let charter = parse_charter(source).expect("parse");
    assert_eq!(charter.domain, ["a, b", "c"]);
    assert_eq!(charter.budget_share, 0.25);
    assert_eq!(charter.kind, RoleKind::Worker);
}

#[test]
fn trial_defaults_false_and_parses_true_and_false() {
    let default = parse_charter("---\nname: analyst\npurpose: analyze\ntools: [read]\n---\n")
        .expect("parse default");
    assert!(!default.trial);
    let trial = parse_charter(
        "---\nname: analyst\npurpose: analyze\ntools: [read]\ntrial: true\n---\n",
    )
    .expect("parse trial");
    assert!(trial.trial);
    let not_trial = parse_charter(
        "---\nname: analyst\npurpose: analyze\ntools: [read]\ntrial: false\n---\n",
    )
    .expect("parse not trial");
    assert!(!not_trial.trial);
    assert!(
        parse_charter(
            "---\nname: analyst\npurpose: analyze\ntools: [read]\ntrial: maybe\n---\n"
        )
        .is_err()
    );
}

#[test]
fn trial_budget_share_is_capped_until_graduation() {
    let charter = parse_charter(
        "---\nname: analyst\npurpose: analyze\ntools: [read]\nbudget_share: 0.2\ntrial: true\n---\n",
    )
    .expect("parse trial");
    assert_eq!(charter.effective_budget_share(0), TRIAL_BUDGET_SHARE);
    assert_eq!(charter.effective_budget_share(2), TRIAL_BUDGET_SHARE);
    assert!((charter.effective_budget_share(TRIAL_GRADUATION) - 0.2).abs() < f64::EPSILON);
    let normal = parse_charter(
        "---\nname: analyst\npurpose: analyze\ntools: [read]\nbudget_share: 0.2\n---\n",
    )
    .expect("parse normal");
    assert!((normal.effective_budget_share(0) - 0.2).abs() < f64::EPSILON);
}

#[test]
fn unknown_key_is_rejected() {
    let source = "---\nname: analyst\npurpose: analyze\ntools: [read]\ntoolz: [read]\n---\n";
    let error = parse_charter(source).expect_err("unknown key");
    assert!(error.contains("toolz"), "{error}");
}

#[test]
fn missing_purpose_is_rejected() {
    let error =
        parse_charter("---\nname: analyst\ntools: [read]\n---\n").expect_err("missing purpose");
    assert!(error.contains("purpose"), "{error}");
}

#[test]
fn bad_name_is_rejected() {
    for name in [
        "Bad_Name",
        "bad name",
        "-leading",
        "trailing-",
        "double--hyphen",
        "",
    ] {
        let source = format!("---\nname: {name}\npurpose: x\ntools: [read]\n---\n");
        assert!(parse_charter(&source).is_err(), "accepted {name:?}");
    }
}

#[test]
fn budget_share_out_of_range_is_rejected() {
    for share in ["0", "-0.1", "1.01", "NaN", "not-a-number"] {
        let source = format!(
            "---\nname: analyst\npurpose: x\ntools: [read]\nbudget_share: {share}\n---\n"
        );
        assert!(parse_charter(&source).is_err(), "accepted {share}");
    }
}

#[test]
fn bad_reasoning_effort_is_rejected() {
    let source =
        "---\nname: analyst\npurpose: x\ntools: [read]\nreasoning_effort: medium\n---\n";
    assert!(parse_charter(source).is_err());
    for effort in ["off", "low", "high", "max"] {
        let source = format!(
            "---\nname: analyst\npurpose: x\ntools: [read]\nreasoning_effort: {effort}\n---\n"
        );
        assert!(parse_charter(&source).is_ok(), "rejected {effort}");
    }
}

#[test]
fn system_prompt_is_stable_and_contains_purpose_and_domain() {
    let charter = parse_charter(FULL).expect("parse");
    let first = charter.system_prompt();
    let second = charter.system_prompt();
    assert_eq!(first, second);
    assert!(first.starts_with("You are the `backend-implementer` role (worker)"));
    assert!(first.contains("Purpose: implement backend work: safely"));
    assert!(first.contains("Domain you own: src/server/**, tests/server/**."));
    assert!(first.contains("- ship tested code"));
    assert!(first.contains("Do the work.\nVerify it."));
}

#[test]
fn filter_tools_keeps_order_and_drops_others() {
    let charter = parse_charter(FULL).expect("parse");
    let all = vec![
        tool("exec"),
        tool("read"),
        tool("write"),
        tool("edit"),
        tool("grep"),
    ];
    let filtered: Vec<String> = charter
        .filter_tools(&all)
        .into_iter()
        .map(|tool| tool.name)
        .collect();
    assert_eq!(filtered, ["read", "write", "edit"]);
    assert!(charter.allows_tool("read"));
    assert!(!charter.allows_tool("exec"));
}

#[test]
fn parses_alternates_and_defaults_to_empty() {
    let source = "---\nname: analyst\npurpose: analyze\ntools: [read]\nmodel: primary\nalternates: [backup, third]\n---\n";
    let charter = parse_charter(source).expect("parse alternates");
    assert_eq!(charter.alternates, ["backup", "third"]);
    let charter = parse_charter(FULL).expect("parse without alternates");
    assert!(charter.alternates.is_empty());
}

#[test]
fn duplicate_alternates_are_rejected() {
    let source = "---\nname: analyst\npurpose: analyze\ntools: [read]\nmodel: primary\nalternates: [backup, backup]\n---\n";
    let error = parse_charter(source).expect_err("duplicate alternate");
    assert!(error.contains("backup"), "{error}");
    assert!(error.contains("duplicate"), "{error}");
}

#[test]
fn alternate_equal_to_model_is_rejected() {
    let source = "---\nname: analyst\npurpose: analyze\ntools: [read]\nmodel: primary\nalternates: [backup, primary]\n---\n";
    let error = parse_charter(source).expect_err("alternate equals model");
    assert!(error.contains("primary"), "{error}");
    assert!(error.contains("model"), "{error}");
}

#[test]
fn candidate_models_orders_and_deduplicates() {
    let source = "---\nname: analyst\npurpose: analyze\ntools: [read]\nmodel: primary\nalternates: [backup, third]\n---\n";
    let charter = parse_charter(source).expect("parse");
    assert_eq!(
        charter.candidate_models("session"),
        ["primary", "backup", "third", "session"]
    );
    assert_eq!(
        charter.candidate_models("backup"),
        ["primary", "backup", "third"]
    );

    let source =
        "---\nname: analyst\npurpose: analyze\ntools: [read]\nalternates: [backup]\n---\n";
    let charter = parse_charter(source).expect("parse without model");
    assert_eq!(charter.candidate_models("session"), ["backup", "session"]);
    assert_eq!(charter.candidate_models("backup"), ["backup"]);

    let source = "---\nname: analyst\npurpose: analyze\ntools: [read]\n---\n";
    let charter = parse_charter(source).expect("parse without models");
    assert_eq!(charter.candidate_models("session"), ["session"]);
}

#[test]
fn builtins_parse_with_expected_kinds() {
    let roles = builtin_roles();
    assert_eq!(roles.len(), 5);
    let kinds: BTreeMap<&str, RoleKind> = roles
        .iter()
        .map(|role| (role.name.as_str(), role.kind))
        .collect();
    assert_eq!(kinds.get("explorer"), Some(&RoleKind::Worker));
    assert_eq!(kinds.get("implementer"), Some(&RoleKind::Worker));
    assert_eq!(kinds.get("reviewer"), Some(&RoleKind::Reviewer));
    assert_eq!(kinds.get("lead"), Some(&RoleKind::Lead));
    assert_eq!(kinds.get("chief"), Some(&RoleKind::Lead));
}

#[test]
fn load_overrides_adds_reports_and_skips() {
    let dir = temp_dir("load");
    std::fs::write(
        dir.0.join("explorer.md"),
        "---\nname: explorer\npurpose: custom exploration\ntools: [read]\n---\n",
    )
    .expect("write override");
    std::fs::write(
        dir.0.join("analyst.md"),
        "---\nname: analyst\npurpose: analyze data\ntools: [read, grep]\n---\n",
    )
    .expect("write new role");
    std::fs::write(dir.0.join("broken.md"), "not a charter").expect("write broken");
    std::fs::write(
        dir.0.join("mismatch.md"),
        "---\nname: other\npurpose: x\ntools: [read]\n---\n",
    )
    .expect("write mismatch");

    let (library, problems) = RoleLibrary::load(&dir.0);
    assert_eq!(
        library.get("explorer").map(|role| role.purpose.as_str()),
        Some("custom exploration")
    );
    assert!(library.get("analyst").is_some());
    assert!(library.get("broken").is_none());
    assert!(library.get("other").is_none());
    assert_eq!(problems.len(), 2);
    assert!(
        problems
            .iter()
            .any(|problem| problem.path.ends_with("broken.md"))
    );
    assert!(
        problems
            .iter()
            .any(|problem| problem.path.ends_with("mismatch.md")
                && problem.message.contains("does not match file stem"))
    );
    assert_eq!(
        library.names(),
        ["analyst", "chief", "explorer", "implementer", "lead", "reviewer"]
    );
    assert_eq!(library.by_kind(RoleKind::Reviewer).len(), 1);
    assert_eq!(library.by_kind(RoleKind::Lead).len(), 2);
}

#[test]
fn missing_role_directory_is_not_an_error() {
    let dir = temp_dir("missing");
    let missing = dir.0.join("does-not-exist");
    let (library, problems) = RoleLibrary::load(&missing);
    assert!(problems.is_empty());
    assert_eq!(library.names().len(), 5);
}
