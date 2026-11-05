//! The size budget and the feature split stay honest (audit row D6).
//!
//! Two things rot silently and neither shows up in a normal test run:
//!
//! * the default build stops being *complete* (a platform family or a model adapter
//!   quietly drops out of `default`/`full`, so a release user loses a feature), and
//! * the documented build variants and budget table drift away from the code
//!   (`docs/BUILD.md` promising a slim build that no longer exists, or a budget
//!   nobody enforces).
//!
//! This test reads the manifests and `tools/size-budget.tsv` as data, so it needs no
//! release build and no network. The measured sizes are enforced by
//! `tools/size-budget.sh` (build + compare); here we only check the wiring and that
//! the documents agree with the budgets.

use std::collections::BTreeMap;

const SEAGENT_MANIFEST: &str = include_str!("../Cargo.toml");
const MODEL_MANIFEST: &str = include_str!("../../seagent-model/Cargo.toml");
const KERNEL_MANIFEST: &str = include_str!("../../seagent-kernel/Cargo.toml");
const BUDGETS: &str = include_str!("../../../tools/size-budget.tsv");
const DOC: &str = include_str!("../../../docs/BUILD.md");

struct Build {
    name: String,
    profile: String,
    features: String,
    budget: u64,
    measured: u64,
    command: String,
}

fn builds() -> Vec<Build> {
    let mut out = Vec::new();
    for (i, line) in BUDGETS.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').map(str::trim).collect();
        assert!(
            f.len() >= 6,
            "tools/size-budget.tsv line {}: expected 6 tab-separated columns \
             (name, profile, features, budget_bytes, measured_bytes, command), got {}",
            i + 1,
            f.len()
        );
        out.push(Build {
            name: f[0].to_string(),
            profile: f[1].to_string(),
            features: f[2].to_string(),
            budget: f[3].parse().unwrap_or_else(|_| panic!("line {}: budget is not a number", i + 1)),
            measured: f[4].parse().unwrap_or_else(|_| panic!("line {}: measured is not a number", i + 1)),
            command: f[5].to_string(),
        });
    }
    assert!(!out.is_empty(), "tools/size-budget.tsv lists no builds");
    out
}

fn features(manifest: &str) -> BTreeMap<String, Vec<String>> {
    let doc: toml::Value = toml::from_str(manifest).expect("manifest parses");
    doc.get("features")
        .and_then(|v| v.as_table())
        .map(|t| {
            t.iter()
                .map(|(k, v)| {
                    let list = v
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                        .unwrap_or_default();
                    (k.clone(), list)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `default` must still mean "everything": the channel platforms and the extra model
/// adapters. This is the invariant a slim build is allowed to break and the default
/// build is not.
#[test]
fn default_build_is_complete() {
    let seagent = features(SEAGENT_MANIFEST);
    let default = seagent.get("default").expect("seagent has [features] default");
    for want in ["channel", "providers"] {
        assert!(
            default.iter().any(|f| f == want),
            "seagent's `default` feature must include `{want}` (a default build is the complete one; \
             slim is opt-in with --no-default-features). default = {default:?}"
        );
    }
    let providers = seagent.get("providers").expect("seagent has a `providers` feature");
    assert!(
        providers.iter().any(|f| f == "seagent-model/full"),
        "seagent's `providers` must enable seagent-model/full, else the binary builds without Bedrock etc."
    );
    // The chain seagent → seagent-app → seagent-kernel → seagent-model must let `providers` travel down.
    for (name, manifest) in [("seagent-kernel", KERNEL_MANIFEST), ("seagent-model", MODEL_MANIFEST)] {
        let f = features(manifest);
        assert!(!f.is_empty(), "{name} has no [features] section");
    }
    let model = features(MODEL_MANIFEST);
    let full = model.get("full").expect("seagent-model has `full`");
    let default_model = model.get("default").expect("seagent-model has `default`");
    assert!(default_model.iter().any(|f| f == "full"), "seagent-model's `default` must include `full`");
    for want in ["bedrock", "gemini", "agent-cli", "agents-api", "local"] {
        assert!(full.iter().any(|f| f == want), "seagent-model's `full` must include `{want}`");
    }
}

/// Every build in the budget table names a real profile and real features, and the
/// budgets shrink in the documented order (more things compiled ⇒ bigger budget).
#[test]
fn budget_table_names_real_builds() {
    let seagent = features(SEAGENT_MANIFEST);
    let builds = builds();
    let mut seen = std::collections::BTreeSet::new();
    for b in &builds {
        assert!(seen.insert(b.name.clone()), "duplicate build name `{}`", b.name);
        assert!(
            matches!(b.profile.as_str(), "release" | "slim"),
            "`{}`: unknown profile `{}` (only `release` and `slim` exist)",
            b.name,
            b.profile
        );
        match b.features.as_str() {
            "default" | "none" => {}
            list => {
                for f in list.split(&[',', '+'][..]) {
                    let f = f.trim();
                    if f.is_empty() {
                        continue;
                    }
                    assert!(
                        seagent.contains_key(f),
                        "`{}`: feature `{f}` does not exist in crates/seagent/Cargo.toml",
                        b.name
                    );
                }
            }
        }
        assert!(b.budget > 0, "`{}`: budget must be set", b.name);
        assert!(
            b.measured > 0 && b.measured <= b.budget,
            "`{}`: measured {} must be recorded and within budget {}",
            b.name,
            b.measured,
            b.budget
        );
        assert!(
            b.command.starts_with("cargo build -p seagent"),
            "`{}`: command must be a `cargo build -p seagent` line",
            b.name
        );
    }
    // Documented order: default ≥ slim-features ≥ slim.
    let by = |n: &str| builds.iter().find(|b| b.name == n).map(|b| b.budget);
    if let (Some(d), Some(f), Some(s)) = (by("default"), by("slim-features"), by("slim")) {
        assert!(d >= f && f >= s, "budgets must shrink: default {d} ≥ slim-features {f} ≥ slim {s}");
    }
}

/// `docs/BUILD.md` is the user-facing half: every build and every number in the table
/// has to appear there, so “documented slim build” cannot mean “documented elsewhere”.
#[test]
fn docs_describe_every_build_and_number() {
    // Docs use thin/plain spaces in large numbers (`33 694 024`), the table uses raw
    // integers; compare with whitespace removed so both spellings agree.
    let doc: String = DOC.chars().filter(|c| !c.is_whitespace()).collect();
    for b in builds() {
        assert!(doc.contains(&b.name), "docs/BUILD.md must describe the `{}` build", b.name);
        assert!(
            doc.contains(&b.measured.to_string()),
            "docs/BUILD.md must state the measured size of `{}` ({} bytes)",
            b.name,
            b.measured
        );
        assert!(
            doc.contains(&b.budget.to_string()),
            "docs/BUILD.md must state the budget of `{}` ({} bytes)",
            b.name,
            b.budget
        );
    }
    assert!(
        doc.contains("tools/size-budget.sh"),
        "docs/BUILD.md must tell the reader how to run the budget check"
    );
    assert!(
        doc.contains("`providers`") && doc.contains("`agent-cli`"),
        "docs/BUILD.md must document the seagent-model features"
    );
}
