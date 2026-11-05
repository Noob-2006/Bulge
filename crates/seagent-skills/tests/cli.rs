//! `seagent curator …` / `seagent bundles …` reach the same code the slash commands use.
//!
//! `crates/seagent/src/main.rs` routes these words through `wire::owns` into
//! `seagent_skills::host::cli`, which is exercised here directly (the `seagent` bin itself is built from
//! other departments' files too, so this keeps the skills CLI contract testable in-crate).

use seagent_kernel::config::{Config, Paths};
use seagent_skills::core::settings::Store;

fn setup(tag: &str) -> (Paths, std::path::PathBuf, Config) {
    let d = seagent_core::tmp::scratch_path(format!("seagent-sklcli-{tag}-{}", seagent_kernel::util::random_hex(6)));
    let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run"), ..Default::default() };
    let ws = d.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let st = Store::new(&paths);
    std::fs::create_dir_all(st.skills.join("mine")).unwrap();
    std::fs::write(st.skills.join("mine/SKILL.md"), "---\nname: mine\ndescription: m\n---\nbody").unwrap();
    (paths, ws, Config::default())
}

#[test]
fn host_cli_routes_curator_bundles_and_blueprints() {
    let (paths, ws, cfg) = setup("cli");
    let st = Store::new(&paths);
    let a = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    // `seagent curator …`
    assert_eq!(seagent_skills::host::cli("curator", &a(&["status"]), &cfg, &paths, &ws).unwrap(), 0);
    assert!(seagent_skills::host::cli("curator", &a(&["adopt", "mine"]), &cfg, &paths, &ws).is_ok());
    assert!(seagent_skills::host::cli("curator", &a(&["archive", "mine"]), &cfg, &paths, &ws).is_ok());
    assert!(st.archive().join("mine/SKILL.md").is_file());
    assert!(seagent_skills::host::cli("curator", &a(&["restore", "mine"]), &cfg, &paths, &ws).is_ok());
    assert!(seagent_skills::host::cli("curator", &a(&["bogus"]), &cfg, &paths, &ws).is_err(), "unknown subcommand is an error");
    // `seagent bundles …`
    assert!(seagent_skills::host::cli("bundles", &a(&["create", "ship", "-s", "mine"]), &cfg, &paths, &ws).is_ok());
    assert!(seagent_skills::host::cli("bundle", &a(&["show", "ship"]), &cfg, &paths, &ws).is_ok(), "`bundle` is an alias");
    assert!(seagent_skills::host::cli("bundles", &a(&["list"]), &cfg, &paths, &ws).is_ok());
    // `seagent skills blueprint …` (the hub CLI dispatches it into core::blueprints).
    assert!(seagent_skills::host::cli("skills", &a(&["blueprint", "list"]), &cfg, &paths, &ws).is_ok());
    assert!(seagent_skills::host::cli("skills", &a(&["blueprint", "show", "morning-brief"]), &cfg, &paths, &ws).is_ok());
    assert!(seagent_skills::host::cli("skills", &a(&["blueprint", "show", "nope"]), &cfg, &paths, &ws).is_err());
    // `seagent skills pending|approve|reject` — the approval queue the `skill` tool stages.
    assert!(seagent_skills::host::cli("skills", &a(&["pending"]), &cfg, &paths, &ws).is_ok());
    assert!(seagent_skills::host::cli("skills", &a(&["approve", "nope"]), &cfg, &paths, &ws).is_err(), "unknown id is an error, not a panic");
    let _ = std::fs::remove_dir_all(paths.data.parent().unwrap());
}
