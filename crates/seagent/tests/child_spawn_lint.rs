//! Child-process spawn lint: no console window flashes on Windows.
//!
//! The desktop app runs the daemon with no console (`seagent daemon start` detaches it with
//! `DETACHED_PROCESS`). A console program it starts — PowerShell for the exec tool, `git`,
//! `where`, `tasklist`, Python, an MCP stdio server — gets a brand-new console window unless
//! it is created with `CREATE_NO_WINDOW`, so every chat turn flashed boxes open and shut. The
//! fix is one helper, `seagent_core::platform::proc::command` (and its layer-1 copies in
//! seagent-security / seagent-vm, which cannot depend on seagent-core), applying the flag
//! whenever this process has no console. This test fails the build when product code makes a
//! `std::process::Command` any other way, or replaces the creation flags with ones that drop
//! `CREATE_NO_WINDOW`.
//!
//! Test code (`tests/`, `tests*.rs`, `testutil.rs`, `#[cfg(test)] mod …` blocks) is exempt:
//! it never runs inside the user's daemon. The test reads files only.
//! Run: `cargo test -p seagent --test child_spawn_lint`.

use std::path::{Path, PathBuf};

/// The helpers themselves, and the files that may spawn directly, each with the reason.
const ALLOWED: &[(&str, &str)] = &[
    ("crates/seagent-core/src/platform/proc.rs", "the helper (`command`, `visible_command`)"),
    ("crates/seagent-security/src/os.rs", "layer-1 copy of the helper (no seagent-core dependency)"),
    ("crates/seagent-vm/src/host.rs", "layer-1 copy of the helper (no seagent-core dependency)"),
    ("crates/seagent-browser/src/launch.rs", "browsers / lightpanda go through `proc::spawn_tied`, whose `new_group_with` ORs in `console_flags()`"),
    ("apps/desktop/src-tauri/src/agent.rs", "the desktop shell's sidecar runner sets CREATE_NO_WINDOW itself"),
    ("apps/desktop/src-tauri/src/lib.rs", "Linux-only (`fc-list` for the AppImage fonts)"),
    ("apps/desktop/src-tauri/src/desktop.rs", "Linux-only (`fc-list`)"),
    ("apps/desktop/devkey/src/linux.rs", "Linux-only (`tpm2` tools)"),
];

/// Ways to make a child process without the helper.
const FORBIDDEN: &[&str] = &["Command::new(", "tokio::process::Command"];

/// A `creation_flags(..)` call replaces the helper's flags; it must keep the no-window flag.
const FLAGS_CALL: &str = ".creation_flags(";
/// Any of these on the same line shows the replacement keeps `CREATE_NO_WINDOW`.
const KEEPS_NO_WINDOW: &[&str] = &["CREATE_NO_WINDOW", "console_flags()", "creation_flags())", "no_window_flag()"];
/// `creation_flags` calls whose argument is a local holding `CREATE_NO_WINDOW` (reviewed).
const FLAGS_ALLOWED: &[(&str, &str)] = &[("crates/seagent/src/ops/hostos.rs", "`spawn_detached`: `base` = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW")];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target" || n == ".git" || n == "node_modules" || n == "tests") {
                continue;
            }
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn is_test_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name == "tests.rs" || name.starts_with("tests_") || name == "testutil.rs" || name.ends_with("_tests.rs")
}

/// The product-code lines of `text` with their 1-based numbers: comments stripped, every
/// `#[cfg(test)]` item (a `mod tests { … }` block or a single test helper) left out.
fn product_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = vec![];
    let mut cfg_test = false;
    let mut skip_depth: Option<i64> = None;
    let mut depth: i64 = 0;
    for (i, line) in text.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("").to_string();
        let opens = code.matches('{').count() as i64;
        let closes = code.matches('}').count() as i64;
        let trimmed = code.trim();
        if let Some(d) = skip_depth {
            depth += opens - closes;
            if depth <= d {
                skip_depth = None;
            }
            continue;
        }
        if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test") {
            cfg_test = true;
            continue;
        }
        if cfg_test && !trimmed.is_empty() && !trimmed.starts_with("#[") {
            cfg_test = false;
            if opens > closes {
                skip_depth = Some(depth);
                depth += opens - closes;
            }
            continue;
        }
        depth += opens - closes;
        out.push((i + 1, code));
    }
    out
}

/// Offending `file:line: what` entries under `crates/` and `apps/`.
fn offenders(root: &Path) -> Vec<String> {
    let mut files = vec![];
    walk(&root.join("crates"), &mut files);
    walk(&root.join("apps"), &mut files);
    let mut bad = vec![];
    for f in files {
        let rel = f.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        if is_test_file(&rel) {
            continue;
        }
        let allowed = ALLOWED.iter().any(|(p, _)| *p == rel);
        let flags_allowed = FLAGS_ALLOWED.iter().any(|(p, _)| *p == rel);
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        for (n, code) in product_lines(&text) {
            if !allowed {
                for pat in FORBIDDEN {
                    if code.contains(pat) {
                        bad.push(format!("{rel}:{n}: `{pat}`"));
                    }
                }
            }
            if !allowed && !flags_allowed && code.contains(FLAGS_CALL) && !KEEPS_NO_WINDOW.iter().any(|k| code.contains(k)) {
                bad.push(format!("{rel}:{n}: `creation_flags` without CREATE_NO_WINDOW / console_flags()"));
            }
        }
    }
    bad
}

#[test]
fn every_child_process_goes_through_the_no_window_helper() {
    let bad = offenders(&root());
    assert!(
        bad.is_empty(),
        "child processes made outside `seagent_core::platform::proc::command` — on Windows each would flash a \
         console window from the console-less daemon / desktop app.\nfix: replace `Command::new(p)` with \
         `seagent_core::platform::proc::command(p)` (seagent-security: `crate::os::command`, seagent-vm: \
         `crate::host::command`); a program the user asked to see uses `proc::visible_command`; OR \
         `console_flags()` into any `creation_flags(..)`.\n{}",
        bad.join("\n")
    );
}

#[test]
fn every_allowlisted_file_still_exists() {
    let r = root();
    for (p, why) in ALLOWED.iter().chain(FLAGS_ALLOWED) {
        assert!(r.join(p).is_file(), "{p} ({why}) is gone: drop it from the allowlist");
    }
}

#[test]
fn the_lint_catches_a_bypass() {
    let tmp = seagent_core::tmp::TempDir::new("seagent-tmp-lint");
    let d = tmp.path().join("crates/x/src");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("lib.rs"),
        "fn a() { let _ = std::process::Command::new(\"git\").output(); }\n\
         // Command::new( in a comment is fine\n\
         fn b() { seagent_core::platform::proc::command(\"git\"); }\n\
         fn c(c: &mut Command) { c.creation_flags(0x200); }\n\
         fn d(c: &mut Command) { c.creation_flags(CREATE_NEW_PROCESS_GROUP | console_flags()); }\n\
         #[cfg(test)]\n\
         mod tests {\n    fn t() {\n        let _ = Command::new(\"sleep\");\n    }\n}\n\
         fn e() { tokio::process::Command::new(\"x\"); }\n",
    )
    .unwrap();
    std::fs::write(d.join("tests_real.rs"), "fn t() { let _ = Command::new(\"x\"); }\n").unwrap();
    let bad = offenders(tmp.path());
    assert_eq!(bad.len(), 4, "{bad:?}");
    assert!(bad[0].starts_with("crates/x/src/lib.rs:1:"), "{bad:?}");
    assert!(bad[1].starts_with("crates/x/src/lib.rs:4:"), "{bad:?}");
    assert!(bad.iter().filter(|b| b.starts_with("crates/x/src/lib.rs:12:")).count() == 2, "{bad:?}");
}
