//! Test hygiene lint (audit row D5).
//!
//! Two habits made this workspace's `/tmp` unusable — ~29,700 leftover entries, 2.5 GB, from test
//! runs: scratch directories that nobody removed (`env::temp_dir().join(..)` + `create_dir_all`),
//! and tests that reached outside their sandbox (the real `$HOME`, or signalling processes they
//! did not start). Both are invisible at review time and only show up weeks later as a full `/tmp`.
//!
//! So they are checked mechanically, over the whole tree, on every `cargo test -p ark`:
//!
//! * (a) a file may not call `env::temp_dir()` unless it also mentions `TempDir::new` (i.e. it has
//!   the self-removing guard from `ark_core::tmp`) or is grandfathered in
//!   `crates/ark/tests/test_hygiene_allow.txt`;
//! * (b) test code may not run `kill`/`pkill`/`killall`, and may not read the real `$HOME`;
//! * (c) every allowlist line must still name an existing file that still needs fixing — the list
//!   can only shrink, and a line left behind after a fix is a failure;
//! * (d) the failure text says how to fix it, and the allowlist header must document the temp-dir
//!   name prefixes the suite uses (the same list `ark system temp-clean` scans for);
//! * (e) a test that spawns the real binary may not leave it online by default: the fresh
//!   `ARK_HOME` every test uses would download the ~6 MB models.dev price file (see
//!   `crates/ark/src/models_cli.rs::auto_refresh_prices`), so such a file has to pin
//!   `ARK_OFFLINE` — `"1"`, or an explicit `"0"` for the rare test that wants the network.
//!
//! The test reads files only: it creates nothing, spawns nothing, and finishes in milliseconds.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// `env::temp_dir()` — direct call, no guard, no cleanup.
const TEMP_DIR_CALL: &str = "env::temp_dir()";
/// Fixed by migrating to the guard: any of these in the same file means the file has adopted it.
const GUARD_MARKERS: &[&str] = &["TempDir::new", "TempDir::new_in"];

/// Escape hatches that make a test escape its sandbox.
const SANDBOX_ESCAPES: &[&str] = &[
    "Command::new(\"kill\")",
    "Command::new(\"/bin/kill\")",
    "Command::new(\"/usr/bin/kill\")",
    "Command::new(\"pkill\")",
    "Command::new(\"killall\")",
    "std::process::Command::new(\"kill\")",
    "env::var(\"HOME\")",
    "env::var_os(\"HOME\")",
];

/// Markers that a file runs the real `ark` binary (the fresh `ARK_HOME` it gets would
/// otherwise reach models.dev on the first model call).
const SPAWNS_BINARY: &str = "CARGO_BIN_EXE_ark";
/// What such a file has to pin: `"1"` (offline) or an explicit `"0"` (this test wants the
/// network, visible in review).
const OFFLINE_PIN: &str = "ARK_OFFLINE";

/// Temp-dir name prefixes the suite uses; `ark system temp-clean` (`crates/ark/src/system_cli.rs`,
/// `TEST_TEMP_PREFIXES`) scans for exactly these families, so the allowlist header documents them
/// and a new family must be added in both places.
const DOCUMENTED_PREFIXES: &[&str] = &[
    ".ark-sync-",
    "ark-agent-",
    "ark-auto-",
    "ark-ch-",
    "ark-cfg-",
    "ark-ckpt-",
    "ark-core-tmp-",
    "ark-k-",
    "ark-kernel-",
    "ark-media-",
    "ark-mem-",
    "ark-plugin-",
    "ark-run-",
    "ark-store-",
    "ark-tmp-",
    "ark-vault-",
    "ark-wire-",
];

fn workspace_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `<workspace>/crates/ark`.
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).expect("workspace root").to_path_buf()
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `.rs` file the lint covers: `crates/*/src/**` and `crates/*/tests/**`.
fn linted_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root.join("crates")) else { return out };
    for entry in rd.flatten() {
        let crate_dir = entry.path();
        if !crate_dir.is_dir() {
            continue;
        }
        rs_files(&crate_dir.join("src"), &mut out);
        rs_files(&crate_dir.join("tests"), &mut out);
    }
    out.sort();
    out
}

/// The part of a file that counts as "test code": the whole file for `crates/*/tests/**`, and from
/// `#[cfg(test)]` on for a source file. Keeps production `expand_home` (which legitimately reads
/// `$HOME`) out of scope while catching tests that do the same.
fn test_region<'a>(rel: &str, text: &'a str) -> &'a str {
    if rel.contains("/tests/") {
        return text;
    }
    match text.find("#[cfg(test)]") {
        Some(i) => &text[i..],
        None => "",
    }
}

/// Parsed allowlist: entries plus the header text (everything before the first entry).
struct Allow {
    entries: BTreeSet<String>,
    header: String,
}

fn load_allowlist(path: &Path) -> Allow {
    let text = std::fs::read_to_string(path).expect("read test_hygiene_allow.txt");
    let mut entries = BTreeSet::new();
    let mut header = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            if entries.is_empty() {
                header.push_str(line);
                header.push('\n');
            }
            continue;
        }
        // `path  # reason`
        let entry = trimmed.split('#').next().unwrap_or("").trim();
        if !entry.is_empty() {
            entries.insert(entry.to_string());
        }
    }
    Allow { entries, header }
}

#[test]
fn test_code_uses_self_cleaning_temp_dirs_and_stays_in_its_sandbox() {
    let root = workspace_root();
    let allow_path = root.join("crates/ark/tests/test_hygiene_allow.txt");
    let allow = load_allowlist(&allow_path);
    let files = linted_files(&root);
    assert!(files.len() > 100, "the lint found only {} source files under {} — wrong root?", files.len(), root.display());

    let fix = "fix: use `ark_core::tmp::TempDir::new(\"ark-<area>\")` (or `new_in(base, prefix)`) and keep \
               the guard alive for the test — it removes the whole tree on drop, also on panic.\n  \
               if the file genuinely cannot (it hands a plain `PathBuf` to a long-lived struct, or \
               signals a process it started), add ONE line `path  # reason` to \
               crates/ark/tests/test_hygiene_allow.txt; that list may only shrink.";
    let mut problems: Vec<String> = Vec::new();

    for path in &files {
        let rel = path.strip_prefix(&root).unwrap_or(path).to_string_lossy().replace('\\', "/");
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        let allowed = allow.entries.contains(&rel);
        let region = test_region(&rel, &text);

        // (a) `env::temp_dir()` without the guard.
        if text.contains(TEMP_DIR_CALL) && !allowed && !GUARD_MARKERS.iter().any(|m| text.contains(m)) {
            problems.push(format!(
                "{rel}: calls `env::temp_dir()` directly, so whatever it creates is left behind in $TMPDIR.\n  {fix}"
            ));
        }

        // (b) sandbox escapes in test code.
        if !allowed {
            if let Some(pat) = SANDBOX_ESCAPES.iter().find(|p| region.contains(**p)) {
                problems.push(format!(
                    "{rel}: test code uses `{pat}`.\n  \
                     fix: never signal a process the test did not start, and never read the real \
                     $HOME — point `ARK_HOME`/`TMPDIR`/`HOME` at a `TempDir` for the child process \
                     instead (see crates/ark/tests/status_cli.rs for the pattern)."
                ));
            }
        }

        // (e) a test that spawns the real binary must pin it offline. `this` file names the
        // marker on purpose, so it is the one exception.
        if rel != "crates/ark/tests/test_hygiene.rs" && text.contains(SPAWNS_BINARY) && !text.contains(OFFLINE_PIN) {
            problems.push(format!(
                "{rel}: spawns the real `ark` binary without pinning {OFFLINE_PIN}.\n  \
                 fix: add `.env(\"ARK_OFFLINE\", \"1\")` next to `.env(\"ARK_HOME\", …)`. A fresh ARK_HOME \
                 otherwise downloads the ~6 MB models.dev price file on the first model call \
                 (crates/ark/src/models_cli.rs::auto_refresh_prices), which makes the suite network-bound \
                 and flaky. A test that really needs the network must say so: `.env(\"ARK_OFFLINE\", \"0\")`."
            ));
        }
    }

    // (c) the allowlist may only shrink and may not rot.
    for entry in &allow.entries {
        let path = root.join(entry);
        if !path.is_file() {
            problems.push(format!(
                "{entry}: allowlisted but the file no longer exists — delete that line from crates/ark/tests/test_hygiene_allow.txt."
            ));
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let region = test_region(entry, &text);
        let needs_temp = text.contains(TEMP_DIR_CALL) && !GUARD_MARKERS.iter().any(|m| text.contains(m));
        let needs_sandbox = SANDBOX_ESCAPES.iter().any(|p| region.contains(p));
        if !needs_temp && !needs_sandbox {
            problems.push(format!(
                "{entry}: allowlisted but it no longer needs to be (it uses the guard / stays in its sandbox).\n  \
                 fix: delete that line — the grandfather list may only shrink."
            ));
        }
    }

    // The allowlist must stay sorted so it reads as a ledger, not a pile.
    let mut seen_unsorted = false;
    let mut prev: Option<String> = None;
    for entry in &allow.entries {
        if let Some(p) = &prev {
            if entry < p {
                seen_unsorted = true;
            }
        }
        prev = Some(entry.clone());
    }
    assert!(!seen_unsorted, "crates/ark/tests/test_hygiene_allow.txt is not sorted");

    // The header must document the prefixes the suite (and `ark system temp-clean`) uses.
    for prefix in DOCUMENTED_PREFIXES {
        if !allow.header.contains(&format!("`{prefix}`")) {
            problems.push(format!(
                "crates/ark/tests/test_hygiene_allow.txt: header does not document the temp-dir prefix `{prefix}`.\n  \
                 fix: keep the prefix list in the header in sync with `TEST_TEMP_PREFIXES` in crates/ark/src/system_cli.rs \
                 and with the name the new test passes to `TempDir::new`."
            ));
        }
    }

    if !problems.is_empty() {
        panic!(
            "test hygiene: {} problem(s)\n\n{}\n",
            problems.len(),
            problems.join("\n\n")
        );
    }
}
