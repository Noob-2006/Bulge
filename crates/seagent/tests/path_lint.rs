//! Hard-coded path lint (docs/paths.md).
//!
//! seagent's own directories (config, data, cache, logs, runtime, share) come from one place:
//! `seagent_core::layout` (and the kernel's `Paths` built on it), which knows the user (XDG), system
//! (FHS, `/etc/seagent` …) and portable (`SEAGENT_HOME`) layouts and their overrides. This test fails the
//! build when non-test code under `crates/` spells such a path itself:
//!
//! 1. **seagent layout** — `/etc/seagent`, `/var/lib/seagent`, `/var/cache/seagent`, `/var/log/seagent`, `/run/seagent`,
//!    `/usr/share/seagent`, `/usr/local/share/seagent`, `/tmp/seagent…`, and the XDG spellings
//!    `.config/seagent`, `.local/share/seagent`, `.cache/seagent` — only in [`LAYOUT_OWNERS`].
//! 2. **every other absolute path literal** (`"/usr/…"`, `"/opt/…"`, `"/var/…"`, …) must either be
//!    an operating-system interface ([`OS_INTERFACE`]: `/proc`, `/sys`, `/dev`, `/etc/os-release`, …)
//!    or be listed, reviewed, in `path_lint_allow.txt` (tool fallbacks after a `$PATH` lookup,
//!    paths inside containers / VMs seagent builds, sensitive-path deny lists). A new one fails until
//!    it is either moved to `Paths` / a PATH lookup / a config key, or added there with a reason.
//!
//! Lines in comments and everything after `#[cfg(test)]` are ignored. Reads files only.
//! Refresh the allowlist after a deliberate change: `SEAGENT_BLESS=1 cargo test -p seagent --test path_lint`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Files that may spell seagent's layout: the layout itself, and code that runs where `seagent_core` is
/// not linked (the microVM guest agent and its protocol, whose image has a fixed layout).
const LAYOUT_OWNERS: &[(&str, &str)] = &[
    ("crates/seagent-core/src/layout.rs", "the one definition of the layout"),
    ("crates/seagent-vm/src/proto.rs", "guest-side socket inside the VM image (fixed image layout)"),
    ("crates/seagent-vm/src/bin/seagent-vm-guest.rs", "guest agent inside the VM image (fixed image layout)"),
    ("crates/seagent-vm/src/image.rs", "seagent-vm stays dependency-free; mirrors layout::system::SHARE"),
    ("crates/seagent-kernel/src/config.rs", "short socket-dir fallback /tmp/seagent-<uid> (sun_path limit)"),
    ("crates/seagent-security/src/threat.rs", "detection patterns for access to seagent's own secrets"),
    ("crates/seagent-security/src/skills_guard.rs", "detection patterns for access to seagent's own config"),
    ("crates/seagent-security/src/plugin_guard.rs", "detection patterns for access to seagent's own secrets"),
    ("crates/seagent-tools/src/exec/sandbox.rs", "defence-in-depth deny list of home subpaths a sandbox never mounts"),
    ("crates/seagent-plugin/src/builtin/disk_cleanup.rs", "describes its cleanup scope (/tmp/seagent-* scratch files)"),
    ("crates/seagent-channel/src/imessage.rs", "a private temp dir on the remote Mac, not on this host"),
    ("crates/seagent/tests/path_lint.rs", "this lint"),
];

const SEAGENT_LAYOUT: &[&str] = &["/etc/seagent", "/var/lib/seagent", "/var/cache/seagent", "/var/log/seagent", "/run/seagent", "/usr/share/seagent", "/usr/local/share/seagent", "/tmp/seagent", ".config/seagent", ".local/share/seagent", ".cache/seagent"];

/// Top-level directories that make a string literal a filesystem path (not a URL route).
const ROOTS: &[&str] = &["etc", "var", "run", "usr", "opt", "tmp", "home", "root", "srv", "proc", "sys", "dev", "bin", "sbin", "lib", "lib32", "lib64", "mnt", "snap", "nix", "boot", "Applications", "Library", "System"];

/// Category (a): kernel / OS interfaces. Fixed by definition; never configurable.
const OS_INTERFACE: &[&str] = &[
    "/proc", "/sys", "/dev", "/etc/os-release", "/etc/hostname", "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers", "/etc/resolv.conf", "/etc/hosts", "/etc/machine-id", "/etc/localtime", "/etc/ssl", "/etc/pki", "/usr/bin/env", "/bin/sh", "/bin/bash", "/usr/share/zoneinfo", "/usr/lib/zoneinfo", "/run/systemd", "/run/user", "/tmp/.X11-unix",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target" || n == ".git" || n == "tests" || n == "benches") {
                continue;
            }
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") && !p.file_name().is_some_and(|n| n == "tests.rs" || n.to_string_lossy().ends_with("_tests.rs")) {
            out.push(p);
        }
    }
}

/// `(file, literal)` for every absolute-path string literal in non-test code, and the seagent-layout
/// spellings found outside [`LAYOUT_OWNERS`].
fn scan(root: &Path) -> (BTreeSet<(String, String)>, Vec<String>) {
    let mut files = vec![];
    walk(&root.join("crates"), &mut files);
    let mut abs = BTreeSet::new();
    let mut layout = vec![];
    for f in files {
        let rel = f.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        let owner = LAYOUT_OWNERS.iter().any(|(o, _)| *o == rel);
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("#[cfg(test)]") {
                break;
            }
            if t.starts_with("//") {
                continue;
            }
            if !owner {
                for pat in SEAGENT_LAYOUT {
                    if line.contains(pat) {
                        layout.push(format!("{rel}:{}: `{pat}`", i + 1));
                    }
                }
            }
            for lit in literals(line) {
                let top = lit.trim_start_matches('/').split('/').next().unwrap_or("");
                if !ROOTS.contains(&top) || lit.contains(char::is_whitespace) {
                    continue;
                }
                if OS_INTERFACE.iter().any(|p| lit == *p || lit.starts_with(&format!("{p}/")) || lit.starts_with(&format!("{p}{{"))) {
                    continue;
                }
                if SEAGENT_LAYOUT.iter().any(|p| lit.starts_with(p)) {
                    continue; // rule 1 covers it
                }
                abs.insert((rel.clone(), lit));
            }
        }
    }
    (abs, layout)
}

/// String-literal contents starting with `/` on one line (good enough for this codebase:
/// paths are short literals; raw strings and escapes do not matter for the first segment).
fn literals(line: &str) -> Vec<String> {
    let mut v = vec![];
    let b = line.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'"' && b[i + 1] == b'/' && (i == 0 || b[i - 1] != b'\\') {
            if let Some(end) = line[i + 1..].find('"') {
                v.push(line[i + 1..i + 1 + end].to_string());
                i += end + 2;
                continue;
            }
        }
        i += 1;
    }
    v
}

fn allow_file() -> PathBuf {
    root().join("crates/seagent/tests/path_lint_allow.txt")
}

fn allowed() -> BTreeSet<(String, String)> {
    std::fs::read_to_string(allow_file())
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t').map(|(f, p)| (f.to_string(), p.split('\t').next().unwrap_or(p).to_string())))
        .collect()
}

#[test]
fn seagent_layout_paths_only_come_from_the_layout() {
    let (_, layout) = scan(&root());
    assert!(
        layout.is_empty(),
        "seagent's own directories spelled outside seagent_core::layout — use `Paths` (data/config_dir/cache_dir()/log_dir()/runtime), \
         `seagent_core::layout::{{detect, data_dir, cache_dir, system::*}}` or `seagent_core::share`:\n{}",
        layout.join("\n")
    );
}

#[test]
fn every_other_absolute_path_is_an_os_interface_or_reviewed() {
    let (found, _) = scan(&root());
    if std::env::var_os("SEAGENT_BLESS").is_some() {
        let mut out = String::from("# Reviewed absolute-path literals in non-test code (crates/seagent/tests/path_lint.rs).\n# file<TAB>literal — tool fallbacks after a $PATH lookup, paths inside containers/VMs seagent builds,\n# sensitive-path deny lists, platform locations. Everything else comes from seagent_core::layout.\n");
        for (f, p) in &found {
            out.push_str(&format!("{f}\t{p}\n"));
        }
        std::fs::write(allow_file(), out).unwrap();
    }
    let allow = allowed();
    let new: Vec<String> = found.difference(&allow).map(|(f, p)| format!("{f}: \"{p}\"")).collect();
    assert!(
        new.is_empty(),
        "new hard-coded absolute paths. Use `Paths` / `seagent_core::layout` for seagent's own files, a $PATH lookup \
         (`seagent_core::layout::which`) or a config key for tools; if it really is fixed (an OS interface, a path inside a \
         container image), add it to crates/seagent/tests/path_lint_allow.txt (SEAGENT_BLESS=1 cargo test -p seagent --test path_lint):\n{}",
        new.join("\n")
    );
}

#[test]
fn the_lint_catches_layout_paths_and_new_absolute_paths() {
    let tmp = seagent_core::tmp::TempDir::new("seagent-path-lint");
    let d = tmp.path().join("crates/x/src");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("lib.rs"),
        "fn a() -> &'static str { \"/var/lib/seagent/sessions\" }\n// \"/etc/seagent/x\" in a comment is fine\nfn b() { let _ = std::fs::read(\"/proc/self/status\"); let _ = \"/opt/vendor/tool\"; let _ = \"/v1/models\"; }\nfn c() -> String { format!(\"{}/.local/share/seagent\", h()) }\n#[cfg(test)]\nmod t { const X: &str = \"/etc/seagent/test\"; }\n",
    )
    .unwrap();
    let (abs, layout) = scan(tmp.path());
    assert_eq!(layout.len(), 2, "{layout:?}");
    assert!(layout[0].starts_with("crates/x/src/lib.rs:1:") && layout[1].starts_with("crates/x/src/lib.rs:4:"));
    assert_eq!(abs.into_iter().map(|(_, p)| p).collect::<Vec<_>>(), vec!["/opt/vendor/tool".to_string()], "OS interfaces and URL routes pass");
}
