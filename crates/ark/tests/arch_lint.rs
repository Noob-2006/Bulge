//! Architecture lint (audit D2 / D3 / D7). Four rules, each one a thing that silently rotted
//! in earlier rounds; all four are cheap to check and cheap to satisfy:
//!
//! 1. **Dependency direction** — every internal dependency of a workspace crate must be in the
//!    layer table below, and must point at a strictly lower layer. That makes cycles impossible
//!    and forces a new edge to be a deliberate decision (add the crate + its allowed deps here
//!    *and* in `docs/ARCHITECTURE.md`, with a reason).
//! 2. **Size** — no file may exceed 3,000 lines. Files over the ceiling must be listed in
//!    `arch_baseline.txt` with the split they are waiting for; an entry without an oversized
//!    file behind it fails, so the list can only shrink.
//! 3. **Anti-fragmentation** — a module directory (one responsibility) may hold at most 5 files
//!    unless they are substantial (average ≥ 150 lines). "One function per file" is the Hermes
//!    failure mode this rule exists to prevent: 70 tiny `hermes_state_*` files are harder to
//!    read than one 900-line module.
//! 4. **Style** — no `todo!`/`unimplemented!`/`dbg!` outside test code, a `//!` purpose header on
//!    every non-test file over 100 lines, and library crates (`crates/ark-*`) print warnings to
//!    stderr only: stdout belongs to the binary. Existing `println!` use is grandfathered per
//!    file in the baseline (counts may only shrink).
//!
//! Run: `cargo test -p ark --test arch_lint`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// `(layer, crate, deps it may have)`. A crate may only depend on a *strictly lower* layer.
/// Leaves (0/1) have no internal dependencies at all: `ark-core` is the interface layer,
/// `ark-net` the transport primitives, `ark-security` the policy helpers.
const LAYERS: &[(u8, &str, &[&str])] = &[
    (0, "ark-core", &[]),
    (0, "ark-net", &[]),
    (1, "ark-security", &[]),
    // microVM execution: provider detection, guest channel, snapshots. Deliberately does not
    // link ark-tools (the `ExecBackend` glue is there) or the kernel, so the guest agent stays
    // tiny and the crate cannot grow into the rest of the runtime.
    (1, "ark-vm", &["ark-net"]),
    (2, "ark-model", &["ark-core", "ark-net", "ark-security"]),
    // `ark-vm` is the microVM transport (the `ExecBackend` glue lives in ark-tools).
    (2, "ark-tools", &["ark-core", "ark-net", "ark-security", "ark-vm"]),
    (2, "ark-browser", &["ark-core", "ark-net", "ark-security"]),
    // A channel needs attachment understanding (images/audio/PDF) from ark-media. The edge is
    // one-way: ark-media never names a channel.
    // A14: the channel fetchers classify addresses with `ark_security::url_safety` (the one
    // SSRF table), so a channel depends on the policy helpers — never the other way round.
    (3, "ark-channel", &["ark-core", "ark-media", "ark-net", "ark-security"]),
    (2, "ark-media", &["ark-core", "ark-net", "ark-security"]),
    (3, "ark-kernel", &["ark-core", "ark-model", "ark-security"]),
    (4, "ark-plugin", &["ark-core", "ark-kernel", "ark-net", "ark-security"]),
    (5, "ark-skills", &["ark-core", "ark-kernel", "ark-plugin", "ark-security", "ark-tools"]),
    // H8: recalled memories are re-scanned with `ark_security::threat` at read time, so memory
    // depends on the policy helpers (a downward edge; security never names memory).
    (5, "ark-memory", &["ark-core", "ark-kernel", "ark-security", "ark-tools"]),
    (6, "ark-app", &["ark-browser", "ark-channel", "ark-core", "ark-kernel", "ark-net", "ark-plugin", "ark-security", "ark-tools"]),
    (7, "ark", &["ark-app", "ark-vm", "ark-browser", "ark-channel", "ark-core", "ark-kernel", "ark-media", "ark-memory", "ark-model", "ark-net", "ark-plugin", "ark-security", "ark-skills", "ark-tools"]),
];

const MAX_FILE_LINES: usize = 3000;
const MAX_FILES_PER_RESPONSIBILITY: usize = 5;
const MIN_AVERAGE_FILE_LINES: usize = 150;
const MODULE_DOC_AFTER_LINES: usize = 100;

fn root() -> PathBuf {
    // crates/ark → workspace root
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn line_count(p: &Path) -> usize {
    read(p).lines().count()
}

/// Workspace members, as paths relative to the root (`crates/ark-core`).
fn members() -> Vec<String> {
    let toml = read(&root().join("Cargo.toml"));
    let start = toml.find("members = [").expect("workspace.members in the root Cargo.toml");
    let rest = &toml[start + "members = [".len()..];
    let end = rest.find(']').expect("closing ] of workspace.members");
    rest[..end].split(',').map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect()
}

/// `[dependencies]` of one crate, as (internal crate name, whole spec line).
fn dependencies(crate_dir: &Path) -> Vec<String> {
    let toml = read(&crate_dir.join("Cargo.toml"));
    let mut out = Vec::new();
    let mut section = String::new();
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.trim_matches(|c| c == '[' || c == ']').to_string();
            continue;
        }
        if section != "dependencies" || t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(key) = t.split(['=', '.', ' ']).next() {
            if key.starts_with("ark-") {
                out.push(key.to_string());
            }
        }
    }
    out
}

/// `.rs` files under `dir`, recursive.
fn rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(rs_files(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

fn rel(p: &Path) -> String {
    p.strip_prefix(root()).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

#[derive(Default)]
struct Baseline {
    oversized: BTreeMap<String, String>,
    println: BTreeMap<String, usize>,
}

fn baseline() -> Baseline {
    let mut b = Baseline::default();
    let path = root().join("crates/ark/tests/arch_baseline.txt");
    for line in read(&path).lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (kind, rest) = t.split_once(' ').unwrap_or((t, ""));
        match kind {
            // `size <path> <note>`: the file is over the ceiling and the note names its split.
            "size" => {
                let (p, note) = rest.split_once(' ').unwrap_or((rest, ""));
                b.oversized.insert(p.trim().to_string(), note.trim().to_string());
            }
            // `println <path> <count>`: grandfathered stdout use, may only shrink.
            "println" => {
                let (p, n) = rest.rsplit_once(' ').unwrap_or((rest, "0"));
                b.println.insert(p.trim().to_string(), n.trim().parse().unwrap_or(0));
            }
            other => panic!("arch_baseline.txt: unknown entry kind `{other}`"),
        }
    }
    b
}

/// Rule 1: the dependency graph of the workspace is the layer table, and points downwards.
#[test]
fn dependency_direction_is_a_layer_dag() {
    let table: BTreeMap<&str, (u8, &[&str])> = LAYERS.iter().map(|(l, c, d)| (*c, (*l, *d))).collect();
    let members = members();
    let mut problems = Vec::new();
    for m in &members {
        let name = m.rsplit('/').next().unwrap_or(m);
        let Some((layer, allowed)) = table.get(name) else {
            problems.push(format!("`{name}` is a workspace member but not in the layer table of crates/ark/tests/arch_lint.rs — add it at the right layer and document the edge in docs/ARCHITECTURE.md"));
            continue;
        };
        for dep in dependencies(&root().join(m)) {
            let Some((dep_layer, _)) = table.get(dep.as_str()) else {
                problems.push(format!("`{name}` depends on `{dep}`, which is not a workspace crate in the layer table"));
                continue;
            };
            if !allowed.contains(&dep.as_str()) {
                problems.push(format!("`{name}` (layer {layer}) depends on `{dep}`: not allowed (allowed: {allowed:?}). Cross-crate calls go through a trait/event in ark-core, or the smaller crate owns the helper"));
            } else if dep_layer >= layer {
                problems.push(format!("`{name}` (layer {layer}) depends on `{dep}` (layer {dep_layer}): dependencies must point at a strictly lower layer (a cycle or a sideways edge)"));
            }
        }
    }
    // A crate in the table that is no longer a member means the table rotted.
    let present: BTreeSet<&str> = members.iter().map(|m| m.rsplit('/').next().unwrap_or(m)).collect();
    for (_, name, _) in LAYERS {
        assert!(present.contains(name), "`{name}` is in the layer table but not a workspace member — drop it");
    }
    // The interface layer stays dependency-free: everything may depend on it, it depends on nobody.
    assert!(dependencies(&root().join("crates/ark-core")).is_empty(), "ark-core must stay the dependency-free interface layer");
    assert!(problems.is_empty(), "dependency direction:\n  {}", problems.join("\n  "));
}

/// Rule 2: 3,000 lines is the ceiling; bigger files need a recorded split plan.
#[test]
fn no_file_grows_past_the_line_ceiling() {
    let b = baseline();
    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    for m in members() {
        for f in rs_files(&root().join(&m).join("src")).into_iter().chain(rs_files(&root().join(&m).join("tests"))) {
            let n = line_count(&f);
            let r = rel(&f);
            if n > MAX_FILE_LINES {
                seen.insert(r.clone());
                if !b.oversized.contains_key(&r) {
                    problems.push(format!("{r}: {n} lines > {MAX_FILE_LINES}. Split it by responsibility (a subdirectory module) instead of growing the file"));
                }
            }
        }
    }
    for (f, note) in &b.oversized {
        if !seen.contains(f) {
            problems.push(format!("arch_baseline.txt lists `{f}` as oversized, but it is not (anymore) — remove the line{}", if note.is_empty() { String::new() } else { format!(" (`{note}`)") }));
        }
    }
    assert!(problems.is_empty(), "file size:\n  {}", problems.join("\n  "));
}

/// Rule 3: one responsibility, a handful of files. A module directory with many tiny files is
/// the fragmentation the plan forbids.
#[test]
fn no_responsibility_is_split_into_tiny_files() {
    let mut problems = Vec::new();
    for m in members() {
        let src = root().join(&m).join("src");
        let mut dirs: Vec<PathBuf> = Vec::new();
        let mut stack = vec![src.clone()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    if p.file_name().is_some_and(|n| n == "tests") {
                        continue;
                    }
                    dirs.push(p.clone());
                    stack.push(p);
                }
            }
        }
        for d in dirs {
            let files = rs_files(&d);
            // Only direct children count as "the files of this responsibility".
            let direct: Vec<PathBuf> = std::fs::read_dir(&d).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "rs")).collect()).unwrap_or_default();
            if direct.len() <= MAX_FILES_PER_RESPONSIBILITY {
                continue;
            }
            let total: usize = files.iter().map(|f| line_count(f)).sum();
            let avg = total / files.len();
            if avg < MIN_AVERAGE_FILE_LINES {
                problems.push(format!("{}: {} files averaging {avg} lines (< {MIN_AVERAGE_FILE_LINES}). Merge them into one module per responsibility", rel(&d), direct.len()));
            }
        }
    }
    assert!(problems.is_empty(), "anti-fragmentation:\n  {}", problems.join("\n  "));
}

/// Rule 4: purpose headers, no placeholder macros in shipped code, and library crates keep
/// stdout for the binary.
#[test]
fn style_is_consistent_across_crates() {
    let b = baseline();
    let mut problems = Vec::new();
    for m in members() {
        for f in rs_files(&root().join(&m).join("src")) {
            let r = rel(&f);
            let text = read(&f);
            let is_test_file = r.contains("/tests") || r.ends_with("tests.rs") || r.ends_with("testutil.rs");
            // (a) module doc
            if !is_test_file && text.lines().count() > MODULE_DOC_AFTER_LINES && !text.lines().take(5).any(|l| l.starts_with("//!")) {
                problems.push(format!("{r}: {} lines without a `//!` purpose header (say what the module is and which upstream it ports)", text.lines().count()));
            }
            // (b) placeholders, outside `#[cfg(test)]` code (which starts at a `#[cfg(test)]` line
            // at the beginning of a line, the house style: one test module at the end).
            let mut in_tests = false;
            for (i, l) in text.lines().enumerate() {
                if l.starts_with("#[cfg(test)]") {
                    in_tests = true;
                }
                if in_tests {
                    continue;
                }
                for mac in ["todo!(", "unimplemented!(", "dbg!("] {
                    if l.contains(mac) && !l.trim_start().starts_with("//") {
                        problems.push(format!("{r}:{}: `{mac}` in shipped code — return an error or finish the feature", i + 1));
                    }
                }
            }
            // (c) library stdout: warnings go to stderr with an `ark:` prefix.
            if m != "crates/ark" {
                // `eprintln!(` is the recommended form, so it must not count as stdout.
                let n = text.match_indices("println!(").filter(|(i, _)| !text[..*i].ends_with('e')).count();
                let allowed = b.println.get(&r).copied().unwrap_or(0);
                if n > allowed {
                    problems.push(format!("{r}: {n} `println!` in a library crate (allowed {allowed}); use `eprintln!(\"ark: …\")` for warnings and return data to the caller"));
                }
            }
        }
    }
    for f in b.println.keys() {
        if !root().join(f).exists() {
            problems.push(format!("arch_baseline.txt lists `{f}` for `println!` but the file is gone — remove the line"));
        }
    }
    assert!(problems.is_empty(), "style:\n  {}", problems.join("\n  "));
}
