//! `ark role` — choose and inspect the professional role (BATCH-next §3, §7-6-4, §7-4-5).
//!
//! ```text
//! ark role list [words] [--layer L0|L1|L2] [--group N] [--all] [--json]
//! ark role use <ISCO code | 中英文職業名 | preset | none> [--agent ID]
//! ark role show [<role>] [--agent ID] [--prompt] [--json]
//! ark role verify [--dir DIR] [--key ed25519:…] [--require-signature]
//! ark role sign --seed-file FILE [--dir DIR]
//! ark role diff <old-dir> [<new-dir>]
//! ```
//!
//! `use` writes `[role] active` (user config) or the agent's `role` (agents.toml); an ISCO
//! code shared by several packs lists them instead of guessing. `verify` runs Skills Guard
//! over every pack and checks the tree against `roles.sig` (an Ed25519 signature over the
//! canonical manifest digest, `ark_security::signing`); `sign` is the release step that writes
//! it (the seed never enters the repo); `diff` shows which rules an update adds or removes.
//! The runtime side (assembly, `/role`, boundaries) is `ark_kernel::roles`.

use ark_kernel::config::{project_config, Config, Paths};
use ark_kernel::roles::{self, Catalog, Found, Layer, Role};
use ark_security::{signing, skills_guard};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "\
ark role <subcommand>
  list [words] [--layer L0|L1|L2] [--group N] [--all] [--json]
                          presets, then occupations by ISCO major group (title_zh)
  use <role> [--agent ID] the default agent's role ([role] active), or a named agent's;
                          <role> = ISCO code (2512), 中文或英文職業名, preset (devops,
                          swdev, secops, data, itsupport) or `none` (L0 core only)
  show [<role>] [--agent ID] [--prompt] [--json]
                          layers, tokens, tool profile, default permissions, reserved acts
  verify [--dir DIR] [--key K] [--require-signature]
                          Skills Guard scan + manifest digest + roles.sig signature
  sign --seed-file FILE [--dir DIR]
                          release step: sign the manifest digest into roles.sig
  diff <old-dir> [<new-dir>]
                          rules added / removed between two role trees";

/// Self-registration: `ark role|roles …` take their own flags.
pub fn register_route() {
    ark_core::registry::register_command_route("role,roles", None, cli);
}

struct Opts {
    pos: Vec<String>,
    vals: BTreeMap<String, String>,
    flags: Vec<String>,
}

const VALUE_FLAGS: &[&str] = &["layer", "group", "agent", "dir", "key", "seed-file"];

fn parse(raw: &[String]) -> Result<Opts, String> {
    let mut o = Opts { pos: vec![], vals: BTreeMap::new(), flags: vec![] };
    let mut it = raw.iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            let (k, v) = name.split_once('=').map(|(k, v)| (k.to_string(), Some(v.to_string()))).unwrap_or((name.to_string(), None));
            if VALUE_FLAGS.contains(&k.as_str()) {
                let v = match v {
                    Some(v) => v,
                    None => it.next().cloned().ok_or_else(|| format!("--{k} needs a value"))?,
                };
                o.vals.insert(k, v);
            } else {
                o.flags.push(k);
            }
        } else {
            o.pos.push(a.clone());
        }
    }
    Ok(o)
}

impl Opts {
    fn flag(&self, f: &str) -> bool {
        self.flags.iter().any(|x| x == f)
    }
    fn val(&self, k: &str) -> Option<&str> {
        self.vals.get(k).map(String::as_str)
    }
    fn rest(&self) -> String {
        self.pos.get(1..).map(|s| s.join(" ")).unwrap_or_default()
    }
}

fn load_cfg(paths: &Paths) -> Config {
    let ws = std::env::current_dir().unwrap_or_else(|_| paths.data.clone());
    Config::load(Some(&paths.user_config()), Some(&project_config(&ws)), &[]).unwrap_or_default()
}

pub fn cli(_cmd: &str, raw: &[String]) -> Result<i32, String> {
    let paths = Paths::from_env();
    let (out, code) = run(&paths, raw)?;
    if !out.trim().is_empty() {
        println!("{}", out.trim_end());
    }
    Ok(code)
}

/// `(output, exit code)`.
pub fn run(paths: &Paths, raw: &[String]) -> Result<(String, i32), String> {
    let o = parse(raw)?;
    let cfg = load_cfg(paths);
    let sub = o.pos.first().map(String::as_str).unwrap_or("show");
    match sub {
        "list" | "ls" | "search" => Ok((list(&cfg, &o)?, 0)),
        "use" | "set" => use_role(paths, &cfg, &o),
        "show" | "status" | "current" => Ok((show(paths, &cfg, &o)?, 0)),
        "verify" => verify(paths, &o),
        "sign" => Ok((sign(&o)?, 0)),
        "diff" => Ok((diff(&o)?, 0)),
        "help" | "--help" | "-h" => Ok((USAGE.into(), 0)),
        other => Err(format!("unknown `role {other}`\n{USAGE}")),
    }
}

// ───────────── list ─────────────

fn list(cfg: &Config, o: &Opts) -> Result<String, String> {
    let cat = Catalog::for_config(cfg);
    let words = o.rest();
    let layer = o.val("layer").map(|l| Layer::parse(l).ok_or_else(|| format!("--layer `{l}`: L0, L1 or L2"))).transpose()?;
    let group = o.val("group").map(str::trim).map(String::from);
    if o.flag("json") {
        let rows: Vec<serde_json::Value> = cat
            .packs
            .values()
            .filter(|p| layer.is_none_or(|l| p.layer == l) && group.as_deref().is_none_or(|g| p.isco.starts_with(g)))
            .map(|p| serde_json::json!({"id": p.slug, "title_zh": p.title_zh, "layer": p.layer.as_str(), "isco": p.isco, "extends": p.extends, "regulated": p.regulated, "description": p.description}))
            .collect();
        let presets: Vec<serde_json::Value> = roles::presets(cfg).iter().map(|p| serde_json::json!({"id": p.id, "title_zh": p.title_zh, "title_en": p.title_en, "packs": p.packs, "tools": p.tools})).collect();
        return Ok(serde_json::to_string_pretty(&serde_json::json!({"presets": presets, "packs": rows})).unwrap_or_default());
    }
    if !words.trim().is_empty() {
        return Ok(match roles::find(cfg, &cat, &words) {
            Found::One(id) => format!("{}\nUse it: ark role use {id}", describe_id(cfg, &cat, &id)),
            Found::Many(v) => format!("{} matches:\n{}", v.len(), v.iter().map(|(_, l)| format!("  {l}")).collect::<Vec<_>>().join("\n")),
            Found::None => format!("no role matches `{}`", words.trim()),
        });
    }
    let mut out = String::new();
    if layer.is_none() && group.is_none() {
        out.push_str("Presets (pre-assembled professional roles):\n");
        for p in roles::presets(cfg) {
            out.push_str(&format!("  {:<10} {} / {} — {} [packs: {}; tools: {}]\n", p.id, p.title_zh, p.title_en, p.summary, p.packs.join(" + "), p.tools));
        }
        out.push('\n');
    }
    let core = roles::core_pack(&cat);
    if layer.is_none_or(|l| l == Layer::L0) && group.is_none() {
        out.push_str(&format!("L0  {} — {} (always loaded, ~{} tokens)\n", core.slug, core.title_zh, core.tokens()));
    }
    let all = o.flag("all") || group.is_some() || layer == Some(Layer::L2);
    let mut l1s: Vec<_> = cat.by_layer(Layer::L1).filter(|p| group.as_deref().is_none_or(|g| p.isco == g[..1.min(g.len())])).collect();
    l1s.sort_by(|a, b| a.isco.cmp(&b.isco));
    for l1 in l1s {
        if layer.is_some_and(|l| l == Layer::L0) {
            break;
        }
        let kids: Vec<_> = cat.by_layer(Layer::L2).filter(|p| p.extends.as_deref() == Some(l1.slug.as_str()) && group.as_deref().is_none_or(|g| p.isco.starts_with(g))).collect();
        if layer != Some(Layer::L2) {
            out.push_str(&format!("L1  {} {} — {} ({} occupations)\n", l1.isco, l1.slug, l1.title_zh, kids.len()));
        }
        if all {
            let mut kids = kids;
            kids.sort_by(|a, b| a.isco.cmp(&b.isco).then(a.slug.cmp(&b.slug)));
            for p in kids {
                out.push_str(&format!("      {} {:<36} {}{}\n", p.isco, p.slug, p.title_zh, if p.regulated { "  ⚖ regulated" } else { "" }));
            }
        }
    }
    if !all {
        out.push_str("\nEvery occupation: ark role list --all · one major group: --group 2 · search: ark role list <words or code>");
    }
    Ok(out)
}

fn describe_id(cfg: &Config, cat: &Catalog, id: &str) -> String {
    match roles::resolve(cfg, cat, id) {
        Ok(r) => format!("{} [{}] — ISCO {}", r.title, r.id, r.isco().join("+")),
        Err(e) => e,
    }
}

// ───────────── use ─────────────

/// Resolve the user's words to one role id, or explain the choice they have to make.
pub fn pick(cfg: &Config, words: &str) -> Result<Option<String>, String> {
    if roles::is_none(words) {
        return Ok(None);
    }
    match roles::find(cfg, &Catalog::for_config(cfg), words) {
        Found::One(id) => Ok(Some(id)),
        Found::Many(v) => Err(format!(
            "`{}` matches several roles; name one of them:\n{}{}",
            words.trim(),
            v.iter().take(40).map(|(id, l)| format!("  ark role use {id:<34} # {l}")).collect::<Vec<_>>().join("\n"),
            if v.len() > 40 { format!("\n  (+{} more)", v.len() - 40) } else { String::new() }
        )),
        Found::None => Err(format!("no role matches `{}` (see `ark role list`)", words.trim())),
    }
}

fn use_role(paths: &Paths, cfg: &Config, o: &Opts) -> Result<(String, i32), String> {
    let words = o.rest();
    if words.trim().is_empty() {
        return Err("usage: ark role use <ISCO code | name | preset | none> [--agent ID]".into());
    }
    let id = match pick(cfg, &words) {
        Ok(id) => id,
        Err(e) => return Ok((e, 2)),
    };
    let role = id.as_deref().map(|i| roles::resolve(cfg, &Catalog::for_config(cfg), i)).transpose()?;
    // A tree that fails its signature is not used (an unsigned tree is, with a note).
    let mut notes = Vec::new();
    if let Some(dir) = roles::roles_dirs(cfg).first() {
        match signature_state(paths, dir, None) {
            SigState::Invalid(e) => return Err(format!("{}: {e}; refusing to use a tampered role tree (`ark role verify`)", dir.display())),
            SigState::Unsigned => notes.push("note: this role tree is unsigned (development build); `ark role verify` checks it".to_string()),
            SigState::Valid(_) => {}
        }
    }
    let saved = match o.val("agent") {
        Some(agent) => {
            ark_kernel::agents::update(paths, agent, |a| a.role = id.clone().unwrap_or_default())?;
            format!("agent `{agent}` → {}", id.as_deref().unwrap_or("none"))
        }
        None => match &id {
            Some(i) => crate::ops::confcli::set(paths, "role.active", &format!("{i:?}"))?,
            None => crate::ops::confcli::unset(paths, "role.active").unwrap_or_else(|_| "role.active was not set".into()),
        },
    };
    let mut out = vec![match &role {
        Some(r) => format!("role → {} [{}]", r.title, r.id),
        None => "role → none (L0 professional core only)".into(),
    }];
    out.push(format!("  {saved}"));
    if let Some(r) = &role {
        out.push(summary(r));
    }
    out.extend(notes);
    out.push("New sessions use it; a running chat can switch with /role.".into());
    Ok((out.join("\n"), 0))
}

// ───────────── show ─────────────

fn summary(r: &Role) -> String {
    let (l0, l1, l2) = r.tokens();
    let mut out = vec![format!("  layers: L0 {} ~{l0}", roles::CORE_SLUG)];
    for p in &r.packs {
        out.push(format!("          {} {} — {} (ISCO {}) ~{}{}", p.layer.as_str(), p.slug, p.title_zh, p.isco, p.tokens(), if p.regulated { " · regulated" } else { "" }));
    }
    out.push(format!("  prompt cost: ~{} tokens (L0 {l0} + L1 {l1} + L2 {l2})", l0 + l1 + l2));
    if let Some(t) = r.tool_profile() {
        out.push(format!("  tool profile: {t}"));
    }
    let pol = r.policy();
    if !pol.is_empty() {
        let mut bits = Vec::new();
        if let Some(a) = &pol.approval {
            bits.push(format!("approval {a}"));
        }
        if pol.workspace_only {
            bits.push("workspace-only writes".into());
        }
        if pol.db_read_only {
            bits.push("read-only databases".into());
        }
        if pol.scan_allowlist {
            bits.push("scans only on [role] scan_targets".into());
        }
        if pol.no_password_entry {
            bits.push("never types passwords".into());
        }
        if !pol.deny.is_empty() {
            bits.push(format!("{} refused command patterns", pol.deny.len()));
        }
        out.push(format!("  defaults: {}", bits.join(", ")));
        if !pol.approve.is_empty() {
            out.push(format!("  asks first: {}", pol.approve.join("; ")));
        }
    }
    let acts = r.acts();
    if !acts.is_empty() {
        out.push(format!("  reserved acts (handed to a licensed person at run time): {}", acts.join(", ")));
    }
    let refs: Vec<String> = r.packs.iter().flat_map(|p| p.references()).map(|(p, first)| format!("    {} — {first}", p.display())).collect();
    if !refs.is_empty() {
        out.push(format!("  references (read on demand):\n{}", refs.join("\n")));
    }
    out.join("\n")
}

fn show(paths: &Paths, cfg: &Config, o: &Opts) -> Result<String, String> {
    let words = o.rest();
    let (id, whose) = if !words.trim().is_empty() {
        (pick(cfg, &words)?, "requested".to_string())
    } else if let Some(agent) = o.val("agent") {
        let a = ark_kernel::agents::resolve(cfg, paths, agent).ok_or_else(|| format!("unknown agent `{agent}`"))?;
        (a.role.clone().or_else(|| Some(cfg.role.active.clone()).filter(|r| !roles::is_none(r))), format!("agent `{agent}`"))
    } else {
        (Some(cfg.role.active.clone()).filter(|r| !roles::is_none(r)), "default agent ([role] active)".into())
    };
    let cat = Catalog::for_config(cfg);
    let core = roles::core_pack(&cat);
    let Some(id) = id else {
        return Ok(format!("{whose}: no occupation — L0 {} only (~{} tokens{})\nChoose one: ark role use <ISCO code | name | preset>", core.slug, core.tokens(), if cfg.role.core { "" } else { ", switched off by [role] core = false" }));
    };
    let r = roles::resolve(cfg, &cat, &id)?;
    if o.flag("json") {
        let (l0, l1, l2) = r.tokens();
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "id": r.id, "title": r.title, "isco": r.isco(), "packs": r.packs.iter().map(|p| &p.slug).collect::<Vec<_>>(),
            "tokens": {"l0": l0, "l1": l1, "l2": l2}, "tool_profile": r.tool_profile(), "policy": r.policy(), "reserved_acts": r.acts(),
        }))
        .unwrap_or_default());
    }
    let mut out = format!("{whose}: {} [{}]\n{}", r.title, r.id, summary(&r));
    if o.flag("prompt") {
        out.push_str(&format!("\n\n--- identity (L0) ---\n{}\n\n--- role segment ---\n{}", roles::core_text(cfg).unwrap_or_default(), r.segment_text()));
    }
    Ok(out)
}

// ───────────── verify / sign / diff (7-4-5) ─────────────

pub const SIG_FILE: &str = "roles.sig";

/// Every file of a role tree (minus the signature and caches), keyed by POSIX relative path.
pub fn tree_files(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    fn walk(root: &Path, d: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<(), String> {
        let mut entries: Vec<_> = std::fs::read_dir(d).map_err(|e| format!("{}: {e}", d.display()))?.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || name == "__pycache__" || name == SIG_FILE {
                continue;
            }
            let ft = e.file_type().map_err(|e| e.to_string())?;
            if ft.is_dir() {
                walk(root, &p, out)?;
            } else if ft.is_file() {
                let rel = p.strip_prefix(root).map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
                out.insert(rel, std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

pub fn tree_digest(dir: &Path) -> Result<String, String> {
    Ok(signing::manifest_digest(&tree_files(dir)?))
}

/// `roles.sig`: `digest`, `key`, `signature` lines (`k = "v"`).
fn read_sig(dir: &Path) -> Option<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(dir.join(SIG_FILE)).ok()?;
    Some(text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string())).collect())
}

pub enum SigState {
    Unsigned,
    /// Signed by this key id.
    Valid(String),
    Invalid(String),
}

/// Check `roles.sig` against the tree; the key must be `--key` or in the trust store.
pub fn signature_state(paths: &Paths, dir: &Path, key: Option<&str>) -> SigState {
    let Some(sig) = read_sig(dir) else { return SigState::Unsigned };
    let digest = match tree_digest(dir) {
        Ok(d) => d,
        Err(e) => return SigState::Invalid(e),
    };
    let (Some(want), Some(k), Some(s)) = (sig.get("digest"), sig.get("key"), sig.get("signature")) else {
        return SigState::Invalid(format!("{SIG_FILE} lacks digest/key/signature"));
    };
    if *want != digest {
        return SigState::Invalid(format!("content changed since it was signed (signed {}, now {digest})", short(want)));
    }
    let pk = match signing::PublicKey::parse(k) {
        Ok(p) => p,
        Err(e) => return SigState::Invalid(format!("{SIG_FILE} key: {e}")),
    };
    let trusted = match key {
        Some(kk) => signing::PublicKey::parse(kk).map(|x| x == pk).unwrap_or(false),
        None => signing::TrustStore::load(&signing::TrustStore::default_path(&paths.data)).map(|t| t.find(&pk.text()).is_some() || t.find(&pk.id()).is_some()).unwrap_or(false),
    };
    if let Err(e) = signing::verify(&pk, digest.as_bytes(), s) {
        return SigState::Invalid(format!("bad signature: {e}"));
    }
    if !trusted {
        return SigState::Invalid(format!("signed by key {} which is not trusted (pass --key or add it to {})", pk.id(), signing::TrustStore::default_path(&paths.data).display()));
    }
    SigState::Valid(pk.id())
}

fn short(d: &str) -> String {
    d.chars().take(19).collect()
}

fn roles_dir_of(o: &Opts) -> Result<PathBuf, String> {
    match o.val("dir") {
        Some(d) => Ok(PathBuf::from(d)),
        None => roles::roles_dir().ok_or_else(|| "no role tree found (set ARK_SHARE_DIR or pass --dir)".into()),
    }
}

fn verify(paths: &Paths, o: &Opts) -> Result<(String, i32), String> {
    let dir = roles_dir_of(o)?;
    let mut out = vec![format!("role tree: {}", dir.display())];
    let mut failed = false;
    // Skills Guard over every pack directory.
    let mut packs = 0usize;
    let mut caution = Vec::new();
    for layer in ["L0", "L1", "L2"] {
        let Ok(rd) = std::fs::read_dir(dir.join(layer)) else { continue };
        let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        dirs.sort();
        for d in dirs {
            packs += 1;
            let r = skills_guard::scan_dir(&d, "official");
            match r.verdict {
                skills_guard::Verdict::Dangerous => {
                    failed = true;
                    out.push(format!("  ✗ {layer}/{}: dangerous\n{}", r.skill_name, skills_guard::format_report(&r)));
                }
                skills_guard::Verdict::Caution => caution.push(format!("{layer}/{}", r.skill_name)),
                _ => {}
            }
        }
    }
    out.push(format!("Skills Guard: {packs} packs scanned, {} dangerous, {} caution{}", if failed { "some" } else { "0" }, caution.len(), if caution.is_empty() { String::new() } else { format!(" ({})", caution.join(", ")) }));
    let digest = tree_digest(&dir)?;
    out.push(format!("manifest digest: {digest}"));
    match signature_state(paths, &dir, o.val("key")) {
        SigState::Valid(k) => out.push(format!("signature: valid (key {k})")),
        SigState::Unsigned if o.flag("require-signature") => {
            failed = true;
            out.push(format!("signature: missing ({SIG_FILE}) and --require-signature was given"));
        }
        SigState::Unsigned => out.push(format!("signature: none ({SIG_FILE} absent — a development tree; releases are signed with `ark role sign`)")),
        SigState::Invalid(e) => {
            failed = true;
            out.push(format!("signature: INVALID — {e}"));
        }
    }
    out.push(if failed { "verify: FAILED".into() } else { "verify: OK".into() });
    Ok((out.join("\n"), if failed { 1 } else { 0 }))
}

fn sign(o: &Opts) -> Result<String, String> {
    let dir = roles_dir_of(o)?;
    let seed_file = o.val("seed-file").ok_or("usage: ark role sign --seed-file FILE [--dir DIR] (the base64 Ed25519 seed; keep it out of the repo)")?;
    let seed = std::fs::read_to_string(seed_file).map_err(|e| format!("{seed_file}: {e}"))?;
    let digest = tree_digest(&dir)?;
    let sig = signing::sign(seed.trim(), digest.as_bytes())?;
    let key = signing::public_of(seed.trim())?;
    let text = format!("# Ed25519 signature over the role tree's manifest digest (`ark role verify`).\ndigest = \"{digest}\"\nkey = \"{key}\"\nsignature = \"{sig}\"\n");
    std::fs::write(dir.join(SIG_FILE), text).map_err(|e| e.to_string())?;
    Ok(format!("signed {} ({digest}) with key {}", dir.display(), signing::PublicKey::parse(&key).map(|k| k.id()).unwrap_or_default()))
}

/// `slug → (layer, rule lines)` of a tree.
fn rules_of(dir: &Path) -> BTreeMap<String, Vec<String>> {
    let cat = Catalog::load_dirs(&[dir.to_path_buf()]);
    cat.packs.values().filter(|p| p.dir.is_some()).map(|p| (format!("{} {}", p.layer.as_str(), p.slug), p.body.lines().filter_map(|l| l.strip_prefix("- ")).map(|l| l.trim().to_string()).collect())).collect()
}

fn diff(o: &Opts) -> Result<String, String> {
    let old = o.pos.get(1).map(PathBuf::from).ok_or("usage: ark role diff <old-dir> [<new-dir>]")?;
    let new = match o.pos.get(2) {
        Some(n) => PathBuf::from(n),
        None => roles::roles_dir().ok_or("no current role tree; pass <new-dir>")?,
    };
    let (a, b) = (rules_of(&old), rules_of(&new));
    if a.is_empty() {
        return Err(format!("{}: no role packs", old.display()));
    }
    let mut out = Vec::new();
    let (mut added, mut removed) = (0, 0);
    for k in a.keys().chain(b.keys()).collect::<std::collections::BTreeSet<_>>() {
        match (a.get(k), b.get(k)) {
            (Some(_), None) => out.push(format!("− pack {k} removed")),
            (None, Some(r)) => {
                out.push(format!("+ pack {k} added ({} rules)", r.len()));
                added += r.len();
            }
            (Some(x), Some(y)) => {
                let gone: Vec<_> = x.iter().filter(|r| !y.contains(r)).collect();
                let new: Vec<_> = y.iter().filter(|r| !x.contains(r)).collect();
                if !gone.is_empty() || !new.is_empty() {
                    out.push(format!("~ {k}"));
                    out.extend(gone.iter().map(|r| format!("    − {r}")));
                    out.extend(new.iter().map(|r| format!("    + {r}")));
                    removed += gone.len();
                    added += new.len();
                }
            }
            (None, None) => {}
        }
    }
    if out.is_empty() {
        return Ok("no rule changes".into());
    }
    out.push(format!("{added} rule(s) added, {removed} removed"));
    Ok(out.join("\n"))
}

// ───────────── `ark setup` step (pro-070) ─────────────

/// Menu rows for the setup wizard's role step: `(label, role id or None)`. The first row keeps
/// the L0 core only; the presets follow; the last row asks for a code or a name.
pub fn setup_choices(zh: bool) -> Vec<(String, Option<String>)> {
    let mut v = vec![(if zh { "先不指定（只帶共通職業操守）".to_string() } else { "None for now (professional core only)".to_string() }, None)];
    for p in roles::builtin_presets() {
        v.push((format!("{} — {}", if zh { &p.title_zh } else { &p.title_en }, p.summary), Some(p.id.clone())));
    }
    v.push((if zh { "其他職業（輸入 ISCO 代碼或職業名稱）".to_string() } else { "Another occupation (ISCO code or name)".to_string() }, Some(String::new())));
    v
}

/// Write the setup choice into the config table being built (`None` leaves it unset).
pub fn setup_apply(root: &mut toml::Table, id: Option<&str>) {
    match id.filter(|i| !i.is_empty()) {
        Some(id) => {
            let t = root.entry("role").or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if let Some(t) = t.as_table_mut() {
                t.insert("active".into(), id.to_string().into());
            }
        }
        None => {
            if let Some(t) = root.get_mut("role").and_then(|v| v.as_table_mut()) {
                t.remove("active");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Env {
        _dir: ark_core::tmp::TempDir,
        paths: Paths,
    }

    fn env() -> Env {
        let dir = ark_core::tmp::TempDir::new("ark-role-cli");
        let paths = Paths { data: dir.join("data"), config_dir: dir.join("cfg"), runtime: dir.join("run") };
        std::fs::create_dir_all(&paths.data).unwrap();
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        Env { _dir: dir, paths }
    }

    fn run_s(e: &Env, args: &[&str]) -> (String, i32) {
        run(&e.paths, &args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn list_use_show_round_trip() {
        let e = env();
        let (l, _) = run_s(&e, &["list"]);
        assert!(l.contains("devops") && l.contains("L1  2 professional-practice") && l.contains("L0  professional-core"), "{l}");
        let (all, _) = run_s(&e, &["list", "--group", "25"]);
        assert!(all.contains("2512 software-developer") && !all.contains("3512"), "{all}");
        let (j, _) = run_s(&e, &["list", "--json"]);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert!(v["packs"].as_array().unwrap().len() >= 548 && v["packs"][0]["isco"].is_string());

        // An ambiguous code lists the candidates and changes nothing.
        let (m, code) = run_s(&e, &["use", "2149"]);
        assert_eq!(code, 2, "{m}");
        assert!(m.contains("ark role use") && !e.paths.user_config().exists());

        let (u, code) = run_s(&e, &["use", "2512"]);
        assert_eq!(code, 0, "{u}");
        assert!(u.contains("software-developer") && u.contains("prompt cost"), "{u}");
        let cfg = Config::load(Some(&e.paths.user_config()), None, &[]).unwrap();
        assert_eq!(cfg.role.active, "software-developer");
        let (s, _) = run_s(&e, &["show"]);
        assert!(s.contains("ISCO 2512"), "{s}");

        let (u, _) = run_s(&e, &["use", "資安維運"]);
        assert!(u.contains("[secops]") && u.contains("tool profile: secops") && u.contains("approval strict"), "{u}");
        let (p, _) = run_s(&e, &["show", "--prompt"]);
        assert!(p.contains("# Professional conduct") && p.contains("[role:secops]"), "{p}");

        run_s(&e, &["use", "none"]);
        assert_eq!(Config::load(Some(&e.paths.user_config()), None, &[]).unwrap().role.active, "");
    }

    #[test]
    fn use_binds_a_named_agent() {
        let e = env();
        ark_kernel::agents::add(&e.paths, "nurse", ark_kernel::agents::AgentDef::default()).unwrap();
        let (u, code) = run_s(&e, &["use", "bedside-nursing", "--agent", "nurse"]);
        assert_eq!(code, 0, "{u}");
        let (s, _) = run_s(&e, &["show", "--agent", "nurse"]);
        assert!(s.contains("reserved acts") && s.contains("administer_medication"), "{s}");
    }

    #[test]
    fn verify_scans_signs_and_detects_tampering() {
        let e = env();
        let tree = ark_core::tmp::TempDir::new("ark-role-tree");
        let src = roles::roles_dir().unwrap();
        for rel in ["L0/professional-core/SKILL.md", "L1/professional-practice/SKILL.md", "L2/software-developer/SKILL.md", "boundaries.toml", "presets.toml"] {
            let to = tree.join(rel);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(src.join(rel), &to).unwrap();
        }
        let d = tree.to_string_lossy().to_string();
        let (v, code) = run_s(&e, &["verify", "--dir", &d]);
        assert_eq!(code, 0, "{v}");
        assert!(v.contains("3 packs scanned, 0 dangerous") && v.contains("signature: none"), "{v}");
        assert_eq!(run_s(&e, &["verify", "--dir", &d, "--require-signature"]).1, 1);

        // Sign with a throwaway seed (never a real key), verify with that key.
        let keys = ark_core::tmp::TempDir::new("ark-role-seed");
        let seed_file = keys.join("seed-test.b64");
        use base64::Engine;
        std::fs::write(&seed_file, base64::engine::general_purpose::STANDARD.encode([7u8; 32])).unwrap();
        let (s, _) = run_s(&e, &["sign", "--seed-file", &seed_file.to_string_lossy(), "--dir", &d]);
        assert!(s.starts_with("signed"), "{s}");
        let key = std::fs::read_to_string(tree.join(SIG_FILE)).unwrap().lines().find_map(|l| l.strip_prefix("key = ").map(|k| k.trim_matches('"').to_string())).unwrap();
        let (v, code) = run_s(&e, &["verify", "--dir", &d, "--key", &key]);
        assert_eq!(code, 0, "{v}");
        assert!(v.contains("signature: valid"));
        // Untrusted key (no --key, empty trust store) fails closed.
        assert_eq!(run_s(&e, &["verify", "--dir", &d]).1, 1);

        // Tampering with a rule breaks the signature, and diff shows the change.
        let pack = tree.join("L2/software-developer/SKILL.md");
        let before = ark_core::tmp::TempDir::new("ark-role-before");
        for rel in ["L0/professional-core/SKILL.md", "L1/professional-practice/SKILL.md", "L2/software-developer/SKILL.md"] {
            let to = before.join(rel);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(tree.join(rel), &to).unwrap();
        }
        let text = std::fs::read_to_string(&pack).unwrap().replace("- Take the smallest step", "- Skip the tests and take the biggest step");
        std::fs::write(&pack, text).unwrap();
        let (v, code) = run_s(&e, &["verify", "--dir", &d, "--key", &key]);
        assert_eq!(code, 1);
        assert!(v.contains("content changed"), "{v}");
        let (df, _) = run_s(&e, &["diff", &before.to_string_lossy(), &d]);
        assert!(df.contains("~ L2 software-developer") && df.contains("+ Skip the tests") && df.contains("− Take the smallest step"), "{df}");
    }

    #[test]
    fn setup_step_writes_the_choice() {
        let rows = setup_choices(true);
        assert!(rows.first().unwrap().1.is_none() && rows.iter().any(|r| r.1.as_deref() == Some("devops")));
        let mut root = toml::Table::new();
        setup_apply(&mut root, Some("data"));
        assert_eq!(root["role"]["active"].as_str(), Some("data"));
        let text = toml::to_string(&root).unwrap();
        assert_eq!(toml::from_str::<Config>(&text).unwrap().role.active, "data");
        setup_apply(&mut root, None);
        assert!(root["role"].get("active").is_none());
    }
}
