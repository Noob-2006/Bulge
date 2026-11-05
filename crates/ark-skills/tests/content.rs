//! Content audit for the shipped skill corpus.
//!
//! These are *content* tests, not unit tests: they read `share/skills/**` and
//! `share/optional-skills/index.json` exactly as the binary ships them, and drive the real
//! `ark_skills` discovery / hub catalog types over them. No network: the official catalog is
//! resolved from the local index, and the install mechanism is exercised on a temp data dir.
//!
//! Provenance of the corpus (all MIT, transcribed or adapted — see THIRD_PARTY_NOTICES.md):
//!   * Hermes `skills/` (58 bundled skills) → `share/skills/<category>/<name>/`
//!   * OpenClaw `skills/` (38 named rows) + `custodian-skills/` (4) → same tree
//!   * Hermes `optional-skills/` (153) → catalog only, `share/optional-skills/index.json`
//!
//! The per-skill size floors in [`MIN_BODY_CHARS`] come from the upstream bodies (60% of the
//! characters a port claims to carry, 50% for the two adapted ports); regenerate with
//! `python3 tools/d5-minbody.py --rust` and never lower a value.

use ark_skills::core::settings::{Settings, Store};
use ark_skills::hub::http::Http;
use ark_skills::hub::install::{Hub, InstallOpts};
use ark_skills::hub::model::{self, Source as HubSource, SkillBundle};
use ark_skills::hub::sources::Official;
use ark_skills::skill::{self, Source};
use ark_skills::yaml;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Per-skill floor: 60% of the upstream body it claims to carry (50% for the two
/// adapted ports). Derived by `tools/d5-minbody.py`; never lower a value here.
const MIN_BODY_CHARS: &[(&str, usize)] = &[
    ("1password", 3744),
    ("add-model-provider", 2429),
    ("airtable", 6533),
    ("apple-notes", 1251),
    ("apple-reminders", 1995),
    ("architecture-diagram", 3246),
    ("ark-agent", 6303),
    ("ark-skill-authoring", 7060),
    ("arxiv", 5859),
    ("ascii-video", 8765),
    ("baoyu-infographic", 5998),
    ("bear-notes", 1258),
    ("blocked-page-recovery", 2893),
    ("blogwatcher", 500),
    ("blucli", 303),
    ("box", 6759),
    ("camsnap", 762),
    ("claude-code", 20812),
    ("claude-design", 14775),
    ("clawhub", 1632),
    ("cloud-image-bake", 2256),
    ("codebase-inspection", 1944),
    ("codex", 3316),
    ("coding-agent", 5821),
    ("competitor-news-monitor", 2551),
    ("computer-use", 10566),
    ("configure-channel", 2185),
    ("design-md", 4831),
    ("diagnose-gateway", 1527),
    ("diagram-maker", 1307),
    ("document-to-action-items", 2130),
    ("docx", 6022),
    ("dogfood", 3603),
    ("eightctl", 301),
    ("email-inbox-triage", 3055),
    ("findmy", 2143),
    ("gemini", 357),
    ("gh-issues", 3457),
    ("gif-search", 1450),
    ("gifgrep", 1103),
    ("github", 4510),
    ("gog", 3709),
    ("google-workspace", 8125),
    ("goplaces", 489),
    ("grounded-citations", 7319),
    ("healthcheck", 1656),
    ("himalaya", 4839),
    ("humanizer", 20377),
    ("imessage", 1294),
    ("llm-wiki", 11734),
    ("manim-video", 7107),
    ("maps", 3750),
    ("meeting-action-items", 2058),
    ("meme-maker", 1417),
    ("model-usage", 1181),
    ("nano-pdf", 259),
    ("node-inspect-debugger", 8437),
    ("notion", 10465),
    ("obsidian", 3279),
    ("openai-whisper", 229),
    ("openai-whisper-api", 861),
    ("opencode", 4178),
    ("openhue", 1146),
    ("oracle", 2589),
    ("ordercli", 932),
    ("p5js", 16200),
    ("pdf", 7252),
    ("peekaboo", 2279),
    ("popular-web-designs", 5506),
    ("powerpoint", 6255),
    ("product-price-monitor", 2440),
    ("python-debugpy", 10182),
    ("requesting-code-review", 4992),
    ("sag", 1099),
    ("sdlc-review", 5227),
    ("sherpa-onnx-tts", 925),
    ("simplify-code", 8530),
    ("skill-creator", 1289),
    ("songsee", 1650),
    ("songwriting-and-ai-music", 6304),
    ("sonoscli", 1157),
    ("spike", 5949),
    ("spotify-player", 531),
    ("summarize", 936),
    ("systematic-debugging", 8166),
    ("teams-meeting-pipeline", 3810),
    ("test-driven-development", 5923),
    ("things-mac", 1652),
    ("tmux", 1212),
    ("trello", 1435),
    ("visualize", 5554),
    ("weather", 1435),
    ("weekly-review-planning", 2148),
    ("xlsx", 5594),
    ("xurl", 10683),
    ("youtube-content", 2444),
];

/// The 55 Hermes bundled skills ported under their own names, plus the two that were adapted
/// (Hermes-internal product docs → ark equivalents) and hence renamed.
const HERMES_BUNDLED: &[&str] = &[
    // adapted (upstream: hermes-agent, hermes-agent-skill-authoring)
    "ark-agent",
    "ark-skill-authoring",
    // verbatim ports
    "airtable", "apple-notes", "apple-reminders", "architecture-diagram", "arxiv", "ascii-video",
    "baoyu-infographic", "blocked-page-recovery", "box", "claude-code", "claude-design",
    "codebase-inspection", "codex", "competitor-news-monitor", "computer-use", "design-md",
    "document-to-action-items", "docx", "dogfood", "email-inbox-triage", "findmy", "gif-search",
    "github", "google-workspace", "grounded-citations", "himalaya", "humanizer", "imessage",
    "llm-wiki", "manim-video", "maps", "meeting-action-items", "node-inspect-debugger", "notion",
    "obsidian", "opencode", "p5js", "pdf", "popular-web-designs", "powerpoint",
    "product-price-monitor", "python-debugpy", "requesting-code-review", "sdlc-review",
    "simplify-code", "songsee", "songwriting-and-ai-music", "spike", "systematic-debugging",
    "teams-meeting-pipeline", "test-driven-development", "xlsx", "xurl", "youtube-content",
    "weekly-review-planning",
];

/// The 38 OpenClaw skill rows of `audit/skills.md` §9 (O§9). Nine of them share a name with a
/// Hermes skill: there the tree carries the Hermes variant with the upstream OpenClaw procedure
/// appended verbatim under `## OpenClaw procedure` (see [`OPENCLAW_MERGED`]).
const OPENCLAW_NAMED: &[&str] = &[
    "1password", "blogwatcher", "blucli", "camsnap", "clawhub", "coding-agent", "diagram-maker", "eightctl",
    "gemini", "gh-issues", "gifgrep", "github", "gog", "goplaces", "healthcheck", "himalaya",
    "meme-maker", "nano-pdf", "node-inspect-debugger", "notion", "obsidian", "openai-whisper",
    "openai-whisper-api", "openhue", "oracle", "ordercli", "python-debugpy", "sag",
    "sherpa-onnx-tts", "skill-creator", "songsee", "sonoscli", "spike", "spotify-player", "summarize", "tmux",
    "trello", "visualize", "weather", "xurl",
];

/// OpenClaw skills whose name collides with a Hermes bundled skill; both upstream procedures must
/// be present in the one file (Hermes body + `## OpenClaw procedure` section).
const OPENCLAW_MERGED: &[&str] = &[
    "github", "himalaya", "node-inspect-debugger", "notion", "obsidian", "python-debugpy",
    "songsee", "spike", "xurl",
];

/// OpenClaw `custodian-skills/` (4).
const CUSTODIAN: &[&str] = &["add-model-provider", "cloud-image-bake", "configure-channel", "diagnose-gateway"];

/// OpenClaw §9 macOS group: content ported, runtime needs macOS tooling (documented in each file
/// under `## Platform note` / `## Prerequisites`). The other three rows of that group are N/A
/// (`control-ui`, `mcporter`, `node-connect` — OpenClaw-only surfaces, not shipped as skills).
const MACOS_PORTS: &[&str] = &["apple-notes", "apple-reminders", "bear-notes", "things-mac", "peekaboo", "model-usage"];

/// Corpus floors (upstream size / 0.6 rule, see module docs).
const MIN_NONEMPTY_LINES: usize = 8;
const MIN_ANY_BODY_CHARS: usize = 220;

fn share_dir() -> PathBuf {
    skill::share_dir().expect("share dir with skills/")
}

fn bundled_roots() -> Vec<(PathBuf, Source)> {
    vec![(share_dir().join("skills"), Source::Bundled)]
}

/// Skills written for ark itself carry `upstream: "ark-original"`; they have no upstream body to
/// measure a size floor against, so the transcription audits below skip them and
/// [`ark_original_skills_are_complete_and_well_formed`] holds them to their own rules.
fn is_original(s: &skill::Skill) -> bool {
    std::fs::read_to_string(&s.file).is_ok_and(|t| t.lines().take(12).any(|l| l.trim() == "upstream: \"ark-original\""))
}

fn corpus() -> Vec<skill::Skill> {
    let all: Vec<skill::Skill> = skill::discover(&bundled_roots()).into_iter().filter(|s| !is_original(s)).collect();
    assert!(!all.is_empty(), "no bundled skills discovered under {}", share_dir().display());
    all
}

fn original_corpus() -> Vec<skill::Skill> {
    skill::discover(&bundled_roots()).into_iter().filter(is_original).collect()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Frontmatter + body, parsed with the same parser the loader uses.
fn parsed(s: &skill::Skill) -> (Value, String) {
    let text = read(&s.file);
    let (front, body) = yaml::frontmatter_strict(&text)
        .unwrap_or_else(|e| panic!("{}: frontmatter does not parse: {e}", s.file.display()));
    assert!(front.is_object(), "{}: frontmatter is not a mapping: {front}", s.file.display());
    (front, body.to_string())
}

fn min_body(name: &str) -> usize {
    MIN_BODY_CHARS.iter().find(|(n, _)| *n == name).map(|(_, m)| *m).unwrap_or(MIN_ANY_BODY_CHARS)
}

fn temp_data(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ark-skills-content-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ───────────── (a) every required skill exists, is discovered and parses ─────────────

#[test]
fn bundled_corpus_covers_every_required_skill_name() {
    let all = corpus();
    let by_name: BTreeMap<&str, &skill::Skill> = all.iter().map(|s| (s.name.as_str(), s)).collect();

    let mut required: Vec<&str> = Vec::new();
    required.extend(HERMES_BUNDLED);
    required.extend(OPENCLAW_NAMED);
    required.extend(CUSTODIAN);
    required.extend(MACOS_PORTS);
    required.sort_unstable();
    required.dedup();

    let mut missing = Vec::new();
    for name in &required {
        let Some(s) = by_name.get(name) else {
            missing.push(*name);
            continue;
        };
        let (front, body) = parsed(s);
        assert_eq!(front["name"].as_str(), Some(*name), "{}: frontmatter name", s.file.display());
        assert_eq!(s.name, *name, "{}: discovery name", s.file.display());
        assert_eq!(s.dir.file_name().and_then(|f| f.to_str()), Some(*name), "{}: directory name", s.file.display());
        assert!(!s.description.trim().is_empty(), "{}: empty description", s.file.display());
        assert!(s.description.chars().count() <= skill::MAX_DESCRIPTION, "{}: description too long", s.file.display());
        // (c) no stubs: the body must keep at least 60% of the upstream characters it claims.
        assert!(body.chars().count() >= min_body(name), "{}: body {} chars < upstream-derived floor {}", s.file.display(), body.chars().count(), min_body(name));
        let lines = body.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(lines >= MIN_NONEMPTY_LINES, "{}: body has only {lines} non-empty lines", s.file.display());
    }
    assert!(missing.is_empty(), "required skills not discovered: {missing:?}");
    assert_eq!(required.len(), 96, "required-name list changed without updating the audit rows");
    assert!(all.len() >= 96, "corpus shrank: {} skills", all.len());

    // Category folders of the shipped tree (Hermes layout) must survive discovery.
    let cats: BTreeSet<&str> = all.iter().filter_map(|s| s.category.as_deref()).collect();
    for c in ["apple", "autonomous-ai-agents", "creative", "custodian", "devops", "email", "media", "note-taking", "openclaw", "productivity", "research", "social-media", "software-development", "web"] {
        assert!(cats.contains(c), "category `{c}` disappeared from the corpus");
    }
}

// ───────────── (c) no stubbed bodies anywhere in the tree ─────────────

#[test]
fn no_bundled_skill_is_a_stub() {
    let all = corpus();
    assert_eq!(all.len(), MIN_BODY_CHARS.len(), "MIN_BODY_CHARS must cover every shipped skill (run tools/d5-minbody.py --rust)");

    for s in &all {
        let (front, body) = parsed(s);
        let chars = body.chars().count();
        let lines = body.lines().filter(|l| !l.trim().is_empty()).count();
        assert!(chars >= MIN_ANY_BODY_CHARS, "{}: body is {chars} chars", s.file.display());
        assert!(lines >= MIN_NONEMPTY_LINES, "{}: body has {lines} non-empty lines", s.file.display());
        assert!(chars >= min_body(&s.name), "{}: body {chars} chars < upstream-derived floor {}", s.file.display(), min_body(&s.name));
        // A frontmatter-only file (the classic stub) leaves the body starting with `name:`.
        assert!(!body.trim_start().starts_with("name:"), "{}: body looks like unparsed frontmatter", s.file.display());
        assert!(front.get("description").is_some(), "{}: no description key", s.file.display());
        // Structural sanity: one H1, balanced code fences (a botched merge breaks these first).
        let (mut fence, mut h1) = (false, 0);
        for line in body.lines() {
            if line.starts_with("```") {
                fence = !fence;
                continue;
            }
            if !fence && line.starts_with("# ") {
                h1 += 1;
            }
        }
        assert!(!fence, "{}: unbalanced ``` fence", s.file.display());
        assert_eq!(h1, 1, "{}: expected exactly one H1, found {h1}", s.file.display());
    }

    // The two thinnest upstream skills are the floor of the corpus: if a future port replaces one
    // of them with a summary, this catches it.
    let mut thin: Vec<&str> = all.iter().filter(|s| min_body(&s.name) < 300).map(|s| s.name.as_str()).collect();
    thin.sort_unstable();
    assert_eq!(thin, ["nano-pdf", "openai-whisper"], "unexpected ultra-short skills: {thin:?}");
}

// ───────────── (c2) skills written for ark (no upstream to transcribe) ─────────────

/// The professional-role skills (BATCH-next §3: pro-022/035/036/041/042) are ark's own. They must
/// exist, say who they are for, keep their references on disk, and name only tools ark ships.
#[test]
fn ark_original_skills_are_complete_and_well_formed() {
    let all = original_corpus();
    let by_name: BTreeMap<&str, &skill::Skill> = all.iter().map(|s| (s.name.as_str(), s)).collect();
    // (skill, references it routes to, tools its text relies on)
    let expected: &[(&str, &[&str], &[&str])] = &[
        ("sql-data-analysis", &["references/schema-exploration.md", "references/data-cleaning.md", "references/report-template.md", "references/example-flow.md"], &["sql_query", "sql_schema"]),
        ("it-support-triage", &["references/account-provisioning.md", "references/permission-requests.md", "references/ticket-flow.md"], &["directory_lookup", "ask_user"]),
        ("forge-issue-to-pr", &["references/webhook-trigger.md", "references/review-reply.md"], &["forge_read", "forge_write"]),
        ("forge-pr-sweep", &[], &["forge_read"]),
    ];
    for (name, refs, tools) in expected {
        let s = by_name.get(name).unwrap_or_else(|| panic!("ark-original skill `{name}` is missing"));
        let (front, body) = parsed(s);
        assert_eq!(front["name"].as_str(), Some(*name));
        assert_eq!(s.dir.file_name().and_then(|f| f.to_str()), Some(*name), "directory name");
        assert!(!s.description.trim().is_empty() && s.description.chars().count() <= skill::MAX_DESCRIPTION, "{name}: description");
        assert!(front["license"].as_str().is_some() && front["author"].as_str().is_some(), "{name}: license/author");
        assert!(body.chars().count() >= 1800, "{name}: body is only {} chars", body.chars().count());
        for r in *refs {
            let text = read(&s.dir.join(r));
            assert!(text.chars().count() >= 800, "{name}/{r} is a stub");
            assert!(body.contains(r), "{name}: SKILL.md does not route to {r}");
        }
        for t in *tools {
            assert!(body.contains(t), "{name}: does not mention `{t}`");
        }
        let (mut fence, mut h1) = (false, 0);
        for line in body.lines() {
            if line.starts_with("```") {
                fence = !fence;
            } else if !fence && line.starts_with("# ") {
                h1 += 1;
            }
        }
        assert!(!fence && h1 == 1, "{name}: fences balanced, exactly one H1 (found {h1})");
    }
    assert_eq!(all.len(), expected.len(), "an ark-original skill is not covered by this audit: {:?}", all.iter().map(|s| &s.name).collect::<Vec<_>>());
    // The sweep is a blueprint: it parses and schedules something sensible.
    let sweep = by_name["forge-pr-sweep"];
    let spec = ark_skills::core::blueprints::parse(&read(&sweep.file)).expect("blueprint block parses").expect("it is a blueprint");
    assert_eq!(spec.skill, "forge-pr-sweep");
    assert!(spec.schedule.split_whitespace().count() == 5 && spec.prompt.as_deref().is_some_and(|p| p.contains("forge_read")), "{spec:?}");
    assert_eq!(spec.deliver, "local");
    // Every tool a skill names exists in ark: the names appear in the tool crates.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ark-tools/src");
    for t in ["sql_query", "sql_schema", "directory_lookup", "forge_read", "forge_write"] {
        let found = ["data/mod.rs", "directory/mod.rs", "forge/mod.rs"].iter().any(|f| read(&root.join(f)).contains(&format!("\"{t}\".into()")));
        assert!(found, "tool `{t}` named by a skill is not defined in ark-tools");
    }
}

// ───────────── (b) optional-skills: 153 entries, resolvable through the catalog types ─────────────

fn catalog() -> Value {
    let p = share_dir().join("optional-skills/index.json");
    serde_json::from_str(&read(&p)).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn catalog_entries() -> Vec<Value> {
    let v = catalog();
    assert_eq!(v["repo"].as_str(), Some("NousResearch/hermes-agent"), "catalog repo");
    assert_eq!(v["prefix"].as_str(), Some("optional-skills"), "catalog prefix");
    v["skills"].as_array().cloned().unwrap_or_default()
}

#[test]
fn optional_skill_catalog_has_153_resolvable_entries() {
    let entries = catalog_entries();
    assert_eq!(entries.len(), 153, "Hermes optional-skills has 153 skills");
    assert!(!share_dir().join("optional-skills").join("skills").exists(), "optional skills must not be vendored as files");

    let (mut names, mut paths) = (BTreeSet::new(), BTreeSet::new());
    for e in &entries {
        let (name, path) = (e["name"].as_str().unwrap_or_default(), e["path"].as_str().unwrap_or_default());
        let desc = e["description"].as_str().unwrap_or_default();
        assert!(!name.is_empty() && !desc.trim().is_empty(), "incomplete catalog entry: {e}");
        assert!(model::validate_skill_name(name).is_ok(), "bad name `{name}`");
        // `<category>/<name>`, validated by the same helper the hub uses for bundle paths.
        let norm = model::normalize_bundle_path(path, "catalog path", true).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(norm, path);
        assert_eq!(path.rsplit('/').next(), Some(name), "path `{path}` must end in the skill name");
        // `<category>/<name>`, `<category>/<sub>/<name>` (mlops) or a bare `<name>` (dogfood).
        assert!((1..=3).contains(&path.split('/').count()), "unexpected catalog path shape: {path}");
        assert!(e["tags"].is_array(), "tags must be an array: {path}");

        let files: Vec<&str> = e["files"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        assert!(files.contains(&"SKILL.md"), "{path}: no SKILL.md in the file list");
        for f in &files {
            let f = model::validate_rel(f).unwrap_or_else(|e| panic!("{path}: bad file `{f}`: {e}"));
            assert!(model::normalize_bundle_path(&f, "file", true).is_ok());
            assert!(!f.starts_with('/') && !f.contains(".."), "{path}: unsafe file {f}");
        }
        names.insert(name.to_string());
        paths.insert(path.to_string());
    }
    assert_eq!(names.len(), 153, "duplicate skill names in the catalog");
    assert_eq!(paths.len(), 153, "duplicate paths in the catalog");

    // The hub's `official` source must resolve every one of them (index read is local, no network).
    let data = temp_data("catalog");
    let settings = Settings::from_table(&toml::Table::new());
    let store = Store::at(&data);
    let http = Http::new(&settings, &store);
    let official = Official { http: &http };
    let listed = HubSource::search(&official, "", 10_000);
    assert_eq!(listed.len(), 153, "official source must list all 153 skills");
    for e in &entries {
        let path = e["path"].as_str().unwrap();
        let meta = HubSource::inspect(&official, &format!("official/{path}"))
            .unwrap_or_else(|| panic!("official source cannot resolve official/{path}"));
        assert_eq!(meta.name, e["name"].as_str().unwrap());
        assert_eq!(meta.description, e["description"].as_str().unwrap());
        assert_eq!(meta.source, "official");
        assert_eq!(meta.trust_level, "builtin");
        assert_eq!(meta.path.as_deref(), Some(format!("optional-skills/{path}").as_str()));
        assert_eq!(meta.repo.as_deref(), Some("NousResearch/hermes-agent"));
        assert_eq!(meta.tags.len(), e["tags"].as_array().map(|t| t.len()).unwrap_or(0));
        assert!(HubSource::claims(&official, &meta.identifier));
    }
    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn optional_skills_install_through_the_hub() {
    // Prove the mechanism end-to-end, offline: every catalog entry is handed to `Hub::install_bundle`
    // with the file list the catalog declares (the SKILL.md bytes are placeholders — the network
    // fetch is what a real install adds) and must land at `<data>/skills/<category>/<name>`.
    let entries = catalog_entries();
    let data = temp_data("install");
    let settings = Settings::from_table(&toml::Table::new());
    let store = Store::at(&data);
    let hub = Hub::new(&settings, &store);

    for e in &entries {
        let path = e["path"].as_str().unwrap();
        let name = e["name"].as_str().unwrap();
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for f in e["files"].as_array().unwrap().iter().filter_map(Value::as_str) {
            let body = if f == "SKILL.md" {
                format!("---\nname: {name}\ndescription: {}\n---\n# {name}\n\nCatalog placeholder for the install-path test.\n", e["description"].as_str().unwrap())
            } else {
                format!("placeholder for {f}\n")
            };
            files.insert(f.to_string(), body.into_bytes());
        }
        let mut bundle = SkillBundle {
            name: name.to_string(),
            files,
            source: "official".into(),
            identifier: format!("official/{path}"),
            trust_level: "builtin".into(),
            metadata: Map::from_iter([("install_parent".to_string(), json!(path.rsplit_once('/').map(|x| x.0).unwrap_or("")))]),
        };
        let installed = hub.install_bundle(&mut bundle, &InstallOpts::default()).unwrap_or_else(|err| panic!("install official/{path}: {err}"));
        assert_eq!(installed.path, store.skills.join(path), "official/{path} installed to the wrong place");
        assert!(installed.path.join("SKILL.md").is_file(), "official/{path}: no SKILL.md after install");
    }

    // Every one is recorded in the lock file, so `check`/`update`/`uninstall` can see it.
    let lock = model::Lock(&store).list();
    assert_eq!(lock.len(), 153, "lock must record every install");
    let discovered = skill::discover(&[(store.skills.clone(), Source::User)]);
    assert!(discovered.len() >= 153, "installed skills are not discoverable: {}", discovered.len());
    let _ = std::fs::remove_dir_all(&data);
}

// ───────────── (d) attribution: MIT + upstream provenance on every transcribed file ─────────────

#[test]
fn transcribed_skills_carry_mit_attribution() {
    let all = corpus();
    let mut wrong = Vec::new();
    for s in &all {
        let (front, body) = parsed(s);
        let upstream = front["upstream"].as_str().unwrap_or_default();
        let corpus_ok = upstream.starts_with("hermes-agent/skills/") || upstream.starts_with("openclaw/skills/") || upstream.starts_with("openclaw/custodian-skills/");
        if !corpus_ok || !upstream.contains("(MIT)") {
            wrong.push(format!("{}: upstream = {upstream:?}", s.file.display()));
        }
        // Merged ports must label the appended OpenClaw procedure and its licence.
        if OPENCLAW_MERGED.contains(&s.name.as_str()) {
            let at = body.find("## OpenClaw procedure (upstream `openclaw/skills/").unwrap_or_else(|| panic!("{}: merged port lost its `## OpenClaw procedure` section", s.file.display()));
            let tail = &body[at..];
            assert!(tail.contains("MIT"), "{}: OpenClaw section lost its MIT notice", s.file.display());
            assert!(tail.to_lowercase().contains("openclaw contributors"), "{}: no upstream copyright line", s.file.display());
        }
        // macOS ports must say out loud that the runtime is macOS-only.
        if MACOS_PORTS.contains(&s.name.as_str()) {
            let text = format!("{}{}", front, body);
            assert!(text.contains("macos"), "{}: macOS requirement not documented", s.file.display());
        }
    }
    assert!(wrong.is_empty(), "skills without an MIT upstream line:\n{}", wrong.join("\n"));

    // The notice file must name the four transcribed corpora.
    let notices = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../THIRD_PARTY_NOTICES.md"));
    for needle in ["hermes-agent/skills", "hermes-agent/optional-skills", "openclaw/skills", "openclaw/custodian-skills"] {
        assert!(notices.contains(needle), "THIRD_PARTY_NOTICES.md does not mention {needle}");
    }
    assert!(notices.contains("MIT"), "THIRD_PARTY_NOTICES.md lost the MIT statement");
}

// ───────────── (e) the shipped plugin catalog: kill list + an honest entry count ─────────────

/// `plugins::catalog()` / `plugins::removed_entries()` read `<share>/plugin-catalog/index.json`
/// in a real install, so that *shipped* file is the production kill list — Hermes keeps the same
/// list in `plugin-catalog/removed.yaml`. This test reads it the way the binary does (through
/// `skill::share_dir()`, not a faked share dir) and drives the real install/resolve paths.
#[test]
fn shipped_catalog_carries_the_kill_list_and_an_honest_count() {
    let index = share_dir().join("plugin-catalog/index.json");
    let raw: Value = serde_json::from_str(&read(&index)).unwrap_or_else(|e| panic!("{}: {e}", index.display()));
    let shipped = raw["plugins"].as_array().expect("`plugins` array");

    // ① the key ships. Name only for or-picker: the replacement entry lives in the *same*
    // repository, so a repo match would refuse that install too (Hermes removed.yaml says so).
    let removed = raw["removed"].as_array().expect("`removed` ships in the catalog (Hermes plugin-catalog/removed.yaml)");
    let or_picker = removed.iter().find(|r| r["name"] == "or-picker").expect("or-picker is on the shipped kill list");
    assert_eq!(or_picker["date"], "2026-09-28");
    assert!(or_picker["reason"].as_str().unwrap_or_default().contains("openrouter-picker"), "{or_picker}");
    assert!(or_picker.get("repo").and_then(Value::as_str).unwrap_or_default().is_empty(), "name only: {or_picker}");

    // ② the production layout is non-empty: removed_entries() reads this very file.
    let live = ark_skills::hub::plugins::removed_entries();
    assert_eq!(live.len(), removed.len(), "removed_entries() reads the shipped file: {live:?}");
    let hit = ark_skills::hub::plugins::match_removed("or-picker", &live).expect("the shipped list matches by name");
    assert!(hit.reason.contains("openrouter-picker") && hit.date == "2026-09-28", "{hit:?}");

    // ③ install / resolve / show refuse it with the recorded reason (no network: the kill-list
    // check runs before any clone).
    let data = temp_data("killlist");
    let paths = ark_kernel::config::Paths { data: data.join("data"), config_dir: data.join("config"), runtime: data.join("run") };
    let paths = &paths;
    let cfg = ark_kernel::config::Config::default();
    let cfg = &cfg;
    let pm = ark_skills::hub::plugins::Plugins::new(cfg, paths);
    let err = pm.install("or-picker", true).unwrap_err();
    assert!(err.contains("was removed from the plugin catalog") && err.contains("2026-09-28") && err.contains("openrouter-picker"), "{err}");
    let err = pm.resolve("or-picker").unwrap_err();
    assert!(err.starts_with("refused: ") && err.contains("openrouter-picker"), "{err}");
    assert_eq!(pm.inspect("or-picker").map(|v| v["source"].as_str().unwrap_or("").to_string()).as_deref(), Some("removed"), "`ark plugins show` reports the removal");
    // The operator-facing report lists what was pulled and why.
    let out = ark_skills::hub::plugins::cli(cfg, paths, &["catalog".into(), "check".into()]).unwrap().unwrap();
    assert!(out.contains(&format!("{} entries", shipped.len())) && out.contains("0 problem(s)"), "{out}");
    assert!(out.contains("1 removed") && out.contains("REMOVED or-picker") && out.contains("openrouter-picker"), "{out}");
    let _ = std::fs::remove_dir_all(&data);

    // ④ the count is the number that actually ships — the docs used to claim 706 for 704 entries.
    assert_eq!(ark_skills::hub::plugins::catalog().len(), shipped.len(), "catalog() lists every shipped entry");
    assert_eq!(ark_skills::hub::plugins::catalog_problems(), Vec::<String>::new());
    assert!(!shipped.iter().any(|e| e["name"] == "or-picker"), "a removed plugin is not also an installable entry");
    let doc = include_str!("../src/hub/plugins.rs");
    let claim = doc.lines().find(|l| l.contains("reviewed")).expect("the module docs state the catalog size");
    let stated: usize = claim.split_whitespace().find_map(|w| w.trim_matches(|c: char| !c.is_ascii_digit()).parse().ok()).unwrap_or_else(|| panic!("no number in {claim}"));
    assert_eq!(stated, shipped.len(), "the module docs' count is the shipped count (no stale 706): {claim}");
}
