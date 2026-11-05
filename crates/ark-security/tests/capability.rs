//! `ark_security::capability` — GAPS-next A5, from the enforcement side.
//!
//! The tests here are the contract another session's broker / egress wiring relies on:
//! undeclared components are refused, a built-in is never widened by someone else's
//! manifest, a declaration is a boundary (not a prompt) for ordinary work, and tier 3 is
//! never authorised by a manifest (A6).
//!
//! They need no `ARK_HOME`, no temp directory, no network and no child process: every
//! check is a pure function of a manifest, so nothing here can touch the real home
//! directory. Registered manifests are process-global, so each test uses a name of its
//! own (`cap-test-…`) and never calls `capability::reset()` — the tests in this binary run
//! in parallel in one process.

use ark_security::capability::{self, Kind, Manifest, Request, Source};

/// Every `ToolSpec` name `crates/ark-tools/src` defines, checked in deliberately.
///
/// `ark-security` cannot depend on `ark-tools` (no dev-dependency may be added here, and
/// it would be a compile cycle), so the list is maintained by hand: it is
/// `ark_tools::builtin_tools()` plus the tool specs that crate registers only on config
/// or credentials (`x_search`, `code_execution`, `github_*`, `tavily_*`, `firecrawl_*`).
/// A new tool in `ark-tools` needs a row in `capability::BUILTIN_ROWS` and a name here.
const BUILTIN_TOOL_NAMES: &[&str] = &[
    "read",
    "write",
    "edit",
    "patch",
    "apply_patch",
    "glob",
    "grep",
    "shell",
    // Not a tool: the guest agent asking on behalf of a session the host cannot attribute to
    // one tool (a background job, a program started earlier). It declares commands and public
    // hosts, and deliberately *no* named secrets — an unattributable request may not have one
    // injected (A4/A5).
    "vm",
    "memory",
    "spawn",
    "ask_user",
    "todo",
    "skill",
    "job",
    "process",
    "read_terminal",
    "close_terminal",
    "web_fetch",
    "web_search",
    "web_extract",
    "x_search",
    "code_execution",
    "github_read",
    "github_search",
    "tavily_search",
    "tavily_extract",
    "firecrawl_search",
    "firecrawl_scrape",
    "sql_query",
    "sql_schema",
    "directory_lookup",
    "forge_read",
    "forge_write",
];

fn argv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn caps(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Rule 1: every built-in tool declares what it needs, and the declaration covers the
/// tool's own obvious effects — the user configures nothing (§0 compromise).
#[test]
fn every_builtin_tool_ships_a_manifest() {
    for name in BUILTIN_TOOL_NAMES {
        let m = capability::builtin(name).unwrap_or_else(|| panic!("no shipped manifest for built-in tool `{name}`"));
        assert_eq!((m.kind, m.source), (Kind::Tool, Source::Builtin), "{name}");
        assert_eq!(m.name, *name);
    }
    // The shipped table holds nothing else, and its names are unique.
    assert_eq!(capability::builtins().len(), BUILTIN_TOOL_NAMES.len());
    for m in capability::builtins() {
        assert!(BUILTIN_TOOL_NAMES.contains(&m.name.as_str()), "`{}` is not a built-in tool name", m.name);
    }

    // The obvious needs of the obvious tools, through the public check, not just the table.
    assert!(capability::check("shell", &Request { exec: Some(&argv(&["cargo", "test", "--all"])), ..Default::default() }).is_ok());
    assert!(capability::check("job", &Request { exec: Some(&argv(&["npm", "run", "dev"])), ..Default::default() }).is_ok());
    assert!(capability::check("read", &Request { fs_read: Some("/work/repo/src/main.rs"), ..Default::default() }).is_ok());
    assert!(capability::check("write", &Request { fs_write: Some("/work/repo/src/main.rs"), ..Default::default() }).is_ok());
    assert!(capability::check("web_fetch", &Request { net: Some(("docs.rs", 443)), ..Default::default() }).is_ok());
    assert!(capability::check("web_search", &Request { net: Some(("api.search.example", 443)), ..Default::default() }).is_ok());
    assert!(capability::check("ask_user", &Request::default()).is_ok());

    // §0: ordinary reversible work must never need a prompt, so it must not be denied by
    // the capability layer either — that would be the "protection eats autonomy" failure.
    for (tool, r) in [
        ("shell", Request { exec: Some(&argv(&["git", "status"])), ..Default::default() }),
        ("grep", Request { fs_read: Some("/work/repo/README.md"), ..Default::default() }),
        ("web_fetch", Request { net: Some(("crates.io", 443)), ..Default::default() }),
        ("edit", Request { fs_write: Some("/work/repo/src/lib.rs"), ..Default::default() }),
        ("memory", Request { fs_write: Some("/home/me/.ark/data/memory/MEMORY.md"), ..Default::default() }),
    ] {
        assert!(capability::check(tool, &r).is_ok(), "{tool}");
    }

    // A tool whose job is not that effect still refuses it: `read` never writes.
    let err = capability::check("read", &Request { fs_write: Some("/work/repo/x"), ..Default::default() }).unwrap_err();
    assert!(err.contains("fs:write") && err.contains("`read`"), "{err}");
    assert!(capability::check("ask_user", &Request { net: Some(("crates.io", 443)), ..Default::default() }).is_err());
}

/// Rule 3: an undeclared component does not run, and the message tells the operator what
/// to do about it (a denial nobody can act on is just an outage).
#[test]
fn undeclared_third_party_is_refused_with_a_next_step() {
    assert!(capability::lookup("cap-test-uninstalled").is_none());
    let err = capability::check("cap-test-uninstalled", &Request::default()).unwrap_err();
    assert!(err.starts_with("no capability manifest for `cap-test-uninstalled`"), "{err}");
    assert!(err.contains("declare") && err.contains("A5"), "{err}");
    // Nothing was invented by the lookup: still unknown afterwards.
    assert!(capability::lookup("cap-test-uninstalled").is_none());

    // A registered third-party skill is known, but only for what it declared.
    capability::register(capability::declared("cap-test-notes", Kind::Skill, Source::ThirdParty, &caps(&["net:crates.io", "tool:read"])).unwrap());
    let m = capability::check("cap-test-notes", &Request { net: Some(("crates.io", 443)), tool: Some("read"), ..Default::default() }).expect("declared host and tool");
    assert_eq!((m.kind, m.source), (Kind::Skill, Source::ThirdParty));
    let err = capability::check("cap-test-notes", &Request { tool: Some("shell"), ..Default::default() }).unwrap_err();
    assert!(err.contains("tool:shell") && err.contains("cap-test-notes"), "{err}");
}

/// `net` patterns: an exact host (and, as in `egress_proxy::host_rule`, its subdomains),
/// `*.host` for subdomains only, and `*` meaning *public hosts only*.
///
/// The private-IP case is the interesting one: `*` never covers loopback, and an explicit
/// entry is the only way a component may reach the local machine. Even then the request
/// has to pass `url_safety` at connect time (it re-checks the resolved address of every
/// hop), because a name that looks public can resolve to `127.0.0.1` — that is the IP
/// layer, and this module is the declaration layer.
#[test]
fn net_patterns_are_hosts_subdomains_and_public_star() {
    // The plain glob, as the vocabulary uses it.
    assert!(capability::matches(&caps(&["*"]), "crates.io"));
    assert!(capability::matches(&caps(&["*.github.com"]), "api.github.com"));
    assert!(!capability::matches(&caps(&["*.github.com"]), "github.com"), "`*.` is subdomains only");
    assert!(capability::matches(&caps(&["crates.io"]), "crates.io"));
    assert!(!capability::matches(&caps(&["crates.io"]), "example.com"));

    // Built-in fetchers declare `*`: the public internet, nothing local.
    assert!(capability::check("web_fetch", &Request { net: Some(("crates.io", 443)), ..Default::default() }).is_ok());
    assert!(capability::check("web_fetch", &Request { net: Some(("8.8.8.8", 53)), ..Default::default() }).is_ok(), "a public literal address");
    let err = capability::check("web_fetch", &Request { net: Some(("127.0.0.1", 80)), ..Default::default() }).unwrap_err();
    assert!(err.contains("net:127.0.0.1:80") && err.contains("private"), "{err}");
    for local in [("10.1.2.3", 443), ("192.168.1.1", 443), ("169.254.169.254", 80), ("localhost", 3000), ("box.internal", 443), ("fileserver", 445)] {
        assert!(capability::check("web_fetch", &Request { net: Some(local), ..Default::default() }).is_err(), "`*` must not cover {local:?}");
    }

    // Declared, it is allowed — and only for the port that was declared.
    capability::register(capability::declared("cap-test-localdev", Kind::Plugin, Source::Operator, &caps(&["net:127.0.0.1:3000"])).unwrap());
    assert!(capability::check("cap-test-localdev", &Request { net: Some(("127.0.0.1", 3000)), ..Default::default() }).is_ok());
    assert!(capability::check("cap-test-localdev", &Request { net: Some(("127.0.0.1", 8080)), ..Default::default() }).is_err());

    // Subdomains follow the egress proxy's rule; an unrelated host is refused.
    capability::register(capability::declared("cap-test-gh", Kind::Mcp, Source::ThirdParty, &caps(&["net:github.com", "net:*.githubusercontent.com"])).unwrap());
    assert!(capability::check("cap-test-gh", &Request { net: Some(("api.github.com", 443)), ..Default::default() }).is_ok());
    assert!(capability::check("cap-test-gh", &Request { net: Some(("raw.githubusercontent.com", 443)), ..Default::default() }).is_ok());
    assert!(capability::check("cap-test-gh", &Request { net: Some(("githubusercontent.com", 443)), ..Default::default() }).is_err());
    assert!(capability::check("cap-test-gh", &Request { net: Some(("example.com", 443)), ..Default::default() }).is_err());
}

/// `exec` is argv-prefix based, matched element by element — a shell line is never
/// re-tokenised into something looser than what was declared.
#[test]
fn exec_patterns_match_argv_prefixes_only() {
    capability::register(capability::declared("cap-test-pkg", Kind::Plugin, Source::Operator, &caps(&["exec:apt-get install *", "exec:cargo build"])).unwrap());
    assert!(capability::check("cap-test-pkg", &Request { exec: Some(&argv(&["apt-get", "install", "jq"])), ..Default::default() }).is_ok());
    assert!(capability::check("cap-test-pkg", &Request { exec: Some(&argv(&["cargo", "build", "--release"])), ..Default::default() }).is_ok(), "a prefix may stop early");
    let err = capability::check("cap-test-pkg", &Request { exec: Some(&argv(&["sh", "-c", "rm -rf /"])), ..Default::default() }).unwrap_err();
    assert!(err.contains("`exec:sh -c rm -rf /`") && err.contains("cap-test-pkg"), "{err}");
    assert!(capability::check("cap-test-pkg", &Request { exec: Some(&argv(&["apt-get", "remove", "jq"])), ..Default::default() }).is_err());
    assert!(capability::check("cap-test-pkg", &Request { exec: Some(&argv(&["cargo", "test"])), ..Default::default() }).is_err());
    // A single-element argv is read as a command line (callers holding a shell string).
    assert!(capability::check("cap-test-pkg", &Request { exec: Some(&argv(&["apt-get install jq"])), ..Default::default() }).is_ok());
    assert!(capability::check("cap-test-pkg", &Request { exec: Some(&argv(&["sh -c 'rm -rf /'"])), ..Default::default() }).is_err());
    // The built-ins that run commands are declared wide on purpose (§0-1: the VM isolates).
    assert!(capability::check("shell", &Request { exec: Some(&argv(&["sh", "-c", "make -j8"])), ..Default::default() }).is_ok());
}

/// A third-party skill reaches what it declared and nothing else; a later registration
/// that adds a capability is recorded, which is what the installation-time confirmation
/// re-reads (H3/MCP rug pull).
#[test]
fn a_third_party_skill_reaches_only_its_declared_host_and_widening_is_visible() {
    let name = "cap-test-rugpull";
    capability::register(capability::declared(name, Kind::Skill, Source::ThirdParty, &caps(&["net:crates.io"])).unwrap());
    assert!(capability::check(name, &Request { net: Some(("crates.io", 443)), ..Default::default() }).is_ok());
    let err = capability::check(name, &Request { net: Some(("example.com", 443)), ..Default::default() }).unwrap_err();
    assert!(err.contains("lacks the `net:example.com:443` capability") && err.contains("cap-test-rugpull"), "{err}");
    assert!(capability::widenings_for(name).is_empty(), "the first registration is not a change");

    // Same manifest again: idempotent, not a change.
    capability::register(capability::declared(name, Kind::Skill, Source::ThirdParty, &caps(&["net:crates.io"])).unwrap());
    assert!(capability::widenings_for(name).is_empty());

    // The upgrade adds a host: visible as a widening, and the new host now works.
    capability::register(capability::declared(name, Kind::Skill, Source::ThirdParty, &caps(&["net:crates.io", "net:example.com", "fs:write:/home/me/proj/**"])).unwrap());
    let w = capability::widenings_for(name);
    assert_eq!(w.len(), 1, "{w:?}");
    let mut added = w[0].added.clone();
    added.sort();
    assert_eq!(added, ["fs:write:/home/me/proj/**", "net:example.com"]);
    assert_eq!(w[0].previous.net, ["crates.io"]);
    assert_eq!(w[0].current.net, ["crates.io", "example.com"]);
    assert!(capability::widenings().iter().any(|x| x.name == name));
    assert!(capability::check(name, &Request { net: Some(("example.com", 443)), ..Default::default() }).is_ok());
    assert!(capability::check(name, &Request { fs_write: Some("/home/me/proj/src/lib.rs"), ..Default::default() }).is_ok());
    assert!(capability::check(name, &Request { fs_write: Some("/etc/passwd"), ..Default::default() }).is_err());

    // Rule 5: a skill or MCP server can never widen or shadow a built-in tool.
    let before = capability::lookup("shell").expect("builtin shell");
    capability::register(Manifest { name: "shell".into(), kind: Kind::Mcp, source: Source::ThirdParty, net: caps(&["*"]), fs_read: caps(&["**"]), fs_write: caps(&["**"]), exec: caps(&["*"]), ..Default::default() });
    assert_eq!(capability::lookup("shell").unwrap(), before);
    assert!(capability::widenings_for("shell").is_empty());
    // A built-in that declares no network cannot be talked into one by somebody's manifest.
    assert!(capability::check("read", &Request { net: Some(("example.com", 443)), ..Default::default() }).is_err());
    assert!(capability::check("read", &Request { fs_write: Some("/work/repo/x"), ..Default::default() }).is_err());
}

/// A6: `destructive: true` lets a component *ask*, and nothing more. Every tier-3 request
/// is refused by the capability layer whatever the manifest says.
#[test]
fn destructive_is_never_authorised_by_a_capability() {
    // A manifest without the capability cannot even attempt it.
    capability::register(capability::declared("cap-test-quiet", Kind::Plugin, Source::Operator, &caps(&["exec:*"])).unwrap());
    let err = capability::check("cap-test-quiet", &Request { destructive: true, ..Default::default() }).unwrap_err();
    assert!(err.contains("destructive") && err.contains("never be authorised"), "{err}");

    // With it, the request reaches the operator gate — and `check` still refuses it.
    capability::register(capability::declared("cap-test-loud", Kind::Plugin, Source::Operator, &caps(&["exec:*", "destructive"])).unwrap());
    let m = capability::lookup("cap-test-loud").unwrap();
    assert!(m.allows(&Request { destructive: true, ..Default::default() }).is_ok(), "the capability itself is declared");
    let err = capability::check("cap-test-loud", &Request { destructive: true, ..Default::default() }).unwrap_err();
    assert!(err.contains("tier 3") && err.contains("operator") && err.contains("A6"), "{err}");

    // Classified tier 3 by the risk table, not just by the caller's flag.
    let wipe = argv(&["aws", "s3", "rm", "s3://prod-backups", "--recursive"]);
    let a = capability::assess("cap-test-loud", &Request { exec: Some(&wipe), ..Default::default() });
    assert!(a.tier.is_irreversible(), "{a:?}");
    assert!(capability::check("cap-test-loud", &Request { exec: Some(&wipe), ..Default::default() }).unwrap_err().contains("tier 3"));
    // And through a built-in that declares `destructive` (shell may ask, never act alone).
    assert!(capability::check("shell", &Request { exec: Some(&wipe), ..Default::default() }).is_err());

    // A backup path is tier 3 without any flag.
    assert!(capability::check("cap-test-loud", &Request { fs_write: Some("/mnt/backups/db.dump"), ..Default::default() }).is_err());
    // Ordinary work is untouched: the capability layer does not add prompts (§0).
    assert!(capability::check("cap-test-loud", &Request { exec: Some(&argv(&["cargo", "test"])), ..Default::default() }).is_ok());
}

/// `declared()` and `from_toml()` fail loudly and name the offending token, and a manifest
/// survives a write/read round trip.
#[test]
fn declaration_and_manifest_files_name_the_bad_token() {
    for (caps_in, needle) in [
        ("net", "`net`"),
        ("glob:*.rs", "glob:*.rs"),
        ("fs:read", "fs:read"),
        ("fs:exec:/x", "exec"),
        ("secret", "`secret`"),
        ("destructive:probably", "probably"),
    ] {
        let err = capability::declared("cap-test-bad", Kind::Tool, Source::Operator, &[caps_in.to_string()]).unwrap_err();
        assert!(err.contains(needle), "{caps_in} → {err}");
        assert!(err.contains("cap-test-bad"), "{err}");
    }
    let err = capability::declared(" ", Kind::Tool, Source::Operator, &[]).unwrap_err();
    assert!(err.contains("name"), "{err}");

    let text = r#"
name = "cap-test-manifest"
kind = "mcp"
source = "third-party"
fs_read = ["/home/me/proj/**"]
fs_write = []
exec = ["cargo build"]
net = ["crates.io", "*.github.com"]
secrets = ["CRATES_TOKEN"]
tools = ["read"]
destructive = false
"#;
    let m = capability::from_toml(text).expect("manifest file");
    assert_eq!((m.kind, m.source), (Kind::Mcp, Source::ThirdParty));
    assert_eq!(m.net, ["crates.io", "*.github.com"]);
    assert_eq!(capability::from_toml(&m.to_toml()).expect("round trip"), m);

    // The parsed manifest is enforceable as written.
    capability::register(m.clone());
    assert!(capability::check("cap-test-manifest", &Request { net: Some(("api.github.com", 443)), ..Default::default() }).is_ok());
    assert!(capability::check("cap-test-manifest", &Request { net: Some(("example.com", 443)), ..Default::default() }).is_err());
    assert!(capability::check("cap-test-manifest", &Request { secret: Some("OTHER_TOKEN"), ..Default::default() }).is_err());

    for (bad, needle) in [("name = \"cap-test-x\"\nkind = \"gadget\"\n", "gadget"), ("name = \"cap-test-x\"\nshell = \"*\"\n", "shell"), ("kind = \"skill\"\n", "name")] {
        let err = capability::from_toml(bad).unwrap_err();
        assert!(err.contains(needle), "{bad:?} → {err}");
    }
}

/// `ark sandbox explain` prints one line per component.
#[test]
fn summary_is_one_line_for_ark_sandbox_explain() {
    let shell = capability::lookup("shell").unwrap();
    let s = shell.summary();
    assert!(!s.contains('\n'), "{s}");
    assert!(s.starts_with("tool shell (builtin): "), "{s}");
    for expect in ["exec *", "fs:read **", "fs:write **", "destructive"] {
        assert!(s.contains(expect), "{s} lacks {expect}");
    }
    let s = capability::lookup("web_fetch").unwrap().summary();
    assert!(s.contains("net * (public hosts only)"), "{s}");
    let s = capability::lookup("ask_user").unwrap().summary();
    assert!(s.contains("no capabilities"), "{s}");
    let m = capability::from_toml("name = \"cap-test-nothing\"\nkind = \"skill\"\nsource = \"operator\"\n").unwrap();
    assert!(m.summary().contains("skill cap-test-nothing (operator): no capabilities"), "{}", m.summary());
}
