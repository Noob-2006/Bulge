//! Ecosystem-compat tests that need more than a unit: the generated Hermes shim
//! driven through ark's real MCP client, and the read-only upstream corpora
//! (OpenClaw `dist/extensions`, Hermes `plugins` + `optional-mcps`).

use ark_plugin::compat::{self, Imported};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat").join(name)
}

fn scratch(tag: &str) -> PathBuf {
    let d = ark_core::tmp::scratch_path(format!("ark-compat-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    d
}

fn python3() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|p| {
        std::process::Command::new(p).arg("-c").arg("import sys").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
    })
}

/// The generated `hermes_shim.py` against ark's own MCP client: initialize (hooks
/// and tools declared), tools/list, tools/call, and an `ark/hook` per_tool request
/// the plugin denies — plus one it lets through. The shim is spawned and killed by
/// the client (`shutdown` closes stdin, which ends the loop).
#[test]
fn compat_hermes_shim_speaks_the_ark_plugin_protocol() {
    let Some(py) = python3() else {
        eprintln!("skipping: no python3 on PATH");
        return;
    };
    let dest = scratch("e2e");
    let imp = compat::import(&fixture("hermes-python")).unwrap();
    let files = compat::write_imported(&imp, &dest).unwrap();
    assert_eq!(files.len(), 1);
    let cfg = ark_plugin::McpServerConfig { command: Some(py.to_string()), args: vec![files[0].display().to_string()], timeout_secs: Some(30), ..Default::default() };
    let client = ark_plugin::Client::new("compat-guard-demo", cfg, ark_plugin::no_secrets()).unwrap();
    let out = (|| -> Result<(), String> {
        let info = client.info()?;
        let hooks: Vec<&str> = info
            .pointer("/capabilities/experimental/ark/hooks")
            .and_then(|h| h.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        assert!(hooks.contains(&"pre_tool"), "the shim advertises the mapped hook: {info}");
        assert!(hooks.contains(&"transform_tool_result"), "the shim advertises the mapped hook: {info}");
        let commands = info.pointer("/capabilities/experimental/ark/commands").and_then(|c| c.as_array()).cloned().unwrap_or_default();
        assert!(commands.iter().any(|c| c["name"] == "guard-demo"), "ctx.register_command is surfaced: {info}");

        let tools = client.list_tools()?;
        assert!(tools.iter().any(|t| t.name == "guard_demo_check"), "provides_tools are exposed: {tools:?}");
        let r = client.call_tool("guard_demo_check", json!({"text": "eval(user_input)"}), &ark_core::Cancel::new())?;
        let text = r.text;
        assert!(text.contains("\"ok\": false") || text.contains("\"ok\":false"), "the plugin's function ran: {text}");

        let deny = client.request("ark/hook", json!({"event": "pre_tool", "payload": {"tool_name": "write_file", "tool_input": {"text": "eval(x)"}, "input": {"text": "eval(x)"}}}), &ark_core::Cancel::new())?;
        assert_eq!(deny["decision"], "deny", "a Hermes `{{action: block}}` becomes ark `deny`: {deny}");
        assert!(deny["reason"].as_str().unwrap_or("").contains("refused"), "{deny}");

        let allow = client.request("ark/hook", json!({"event": "pre_tool", "payload": {"tool_name": "read_file", "tool_input": {"path": "notes.md"}, "input": {"path": "notes.md"}}}), &ark_core::Cancel::new())?;
        assert_eq!(allow["decision"], "allow", "{allow}");

        // Hermes' string-returning transform hook becomes ark's `modify` (PluginHook
        // maps TransformToolResult's `result` onto the protocol's `input`).
        let modify = client.request("ark/hook", json!({"event": "transform_tool_result", "payload": {"tool": "read", "input": "body"}}), &ark_core::Cancel::new())?;
        assert_eq!(modify["decision"], "modify", "{modify}");
        assert_eq!(modify["input"], "body\n[guard-demo: reviewed]", "{modify}");

        // A command the plugin registered through ctx.register_command.
        let cmd = client.request("ark/command", json!({"name": "guard-demo", "args": ""}), &ark_core::Cancel::new())?;
        assert_eq!(cmd["text"], "guard-demo: ok", "{cmd}");

        // A hook event the shim never declared still gets an answer (fail open), not a hang.
        let unknown = client.request("ark/hook", json!({"event": "post_tool", "payload": {}}), &ark_core::Cancel::new())?;
        assert_eq!(unknown["decision"], "allow", "{unknown}");
        Ok(())
    })();
    client.shutdown();
    let _ = fs::remove_dir_all(&dest);
    out.unwrap();
}

/// The generated `openclaw_shim.mjs`: same protocol, and the fixture's `register(api)`
/// tool is callable through it (no `openclaw/plugin-sdk` here, but the fixture entry
/// does not import it — a real one would log and be served as a declaration).
#[test]
fn compat_openclaw_shim_speaks_the_ark_plugin_protocol() {
    let node = std::process::Command::new("node").arg("--version").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    if !node {
        eprintln!("skipping: no node on PATH");
        return;
    }
    let dest = scratch("e2e-oc");
    let imp = compat::import(&fixture("openclaw-node")).unwrap();
    let files = compat::write_imported(&imp, &dest).unwrap();
    let cfg = ark_plugin::McpServerConfig { command: Some("node".into()), args: vec![files[0].display().to_string()], timeout_secs: Some(30), ..Default::default() };
    let client = ark_plugin::Client::new("compat-demo-search", cfg, ark_plugin::no_secrets()).unwrap();
    let out = (|| -> Result<(), String> {
        let info = client.info()?;
        let commands = info.pointer("/capabilities/experimental/ark/commands").and_then(|c| c.as_array()).cloned().unwrap_or_default();
        assert!(commands.iter().any(|c| c["name"] == "demo"), "manifest cliCommands are advertised: {info}");
        let tools = client.list_tools()?;
        assert!(tools.iter().any(|t| t.name == "demo_search"), "register(api) tools are bridged: {tools:?}");
        let r = client.call_tool("demo_search", json!({"query": "rust"}), &ark_core::Cancel::new())?;
        assert!(r.text.contains("rust"), "{r:?}");
        // A declared-but-unimplemented command answers with an explanation, not an error.
        let cmd = client.request("ark/command", json!({"name": "demo", "args": "status"}), &ark_core::Cancel::new())?;
        assert!(cmd["text"].as_str().unwrap_or("").contains("not implemented"), "{cmd}");
        let allow = client.request("ark/hook", json!({"event": "pre_tool", "payload": {}}), &ark_core::Cancel::new())?;
        assert_eq!(allow["decision"], "allow", "{allow}");
        Ok(())
    })();
    client.shutdown();
    let _ = fs::remove_dir_all(&dest);
    out.unwrap();
}

/// A plugin that cannot load (Hermes-only imports) must still serve an empty
/// plugin instead of failing the handshake.
#[test]
fn compat_broken_python_plugin_still_initializes() {
    let Some(py) = python3() else {
        eprintln!("skipping: no python3 on PATH");
        return;
    };
    let dest = scratch("e2e-broken");
    let src = dest.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("plugin.yaml"), "name: broken\nprovides_hooks:\n  - pre_tool_call\n").unwrap();
    fs::write(src.join("__init__.py"), "import hermes_cli.plugins\n").unwrap();
    let imp = compat::import(&src).unwrap();
    let files = compat::write_imported(&imp, &dest.join("plugins")).unwrap();
    let cfg = ark_plugin::McpServerConfig { command: Some(py.to_string()), args: vec![files[0].display().to_string()], timeout_secs: Some(30), ..Default::default() };
    let client = ark_plugin::Client::new("compat-broken", cfg, ark_plugin::no_secrets()).unwrap();
    let info = client.info().unwrap();
    assert_eq!(info.pointer("/capabilities/experimental/ark/hooks").and_then(|h| h.as_array()).map(|a| a.len()), Some(0), "{info}");
    assert!(client.list_tools().unwrap().is_empty());
    client.shutdown();
    let _ = fs::remove_dir_all(&dest);
}

/// Every real manifest parses, and the numbers are printed (`-- --nocapture`).
#[test]
fn compat_real_corpora_all_parse() {
    let openclaw = Path::new("/home/noob/openclaw");
    let hermes = Path::new("/home/noob/hermes-agent");
    if !openclaw.is_dir() || !hermes.is_dir() {
        eprintln!("skipping: read-only upstreams not present");
        return;
    }
    let mut ocs: Vec<PathBuf> = Vec::new();
    walk(&openclaw.join("dist/extensions"), 6, &mut |p: &Path| {
        if p.file_name().is_some_and(|n| n == "openclaw.plugin.json") {
            ocs.push(p.to_path_buf());
        }
    });
    let ocs: Vec<PathBuf> = ocs;
    let mut stats = Stats::default();
    let mut failures: Vec<String> = Vec::new();
    for p in &ocs {
        match compat::import(p.parent().unwrap()) {
            Ok(i) => stats.add(&i),
            Err(e) => failures.push(e),
        }
    }
    println!("openclaw: {} openclaw.plugin.json under dist/extensions, {} imported, {} failed", ocs.len(), stats.n, failures.len());
    stats.print("openclaw");
    assert!(!ocs.is_empty(), "expected the OpenClaw corpus");
    assert!(failures.is_empty(), "openclaw failures: {failures:#?}");
    assert_eq!(stats.n, ocs.len());

    // The whole checkout — 529 manifests in this tree (dist/, dist-runtime/ and the
    // source `extensions/`) — all import without a failure too.
    let mut all: Vec<PathBuf> = Vec::new();
    walk(openclaw, 8, &mut |p: &Path| {
        if p.file_name().is_some_and(|n| n == "openclaw.plugin.json") {
            all.push(p.to_path_buf());
        }
    });
    let all: Vec<PathBuf> = all;
    let mut afail: Vec<String> = Vec::new();
    for p in &all {
        if let Err(e) = compat::import(p.parent().unwrap()) {
            afail.push(e);
        }
    }
    println!("openclaw repo: {} manifests anywhere in the tree, {} imported, {} failed", all.len(), all.len() - afail.len(), afail.len());
    assert!(all.len() >= ocs.len());
    assert!(afail.is_empty(), "openclaw failures outside dist/extensions: {afail:#?}");

    let mut mcps: Vec<PathBuf> = Vec::new();
    walk(&hermes.join("optional-mcps"), 3, &mut |p: &Path| {
        if p.file_name().is_some_and(|n| n == "manifest.yaml") {
            mcps.push(p.to_path_buf());
        }
    });
    let mut mstats = Stats::default();
    let mut mfail: Vec<String> = Vec::new();
    let mut needs_url: Vec<String> = Vec::new();
    for p in &mcps {
        match compat::hermes_optional_mcp(p) {
            Ok(t) => {
                mstats.n += 1;
                // It must be a config ark can actually load.
                match toml::Value::Table(t.clone()).try_into::<ark_plugin::McpServerConfig>() {
                    Ok(c) => match c.validate(p.parent().and_then(|d| d.file_name()).and_then(|n| n.to_str()).unwrap_or("x")) {
                        Ok(()) => mstats.ok += 1,
                        Err(e) => mfail.push(format!("{}: {e}", p.display())),
                    },
                    Err(e) => mfail.push(format!("{}: {e}", p.display())),
                }
                if let Ok(imp) = compat::hermes_optional_mcp_notes(p) {
                    mstats.notes += imp.len();
                }
            }
            // The one entry whose url is `${VAR}` until the user supplies it: a
            // conversion refusal with an actionable message, not a parse failure.
            Err(e) if e.contains("must be replaced with a real URL") => needs_url.push(e),
            Err(e) => mfail.push(e),
        }
    }
    println!(
        "hermes optional-mcps: {} manifests, {} tables, {} validate as [mcp.<name>], {} need a url at install time, {} failed",
        mcps.len(),
        mstats.n,
        mstats.ok,
        needs_url.len(),
        mfail.len()
    );
    for e in &needs_url {
        println!("  needs url: {e}");
    }
    assert!(!mcps.is_empty(), "expected the optional-mcps corpus");
    assert!(mfail.is_empty(), "optional-mcp failures: {mfail:#?}");
    assert_eq!(mstats.ok + needs_url.len(), mcps.len(), "every optional MCP either becomes a valid [mcp.<name>] table or says which url to set");

    let mut plugins: Vec<PathBuf> = Vec::new();
    walk(&hermes.join("plugins"), 4, &mut |p: &Path| {
        if p.file_name().is_some_and(|n| n == "plugin.yaml") {
            plugins.push(p.to_path_buf());
        }
    });
    let mut pstats = Stats::default();
    let mut pfail: Vec<String> = Vec::new();
    for p in &plugins {
        match compat::import(p.parent().unwrap()) {
            Ok(i) => pstats.add(&i),
            Err(e) => pfail.push(e),
        }
    }
    println!("hermes plugins: {} plugin.yaml under plugins/, {} imported, {} failed", plugins.len(), pstats.n, pfail.len());
    pstats.print("hermes");
    assert!(!plugins.is_empty(), "expected the Hermes plugin corpus");
    assert!(pfail.is_empty(), "hermes plugin failures: {pfail:#?}");
    assert_eq!(pstats.n, plugins.len());

    // A spot check that the import is not merely "did not error".
    let brave = ocs.iter().find(|p| p.to_string_lossy().contains("/brave/")).expect("brave extension");
    let imp = compat::import(brave.parent().unwrap()).unwrap();
    assert_eq!(imp.idiom, "openclaw");
    assert!(imp.secrets.contains(&"BRAVE_API_KEY".to_string()), "setup.providers[].envVars become secrets: {:?}", imp.secrets);
    assert!(imp.warnings.iter().any(|w| w.contains("webSearchProviders")), "{:?}", imp.warnings);
}

#[derive(Default)]
struct Stats {
    n: usize,
    ok: usize,
    notes: usize,
    node: usize,
    python: usize,
    declarative: usize,
    with_shim: usize,
    warnings: usize,
    secrets: usize,
    skills: usize,
    mcp: usize,
}

impl Stats {
    fn add(&mut self, i: &Imported) {
        self.n += 1;
        match i.kind.as_str() {
            "node" => self.node += 1,
            "python" => self.python += 1,
            _ => self.declarative += 1,
        }
        if i.shim.is_some() {
            self.with_shim += 1;
        }
        self.warnings += i.warnings.len();
        self.secrets += i.secrets.len();
        self.skills += i.skills.len();
        self.mcp += i.mcp_servers.len();
        if i.id.is_empty() || i.name.is_empty() {
            panic!("imported {} without an id/name", i.idiom);
        }
    }

    fn print(&self, what: &str) {
        println!(
            "{what}: {} imported — node {}, python {}, declarative {}; shims {}; skills {}, mcp servers {}, secrets {}, warnings {}",
            self.n, self.node, self.python, self.declarative, self.with_shim, self.skills, self.mcp, self.secrets, self.warnings
        );
    }
}

fn walk(dir: &Path, depth: usize, f: &mut impl FnMut(&Path)) {
    if depth == 0 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name == "node_modules" || name == "__pycache__" || name == ".git" {
            continue;
        }
        if p.is_dir() {
            walk(&p, depth - 1, f);
        } else {
            f(&p);
        }
    }
}
