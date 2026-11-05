//! Session exports (Markdown with verification digest, standalone HTML, JSON),
//! trajectories (Hermes ShareGPT JSONL, OpenClaw bundle), Hugging Face trace
//! upload, and checkpoint-store maintenance commands.

use crate::{find_session, usage, Args, Fail, R};
use seagent_kernel::event::Event;
use seagent_kernel::projection::project;
use seagent_kernel::trajectory::{self as tj, Flat};
use seagent_kernel::vault::Vault;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

mod icons {
    include!("export_icons.rs");
}

/// What every export needs about a session.
pub struct SessionData {
    pub id: String,
    pub title: Option<String>,
    pub model: String,
    pub workspace: String,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub system: String,
    pub flats: Vec<Flat>,
}

impl SessionData {
    pub fn from_events(events: &[Event]) -> SessionData {
        let v = project(events);
        let first = events.first().map(|e| e.ts).unwrap_or(0);
        SessionData {
            id: v.session_id.clone(),
            title: v.title.clone(),
            model: v.model.clone(),
            workspace: v.workspace.clone(),
            created_ms: first,
            updated_ms: events.last().map(|e| e.ts).unwrap_or(first),
            system: v.system.iter().map(|s| s.text.as_str()).collect::<Vec<_>>().join("\n\n"),
            flats: tj::flatten(events),
        }
    }
    /// Secrets out of every body (vault values, then credential patterns).
    pub fn redact(&mut self, vault: &Vault) {
        let f = |s: &str| tj::redact_patterns(&vault.redact(s));
        tj::redact_flats(&mut self.flats, &f);
        self.system = f(&self.system);
    }
    /// PII out of every body (`[compliance.pii]` classes).
    pub fn mask_pii(&mut self, c: &seagent_security::pii::PiiConfig) {
        let f = |s: &str| seagent_security::pii::mask_with(s, c);
        tj::redact_flats(&mut self.flats, &f);
        self.system = f(&self.system);
        self.title = self.title.as_deref().map(f);
    }
    fn tool_call_count(&self) -> usize {
        self.flats.iter().map(|f| f.tool_calls.len()).sum()
    }
}

fn openai_tool_calls(f: &Flat) -> Value {
    Value::Array(f.tool_calls.iter().map(|(id, name, input)| json!({"id": id, "type": "function", "function": {"name": name, "arguments": input.to_string()}})).collect())
}

// ───────────────────────── Markdown (Hermes md/qmd v1) ─────────────────────────

pub const EXPORTER_VERSION: &str = "seagent session export (md/qmd) v1";
const SHA_PLACEHOLDER: &str = "__SHA256_PLACEHOLDER__";
const VERIFICATION_HEADING: &str = "## Export verification";

fn frontmatter_line(k: &str, v: &Value) -> String {
    let shown = match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(_) | Value::Array(_) => v.to_string(),
        Value::String(s) => json!(s).to_string(),
        other => json!(other.to_string()).to_string(),
    };
    format!("{k}: {shown}")
}

fn json_block(v: &Value) -> String {
    format!("```json\n{}\n```", serde_json::to_string_pretty(v).unwrap_or_default())
}

fn opt_iso(ms: u64) -> String {
    if ms == 0 {
        String::new()
    } else {
        tj::iso_ms(ms).replace(".000Z", "Z")
    }
}

fn md_messages(s: &SessionData) -> String {
    if s.flats.is_empty() {
        return "## Messages\n\n_No messages in this session._\n".into();
    }
    let mut parts = vec!["## Messages\n".to_string()];
    for f in &s.flats {
        let label = match f.role {
            "tool" => format!("Tool — {}", f.tool_name),
            r => {
                let mut c = r.chars();
                c.next().map(|x| x.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
            }
        };
        let ts = opt_iso(f.ts);
        parts.push(format!("### {label}{}\n", if ts.is_empty() { String::new() } else { format!(" — {ts}") }));
        let body = f.content.trim_end();
        if !body.is_empty() {
            parts.push(format!("{body}\n"));
        }
        if !f.tool_calls.is_empty() {
            parts.push(format!("\n\n## Tool calls\n\n{}\n", json_block(&openai_tool_calls(f))));
        }
        parts.push(String::new());
    }
    parts.join("\n").trim_end().to_string() + "\n"
}

fn md_body(s: &SessionData, fmt: &str, exported_ms: u64) -> String {
    let n = s.flats.len();
    let exported = opt_iso(exported_ms);
    let (provider, _) = s.model.split_once('/').unwrap_or(("", &s.model));
    let fields: Vec<(&str, Value)> = vec![
        ("session_id", json!(s.id)),
        ("title", s.title.clone().map(Value::String).unwrap_or(Value::Null)),
        ("source", Value::Null),
        ("created_at", json!(opt_iso(s.created_ms))),
        ("updated_at", json!(opt_iso(s.updated_ms))),
        ("ended_at", json!("")),
        ("model", json!(s.model)),
        ("provider", json!(provider)),
        ("cwd", json!(s.workspace)),
        ("archived", json!(false)),
        ("message_count", json!(n)),
        ("tool_call_count", json!(s.tool_call_count())),
        ("format", json!(fmt)),
        ("exported_at", json!(exported)),
        ("exporter", json!(EXPORTER_VERSION)),
    ];
    let mut parts = vec![format!("---\n{}\n---\n", fields.iter().map(|(k, v)| frontmatter_line(k, v)).collect::<Vec<_>>().join("\n"))];
    parts.push(format!("# {}\n", s.title.as_deref().filter(|t| !t.is_empty()).unwrap_or(&s.id)));
    parts.push(format!("Session ID: `{}`\n", s.id));
    if !s.workspace.is_empty() {
        parts.push(format!("Working directory: `{}`\n", s.workspace));
    }
    parts.push(md_messages(s));
    parts.push(format!("{VERIFICATION_HEADING}\n"));
    parts.push(format!("- Session id: `{}`", s.id));
    parts.push(format!("- Exported messages: `{n}`"));
    parts.push(format!("- Source DB message count at export: `{n}`"));
    parts.push(format!("- Exported at: `{exported}`"));
    parts.push(format!("- SHA256 of exported body: `{SHA_PLACEHOLDER}`"));
    parts.join("\n").trim_end().to_string() + "\n"
}

/// Markdown/QMD with a SHA-256 over the body (the SHA line reads `pending` while hashing).
pub fn render_markdown(s: &SessionData, fmt: &str, verification: bool, exported_ms: u64) -> String {
    let body = md_body(s, fmt, exported_ms);
    if !verification {
        return body.split(&format!("\n{VERIFICATION_HEADING}\n")).next().unwrap_or("").trim_end().to_string() + "\n";
    }
    let digest_body = body.replace(&format!("`{SHA_PLACEHOLDER}`"), "`pending`");
    body.replace(SHA_PLACEHOLDER, &seagent_net::crypto::hex(&seagent_net::crypto::sha256(digest_body.as_bytes())))
}

/// Re-check an exported file's digest and identity (Hermes `verify_export_file`).
pub fn verify_markdown(text: &str, s: &SessionData) -> Result<(), String> {
    let re = regex_lite_sha(text).ok_or("sha256 marker missing")?;
    let digest_body = text.replace(&format!("- SHA256 of exported body: `{re}`"), "- SHA256 of exported body: `pending`");
    if seagent_net::crypto::hex(&seagent_net::crypto::sha256(digest_body.as_bytes())) != re {
        return Err("sha256 mismatch".into());
    }
    if !text.contains(&format!("- Exported messages: `{}`", s.flats.len())) {
        return Err("message count mismatch".into());
    }
    if !text.contains(&format!("- Session id: `{}`", s.id)) {
        return Err("session id mismatch".into());
    }
    Ok(())
}

fn regex_lite_sha(text: &str) -> Option<String> {
    let marker = "- SHA256 of exported body: `";
    let i = text.find(marker)? + marker.len();
    let h: String = text[i..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    (h.len() == 64).then_some(h)
}

/// `<id>-<slug>.<fmt>`, path-safe.
pub fn safe_filename(s: &SessionData, ext: &str) -> String {
    let title = s.title.as_deref().unwrap_or("session");
    let mut slug = String::new();
    for c in title.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            slug.push(c);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches(|c| matches!(c, '.' | '-' | '_')).to_lowercase();
    let slug = if slug.is_empty() { "session".to_string() } else { slug.chars().take(60).collect() };
    format!("{}-{slug}.{ext}", s.id)
}

// ───────────────────────── HTML (standalone, no remote deps) ─────────────────────────

const HTML_TEMPLATE: &str = include_str!("export_template.html");

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn fmt_local(ms: u64, offset: i32) -> String {
    if ms == 0 {
        return "N/A".into();
    }
    let t = (ms / 1000) as i64 + offset as i64 * 60;
    let (y, m, d) = seagent_kernel::util::civil_from_days(t.div_euclid(86_400));
    let r = t.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", r / 3600, r / 60 % 60, r % 60)
}

fn chevron() -> String {
    icons::ICON_CHEVRON_RIGHT.replacen("class=\"", "class=\"chevron ", 1)
}

fn collapsible(kind: &str, icon: &str, title: &str, inner: &str, indent: &str, outer: &str) -> String {
    let outer = if outer.is_empty() { kind } else { outer };
    format!(
        "\n{indent}<div class=\"{outer}\">\n{indent}    <div class=\"{kind}-header\">\n{indent}        {}\n{indent}        {icon} {title}\n{indent}    </div>\n{indent}    <div class=\"{kind}-content\">\n{indent}        {inner}\n{indent}    </div>\n{indent}</div>\n{indent}",
        chevron()
    )
}

fn role_icon(role: &str) -> &'static str {
    match role {
        "user" => icons::ICON_USER,
        "assistant" => icons::ICON_BOT,
        "system" => icons::ICON_SHIELD,
        _ => icons::ICON_TERMINAL,
    }
}

fn messages_html(s: &SessionData, offset: i32) -> String {
    let mut out = Vec::new();
    for (i, f) in s.flats.iter().enumerate() {
        let role_class: String = f.role.to_lowercase().chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
        let delay = if i < 10 { format!(" style=\"animation-delay: {}s\"", (i as f64 * 0.05).min(1.0)) } else { String::new() };
        let mut h = format!(
            "<div class=\"message message-{role_class} active\"{delay}>  <div class=\"message-header\">    <div class=\"role-badge\">{} {} {}</div>    <div class=\"timestamp\">{}</div>  </div>  <div class=\"message-body\">",
            chevron(),
            role_icon(f.role),
            escape_html(f.role),
            fmt_local(f.ts, offset)
        );
        for (_, name, input) in &f.tool_calls {
            h.push_str(&collapsible("tool-call", icons::ICON_WRENCH, &format!("Tool Call: {}", escape_html(name)), &format!("<pre><code>{}</code></pre>", escape_html(&input.to_string())), &" ".repeat(16), ""));
        }
        let mut content = f.content.clone();
        for _ in 0..f.images {
            content.push_str(if content.is_empty() { "[Image Attachment]" } else { "\n[Image Attachment]" });
        }
        if !content.is_empty() {
            let e = escape_html(&content);
            h.push_str(&format!("  <div class=\"content\">{}</div>", if f.role == "tool" { format!("<pre><code>{e}</code></pre>") } else { e }));
        }
        if !f.reasoning.is_empty() {
            h.push_str(&collapsible("reasoning", icons::ICON_SPARKLES, "Reasoning", &format!("<div class=\"content\">{}</div>", escape_html(&f.reasoning)), &" ".repeat(12), ""));
        }
        out.push(h + "  </div></div>");
    }
    out.join("\n")
}

fn sidebar_item(s: &SessionData, offset: i32) -> String {
    let mut title = s.title.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| "Untitled Session".into());
    if title.chars().count() > 50 {
        title = title.chars().take(47).collect::<String>() + "...";
    }
    let short: String = s.id.chars().take(8).collect();
    let href: String = s.id.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
    format!(
        "\n            <a class=\"session-item\" data-id=\"{}\" href=\"#{href}\">\n                <div class=\"session-item-title\">{}</div>\n                <div class=\"session-item-meta\">\n                    <span>{}</span>\n                    <span>{}</span>\n                </div>\n            </a>\n            ",
        escape_html(&s.id),
        escape_html(&title),
        escape_html(&short),
        fmt_local(s.created_ms, offset).split(' ').next().unwrap_or("")
    )
}

fn sidebar(sessions: &[SessionData], offset: i32) -> String {
    format!(
        "\n        <aside class=\"sidebar\">\n            <div class=\"sidebar-header\">\n                <div class=\"sidebar-brand\">\n                    {} seagent History\n                </div>\n                <div class=\"search-container\">\n                    {}\n                    <input type=\"text\" id=\"session-search\" placeholder=\"Search sessions...\">\n                </div>\n            </div>\n            <div class=\"session-list\">\n                {}\n            </div>\n        </aside>\n        ",
        icons::ICON_HERMES,
        icons::ICON_SEARCH,
        sessions.iter().map(|s| sidebar_item(s, offset)).collect::<String>()
    )
}

fn session_view(s: &SessionData, multi: bool, offset: i32) -> String {
    let sid = escape_html(&s.id);
    let system = if s.system.is_empty() { String::new() } else { collapsible("system-prompt", icons::ICON_SHIELD, "System Prompt (Persona)", &format!("<div class=\"content\">{}</div>", escape_html(&s.system)), &" ".repeat(12), "system-prompt-section active") };
    format!(
        "\n        <div class=\"{}\" id=\"view-{sid}\">\n            <header class=\"fade-in\">\n                <h1>{}</h1>\n                <div class=\"meta\">\n                    <div class=\"meta-item\"><strong>ID:</strong> {sid}</div>\n                    <div class=\"meta-item\"><strong>Model:</strong> {}</div>\n                    <div class=\"meta-item\"><strong>Started:</strong> {}</div>\n                </div>\n                {system}\n            </header>\n            <main>\n                {}\n            </main>\n        </div>\n        ",
        if multi { "session-view" } else { "session-view active" },
        escape_html(s.title.as_deref().filter(|t| !t.is_empty()).unwrap_or("seagent Session")),
        escape_html(if s.model.is_empty() { "Unknown" } else { &s.model }),
        fmt_local(s.created_ms, offset),
        messages_html(s, offset)
    )
}

/// One self-contained page; several sessions get a searchable sidebar.
pub fn render_html(sessions: &[SessionData], offset: i32, now_ms: u64) -> String {
    if sessions.is_empty() {
        return "<html><body><h1>No sessions to export.</h1></body></html>".into();
    }
    let multi = sessions.len() > 1;
    let title = if multi { "seagent Session Export".to_string() } else { escape_html(sessions[0].title.as_deref().filter(|t| !t.is_empty()).unwrap_or("seagent Session")) };
    HTML_TEMPLATE
        .replace("@@page_title@@", &title)
        .replace("@@sidebar_html@@", &if multi { sidebar(sessions, offset) } else { String::new() })
        .replace("@@layout_class@@", if multi { "layout-multi" } else { "layout-single" })
        .replace("@@main_margin@@", if multi { "var(--sidebar-width)" } else { "0" })
        .replace("@@generated_at@@", &fmt_local(now_ms, offset))
        .replace("@@script_nonce@@", &seagent_net::crypto::random_token(16))
        .replace("@@sessions_html@@", &sessions.iter().map(|s| session_view(s, multi, offset)).collect::<Vec<_>>().join("\n"))
}

// ───────────────────────── JSON ─────────────────────────

pub fn render_json(s: &SessionData) -> Value {
    json!({
        "session_id": s.id, "title": s.title, "model": s.model, "cwd": s.workspace,
        "created_at": opt_iso(s.created_ms), "updated_at": opt_iso(s.updated_ms),
        "message_count": s.flats.len(), "tool_call_count": s.tool_call_count(), "system_prompt": s.system,
        "messages": s.flats.iter().map(|f| {
            let mut m = json!({"role": f.role, "content": f.content, "timestamp": opt_iso(f.ts), "id": f.seq});
            if !f.reasoning.is_empty() { m["reasoning"] = json!(f.reasoning); }
            if !f.tool_calls.is_empty() { m["tool_calls"] = openai_tool_calls(f); }
            if f.role == "tool" { m["tool_call_id"] = json!(f.tool_call_id); m["tool_name"] = json!(f.tool_name); m["is_error"] = json!(f.is_error); }
            m
        }).collect::<Vec<_>>(),
    })
}

// ───────────────────────── Hugging Face upload ─────────────────────────

const TOKEN_ENV_VARS: &[&str] = &["HF_TOKEN", "HUGGINGFACE_HUB_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN"];

pub const NO_TOKEN_MESSAGE: &str = "Can't upload — no Hugging Face token is available. To set it up:\n\n1. Create a token with WRITE access at https://huggingface.co/settings/tokens\n   (New token -> type \"Write\" -> copy it).\n2. Store it in the vault: `seagent secrets set HF_TOKEN` (the value is read from stdin)\n   or export HF_TOKEN in the environment.\n3. Run `seagent session upload-trace <id>` (or /upload-trace) again.";

/// Vault secret first (never argv), then the usual environment variables.
pub fn hf_token(vault: &Vault, secret: &str) -> Option<String> {
    let placeholder = format!("{{{{secret:{secret}}}}}");
    let v = vault.substitute(&placeholder);
    if v != placeholder && !v.trim().is_empty() {
        return Some(v.trim().to_string());
    }
    TOKEN_ENV_VARS.iter().find_map(|k| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
}

fn http() -> ureq::Agent {
    seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(std::time::Duration::from_secs(60))).build().into()
}

fn body_json(r: ureq::http::Response<ureq::Body>) -> (u16, Value, String) {
    use std::io::Read;
    let status = r.status().as_u16();
    let mut raw = String::new();
    let _ = r.into_body().into_reader().take(1 << 20).read_to_string(&mut raw);
    (status, serde_json::from_str(&raw).unwrap_or(Value::Null), raw)
}

fn hub_error(v: &Value, raw: &str) -> String {
    v["error"].as_str().map(String::from).unwrap_or_else(|| raw.chars().take(200).collect())
}

/// Create the dataset (idempotently) and commit `sessions/<id>.jsonl` through the
/// Hub HTTP API (`whoami-v2`, `repos/create`, `preupload`, `commit`), as
/// `huggingface_hub.HfApi` does for a small regular file. Returns the status text.
pub fn hf_upload(endpoint: &str, token: &str, dataset: &str, private: bool, session: &str, jsonl: &str) -> Result<String, String> {
    let base = endpoint.trim_end_matches('/');
    let a = http();
    let auth = format!("Bearer {token}");
    let (s, who, _) = body_json(a.get(&format!("{base}/api/whoami-v2")).header("authorization", &auth).call().map_err(|e| format!("Hugging Face unreachable: {e}"))?);
    if s != 200 {
        return Err("Your Hugging Face token was rejected (whoami failed). Make sure it has WRITE access and isn't expired.".into());
    }
    let user = who["name"].as_str().filter(|u| !u.is_empty()).ok_or("Could not resolve your Hugging Face username from the token.")?;
    let repo = format!("{user}/{dataset}");
    let (s, v, raw) = body_json(a.post(&format!("{base}/api/repos/create")).header("authorization", &auth).header("content-type", "application/json").send(json!({"name": dataset, "type": "dataset", "private": private}).to_string().as_bytes()).map_err(|e| e.to_string())?);
    // 409 = already exists (exist_ok=True upstream).
    if !(200..300).contains(&s) && s != 409 {
        return Err(format!("Could not create/access dataset {repo}: {}", hub_error(&v, &raw)));
    }
    let path = format!("sessions/{session}.jsonl");
    let bytes = jsonl.as_bytes();
    let sample = seagent_net::crypto::b64(&bytes[..bytes.len().min(512)]);
    let (s, v, raw) = body_json(a.post(&format!("{base}/api/datasets/{repo}/preupload/main")).header("authorization", &auth).header("content-type", "application/json").send(json!({"files": [{"path": path, "sample": sample, "size": bytes.len()}]}).to_string().as_bytes()).map_err(|e| e.to_string())?);
    if s != 200 {
        return Err(format!("Upload to Hugging Face failed: {}", hub_error(&v, &raw)));
    }
    if v["files"].as_array().and_then(|f| f.iter().find(|x| x["path"] == path.as_str())).and_then(|x| x["uploadMode"].as_str()) == Some("lfs") {
        return Err(format!("Upload to Hugging Face failed: the Hub wants {path} stored with LFS ({} bytes); upload it with `huggingface-cli upload` instead", bytes.len()));
    }
    let body = [json!({"key": "header", "value": {"summary": format!("add session trace {session}"), "description": ""}}), json!({"key": "file", "value": {"content": seagent_net::crypto::b64(bytes), "path": path, "encoding": "base64"}})]
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let (s, v, raw) = body_json(a.post(&format!("{base}/api/datasets/{repo}/commit/main")).header("authorization", &auth).header("content-type", "application/x-ndjson").send(body.as_bytes()).map_err(|e| e.to_string())?);
    if s != 200 {
        return Err(format!("Upload to Hugging Face failed: {}", hub_error(&v, &raw)));
    }
    Ok(format!("Uploaded -> {base}/datasets/{repo}/blob/main/{path}\nView in the trace viewer: {base}/datasets/{repo}"))
}

fn git_branch(cwd: &str) -> String {
    if cwd.is_empty() {
        return String::new();
    }
    std::process::Command::new("git").args(["rev-parse", "--abbrev-ref", "HEAD"]).current_dir(cwd).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

/// Build the Claude Code JSONL trace for a session (redacted unless `redact` is false).
pub fn trace_jsonl(events: &[Event], vault: &Vault, redact: bool) -> (String, String) {
    let mut s = SessionData::from_events(events);
    if redact {
        s.redact(vault);
    }
    (tj::claude_code_trace(&s.flats, &s.id, &s.model, &s.workspace, &git_branch(&s.workspace), seagent_kernel::event::now_ms()), s.id)
}

// ───────────────────────── trajectories ─────────────────────────

/// Append the Hermes ShareGPT entry for a session; returns the file written.
pub fn save_sharegpt(events: &[Event], specs: &[seagent_core::ToolSpec], dir: &Path, file: Option<&Path>) -> Result<PathBuf, String> {
    let s = SessionData::from_events(events);
    let done = tj::completed(events);
    let entry = tj::sharegpt_entry(tj::sharegpt(&s.flats, &tj::tools_for_system_message(specs)), &s.model, done, seagent_kernel::event::now_ms());
    let path = file.map(Path::to_path_buf).unwrap_or_else(|| dir.join(tj::sharegpt_file(done)));
    append_locked(&path, &(entry.to_string() + "\n"))?;
    Ok(path)
}

/// Whole-line append under an exclusive lock so concurrent writers never interleave.
fn append_locked(path: &Path, line: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    if let Some(d) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: flock on our own fd; released on close.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    let r = f.write_all(line.as_bytes()).and_then(|_| f.flush());
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
    r.map_err(|e| e.to_string())
}

/// OpenClaw-style bundle: `<dir>/{manifest.json, events.jsonl, metadata.json}`.
pub fn write_bundle(events: &[Event], dir: &Path, vault: &Vault) -> Result<PathBuf, String> {
    let trace = tj::uuid4();
    let now = seagent_kernel::event::now_ms();
    let evs = tj::bundle_events(events, &trace);
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let red = |s: String| tj::redact_patterns(&vault.redact(&s));
    let lines: String = evs.iter().map(|e| red(e.to_string()) + "\n").collect();
    std::fs::write(dir.join("events.jsonl"), &lines).map_err(|e| e.to_string())?;
    let v = project(events);
    let meta = json!({"sessionId": v.session_id, "title": v.title, "model": v.model, "turns": v.turns, "usage": v.usage, "compactions": v.compactions, "exporter": concat!("seagent ", env!("CARGO_PKG_VERSION"))});
    std::fs::write(dir.join("metadata.json"), red(serde_json::to_string_pretty(&meta).unwrap_or_default())).map_err(|e| e.to_string())?;
    let mut manifest = tj::bundle_manifest(events, &trace, evs.len(), "events.jsonl", now);
    manifest["supplementalFiles"] = json!(["metadata.json"]);
    let contents: Vec<Value> = ["events.jsonl", "metadata.json"].iter().map(|f| json!({"path": f, "mediaType": if f.ends_with("jsonl") { "application/x-ndjson" } else { "application/json" }, "bytes": std::fs::metadata(dir.join(f)).map(|m| m.len()).unwrap_or(0)})).collect();
    manifest["contents"] = json!(contents);
    std::fs::write(dir.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap_or_default()).map_err(|e| e.to_string())?;
    Ok(dir.to_path_buf())
}

// ───────────────────────── CLI ─────────────────────────

fn write_out(out: Option<&str>, text: &str) -> R {
    match out {
        Some("-") | None => {
            print!("{text}");
            Ok(0)
        }
        Some(p) => {
            let p = Path::new(p);
            if let Some(d) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
            }
            std::fs::write(p, text).map_err(|e| format!("{}: {e}", p.display()))?;
            eprintln!("exported to {}", p.display());
            Ok(0)
        }
    }
}

/// `seagent session export <id…> [--format md|qmd|html|json] [--out FILE|DIR] [--no-redact]`.
pub fn cmd_export(a: &Args) -> R {
    let c = crate::build(a, crate::approver_for(a, false))?;
    let fmt = a.val("format").unwrap_or("md");
    if !matches!(fmt, "md" | "qmd" | "html" | "json") {
        return usage(format!("--format {fmt}: use md, qmd, html or json"));
    }
    let ids: Vec<String> = if a.pos.len() > 1 { a.pos[1..].iter().map(|q| find_session(&c.k, q)).collect::<Result<_, _>>()? } else { vec![find_session(&c.k, "last")?] };
    let mut sessions = Vec::new();
    for id in &ids {
        let mut s = SessionData::from_events(&c.k.store.read(id).map_err(|e| e.to_string())?);
        if !a.flag("no-redact") {
            s.redact(&c.k.vault);
        }
        // ent-078: exports leave the box, so personal data is masked unless asked otherwise.
        let mask = c.k.cfg.compliance.pii.exports && !a.flag("keep-pii");
        if mask {
            s.mask_pii(&c.k.cfg.compliance.pii);
        }
        seagent_security::audit::record(&c.k.paths.data, seagent_security::audit::Event::new("session.export", seagent_security::audit::Actor::local(), id, "ok").session(id).detail(json!({"format": fmt, "pii_masked": mask, "secrets_redacted": !a.flag("no-redact")})));
        sessions.push(s);
    }
    let offset = c.k.cfg.schedule.utc_offset_minutes;
    let now = seagent_kernel::event::now_ms();
    let out = a.val("out");
    // A directory target gets `<id>-<slug>.<ext>` per session (plus manifest.jsonl for md).
    if let Some(dir) = out.filter(|o| Path::new(o).is_dir() || o.ends_with('/')) {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        if fmt == "html" && sessions.len() > 1 {
            let p = Path::new(dir).join("sessions.html");
            return write_out(p.to_str(), &render_html(&sessions, offset, now));
        }
        for s in &sessions {
            let text = render_one(s, fmt, offset, now);
            let p = Path::new(dir).join(safe_filename(s, fmt));
            if p.exists() && !a.flag("force") {
                return Err(format!("{} exists (use --force)", p.display()).into());
            }
            std::fs::write(&p, &text).map_err(|e| e.to_string())?;
            if matches!(fmt, "md" | "qmd") {
                let entry = json!({"session_id": s.id, "lineage_session_ids": [s.id], "path": p, "format": fmt, "message_count": s.flats.len(), "sha256": seagent_net::crypto::hex(&seagent_net::crypto::sha256(text.as_bytes())), "exported_at": now as f64 / 1000.0});
                append_locked(&Path::new(dir).join("manifest.jsonl"), &(entry.to_string() + "\n"))?;
            }
            eprintln!("exported {} → {}", s.id, p.display());
        }
        return Ok(0);
    }
    let text = if fmt == "html" { render_html(&sessions, offset, now) } else { sessions.iter().map(|s| render_one(s, fmt, offset, now)).collect::<Vec<_>>().join("\n") };
    write_out(out, &text)
}

pub fn render_one(s: &SessionData, fmt: &str, offset: i32, now: u64) -> String {
    match fmt {
        "html" => render_html(std::slice::from_ref(s), offset, now),
        "json" => serde_json::to_string_pretty(&render_json(s)).unwrap_or_default() + "\n",
        f => render_markdown(s, f, true, now),
    }
}

/// `seagent session verify-export <file> <id>`.
pub fn cmd_verify(a: &Args) -> R {
    let c = crate::build(a, crate::approver_for(a, false))?;
    let file = a.need(1, "file")?;
    let id = find_session(&c.k, a.pos(2).unwrap_or("last"))?;
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let mut s = SessionData::from_events(&c.k.store.read(&id).map_err(|e| e.to_string())?);
    if !a.flag("no-redact") {
        s.redact(&c.k.vault);
    }
    match verify_markdown(text.trim_start_matches('\u{feff}'), &s) {
        Ok(()) => {
            println!("ok");
            Ok(0)
        }
        Err(e) => Err(e.into()),
    }
}

/// `seagent session trajectory <id> [--format sharegpt|bundle] [--out PATH]`.
pub fn cmd_trajectory(a: &Args) -> R {
    let c = crate::build(a, crate::approver_for(a, false))?;
    let id = find_session(&c.k, a.pos(1).unwrap_or("last"))?;
    let events = c.k.store.read(&id).map_err(|e| e.to_string())?;
    match a.val("format").unwrap_or("sharegpt") {
        "sharegpt" => {
            let p = save_sharegpt(&events, &c.k.specs(), &std::env::current_dir().unwrap_or_default(), a.val("out").map(Path::new))?;
            println!("{}", p.display());
            Ok(0)
        }
        "bundle" => {
            let ws = project(&events).workspace;
            let dir = a.val("out").map(PathBuf::from).unwrap_or_else(|| Path::new(&ws).join(".seagent/trajectory-exports").join(tj::bundle_dir_name(&id, seagent_kernel::event::now_ms())));
            println!("{}", write_bundle(&events, &dir, &c.k.vault)?.display());
            Ok(0)
        }
        f => usage(format!("--format {f}: use sharegpt or bundle")),
    }
}

/// `seagent session upload-trace <id> [--dataset NAME] [--public] [--no-redact]`.
pub fn cmd_upload_trace(a: &Args) -> R {
    let c = crate::build(a, crate::approver_for(a, false))?;
    let id = find_session(&c.k, a.pos(1).unwrap_or("last"))?;
    println!("{}", upload_trace(&c.k, &id, a.val("dataset"), !a.flag("public"), !a.flag("no-redact"))?);
    Ok(0)
}

pub fn upload_trace(k: &seagent_kernel::kernel::Kernel, id: &str, dataset: Option<&str>, private: bool, redact: bool) -> Result<String, String> {
    let cfg = &k.cfg.trace;
    let token = hf_token(&k.vault, &cfg.token_secret).ok_or(NO_TOKEN_MESSAGE)?;
    let events = k.store.read(id).map_err(|e| format!("Could not load session {id}: {e}"))?;
    let (jsonl, sid) = trace_jsonl(&events, &k.vault, redact);
    if jsonl.trim().is_empty() {
        return Err("No transcript to upload for this session yet.".into());
    }
    hf_upload(&cfg.endpoint, &token, dataset.unwrap_or(&cfg.dataset), private && cfg.private, &sid, &jsonl)
}

/// Auto-save after `seagent run` when `trajectory.save` is on.
pub fn maybe_save_trajectory(k: &seagent_kernel::kernel::Kernel, id: &str) {
    if !k.cfg.trajectory.save {
        return;
    }
    let dir = if k.cfg.trajectory.dir.is_empty() { std::env::current_dir().unwrap_or_default() } else { seagent_core::tool::expand_home(&k.cfg.trajectory.dir) };
    match k.store.read(id).map_err(|e| e.to_string()).and_then(|ev| save_sharegpt(&ev, &k.specs(), &dir, None)) {
        Ok(p) => eprintln!("• trajectory saved to {}", p.display()),
        Err(e) => eprintln!("seagent: warning: failed to save trajectory: {e}"),
    }
}

/// y/N on the terminal; anything else (or no terminal) is a no.
fn confirm(q: &str) -> bool {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("{q} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut l = String::new();
    std::io::stdin().lock().read_line(&mut l).is_ok() && matches!(l.trim().to_lowercase().as_str(), "y" | "yes")
}

/// `seagent checkpoint status|prune|clear` (the store-wide commands).
pub fn cmd_checkpoint_store(a: &Args, sub: &str) -> R {
    use seagent_kernel::checkpoint::{PruneOpts, Store};
    let paths = seagent_kernel::config::Paths::from_env();
    let store = Store::new(&paths.data);
    let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
    match sub {
        "status" => {
            let st = store.status();
            let lim = a.num::<usize>("limit").map_err(Fail::Usage)?.unwrap_or(20);
            println!("checkpoint store {} · {:.1} MB · {} workspace(s)", st.base.display(), mb(st.total_size_bytes), st.projects.len());
            let mut ps = st.projects.clone();
            ps.sort_by_key(|p| std::cmp::Reverse(p.size_bytes));
            for p in ps.iter().take(lim) {
                let touched = if p.last_touch > 0 { seagent_kernel::util::fmt_time(p.last_touch, 480) } else { "unknown".into() };
                println!("{}  {:>8.1} MB  {:>3} snapshots  last {touched}  {}{}", p.id, mb(p.size_bytes), p.snapshots, if p.workdir.is_empty() { "(workspace unknown)" } else { &p.workdir }, if !p.workdir.is_empty() && !p.exists { "  [missing]" } else { "" });
            }
            Ok(0)
        }
        "prune" => {
            let cfg = crate::load_config(a, &crate::workspace(a)?, &paths)?;
            let keep_orphans = a.flag("keep-orphans");
            let retention = a.num::<u32>("retention-days").map_err(Fail::Usage)?.unwrap_or(cfg.checkpoint.retention_days);
            let cap = a.num::<u64>("max-size-mb").map_err(Fail::Usage)?.unwrap_or(cfg.checkpoint.max_total_size_mb);
            if !keep_orphans && !a.flag("force") && !a.flag("yes") {
                let orphans: Vec<_> = store.status().projects.into_iter().filter(|p| !p.workdir.is_empty() && !p.exists).collect();
                if !orphans.is_empty() {
                    eprintln!("{} workspace(s) no longer exist; their checkpoints will be deleted if the deletion is observable:", orphans.len());
                    for o in &orphans {
                        eprintln!("  {}", o.workdir);
                    }
                    if !confirm("Delete them?") {
                        return Err("aborted (use --keep-orphans to skip them, --force to skip this prompt)".into());
                    }
                }
            }
            let r = store.prune(PruneOpts { retention_days: retention, delete_orphans: !keep_orphans, max_total_bytes: cap * 1024 * 1024 });
            println!("scanned {} · deleted {} orphan, {} stale · reclaimed {:.1} MB{}", r.scanned, r.deleted_orphan, r.deleted_stale, mb(r.bytes_freed), if r.errors > 0 { format!(" · {} error(s)", r.errors) } else { String::new() });
            Ok(if r.errors > 0 { 1 } else { 0 })
        }
        "clear" => {
            if !a.flag("force") && !a.flag("yes") && !confirm("Delete ALL checkpoints (every workspace's undo history)?") {
                return Err("aborted".into());
            }
            println!("cleared · {:.1} MB freed", mb(store.clear()?));
            Ok(0)
        }
        other => usage(format!("unknown `checkpoint {other}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::{Block, Message, Role};
    use seagent_kernel::event::{EventKind, LOG_VERSION};
    use std::io::{BufRead, BufReader, Read, Write};

    fn evs() -> Vec<Event> {
        let kinds = vec![
            EventKind::Header { version: LOG_VERSION, session_id: "sess1".into(), workspace: "/w".into(), model: "anthropic/claude".into(), parent: None, title: Some("Fix <b>bug</b>".into()) },
            EventKind::System { segments: vec![seagent_core::SystemSegment { id: "identity".into(), text: "You are SE Agent".into(), cache: false }] },
            EventKind::Message { message: Message::user("deploy with sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX please"), usage: None, model: None, inbox: None },
            EventKind::Message { message: Message { role: Role::Assistant, content: vec![Block::text("ok"), Block::ToolUse { id: "t1".into(), name: "shell".into(), input: json!({"command": "<rm>"}) }] }, usage: None, model: None, inbox: None },
            EventKind::Message { message: Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "t1".into(), content: "done".into(), is_error: false }] }, usage: None, model: None, inbox: None },
        ];
        kinds.into_iter().enumerate().map(|(i, k)| Event { seq: i as u64, ts: 1_700_000_000_000 + i as u64 * 1000, kind: k }).collect()
    }

    #[test]
    fn markdown_has_frontmatter_messages_and_verifiable_digest() {
        let mut s = SessionData::from_events(&evs());
        s.redact(&Vault::empty());
        let md = render_markdown(&s, "md", true, 1_700_000_100_000);
        assert!(md.starts_with("---\nsession_id: \"sess1\"\ntitle: \"Fix <b>bug</b>\""));
        assert!(md.contains("message_count: 3") && md.contains("tool_call_count: 1") && md.contains("format: \"md\""));
        assert!(md.contains("### User — 2023-11-14T22:13:22Z") && md.contains("### Tool — shell"));
        assert!(md.contains("## Tool calls\n\n```json") && md.contains("\"name\": \"shell\""));
        assert!(!md.contains("sk-ant-ABC"), "redacted");
        verify_markdown(&md, &s).unwrap();
        assert_eq!(verify_markdown(&md.replace("ok\n", "OK\n"), &s).unwrap_err(), "sha256 mismatch");
        assert!(!render_markdown(&s, "qmd", false, 0).contains("Export verification"));
        assert_eq!(safe_filename(&s, "md"), "sess1-fix-b-bug-b.md");
    }

    #[test]
    fn html_is_standalone_escaped_and_collapsible() {
        let s = SessionData::from_events(&evs());
        let h = render_html(std::slice::from_ref(&s), 480, 0);
        assert!(h.starts_with("<!DOCTYPE html>") && !h.contains("@@"));
        assert!(h.contains("<title>Fix &lt;b&gt;bug&lt;/b&gt;</title>"));
        assert!(h.contains("class=\"tool-call\"") && h.contains("Tool Call: shell") && h.contains("&lt;rm&gt;"));
        assert!(h.contains("System Prompt (Persona)") && h.contains("message-tool"));
        assert!(!h.contains("googleapis") && !h.contains("src=\"http"), "no remote dependencies");
        let nonce = h.split("'nonce-").nth(1).unwrap().split('\'').next().unwrap().to_string();
        assert!(h.contains(&format!("<script nonce=\"{nonce}\">")));
        let mut t = SessionData::from_events(&evs());
        t.id = "other".into();
        let multi = render_html(&[s, t], 480, 0);
        assert!(multi.contains("session-search") && multi.contains("data-id=\"other\"") && multi.contains("layout-multi"));
        assert!(render_html(&[], 0, 0).contains("No sessions"));
    }

    #[test]
    fn json_export_shape() {
        let v = render_json(&SessionData::from_events(&evs()));
        assert_eq!(v["message_count"], 3);
        assert_eq!(v["messages"][1]["tool_calls"][0]["function"]["name"], "shell");
        assert_eq!(v["messages"][2]["tool_call_id"], "t1");
    }

    #[test]
    fn sharegpt_and_bundle_files() {
        let dir = seagent_core::tmp::scratch_path(format!("seagent-traj-{}", seagent_kernel::util::random_hex(6)));
        let p = save_sharegpt(&evs(), &[], &dir, None).unwrap();
        assert!(p.ends_with("failed_trajectories.jsonl"), "no clean turn end → failed");
        save_sharegpt(&evs(), &[], &dir, None).unwrap();
        let lines: Vec<Value> = std::fs::read_to_string(&p).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["conversations"][1]["from"], "human");
        let vault = Vault::empty();
        let b = write_bundle(&evs(), &dir.join("bundle"), &vault).unwrap();
        let m: Value = serde_json::from_str(&std::fs::read_to_string(b.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m["traceSchema"], "openclaw-trajectory");
        let n = std::fs::read_to_string(b.join("events.jsonl")).unwrap();
        assert_eq!(n.lines().count() as u64, m["eventCount"].as_u64().unwrap());
        assert!(!n.contains("sk-ant-ABC"));
    }

    /// Minimal Hub: whoami, repos/create (409 the second time), preupload, commit.
    /// (path, authorization, body) per request.
    type Seen = std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>;

    fn fake_hub(reject_token: bool) -> (String, Seen) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", l.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            let mut created = false;
            for conn in l.incoming().flatten() {
                let mut r = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let (mut len, mut auth) = (0usize, String::new());
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    let lower = h.to_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if lower.starts_with("authorization:") {
                        auth = h["authorization:".len()..].trim().to_string();
                    }
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let path = line.split_whitespace().nth(1).unwrap().to_string();
                s2.lock().unwrap().push((path.clone(), auth.clone(), String::from_utf8_lossy(&body).to_string()));
                let (code, resp) = if auth != "Bearer hf_test" || reject_token {
                    (401, json!({"error": "Invalid credentials"}))
                } else if path == "/api/whoami-v2" {
                    (200, json!({"name": "amy", "type": "user"}))
                } else if path == "/api/repos/create" {
                    let c = if created { 409 } else { 200 };
                    created = true;
                    (c, json!({"url": "x"}))
                } else if path.ends_with("/preupload/main") {
                    (200, json!({"files": [{"path": "sessions/sess1.jsonl", "uploadMode": "regular"}]}))
                } else if path.ends_with("/commit/main") {
                    (200, json!({"commitOid": "abc", "success": true}))
                } else {
                    (404, json!({"error": "nope"}))
                };
                let b = resp.to_string();
                let mut w = conn;
                let _ = write!(w, "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{b}", b.len());
            }
        });
        (addr, seen)
    }

    #[test]
    fn hf_upload_creates_private_dataset_and_commits_the_trace() {
        let (url, seen) = fake_hub(false);
        let vault = Vault::empty();
        let (jsonl, sid) = trace_jsonl(&evs(), &vault, true);
        assert!(!jsonl.contains("sk-ant-ABC"));
        let msg = hf_upload(&url, "hf_test", "seagent-traces", true, &sid, &jsonl).unwrap();
        assert!(msg.contains("/datasets/amy/seagent-traces/blob/main/sessions/sess1.jsonl"), "{msg}");
        // Second upload: repo exists (409) is fine.
        hf_upload(&url, "hf_test", "seagent-traces", true, &sid, &jsonl).unwrap();
        let s = seen.lock().unwrap();
        assert_eq!(s[1].0, "/api/repos/create");
        let create: Value = serde_json::from_str(&s[1].2).unwrap();
        assert_eq!(create, json!({"name": "seagent-traces", "type": "dataset", "private": true}));
        assert_eq!(s[2].0, "/api/datasets/amy/seagent-traces/preupload/main");
        let commit: Vec<Value> = s[3].2.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(commit[0]["value"]["summary"], "add session trace sess1");
        assert_eq!(commit[1]["value"]["path"], "sessions/sess1.jsonl");
        let raw = seagent_net::crypto::b64_decode(commit[1]["value"]["content"].as_str().unwrap()).unwrap();
        assert_eq!(String::from_utf8(raw).unwrap(), jsonl);
        drop(s);
        let (url, _) = fake_hub(true);
        assert!(hf_upload(&url, "hf_test", "d", true, "s", "x\n").unwrap_err().contains("whoami failed"));
    }

    #[test]
    fn token_comes_from_the_vault() {
        let v = Vault::empty();
        v.set("HF_TOKEN", "hf_fromvault").unwrap();
        assert_eq!(hf_token(&v, "HF_TOKEN").as_deref(), Some("hf_fromvault"));
    }
}
