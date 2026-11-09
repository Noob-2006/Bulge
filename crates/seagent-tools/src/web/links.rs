//! Link understanding for inbound channel messages (OpenClaw `src/link-understanding/*`).
//!
//! Bare http(s) URLs in the user's text (markdown links / autolinks are display-only and
//! skipped; private / internal targets are dropped) are fetched through the SSRF guard,
//! and each page body is piped on stdin to the configured `cli` processors in order: the
//! first non-empty stdout wins, else the fetched body itself is used. The outputs are
//! appended to the message body, one per line, after a blank line.

use super::config::{LinkScope, LinksConfig, WebConfig};
use super::ssrf::{self, SsrfPolicy};
use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

/// Default per-link fetch and CLI timeout, seconds (OpenClaw `DEFAULT_LINK_TIMEOUT_SECONDS`).
pub const DEFAULT_LINK_TIMEOUT_SECONDS: u64 = 30;
/// Default cap for links taken from one message (OpenClaw `DEFAULT_MAX_LINKS`).
pub const DEFAULT_MAX_LINKS: usize = 3;
/// Fetched body / processor stdout cap (OpenClaw `CLI_OUTPUT_MAX_BUFFER`, 5 MB).
pub const MAX_OUTPUT_BYTES: usize = 5 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const USER_AGENT: &str = "seagent-LinkUnderstanding/1.0";
const ACCEPT: &str = "text/*,application/json,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// The inbound message as link understanding sees it.
#[derive(Debug, Clone, Default)]
pub struct LinkMessage<'a> {
    /// The user's own text: links are detected here (OpenClaw `CommandBody ?? RawBody ?? Body`).
    pub text: &'a str,
    /// Channel id (`telegram`, `slack`, …): scope `channel`, template `{{Provider}}` / `{{Surface}}`.
    pub channel: &'a str,
    /// `direct` | `group` | `channel` | `thread` (`dm` = direct).
    pub chat_type: &'a str,
    /// Scope `key_prefix` is matched against this (seagent: `<channel>:<chat_type>:<chat>[:<sender>]`).
    pub session_key: &'a str,
    pub sender: &'a str,
    pub sender_name: &'a str,
}

// ── detection (OpenClaw detect.ts) ──

/// Unique, SSRF-filtered bare http(s) links from inbound text, at most `max_links` (default 3).
/// Markdown links, images and autolinks are ignored so display-only citations do not trigger fetches.
pub fn extract_links(message: &str, max_links: Option<usize>, policy: &SsrfPolicy) -> Vec<String> {
    let source = message.trim();
    if source.is_empty() {
        return vec![];
    }
    let max = max_links.filter(|&n| n > 0).unwrap_or(DEFAULT_MAX_LINKS);
    let sanitized = strip_markdown_links(source);
    let mut out: Vec<String> = Vec::new();
    for raw in bare_links(&sanitized) {
        if !is_allowed_url(raw, policy) || out.iter().any(|s| s == raw) {
            continue;
        }
        out.push(raw.to_string());
        if out.len() >= max {
            break;
        }
    }
    out
}

fn is_allowed_url(raw: &str, policy: &SsrfPolicy) -> bool {
    ssrf::parse_url(raw).is_ok_and(|u| ssrf::check_host(&u.host, u.scheme == "https", policy).is_ok())
}

fn is_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// `/https?:\/\/\S+/gi` matches.
fn bare_links(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let rest = &b[i..];
        let prefix = if rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(b"https://") {
            8
        } else if rest.len() >= 7 && rest[..7].eq_ignore_ascii_case(b"http://") {
            7
        } else {
            i += 1;
            continue;
        };
        let tail = &s[i + prefix..];
        let len = tail.find(is_space).unwrap_or(tail.len());
        if len == 0 {
            i += prefix;
            continue;
        }
        out.push(&s[i..i + prefix + len]);
        i += prefix + len;
    }
    out
}

/// Replace every markdown inline link / image / autolink span with a space.
fn strip_markdown_links(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    for (start, end) in markdown_link_spans(s) {
        out.push_str(&s[cursor..start]);
        out.push(' ');
        cursor = end;
    }
    out.push_str(&s[cursor..]);
    out
}

/// Source spans of CommonMark inline links (`[text](dest "title")`), images and `<scheme:…>`
/// autolinks; code spans are skipped (OpenClaw `findMarkdownLinkSourceSpans`).
fn markdown_link_spans(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'`' => i = skip_code_span(b, i),
            b'<' => match autolink_end(b, i) {
                Some(end) => {
                    spans.push((i, end));
                    i = end;
                }
                None => i += 1,
            },
            b'[' => match inline_link_end(b, i) {
                Some(end) => {
                    let start = if i > 0 && b[i - 1] == b'!' { i - 1 } else { i };
                    spans.push((start, end));
                    i = end;
                }
                None => i += 1,
            },
            _ => i += 1,
        }
    }
    spans
}

fn run_len(b: &[u8], i: usize, c: u8) -> usize {
    b[i..].iter().take_while(|&&x| x == c).count()
}

/// Past a backtick code span opened at `i` (or past the run when it never closes).
fn skip_code_span(b: &[u8], i: usize) -> usize {
    let n = run_len(b, i, b'`');
    let mut j = i + n;
    while j < b.len() {
        if b[j] == b'`' {
            let m = run_len(b, j, b'`');
            if m == n {
                return j + m;
            }
            j += m;
        } else {
            j += 1;
        }
    }
    i + n
}

/// `<scheme:non-space>` (CommonMark URI autolink).
fn autolink_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if !b.get(j)?.is_ascii_alphabetic() {
        return None;
    }
    let s0 = j;
    while j < b.len() && (b[j].is_ascii_alphanumeric() || matches!(b[j], b'+' | b'.' | b'-')) {
        j += 1;
    }
    if !(2..=32).contains(&(j - s0)) || b.get(j) != Some(&b':') {
        return None;
    }
    j += 1;
    while j < b.len() {
        match b[j] {
            b'>' => return Some(j + 1),
            b'<' => return None,
            c if c <= b' ' => return None,
            _ => j += 1,
        }
    }
    None
}

/// Spaces / tabs with at most one line ending; None on a blank line.
fn skip_ws(b: &[u8], mut j: usize) -> Option<usize> {
    let mut newlines = 0;
    while j < b.len() && matches!(b[j], b' ' | b'\t' | b'\n' | b'\r') {
        if b[j] == b'\n' {
            newlines += 1;
            if newlines > 1 {
                return None;
            }
        }
        j += 1;
    }
    Some(j)
}

/// End (exclusive) of an inline link whose label opens at `open`.
fn inline_link_end(b: &[u8], open: usize) -> Option<usize> {
    // Label: balanced brackets, backslash escapes.
    let (mut depth, mut j) = (1usize, open + 1);
    while j < b.len() {
        match b[j] {
            b'\\' => j += 1,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        j += 1;
    }
    if depth != 0 || b.get(j + 1) != Some(&b'(') {
        return None;
    }
    j = skip_ws(b, j + 2)?;
    // Destination.
    if b.get(j) == Some(&b'<') {
        j += 1;
        loop {
            match *b.get(j)? {
                b'\\' => j += 2,
                b'>' => {
                    j += 1;
                    break;
                }
                b'<' | b'\n' | b'\r' => return None,
                _ => j += 1,
            }
        }
    } else {
        let mut parens = 0usize;
        while j < b.len() {
            match b[j] {
                b'\\' => j += 1,
                b'(' => {
                    parens += 1;
                    if parens > 32 {
                        return None;
                    }
                }
                b')' if parens == 0 => break,
                b')' => parens -= 1,
                c if c <= b' ' || c == 0x7f => break,
                _ => {}
            }
            j += 1;
        }
        if parens != 0 {
            return None;
        }
    }
    let after_dest = j;
    j = skip_ws(b, j)?;
    if b.get(j) == Some(&b')') {
        return Some(j + 1);
    }
    // Title must be separated from the destination by whitespace.
    let close = match *b.get(j)? {
        b'"' => b'"',
        b'\'' => b'\'',
        b'(' => b')',
        _ => return None,
    };
    if j == after_dest {
        return None;
    }
    let open_c = b[j];
    j += 1;
    let mut newline_run = false;
    loop {
        let c = *b.get(j)?;
        match c {
            b'\\' => j += 2,
            _ if c == close => {
                j += 1;
                break;
            }
            b'(' if open_c == b'(' => return None,
            b'\n' => {
                if newline_run {
                    return None; // blank line ends the paragraph
                }
                newline_run = true;
                j += 1;
            }
            b' ' | b'\t' | b'\r' => j += 1,
            _ => {
                newline_run = false;
                j += 1;
            }
        }
    }
    j = skip_ws(b, j)?;
    (b.get(j) == Some(&b')')).then_some(j + 1)
}

// ── scope (OpenClaw media-understanding/resolve.ts `resolveScopeDecision`) ──

/// `dm` → `direct`; unknown types are None.
fn normalize_chat_type(raw: Option<&str>) -> Option<String> {
    let v = raw?.trim().to_ascii_lowercase();
    match v.as_str() {
        "dm" => Some("direct".into()),
        "direct" | "group" | "channel" | "thread" => Some(v),
        _ => None,
    }
}

fn lower(v: Option<&str>) -> Option<String> {
    v.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty())
}

/// First matching rule wins; then `default` (allow when unset). True = allowed.
pub fn scope_allows(scope: Option<&LinkScope>, msg: &LinkMessage) -> bool {
    let Some(scope) = scope else { return true };
    let channel = lower(Some(msg.channel));
    let chat_type = normalize_chat_type(Some(msg.chat_type));
    let key = lower(Some(msg.session_key)).unwrap_or_default();
    for rule in &scope.rules {
        let m = rule.matches.as_ref();
        fn pick<'s>(a: Option<&'s String>, b: &'s Option<String>) -> Option<&'s str> {
            a.or(b.as_ref()).map(|s| s.as_str())
        }
        let r_channel = lower(pick(m.and_then(|m| m.channel.as_ref()), &rule.channel));
        let r_chat = normalize_chat_type(pick(m.and_then(|m| m.chat_type.as_ref()), &rule.chat_type));
        let r_prefix = lower(pick(m.and_then(|m| m.key_prefix.as_ref()), &rule.key_prefix));
        if r_channel.is_some() && r_channel != channel {
            continue;
        }
        if r_chat.is_some() && r_chat != chat_type {
            continue;
        }
        if r_prefix.as_ref().is_some_and(|p| !key.starts_with(p.as_str())) {
            continue;
        }
        return !rule.action.trim().eq_ignore_ascii_case("deny");
    }
    !scope.default.as_deref().is_some_and(|d| d.trim().eq_ignore_ascii_case("deny"))
}

// ── templating (OpenClaw `applyTemplate`) ──

/// `{{Key}}` from the message context; unknown keys become empty.
fn apply_template(arg: &str, msg: &LinkMessage, body: &str) -> String {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"\{\{\s*(\w+)\s*\}\}").expect("template regex"));
    re.replace_all(arg, |c: &regex::Captures| {
        match &c[1] {
            "Body" | "BodyForAgent" => body,
            "RawBody" | "CommandBody" | "BodyForCommands" => msg.text,
            "Provider" | "Surface" | "OriginatingChannel" => msg.channel,
            "ChatType" => msg.chat_type,
            "SessionKey" => msg.session_key,
            "From" | "SenderId" => msg.sender,
            "SenderName" => msg.sender_name,
            _ => "",
        }
        .to_string()
    })
    .into_owned()
}

fn is_link_url_template(v: &str) -> bool {
    v.contains("LinkUrl") || v.contains("LinkFinalUrl")
}

// ── fetch (guarded, strict) ──

/// A fetched page: trimmed body and the URL after redirects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub content: String,
    pub final_url: String,
}

/// GET under the SSRF guard (every hop re-checked), redirects ≤ 3, body ≤ 5 MB.
/// Ok(None) for an empty body; Err for a block, non-2xx, overflow or transport failure.
pub fn fetch_link(cfg: &WebConfig, home: &Path, url: &str, timeout_secs: u64) -> Result<Option<Fetched>, String> {
    let policy = Arc::new(SsrfPolicy::from_config(cfg));
    let agent = ssrf::guarded_agent(policy.clone(), timeout_secs);
    let mut cur = ssrf::normalize_url_for_request(url);
    for hop in 0..=MAX_REDIRECTS + 1 {
        if hop > MAX_REDIRECTS {
            return Err(format!("Too many redirects (limit: {MAX_REDIRECTS})"));
        }
        ssrf::check_url(&cur, &policy)?;
        if let Some(b) = super::policy::check(&cfg.blocklist, home, &cur) {
            return Err(b);
        }
        let mut resp = agent.get(&cur).header("Accept", ACCEPT).header("User-Agent", USER_AGENT).call().map_err(|e| ssrf::error_text(&e))?;
        let status = resp.status();
        if status.is_redirection() {
            if let Some(loc) = resp.headers().get("location").and_then(|l| l.to_str().ok()) {
                cur = ssrf::normalize_url_for_request(&ssrf::join_url(&cur, loc));
                continue;
            }
        }
        if !status.is_success() {
            return Err(format!("Link fetch failed with HTTP {}", status.as_u16()));
        }
        let mut raw = Vec::new();
        resp.body_mut().with_config().limit(u64::MAX).reader().take(MAX_OUTPUT_BYTES as u64 + 1).read_to_end(&mut raw).map_err(|e| format!("reading link body failed: {e}"))?;
        if raw.len() > MAX_OUTPUT_BYTES {
            return Err(format!("Content too large (limit: {MAX_OUTPUT_BYTES} bytes)"));
        }
        let content = String::from_utf8_lossy(&raw).trim().to_string();
        return Ok((!content.is_empty()).then_some(Fetched { content, final_url: cur }));
    }
    unreachable!("redirect loop always returns")
}

// ── processors (OpenClaw `runCommandWithTimeout` with killProcessTree) ──

/// Run `argv` with `input` on stdin; trimmed stdout on exit 0. The process group is killed
/// on timeout (also when descendants keep stdout open past the deadline).
pub fn run_cli(argv: &[String], input: &str, timeout: Duration, env: &[(&str, &str)]) -> Result<String, String> {
    let (cmd, args) = argv.split_first().ok_or("empty command")?;
    // Unix: `Command::new(cmd)`; Windows: PATHEXT shims, `sh` = Git Bash, `python3` = `py -3`.
    let mut c = seagent_core::platform::layout::program_command(cmd);
    seagent_core::platform::layout::msys_args(&mut c, args);
    c.envs(env.iter().copied()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    // Own process group (Windows: a kill-on-close job), so the whole tree can be killed.
    let mut child = crate::exec::local::spawn_own_group(&mut c).map_err(|e| format!("spawn failed: {e}"))?;
    let pgid = child.id() as i32;
    let kill_group = || crate::exec::local::kill_group_now(pgid);
    if let Some(mut stdin) = child.stdin.take() {
        let data = input.as_bytes().to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let (tx, rx) = mpsc::channel();
    if let Some(mut out) = child.stdout.take() {
        std::thread::spawn(move || {
            let (mut buf, mut chunk) = (Vec::new(), [0u8; 8192]);
            loop {
                match out.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    // Past the cap keep draining so the child never blocks on a full pipe.
                    Ok(n) if buf.len() < MAX_OUTPUT_BYTES => buf.extend_from_slice(&chunk[..n.min(MAX_OUTPUT_BYTES - buf.len())]),
                    Ok(_) => {}
                }
            }
            let _ = tx.send(buf);
        });
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                kill_group();
                let _ = child.wait();
                return Err(format!("timed out after {}s", timeout.as_secs_f64()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                kill_group();
                return Err(format!("wait failed: {e}"));
            }
        }
    };
    let stdout = match rx.recv_timeout(deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(50))) {
        Ok(b) => b,
        Err(_) => {
            kill_group();
            return Err(format!("timed out after {}s (output still open)", timeout.as_secs_f64()));
        }
    };
    if !status.success() {
        return Err(format!("exited with code {}", status.code().map_or("unknown".into(), |c| c.to_string())));
    }
    Ok(String::from_utf8_lossy(&stdout).trim().to_string())
}

fn timeout_secs(v: Option<u64>) -> u64 {
    v.unwrap_or(DEFAULT_LINK_TIMEOUT_SECONDS).max(1)
}

/// Fetch timeout: the global one, else the slowest processor's.
pub fn fetch_timeout(cfg: &LinksConfig) -> u64 {
    match cfg.timeout_seconds {
        Some(t) => timeout_secs(Some(t)),
        None => cfg.models.iter().map(|m| timeout_secs(m.timeout_seconds)).max().unwrap_or(DEFAULT_LINK_TIMEOUT_SECONDS),
    }
}

/// Processors for one fetched link: first non-empty stdout, else the page body itself.
/// Fetch-only `curl` / `wget` entries naming `{{LinkUrl}}` are answered by the guarded fetch
/// (never run against an attacker-chosen URL).
fn process(cfg: &LinksConfig, msg: &LinkMessage, body: &str, url: &str, fetched: &Fetched) -> String {
    for entry in &cfg.models {
        if entry.kind.as_deref().map(str::trim).unwrap_or("cli") != "cli" {
            continue;
        }
        let command = entry.command.trim();
        if command.is_empty() {
            continue;
        }
        let name = command.rsplit(['/', '\\']).next().unwrap_or(command).to_ascii_lowercase();
        if (name == "curl" || name == "wget") && entry.args.iter().any(|a| is_link_url_template(a)) {
            return fetched.content.clone();
        }
        let mut argv = vec![command.to_string()];
        argv.extend(entry.args.iter().filter(|a| !is_link_url_template(a)).map(|a| apply_template(a, msg, body)));
        let timeout = Duration::from_secs(timeout_secs(entry.timeout_seconds.or(cfg.timeout_seconds)));
        let env = [("SEAGENT_LINK_URL", url), ("SEAGENT_LINK_FINAL_URL", fetched.final_url.as_str()), ("OPENCLAW_LINK_URL", url), ("OPENCLAW_LINK_FINAL_URL", fetched.final_url.as_str())];
        match run_cli(&argv, &fetched.content, timeout, &env) {
            Ok(out) if !out.is_empty() => return out,
            Ok(_) => {}
            // Content-free log: neither the URL nor the page goes to the log.
            Err(e) => eprintln!("seagent: link understanding: processor `{name}` failed ({e}); trying the next entry"),
        }
    }
    fetched.content.clone()
}

/// One output per link that fetched non-empty (in message order). Empty when disabled,
/// denied by scope, without links or without processors.
pub fn understand_links(cfg: &WebConfig, home: &Path, msg: &LinkMessage, body: &str) -> Vec<String> {
    let lc = &cfg.links;
    if !lc.enabled || !scope_allows(lc.scope.as_ref(), msg) {
        return vec![];
    }
    let links = extract_links(msg.text, lc.max_links, &SsrfPolicy::from_config(cfg));
    if links.is_empty() || lc.models.is_empty() {
        return vec![];
    }
    let timeout = fetch_timeout(lc);
    let mut outputs = Vec::new();
    for url in &links {
        match fetch_link(cfg, home, url, timeout) {
            Ok(Some(f)) => outputs.push(process(lc, msg, body, url, &f)),
            Ok(None) => {}
            Err(_) => eprintln!("seagent: link understanding: fetch blocked or failed"),
        }
    }
    outputs
}

/// `body` + blank line + outputs joined by newlines (just the outputs when `body` is blank).
pub fn enrich(body: &str, outputs: &[String]) -> String {
    let suffix = outputs.join("\n");
    let base = body.trim();
    if base.is_empty() {
        suffix
    } else {
        format!("{base}\n\n{suffix}")
    }
}

/// The augmented message body, or None when link understanding added nothing.
/// `body` is the prompt being built (also `{{Body}}` in processor args).
pub fn apply_link_understanding(cfg: &WebConfig, home: &Path, msg: &LinkMessage, body: &str) -> Option<String> {
    let outputs = understand_links(cfg, home, msg, body);
    (!outputs.is_empty()).then(|| enrich(body, &outputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::config::{LinkModel, LinkScopeMatch, LinkScopeRule};
    use crate::web::testutil::FakeServer;
    use serde_json::json;

    fn strict() -> SsrfPolicy {
        SsrfPolicy::default()
    }

    // detect.test.ts

    #[test]
    fn dedupes_links_and_enforces_max_links() {
        let l = extract_links("https://a.example https://a.example https://b.test https://c.test", Some(2), &strict());
        assert_eq!(l, vec!["https://a.example", "https://b.test"]);
        let l = extract_links("https://a.example https://b.test https://c.test https://d.test", None, &strict());
        assert_eq!(l.len(), DEFAULT_MAX_LINKS);
        assert_eq!(extract_links("https://a.example https://b.test", Some(0), &strict()).len(), 2);
    }

    #[test]
    fn ignores_markdown_links_whose_label_contains_brackets() {
        assert!(extract_links("Check [my notes [v2]](https://internal.example/doc) for details", None, &strict()).is_empty());
    }

    #[test]
    fn ignores_markdown_links_with_a_title_line_break() {
        let l = extract_links("[doc](https://docs.example \"line one\nline two\") https://bare.example", None, &strict());
        assert_eq!(l, vec!["https://bare.example"]);
    }

    #[test]
    fn does_not_strip_a_link_with_an_escaped_closing_delimiter() {
        assert_eq!(extract_links("[doc](https://docs.example \"t\\\")", None, &strict()), vec!["https://docs.example"]);
    }

    #[test]
    fn blocks_loopback_and_private_targets() {
        assert_eq!(extract_links("http://127.0.0.1/test https://ok.test", None, &strict()), vec!["https://ok.test"]);
        assert!(extract_links("http://[2001:db8:1234::5efe:127.0.0.1]/secret", None, &strict()).is_empty());
        assert!(extract_links("http://localhost:8080/ http://printer.local/ http://169.254.169.254/latest http://10.0.0.1/ http://2130706433/", None, &strict()).is_empty());
        assert!(extract_links("ftp://example.com/x mailto:a@b.c", None, &strict()).is_empty());
    }

    // runner.transport.test.ts "fetches bare URLs in order while ignoring titled markdown links"
    #[test]
    fn ignores_titled_angle_image_and_autolinks() {
        let msg = "[quoted](https://h.test/quoted \"Docs\") https://h.test/bare-one [angle](<https://h.test/angle> 'Docs') ![img](https://h.test/i.png) <https://h.test/auto> https://h.test/bare-two";
        assert_eq!(extract_links(msg, None, &strict()), vec!["https://h.test/bare-one", "https://h.test/bare-two"]);
        // Inside a code span a link is literal text: its URL counts as bare.
        assert_eq!(extract_links("`[a](https://h.test/code)`", None, &strict()), vec!["https://h.test/code)`"]);
        assert_eq!(extract_links("HTTPS://Up.test/x, then", None, &strict()), vec!["HTTPS://Up.test/x,"]);
        assert!(extract_links("   ", None, &strict()).is_empty());
    }

    // scope (runner.test.ts "applies shared media scope rules to link message context")

    fn m<'a>(channel: &'a str, chat_type: &'a str, key: &'a str) -> LinkMessage<'a> {
        LinkMessage { text: "see https://example.com/page", channel, chat_type, session_key: key, ..Default::default() }
    }

    #[test]
    fn scope_rules_first_match_and_default() {
        let rule = |action: &str, ch: Option<&str>, ct: Option<&str>, kp: Option<&str>| LinkScopeRule { action: action.into(), channel: ch.map(Into::into), chat_type: ct.map(Into::into), key_prefix: kp.map(Into::into), matches: None };
        let scope = LinkScope { default: Some("allow".into()), rules: vec![rule("deny", Some("Slack"), Some("channel"), Some("agent:main:"))] };
        assert!(!scope_allows(Some(&scope), &m("slack", "channel", "agent:main:slack:channel:C123")));
        assert!(scope_allows(Some(&scope), &m("slack", "group", "agent:main:slack:channel:C123")));
        assert!(scope_allows(Some(&scope), &m("slack", "channel", "other:")));
        assert!(scope_allows(Some(&scope), &m("discord", "channel", "agent:main:x")));
        assert!(scope_allows(None, &m("x", "direct", "")));
        let scope = LinkScope { default: Some("deny".into()), rules: vec![rule("allow", None, Some("dm"), None), rule("deny", None, None, None)] };
        assert!(scope_allows(Some(&scope), &m("telegram", "direct", "k")));
        assert!(!scope_allows(Some(&scope), &m("telegram", "group", "k")));
        assert!(!scope_allows(Some(&LinkScope { default: Some("deny".into()), rules: vec![] }), &m("x", "direct", "")));
        // OpenClaw `match` shape overrides the flat keys.
        let r = LinkScopeRule { action: "deny".into(), channel: Some("discord".into()), matches: Some(LinkScopeMatch { channel: Some("slack".into()), ..Default::default() }), ..Default::default() };
        let scope = LinkScope { default: None, rules: vec![r] };
        assert!(!scope_allows(Some(&scope), &m("slack", "group", "")));
        assert!(scope_allows(Some(&scope), &m("discord", "group", "")));
        let cfg = WebConfig::from_value(json!({"links":{"scope":{"rules":[{"action":"deny","match":{"chatType":"group","keyPrefix":"tg:"}}]}}})).unwrap();
        assert!(!scope_allows(cfg.links.scope.as_ref(), &m("x", "group", "tg:1")));
    }

    #[test]
    fn templates_and_url_args() {
        let msg = LinkMessage { text: "raw https://x.test", channel: "slack", chat_type: "group", session_key: "k", sender: "u1", sender_name: "Ann" };
        assert_eq!(apply_template("{{Body}}|{{ RawBody }}|{{Provider}}|{{ChatType}}|{{SessionKey}}|{{SenderName}}|{{Nope}}", &msg, "B"), "B|raw https://x.test|slack|group|k|Ann|");
        assert!(is_link_url_template("{{LinkUrl}}") && is_link_url_template("--u={{LinkFinalUrl}}") && !is_link_url_template("{{Body}}"));
    }

    // runner

    fn sh(script: &str) -> Vec<String> {
        vec!["sh".into(), "-c".into(), script.into()]
    }

    #[test]
    fn run_cli_stdin_env_exit_and_timeout() {
        let out = run_cli(&sh("printf '%s|' \"$SEAGENT_LINK_URL\"; tr a-z A-Z"), "page body\n", Duration::from_secs(5), &[("SEAGENT_LINK_URL", "https://u")]).unwrap();
        assert_eq!(out, "https://u|PAGE BODY");
        assert!(run_cli(&sh("echo hi; exit 3"), "", Duration::from_secs(5), &[]).unwrap_err().contains("code 3"));
        let t = Instant::now();
        assert!(run_cli(&sh("sleep 5; echo late"), "", Duration::from_millis(300), &[]).unwrap_err().contains("timed out"));
        assert!(t.elapsed() < Duration::from_secs(3));
        // A backgrounded descendant holding stdout open is killed at the deadline too.
        let t = Instant::now();
        assert!(run_cli(&sh("(sleep 5) & echo early"), "", Duration::from_millis(300), &[]).is_err());
        assert!(t.elapsed() < Duration::from_secs(3));
        assert!(run_cli(&["/nonexistent/seagent-link-proc".to_string()], "", Duration::from_secs(1), &[]).unwrap_err().contains("spawn"));
    }

    fn cfg_with(server: &FakeServer, links: serde_json::Value) -> WebConfig {
        let _ = server;
        let mut c = WebConfig::from_value(json!({"allow_private_urls": true, "links": links})).unwrap();
        c.links.enabled = true;
        c
    }

    fn model(cmd: Vec<String>, timeout: Option<u64>) -> LinkModel {
        let (command, args) = cmd.split_first().map(|(c, a)| (c.clone(), a.to_vec())).unwrap();
        LinkModel { kind: None, command, args, timeout_seconds: timeout }
    }

    fn home() -> std::path::PathBuf {
        crate::testutil::tmpdir("links")
    }

    #[test]
    fn end_to_end_fetch_process_and_enrich() {
        let s = FakeServer::start(vec![("GET /page", 200, "text/plain", "page body".into()), ("GET /two", 200, "text/plain", "second page".into())]);
        let mut c = cfg_with(&s, json!({}));
        c.links.models = vec![model(sh("printf 'summary of %s: ' \"$SEAGENT_LINK_URL\"; cat; printf ' [%s]' \"$1\""), None)];
        c.links.models[0].args.extend(["x".into(), "{{LinkUrl}}".into(), "{{SenderName}}".into()]);
        let text = format!("see {0}/page and {0}/two", s.url);
        let msg = LinkMessage { text: &text, channel: "telegram", chat_type: "direct", sender_name: "Ann", ..Default::default() };
        let out = apply_link_understanding(&c, &home(), &msg, "transport envelope").unwrap();
        assert_eq!(out, format!("transport envelope\n\nsummary of {0}/page: page body [Ann]\nsummary of {0}/two: second page [Ann]", s.url));
        let r = s.last();
        assert_eq!(r.header("user-agent").as_deref(), Some(USER_AGENT));
        assert!(r.header("accept").unwrap().starts_with("text/*"));
        assert_eq!(enrich("  ", &["a".into(), "b".into()]), "a\nb");
    }

    #[test]
    fn fallback_to_next_processor_then_page_body() {
        let s = FakeServer::start(vec![("GET /p", 200, "text/plain", "  raw page  ".into())]);
        let mut c = cfg_with(&s, json!({}));
        c.links.models = vec![
            model(sh("exit 1"), None),
            model(sh("cat >/dev/null; echo"), None),
            LinkModel { kind: Some("provider".into()), command: "echo".into(), args: vec!["skipped".into()], timeout_seconds: None },
            model(sh("sleep 5"), Some(1)),
            model(sh("cat >/dev/null; echo second summary"), None),
        ];
        let text = format!("{}/p", s.url);
        let msg = LinkMessage { text: &text, ..Default::default() };
        assert_eq!(understand_links(&c, &home(), &msg, ""), vec!["second summary"]);
        c.links.models.pop();
        assert_eq!(understand_links(&c, &home(), &msg, ""), vec!["raw page"]);
    }

    #[test]
    fn curl_entries_use_the_guarded_fetch() {
        let s = FakeServer::start(vec![("GET /p", 200, "text/plain", "guarded page body".into())]);
        let mut c = cfg_with(&s, json!({}));
        c.links.models = vec![LinkModel { kind: Some("cli".into()), command: "/usr/bin/curl".into(), args: vec!["-s".into(), "-L".into(), "{{LinkUrl}}".into()], timeout_seconds: None }];
        let text = format!("{}/p", s.url);
        assert_eq!(understand_links(&c, &home(), &LinkMessage { text: &text, ..Default::default() }, ""), vec!["guarded page body"]);
        assert_eq!(s.requests().len(), 1);
    }

    #[test]
    fn failed_or_empty_fetches_are_skipped_and_redirects_followed() {
        let s = FakeServer::with(|r| match r.path.as_str() {
            "/err" => (500, "text/plain".into(), b"error".to_vec(), vec![]),
            "/empty" => (200, "text/plain".into(), b"   ".to_vec(), vec![]),
            "/r" => (302, "text/plain".into(), vec![], vec![("Location".into(), "/final".into())]),
            "/loop" => (302, "text/plain".into(), vec![], vec![("Location".into(), "/loop".into())]),
            _ => (200, "text/plain".into(), r.path.clone().into_bytes(), vec![]),
        });
        let mut c = cfg_with(&s, json!({"max_links": 5}));
        c.links.models = vec![model(sh("printf '%s ' \"$SEAGENT_LINK_FINAL_URL\"; cat"), None)];
        let text = format!("{0}/err {0}/empty {0}/loop {0}/r {0}/ok", s.url);
        let out = understand_links(&c, &home(), &LinkMessage { text: &text, ..Default::default() }, "");
        assert_eq!(out, vec![format!("{}/final /final", s.url), format!("{}/ok /ok", s.url)]);
        // Website blocklist applies like any other fetch.
        c.blocklist.domains = vec!["127.0.0.1".into()];
        assert!(understand_links(&c, &home(), &LinkMessage { text: &text, ..Default::default() }, "").is_empty());
    }

    #[test]
    fn disabled_denied_no_models_or_private_policy_do_nothing() {
        let s = FakeServer::start(vec![("GET /p", 200, "text/plain", "body".into())]);
        let text = format!("{}/p", s.url);
        let msg = LinkMessage { text: &text, channel: "slack", chat_type: "group", ..Default::default() };
        let mut c = cfg_with(&s, json!({}));
        c.links.models = vec![model(sh("cat"), None)];
        assert!(apply_link_understanding(&c, &home(), &msg, "b").is_some());
        let mut off = c.clone();
        off.links.enabled = false;
        assert!(apply_link_understanding(&off, &home(), &msg, "b").is_none());
        let mut denied = c.clone();
        denied.links.scope = Some(LinkScope { default: Some("deny".into()), rules: vec![] });
        assert!(apply_link_understanding(&denied, &home(), &msg, "b").is_none());
        let mut none = c.clone();
        none.links.models.clear();
        assert!(apply_link_understanding(&none, &home(), &msg, "b").is_none());
        let mut strict = c.clone();
        strict.allow_private_urls = false;
        if std::env::var("SEAGENT_ALLOW_PRIVATE_URLS").is_err() {
            assert!(apply_link_understanding(&strict, &home(), &msg, "b").is_none());
        }
        assert_eq!(s.requests().len(), 1);
    }

    #[test]
    fn fetch_timeout_resolution() {
        let mut lc = LinksConfig { models: vec![model(sh("a"), Some(1)), model(sh("b"), Some(9))], ..Default::default() };
        assert_eq!(fetch_timeout(&lc), 9);
        lc.timeout_seconds = Some(15);
        assert_eq!(fetch_timeout(&lc), 15);
        lc.timeout_seconds = Some(0);
        assert_eq!(fetch_timeout(&lc), 1);
        assert_eq!(fetch_timeout(&LinksConfig::default()), DEFAULT_LINK_TIMEOUT_SECONDS);
        assert_eq!(fetch_timeout(&LinksConfig { models: vec![model(sh("a"), None)], ..Default::default() }), 30);
    }
}
