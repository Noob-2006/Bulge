//! Daemon-side broker: privileged command requests and egress on behalf of the VM
//! (GAPS-next A2/A3/A4). Wire protocol: `audit/round5/AB-interface.md`.
//!
//! The VM has no keys, no daemon files and no network of its own: it can only send JSON
//! lines to this socket. Every request is classified with [`crate::risk`] (never by the
//! model), matched against the command allowlist, scanned for credentials on the way out,
//! executed here, and written to an audit log. Credentials are injected here and never
//! travel back over the channel.
//!
//! Review questions (§0): this adds no prompt for tier 0/1 work — a package install or a
//! restart from the built-in list runs immediately; only tier 2/3 queues, and only for the
//! branch that asked. The isolation alternative (do it inside the VM) stays available for
//! anything that does not need root.

use crate::approvals;
use crate::capability;
use crate::egress_proxy::{self, host_rule, Policy};
use crate::risk::{self, Tier};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// `[security.broker]`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrokerConfig {
    /// Serve `<runtime>/broker.sock`. Off unless the VM needs it.
    pub enabled: bool,
    /// Unix socket path; `None` = `<runtime>/broker.sock`.
    pub socket: Option<String>,
    /// Command patterns that run without asking (`apt-get install *`, `systemctl restart *`).
    pub exec_allow: Vec<String>,
    /// Command patterns that never run (`rm -rf *` is refused by tier 3 anyway).
    pub exec_deny: Vec<String>,
    /// Enforce capability manifests (A5) on every brokered request: a component may only ask
    /// for hosts, secrets and commands it declared. Built-in tools ship their declarations, so
    /// ordinary work is never refused by this; a third-party skill/plugin/MCP server without a
    /// manifest is (`[security.broker] enforce_capabilities = false` is the escape hatch).
    pub enforce_capabilities: bool,
    /// Wall-clock limit for one brokered command.
    pub timeout_secs: u64,
    /// Largest response the broker returns.
    pub max_output_bytes: usize,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        BrokerConfig {
            enabled: false,
            socket: None,
            // §0-3 A2: common, recoverable system work is pre-authorised.
            exec_allow: vec![
                "apt-get install *".into(),
                "apt-get update".into(),
                "apt update".into(),
                "dnf install *".into(),
                "systemctl restart *".into(),
                "systemctl reload *".into(),
                "systemctl status *".into(),
                "mount *".into(),
                "umount *".into(),
                "service * reload".into(),
            ],
            exec_deny: vec![],
            enforce_capabilities: true,
            timeout_secs: 120,
            max_output_bytes: 4 * 1024 * 1024,
        }
    }
}

impl BrokerConfig {
    pub fn socket_path(&self, runtime: &Path) -> PathBuf {
        self.socket.as_ref().map(PathBuf::from).unwrap_or_else(|| runtime.join("broker.sock"))
    }

    pub fn allows(&self, argv: &[String]) -> bool {
        let line = argv.join(" ");
        if self.exec_deny.iter().any(|p| pattern(p, &line, argv)) {
            return false;
        }
        self.exec_allow.iter().any(|p| pattern(p, &line, argv))
    }
}

/// `apt-get install *` matches an argv prefix; a bare pattern matches exactly.
fn pattern(p: &str, line: &str, argv: &[String]) -> bool {
    let p = p.trim();
    if p == "*" {
        return true;
    }
    match p.strip_suffix('*') {
        Some(prefix) => {
            let prefix = prefix.trim_end();
            // `/bin/echo` matches the `echo *` rule: the allowlist names the program, not a path.
            let first_matches = argv.first().is_some_and(|a| a == prefix || a.ends_with(&format!("/{prefix}")));
            line == prefix || line.starts_with(&format!("{prefix} ")) || first_matches
        }
        None => line == p,
    }
}

/// Verdict on an outgoing body: `Some(reason)` = refuse.
pub type BodyCheck = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// What the broker may use: vault values by name, the egress policy, the data dir.
#[derive(Clone)]
pub struct Ctx {
    pub data: PathBuf,
    pub session: String,
    pub cfg: BrokerConfig,
    pub policy: Policy,
    pub resolve: egress_proxy::Resolver,
    /// `NAME` → value (vault). Never logged.
    pub secret: egress_proxy::Secrets,
    /// Outgoing-body verdict (`Some(reason)` = refuse).
    pub check_body: BodyCheck,
}

impl Ctx {
    /// A test / in-process context with no secrets and a permissive resolver.
    pub fn new(data: PathBuf, policy: Policy) -> Ctx {
        Ctx {
            data,
            session: "broker".into(),
            cfg: BrokerConfig::default(),
            policy,
            resolve: Arc::new(|h: &str, _p: u16| format!("{h}:0").parse::<std::net::IpAddr>().map(|ip| vec![ip]).map_err(|e| e.to_string())),
            secret: Arc::new(|_: &str| String::new()),
            check_body: Arc::new(|_: &str| None),
        }
    }
}

/// The system resolver, as `Policy::vet` wants it: `(host, port) → addresses`. `vet` dials
/// exactly what it vetted, so resolving here does not open a rebinding window.
pub fn system_resolver() -> egress_proxy::Resolver {
    Arc::new(|host: &str, port: u16| {
        use std::net::ToSocketAddrs;
        (host, port).to_socket_addrs().map(|it| it.map(|a| a.ip()).collect::<Vec<_>>()).map_err(|e| e.to_string())
    })
}

impl Ctx {
    /// The daemon's context (A2/A3/A4): the operator's egress policy *including the built-in
    /// development hosts* (§0-3 A3), the vault behind `secret:` header injection, and the
    /// outgoing-body scan every request passes — a credential leaving the machine is refused
    /// here whatever the agent believed it was doing (H11).
    pub fn for_daemon(sec: &crate::SecurityConfig, data: &Path, config_dir: &Path, session: &str, secret: egress_proxy::Secrets, gate_allow: &[String], gate_deny: &[String]) -> Ctx {
        let policy = Policy::from_config(&sec.egress_proxy, sec.url_policy(), sec.website_blocklist.clone(), config_dir, gate_allow, gate_deny);
        Ctx {
            data: data.to_path_buf(),
            session: session.to_string(),
            cfg: sec.broker.clone(),
            policy,
            resolve: system_resolver(),
            secret,
            check_body: Arc::new(|body: &str| crate::risk::secret_kind(body).map(|k| format!("the body contains a {k}"))),
        }
    }
}

/// Start the daemon broker (A1/A3): the VM's only way out.
///
/// `needed` is the caller's decision that a microVM is in use (`seagent_vm::policy`: a VM cannot
/// exist without a broker, since its only channel is the guest agent). `[security.broker]
/// enabled = true` starts it regardless. Returns `None` when nothing needs it, so a host-only
/// seagent instance does not open a socket it will not use.
pub fn start_daemon(d: Daemon<'_>, needed: bool) -> Result<Option<Broker>, String> {
    if !(d.sec.broker.enabled || needed) {
        return Ok(None);
    }
    let socket = d.sec.broker.socket_path(d.runtime);
    let ctx = Ctx::for_daemon(d.sec, d.data, d.config_dir, "daemon", d.secret, d.gate_allow, d.gate_deny);
    Broker::serve(&socket, ctx).map(Some)
}

/// Where the daemon broker lives and what it may use: the pieces `start_daemon` needs, as one
/// value (the socket path, the data dir for the audit log, the vault and the host lists).
pub struct Daemon<'a> {
    pub sec: &'a crate::SecurityConfig,
    pub data: &'a Path,
    pub config_dir: &'a Path,
    pub runtime: &'a Path,
    /// `NAME → value` for `secret:` header injection. Never logged, never returned.
    pub secret: egress_proxy::Secrets,
    pub gate_allow: &'a [String],
    pub gate_deny: &'a [String],
}

fn err(id: &Value, code: &str, message: &str) -> Value {
    json!({"id": id, "ok": false, "error": {"code": code, "message": message}})
}

fn ok(id: &Value, result: Value) -> Value {
    json!({"id": id, "ok": true, "result": result})
}

/// One request → one response. Pure policy + execution: the socket layer only moves lines.
///
/// The component that asked defaults to `vm` (the guest agent acting for the session). The
/// host-side adapter (`SocketBroker`) names the *tool* that spawned the command instead, so a
/// capability manifest is checked against the thing that really acted (A5); a program inside
/// the VM cannot name itself.
pub fn handle(req: &Value, ctx: &Ctx) -> Value {
    handle_for(req, ctx, "vm")
}

/// [`handle`] with the component that asked (`shell`, `code`, a skill's tool, …).
pub fn handle_for(req: &Value, ctx: &Ctx, default_component: &str) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let component = req.get("component").and_then(Value::as_str).filter(|c| !c.trim().is_empty()).unwrap_or(default_component);
    // The session the request belongs to: its task envelope applies and its approval queue is
    // where a queued command waits (§0-2 #01/#03). A request without one is the daemon's own.
    let wanted = req.get("session").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).unwrap_or(&ctx.session).to_string();
    // `Ctx` is cheap to clone (four `Arc`s and a few small fields); the borrowed one wins so
    // the common case allocates nothing.
    let per_session;
    let ctx = if wanted == ctx.session {
        ctx
    } else {
        per_session = Ctx { session: wanted, ..ctx.clone() };
        &per_session
    };
    let op = req.get("op").and_then(Value::as_str).unwrap_or("");
    match op {
        "health" => ok(&id, json!({"version": env!("CARGO_PKG_VERSION"), "broker": true, "session": ctx.session, "tier_max": 3, "capabilities": ctx.cfg.enforce_capabilities})),
        "host.check" => {
            let host = req.get("host").and_then(Value::as_str).unwrap_or("");
            let port = req.get("port").and_then(Value::as_u64).unwrap_or(443) as u16;
            if host.is_empty() {
                return err(&id, "bad_request", "host is required");
            }
            match ctx.policy.vet(host, port, &ctx.resolve) {
                Ok(_) => ok(&id, json!({"allowed": true, "mode": format!("{:?}", ctx.policy.mode).to_lowercase()})),
                Err(why) => ok(&id, json!({"allowed": false, "reason": why})),
            }
        }
        "envelope" => match crate::envelope::active(&ctx.data, &ctx.session) {
            Some(e) => ok(&id, json!({
                "session": ctx.session,
                "label": e.label,
                "tier_max": e.max_tier,
                "expires_ms": e.expires_ms,
                "paths": e.paths,
                "hosts": e.hosts,
                "commands": e.commands,
                "spend_left_usd": e.spend_usd,
            })),
            None => ok(&id, json!({"session": Value::Null})),
        },
        "approval.pending" => {
            let items: Vec<Value> = approvals::deferred(&ctx.data).into_iter().map(|d| json!({"approval_id": d.id, "tier": d.tier, "tool": d.tool, "summary": d.summary, "created_ms": d.created_at * 1000})).collect();
            ok(&id, json!({"items": items}))
        }
        "approval.wait" => {
            let aid = req.get("approval_id").and_then(Value::as_str).unwrap_or("");
            let status = approvals::deferred(&ctx.data).iter().find(|d| d.id == aid).map(|_| "pending").unwrap_or("gone");
            ok(&id, json!({"status": if status == "pending" { "timeout" } else { "gone" }, "fallback": "the owner has not answered; do the reversible part and report the rest"}))
        }
        "exec" => exec(&id, req, ctx, component),
        "egress" => egress(&id, req, ctx, component),
        "" => err(&id, "bad_request", "op is required"),
        other => err(&id, "unsupported", &format!("unknown op `{other}`")),
    }
}

/// A5 at the front door: the component that asked may only use what its manifest declares.
/// `Manifest::allows` rather than [`capability::check`] because tier 3 must reach the approval
/// queue below (A6), not be refused outright: a manifest can *deny* a capability, never
/// *authorise* an irreversible action.
fn capability_allows(ctx: &Ctx, component: &str, r: &capability::Request<'_>) -> Result<(), String> {
    if !ctx.cfg.enforce_capabilities {
        return Ok(());
    }
    let m = capability::lookup(component).ok_or_else(|| format!("no capability manifest for `{component}`: third-party components must declare what they need before they run (A5)"))?;
    m.allows(r).map_err(|why| format!("{component}: {why}"))
}

fn exec(id: &Value, req: &Value, ctx: &Ctx, component: &str) -> Value {
    let argv: Vec<String> = req.get("argv").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    if argv.is_empty() {
        return err(id, "bad_request", "argv is required (no shell strings)");
    }
    // A shell metacharacter in an argv element means the caller tried to smuggle a shell.
    if argv.iter().any(|a| a.contains([';', '|', '\n', '\0', '`']) || a.contains("$(")) {
        return err(id, "denied", "argv elements may not contain shell syntax");
    }
    let line = argv.join(" ");
    let a = risk::assess(&risk::Candidate { tool: "broker".into(), exec: vec![line.clone()], sandboxed: false, ..Default::default() });
    let tier = a.tier;
    // A5: the component may only run what it declared. A missing manifest is a refusal, not
    // a default-allow; the built-in tools ship declarations so ordinary work is untouched.
    if let Err(why) = capability_allows(ctx, component, &capability::Request { exec: Some(&argv), destructive: tier.is_irreversible(), ..Default::default() }) {
        audit(ctx, component, "exec", tier, "denied", &line);
        return err(id, "capability", &why);
    }
    // §0-2 #01: an active task envelope pre-authorises its command patterns, so a long
    // unattended task does not stop at the static allowlist. It can never widen tier 3.
    let by_envelope = crate::envelope::active(&ctx.data, &ctx.session).is_some_and(|e| e.covers_command(&line)) && !tier.is_irreversible();
    // Tier 3 is never pre-authorised, even by the allowlist or an envelope (§0-1 A6).
    let allowed = (ctx.cfg.allows(&argv) || by_envelope) && !tier.is_irreversible();
    if tier.is_irreversible() || !allowed {
        let reason = if tier.is_irreversible() {
            format!("{}: {}", tier.label(), risk::describe(&a))
        } else {
            format!("`{line}` is not on the broker exec allowlist")
        };
        let qid = approvals::defer(&ctx.data, &ctx.session, "exec", &line, tier.as_u8(), &reason).unwrap_or_default();
        audit(ctx, component, "exec", tier, "queued", &line);
        return ok(id, json!({"status": "queued", "approval_id": qid, "tier": tier.as_u8(), "reason": reason, "fallback": risk::fallback(tier, "exec", &a.destructive)}));
    }
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    if let Some(cwd) = req.get("cwd").and_then(Value::as_str) {
        cmd.current_dir(cwd);
    }
    // Never hand the child the daemon's credentials.
    crate::envscrub::apply(&mut cmd, crate::envscrub::Surface::Terminal);
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let started = std::time::Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return err(id, "internal", &format!("cannot start {}: {e}", argv[0])),
    };
    let deadline = started + Duration::from_secs(ctx.cfg.timeout_secs.max(1));
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                audit(ctx, component, "exec", tier, "timeout", &line);
                return ok(id, json!({"status": "timeout", "tier": tier.as_u8(), "reason": format!("exceeded {}s", ctx.cfg.timeout_secs)}));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return err(id, "internal", &e.to_string()),
        }
    }
    let out = child.wait_with_output().ok();
    let (code, stdout, stderr) = match out {
        Some(o) => (
            o.status.code().unwrap_or(-1),
            clip(&String::from_utf8_lossy(&o.stdout), ctx.cfg.max_output_bytes),
            clip(&String::from_utf8_lossy(&o.stderr), ctx.cfg.max_output_bytes),
        ),
        None => (-1, String::new(), String::new()),
    };
    audit(ctx, component, "exec", tier, if by_envelope { "ran (envelope)" } else { "ran" }, &line);
    ok(id, json!({"status": "ran", "exit": code, "stdout": stdout, "stderr": stderr, "tier": tier.as_u8(), "duration_ms": started.elapsed().as_millis() as u64}))
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let cut = s.char_indices().take_while(|(i, _)| *i < max).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0);
    format!("{}\n…[truncated {} bytes]", &s[..cut], s.len() - cut)
}

fn egress(id: &Value, req: &Value, ctx: &Ctx, component: &str) -> Value {
    let method = req.get("method").and_then(Value::as_str).unwrap_or("GET").to_ascii_uppercase();
    let url = req.get("url").and_then(Value::as_str).unwrap_or("");
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return err(id, "bad_request", "url must be http(s)");
    }
    let (host, port) = host_port(url);
    // A5: the host has to be one this component declared. `net: ["*"]` means public hosts
    // only, and the SSRF floor below still runs on every resolved address.
    if let Err(why) = capability_allows(ctx, component, &capability::Request { net: Some((&host, port)), ..Default::default() }) {
        audit(ctx, component, "egress", Tier::Impactful, "denied", url);
        return err(id, "capability", &why);
    }
    // §0-2 #01: the task envelope may name hosts the static policy does not ("new host in
    // the envelope is added without asking"). It widens the *name* list only: `vet` still
    // resolves and refuses private/metadata addresses, so an envelope cannot open the host.
    let by_envelope = !ctx.policy.allow.iter().any(|r| host_rule(&host, r)) && crate::envelope::active(&ctx.data, &ctx.session).is_some_and(|e| e.covers_host(&host));
    let mut policy = ctx.policy.clone();
    if by_envelope {
        // Name-level only: `Policy::vet` still resolves the host and refuses private /
        // metadata addresses, so an envelope cannot turn into an SSRF exception.
        policy.envelope_hosts.push(host.clone());
    }
    if let Err(why) = policy.vet(&host, port, &ctx.resolve) {
        audit(ctx, component, "egress", Tier::Impactful, "denied", url);
        return err(id, "denied", &why);
    }
    let body = req.get("body_b64").and_then(Value::as_str).map(b64_decode).unwrap_or_default();
    let body = String::from_utf8_lossy(&body).to_string();
    // Data leaving the machine is scanned: a credential in the body is refused here,
    // whatever the agent believed it was doing (H11, A4).
    if let Some(why) = (ctx.check_body)(&body) {
        audit(ctx, component, "egress", Tier::Irreversible, "denied", url);
        return with_code(id, "exfil", &format!("refused: {why}"));
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(h) = req.get("headers").and_then(Value::as_object) {
        for (k, v) in h {
            let v = v.as_str().unwrap_or("");
            let value = match v.strip_prefix("secret:") {
                Some(name) => {
                    // A4/A5: a component may only have injected a secret it declared. The
                    // value never travels back to the guest either way.
                    if let Err(why) = capability_allows(ctx, component, &capability::Request { secret: Some(name), ..Default::default() }) {
                        audit(ctx, component, "egress", Tier::Irreversible, "denied", url);
                        return err(id, "capability", &why);
                    }
                    (ctx.secret)(name)
                }
                None => {
                    if let Some(kind) = risk::secret_kind(v) {
                        audit(ctx, component, "egress", Tier::Irreversible, "denied", url);
                        return with_code(id, "exfil", &format!("refused: header {k} looks like a {kind}"));
                    }
                    v.to_string()
                }
            };
            headers.push((k.clone(), value));
        }
    }
    let agent: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(60))).build().into();
    let keep = |r: ureq::RequestBuilder<ureq::typestate::WithoutBody>| {
        let mut r = r;
        for (k, v) in &headers {
            r = r.header(k, v);
        }
        r.call()
    };
    let with_body = |r: ureq::RequestBuilder<ureq::typestate::WithBody>| {
        let mut r = r;
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("content-type") && body.is_empty() {
                continue;
            }
            r = r.header(k, v);
        }
        r.send(body.as_bytes())
    };
    let resp = if body.is_empty() {
        match method.as_str() {
            "HEAD" => keep(agent.head(url)),
            "DELETE" => keep(agent.delete(url)),
            "PUT" => with_body(agent.put(url)),
            "PATCH" => with_body(agent.patch(url)),
            "POST" => with_body(agent.post(url)),
            _ => keep(agent.get(url)),
        }
    } else {
        match method.as_str() {
            "PUT" => with_body(agent.put(url)),
            "PATCH" => with_body(agent.patch(url)),
            _ => with_body(agent.post(url)),
        }
    };
    match resp {
        Ok(mut resp) => {
            let code = resp.status().as_u16();
            let mut hdrs = serde_json::Map::new();
            for (n, v) in resp.headers().iter() {
                if n.as_str().eq_ignore_ascii_case("set-cookie") {
                    continue;
                }
                if let Ok(v) = v.to_str() {
                    hdrs.insert(n.as_str().to_ascii_lowercase(), json!(v));
                }
            }
            let buf = resp.body_mut().with_config().limit(ctx.cfg.max_output_bytes as u64).read_to_vec().unwrap_or_default();
            audit(ctx, component, "egress", Tier::Recoverable, if by_envelope { "ok (envelope)" } else { "ok" }, url);
            ok(id, json!({"status": "ok", "code": code, "headers": Value::Object(hdrs), "body_b64": b64_encode(&buf), "host": host}))
        }
        Err(e) => err(id, "internal", &format!("request failed: {e}")),
    }
}

fn with_code(id: &Value, code: &str, message: &str) -> Value {
    json!({"id": id, "ok": false, "error": {"code": code, "message": message}})
}

fn host_port(url: &str) -> (String, u16) {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (h, p) = match auth.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h, p.parse().unwrap_or(443)),
        _ => (auth, 0),
    };
    let host = h.trim_matches(['[', ']']).to_string();
    let port = if p != 0 { p } else if url.starts_with("http://") { 80 } else { 443 };
    (host, port)
}

/// One audit line per request. No secret values, no bodies — only the URL/host and size.
fn audit(ctx: &Ctx, component: &str, op: &str, tier: Tier, verdict: &str, subject: &str) {
    let dir = ctx.data.join("audit");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let line = json!({
        "ts_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
        "session": ctx.session,
        "component": component,
        "op": op,
        "tier": tier.as_u8(),
        "verdict": verdict,
        "subject": subject.chars().take(300).collect::<String>(),
    });
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("broker.jsonl")) {
        let _ = writeln!(f, "{line}");
    }
    // ent-073: the same fact in the unified, hash-chained stream.
    let ev = crate::audit::Event::new(&format!("broker.{component}"), crate::audit::Actor::new("agent", &ctx.session), &subject.chars().take(300).collect::<String>(), verdict).session(&ctx.session).detail(json!({"op": op, "tier": tier.as_u8()}));
    crate::audit::record(&ctx.data, ev);
}

// ───────────────────────── base64 (the wire uses it for bodies) ─────────────────────────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in s.bytes() {
        if ch == b'=' || ch.is_ascii_whitespace() {
            continue;
        }
        let Some(v) = B64.iter().position(|x| *x == ch) else { continue };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

// ───────────────────────── socket ─────────────────────────

/// A running broker socket. Dropping it (or calling [`Broker::stop`]) removes the socket.
pub struct Broker {
    path: PathBuf,
    stop: Arc<AtomicBool>,
}

impl Broker {
    /// Serve JSON lines on `path` (0600, parent 0700). One thread per connection.
    pub fn serve(path: &Path, ctx: Ctx) -> Result<Broker, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let _ = std::fs::remove_file(path);
        let listener = endpoint::bind(path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let ctx = Arc::new(ctx);
        let p = path.to_path_buf();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = conn else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));
                let ctx = ctx.clone();
                // `()` on Unix (the socket's 0600 mode is the check), a token on Windows.
                #[allow(clippy::let_unit_value)]
                let listener_auth = listener.auth();
                std::thread::spawn(move || {
                    let mut writer = match stream.try_clone() {
                        Ok(w) => w,
                        Err(_) => return,
                    };
                    let mut reader = BufReader::new(stream);
                    if !endpoint::admit(&mut reader, &listener_auth) {
                        return;
                    }
                    for line in reader.lines() {
                        let Ok(line) = line else { break };
                        if line.trim().is_empty() {
                            continue;
                        }
                        let resp = match serde_json::from_str::<Value>(&line) {
                            Ok(req) => handle(&req, &ctx),
                            Err(e) => err(&Value::Null, "bad_request", &e.to_string()),
                        };
                        let mut out = resp.to_string();
                        out.push('\n');
                        if writer.write_all(out.as_bytes()).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Ok(Broker { path: p, stop })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        endpoint::wake(&self.path);
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A client connection to a broker at `path` (what the VM-side forwarder and tests use):
/// a unix socket on unix; on other systems the loopback endpoint named by the file at
/// `path`, already authenticated with its token. Speak JSON lines on it.
pub fn connect(path: &Path) -> Result<Conn, String> {
    endpoint::connect(path)
}

/// The stream type [`connect`] returns.
#[cfg(unix)]
pub type Conn = std::os::unix::net::UnixStream;
/// The stream type [`connect`] returns.
#[cfg(not(unix))]
pub type Conn = std::net::TcpStream;

/// Where the broker listens. Unix: a 0600 unix socket at `path`, exactly as the interface
/// document says. Elsewhere (Windows has no unix sockets in std): a `127.0.0.1` TCP port with
/// a 256-bit token. `path` then holds `seagent-broker tcp <addr> <token>`; the client sends
/// the token as its first line and anything else is dropped unanswered, so another local
/// user who can reach the port but not read the file gets nothing.
#[cfg(unix)]
mod endpoint {
    use std::io::BufRead;
    use std::path::Path;

    pub struct Listener(std::os::unix::net::UnixListener);
    impl Listener {
        pub fn incoming(&self) -> std::os::unix::net::Incoming<'_> {
            self.0.incoming()
        }
        pub fn auth(&self) {}
    }

    pub fn bind(path: &Path) -> Result<Listener, String> {
        let listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
        // 0600, as the interface promises: the directory is 0700 too, but the mode must not
        // depend on the umask (`bind` creates the socket 0777 & ~umask).
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("chmod {}: {e}", path.display()))?;
        Ok(Listener(listener))
    }

    pub fn admit(_: &mut impl BufRead, _: &()) -> bool {
        true
    }

    pub fn wake(path: &Path) {
        let _ = std::os::unix::net::UnixStream::connect(path);
    }

    pub fn connect(path: &Path) -> Result<super::Conn, String> {
        std::os::unix::net::UnixStream::connect(path).map_err(|e| format!("broker {}: {e}", path.display()))
    }
}

#[cfg(not(unix))]
mod endpoint {
    use std::io::{BufRead, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::time::Duration;

    pub struct Listener(TcpListener, String);
    impl Listener {
        pub fn incoming(&self) -> std::net::Incoming<'_> {
            self.0.incoming()
        }
        pub fn auth(&self) -> String {
            self.1.clone()
        }
    }

    pub fn bind(path: &Path) -> Result<Listener, String> {
        let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("cannot listen on 127.0.0.1 for {}: {e}", path.display()))?;
        let addr = l.local_addr().map_err(|e| e.to_string())?;
        let mut b = [0u8; 32];
        if !crate::os::fill_random(&mut b) {
            return Err("broker: no OS random source for the endpoint token".into());
        }
        let token: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::fs::write(path, format!("seagent-broker tcp {addr} {token}\n")).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Listener(l, token))
    }

    /// Constant-time check of the first line against the token.
    pub fn admit(r: &mut impl BufRead, token: &str) -> bool {
        let mut line = String::new();
        if r.read_line(&mut line).is_err() {
            return false;
        }
        let got = line.trim_end().as_bytes();
        got.len() == token.len() && got.iter().zip(token.as_bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
    }

    fn read(path: &Path) -> Result<(String, String), String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("broker {}: {e}", path.display()))?;
        let mut it = s.split_whitespace();
        match (it.next(), it.next(), it.next(), it.next()) {
            (Some("seagent-broker"), Some("tcp"), Some(addr), Some(token)) => Ok((addr.to_string(), token.to_string())),
            _ => Err(format!("broker {}: not a broker endpoint file", path.display())),
        }
    }

    pub fn wake(path: &Path) {
        if let Ok((addr, _)) = read(path) {
            let _ = TcpStream::connect(addr);
        }
    }

    pub fn connect(path: &Path) -> Result<super::Conn, String> {
        let (addr, token) = read(path)?;
        let mut s = TcpStream::connect(&addr).map_err(|e| format!("broker {addr}: {e}"))?;
        let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
        s.write_all(format!("{token}\n").as_bytes()).map_err(|e| format!("broker {addr}: {e}"))?;
        Ok(s)
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for s in ["", "a", "ab", "abc", "hello world", "{\"x\":1}"] {
            assert_eq!(b64_decode(&b64_encode(s.as_bytes())), s.as_bytes(), "{s}");
        }
        assert_eq!(b64_encode(b"hi"), "aGk=");
    }

    #[test]
    fn command_patterns() {
        let c = BrokerConfig::default();
        assert!(c.allows(&["apt-get".into(), "install".into(), "jq".into()]));
        assert!(c.allows(&["systemctl".into(), "restart".into(), "nginx".into()]));
        assert!(!c.allows(&["apt-get".into(), "remove".into(), "jq".into()]));
        assert!(!c.allows(&["sh".into(), "-c".into(), "id".into()]));
    }
}
