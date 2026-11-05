//! Agent work surfaces (parity with OpenClaw's llm-task, lobster, diffs, canvas, show_widget,
//! dashboard, progress_card, gateway, team-reports and file-transfer, MIT).
//!
//! ```toml
//! [surfaces]
//! public_url = "https://ark.example.net"   # links in tool results (default: [app] listen)
//! [surfaces.llm_task]
//! default_model = "openai/gpt-5-mini"
//! [surfaces.team_reports]
//! github = { token = "{{secret:GH}}", orgs = ["acme"] }
//! ```
//!
//! Everything is stored under `<data>/surfaces/`; the daemon serves hosted documents
//! (`/surfaces/…`) next to the web UI and the ARP methods in [`METHODS`].

pub mod cards;
pub mod canvas;
pub mod diffs;
pub mod file_transfer;
pub mod gateway;
pub mod graph;
pub mod llm_task;
pub mod lobster;
pub mod team_reports;
pub mod widgets;
pub(crate) mod yaml;

use ark_channel::Channel;
use ark_core::{Block, Cancel, Message, Role, SystemSegment, Tool};
use ark_kernel::config::{Config, Paths};
use ark_kernel::kernel::Kernel;
use ark_net::httpd::{Handler, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Set once the kernel exists (`Ext.kernel`).
pub type Slot = Arc<OnceLock<Kernel>>;

/// `[surfaces]`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SurfacesConfig {
    /// Origin used in links the tools return (viewer, canvas and report URLs). Default:
    /// `http://<[app] listen>` with a wildcard bind shown as 127.0.0.1.
    pub public_url: Option<String>,
    pub llm_task: llm_task::LlmTaskConfig,
    pub lobster: lobster::LobsterConfig,
    pub graph: graph::GraphConfig,
    pub diffs: diffs::DiffsConfig,
    pub canvas: canvas::CanvasConfig,
    pub widgets: widgets::WidgetsConfig,
    pub cards: cards::CardsConfig,
    pub gateway: gateway::GatewayConfig,
    pub file_transfer: file_transfer::FileTransferConfig,
    /// Off unless configured.
    pub team_reports: Option<team_reports::TeamReportsConfig>,
}

impl SurfacesConfig {
    pub fn parse(t: &toml::Table) -> Result<SurfacesConfig, String> {
        SurfacesConfig::deserialize(toml::Value::Table(t.clone())).map_err(|e| format!("[surfaces]: {e}"))
    }
}

/// Everything the surface tools share.
#[derive(Clone)]
pub struct Env {
    pub cfg: SurfacesConfig,
    /// `<data>/surfaces`
    pub dir: PathBuf,
    pub kernel: Slot,
    pub channels: BTreeMap<String, Arc<dyn Channel>>,
    /// Origin for links, without a trailing slash.
    pub base_url: String,
    /// Channel routes (`<data>/channels/routes.json`): which chat a session belongs to.
    pub routes: PathBuf,
    pub user_config: PathBuf,
}

impl Env {
    pub fn new(cfg: &Config, paths: &Paths, kernel: Slot, channels: BTreeMap<String, Arc<dyn Channel>>) -> Result<Env, String> {
        let s = SurfacesConfig::parse(&cfg.surfaces)?;
        let listen = crate::AppConfig::parse(&cfg.app).map(|a| a.listen).unwrap_or_else(|_| "127.0.0.1:8640".into());
        let base_url = base_url(s.public_url.as_deref(), &listen);
        Ok(Env { cfg: s, dir: paths.data.join("surfaces"), kernel, channels, base_url, routes: paths.data.join("channels/routes.json"), user_config: paths.user_config() })
    }

    pub fn kernel(&self) -> Result<&Kernel, String> {
        self.kernel.get().ok_or_else(|| "agent not ready".to_string())
    }

    /// The channel chat a session was routed from, if any: (channel, chat, thread, sender).
    pub fn route_of(&self, session: &str) -> Option<(String, String, Option<String>, Option<String>)> {
        if !self.routes.exists() {
            return None;
        }
        let r = ark_channel::router::Router::open(self.routes.clone(), Default::default());
        r.routes().into_iter().find(|x| x.session == session).map(|x| {
            let (chat, thread) = match x.key.chat.split_once(":thread:") {
                Some((c, t)) => (c.to_string(), Some(t.to_string())),
                None => (x.key.chat.clone(), None),
            };
            (x.key.channel, chat, thread, x.key.sender)
        })
    }
}

fn base_url(public: Option<&str>, listen: &str) -> String {
    if let Some(p) = public.map(str::trim).filter(|p| !p.is_empty()) {
        return p.trim_end_matches('/').to_string();
    }
    let l = listen.replace("0.0.0.0", "127.0.0.1").replace("[::]", "127.0.0.1");
    format!("http://{l}")
}

/// The surface tools (assembled into the agent next to the builtin ones).
pub fn tools(cfg: &Config, paths: &Paths, kernel: Slot, channels: BTreeMap<String, Arc<dyn Channel>>) -> Result<Vec<Arc<dyn Tool>>, String> {
    let env = Arc::new(Env::new(cfg, paths, kernel, channels)?);
    let mut t: Vec<Arc<dyn Tool>> = vec![
        Arc::new(llm_task::LlmTask(env.clone())),
        Arc::new(lobster::LobsterTool(env.clone())),
        Arc::new(graph::GraphTool::new(env.clone())),
        Arc::new(diffs::DiffsTool(env.clone())),
        Arc::new(gateway::GatewayTool(env.clone())),
        Arc::new(canvas::CanvasTool::new(env.clone())),
        Arc::new(widgets::ShowWidget(env.clone())),
        Arc::new(widgets::DashboardTool(env.clone())),
        Arc::new(cards::ProgressCard(env.clone())),
    ];
    t.extend(file_transfer::tools(env.clone()));
    if env.cfg.team_reports.is_some() {
        t.push(Arc::new(team_reports::TeamReportsTool(env.clone())));
    }
    Ok(t)
}

/// ARP methods the daemon adds (web UI dashboards, progress cards, workflows).
pub const METHODS: &[&str] = &["surfaces.boards", "surfaces.board", "surfaces.board.update", "surfaces.card", "surfaces.poll", "lobster.runs", "graph.threads", "team_reports.list", "team_reports.get", "team_reports.generate"];

pub fn methods(env: Arc<Env>) -> ark_kernel::daemon::MethodExt {
    Arc::new(move |m: &str, p: &Value| {
        let r = match m {
            "surfaces.boards" => Ok(widgets::list_boards(&env)),
            "surfaces.board" => widgets::board_json(&env, p["session"].as_str().unwrap_or("")),
            "surfaces.board.update" => widgets::ui_update(&env, p),
            "surfaces.card" => Ok(cards::get(&env.dir, p["session"].as_str().unwrap_or("")).map(|c| json!(c)).unwrap_or(Value::Null)),
            "surfaces.poll" => Ok(widgets::poll(&env, p["session"].as_str().unwrap_or(""))),
            "lobster.runs" => Ok(lobster::list_paused(&env.dir)),
            "graph.threads" => Ok(graph::list_threads(&env)),
            "team_reports.list" => team_reports::rpc_list(&env, p),
            "team_reports.get" => team_reports::rpc_get(&env, p),
            "team_reports.generate" => team_reports::rpc_generate(&env, p),
            _ => return None,
        };
        Some(r.map_err(|e| (-32000, e)))
    })
}

/// HTTP routes served before the app token check; each checks access itself.
pub fn routes(env: Arc<Env>, token: String) -> Vec<(String, Handler)> {
    let e = env.clone();
    let tok = token.clone();
    let h: Handler = Arc::new(move |r: Request| serve(&e, &tok, &r));
    vec![("/surfaces/".into(), h)]
}

fn serve(env: &Env, token: &str, r: &Request) -> Response {
    let path = r.path.trim_start_matches("/surfaces");
    if r.method != "GET" && r.method != "HEAD" {
        return Response::text(405, "Method Not Allowed");
    }
    let resp = if let Some(rest) = path.strip_prefix("/canvas/documents/") {
        canvas::serve_document(&env.dir, rest)
    } else if let Some(rest) = path.strip_prefix("/a2ui/") {
        canvas::serve_a2ui(&env.dir, rest)
    } else if let Some(rest) = path.strip_prefix("/diffs/view/") {
        diffs::serve_viewer(&env.dir, rest)
    } else if let Some(rest) = path.strip_prefix("/team-reports") {
        if !authorized(token, r) {
            return Response::text(401, "unauthorized: send the app token").with_header("www-authenticate", "Bearer");
        }
        team_reports::serve(env, rest)
    } else {
        Response::text(404, "not found")
    };
    let resp = resp.with_header("x-content-type-options", "nosniff").with_header("cache-control", "no-store").with_header("referrer-policy", "no-referrer");
    if r.method == "HEAD" {
        let len = match &resp.body {
            ark_net::httpd::Body::Bytes(b) => b.len(),
            _ => 0,
        };
        let mut h = Response::new(resp.status, "text/plain", Vec::new());
        h.headers = resp.headers.clone();
        return h.with_header("content-length", &len.to_string());
    }
    resp
}

fn authorized(token: &str, r: &Request) -> bool {
    let given = r.bearer().or_else(|| r.query("token"));
    !token.is_empty() && given.is_some_and(|g| ark_net::crypto::ct_eq(g.as_bytes(), token.as_bytes()))
}

/// Background work for the daemon (team-report schedule).
pub fn spawn_daemon(env: Arc<Env>, cancel: Cancel) -> Option<std::thread::JoinHandle<()>> {
    team_reports::spawn_scheduler(env, cancel)
}

// ───────────────────────── shared helpers ─────────────────────────

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Days since 1970-01-01 → (year, month, day) (proleptic Gregorian).
pub(crate) fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// (year, month, day) → days since 1970-01-01.
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 3339 UTC timestamp for `ms`.
pub(crate) fn iso(ms: u64) -> String {
    let s = (ms / 1000) as i64;
    let (y, mo, d) = civil(s.div_euclid(86_400));
    let t = s.rem_euclid(86_400);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z", t / 3600, t % 3600 / 60, t % 60)
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)` → epoch ms.
pub(crate) fn parse_iso(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_at(s.find('T').unwrap_or(s.len()));
    let mut dp = date.split('-');
    let (y, m, d): (i64, u32, u32) = (dp.next()?.parse().ok()?, dp.next()?.parse().ok()?, dp.next()?.parse().ok()?);
    let mut secs = days_from_civil(y, m, d) * 86_400;
    let mut ms = 0i64;
    if let Some(t) = rest.strip_prefix('T') {
        let (clock, tz) = match t.find(['Z', '+', '-']) {
            Some(i) => t.split_at(i),
            None => (t, ""),
        };
        let mut cp = clock.split(':');
        let h: i64 = cp.next()?.parse().ok()?;
        let mi: i64 = cp.next().unwrap_or("0").parse().ok()?;
        let sec = cp.next().unwrap_or("0");
        let (whole, frac) = sec.split_once('.').unwrap_or((sec, ""));
        secs += h * 3600 + mi * 60 + whole.parse::<i64>().ok()?;
        ms = format!("{:0<3}", &frac[..frac.len().min(3)]).parse().unwrap_or(0);
        if let Some(off) = tz.strip_prefix('+').map(|o| (1, o)).or_else(|| tz.strip_prefix('-').map(|o| (-1, o))) {
            let (sign, o) = off;
            let (oh, om) = o.split_once(':').unwrap_or((o, "0"));
            secs -= sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().ok()? * 60);
        }
    }
    u64::try_from(secs * 1000 + ms).ok()
}

/// Write via a temp file + rename, mode 0600.
pub(crate) fn write_atomic(p: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let tmp = p.with_extension(format!("tmp-{}", ark_net::crypto::random_token(6)));
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, p).map_err(|e| format!("{}: {e}", p.display()))
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> Option<T> {
    std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

pub(crate) fn write_json(p: &Path, v: &impl Serialize) -> Result<(), String> {
    write_atomic(p, serde_json::to_string_pretty(v).map_err(|e| e.to_string())?.as_bytes())
}

/// Session ids are used as file names: keep them to a safe alphabet.
pub(crate) fn safe_key(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() || s.len() > 128 || s.starts_with('.') || !s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        return Err(format!("invalid session key `{s}`"));
    }
    Ok(s.to_string())
}

pub(crate) fn esc_html(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// Drop zero-width and bidi control characters (OpenClaw `stripInvisibleUnicode`).
pub(crate) fn strip_invisible(s: &str) -> String {
    s.chars().filter(|c| !matches!(*c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF | 0x00AD)).collect()
}

/// One model completion through the kernel's resolver (aux model unless `model` is given).
pub struct Completion<'a> {
    pub model: Option<&'a str>,
    pub system: &'a str,
    pub user: String,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
    pub reasoning: Option<String>,
    pub timeout: Duration,
}

/// Returns (text, `provider/model`).
pub fn complete(k: &Kernel, c: Completion, cancel: &Cancel) -> Result<(String, String), String> {
    let m = c.model.filter(|m| !m.trim().is_empty()).map(str::to_string).unwrap_or_else(|| k.cfg.aux_model().to_string());
    let (pid, name) = ark_kernel::context::split_model(&m);
    let p = k.resolver.provider(pid)?;
    let req = ark_core::ModelRequest {
        model: name.to_string(),
        system: if c.system.is_empty() { vec![] } else { vec![SystemSegment { id: "surface".into(), text: c.system.to_string(), cache: false }] },
        messages: vec![Message { role: Role::User, content: vec![Block::text(c.user)] }],
        tools: vec![],
        max_tokens: c.max_tokens,
        temperature: c.temperature,
        cache_after_message: None,
        reasoning: c.reasoning,
        options: Default::default(),
    };
    // The provider polls `cancel`; a watchdog fires it when the timeout passes.
    let local = cancel.child();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let watchdog = {
        let l = local.clone();
        let t = c.timeout;
        std::thread::spawn(move || {
            if done_rx.recv_timeout(t).is_err() {
                l.cancel();
            }
        })
    };
    let r = p.complete(&req, &mut |_| {}, &local);
    let _ = done_tx.send(());
    let _ = watchdog.join();
    let r = r.map_err(|e| if local.is_cancelled() && !cancel.is_cancelled() { format!("model call timed out after {} ms", c.timeout.as_millis()) } else { e.message })?;
    let text = r.message.content.iter().filter_map(|b| if let Block::Text { text } = b { Some(text.as_str()) } else { None }).collect::<Vec<_>>().join("");
    Ok((text, m))
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Fake model provider, kernel and HTTP server for the surface tests.
    use super::*;
    use ark_core::{ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, StopReason, StreamEvent, Usage};
    use ark_kernel::kernel::Resolver;
    use std::collections::VecDeque;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::Mutex;

    pub struct Fake {
        pub replies: Mutex<VecDeque<String>>,
        pub seen: Mutex<Vec<ModelRequest>>,
    }
    impl Provider for Fake {
        fn id(&self) -> &str {
            "fake"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 100_000, max_output: 8192, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            self.seen.lock().unwrap().push(req.clone());
            let text = self.replies.lock().unwrap().pop_front().unwrap_or_else(|| "{}".into());
            Ok(ModelResponse { message: Message { role: Role::Assistant, content: vec![Block::text(text)] }, stop: StopReason::EndTurn, usage: Usage::default(), model: req.model.clone() })
        }
    }
    struct Res(Arc<Fake>);
    impl Resolver for Res {
        fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
            if id == "fake" { Ok(self.0.clone()) } else { Err(format!("no provider {id}")) }
        }
    }

    pub fn temp(tag: &str) -> PathBuf {
        // Removed when the test's thread ends (ark_core::tmp::scratch): every surfaces test used
        // to leave `ark-surf-*` behind in $TMPDIR.
        ark_core::tmp::scratch(&format!("ark-surf-{tag}"))
    }

    /// A kernel whose models are all the scripted fake, plus an Env over a temp data dir.
    pub fn env(tag: &str, replies: &[&str], surfaces: &str) -> (Arc<Env>, Arc<Fake>) {
        let root = temp(tag);
        let paths = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") };
        // Test snippets are written relative to [surfaces]: `[diffs]` means `[surfaces.diffs]`.
        let scoped: String = surfaces.lines().map(|l| if let Some(r) = l.strip_prefix("[[") { format!("[[surfaces.{r}\n") } else if let Some(r) = l.strip_prefix('[') { format!("[surfaces.{r}\n") } else { format!("{l}\n") }).collect();
        let toml_cfg = format!("[model]\ndefault = \"fake/m\"\naux = \"fake/aux\"\n[surfaces]\n{scoped}");
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), &toml_cfg).unwrap();
        let cfg = Config::load(Some(&paths.user_config()), None, &[]).unwrap();
        let fake = Arc::new(Fake { replies: Mutex::new(replies.iter().map(|s| s.to_string()).collect()), seen: Mutex::new(vec![]) });
        let vault = Arc::new(ark_kernel::vault::Vault::load(&paths.secrets()).unwrap());
        let k = ark_kernel::kernel::new_kernel(cfg.clone(), paths.clone(), Arc::new(Res(fake.clone())), vec![], vault, Arc::new(ark_kernel::approver::Policy { allow_privilege: true, allow_egress: true }));
        let slot: Slot = Arc::default();
        let _ = slot.set(k);
        (Arc::new(Env::new(&cfg, &paths, slot, BTreeMap::new()).unwrap()), fake)
    }

    pub fn ctx(env: &Env, ws: &Path) -> ark_core::ToolCtx {
        struct H;
        impl ark_core::ToolHost for H {
            fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
                Err("no".into())
            }
            fn ask_user(&self, _: &str) -> Result<String, String> {
                Err("headless".into())
            }
        }
        ark_core::ToolCtx { workspace: ws.to_path_buf(), session_id: "s1".into(), artifacts: ws.join(".art"), home: env.dir.parent().unwrap().to_path_buf(), cancel: Cancel::new(), host: Arc::new(H), secrets: Arc::new(|s: &str| s.to_string()) }
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct Seen {
        pub method: String,
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }
    pub type Handler = Box<dyn Fn(&Seen) -> (u16, Vec<(String, String)>, String) + Send>;

    /// One request per connection; `handler` answers each.
    pub fn server(handler: Handler) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { break };
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
                let mut headers = vec![];
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.trim().split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        headers.push((k.trim().to_lowercase(), v.trim().to_string()));
                    }
                }
                let mut body = vec![0; len];
                let _ = r.read_exact(&mut body);
                let req = Seen { method, path, headers, body: String::from_utf8_lossy(&body).into() };
                let (status, hs, b) = handler(&req);
                s2.lock().unwrap().push(req);
                let mut out = format!("HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n", b.len());
                for (k, v) in hs {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                out.push_str(&b);
                let _ = c.write_all(out.as_bytes());
            }
        });
        (url, seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2026, 11, 3), civil_inv(2026, 11, 3));
        assert_eq!(iso(1_793_664_000_000), "2026-11-03T00:00:00Z");
        assert_eq!(parse_iso("2026-11-03T01:02:03.5Z"), Some(1_793_664_000_000 + 3_723_500));
        assert_eq!(parse_iso("2026-11-03T09:00:00+08:00"), Some(1_793_664_000_000 + 3_600_000));
        assert_eq!(parse_iso("2026-11-03"), Some(1_793_664_000_000));
    }
    fn civil_inv(y: i64, m: u32, d: u32) -> i64 {
        (0..30000).find(|n| civil(*n) == (y, m, d)).unwrap()
    }

    #[test]
    fn base_url_defaults_to_listen() {
        assert_eq!(base_url(None, "0.0.0.0:8640"), "http://127.0.0.1:8640");
        assert_eq!(base_url(Some("https://x.example/"), "0.0.0.0:1"), "https://x.example");
    }

    #[test]
    fn config_parses_and_rejects_unknown_keys() {
        let t: toml::Table = "[llm_task]\ndefault_model = \"a/b\"\n".parse().unwrap();
        assert_eq!(SurfacesConfig::parse(&t).unwrap().llm_task.default_model, "a/b");
        let bad: toml::Table = "nope = 1".parse().unwrap();
        assert!(SurfacesConfig::parse(&bad).is_err());
    }

    /// The `surfaces::tools()` catalog the agent sees: every surface tool is registered
    /// under the name its module documents (a missing entry means the model cannot call it).
    #[test]
    fn every_surface_tool_is_registered() {
        let root = testkit::temp("tools");
        let paths = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), "[model]\ndefault = \"fake/m\"\n[surfaces.team_reports]\n[surfaces.team_reports.github]\ntoken = \"{{secret:GH}}\"\norgs = [\"acme\"]\n").unwrap();
        let cfg = Config::load(Some(&paths.user_config()), None, &[]).unwrap();
        let names: Vec<String> = tools(&cfg, &paths, Slot::default(), BTreeMap::new()).unwrap().iter().map(|t| t.spec().name).collect();
        for want in ["canvas", "show_widget", "dashboard", "progress_card", "gateway", "lobster", "diffs", "llm-task", "file_fetch", "dir_list", "dir_fetch", "file_write", "team_reports"] {
            assert!(names.iter().any(|n| n == want), "{want} is not registered: {names:?}");
        }
        // team_reports is opt-in: without `[surfaces.team_reports]` it is not offered.
        let t: toml::Table = toml::Table::new();
        let plain = SurfacesConfig::parse(&t).unwrap();
        assert!(plain.team_reports.is_none());
    }

    #[test]
    fn complete_times_out() {
        struct Slow;
        impl ark_core::Provider for Slow {
            fn id(&self) -> &str {
                "slow"
            }
            fn caps(&self, _: &str) -> ark_core::ModelCaps {
                ark_core::ModelCaps { context_window: 1000, max_output: 100, tools: false, vision: false, explicit_cache: false }
            }
            fn complete(&self, _: &ark_core::ModelRequest, _: &mut dyn FnMut(ark_core::StreamEvent), c: &Cancel) -> Result<ark_core::ModelResponse, ark_core::ProviderError> {
                while !c.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(ark_core::ProviderError::new(ark_core::ProviderErrorKind::Cancelled, "cancelled"))
            }
        }
        struct R;
        impl ark_kernel::kernel::Resolver for R {
            fn provider(&self, _: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
                Ok(Arc::new(Slow))
            }
        }
        let root = testkit::temp("slow");
        let paths = Paths { data: root.join("d"), config_dir: root.join("c"), runtime: root.join("r") };
        let cfg = Config::load(None, None, &["model.default=slow/x".into()]).unwrap();
        let vault = Arc::new(ark_kernel::vault::Vault::load(&paths.secrets()).unwrap());
        let k = ark_kernel::kernel::new_kernel(cfg, paths, Arc::new(R), vec![], vault, Arc::new(ark_kernel::approver::Policy { allow_privilege: false, allow_egress: false }));
        let e = complete(&k, Completion { model: Some("slow/x"), system: "", user: "hi".into(), max_tokens: 10, temperature: None, reasoning: None, timeout: Duration::from_millis(50) }, &Cancel::new()).unwrap_err();
        assert!(e.contains("timed out"), "{e}");
    }
}
