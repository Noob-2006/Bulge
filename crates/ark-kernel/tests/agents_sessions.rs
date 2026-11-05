//! Session / agent tools (`sessions`, `sessions_create`, `sessions_list`,
//! `sessions_history`, `sessions_send`, `clarify`), `session_search` shapes and the
//! rewind / branch / structured-output paths, driven through a scripted provider.

use ark_core::*;
use ark_kernel::agents::{session_search, AgentDef};
use ark_kernel::approver::{Approval, ApprovalRequest, Approver, ClarifyQuestion, ClarifyReply, Policy};
use ark_kernel::config::{Config, Paths};
use ark_kernel::event::{Event, EventKind};
use ark_kernel::hooks::{Hook, HookDecision, HookEvent};
use ark_kernel::kernel::{new_kernel, EndReason, Kernel, Resolver, RunOpts};
use ark_kernel::projection::{project, View};
use ark_kernel::vault::Vault;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod agents_sessions {
    use super::*;

    // ───────────── scripted providers ─────────────

    type Step = Box<dyn FnOnce(&ModelRequest) -> Result<ModelResponse, ProviderError> + Send>;

    struct Scripted {
        id: String,
        steps: Mutex<VecDeque<Step>>,
        seen: Mutex<Vec<ModelRequest>>,
    }

    impl Scripted {
        fn new(id: &str) -> Arc<Self> {
            Arc::new(Scripted { id: id.into(), steps: Mutex::new(VecDeque::new()), seen: Mutex::new(vec![]) })
        }
        fn text(&self, t: &str) {
            let t = t.to_string();
            self.push(move |_| Ok(resp(vec![Block::text(t)], StopReason::EndTurn)));
        }
        fn call(&self, name: &str, input: Value) {
            let (name, input) = (name.to_string(), input);
            self.push(move |_| Ok(resp(vec![Block::ToolUse { id: format!("tu_{}", rand()) , name, input }], StopReason::ToolUse)));
        }
        fn push(&self, s: impl FnOnce(&ModelRequest) -> Result<ModelResponse, ProviderError> + Send + 'static) {
            self.steps.lock().unwrap().push_back(Box::new(s));
        }
        fn requests(&self) -> Vec<ModelRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    /// A provider that answers nothing until the run is cancelled (a "stuck" session).
    struct Blocking {
        id: String,
    }

    impl Provider for Blocking {
        fn id(&self) -> &str {
            &self.id
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, _: &ModelRequest, _: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !cancel.is_cancelled() {
                if Instant::now() > deadline {
                    return Ok(resp(vec![Block::text("blocking provider timed out")], StopReason::EndTurn));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(ProviderError::new(ProviderErrorKind::Cancelled, "cancelled"))
        }
    }

    impl Provider for Scripted {
        fn id(&self) -> &str {
            &self.id
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 200_000, max_output: 8192, tools: true, vision: true, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
            self.seen.lock().unwrap().push(req.clone());
            if cancel.is_cancelled() {
                return Err(ProviderError::new(ProviderErrorKind::Cancelled, "c"));
            }
            match self.steps.lock().unwrap().pop_front() {
                Some(s) => {
                    let r = s(req);
                    if let Ok(r) = &r {
                        on(StreamEvent::TextDelta(r.message.text()));
                    }
                    r
                }
                None => Ok(resp(vec![Block::text("(script exhausted)")], StopReason::EndTurn)),
            }
        }
    }

    fn rand() -> String {
        static N: AtomicUsize = AtomicUsize::new(0);
        format!("{}", N.fetch_add(1, Ordering::SeqCst))
    }

    fn rand_hex() -> String {
        format!("{:x}{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(), rand())
    }

    fn resp(content: Vec<Block>, stop: StopReason) -> ModelResponse {
        ModelResponse { message: Message { role: Role::Assistant, content }, stop, usage: Usage { input_tokens: 10, output_tokens: 5, ..Default::default() }, model: String::new() }
    }

    struct Res(HashMap<String, Arc<dyn Provider>>);
    impl Resolver for Res {
        fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
            self.0.get(id).cloned().ok_or_else(|| format!("no provider {id}"))
        }
    }

    // ───────────── env ─────────────

    struct Env {
        k: Kernel,
        paths: Paths,
        ws: PathBuf,
        main: Arc<Scripted>,
        aux: Arc<Scripted>,
    }

    struct Yes;
    impl Approver for Yes {
        fn approve(&self, _: &ApprovalRequest) -> Approval {
            Approval::Always
        }
        fn ask(&self, _: &str, q: &str) -> Result<String, String> {
            Ok(format!("answer to {q}"))
        }
    }

    fn env_with(approver: Arc<dyn Approver>, cfg_mut: impl FnOnce(&mut Config)) -> Env {
        let root = ark_core::tmp::scratch_path(format!("ark-as-{}", rand_hex()));
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let mut cfg = Config::default();
        cfg.model.default = "main/m1".into();
        cfg.checkpoint.enabled = false;
        cfg.runner.max_retries = 1;
        cfg_mut(&mut cfg);
        let main = Scripted::new("main");
        let aux = Scripted::new("aux");
        let mut map: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        map.insert("main".into(), main.clone());
        map.insert("aux".into(), aux.clone());
        map.insert("slow".into(), Arc::new(Blocking { id: "slow".into() }));
        let k = new_kernel(cfg, paths.clone(), Arc::new(Res(map)), vec![], Arc::new(Vault::empty()), approver);
        Env { k, paths, ws, main, aux }
    }

    fn env() -> Env {
        env_with(Arc::new(Yes), |_| {})
    }

    fn new_session(e: &Env, prompt: &str) -> String {
        let id = e.k.create_session(&e.ws, None, None, None).unwrap();
        e.k.submit(&id, prompt, "cli").unwrap();
        e.k.run(&id, RunOpts::default()).unwrap();
        id
    }

    /// One more turn on an existing session.
    fn turn(e: &Env, id: &str, prompt: &str) -> EndReason {
        e.k.submit(id, prompt, "cli").unwrap();
        e.k.run(id, RunOpts::default()).unwrap().reason
    }

    fn events(e: &Env, id: &str) -> Vec<Event> {
        e.k.store.read(id).unwrap()
    }

    fn view(e: &Env, id: &str) -> View {
        project(&events(e, id))
    }

    /// `(tool name, output content, is_error)` for every settled tool call, in order.
    fn tool_outputs(e: &Env, id: &str) -> Vec<(String, String, bool)> {
        let mut names: HashMap<String, String> = HashMap::new();
        let mut out = Vec::new();
        for ev in events(e, id) {
            if let EventKind::Message { message, .. } = ev.kind {
                for b in message.content {
                    match b {
                        Block::ToolUse { id, name, .. } => {
                            names.insert(id, name);
                        }
                        Block::ToolResult { tool_use_id, content, is_error } => {
                            out.push((names.get(&tool_use_id).cloned().unwrap_or_default(), content, is_error));
                        }
                        _ => {}
                    }
                }
            }
        }
        out
    }

    fn last_json(e: &Env, id: &str) -> Value {
        let (name, content, is_err) = tool_outputs(e, id).pop().unwrap_or_else(|| panic!("no tool call in session {id}"));
        assert!(!is_err, "{name} failed: {content}");
        serde_json::from_str(&content).unwrap_or_else(|e| panic!("{name} did not return JSON ({e}): {content}"))
    }

    fn last_error(e: &Env, id: &str) -> String {
        let (name, content, is_err) = tool_outputs(e, id).pop().unwrap_or_else(|| panic!("no tool call in session {id}"));
        assert!(is_err, "{name} was expected to fail, got: {content}");
        content
    }

    // ───────────── sessions: patch / list / stop ─────────────

    #[test]
    fn sessions_patch_pin_archive_group_and_stop() {
        let e = env();
        let id = new_session(&e, "hello");

        e.main.call("sessions", json!({"action": "patch", "label": "My session", "pinned": true, "group": "work", "status": "waiting on CI"}));
        e.main.text("patched");
        turn(&e, &id, "name this session");
        let out = last_json(&e, &id);
        assert_eq!(out["action"], "patch");
        assert_eq!(out["applied"]["label"], "My session");
        assert_eq!(out["applied"]["pinned"], true);
        assert_eq!(out["applied"]["group"], "work");
        assert_eq!(out["applied"]["status"], "waiting on CI");
        let v = view(&e, &id);
        assert!(v.title.as_deref() == Some("My session"), "title event landed: {:?}", v.title);
        assert!(v.pinned && v.group.as_deref() == Some("work") && v.status.as_deref() == Some("waiting on CI"));
        // The events are what other readers see, not just this session's projection.
        assert!(events(&e, &id).iter().any(|ev| matches!(&ev.kind, EventKind::Title { title } if title == "My session")));
        assert!(events(&e, &id).iter().any(|ev| matches!(&ev.kind, EventKind::Meta { pinned: Some(true), .. })));

        // Archived sessions drop out of the default list and come back with archived=true.
        e.main.call("sessions", json!({"action": "patch", "archived": true}));
        e.main.call("sessions_list", json!({"limit": 50}));
        e.main.call("sessions_list", json!({"limit": 50, "archived": true}));
        e.main.text("archived");
        turn(&e, &id, "archive it");
        let outs = tool_outputs(&e, &id);
        let listed: Vec<&(String, String, bool)> = outs.iter().filter(|o| o.0 == "sessions_list").collect();
        assert_eq!(listed.len(), 2);
        let active: Value = serde_json::from_str(&listed[0].1).unwrap();
        assert!(active.as_array().unwrap().iter().all(|r| r["id"] != json!(id)), "archived row hidden by default: {active}");
        let all: Value = serde_json::from_str(&listed[1].1).unwrap();
        let row = all.as_array().unwrap().iter().find(|r| r["id"] == json!(id)).cloned().expect("archived row listed with archived=true");
        assert_eq!(row["archived"], true);
        assert_eq!(row["pinned"], true);
        assert_eq!(row["group"], "work");

        // stop: a session stuck inside its provider is cancelled by another session's tool call.
        let stuck = e.k.create_session(&e.ws, Some("slow/m1"), None, None).unwrap();
        e.k.submit(&stuck, "work forever", "cli").unwrap();
        let k = e.k.clone();
        let sid = stuck.clone();
        let h = std::thread::spawn(move || k.run(&sid, RunOpts::default()));
        let deadline = Instant::now() + Duration::from_secs(10);
        while !e.k.is_running(&stuck) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(e.k.is_running(&stuck), "the stuck session never started");

        e.main.call("sessions", json!({"action": "stop", "session": stuck.clone()}));
        e.main.text("stopped it");
        turn(&e, &id, "stop the stuck session");
        let out = last_json(&e, &id);
        assert_eq!(out["action"], "stop");
        assert_eq!(out["wasRunning"], true);
        assert_eq!(out["stopped"], true, "interrupt reached the running session: {out}");
        let o = h.join().unwrap().unwrap();
        assert_eq!(o.reason, EndReason::Interrupted, "the stuck turn was cancelled");
        assert!(!e.k.is_running(&stuck));

        // A second stop has nothing to cancel, and says so instead of failing.
        e.main.call("sessions", json!({"action": "stop", "session": stuck.clone()}));
        e.main.text("already idle");
        turn(&e, &id, "stop again");
        let out = last_json(&e, &id);
        assert_eq!(out["stopped"], false);

        // status: this session is running right now (the call comes from its own turn), the
        // stopped one is not.
        e.main.call("sessions", json!({"action": "status", "session": id.clone()}));
        e.main.call("sessions", json!({"action": "status", "session": stuck.clone()}));
        e.main.call("sessions", json!({"action": "list", "group_filter": "work", "archived": true}));
        e.main.call("sessions", json!({"action": "list", "group_filter": "other", "archived": true}));
        e.main.text("status");
        turn(&e, &id, "inspect");
        let outs = tool_outputs(&e, &id);
        let statuses: Vec<Value> = outs.iter().filter(|o| o.0 == "sessions" && o.1.contains("\"action\": \"status\"")).map(|o| serde_json::from_str(&o.1).unwrap()).collect();
        assert_eq!(statuses.len(), 2);
        let status = &statuses[0];
        assert_eq!(status["session"]["id"], json!(id));
        assert_eq!(status["session"]["pinned"], true);
        assert_eq!(status["session"]["archived"], true);
        assert_eq!(status["session"]["group"], "work");
        assert_eq!(status["session"]["running"], true, "a session asking about itself is running");
        assert!(status["session"]["pending_input"].is_array());
        assert_eq!(statuses[1]["session"]["running"], false, "the stopped session is idle again");
        let groups: Vec<Value> = outs.iter().filter(|o| o.0 == "sessions" && o.1.contains("\"action\": \"list\"")).map(|o| serde_json::from_str(&o.1).unwrap()).collect();
        assert_eq!(groups.len(), 2);
        assert!(groups[0]["sessions"].as_array().unwrap().iter().any(|r| r["id"] == json!(id)), "group filter finds it: {}", groups[0]);
        assert!(groups[1]["sessions"].as_array().unwrap().is_empty(), "other group is empty: {}", groups[1]);

        // reset: hooks fire, the transcript is kept, the caller's own turn is not cut.
        e.main.call("sessions", json!({"action": "reset", "session": id.clone()}));
        e.main.text("reset");
        let reason = turn(&e, &id, "reset this session");
        let out = last_json(&e, &id);
        assert_eq!(out["reset"], true);
        assert_eq!(out["wasRunning"], true, "the call comes from this session's own running turn");
        assert_eq!(reason, EndReason::Done, "a self-reset does not cancel the turn that asked for it");
        assert!(!events(&e, &id).is_empty(), "reset kept the transcript");

        // Unknown targets are named, with the inventory tool as the way out.
        e.main.call("sessions", json!({"action": "stop", "session": "nope-123"}));
        e.main.text("done");
        turn(&e, &id, "stop a ghost");
        assert!(last_error(&e, &id).contains("no session `nope-123`"));
    }

    // ───────────── create / list / history / send ─────────────

    #[test]
    fn sessions_create_list_history_send() {
        let e = env_with(Arc::new(Yes), |c| {
            c.agents.insert("ops".into(), AgentDef { name: "Ops".into(), identity: "You are ops, the on-call agent.".into(), ..Default::default() });
        });
        let user = ark_kernel::agents::user_add(&e.paths, "Amy").unwrap();
        ark_kernel::agents::user_set_instructions(&e.paths, &user.id, "Reply in 繁體中文.").unwrap();
        let id = new_session(&e, "start");

        e.main.call("sessions_create", json!({"agent": "ops", "user": user.id, "title": "ops chat", "model": "aux/m1"}));
        e.main.call("sessions_create", json!({"agentId": "ghost"}));
        e.main.text("created");
        turn(&e, &id, "make a session");
        let outs = tool_outputs(&e, &id);
        let created: Value = serde_json::from_str(outs.iter().find(|o| o.0 == "sessions_create" && !o.2).map(|o| o.1.as_str()).expect("created a session")).unwrap();
        let child = created["session_id"].as_str().unwrap().to_string();
        assert_eq!(created["agent"], "ops");
        assert_eq!(created["user"], user.id);
        assert_eq!(created["model"], "aux/m1");
        assert_eq!(created["title"], "ops chat");
        let ghost = outs.iter().find(|o| o.0 == "sessions_create" && o.2).expect("unknown agent is an error");
        assert!(ghost.1.contains("unknown agent `ghost`"), "{}", ghost.1);

        // The agent's identity and the user's personal instructions land in the System segment.
        let cv = view(&e, &child);
        assert_eq!(cv.agent.as_deref(), Some("ops"));
        assert_eq!(cv.user.as_deref(), Some(user.id.as_str()));
        let identity = cv.system.iter().find(|s| s.id == "identity").map(|s| s.text.clone()).unwrap_or_default();
        assert!(identity.contains("You are ops"), "{identity}");
        assert!(identity.contains("Personal instructions from Amy") && identity.contains("繁體中文"), "{identity}");

        // list: query filters id/title, rows carry the sidebar settings.
        let child_of_caller = e.k.create_session(&e.ws, None, Some(&id), Some("child of caller")).unwrap();
        e.main.call("sessions_list", json!({"query": "ops chat"}));
        e.main.call("sessions_list", json!({"query": "nothing-matches-this"}));
        e.main.call("sessions_list", json!({"include_children": false}));
        e.main.text("listed");
        turn(&e, &id, "list them");
        let outs = tool_outputs(&e, &id);
        let listed: Vec<Value> = outs.iter().filter(|o| o.0 == "sessions_list").map(|o| serde_json::from_str(&o.1).unwrap()).collect();
        assert_eq!(listed[0].as_array().unwrap().len(), 1);
        assert_eq!(listed[0][0]["id"], json!(child));
        for k in ["title", "model", "updated", "messages", "pinned", "archived", "group", "status", "parent"] {
            assert!(listed[0][0].get(k).is_some(), "row is missing `{k}`: {}", listed[0][0]);
        }
        assert!(listed[1].as_array().unwrap().is_empty());
        assert!(
            listed[2].as_array().unwrap().iter().all(|r| r["id"] != json!(child_of_caller)),
            "include_children=false hides sessions whose header names a parent: {}",
            listed[2]
        );
        assert!(listed[2].as_array().unwrap().iter().any(|r| r["id"] == json!(id)), "the caller itself stays");

        // history: role filter, tools hidden by default.
        e.main.call("sessions_history", json!({"session": id.clone(), "role": "assistant", "limit": 10}));
        e.main.call("sessions_history", json!({"session": id.clone(), "tools": true, "limit": 40}));
        e.main.call("sessions_history", json!({"session": child.clone(), "limit": 10}));
        e.main.text("history");
        turn(&e, &id, "read history");
        let outs = tool_outputs(&e, &id);
        let hs: Vec<Value> = outs.iter().filter(|o| o.0 == "sessions_history").map(|o| serde_json::from_str(&o.1).unwrap()).collect();
        assert_eq!(hs.len(), 3);
        let h = &hs[0];
        assert!(h["messages"].as_array().unwrap().iter().all(|m| m["role"] == "assistant"), "{h}");
        assert!(h["total"].as_u64().unwrap() >= 1);
        assert!(h["messages"].as_array().unwrap().iter().all(|m| !m["text"].as_str().unwrap().contains("[called ")), "tool calls hidden by default: {h}");
        let with_tools = &hs[1];
        assert!(with_tools["messages"].as_array().unwrap().iter().any(|m| m["text"].as_str().unwrap().contains("[called ")), "tools:true shows the calls: {with_tools}");
        let child_h = &hs[2];
        assert_eq!(child_h["messages"].as_array().unwrap().len(), 0, "an idle new session has no messages");

        // send wait=true: the target runs now and its reply comes back in the call.
        e.aux.text("target reply");
        e.main.call("sessions_send", json!({"session": child.clone(), "message": "say hi", "wait": true}));
        e.main.text("sent");
        turn(&e, &id, "talk to ops");
        let out = last_json(&e, &id);
        assert_eq!(out["sessionKey"], json!(child));
        assert_eq!(out["wait"], true);
        assert_eq!(out["reply"], "target reply", "{out}");
        assert_eq!(out["reason"], "done");

        // send wait=false: a background run, addressed by runId.
        let bg = e.k.create_session(&e.ws, Some("aux/m1"), None, None).unwrap();
        e.aux.text("background reply");
        e.main.call("sessions_send", json!({"session": bg.clone(), "message": "go", "wait": false}));
        e.main.text("sent");
        turn(&e, &id, "start background work");
        let out = last_json(&e, &id);
        let run_id = out["runId"].as_str().expect("wait=false returns runId").to_string();
        assert!(run_id.starts_with("dm-"), "{run_id}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen_reply = false;
        while Instant::now() < deadline && !seen_reply {
            seen_reply = events(&e, &bg).iter().any(|ev| matches!(&ev.kind, EventKind::Message { message, .. } if message.text().contains("background reply")));
            if !seen_reply {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        assert!(seen_reply, "the background run actually ran the target session");

        // Targeting yourself is refused (it would recurse into the running turn).
        e.main.call("sessions_send", json!({"session": id.clone(), "message": "hello me"}));
        e.main.text("done");
        turn(&e, &id, "self send");
        assert!(last_error(&e, &id).contains("cannot target the calling session"));
    }

    // ───────────── clarify ─────────────

    struct Clarifier {
        seen: Arc<Mutex<Vec<ClarifyQuestion>>>,
        answers: Vec<(&'static str, Value)>,
    }

    impl Approver for Clarifier {
        fn approve(&self, _: &ApprovalRequest) -> Approval {
            Approval::Deny
        }
        fn ask(&self, _: &str, _: &str) -> Result<String, String> {
            Err("headless".into())
        }
        fn clarify(&self, _session: &str, qs: &[ClarifyQuestion]) -> ClarifyReply {
            self.seen.lock().unwrap().extend(qs.iter().cloned());
            let mut answers = BTreeMap::new();
            for q in qs {
                answers.insert(q.qid.clone(), self.answers.iter().find(|(id, _)| *id == q.qid).map(|(_, v)| v.clone()));
            }
            ClarifyReply { answers, outcome: "submitted".into(), notice: None }
        }
    }

    /// Records the human-input hook payloads (what a channel/UI would render).
    struct InputHook(Arc<Mutex<Vec<Value>>>);
    impl Hook for InputHook {
        fn name(&self) -> String {
            "test-input-hook".into()
        }
        fn wants(&self, event: HookEvent, _: Option<&str>) -> bool {
            matches!(event, HookEvent::HumanInputRequest | HookEvent::HumanInputResolved)
        }
        fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
            let mut p = payload.clone();
            p["event"] = json!(format!("{event:?}"));
            self.0.lock().unwrap().push(p);
            Ok(HookDecision::Allow)
        }
    }

    #[test]
    fn clarify_choices_and_free_text() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let hook_seen = Arc::new(Mutex::new(Vec::new()));
        let approver = Arc::new(Clarifier { seen: seen.clone(), answers: vec![("q0", json!("Postgres")), ("q1", json!("Ada"))] });
        let e = env_with(approver, |_| {});
        e.k.add_hooks(vec![Arc::new(InputHook(hook_seen.clone()))]);
        let id = new_session(&e, "start");

        e.main.call(
            "clarify",
            json!({"questions": [
                {"question": "Which database?", "choices": ["Postgres", "SQLite"]},
                {"question": "What is the project name?"}
            ]}),
        );
        e.main.text("thanks");
        turn(&e, &id, "ask the user");
        let out = last_json(&e, &id);
        assert_eq!(out["outcome"], "submitted");
        assert_eq!(out["answers"]["q0"], "Postgres", "presentation label is stripped from the answer: {out}");
        assert_eq!(out["answers"]["q1"], "Ada");
        assert_eq!(out["responses"][0]["status"], "answered");
        assert_eq!(out["responses"][1]["question"], "What is the project name?");

        // The recommended option is marked once, by the tool, before the surface sees it.
        let qs = seen.lock().unwrap().clone();
        assert_eq!(qs[0].choices, vec!["Postgres (Recommended)".to_string(), "SQLite".to_string()]);
        assert!(!qs[0].multi_select && qs[1].choices.is_empty());
        // Hooks saw the questions as a UI would.
        let hooked = hook_seen.lock().unwrap().clone();
        let req = hooked.iter().find(|p| p["event"] == "HumanInputRequest").expect("HumanInputRequest fired");
        assert_eq!(req["kind"], "clarify");
        assert!(req["message"].as_str().unwrap().contains("Which database?"));
        assert_eq!(req["questions"][0]["choices"][0], "Postgres (Recommended)");
        assert!(hooked.iter().any(|p| p["event"] == "HumanInputResolved" && p["outcome"] == "submitted"));

        // multi_select: a list answer, and a skipped question reports status=skipped.
        let seen2 = Arc::new(Mutex::new(Vec::new()));
        let approver2 = Arc::new(Clarifier { seen: seen2.clone(), answers: vec![("q0", json!(["a", "c"])), ("q1", Value::Null)] });
        let e2 = env_with(approver2, |_| {});
        let id2 = new_session(&e2, "start");
        e2.main.call(
            "clarify",
            json!({"questions": [{"question": "Which features?", "choices": ["a", "b", "c"], "multi_select": true}, {"question": "Anything else?"}]}),
        );
        e2.main.text("ok");
        turn(&e2, &id2, "ask");
        let out = last_json(&e2, &id2);
        assert_eq!(out["answers"]["q0"], json!(["a", "c"]));
        assert_eq!(out["answers"]["q1"], Value::Null);
        assert_eq!(out["responses"][0]["multi_select"], true);
        assert_eq!(out["responses"][1]["status"], "skipped");
        assert_eq!(seen2.lock().unwrap()[0].choices[0], "a (Recommended)");

        // Validation errors are readable, not panics.
        e2.main.call("clarify", json!({"questions": [{"question": "  "}]}));
        e2.main.call("clarify", json!({"questions": []}));
        e2.main.call("clarify", json!({"questions": [{"question": "pick", "choices": [" ", ""]}]}));
        e2.main.text("done");
        turn(&e2, &id2, "bad questions");
        let outs = tool_outputs(&e2, &id2);
        let errs: Vec<&str> = outs.iter().filter(|o| o.0 == "clarify" && o.2).map(|o| o.1.as_str()).collect();
        assert_eq!(errs.len(), 3);
        assert!(errs[0].contains("questions[0].question must be non-empty"), "{}", errs[0]);
        assert!(errs[1].contains("at least one question"), "{}", errs[1]);
        assert!(errs[2].contains("all are blank"), "{}", errs[2]);
    }

    #[test]
    fn clarify_headless_reports_undelivered() {
        let e = env_with(Arc::new(Policy { allow_privilege: false, allow_egress: false }), |_| {});
        let id = new_session(&e, "start");
        e.main.call("clarify", json!({"question": "Which way?", "choices": ["left", "right"]}));
        e.main.text("decided myself");
        let reason = turn(&e, &id, "ask a headless session");
        assert_eq!(reason, EndReason::Done, "no panic, the turn finishes");
        let out = last_json(&e, &id);
        assert_eq!(out["outcome"], "undelivered");
        assert_eq!(out["answers"]["q0"], Value::Null);
        assert_eq!(out["responses"][0]["status"], "unanswered");
        assert!(out["notice"].as_str().unwrap().contains("no human"), "{out}");
    }

    // ───────────── session_search ─────────────

    #[test]
    fn session_search_read_scroll_filters_summary() {
        let e = env();
        e.main.text("alpha answer one");
        let s1 = new_session(&e, "alpha beta question");
        e.main.text("second answer");
        turn(&e, &s1, "second question");
        e.main.text("delta alpha two");
        let s2 = new_session(&e, "gamma question");

        // query over all sessions
        let out = session_search(&e.k.store, &json!({"query": "alpha", "limit": 10}));
        assert!(out.contains(&s1) && out.contains(&s2), "{out}");
        assert!(out.contains("[assistant]") && out.contains("[user]"), "{out}");
        // role filter
        let out = session_search(&e.k.store, &json!({"query": "alpha", "role": "assistant"}));
        assert!(out.contains(&s2) && !out.contains("[user]"), "{out}");
        // session filter
        let out = session_search(&e.k.store, &json!({"query": "alpha", "session": s1}));
        assert!(out.contains(&s1) && !out.contains(&s2), "{out}");
        // no match
        assert_eq!(session_search(&e.k.store, &json!({"query": "zzz-none"})), "no matches");

        // read: the tail of one transcript
        let v: Value = serde_json::from_str(&session_search(&e.k.store, &json!({"session": s1, "read": true, "limit": 2}))).unwrap();
        assert_eq!(v["total"], 4, "{v}");
        assert_eq!(v["offset"], 2);
        assert_eq!(v["returned"], 2);
        assert_eq!(v["has_more"], false);
        assert_eq!(v["messages"][0]["role"], "user");
        assert_eq!(v["messages"][1]["text"], "second answer");
        // read without `read`: `session` alone reads the transcript (a friendlier default)
        let solo: Value = serde_json::from_str(&session_search(&e.k.store, &json!({"session": s1, "limit": 3}))).unwrap();
        assert_eq!(solo["mode"], "read");
        assert_eq!(solo["returned"], 3);

        // scroll: forward pages with next_offset
        let p1: Value = serde_json::from_str(&session_search(&e.k.store, &json!({"session": s1, "read": true, "scroll": true, "limit": 1}))).unwrap();
        assert_eq!(p1["mode"], "scroll");
        assert_eq!(p1["offset"], 0);
        assert_eq!(p1["next_offset"], 1);
        assert_eq!(p1["has_more"], true);
        assert_eq!(p1["messages"][0]["text"], "alpha beta question");
        let p2: Value = serde_json::from_str(&session_search(&e.k.store, &json!({"session": s1, "read": true, "scroll": true, "offset": 1, "limit": 1}))).unwrap();
        assert_eq!(p2["offset"], 1);
        assert_eq!(p2["messages"][0]["text"], "alpha answer one");
        let p4: Value = serde_json::from_str(&session_search(&e.k.store, &json!({"session": s1, "read": true, "scroll": true, "offset": 3, "limit": 5}))).unwrap();
        assert_eq!(p4["has_more"], false);
        assert_eq!(p4["next_offset"], Value::Null);

        // time bounds: ISO dates and relative spans
        let out = session_search(&e.k.store, &json!({"query": "alpha", "after": "2000-01-01", "before": "2100-01-01"}));
        assert!(out.contains(&s1), "{out}");
        assert_eq!(session_search(&e.k.store, &json!({"query": "alpha", "after": "2100-01-01"})), "no matches");
        assert_eq!(session_search(&e.k.store, &json!({"query": "alpha", "before": "1h"})), "no matches", "before=1h means older than an hour");
        let out = session_search(&e.k.store, &json!({"query": "alpha", "after": "1h"}));
        assert!(out.contains(&s1), "{out}");
        let bad = session_search(&e.k.store, &json!({"query": "alpha", "after": "not-a-date"}));
        assert!(bad.starts_with("session_search: invalid time bound"), "{bad}");
        // bounds also page reads
        let v: Value = serde_json::from_str(&session_search(&e.k.store, &json!({"session": s1, "read": true, "role": "assistant"}))).unwrap();
        assert_eq!(v["total"], 2, "{v}");

        // summary: one block per session, hit count + time range + first sentence
        let s = session_search(&e.k.store, &json!({"query": "alpha", "summary": true}));
        assert!(s.contains(&s1) && s.contains(&s2), "{s}");
        assert!(s.contains("hit(s)"), "{s}");
        assert!(s.contains("→"), "{s}");
        assert!(s.contains("[user] alpha beta question"), "first sentence is quoted: {s}");
        // browse: no query lists recent sessions
        let b = session_search(&e.k.store, &json!({}));
        assert!(b.contains(&s1) && b.contains(&s2), "{b}");
    }

    // ───────────── rewind / branch ─────────────

    #[test]
    fn rewind_and_branch_roundtrip() {
        let e = env();
        e.main.text("answer one");
        let id = new_session(&e, "first question");
        e.main.text("answer two");
        turn(&e, &id, "second question");
        let before = view(&e, &id);
        assert_eq!(before.user_turns.len(), 2);
        assert_eq!(before.messages.len(), 4);

        // rewind one turn: the log is append-only, the projection drops it
        let seq = e.k.rewind(&id, 1).unwrap();
        assert_eq!(seq, before.user_turns[1]);
        let after = view(&e, &id);
        assert_eq!(after.user_turns.len(), 1);
        assert_eq!(after.messages.len(), 2);
        assert!(after.messages.iter().all(|m| !m.text().contains("answer two")), "the rewound exchange is gone from context");
        // ... and from recall: search and reads follow the same view (undo means undone).
        assert_eq!(session_search(&e.k.store, &json!({"query": "answer two"})), "no matches");
        let read: Value = serde_json::from_str(&session_search(&e.k.store, &json!({"session": id, "read": true}))).unwrap();
        assert_eq!(read["total"], 2, "{read}");
        // error paths carry a message
        assert!(e.k.rewind(&id, 0).unwrap_err().contains("nothing to rewind"));
        let err = e.k.rewind(&id, 9).unwrap_err();
        assert!(err.contains("only 1 turn(s)") && err.contains("cannot rewind 9"), "{err}");

        // branch: everything that is live now
        let b = e.k.branch(&id, None).unwrap();
        let bv = view(&e, &b);
        assert_eq!(bv.messages.len(), after.messages.len());
        assert_eq!(bv.messages[0].text(), "first question");
        assert!(bv.title.unwrap_or_default().contains("branch of"));
        assert!(bv.session_id == b);

        // branch at a turn boundary keeps exactly that many turns
        e.main.text("two answer");
        let id2 = new_session(&e, "two one");
        e.main.text("three answer");
        turn(&e, &id2, "two two");
        let b2 = e.k.branch(&id2, Some(1)).unwrap();
        let b2v = view(&e, &b2);
        assert_eq!(b2v.messages.len(), 2, "one user turn + its answer: {:?}", b2v.messages.iter().map(|m| m.text()).collect::<Vec<_>>());
        assert!(b2v.messages[0].text().contains("two one"));
        let err = e.k.branch(&id2, Some(9)).unwrap_err();
        assert!(err.contains("only 2 turn(s)"), "{err}");

        // a running session cannot be rewound mid-turn
        let stuck = e.k.create_session(&e.ws, Some("slow/m1"), None, None).unwrap();
        e.k.submit(&stuck, "forever", "cli").unwrap();
        let k = e.k.clone();
        let sid = stuck.clone();
        let h = std::thread::spawn(move || k.run(&sid, RunOpts::default()));
        let deadline = Instant::now() + Duration::from_secs(10);
        while !e.k.is_running(&stuck) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let err = e.k.rewind(&stuck, 1).unwrap_err();
        assert!(err.contains("still running"), "{err}");
        e.k.interrupt(&stuck);
        let _ = h.join().unwrap();

        // Reachable from the model: `sessions` action=branch (any session, even this one) and
        // action=rewind (an idle session; a running caller is refused with a reason).
        e.main.call("sessions", json!({"action": "branch", "session": id2, "turns": 1}));
        e.main.call("sessions", json!({"action": "rewind", "session": id2, "turns": 1}));
        e.main.call("sessions", json!({"action": "rewind", "turns": 1}));
        e.main.text("done");
        turn(&e, &id, "fork and undo");
        let outs = tool_outputs(&e, &id);
        let branch_out: Value = serde_json::from_str(outs.iter().find(|o| o.0 == "sessions" && o.1.contains("\"action\": \"branch\"")).map(|o| o.1.as_str()).unwrap()).unwrap();
        let fork = branch_out["new_session"].as_str().unwrap().to_string();
        assert_eq!(branch_out["messages"], 2);
        assert_eq!(view(&e, &fork).messages.len(), 2);
        let rewind_out: Value = serde_json::from_str(outs.iter().find(|o| o.0 == "sessions" && o.1.contains("\"action\": \"rewind\"") && !o.2).map(|o| o.1.as_str()).unwrap()).unwrap();
        assert_eq!(rewind_out["turns"], 1);
        assert!(rewind_out["from_seq"].as_u64().unwrap() > 0);
        assert_eq!(view(&e, &id2).user_turns.len(), 1, "the other session really lost its last turn");
        let self_err = outs.iter().find(|o| o.0 == "sessions" && o.2).expect("self-rewind is refused").1.clone();
        assert!(self_err.contains("cannot rewind the session that is running this turn"), "{self_err}");
    }

    /// `sessions_history` `offset` is real plain pagination: a window starting at `offset`, with
    /// `next_offset` / `hasMore` walking forward, and the no-offset form still the tail.
    #[test]
    fn sessions_history_offset_pages_through_the_transcript() {
        let e = env();
        let subject = new_session(&e, "first question");
        turn(&e, &subject, "second question");
        turn(&e, &subject, "third question");
        let reader = e.k.create_session(&e.ws, None, None, None).unwrap();
        e.main.call("sessions_history", json!({"session": subject.clone(), "limit": 500}));
        e.main.call("sessions_history", json!({"session": subject.clone(), "limit": 2, "offset": 0}));
        e.main.call("sessions_history", json!({"session": subject.clone(), "limit": 2, "offset": 2}));
        e.main.call("sessions_history", json!({"session": subject.clone(), "limit": 2}));
        e.main.call("sessions_history", json!({"session": subject.clone(), "limit": 2, "offset": 50}));
        e.main.text("read it");
        turn(&e, &reader, "page through the transcript");
        let pages: Vec<Value> = tool_outputs(&e, &reader).into_iter().filter(|o| o.0 == "sessions_history" && !o.2).map(|o| serde_json::from_str(&o.1).unwrap()).collect();
        assert_eq!(pages.len(), 5, "{pages:?}");
        let texts = |p: &Value| -> Vec<String> { p["messages"].as_array().unwrap().iter().map(|m| m["text"].as_str().unwrap().to_string()).collect() };
        let full = &pages[0];
        assert_eq!(full["total"], 6, "three turns are six messages: {full}");
        let users = |p: &Value| -> Vec<String> { texts(p).into_iter().step_by(2).collect() };
        assert_eq!(users(full), ["first question", "second question", "third question"]);

        // A page from offset 0 is the oldest messages, not the tail, and says where to continue.
        let p0 = &pages[1];
        assert_eq!((p0["offset"].as_u64(), p0["returned"].as_u64()), (Some(0), Some(2)), "{p0}");
        assert_eq!(p0["next_offset"], 2);
        assert_eq!(p0["hasMore"], true);
        assert_eq!(texts(p0)[0], "first question", "offset=0 starts at the oldest message");

        let p2 = &pages[2];
        assert_eq!((p2["offset"].as_u64(), p2["returned"].as_u64()), (Some(2), Some(2)), "{p2}");
        assert_eq!(texts(p2)[0], "second question", "the second page continues where the first stopped");

        // No offset still means the tail (the common call), and the last page has no more.
        let tail = &pages[3];
        assert_eq!((tail["offset"].as_u64(), tail["hasMore"].clone()), (Some(4), json!(false)), "{tail}");
        assert_eq!(texts(tail), &texts(full)[4..], "the tail is the last `limit` messages");

        // An offset past the end is an empty page at `total`, not an error and not a panic.
        let over = &pages[4];
        assert_eq!((over["offset"].as_u64(), over["returned"].as_u64(), over["hasMore"].clone()), (Some(6), Some(0), json!(false)), "{over}");

        // The three windows tile the whole transcript with no gaps and no repeats.
        let mut walked: Vec<String> = Vec::new();
        let mut at = 0u64;
        loop {
            e.main.call("sessions_history", json!({"session": subject.clone(), "limit": 2, "offset": at}));
            e.main.text("next");
            turn(&e, &reader, "next page");
            let page = last_json(&e, &reader);
            walked.extend(texts(&page));
            match page["next_offset"].as_u64() {
                Some(n) if page["hasMore"] == json!(true) => at = n,
                _ => break,
            }
        }
        assert_eq!(walked, texts(full), "paging reproduces the transcript exactly");
    }

    // ───────────── structured output ─────────────
    #[test]
    fn structured_output_schema_producer() {
        let e = env();
        e.main.text("started");
        let id = new_session(&e, "start");

        // The model sets the contract itself (sessions action=schema).
        e.main.call("sessions", json!({"action": "schema", "schema": {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}}));
        e.main.text("schema set");
        turn(&e, &id, "set an output contract");
        let out = last_json(&e, &id);
        assert_eq!(out["structured_output_tool"], true, "{out}");
        let v = view(&e, &id);
        let schema = v.output_schema.clone().expect("OutputSchema event landed");
        assert_eq!(schema["required"], json!(["answer"]));

        // The next turn must submit: prose is nudged, structured_output ends the turn.
        let mark = e.main.requests().len();
        e.main.text("here is prose instead");
        e.main.call("structured_output", json!({"result": {"answer": "42"}}));
        let reason = turn(&e, &id, "answer with the contract");
        assert_eq!(reason, EndReason::Done);
        let reqs = e.main.requests();
        let turn_reqs = &reqs[mark..];
        assert!(turn_reqs[0].tools.iter().any(|t| t.name == "structured_output"), "the kernel offered structured_output: {:?}", turn_reqs[0].tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>());
        assert!(
            turn_reqs.iter().any(|r| r.messages.iter().any(|m| m.text().contains("output contract"))),
            "a prose answer is nudged, not accepted: {:?}",
            turn_reqs.iter().map(|r| r.messages.last().map(|m| m.text()).unwrap_or_default()).collect::<Vec<_>>()
        );
        let v = view(&e, &id);
        assert_eq!(v.structured, Some(json!({"answer": "42"})), "the validated result was recorded");

        // null clears the contract; the tool disappears from the request.
        e.main.call("sessions", json!({"action": "schema", "schema": null}));
        e.main.text("cleared");
        turn(&e, &id, "clear the contract");
        let out = last_json(&e, &id);
        assert_eq!(out["structured_output_tool"], false);
        assert!(view(&e, &id).output_schema.is_none());
        let mark = e.main.requests().len();
        e.main.text("plain prose is fine now");
        assert_eq!(turn(&e, &id, "no contract any more"), EndReason::Done);
        assert!(e.main.requests()[mark..].iter().all(|r| !r.tools.iter().any(|t| t.name == "structured_output")));

        // An invalid schema is refused with the validator's message, not stored.
        e.main.call("sessions", json!({"action": "schema", "schema": {"type": "nonsense"}}));
        e.main.text("refused");
        turn(&e, &id, "try a broken schema");
        let err = last_error(&e, &id);
        assert!(err.contains("not a valid JSON Schema"), "{err}");
        assert!(view(&e, &id).output_schema.is_none());
    }
}
