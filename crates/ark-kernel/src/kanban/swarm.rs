//! Kanban Swarm v1: a small task graph on the ordinary board — a planning root
//! (completed at once, kept as the shared blackboard), parallel specialist workers,
//! a verifier waiting on every worker, and a synthesizer waiting on the verifier.
//! The blackboard is structured JSON comments on the root.

use super::ops::{self, NewTask};
use super::store::BoardData;
use serde_json::{json, Value};

pub const BLACKBOARD_PREFIX: &str = "[swarm:blackboard] ";

#[derive(Debug, Clone, Default)]
pub struct WorkerSpec {
    pub profile: String,
    pub title: String,
    pub body: String,
    pub skills: Vec<String>,
    pub priority: i64,
    pub max_runtime_seconds: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct SwarmSpec {
    pub goal: String,
    pub workers: Vec<WorkerSpec>,
    pub verifier: String,
    pub synthesizer: String,
    pub root_title: Option<String>,
    pub tenant: Option<String>,
    pub created_by: Option<String>,
    pub priority: i64,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Created {
    pub root_id: String,
    pub worker_ids: Vec<String>,
    pub verifier_id: String,
    pub synthesizer_id: String,
}

impl Created {
    pub fn to_json(&self) -> Value {
        json!({"root_id": self.root_id, "worker_ids": self.worker_ids, "verifier_id": self.verifier_id, "synthesizer_id": self.synthesizer_id})
    }
}

/// `--worker profile:title[:skill,skill]`.
pub fn parse_worker(raw: &str) -> Result<WorkerSpec, String> {
    let p: Vec<&str> = raw.splitn(3, ':').map(str::trim).collect();
    if p.len() < 2 || p[0].is_empty() || p[1].is_empty() {
        return Err("worker must be profile:title or profile:title:skill,skill".into());
    }
    let skills = p.get(2).map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()).unwrap_or_default();
    Ok(WorkerSpec { profile: p[0].into(), title: p[1].into(), body: p[1].into(), skills, ..Default::default() })
}

fn req(v: &str, name: &str) -> Result<String, String> {
    let t = v.trim();
    if t.is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(t.into())
}

/// Atomically create the swarm (one board write); idempotent on the root's key.
pub fn create(b: &mut BoardData, s: SwarmSpec, failure_limit: u32) -> Result<Created, String> {
    let goal = req(&s.goal, "goal")?;
    let verifier = req(&s.verifier, "verifier_assignee")?;
    let synth = req(&s.synthesizer, "synthesizer_assignee")?;
    if s.workers.is_empty() {
        return Err("at least one worker is required".into());
    }
    for (i, w) in s.workers.iter().enumerate() {
        req(&w.profile, &format!("workers[{}].profile", i + 1))?;
        req(&w.title, &format!("workers[{}].title", i + 1))?;
    }
    let by = s.created_by.clone().unwrap_or_else(|| "swarm-orchestrator".into());
    let root = ops::create_task(b, NewTask { title: s.root_title.clone().unwrap_or_else(|| format!("Swarm: {}", goal.lines().next().unwrap_or("").chars().take(80).collect::<String>())), body: Some(format!("Kanban Swarm v1 planning/root card. This card is completed immediately so parallel workers can start while it remains the shared blackboard and audit anchor.\n\nGoal:\n{goal}")), assignee: Some(by.clone()), created_by: Some(by.clone()), priority: s.priority, idempotency_key: s.idempotency_key.clone(), initial_status: Some("blocked".into()), tenant: s.tenant.clone(), ..Default::default() })?;
    if let Some(Value::Object(t)) = latest_blackboard(b, &root).get("topology") {
        let ids: Vec<String> = t.get("worker_ids").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        if let (false, Some(v), Some(sy)) = (ids.is_empty(), t.get("verifier_id").and_then(|v| v.as_str()), t.get("synthesizer_id").and_then(|v| v.as_str())) {
            return Ok(Created { root_id: root, worker_ids: ids, verifier_id: v.into(), synthesizer_id: sy.into() });
        }
    }
    let ctx = format!("\n\n## Swarm protocol\n- Swarm root / shared blackboard: `{root}`.\n- Read sibling/parent handoffs from Kanban context before working.\n- Put machine-readable facts in completion metadata.\n- Put cross-worker notes on the root task using structured comments.\n- Goal: {goal}\n");
    let mut workers = vec![];
    for w in &s.workers {
        workers.push(ops::create_task(b, NewTask { title: w.title.clone(), body: Some(format!("{}{ctx}", w.body)), assignee: Some(w.profile.clone()), parents: vec![root.clone()], priority: if w.priority != 0 { w.priority } else { s.priority }, skills: (!w.skills.is_empty()).then(|| w.skills.clone()), max_runtime_seconds: w.max_runtime_seconds, created_by: Some(by.clone()), tenant: s.tenant.clone(), ..Default::default() })?);
    }
    let verifier_id = ops::create_task(b, NewTask { title: "Verify swarm outputs".into(), body: Some(format!("Review every worker handoff and blackboard update. Gate the swarm: complete only with metadata {{\"gate\": \"pass\"}} when evidence is sufficient; otherwise block with exact missing work.{ctx}")), assignee: Some(verifier), parents: workers.clone(), priority: s.priority, skills: Some(vec!["requesting-code-review".into()]), created_by: Some(by.clone()), tenant: s.tenant.clone(), ..Default::default() })?;
    let synthesizer_id = ops::create_task(b, NewTask { title: "Synthesize swarm outputs".into(), body: Some(format!("Synthesize the verified worker outputs into the final deliverable. Do not start until the verifier has passed the gate.{ctx}")), assignee: Some(synth), parents: vec![verifier_id.clone()], priority: s.priority, skills: Some(vec!["humanizer".into()]), created_by: Some(by.clone()), tenant: s.tenant.clone(), ..Default::default() })?;
    let c = Created { root_id: root.clone(), worker_ids: workers, verifier_id, synthesizer_id };
    let mut topo = c.to_json();
    topo["goal"] = goal.clone().into();
    post(b, &root, &by, "topology", topo)?;
    // Activate: blocked -> done so the workers become ready.
    let t = b.task_mut(&root).unwrap();
    t.status = "done".into();
    t.completed_at = Some(super::now());
    let summary = "Swarm topology planned; root remains the shared blackboard.";
    let rid = ops::synthesize_run(b, &root, "completed", Some(summary), None, Some(json!({"kind": "kanban_swarm_v1", "goal": goal, "worker_count": c.worker_ids.len()})), None);
    b.append_event(&root, "completed", Some(json!({"result_len": 0, "summary": summary})), Some(rid));
    ops::recompute_ready(b, failure_limit);
    Ok(c)
}

/// Append one structured update to the root's blackboard.
pub fn post(b: &mut BoardData, root: &str, author: &str, key: &str, value: Value) -> Result<u64, String> {
    req(root, "root_id")?;
    let author = req(author, "author")?;
    let key = req(key, "key")?;
    ops::add_comment(b, root, &author, &format!("{BLACKBOARD_PREFIX}{}", json!({"key": key, "value": value})))
}

/// Merge blackboard comments (later wins); `_authors` names each winning author.
pub fn latest_blackboard(b: &BoardData, root: &str) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    let mut authors = serde_json::Map::new();
    for c in b.comments_for(root) {
        let Some(rest) = c.body.strip_prefix(BLACKBOARD_PREFIX) else { continue };
        let Ok(p) = serde_json::from_str::<Value>(rest) else { continue };
        let Some(k) = p["key"].as_str().filter(|k| !k.is_empty()) else { continue };
        m.insert(k.into(), p["value"].clone());
        authors.insert(k.into(), c.author.clone().into());
    }
    if !authors.is_empty() {
        m.insert("_authors".into(), Value::Object(authors));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swarm_topology_blackboard_and_idempotency() {        let mut b = BoardData::default();
        let spec = SwarmSpec { goal: "ship docs".into(), workers: vec![parse_worker("writer:draft intro:humanizer").unwrap(), parse_worker("researcher:collect refs").unwrap()], verifier: "reviewer".into(), synthesizer: "writer".into(), idempotency_key: Some("k1".into()), ..Default::default() };
        let c = create(&mut b, spec.clone(), 2).unwrap();
        assert_eq!(b.status_of(&c.root_id), Some("done"));
        for w in &c.worker_ids {
            assert_eq!(b.status_of(w), Some("ready"), "workers start in parallel");
        }
        assert_eq!(b.status_of(&c.verifier_id), Some("todo"));
        assert_eq!(b.parent_ids(&c.synthesizer_id), vec![c.verifier_id.clone()]);
        assert_eq!(b.task(&c.worker_ids[0]).unwrap().skills.as_deref(), Some(&["humanizer".to_string()][..]));
        let again = create(&mut b, spec, 2).unwrap();
        assert_eq!(again, c, "idempotent on the root key");
        post(&mut b, &c.root_id, "writer", "outline", json!(["a"])).unwrap();
        post(&mut b, &c.root_id, "reviewer", "outline", json!(["b"])).unwrap();
        let bb = latest_blackboard(&b, &c.root_id);
        assert_eq!(bb["outline"], json!(["b"]));
        assert_eq!(bb["_authors"]["outline"], "reviewer");
        assert!(parse_worker("nope").is_err());
        assert!(create(&mut b, SwarmSpec { goal: "g".into(), verifier: "v".into(), synthesizer: "s".into(), ..Default::default() }, 2).is_err());
    }

    #[test]
    fn worker_specs_parse_the_cli_grammar() {
        let w = parse_worker(" writer : Draft the intro : humanizer, editor ").unwrap();
        assert_eq!(w.profile, "writer");
        assert_eq!(w.title, "Draft the intro");
        assert_eq!(w.body, "Draft the intro", "the title doubles as the initial body");
        assert_eq!(w.skills, vec!["humanizer".to_string(), "editor".to_string()]);
        let bare = parse_worker("researcher:collect refs").unwrap();
        assert!(bare.skills.is_empty());
        for bad in ["nope", ":title", "profile:", "  "] {
            assert!(parse_worker(bad).is_err(), "{bad:?} was accepted");
        }
        // Validation happens before anything is written.
        let mut b = BoardData::default();
        assert!(create(&mut b, SwarmSpec { goal: "  ".into(), workers: vec![parse_worker("a:b").unwrap()], verifier: "v".into(), synthesizer: "s".into(), ..Default::default() }, 2).unwrap_err().contains("goal is required"));
        assert!(create(&mut b, SwarmSpec { goal: "g".into(), workers: vec![], verifier: "v".into(), synthesizer: "s".into(), ..Default::default() }, 2).unwrap_err().contains("at least one worker"));
        assert!(b.tasks.is_empty(), "a rejected swarm leaves the board empty");
    }

    #[test]
    fn arp_kanban_swarm_is_the_user_reachable_entry_point() {
        use crate::kanban::{boards, methods, store};
        let (k, _p, _ws) = crate::kanban::testutil::kernel(|c| c.kanban.enabled = true);
        let d = k.paths.data.clone();
        boards::create_board(&d, "proj", Default::default()).unwrap();
        assert!(methods::NAMES.contains(&"kanban.swarm"), "the dashboard/CLI method must be advertised");

        let v = methods::call(&k, "kanban.swarm", &json!({
            "board": "proj",
            "goal": "ship the docs site",
            "workers": ["writer:draft intro:humanizer", {"profile": "researcher", "title": "collect refs", "skills": ["web-search"]}],
            "verifier": "reviewer",
            "synthesizer": "writer",
            "tenant": "acme",
            "priority": 3,
            "idempotency_key": "swarm-1",
        })).unwrap().unwrap();
        assert_eq!(v["board"], "proj");
        let root = v["root_id"].as_str().unwrap().to_string();
        let workers: Vec<String> = v["worker_ids"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        assert_eq!(workers.len(), 2, "{v}");
        let b = store::read_board(&d, "proj").unwrap();
        assert_eq!(b.status_of(&root), Some("done"), "the root is completed at once so workers can start");
        for w in &workers {
            assert_eq!(b.status_of(w), Some("ready"), "specialists run in parallel");
            assert_eq!(b.task(w).unwrap().tenant.as_deref(), Some("acme"), "the tenant is inherited by every card");
            assert_eq!(b.task(w).unwrap().priority, 3);
        }
        let verifier = v["verifier_id"].as_str().unwrap();
        let synth = v["synthesizer_id"].as_str().unwrap();
        assert_eq!(b.status_of(verifier), Some("todo"));
        assert_eq!(b.parent_ids(verifier), {
            let mut want = workers.clone();
            want.sort();
            want
        });
        assert_eq!(b.parent_ids(synth), vec![verifier.to_string()]);
        assert_eq!(b.task(&workers[1]).unwrap().skills.as_deref(), Some(&["web-search".to_string()][..]));
        let bb = latest_blackboard(&b, &root);
        assert_eq!(bb["topology"]["goal"], json!("ship the docs site"));
        assert!(bb["_authors"]["topology"].is_string());

        // Idempotent on the root's key: a double submit (dashboard retry) makes one swarm.
        let again = methods::call(&k, "kanban.swarm", &json!({"board": "proj", "goal": "ship the docs site", "workers": ["writer:draft intro"], "verifier": "reviewer", "synthesizer": "writer", "idempotency_key": "swarm-1", "actor": "dash"})).unwrap().unwrap();
        assert_eq!(again["root_id"], json!(root));
        assert_eq!(store::read_board(&d, "proj").unwrap().tasks.len(), 5, "root + 2 workers + verifier + synthesizer");

        // Argument errors are ARP parameter errors with a usable message.
        for (payload, want) in [
            (json!({"goal": "g", "verifier": "v", "synthesizer": "s"}), "missing `workers`"),
            (json!({"goal": "g", "workers": ["a:b"], "synthesizer": "s"}), "missing `verifier`"),
            (json!({"goal": "g", "workers": ["a:b"], "verifier": "v"}), "missing `synthesizer`"),
            (json!({"workers": ["a:b"], "verifier": "v", "synthesizer": "s"}), "missing `goal`"),
        ] {
            let (code, msg) = methods::call(&k, "kanban.swarm", &payload).unwrap().unwrap_err();
            assert_eq!(code, -32602);
            assert!(msg.contains(want), "{payload} → {msg}");
        }
        let (_, msg) = methods::call(&k, "kanban.swarm", &json!({"goal": "g", "workers": ["nope"], "verifier": "v", "synthesizer": "s"})).unwrap().unwrap_err();
        assert!(msg.contains("worker must be profile:title"), "{msg}");
        // A missing board is created rather than failing the first swarm on a fresh install.
        methods::call(&k, "kanban.swarm", &json!({"board": "fresh", "goal": "g", "workers": ["a:b"], "verifier": "v", "synthesizer": "s"})).unwrap().unwrap();
        assert!(boards::board_exists(&d, "fresh"));
    }
}
