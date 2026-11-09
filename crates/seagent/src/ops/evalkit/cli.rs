//! `seagent evals …` subcommands of the scored runner (the probes keep `list` / `run`).

use super::bench::{self, LoadOpts};
use super::external;
use super::report;
use super::roles;
use super::run::{Attempt, Harness, Runner, Subject, SubjectKind};
use super::{fake, Task};
use crate::args::Args;
use crate::{usage, R};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const VALUE_FLAGS: &[&str] = &["suite", "models", "agents", "agents-file", "judge", "repeat", "harness", "tool-profile", "price", "repos", "desktop-image", "container-bin", "container-env", "cache-dir", "mode", "threshold", "questions", "provenance", "to", "report"];
pub const BOOL_FLAGS: &[&str] = &["exec-external", "swe-images", "ablate"];

pub const USAGE: &str = "usage:
  seagent evals list|run …                         the hermetic runtime probes (unchanged)
  seagent evals bench --suite SPEC… [--model M]… [--agents ID[=MODEL],…] [--judge M] [--repeat N]
                  [--out DIR] [--resume] [--harness auto|seagent|mini] [--tool-profile NAME] [--role ID] [--limit N] [--filter S]
                  [--price MODEL=IN,OUT]… [--exec-external] [--agents-file F] [--swe-images] [--repos DIR]
                  [--desktop-image IMG] [--container-bin podman] [--container-env FILE] [--cache-dir DIR]
  seagent evals roles [--preset ID,…|all] [--model M]… --judge M [--mode both|with|without] [--ablate]
                  [--threshold X] [--repeat N] [--out DIR] [--questions DIR] [--provenance DIR]
  seagent evals fetch swe-lite|swe-verified|tbench|gaia|osworld --to DIR [--dry-run]
  seagent evals import SPEC --out FILE.jsonl         benchmark → native tasks (to inspect or edit)
  seagent evals suites | agents                      what can be run
  seagent evals report DIR | compare DIR_A DIR_B | collect DIR | swe-score DIR --report FILE
suites: builtin:smoke, builtin:devops-incidents, builtin:roles, swe-lite:PATH, swe-verified:PATH,
        tbench:PATH[#category=…], gaia:PATH[#level=N&split=…], osworld:PATH[#domain=…&index=…], FILE.jsonl
models: provider/model as configured for seagent; fake/oracle and fake/blank run offline";

fn split_list(a: &Args, many: &str, one: &str) -> Vec<String> {
    let mut v: Vec<String> = a.vals(one);
    for x in a.vals(many) {
        v.extend(x.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    }
    v
}

fn now() -> String {
    seagent_kernel::trajectory::iso_ms(seagent_kernel::event::now_ms())
}

/// A runner over `out`, with real providers only when a real model is named.
pub fn runner_for(a: &Args, out: &Path, models: &[String]) -> Result<Runner, String> {
    let real: Vec<&String> = models.iter().filter(|m| !fake::is_fake(m)).collect();
    let (cfg, resolver) = if real.is_empty() {
        (seagent_kernel::config::Config::default(), None)
    } else {
        let ba = Args::parse(&[]).map_err(|e| e.to_string())?;
        let c = crate::build_agent(&ba, crate::approver_for(&ba, false), false).map_err(|e| e.to_string())?;
        (c.k.cfg.clone(), Some(c.k.resolver.clone()))
    };
    let mut r = Runner::new(out, cfg, resolver);
    r.repeat = a.num::<u32>("repeat")?.unwrap_or(1).max(1);
    r.resume = a.flag("resume");
    r.exec_external = a.flag("exec-external");
    r.quiet = a.flag("quiet") || a.flag("json");
    if let Some(b) = a.val("container-bin") {
        r.container_bin = b.into();
    }
    r.container_env_file = a.val("container-env").map(String::from);
    r.tool_profile = a.val("tool-profile").map(String::from);
    r.cache_dir = a.val("cache-dir").map(PathBuf::from);
    if let Some(n) = a.num::<u32>("max-iterations")? {
        r.max_iterations = n;
    }
    for p in a.vals("price") {
        let (m, v) = p.split_once('=').ok_or_else(|| format!("--price {p}: want MODEL=IN,OUT (USD per million tokens)"))?;
        let (i, o) = v.split_once(',').ok_or_else(|| format!("--price {p}: want MODEL=IN,OUT"))?;
        r.prices.insert(m.into(), (i.trim().parse().map_err(|_| format!("--price {p}: bad number"))?, o.trim().parse().map_err(|_| format!("--price {p}: bad number"))?));
    }
    if let Some(j) = a.val("judge") {
        r.set_judge(j)?;
    }
    Ok(r)
}

fn default_out(kind: &str) -> PathBuf {
    let stamp: String = now().chars().filter(|c| c.is_ascii_digit()).take(14).collect();
    PathBuf::from("evals-out").join(format!("{kind}-{stamp}"))
}

fn load_opts(a: &Args) -> LoadOpts {
    LoadOpts { swe_images: a.flag("swe-images"), repos: a.val("repos").map(PathBuf::from), desktop_image: a.val("desktop-image").map(String::from) }
}

fn load_tasks(a: &Args) -> Result<Vec<Task>, String> {
    let specs = a.vals("suite");
    if specs.is_empty() {
        return Err("--suite is required (e.g. builtin:smoke; see `seagent evals suites`)".into());
    }
    let lo = load_opts(a);
    let mut tasks = vec![];
    for s in &specs {
        tasks.extend(bench::load_suite(s, &lo)?);
    }
    if let Some(f) = a.val("filter") {
        let f = f.to_lowercase();
        tasks.retain(|t| t.id.to_lowercase().contains(&f) || t.suite.to_lowercase().contains(&f));
    }
    if let Some(n) = a.num::<usize>("limit")? {
        tasks.truncate(n);
    }
    if tasks.is_empty() {
        return Err("no task matches".into());
    }
    Ok(tasks)
}

fn subjects(a: &Args, models: &[String]) -> Result<Vec<Subject>, String> {
    let harness = Harness::parse(a.val("harness").unwrap_or("auto"))?;
    let mut v: Vec<Subject> = models
        .iter()
        .map(|m| {
            let mut s = Subject::seagent(m);
            if let SubjectKind::Seagent { harness: h, role, .. } = &mut s.kind {
                *h = harness;
                *role = a.val("role").map(String::from);
            }
            if let Some(r) = a.val("role") {
                s.label = format!("{} role:{r}", s.label);
            }
            s
        })
        .collect();
    let agents = split_list(a, "agents", "__none__");
    if !agents.is_empty() {
        let specs = external::load_specs(a.val("agents-file").map(Path::new))?;
        for w in agents {
            let (spec, model) = external::pick(&specs, &w)?;
            v.push(Subject { label: format!("ext:{}{}", spec.id, model.as_deref().map(|m| format!("={m}")).unwrap_or_default()), kind: SubjectKind::External { agent: spec, model } });
        }
    }
    if v.is_empty() {
        return Err("name at least one --model (seagent × model) or --agents".into());
    }
    Ok(v)
}

fn save_tasks(out: &Path, tasks: &[Task]) -> Result<(), String> {
    let lines: Vec<String> = tasks.iter().map(|t| serde_json::to_string(t).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    std::fs::write(out.join("tasks.jsonl"), lines.join("\n") + "\n").map_err(|e| e.to_string())
}

fn finish(out: &Path, manifest: &Value, extra: Option<&str>, json_out: bool) -> R {
    std::fs::write(out.join("manifest.json"), serde_json::to_string_pretty(manifest).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let (jp, mp) = report::write(out, manifest, extra)?;
    let swe = bench::swe_commands(out);
    if !swe.is_empty() {
        std::fs::write(out.join("swe").join("commands.sh"), format!("#!/bin/sh\n# Official SWE-bench scoring (Docker); then import the report.\n{}\n", swe.join("\n"))).map_err(|e| e.to_string())?;
    }
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&jp).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    if json_out {
        println!("{doc}");
    } else {
        println!("{}", std::fs::read_to_string(&mp).map_err(|e| e.to_string())?.split("\n## Tasks").next().unwrap_or(""));
        println!("report: {}\n        {}", mp.display(), jp.display());
        if out.join("external/commands.sh").exists() && doc["summary"]["subjects"].as_array().is_some_and(|s| s.iter().any(|x| x["pending"].as_u64().unwrap_or(0) > 0 && x["subject"].as_str().is_some_and(|l| l.starts_with("ext:")))) {
            println!("external agents: review and run {}, then `seagent evals collect {}`", out.join("external/commands.sh").display(), out.display());
        }
        if !swe.is_empty() {
            println!("SWE-bench: score with {}", out.join("swe/commands.sh").display());
        }
    }
    Ok(0)
}

fn bench_cmd(a: &Args) -> R {
    let tasks = load_tasks(a)?;
    let models = split_list(a, "models", "model");
    let subs = subjects(a, &models)?;
    let out = a.val("out").map(PathBuf::from).unwrap_or_else(|| default_out("bench"));
    let r = runner_for(a, &out, &models)?;
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    save_tasks(&out, &tasks)?;
    r.run(&tasks, &subs)?;
    let manifest = json!({
        "kind": "bench", "suites": a.vals("suite"), "subjects": subs.iter().map(|s| s.label.clone()).collect::<Vec<_>>(),
        "models": models, "agents": split_list(a, "agents", "__none__"), "agents_file": a.val("agents-file"),
        "judge": a.val("judge"), "repeat": r.repeat, "harness": a.val("harness").unwrap_or("auto"), "role": a.val("role"), "tool_profile": r.tool_profile,
        "tasks": tasks.len(), "started": now(), "prices": r.prices,
    });
    finish(&out, &manifest, None, a.flag("json"))
}

fn roles_cmd(a: &Args) -> R {
    let models = split_list(a, "models", "model");
    if models.is_empty() {
        return usage("seagent evals roles needs --model (e.g. fake/oracle offline)");
    }
    let presets: Vec<String> = match a.val("preset") {
        None | Some("all") => roles::PRESETS.iter().map(|s| s.to_string()).collect(),
        Some(p) => p.split(',').map(|s| s.trim().to_string()).collect(),
    };
    let qdir = match a.val("questions") {
        Some(q) => PathBuf::from(q),
        None => super::share_evals().map(|d| d.join("roles")).ok_or("no <share>/evals/roles (pass --questions DIR)")?,
    };
    let out = a.val("out").map(PathBuf::from).unwrap_or_else(|| default_out("roles"));
    let r = runner_for(a, &out, &models)?;
    if r.judge.is_none() {
        return usage("seagent evals roles needs --judge MODEL (fake/judge scores offline by rubric keywords)");
    }
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    if !r.resume {
        let _ = std::fs::remove_file(r.results_path());
    }
    let mode = a.val("mode").unwrap_or("both");
    if !["both", "with", "without"].contains(&mode) {
        return usage(format!("--mode {mode}: want both, with or without"));
    }
    let threshold = a.val("threshold").map(|t| t.parse::<f64>().map_err(|_| format!("--threshold {t}: not a number"))).transpose()?.unwrap_or(0.0);
    let mut all_tasks = vec![];
    let mut blocks = vec![];
    for p in &presets {
        let (text, rules) = roles::guidelines(&r.base_cfg, p)?;
        let mut qs = roles::questions(&qdir, p)?;
        if let Some(n) = a.num::<usize>("limit")? {
            qs.truncate(n);
        }
        if let Some(prov) = a.val("provenance") {
            roles::add_provenance(&mut qs, &r.base_cfg, p, Path::new(prov));
        }
        let ab = out.join("ablation");
        for m in &models {
            let c = roles::Compare { model: m, name: p, text: &text, rules: &rules, mode, threshold, ablation_root: a.flag("ablate").then_some(ab.as_path()) };
            blocks.push(roles::compare_guidelines(&r, &qs, &c)?);
        }
        all_tasks.extend(qs);
    }
    save_tasks(&out, &all_tasks)?;
    std::fs::write(out.join("roles.json"), serde_json::to_string_pretty(&blocks).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let manifest = json!({"kind": "roles", "suites": presets.iter().map(|p| format!("roles/{p}")).collect::<Vec<_>>(), "models": models, "judge": a.val("judge"), "repeat": r.repeat, "mode": mode, "ablate": a.flag("ablate"), "threshold": threshold, "started": now(), "tasks": all_tasks.len()});
    finish(&out, &manifest, Some(&roles::render_md(&blocks)), a.flag("json"))
}

fn fetch_cmd(a: &Args) -> R {
    let b = a.need(1, "benchmark")?;
    let to = PathBuf::from(a.val("to").ok_or("--to DIR is required (where the local copy goes)")?);
    let cmds = bench::fetch_commands(b, &to)?;
    let offline = std::env::var_os("SEAGENT_OFFLINE").is_some();
    if a.flag("dry-run") || offline {
        if offline && !a.flag("dry-run") {
            println!("# SEAGENT_OFFLINE is set: not downloading. Run these yourself:");
        }
        for c in &cmds {
            println!("{c}");
        }
        return Ok(0);
    }
    for c in &cmds {
        eprintln!("+ {c}");
        let st = std::process::Command::new("bash").arg("-c").arg(c).status().map_err(|e| e.to_string())?;
        if !st.success() {
            return Err(format!("`{c}` failed ({st})").into());
        }
    }
    std::fs::write(to.join(".seagent-dataset.json"), json!({"bench": b, "fetched": now(), "commands": cmds}).to_string()).map_err(|e| e.to_string())?;
    println!("{b} is in {} — run it with --suite {b}:{}", to.display(), to.display());
    Ok(0)
}

fn import_cmd(a: &Args) -> R {
    let spec = a.need(1, "suite spec")?;
    let tasks = bench::load_suite(spec, &load_opts(a))?;
    let out = PathBuf::from(a.val("out").ok_or("--out FILE.jsonl is required")?);
    save_tasks_file(&out, &tasks)?;
    println!("{} tasks → {}", tasks.len(), out.display());
    Ok(0)
}

fn save_tasks_file(p: &Path, tasks: &[Task]) -> Result<(), String> {
    let lines: Vec<String> = tasks.iter().map(|t| serde_json::to_string(t).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    std::fs::write(p, lines.join("\n") + "\n").map_err(|e| format!("{}: {e}", p.display()))
}

fn read_manifest(out: &Path) -> Value {
    std::fs::read_to_string(out.join("manifest.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null)
}

fn extra_md(out: &Path) -> Option<String> {
    let blocks: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(out.join("roles.json")).ok()?).ok()?;
    Some(roles::render_md(&blocks))
}

fn report_cmd(a: &Args) -> R {
    let out = PathBuf::from(a.need(1, "run dir")?);
    let m = read_manifest(&out);
    finish(&out, &m, extra_md(&out).as_deref(), a.flag("json"))
}

fn compare_cmd(a: &Args) -> R {
    let (x, y) = (PathBuf::from(a.need(1, "run dir A")?), PathBuf::from(a.need(2, "run dir B")?));
    let rd = |p: &Path| -> Result<Value, String> { serde_json::from_str(&std::fs::read_to_string(p.join("report.json")).map_err(|e| format!("{}: {e} (run `seagent evals report` first)", p.join("report.json").display()))?).map_err(|e| e.to_string()) };
    println!("{}", report::compare(&rd(&x)?, &rd(&y)?, &x.display().to_string(), &y.display().to_string()));
    Ok(0)
}

/// Grade external agents' outputs written after `bench` (without `--exec-external`).
pub fn collect(out: &Path, a: &Args) -> Result<(usize, usize), String> {
    let m = read_manifest(out);
    let tasks = super::load_native(&out.join("tasks.jsonl"))?;
    let specs = external::load_specs(m["agents_file"].as_str().map(Path::new))?;
    let mut r = Runner::new(out, seagent_kernel::config::Config::default(), None);
    if let Some(j) = a.val("judge").or(m["judge"].as_str()) {
        if fake::is_fake(j) {
            r.set_judge(j)?;
        } else {
            let mut rr = runner_for(a, out, &[j.to_string()])?;
            rr.set_judge(j)?;
            r = rr;
        }
    }
    let attempts = report::read_results(out)?;
    let (mut seen, mut graded) = (0, 0);
    let mut rows = vec![];
    for mut at in attempts {
        if at.status == "pending" && at.subject.starts_with("ext:") {
            seen += 1;
            let id = at.subject.trim_start_matches("ext:").split('=').next().unwrap_or("").to_string();
            if let (Some(spec), Some(t)) = (specs.iter().find(|s| s.id == id), tasks.iter().find(|t| t.id == at.task)) {
                let f = external::out_file(&r, spec, t, at.rep);
                if let Ok(stdout) = std::fs::read_to_string(&f) {
                    let o = external::outcome_from(spec, &stdout, 0);
                    at = grade_collected(&r, at, t, o);
                    graded += 1;
                }
            }
        }
        rows.push(serde_json::to_string(&at).map_err(|e| e.to_string())?);
    }
    std::fs::write(r.results_path(), rows.join("\n") + "\n").map_err(|e| e.to_string())?;
    Ok((seen, graded))
}

fn grade_collected(r: &Runner, mut at: Attempt, t: &Task, o: super::run::Outcome) -> Attempt {
    let dir = at.workdir.clone().map(PathBuf::from);
    let ex = dir.as_ref().map(|d| super::grade::host_exec(d, 600));
    let (checks, score, pass) = super::grade::grade(t, &o.answer, dir.as_deref(), ex.as_ref().map(|e| e as &dyn Fn(&str) -> (String, i32)), r.judge.as_ref());
    at.answer = o.answer.chars().take(8000).collect();
    at.input_tokens = o.usage.input_tokens;
    at.output_tokens = o.usage.output_tokens;
    at.cost_usd = o.artifacts["reported_cost_usd"].as_f64();
    at.checks = checks;
    at.score = score;
    at.pass = pass;
    at.status = "done".into();
    at
}

fn collect_cmd(a: &Args) -> R {
    let out = PathBuf::from(a.need(1, "run dir")?);
    let (seen, graded) = collect(&out, a)?;
    println!("collected {graded} of {seen} pending external attempt(s)");
    let m = read_manifest(&out);
    finish(&out, &m, extra_md(&out).as_deref(), a.flag("json"))
}

fn swe_score_cmd(a: &Args) -> R {
    let out = PathBuf::from(a.need(1, "run dir")?);
    let rep = a.val("report").ok_or("--report FILE (the swebench run_evaluation JSON) is required")?;
    let v: Value = serde_json::from_str(&std::fs::read_to_string(rep).map_err(|e| format!("{rep}: {e}"))?).map_err(|e| format!("{rep}: {e}"))?;
    let (n, ok) = bench::swe_score(&out, &v)?;
    println!("SWE-bench: {ok}/{n} pending instance(s) resolved");
    let m = read_manifest(&out);
    finish(&out, &m, None, a.flag("json"))
}

fn suites_cmd() -> R {
    if let Some(d) = super::share_evals() {
        for s in ["smoke", "devops-incidents", "roles"] {
            let n = super::load_native(&d.join(s)).map(|t| t.len()).unwrap_or(0);
            println!("builtin:{s:<18} {n} tasks");
        }
    }
    for (id, what, _, note) in bench::SOURCES {
        println!("{id}:PATH{:<width$} {what} — {note}", "", width = 14usize.saturating_sub(id.len()));
    }
    Ok(0)
}

fn agents_cmd(a: &Args) -> R {
    for s in external::load_specs(a.val("agents-file").map(Path::new))? {
        println!("{:<12} {:<28} {} {}  (install: {})", s.id, s.name, s.bin, s.args.join(" "), s.install);
    }
    Ok(0)
}

/// `seagent evals <sub>` for the scored runner; None = not ours.
pub fn dispatch_sub(a: &Args) -> Option<R> {
    Some(match a.pos(0)? {
        "bench" => bench_cmd(a),
        "roles" => roles_cmd(a),
        "fetch" => fetch_cmd(a),
        "import" => import_cmd(a),
        "report" => report_cmd(a),
        "compare" => compare_cmd(a),
        "collect" => collect_cmd(a),
        "swe-score" => swe_score_cmd(a),
        "suites" => suites_cmd(),
        "agents" => agents_cmd(a),
        "help" => {
            println!("{USAGE}");
            Ok(0)
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Args {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[cfg(unix)]
    /// The acceptance run of this round: fake models through the whole pipeline on the shipped
    /// smoke suite (load → run → grade → report), plus an external agent as a command.
    #[test]
    fn bench_smoke_end_to_end_with_fake_models_and_an_external_agent() {
        let _l = crate::testkit::env_lock();
        let out = seagent_core::tmp::scratch("seagent-bench-e2e");
        let share = super::super::repo_share();
        // a stand-in "external agent": prints a Claude-Code-shaped JSON result
        let bin = out.join("fake-agent");
        std::fs::write(&bin, "#!/bin/sh\necho '{\"result\":\"FINAL ANSWER: Paris\",\"total_cost_usd\":0.01,\"usage\":{\"input_tokens\":12,\"output_tokens\":3}}'\n").unwrap();
        {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let agents = out.join("agents.toml");
        std::fs::write(&agents, format!("[[agent]]\nid = \"stub\"\nbin = '{}'\nargs = [\"-p\", \"{{prompt}}\"]\noutput = \"json\"\n", bin.display())).unwrap();
        let run = out.join("run");
        let a = p(&["bench", "--suite", &share.join("evals/smoke").display().to_string(), "--model", "fake/oracle", "--model", "fake/blank", "--agents", "stub", "--agents-file", &agents.display().to_string(), "--judge", "fake/judge", "--repeat", "2", "--out", &run.display().to_string(), "--price", "fake/oracle=3,15", "--quiet"]);
        assert_eq!(dispatch_sub(&a).unwrap().unwrap(), 0);
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(run.join("report.json")).unwrap()).unwrap();
        let subj = |l: &str| doc["summary"]["subjects"].as_array().unwrap().iter().find(|s| s["subject"] == l).cloned().unwrap();
        let o = subj("seagent:fake/oracle");
        assert_eq!((o["done"].as_u64(), o["passed"].as_u64()), (Some(6), Some(6)), "{o}");
        assert!(o["cost_usd"].as_f64().unwrap() > 0.0 && o["input_tokens"].as_u64().unwrap() > 0);
        assert_eq!(subj("seagent:fake/blank")["passed"].as_u64(), Some(0));
        // external: commands written, attempts pending until collected
        assert_eq!(subj("ext:stub")["pending"].as_u64(), Some(6));
        let script = std::fs::read_to_string(run.join("external/commands.sh")).unwrap();
        assert_eq!(script.lines().filter(|l| l.contains("fake-agent")).count(), 6);
        // pretend the user ran the script: run each line
        for l in script.lines().filter(|l| l.starts_with('(')) {
            assert!(std::process::Command::new("sh").arg("-c").arg(l).status().unwrap().success());
        }
        assert_eq!(dispatch_sub(&p(&["collect", &run.display().to_string(), "--quiet"])).unwrap().unwrap(), 0);
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(run.join("report.json")).unwrap()).unwrap();
        let e = doc["summary"]["subjects"].as_array().unwrap().iter().find(|s| s["subject"] == "ext:stub").cloned().unwrap();
        // the stub answers "Paris": the QA passes twice, the two agent tasks fail (nothing fixed)
        assert_eq!((e["done"].as_u64(), e["passed"].as_u64(), e["pending"].as_u64()), (Some(6), Some(2), Some(0)), "{e}");
        assert!((e["cost_usd"].as_f64().unwrap() - 0.06).abs() < 1e-9);
        let md = std::fs::read_to_string(run.join("report.md")).unwrap();
        assert!(md.contains("| seagent:fake/oracle | 6 | 100.0% |"), "{md}");
        // the SWE-style smoke task produced a patch for the official harness format
        assert!(std::fs::read_to_string(run.join("swe/predictions-seagent_fake_oracle.jsonl")).unwrap().contains("hello, $1"));
        // compare two runs
        assert_eq!(dispatch_sub(&p(&["compare", &run.display().to_string(), &run.display().to_string()])).unwrap().unwrap(), 0);
        // resume: nothing reruns
        let n = std::fs::read_to_string(run.join("results.jsonl")).unwrap().lines().count();
        let a = p(&["bench", "--suite", &share.join("evals/smoke").display().to_string(), "--model", "fake/oracle", "--judge", "fake/judge", "--repeat", "2", "--out", &run.display().to_string(), "--resume", "--quiet"]);
        assert_eq!(dispatch_sub(&a).unwrap().unwrap(), 0);
        assert_eq!(std::fs::read_to_string(run.join("results.jsonl")).unwrap().lines().count(), n);
    }

    #[test]
    fn devops_incidents_and_roles_run_offline() {
        let _l = crate::testkit::env_lock();
        let out = seagent_core::tmp::scratch("seagent-roles-cli");
        let share = super::super::repo_share();
        let run = out.join("inc");
        let a = p(&["bench", "--suite", &share.join("evals/devops-incidents").display().to_string(), "--model", "fake/oracle", "--judge", "fake/judge", "--limit", "2", "--out", &run.display().to_string(), "--quiet"]);
        assert_eq!(dispatch_sub(&a).unwrap().unwrap(), 0);
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(run.join("report.json")).unwrap()).unwrap();
        assert_eq!(doc["summary"]["subjects"][0]["passed"].as_u64(), Some(2), "{doc}");
        // roles: --questions points at the shipped set; seagent resolves the role tree from the checkout
        std::env::set_var("SEAGENT_ROLES_DIR", share.join("roles"));
        let rr = out.join("roles");
        let a = p(&["roles", "--preset", "itsupport", "--model", "fake/oracle", "--judge", "fake/judge", "--questions", &share.join("evals/roles").display().to_string(), "--limit", "2", "--ablate", "--out", &rr.display().to_string(), "--quiet"]);
        let res = dispatch_sub(&a).unwrap();
        std::env::remove_var("SEAGENT_ROLES_DIR");
        assert_eq!(res.unwrap(), 0);
        let blocks: Value = serde_json::from_str(&std::fs::read_to_string(rr.join("roles.json")).unwrap()).unwrap();
        assert!(blocks[0]["with"].as_f64().unwrap() > blocks[0]["without"].as_f64().unwrap(), "{blocks}");
        assert!(std::fs::read_to_string(rr.join("report.md")).unwrap().contains("### Ablation: itsupport"));
        // usage errors are errors, not silent no-ops
        assert!(dispatch_sub(&p(&["roles", "--model", "fake/oracle"])).unwrap().is_err());
        assert!(dispatch_sub(&p(&["bench", "--model", "fake/oracle"])).unwrap().is_err());
        assert!(dispatch_sub(&p(&["nope"])).is_none());
    }

    #[test]
    fn fetch_is_offline_safe_and_import_writes_native_tasks() {
        let _l = crate::testkit::env_lock();
        let out = seagent_core::tmp::scratch("seagent-fetch");
        std::env::set_var("SEAGENT_OFFLINE", "1");
        let r = dispatch_sub(&p(&["fetch", "tbench", "--to", &out.join("tb").display().to_string()])).unwrap();
        std::env::remove_var("SEAGENT_OFFLINE");
        assert_eq!(r.unwrap(), 0);
        assert!(!out.join("tb").exists(), "offline fetch must not download");
        let f = out.join("smoke.jsonl");
        assert_eq!(dispatch_sub(&p(&["import", &super::super::repo_share().join("evals/smoke").display().to_string(), "--out", &f.display().to_string()])).unwrap().unwrap(), 0);
        assert_eq!(super::super::load_native(&f).unwrap().len(), 3);
    }
}
