//! Headless bulge CLI.
//!
//!   bulge run --goal "..." --workspace DIR [options]
//!
//! Events stream to stdout as JSONL (the job log, line by line); diagnostics go to
//! stderr. Workspace changes stay in the VM overlay and are written as a diff for
//! review — the host is never modified.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use bulge_cli::backend::{BackendSpec, Protocol};
use bulge_cli::eval::{self, EvalConfig};
use bulge_cli::run::{self, RunConfig};
use bulge_org::{RoleLibrary, append_decision, parse_charter};
use bulge_store::{Autonomy, Budget};

const USAGE: &str = "\
bulge — headless sandboxed agent

USAGE:
    bulge run  --goal <TEXT> --workspace <DIR> [OPTIONS]
    bulge eval --tasks <FILE.json> [OPTIONS]
    bulge acp  (ACP agent server over stdio; editors spawn this)
    bulge schedule add|list|remove|tick   (scheduled tasks; see below)
    bulge recall <query> [--limit N]      (keyword search over past jobs)
    bulge org roles|veto <name>|log [--harness DIR]
                                          (inspect, veto, or review governed roles)

`schedule` runs a saved task later or on a recurring basis:
    bulge schedule add --goal <T> --workspace <DIR> <SELECTOR> [run options]
    bulge schedule list
    bulge schedule remove --id <ID>
    bulge schedule tick     (run every due task once; drive from cron/systemd)
  SELECTOR (exactly one): --after <secs> | --at <unix> | --every <secs>
    | --daily HH:MM | --weekly mon,wed,fri:HH:MM | --cron \"m h dom mon dow\"
    | --on-change <PATH>  (event-driven: run when PATH's mtime changes)
  Wall-clock selectors use --offset-min <N> (fixed UTC offset in minutes).
  A scheduled run is autonomous, skips the learning loop, and leaves its changes
  as a reviewable diff in the job store (never written back without approval).

`eval` runs each task (a JSON array of {id, goal, rubric, setup?}) in a fresh
workspace and scores it with a blind judge model, reporting the completion rate.
It accepts the same model/budget/VM options as `run`, plus --workspace-root <DIR>.

`org` needs no VM or model. `roles` lists the role library, including trial
roles; `veto` removes an installed role charter and records the veto so the role
can never be installed again; `log` prints the governance decisions.

REQUIRED (run):
    --goal <TEXT>          What the job should accomplish
    --workspace <DIR>      Host directory exposed to the VM as the workspace

OPTIONS:
    --title <TEXT>         Job title (default: first line of the goal)
    --store <DIR>          Job store root (default: ~/.bulge/jobs)
    --harness <DIR>        Harness tree + memory root (default: ~/.bulge/harness)
    --autonomy <MODE>      collaborative | autonomous | full-auto (default: autonomous)
    --model <ID>           Model id (default: deepseek-chat)
    --base-url <URL>       API base URL (default: https://api.deepseek.com)
    --protocol <P>         openai | anthropic (default: openai)
    --backend-id <ID>      Logical backend name recorded in the job (default: from host)
    --context-window <N>   Context window in tokens (default: 128000)
    --max-tokens <N>       Max output tokens per call (default: 8192)
    --reasoning            Advertise reasoning support to the backend
    --review               LLM-review every mutating tool call before it runs
    --max-steps <N>        Step budget (default: 200)
    --max-model-tokens <N> Token budget (default: 2000000)
    --max-secs <N>         Wall-clock budget in seconds (default: 14400)
    --network              Allow guest network egress (public internet; host/LAN blocked)
    --cpus <N>             Guest vCPUs (default: 2)
    --ram <MiB>            Guest RAM in MiB (default: 1024)
    -h, --help             Show this help

The API key is read from $BULGE_API_KEY or ~/.bulge/keys/<host> (chmod 600).
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => {
            // `--writeback <dir>` (headless/eval only): after the run, apply the
            // collected changes to <dir>. Off by default — a plain `run` still
            // only leaves a reviewable diff and never writes anything back.
            let (writeback, rest) = take_writeback(&args[1..]);
            match parse_run(&rest) {
            Ok(config) => {
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                match rt.block_on(run::run(config)) {
                    Ok(result) => {
                        if let Some(dir) = writeback {
                            let names: Vec<String> = result.changes.iter().map(|c| c.path().to_string()).collect();
                            let report = bulge_vm::changes::apply(&dir, &result.changes, &names);
                            eprintln!("writeback: applied {} change(s) to {}", report.applied.len(), dir.display());
                            for (path, why) in &report.skipped {
                                eprintln!("writeback: skipped {path}: {why}");
                            }
                        }
                        std::process::exit(i32::from(result.status != bulge_store::JobStatus::Succeeded));
                    }

                    Err(error) => {
                        eprintln!("error: {error}");
                        std::process::exit(1);
                    }
                }
            }
            Err(error) => {
                eprintln!("error: {error}\n\n{USAGE}");
                std::process::exit(2);
            }
            }
        }
        Some("eval") => match parse_eval(&args[1..]) {
            Ok(config) => {
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                match rt.block_on(eval::run_eval(config)) {
                    Ok(summary) => {
                        // Non-zero exit if any task failed or a boundary was crossed.
                        let clean = summary.passed == summary.total && summary.boundary_violations == 0;
                        std::process::exit(i32::from(!clean));
                    }
                    Err(error) => {
                        eprintln!("error: {error}");
                        std::process::exit(1);
                    }
                }
            }
            Err(error) => {
                eprintln!("error: {error}\n\n{USAGE}");
                std::process::exit(2);
            }
        },
        Some("acp") => {
            // Expose bulge as an ACP agent server over stdio (editors spawn this).
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            if let Err(error) = rt.block_on(bulge_cli::acp::serve()) {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Some("schedule") => {
            // Scheduled tasks: add/list/remove/tick. `tick` runs its own runtime.
            std::process::exit(bulge_cli::cron::dispatch(&args[1..]));
        }
        Some("recall") => {
            // Keyword search over past job transcripts.
            std::process::exit(bulge_cli::recall::dispatch(&args[1..]));
        }
        Some("org") => {
            // Role governance: list, veto, or inspect the decision log. No VM.
            std::process::exit(org_dispatch(&args[1..]));
        }
        Some("-h") | Some("--help") | Some("help") | None => {
            print!("{USAGE}");
        }
        Some(other) => {
            eprintln!("error: unknown command {other:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Minimal flag parser: `--key value` and `--flag`. Unknown flags are an error.
/// Split out an optional `--writeback <dir>` flag, returning it and the remaining
/// args (so `parse_run`, which rejects unknown flags, never sees it).
fn take_writeback(args: &[String]) -> (Option<std::path::PathBuf>, Vec<String>) {
    let mut dir = None;
    let mut rest = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--writeback" {
            dir = iter.next().map(std::path::PathBuf::from);
        } else {
            rest.push(arg.clone());
        }
    }
    (dir, rest)
}

fn parse_run(args: &[String]) -> Result<RunConfig, String> {
    let mut goal = None;
    let mut title = None;
    let mut workspace = None;
    let mut store = None;
    let mut harness = None;
    let mut autonomy = Autonomy::Autonomous;
    let mut model = "deepseek-chat".to_string();
    let mut base_url = "https://api.deepseek.com".to_string();
    let mut protocol = Protocol::OpenAiChat;
    let mut backend_id: Option<String> = None;
    let mut context_window: u32 = 128_000;
    let mut max_tokens: u32 = 8_192;
    let mut reasoning = false;
    let mut auto_review = false;
    let mut max_steps: u64 = 200;
    let mut max_model_tokens: u64 = 2_000_000;
    let mut max_secs: u64 = 14_400;
    let mut network = false;
    let mut cpus: u8 = 2;
    let mut ram_mib: u32 = 1_024;

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().cloned().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--goal" => goal = Some(value()?),
            "--title" => title = Some(value()?),
            "--workspace" => workspace = Some(PathBuf::from(value()?)),
            "--store" => store = Some(PathBuf::from(value()?)),
            "--harness" => harness = Some(PathBuf::from(value()?)),
            "--autonomy" => autonomy = parse_autonomy(&value()?)?,
            "--model" => model = value()?,
            "--base-url" => base_url = value()?,
            "--protocol" => protocol = Protocol::parse(&value()?)?,
            "--backend-id" => backend_id = Some(value()?),
            "--context-window" => context_window = parse_num(&value()?, flag)?,
            "--max-tokens" => max_tokens = parse_num(&value()?, flag)?,
            "--reasoning" => reasoning = true,
            "--review" => auto_review = true,
            "--max-steps" => max_steps = parse_num(&value()?, flag)?,
            "--max-model-tokens" => max_model_tokens = parse_num(&value()?, flag)?,
            "--max-secs" => max_secs = parse_num(&value()?, flag)?,
            "--network" => network = true,
            "--cpus" => cpus = parse_num(&value()?, flag)?,
            "--ram" => ram_mib = parse_num(&value()?, flag)?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    let goal = goal.ok_or("--goal is required")?;
    let workspace = workspace.ok_or("--workspace is required")?;
    if !workspace.is_dir() {
        return Err(format!("workspace {} is not a directory", workspace.display()));
    }
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?);
    let title = title.unwrap_or_else(|| goal.lines().next().unwrap_or("job").chars().take(80).collect());
    let backend_host = base_url.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or("backend").to_string();

    Ok(RunConfig {
        job_id: None,
        goal,
        title,
        workspace,
        store_root: store.unwrap_or_else(|| home.join(".bulge/jobs")),
        harness_dir: harness.unwrap_or_else(|| home.join(".bulge/harness")),
        autonomy,
        budget: Budget { max_steps, max_tokens: max_model_tokens, max_wall_secs: max_secs },
        backend: BackendSpec {
            id: backend_id.unwrap_or(backend_host),
            base_url,
            protocol,
            model,
            context_window,
            max_tokens,
            reasoning,
        },
        network,
        cpus,
        ram_mib,
        sampling: bulge_cli::run::Sampling::default(),
        system_prompt: None,
        egress_approvals: None,
        skip_review: false,
        auto_review,
    })
}

/// Parse `bulge eval` flags. Shares the model/budget/VM options with `run`.
fn parse_eval(args: &[String]) -> Result<EvalConfig, String> {
    let mut tasks_file = None;
    let mut workspace_root = None;
    let mut store = None;
    let mut harness = None;
    let mut autonomy = Autonomy::Autonomous;
    let mut model = "deepseek-chat".to_string();
    let mut base_url = "https://api.deepseek.com".to_string();
    let mut protocol = Protocol::OpenAiChat;
    let mut backend_id: Option<String> = None;
    let mut context_window: u32 = 128_000;
    let mut max_tokens: u32 = 8_192;
    let mut reasoning = false;
    let mut max_steps: u64 = 200;
    let mut max_model_tokens: u64 = 2_000_000;
    let mut max_secs: u64 = 14_400;
    let mut network = false;
    let mut cpus: u8 = 2;
    let mut ram_mib: u32 = 1_024;

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().cloned().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--tasks" => tasks_file = Some(PathBuf::from(value()?)),
            "--workspace-root" => workspace_root = Some(PathBuf::from(value()?)),
            "--store" => store = Some(PathBuf::from(value()?)),
            "--harness" => harness = Some(PathBuf::from(value()?)),
            "--autonomy" => autonomy = parse_autonomy(&value()?)?,
            "--model" => model = value()?,
            "--base-url" => base_url = value()?,
            "--protocol" => protocol = Protocol::parse(&value()?)?,
            "--backend-id" => backend_id = Some(value()?),
            "--context-window" => context_window = parse_num(&value()?, flag)?,
            "--max-tokens" => max_tokens = parse_num(&value()?, flag)?,
            "--reasoning" => reasoning = true,
            "--max-steps" => max_steps = parse_num(&value()?, flag)?,
            "--max-model-tokens" => max_model_tokens = parse_num(&value()?, flag)?,
            "--max-secs" => max_secs = parse_num(&value()?, flag)?,
            "--network" => network = true,
            "--cpus" => cpus = parse_num(&value()?, flag)?,
            "--ram" => ram_mib = parse_num(&value()?, flag)?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    let tasks_file = tasks_file.ok_or("--tasks is required")?;
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?);
    let backend_host = base_url.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or("backend").to_string();

    Ok(EvalConfig {
        tasks_file,
        workspace_root: workspace_root.unwrap_or_else(std::env::temp_dir),
        store_root: store.unwrap_or_else(|| home.join(".bulge/jobs")),
        harness_dir: harness.unwrap_or_else(|| home.join(".bulge/harness")),
        autonomy,
        budget: Budget { max_steps, max_tokens: max_model_tokens, max_wall_secs: max_secs },
        backend: BackendSpec { id: backend_id.unwrap_or(backend_host), base_url, protocol, model, context_window, max_tokens, reasoning },
        network,
        cpus,
        ram_mib,
    })
}


/// Parse an `org` subcommand's optional `--harness DIR` and optional positional
/// role name. Unknown flags and extra positionals are errors.
fn parse_org_args(args: &[String]) -> Result<(Option<String>, PathBuf), String> {
    let mut harness = None;
    let mut name: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--harness" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--harness needs a value".to_string())?;
                harness = Some(PathBuf::from(value));
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag {other:?}"));
            }
            other => {
                if name.is_some() {
                    return Err(format!("unexpected argument {other:?}"));
                }
                name = Some(other.to_string());
            }
        }
    }
    let harness = match harness {
        Some(path) => path,
        None => {
            let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
            PathBuf::from(home).join(".bulge/harness")
        }
    };
    Ok((name, harness))
}

/// Entry point for `bulge org <sub> …`. Returns a process exit code.
fn org_dispatch(args: &[String]) -> i32 {
    let result = match args.first().map(String::as_str) {
        Some("roles") => org_roles(&args[1..]),
        Some("veto") => org_veto(&args[1..]),
        Some("log") => org_log(&args[1..]),
        Some(other) => Err(format!(
            "unknown org command {other:?} (roles|veto <name>|log)"
        )),
        None => Err("org needs a command (roles|veto <name>|log)".to_string()),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: {error}");
            2
        }
    }
}

/// A one-line purpose, clipped to at most 60 characters for the roles table.
fn clip_purpose(purpose: &str) -> String {
    let cleaned = purpose.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() <= 60 {
        cleaned
    } else {
        let mut clipped: String = cleaned.chars().take(59).collect();
        clipped.push('…');
        clipped
    }
}

fn org_roles(args: &[String]) -> Result<(), String> {
    let (name, harness) = parse_org_args(args)?;
    if name.is_some() {
        return Err("org roles takes no role name".to_string());
    }
    let roles_dir = harness.join("org").join("roles");
    let (library, problems) = RoleLibrary::load(&roles_dir);
    for problem in problems {
        eprintln!("org: role {}: {}", problem.path, problem.message);
    }
    println!(
        "{:<24} {:<8} {:<5} {:<6} {:<20} {:<7} PURPOSE",
        "NAME", "KIND", "TRIAL", "SHARE", "MODEL", "SOURCE"
    );
    for name in library.names() {
        let Some(role) = library.get(&name) else {
            continue;
        };
        let path = roles_dir.join(format!("{name}.md"));
        let source = match std::fs::read_to_string(&path) {
            Ok(source) => match parse_charter(&source) {
                Ok(charter) if charter.name == name => "file",
                _ => "builtin",
            },
            Err(_) => "builtin",
        };
        let model = role.model.as_deref().unwrap_or("-");
        println!(
            "{:<24} {:<8} {:<5} {:<6} {:<20} {:<7} {}",
            role.name,
            role.kind.to_string(),
            role.trial,
            format!("{:.2}", role.budget_share),
            model,
            source,
            clip_purpose(&role.purpose),
        );
    }
    Ok(())
}

/// Role names are kebab-case, which also keeps `veto` from escaping the roles
/// directory with a path.
fn is_safe_role_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

fn org_veto(args: &[String]) -> Result<(), String> {
    let (name, harness) = parse_org_args(args)?;
    let name = name.ok_or_else(|| "org veto needs a role name".to_string())?;
    if !is_safe_role_name(&name) {
        return Err(format!("invalid role name {name:?}"));
    }
    if RoleLibrary::builtin().get(&name).is_some() {
        return Err(format!("cannot veto built-in role `{name}`"));
    }
    let path = harness.join("org").join("roles").join(format!("{name}.md"));
    if !path.is_file() {
        return Err(format!(
            "role `{name}` is not installed at {}",
            path.display()
        ));
    }
    std::fs::remove_file(&path).map_err(|error| format!("remove {}: {error}", path.display()))?;
    let decisions = harness.join("org").join("governance.jsonl");
    append_decision(
        &decisions,
        "vetoed",
        &name,
        "user",
        &format!("removed {}", path.display()),
        now_ms(),
    )?;
    println!("vetoed role {name}; removed {}", path.display());
    Ok(())
}

fn org_log(args: &[String]) -> Result<(), String> {
    let (name, harness) = parse_org_args(args)?;
    if name.is_some() {
        return Err("org log takes no role name".to_string());
    }
    let path = harness.join("org").join("governance.jsonl");
    match std::fs::read_to_string(&path) {
        Ok(source) => {
            if source.trim().is_empty() {
                println!("no governance decisions");
            } else {
                for line in source.lines().filter(|line| !line.trim().is_empty()) {
                    println!("{line}");
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("no governance decisions");
            Ok(())
        }
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

/// Current wall-clock time in Unix milliseconds (0 before the epoch).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_autonomy(value: &str) -> Result<Autonomy, String> {
    match value {
        "collaborative" => Ok(Autonomy::Collaborative),
        "autonomous" => Ok(Autonomy::Autonomous),
        "full-auto" | "full_auto" | "fullauto" => Ok(Autonomy::FullAuto),
        other => Err(format!("unknown autonomy {other:?} (collaborative|autonomous|full-auto)")),
    }
}

fn parse_num<T: std::str::FromStr>(value: &str, flag: &str) -> Result<T, String> {
    value.parse::<T>().map_err(|_| format!("{flag} expects a number, got {value:?}"))
}
