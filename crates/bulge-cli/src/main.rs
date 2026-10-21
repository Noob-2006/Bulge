//! Headless bulge CLI.
//!
//!   bulge run --goal "..." --workspace DIR [options]
//!
//! Events stream to stdout as JSONL (the job log, line by line); diagnostics go to
//! stderr. Workspace changes stay in the VM overlay and are written as a diff for
//! review — the host is never modified.

use std::path::PathBuf;

use bulge_cli::backend::{BackendSpec, Protocol};
use bulge_cli::eval::{self, EvalConfig};
use bulge_cli::run::{self, RunConfig};
use bulge_store::{Autonomy, Budget};

const USAGE: &str = "\
bulge — headless sandboxed agent

USAGE:
    bulge run  --goal <TEXT> --workspace <DIR> [OPTIONS]
    bulge eval --tasks <FILE.json> [OPTIONS]
    bulge acp  (ACP agent server over stdio; editors spawn this)
    bulge schedule add|list|remove|tick   (scheduled tasks; see below)
    bulge recall <query> [--limit N]      (keyword search over past jobs)

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
        Some("run") => match parse_run(&args[1..]) {
            Ok(config) => {
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                match rt.block_on(run::run(config)) {
                    Ok(result) => {
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
        },
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
