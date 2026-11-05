//! `ark docker check`: lint the container files this repo ships (OpenClaw §11
//! `Docker / compose / fly / render`, `src/dockerfile.test.ts`,
//! `src/docker-healthcheck.ts`).
//!
//! The repo has a real `Dockerfile` (cargo-chef build, debian-slim runtime, tini,
//! non-root `ark` user, `HEALTHCHECK ark health`) and no compose/fly/render
//! manifests, but nothing checked any of it. This module turns the properties
//! upstream asserts in tests into one linter that runs offline:
//!
//! ```text
//! ark docker check [--file Dockerfile] [--json]
//! ```
//!
//! Rules (`Finding::rule`), printed ✓/✗ one per line, exit 1 on any ✗:
//!
//! * `multistage` — at least two `FROM`s, the final stage is not a toolchain
//!   image (`rust`, `cargo`, `buildpack-deps`, `golang`, `gcc`, `clang`) and does
//!   not `COPY --from` the toolchain in (`/root/.cargo`, `/usr/local/cargo`,
//!   `/usr/local/rustup`, `/usr/local/go`, …).
//! * `nonroot` — the final stage sets `USER` to something other than `root`/`0`.
//! * `healthcheck` — `HEALTHCHECK … CMD` in the final stage that calls
//!   `ark health` (or a `…/health`/`/healthz` endpoint), with sane
//!   `--interval` (5–300 s), `--timeout` (1–60 s), `--retries` (1–10) and
//!   `--start-period` (≤ 600 s); omitted options fall back to Docker's defaults.
//! * `entrypoint` — `ENTRYPOINT`/`CMD` that ends up starting `ark daemon run`
//!   (in that order, exec form preferred); `sh -c` without `exec` is flagged
//!   because the shell stays PID 1 and does not forward signals.
//! * `secrets` — no `ENV`/`ARG` pair whose name looks like a credential (`KEY`,
//!   `TOKEN`, `SECRET`, `PASSWORD`) carries a non-empty value, i.e. no build
//!   secret is baked into a layer.
//! * `lockfile` — the build is lock-aware (`--locked`) *and* dependency layers
//!   are cached before the sources: either `COPY … recipe.json` +
//!   `cargo chef cook` or `COPY Cargo.toml Cargo.lock …` ahead of `COPY . .`.
//!
//! When a sibling `docker-compose.yml`/`compose.yaml` exists it is scanned too
//! (`compose_privileged`, `compose_network`, `compose_healthcheck`,
//! `compose_volume`): no `privileged: true`, no `network_mode: host`, a
//! healthcheck, and a volume mounted at `/data`. This is a textual scan on
//! purpose — ark has no YAML parser and the rules are one line each.
//!
//! The linting core is pure (`lint(name, text)` / `lint_compose(name, text)`) so
//! fixtures are linted as strings; the file plumbing is `check`.
//!
//! Wiring: `ops/mod.rs` needs the module row
//! `(docker::COMMANDS, docker::VALUE_FLAGS, docker::BOOL_FLAGS, docker::dispatch)` —
//! until it exists `dispatch` is only reachable from the tests (and `--file`/`--json`
//! are unknown to `Args::parse`).
//!
//! Scope: `ark docker` owns only `check`. `build`/`run`/`compose up` stay the
//! user's `docker` (ark does not shell out to a container engine), and
//! `fly.toml`/`render.yaml` are not covered — ark ships neither.

use crate::args::Args;
use crate::{usage, Fail, R};
use serde_json::json;

pub const COMMANDS: &[&str] = &["docker"];
pub const VALUE_FLAGS: &[&str] = &["file"];
pub const BOOL_FLAGS: &[&str] = &["json"];

/// One lint result. `rule` is a stable id (JSON output keys on it).
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub rule: &'static str,
    pub ok: bool,
    pub detail: String,
}

impl Finding {
    fn new(rule: &'static str, ok: bool, detail: impl Into<String>) -> Finding {
        Finding {
            rule,
            ok,
            detail: detail.into(),
        }
    }
}

// ───────────── Dockerfile parsing ─────────────

#[derive(Debug, Clone)]
struct Instr {
    cmd: String,
    args: String,
    stage: usize,
}

/// Logical instructions: comments and blank lines dropped, `\` continuations
/// joined, stage index = number of `FROM`s seen so far (0 before the first).
fn parse(text: &str) -> Vec<Instr> {
    let mut out: Vec<Instr> = vec![];
    let mut buf = String::new();
    let mut stage: Option<usize> = None;
    for raw in text.lines() {
        let t = raw.trim_start();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let cont = t.trim_end().ends_with('\\');
        let piece = if cont {
            t.trim_end().trim_end_matches('\\').trim_end()
        } else {
            t.trim_end()
        };
        if !buf.is_empty() {
            buf.push(' ');
        }
        buf.push_str(piece);
        if cont {
            continue;
        }
        let logical = std::mem::take(&mut buf);
        let (cmd, args) = match logical.split_once(char::is_whitespace) {
            Some((c, a)) => (c.to_ascii_uppercase(), a.trim().to_string()),
            None => (logical.to_ascii_uppercase(), String::new()),
        };
        if cmd == "FROM" {
            stage = Some(stage.map_or(0, |s| s + 1));
        }
        out.push(Instr {
            cmd,
            args,
            stage: stage.unwrap_or(0),
        });
    }
    out
}

fn base_image(args: &str) -> String {
    args.split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn image_name(base: &str) -> &str {
    base.rsplit('/')
        .next()
        .unwrap_or(base)
        .split([':', '@'])
        .next()
        .unwrap_or("")
}

fn toolchain_base(base: &str) -> bool {
    let name = image_name(base);
    [
        "rust",
        "cargo",
        "buildpack-deps",
        "golang",
        "gcc",
        "clang",
        "llvm",
        "rustlang",
    ]
    .iter()
    .any(|k| name.starts_with(k))
}

const TOOLCHAIN_PATHS: &[&str] = &[
    "/root/.cargo",
    "/usr/local/cargo",
    "/usr/local/rustup",
    "/root/.rustup",
    "/usr/local/go",
    "/usr/lib/go",
    "/usr/local/lib/rustlib",
];

/// Exec form (`["a","b"]`) or shell form (`a b c`) → tokens.
fn tokens(args: &str) -> Vec<String> {
    let a = args.trim();
    if a.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(a) {
            return v
                .into_iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| x.to_string())
                })
                .collect();
        }
    }
    a.split_whitespace().map(str::to_string).collect()
}

fn find_after(hay: &[String], needle: &str, from: usize) -> Option<usize> {
    hay.iter()
        .enumerate()
        .skip(from)
        .find(|(_, t)| t.as_str() == needle)
        .map(|(i, _)| i)
}

// ───────────── Dockerfile rules ─────────────

/// Pure Dockerfile lint: rules are evaluated in a fixed order.
pub fn lint(_name: &str, text: &str) -> Vec<Finding> {
    let ins = parse(text);
    let froms: Vec<&Instr> = ins.iter().filter(|i| i.cmd == "FROM").collect();
    let final_stage = froms.iter().map(|i| i.stage).max();
    let fin: Vec<&Instr> = match final_stage {
        Some(s) => ins.iter().filter(|i| i.stage == s).collect(),
        None => vec![],
    };
    let mut out = vec![];

    // 1. multi-stage, runtime layer without a build toolchain
    let base = froms
        .last()
        .map(|i| base_image(&i.args))
        .unwrap_or_default();
    let copied_toolchain: Vec<&str> = fin
        .iter()
        .filter(|i| i.cmd == "COPY" && i.args.contains("--from="))
        .flat_map(|i| {
            TOOLCHAIN_PATHS
                .iter()
                .filter(move |p| i.args.contains(**p))
                .copied()
        })
        .collect();
    out.push(if froms.len() < 2 {
        Finding::new("multistage", false, format!("single-stage build ({}) — the build toolchain ships in the runtime image", base))
    } else if toolchain_base(&base) {
        Finding::new("multistage", false, format!("final stage `{base}` is a build toolchain image; build in one stage, run on a slim/distroless/debian base"))
    } else if !copied_toolchain.is_empty() {
        Finding::new("multistage", false, format!("final stage copies the toolchain from the builder: {}", copied_toolchain.join(", ")))
    } else {
        Finding::new("multistage", true, format!("{} stages · runtime base `{base}` carries no toolchain", froms.len()))
    });

    // 2. non-root runtime user
    let user = fin.iter().rfind(|i| i.cmd == "USER").map(|i| i.args.trim().to_string());
    let rootless = user.as_deref().is_some_and(|u| {
        let n = u.split(':').next().unwrap_or(u).trim().to_ascii_lowercase();
        !n.is_empty() && n != "root" && n != "0"
    });
    out.push(if rootless {
        Finding::new("nonroot", true, format!("USER {}", user.unwrap_or_default()))
    } else {
        Finding::new(
            "nonroot",
            false,
            match user {
                Some(u) => format!("final stage sets USER {u} (runs as root) — add `useradd -m ark` and `USER ark`"),
                None => "final stage sets no USER, so the container runs as root".to_string(),
            },
        )
    });

    // 3. healthcheck that probes the daemon, with sane timings
    let hc = fin.iter().rfind(|i| i.cmd == "HEALTHCHECK");
    out.push(match hc {
        None => Finding::new(
            "healthcheck",
            false,
            "no HEALTHCHECK in the final stage — `ark health` is the documented probe",
        ),
        Some(i) if i.args.trim().eq_ignore_ascii_case("NONE") => Finding::new(
            "healthcheck",
            false,
            "HEALTHCHECK NONE disables the container health probe",
        ),
        Some(i) => healthcheck_finding(&i.args),
    });

    // 4. entrypoint/cmd: signals reach ark, and it starts `ark daemon run`
    out.push(entrypoint_finding(&fin));

    // 5. no credential baked into the image by ENV/ARG
    let mut leaks: Vec<String> = vec![];
    for i in ins.iter().filter(|i| i.cmd == "ENV" || i.cmd == "ARG") {
        for pair in i.args.split_whitespace() {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            let key = k.trim().to_ascii_uppercase();
            let looks_secret = ["KEY", "TOKEN", "SECRET", "PASSWORD"]
                .iter()
                .any(|w| key.contains(w));
            if looks_secret && !v.trim().trim_matches(['"', '\'']).is_empty() {
                leaks.push(format!("{} {}={}…", i.cmd, k, "[redacted]"));
            }
        }
    }
    out.push(if leaks.is_empty() {
        Finding::new(
            "secrets",
            true,
            "no credential is ENVed/ARGed into the image (pass secrets at run time)",
        )
    } else {
        Finding::new(
            "secrets",
            false,
            format!(
                "credential baked into a layer: {} — use `docker run -e`/a secret mount",
                leaks.join(", ")
            ),
        )
    });

    // 6. lockfile-aware, cache-friendly dependency layer
    out.push(lockfile_finding(&ins));

    out
}

fn healthcheck_finding(args: &str) -> Finding {
    let lower = args.to_ascii_lowercase();
    let secs = |flag: &str| -> Option<u64> {
        let key = format!("--{flag}=");
        let i = lower.find(&key)? + key.len();
        let raw: String = lower[i..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || c.is_ascii_alphabetic())
            .collect();
        let (num, mult) = match raw.trim_end_matches(['s', 'm', 'h']).parse::<f64>() {
            Ok(n) => (
                n,
                if raw.ends_with('m') {
                    60.0
                } else if raw.ends_with('h') {
                    3600.0
                } else {
                    1.0
                },
            ),
            Err(_) => return None,
        };
        Some((num * mult) as u64)
    };
    let cmd_ok = lower.contains("ark health")
        || lower.contains("\"health\"")
        || lower.contains("/health")
        || lower.contains("ark\",\"health");
    let interval = secs("interval");
    let timeout = secs("timeout");
    let retries: Option<u64> = lower
        .find("--retries=")
        .map(|i| {
            lower[i + 10..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
        })
        .and_then(|s| s.parse().ok());
    let start = secs("start-period");
    let mut bad: Vec<String> = vec![];
    if !cmd_ok {
        bad.push("the probe does not call `ark health` or a /health endpoint".into());
    }
    if interval.is_some_and(|s| !(5..=300).contains(&s)) {
        bad.push(format!(
            "--interval={}s is outside 5–300 s",
            interval.unwrap_or(0)
        ));
    }
    if timeout.is_some_and(|s| !(1..=60).contains(&s)) {
        bad.push(format!(
            "--timeout={}s is outside 1–60 s",
            timeout.unwrap_or(0)
        ));
    }
    if retries.is_some_and(|r| !(1..=10).contains(&r)) {
        bad.push(format!(
            "--retries={} is outside 1–10",
            retries.unwrap_or(0)
        ));
    }
    if start.is_some_and(|s| s > 600) {
        bad.push(format!(
            "--start-period={}s is longer than 600 s",
            start.unwrap_or(0)
        ));
    }
    if bad.is_empty() {
        Finding::new(
            "healthcheck",
            true,
            format!(
                "HEALTHCHECK probes ark (interval {}s, timeout {}s, retries {}, start-period {}s)",
                interval.unwrap_or(30),
                timeout.unwrap_or(30),
                retries.unwrap_or(3),
                start.unwrap_or(0)
            ),
        )
    } else {
        Finding::new("healthcheck", false, bad.join("; "))
    }
}

fn entrypoint_finding(fin: &[&Instr]) -> Finding {
    let ep = fin.iter().rfind(|i| i.cmd == "ENTRYPOINT");
    let cmd = fin.iter().rfind(|i| i.cmd == "CMD");
    if ep.is_none() && cmd.is_none() {
        return Finding::new(
            "entrypoint",
            false,
            "no ENTRYPOINT/CMD — the image has nothing to start",
        );
    }
    let ep_tokens = ep.map(|i| tokens(&i.args)).unwrap_or_default();
    let cmd_tokens = cmd.map(|i| tokens(&i.args)).unwrap_or_default();
    let chain: Vec<String> = ep_tokens.iter().chain(cmd_tokens.iter()).cloned().collect();
    let shown = chain.join(" ");
    // Match on basenames so `/usr/bin/ark` counts as `ark`.
    let base: Vec<String> = chain
        .iter()
        .map(|t| t.rsplit('/').next().unwrap_or(t).to_string())
        .collect();
    // `sh -c` (or `bash -c`) as the entrypoint keeps the shell in PID 1: signals
    // and the exit status of ark are lost unless the shell is told to `exec`.
    let shell_c = base.iter().enumerate().any(|(i, t)| {
        (t == "sh" || t == "bash" || t == "dash")
            && base.get(i + 1).map(String::as_str) == Some("-c")
    });
    let has_exec = base.iter().any(|t| t == "exec");
    if shell_c && !has_exec {
        return Finding::new("entrypoint", false, format!("ENTRYPOINT runs `sh -c` without `exec` ({shown}) — the shell stays PID 1 and does not forward signals; use exec form with tini"));
    }
    let mut at = 0;
    let mut ok = true;
    for expect in ["ark", "daemon", "run"] {
        match find_after(&base, expect, at) {
            Some(i) => at = i + 1,
            None => {
                ok = false;
                break;
            }
        }
    }
    if ok {
        Finding::new(
            "entrypoint",
            true,
            format!("starts `{shown}` (exec form, signals reach ark)"),
        )
    } else {
        Finding::new("entrypoint", false, format!("ENTRYPOINT/CMD does not start `ark daemon run` (got `{shown}`) — a shell string cannot receive signals"))
    }
}

fn lockfile_finding(ins: &[Instr]) -> Finding {
    let locked = ins
        .iter()
        .any(|i| i.cmd == "RUN" && i.args.split_whitespace().any(|w| w == "--locked"));
    let chef = ins
        .iter()
        .any(|i| i.cmd == "RUN" && i.args.contains("cargo chef cook"))
        && ins
            .iter()
            .any(|i| i.cmd == "COPY" && i.args.contains("recipe.json"));
    let manifest_copy = ins.iter().position(|i| {
        i.cmd == "COPY" && i.args.contains("Cargo.lock") && i.args.contains("Cargo.toml")
    });
    let source_copy = ins
        .iter()
        .position(|i| i.cmd == "COPY" && i.args.split_whitespace().any(|w| w == "."));
    let manifest_first = manifest_copy.is_some_and(|m| source_copy.is_none_or(|s| m < s));
    if !locked {
        return Finding::new(
            "lockfile",
            false,
            "the build is not lock-aware — use `cargo build --locked` so Cargo.lock is honoured",
        );
    }
    if chef {
        Finding::new(
            "lockfile",
            true,
            "cargo-chef stages recipe.json (dependency layers cache) and builds `--locked`",
        )
    } else if manifest_first {
        Finding::new("lockfile", true, "Cargo.toml + Cargo.lock are copied before the sources (dependency layer caches) and the build is `--locked`")
    } else {
        Finding::new("lockfile", false, "sources are copied before Cargo.toml/Cargo.lock, so every source edit re-resolves the whole dependency graph")
    }
}

// ───────────── compose ─────────────

/// Pure compose lint (textual): no privileged mode, no host network, a
/// healthcheck and a `/data` volume.
pub fn lint_compose(name: &str, text: &str) -> Vec<Finding> {
    let lower = text.to_ascii_lowercase();
    let has = |needle: &str| lower.lines().any(|l| l.trim().starts_with(needle));
    let mut out = vec![];
    out.push(if lower.lines().any(|l| {
        let t = l.trim();
        t.starts_with("privileged:") && t["privileged:".len()..].trim().trim_matches(['"', '\'']).trim() == "true"
    }) {
        Finding::new("compose_privileged", false, format!("{name}: privileged: true gives the container the host's devices and capabilities"))
    } else {
        Finding::new("compose_privileged", true, format!("{name}: no privileged: true"))
    });
    out.push(if lower.lines().any(|l| {
        let t: String = l.trim().chars().filter(|c| !c.is_whitespace()).collect();
        t.starts_with("network_mode:") && t["network_mode:".len()..].trim_matches(['"', '\'']).trim() == "host"
    }) {
        Finding::new("compose_network", false, format!("{name}: network_mode: host exposes every service on the host stack; publish the port instead"))
    } else {
        Finding::new("compose_network", true, format!("{name}: no host networking"))
    });
    out.push(if has("healthcheck:") {
        Finding::new(
            "compose_healthcheck",
            true,
            format!("{name}: service healthcheck declared"),
        )
    } else {
        Finding::new(
            "compose_healthcheck",
            false,
            format!("{name}: no healthcheck: block (add `test: [\"CMD\", \"ark\", \"health\"]`)"),
        )
    });
    out.push(if lower.lines().any(|l| l.contains(":/data")) {
        Finding::new("compose_volume", true, format!("{name}: /data is a mounted volume (state survives the container)"))
    } else {
        Finding::new("compose_volume", false, format!("{name}: nothing is mounted at /data (ARK_HOME) — sessions and config would live in the container layer"))
    });
    out
}

// ───────────── command ─────────────

fn render(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| {
            format!(
                "{} {:<18} {}",
                if f.ok { "✓" } else { "✗" },
                f.rule,
                f.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `ark docker check [--file Dockerfile] [--json]`: lint the file (and a sibling
/// compose manifest), returning the exit code and the text to print.
pub fn check(file: Option<&str>, as_json: bool) -> Result<(i32, String), String> {
    let path = std::path::PathBuf::from(file.unwrap_or("Dockerfile"));
    if !path.is_file() {
        return Err(format!(
            "no such Dockerfile: {} (pass --file PATH)",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let name = path.display().to_string();
    let mut findings = lint(&name, &text);
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let mut compose_files: Vec<String> = vec![];
    for cand in [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ] {
        let p = dir.join(cand);
        if let Ok(t) = std::fs::read_to_string(&p) {
            compose_files.push(p.display().to_string());
            findings.extend(lint_compose(&p.display().to_string(), &t));
        }
    }
    let failed = findings.iter().filter(|f| !f.ok).count();
    let code = if failed == 0 { 0 } else { 1 };
    if as_json {
        let rows: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| json!({"rule": f.rule, "ok": f.ok, "detail": f.detail}))
            .collect();
        return Ok((
            code,
            json!({"file": name, "compose": compose_files, "ok": failed == 0, "failed": failed, "findings": rows}).to_string(),
        ));
    }
    let mut out = vec![format!(
        "{name}  ({} rules, {failed} failing)",
        findings.len()
    )];
    out.push(render(&findings));
    Ok((code, out.join("\n")))
}

fn parse_args(raw: &[String]) -> Result<(Option<String>, bool), String> {
    let mut file = None;
    let mut as_json = false;
    let mut i = 0;
    while i < raw.len() {
        let r = raw[i].as_str();
        i += 1;
        match r {
            "--json" => as_json = true,
            "--file" => {
                file = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| "--file needs a value".to_string())?,
                );
                i += 1;
            }
            f if f.starts_with("--file=") => file = Some(f["--file=".len()..].to_string()),
            f if f.starts_with('-') => {
                return Err(format!("unknown option {f} for `ark docker check`"))
            }
            "check" => {}
            w => return Err(format!("unexpected argument `{w}` (only `check`)")),
        }
    }
    Ok((file, as_json))
}

pub fn dispatch(cmd: &str, _a: &Args, raw: &[String]) -> Option<R> {
    if cmd != "docker" || raw.first().map(String::as_str) != Some("check") {
        return None;
    }
    let (file, as_json) = match parse_args(raw) {
        Ok(v) => v,
        Err(e) => return Some(usage(e)),
    };
    Some((|| {
        let (code, out) = check(file.as_deref(), as_json).map_err(Fail::Usage)?;
        println!("{out}");
        Ok(code)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BAD: &str = r#"# a Dockerfile that violates one rule per finding
FROM rust:1-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked

FROM debian:bookworm-slim
ENV OPENAI_API_KEY=sk-leaked-value
COPY --from=builder /app/target/release/ark /usr/local/bin/ark
ENTRYPOINT ["sh", "-c", "ark daemon run"]
"#;

    const GOOD: &str = r#"FROM golang:1.22 AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked

FROM gcr.io/distroless/static-debian12
COPY --from=builder /src/target/release/ark /ark
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/ark", "health"]
ENTRYPOINT ["/ark", "daemon", "run"]
"#;

    fn failed(f: &[Finding]) -> Vec<&'static str> {
        f.iter().filter(|x| !x.ok).map(|x| x.rule).collect()
    }

    #[test]
    fn repo_dockerfile_passes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Dockerfile");
        assert!(path.is_file(), "missing {}", path.display());
        let text = std::fs::read_to_string(&path).unwrap();
        let f = lint("Dockerfile", &text);
        assert!(
            failed(&f).is_empty(),
            "repo Dockerfile fails: {:?}",
            f.iter().filter(|x| !x.ok).collect::<Vec<_>>()
        );
        assert_eq!(f.len(), 6, "every rule reports once");
        // `check` on the real path: the Dockerfile rules must all pass. A compose
        // manifest added next to it later is linted too, hence the rule-by-rule
        // assertion rather than a bare exit code.
        let (code, out) = check(Some(path.to_str().unwrap()), false).unwrap();
        for rule in [
            "multistage",
            "nonroot",
            "healthcheck",
            "entrypoint",
            "secrets",
            "lockfile",
        ] {
            assert!(out.contains(&format!("✓ {rule}")), "{rule}: {out}");
        }
        assert_eq!(code == 0, !out.contains("✗"), "{code}\n{out}");
        if !out.contains("compose_") {
            assert_eq!(code, 0, "{out}");
        }
    }

    /// The image's default command must start (A9 refuses an unprotected 0.0.0.0 app server), and
    /// the image must carry share/ — the two PoC-breaking gaps of the old Dockerfile.
    #[test]
    fn repo_dockerfile_starts_safely_and_ships_share() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("Dockerfile")).unwrap();
        let cmd = text.lines().find(|l| l.starts_with("CMD ")).expect("CMD");
        assert!(!cmd.contains("0.0.0.0") && !cmd.contains("app.listen"), "default CMD must not bind publicly: {cmd}");
        assert!(text.lines().any(|l| l.starts_with("COPY --from=builder /app/share/ /usr/share/ark/")), "share/ is copied into the image");
        assert!(text.contains("ARK_SHARE_DIR=/usr/share/ark") && text.contains("packaging/vm/build-image.sh") && text.contains("packaging/sandbox-browser"));
        assert!(!text.lines().filter(|l| !l.trim_start().starts_with('#')).any(|l| l.contains("ARK_APP_ENABLED")), "app server stays opt-in (it needs a token to start)");

        // What the default does: nothing listens, so there is no refusal to hit.
        let cfg = ark_app::AppConfig::default();
        assert!(!cfg.enabled);

        // The documented public config satisfies every layer; the old bare bind is refused.
        let pub_toml: toml::Table = std::fs::read_to_string(root.join("packaging/docker/config.public.toml")).unwrap().parse().unwrap();
        let app = ark_app::AppConfig::parse(pub_toml["app"].as_table().unwrap()).unwrap();
        ark_app::exposure::check_start(&app).expect("config.public.toml must pass the app server's start-up policy");
        let bare: toml::Table = "listen = \"0.0.0.0:8640\"\nenabled = true\ntoken = \"t\"".parse().unwrap();
        assert!(ark_app::exposure::check_start(&ark_app::AppConfig::parse(&bare).unwrap()).is_err());
        assert!(root.join("packaging/docker/compose.yml").is_file());
    }

    #[test]
    fn fixture_findings_are_exact() {
        let f = lint("fixture.Dockerfile", BAD);
        assert_eq!(
            failed(&f),
            vec!["nonroot", "healthcheck", "entrypoint", "secrets"]
        );
        assert!(f
            .iter()
            .find(|x| x.rule == "entrypoint")
            .unwrap()
            .detail
            .contains("sh -c"));
        assert!(f
            .iter()
            .find(|x| x.rule == "secrets")
            .unwrap()
            .detail
            .contains("OPENAI_API_KEY"));
        assert!(f
            .iter()
            .find(|x| x.rule == "nonroot")
            .unwrap()
            .detail
            .contains("no USER"));
        // …and the well-formed fixture is clean.
        let g = lint("good.Dockerfile", GOOD);
        assert!(
            failed(&g).is_empty(),
            "{:?}",
            g.iter().filter(|x| !x.ok).collect::<Vec<_>>()
        );

        // single stage / toolchain runtime base / copied toolchain
        let single = lint("x", "FROM rust:1\nUSER ark\nHEALTHCHECK CMD [\"ark\",\"health\"]\nENTRYPOINT [\"ark\",\"daemon\",\"run\"]\n");
        assert!(single
            .iter()
            .any(|x| x.rule == "multistage" && !x.ok && x.detail.contains("single-stage")));
        let toolchain =
            lint("x", "FROM rust:1 AS b\nRUN cargo build --release --locked\nFROM rust:1\nUSER ark\nHEALTHCHECK CMD [\"ark\",\"health\"]\nENTRYPOINT [\"ark\",\"daemon\",\"run\"]\n");
        assert!(toolchain
            .iter()
            .any(|x| x.rule == "multistage" && !x.ok && x.detail.contains("toolchain image")));
        // secret-ish ARG with no value is the *correct* pattern, not a leak
        let arg = lint("x", "FROM a AS b\nARG GITHUB_TOKEN\nFROM debian:slim\nENV ARK_HOME=/data\nUSER ark\nHEALTHCHECK CMD [\"ark\",\"health\"]\nENTRYPOINT [\"ark\",\"daemon\",\"run\"]\n");
        assert!(arg.iter().find(|x| x.rule == "secrets").unwrap().ok);
    }

    #[test]
    fn json_and_file_errors() {
        let dir =
            std::env::temp_dir().join(format!("ark-docker-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("Dockerfile.bad");
        std::fs::write(&p, BAD).unwrap();
        let (code, out) = check(Some(p.to_str().unwrap()), true).unwrap();
        assert_eq!(code, 1);
        let j: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(j["ok"], false);
        assert_eq!(j["failed"], 4);
        assert!(j["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule"] == "nonroot" && f["ok"] == false));
        assert!(j["file"].as_str().unwrap().ends_with("Dockerfile.bad"));

        let e = check(Some(dir.join("nope").to_str().unwrap()), false).unwrap_err();
        assert!(e.contains("no such Dockerfile"), "{e}");

        // compose: privileged/host-network/no-healthcheck/missing volume all flagged
        let c = lint_compose(
            "compose.yaml",
            "services:\n  ark:\n    privileged: true\n    network_mode: host\n",
        );
        assert_eq!(
            failed(&c),
            vec![
                "compose_privileged",
                "compose_network",
                "compose_healthcheck",
                "compose_volume"
            ]
        );
        let ok = lint_compose(
            "compose.yaml",
            "services:\n  ark:\n    image: ark\n    healthcheck:\n      test: [\"CMD\", \"ark\", \"health\"]\n    volumes:\n      - ark-data:/data\n",
        );
        assert!(failed(&ok).is_empty(), "{:?}", failed(&ok));
    }

    #[test]
    fn dispatch_scope() {
        let a = Args::default();
        let raw = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };
        assert!(dispatch("tools", &a, &raw(&["check"])).is_none());
        assert!(dispatch("docker", &a, &[]).is_none());
        assert!(dispatch("docker", &a, &raw(&["build"])).is_none());
        match dispatch(
            "docker",
            &a,
            &raw(&["check", "--file", "/nonexistent/Dockerfile"]),
        ) {
            Some(Err(Fail::Usage(m))) => assert!(m.contains("no such Dockerfile"), "{m}"),
            other => panic!("expected a usage failure, got {other:?}"),
        }
    }
}
