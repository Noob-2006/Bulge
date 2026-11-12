//! Post-write syntax lint (port of Hermes `tools/file_operations_lint.py`, MIT): in-process
//! parsers for JSON/TOML (and YAML/Python through python3 when available), per-file shell
//! linters for JS/TS/Go/Rust. JSON/YAML/TOML parse failures refuse a whole-file write;
//! everything else is reported after the write, filtered to errors the edit introduced.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum Lint {
    Ok,
    Failed(String),
    Skipped(String),
}

/// Extensions whose parse failure refuses a write (text fixtures use `.py`, so not Python).
pub const FAIL_CLOSED: &[&str] = &["json", "yaml", "yml", "toml"];

fn ext(p: &Path) -> String {
    p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

fn run(cmd: &mut Command, input: Option<&str>, timeout: Duration) -> Option<(bool, String)> {
    use std::io::Write as _;
    let mut child = cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().ok()?;
    if let (Some(i), Some(mut s)) = (input, child.stdin.take()) {
        let _ = s.write_all(i.as_bytes());
    }
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Some((false, format!("linter timed out after {}s", timeout.as_secs())));
            }
        }
    }
    let o = child.wait_with_output().ok()?;
    let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&o.stderr));
    Some((o.status.success(), crate::extract::strip_ansi(text.trim())))
}

const PY_SYNTAX: &str = "import ast,sys\ntry:\n    ast.parse(sys.stdin.buffer.read())\nexcept SyntaxError as e:\n    loc=f' (line {e.lineno}, column {e.offset})' if e.lineno else ''\n    print(f'{type(e).__name__}: {e.msg}{loc}'); sys.exit(1)\n";
const PY_YAML: &str = "import sys\ntry:\n    import yaml\nexcept ImportError:\n    sys.exit(3)\ntry:\n    for _ in yaml.parse(sys.stdin.read(), Loader=yaml.SafeLoader): pass\nexcept yaml.YAMLError as e:\n    print(f'YAMLError: {e}'); sys.exit(1)\n";

/// In-process (or interpreter-backed) syntax check of `content` for `path`'s type.
pub fn check_content(path: &Path, content: &str) -> Lint {
    match ext(path).as_str() {
        "json" => match serde_json::from_str::<serde_json::Value>(content) {
            Ok(_) => Lint::Ok,
            Err(e) => Lint::Failed(format!("JSONDecodeError: {e}")),
        },
        "toml" => match content.parse::<toml::Table>() {
            Ok(_) => Lint::Ok,
            Err(e) => Lint::Failed(format!("TOMLDecodeError: {}", e.message())),
        },
        "yaml" | "yml" => {
            if !which("python3") {
                return Lint::Skipped("No linter available for .yaml (python3 missing)".into());
            }
            let mut c = seagent_core::platform::proc::command("python3");
            c.arg("-I").arg("-c").arg(PY_YAML);
            match c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().and_then(|mut ch| {
                use std::io::Write as _;
                if let Some(mut s) = ch.stdin.take() {
                    let _ = s.write_all(content.as_bytes());
                }
                ch.wait_with_output()
            }) {
                Ok(o) if o.status.code() == Some(3) => Lint::Skipped("No linter available for .yaml (missing dependency: PyYAML)".into()),
                Ok(o) if o.status.success() => Lint::Ok,
                Ok(o) => Lint::Failed(String::from_utf8_lossy(&o.stdout).trim().to_string()),
                Err(e) => Lint::Skipped(format!("yaml lint failed to start: {e}")),
            }
        }
        "py" => {
            if !which("python3") {
                return Lint::Skipped("python3 not available".into());
            }
            match run(seagent_core::platform::proc::command("python3").arg("-I").arg("-c").arg(PY_SYNTAX), Some(content), Duration::from_secs(30)) {
                Some((true, _)) => Lint::Ok,
                Some((false, out)) => Lint::Failed(out),
                None => Lint::Skipped("python3 failed to start".into()),
            }
        }
        e => Lint::Skipped(format!("No in-process linter for .{e} files")),
    }
}

fn has_ancestor(path: &Path, name: &str) -> bool {
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    abs.ancestors().skip(1).any(|d| d.join(name).is_file())
}

/// Lint the file on disk (shell linters) or its content (in-process).
pub fn check(path: &Path, content: Option<&str>, project_toolchains: bool) -> Lint {
    let e = ext(path);
    if matches!(e.as_str(), "json" | "toml" | "yaml" | "yml" | "py") {
        let owned;
        let c = match content {
            Some(c) => c,
            None => {
                owned = match std::fs::read_to_string(path) {
                    Ok(s) => s,
                    Err(_) => return Lint::Skipped(format!("Failed to read {} for lint", path.display())),
                };
                &owned
            }
        };
        return check_content(path, c);
    }
    let (bin, args): (&str, Vec<&str>) = match e.as_str() {
        "js" | "mjs" | "cjs" => ("node", vec!["--check"]),
        "ts" => ("npx", vec!["tsc", "--noEmit"]),
        "go" => ("go", vec!["vet"]),
        "rs" => ("rustfmt", vec!["--check", "--edition", "2021"]),
        _ => return Lint::Skipped(format!("No linter for .{e} files")),
    };
    if e == "ts" && has_ancestor(path, "tsconfig.json") {
        return Lint::Skipped("Project tsconfig.json detected — per-file tsc skipped (single-file tsc can't resolve project aliases/globals; use `tsc -p tsconfig.json` for real diagnostics).".into());
    }
    if matches!(e.as_str(), "ts" | "rs") && !project_toolchains {
        return Lint::Skipped(format!("{bin} skipped: it resolves the toolchain from the workspace (set files.lint_project_toolchains = true to lint .{e} here)"));
    }
    if !which(bin) {
        return Lint::Skipped(format!("{bin} not available"));
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let Some((ok, out)) = run(seagent_core::platform::proc::command(bin).args(&args).arg(path).current_dir(dir), None, Duration::from_secs(30)) else { return Lint::Skipped(format!("{bin} failed to start")) };
    let unusable: &[&str] = match bin {
        "npx" => &["this is not the tsc command you are looking for", "could not determine executable to run", "not found in npm registry"],
        "rustfmt" => &["no input filename given", "error: not a workspace"],
        "go" => &["cannot find package", "go: cannot find main module"],
        _ => &[],
    };
    let lower = out.to_lowercase();
    if !ok && unusable.iter().any(|u| lower.contains(u)) {
        let first = out.lines().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(200).collect::<String>();
        return Lint::Skipped(format!("{bin} not usable: {first}"));
    }
    if ok {
        Lint::Ok
    } else {
        Lint::Failed(out)
    }
}

/// Post-write lint; when it fails and the previous content is known, report only errors
/// the edit introduced.
pub fn check_delta(path: &Path, pre: Option<&str>, post: Option<&str>, project_toolchains: bool) -> Lint {
    let after = check(path, post, project_toolchains);
    let Lint::Failed(out) = &after else { return after };
    let Some(pre) = pre else { return after };
    // Shell linters read the file: compare against an in-process run of the old content when we can.
    let before = check_content(path, pre);
    let Lint::Failed(bout) = before else { return after };
    let old: std::collections::HashSet<&str> = bout.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let new: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty() && !old.contains(l.trim())).collect();
    if new.is_empty() {
        return Lint::Failed(format!("Pre-existing lint errors — this edit didn't introduce new ones but the file is still broken.\n{out}"));
    }
    Lint::Failed(format!("New lint errors introduced by this edit (pre-existing errors filtered out):\n{}", new.join("\n")))
}

/// The suffix a tool result carries for a lint outcome ("" unless it failed).
pub fn suffix(l: &Lint) -> String {
    match l {
        Lint::Failed(o) => format!("\n[lint failed — fix these before moving on]\n{}", crate::util::truncate_str(o, 4000)),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_toml_in_process() {
        assert_eq!(check_content(Path::new("a.json"), "{\"a\": 1}"), Lint::Ok);
        assert!(matches!(check_content(Path::new("a.json"), "{\"a\": }"), Lint::Failed(e) if e.contains("JSONDecodeError")));
        assert_eq!(check_content(Path::new("a.toml"), "a = 1\n[b]\nc = \"x\""), Lint::Ok);
        assert!(matches!(check_content(Path::new("a.toml"), "a = = 1"), Lint::Failed(e) if e.contains("TOMLDecodeError")));
        assert!(matches!(check_content(Path::new("a.txt"), "x"), Lint::Skipped(_)));
    }

    #[test]
    fn python_and_yaml_via_interpreter() {
        if !which("python3") {
            return;
        }
        assert_eq!(check_content(Path::new("a.py"), "def f():\n    return 1\n"), Lint::Ok);
        assert!(matches!(check_content(Path::new("a.py"), "def f(:\n"), Lint::Failed(e) if e.contains("SyntaxError") && e.contains("line 1")));
        match check_content(Path::new("a.yaml"), "a: [1, 2\n") {
            Lint::Failed(e) => assert!(e.contains("YAMLError")),
            Lint::Skipped(s) => assert!(s.contains("PyYAML")),
            Lint::Ok => panic!("broken yaml passed"),
        }
    }

    #[test]
    fn delta_filters_preexisting_and_shell_skips() {
        let d = crate::testutil::tmpdir("lint");
        let p = d.join("x.json");
        std::fs::write(&p, "{bad").unwrap();
        assert!(matches!(check_delta(&p, Some("{bad"), None, false), Lint::Failed(e) if e.contains("Pre-existing")));
        std::fs::write(&p, "{}").unwrap();
        assert_eq!(check_delta(&p, Some("{bad"), None, false), Lint::Ok);
        let r = d.join("m.rs");
        std::fs::write(&r, "fn main(){}").unwrap();
        assert!(matches!(check(&r, None, false), Lint::Skipped(s) if s.contains("lint_project_toolchains")));
        std::fs::write(d.join("tsconfig.json"), "{}").unwrap();
        assert!(matches!(check(&d.join("a.ts"), None, true), Lint::Skipped(s) if s.contains("tsconfig")));
        if which("node") {
            let j = d.join("a.js");
            std::fs::write(&j, "function (").unwrap();
            assert!(matches!(check(&j, None, false), Lint::Failed(_)));
            std::fs::write(&j, "function f() {}").unwrap();
            assert_eq!(check(&j, None, false), Lint::Ok);
        }
        assert_eq!(suffix(&Lint::Ok), "");
        assert!(suffix(&Lint::Failed("boom".into())).contains("boom"));
    }
}
