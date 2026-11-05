//! The CI integrations (BATCH-next §2, ent-108/109/110): the GitHub Action, the GitLab CI
//! template and the Jenkinsfile under `integrations/`, and the script they all call.
//!
//! Nothing here talks to a forge or a model. `ark` is a fake executable that records how it
//! was started and what it was given; `curl` is a fake that records the request. What is
//! checked: the script's behaviour (diff in, review out, the agent never sees the posting
//! token, fix rounds, patch contents, the comment request), and that the three CI files parse
//! and wire the script correctly (their `run:` blocks even pass `sh -n`).

use ark_core::tmp::TempDir;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().to_path_buf()
}

fn script() -> PathBuf {
    root().join("integrations/ci/ark-ci.sh")
}

fn write_exec(p: &Path, body: &str) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn git(dir: &Path, args: &[&str]) {
    let o = Command::new("git").args(["-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(args).current_dir(dir).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

struct Fixture {
    _dir: TempDir,
    repo: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

/// A repo with `main` and a feature commit, a fake `ark` that logs and answers, a fake `curl`.
fn fixture(fake_ark_body: &str) -> Fixture {
    let dir = TempDir::new("ark-run-ci");
    let repo = dir.join("repo");
    let bin = dir.join("bin");
    let log = dir.join("log");
    for d in [&repo, &bin, &log] {
        std::fs::create_dir_all(d).unwrap();
    }
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("app.py"), "def total(xs):\n    return sum(xs)\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-qm", "base"]);
    git(&repo, &["switch", "-q", "-c", "feature"]);
    std::fs::write(repo.join("app.py"), "def total(xs):\n    return sum(xs) / len(xs)\n").unwrap();
    git(&repo, &["commit", "-qam", "change total"]);
    let l = log.display();
    write_exec(
        &bin.join("ark"),
        &format!(
            "#!/bin/sh\nn=$(ls '{l}' | grep -c '^args') ; printf '%s\\n' \"$@\" > '{l}/args'$n\ncat > '{l}/stdin'$n\nenv > '{l}/env'$n\n{fake_ark_body}\n"
        ),
    );
    write_exec(&bin.join("curl"), &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{l}/curl-args'\nfor a in \"$@\"; do case \"$a\" in @*) cp \"${{a#@}}\" '{l}/curl-body';; esac; done\n"));
    Fixture { _dir: dir, repo, bin, log }
}

impl Fixture {
    fn run(&self, mode: &str, env: &[(&str, &str)]) -> Output {
        let mut c = Command::new("sh");
        c.arg(script()).arg(mode).current_dir(&self.repo).env("PATH", format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap_or_default())).env("ARK_BIN", self.bin.join("ark")).env("ARK_OFFLINE", "1");
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.log.join(name)).unwrap_or_default()
    }
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[test]
fn review_hands_the_diff_over_as_data_and_never_the_posting_token() {
    let f = fixture("echo '### Review\n- blocker: division by zero in total() when xs is empty\nVerdict: REQUEST CHANGES'");
    let o = f.run("review", &[("GITHUB_TOKEN", "ghs_posting_token_123456"), ("GITLAB_TOKEN", "glpat-posting-token"), ("CI_JOB_TOKEN", "jobtoken"), ("ARK_CI_MODEL", "anthropic/test-model"), ("ARK_CI_BUDGET_USD", "3")]);
    assert!(o.status.success(), "{}", text(&o));
    let review = std::fs::read_to_string(f.repo.join(".ark-ci/review.md")).unwrap();
    assert!(review.contains("division by zero") && review.contains("REQUEST CHANGES"), "{review}");
    let args = f.read("args0");
    for want in ["run", "--quiet", "--workspace", "--budget-usd\n3", "--max-steps\n40", "--set\nrole.active=swdev", "--model\nanthropic/test-model"] {
        assert!(args.contains(want), "ark was started with {want:?}: {args}");
    }
    assert!(args.trim_end().ends_with('-'), "the prompt comes on stdin: {args}");
    let stdin = f.read("stdin0");
    assert!(stdin.contains("not instructions") && stdin.contains("=== DATA: unified diff (untrusted) ===") && stdin.contains("=== END DATA ==="), "{stdin}");
    assert!(stdin.contains("-    return sum(xs)\n+    return sum(xs) / len(xs)"), "the diff is in the prompt: {stdin}");
    assert!(stdin.contains("do not modify any file"));
    let env = f.read("env0");
    for secret in ["ghs_posting_token_123456", "glpat-posting-token", "jobtoken", "GITHUB_TOKEN", "GITLAB_TOKEN", "CI_JOB_TOKEN"] {
        assert!(!env.contains(secret), "the agent's environment must not carry {secret}");
    }
}

#[test]
fn a_huge_diff_is_cut_and_the_model_is_told() {
    let f = fixture("echo ok");
    std::fs::write(f.repo.join("big.txt"), "line of text\n".repeat(5000)).unwrap();
    git(&f.repo, &["add", "."]);
    git(&f.repo, &["commit", "-qm", "big"]);
    let o = f.run("review", &[("ARK_CI_MAX_DIFF_BYTES", "2000")]);
    assert!(o.status.success(), "{}", text(&o));
    let stdin = f.read("stdin0");
    assert!(stdin.contains("The diff was cut at 2000 of "), "{stdin}");
    assert!(stdin.len() < 12_000, "prompt is bounded: {}", stdin.len());
}

#[test]
fn an_empty_change_is_not_sent_to_the_model() {
    let f = fixture("echo should-not-run");
    let o = f.run("review", &[("ARK_CI_BASE", "feature")]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(f.read("args0").is_empty(), "ark was not started");
    assert!(std::fs::read_to_string(f.repo.join(".ark-ci/review.md")).unwrap().contains("No changes"));
}

#[test]
fn a_failing_agent_fails_the_job() {
    let f = fixture("echo boom >&2; exit 3");
    let o = f.run("review", &[]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("ark failed"));
}

#[test]
fn fix_tests_loops_until_green_and_leaves_a_patch_with_new_files() {
    // The first fix round does nothing useful, the second creates the file the tests need.
    let f = fixture("if [ -f round1 ]; then echo 'def helper(): pass' > helper.py; echo fixed; else touch round1; echo 'tried'; fi");
    let o = f.run("fix-tests", &[("ARK_CI_TEST_CMD", "test -f helper.py"), ("ARK_CI_FIX_ATTEMPTS", "3"), ("ARK_CI_ROLE", "devops")]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("tests pass after 2 fix round"), "{}", text(&o));
    let patch = std::fs::read_to_string(f.repo.join(".ark-ci/fix.patch")).unwrap();
    assert!(patch.contains("helper.py") && patch.contains("+def helper(): pass"), "new files are in the patch: {patch}");
    assert!(!patch.contains(".ark-ci"), "our own output is not in the patch");
    assert!(f.read("args1").contains("role.active=devops"));
    let stdin = f.read("stdin1");
    assert!(stdin.contains("Test command: test -f helper.py") && stdin.contains("Fix round: 2 of 3") && stdin.contains("do not delete or skip tests"), "{stdin}");
    assert!(stdin.contains("=== DATA: last 200 lines"), "the log is data");
}

#[test]
fn fix_tests_gives_up_after_the_attempts_and_passing_tests_need_no_agent() {
    let f = fixture("echo tried");
    let o = f.run("fix-tests", &[("ARK_CI_TEST_CMD", "false"), ("ARK_CI_FIX_ATTEMPTS", "2")]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("still failing after 2 fix round"));
    assert_eq!(std::fs::read_dir(&f.log).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with("args")).count(), 2, "exactly two agent runs");
    let g = fixture("echo no");
    let o = g.run("fix-tests", &[("ARK_CI_TEST_CMD", "true")]);
    assert!(o.status.success() && text(&o).contains("nothing to fix"), "{}", text(&o));
    assert!(g.read("args0").is_empty());
    assert_eq!(g.run("fix-tests", &[]).status.code(), Some(2), "a test command is required");
}

#[test]
fn run_mode_wraps_the_prompt_with_the_ci_rules() {
    let f = fixture("echo 'answer 42'");
    let o = f.run("run", &[("ARK_CI_PROMPT", "Summarise the open TODOs in this repository.")]);
    assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains("answer 42"), "{}", text(&o));
    let stdin = f.read("stdin0");
    assert!(stdin.contains("running unattended inside a CI job") && stdin.contains("Summarise the open TODOs"), "{stdin}");
}

#[test]
fn posting_uses_the_forge_api_with_the_token_and_marks_the_comment() {
    let f = fixture("echo ok");
    std::fs::create_dir_all(f.repo.join(".ark-ci")).unwrap();
    std::fs::write(f.repo.join(".ark-ci/review.md"), "Looks fine, one nit: \"quote\" and a `tick`.\n").unwrap();
    let o = f.run("post", &[("ARK_CI_PROVIDER", "github"), ("GITHUB_TOKEN", "ghs_posting_token_123456"), ("GITHUB_REPOSITORY", "acme/api"), ("GITHUB_REF", "refs/pull/17/merge")]);
    assert!(o.status.success(), "{}", text(&o));
    let a = f.read("curl-args");
    assert!(a.contains("https://api.github.com/repos/acme/api/issues/17/comments") && a.contains("Authorization: Bearer ghs_posting_token_123456") && a.contains("POST"), "{a}");
    let body: Value = serde_json::from_str(&f.read("curl-body")).unwrap();
    assert!(body["body"].as_str().unwrap().starts_with("<!-- ark-ci-review -->\n") && body["body"].as_str().unwrap().contains("\"quote\" and a `tick`"), "{body}");
    // GitLab, self-managed API base from the CI environment.
    let o = f.run("post", &[("ARK_CI_PROVIDER", "gitlab"), ("GITLAB_TOKEN", "glpat-xyz-1234"), ("CI_API_V4_URL", "https://git.corp.example/api/v4"), ("CI_PROJECT_ID", "42"), ("CI_MERGE_REQUEST_IID", "9")]);
    assert!(o.status.success(), "{}", text(&o));
    let a = f.read("curl-args");
    assert!(a.contains("https://git.corp.example/api/v4/projects/42/merge_requests/9/notes") && a.contains("PRIVATE-TOKEN: glpat-xyz-1234"), "{a}");
    // Not a pull request run, no token, nothing to post: refused before any request.
    std::fs::remove_file(f.log.join("curl-args")).unwrap();
    assert_eq!(f.run("post", &[("ARK_CI_PROVIDER", "github"), ("GITHUB_REPOSITORY", "a/b"), ("GITHUB_TOKEN", "x"), ("GITHUB_REF", "refs/heads/main")]).status.code(), Some(2));
    assert_eq!(f.run("post", &[("ARK_CI_PROVIDER", "gitlab")]).status.code(), Some(2));
    assert!(!f.log.join("curl-args").exists());
    assert_eq!(f.run("bogus", &[]).status.code(), Some(2));
}

// ───────────── the three CI files ─────────────

fn yaml(rel: &str) -> Value {
    let text = std::fs::read_to_string(root().join(rel)).unwrap();
    ark_skills::yaml::parse(&text).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn sh_n(code: &str) {
    let dir = TempDir::new("ark-run-ci");
    let f = dir.join("snippet.sh");
    std::fs::write(&f, code).unwrap();
    let o = Command::new("sh").arg("-n").arg(&f).output().unwrap();
    assert!(o.status.success(), "sh -n failed: {}\n{code}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn the_github_action_is_a_composite_action_that_calls_the_script() {
    let a = yaml("integrations/github-action/action.yml");
    assert_eq!(a["name"], "ark agent");
    assert_eq!(a["runs"]["using"], "composite");
    let inputs = a["inputs"].as_object().unwrap();
    for k in ["task", "prompt", "test-command", "fix-attempts", "post-comment", "github-token", "base-ref", "model", "role", "budget-usd", "extra-instructions", "ark-version", "ark-repo", "install"] {
        assert!(inputs.contains_key(k), "input {k}");
        assert!(inputs[k]["description"].as_str().is_some_and(|d| !d.is_empty()), "{k} is documented");
    }
    assert_eq!(inputs["task"]["default"], "review");
    assert_eq!(inputs["github-token"]["default"], "${{ github.token }}");
    assert!(a["outputs"]["result-file"]["value"].as_str().unwrap().contains("steps.run.outputs"));
    let steps = a["runs"]["steps"].as_array().unwrap();
    assert!(steps.len() >= 2);
    for s in steps {
        assert_eq!(s["shell"], "sh", "composite steps name their shell");
        sh_n(s["run"].as_str().unwrap());
    }
    let run = steps.iter().find(|s| s["id"] == "run").unwrap();
    let code = run["run"].as_str().unwrap();
    assert!(code.contains("ark-ci.sh") && code.contains("review") && code.contains("fix-tests"));
    // The token is handed to the posting step only, under another name; the script strips it for the agent.
    assert!(run["env"]["POST_TOKEN"].as_str().unwrap().contains("inputs.github-token"));
    assert!(!run["env"].as_object().unwrap().contains_key("GITHUB_TOKEN"));
    assert!(root().join("integrations/github-action/README.md").exists());
    // The relative path the action uses to reach the script exists in the repo.
    assert!(root().join("integrations/github-action/../ci/ark-ci.sh").exists());
}

#[test]
fn the_gitlab_template_defines_review_and_fix_jobs() {
    let g = yaml("integrations/gitlab-ci/ark.gitlab-ci.yml");
    for job in [".ark-base", "ark-review", "ark-fix-tests"] {
        assert!(g.get(job).is_some(), "{job}");
    }
    assert_eq!(g["ark-review"]["extends"], ".ark-base");
    assert!(g["ark-review"]["rules"][0]["if"].as_str().unwrap().contains("merge_request_event"));
    assert!(g["ark-review"]["rules"][0]["if"].as_str().unwrap().contains("CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID"), "forks are excluded");
    assert_eq!(g["ark-review"]["allow_failure"], true);
    assert_eq!(g["ark-fix-tests"]["rules"][0]["when"], "manual");
    for job in [".ark-base", "ark-review", "ark-fix-tests"] {
        for key in ["before_script", "script"] {
            for line in g[job].get(key).and_then(Value::as_array).into_iter().flatten() {
                sh_n(line.as_str().unwrap());
            }
        }
    }
    assert!(g["ark-review"]["script"].as_array().unwrap().iter().any(|l| l.as_str().unwrap().contains("review")));
    assert_eq!(g[".ark-base"]["variables"]["ARK_CI_PROVIDER"], "gitlab");
}

#[test]
fn the_jenkinsfile_is_a_balanced_pipeline_that_uses_the_script() {
    let j = std::fs::read_to_string(root().join("integrations/jenkins/Jenkinsfile")).unwrap();
    assert!(j.contains("pipeline {") && j.contains("stage('Review')") && j.contains("stage('Fix tests')") && j.contains("ark-ci.sh"));
    let (mut depth, mut max) = (0i32, 0i32);
    let (mut in_s, mut prev) = (None::<char>, ' ');
    let mut in_line_comment = false;
    for c in j.chars() {
        if c == '\n' {
            in_line_comment = false;
        }
        if in_line_comment {
            prev = c;
            continue;
        }
        match in_s {
            Some(q) => {
                if c == q && prev != '\\' {
                    in_s = None;
                }
            }
            None => match c {
                '\'' | '"' => in_s = Some(c),
                '/' if prev == '/' => in_line_comment = true,
                '{' => {
                    depth += 1;
                    max = max.max(depth)
                }
                '}' => depth -= 1,
                _ => {}
            },
        }
        prev = c;
    }
    assert_eq!(depth, 0, "braces are balanced");
    assert!(max >= 4);
    // Credentials come from Jenkins, never inline.
    assert!(j.contains("withCredentials") && !j.contains("sk-") && !j.contains("ghp_"));
    // The shell blocks inside sh ''' ... ''' parse.
    for chunk in j.split("'''").skip(1).step_by(2) {
        sh_n(chunk);
    }
}

#[test]
fn the_script_itself_is_valid_posix_sh_and_documented() {
    let o = Command::new("sh").arg("-n").arg(script()).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let t = std::fs::read_to_string(script()).unwrap();
    assert!(t.starts_with("#!/bin/sh") && t.contains("set -eu"));
    let help = Command::new("sh").arg(script()).arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("ark-ci.sh review"));
}
