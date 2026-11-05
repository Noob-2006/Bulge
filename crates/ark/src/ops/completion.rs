//! Shell completion scripts (Hermes `completion`, OpenClaw `completion`): bash, zsh and
//! fish, generated from the real command tree (built-ins, ops commands, subcommands,
//! global flags) plus plugin CLI commands found in the config.

use crate::args::Args;
use crate::{usage, R};

pub const COMMANDS: &[&str] = &["completion", "completions"];
pub const VALUE_FLAGS: &[&str] = &[];
pub const BOOL_FLAGS: &[&str] = &[];

/// Subcommands per top-level command.
pub const SUBS: &[(&str, &[&str])] = &[
    ("session", &["list", "show", "resume", "fork", "search", "export", "compact", "model", "rm"]),
    ("daemon", &["start", "stop", "status", "run", "install"]),
    ("gate", &["list", "answer"]),
    ("schedule", &["add", "list", "rm", "enable", "disable", "run"]),
    ("goal", &["add", "list", "show", "run", "pause", "resume", "cancel"]),
    ("memory", &["show", "add", "review", "accept", "reject"]),
    ("index", &["status", "sync", "rebuild", "bench"]),
    ("checkpoint", &["list", "restore"]),
    ("config", &["path", "show", "init", "get", "set", "unset", "edit", "patch", "schema", "file", "env-path", "check", "migrate", "backups", "restore", "validate"]),
    ("secrets", &["set", "list", "rm", "sources", "test", "import"]),
    ("providers", &["list", "check"]),
    ("mcp", &["list", "tools", "test", "refresh", "add", "rm", "serve", "login", "logout"]),
    ("channel", &["list", "send"]),
    ("webhook", &["list", "subscribe", "rm"]),
    ("nodes", &["list", "pending", "approve", "reject", "remove", "rename", "describe", "invoke", "queue", "events", "rotate", "wake", "setup-code"]),
    ("app", &["status", "token", "open"]),
    ("pairing", &["list", "approve", "revoke"]),
    ("service", &["install", "uninstall", "status", "print", "restart", "logs", "audit"]),
    ("data", &["export", "delete"]),
    ("profile", &["list", "current", "use", "create", "delete", "describe", "show", "alias", "rename", "export", "import", "install", "update"]),
    ("backup", &["create", "verify", "restore", "list", "prune", "schedule"]),
    ("snapshot", &["create", "list", "restore"]),
    ("migrate", &["from", "detect", "retired-models"]),
    ("claw", &["migrate", "cleanup"]),
    ("completion", &["bash", "zsh", "fish"]),
    ("slack", &["manifest"]),
    ("logs", &["tail"]),
    ("telemetry", &["status", "test"]),
    ("monitoring", &["status"]),
    ("worktree", &["list", "add", "rm", "prune", "restore"]),
    ("batch", &["run", "status", "stats"]),
    ("eval", &["run", "list", "compare"]),
    ("lsp", &["status", "list", "install", "which", "restart", "check"]),
    ("debug", &["share", "delete", "list"]),
    ("hooks", &["list", "test", "doctor"]),
    ("skin", &["list", "use", "set", "show"]),
    ("pets", &["list", "show", "hatch", "adopt", "feed"]),
    ("system", &["events", "heartbeat", "presence"]),
    ("kanban", &["init", "boards", "create", "list", "show", "assign", "reclaim", "diagnostics", "link", "unlink", "comment", "complete", "edit", "block", "unblock", "archive", "move", "dispatch", "stats", "log", "context", "assignees", "specify", "decompose", "board"]),
    ("meet", &["join", "status", "transcript", "say", "stop", "setup", "auth"]),
    ("teams", &["list", "show", "run", "fetch", "subscriptions", "subscribe", "renew-subscription", "delete-subscription", "maintain-subscriptions", "token-health", "validate"]),
    ("sandbox", &["list", "recreate", "explain"]),
    ("suggestions", &["accept", "dismiss", "catalog", "clear"]),
    ("web", &["providers", "test", "fetch"]),
    ("project", &["create", "list", "show", "add-folder", "remove-folder", "rm", "use"]),
];

const GLOBAL_FLAGS: &[&str] = &["--model", "--workspace", "--session", "--set", "--budget-tokens", "--budget-usd", "--max-steps", "--yes", "--allow-privilege", "--allow-egress", "--json", "--quiet", "--profile", "--help"];

/// Commands `wire::owns` dispatches before main.rs's own argument parser: they are not in
/// `BUILTINS`, but a user types them like any other command, so they complete the same way.
const EARLY_COMMANDS: &[&str] = &["sandbox", "suggestions", "system"];

pub fn commands() -> Vec<String> {
    let mut v: Vec<String> = crate::BUILTINS.iter().filter(|c| !c.starts_with('-')).map(|s| s.to_string()).collect();
    v.extend(EARLY_COMMANDS.iter().map(|s| s.to_string()));
    for (names, ..) in crate::ops::modules() {
        v.extend(names.iter().map(|s| s.to_string()));
    }
    // Plugin CLI commands from the active config (best effort, no plugin start-up cost when none).
    let paths = ark_kernel::config::Paths::from_env();
    if let Ok(cfg) = ark_kernel::config::Config::load(Some(&paths.user_config()), None, &[]) {
        for (name, t) in &cfg.plugins {
            if let Some(cli) = t.get("cli").and_then(|c| c.as_array()) {
                v.extend(cli.iter().filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(String::from)));
            }
            let _ = name;
        }
    }
    v.sort();
    v.dedup();
    v
}

fn subs(cmd: &str) -> &'static [&'static str] {
    let canon = match cmd {
        "sessions" => "session",
        "gates" => "gate",
        "cron" => "schedule",
        "goals" => "goal",
        "checkpoints" | "undo" => "checkpoint",
        "secret" => "secrets",
        "models" => "providers",
        "connector" | "connectors" => "mcp",
        "channels" => "channel",
        "webhooks" => "webhook",
        "pair" => "pairing",
        "profiles" => "profile",
        "backups" => "backup",
        "completions" => "completion",
        c => c,
    };
    SUBS.iter().find(|(c, _)| *c == canon).map(|(_, s)| *s).unwrap_or(&[])
}

pub fn bash() -> String {
    let cmds = commands();
    let mut cases = String::new();
    for c in &cmds {
        let s = subs(c);
        if !s.is_empty() {
            cases.push_str(&format!("    {c}) subs=\"{}\" ;;\n", s.join(" ")));
        }
    }
    format!(
        "# ark bash completion — eval \"$(ark completion bash)\" or save to /etc/bash_completion.d/ark\n_ark() {{\n  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\" cmd=\"\" i\n  for ((i=1; i<COMP_CWORD; i++)); do\n    case \"${{COMP_WORDS[i]}}\" in -p|--profile|-m|--model|-w|--workspace|-s|--session|--set) ((i++)) ;; -*) ;; *) cmd=\"${{COMP_WORDS[i]}}\"; break ;; esac\n  done\n  if [[ \"$cur\" == -* ]]; then COMPREPLY=($(compgen -W \"{flags}\" -- \"$cur\")); return; fi\n  if [[ \"${{COMP_WORDS[COMP_CWORD-1]}}\" == -p || \"${{COMP_WORDS[COMP_CWORD-1]}}\" == --profile ]]; then\n    COMPREPLY=($(compgen -W \"$(ark profile list 2>/dev/null | sed 's/^[* ] //' | cut -d' ' -f1)\" -- \"$cur\")); return\n  fi\n  if [[ -z \"$cmd\" ]]; then COMPREPLY=($(compgen -W \"{cmds}\" -- \"$cur\")); return; fi\n  local subs=\"\"\n  case \"$cmd\" in\n{cases}  esac\n  [[ $((COMP_CWORD - i)) -eq 1 && -n \"$subs\" ]] && COMPREPLY=($(compgen -W \"$subs\" -- \"$cur\"))\n}}\ncomplete -o default -F _ark ark\n",
        flags = GLOBAL_FLAGS.join(" "),
        cmds = cmds.join(" ")
    )
}

pub fn zsh() -> String {
    let cmds = commands();
    let mut cases = String::new();
    for c in &cmds {
        let s = subs(c);
        if !s.is_empty() {
            cases.push_str(&format!("      {c}) _values 'subcommand' {} ;;\n", s.iter().map(|x| format!("'{x}'")).collect::<Vec<_>>().join(" ")));
        }
    }
    format!(
        "#compdef ark\n# ark zsh completion — save as _ark in a directory on $fpath, or: source <(ark completion zsh)\n_ark() {{\n  local -a cmds\n  cmds=({cmds})\n  _arguments -C \\\n    '(-p --profile)'{{-p,--profile}}'[profile]:profile:->profiles' \\\n    '(-m --model)'{{-m,--model}}'[provider/model]:model:' \\\n    '(-w --workspace)'{{-w,--workspace}}'[workspace]:dir:_files -/' \\\n    '--json[JSON output]' '--yes[approve prompts]' '(-q --quiet)'{{-q,--quiet}}'[quiet]' \\\n    '1:command:->cmd' '2:subcommand:->sub' '*::arg:_files'\n  case $state in\n    profiles) _values 'profile' ${{(f)\"$(ark profile list 2>/dev/null | sed 's/^[* ] //' | cut -d' ' -f1)\"}} ;;\n    cmd) _describe 'command' cmds ;;\n    sub) case $words[2] in\n{cases}    esac ;;\n  esac\n}}\ncompdef _ark ark 2>/dev/null || true\n",
        cmds = cmds.join(" ")
    )
}

pub fn fish() -> String {
    let cmds = commands();
    let mut o = String::from("# ark fish completion — ark completion fish > ~/.config/fish/completions/ark.fish\ncomplete -c ark -f\n");
    o.push_str("complete -c ark -s p -l profile -x -a '(ark profile list 2>/dev/null | string replace -r \"^[* ] \" \"\" | string split -f1 \" \")' -d profile\n");
    o.push_str("complete -c ark -s m -l model -x -d provider/model\ncomplete -c ark -s w -l workspace -r -d workspace\ncomplete -c ark -l json -d 'JSON output'\ncomplete -c ark -l yes -d 'approve prompts'\n");
    o.push_str(&format!("complete -c ark -n __fish_use_subcommand -a '{}'\n", cmds.join(" ")));
    for c in &cmds {
        let s = subs(c);
        if !s.is_empty() {
            o.push_str(&format!("complete -c ark -n '__fish_seen_subcommand_from {c}' -a '{}'\n", s.join(" ")));
        }
    }
    o
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some(match a.pos(0) {
        Some("bash") => {
            print!("{}", bash());
            Ok(0)
        }
        Some("zsh") => {
            print!("{}", zsh());
            Ok(0)
        }
        Some("fish") => {
            print!("{}", fish());
            Ok(0)
        }
        Some("install") => {
            let shell = std::env::var("SHELL").unwrap_or_default();
            let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
            let (path, body) = if shell.ends_with("fish") {
                (home.join(".config/fish/completions/ark.fish"), fish())
            } else if shell.ends_with("zsh") {
                (home.join(".zfunc/_ark"), zsh())
            } else {
                (home.join(".local/share/bash-completion/completions/ark"), bash())
            };
            if let Some(d) = path.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            match std::fs::write(&path, body) {
                Ok(()) => {
                    println!("wrote {}{}", path.display(), if shell.ends_with("zsh") { "\nadd to ~/.zshrc (before compinit): fpath=(~/.zfunc $fpath)" } else { "" });
                    Ok(0)
                }
                Err(e) => Err(format!("{}: {e}", path.display()).into()),
            }
        }
        _ => usage("usage: ark completion bash|zsh|fish|install"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_cover_the_tree() {
        let b = bash();
        assert!(b.contains("complete -o default -F _ark ark") && b.contains("profile) subs=\"list current use") && b.contains(" backup "));
        assert!(zsh().starts_with("#compdef ark") && zsh().contains("'restore'"));
        let f = fish();
        assert!(f.contains("__fish_seen_subcommand_from config' -a 'path show init get set"));
        assert!(commands().iter().any(|c| c == "migrate") && commands().iter().any(|c| c == "run"));
        // g4 commands reach the word lists: kanban/worktree/meet/teams/sandbox/suggestions/web
        // (sandbox & suggestions are `wire::owns` commands, so they need EARLY_COMMANDS).
        for c in ["kanban", "worktree", "meet", "teams", "sandbox", "suggestions", "system", "web"] {
            assert!(commands().iter().any(|x| x == c), "missing command {c}");
            assert!(!subs(c).is_empty(), "missing subcommands for {c}");
        }
        assert!(b.contains(" kanban ") && b.contains("sandbox) subs=\"list recreate explain\"") && b.contains(" web) subs=\"providers test fetch\""), "{b}");
        assert!(fish().contains("__fish_seen_subcommand_from kanban' -a 'init boards create"), "fish: subcommands for kanban");
        if std::process::Command::new("bash").arg("--version").output().is_ok() {
            let d = std::env::temp_dir().join(format!("ark-comp-{}.sh", ark_kernel::util::random_hex(4)));
            std::fs::write(&d, &b).unwrap();
            let o = std::process::Command::new("bash").arg("-n").arg(&d).output().unwrap();
            assert!(o.status.success(), "bash syntax: {}", String::from_utf8_lossy(&o.stderr));
        }
    }
}
