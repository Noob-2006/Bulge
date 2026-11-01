//! Durable semantic memory: MEMORY.md (agent notes) and USER.md (user profile).
//! Entries are separated by "\n§\n" and each file has a character budget so the
//! frozen snapshot in the system prompt stays small.

use crate::util::{atomic_write, io_err};
use ark_core::tool::{arg_opt_str, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const SEP: &str = "\n§\n";
pub const CHAR_CAP: usize = 4000;

fn file_of(ctx: &ToolCtx, input: &Value) -> Result<PathBuf, String> {
    let name = match arg_opt_str(input, "file").unwrap_or("memory") {
        "memory" => "MEMORY.md",
        "user" => "USER.md",
        other => return Err(format!("unknown file `{other}`; use `memory` or `user`")),
    };
    Ok(ctx.home.join("memory").join(name))
}

fn load(p: &Path) -> Result<Vec<String>, String> {
    match fs::read_to_string(p) {
        Ok(t) => Ok(t.split(SEP).map(|e| e.trim().to_string()).filter(|e| !e.is_empty()).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(io_err("read memory", p, &e)),
    }
}

fn store(p: &Path, entries: &[String]) -> Result<usize, String> {
    let text = entries.join(SEP);
    let n = text.chars().count();
    if n > CHAR_CAP {
        return Err(format!(
            "memory file would be {n} chars, over the {CHAR_CAP} cap; consolidate or remove entries first"
        ));
    }
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| io_err("create", d, &e))?;
    }
    atomic_write(p, text.as_bytes()).map_err(|e| io_err("write memory", p, &e))?;
    Ok(n)
}

fn find_one(entries: &[String], needle: &str) -> Result<usize, String> {
    if needle.trim().is_empty() {
        return Err("`old` must not be empty".into());
    }
    let hits: Vec<usize> = entries.iter().enumerate().filter(|(_, e)| e.contains(needle)).map(|(i, _)| i).collect();
    match hits.len() {
        0 => Err(format!("no entry contains `{needle}`; use action=read to see entries")),
        1 => Ok(hits[0]),
        n => Err(format!("{n} entries contain `{needle}`; use a longer, unique substring")),
    }
}

pub struct Memory;

impl Tool for Memory {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "memory".into(),
            description: "Persistent memory across sessions. file=memory for your notes, file=user for facts about the user. Actions: read, add, replace (old→text), remove (old).".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["read","add","replace","remove"]},
                "file":{"type":"string","enum":["memory","user"],"default":"memory"},
                "text":{"type":"string"},
                "old":{"type":"string","description":"Unique substring of the entry to replace/remove"}},
                "required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut input = input.clone();
        actions(&mut input);
        let input = &input;
        let Ok(path) = file_of(ctx, input) else { return vec![] };
        match arg_opt_str(input, "action") {
            Some("read") => vec![Effect::Read { path }],
            Some(_) => vec![Effect::Write { path }],
            None => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::alias(&mut input, "text", &["content", "value", "note", "entry"]);
        actions(&mut input);
        let run = || -> Result<String, String> {
            let action = arg_str(&input, "action")?;
            let p = file_of(ctx, &input)?;
            let mut entries = load(&p)?;
            let text = || -> Result<String, String> {
                let t = arg_str(&input, "text")?.trim().to_string();
                if t.is_empty() {
                    return Err("`text` must not be empty".into());
                }
                if t.contains('§') {
                    return Err("`text` must not contain the § separator".into());
                }
                Ok(t)
            };
            match action {
                "read" => Ok(if entries.is_empty() { "(no entries)".into() } else { entries.join(SEP) }),
                "add" => {
                    let t = text()?;
                    if entries.contains(&t) {
                        return Ok("already present; nothing added".into());
                    }
                    entries.push(t);
                    let n = store(&p, &entries)?;
                    Ok(format!("added ({} entries, {n}/{CHAR_CAP} chars)", entries.len()))
                }
                "replace" => {
                    let i = find_one(&entries, arg_str(&input, "old")?)?;
                    entries[i] = text()?;
                    let n = store(&p, &entries)?;
                    Ok(format!("replaced ({n}/{CHAR_CAP} chars)"))
                }
                "remove" => {
                    let i = find_one(&entries, arg_str(&input, "old")?)?;
                    entries.remove(i);
                    let n = store(&p, &entries)?;
                    Ok(format!("removed ({} entries left, {n}/{CHAR_CAP} chars)", entries.len()))
                }
                other => Err(format!("unknown action `{other}`; use read, add, replace or remove")),
            }
        };
        match run() {
            Ok(s) => ToolOutput::ok(s),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn actions(input: &mut Value) {
    // Memory has no `command` argument of its own, so it can stand in for `action` here.
    crate::util::rename(input, "action", &["command"]);
    crate::util::action_synonyms(input, &[
        ("create", "add"), ("new", "add"), ("save", "add"), ("write", "add"), ("set", "add"), ("append", "add"),
        ("update", "replace"), ("edit", "replace"),
        ("delete", "remove"), ("forget", "remove"),
        ("get", "read"), ("list", "read"), ("show", "read"), ("view", "read"),
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lifecycle() {
        let c = ctx("mem");
        assert_eq!(Memory.call(&c, json!({"action":"read"})).content, "(no entries)");
        assert!(!Memory.call(&c, json!({"action":"add","text":"prefers Rust"})).is_error);
        assert!(!Memory.call(&c, json!({"action":"add","text":"uses Linux"})).is_error);
        assert!(Memory.call(&c, json!({"action":"add","text":"uses Linux"})).content.contains("already"));
        assert!(!Memory.call(&c, json!({"action":"replace","old":"Rust","text":"prefers Rust, minimal deps"})).is_error);
        assert!(!Memory.call(&c, json!({"action":"remove","old":"Linux"})).is_error);
        assert_eq!(Memory.call(&c, json!({"action":"read"})).content, "prefers Rust, minimal deps");
        Memory.call(&c, json!({"action":"add","file":"user","text":"lives in Taiwan"}));
        assert!(fs::read_to_string(c.home.join("memory/USER.md")).unwrap().contains("Taiwan"));
        assert!(!fs::read_to_string(c.home.join("memory/MEMORY.md")).unwrap().contains("Taiwan"));
    }

    #[test]
    fn failures() {
        let c = ctx("memf");
        assert!(Memory.call(&c, json!({})).is_error);
        assert!(Memory.call(&c, json!({"action":"frobnicate"})).content.contains("unknown action"));
        // Seen with Haiku: `create` + `value`, and `operation` instead of `action`.
        assert!(!Memory.call(&c, json!({"action":"create","key":"k","value":"uses unittest"})).is_error);
        assert!(Memory.call(&c, json!({"operation":"get"})).content.contains("uses unittest"));
        assert!(!Memory.call(&c, json!({"command":"add","value":"tests in tests/"})).is_error);
        assert!(Memory.call(&c, json!({"action":"read","file":"secrets"})).content.contains("unknown file"));
        assert!(Memory.call(&c, json!({"action":"add"})).is_error);
        assert!(Memory.call(&c, json!({"action":"add","text":"   "})).is_error);
        assert!(!Memory.call(&c, json!({"action":"add","key":"k","value":"via alias"})).is_error);
        assert!(Memory.call(&c, json!({"action":"read"})).content.contains("via alias"));
        assert!(Memory.call(&c, json!({"action":"add","text":"a § b"})).is_error);
        let o = Memory.call(&c, json!({"action":"remove","old":"nothing"}));
        assert!(o.is_error && o.content.contains("no entry"));
        Memory.call(&c, json!({"action":"add","text":"note one"}));
        Memory.call(&c, json!({"action":"add","text":"note two"}));
        let o = Memory.call(&c, json!({"action":"remove","old":"note"}));
        assert!(o.is_error && o.content.contains("2 entries"));
        assert!(Memory.call(&c, json!({"action":"remove","old":""})).is_error);
        assert!(Memory.call(&c, json!({"action":"replace","old":"one"})).is_error, "missing text");
    }

    #[test]
    fn cap_is_enforced_and_file_untouched() {
        let c = ctx("memcap");
        Memory.call(&c, json!({"action":"add","text":"x".repeat(3000)}));
        let o = Memory.call(&c, json!({"action":"add","text":"y".repeat(1500)}));
        assert!(o.is_error && o.content.contains("cap"), "{}", o.content);
        assert_eq!(Memory.call(&c, json!({"action":"read"})).content.len(), 3000);
    }

    #[test]
    fn unreadable_memory_file() {
        let c = ctx("memperm");
        Memory.call(&c, json!({"action":"add","text":"a"}));
        let p = c.home.join("memory/MEMORY.md");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        let o = Memory.call(&c, json!({"action":"read"}));
        assert!(o.is_error && o.content.contains("permission denied"));
    }

    #[test]
    fn effects() {
        let c = ctx("memeff");
        assert!(matches!(&Memory.effects(&c, &json!({"action":"read"}))[..], [Effect::Read { .. }]));
        assert!(matches!(&Memory.effects(&c, &json!({"action":"add","file":"user"}))[..], [Effect::Write { path }] if path.ends_with("USER.md")));
        assert!(Memory.effects(&c, &json!({"action":"add","file":"bad"})).is_empty());
    }
}
