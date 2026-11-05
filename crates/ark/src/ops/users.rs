//! `ark users` (OpenClaw `openclaw users`): durable user profiles and their email /
//! channel identities, over the registry in `ark_kernel::agents` (`<data>/users.json`).
//!
//! `list [--json]`, `add <name>`, `link-email <email> --to <id>`, `link <channel> <sender>
//! --to <id>`, `merge <source> --into <target>`, `instructions <id> <text…>`, `rm <id>`,
//! `whois <channel> <sender>`. Output is terminal-sanitised (control characters dropped).

use crate::args::Args;
use crate::R;
use ark_kernel::agents::{self, User};
use ark_kernel::config::Paths;

pub const COMMANDS: &[&str] = &["users", "user"];
pub const VALUE_FLAGS: &[&str] = &["to", "into"];
pub const BOOL_FLAGS: &[&str] = &[];

/// Drop control characters (OpenClaw `sanitizeTerminalText`): names come from chats.
pub fn safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

pub fn line(u: &User) -> String {
    let mut l = format!("{}\t{}\t{}", safe(&u.id), safe(&u.name), safe(&u.emails.join(",")));
    if !u.role.is_empty() || !u.team.is_empty() || u.disabled {
        l.push_str(&format!("\trole={}\tteam={}{}", if u.role.is_empty() { "-" } else { &u.role }, if u.team.is_empty() { "-" } else { &u.team }, if u.disabled { "\tdisabled" } else { "" }));
    }
    l
}

fn audit(p: &Paths, kind: &str, target: &str, detail: &serde_json::Value) {
    ark_security::audit::record(&p.data, ark_security::audit::Event::new(kind, ark_security::audit::Actor::local(), target, "ok").detail(detail.clone()));
}

fn show(us: &[User], json: bool) -> String {
    if json {
        serde_json::to_string_pretty(&serde_json::json!({"profiles": us})).unwrap_or_default()
    } else if us.is_empty() {
        "No user profiles found.".into()
    } else {
        us.iter().map(line).collect::<Vec<_>>().join("\n")
    }
}

/// One `ark users …` invocation → its output.
pub fn run(p: &Paths, a: &Args) -> Result<String, String> {
    let _ = std::fs::create_dir_all(&p.data);
    let js = a.flag("json");
    let to = || a.val("to").ok_or_else(|| "--to <profileId> is required".to_string());
    Ok(match a.pos(0).unwrap_or("list") {
        "list" | "ls" => show(&agents::users(p), js),
        "add" | "create" => show(&[agents::user_add(p, &a.rest(1))?], js),
        "link-email" => show(&[agents::user_link_email(p, to()?, a.need(1, "email")?)?], js),
        "link" => show(&[agents::user_link(p, to()?, a.need(1, "channel")?, a.need(2, "sender")?)?], js),
        "instructions" => show(&[agents::user_set_instructions(p, a.need(1, "id")?, &a.rest(2))?], js),
        // ent-060: the registry is also who may log in and what they may do.
        "role" => {
            let role = a.need(2, "role")?.to_string();
            if role != "-" {
                ark_app::identity::Role::parse(&role)?;
            }
            let u = agents::user_update(p, a.need(1, "id")?, |u| {
                u.role = if role == "-" { String::new() } else { role.clone() };
                Ok(())
            })?;
            audit(p, "user.role", &u.name, &serde_json::json!({"role": u.role}));
            show(&[u], js)
        }
        "team" => {
            let team = a.rest(2);
            let u = agents::user_update(p, a.need(1, "id")?, |u| {
                u.team = if team.trim() == "-" { String::new() } else { team.trim().to_string() };
                Ok(())
            })?;
            audit(p, "user.team", &u.name, &serde_json::json!({"team": u.team}));
            show(&[u], js)
        }
        "disable" | "enable" => {
            let off = a.pos(0) == Some("disable");
            let u = agents::user_update(p, a.need(1, "id")?, |u| {
                u.disabled = off;
                Ok(())
            })?;
            audit(p, if off { "user.disable" } else { "user.enable" }, &u.name, &serde_json::Value::Null);
            show(&[u], js)
        }
        // Bind an SSO subject (`sub` claim) to a profile; logins then resolve to it.
        "link-oidc" => {
            let u = agents::user_link(p, to()?, "oidc", a.need(1, "subject")?)?;
            audit(p, "user.link", &u.name, &serde_json::json!({"oidc": a.pos(1)}));
            show(&[u], js)
        }
        "merge" => {
            let src = a.need(1, "sourceProfileId")?;
            let into = a.val("into").ok_or("--into <targetProfileId> is required")?;
            let u = agents::user_merge(p, src, into)?;
            if js {
                serde_json::json!({"profile": u, "retired": src}).to_string()
            } else {
                format!("Survivor: {}\nRetired profile: {}\nHistory keeps its original attribution; logins, links, and accounts follow the survivor.", safe(&u.id), safe(src))
            }
        }
        "rm" | "remove" => {
            agents::user_remove(p, a.need(1, "id")?)?;
            "removed".into()
        }
        "whois" => match agents::find_user(p, a.need(1, "channel")?, a.need(2, "sender")?) {
            Some(u) => show(&[u], js),
            None => return Err("no user profile has that identity".into()),
        },
        other => return Err(format!("unknown `users {other}` (list | add <name> | link-email <email> --to <id> | link <channel> <sender> --to <id> | link-oidc <subject> --to <id> | role <id> <admin|operator|user|auditor|-> | team <id> <team|-> | disable <id> | enable <id> | merge <source> --into <target> | instructions <id> <text> | rm <id> | whois <channel> <sender>)")),
    })
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some(run(&Paths::from_env(), a).map(|o| {
        println!("{o}");
        0
    }).map_err(Into::into))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_sanitised() {
        let u = User { id: "u-1".into(), name: "Eve\x1b[2J\u{7}".into(), emails: vec!["a@x".into(), "b@x".into()], ..Default::default() };
        assert_eq!(line(&u), "u-1\tEve[2J\ta@x,b@x");
        let kit = crate::testkit::kit();
        let p = &kit.paths;
        let r = |v: &[&str]| run(p, &Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap());
        assert_eq!(r(&["list"]).unwrap(), "No user profiles found.");
        r(&["add", "Ann"]).unwrap();
        r(&["add", "Ann", "dup"]).unwrap();
        let us = agents::users(p);
        let (a, b) = (us[0].id.clone(), us[1].id.clone());
        assert!(r(&["link-email", "ann@x.org"]).unwrap_err().contains("--to"));
        assert!(r(&["link-email", "ann@x.org", "--to", &b]).unwrap().contains("ann@x.org"));
        r(&["link", "telegram", "42", "--to", &b]).unwrap();
        let m = r(&["merge", &b, "--into", &a]).unwrap();
        assert!(m.starts_with(&format!("Survivor: {a}")) && m.contains(&format!("Retired profile: {b}")));
        assert!(r(&["whois", "telegram", "42"]).unwrap().starts_with(&a));
        assert!(r(&["list", "--json"]).unwrap().contains("\"profiles\""));
        // ent-060: role, team, disable and an SSO subject on the same profile.
        assert!(r(&["role", &a, "root"]).is_err());
        assert!(r(&["role", &a, "auditor"]).unwrap().contains("role=auditor"));
        assert!(r(&["team", &a, "eng"]).unwrap().contains("team=eng"));
        r(&["link-oidc", "sub-123", "--to", &a]).unwrap();
        assert_eq!(agents::find_login(p, "sub-123", "").unwrap().id, a);
        assert!(r(&["disable", &a]).unwrap().contains("disabled"));
        assert!(ark_app::identity::channel_permits(p, "telegram", "42", false).unwrap_err().contains("disabled"));
        assert!(r(&["enable", &a]).unwrap().contains("role=auditor"));
        assert!(ark_app::identity::channel_permits(p, "telegram", "42", true).is_err(), "auditors do not approve from chat");
        assert!(ark_security::audit::all(&p.data).iter().any(|e| e["kind"] == "user.role"));
        assert!(r(&["bogus"]).is_err());
    }

    /// `ark users …` reaches this module through `ops::MODULES`; other names fall through.
    #[test]
    fn dispatch_is_wired() {
        let me: fn(&str, &Args, &[String]) -> Option<R> = dispatch;
        assert!(crate::ops::modules().iter().any(|m| m.0 == COMMANDS && m.3 as usize == me as usize), "users::dispatch is registered in ops::MODULES");
        let a = Args::parse(&[]).unwrap();
        assert!(dispatch("storage", &a, &[]).is_none() && dispatch("project", &a, &[]).is_none());
    }
}
