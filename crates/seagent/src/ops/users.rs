//! `seagent users` (OpenClaw `openclaw users`): durable user profiles and their email /
//! channel identities, over the registry in `seagent_kernel::agents` (`<data>/users.json`).
//!
//! `list [--json]`, `add <name>`, `link-email <email> --to <id>`, `link <channel> <sender>
//! --to <id>`, `merge <source> --into <target>`, `instructions <id> <text…>`, `rm <id>`,
//! `whois <channel> <sender>`. Output is terminal-sanitised (control characters dropped).

use crate::args::Args;
use crate::R;
use seagent_kernel::agents::{self, User};
use seagent_kernel::config::Paths;

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
    seagent_security::audit::record(&p.data, seagent_security::audit::Event::new(kind, seagent_security::audit::Actor::local(), target, "ok").detail(detail.clone()));
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

/// One `seagent users …` invocation → its output.
pub fn run(p: &Paths, a: &Args) -> Result<String, String> {
    let _ = std::fs::create_dir_all(&p.data);
    let js = a.flag("json");
    let to = || a.val("to").ok_or_else(|| "--to <profileId> is required".to_string());
    Ok(match a.pos(0).unwrap_or("list") {
        "list" | "ls" => show(&agents::users(p), js),
        // Every registry change is audited: an identity link decides who a login or a chat
        // sender *is* (roles, dual control's "same person" check, quotas).
        "add" | "create" => {
            let u = agents::user_add(p, &a.rest(1))?;
            audit(p, "user.add", &u.name, &serde_json::json!({"id": u.id}));
            show(&[u], js)
        }
        "link-email" => {
            let u = agents::user_link_email(p, to()?, a.need(1, "email")?)?;
            audit(p, "user.link", &u.name, &serde_json::json!({"email": a.pos(1)}));
            show(&[u], js)
        }
        "link" => {
            let u = agents::user_link(p, to()?, a.need(1, "channel")?, a.need(2, "sender")?)?;
            audit(p, "user.link", &u.name, &serde_json::json!({"channel": a.pos(1), "sender": a.pos(2)}));
            show(&[u], js)
        }
        "instructions" => {
            let u = agents::user_set_instructions(p, a.need(1, "id")?, &a.rest(2))?;
            audit(p, "user.instructions", &u.name, &serde_json::Value::Null);
            show(&[u], js)
        }
        // ent-060: the registry is also who may log in and what they may do.
        "role" => {
            let role = a.need(2, "role")?.to_string();
            if role != "-" {
                seagent_app::identity::Role::parse(&role)?;
            }
            let u = agents::user_update(p, a.need(1, "id")?, |u| {
                u.role = if role == "-" { String::new() } else { role.clone() };
                Ok(())
            })?;
            audit(p, "user.role", &u.name, &serde_json::json!({"role": u.role}));
            show(&[u], js)
        }
        // ent-050: organization (`*` with the admin role = global administrator).
        "org" => {
            let org = a.need(2, "org")?.trim().to_string();
            let u = agents::user_update(p, a.need(1, "id")?, |u| {
                u.org = if org == "-" { String::new() } else { org.clone() };
                Ok(())
            })?;
            audit(p, "user.org", &u.name, &serde_json::json!({"org": u.org}));
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
            if off {
                revoke_running(p, &u);
            }
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
            audit(p, "user.merge", &u.name, &serde_json::json!({"retired": src, "into": u.id}));
            if js {
                serde_json::json!({"profile": u, "retired": src}).to_string()
            } else {
                format!("Survivor: {}\nRetired profile: {}\nHistory keeps its original attribution; logins, links, and accounts follow the survivor.", safe(&u.id), safe(src))
            }
        }
        "rm" | "remove" => {
            agents::user_remove(p, a.need(1, "id")?)?;
            audit(p, "user.remove", a.need(1, "id")?, &serde_json::Value::Null);
            "removed".into()
        }
        "whois" => match agents::find_user(p, a.need(1, "channel")?, a.need(2, "sender")?) {
            Some(u) => show(&[u], js),
            None => return Err("no user profile has that identity".into()),
        },
        other => return Err(format!("unknown `users {other}` (list | add <name> | link-email <email> --to <id> | link <channel> <sender> --to <id> | link-oidc <subject> --to <id> | role <id> <admin|operator|user|auditor|-> | org <id> <org|*|-> | team <id> <team|-> | disable <id> | enable <id> | merge <source> --into <target> | instructions <id> <text> | rm <id> | whois <channel> <sender>)")),
    })
}

/// ent-049: a disabled user's running turns stop now. Logins, personal tokens, open sockets and
/// chat identities already re-check the registry on use; running turns are interrupted through
/// the daemon (when one is up — otherwise nothing is running).
fn revoke_running(p: &Paths, u: &User) {
    let sock = p.socket();
    let Ok(ping) = seagent_kernel::daemon::call(&sock, "ping", serde_json::json!({})) else { return };
    let running: Vec<String> = ping["running"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let store = seagent_kernel::store::Store::new(p.sessions());
    for sid in seagent_kernel::governance::sessions_of_user(p, &store, &running, u) {
        let _ = seagent_kernel::daemon::call(&sock, "session.interrupt", serde_json::json!({"id": sid}));
    }
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
        assert!(seagent_app::identity::channel_permits(p, "telegram", "42", false).unwrap_err().contains("disabled"));
        assert!(r(&["enable", &a]).unwrap().contains("role=auditor"));
        assert!(seagent_app::identity::channel_permits(p, "telegram", "42", true).is_err(), "auditors do not approve from chat");
        assert!(seagent_security::audit::all(&p.data).iter().any(|e| e["kind"] == "user.role"));
        assert!(r(&["bogus"]).is_err());
    }

    /// Audit coverage for the admin CLI: every `seagent users` / `seagent tenancy` / `seagent accounts`
    /// subcommand named in its usage text is either read-only (listed with a reason) or leaves
    /// an audit record of the expected kind. A new subcommand that is in neither list fails
    /// this test until it is classified.
    #[test]
    fn every_admin_cli_change_is_audited() {
        let kit = crate::testkit::kit();
        let p = &kit.paths;
        let args = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let usage_words = |err: String| -> Vec<String> { err.split_once('(').map(|(_, r)| r).unwrap_or("").split(" | ").filter_map(|c| c.split_whitespace().next()).map(|w| w.trim_end_matches(')').to_string()).collect() };
        let kinds = || seagent_security::audit::all(&p.data).iter().map(|r| r["kind"].as_str().unwrap_or("").to_string()).collect::<Vec<_>>();
        let a = agents::user_add(p, "Ann").unwrap().id;
        let b = agents::user_add(p, "Bea").unwrap().id;
        // (subcommand, argv, expected audit kind)
        let mutating: Vec<(&str, Vec<&str>, &str)> = vec![
            ("add", vec!["add", "Cy"], "user.add"),
            ("link-email", vec!["link-email", "ann@x.org", "--to", &a], "user.link"),
            ("link", vec!["link", "telegram", "42", "--to", &a], "user.link"),
            ("link-oidc", vec!["link-oidc", "sub-1", "--to", &a], "user.link"),
            ("role", vec!["role", &a, "auditor"], "user.role"),
            ("org", vec!["org", &a, "acme"], "user.org"),
            ("team", vec!["team", &a, "eng"], "user.team"),
            ("disable", vec!["disable", &a], "user.disable"),
            ("enable", vec!["enable", &a], "user.enable"),
            ("instructions", vec!["instructions", &a, "be brief"], "user.instructions"),
            ("merge", vec!["merge", &b, "--into", &a], "user.merge"),
            ("rm", vec!["rm", &a], "user.remove"),
        ];
        const READ_ONLY: &[(&str, &str)] = &[("list", "lists profiles"), ("whois", "looks one identity up")];
        let words = usage_words(run(p, &args(&["bogus"])).unwrap_err());
        for w in &words {
            assert!(mutating.iter().any(|(m, _, _)| m == w) || READ_ONLY.iter().any(|(r, _)| r == w), "`seagent users {w}` is not classified as audited or read-only");
        }
        for (name, argv, kind) in &mutating {
            let before = kinds().iter().filter(|k| k == kind).count();
            run(p, &args(argv)).unwrap_or_else(|e| panic!("users {name}: {e}"));
            assert_eq!(kinds().iter().filter(|k| k == kind).count(), before + 1, "`seagent users {name}` must write one `{kind}` record");
        }
        // `seagent tenancy`: every change is `tenancy.*`.
        let t = |v: &[&str]| crate::ops::tenancy::run(p, &args(v));
        let words = usage_words(t(&["bogus"]).unwrap_err());
        assert!(words.contains(&"org".to_string()) && words.contains(&"set".to_string()));
        for argv in [vec!["org", "add", "acme"], vec!["team", "add", "eng", "--org", "acme"], vec!["project", "add", "p1", "--team", "eng"], vec!["project", "member", "p1", "add", "u1"], vec!["set", "team:eng", "model", "x/y"], vec!["rm", "project", "p1"]] {
            let before = kinds().iter().filter(|k| k.starts_with("tenancy.")).count();
            t(&argv).unwrap_or_else(|e| panic!("tenancy {argv:?}: {e}"));
            assert_eq!(kinds().iter().filter(|k| k.starts_with("tenancy.")).count(), before + 1, "`seagent tenancy {argv:?}` must be audited");
        }
        // `seagent accounts`: issue / rotate / revoke are `token.*`.
        let acc = |v: &[&str]| crate::ops::enterprise::accounts(p, &args(v), 0);
        for argv in [vec!["issue", "ci", "--role", "operator"], vec!["rotate", "ci"], vec!["revoke", "ci"]] {
            let before = kinds().iter().filter(|k| k.starts_with("token.")).count();
            acc(&argv).unwrap();
            assert_eq!(kinds().iter().filter(|k| k.starts_with("token.")).count(), before + 1, "`seagent accounts {argv:?}` must be audited");
        }
        assert!(seagent_security::audit::verify(&p.data, None).ok);
    }

    /// `seagent users …` reaches this module through `ops::MODULES`; other names fall through.
    #[test]
    fn dispatch_is_wired() {
        let me: fn(&str, &Args, &[String]) -> Option<R> = dispatch;
        assert!(crate::ops::modules().iter().any(|m| m.0 == COMMANDS && m.3 as usize == me as usize), "users::dispatch is registered in ops::MODULES");
        let a = Args::parse(&[]).unwrap();
        assert!(dispatch("storage", &a, &[]).is_none() && dispatch("project", &a, &[]).is_none());
    }
}
