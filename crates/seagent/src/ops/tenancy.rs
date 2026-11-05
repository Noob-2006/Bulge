//! `seagent tenancy` (ent-050) and `seagent saml` (ent-048): manage organizations, teams, projects
//! and their settings, and check a SAML setup without a browser.
//!
//! * `seagent tenancy show [--json]` — the registry and whether multi-tenancy is active;
//! * `seagent tenancy org add <id> [--name N]`, `team add <id> --org <org> [--name N]`,
//!   `project add <id> --team <team> [--member U]…`, `project member <id> add|rm <user>`,
//!   `rm org|team|project <id>`;
//! * `seagent tenancy set <org:id|team:id|project:id> <model|workspace> <value|->`;
//! * `seagent tenancy session <session-id>` — where a session belongs;
//! * `seagent saml metadata` — the SP metadata from `[app.auth.saml]` (for the IdP admin);
//! * `seagent saml verify <response.xml|-> [--request-id ID]` — check a captured, base64-decoded
//!   `SAMLResponse` against the configuration (signature, wrapping, audience, time) and print
//!   the identity it carries.
//!
//! Every registry change is written to the audit stream (`tenancy.*`).

use crate::args::Args;
use crate::R;
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::tenancy;
use serde_json::json;

pub const COMMANDS: &[&str] = &["tenancy", "tenants", "saml"];
pub const VALUE_FLAGS: &[&str] = &["name", "member", "request-id"];
pub const BOOL_FLAGS: &[&str] = &[];

fn audit(p: &Paths, kind: &str, target: &str, detail: serde_json::Value) {
    seagent_security::audit::record(&p.data, seagent_security::audit::Event::new(kind, seagent_security::audit::Actor::local(), target, "ok").detail(detail));
}

pub fn run(p: &Paths, a: &Args) -> Result<String, String> {
    let _ = std::fs::create_dir_all(&p.data);
    let d = &p.data;
    let name = a.val("name").unwrap_or("");
    Ok(match (a.pos(0).unwrap_or("show"), a.pos(1).unwrap_or("")) {
        ("show" | "list" | "ls", _) => {
            let r = tenancy::registry(d);
            if a.flag("json") {
                return Ok(serde_json::to_string_pretty(&json!({"active": tenancy::active(d), "registry": r})).unwrap_or_default());
            }
            let mut out = vec![format!("multi-tenancy: {}", if tenancy::active(d) { "active" } else { "off (single organization `default`)" })];
            for o in &r.orgs {
                out.push(format!("org {}\t{}", o.id, o.name));
            }
            for t in &r.teams {
                out.push(format!("team {}\torg={}\t{}", t.id, t.org, t.name));
            }
            for x in &r.projects {
                out.push(format!("project {}\tteam={}\tmembers={}", x.id, x.team, if x.members.is_empty() { "(whole team)".into() } else { x.members.join(",") }));
            }
            out.join("\n")
        }
        ("org", "add") => {
            let o = tenancy::org_add(d, a.need(2, "org id")?, name)?;
            audit(p, "tenancy.org.add", &o.id, json!({"name": o.name}));
            format!("organization `{}` added", o.id)
        }
        ("team", "add") => {
            let t = tenancy::team_add(d, a.need(2, "team id")?, a.val("org").unwrap_or(""), name)?;
            audit(p, "tenancy.team.add", &t.id, json!({"org": t.org}));
            format!("team `{}` added to `{}`", t.id, t.org)
        }
        ("project", "add") => {
            let x = tenancy::project_add(d, a.need(2, "project id")?, a.val("team").ok_or("--team <team> is required")?, name, &a.vals("member"))?;
            audit(p, "tenancy.project.add", &x.id, json!({"team": x.team, "members": x.members}));
            format!("project `{}` added to team `{}`", x.id, x.team)
        }
        ("project", "member") => {
            let id = a.need(2, "project id")?;
            let add = match a.need(3, "add|rm")? {
                "add" => true,
                "rm" | "remove" => false,
                o => return Err(format!("`{o}`: use add or rm")),
            };
            let x = tenancy::project_member(d, id, a.need(4, "user")?, add)?;
            audit(p, "tenancy.project.member", &x.id, json!({"members": x.members}));
            format!("project `{}` members: {}", x.id, x.members.join(", "))
        }
        ("rm" | "remove", kind) => {
            let id = a.need(2, "id")?;
            tenancy::remove(d, kind, id)?;
            audit(p, "tenancy.remove", id, json!({"kind": kind}));
            format!("removed {kind} `{id}`")
        }
        ("set", scope) => {
            let key = a.need(2, "model|workspace")?;
            let v = a.need(3, "value (or - to clear)")?;
            tenancy::set_setting(d, scope, key, (v != "-").then_some(v))?;
            audit(p, "tenancy.setting", scope, json!({"key": key, "value": v}));
            format!("{scope} {key} = {v}")
        }
        ("session", sid) if !sid.is_empty() => {
            let t = tenancy::session_tenant(d, sid);
            format!("org={}\tteam={}\tproject={}", t.org(), if t.team.is_empty() { "-" } else { &t.team }, if t.project.is_empty() { "-" } else { &t.project })
        }
        (o, _) => return Err(format!("unknown `tenancy {o}` (show | org add <id> | team add <id> --org <org> | project add <id> --team <team> [--member U]… | project member <id> add|rm <user> | rm org|team|project <id> | set <org:id|team:id|project:id> <model|workspace> <value|-> | session <id>)")),
    })
}

fn saml_cfg(p: &Paths) -> Result<seagent_app::saml::SamlConfig, String> {
    let cfg = Config::load(Some(&p.user_config()), None, &[])?;
    Ok(seagent_app::AppConfig::parse(&cfg.app)?.auth.saml)
}

pub fn saml(p: &Paths, a: &Args) -> Result<String, String> {
    let c = saml_cfg(p)?;
    let keys = c.keys()?;
    match a.pos(0).unwrap_or("metadata") {
        "metadata" => Ok(seagent_app::saml::metadata(&c, c.sp_entity_id(), c.acs_url())),
        "verify" => {
            let src = a.need(1, "response.xml (or - for stdin)")?;
            let xml = if src == "-" {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).map_err(|e| e.to_string())?;
                s
            } else {
                std::fs::read_to_string(src).map_err(|e| format!("{src}: {e}"))?
            };
            let exp = seagent_app::saml::Expect { sp_entity_id: c.sp_entity_id(), acs_url: c.acs_url(), now: seagent_kernel::util::unix_now() };
            let got = seagent_app::saml::verify_response(&xml, &keys, &c, &exp)?;
            if let Some(want) = a.val("request-id") {
                if got.in_response_to != want {
                    return Err(format!("InResponseTo is `{}`, not `{want}`", got.in_response_to));
                }
            }
            Ok(serde_json::to_string_pretty(&json!({"ok": true, "subject": got.subject, "email": got.email, "name": got.name, "groups": got.groups, "assertion": got.id, "in_response_to": got.in_response_to})).unwrap_or_default())
        }
        o => Err(format!("unknown `saml {o}` (metadata | verify <response.xml|-> [--request-id ID])")),
    }
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    let p = Paths::from_env();
    let r = if cmd == "saml" { saml(&p, a) } else { run(&p, a) };
    Some(r.map(|o| {
        println!("{o}");
        0
    }).map_err(Into::into))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenancy_cli_manages_the_registry_and_is_audited() {
        let kit = crate::testkit::kit();
        let p = &kit.paths;
        let r = |v: &[&str]| run(p, &Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap());
        assert!(r(&["show"]).unwrap().contains("off"));
        r(&["org", "add", "acme", "--name", "Acme Inc"]).unwrap();
        r(&["team", "add", "eng", "--org", "acme"]).unwrap();
        assert!(r(&["team", "add", "x", "--org", "nope"]).is_err());
        r(&["project", "add", "apollo", "--team", "eng", "--member", "u-1"]).unwrap();
        assert!(r(&["project", "member", "apollo", "add", "u-2"]).unwrap().contains("u-1, u-2"));
        r(&["set", "team:eng", "model", "local/x"]).unwrap();
        assert!(r(&["set", "team:eng", "token", "x"]).is_err());
        let s = r(&["show"]).unwrap();
        assert!(s.contains("active") && s.contains("team eng\torg=acme"), "{s}");
        assert!(r(&["rm", "org", "acme"]).is_err(), "still has teams");
        assert!(r(&["session", "nope"]).unwrap().starts_with("org=default"));
        let kinds: Vec<String> = seagent_security::audit::all(&p.data).iter().map(|e| e["kind"].as_str().unwrap_or("").to_string()).collect();
        assert!(kinds.iter().any(|k| k == "tenancy.team.add") && kinds.iter().any(|k| k == "tenancy.setting"));
        assert!(r(&["bogus"]).is_err());
        let me: fn(&str, &Args, &[String]) -> Option<R> = dispatch;
        assert!(crate::ops::modules().iter().any(|m| m.0 == COMMANDS && m.3 as usize == me as usize));
    }
}
