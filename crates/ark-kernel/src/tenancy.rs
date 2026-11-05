//! Organizations → teams → projects (ent-050): who owns a piece of data, and who may see it.
//!
//! A single-machine install has one implicit organization, [`DEFAULT_ORG`], and nothing changes
//! for it: multi-tenancy is **active** only once the registry (`<data>/tenancy/registry.json`,
//! managed with `ark tenancy …`) defines a team, a project or a second organization. Data that
//! predates the registry carries no tenant and belongs to the default organization, so an upgrade
//! never moves or hides existing sessions.
//!
//! Every session gets a [`Tenant`] stamp when it is created through the app server (the
//! creating principal's organization and team, plus an optional project), inherited by child
//! sessions (sub-agents) and taken from a registered user's profile for sessions started on their
//! behalf. Stamps live in `<data>/tenancy/sessions.json` (first writer wins).
//!
//! A [`Viewer`] is what a caller may see: `global` (the local owner, the app token, untenanted
//! service accounts) sees everything; an organization admin sees their organization; everybody
//! else sees their own team's data plus the organization-wide data (no team), and project data
//! only as a project member (an empty member list = the whole team). Everything that filters —
//! ARP session methods and event streams, the audit stream, usage, the knowledge base and long
//! term memory — asks [`Viewer::sees`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_ORG: &str = "default";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Org {
    pub id: String,
    pub name: String,
    pub created_ms: u64,
    /// Organization defaults for its sessions (`model`, `workspace`).
    pub settings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Team {
    pub id: String,
    pub org: String,
    pub name: String,
    pub created_ms: u64,
    pub settings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Project {
    pub id: String,
    pub team: String,
    pub name: String,
    /// User ids or names; empty = every member of the team.
    pub members: Vec<String>,
    pub created_ms: u64,
    pub settings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Registry {
    pub orgs: Vec<Org>,
    pub teams: Vec<Team>,
    pub projects: Vec<Project>,
}

/// Where a piece of data belongs. `org` empty = [`DEFAULT_ORG`]; `team` empty = organization
/// wide; `project` empty = no project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tenant {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub org: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub team: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub project: String,
}

impl Tenant {
    pub fn org(&self) -> &str {
        if self.org.is_empty() {
            DEFAULT_ORG
        } else {
            &self.org
        }
    }
}

/// What a caller may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Viewer {
    pub global: bool,
    pub org: String,
    pub team: String,
    /// Sees the whole organization.
    pub org_admin: bool,
    /// User id / name, for project membership.
    pub user: String,
}

impl Default for Viewer {
    fn default() -> Self {
        Viewer::global()
    }
}

impl Viewer {
    pub fn global() -> Viewer {
        Viewer { global: true, org: String::new(), team: String::new(), org_admin: true, user: String::new() }
    }

    pub fn member(org: &str, team: &str, user: &str, org_admin: bool) -> Viewer {
        Viewer { global: false, org: if org.is_empty() { DEFAULT_ORG.into() } else { org.into() }, team: team.into(), org_admin, user: user.into() }
    }

    /// The viewer a session acts as (its tools search what its tenant may see).
    pub fn of_session(t: &Tenant) -> Viewer {
        Viewer::member(t.org(), &t.team, "", false)
    }

    pub fn sees(&self, t: &Tenant, reg: &Registry) -> bool {
        if self.global {
            return true;
        }
        if t.org() != self.org {
            return false;
        }
        if self.org_admin {
            return true;
        }
        if !t.team.is_empty() && t.team != self.team {
            return false;
        }
        if !t.project.is_empty() {
            return match reg.projects.iter().find(|p| p.id == t.project) {
                Some(p) => p.members.is_empty() || (!self.user.is_empty() && p.members.iter().any(|m| m == &self.user)),
                None => false,
            };
        }
        true
    }

    /// Plain team-level check for data that has no project (knowledge bases, memories).
    pub fn sees_team(&self, org: &str, team: &str) -> bool {
        self.sees(&Tenant { org: org.into(), team: team.into(), project: String::new() }, &Registry::default())
    }

    pub fn label(&self) -> String {
        if self.global {
            "global".into()
        } else if self.team.is_empty() {
            self.org.clone()
        } else {
            format!("{}/{}", self.org, self.team)
        }
    }
}

fn dir(data: &Path) -> PathBuf {
    data.join("tenancy")
}

pub fn registry_path(data: &Path) -> PathBuf {
    dir(data).join("registry.json")
}

fn stamps_path(data: &Path) -> PathBuf {
    dir(data).join("sessions.json")
}

pub fn registry(data: &Path) -> Registry {
    std::fs::read_to_string(registry_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save(data: &Path, r: &Registry) -> Result<(), String> {
    std::fs::create_dir_all(dir(data)).map_err(|e| e.to_string())?;
    crate::util::atomic_write(&registry_path(data), serde_json::to_string_pretty(r).map_err(|e| e.to_string())?.as_bytes()).map_err(|e| e.to_string())
}

/// Multi-tenancy is on once anything beyond the implicit default organization exists.
pub fn active(data: &Path) -> bool {
    let r = registry(data);
    !r.teams.is_empty() || !r.projects.is_empty() || r.orgs.iter().any(|o| o.id != DEFAULT_ORG)
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) && s != "*"
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// The organization a team belongs to (an unregistered team name lives in the default org, so
/// free-form `ark users team` values from before the registry keep working).
pub fn team_org(reg: &Registry, team: &str) -> String {
    reg.teams.iter().find(|t| t.id == team).map(|t| if t.org.is_empty() { DEFAULT_ORG.to_string() } else { t.org.clone() }).unwrap_or_else(|| DEFAULT_ORG.into())
}

pub fn org_add(data: &Path, id: &str, name: &str) -> Result<Org, String> {
    if !valid_id(id) {
        return Err(format!("organization id `{id}`: letters, digits, - _ . (max 64)"));
    }
    let mut r = registry(data);
    if r.orgs.iter().any(|o| o.id == id) {
        return Err(format!("organization `{id}` exists"));
    }
    let o = Org { id: id.into(), name: if name.is_empty() { id.into() } else { name.into() }, created_ms: now_ms(), settings: BTreeMap::new() };
    r.orgs.push(o.clone());
    save(data, &r)?;
    Ok(o)
}

pub fn team_add(data: &Path, id: &str, org: &str, name: &str) -> Result<Team, String> {
    if !valid_id(id) {
        return Err(format!("team id `{id}`: letters, digits, - _ . (max 64)"));
    }
    let mut r = registry(data);
    let org = if org.is_empty() { DEFAULT_ORG } else { org };
    if org != DEFAULT_ORG && !r.orgs.iter().any(|o| o.id == org) {
        return Err(format!("no organization `{org}` (ark tenancy org add {org})"));
    }
    if r.teams.iter().any(|t| t.id == id) {
        return Err(format!("team `{id}` exists (team ids are unique across organizations)"));
    }
    let t = Team { id: id.into(), org: org.into(), name: if name.is_empty() { id.into() } else { name.into() }, created_ms: now_ms(), settings: BTreeMap::new() };
    r.teams.push(t.clone());
    save(data, &r)?;
    Ok(t)
}

pub fn project_add(data: &Path, id: &str, team: &str, name: &str, members: &[String]) -> Result<Project, String> {
    if !valid_id(id) {
        return Err(format!("project id `{id}`: letters, digits, - _ . (max 64)"));
    }
    let mut r = registry(data);
    if !r.teams.iter().any(|t| t.id == team) {
        return Err(format!("no team `{team}`"));
    }
    if r.projects.iter().any(|p| p.id == id) {
        return Err(format!("project `{id}` exists"));
    }
    let p = Project { id: id.into(), team: team.into(), name: if name.is_empty() { id.into() } else { name.into() }, members: members.to_vec(), created_ms: now_ms(), settings: BTreeMap::new() };
    r.projects.push(p.clone());
    save(data, &r)?;
    Ok(p)
}

/// Add (`add = true`) or remove a project member.
pub fn project_member(data: &Path, project: &str, user: &str, add: bool) -> Result<Project, String> {
    let mut r = registry(data);
    let p = r.projects.iter_mut().find(|p| p.id == project).ok_or_else(|| format!("no project `{project}`"))?;
    p.members.retain(|m| m != user);
    if add {
        p.members.push(user.into());
    }
    let out = p.clone();
    save(data, &r)?;
    Ok(out)
}

/// Remove an organization, team or project. Refused while something still points at it.
pub fn remove(data: &Path, kind: &str, id: &str) -> Result<(), String> {
    let mut r = registry(data);
    match kind {
        "org" => {
            if r.teams.iter().any(|t| t.org == id) {
                return Err(format!("organization `{id}` still has teams"));
            }
            r.orgs.retain(|o| o.id != id);
        }
        "team" => {
            if r.projects.iter().any(|p| p.team == id) {
                return Err(format!("team `{id}` still has projects"));
            }
            r.teams.retain(|t| t.id != id);
        }
        "project" => r.projects.retain(|p| p.id != id),
        _ => return Err(format!("unknown kind `{kind}` (org, team, project)")),
    }
    save(data, &r)
}

/// Set (`Some`) or clear a setting on `org:<id>`, `team:<id>` or `project:<id>`.
pub fn set_setting(data: &Path, scope: &str, key: &str, value: Option<&str>) -> Result<(), String> {
    const KEYS: &[&str] = &["model", "workspace"];
    if !KEYS.contains(&key) {
        return Err(format!("unknown tenant setting `{key}` (one of: {})", KEYS.join(", ")));
    }
    let mut r = registry(data);
    let (kind, id) = scope.split_once(':').ok_or("scope is org:<id>, team:<id> or project:<id>")?;
    let map = match kind {
        "org" => {
            if id == DEFAULT_ORG && !r.orgs.iter().any(|o| o.id == id) {
                r.orgs.push(Org { id: id.into(), name: id.into(), created_ms: now_ms(), settings: BTreeMap::new() });
            }
            r.orgs.iter_mut().find(|o| o.id == id).map(|o| &mut o.settings)
        }
        "team" => r.teams.iter_mut().find(|t| t.id == id).map(|t| &mut t.settings),
        "project" => r.projects.iter_mut().find(|p| p.id == id).map(|p| &mut p.settings),
        _ => None,
    }
    .ok_or_else(|| format!("no {scope}"))?;
    match value {
        Some(v) => map.insert(key.into(), v.into()),
        None => map.remove(key),
    };
    save(data, &r)
}

/// The effective setting for a tenant: project, then team, then organization.
pub fn setting(reg: &Registry, t: &Tenant, key: &str) -> Option<String> {
    let p = reg.projects.iter().find(|p| !t.project.is_empty() && p.id == t.project).and_then(|p| p.settings.get(key));
    let tm = reg.teams.iter().find(|x| !t.team.is_empty() && x.id == t.team).and_then(|x| x.settings.get(key));
    let o = reg.orgs.iter().find(|o| o.id == t.org()).and_then(|o| o.settings.get(key));
    p.or(tm).or(o).cloned()
}

/// Check that `viewer` may create data in `t` (a project must belong to the viewer's team).
pub fn may_create(reg: &Registry, viewer: &Viewer, t: &Tenant) -> Result<(), String> {
    if !t.team.is_empty() && team_org(reg, &t.team) != t.org() {
        return Err(format!("team `{}` is not in organization `{}`", t.team, t.org()));
    }
    if !t.project.is_empty() {
        let p = reg.projects.iter().find(|p| p.id == t.project).ok_or_else(|| format!("no project `{}`", t.project))?;
        if p.team != t.team {
            return Err(format!("project `{}` belongs to another team", t.project));
        }
    }
    if viewer.sees(t, reg) {
        Ok(())
    } else {
        Err("forbidden: outside your organization / team / project".into())
    }
}

// ───────────────────────── session stamps ─────────────────────────

fn stamps(data: &Path) -> BTreeMap<String, Tenant> {
    std::fs::read_to_string(stamps_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Exclusive `flock` on `<data>/tenancy/.lock` while a stamp is read-modified-written (the
/// daemon and a CLI may stamp at the same time). Released when the file closes.
fn lock(data: &Path) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    std::fs::create_dir_all(dir(data)).ok()?;
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir(data).join(".lock")).ok()?;
    // SAFETY: flock on an fd we own; released when it closes.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    Some(f)
}

/// Record where a session belongs. First writer wins; the default tenant is not written.
pub fn stamp(data: &Path, session: &str, t: &Tenant) {
    if session.is_empty() || *t == Tenant::default() {
        return;
    }
    let _l = lock(data);
    let mut all = stamps(data);
    if all.contains_key(session) {
        return;
    }
    all.insert(session.into(), t.clone());
    let _ = std::fs::create_dir_all(dir(data));
    let _ = crate::util::atomic_write(&stamps_path(data), serde_json::to_string(&all).unwrap_or_default().as_bytes());
}

/// A child session (sub-agent, branch) belongs where its parent does.
pub fn inherit(data: &Path, child: &str, parent: &str) {
    let t = session_tenant(data, parent);
    stamp(data, child, &t);
}

/// Where a session belongs (default organization when never stamped).
pub fn session_tenant(data: &Path, session: &str) -> Tenant {
    stamps(data).remove(session).unwrap_or_default()
}

/// All stamps (for filtering lists without one read per row).
pub fn session_tenants(data: &Path) -> BTreeMap<String, Tenant> {
    stamps(data)
}

/// The tenant a registered user's own data goes to (organization from the profile, else from
/// the team's registry entry).
/// May a session in `caller`'s tenant create a session for a user in `target`? Unstamped
/// callers (single-tenant installs, local CLI) are unrestricted; a stamped caller stays in its
/// organization, and a team-scoped caller in its team.
pub fn may_attach(caller: Option<&Tenant>, target: &Tenant) -> bool {
    match caller {
        None => true,
        Some(c) => c.org() == target.org() && (c.team.is_empty() || c.team == target.team),
    }
}

pub fn user_tenant(reg: &Registry, user: &crate::agents::User) -> Tenant {
    let org = if !user.org.is_empty() && user.org != "*" { user.org.clone() } else if !user.team.is_empty() { team_org(reg, &user.team) } else { DEFAULT_ORG.into() };
    Tenant { org: if org == DEFAULT_ORG { String::new() } else { org }, team: user.team.clone(), project: String::new() }
}

/// The viewer of a registered user. `org = "*"` with the admin role is a global administrator.
pub fn user_viewer(reg: &Registry, user: &crate::agents::User, admin: bool) -> Viewer {
    if user.org == "*" && admin {
        return Viewer::global();
    }
    let t = user_tenant(reg, user);
    Viewer::member(t.org(), &t.team, &user.id, admin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_cannot_be_created_for_users_of_another_tenant() {
        let t = |org: &str, team: &str| Tenant { org: org.into(), team: team.into(), project: String::new() };
        assert!(may_attach(None, &t("acme", "ops")), "unstamped caller");
        assert!(may_attach(Some(&t("acme", "")), &t("acme", "ops")), "org-wide caller, own org");
        assert!(may_attach(Some(&t("acme", "ops")), &t("acme", "ops")));
        assert!(!may_attach(Some(&t("acme", "ops")), &t("acme", "sales")), "other team");
        assert!(!may_attach(Some(&t("acme", "")), &t("globex", "")), "other org");
        assert!(may_attach(Some(&t("", "")), &t("default", "")), "empty org is the default org");
    }

    #[test]
    fn registry_viewers_and_stamps() {
        let tmp = ark_core::tmp::TempDir::new("ark-kernel-tenancy");
        let d = tmp.path();
        assert!(!active(d), "a fresh install is single-tenant");
        // Legacy, unstamped data is in the default org and visible to its members.
        let legacy = session_tenant(d, "old");
        assert_eq!(legacy.org(), DEFAULT_ORG);
        assert!(Viewer::member("", "", "u", false).sees(&legacy, &Registry::default()));
        org_add(d, "acme", "Acme").unwrap();
        assert!(active(d));
        assert!(org_add(d, "acme", "").is_err() && org_add(d, "*", "").is_err());
        team_add(d, "eng", "acme", "").unwrap();
        team_add(d, "ops", "acme", "").unwrap();
        assert!(team_add(d, "x", "nope", "").is_err());
        project_add(d, "apollo", "eng", "", &["u-eng".into()]).unwrap();
        assert!(project_add(d, "p2", "nope", "", &[]).is_err());
        let reg = registry(d);
        let eng = Tenant { org: "acme".into(), team: "eng".into(), project: String::new() };
        let ops = Tenant { org: "acme".into(), team: "ops".into(), project: String::new() };
        let apollo = Tenant { org: "acme".into(), team: "eng".into(), project: "apollo".into() };
        let org_wide = Tenant { org: "acme".into(), ..Default::default() };
        let v_eng = Viewer::member("acme", "eng", "u-eng", false);
        let v_eng2 = Viewer::member("acme", "eng", "u-other", false);
        let v_ops = Viewer::member("acme", "ops", "u-ops", false);
        let v_admin = Viewer::member("acme", "", "boss", true);
        let v_default = Viewer::member("", "", "x", false);
        assert!(v_eng.sees(&eng, &reg) && v_eng.sees(&org_wide, &reg) && !v_eng.sees(&ops, &reg));
        assert!(v_eng.sees(&apollo, &reg) && !v_eng2.sees(&apollo, &reg), "project members only");
        assert!(!v_ops.sees(&eng, &reg) && v_ops.sees(&ops, &reg));
        assert!(v_admin.sees(&eng, &reg) && v_admin.sees(&apollo, &reg) && !v_admin.sees(&legacy, &reg));
        assert!(!v_default.sees(&eng, &reg) && v_default.sees(&legacy, &reg));
        assert!(Viewer::global().sees(&eng, &reg));
        assert!(may_create(&reg, &v_ops, &eng).is_err() && may_create(&reg, &v_eng, &apollo).is_ok());
        assert!(may_create(&reg, &v_ops, &Tenant { project: "apollo".into(), ..ops.clone() }).is_err());
        // Stamps: first writer wins, children inherit.
        stamp(d, "s1", &eng);
        stamp(d, "s1", &ops);
        assert_eq!(session_tenant(d, "s1"), eng);
        inherit(d, "s1-child", "s1");
        assert_eq!(session_tenant(d, "s1-child"), eng);
        // Settings resolve project → team → org.
        set_setting(d, "org:acme", "model", Some("local/a")).unwrap();
        set_setting(d, "team:eng", "model", Some("local/b")).unwrap();
        assert!(set_setting(d, "team:eng", "secret", Some("x")).is_err());
        let reg = registry(d);
        assert_eq!(setting(&reg, &ops, "model").as_deref(), Some("local/a"));
        assert_eq!(setting(&reg, &eng, "model").as_deref(), Some("local/b"));
        assert!(remove(d, "org", "acme").is_err());
        remove(d, "project", "apollo").unwrap();
        assert_eq!(team_org(&registry(d), "eng"), "acme");
        assert_eq!(team_org(&registry(d), "free-form"), DEFAULT_ORG);
    }
}
