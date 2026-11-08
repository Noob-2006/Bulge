//! LDAP / Active Directory through the stock `ldapsearch` client (OpenLDAP tools).
//!
//! Search only. The bind password goes to the client through a 0600 file (`-y`), deleted when
//! the call ends — never on the command line, where `ps` would show it. Whatever the
//! directory returns, attributes that look like credentials are dropped.

use super::{Provider, Query};
use serde_json::{json, Map, Value};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// RFC 4515 filter value escaping.
pub fn escape_filter(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\5c"),
            '*' => o.push_str("\\2a"),
            '(' => o.push_str("\\28"),
            ')' => o.push_str("\\29"),
            '\0' => o.push_str("\\00"),
            c => o.push(c),
        }
    }
    o
}

/// `abc*` keeps a trailing wildcard (prefix search); every other `*` is literal.
pub fn pattern(q: &str) -> String {
    match q.strip_suffix('*') {
        Some(p) => format!("{}*", escape_filter(p)),
        None => escape_filter(q),
    }
}

const USER_ATTRS: &[&str] = &["dn", "cn", "uid", "sAMAccountName", "userPrincipalName", "mail", "displayName", "title", "department", "userAccountControl", "accountExpires", "lastLogonTimestamp", "whenCreated", "memberOf", "manager", "employeeID", "shadowExpire", "nsAccountLock", "pwdAccountLockedTime"];
const GROUP_ATTRS: &[&str] = &["dn", "cn", "description", "member", "uniqueMember", "memberUid", "gidNumber", "sAMAccountName", "mail", "groupType"];

/// `ad`: Active Directory also stores machines as `user` objects, so they are excluded there;
/// OpenLDAP does not know the class `computer` and would treat `(!(objectClass=computer))` as undefined.
pub fn user_filter(q: &str, ad: bool) -> String {
    let p = pattern(q);
    let not_computer = if ad { "(!(objectClass=computer))" } else { "" };
    format!("(&(|(objectClass=person)(objectClass=inetOrgPerson)(objectClass=user)){not_computer}(|(sAMAccountName={p})(uid={p})(userPrincipalName={p})(mail={p})(cn={p})(displayName={p})))")
}

pub fn group_filter(q: &str) -> String {
    let p = pattern(q);
    format!("(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(cn={p})(sAMAccountName={p})))")
}

fn secret_like(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    ["pass", "pwd", "secret", "hash", "token", "credential", "private", "key", "unicodepwd", "ntpassword"].iter().any(|k| l.contains(k)) && !matches!(l.as_str(), "pwdaccountlockedtime")
}

/// Parse `ldapsearch -LLL -o ldif-wrap=no` output into entries (`attr -> [values]`).
pub fn parse_ldif(text: &str) -> Vec<Map<String, Value>> {
    use base64::Engine as _;
    let mut out = vec![];
    let mut cur: Map<String, Value> = Map::new();
    let flush = |cur: &mut Map<String, Value>, out: &mut Vec<Map<String, Value>>| {
        if !cur.is_empty() {
            out.push(std::mem::take(cur));
        }
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            flush(&mut cur, &mut out);
            continue;
        }
        if line.starts_with('#') || line.starts_with("search:") || line.starts_with("result:") {
            continue;
        }
        let Some((k, rest)) = line.split_once(':') else { continue };
        if secret_like(k) {
            continue;
        }
        let v = if let Some(b) = rest.strip_prefix(':') {
            base64::engine::general_purpose::STANDARD.decode(b.trim()).ok().map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_else(|| "<binary>".into())
        } else {
            rest.trim_start().to_string()
        };
        let e = cur.entry(k.to_string()).or_insert_with(|| json!([]));
        if let Some(a) = e.as_array_mut() {
            a.push(Value::String(super::clip(&v)));
        }
    }
    flush(&mut cur, &mut out);
    out
}

fn first<'a>(e: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    e.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).and_then(|(_, v)| v.as_array()).and_then(|a| a.first()).and_then(Value::as_str)
}

fn all(e: &Map<String, Value>, k: &str) -> Vec<String> {
    e.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).and_then(|(_, v)| v.as_array()).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default()
}

/// First RDN value of a DN: `CN=Ann Lee,OU=x` -> `Ann Lee`.
fn rdn(dn: &str) -> String {
    dn.split(',').next().and_then(|r| r.split_once('=')).map(|(_, v)| v.to_string()).unwrap_or_else(|| dn.to_string())
}

pub fn user_record(e: &Map<String, Value>) -> Value {
    let uac = first(e, "userAccountControl").and_then(|v| v.parse::<u64>().ok());
    let disabled = uac.map(|u| u & 2 != 0).or_else(|| first(e, "nsAccountLock").map(|v| v.eq_ignore_ascii_case("true"))).unwrap_or(false);
    let locked = first(e, "pwdAccountLockedTime").is_some();
    let groups: Vec<String> = all(e, "memberOf").iter().map(|d| rdn(d)).collect();
    json!({
        "dn": first(e, "dn"),
        "login": first(e, "sAMAccountName").or(first(e, "uid")),
        "upn": first(e, "userPrincipalName"),
        "name": first(e, "displayName").or(first(e, "cn")),
        "mail": first(e, "mail"),
        "title": first(e, "title"),
        "department": first(e, "department"),
        "manager": first(e, "manager").map(rdn),
        "enabled": !disabled,
        "locked": locked,
        "created": first(e, "whenCreated"),
        "groups": groups,
    })
}

pub fn group_record(e: &Map<String, Value>, limit: usize) -> Value {
    let mut members: Vec<String> = all(e, "member").iter().chain(all(e, "uniqueMember").iter()).map(|d| rdn(d)).collect();
    members.extend(all(e, "memberUid"));
    let total = members.len();
    members.truncate(limit);
    json!({"dn": first(e, "dn"), "name": first(e, "cn"), "description": first(e, "description"), "mail": first(e, "mail"), "member_count": total, "members": members, "members_truncated": total > limit})
}

struct PwFile(Option<std::path::PathBuf>);
impl Drop for PwFile {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn run(p: &Provider, ctx: &seagent_core::ToolCtx, filter: &str, attrs: &[&str], limit: usize) -> Result<Vec<Map<String, Value>>, String> {
    let uri = p.uri.as_deref().ok_or("ldap provider needs `uri`")?;
    let base = p.base_dn.as_deref().ok_or("ldap provider needs `base_dn`")?;
    let mut argv: Vec<String> = if p.client.is_empty() { vec!["ldapsearch".into()] } else { p.client.clone() };
    let prog = argv.remove(0);
    argv.extend(["-LLL", "-x", "-o", "ldif-wrap=no", "-H", uri, "-b", base, "-z", &limit.to_string(), "-l", &p.timeout().to_string(), "-s", "sub"].map(String::from));
    if p.starttls {
        argv.push("-ZZ".into());
    }
    let mut pw = PwFile(None);
    if let Some(dn) = p.bind_dn.as_deref().filter(|d| !d.is_empty()) {
        let password = super::secret(ctx, p.bind_password.as_deref().unwrap_or(""))?;
        std::fs::create_dir_all(&ctx.artifacts).map_err(|e| e.to_string())?;
        let path = ctx.artifacts.join(format!(".ldap-{}", seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(8))));
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let mut f = o.open(&path).map_err(|e| e.to_string())?;
            // Windows: an owner-only DACL before the password goes in (Unix: the 0600 above).
            #[cfg(not(unix))]
            seagent_core::platform::fs_private::set_private(&path).map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut f, password.as_bytes()).map_err(|e| e.to_string())?;
        }
        pw.0 = Some(path.clone());
        argv.extend(["-D".into(), dn.to_string(), "-y".into(), path.to_string_lossy().into_owned()]);
    }
    argv.push(filter.to_string());
    argv.extend(attrs.iter().map(|s| s.to_string()));
    // ETXTBSY: a just-written client script can still be open in a concurrently forked child.
    let mut tries = 0;
    let mut child = loop {
        match Command::new(&prog).args(&argv).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
            Err(e) if crate::exec::local::is_text_busy(&e) && tries < 20 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            r => break r.map_err(|e| format!("cannot start `{prog}`: {e} (install the OpenLDAP client tools or set `client`)"))?,
        }
    };
    let mut out = child.stdout.take().ok_or("no stdout")?;
    let mut err = child.stderr.take().ok_or("no stderr")?;
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut out).take(4 * 1024 * 1024).read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = (&mut err).take(8192).read_to_end(&mut b);
        b
    });
    let t0 = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if ctx.cancel.is_cancelled() || t0.elapsed() > Duration::from_secs(p.timeout() + 5) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(if ctx.cancel.is_cancelled() { "Interrupted".into() } else { format!("directory search exceeded {} seconds", p.timeout()) });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
    // 4 = size limit exceeded: the entries read so far are still valid.
    if !status.success() && status.code() != Some(4) {
        let pwv = p.bind_password.as_deref().map(|b| super::secret(ctx, b).unwrap_or_default()).unwrap_or_default();
        return Err(format!("ldapsearch failed ({}): {}", status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()), crate::pro_http::scrub(stderr.trim(), &[&pwv])));
    }
    Ok(parse_ldif(&stdout))
}

pub fn lookup(p: &Provider, ctx: &seagent_core::ToolCtx, q: &Query) -> Result<Value, String> {
    let limit = q.limit;
    match q.kind.as_str() {
        "user" => {
            let r = run(p, ctx, &user_filter(&q.query, p.kind == "ad"), USER_ATTRS, limit + 1)?;
            Ok(json!({"results": r.iter().take(limit).map(user_record).collect::<Vec<_>>(), "truncated": r.len() > limit}))
        }
        "group" => {
            let r = run(p, ctx, &group_filter(&q.query), GROUP_ATTRS, limit + 1)?;
            Ok(json!({"results": r.iter().take(limit).map(|e| group_record(e, 0)).collect::<Vec<_>>(), "truncated": r.len() > limit}))
        }
        "members" => {
            let r = run(p, ctx, &group_filter(&q.query), GROUP_ATTRS, 2)?;
            match r.as_slice() {
                [] => Err(format!("no group matches `{}`", q.query)),
                [g] => Ok(json!({"results": [group_record(g, limit.max(1) * 4)]})),
                _ => Err(format!("`{}` matches several groups; use the exact name: {}", q.query, r.iter().filter_map(|e| first(e, "cn")).collect::<Vec<_>>().join(", "))),
            }
        }
        "groups_of" => {
            let u = run(p, ctx, &user_filter(&q.query, p.kind == "ad"), USER_ATTRS, 2)?;
            let user = match u.as_slice() {
                [] => return Err(format!("no user matches `{}`", q.query)),
                [u] => u,
                _ => return Err(format!("`{}` matches several users; use the exact login", q.query)),
            };
            let dn = first(user, "dn").unwrap_or("");
            let uid = first(user, "uid").or(first(user, "sAMAccountName")).unwrap_or("");
            let filter = format!("(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(member={d})(uniqueMember={d})(memberUid={u})))", d = escape_filter(dn), u = escape_filter(uid));
            let g = run(p, ctx, &filter, &["dn", "cn", "description"], limit + 1)?;
            let mut names: Vec<String> = g.iter().filter_map(|e| first(e, "cn").map(String::from)).collect();
            // AD also lists the groups on the user entry (nested ones come from memberOf).
            for n in all(user, "memberOf").iter().map(|d| rdn(d)) {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
            let truncated = names.len() > limit;
            names.truncate(limit);
            Ok(json!({"results": [{"user": first(user, "cn"), "dn": dn, "groups": names}], "truncated": truncated}))
        }
        k => Err(format!("unknown kind `{k}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_values_cannot_break_out_of_the_filter() {
        assert_eq!(escape_filter("a*)(uid=*))(|(x=b"), "a\\2a\\29\\28uid=\\2a\\29\\29\\28|\\28x=b");
        assert_eq!(pattern("ann*"), "ann*");
        assert_eq!(pattern("*"), "*");
        assert_eq!(pattern("a*b"), "a\\2ab");
        let f = user_filter("x)(objectClass=*", true);
        assert!(f.contains("(!(objectClass=computer))") && !user_filter("a", false).contains("computer"));
        assert!(!f.contains("x)(objectClass=") && f.contains("x\\29\\28objectClass=*"), "{f}");
    }

    #[test]
    fn ldif_is_parsed_decoded_and_stripped_of_credentials() {
        let ldif = "dn: CN=Ann Lee,OU=Staff,DC=corp,DC=example\ncn: Ann Lee\nsAMAccountName: alee\nmail: ann@corp.example\nuserPassword: {SSHA}abc\nunicodePwd:: AAAA\nuserAccountControl: 514\nmemberOf: CN=VPN,OU=Groups,DC=corp,DC=example\nmemberOf: CN=Finance,OU=Groups,DC=corp,DC=example\ndisplayName:: w4lsb2lzZQ==\n\ndn: CN=Bob\ncn: Bob\n\n";
        let r = parse_ldif(ldif);
        assert_eq!(r.len(), 2);
        assert!(!r[0].contains_key("userPassword") && !r[0].contains_key("unicodePwd"));
        let u = user_record(&r[0]);
        assert_eq!(u["login"], "alee");
        assert_eq!(u["enabled"], false, "userAccountControl bit 2");
        assert_eq!(u["groups"], json!(["VPN", "Finance"]));
        assert_eq!(u["name"], "Éloise");
        assert_eq!(user_record(&r[1])["enabled"], true);
    }

    #[test]
    fn group_members_are_names_not_dns_and_capped() {
        let r = parse_ldif("dn: cn=ops,ou=g\ncn: ops\nmember: uid=a,ou=p\nmember: uid=b,ou=p\nmemberUid: c\n\n");
        let g = group_record(&r[0], 2);
        assert_eq!((g["member_count"].clone(), g["members"].clone(), g["members_truncated"].clone()), (json!(3), json!(["a", "b"]), json!(true)));
    }
}
