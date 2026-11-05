use super::*;
use crate::testutil::ctx;
use crate::web::testutil::FakeServer;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn one(cfg: Value) -> Arc<dyn Tool> {
    tools(cfg).unwrap().pop().unwrap()
}

fn body(o: &ToolOutput) -> Value {
    assert!(!o.is_error, "{}", o.content);
    assert!(o.content.contains("EXTERNAL_UNTRUSTED_CONTENT"));
    serde_json::from_str(&o.content[o.content.find('{').unwrap()..=o.content.rfind('}').unwrap()]).unwrap()
}

/// A fake `ldapsearch` that records its argv and the password file's content, and answers by filter.
fn fake_ldapsearch(dir: &Path) -> (String, PathBuf) {
    let out = dir.join("ld-out");
    std::fs::create_dir_all(&out).unwrap();
    let script = dir.join("ldapsearch");
    let o = out.display();
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$@" > '{o}/argv.txt'
while [ $# -gt 0 ]; do case "$1" in -y) cp "$2" '{o}/pw.txt'; ls -l "$2" | cut -c1-10 > '{o}/pwmode.txt';; esac; last="$1"; shift; done
F=$(grep '^(&' '{o}/argv.txt' | head -1)
case "$F" in
*memberUid*|*"(member="*) printf 'dn: cn=vpn,ou=g,dc=corp\ncn: vpn\n\n' ;;
*"objectClass=group)"*"(cn=vpn"*) printf 'dn: cn=vpn,ou=g,dc=corp\ncn: vpn\nmember: uid=alee,ou=p,dc=corp\nmember: uid=bob,ou=p,dc=corp\n\n' ;;
*"sAMAccountName=alee"*) printf 'dn: uid=alee,ou=p,dc=corp\nuid: alee\ncn: Ann Lee\nmail: ann@corp.example\nuserPassword: {{SSHA}}zzz\nmemberOf: cn=staff,ou=g,dc=corp\n\n' ;;
*"sAMAccountName=bad"*) echo 'ldap_bind: Invalid credentials (49) hunter2' >&2; exit 49 ;;
*) : ;;
esac
"#
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script.to_string_lossy().into_owned(), out)
}

#[test]
fn ldap_user_lookup_binds_through_a_private_file_and_drops_credentials() {
    let mut c = ctx("dir-ldap");
    c.secrets = Arc::new(|s: &str| s.replace("{{secret:LDAP_PW}}", "hunter2"));
    let (client, out) = fake_ldapsearch(&c.workspace);
    let t = one(json!({"providers": {"corp": {"kind": "ad", "uri": "ldaps://dc1.corp.example:636", "base_dn": "DC=corp", "bind_dn": "CN=svc,DC=corp", "bind_password": "{{secret:LDAP_PW}}", "client": [client]}}}));
    let v = body(&t.call(&c, json!({"kind": "user", "query": "alee"})));
    assert_eq!(v["results"][0]["login"], "alee");
    assert_eq!(v["results"][0]["mail"], "ann@corp.example");
    assert_eq!(v["results"][0]["groups"], json!(["staff"]));
    assert_eq!(v["read_only"], true);
    assert!(!v.to_string().contains("SSHA"), "credential attributes are dropped");
    let argv = std::fs::read_to_string(out.join("argv.txt")).unwrap();
    assert!(!argv.contains("hunter2"), "the bind password is never on the command line: {argv}");
    assert!(argv.contains("-H\nldaps://dc1.corp.example:636") && argv.contains("-b\nDC=corp") && argv.contains("-D\nCN=svc,DC=corp"), "{argv}");
    assert_eq!(std::fs::read_to_string(out.join("pw.txt")).unwrap(), "hunter2");
    assert_eq!(std::fs::read_to_string(out.join("pwmode.txt")).unwrap().trim(), "-rw-------");
    let left: Vec<_> = std::fs::read_dir(&c.artifacts).unwrap().flatten().collect();
    assert!(left.is_empty(), "the password file is gone: {left:?}");
}

#[test]
fn ldap_group_members_and_memberships() {
    let c = ctx("dir-ldap2");
    let (client, _) = fake_ldapsearch(&c.workspace);
    let t = one(json!({"providers": {"corp": {"kind": "ldap", "uri": "ldap://x", "base_dn": "dc=corp", "client": [client]}}}));
    let v = body(&t.call(&c, json!({"kind": "members", "query": "vpn"})));
    assert_eq!(v["results"][0]["members"], json!(["alee", "bob"]));
    let v = body(&t.call(&c, json!({"kind": "groups_of", "query": "alee"})));
    let g: Vec<&str> = v["results"][0]["groups"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert_eq!(g, ["vpn", "staff"]);
    // Nothing found is an error the model can act on, not an empty success.
    let o = t.call(&c, json!({"kind": "members", "query": "nosuchgroup"}));
    assert!(o.is_error && o.content.contains("no group"), "{}", o.content);
}

#[test]
fn ldap_errors_hide_the_password_and_filters_are_escaped() {
    let mut c = ctx("dir-ldap3");
    c.secrets = Arc::new(|s: &str| s.replace("{{secret:LDAP_PW}}", "hunter2"));
    let (client, out) = fake_ldapsearch(&c.workspace);
    let t = one(json!({"providers": {"corp": {"kind": "ad", "uri": "ldap://x", "base_dn": "dc=corp", "bind_dn": "cn=svc", "bind_password": "{{secret:LDAP_PW}}", "client": [client]}}}));
    let o = t.call(&c, json!({"kind": "user", "query": "bad"}));
    assert!(o.is_error && o.content.contains("Invalid credentials") && !o.content.contains("hunter2"), "{}", o.content);
    let _ = t.call(&c, json!({"kind": "user", "query": "x)(objectClass=*"}));
    let argv = std::fs::read_to_string(out.join("argv.txt")).unwrap();
    assert!(argv.contains("x\\29\\28objectClass=*") && !argv.contains("x)(objectClass="), "{argv}");
}

#[test]
fn entra_queries_graph_with_a_bearer_token_and_odata_escaping() {
    let mut c = ctx("dir-entra");
    c.secrets = Arc::new(|s: &str| s.replace("{{secret:GRAPH}}", "eyJ.fake.token"));
    let srv = FakeServer::with(|r| {
        let ok = |v: Value| (200, "application/json".to_string(), v.to_string().into_bytes(), vec![]);
        if r.path.starts_with("/users?") {
            ok(json!({"value": [{"id": "u1", "displayName": "Ann Lee", "userPrincipalName": "ann@corp.example", "mail": "ann@corp.example", "accountEnabled": false}, {"id": "u2", "displayName": "Ann Two", "userPrincipalName": "a2@corp.example", "accountEnabled": true}, {"id": "u3", "displayName": "x"}]}))
        } else if r.path.starts_with("/groups?") {
            ok(json!({"value": [{"id": "11111111-1111-1111-1111-111111111111", "displayName": "VPN"}]}))
        } else if r.path.starts_with("/groups/11111111-1111-1111-1111-111111111111/members") {
            ok(json!({"value": [{"id": "u1", "displayName": "Ann Lee"}]}))
        } else {
            (404, "application/json".into(), br#"{"error":{"message":"nope"}}"#.to_vec(), vec![])
        }
    });
    let t = one(json!({"providers": {"cloud": {"kind": "entra", "token": "{{secret:GRAPH}}", "api_base": srv.url}}}));
    let v = body(&t.call(&c, json!({"kind": "user", "query": "O'Brien", "limit": 2})));
    assert_eq!(v["results"].as_array().unwrap().len(), 2);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["results"][0]["enabled"], false);
    let r = srv.requests()[0].clone();
    assert_eq!(r.header("Authorization").as_deref(), Some("Bearer eyJ.fake.token"));
    assert!(r.query("$filter").unwrap().contains("startswith(displayName,'O''Brien')"), "{}", r.path);
    assert_eq!(r.query("$top").as_deref(), Some("3"));
    // members: resolves the group by name first.
    let v = body(&t.call(&c, json!({"kind": "members", "query": "VPN"})));
    assert_eq!(v["results"][0]["members"][0]["name"], "Ann Lee");
    // An API error carries the status and no token.
    let o = t.call(&c, json!({"kind": "groups_of", "query": "11111111-1111-1111-1111-111111111111"}));
    assert!(o.is_error && o.content.contains("404") && !o.content.contains("eyJ.fake.token"), "{}", o.content);
}

#[test]
fn entra_client_credentials_flow_fetches_a_token_once() {
    let c = {
        let mut c = ctx("dir-entra2");
        c.secrets = Arc::new(|s: &str| s.replace("{{secret:ENTRA_SECRET}}", "client-secret-value"));
        c
    };
    let srv = FakeServer::with(|r| {
        if r.method == "POST" && r.path.ends_with("/oauth2/v2.0/token") {
            (200, "application/json".into(), json!({"access_token": "tok-from-flow", "expires_in": 3599}).to_string().into_bytes(), vec![])
        } else {
            (200, "application/json".into(), json!({"value": []}).to_string().into_bytes(), vec![])
        }
    });
    let t = one(json!({"providers": {"c": {"kind": "entra", "tenant": "t-ark-test-1", "client_id": "app-1", "client_secret": "{{secret:ENTRA_SECRET}}", "api_base": srv.url, "login_base": srv.url}}}));
    body(&t.call(&c, json!({"kind": "user", "query": "a"})));
    body(&t.call(&c, json!({"kind": "group", "query": "a"})));
    let reqs = srv.requests();
    let token_calls = reqs.iter().filter(|r| r.path.contains("oauth2")).count();
    assert_eq!(token_calls, 1, "the token is cached");
    assert!(reqs[0].body.contains("grant_type=client_credentials") && reqs[0].body.contains("client_secret=client-secret-value"));
    assert_eq!(reqs[1].header("Authorization").as_deref(), Some("Bearer tok-from-flow"));
}

#[test]
fn okta_uses_ssws_and_resolves_names_to_ids() {
    let mut c = ctx("dir-okta");
    c.secrets = Arc::new(|s: &str| s.replace("{{secret:OKTA}}", "00abcSECRETtoken"));
    let srv = FakeServer::with(|r| {
        let ok = |v: Value| (200, "application/json".to_string(), v.to_string().into_bytes(), vec![]);
        let p = r.path.split('?').next().unwrap().to_string();
        match p.as_str() {
            "/api/v1/users" => ok(json!([{"id": "00u1aaaaaaaaaaaaaaaa", "status": "ACTIVE", "profile": {"login": "ann@corp.example", "email": "ann@corp.example", "firstName": "Ann", "lastName": "Lee"}}])),
            "/api/v1/groups" => ok(json!([{"id": "00g1bbbbbbbbbbbbbbbb", "type": "OKTA_GROUP", "profile": {"name": "VPN", "description": "remote access"}}])),
            "/api/v1/groups/00g1bbbbbbbbbbbbbbbb/users" => ok(json!([{"id": "00u1aaaaaaaaaaaaaaaa", "status": "SUSPENDED", "profile": {"login": "ann@corp.example", "firstName": "Ann", "lastName": "Lee"}}])),
            "/api/v1/users/00u1aaaaaaaaaaaaaaaa/groups" => ok(json!([{"id": "00g1bbbbbbbbbbbbbbbb", "profile": {"name": "VPN"}}])),
            _ => (404, "application/json".into(), br#"{"errorSummary":"Not found: Resource not found"}"#.to_vec(), vec![]),
        }
    });
    let t = one(json!({"providers": {"sso": {"kind": "okta", "org_url": srv.url, "token": "{{secret:OKTA}}"}}}));
    let v = body(&t.call(&c, json!({"kind": "user", "query": "ann"})));
    assert_eq!(v["results"][0]["name"], "Ann Lee");
    assert_eq!(v["results"][0]["enabled"], true);
    assert_eq!(srv.requests()[0].header("Authorization").as_deref(), Some("SSWS 00abcSECRETtoken"));
    let v = body(&t.call(&c, json!({"kind": "members", "query": "VPN"})));
    assert_eq!(v["results"][0]["members"][0]["enabled"], false, "SUSPENDED is not enabled");
    let v = body(&t.call(&c, json!({"kind": "groups_of", "query": "ann@corp.example"})));
    assert_eq!(v["results"][0]["groups"][0]["name"], "VPN");
    // The query never becomes a path segment: it is one encoded query value.
    let _ = t.call(&c, json!({"kind": "members", "query": "../../users"}));
    let reqs = srv.requests();
    assert!(reqs.iter().all(|r| !r.path.contains("../")), "no traversal in any request");
    assert!(reqs.iter().any(|r| r.path.starts_with("/api/v1/groups?q=") && r.path.contains("..%2F..%2Fusers")));
}

#[test]
fn there_is_no_way_to_change_anything() {
    let t = one(json!({"providers": {"sso": {"kind": "okta", "org_url": "http://127.0.0.1:1", "token": "t"}}}));
    let spec = t.spec();
    let kinds = spec.input_schema["properties"]["kind"]["enum"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(kinds, ["user", "group", "members", "groups_of"]);
    assert!(spec.input_schema["properties"].as_object().unwrap().keys().all(|k| matches!(k.as_str(), "provider" | "kind" | "query" | "limit")), "no password / attribute / action parameters");
    let c = ctx("dir-ro");
    for bad in ["create", "reset_password", "disable", "delete"] {
        assert!(t.call(&c, json!({"kind": bad, "query": "x"})).is_error);
    }
    assert!(t.effects(&c, &json!({"kind": "user", "query": "x"})).iter().all(|e| matches!(e, Effect::Net { payload, .. } if payload.is_empty())));
}

#[test]
fn config_validation() {
    assert!(tools(json!({})).unwrap().is_empty());
    assert!(DirectoryConfig::from_value(json!({"providers": {"a": {"kind": "ad", "uri": "ldap://x"}}})).unwrap_err().contains("base_dn"));
    assert!(DirectoryConfig::from_value(json!({"providers": {"a": {"kind": "okta", "org_url": "https://x"}}})).unwrap_err().contains("token"));
    assert!(DirectoryConfig::from_value(json!({"providers": {"a": {"kind": "saml"}}})).unwrap_err().contains("saml"));
    assert!(DirectoryConfig::from_value(json!({"providers": {"a": {"kind": "entra"}}})).unwrap_err().contains("tenant"));
    let c = ctx("dir-cfg");
    let t = one(json!({"providers": {"a": {"kind": "okta", "org_url": "http://127.0.0.1:1", "token": "{{secret:NOPE}}"}, "b": {"kind": "okta", "org_url": "http://127.0.0.1:1", "token": "x"}}}));
    assert!(t.call(&c, json!({"kind": "user", "query": "x"})).content.contains("name a `provider`"));
    assert!(t.call(&c, json!({"provider": "a", "kind": "user", "query": "x"})).content.contains("NOPE"));
}
