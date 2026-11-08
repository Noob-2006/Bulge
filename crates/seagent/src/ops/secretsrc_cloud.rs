//! Enterprise secret managers for `secretsrc` (ent-081): HashiCorp Vault natively over HTTP,
//! and AWS Secrets Manager / GCP Secret Manager / Azure Key Vault through their official CLIs —
//! one mapped interface for all four:
//!
//! ```toml
//! [vault]                        # HashiCorp Vault, KV v2 (full implementation)
//! enabled = true
//! addr = "https://vault.corp:8200"   # else $VAULT_ADDR
//! namespace = "team-a"               # Enterprise namespaces; else $VAULT_NAMESPACE
//! mount = "secret"                   # KV v2 mount
//! auth = "token"                     # "token" ($VAULT_TOKEN / token_env) or "approle"
//! role_id = "…"                      # approle: or role_id_env (default VAULT_ROLE_ID)
//! secret_id_env = "VAULT_SECRET_ID"  # approle: the secret id never sits in the file
//! env = { OPENAI_API_KEY = "seagent/providers#openai", ANTHROPIC_API_KEY = "seagent/providers#anthropic" }
//!
//! [aws]    env = { NAME = "secret-id#json-key" }  region = "eu-west-1"      # aws CLI
//! [gcp]    env = { NAME = "secret[@version]" }    project = "my-project"     # gcloud CLI
//! [azure]  env = { NAME = "secret-name" }         vault_name = "corp-kv"     # az CLI
//! ```
//!
//! Vault traffic goes through `seagent_net::http::builder()`, so `[network]` proxy / NO_PROXY / CA
//! (an internal PKI) apply. The cloud CLIs use whatever auth they already have (instance role,
//! workload identity, `az login`); seagent never handles their long-lived credentials.

use super::{base_env, cache_lookup, cache_store, f, fingerprint, run_cli, s, which, ErrorKind, Fetch};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

/// `NAME = "path#field"` bindings (field defaults to `value`), env names validated.
pub fn bindings(c: &toml::Table) -> (BTreeMap<String, String>, Vec<String>) {
    let mut ok = BTreeMap::new();
    let mut warn = vec![];
    for (k, v) in c.get("env").and_then(|v| v.as_table()).cloned().unwrap_or_default() {
        match v.as_str().map(str::trim) {
            Some(r) if super::valid_env_name(&k) && !r.is_empty() => {
                ok.insert(k, r.to_string());
            }
            _ => warn.push(format!("env.{k}: needs a valid variable name and a non-empty reference")),
        }
    }
    (ok, warn)
}

fn split_ref(r: &str) -> (&str, &str) {
    r.split_once('#').unwrap_or((r, "value"))
}

// ───────────────────────── HashiCorp Vault ─────────────────────────

fn vault_addr(c: &toml::Table, env: &HashMap<String, String>) -> String {
    let a = s(c, "addr", "");
    let a = if a.is_empty() { env.get("VAULT_ADDR").cloned().unwrap_or_default() } else { a };
    a.trim().trim_end_matches('/').to_string()
}

fn http_err(e: &str) -> ErrorKind {
    let l = e.to_lowercase();
    if l.contains("offline mode") || l.contains("connect") || l.contains("resolve") || l.contains("dns") || l.contains("certificate") || l.contains("tls") {
        ErrorKind::Network
    } else if l.contains("timed out") || l.contains("timeout") {
        ErrorKind::Timeout
    } else {
        ErrorKind::Internal
    }
}

/// One Vault HTTP call: `(status, json body)`.
fn vault_call(method: &str, url: &str, token: Option<&str>, ns: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
    let agent: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).max_redirects(0).timeout_global(Some(Duration::from_secs(15))).build().into();
    let with = |mut r: ureq::RequestBuilder<ureq::typestate::WithoutBody>| {
        if let Some(t) = token {
            r = r.header("X-Vault-Token", t);
        }
        if !ns.is_empty() {
            r = r.header("X-Vault-Namespace", ns);
        }
        r
    };
    let resp = match (method, body) {
        ("GET", _) => with(agent.get(url)).call(),
        (_, b) => {
            let mut r = agent.post(url).header("content-type", "application/json");
            if let Some(t) = token {
                r = r.header("X-Vault-Token", t);
            }
            if !ns.is_empty() {
                r = r.header("X-Vault-Namespace", ns);
            }
            r.send(serde_json::to_vec(b.unwrap_or(&json!({}))).unwrap_or_default())
        }
    };
    let mut resp = resp.map_err(|e| format!("vault {url}: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

fn vault_errors(v: &Value) -> String {
    v["errors"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; ")).filter(|s| !s.is_empty()).unwrap_or_else(|| "no detail".into())
}

/// A client token: `auth = "token"` reads `token_env` (default `VAULT_TOKEN`); `auth = "approle"`
/// logs in with `role_id` + the secret id from `secret_id_env`.
pub fn vault_token(c: &toml::Table, env: &HashMap<String, String>) -> Result<String, (String, ErrorKind)> {
    let addr = vault_addr(c, env);
    let ns = s(c, "namespace", env.get("VAULT_NAMESPACE").map(String::as_str).unwrap_or(""));
    match s(c, "auth", "token").as_str() {
        "approle" => {
            let role = s(c, "role_id", "");
            let role = if role.is_empty() { env.get(&s(c, "role_id_env", "VAULT_ROLE_ID")).cloned().unwrap_or_default() } else { role };
            let sid = env.get(&s(c, "secret_id_env", "VAULT_SECRET_ID")).cloned().unwrap_or_default();
            if role.trim().is_empty() || sid.trim().is_empty() {
                return Err(("vault approle: role_id and the secret id (secret_id_env) are both needed".into(), ErrorKind::NotConfigured));
            }
            let url = format!("{addr}/v1/auth/{}/login", s(c, "approle_mount", "approle"));
            let (st, v) = vault_call("POST", &url, None, &ns, Some(&json!({"role_id": role.trim(), "secret_id": sid.trim()}))).map_err(|e| {
                let k = http_err(&e);
                (e, k)
            })?;
            match (st, v["auth"]["client_token"].as_str()) {
                (200, Some(t)) => Ok(t.to_string()),
                (400 | 401 | 403, _) => Err((format!("vault approle login refused ({st}): {}", vault_errors(&v)), ErrorKind::AuthFailed)),
                _ => Err((format!("vault approle login failed ({st}): {}", vault_errors(&v)), ErrorKind::Internal)),
            }
        }
        "token" => env.get(&s(c, "token_env", "VAULT_TOKEN")).map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).ok_or_else(|| (format!("vault: no token in ${}", s(c, "token_env", "VAULT_TOKEN")), ErrorKind::NotConfigured)),
        other => Err((format!("vault.auth `{other}`: expected token or approle"), ErrorKind::NotConfigured)),
    }
}

/// Read one KV v2 secret's `data` map.
pub fn vault_read(c: &toml::Table, env: &HashMap<String, String>, token: &str, path: &str) -> Result<serde_json::Map<String, Value>, (String, ErrorKind)> {
    let addr = vault_addr(c, env);
    let ns = s(c, "namespace", env.get("VAULT_NAMESPACE").map(String::as_str).unwrap_or(""));
    let url = format!("{addr}/v1/{}/data/{}", s(c, "mount", "secret").trim_matches('/'), path.trim_matches('/'));
    let (st, v) = vault_call("GET", &url, Some(token), &ns, None).map_err(|e| {
        let k = http_err(&e);
        (e, k)
    })?;
    match st {
        200 => v["data"]["data"].as_object().cloned().ok_or_else(|| (format!("vault {path}: not a KV v2 secret"), ErrorKind::Internal)),
        401 | 403 => Err((format!("vault {path}: permission denied ({st}): {}", vault_errors(&v)), ErrorKind::AuthFailed)),
        404 => Err((format!("vault {path}: no such secret"), ErrorKind::EmptyValue)),
        _ => Err((format!("vault {path}: HTTP {st}: {}", vault_errors(&v)), ErrorKind::Internal)),
    }
}

/// Write (create a new version of) one KV v2 secret — used by key rotation.
pub fn vault_write(c: &toml::Table, env: &HashMap<String, String>, path: &str, data: &serde_json::Map<String, Value>) -> Result<u64, String> {
    let token = vault_token(c, env).map_err(|e| e.0)?;
    let addr = vault_addr(c, env);
    let ns = s(c, "namespace", env.get("VAULT_NAMESPACE").map(String::as_str).unwrap_or(""));
    let url = format!("{addr}/v1/{}/data/{}", s(c, "mount", "secret").trim_matches('/'), path.trim_matches('/'));
    let (st, v) = vault_call("POST", &url, Some(&token), &ns, Some(&json!({"data": data})))?;
    if st == 200 || st == 204 {
        Ok(v["data"]["version"].as_u64().unwrap_or(0))
    } else {
        Err(format!("vault write {path}: HTTP {st}: {}", vault_errors(&v)))
    }
}

pub fn fetch_vault(c: &toml::Table, env: &HashMap<String, String>, data: &Path, use_cache: bool) -> Fetch {
    let mut r = Fetch::default();
    let (refs, warn) = bindings(c);
    r.warnings = warn;
    if refs.is_empty() {
        return r.fail("vault.enabled is true but vault.env has no bindings. Add one with `seagent secrets vault set NAME path#field`.", ErrorKind::NotConfigured);
    }
    if vault_addr(c, env).is_empty() {
        return r.fail("vault: no address (vault.addr or $VAULT_ADDR)", ErrorKind::NotConfigured);
    }
    let ttl = f(c, "cache_ttl_seconds", 300.0);
    let key = format!("{}|{}|{}", fingerprint(&vault_addr(c, env)), fingerprint(&format!("{}{}", s(c, "auth", "token"), env.get(&s(c, "token_env", "VAULT_TOKEN")).cloned().unwrap_or_default())), fingerprint(&format!("{refs:?}")));
    if use_cache {
        if let Some(v) = cache_lookup(data, "vault_cache.json", &key, ttl) {
            r.secrets = v;
            return r;
        }
    }
    let token = match vault_token(c, env) {
        Ok(t) => t,
        Err((e, k)) => return r.fail(e, k),
    };
    // One read per path, however many fields are bound from it.
    let mut by_path: BTreeMap<&str, Vec<(&String, &str)>> = BTreeMap::new();
    for (n, rf) in &refs {
        let (p, field) = split_ref(rf);
        by_path.entry(p).or_default().push((n, field));
    }
    let mut first_err = None;
    for (p, fields) in by_path {
        match vault_read(c, env, &token, p) {
            Ok(m) => {
                for (n, field) in fields {
                    match m.get(field).and_then(|v| v.as_str().map(String::from).or_else(|| (!v.is_null()).then(|| v.to_string()))) {
                        Some(v) if !v.is_empty() => {
                            r.secrets.insert(n.clone(), v);
                        }
                        _ => r.warnings.push(format!("{n}: vault {p} has no field `{field}`")),
                    }
                }
            }
            Err((e, k)) => {
                r.warnings.push(e.clone());
                first_err.get_or_insert((e, k));
            }
        }
    }
    if use_cache && first_err.is_none() && !r.secrets.is_empty() {
        cache_store(data, "vault_cache.json", &key, &r.secrets, ttl);
    }
    if r.secrets.is_empty() {
        if let Some((e, k)) = first_err {
            return r.fail(format!("no Vault reference resolved: {e}"), k);
        }
    }
    r
}

// ───────────────────────── cloud CLIs ─────────────────────────

/// `(binary, argv for one reference, label)` per cloud.
fn cloud_argv(cloud: &str, c: &toml::Table, rf: &str) -> Result<(String, Vec<String>), String> {
    let (id, _) = split_ref(rf);
    Ok(match cloud {
        "aws" => {
            let mut a = vec!["secretsmanager".into(), "get-secret-value".into(), "--secret-id".into(), id.into(), "--query".into(), "SecretString".into(), "--output".into(), "text".into()];
            let region = s(c, "region", "");
            if !region.is_empty() {
                a.extend(["--region".into(), region]);
            }
            (s(c, "binary_path", "aws"), a)
        }
        "gcp" => {
            let (name, ver) = id.split_once('@').unwrap_or((id, "latest"));
            let mut a = vec!["secrets".into(), "versions".into(), "access".into(), ver.into(), format!("--secret={name}")];
            let project = s(c, "project", "");
            if !project.is_empty() {
                a.push(format!("--project={project}"));
            }
            (s(c, "binary_path", "gcloud"), a)
        }
        "azure" => {
            let v = s(c, "vault_name", "");
            if v.is_empty() {
                return Err("azure.vault_name is not set".into());
            }
            (s(c, "binary_path", "az"), vec!["keyvault".into(), "secret".into(), "show".into(), "--vault-name".into(), v, "--name".into(), id.into(), "--query".into(), "value".into(), "-o".into(), "tsv".into()])
        }
        other => return Err(format!("unknown cloud {other}")),
    })
}

/// Env the cloud CLIs need for their own auth (profiles, workload identity), nothing else.
const CLOUD_ENV: &[&str] = &[
    "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "CLOUDSDK_CONFIG", "CLOUDSDK_CORE_PROJECT", "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CONFIG_DIR", "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE", "IDENTITY_ENDPOINT", "IDENTITY_HEADER",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE", "SSL_CERT_FILE",
];

pub fn fetch_cloud(cloud: &str, c: &toml::Table, env: &HashMap<String, String>, data: &Path, use_cache: bool) -> Fetch {
    let mut r = Fetch::default();
    let (refs, warn) = bindings(c);
    r.warnings = warn;
    if refs.is_empty() {
        return r.fail(format!("{cloud}.enabled is true but {cloud}.env has no bindings. Add one with `seagent secrets {cloud} set NAME <secret>`."), ErrorKind::NotConfigured);
    }
    let ttl = f(c, "cache_ttl_seconds", 300.0);
    let file = format!("{cloud}_cache.json");
    let key = fingerprint(&format!("{c:?}"));
    if use_cache {
        if let Some(v) = cache_lookup(data, &file, &key, ttl) {
            r.secrets = v;
            return r;
        }
    }
    let cli_env = base_env(env, CLOUD_ENV);
    let mut first_err = None;
    for (n, rf) in &refs {
        let (bin, args) = match cloud_argv(cloud, c, rf) {
            Ok(x) => x,
            Err(e) => return r.fail(e, ErrorKind::NotConfigured),
        };
        let Some(path) = (if bin.contains('/') { Some(std::path::PathBuf::from(&bin)).filter(|p| p.is_file()) } else { which(&bin, env) }) else {
            return r.fail(format!("{cloud}: the `{bin}` CLI was not found on PATH (or set {cloud}.binary_path)"), ErrorKind::BinaryMissing);
        };
        r.binary = Some(path.clone());
        let mut argv = vec![path.display().to_string()];
        argv.extend(args);
        match run_cli(&argv, &cli_env, Duration::from_secs(30), &bin) {
            Ok(o) if o.code == 0 => {
                let raw = o.stdout.trim_end_matches(['\n', '\r']).to_string();
                // `secret#key` picks one key out of a JSON secret (the AWS convention).
                let val = match split_ref(rf) {
                    (_, field) if rf.contains('#') => serde_json::from_str::<Value>(&raw).ok().and_then(|v| v.get(field).map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string()))),
                    _ => Some(raw),
                };
                match val.filter(|v| !v.is_empty()) {
                    Some(v) => {
                        r.secrets.insert(n.clone(), v);
                    }
                    None => r.warnings.push(format!("{n}: {rf} returned an empty value")),
                }
            }
            Ok(o) => {
                let e = format!("{n}: {bin} exited {}: {}", o.code, o.stderr.lines().last().unwrap_or("").trim());
                let l = e.to_lowercase();
                let k = if l.contains("accessdenied") || l.contains("permission") || l.contains("unauthor") || l.contains("forbidden") || l.contains("login") || l.contains("credentials") { ErrorKind::AuthFailed } else { ErrorKind::Internal };
                r.warnings.push(e.clone());
                first_err.get_or_insert((e, k));
            }
            Err(e) => {
                let k = if e.contains("timed out") { ErrorKind::Timeout } else { ErrorKind::BinaryMissing };
                r.warnings.push(e.clone());
                first_err.get_or_insert((e, k));
            }
        }
    }
    if use_cache && first_err.is_none() && !r.secrets.is_empty() {
        cache_store(data, &file, &key, &r.secrets, ttl);
    }
    if r.secrets.is_empty() {
        if let Some((e, k)) = first_err {
            return r.fail(e, k);
        }
    }
    r
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use seagent_net::httpd::{Opts, Request, Response, Server};
    use std::sync::{Arc, Mutex};

    /// A fake Vault: KV v2 under `secret/`, a token `t-root`, AppRole `role-1`/`sid-1`, and
    /// writes that bump the version. Returns the server and the request log.
    pub type FakeVault = (Server, Arc<Mutex<Vec<String>>>, Arc<Mutex<serde_json::Map<String, Value>>>);

    pub fn fake_vault() -> FakeVault {
        let log = Arc::new(Mutex::new(vec![]));
        let store = Arc::new(Mutex::new(serde_json::Map::new()));
        store.lock().unwrap().insert("seagent/providers".into(), json!({"openai": "sk-from-vault", "anthropic": "ant-from-vault"}));
        let (l, st) = (log.clone(), store.clone());
        let h = Arc::new(move |r: Request| {
            l.lock().unwrap().push(format!("{} {} ns={}", r.method, r.path, r.header("x-vault-namespace").unwrap_or("")));
            if r.path == "/v1/auth/approle/login" {
                let b: Value = serde_json::from_slice(&r.body).unwrap_or_default();
                return if b["role_id"] == "role-1" && b["secret_id"] == "sid-1" { Response::json(200, &json!({"auth": {"client_token": "t-approle"}}).to_string()) } else { Response::json(400, &json!({"errors": ["invalid role or secret ID"]}).to_string()) };
            }
            if !matches!(r.header("x-vault-token"), Some("t-root") | Some("t-approle")) {
                return Response::json(403, &json!({"errors": ["permission denied"]}).to_string());
            }
            let Some(path) = r.path.strip_prefix("/v1/secret/data/") else { return Response::json(404, &json!({"errors": []}).to_string()) };
            let mut s = st.lock().unwrap();
            if r.method == "POST" {
                let b: Value = serde_json::from_slice(&r.body).unwrap_or_default();
                s.insert(path.into(), b["data"].clone());
                return Response::json(200, &json!({"data": {"version": 2}}).to_string());
            }
            match s.get(path) {
                Some(d) => Response::json(200, &json!({"data": {"data": d, "metadata": {"version": 1}}}).to_string()),
                None => Response::json(404, &json!({"errors": []}).to_string()),
            }
        });
        (Server::bind("127.0.0.1:0", Opts::default(), h).unwrap(), log, store)
    }

    fn table(src: &str) -> toml::Table {
        src.parse().unwrap()
    }

    #[test]
    fn vault_kv2_with_token_and_approle() {
        let (srv, log, _) = fake_vault();
        let data = seagent_core::tmp::TempDir::new("seagent-tmp-vaultsrc");
        let addr = format!("http://{}", srv.local_addr());
        let c = table(&format!("addr = {addr:?}\nnamespace = \"team-a\"\nenv = {{ OPENAI_API_KEY = \"seagent/providers#openai\", ANTHROPIC_API_KEY = \"seagent/providers#anthropic\", MISSING = \"seagent/providers#nope\" }}"));
        let mut env = HashMap::from([("VAULT_TOKEN".to_string(), "t-root".to_string())]);
        let r = fetch_vault(&c, &env, data.path(), true);
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(r.secrets.get("OPENAI_API_KEY").map(String::as_str), Some("sk-from-vault"));
        assert_eq!(r.secrets.get("ANTHROPIC_API_KEY").map(String::as_str), Some("ant-from-vault"));
        assert!(r.warnings.iter().any(|w| w.contains("no field `nope`")));
        assert_eq!(log.lock().unwrap().iter().filter(|l| l.starts_with("GET")).count(), 1, "one read per path");
        assert!(log.lock().unwrap()[0].ends_with("ns=team-a"));
        // Cached: no second request.
        let n = log.lock().unwrap().len();
        assert_eq!(fetch_vault(&c, &env, data.path(), true).secrets.len(), 2);
        assert_eq!(log.lock().unwrap().len(), n);
        // A bad token is an auth failure.
        env.insert("VAULT_TOKEN".into(), "wrong".into());
        let r = fetch_vault(&c, &env, data.path(), false);
        assert_eq!(r.error.unwrap().1, ErrorKind::AuthFailed);
        // AppRole: login, then read with the client token.
        let ar = table(&format!("addr = {addr:?}\nauth = \"approle\"\nrole_id = \"role-1\"\nenv = {{ K = \"seagent/providers#openai\" }}"));
        let env = HashMap::from([("VAULT_SECRET_ID".to_string(), "sid-1".to_string())]);
        assert_eq!(fetch_vault(&ar, &env, data.path(), false).secrets["K"], "sk-from-vault");
        let bad = HashMap::from([("VAULT_SECRET_ID".to_string(), "nope".to_string())]);
        assert_eq!(fetch_vault(&ar, &bad, data.path(), false).error.unwrap().1, ErrorKind::AuthFailed);
        // Rotation writes a new version.
        let mut m = serde_json::Map::new();
        m.insert("openai".into(), json!("sk-rotated"));
        let env = HashMap::from([("VAULT_TOKEN".to_string(), "t-root".to_string())]);
        assert_eq!(vault_write(&c, &env, "seagent/providers", &m).unwrap(), 2);
        assert_eq!(fetch_vault(&c, &env, data.path(), false).secrets["OPENAI_API_KEY"], "sk-rotated");
    }

    // Unix only: the fake aws/gcloud/az are `#!/bin/sh` scripts.
    #[cfg(unix)]
    #[test]
    fn cloud_clis_share_the_interface() {
        use std::os::unix::fs::PermissionsExt;
        let d = seagent_core::tmp::TempDir::new("seagent-tmp-cloudsrc");
        let bin = d.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        // Fake CLIs that echo what they were asked for, the way the real ones print values.
        for (name, body) in [
            ("aws", "#!/bin/sh\n[ \"$1 $2\" = \"secretsmanager get-secret-value\" ] || exit 9\necho '{\"api_key\":\"aws-'\"$4\"'\"}'\n"),
            ("gcloud", "#!/bin/sh\necho \"gcp-$4-$5\"\n"),
            ("az", "#!/bin/sh\n[ \"$5\" = corp-kv ] || { echo 'ERROR: Forbidden' >&2; exit 1; }\necho \"az-$7\"\n"),
        ] {
            let p = bin.join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let env = HashMap::from([("PATH".to_string(), bin.display().to_string())]);
        let r = fetch_cloud("aws", &table("region = \"eu-west-1\"\nenv = { OPENAI_API_KEY = \"prod/openai#api_key\" }"), &env, d.path(), false);
        assert_eq!(r.secrets["OPENAI_API_KEY"], "aws-prod/openai", "{r:?}");
        let r = fetch_cloud("gcp", &table("project = \"p1\"\nenv = { K = \"openai-key@3\" }"), &env, d.path(), false);
        assert_eq!(r.secrets["K"], "gcp-3---secret=openai-key", "{r:?}");
        let r = fetch_cloud("azure", &table("vault_name = \"corp-kv\"\nenv = { K = \"openai\" }"), &env, d.path(), false);
        assert_eq!(r.secrets["K"], "az-openai", "{r:?}");
        let r = fetch_cloud("azure", &table("vault_name = \"other\"\nenv = { K = \"openai\" }"), &env, d.path(), false);
        assert_eq!(r.error.unwrap().1, ErrorKind::AuthFailed);
        let r = fetch_cloud("azure", &table("env = { K = \"x\" }"), &env, d.path(), false);
        assert_eq!(r.error.unwrap().1, ErrorKind::NotConfigured);
        let none = HashMap::from([("PATH".to_string(), "/nonexistent".to_string())]);
        assert_eq!(fetch_cloud("aws", &table("env = { K = \"x\" }"), &none, d.path(), false).error.unwrap().1, ErrorKind::BinaryMissing);
    }
}
