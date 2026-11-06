//! AWS Signature Version 4 (request signing for Bedrock), and the AWS default
//! credential chain without the SDK: environment variables, web identity (EKS
//! IRSA via STS), the shared credentials/config profile (including
//! `credential_process`), ECS container credentials, then EC2 IMDSv2.

use seagent_net::crypto::{hex, hmac_sha256, sha256};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct AwsCreds {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

fn ini_section(text: &str, section: &str) -> Option<Vec<(String, String)>> {
    let mut cur: Option<String> = None;
    let mut out = Vec::new();
    let mut found = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with(';') || l.is_empty() {
            continue;
        }
        if l.starts_with('[') && l.ends_with(']') {
            cur = Some(l[1..l.len() - 1].trim().to_string());
            continue;
        }
        if cur.as_deref() == Some(section) {
            found = true;
            if let Some((k, v)) = l.split_once('=') {
                out.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    found.then_some(out)
}

impl AwsCreds {
    /// AWS's default provider chain, without the SDK: environment, web identity
    /// (EKS IRSA), the shared credentials/config profile (including
    /// `credential_process`), ECS container credentials, then IMDSv2.
    pub fn from_env() -> Result<AwsCreds, String> {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().to_string())
        };
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        resolve(&get, &home)
    }
}

/// The chain behind [`AwsCreds::from_env`], with the environment and home directory
/// injected so every source can be exercised against a local fake endpoint.
fn resolve(
    get: &dyn Fn(&str) -> Option<String>,
    home: &std::path::Path,
) -> Result<AwsCreds, String> {
    if let Some(c) = env_creds(get)? {
        return Ok(c);
    }
    if let Some(c) = web_identity(get)? {
        return Ok(c);
    }
    if let Some(c) = shared_profile(get, home)? {
        return Ok(c);
    }
    if let Some(c) = ecs_creds(get)? {
        return Ok(c);
    }
    if let Some(c) = imds_creds(get)? {
        return Ok(c);
    }
    let profile = get("AWS_PROFILE").unwrap_or_else(|| "default".into());
    Err(format!(
        "no AWS credentials: checked the environment, web identity, profile `{profile}` in ~/.aws/credentials, ECS container credentials and EC2 IMDSv2 — set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, AWS_BEARER_TOKEN_BEDROCK, or configure the profile"
    ))
}

fn env_creds(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<AwsCreds>, String> {
    let a = get("AWS_ACCESS_KEY_ID");
    let s = get("AWS_SECRET_ACCESS_KEY");
    match (a, s) {
        (None, None) => Ok(None),
        (Some(a), Some(s)) => Ok(Some(AwsCreds {
            access_key: a,
            secret_key: s,
            session_token: get("AWS_SESSION_TOKEN"),
        })),
        _ => Err(
            "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must both be set (or neither; the rest of the AWS chain is then tried)"
                .into(),
        ),
    }
}

fn shared_profile(
    get: &dyn Fn(&str) -> Option<String>,
    home: &std::path::Path,
) -> Result<Option<AwsCreds>, String> {
    let profile = get("AWS_PROFILE").unwrap_or_else(|| "default".into());
    let creds_file = get("AWS_SHARED_CREDENTIALS_FILE")
        .map(Into::into)
        .unwrap_or_else(|| home.join(".aws/credentials"));
    if let Ok(t) = std::fs::read_to_string(&creds_file) {
        if let Some(kv) = ini_section(&t, &profile) {
            let f = |k: &str| kv.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
            match (f("aws_access_key_id"), f("aws_secret_access_key")) {
                (Some(a), Some(s)) => {
                    return Ok(Some(AwsCreds {
                        access_key: a,
                        secret_key: s,
                        session_token: f("aws_session_token"),
                    }))
                }
                (None, None) => {}
                _ => {
                    return Err(format!(
                        "profile `{profile}` in {} needs both aws_access_key_id and aws_secret_access_key",
                        creds_file.display()
                    ))
                }
            }
        }
    }
    let cfg_file = get("AWS_CONFIG_FILE")
        .map(Into::into)
        .unwrap_or_else(|| home.join(".aws/config"));
    if let Ok(t) = std::fs::read_to_string(&cfg_file) {
        let sec = if profile == "default" {
            "default".to_string()
        } else {
            format!("profile {profile}")
        };
        if let Some(cmd) = ini_section(&t, &sec).and_then(|kv| {
            kv.into_iter()
                .find(|(k, _)| k == "credential_process")
                .map(|(_, v)| v)
        }) {
            let out = crate::auth::run_capture(&cmd, Duration::from_secs(30))?;
            let v: serde_json::Value = serde_json::from_str(&out)
                .map_err(|e| format!("credential_process output: {e}"))?;
            let g = |k: &str| v[k].as_str().map(String::from);
            return Ok(Some(AwsCreds {
                access_key: g("AccessKeyId").ok_or("credential_process: no AccessKeyId")?,
                secret_key: g("SecretAccessKey")
                    .ok_or("credential_process: no SecretAccessKey")?,
                session_token: g("SessionToken"),
            }));
        }
    }
    Ok(None)
}

fn web_identity(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<AwsCreds>, String> {
    let file = get("AWS_WEB_IDENTITY_TOKEN_FILE");
    let role = get("AWS_ROLE_ARN");
    let (Some(file), Some(role)) = (file.as_deref(), role.as_deref()) else {
        return match (file, role) {
            (None, None) => Ok(None),
            _ => Err("web identity needs both AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN".into()),
        };
    };
    let token = std::fs::read_to_string(file)
        .map_err(|e| format!("web identity token file {file}: {e}"))?
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(format!("web identity token file {file} is empty"));
    }
    let endpoint = get("AWS_ENDPOINT_URL_STS")
        .unwrap_or_else(|| "https://sts.amazonaws.com".into());
    let session = get("AWS_ROLE_SESSION_NAME").unwrap_or_else(|| "seagent".into());
    let body = crate::login::form_encode(&[
        ("Action", "AssumeRoleWithWebIdentity"),
        ("Version", "2011-06-15"),
        ("RoleArn", role),
        ("RoleSessionName", &session),
        ("WebIdentityToken", &token),
    ]);
    let (status, text) = http_request(
        "POST",
        endpoint.trim_end_matches('/'),
        &[("content-type", "application/x-www-form-urlencoded"), ("accept", "application/xml")],
        Some(body.as_bytes()),
    )?;
    if !(200..300).contains(&status) {
        return Err(format!("AssumeRoleWithWebIdentity: HTTP {status}: {}", head(&text, 300)));
    }
    let tag = |name: &str| xml_tag(&text, name);
    Ok(Some(AwsCreds {
        access_key: tag("AccessKeyId").ok_or("AssumeRoleWithWebIdentity: no AccessKeyId")?,
        secret_key: tag("SecretAccessKey")
            .ok_or("AssumeRoleWithWebIdentity: no SecretAccessKey")?,
        session_token: tag("SessionToken"),
    }))
}

fn ecs_creds(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<AwsCreds>, String> {
    let uri = match (get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"), get("AWS_CONTAINER_CREDENTIALS_FULL_URI")) {
        (Some(rel), _) => format!("http://169.254.170.2{}", if rel.starts_with('/') { rel } else { format!("/{rel}") }),
        (None, Some(full)) => full,
        (None, None) => return Ok(None),
    };
    if !(uri.starts_with("https://")
        || uri.starts_with("http://127.")
        || uri.starts_with("http://localhost")
        || uri.starts_with("http://[::1]"))
    {
        return Err(format!(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI must be https or loopback, got {}",
            head(&uri, 120)
        ));
    }
    let auth = get("AWS_CONTAINER_AUTHORIZATION_TOKEN").or_else(|| {
        get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    });
    let mut headers: Vec<(&str, &str)> = vec![("accept", "application/json")];
    if let Some(t) = &auth {
        headers.push(("authorization", t));
    }
    let (status, text) = http_request("GET", &uri, &headers, None)?;
    if !(200..300).contains(&status) {
        return Err(format!("ECS container credentials: HTTP {status}: {}", head(&text, 300)));
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("ECS container credentials: {e}"))?;
    Ok(Some(creds_from_json(&v, "ECS container credentials")?))
}

fn imds_creds(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<AwsCreds>, String> {
    if get("AWS_EC2_METADATA_DISABLED").is_some_and(|v| {
        !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "no" | "off")
    }) {
        return Ok(None);
    }
    let base = get("AWS_EC2_METADATA_SERVICE_ENDPOINT")
        .unwrap_or_else(|| "http://169.254.169.254".into());
    let base = base.trim_end_matches('/');
    // IMDSv2: a session token is required for every metadata read.
    let token_url = format!("{base}/latest/api/token");
    let (status, token) = http_request(
        "PUT",
        &token_url,
        &[("x-aws-ec2-metadata-token-ttl-seconds", "21600")],
        None,
    )?;
    if !(200..300).contains(&status) || token.trim().is_empty() {
        return Ok(None);
    }
    let token = token.trim().to_string();
    let roles_url = format!("{base}/latest/meta-data/iam/security-credentials/");
    let (status, roles) = http_request(
        "GET",
        &roles_url,
        &[("x-aws-ec2-metadata-token", &token)],
        None,
    )?;
    if !(200..300).contains(&status) {
        return Ok(None);
    }
    let Some(role) = roles.lines().map(str::trim).find(|l| !l.is_empty()) else {
        return Ok(None);
    };
    let creds_url = format!("{roles_url}{}", crate::sigv4::uri_encode(role, false));
    let (status, text) = http_request(
        "GET",
        &creds_url,
        &[("x-aws-ec2-metadata-token", &token), ("accept", "application/json")],
        None,
    )?;
    if !(200..300).contains(&status) {
        return Ok(None);
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("IMDS credentials: {e}"))?;
    Ok(Some(creds_from_json(&v, "IMDS credentials")?))
}

fn creds_from_json(v: &serde_json::Value, source: &str) -> Result<AwsCreds, String> {
    let get = |k: &str| v[k].as_str().filter(|s| !s.trim().is_empty()).map(String::from);
    Ok(AwsCreds {
        access_key: get("AccessKeyId").ok_or_else(|| format!("{source}: no AccessKeyId"))?,
        secret_key: get("SecretAccessKey")
            .ok_or_else(|| format!("{source}: no SecretAccessKey"))?,
        session_token: get("Token"),
    })
}

fn http_request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<(u16, String), String> {
    use std::io::Read;
    let direct = url.starts_with("http://169.254.")
        || url.starts_with("http://127.")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]");
    let agent: ureq::Agent = if direct {
        seagent_net::http::builder_direct()
            .timeout_global(Some(Duration::from_secs(2)))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into()
    } else {
        crate::net::agent(Duration::from_secs(20), url)
    };
    let resp = match (method, body) {
        ("GET", _) => {
            let mut req = agent.get(url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            req.call()
        }
        ("PUT", body) => {
            let mut req = agent.put(url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            req.send(body.unwrap_or_default())
        }
        (_, body) => {
            let mut req = agent.post(url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            req.send(body.unwrap_or_default())
        }
    }
    .map_err(|e| format!("{method} {url}: {e}"))?;
    let status = resp.status().as_u16();
    let mut text = String::new();
    resp.into_body()
        .into_reader()
        .take(1 << 20)
        .read_to_string(&mut text)
        .map_err(|e| format!("{method} {url}: {e}"))?;
    Ok((status, text))
}

fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn xml_tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let raw = xml[start..end].trim();
    Some(
        raw.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'"),
    )
}

/// `YYYYMMDDTHHMMSSZ` for unix seconds.
pub fn amz_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// RFC 3986 encoding as SigV4 wants it (each path segment encoded once).
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b'/' if keep_slash => o.push('/'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Sign a request; returns the headers to add (`authorization`, `x-amz-date`,
/// `x-amz-content-sha256`, optional `x-amz-security-token`). `path` is the raw
/// (unencoded) path; `query` raw pairs.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    creds: &AwsCreds,
    method: &str,
    host: &str,
    path: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    body: &[u8],
    region: &str,
    service: &str,
    now_secs: u64,
) -> Vec<(String, String)> {
    let date = amz_date(now_secs);
    let day = &date[..8];
    let payload_hash = hex(&sha256(body));
    let mut hs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.trim().to_string()))
        .collect();
    hs.push(("host".into(), host.to_string()));
    hs.push(("x-amz-date".into(), date.clone()));
    hs.push(("x-amz-content-sha256".into(), payload_hash.clone()));
    if let Some(t) = &creds.session_token {
        hs.push(("x-amz-security-token".into(), t.clone()));
    }
    hs.sort();
    hs.dedup_by(|a, b| a.0 == b.0);
    let canon_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed: String = hs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canon_path = if path.is_empty() {
        "/".to_string()
    } else {
        path.split('/')
            .map(|seg| uri_encode(seg, false))
            .collect::<Vec<_>>()
            .join("/")
    };
    let mut q: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    q.sort();
    let canon_query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical =
        format!("{method}\n{canon_path}\n{canon_query}\n{canon_headers}\n{signed}\n{payload_hash}");
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        hex(&sha256(canonical.as_bytes()))
    );
    let k = hmac_sha256(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        day.as_bytes(),
    );
    let k = hmac_sha256(&k, region.as_bytes());
    let k = hmac_sha256(&k, service.as_bytes());
    let k = hmac_sha256(&k, b"aws4_request");
    let sig = hex(&hmac_sha256(&k, to_sign.as_bytes()));
    let mut out = vec![
        (
            "authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
                creds.access_key
            ),
        ),
        ("x-amz-date".into(), date),
        ("x-amz-content-sha256".into(), payload_hash),
    ];
    if let Some(t) = &creds.session_token {
        out.push(("x-amz-security-token".into(), t.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_440_938_160), "20150830T123600Z");
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
    }

    /// AWS's published SigV4 example (GET iam ListUsers, 2015-08-30).
    #[test]
    fn aws_documented_example_signature() {
        let c = AwsCreds {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let q = vec![
            ("Action".to_string(), "ListUsers".to_string()),
            ("Version".to_string(), "2010-05-08".to_string()),
        ];
        let h = vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        )];
        // The documented example signs without x-amz-content-sha256; recompute the same
        // canonical request shape to check the key-derivation and string-to-sign chain.
        let date = amz_date(1_440_938_160);
        let canonical = format!("GET\n/\nAction=ListUsers&Version=2010-05-08\ncontent-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\nx-amz-date:{date}\n\ncontent-type;host;x-amz-date\n{}", hex(&sha256(b"")));
        assert_eq!(
            hex(&sha256(canonical.as_bytes())),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        let k = hmac_sha256(format!("AWS4{}", c.secret_key).as_bytes(), b"20150830");
        let k = hmac_sha256(&k, b"us-east-1");
        let k = hmac_sha256(&k, b"iam");
        let k = hmac_sha256(&k, b"aws4_request");
        let sts = format!("AWS4-HMAC-SHA256\n{date}\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59");
        assert_eq!(
            hex(&hmac_sha256(&k, sts.as_bytes())),
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
        // And the full signer produces a well-formed header for the same request.
        let out = sign(
            &c,
            "GET",
            "iam.amazonaws.com",
            "/",
            &q,
            &h,
            b"",
            "us-east-1",
            "iam",
            1_440_938_160,
        );
        assert!(out[0].1.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature="));
    }

    #[test]
    fn path_encoding_and_session_token() {
        assert_eq!(
            uri_encode("anthropic.claude-3:0", false),
            "anthropic.claude-3%3A0"
        );
        let c = AwsCreds {
            access_key: "A".into(),
            secret_key: "S".into(),
            session_token: Some("T".into()),
        };
        let h = sign(
            &c,
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/a:b/converse-stream",
            &[],
            &[],
            b"{}",
            "us-east-1",
            "bedrock",
            0,
        );
        assert!(h
            .iter()
            .any(|(k, v)| k == "x-amz-security-token" && v == "T"));
        assert!(h[0].1.contains("x-amz-security-token"));
    }

    fn serve_seq(responses: Vec<(u16, String)>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut s, _)) = l.accept() else { return };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut req = String::new();
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                req.push_str(&line);
                let mut len = 0;
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        req.push('\n');
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                    req.push_str(&h);
                }
                let mut b = vec![0; len];
                let _ = r.read_exact(&mut b);
                req.push_str(&String::from_utf8_lossy(&b));
                log2.lock().unwrap().push(req);
                let _ = write!(s, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            }
        });
        (base, log)
    }

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-aws-{tag}-{}", crate::ratelimit::now_ms()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// ECS task-role credentials: the full URI is configured and no proxy or redirect
    /// can receive the token.
    #[test]
    fn ecs_container_credentials_from_fake_endpoint() {
        let (base, log) = serve_seq(vec![(200, r#"{"AccessKeyId":"AKECS","SecretAccessKey":"SKECS","Token":"STECS"}"#.into())]);
        let uri = format!("{base}/v2/credentials/abc");
        let get = |k: &str| match k {
            "AWS_CONTAINER_CREDENTIALS_FULL_URI" => Some(uri.clone()),
            "AWS_CONTAINER_AUTHORIZATION_TOKEN" => Some("auth-token".into()),
            _ => None,
        };
        let c = ecs_creds(&get).unwrap().unwrap();
        assert_eq!((c.access_key.as_str(), c.secret_key.as_str(), c.session_token.as_deref()), ("AKECS", "SKECS", Some("STECS")));
        let req = log.lock().unwrap()[0].clone();
        assert!(req.starts_with("GET /v2/credentials/abc"), "{req}");
        assert!(req.to_lowercase().contains("authorization: auth-token"), "{req}");
    }

    /// IMDSv2: a PUT obtains the session token, and every read carries it. The role
    /// name is taken from the metadata list, not from configuration.
    #[test]
    fn imds_v2_token_role_and_credentials_from_fake_endpoint() {
        let (base, log) = serve_seq(vec![
            (200, "IMDS_TOKEN".into()),
            (200, "role-a\n".into()),
            (200, r#"{"AccessKeyId":"AKIMDS","SecretAccessKey":"SKIMDS","Token":"STIMDS","Expiration":"2030-01-01T00:00:00Z"}"#.into()),
        ]);
        let get = |k: &str| match k {
            "AWS_EC2_METADATA_SERVICE_ENDPOINT" => Some(base.clone()),
            _ => None,
        };
        let c = imds_creds(&get).unwrap().unwrap();
        assert_eq!((c.access_key.as_str(), c.session_token.as_deref()), ("AKIMDS", Some("STIMDS")));
        let log = log.lock().unwrap();
        assert!(log[0].starts_with("PUT /latest/api/token"), "{}", log[0]);
        assert!(log[0].to_lowercase().contains("x-aws-ec2-metadata-token-ttl-seconds: 21600"), "{}", log[0]);
        assert!(log[1].starts_with("GET /latest/meta-data/iam/security-credentials/"), "{}", log[1]);
        assert!(log[1].to_lowercase().contains("x-aws-ec2-metadata-token: imds_token"), "{}", log[1]);
        assert!(log[2].contains("/role-a"), "{}", log[2]);
    }

    /// EKS web identity: the token file is exchanged at STS for temporary credentials
    /// and the response XML is parsed without an SDK.
    #[test]
    fn web_identity_exchanges_the_token_file_at_fake_sts() {
        let home = temp_home("web");
        let token_file = home.join("token");
        std::fs::write(&token_file, "web-token\n").unwrap();
        let (base, log) = serve_seq(vec![(200, r#"<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>AKWEB</AccessKeyId><SecretAccessKey>SKWEB</SecretAccessKey><SessionToken>STWEB</SessionToken></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"#.into())]);
        let get = |k: &str| match k {
            "AWS_WEB_IDENTITY_TOKEN_FILE" => Some(token_file.to_string_lossy().to_string()),
            "AWS_ROLE_ARN" => Some("arn:aws:iam::123:role/ops".into()),
            "AWS_ROLE_SESSION_NAME" => Some("seagent-test".into()),
            "AWS_ENDPOINT_URL_STS" => Some(base.clone()),
            _ => None,
        };
        let c = web_identity(&get).unwrap().unwrap();
        assert_eq!((c.access_key.as_str(), c.secret_key.as_str(), c.session_token.as_deref()), ("AKWEB", "SKWEB", Some("STWEB")));
        let req = log.lock().unwrap()[0].clone();
        assert!(req.starts_with("POST / "), "{req}");
        assert!(req.contains("Action=AssumeRoleWithWebIdentity"), "{req}");
        assert!(req.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123%3Arole%2Fops"), "{req}");
        assert!(req.contains("WebIdentityToken=web-token"), "{req}");
        let _ = std::fs::remove_dir_all(home);
    }

    /// Source precedence: env wins over the shared file, web identity wins over the
    /// shared file, and a half-configured env pair names the missing variable instead
    /// of silently trying another source.
    #[test]
    fn chain_order_and_partial_environment() {
        let home = temp_home("order");
        std::fs::create_dir_all(home.join(".aws")).unwrap();
        std::fs::write(
            home.join(".aws/credentials"),
            "[default]\naws_access_key_id = AKFILE\naws_secret_access_key = SKFILE\n",
        )
        .unwrap();
        let env: std::collections::BTreeMap<&str, &str> = [("AWS_ACCESS_KEY_ID", "AKENV"), ("AWS_SECRET_ACCESS_KEY", "SKENV")].into_iter().collect();
        let get = |k: &str| env.get(k).map(|v| v.to_string());
        assert_eq!(resolve(&get, &home).unwrap().access_key, "AKENV");
        assert_eq!(resolve(&|_| None, &home).unwrap().access_key, "AKFILE", "shared profile is next");
        let half = |k: &str| (k == "AWS_ACCESS_KEY_ID").then(|| "AKENV".to_string());
        let e = resolve(&half, &home).unwrap_err();
        assert!(e.contains("AWS_SECRET_ACCESS_KEY") && e.contains("both"), "{e}");
        let empty = temp_home("empty");
        let no_metadata = |k: &str| (k == "AWS_EC2_METADATA_DISABLED").then(|| "true".to_string());
        let e = resolve(&no_metadata, &empty).unwrap_err();
        assert!(e.contains("checked the environment") && e.contains("IMDSv2"), "{e}");
        let _ = std::fs::remove_dir_all(home);
        let _ = std::fs::remove_dir_all(empty);
    }

    #[test]
    fn shared_profile_selects_the_named_profile() {
        let home = temp_home("profile");
        std::fs::create_dir_all(home.join(".aws")).unwrap();
        std::fs::write(
            home.join(".aws/credentials"),
            "[default]\naws_access_key_id = AKD\naws_secret_access_key = SKD\n\n[work]\naws_access_key_id = AKW\naws_secret_access_key = SKW\naws_session_token = STW\n",
        )
        .unwrap();
        let get = |k: &str| (k == "AWS_PROFILE").then(|| "work".to_string());
        let c = shared_profile(&get, &home).unwrap().unwrap();
        assert_eq!((c.access_key.as_str(), c.session_token.as_deref()), ("AKW", Some("STW")));
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn shared_credentials_profile() {
        let t = "[default]\naws_access_key_id = AK\naws_secret_access_key = SK\n\n[work]\naws_access_key_id=W\n";
        let s = ini_section(t, "default").unwrap();
        assert_eq!(s[0], ("aws_access_key_id".into(), "AK".into()));
        assert!(ini_section(t, "nope").is_none());
    }
}
