//! AWS Signature Version 4 (request signing for Bedrock), and the AWS credential
//! chain seagent understands without the SDK: `$AWS_ACCESS_KEY_ID`/`$AWS_SECRET_ACCESS_KEY`
//! (+ `$AWS_SESSION_TOKEN`), then `~/.aws/credentials` for `$AWS_PROFILE` (default
//! `default`), then `credential_process` from `~/.aws/config`.

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
    pub fn from_env() -> Result<AwsCreds, String> {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().to_string())
        };
        if let (Some(a), Some(s)) = (get("AWS_ACCESS_KEY_ID"), get("AWS_SECRET_ACCESS_KEY")) {
            return Ok(AwsCreds {
                access_key: a,
                secret_key: s,
                session_token: get("AWS_SESSION_TOKEN"),
            });
        }
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        let profile = get("AWS_PROFILE").unwrap_or_else(|| "default".into());
        let creds_file = get("AWS_SHARED_CREDENTIALS_FILE")
            .map(Into::into)
            .unwrap_or_else(|| home.join(".aws/credentials"));
        if let Ok(t) = std::fs::read_to_string(&creds_file) {
            if let Some(kv) = ini_section(&t, &profile) {
                let f = |k: &str| kv.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
                if let (Some(a), Some(s)) = (f("aws_access_key_id"), f("aws_secret_access_key")) {
                    return Ok(AwsCreds {
                        access_key: a,
                        secret_key: s,
                        session_token: f("aws_session_token"),
                    });
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
                return Ok(AwsCreds {
                    access_key: g("AccessKeyId").ok_or("credential_process: no AccessKeyId")?,
                    secret_key: g("SecretAccessKey")
                        .ok_or("credential_process: no SecretAccessKey")?,
                    session_token: g("SessionToken"),
                });
            }
        }
        Err(format!("no AWS credentials: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, AWS_BEARER_TOKEN_BEDROCK, or configure profile `{profile}` in ~/.aws/credentials"))
    }
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

    #[test]
    fn shared_credentials_profile() {
        let t = "[default]\naws_access_key_id = AK\naws_secret_access_key = SK\n\n[work]\naws_access_key_id=W\n";
        let s = ini_section(t, "default").unwrap();
        assert_eq!(s[0], ("aws_access_key_id".into(), "AK".into()));
        assert!(ini_section(t, "nope").is_none());
    }
}
