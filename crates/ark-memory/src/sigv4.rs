//! AWS Signature Version 4 (ring HMAC-SHA256) for Bedrock `InvokeModel`.

use crate::util::sha256_hex;
use ring::hmac;

#[derive(Debug, Clone, PartialEq)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl Credentials {
    /// `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`, else the
    /// `[default]` (or `AWS_PROFILE`) section of ~/.aws/credentials.
    pub fn from_env() -> Option<Credentials> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if let (Some(a), Some(s)) = (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY")) {
            return Some(Credentials { access_key: a, secret_key: s, session_token: env("AWS_SESSION_TOKEN") });
        }
        let path = env("AWS_SHARED_CREDENTIALS_FILE").map(std::path::PathBuf::from).or_else(|| env("HOME").map(|h| std::path::Path::new(&h).join(".aws/credentials")))?;
        Self::from_ini(&std::fs::read_to_string(path).ok()?, &env("AWS_PROFILE").unwrap_or_else(|| "default".into()))
    }

    pub fn from_ini(text: &str, profile: &str) -> Option<Credentials> {
        let mut cur = String::new();
        let (mut a, mut s, mut t) = (None, None, None);
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') && line.ends_with(']') {
                cur = line[1..line.len() - 1].trim().to_string();
            } else if cur == profile {
                if let Some((k, v)) = line.split_once('=') {
                    let v = Some(v.trim().to_string());
                    match k.trim() {
                        "aws_access_key_id" => a = v,
                        "aws_secret_access_key" => s = v,
                        "aws_session_token" => t = v,
                        _ => {}
                    }
                }
            }
        }
        Some(Credentials { access_key: a?, secret_key: s?, session_token: t })
    }
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes()).as_ref().to_vec()
}

/// RFC 3986 encoding as SigV4 wants it (`/` kept when `keep_slash`).
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Headers to add (`x-amz-date`, optional `x-amz-security-token`, `authorization`).
/// `path` is the already-encoded request path; non-S3 services encode it once more.
#[allow(clippy::too_many_arguments)]
pub fn sign(method: &str, host: &str, path: &str, query: &str, headers: &[(String, String)], payload: &[u8], creds: &Credentials, region: &str, service: &str, amz_date: &str) -> Vec<(String, String)> {
    let date = &amz_date[..8];
    let mut hs: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string())).collect();
    hs.push(("host".into(), host.to_string()));
    hs.push(("x-amz-date".into(), amz_date.to_string()));
    if let Some(t) = &creds.session_token {
        hs.push(("x-amz-security-token".into(), t.clone()));
    }
    hs.sort();
    let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed: String = hs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let canonical_uri = if service == "s3" { path.to_string() } else { uri_encode(path, true) };
    let mut q: Vec<(String, String)> = query.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((p.to_string(), String::new()))).collect();
    q.sort();
    let canonical_query = q.iter().map(|(a, b)| format!("{a}={b}")).collect::<Vec<_>>().join("&");
    let canonical = format!("{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed}\n{}", sha256_hex(payload));
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let k = hmac(format!("AWS4{}", creds.secret_key).as_bytes(), date);
    let k = hmac(&k, region);
    let k = hmac(&k, service);
    let k = hmac(&k, "aws4_request");
    let sig: String = hmac(&k, &to_sign).iter().map(|b| format!("{b:02x}")).collect();
    let mut out = vec![("x-amz-date".to_string(), amz_date.to_string())];
    if let Some(t) = &creds.session_token {
        out.push(("x-amz-security-token".into(), t.clone()));
    }
    out.push(("authorization".into(), format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}", creds.access_key)));
    out
}

/// `YYYYMMDDTHHMMSSZ` for `ms`.
pub fn amz_date(ms: u64) -> String {
    let iso = crate::util::iso(ms);
    iso.replace(['-', ':'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_get_vanilla_test_vector() {
        // AWS SigV4 test suite "get-vanilla".
        let c = Credentials { access_key: "AKIDEXAMPLE".into(), secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(), session_token: None };
        let h = sign("GET", "example.amazonaws.com", "/", "", &[], b"", &c, "us-east-1", "service", "20150830T123600Z");
        let auth = &h.iter().find(|(k, _)| k == "authorization").unwrap().1;
        assert_eq!(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
        assert_eq!(amz_date(1_440_938_160_000), "20150830T123600Z");
    }

    #[test]
    fn encodes_and_reads_ini() {
        assert_eq!(uri_encode("/model/amazon.titan-embed-text-v2%3A0/invoke", true), "/model/amazon.titan-embed-text-v2%253A0/invoke");
        let c = Credentials::from_ini("[other]\naws_access_key_id=X\n[default]\naws_access_key_id = A\naws_secret_access_key = S\n", "default").unwrap();
        assert_eq!((c.access_key.as_str(), c.secret_key.as_str()), ("A", "S"));
        let c = Credentials { access_key: "A".into(), secret_key: "S".into(), session_token: Some("T".into()) };
        let h = sign("POST", "h", "/x", "", &[("Content-Type".into(), "application/json".into())], b"{}", &c, "us-west-2", "bedrock", "20240101T000000Z");
        assert!(h.iter().any(|(k, v)| k == "x-amz-security-token" && v == "T"));
        assert!(h.iter().any(|(k, v)| k == "authorization" && v.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token")));
    }
}
