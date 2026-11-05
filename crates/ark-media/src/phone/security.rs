//! Webhook signature verification (OpenClaw `extensions/voice-call/src/webhook-security.ts`, MIT):
//! Twilio `X-Twilio-Signature` (HMAC-SHA1 over URL + sorted form params, Base64),
//! Telnyx `telnyx-signature-ed25519` over `timestamp|body` (±5 min), Plivo V3
//! (HMAC-SHA256 over the sorted URL/params + `.` + nonce) with V2 fallback. Accepted
//! requests are de-duplicated by a replay key.

use ark_net::crypto;
use std::collections::HashMap;
use std::sync::Mutex;

pub type Params = Vec<(String, String)>;

fn header<'a>(h: &'a [(String, String)], k: &str) -> Option<&'a str> {
    h.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(k))
        .map(|(_, v)| v.as_str())
}

fn sorted(p: &Params) -> Params {
    let mut v = p.clone();
    v.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    v
}

/// Twilio: `url` + concatenated sorted `keyvalue` pairs, HMAC-SHA1(auth token), Base64.
pub fn twilio_signature(auth_token: &str, url: &str, params: &Params) -> String {
    let mut data = url.to_string();
    for (k, v) in sorted(params) {
        data.push_str(&k);
        data.push_str(&v);
    }
    crypto::b64(&crypto::hmac_sha1(auth_token.as_bytes(), data.as_bytes()))
}

pub fn verify_twilio(
    auth_token: &str,
    headers: &[(String, String)],
    url: &str,
    params: &Params,
) -> Result<String, String> {
    let sig = header(headers, "x-twilio-signature").ok_or("Missing X-Twilio-Signature header")?;
    let want = twilio_signature(auth_token, url, params);
    if !crypto::ct_eq(sig.as_bytes(), want.as_bytes()) {
        return Err("Invalid signature".into());
    }
    let canon: Vec<String> = sorted(params)
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    Ok(format!(
        "twilio:req:{}",
        crypto::hex(&crypto::sha256(
            format!("{url}\n{}", canon.join("&")).as_bytes()
        ))
    ))
}

/// Telnyx: Ed25519 over `timestamp|raw body`, public key Base64 (raw 32 bytes or SPKI DER).
pub fn verify_telnyx(
    public_key_b64: &str,
    headers: &[(String, String)],
    raw_body: &str,
    now_s: u64,
) -> Result<String, String> {
    let sig = header(headers, "telnyx-signature-ed25519");
    let ts = header(headers, "telnyx-timestamp");
    let (Some(sig), Some(ts)) = (sig, ts) else {
        return Err("Missing signature or timestamp header".into());
    };
    if ts.is_empty()
        || !ts.bytes().all(|b| b.is_ascii_digit())
        || (ts.len() > 1 && ts.starts_with('0'))
    {
        return Err("Invalid timestamp header".into());
    }
    let t: u64 = ts
        .parse()
        .map_err(|_| "Invalid timestamp header".to_string())?;
    let sigb = crypto::b64_decode(sig)
        .or_else(|| crypto::b64url_decode(sig.trim_end_matches('=')))
        .ok_or("Invalid signature")?;
    let mut key = crypto::b64_decode(public_key_b64.trim()).ok_or("Invalid Telnyx public key")?;
    if key.len() == 44 {
        key = key[12..].to_vec(); // SPKI DER prefix (302a300506032b6570032100)
    }
    if key.len() != 32
        || !crypto::ed25519_verify(&key, format!("{ts}|{raw_body}").as_bytes(), &sigb)
    {
        return Err("Invalid signature".into());
    }
    if t.abs_diff(now_s) > 300 {
        return Err("Timestamp too old".into());
    }
    Ok(format!(
        "telnyx:{}",
        crypto::hex(&crypto::sha256(
            format!("{ts}\n{}\n{raw_body}", crypto::b64(&sigb)).as_bytes()
        ))
    ))
}

fn plivo_sorted(p: &Params, query: bool) -> String {
    sorted(p)
        .into_iter()
        .map(|(k, v)| {
            if query {
                format!("{k}={v}")
            } else {
                format!("{k}{v}")
            }
        })
        .collect::<Vec<_>>()
        .join(if query { "&" } else { "" })
}

/// Plivo V3 base: `scheme://host/path?sortedquery[.]` + sorted body params (POST).
pub fn plivo_v3_base(method: &str, url: &str, post: &Params) -> String {
    let (no_q, q) = url.split_once('?').unwrap_or((url, ""));
    let query: Params = ark_net::parse_query(q);
    let qs = plivo_sorted(&query, true);
    let mut base = no_q.to_string();
    if !qs.is_empty() || !post.is_empty() {
        base = format!("{no_q}?{qs}");
    }
    if !qs.is_empty() && !post.is_empty() {
        base.push('.');
    }
    if method == "GET" {
        return base;
    }
    base + &plivo_sorted(post, false)
}

pub fn plivo_signature(auth_token: &str, v3: bool, base: &str, nonce: &str) -> String {
    let data = format!("{base}{}{nonce}", if v3 { "." } else { "" });
    crypto::b64(&crypto::hmac_sha256(auth_token.as_bytes(), data.as_bytes()))
}

pub fn verify_plivo(
    auth_token: &str,
    headers: &[(String, String)],
    method: &str,
    url: &str,
    post: &Params,
) -> Result<String, String> {
    let norm = |s: &str| {
        s.trim()
            .trim_end_matches('=')
            .replace('-', "+")
            .replace('_', "/")
    };
    if let (Some(sig), Some(nonce)) = (
        header(headers, "x-plivo-signature-v3"),
        header(headers, "x-plivo-signature-v3-nonce"),
    ) {
        if method != "GET" && method != "POST" {
            return Err(format!(
                "Unsupported HTTP method for Plivo V3 signature: {method}"
            ));
        }
        let base = plivo_v3_base(method, url, post);
        let want = norm(&plivo_signature(auth_token, true, &base, nonce));
        if !sig
            .split(',')
            .any(|s| crypto::ct_eq(norm(s).as_bytes(), want.as_bytes()))
        {
            return Err("Invalid Plivo V3 signature".into());
        }
        return Ok(format!(
            "plivo:v3:{}",
            crypto::hex(&crypto::sha256(format!("{base}\n{nonce}").as_bytes()))
        ));
    }
    if let (Some(sig), Some(nonce)) = (
        header(headers, "x-plivo-signature-v2"),
        header(headers, "x-plivo-signature-v2-nonce"),
    ) {
        let base = url.split('?').next().unwrap_or(url);
        let want = norm(&plivo_signature(auth_token, false, base, nonce));
        if !crypto::ct_eq(norm(sig).as_bytes(), want.as_bytes()) {
            return Err("Invalid Plivo V2 signature".into());
        }
        return Ok(format!(
            "plivo:v2:{}",
            crypto::hex(&crypto::sha256(format!("{base}\n{nonce}").as_bytes()))
        ));
    }
    Err("Missing Plivo signature headers (V3 or V2)".into())
}

/// Replay guard: a verified request key seen within 10 minutes is a duplicate.
#[derive(Default)]
pub struct Replay(Mutex<HashMap<String, u64>>);

impl Replay {
    /// True the first time `key` is seen.
    pub fn reserve(&self, key: &str, now_s: u64) -> bool {
        let mut m = self.0.lock().unwrap();
        m.retain(|_, t| now_s.saturating_sub(*t) < 600);
        if m.contains_key(key) {
            return false;
        }
        m.insert(key.into(), now_s);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn twilio_matches_documented_example() {
        // Twilio's documented example (security docs): token 12345, this URL and params.
        let url = "https://mycompany.com/myapp.php?foo=1&bar=2";
        let p: Params = [
            ("CallSid", "CA1234567890ABCDE"),
            ("Caller", "+12349013030"),
            ("Digits", "1234"),
            ("From", "+12349013030"),
            ("To", "+18005551212"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(
            twilio_signature("12345", url, &p),
            "0/KCTR6DLpKmkAf8muzZqo1nDgQ="
        );
        let ok = verify_twilio(
            "12345",
            &h(&[("X-Twilio-Signature", "0/KCTR6DLpKmkAf8muzZqo1nDgQ=")]),
            url,
            &p,
        )
        .unwrap();
        assert!(ok.starts_with("twilio:req:"));
        assert_eq!(
            verify_twilio("12345", &h(&[("X-Twilio-Signature", "bad")]), url, &p).unwrap_err(),
            "Invalid signature"
        );
        assert!(verify_twilio("12345", &[], url, &p)
            .unwrap_err()
            .contains("Missing"));
    }

    #[test]
    fn telnyx_ed25519_and_skew() {
        let seed = [7u8; 32];
        let pk = crypto::b64(&crypto::ed25519_public(&seed));
        let body = r#"{"data":{"event_type":"call.answered"}}"#;
        let sig = crypto::b64(&crypto::ed25519_sign(
            &seed,
            format!("1700000000|{body}").as_bytes(),
        ));
        let hs = h(&[
            ("telnyx-signature-ed25519", &sig),
            ("telnyx-timestamp", "1700000000"),
        ]);
        assert!(verify_telnyx(&pk, &hs, body, 1700000100)
            .unwrap()
            .starts_with("telnyx:"));
        assert_eq!(
            verify_telnyx(&pk, &hs, body, 1700001000).unwrap_err(),
            "Timestamp too old"
        );
        assert_eq!(
            verify_telnyx(&pk, &hs, "tampered", 1700000000).unwrap_err(),
            "Invalid signature"
        );
        let bad_ts = h(&[
            ("telnyx-signature-ed25519", &sig),
            ("telnyx-timestamp", "01"),
        ]);
        assert_eq!(
            verify_telnyx(&pk, &bad_ts, body, 0).unwrap_err(),
            "Invalid timestamp header"
        );
        // SPKI-wrapped key works too.
        let mut der = crypto::hex_decode("302a300506032b6570032100").unwrap();
        der.extend(crypto::ed25519_public(&seed));
        assert!(verify_telnyx(&crypto::b64(&der), &hs, body, 1700000000).is_ok());
    }

    #[test]
    fn plivo_v3_v2_and_replay() {
        let url = "https://x.example/voice/webhook?callId=c1&flow=answer";
        let post: Params = vec![
            ("CallUUID".into(), "u1".into()),
            ("CallStatus".into(), "in-progress".into()),
        ];
        let base = plivo_v3_base("POST", url, &post);
        assert_eq!(
            base,
            "https://x.example/voice/webhook?callId=c1&flow=answer.CallStatusin-progressCallUUIDu1"
        );
        let sig = plivo_signature("tok", true, &base, "n1");
        assert!(verify_plivo(
            "tok",
            &h(&[
                ("X-Plivo-Signature-V3", &format!("zzz,{sig}")),
                ("X-Plivo-Signature-V3-Nonce", "n1")
            ]),
            "POST",
            url,
            &post
        )
        .is_ok());
        assert!(verify_plivo(
            "tok",
            &h(&[
                ("X-Plivo-Signature-V3", "nope"),
                ("X-Plivo-Signature-V3-Nonce", "n1")
            ]),
            "POST",
            url,
            &post
        )
        .unwrap_err()
        .contains("V3"));
        let v2 = plivo_signature("tok", false, "https://x.example/voice/webhook", "n2");
        assert!(verify_plivo(
            "tok",
            &h(&[
                ("X-Plivo-Signature-V2", &v2),
                ("X-Plivo-Signature-V2-Nonce", "n2")
            ]),
            "POST",
            url,
            &post
        )
        .is_ok());
        assert!(verify_plivo("tok", &[], "POST", url, &post)
            .unwrap_err()
            .contains("Missing"));
        let r = Replay::default();
        assert!(r.reserve("k", 1) && !r.reserve("k", 2) && r.reserve("k", 700));
    }
}
