//! Signed audit seals and RFC 3161 timestamps.
//!
//! Every rotated audit segment already has a seal (`events-<a>-<b>.seal`: first/last seq,
//! the hash it links from, its last hash, the segment's sha256). A seal on its own proves
//! nothing to someone who does not trust the host: whoever can rewrite the segment can rewrite
//! the seal. Two things here make the seal checkable from outside:
//!
//! * **Ed25519 signature** — `[audit] seal_key` names a 32-byte seed (base64, in a file or a
//!   `{{secret:NAME}}`); each seal gets `events-<a>-<b>.sig`
//!   `{"alg":"ed25519","key":"ed25519:<pub>","sig":<base64 over the canonical seal>}`. The
//!   auditor only needs the public key (`[audit] seal_pubkey`, or `seagent audit verify --pubkey`).
//!   Keep the seed off the audited host (an HSM-backed signer or a separate account) if the
//!   threat is the host's own administrator: a key the attacker can read signs forgeries too.
//! * **RFC 3161 timestamp** — `[audit] tsa_url`: the sha256 of the canonical seal is sent to a
//!   Time-Stamping Authority as a `TimeStampReq`; the granted `TimeStampToken` is stored in
//!   the `.sig` file (`tsr`). We check the TSA's status, that the token carries our message
//!   imprint and our nonce; the token's CMS signature chain is verified with the TSA's
//!   certificate by `openssl ts -verify` (see the docs) — seagent does not ship a CMS verifier.
//!
//! Signing happens after rotation (`sign_pending`), from the daemon's export pump and from
//! `seagent audit rotate` / `seagent audit seal`, so rotation itself never blocks on a key or a TSA.

use crate::audit;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SealCheck {
    pub signed: usize,
    pub unsigned: usize,
    pub timestamped: usize,
    pub errors: Vec<String>,
}

impl SealCheck {
    pub fn ok(&self, require_signed: bool) -> bool {
        self.errors.is_empty() && (!require_signed || self.unsigned == 0)
    }
}

fn seals(data: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(audit::archive_dir(data))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "seal"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// The bytes a seal signature and timestamp cover.
fn seal_message(seal_path: &Path) -> Result<Vec<u8>, String> {
    let v: Value = std::fs::read_to_string(seal_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .ok_or_else(|| format!("{}: unreadable seal", seal_path.display()))?;
    Ok(format!("seagent-audit-seal|v1|{}", audit::canonical(&v)).into_bytes())
}

/// Sign (and optionally timestamp) every seal that has no `.sig` yet. Returns how many.
pub fn sign_pending(data: &Path, seed_b64: &str, tsa_url: Option<&str>) -> Result<usize, String> {
    let key = crate::signing::public_of(seed_b64)?;
    let mut n = 0;
    for sp in seals(data) {
        let sig_path = sp.with_extension("sig");
        if sig_path.exists() {
            continue;
        }
        let msg = seal_message(&sp)?;
        let sig = crate::signing::sign(seed_b64, &msg)?;
        let mut rec =
            json!({"alg": "ed25519", "key": key, "sig": sig, "signed_at": audit::now_ms()});
        if let Some(url) = tsa_url.filter(|u| !u.trim().is_empty()) {
            let t = timestamp(url, &crate::signing::sha256_bytes(&msg))?;
            rec["tsa"] = url.into();
            rec["tsr"] = seagent_net::crypto::b64(&t).into();
        }
        std::fs::write(
            &sig_path,
            serde_json::to_string_pretty(&rec).unwrap_or_default(),
        )
        .map_err(|e| format!("{}: {e}", sig_path.display()))?;
        let _ = crate::os::set_mode(&sig_path, 0o400);
        n += 1;
    }
    if n > 0 {
        audit::emit(data, audit::Event::new("audit.seal_signed", audit::Actor::system(), "audit", "ok").detail(json!({"seals": n, "key": key, "timestamped": tsa_url.is_some_and(|u| !u.trim().is_empty())})))?;
    }
    Ok(n)
}

/// Check every seal's signature against `pubkey` (`ed25519:<b64>` or bare base64).
pub fn check_all(data: &Path, pubkey: &[u8]) -> SealCheck {
    let mut c = SealCheck::default();
    let key = match std::str::from_utf8(pubkey)
        .map_err(|e| e.to_string())
        .and_then(crate::signing::PublicKey::parse)
    {
        Ok(k) => k,
        Err(e) => {
            c.errors.push(format!("seal public key: {e}"));
            return c;
        }
    };
    for sp in seals(data) {
        let name = sp
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let Some(sig): Option<Value> = std::fs::read_to_string(sp.with_extension("sig"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        else {
            c.unsigned += 1;
            continue;
        };
        let msg = match seal_message(&sp) {
            Ok(m) => m,
            Err(e) => {
                c.errors.push(e);
                continue;
            }
        };
        match crate::signing::verify(&key, &msg, sig["sig"].as_str().unwrap_or("")) {
            Ok(()) => c.signed += 1,
            Err(e) => c.errors.push(format!("{name}: {e}")),
        }
        if let Some(t) = sig["tsr"].as_str() {
            match seagent_net::crypto::b64_decode(t) {
                Some(tok) if contains(&tok, &crate::signing::sha256_bytes(&msg)) => {
                    c.timestamped += 1
                }
                _ => c.errors.push(format!(
                    "{name}: the RFC 3161 token does not cover this seal"
                )),
            }
        }
    }
    c
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

// ───────────────────────── RFC 3161 (minimal DER) ─────────────────────────

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let b: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|x| *x == 0)
            .collect();
        let mut v = vec![0x80 | b.len() as u8];
        v.extend(b);
        v
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(body.len()));
    v.extend_from_slice(body);
    v
}

/// DER INTEGER from big-endian magnitude bytes (positive).
fn der_uint(b: &[u8]) -> Vec<u8> {
    let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    let mut body = if b.is_empty() { vec![0] } else { b };
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(0x02, &body)
}

/// `TimeStampReq` for a sha256 imprint with `nonce`, asking for the TSA certificate.
pub fn timestamp_request(imprint: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    // sha256 OID 2.16.840.1.101.3.4.2.1
    let alg = tlv(
        0x30,
        &[
            tlv(
                0x06,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            ),
            vec![0x05, 0x00],
        ]
        .concat(),
    );
    let mi = tlv(0x30, &[alg, tlv(0x04, imprint)].concat());
    tlv(
        0x30,
        &[der_uint(&[1]), mi, der_uint(nonce), vec![0x01, 0x01, 0xff]].concat(),
    )
}

/// Read one TLV at `i`: (tag, body range, next index).
fn read_tlv(b: &[u8], i: usize) -> Option<(u8, std::ops::Range<usize>, usize)> {
    let tag = *b.get(i)?;
    let l0 = *b.get(i + 1)? as usize;
    let (len, start) = if l0 < 0x80 {
        (l0, i + 2)
    } else {
        let k = l0 & 0x7f;
        if k == 0 || k > 4 {
            return None;
        }
        let mut n = 0usize;
        for j in 0..k {
            n = (n << 8) | *b.get(i + 2 + j)? as usize;
        }
        (n, i + 2 + k)
    };
    let end = start.checked_add(len)?;
    (end <= b.len()).then_some((tag, start..end, end))
}

/// Parse a `TimeStampResp`: the PKI status and the token's bytes.
pub fn parse_response(b: &[u8]) -> Result<(u64, Vec<u8>), String> {
    let (t, body, _) = read_tlv(b, 0).ok_or("TSA reply is not DER")?;
    if t != 0x30 {
        return Err("TSA reply is not a TimeStampResp".into());
    }
    let (t, status_body, next) = read_tlv(b, body.start).ok_or("TSA reply: no status")?;
    if t != 0x30 {
        return Err("TSA reply: bad PKIStatusInfo".into());
    }
    let (t, int, _) = read_tlv(b, status_body.start).ok_or("TSA reply: no status value")?;
    if t != 0x02 {
        return Err("TSA reply: bad status".into());
    }
    let status = b[int].iter().fold(0u64, |a, x| (a << 8) | *x as u64);
    let token = if next < body.end {
        read_tlv(b, next)
            .map(|(_, _, e)| b[next..e].to_vec())
            .unwrap_or_default()
    } else {
        vec![]
    };
    Ok((status, token))
}

/// Ask the TSA at `url` to timestamp `imprint`. Returns the `TimeStampToken` DER.
pub fn timestamp(url: &str, imprint: &[u8; 32]) -> Result<Vec<u8>, String> {
    let nonce = seagent_net::crypto::random_bytes(8);
    let req = timestamp_request(imprint, &nonce);
    let agent: ureq::Agent = seagent_net::http::builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into();
    let mut resp = agent
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .send(&req[..])
        .map_err(|e| format!("TSA {url}: {e}"))?;
    let st = resp.status().as_u16();
    if !(200..300).contains(&st) {
        return Err(format!("TSA {url}: HTTP {st}"));
    }
    let body = resp
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_vec()
        .map_err(|e| format!("TSA {url}: {e}"))?;
    let (status, token) = parse_response(&body)?;
    // 0 = granted, 1 = grantedWithMods.
    if status > 1 {
        return Err(format!(
            "TSA {url} refused the request (PKIStatus {status})"
        ));
    }
    if !contains(&token, imprint) {
        return Err(format!(
            "TSA {url}: the token does not carry our message imprint"
        ));
    }
    let n: Vec<u8> = nonce.iter().copied().skip_while(|x| *x == 0).collect();
    if !contains(&token, &n) {
        return Err(format!(
            "TSA {url}: the token does not echo our nonce (replayed answer?)"
        ));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{emit, rotate, Actor, Event};
    use std::io::{BufRead, BufReader, Read, Write};

    const SEED: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

    /// A fake TSA: answers with a granted TimeStampResp whose "token" echoes the request's
    /// message imprint and nonce (enough for the checks seagent makes; no real CMS).
    fn fake_tsa(status: u8) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/tsa", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut len = 0usize;
            let mut ctype = String::new();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                let low = line.to_ascii_lowercase();
                if let Some(v) = low.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if let Some(v) = low.strip_prefix("content-type:") {
                    ctype = v.trim().to_string();
                }
            }
            let mut req = vec![0u8; len];
            r.read_exact(&mut req).unwrap();
            assert_eq!(ctype, "application/timestamp-query");
            let token = tlv(
                0x30,
                &[
                    tlv(
                        0x06,
                        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02],
                    ),
                    tlv(0x04, &req),
                ]
                .concat(),
            );
            let resp = tlv(0x30, &[tlv(0x30, &der_uint(&[status])), token].concat());
            let mut s = s;
            write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/timestamp-reply\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", resp.len()).unwrap();
            s.write_all(&resp).unwrap();
            req
        });
        (url, h)
    }

    fn seed_chain(d: &Path) {
        for i in 0..3 {
            emit(d, Event::new("x", Actor::system(), &i.to_string(), "ok")).unwrap();
        }
        rotate(d).unwrap();
        emit(d, Event::new("x", Actor::system(), "live", "ok")).unwrap();
    }

    struct Clean(PathBuf);
    impl Drop for Clean {
        fn drop(&mut self) {
            for e in std::fs::read_dir(audit::archive_dir(&self.0))
                .into_iter()
                .flatten()
                .flatten()
            {
                let _ = crate::os::set_mode(&e.path(), 0o600);
            }
        }
    }

    #[test]
    fn seals_are_signed_verified_and_tampering_is_caught() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-audit-seal");
        let d = tmp.path();
        let _c = Clean(d.to_path_buf());
        seed_chain(d);
        let pubkey = crate::signing::public_of(SEED).unwrap();
        assert_eq!(check_all(d, pubkey.as_bytes()).unsigned, 1);
        assert!(
            !check_all(d, pubkey.as_bytes()).ok(true),
            "unsigned fails when signatures are required"
        );
        assert_eq!(sign_pending(d, SEED, None).unwrap(), 1);
        assert_eq!(sign_pending(d, SEED, None).unwrap(), 0, "already signed");
        let c = check_all(d, pubkey.as_bytes());
        assert_eq!((c.signed, c.unsigned), (1, 0));
        assert!(c.ok(true));
        // Another key does not verify.
        let other =
            crate::signing::public_of("ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=").unwrap();
        assert!(!check_all(d, other.as_bytes()).errors.is_empty());
        // Rewriting the seal (to match a rewritten segment) breaks the signature.
        let sp = seals(d)[0].clone();
        crate::os::set_mode(&sp, 0o600).unwrap();
        let t = std::fs::read_to_string(&sp)
            .unwrap()
            .replace("\"last_seq\": 3", "\"last_seq\": 4");
        std::fs::write(&sp, t).unwrap();
        let c = check_all(d, pubkey.as_bytes());
        assert!(
            c.errors.iter().any(|e| e.contains("bad signature")),
            "{c:?}"
        );
        assert!(
            audit::query(
                d,
                &audit::Query {
                    kind: Some("audit.seal_signed".into()),
                    ..Default::default()
                }
            )
            .len()
                == 1
        );
    }

    #[test]
    fn rfc3161_timestamps_come_from_the_configured_tsa() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-audit-tsa");
        let d = tmp.path();
        let _c = Clean(d.to_path_buf());
        seed_chain(d);
        let (url, h) = fake_tsa(0);
        assert_eq!(sign_pending(d, SEED, Some(&url)).unwrap(), 1);
        let req = h.join().unwrap();
        // The request is a TimeStampReq v1 with a sha256 imprint of the seal message.
        let imprint = crate::signing::sha256_bytes(&seal_message(&seals(d)[0]).unwrap());
        assert!(
            req[0] == 0x30 && contains(&req, &imprint) && req.ends_with(&[0x01, 0x01, 0xff]),
            "SEQUENCE with our imprint and certReq"
        );
        assert!(
            contains(
                &req,
                &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
            ),
            "sha256 algorithm"
        );
        let pubkey = crate::signing::public_of(SEED).unwrap();
        let c = check_all(d, pubkey.as_bytes());
        assert_eq!((c.signed, c.timestamped), (1, 1), "{c:?}");
        // A TSA that refuses (status 2 = rejection) fails the signing step.
        let tmp2 = seagent_core::tmp::TempDir::new("seagent-audit-tsa2");
        let _c2 = Clean(tmp2.path().to_path_buf());
        seed_chain(tmp2.path());
        let (url, h) = fake_tsa(2);
        assert!(sign_pending(tmp2.path(), SEED, Some(&url))
            .unwrap_err()
            .contains("refused"));
        h.join().unwrap();
        assert!(parse_response(b"junk").is_err());
    }
}
