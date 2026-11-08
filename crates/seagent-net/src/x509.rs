//! A self-signed X.509 identity for LAN mode (docs/cross-platform.md, 區域網路互聯).
//!
//! Hand-rolled DER instead of `rcgen` (dependency budget, packaging/release/DEPENDENCY-REVIEW.md):
//! one certificate shape is all we need — ECDSA P-256 (ring signs it), v3, a random serial,
//! `CN=SE Agent <host>` as both subject and issuer, `subjectAltName` with DNS names and IP
//! addresses, `basicConstraints CA:FALSE`, `keyUsage digitalSignature`, `extKeyUsage serverAuth`.
//!
//! Clients do not trust this certificate through a CA: they pin the SHA-256 of the DER leaf
//! ([`fingerprint`], lower-case hex — exactly what the desktop/mobile app's `tls.rs` computes).
//! The validity period still matters to plain browsers (the phone PWA path), which refuse
//! leaf certificates valid for more than 825 days, so [`VALIDITY_DAYS`] stays under that.

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use std::net::IpAddr;

/// Browsers (Apple's TLS policy, Chrome) refuse server certificates valid for longer than
/// 825 days; pinning clients ignore the dates altogether.
pub const VALIDITY_DAYS: u64 = 825;

/// A generated identity: DER certificate and PKCS#8 private key.
pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_pkcs8: Vec<u8>,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
}

/// SHA-256 over the DER certificate, lower-case hex: the server's identity.
pub fn fingerprint(cert_der: &[u8]) -> String {
    crate::crypto::hex(&crate::crypto::sha256(cert_der))
}

/// The first 16 hex digits in groups of four, upper-case — what both screens show for a human
/// comparison (the app's `short_fingerprint`).
pub fn short_fingerprint(fp: &str) -> String {
    let v: Vec<char> = fp.chars().filter(|c| c.is_ascii_hexdigit()).take(16).collect();
    v.chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join(" ").to_ascii_uppercase()
}

/// PEM armour (`-----BEGIN <label>-----`, 64-column base64).
pub fn pem(label: &str, der: &[u8]) -> String {
    let b = crate::crypto::b64(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

// ── DER ──

fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
    let mut v = vec![0x80 | bytes.len() as u8];
    v.extend(bytes);
    v
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(len(content.len()));
    v.extend_from_slice(content);
    v
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut chunk = vec![(a & 0x7f) as u8];
        let mut x = a >> 7;
        while x > 0 {
            chunk.push(0x80 | (x & 0x7f) as u8);
            x >>= 7;
        }
        chunk.reverse();
        body.extend(chunk);
    }
    tlv(0x06, &body)
}

/// A non-negative INTEGER from big-endian bytes (a leading 0x00 when the top bit is set).
fn uint(bytes: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = bytes.iter().copied().skip_while(|x| *x == 0).collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8];
    b.extend_from_slice(bytes);
    tlv(0x03, &b)
}

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// UTCTime before 2050, GeneralizedTime from 2050 on (RFC 5280 §4.1.2.5).
fn time(unix_secs: u64) -> Vec<u8> {
    let (y, mo, d) = civil((unix_secs / 86_400) as i64);
    let s = unix_secs % 86_400;
    let (h, mi, se) = (s / 3600, (s / 60) % 60, s % 60);
    if y < 2050 {
        tlv(0x17, format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z", y % 100).as_bytes())
    } else {
        tlv(0x18, format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z").as_bytes())
    }
}

fn name(cn: &str) -> Vec<u8> {
    seq(&[tlv(0x31, &seq(&[oid(&[2, 5, 4, 3]), tlv(0x0c, cn.as_bytes())]))])
}

fn extension(id: &[u64], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![oid(id)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(tlv(0x04, &value));
    seq(&parts)
}

/// A DNS name usable in a SAN: lower-case letters, digits, `-` and `.`; anything else becomes `-`.
pub fn dns_label(s: &str) -> String {
    let v: String = s.trim().trim_end_matches('.').to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' }).collect();
    v.trim_matches('-').to_string()
}

/// Generate a fresh P-256 key and a self-signed certificate for `dns` names and `ips`, valid
/// from a day before `now_secs` for [`VALIDITY_DAYS`].
pub fn self_signed(common_name: &str, dns: &[String], ips: &[IpAddr], now_secs: u64) -> Result<Identity, String> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(|_| "cannot generate a P-256 key".to_string())?;
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).map_err(|_| "generated key does not load".to_string())?;
    let ecdsa_sha256 = seq(&[oid(&[1, 2, 840, 10045, 4, 3, 2])]);
    let mut serial = crate::crypto::random_bytes(16);
    serial[0] &= 0x7f;
    serial[0] |= 0x01; // never zero, never negative
    let not_before = now_secs.saturating_sub(86_400);
    let not_after = not_before + VALIDITY_DAYS * 86_400;
    let spki = seq(&[seq(&[oid(&[1, 2, 840, 10045, 2, 1]), oid(&[1, 2, 840, 10045, 3, 1, 7])]), bit_string(kp.public_key().as_ref())]);
    let mut san = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for d in dns.iter().map(|d| dns_label(d)).filter(|d| !d.is_empty() && d.len() <= 253) {
        if seen.insert(d.clone()) {
            san.extend(tlv(0x82, d.as_bytes()));
        }
    }
    for ip in ips {
        let b = match ip {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        if seen.insert(ip.to_string()) {
            san.extend(tlv(0x87, &b));
        }
    }
    let exts = vec![
        extension(&[2, 5, 29, 17], false, tlv(0x30, &san)),
        extension(&[2, 5, 29, 19], true, seq(&[])),
        // keyUsage: digitalSignature (bit 0) → one unused bit count of 7.
        extension(&[2, 5, 29, 15], true, tlv(0x03, &[0x07, 0x80])),
        extension(&[2, 5, 29, 37], false, seq(&[oid(&[1, 3, 6, 1, 5, 5, 7, 3, 1])])),
    ];
    let subject = name(common_name);
    let tbs = seq(&[
        tlv(0xa0, &uint(&[2])),
        uint(&serial),
        ecdsa_sha256.clone(),
        subject.clone(),
        seq(&[time(not_before), time(not_after)]),
        subject,
        spki,
        tlv(0xa3, &seq(&exts)),
    ]);
    let sig = kp.sign(&rng, &tbs).map_err(|_| "signing the certificate failed".to_string())?;
    let cert = seq(&[tbs, ecdsa_sha256, bit_string(sig.as_ref())]);
    Ok(Identity { cert_der: cert, key_pkcs8: pkcs8.as_ref().to_vec(), not_before_ms: not_before * 1000, not_after_ms: not_after * 1000 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_primitives() {
        assert_eq!(len(5), vec![5]);
        assert_eq!(len(200), vec![0x81, 200]);
        assert_eq!(len(0x1234), vec![0x82, 0x12, 0x34]);
        assert_eq!(oid(&[1, 2, 840, 10045, 2, 1]), vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
        assert_eq!(uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[0, 0, 5]), vec![0x02, 0x01, 0x05]);
        assert_eq!(time(0), tlv(0x17, b"700101000000Z"));
        assert_eq!(time(951_782_400), tlv(0x17, b"000229000000Z"), "leap day 2000");
        assert_eq!(time(2_524_608_000), tlv(0x18, b"20500101000000Z"));
        assert_eq!(dns_label("My_PC!"), "my-pc");
        assert_eq!(short_fingerprint(&"0123456789abcdef".repeat(4)), "0123 4567 89AB CDEF");
    }

    #[test]
    fn generated_certificate_parses_and_carries_the_names() {
        let id = self_signed("SE Agent studio", &["studio".into(), "studio.local".into(), "studio".into()], &["192.168.1.20".parse().unwrap(), "127.0.0.1".parse().unwrap()], 1_800_000_000).unwrap();
        let ci = crate::tlsd::CertIdentity::from_der(&id.cert_der);
        assert_eq!(ci.dns, vec!["studio".to_string(), "studio.local".to_string()]);
        assert_eq!(ci.fingerprint, fingerprint(&id.cert_der));
        assert_eq!(fingerprint(&id.cert_der).len(), 64);
        assert!(id.not_after_ms > id.not_before_ms);
        let p = pem("CERTIFICATE", &id.cert_der);
        assert!(p.starts_with("-----BEGIN CERTIFICATE-----\n") && p.lines().all(|l| l.len() <= 64));
    }

    /// A real TLS 1.3 handshake, in memory: rustls serves the generated certificate and key, a
    /// pinning client (the same verifier `Stream::connect_pinned` uses, which checks the
    /// handshake signature with webpki and therefore parses the DER) accepts the right pin and
    /// refuses a wrong one.
    #[test]
    fn rustls_serves_it_and_a_pinning_client_accepts_it() {
        use std::sync::Arc;
        let id = self_signed("SE Agent t", &["t.local".into()], &["127.0.0.1".parse().unwrap()], 1_800_000_000).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(id.key_pkcs8.clone()));
        let server_cfg = Arc::new(rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![id.cert_der.clone().into()], key).unwrap());
        let fp = fingerprint(&id.cert_der);
        let handshake = |want: &str| -> Result<(), String> {
            let mut server = rustls::ServerConnection::new(server_cfg.clone()).unwrap();
            let name = rustls::pki_types::ServerName::try_from("192.168.1.9").unwrap();
            let mut client = rustls::ClientConnection::new(crate::stream::pinned_config(Some(want.to_string())), name).unwrap();
            for _ in 0..20 {
                let mut buf = Vec::new();
                while client.wants_write() {
                    client.write_tls(&mut buf).unwrap();
                }
                server.read_tls(&mut buf.as_slice()).map_err(|e| e.to_string())?;
                server.process_new_packets().map_err(|e| e.to_string())?;
                let mut back = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut back).unwrap();
                }
                client.read_tls(&mut back.as_slice()).map_err(|e| e.to_string())?;
                client.process_new_packets().map_err(|e| e.to_string())?;
                if !client.is_handshaking() && !server.is_handshaking() {
                    return Ok(());
                }
            }
            Err("handshake did not finish".into())
        };
        handshake(&fp).unwrap();
        assert!(handshake(&"00".repeat(32)).is_err(), "a wrong pin is refused");
    }
}
