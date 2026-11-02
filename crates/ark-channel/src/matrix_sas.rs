//! Matrix SAS device verification (`m.sas.v1`, client-server spec §"Short
//! Authentication String (SAS) verification"): a pure state machine for one
//! verification flow, as requester or responder, to-device (`transaction_id`)
//! or in a room (`m.relates_to` `m.reference` to the request event).
//!
//! Key agreement `curve25519-hkdf-sha256` (ephemeral X25519, the accepter's
//! commitment `SHA-256(key ‖ canonical JSON of start)`), SAS bytes
//! `HKDF(∅, S, "MATRIX_KEY_VERIFICATION_SAS|…")`, `emoji` (7 × 6 bits) and
//! `decimal` (3 × 13 bits + 1000), MACs `hkdf-hmac-sha256.v2` over every key
//! id and over the sorted key-id list. The caller (matrix_e2ee) owns transport,
//! policy and what a verified MAC means for trust.

use crate::olm::{b64, hkdf, key32, Curve};
use ark_net::crypto::{ct_eq, hmac_sha256, sha256};
use serde_json::{json, Value};
use std::time::Instant;

pub const SAS: &str = "m.sas.v1";
const KEY_AGREEMENT: &str = "curve25519-hkdf-sha256";
const MAC: &str = "hkdf-hmac-sha256.v2";

/// The spec's 64 SAS emoji (index → symbol, English name).
pub const EMOJI: [(&str, &str); 64] = [
    ("🐶", "Dog"), ("🐱", "Cat"), ("🦁", "Lion"), ("🐎", "Horse"), ("🦄", "Unicorn"), ("🐷", "Pig"), ("🐘", "Elephant"), ("🐰", "Rabbit"),
    ("🐼", "Panda"), ("🐓", "Rooster"), ("🐧", "Penguin"), ("🐢", "Turtle"), ("🐟", "Fish"), ("🐙", "Octopus"), ("🦋", "Butterfly"), ("🌷", "Flower"),
    ("🌳", "Tree"), ("🌵", "Cactus"), ("🍄", "Mushroom"), ("🌏", "Globe"), ("🌙", "Moon"), ("☁️", "Cloud"), ("🔥", "Fire"), ("🍌", "Banana"),
    ("🍎", "Apple"), ("🍓", "Strawberry"), ("🌽", "Corn"), ("🍕", "Pizza"), ("🎂", "Cake"), ("❤️", "Heart"), ("😀", "Smiley"), ("🤖", "Robot"),
    ("🎩", "Hat"), ("👓", "Glasses"), ("🔧", "Spanner"), ("🎅", "Santa"), ("👍", "Thumbs Up"), ("☂️", "Umbrella"), ("⌛", "Hourglass"), ("⏰", "Clock"),
    ("🎁", "Gift"), ("💡", "Light Bulb"), ("📕", "Book"), ("✏️", "Pencil"), ("📎", "Paperclip"), ("✂️", "Scissors"), ("🔒", "Lock"), ("🔑", "Key"),
    ("🔨", "Hammer"), ("☎️", "Telephone"), ("🏁", "Flag"), ("🚂", "Train"), ("🚲", "Bicycle"), ("✈️", "Aeroplane"), ("🚀", "Rocket"), ("🏆", "Trophy"),
    ("⚽", "Ball"), ("🎸", "Guitar"), ("🎺", "Trumpet"), ("🔔", "Bell"), ("⚓", "Anchor"), ("🎧", "Headphones"), ("📁", "Folder"), ("📌", "Pin"),
];

/// Three 13-bit numbers + 1000 from the first 5 SAS bytes.
pub fn decimals(b: &[u8; 6]) -> [u16; 3] {
    let b: Vec<u16> = b.iter().map(|&x| x as u16).collect();
    [(b[0] << 5 | b[1] >> 3) + 1000, ((b[1] & 7) << 10 | b[2] << 2 | b[3] >> 6) + 1000, ((b[3] & 0x3f) << 7 | b[4] >> 1) + 1000]
}

/// Seven 6-bit emoji indices from the first 42 SAS bits.
pub fn emoji_indices(b: &[u8; 6]) -> [u8; 7] {
    let n = b.iter().fold(0u64, |a, &x| a << 8 | x as u64);
    std::array::from_fn(|i| ((n >> (42 - 6 * i)) & 63) as u8)
}

/// `hkdf-hmac-sha256.v2`: HMAC key from HKDF over the shared secret; unpadded base64.
pub fn mac_v2(shared: &[u8; 32], info: &str, input: &str) -> String {
    b64(&hmac_sha256(&hkdf(&[], shared, info.as_bytes(), 32), input.as_bytes()))
}

/// The accepter's commitment: `SHA-256(their key (base64) ‖ canonical start content)`.
pub fn commitment(key_b64: &str, start: &Value) -> String {
    b64(&sha256(format!("{key_b64}{}", crate::reef::canonical(start)).as_bytes()))
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Phase {
    Requested,
    Ready,
    Started,
    Accepted,
    Keys,
    MacSent,
    Done,
    Cancelled,
}

/// Keys the MAC covers: device Ed25519 and (when cross-signing is set up) the master key.
#[derive(Clone, Default, Debug)]
pub struct Keys {
    pub device_ed25519: String,
    pub master: Option<String>,
}

/// What a verified MAC from the other side proves.
#[derive(Debug, Default, PartialEq)]
pub struct Verified {
    pub device: bool,
    pub master: Option<String>,
}

pub struct Flow {
    pub id: String,
    pub room: Option<String>,
    pub me: (String, String),
    pub them: String,
    pub their_device: Option<String>,
    pub we_requested: bool,
    pub phase: Phase,
    eph: Curve,
    start: Option<Value>,
    we_started: bool,
    their_commitment: Option<String>,
    their_key: Option<[u8; 32]>,
    shared: Option<[u8; 32]>,
    pub sas: Option<[u8; 6]>,
    pub verified: Option<Verified>,
    pub created: Instant,
}

/// `(event type, content)` to send to the other side (the flow id is already in it).
pub type Msg = (String, Value);

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn has(v: &Value, want: &str) -> bool {
    v.as_array().is_some_and(|a| a.iter().any(|x| x == want))
}

impl Flow {
    pub fn new(id: &str, room: Option<&str>, me: (&str, &str), them: &str, their_device: Option<&str>, we_requested: bool) -> Flow {
        Flow { id: id.into(), room: room.map(str::to_string), me: (me.0.into(), me.1.into()), them: them.into(), their_device: their_device.map(str::to_string), we_requested, phase: Phase::Requested, eph: Curve::generate(), start: None, we_started: false, their_commitment: None, their_key: None, shared: None, sas: None, verified: None, created: Instant::now() }
    }

    fn msg(&self, typ: &str, mut c: Value) -> Msg {
        match &self.room {
            Some(_) => c["m.relates_to"] = json!({"rel_type": "m.reference", "event_id": self.id}),
            None => c["transaction_id"] = json!(self.id),
        }
        (format!("m.key.verification.{typ}"), c)
    }

    /// Request content (to-device; in a room the caller wraps it in an `m.room.message`).
    pub fn request(&self, now_ms: u64) -> Value {
        let mut c = json!({"from_device": self.me.1, "methods": [SAS]});
        match &self.room {
            Some(_) => {
                c["msgtype"] = json!("m.key.verification.request");
                c["to"] = json!(self.them);
                c["body"] = json!(format!("{} is requesting to verify your key, but your client does not support in-chat key verification.", self.me.0));
            }
            None => {
                c["transaction_id"] = json!(self.id);
                c["timestamp"] = json!(now_ms);
            }
        }
        c
    }

    pub fn cancel(&mut self, code: &str, reason: &str) -> Vec<Msg> {
        if matches!(self.phase, Phase::Done | Phase::Cancelled) {
            return vec![];
        }
        self.phase = Phase::Cancelled;
        vec![self.msg("cancel", json!({"code": code, "reason": reason}))]
    }

    /// Responder: answer an incoming request (policy already allowed it).
    pub fn ready(&mut self) -> Vec<Msg> {
        self.phase = Phase::Ready;
        vec![self.msg("ready", json!({"from_device": self.me.1, "methods": [SAS]}))]
    }

    fn our_start(&mut self) -> Vec<Msg> {
        let (typ, c) = self.msg("start", json!({"from_device": self.me.1, "method": SAS, "key_agreement_protocols": [KEY_AGREEMENT], "hashes": ["sha256"],
            "message_authentication_codes": [MAC], "short_authentication_string": ["decimal", "emoji"]}));
        self.start = Some(c.clone());
        self.we_started = true;
        self.phase = Phase::Started;
        vec![(typ, c)]
    }

    /// Requester: the other side is ready → we start SAS.
    pub fn on_ready(&mut self, c: &Value) -> Vec<Msg> {
        if !self.we_requested || self.phase != Phase::Requested {
            return vec![];
        }
        if !has(&c["methods"], SAS) {
            return self.cancel("m.unknown_method", "only m.sas.v1 is supported");
        }
        self.their_device = Some(s(&c["from_device"]).to_string());
        self.our_start()
    }

    /// A start from the other side (also a bare to-device start with no request).
    pub fn on_start(&mut self, c: &Value) -> Vec<Msg> {
        if c["method"] != SAS {
            return self.cancel("m.unknown_method", "only m.sas.v1 is supported");
        }
        if self.we_started {
            // Both started: the lexicographically smaller (user, device) wins.
            let theirs = (self.them.as_str(), s(&c["from_device"]));
            if (self.me.0.as_str(), self.me.1.as_str()) < theirs || self.phase != Phase::Started {
                return vec![];
            }
            self.we_started = false;
        } else if !matches!(self.phase, Phase::Requested | Phase::Ready) {
            return self.cancel("m.unexpected_message", "unexpected start");
        }
        if !has(&c["key_agreement_protocols"], KEY_AGREEMENT) || !has(&c["hashes"], "sha256") || !has(&c["message_authentication_codes"], MAC) || !(has(&c["short_authentication_string"], "emoji") || has(&c["short_authentication_string"], "decimal")) {
            return self.cancel("m.unknown_method", "no common SAS parameters (need curve25519-hkdf-sha256, sha256, hkdf-hmac-sha256.v2)");
        }
        self.their_device = Some(s(&c["from_device"]).to_string());
        self.start = Some(c.clone());
        self.phase = Phase::Accepted;
        let sas: Vec<&str> = ["decimal", "emoji"].into_iter().filter(|m| has(&c["short_authentication_string"], m)).collect();
        vec![self.msg("accept", json!({"method": SAS, "key_agreement_protocol": KEY_AGREEMENT, "hash": "sha256", "message_authentication_code": MAC,
            "short_authentication_string": sas, "commitment": commitment(&b64(&self.eph.public), c)}))]
    }

    /// Starter: the other side accepted → send our ephemeral key.
    pub fn on_accept(&mut self, c: &Value) -> Vec<Msg> {
        if !self.we_started || self.phase != Phase::Started {
            return self.cancel("m.unexpected_message", "unexpected accept");
        }
        if c["key_agreement_protocol"] != KEY_AGREEMENT || c["hash"] != "sha256" || c["message_authentication_code"] != MAC {
            return self.cancel("m.unknown_method", "accept chose parameters we did not offer");
        }
        self.their_commitment = Some(s(&c["commitment"]).to_string());
        self.phase = Phase::Accepted;
        vec![self.msg("key", json!({"key": b64(&self.eph.public)}))]
    }

    /// Their ephemeral key: derive the shared secret and SAS. The accepter answers with its key.
    pub fn on_key(&mut self, c: &Value) -> Vec<Msg> {
        if self.phase != Phase::Accepted || self.their_key.is_some() {
            return self.cancel("m.unexpected_message", "unexpected key");
        }
        let Some(k) = key32(s(&c["key"])) else { return self.cancel("m.invalid_message", "bad key") };
        let mut out = vec![];
        if self.we_started {
            let start = self.start.clone().unwrap_or_default();
            if self.their_commitment.as_deref() != Some(&commitment(s(&c["key"]), &start)) {
                return self.cancel("m.mismatched_commitment", "commitment mismatch");
            }
        } else {
            out.push(self.msg("key", json!({"key": b64(&self.eph.public)})));
        }
        self.their_key = Some(k);
        let shared = self.eph.dh(&k);
        let (ours, theirs) = (b64(&self.eph.public), b64(&k));
        let (tdev, (mu, md)) = (self.their_device.clone().unwrap_or_default(), self.me.clone());
        let info = if self.we_started {
            format!("MATRIX_KEY_VERIFICATION_SAS|{mu}|{md}|{ours}|{}|{tdev}|{theirs}|{}", self.them, self.id)
        } else {
            format!("MATRIX_KEY_VERIFICATION_SAS|{}|{tdev}|{theirs}|{mu}|{md}|{ours}|{}", self.them, self.id)
        };
        self.sas = Some(hkdf(&[], &shared, info.as_bytes(), 6).try_into().unwrap());
        self.shared = Some(shared);
        self.phase = Phase::Keys;
        out
    }

    /// The codes to compare, for humans.
    pub fn describe(&self) -> Option<String> {
        let b = self.sas?;
        let e: Vec<String> = emoji_indices(&b).iter().map(|&i| format!("{} {}", EMOJI[i as usize].0, EMOJI[i as usize].1)).collect();
        let d = decimals(&b);
        Some(format!("{} | {} {} {}", e.join(", "), d[0], d[1], d[2]))
    }

    fn mac_info(&self, from: (&str, &str), to: (&str, &str)) -> String {
        format!("MATRIX_KEY_VERIFICATION_MAC{}{}{}{}{}", from.0, from.1, to.0, to.1, self.id)
    }

    /// We confirm the SAS matches: MAC our device (and master) key.
    pub fn confirm(&mut self, ours: &Keys) -> Vec<Msg> {
        let Some(shared) = self.shared.filter(|_| self.phase == Phase::Keys) else { return vec![] };
        let tdev = self.their_device.clone().unwrap_or_default();
        let base = self.mac_info((&self.me.0, &self.me.1), (&self.them, &tdev));
        let mut keys = vec![(format!("ed25519:{}", self.me.1), ours.device_ed25519.clone())];
        if let Some(m) = &ours.master {
            keys.push((format!("ed25519:{m}"), m.clone()));
        }
        let mut ids: Vec<String> = keys.iter().map(|(k, _)| k.clone()).collect();
        ids.sort();
        let mac: serde_json::Map<String, Value> = keys.iter().map(|(id, k)| (id.clone(), json!(mac_v2(&shared, &format!("{base}{id}"), k)))).collect();
        self.phase = Phase::MacSent;
        let mut out = vec![self.msg("mac", json!({"mac": mac, "keys": mac_v2(&shared, &format!("{base}KEY_IDS"), &ids.join(","))}))];
        if self.verified.is_some() {
            out.extend(self.finish());
        }
        out
    }

    fn finish(&mut self) -> Vec<Msg> {
        self.phase = Phase::Done;
        vec![self.msg("done", json!({}))]
    }

    /// Their MAC, checked against what we know of their keys. Key ids we do not know
    /// are skipped (the key-list MAC still covers them); a wrong MAC cancels the flow.
    pub fn on_mac(&mut self, c: &Value, theirs: &Keys) -> Vec<Msg> {
        let Some(shared) = self.shared.filter(|_| matches!(self.phase, Phase::Keys | Phase::MacSent)) else { return self.cancel("m.unexpected_message", "unexpected mac") };
        let tdev = self.their_device.clone().unwrap_or_default();
        let base = self.mac_info((&self.them, &tdev), (&self.me.0, &self.me.1));
        let Some(macs) = c["mac"].as_object() else { return self.cancel("m.invalid_message", "no mac") };
        let mut ids: Vec<&String> = macs.keys().collect();
        ids.sort();
        let ids: Vec<&str> = ids.into_iter().map(|s| s.as_str()).collect();
        if !ct_eq(mac_v2(&shared, &format!("{base}KEY_IDS"), &ids.join(",")).as_bytes(), s(&c["keys"]).as_bytes()) {
            return self.cancel("m.key_mismatch", "key list MAC mismatch");
        }
        let mut v = Verified::default();
        for (id, m) in macs {
            let key = match id.strip_prefix("ed25519:") {
                Some(d) if d == tdev && !theirs.device_ed25519.is_empty() => theirs.device_ed25519.clone(),
                Some(k) if theirs.master.as_deref() == Some(k) => k.to_string(),
                _ => continue,
            };
            if !ct_eq(mac_v2(&shared, &format!("{base}{id}"), &key).as_bytes(), s(m).as_bytes()) {
                return self.cancel("m.key_mismatch", &format!("MAC mismatch for {id}"));
            }
            if key == theirs.device_ed25519 {
                v.device = true;
            } else {
                v.master = Some(key);
            }
        }
        if !v.device && v.master.is_none() {
            return self.cancel("m.key_mismatch", "no MAC for a key we know");
        }
        self.verified = Some(v);
        if self.phase == Phase::MacSent {
            self.finish()
        } else {
            vec![]
        }
    }

    pub fn finished(&self) -> bool {
        matches!(self.phase, Phase::Done | Phase::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(f: &mut Flow, t: &str, c: &Value, mine: &Keys, theirs: &Keys) -> Vec<Msg> {
        let mut out = match t.trim_start_matches("m.key.verification.") {
            "ready" => f.on_ready(c),
            "start" => f.on_start(c),
            "accept" => f.on_accept(c),
            "key" => f.on_key(c),
            "mac" => f.on_mac(c, theirs),
            _ => vec![],
        };
        if f.phase == Phase::Keys {
            out.extend(f.confirm(mine));
        }
        out
    }

    #[test]
    fn sas_number_and_emoji_extraction() {
        // Spec example layout: bits split MSB first.
        let b = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decimals(&b), [9191, 9191, 9191]);
        assert_eq!(emoji_indices(&b), [63; 7]);
        let b = [0, 0, 0, 0, 0, 0];
        assert_eq!((decimals(&b), emoji_indices(&b)), ([1000; 3], [0; 7]));
        // 0b000001 000010 000011 000100 000101 000110 000111 + 6 spare bits.
        let n: u64 = (1 << 42) | (2 << 36) | (3 << 30) | (4 << 24) | (5 << 18) | (6 << 12) | (7 << 6);
        let b: [u8; 6] = n.to_be_bytes()[2..].try_into().unwrap();
        assert_eq!(emoji_indices(&b), [1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(decimals(&[0x80, 0, 0x20, 0, 2, 0]), [4096 + 1000, 128 + 1000, 1 + 1000]);
        assert_eq!((EMOJI[0].1, EMOJI[63].1, EMOJI[36].0), ("Dog", "Pin", "👍"));
    }

    #[test]
    fn both_roles_agree_and_verify_each_other() {
        for room in [None, Some("!r:hs")] {
            let ka = Keys { device_ed25519: "AEDKEY".into(), master: Some("AMASTER".into()) };
            let kb = Keys { device_ed25519: "BEDKEY".into(), master: None };
            let mut a = Flow::new("$req", room, ("@a:hs", "ADEV"), "@b:hs", Some("BDEV"), true);
            let mut b = Flow::new("$req", room, ("@b:hs", "BDEV"), "@a:hs", Some("ADEV"), false);
            let mut to_a = b.ready();
            let mut to_b = vec![];
            for _ in 0..10 {
                for (t, c) in std::mem::take(&mut to_a) {
                    to_b.extend(step(&mut a, &t, &c, &ka, &kb));
                }
                for (t, c) in std::mem::take(&mut to_b) {
                    to_a.extend(step(&mut b, &t, &c, &kb, &ka));
                }
            }
            assert_eq!((a.phase, b.phase), (Phase::Done, Phase::Done));
            assert_eq!(a.sas, b.sas);
            assert_eq!(a.describe(), b.describe());
            assert_eq!(a.verified, Some(Verified { device: true, master: None }));
            assert_eq!(b.verified, Some(Verified { device: true, master: Some("AMASTER".into()) }));
        }
    }

    #[test]
    fn tampering_and_races_cancel() {
        let k = Keys { device_ed25519: "K".into(), master: None };
        // A MITM swapping keys breaks the commitment.
        let mut a = Flow::new("t", None, ("@a:hs", "A"), "@b:hs", None, true);
        let mut b = Flow::new("t", None, ("@b:hs", "B"), "@a:hs", Some("A"), false);
        b.ready();
        let (_, start) = a.on_ready(&json!({"from_device": "B", "methods": [SAS]})).remove(0);
        let (_, accept) = b.on_start(&start).remove(0);
        a.on_accept(&accept);
        let out = a.on_key(&json!({"key": b64(&Curve::generate().public)}));
        assert_eq!((out[0].0.as_str(), out[0].1["code"].as_str()), ("m.key.verification.cancel", Some("m.mismatched_commitment")));
        // Wrong MAC → key mismatch; unknown method → cancel.
        let mut a = Flow::new("t", None, ("@a:hs", "A"), "@b:hs", None, true);
        let (_, start) = a.on_ready(&json!({"from_device": "B", "methods": [SAS]})).remove(0);
        let mut b = Flow::new("t", None, ("@b:hs", "B"), "@a:hs", Some("A"), false);
        let (_, accept) = b.on_start(&start).remove(0);
        let (_, ka) = a.on_accept(&accept).remove(0);
        let (_, kb) = b.on_key(&ka).remove(0);
        a.on_key(&kb);
        let (_, mut mac) = b.confirm(&k).remove(0);
        mac["mac"]["ed25519:B"] = json!("AAAA");
        assert_eq!(a.on_mac(&mac, &k)[0].1["code"], "m.key_mismatch");
        let mut c = Flow::new("t", None, ("@a:hs", "A"), "@b:hs", None, false);
        assert_eq!(c.on_start(&json!({"method": "m.reciprocate.v1"}))[0].1["code"], "m.unknown_method");
        // Simultaneous starts: the smaller user id's start wins.
        let mut a = Flow::new("t", None, ("@a:hs", "A"), "@b:hs", None, true);
        let mut b = Flow::new("t", None, ("@b:hs", "B"), "@a:hs", Some("A"), false);
        let (_, sa) = a.on_ready(&json!({"from_device": "B", "methods": [SAS]})).remove(0);
        b.phase = Phase::Ready;
        let sb = b.our_start().remove(0).1;
        assert!(a.on_start(&sb).is_empty(), "a's start wins; a ignores b's");
        assert_eq!(b.on_start(&sa)[0].0, "m.key.verification.accept");
    }
}
