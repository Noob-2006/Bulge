//! Audit-grade export of the audit stream (ARP `audit.export`, `seagent audit export --format`).
//!
//! One period (and optional kind / actor / outcome filters) of the hash-chained stream
//! ([`crate::audit`]) as a file an auditor can take away and check without SE Agent:
//!
//! * `jsonl`  — every record verbatim, `seq` / `prev` / `hash` included, so each record's hash
//!   and the links between consecutive records can be recomputed offline;
//! * `csv`    — every column (`seq`, `prev`, `hash`, `detail` as canonical JSON) for spreadsheets;
//! * `cef` / `leef` — the SIEM line formats of [`crate::audit_export`];
//! * `bundle` — an evidence package (ZIP): `records.jsonl`, `report.html` (the auditor's report
//!   for the same period, [`crate::audit_report`]), `verify.py` (a dependency-free checker),
//!   `README.txt` and `manifest.json` with the SHA-256 of every file, the chain verification
//!   ([`audit::verify`]) and the head hash at export time, the range, the generator and how to
//!   verify offline.
//!
//! Large ranges are bounded by [`MAX_EXPORT_BYTES`] of records: the export says `truncated` and
//! where to continue (`next_from_ms`). Records are read segment by segment, never all at once.

use crate::audit::{self, Query};
use serde::Serialize;
use serde_json::{json, Value};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Raw record bytes one export carries at most (the stream rotates at 64 MB by default).
pub const MAX_EXPORT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Jsonl,
    Csv,
    Cef,
    Leef,
    Bundle,
}

impl Format {
    pub fn parse(s: &str) -> Result<Format, String> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "jsonl" | "ndjson" | "json" => Format::Jsonl,
            "csv" => Format::Csv,
            "cef" => Format::Cef,
            "leef" => Format::Leef,
            "bundle" | "zip" | "evidence" => Format::Bundle,
            other => return Err(format!("format `{other}`: use bundle, jsonl, csv, cef or leef")),
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Jsonl => "jsonl",
            Format::Csv => "csv",
            Format::Cef => "cef",
            Format::Leef => "leef",
            Format::Bundle => "bundle",
        }
    }
    pub fn extension(self) -> &'static str {
        match self {
            Format::Jsonl => "jsonl",
            Format::Csv => "csv",
            Format::Cef => "cef.log",
            Format::Leef => "leef.log",
            Format::Bundle => "zip",
        }
    }
    pub fn content_type(self) -> &'static str {
        match self {
            Format::Jsonl => "application/x-ndjson",
            Format::Csv => "text/csv; charset=utf-8",
            Format::Cef | Format::Leef => "text/plain; charset=utf-8",
            Format::Bundle => "application/zip",
        }
    }
    /// Binary output (base64 over JSON-RPC).
    pub fn binary(self) -> bool {
        self == Format::Bundle
    }
}

/// `[from_ms, to_ms)` (0 = open end) and the optional record filters of `audit.query`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Filter {
    pub from_ms: u64,
    pub to_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

impl Filter {
    fn query(&self) -> Query {
        Query { kind: self.kind.clone(), actor: self.actor.clone(), outcome: self.outcome.clone(), after_ms: (self.from_ms > 0).then_some(self.from_ms), before_ms: (self.to_ms > 0).then_some(self.to_ms), ..Default::default() }
    }
}

/// The matching records, verbatim.
#[derive(Debug, Clone, Default)]
pub struct Selected {
    pub lines: Vec<String>,
    pub bytes: usize,
    pub truncated: bool,
    /// Where the next export continues when `truncated`.
    pub next_from_ms: Option<u64>,
}

/// Walk the segments (archived, then live) and keep the matching lines, at most `max_bytes`.
pub fn select(data: &Path, f: &Filter, max_bytes: usize) -> Selected {
    let q = f.query();
    let mut s = Selected::default();
    for p in audit::segments(data) {
        let Ok(file) = File::open(&p) else { continue };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }
            let Ok(r) = serde_json::from_str::<Value>(line) else { continue };
            if !q.matches(&r) {
                continue;
            }
            if s.bytes + line.len() + 1 > max_bytes && !s.lines.is_empty() {
                s.truncated = true;
                s.next_from_ms = r["ts"].as_u64();
                return s;
            }
            s.bytes += line.len() + 1;
            s.lines.push(line.to_string());
        }
    }
    s
}

/// The offline check of exported records (`seagent audit verify --file`, `verify.py`).
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct LinesCheck {
    pub ok: bool,
    pub records: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    /// `prev` of the first exported record: the hash it hangs from in the full chain.
    pub first_prev: String,
    pub last_hash: String,
    /// Every record follows the previous one (`seq + 1`, `prev` = its hash): no filter gaps.
    pub contiguous: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Recompute every record's hash from its own `prev` and check the link of each consecutive
/// pair: a record changed after it was written, or a record removed from or reordered within a
/// contiguous run, fails.
pub fn verify_lines(text: &str) -> LinesCheck {
    let mut c = LinesCheck { ok: true, contiguous: true, ..Default::default() };
    let mut last: Option<(u64, String)> = None;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let fail = |c: &mut LinesCheck, e: String| {
            c.ok = false;
            c.error = Some(e);
        };
        let Ok(mut rec) = serde_json::from_str::<Value>(line) else {
            fail(&mut c, format!("line {}: not JSON", i + 1));
            return c;
        };
        let seq = rec["seq"].as_u64().unwrap_or(0);
        let given = rec["hash"].as_str().unwrap_or("").to_string();
        let prev = rec["prev"].as_str().unwrap_or("").to_string();
        if let Some(o) = rec.as_object_mut() {
            o.remove("hash");
        }
        if audit::chain_hash(&prev, &rec) != given {
            fail(&mut c, format!("line {}: seq {seq} was modified (hash mismatch)", i + 1));
            return c;
        }
        match &last {
            None => {
                c.first_seq = seq;
                c.first_prev = prev;
            }
            Some((ls, _)) if seq <= *ls => {
                fail(&mut c, format!("line {}: seq {seq} after {ls} (records reordered or duplicated)", i + 1));
                return c;
            }
            Some((ls, lh)) if seq == ls + 1 && prev != *lh => {
                fail(&mut c, format!("line {}: seq {seq} does not link to seq {ls}", i + 1));
                return c;
            }
            Some((ls, _)) if seq != ls + 1 => c.contiguous = false,
            Some(_) => {}
        }
        c.records += 1;
        c.last_seq = seq;
        c.last_hash = given.clone();
        last = Some((seq, given));
    }
    c
}

/// One finished export.
#[derive(Debug, Clone)]
pub struct Export {
    pub format: Format,
    pub filename: String,
    pub bytes: Vec<u8>,
    pub records: usize,
    pub truncated: bool,
    pub next_from_ms: Option<u64>,
    /// SHA-256 of `bytes` (written into the `audit.export` record by the caller).
    pub sha256: String,
    pub range: LinesCheck,
    /// The whole chain, for the bundle.
    pub chain: Option<audit::Verify>,
}

impl Export {
    /// `bytes` for a JSON-RPC answer: text as is, the ZIP as standard base64.
    pub fn payload(&self) -> (String, &'static str) {
        if self.format.binary() {
            use base64::Engine as _;
            (base64::engine::general_purpose::STANDARD.encode(&self.bytes), "base64")
        } else {
            (String::from_utf8_lossy(&self.bytes).into_owned(), "utf-8")
        }
    }
    /// The JSON-RPC result (also what `seagent audit export --json` prints, without `data`).
    pub fn summary(&self) -> Value {
        json!({
            "format": self.format.as_str(),
            "filename": self.filename,
            "content_type": self.format.content_type(),
            "bytes": self.bytes.len(),
            "records": self.records,
            "truncated": self.truncated,
            "next_from_ms": self.next_from_ms,
            "sha256": self.sha256,
            "range": self.range,
            "chain": self.chain,
        })
    }
}

fn date_part(ms: u64) -> String {
    crate::audit_export::rfc3339(ms)[..10].replace('-', "")
}

/// `seagent-audit-20261015-20261114.zip` (an open start says `start`, an open end the export day).
pub fn filename(f: &Filter, format: Format, now_ms: u64) -> String {
    let from = if f.from_ms == 0 { "start".to_string() } else { date_part(f.from_ms) };
    let to = date_part(if f.to_ms == 0 { now_ms } else { f.to_ms.saturating_sub(1) });
    format!("seagent-audit-{from}-{to}.{}", format.extension())
}

/// Build the export. `generator`: the program and version written into the manifest.
pub fn export(data: &Path, f: &Filter, format: Format, generator: &str, seal_key: Option<&[u8]>, max_bytes: usize) -> Export {
    let now = audit::now_ms();
    let sel = select(data, f, max_bytes);
    let jsonl = {
        let mut s = sel.lines.join("\n");
        if !s.is_empty() {
            s.push('\n');
        }
        s
    };
    let range = verify_lines(&jsonl);
    let recs = || sel.lines.iter().filter_map(|l| serde_json::from_str::<Value>(l).ok());
    let mut chain = None;
    let bytes = match format {
        Format::Jsonl => jsonl.into_bytes(),
        Format::Csv => csv(recs()).into_bytes(),
        Format::Cef => recs().map(|r| crate::audit_export::cef(&r) + "\n").collect::<String>().into_bytes(),
        Format::Leef => recs().map(|r| crate::audit_export::leef(&r) + "\n").collect::<String>().into_bytes(),
        Format::Bundle => {
            let v = audit::verify(data, None);
            let report = crate::audit_report::build(data, f.from_ms, f.to_ms, seal_key);
            let html = crate::audit_report::html(&report);
            let readme = readme(f, &sel, &range);
            let mut files: Vec<(&str, Vec<u8>)> = vec![("records.jsonl", jsonl.into_bytes()), ("report.html", html.into_bytes()), ("verify.py", VERIFY_PY.as_bytes().to_vec()), ("README.txt", readme.into_bytes())];
            let listed: Vec<Value> = files.iter().map(|(n, b)| json!({"name": n, "bytes": b.len(), "sha256": audit::sha256_hex(b)})).collect();
            let head = audit::head(data);
            let manifest = json!({
                "kind": "seagent.audit.evidence",
                "version": 1,
                "generator": generator,
                "created_ms": now,
                "created": crate::audit_export::rfc3339(now),
                "range": {
                    "from_ms": f.from_ms, "to_ms": f.to_ms,
                    "from": if f.from_ms == 0 { "start of the stream".to_string() } else { crate::audit_export::rfc3339(f.from_ms) },
                    "to": if f.to_ms == 0 { "export time".to_string() } else { crate::audit_export::rfc3339(f.to_ms) },
                    "end_exclusive": true,
                },
                "filters": f,
                "records": sel.lines.len(),
                "truncated": sel.truncated,
                "next_from_ms": sel.next_from_ms,
                "records_check": range,
                "chain_at_export": v,
                "head_at_export": {"seq": head.seq, "hash": head.hash},
                "files": listed,
                "hash_rule": "hash = sha256_hex(prev + \"\\n\" + canonical_json(record without \"hash\")); canonical_json = UTF-8, object keys sorted at every level, no whitespace",
                "how_to_verify": [
                    "1. Check every file against `files[].sha256` (sha256sum FILE / PowerShell: Get-FileHash FILE -Algorithm SHA256).",
                    "2. Recompute every record's hash and the links between consecutive records: `python3 verify.py` (no dependencies), or `seagent audit verify --file records.jsonl`.",
                    "3. Tie the export to the live chain or the SIEM copy: `seagent audit verify --anchor <records_check.last_hash>` must succeed on the installation (or the SIEM must hold the same hash for that seq).",
                    "4. The export itself is an `audit.export` record in the chain whose detail carries this ZIP's SHA-256.",
                ],
            });
            files.push(("manifest.json", serde_json::to_string_pretty(&manifest).unwrap_or_default().into_bytes()));
            chain = Some(v);
            zip(&files, now)
        }
    };
    let sha256 = audit::sha256_hex(&bytes);
    Export { format, filename: filename(f, format, now), records: sel.lines.len(), truncated: sel.truncated, next_from_ms: sel.next_from_ms, sha256, range, chain, bytes }
}

fn readme(f: &Filter, sel: &Selected, range: &LinesCheck) -> String {
    let t = |ms: u64, open: &str| if ms == 0 { open.to_string() } else { crate::audit_export::rfc3339(ms) };
    format!(
        "SE Agent 稽核證據包 / audit evidence package\r\n\r\n\
         期間 Period: {} → {} (end exclusive)\r\n\
         紀錄數 Records: {}{}\r\n\
         序號 seq: {} – {}   最後雜湊 last hash: {}\r\n\r\n\
         records.jsonl  每筆稽核紀錄原文（含 seq / prev / hash）— every record verbatim\r\n\
         report.html    同期間的稽核報告 — the auditor's report for the period\r\n\
         manifest.json  各檔 SHA-256、匯出時的雜湊鏈驗證結果與鏈頭 — file hashes, chain check, head\r\n\
         verify.py      離線驗證程式（Python 3，免安裝套件）— offline checker\r\n\r\n\
         離線驗證 How to verify offline:\r\n\
         1. python3 verify.py（Windows：py verify.py；或 seagent audit verify --file records.jsonl）\r\n\
         2. 比對 manifest.json 的 files[].sha256（PowerShell: Get-FileHash 檔名 -Algorithm SHA256）\r\n\
         3. 在原系統執行 seagent audit verify --anchor <最後雜湊>，確認這段紀錄仍在鏈上\r\n\
         hash = sha256(prev + \"\\n\" + 排序鍵、無空白的 JSON（不含 hash 欄位）)\r\n",
        t(f.from_ms, "start"),
        t(f.to_ms, "export time"),
        sel.lines.len(),
        if sel.truncated { format!(" (truncated: continue from {})", sel.next_from_ms.map(crate::audit_export::rfc3339).unwrap_or_default()) } else { String::new() },
        range.first_seq,
        range.last_seq,
        range.last_hash,
    )
}

/// RFC 4180 with every chain column; text cells that a spreadsheet would run as a formula get
/// a leading `'` (the JSONL is the verbatim copy).
pub fn csv(recs: impl Iterator<Item = Value>) -> String {
    fn cell(s: &str, text: bool) -> String {
        let s = if text && s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    }
    let mut o = String::from("\u{feff}seq,ts,time,kind,actor_kind,actor_name,actor_role,actor_ip,target,outcome,session,org,team,prev,hash,detail\r\n");
    for r in recs {
        let st = |v: &Value| v.as_str().unwrap_or("").to_string();
        let ts = r["ts"].as_u64().unwrap_or(0);
        let detail = if r["detail"].is_null() { String::new() } else { audit::canonical(&r["detail"]) };
        let row = [
            cell(&r["seq"].as_u64().unwrap_or(0).to_string(), false),
            cell(&ts.to_string(), false),
            cell(&crate::audit_export::rfc3339(ts), false),
            cell(&st(&r["kind"]), true),
            cell(&st(&r["actor"]["kind"]), true),
            cell(&st(&r["actor"]["name"]), true),
            cell(&st(&r["actor"]["role"]), true),
            cell(&st(&r["actor"]["ip"]), true),
            cell(&st(&r["target"]), true),
            cell(&st(&r["outcome"]), true),
            cell(&st(&r["session"]), true),
            cell(&st(&r["org"]), true),
            cell(&st(&r["team"]), true),
            cell(&st(&r["prev"]), false),
            cell(&st(&r["hash"]), false),
            cell(&detail, true),
        ];
        o.push_str(&row.join(","));
        o.push_str("\r\n");
    }
    o
}

// ───────────────────────── ZIP (deflate, no extra crate) ─────────────────────────

fn crc32(b: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });
    !b.iter().fold(!0u32, |c, &x| t[((c ^ x as u32) & 0xff) as usize] ^ (c >> 8))
}

/// MS-DOS (time, date) of a UTC instant.
fn dos_time(ms: u64) -> (u16, u16) {
    let s = crate::audit_export::rfc3339(ms);
    let n = |a: usize, b: usize| s[a..b].parse::<u16>().unwrap_or(0);
    let (y, mo, d, h, mi, se) = (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19));
    ((h << 11) | (mi << 5) | (se / 2), (y.saturating_sub(1980) << 9) | (mo << 5) | d)
}

/// A ZIP of `files` (deflated, UTF-8 names): opens in Explorer, Finder, `unzip`, Python.
pub fn zip(files: &[(&str, Vec<u8>)], mtime_ms: u64) -> Vec<u8> {
    let (time, date) = dos_time(mtime_ms);
    let mut out = Vec::new();
    let mut central = Vec::new();
    let le16 = |v: &mut Vec<u8>, x: u16| v.extend_from_slice(&x.to_le_bytes());
    let le32 = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());
    for (name, data) in files {
        let crc = crc32(data);
        let packed = miniz_oxide::deflate::compress_to_vec(data, 6);
        let (method, body): (u16, &[u8]) = if packed.len() < data.len() { (8, &packed) } else { (0, data) };
        let offset = out.len() as u32;
        le32(&mut out, 0x0403_4b50);
        for x in [20u16, 0x0800, method, time, date] {
            le16(&mut out, x);
        }
        for x in [crc, body.len() as u32, data.len() as u32] {
            le32(&mut out, x);
        }
        le16(&mut out, name.len() as u16);
        le16(&mut out, 0);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(body);
        le32(&mut central, 0x0201_4b50);
        for x in [20u16, 20, 0x0800, method, time, date] {
            le16(&mut central, x);
        }
        for x in [crc, body.len() as u32, data.len() as u32] {
            le32(&mut central, x);
        }
        for x in [name.len() as u16, 0, 0, 0, 0] {
            le16(&mut central, x);
        }
        le32(&mut central, 0);
        le32(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);
    le32(&mut out, 0x0605_4b50);
    for x in [0u16, 0, files.len() as u16, files.len() as u16] {
        le16(&mut out, x);
    }
    le32(&mut out, cd_len);
    le32(&mut out, cd_offset);
    le16(&mut out, 0);
    out
}

/// The bundle's offline checker: Python 3 standard library only.
pub const VERIFY_PY: &str = r#"#!/usr/bin/env python3
"""Offline check of a SE Agent audit evidence package (no SE Agent, no extra packages).

  python3 verify.py [records.jsonl]

1. every file listed in manifest.json matches its SHA-256;
2. every record's hash = sha256(prev + "\n" + canonical JSON of the record without "hash"),
   canonical = UTF-8, keys sorted at every level, no whitespace;
3. consecutive records (seq n, n+1) link: the later one's prev is the earlier one's hash.
Exit status 0 = all checks passed.
"""
import hashlib, json, os, sys

here = os.path.dirname(os.path.abspath(__file__))
ok = True

def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def fail(msg):
    global ok
    ok = False
    print("FAIL", msg)

manifest = os.path.join(here, "manifest.json")
if os.path.exists(manifest):
    with open(manifest, encoding="utf-8") as fh:
        man = json.load(fh)
    for f in man.get("files", []):
        p = os.path.join(here, f["name"])
        if not os.path.exists(p):
            fail("%s is missing" % f["name"])
            continue
        with open(p, "rb") as fh:
            got = sha(fh.read())
        if got != f["sha256"]:
            fail("%s: sha256 %s, manifest says %s" % (f["name"], got, f["sha256"]))
        else:
            print("ok   %s sha256 %s" % (f["name"], got))

path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "records.jsonl")
n = gaps = 0
first = last_seq = last_hash = None
with open(path, encoding="utf-8") as fh:
    for i, line in enumerate(fh, 1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        rec = json.loads(line)
        given = rec.pop("hash", "")
        prev = rec.get("prev", "")
        if sha((prev + "\n" + canon(rec)).encode("utf-8")) != given:
            fail("line %d: seq %s was modified (hash mismatch)" % (i, rec.get("seq")))
            break
        seq = rec.get("seq", 0)
        if last_seq is not None:
            if seq <= last_seq:
                fail("line %d: seq %s after %s (reordered or duplicated)" % (i, seq, last_seq))
                break
            if seq == last_seq + 1 and prev != last_hash:
                fail("line %d: seq %s does not link to seq %s" % (i, seq, last_seq))
                break
            if seq != last_seq + 1:
                gaps += 1
        if first is None:
            first = seq
        last_seq, last_hash = seq, given
        n += 1

if ok:
    print("ok   %d record(s), seq %s-%s, last hash %s%s" % (n, first, last_seq, last_hash, (" (%d filter gap(s))" % gaps) if gaps else ""))
    print("ALL CHECKS PASSED")
sys.exit(0 if ok else 1)
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{emit, Actor, Event};

    fn unzip(z: &[u8]) -> Vec<(String, Vec<u8>)> {
        let rd16 = |i: usize| u16::from_le_bytes([z[i], z[i + 1]]) as usize;
        let rd32 = |i: usize| u32::from_le_bytes([z[i], z[i + 1], z[i + 2], z[i + 3]]) as usize;
        let mut out = vec![];
        let mut i = 0;
        while rd32(i) == 0x0403_4b50 {
            let (method, crc, csize, usize_, nlen, xlen) = (rd16(i + 8), rd32(i + 14) as u32, rd32(i + 18), rd32(i + 22), rd16(i + 26), rd16(i + 28));
            let name = String::from_utf8(z[i + 30..i + 30 + nlen].to_vec()).unwrap();
            let start = i + 30 + nlen + xlen;
            let body = &z[start..start + csize];
            let data = if method == 8 { miniz_oxide::inflate::decompress_to_vec(body).unwrap() } else { body.to_vec() };
            assert_eq!(data.len(), usize_);
            assert_eq!(crc32(&data), crc, "{name}");
            out.push((name, data));
            i = start + csize;
        }
        assert_eq!(rd32(z.len() - 22), 0x0605_4b50, "end of central directory");
        assert_eq!(rd16(z.len() - 12), out.len());
        out
    }

    fn sample(d: &Path) {
        for i in 0..6 {
            emit(d, Event::new(if i % 2 == 0 { "app.request" } else { "auth.denied" }, Actor::new("token", if i < 3 { "ann" } else { "bob" }).with_ip("10.0.0.1"), &format!("config.set{i}"), if i % 2 == 0 { "allow" } else { "deny" }).detail(json!({"n": i, "note": "=cmd, \"quoted\""}))).unwrap();
        }
    }

    #[test]
    fn crc_and_formats() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(Format::parse("ZIP").unwrap(), Format::Bundle);
        assert!(Format::parse("xml").is_err());
        assert_eq!(dos_time(0).1 >> 9, 0, "before 1980 saturates");
        let f = Filter { from_ms: 1_760_486_400_000, to_ms: 1_763_078_400_000, ..Default::default() };
        assert_eq!(filename(&f, Format::Bundle, 0), "seagent-audit-20251015-20251113.zip");
    }

    #[test]
    fn jsonl_is_verbatim_and_verifies_offline() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-audit-evidence");
        let d = tmp.path();
        sample(d);
        let e = export(d, &Filter::default(), Format::Jsonl, "test", None, MAX_EXPORT_BYTES);
        assert_eq!(e.records, 6);
        let text = String::from_utf8(e.bytes.clone()).unwrap();
        let on_disk = std::fs::read_to_string(audit::segments(d).last().unwrap()).unwrap();
        assert_eq!(text, on_disk, "the records are byte-for-byte the chain");
        let c = verify_lines(&text);
        assert!(c.ok && c.contiguous && c.records == 6 && c.first_seq == 1 && c.last_seq == 6, "{c:?}");
        assert_eq!(c.last_hash, audit::head(d).hash);
        // Tampering with one record, or dropping one from the middle, is caught.
        let bad = text.replacen("\"n\":2", "\"n\":9", 1);
        assert!(verify_lines(&bad).error.unwrap().contains("hash mismatch"));
        let mut lines: Vec<&str> = text.lines().collect();
        lines.swap(2, 3);
        assert!(!verify_lines(&lines.join("\n")).ok);
        // A filtered export is not contiguous but every record still checks out.
        let e = export(d, &Filter { outcome: Some("deny".into()), ..Default::default() }, Format::Jsonl, "test", None, MAX_EXPORT_BYTES);
        let c = verify_lines(std::str::from_utf8(&e.bytes).unwrap());
        assert!(c.ok && !c.contiguous && c.records == 3, "{c:?}");
        // The byte limit truncates and says where to continue.
        let two: usize = on_disk.lines().take(2).map(|l| l.len() + 1).sum();
        let e = export(d, &Filter::default(), Format::Jsonl, "test", None, two);
        assert!(e.truncated && e.records == 2 && e.next_from_ms == audit::all(d)[2]["ts"].as_u64(), "{} {:?}", e.records, e.next_from_ms);
    }

    #[test]
    fn csv_cef_leef_carry_the_chain_columns() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-audit-evidence-csv");
        let d = tmp.path();
        sample(d);
        let csv = String::from_utf8(export(d, &Filter { kind: Some("auth.denied".into()), ..Default::default() }, Format::Csv, "t", None, MAX_EXPORT_BYTES).bytes).unwrap();
        let rows: Vec<&str> = csv.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert_eq!(rows.len(), 4, "header + 3 denials: {csv}");
        assert!(rows[0].contains("seq,ts,time,kind") && rows[0].ends_with("prev,hash,detail"));
        let h = audit::all(d)[1]["hash"].as_str().unwrap().to_string();
        assert!(rows[1].starts_with("2,") && rows[1].contains(&h), "{}", rows[1]);
        assert!(rows[1].contains("\"{\"\"n\"\":1"), "detail is quoted JSON: {}", rows[1]);
        let cef = String::from_utf8(export(d, &Filter::default(), Format::Cef, "t", None, MAX_EXPORT_BYTES).bytes).unwrap();
        assert_eq!(cef.lines().count(), 6);
        assert!(cef.lines().all(|l| l.starts_with("CEF:0|seagent|")));
        let leef = String::from_utf8(export(d, &Filter::default(), Format::Leef, "t", None, MAX_EXPORT_BYTES).bytes).unwrap();
        assert!(leef.lines().all(|l| l.starts_with("LEEF:1.0|seagent|")) && leef.contains("seagentHash="));
    }

    #[test]
    fn bundle_is_a_zip_with_manifest_hashes_report_and_checker() {
        let tmp = seagent_core::tmp::TempDir::new("seagent-audit-evidence-zip");
        let d = tmp.path();
        sample(d);
        let e = export(d, &Filter::default(), Format::Bundle, "seagent 9.9", None, MAX_EXPORT_BYTES);
        assert!(e.filename.ends_with(".zip") && e.sha256 == audit::sha256_hex(&e.bytes));
        let files = unzip(&e.bytes);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["records.jsonl", "report.html", "verify.py", "README.txt", "manifest.json"]);
        let man: Value = serde_json::from_slice(&files[4].1).unwrap();
        assert_eq!(man["generator"], "seagent 9.9");
        assert_eq!(man["records"], 6);
        assert_eq!(man["chain_at_export"]["ok"], true);
        assert_eq!(man["head_at_export"]["hash"], audit::head(d).hash.as_str());
        for (i, f) in man["files"].as_array().unwrap().iter().enumerate() {
            assert_eq!(f["name"], files[i].0.as_str());
            assert_eq!(f["sha256"], audit::sha256_hex(&files[i].1).as_str());
        }
        assert!(String::from_utf8_lossy(&files[1].1).contains("<h1>seagent audit report</h1>"));
        assert!(man["how_to_verify"].as_array().unwrap().len() >= 3);
        let (b64, enc) = e.payload();
        assert_eq!(enc, "base64");
        use base64::Engine as _;
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(b64).unwrap(), e.bytes);
    }
}
