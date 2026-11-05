//! Durable local state for the Teams pipeline (Hermes `plugins/teams_pipeline/store.py`, MIT).
//!
//! One JSON file with five buckets (`subscriptions`, `notification_receipts`,
//! `event_timestamps`, `jobs`, `sink_records`); every write merges into the bucket and replaces
//! the file atomically, stamping `created_at`/`updated_at` as upstream does. The on-disk shape
//! stays compatible with stores written by Hermes.

use super::models::{iso_z, now_secs};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const STORE_FILENAME: &str = "teams_pipeline_store.json";
pub const BUCKETS: &[&str] = &["subscriptions", "notification_receipts", "event_timestamps", "jobs", "sink_records"];

type Bucket = BTreeMap<String, Value>;

/// `<data>/teams_pipeline_store.json` unless `store_path` / `MSGRAPH_WEBHOOK_STORE_PATH` says otherwise.
pub fn resolve_path(explicit: Option<&str>, data: &Path) -> PathBuf {
    let explicit = explicit.map(str::trim).unwrap_or("");
    let env = std::env::var("MSGRAPH_WEBHOOK_STORE_PATH").unwrap_or_default();
    let pick = if !explicit.is_empty() { explicit } else { env.trim() };
    if pick.is_empty() {
        data.join(STORE_FILENAME)
    } else {
        PathBuf::from(pick)
    }
}

/// JSON-backed store; loads on open, persists on every mutation.
pub struct Store {
    pub path: PathBuf,
    state: BTreeMap<String, Bucket>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store, String> {
        let mut s = Store { path: path.to_path_buf(), state: BUCKETS.iter().map(|b| (b.to_string(), Bucket::new())).collect() };
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(s),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
        if let Some(o) = v.as_object() {
            for b in BUCKETS {
                let bucket = o.get(*b).and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
                s.state.insert(b.to_string(), bucket);
            }
        }
        Ok(s)
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
        }
        let doc = Value::Object(self.state.iter().map(|(k, v)| (k.clone(), Value::Object(v.iter().map(|(k, v)| (k.clone(), v.clone())).collect()))).collect());
        let mut text = serde_json::to_string_pretty(&doc).map_err(|e| format!("store: {e}"))?;
        text.push('\n');
        seagent_kernel::util::atomic_write(&self.path, text.as_bytes()).map_err(|e| format!("cannot write {}: {e}", self.path.display()))
    }

    fn bucket(&self, name: &str) -> &Bucket {
        self.state.get(name).expect("known bucket")
    }

    pub fn list(&self, name: &str) -> Bucket {
        self.bucket(name).clone()
    }

    pub fn get(&self, name: &str, key: &str) -> Option<Value> {
        self.bucket(name).get(key).cloned()
    }

    /// Merge `payload` over the record, stamping `id_field` and created/updated timestamps.
    pub fn upsert(&mut self, name: &str, id_field: &str, key: &str, payload: &Value) -> Result<Value, String> {
        let existing = self.bucket(name).get(key).and_then(Value::as_object).cloned().unwrap_or_default();
        let mut merged: Map<String, Value> = existing.clone();
        for (k, v) in payload.as_object().cloned().unwrap_or_default() {
            merged.insert(k, v);
        }
        merged.insert(id_field.to_string(), json!(key));
        let created = existing.get("created_at").cloned().unwrap_or(Value::Null);
        if !created.as_str().map(|s| !s.is_empty()).unwrap_or(false) {
            merged.insert("created_at".into(), json!(iso_z(now_secs())));
        }
        merged.insert("updated_at".into(), json!(iso_z(now_secs())));
        let out = Value::Object(merged);
        self.state.get_mut(name).expect("known bucket").insert(key.to_string(), out.clone());
        self.persist()?;
        Ok(out)
    }

    /// Record a notification receipt once; `false` when the key was already seen (a duplicate
    /// Graph delivery).
    pub fn record_receipt(&mut self, key: &str, payload: &Value) -> Result<bool, String> {
        if self.bucket("notification_receipts").contains_key(key) {
            return Ok(false);
        }
        let rec = json!({"received_at": iso_z(now_secs()), "payload": payload});
        self.state.get_mut("notification_receipts").expect("known bucket").insert(key.to_string(), rec);
        self.persist()?;
        Ok(true)
    }

    pub fn delete_subscription(&mut self, id: &str) -> Result<bool, String> {
        if self.state.get_mut("subscriptions").expect("known bucket").remove(id).is_none() {
            return Ok(false);
        }
        self.persist()?;
        Ok(true)
    }

    pub fn stats(&self) -> Value {
        Value::Object(BUCKETS.iter().map(|b| (b.to_string(), json!(self.bucket(b).len()))).collect())
    }

    // ── typed accessors (upstream's partialmethods) ──
    pub fn list_subscriptions(&self) -> Bucket {
        self.list("subscriptions")
    }
    pub fn get_subscription(&self, id: &str) -> Option<Value> {
        self.get("subscriptions", id)
    }
    pub fn upsert_subscription(&mut self, id: &str, payload: &Value) -> Result<Value, String> {
        self.upsert("subscriptions", "subscription_id", id, payload)
    }
    pub fn list_jobs(&self) -> Bucket {
        self.list("jobs")
    }
    pub fn get_job(&self, id: &str) -> Option<Value> {
        self.get("jobs", id)
    }
    pub fn upsert_job(&mut self, id: &str, payload: &Value) -> Result<Value, String> {
        self.upsert("jobs", "job_id", id, payload)
    }
    pub fn get_sink_record(&self, key: &str) -> Option<Value> {
        self.get("sink_records", key)
    }
    pub fn upsert_sink_record(&mut self, key: &str, payload: &Value) -> Result<Value, String> {
        self.upsert("sink_records", "sink_key", key, payload)
    }
}

/// `id:<id>` when Graph gave the notification an id, else `sha256:<canonical json>`.
pub fn notification_receipt_key(notification: &Value) -> String {
    if let Some(id) = notification.get("id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
        return format!("id:{id}");
    }
    format!("sha256:{}", sha256_hex(canonical(notification).as_bytes()))
}

/// `json.dumps(sort_keys=True, separators=(",", ":"))` (upstream's canonical form).
fn canonical(v: &Value) -> String {
    let mut s = String::new();
    write_canonical(v, &mut s);
    s
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_canonical(&o[*k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-teams-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn store_round_trips_buckets_and_stamps_timestamps() {
        let dir = tmp("roundtrip");
        let path = dir.join("store.json");
        let mut s = Store::open(&path).unwrap();
        assert_eq!(s.stats()["jobs"], 0);
        s.upsert_job("j1", &json!({"status": "received", "meeting_ref": {"meeting_id": "M1"}})).unwrap();
        let job = s.get_job("j1").unwrap();
        assert_eq!((job["job_id"].as_str(), job["status"].as_str()), (Some("j1"), Some("received")));
        assert!(job["created_at"].is_string() && job["updated_at"].is_string());
        let created = job["created_at"].clone();
        s.upsert_job("j1", &json!({"status": "completed"})).unwrap();
        let job = s.get_job("j1").unwrap();
        assert_eq!(job["status"], "completed", "merge keeps other fields");
        assert_eq!(job["created_at"], created, "created_at is stable");
        assert_eq!(job["meeting_ref"]["meeting_id"], "M1", "merge keeps nested ref");
        // Re-opening reads what was persisted.
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.get_job("j1").unwrap()["status"], "completed");
        assert_eq!(reopened.stats()["jobs"], 1);
        assert!(reopened.get_job("nope").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipts_dedupe_by_id_or_content_hash() {
        let dir = tmp("receipts");
        let mut s = Store::open(&dir.join("store.json")).unwrap();
        let with_id = json!({"id": "n1", "resource": "x"});
        assert!(s.record_receipt(&notification_receipt_key(&with_id), &with_id).unwrap());
        assert!(!s.record_receipt(&notification_receipt_key(&with_id), &with_id).unwrap(), "duplicate delivery");
        // No id: the same document in a different key order hashes the same.
        let a = json!({"resource": "y", "changeType": "updated"});
        let b = json!({"changeType": "updated", "resource": "y"});
        assert_eq!(notification_receipt_key(&a), notification_receipt_key(&b));
        assert!(notification_receipt_key(&a).starts_with("sha256:"));
        assert!(s.record_receipt(&notification_receipt_key(&a), &a).unwrap());
        assert_eq!(s.stats()["notification_receipts"], 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn subscriptions_and_sinks_persist_and_delete() {
        let dir = tmp("subs");
        let mut s = Store::open(&dir.join("store.json")).unwrap();
        s.upsert_subscription("s1", &json!({"resource": "me", "status": "active"})).unwrap();
        assert_eq!(s.get_subscription("s1").unwrap()["subscription_id"], "s1");
        s.upsert_sink_record("notion:M1", &json!({"page_id": "p1"})).unwrap();
        assert_eq!(s.get_sink_record("notion:M1").unwrap()["page_id"], "p1");
        assert!(s.delete_subscription("s1").unwrap());
        assert!(!s.delete_subscription("s1").unwrap());
        assert!(s.get_subscription("s1").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
