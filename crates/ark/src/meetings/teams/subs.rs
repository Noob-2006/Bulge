//! Graph subscription upkeep for the Teams pipeline (Hermes
//! `plugins/teams_pipeline/subscriptions.py`, MIT).
//!
//! `maintain-subscriptions` walks `/subscriptions`, syncs what it finds into the local store and
//! renews the ones inside the renewal window; it never deletes a subscription, it flags the local
//! records Graph no longer reports as `missing_remote`. A subscription counts as ours when the
//! store knows it or its `clientState` matches the configured one.

use super::graph::Client;
use super::models::{parse_iso, GraphSubscription};
use super::store::Store;
use serde_json::{json, Map, Value};

/// `MSGRAPH_WEBHOOK_CLIENT_STATE` unless the caller passes one.
pub fn expected_client_state(raw: Option<&str>) -> Option<String> {
    let raw = raw.map(str::to_string).or_else(|| std::env::var("MSGRAPH_WEBHOOK_CLIENT_STATE").ok()).unwrap_or_default();
    Some(raw.trim().to_string()).filter(|s| !s.is_empty())
}

/// Sync one Graph subscription payload into the store (normalising camelCase keys).
pub fn sync_graph_subscription_record(store: &mut Store, payload: &Value, status: Option<&str>, renewed: bool) -> Result<Value, String> {
    let sub = GraphSubscription::from_value(payload)?;
    let status = status.map(str::to_string).unwrap_or_else(|| if sub.is_expired(super::models::now_secs()) { "expired".into() } else { "active".into() });
    let mut v = sub.to_value();
    if let Some(o) = v.as_object_mut() {
        o.insert("status".into(), json!(status));
        if renewed {
            o.insert("latest_renewal_at".into(), json!(super::models::iso_z(super::models::now_secs())));
        }
    }
    store.upsert_subscription(&sub.subscription_id, &v)
}

/// A subscription is ours when the store knows it, or its clientState matches ours.
pub fn is_managed_subscription(store: &Store, payload: &Value, expected: Option<&str>) -> bool {
    let id = payload.get("subscription_id").or_else(|| payload.get("id")).and_then(Value::as_str).unwrap_or("").trim();
    if !id.is_empty() && store.get_subscription(id).is_some() {
        return true;
    }
    let state = payload.get("client_state").or_else(|| payload.get("clientState")).and_then(Value::as_str).unwrap_or("").trim();
    expected.map(|e| !e.is_empty() && e == state).unwrap_or(false)
}

/// One `skipped` entry: the reason plus any extra fields.
fn skip_record(id: &str, reason: &str, extra: Value) -> Value {
    let mut v = json!({"subscription_id": id, "reason": reason});
    if let (Some(dst), Some(src)) = (v.as_object_mut(), extra.as_object()) {
        for (k, x) in src {
            dst.insert(k.clone(), x.clone());
        }
    }
    v
}

/// Renew every managed subscription inside `renew_within_hours`, extending by `extend_hours`.
pub fn maintain_graph_subscriptions(client: &Client, store: &mut Store, renew_within_hours: i64, extend_hours: i64, dry_run: bool, client_state: Option<&str>) -> Result<Value, String> {
    let threshold = renew_within_hours.max(1);
    let extend = extend_hours.max(1);
    let managed_state = expected_client_state(client_state);
    let now = super::models::now_secs();
    let remote = client.collect_paginated("/subscriptions", &[]).map_err(|e| e.message)?;
    let mut remote_ids: Vec<String> = Vec::new();
    let mut synced = 0usize;
    let mut renewed: Vec<Value> = Vec::new();
    let mut candidates: Vec<Value> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    for raw in remote.iter().filter(|v| v.is_object()) {
        let Some(id) = raw.get("id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string) else { continue };
        macro_rules! skip {
            ($reason:expr, $extra:expr) => {
                skipped.push(skip_record(&id, $reason, $extra))
            };
        }
        if !is_managed_subscription(store, raw, managed_state.as_deref()) {
            skip!("not_managed_by_teams_pipeline", json!({}));
            continue;
        }
        remote_ids.push(id.clone());
        if sync_graph_subscription_record(store, raw, None, false).is_err() {
            skip!("failed_to_sync_local_store", json!({}));
            continue;
        }
        synced += 1;
        let expiration = raw.get("expirationDateTime").or_else(|| raw.get("expiration_datetime")).and_then(Value::as_str).unwrap_or("");
        let Some(exp) = parse_iso(expiration) else {
            skip!("missing_expiration", json!({}));
            continue;
        };
        let seconds = exp - now;
        if seconds < 0 {
            let _ = store.upsert_subscription(&id, &json!({"status": "expired", "expiration_datetime": super::models::iso_z(exp)}));
            skip!("already_expired", json!({"expiration_datetime": super::models::iso_z(exp)}));
            continue;
        }
        if seconds > threshold * 3600 {
            skip!("not_due", json!({"expires_in_seconds": seconds}));
            continue;
        }
        let new_expiration = super::models::iso_z(exp.max(now) + extend * 3600);
        let candidate = json!({
            "subscription_id": id,
            "resource": raw.get("resource").cloned().unwrap_or(Value::Null),
            "current_expiration": super::models::iso_z(exp),
            "new_expiration": new_expiration,
        });
        candidates.push(candidate.clone());
        if dry_run {
            continue;
        }
        let patched = client.patch_json(&format!("/subscriptions/{id}"), &json!({"expirationDateTime": new_expiration})).map_err(|e| e.message)?;
        let mut merged: Map<String, Value> = raw.as_object().cloned().unwrap_or_default();
        for (k, v) in patched.as_object().cloned().unwrap_or_default() {
            merged.insert(k, v);
        }
        merged.insert("id".into(), json!(id));
        merged.insert("expirationDateTime".into(), json!(new_expiration));
        sync_graph_subscription_record(store, &Value::Object(merged), Some("active"), true)?;
        let mut c = candidate;
        c["result"] = patched;
        renewed.push(c);
    }
    // Locally-known subscriptions Graph no longer reports are flagged, never deleted.
    let known: Vec<String> = store.list_subscriptions().keys().cloned().collect();
    for id in known {
        if !remote_ids.contains(&id) {
            let _ = store.upsert_subscription(&id, &json!({"status": "missing_remote", "last_seen_missing_remote_at": super::models::iso_z(now)}));
        }
    }
    Ok(json!({
        "success": true,
        "dry_run": dry_run,
        "store_path": store.path.display().to_string(),
        "remote_subscription_count": remote.len(),
        "synced_subscription_count": synced,
        "candidate_count": candidates.len(),
        "renewed_count": renewed.len(),
        "threshold_hours": threshold,
        "extend_hours": extend,
        "candidates": candidates,
        "renewed": renewed,
        "skipped": skipped,
    }))
}
