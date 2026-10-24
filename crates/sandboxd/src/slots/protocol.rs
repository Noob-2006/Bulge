//! Slot errors and the line protocol between sandboxd, the privileged
//! helper, and the slot servers.

use bulge_proto::msg::Outcome;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotError {
    pub code: String,
    pub message: String,
}

impl SlotError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub(crate) fn invalid(message: impl std::fmt::Display) -> Self {
        Self::new("INVALID_PARAMS", message.to_string())
    }

    pub(crate) fn failed(error: impl std::fmt::Display) -> Self {
        Self::new("SLOT_FAILED", error.to_string())
    }
}

impl std::fmt::Display for SlotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SlotError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRequest {
    pub id: u64,
    pub op: String,
    pub slot: u8,
    /// Source slot for `stage`; ignored (and zero) for every other operation.
    #[serde(default)]
    pub from: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperReply {
    Ok { id: u64, value: Value },
    Err { id: u64, code: String, message: String },
}

#[derive(Debug, Deserialize)]
pub(crate) struct HelperErrorBody {
    pub(crate) code: String,
    pub(crate) message: String,
}

pub fn parse_helper_request(line: &str) -> Result<HelperRequest, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}

pub fn parse_helper_response(line: &str) -> Result<HelperReply, String> {
    let mut raw: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let object = raw
        .as_object_mut()
        .ok_or_else(|| "helper reply is not an object".to_owned())?;
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| "helper reply has no id".to_owned())?;
    let ok = object.remove("ok");
    let err = object.remove("err");
    // Only `id` may remain once the two mutually exclusive payloads are gone.
    let clean = object.len() == 1;
    match (clean, ok, err) {
        (true, Some(value), None) => Ok(HelperReply::Ok { id, value }),
        (true, None, Some(err)) => {
            let err: HelperErrorBody = serde_json::from_value(err).map_err(|e| e.to_string())?;
            Ok(HelperReply::Err {
                id,
                code: err.code,
                message: err.message,
            })
        }
        _ => Err("helper reply must contain exactly one of ok/err".into()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotRequest {
    pub id: u64,
    pub command: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotResponse {
    pub id: u64,
    pub outcome: Outcome,
}

pub fn parse_slot_request(line: &str) -> Result<SlotRequest, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}

pub(crate) fn parse_slot_response(line: &str) -> Result<SlotResponse, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}
