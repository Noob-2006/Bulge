//! `ToolDispatcher` backed by the guest VM.

use std::sync::Arc;
use std::time::Duration;

use bulge_proto::msg::Outcome;
use bulge_vm::vm::Vm;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::dispatch::{ToolCall, ToolDispatcher, builtin_concurrency_safe};
use crate::schedule::CallOutcome;

pub struct VmDispatcher {
    vm: Arc<Vm>,
    timeout: Duration,
    slot: Option<u8>,
}

impl VmDispatcher {
    pub fn new(vm: Arc<Vm>, timeout: Duration) -> Self {
        Self { vm, timeout, slot: None }
    }

    /// Route every tool call through a VM workspace slot. The guest runs the
    /// call inside the slot's namespace as the slot's uid, so concurrent
    /// sub-agents get private workspace views.
    pub fn with_slot(mut self, slot: u8) -> Self {
        self.slot = Some(slot);
        self
    }
}

fn timeout_ms(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)
}

/// Build the guest envelope for a tool call running in `slot`.
fn slot_envelope(slot: u8, name: &str, args: serde_json::Map<String, Value>, timeout: Duration) -> Value {
    serde_json::json!({
        "slot": slot,
        "command": name,
        "params": Value::Object(args),
        "timeout_ms": timeout_ms(timeout),
    })
}

impl ToolDispatcher for VmDispatcher {
    fn dispatch(&self, call: ToolCall, cancel: CancellationToken) -> BoxFuture<'static, CallOutcome> {
        let vm = self.vm.clone();
        let timeout = self.timeout;
        let slot = self.slot;
        async move {
            let (command, params) = match slot {
                Some(slot) => ("slot_run".to_string(), slot_envelope(slot, &call.name, call.arguments, timeout)),
                None => (call.name, Value::Object(call.arguments)),
            };
            tokio::select! {
                // The guest also enforces the timeout; this is the host-side cancel path.
                () = cancel.cancelled() => CallOutcome::Skipped,
                outcome = vm.invoke(&command, params, Some(timeout)) => match outcome {
                    Outcome::Ok { value } => CallOutcome::Ok(value),
                    Outcome::Err { code, message } => CallOutcome::Err { code, message },
                },
            }
        }
        .boxed()
    }

    fn concurrency_safe(&self, name: &str) -> bool {
        builtin_concurrency_safe(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_envelope_wraps_the_tool_call() {
        let mut args = serde_json::Map::new();
        args.insert("command".into(), Value::String("ls".into()));
        let envelope = slot_envelope(3, "exec", args, Duration::from_millis(1_500));
        assert_eq!(
            envelope,
            serde_json::json!({
                "slot": 3,
                "command": "exec",
                "params": { "command": "ls" },
                "timeout_ms": 1_500,
            })
        );
    }

    #[test]
    fn slot_envelope_uses_whole_milliseconds() {
        let envelope = slot_envelope(0, "read", serde_json::Map::new(), Duration::from_secs(120));
        assert_eq!(envelope["slot"], 0);
        assert_eq!(envelope["params"], serde_json::json!({}));
        assert_eq!(envelope["timeout_ms"], 120_000);
    }
}
