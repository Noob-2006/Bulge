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
}

impl VmDispatcher {
    pub fn new(vm: Arc<Vm>, timeout: Duration) -> Self {
        Self { vm, timeout }
    }
}

impl ToolDispatcher for VmDispatcher {
    fn dispatch(&self, call: ToolCall, cancel: CancellationToken) -> BoxFuture<'static, CallOutcome> {
        let vm = self.vm.clone();
        let timeout = self.timeout;
        async move {
            let params = Value::Object(call.arguments);
            tokio::select! {
                // The guest also enforces the timeout; this is the host-side cancel path.
                () = cancel.cancelled() => CallOutcome::Skipped,
                outcome = vm.invoke(&call.name, params, Some(timeout)) => match outcome {
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
