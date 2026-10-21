//! Tool dispatch: the loop asks a `ToolDispatcher` to run one tool call. The
//! real implementation forwards to the guest VM; tests use a fake.

use futures::future::BoxFuture;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use bulge_llm::ToolSchema;

use crate::schedule::CallOutcome;

/// A tool call handed to the dispatcher.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub name: String,
    pub arguments: serde_json::Map<String, Value>,
}

pub trait ToolDispatcher: Send + Sync {
    fn dispatch(&self, call: ToolCall, cancel: CancellationToken) -> BoxFuture<'static, CallOutcome>;
    /// Whether this tool may run concurrently with adjacent ones (read-only).
    fn concurrency_safe(&self, name: &str) -> bool;
}

/// Built-in tool schemas the model sees, matching sandboxd's handlers. Backends
/// (MCP, etc.) can append more later.
pub fn builtin_tools() -> Vec<ToolSchema> {
    let obj = |props: Value, required: Value| json!({ "type": "object", "properties": props, "required": required });
    vec![
        ToolSchema {
            name: "read".into(),
            description: "Read a UTF-8 text file (or list a directory) in the workspace, with line numbers. Use offset/limit to page.".into(),
            parameters: obj(json!({ "path": { "type": "string" }, "offset": { "type": "integer" }, "limit": { "type": "integer" } }), json!(["path"])),
            defer_loading: false,
        },
        ToolSchema {
            name: "write".into(),
            description: "Create or overwrite a workspace file with exact content.".into(),
            parameters: obj(json!({ "path": { "type": "string" }, "content": { "type": "string" } }), json!(["path", "content"])),
            defer_loading: false,
        },
        ToolSchema {
            name: "edit".into(),
            description: "Replace an exact string in a workspace file. old_string must be unique unless replace_all is set.".into(),
            parameters: obj(
                json!({ "path": { "type": "string" }, "old_string": { "type": "string" }, "new_string": { "type": "string" }, "replace_all": { "type": "boolean" } }),
                json!(["path", "old_string", "new_string"]),
            ),
            defer_loading: false,
        },
        ToolSchema {
            name: "glob".into(),
            description: "List workspace files matching a glob pattern (honours .gitignore).".into(),
            parameters: obj(json!({ "pattern": { "type": "string" }, "path": { "type": "string" } }), json!(["pattern"])),
            defer_loading: false,
        },
        ToolSchema {
            name: "grep".into(),
            description: "Search workspace file contents with a regular expression.".into(),
            parameters: obj(
                json!({ "pattern": { "type": "string" }, "path": { "type": "string" }, "glob": { "type": "string" }, "case_insensitive": { "type": "boolean" } }),
                json!(["pattern"]),
            ),
            defer_loading: false,
        },
        ToolSchema {
            name: "exec".into(),
            description: "Run a shell command in the workspace. Output is captured; large output is saved to a file you can read.".into(),
            parameters: obj(json!({ "command": { "type": "string" }, "cwd": { "type": "string" } }), json!(["command"])),
            defer_loading: false,
        },
    ]
}

/// Read-only tools may run concurrently; mutating ones are barriers.
pub fn builtin_concurrency_safe(name: &str) -> bool {
    matches!(name, "read" | "glob" | "grep")
}

/// Name of the host-side planning tool (handled by the driver, never the VM).
pub const PLAN_TOOL: &str = "update_plan";

/// Name of the host-side delegation tool (handled by the driver via a
/// [`crate::driver::DelegateHandler`], never sent to the VM).
pub const DELEGATE_TOOL: &str = "delegate";

/// Name of the host-side recall tool: the agent searches its own past jobs
/// (handled by the driver via a [`crate::driver::RecallHandler`], never the VM).
pub const RECALL_TOOL: &str = "recall";

/// Schema for the planning tool. Callers append it to `builtin_tools()` when they
/// want the model to keep a visible plan; the driver intercepts its calls,
/// records the plan, and watches for a stall. Status is one of
/// `pending` | `in_progress` | `done` | `dropped` (default `pending`).
pub fn plan_tool() -> ToolSchema {
    ToolSchema {
        name: PLAN_TOOL.into(),
        description: "Replace your working plan with an ordered checklist. Call it when the plan changes and mark items done as you finish them, so progress is visible and a stall can be caught.".into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "text": { "type": "string" },
                            "status": { "type": "string", "enum": ["pending", "in_progress", "done", "dropped"] }
                        },
                        "required": ["text"]
                    }
                }
            },
            "required": ["items"]
        }),
        defer_loading: false,
    }
}
