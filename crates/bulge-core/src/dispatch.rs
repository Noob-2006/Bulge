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
            description: "Create or overwrite a workspace file with exact content. A success result means the file was written exactly; no need to read it back.".into(),
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
            description: "Run a shell command in the workspace. Output is captured; large output is saved to a file you can read. Chain related steps (`&&`, heredocs) into one command when you do not need to inspect the output in between.".into(),
            parameters: obj(json!({ "command": { "type": "string" }, "cwd": { "type": "string" } }), json!(["command"])),
            defer_loading: false,
        },
    ]
}

/// Read-only tools may run concurrently; mutating ones are barriers.
pub fn builtin_concurrency_safe(name: &str) -> bool {
    matches!(name, "read" | "glob" | "grep" | "view_image")
}

/// Name of the host-side planning tool (handled by the driver, never the VM).
pub const PLAN_TOOL: &str = "update_plan";

/// Name of the host-side delegation tool (handled by the driver via a
/// [`crate::driver::DelegateHandler`], never sent to the VM).
pub const DELEGATE_TOOL: &str = "delegate";

/// Name of the host-side recall tool: the agent searches its own past jobs
/// (handled by the driver via a [`crate::driver::RecallHandler`], never the VM).
pub const RECALL_TOOL: &str = "recall";

/// Name of the in-VM browser tool (headless Firefox driven over WebDriver BiDi
/// by sandboxd). Offered to the head agent only: sub-agent workspace slots do
/// not run a browser.
pub const BROWSER_TOOL: &str = "browser";

/// Schema for the `browser` tool.
pub fn browser_tool() -> ToolSchema {
    ToolSchema {
        name: BROWSER_TOOL.into(),
        description: "Use a real web browser (Firefox, inside the sandbox) to read and operate web pages: \
            navigate, then act on the page by the [eN] refs its snapshot lists. Every action returns a fresh \
            snapshot (URL, title, interactive elements with refs, visible text); refs change after each \
            snapshot, so always use the latest. Clicks and typing are real pointer/key events. Prefer `exec` \
            with curl for plain downloads or APIs; use the browser for pages that need JavaScript, forms, or \
            clicking through. To search the web, navigate straight to a results page — \
            https://duckduckgo.com/?q=<words> or https://www.bing.com/search?q=<words> — then open the \
            results that answer the question. Google answers automated browsers with a robot check; do not \
            try to get around it or any other captcha. Never submit payments, purchases, or other irreversible actions; ask the user instead.".into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["navigate", "snapshot", "click", "type", "press", "scroll", "back", "screenshot", "close"] },
                "url": { "type": "string", "description": "navigate: the address (https is assumed)" },
                "ref": { "type": "string", "description": "click/type: an element ref from the latest snapshot, e.g. e12" },
                "x": { "type": "integer", "description": "click without a ref: viewport x" },
                "y": { "type": "integer", "description": "click without a ref: viewport y" },
                "text": { "type": "string", "description": "type: the text to enter" },
                "clear": { "type": "boolean", "description": "type: replace the field's current content" },
                "submit": { "type": "boolean", "description": "type: press Enter afterwards" },
                "key": { "type": "string", "description": "press: Enter, Tab, Escape, Backspace, Delete, Space, ArrowUp/Down/Left/Right, PageUp, PageDown, Home, End" },
                "pages": { "type": "number", "description": "scroll: viewport heights, negative scrolls up (default 1)" }
            },
            "required": ["action"]
        }),
        defer_loading: false,
    }
}

/// Name of the image tool: sandboxd loads an image from the VM and the
/// driver attaches it to the conversation so the model sees it. Offered only
/// when the model accepts image input.
pub const VIEW_IMAGE_TOOL: &str = "view_image";

pub fn view_image_tool() -> ToolSchema {
    ToolSchema {
        name: VIEW_IMAGE_TOOL.into(),
        description: "Look at an image file (PNG, JPEG, GIF or WebP, up to 5 MB) in the workspace or the sandbox: \
            photos and files the user sent (inbox/), browser screenshots, charts you rendered. The image is shown \
            to you right after the result.".into(),
        parameters: json!({ "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] }),
        defer_loading: false,
    }
}

/// Name of the host-side skill tool: the agent loads the steps of one skill
/// from `<available_skills>` (handled by the driver via a
/// [`crate::driver::SkillHandler`], never the VM — skills live on the host).
pub const SKILL_TOOL: &str = "skill";

/// Name of the host-side organization status tool: a model-free digest of the
/// ticket board, budget, and running sub-agents (handled by the driver via a
/// [`crate::driver::OrgStatusHandler`], never the VM).
pub const ORG_STATUS_TOOL: &str = "org_status";

/// Schema for the organization situation-report tool. It takes no parameters.
pub fn org_status_tool() -> ToolSchema {
    ToolSchema {
        name: ORG_STATUS_TOOL.into(),
        description: "Get a model-free situation report of the organization: budget used, sub-agents running, and every ticket with its role and status. Cheap; call it before planning more work or when a delegation failed.".into(),
        parameters: json!({ "type": "object", "properties": {} }),
        defer_loading: false,
    }
}


/// Name of the host-side role-proposal tool (handled by the driver via a
/// [`crate::driver::ProposeRoleHandler`], never sent to the VM).
pub const PROPOSE_ROLE_TOOL: &str = "propose_role";

/// Schema for the governance proposal tool. A lead submits a full Markdown
/// charter; the host validates it, audits it independently, and installs it on
/// trial if both pass. The user can veto the role afterwards.
pub fn propose_role_tool() -> ToolSchema {
    ToolSchema {
        name: PROPOSE_ROLE_TOOL.into(),
        description: "Propose a new role for the organization when no existing role fits. Supply the full Markdown charter (with `---` frontmatter, the same format as <harness>/org/roles/*.md) and why you need it. The proposal is checked mechanically and audited independently; if both pass it is installed as a TRIAL role with a small budget share until it has a track record. The user can veto the role at any time.".into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "charter": {
                    "type": "string",
                    "description": "The full Markdown charter, frontmatter included, in the same format as <harness>/org/roles/*.md."
                },
                "reason": {
                    "type": "string",
                    "description": "Why the organization needs this role."
                }
            },
            "required": ["charter", "reason"]
        }),
        defer_loading: false,
    }
}

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
