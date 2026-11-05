//! Native slash commands the host registers in-process (skills as `/name`, `/skills`,
//! `/memory`-family, `/context`, `/btw`, `/plugins` …). Every surface (`ark run`, `ark chat`,
//! channels, the daemon's `command.run` for the TUI / web UI) asks the kernel first via
//! `Runtime::run_slash`, then plugin commands, then Markdown custom commands.

use crate::kernel::Kernel;

/// What a native command produced: text to show the person and/or a prompt to send to the
/// session as if typed (e.g. a skill body, a `/learn` brief). Both `None` = handled silently.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SlashReply {
    pub text: Option<String>,
    pub prompt: Option<String>,
}

impl SlashReply {
    pub fn text(t: impl Into<String>) -> Self {
        SlashReply { text: Some(t.into()), prompt: None }
    }
    pub fn prompt(p: impl Into<String>) -> Self {
        SlashReply { text: None, prompt: Some(p.into()) }
    }
}

/// Where a command was typed.
pub struct SlashCtx {
    pub kernel: Kernel,
    /// The current session, when the surface has one.
    pub session: Option<String>,
    /// `cli` | `chat` | `tui` | `web` | `channel`.
    pub surface: String,
}

pub trait Slash: Send + Sync {
    /// (name, description) for help listings. Names have no leading `/`.
    fn commands(&self) -> Vec<(String, String)>;
    /// `None` when `name` is not one of this handler's commands.
    fn run(&self, ctx: &SlashCtx, name: &str, args: &str) -> Option<Result<SlashReply, String>>;
}

/// `/name args` → (name, args). `name@bot` (Telegram groups) drops the suffix.
pub fn split(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim().strip_prefix('/')?;
    let (name, args) = rest.split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())).unwrap_or((rest, ""));
    let name = name.split('@').next().unwrap_or(name);
    (!name.is_empty()).then_some((name, args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_names_and_args() {
        assert_eq!(split("/skills search pdf"), Some(("skills", "search pdf")));
        assert_eq!(split("  /btw@arkbot  why? "), Some(("btw", "why?")));
        assert_eq!(split("/"), None);
        assert_eq!(split("hello"), None);
    }
}
