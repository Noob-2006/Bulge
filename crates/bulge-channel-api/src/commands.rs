//! Chat commands: one list, shown everywhere a command menu exists.
//!
//! The same table drives the reply to `/help`, the Telegram command menu
//! (`setMyCommands`), and the command palette of bulge's own clients (the
//! remote channel sends it to devices when they connect), so a command is
//! added in one place.

use serde::{Deserialize, Serialize};

/// One command as shown in a menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command {
    /// Lowercase, without the slash.
    pub name: &'static str,
    /// What it does, in Traditional Chinese (the menus' language).
    pub summary: &'static str,
    /// The same in English (for apps whose menus are not localized).
    pub summary_en: &'static str,
    /// Handled at once, ahead of the chat's queue (it must work while a
    /// task is running).
    pub urgent: bool,
}

pub const COMMANDS: &[Command] = &[
    Command { name: "new", summary: "開始新的對話", summary_en: "Start a new conversation", urgent: false },
    Command { name: "stop", summary: "停止正在跑的任務", summary_en: "Stop the running task", urgent: true },
    Command { name: "status", summary: "目前的任務、模型與工作區", summary_en: "Current task, model and workspace", urgent: true },
    Command { name: "undo", summary: "回復最近一次寫回工作區的改動", summary_en: "Undo the latest write-back", urgent: false },
    Command { name: "help", summary: "列出指令與用法", summary_en: "List the commands", urgent: true },
];

/// A command as sent to bulge's own clients for their palette.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandInfo {
    pub name: String,
    pub summary: String,
}

pub fn infos() -> Vec<CommandInfo> {
    COMMANDS.iter().map(|c| CommandInfo { name: c.name.to_owned(), summary: c.summary.to_owned() }).collect()
}

/// What a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed<'a> {
    Command(&'static Command, &'a str),
    /// Looks like a command but is not one of ours.
    Unknown(&'a str),
    Text,
}

/// `/name args` (case-insensitive; `/name@bot` as Telegram writes it in
/// groups). `/start` is Telegram's greeting and means `/help`. Text that
/// starts with a path-like `/x/y` is not a command.
pub fn parse(text: &str) -> Parsed<'_> {
    let text = text.trim();
    let Some(rest) = text.strip_prefix('/') else { return Parsed::Text };
    let (head, args) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    let name = head.split('@').next().unwrap_or("");
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Parsed::Text;
    }
    let lower = name.to_ascii_lowercase();
    let lookup = if lower == "start" { "help" } else { lower.as_str() };
    match COMMANDS.iter().find(|c| c.name == lookup) {
        Some(command) => Parsed::Command(command, args.trim()),
        None => Parsed::Unknown(name),
    }
}

/// The `/help` text.
pub fn help() -> String {
    let mut out = String::from("直接傳訊息交辦任務；同一個聊天的訊息會接續同一段對話。可以先傳圖片或檔案，再用文字說明要做什麼。\n");
    for command in COMMANDS {
        out.push_str(&format!("\n/{} — {}", command.name, command.summary));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_parse_with_bot_suffix_case_and_args() {
        assert!(matches!(parse("/stop"), Parsed::Command(c, "") if c.name == "stop"));
        assert!(matches!(parse("  /NEW  "), Parsed::Command(c, "") if c.name == "new"));
        assert!(matches!(parse("/status@Bluge_bot"), Parsed::Command(c, _) if c.name == "status"));
        assert!(matches!(parse("/start"), Parsed::Command(c, _) if c.name == "help"));
        assert!(matches!(parse("/undo please"), Parsed::Command(c, "please") if c.name == "undo"));
        assert_eq!(parse("/frobnicate"), Parsed::Unknown("frobnicate"));
        assert_eq!(parse("/usr/bin is a path"), Parsed::Text);
        assert_eq!(parse("hello /stop"), Parsed::Text);
        assert!(help().contains("/stop — 停止正在跑的任務"));
        assert!(COMMANDS.iter().all(|c| c.name.chars().all(|ch| ch.is_ascii_lowercase()) && c.summary.chars().count() <= 256));
    }
}
