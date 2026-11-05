//! Startup tips (Hermes `hermes_cli/tips.py`): one random tip at `seagent tui` / `seagent chat`
//! start (and on `/new`) to help discover features, plus rotating example prompts for an
//! empty composer. Off with `tips = false` in `ui.json` (`/tips off`). The catalog is
//! seagent's own (the commands differ from Hermes'); zh-Hant when `LANG` starts with `zh`.

const TIPS_EN: &[&str] = &[
    "/btw <question> answers a side question about this conversation without interrupting the running turn.",
    "/queue <prompt> lines up a prompt for after the current turn; /busy picks steer, queue, collect or interrupt.",
    "/steer <text> nudges a running turn without stopping it.",
    "/undo restores workspace files to the last checkpoint; /diff shows what changed.",
    "/compact squeezes the context now instead of waiting for the automatic threshold.",
    "/plan <task> asks for a plan first; /review reviews the current diff.",
    "/init writes an AGENTS.md for this project so future sessions start with context.",
    "/learn <source> turns a directory, URL or this chat into a reusable skill.",
    "/model provider/model switches this session's model; /status shows tokens, context and queue.",
    "/export-session file.html saves a shareable transcript; /save writes Markdown.",
    "Ctrl+S parks the draft you are typing; press it again on an empty composer to bring it back.",
    "/skin lists themes; /skin ares switches the whole terminal look. `seagent skin set ui_accent '#00FFFF'` tweaks one colour.",
    "/battery shows a colour-coded battery level in the status bar.",
    "/indicator kaomoji|emoji|unicode|ascii picks the busy indicator.",
    "/pet adopts an animated petdex mascot that reacts to what the agent is doing; /hatch draws a new one.",
    "/statusbar toggles the bottom bar with model, context %, git branch and elapsed time.",
    "/copy puts the last answer on the clipboard; /paste attaches a clipboard image to your next message.",
    "/prompt opens $EDITOR to compose a long message.",
    "/personality switches the agent's voice; /verbose and /focus change how much tool output you see.",
    "/timestamps on adds [HH:MM] to messages and /history.",
    "`seagent profile create work` keeps a separate config, memory and skills; run with `seagent -p work tui`.",
    "`seagent rooms create` starts a group chat where several profiles discuss your question in turns.",
    "`seagent backup create` snapshots config and state; `seagent backup restore` brings them back.",
    "`seagent doctor` checks config, providers and the daemon; `seagent logs -f` follows the daemon log.",
    "`seagent cron` schedules prompts; the daemon runs them even while no terminal is open.",
    "`seagent mcp` adds tool servers; /mcp shows which are connected in this session.",
    "`seagent update` checks for and installs a newer release (with rollback).",
    "Long tasks keep running in the daemon: close the terminal and reattach later with `seagent tui`.",
    "Alt+Enter inserts a newline; Ctrl+↑/↓ switches between sessions in the TUI.",
    "Set `bell_on_complete = true` (`/bell on`) to get a desktop notification when a turn finishes.",
];

const TIPS_ZH: &[&str] = &[
    "/btw <問題> 可在不打斷目前回合的情況下問一個旁支問題。",
    "/queue <提示> 把提示排到目前回合之後；/busy 選擇 steer、queue、collect 或 interrupt。",
    "/steer <文字> 在不停止的情況下引導正在進行的回合。",
    "/undo 把工作區檔案還原到上一個檢查點；/diff 顯示改了什麼。",
    "/compact 立即壓縮上下文，不必等自動門檻。",
    "/plan <任務> 先產生計畫；/review 審查目前的 diff。",
    "/init 為專案寫一份 AGENTS.md，之後的對話一開始就有脈絡。",
    "/learn <來源> 把資料夾、網址或這段對話變成可重用的技能。",
    "/model provider/model 切換本對話的模型；/status 顯示 token、上下文與佇列。",
    "Ctrl+S 暫存正在輸入的草稿；在空白輸入框再按一次即可取回。",
    "/skin 列出主題；/skin ares 切換整個終端機外觀。`seagent skin set ui_accent '#00FFFF'` 可調單一顏色。",
    "/battery 在狀態列顯示依電量上色的電池指示。",
    "/indicator kaomoji|emoji|unicode|ascii 選擇忙碌指示樣式。",
    "/pet 領養會隨 agent 動作變化的 petdex 寵物；/hatch 畫一隻新的。",
    "/statusbar 開關底部狀態列（模型、上下文 %、git 分支、經過時間）。",
    "/copy 複製上一則回答；/paste 把剪貼簿圖片附到下一則訊息。",
    "`seagent profile create work` 建立獨立的設定、記憶與技能；用 `seagent -p work tui` 執行。",
    "`seagent rooms create` 建立群組聊天，讓多個 profile 輪流討論你的問題。",
    "`seagent doctor` 檢查設定、供應商與 daemon；`seagent logs -f` 追蹤 daemon 日誌。",
    "長時間任務在 daemon 中繼續執行：關掉終端機，之後用 `seagent tui` 回來。",
    "Alt+Enter 換行；TUI 中 Ctrl+↑/↓ 切換對話。",
    "設定 `/bell on`，回合結束時會跳出桌面通知。",
];

const PLACEHOLDERS_EN: &[&str] = &["Ask anything, or describe a task…", "Summarize what changed in this project this week", "Find and fix the failing test", "Draft a reply to the last email in my inbox", "Plan a refactor of the module I have open"];
const PLACEHOLDERS_ZH: &[&str] = &["輸入任何問題，或描述一個任務…", "整理這個專案本週的變更", "找出並修好失敗的測試", "幫我規劃目前這個模組的重構"];

fn zh() -> bool {
    ["LC_ALL", "LC_MESSAGES", "LANG"].iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty())).is_some_and(|v| v.starts_with("zh"))
}

pub fn tips(zh_hant: bool) -> &'static [&'static str] {
    if zh_hant {
        TIPS_ZH
    } else {
        TIPS_EN
    }
}

fn pick<'a>(list: &'a [&'a str], seed: u64) -> &'a str {
    list.get((seed % list.len().max(1) as u64) as usize).copied().unwrap_or("")
}

fn seed() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64 ^ std::process::id() as u64).unwrap_or(7)
}

/// A random tip in the active language (empty when the catalog is empty).
pub fn random_tip() -> String {
    pick(tips(zh()), seed()).to_string()
}

pub fn random_placeholder() -> String {
    pick(if zh() { PLACEHOLDERS_ZH } else { PLACEHOLDERS_EN }, seed()).to_string()
}

/// The startup line, or `None` when tips are switched off in `ui.json`.
pub fn startup_line(prefs: &serde_json::Value) -> Option<String> {
    super::prefs::get_bool(prefs, "tips", true).then(|| format!("✦ tip: {}", random_tip()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tips_pick_and_switch_off() {
        assert!(TIPS_EN.len() >= 25 && TIPS_ZH.len() >= 20);
        // The catalog follows the language flag (`LANG` starts with `zh` → zh-Hant).
        assert_eq!(tips(false), TIPS_EN);
        assert_eq!(tips(true), TIPS_ZH);
        assert!(tips(true)[0].starts_with("/btw") && tips(true)[0].chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)));
        assert_eq!(pick(TIPS_EN, 0), TIPS_EN[0]);
        assert_eq!(pick(TIPS_EN, TIPS_EN.len() as u64 + 1), TIPS_EN[1]);
        assert!(!random_tip().is_empty());
        assert!(startup_line(&serde_json::json!({})).unwrap().starts_with("✦ tip: "));
        assert!(startup_line(&serde_json::json!({"tips": false})).is_none());
        assert!(!random_placeholder().is_empty());
    }
}
