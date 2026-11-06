//! What the TUI does with a `command.run` reply (Hermes `ui-tui/src/app/slash/commands*`):
//! the daemon answers a slash line with `{handled, text, prompt, action}`, and the
//! `action` is a surface-local effect — `new_session` (`/new`, `/reset`, `/clear`),
//! `quit` (`/quit`, `/exit`, `--delete`), or a `local` command: `redraw`, `copy`,
//! `paste`, `image`, `compose` (`/prompt`), `palette`, `statusbar`, `workspace` and the
//! display preferences (`verbose`, `timestamps`, `focus`, `trace`, `footer`).
//!
//! [`apply_reply`] is deliberately free of I/O: every daemon call goes through the
//! `rpc` closure, so the whole slash surface is unit-tested with a fake daemon.

use super::palette;
use super::{display, prefs, statusbar, Flow, State};
use crate::clip;
use serde_json::{json, Value};
use std::path::PathBuf;

pub type Rpc<'a> = &'a mut dyn FnMut(&str, Value) -> Result<Value, String>;

/// Apply the `action` (and the text/prompt) of one `command.run` reply.
pub(crate) fn apply_reply(st: &mut State, reply: &Value, rpc: Rpc) -> Flow {
    if reply["handled"].as_bool() != Some(true) {
        return Flow::Continue;
    }
    let action = &reply["action"];
    match action["kind"].as_str() {
        Some("new_session") => new_session(st, action["clear"].as_bool() == Some(true), rpc),
        Some("quit") => {
            quit(st, action["delete"].as_bool() == Some(true), rpc);
            return Flow::Quit;
        }
        Some("local") => local(st, action["name"].as_str().unwrap_or(""), action["arg"].as_str().unwrap_or(""), rpc),
        _ => {}
    }
    if let Some(t) = reply["text"].as_str().filter(|t| !t.trim().is_empty()) {
        st.notice(t);
    }
    // `/model x`, plugin commands and custom prompts hand the line back for submission.
    match reply["prompt"].as_str().filter(|p| !p.trim().is_empty()) {
        Some(p) => super::submit_text(st, p.to_string(), rpc),
        None => Flow::Continue,
    }
}

/// Re-read the current session's transcript (after `/undo` or a switch to a fork).
pub(crate) fn reload_current(st: &mut State, rpc: Rpc) {
    let Some(id) = st.current.clone() else { return };
    st.lines.clear();
    st.streaming.clear();
    st.scroll = 0;
    if let Ok(v) = rpc("session.view", json!({"id": id})) {
        st.running = v["running"].as_bool().unwrap_or(false);
        for m in v["messages"].as_array().into_iter().flatten() {
            super::push_message(st, m);
        }
    }
}

/// Adopt an existing session (a `/branch` returns its id through a `local` action).
fn adopt(st: &mut State, id: &str, rpc: Rpc) {
    st.current = Some(id.to_string());
    st.sessions = rpc("session.list", json!({"limit": 200})).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
    reload_current(st, rpc);
    st.reload_display();
}

/// `/new` and `/clear`: create a session on the daemon and adopt it here.
pub(crate) fn new_session(st: &mut State, clear: bool, rpc: Rpc) {
    // `/new` mid-turn: the daemon keeps the old turn running; remember it so its
    // completion is announced here when it lands.
    let background = super::background_current(st);
    let create = rpc("session.create", json!({"workspace": st.workspace.display().to_string(), "title": "終端機對話"}));
    match create {
        Ok(r) => {
            st.current = r["id"].as_str().map(str::to_string);
            st.sessions = rpc("session.list", json!({"limit": 200})).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
            st.lines.clear();
            st.streaming.clear();
            st.scroll = 0;
            if let Some(id) = st.current.clone() {
                if let Ok(v) = rpc("session.view", json!({"id": id})) {
                    st.running = v["running"].as_bool().unwrap_or(false);
                    for m in v["messages"].as_array().into_iter().flatten() {
                        super::push_message(st, m);
                    }
                }
                if clear {
                    st.notice(format!("・已清空畫面，新對話 {id}"));
                } else {
                    st.notice(format!("・新對話 {id}"));
                }
                if let Some(old) = background {
                    st.notice(format!("・{old} 仍在背景執行；完成時會在這裡通知（原對話保留）"));
                }
            }
            st.reload_display();
            // `/clear` wipes the screen too.
            st.repaint = clear;
        }
        Err(e) => st.notice(format!("⚠ 無法建立對話：{e}")),
    }
}

/// `/quit`, `/exit` and `--delete`. Ending/removing sessions is best-effort: the daemon
/// may serve `session.remove`/`session.end`, and either way the loop exits cleanly.
fn quit(st: &mut State, delete: bool, rpc: Rpc) {
    let Some(id) = st.current.clone() else { return };
    if !delete {
        return;
    }
    // `seagent chat --delete` ends the session, then drops its log: same order here.
    let _ = rpc("session.end", json!({"id": id, "reason": "exit"}));
    let _ = rpc("session.remove", json!({"id": id}));
    st.status = format!("已刪除對話 {id}");
}

/// A surface-local command (`action.kind == "local"`).
fn local(st: &mut State, name: &str, arg: &str, rpc: Rpc) {
    match name {
        "redraw" => {
            st.repaint = true;
            st.scroll = 0;
        }
        "copy" => {
            let last = st.lines.iter().rev().find(|l| l.kind == "assistant").map(|l| l.text.clone()).filter(|t| !t.trim().is_empty());
            match last {
                Some(t) => match clip::copy(&t) {
                    Ok(how) => st.status = format!("已複製 {} 字元（{how}）", t.chars().count()),
                    Err(e) => st.status = format!("⚠ 無法複製：{e}"),
                },
                None => st.status = "還沒有可以複製的回答".into(),
            }
        }
        "paste" => match clip::paste_image() {
            Ok(b) => {
                st.attach.push(b);
                st.status = format!("已附加剪貼簿圖片（{} 張待送出）", st.attach.len());
            }
            Err(e) => st.status = format!("⚠ {e}"),
        },
        "image" => {
            let (path, rest) = clip::split_path_input(arg);
            match clip::image_file(&path, &st.workspace) {
                Ok(b) => {
                    st.attach.push(b);
                    st.status = format!("已附加 {path}（{} 張待送出）", st.attach.len());
                    // Hermes leaves the rest of the line as the prompt.
                    if !rest.is_empty() {
                        st.input = rest;
                    }
                }
                Err(e) => st.status = format!("⚠ {e}"),
            }
        }
        // `/prompt`, `/compose`: the loop suspends raw mode and runs `$EDITOR` on this seed.
        "compose" => {
            if !arg.trim().is_empty() {
                st.input = arg.to_string();
            }
            st.compose = Some(st.input.clone());
        }
        "palette" => {
            let list = rpc("command.list", json!({})).unwrap_or(Value::Null);
            st.palette.open_with(palette::items(&list), arg);
            st.status = format!("指令面板 · {} 個符合", st.palette.matches.len());
        }
        "statusbar" => {
            let cur = statusbar::Mode::from_value(&prefs::get(&st.ux.prefs, "statusbar"));
            match statusbar::Mode::parse(arg, cur) {
                Some(m) => {
                    if !st.ux.prefs.is_object() {
                        st.ux.prefs = json!({});
                    }
                    st.ux.prefs["statusbar"] = json!(m.as_str());
                    let _ = prefs::set(&st.ux.paths, "statusbar", json!(m.as_str()));
                    st.status = format!("狀態列 → {}", m.as_str());
                }
                None => st.status = "用法：/statusbar [on|off|top|bottom]".into(),
            }
        }
        // The slash layer already wrote `<data>/display.json`; mirror it for this frame.
        "verbose" | "timestamps" | "focus" | "trace" | "footer" => apply_display(st, name, arg),
        // `/branch` / `/fork`: the reply names the new session id.
        "session" => {
            if !arg.is_empty() {
                adopt(st, arg, rpc);
            }
        }
        // `/worktree new` moved the session in the daemon; adopt the tree here too.
        "workspace" => {
            if !arg.is_empty() {
                st.workspace = PathBuf::from(arg);
            }
            st.ux.reload();
        }
        _ => st.status = format!("· {name} {arg}"),
    }
}

fn apply_display(st: &mut State, key: &str, arg: &str) {
    let flag = |a: &str, cur: bool| match a.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => true,
        "off" | "false" | "no" | "0" => false,
        _ => cur,
    };
    match key {
        "verbose" => match display::Verbose::parse(arg) {
            Some(v) => st.disp.verbose = v,
            None => st.reload_display(),
        },
        "timestamps" => st.disp.timestamps = flag(arg, st.disp.timestamps),
        "focus" => st.disp.focus = flag(arg, st.disp.focus),
        "trace" => st.disp.trace = flag(arg, st.disp.trace),
        "footer" => st.disp.footer = flag(arg, st.disp.footer),
        _ => {}
    }
    st.status = format!("{key} → {arg}");
}

#[cfg(test)]
mod tests {
    use super::super::Line;
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Calls the fake daemon recorded, in order.
    type Calls = Rc<RefCell<Vec<(String, Value)>>>;

    /// Fake daemon: records every call and answers like `command.run`/`session.*` do.
    fn fake() -> (Calls, impl FnMut(&str, Value) -> Result<Value, String>) {
        let log = Rc::new(RefCell::new(Vec::new()));
        let l = log.clone();
        let f = move |m: &str, p: Value| -> Result<Value, String> {
            l.borrow_mut().push((m.to_string(), p));
            Ok(match m {
                "session.create" => json!({"id": "s-new"}),
                "session.list" => json!([{"id": "s-new", "title": "終端機對話", "running": false}]),
                "session.view" => json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}], "running": false}),
                "command.list" => json!([
                    {"name": "redraw", "aliases": [], "args": "", "description": "Force a full repaint", "category": "Session", "source": "builtin", "local": true},
                    {"name": "model", "aliases": [], "args": "[provider/model]", "description": "Show or switch this session's model", "category": "Session", "source": "builtin"},
                    {"name": "custom-thing", "description": "A custom Markdown command", "category": "Custom", "source": "custom"}
                ]),
                "session.submit" | "session.submit_with" => json!({"queued": true, "started": true}),
                "gate.pending" => json!([]),
                _ => json!({}),
            })
        };
        (log, f)
    }

    fn reply(action: Value) -> Value {
        json!({"handled": true, "text": null, "prompt": null, "action": action})
    }

    fn state(tag: &str) -> State {
        super::super::test_state(tag)
    }

    fn calls(log: &Rc<RefCell<Vec<(String, Value)>>>) -> Vec<(String, Value)> {
        log.borrow().clone()
    }

    #[test]
    fn new_session_creates_and_adopts() {
        let mut st = state("act-new");
        st.current = Some("old".into());
        st.lines.push(Line::new("user", "old line"));
        let (log, mut rpc) = fake();
        assert_eq!(apply_reply(&mut st, &reply(json!({"kind": "new_session", "clear": false})), &mut rpc), Flow::Continue);
        assert_eq!(st.current.as_deref(), Some("s-new"));
        assert_eq!(st.sessions.len(), 1);
        assert!(st.lines.iter().any(|l| l.text == "hi"), "history of the new session is loaded");
        assert!(!st.lines.iter().any(|l| l.text == "old line"), "the old transcript is gone");
        let names: Vec<String> = calls(&log).into_iter().map(|(m, _)| m).collect();
        assert_eq!(&names[..2], ["session.create", "session.list"]);
        assert!(names.contains(&"session.view".to_string()));
        assert!(!st.repaint, "/new keeps the screen");
    }

    #[test]
    fn new_mid_turn_keeps_the_old_turn_in_the_background() {
        let mut st = state("act-bg");
        st.current = Some("old".into());
        st.running = true;
        st.sessions = vec![json!({"id": "old", "title": "deploy", "running": true})];
        let (_log, mut rpc) = fake();
        apply_reply(&mut st, &reply(json!({"kind": "new_session", "clear": false})), &mut rpc);
        assert_eq!(st.current.as_deref(), Some("s-new"));
        assert_eq!(st.background.get("old").map(String::as_str), Some("deploy"), "the old turn is remembered for its completion notice");
        assert!(st.lines.iter().any(|l| l.text.contains("old") && l.text.contains("背景執行")), "the user is told it keeps running");
        assert!(!st.running, "the new session is idle");
    }

    #[test]
    fn clear_clears_lines_and_repaints() {
        let mut st = state("act-clear");
        st.lines.push(Line::new("assistant", "long answer"));
        st.scroll = 42;
        let (_log, mut rpc) = fake();
        apply_reply(&mut st, &reply(json!({"kind": "new_session", "clear": true})), &mut rpc);
        assert_eq!(st.current.as_deref(), Some("s-new"));
        assert!(!st.lines.iter().any(|l| l.text == "long answer"));
        assert_eq!(st.scroll, 0);
        assert!(st.repaint, "/clear repaints the screen");
    }

    #[test]
    fn branch_session_action_switches_to_the_fork() {
        let mut st = state("act-fork");
        st.current = Some("old".into());
        st.lines.push(Line::new("user", "old line"));
        let (log, mut rpc) = fake();
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "session", "arg": "s-new"})), &mut rpc);
        assert_eq!(st.current.as_deref(), Some("s-new"));
        assert!(!st.lines.iter().any(|l| l.text == "old line"));
        assert!(st.lines.iter().any(|l| l.text == "hi"), "the fork's transcript is loaded");
        let names: Vec<String> = calls(&log).into_iter().map(|(m, _)| m).collect();
        assert_eq!(names, ["session.list", "session.view"]);
    }

    #[test]
    fn quit_with_delete_removes_the_session() {
        let mut st = state("act-quit");
        st.current = Some("s1".into());
        let (log, mut rpc) = fake();
        assert_eq!(apply_reply(&mut st, &reply(json!({"kind": "quit", "delete": true})), &mut rpc), Flow::Quit);
        let c = calls(&log);
        assert_eq!(c[0].0, "session.end");
        assert_eq!(c[0].1["id"], json!("s1"));
        assert_eq!(c[1].0, "session.remove");
        // Without --delete nothing is removed.
        let (log, mut rpc) = fake();
        assert_eq!(apply_reply(&mut st, &reply(json!({"kind": "quit", "delete": false})), &mut rpc), Flow::Quit);
        assert!(calls(&log).is_empty(), "no deletion without --delete");
    }

    #[test]
    fn redraw_and_copy() {
        let mut st = state("act-redraw");
        st.scroll = 30;
        let (_log, mut rpc) = fake();
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "redraw", "arg": ""})), &mut rpc);
        assert!(st.repaint && st.scroll == 0);
        // /copy with nothing to copy just says so; with an answer it never panics.
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "copy", "arg": ""})), &mut rpc);
        assert!(st.status.contains("沒有"));
        st.lines.push(Line::new("assistant", "the last answer"));
        st.repaint = false;
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "copy", "arg": ""})), &mut rpc);
        assert!(st.status.contains("複製") || st.status.contains("無法"), "{}", st.status);
    }

    #[test]
    fn image_and_paste_attach_blocks_to_the_next_message() {
        let mut st = state("act-attach");
        st.current = Some("s1".into());
        let dir = seagent_core::tmp::scratch("seagent-tui-img");
        std::fs::write(dir.join("shot.png"), b"\x89PNG\r\n\x1a\n0000").unwrap();
        st.workspace = dir.clone();
        let (_log, mut rpc) = fake();
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "image", "arg": "shot.png"})), &mut rpc);
        assert_eq!(st.attach.len(), 1, "{}", st.status);
        assert!(matches!(&st.attach[0], seagent_core::Block::Image { media_type, .. } if media_type == "image/png"));
        // The next submit carries them as blocks.
        let (log, mut rpc) = fake();
        super::super::submit_text(&mut st, "look at this".into(), &mut rpc);
        let submit = calls(&log).into_iter().find(|(m, _)| m == "session.submit_with").expect("submitted through submit_with");
        assert_eq!(submit.1["blocks"][0]["type"], json!("image"));
        assert_eq!(submit.1["text"], json!("look at this"));
        assert!(st.attach.is_empty(), "attachments are consumed once sent");
        // A missing file reports an error instead of attaching.
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "image", "arg": "nope.png"})), &mut rpc);
        assert!(st.attach.is_empty() && st.status.starts_with('⚠'));
        // `/image shot.png describe it`: the rest of the line becomes the pending prompt.
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "image", "arg": "shot.png describe it"})), &mut rpc);
        assert_eq!(st.attach.len(), 1, "{}", st.status);
        assert_eq!(st.input, "describe it");
    }

    #[test]
    fn compose_asks_the_loop_to_open_the_editor() {
        let mut st = state("act-compose");
        st.input = "half-written".into();
        let (_log, mut rpc) = fake();
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "compose", "arg": ""})), &mut rpc);
        assert_eq!(st.compose.as_deref(), Some("half-written"), "seeded with the draft");
        st.compose = None;
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "compose", "arg": "from the slash line"})), &mut rpc);
        assert_eq!(st.input, "from the slash line");
        assert_eq!(st.compose.as_deref(), Some("from the slash line"));
    }

    #[test]
    fn display_preferences_apply() {
        let mut st = state("act-disp");
        assert!(!st.disp.timestamps && !st.disp.focus && st.disp.footer && st.disp.trace);
        let (_log, mut rpc) = fake();
        for (name, arg) in [("timestamps", "on"), ("focus", "off"), ("footer", "off"), ("trace", "off")] {
            apply_reply(&mut st, &reply(json!({"kind": "local", "name": name, "arg": arg})), &mut rpc);
        }
        assert!(st.disp.timestamps);
        assert!(!st.disp.focus && !st.disp.footer && !st.disp.trace);
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "verbose", "arg": "off"})), &mut rpc);
        assert_eq!(st.disp.verbose, display::Verbose::Off);
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "verbose", "arg": "verbose"})), &mut rpc);
        assert_eq!(st.disp.verbose, display::Verbose::Verbose);
        // Tool lines disappear with /verbose off and /focus, and daemon notices with /trace off.
        st.lines = vec![Line::new("user", "q"), Line::new("tool", "⚙ run"), Line::new("assistant", "a"), Line::new("trace", "· notice")];
        let kinds = |s: &State| super::super::visible_lines(s).into_iter().map(|l| l.kind).collect::<Vec<_>>();
        assert_eq!(kinds(&st), vec!["user", "tool", "assistant"], "verbose keeps tool lines, trace off drops notices");
        st.disp.verbose = display::Verbose::Off;
        assert_eq!(kinds(&st), vec!["user", "assistant"]);
        st.disp.verbose = display::Verbose::All;
        st.disp.trace = true;
        assert_eq!(kinds(&st).len(), 4);
        st.disp.focus = true;
        assert_eq!(kinds(&st), vec!["user", "assistant"]);
    }

    #[test]
    fn statusbar_modes_hide_and_move_the_bar() {
        let mut st = state("act-sb");
        let (_log, mut rpc) = fake();
        assert_eq!(st.status_mode(), statusbar::Mode::Top, "upstream default");
        assert!(super::super::draw(&mut st).contains("ctx —") || super::super::draw(&mut st).contains("⏲ 0s"));
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "statusbar", "arg": "off"})), &mut rpc);
        assert_eq!(st.status_mode(), statusbar::Mode::Off);
        assert!(!super::super::draw(&mut st).contains("⏲ 0s"), "off hides the bar");
        assert_eq!(prefs::get_str(&prefs::load(&st.ux.paths), "statusbar", "?"), "off", "persisted in ui.json");
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "statusbar", "arg": ""})), &mut rpc);
        assert_eq!(st.status_mode(), statusbar::Mode::Top, "bare /statusbar toggles back on at the top");
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "statusbar", "arg": "bottom"})), &mut rpc);
        assert_eq!(st.status_mode(), statusbar::Mode::Bottom);
        assert!(super::super::draw(&mut st).contains("⏲ 0s"));
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "statusbar", "arg": "sideways"})), &mut rpc);
        assert!(st.status.contains("用法"), "{}", st.status);
    }

    #[test]
    fn palette_opens_and_enter_runs_the_command() {
        let mut st = state("act-pal");
        let (log, mut rpc) = fake();
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "palette", "arg": ""})), &mut rpc);
        assert!(st.palette.open);
        assert_eq!(st.palette.items.len(), 3);
        assert!(calls(&log).iter().any(|(m, _)| m == "command.list"));
        assert!(super::super::draw(&mut st).contains("指令面板"), "the overlay is rendered");
        // Typing filters, Enter on a command with no args runs it.
        st.palette.push('r');
        st.palette.push('e');
        st.palette.push('d');
        assert_eq!(st.palette.selected().map(|i| i.name.as_str()), Some("redraw"));
        let mut rpc = { let log = log.clone(); move |m: &str, p: Value| { log.borrow_mut().push((m.to_string(), p)); Ok(json!({"handled": true, "action": {"kind": "local", "name": "redraw", "arg": ""}})) } };
        st.repaint = false;
        assert_eq!(super::super::palette_run(&mut st, &mut rpc), Flow::Continue);
        assert!(!st.palette.open);
        assert!(st.repaint, "the palette ran /redraw through the normal submit path");
        // A command with arguments fills the composer instead of running.
        let (_log, mut rpc) = fake();
        apply_reply(&mut st, &reply(json!({"kind": "local", "name": "palette", "arg": ""})), &mut rpc);
        st.palette.push('m');
        st.palette.push('o');
        assert_eq!(st.palette.selected().map(|i| i.name.as_str()), Some("model"));
        assert_eq!(super::super::palette_run(&mut st, &mut rpc), Flow::Continue);
        assert_eq!(st.input, "/model ");
        assert!(!st.palette.open);
    }

    #[test]
    fn prompt_reply_is_submitted() {
        let mut st = state("act-prompt");
        st.current = Some("s1".into());
        let (log, mut rpc) = fake();
        let r = json!({"handled": true, "text": "switching", "prompt": "explain this repo", "action": null});
        assert_eq!(apply_reply(&mut st, &r, &mut rpc), Flow::Continue);
        assert!(st.lines.iter().any(|l| l.text == "switching"));
        let submit = calls(&log).into_iter().find(|(m, _)| m == "session.submit").expect("prompt submitted");
        assert_eq!(submit.1["text"], json!("explain this repo"));
        // Unhandled replies (plugin/custom commands the daemon does not know) do nothing.
        let (_log, mut rpc) = fake();
        assert_eq!(apply_reply(&mut st, &json!({"handled": false}), &mut rpc), Flow::Continue);
    }
}
