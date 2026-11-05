//! TUI status bar (Hermes `cli_status_bar_mixin.py`): busy indicator, model, context
//! gauge (`[████░░░░░░] 42%`, coloured good/warn/bad/critical), tokens, prompt-cache hit
//! rate, compactions, per-prompt elapsed time (`⏱` live / `⏲` frozen), `✓ 42s` idle-since,
//! git branch, battery (when `/battery on`) and the Ctrl+S stash indicator. Segments
//! are dropped lowest-priority first when the terminal is narrow.

use super::battery::{self, Battery};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where the bar sits (`/statusbar [on|off|top|bottom|toggle]`, Hermes `core.ts`):
/// upstream defaults to `top` and a bare `/statusbar` toggles between top and off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    Off,
    #[default]
    Top,
    Bottom,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Top => "top",
            Mode::Bottom => "bottom",
        }
    }

    pub fn shown(&self) -> bool {
        !matches!(self, Mode::Off)
    }

    /// `/statusbar <arg>` against the current mode; `None` = unknown argument.
    pub fn parse(arg: &str, current: Mode) -> Option<Mode> {
        match arg.trim().to_ascii_lowercase().as_str() {
            "" | "toggle" => Some(if current.shown() { Mode::Off } else { Mode::Top }),
            "on" | "top" | "true" | "yes" => Some(Mode::Top),
            "off" | "false" | "no" => Some(Mode::Off),
            "bottom" => Some(Mode::Bottom),
            _ => None,
        }
    }

    /// The `statusbar` value in `ui.json`: a string mode, or the older bool (true = top).
    pub fn from_value(v: &serde_json::Value) -> Mode {
        match v {
            serde_json::Value::Bool(true) => Mode::Top,
            serde_json::Value::Bool(false) => Mode::Off,
            serde_json::Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "off" | "false" | "no" => Mode::Off,
                "bottom" => Mode::Bottom,
                _ => Mode::Top,
            },
            _ => Mode::Top,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Input {
    pub indicator: String,
    pub model: String,
    pub context_pct: Option<u8>,
    pub tokens: u64,
    pub cache_pct: Option<f64>,
    pub compactions: u64,
    /// Elapsed time of the live prompt, or of the last one when idle.
    pub elapsed: Option<Duration>,
    pub live: bool,
    pub idle_since: Option<Duration>,
    pub branch: Option<String>,
    pub battery: Option<Battery>,
    pub stash: String,
}

/// `(text, style)` where style is one of status/strong/dim/good/warn/bad/critical.
pub type Seg = (String, &'static str);

pub fn context_style(pct: Option<u8>) -> &'static str {
    match pct {
        None => "dim",
        Some(p) if p >= 95 => "critical",
        Some(p) if p > 80 => "bad",
        Some(p) if p >= 50 => "warn",
        _ => "good",
    }
}

pub fn cache_style(pct: f64) -> &'static str {
    if pct >= 70.0 {
        "good"
    } else if pct >= 40.0 {
        "warn"
    } else {
        "bad"
    }
}

pub fn compaction_style(n: u64) -> &'static str {
    if n >= 10 {
        "bad"
    } else if n >= 5 {
        "warn"
    } else {
        "dim"
    }
}

pub fn context_bar(pct: Option<u8>, width: usize) -> String {
    let p = pct.unwrap_or(0).min(100) as usize;
    let filled = ((p as f64 / 100.0) * width as f64).round() as usize;
    format!("[{}{}]", "█".repeat(filled), "░".repeat(width.saturating_sub(filled)))
}

/// `42s`, `2m 1s`, `1h 3m`, `2d 4h 1m` — seconds stay visible below an hour.
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    let (days, rem) = (s / 86400, s % 86400);
    let (h, rem) = (rem / 3600, rem % 3600);
    let (m, sec) = (rem / 60, rem % 60);
    if days > 0 {
        format!("{days}d {h}h {m}m")
    } else if h > 0 {
        if sec > 0 {
            format!("{h}h {m}m {sec}s")
        } else {
            format!("{h}h {m}m")
        }
    } else if m > 0 {
        if sec > 0 {
            format!("{m}m {sec}s")
        } else {
            format!("{m}m")
        }
    } else {
        format!("{sec}s")
    }
}

pub fn tokens(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1000 {
        format!("{:.1}k", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

/// Model id shortened for the bar: drop the provider prefix, keep ≤ 28 chars.
pub fn short_model(m: &str) -> String {
    let m = m.rsplit('/').next().unwrap_or(m);
    if m.chars().count() > 28 {
        m.chars().take(27).collect::<String>() + "…"
    } else {
        m.to_string()
    }
}

/// The git branch of `dir` (walking up), short sha when detached; worktree `.git` files ok.
pub fn git_branch(dir: &Path) -> Option<String> {
    let mut d: Option<&Path> = Some(dir);
    while let Some(cur) = d {
        let g = cur.join(".git");
        let gitdir: Option<PathBuf> = if g.is_dir() {
            Some(g)
        } else if g.is_file() {
            std::fs::read_to_string(&g).ok().and_then(|s| s.trim().strip_prefix("gitdir:").map(|p| {
                let p = PathBuf::from(p.trim());
                if p.is_absolute() {
                    p
                } else {
                    cur.join(p)
                }
            }))
        } else {
            None
        };
        if let Some(gd) = gitdir {
            let head = std::fs::read_to_string(gd.join("HEAD")).ok()?;
            let head = head.trim();
            return Some(match head.strip_prefix("ref: ") {
                Some(r) => r.strip_prefix("refs/heads/").unwrap_or(r).to_string(),
                None => head.chars().take(7).collect(),
            });
        }
        d = cur.parent();
    }
    None
}

/// One-line status bar for the plain-text REPL (`ark chat`): model, context gauge, tokens and
/// the git branch, plain text so it reads in any terminal (Hermes `cli_status_bar_mixin.py`).
pub fn chat_line(model: &str, context_pct: Option<u8>, used: u64, branch: Option<&str>) -> String {
    let mut s = format!("[{}]", short_model(model));
    if let Some(p) = context_pct {
        s.push_str(&format!(" {} {p}%", context_bar(Some(p), 10)));
    }
    s.push_str(&format!(" {} tok", tokens(used)));
    if let Some(b) = branch {
        s.push_str(&format!(" ⎇ {b}"));
    }
    s
}

/// Segments in display order, each with a drop priority (higher = dropped first).
pub fn segments(i: &Input) -> Vec<(Seg, u8)> {
    let mut v: Vec<(Seg, u8)> = vec![];
    if !i.indicator.is_empty() {
        v.push(((i.indicator.clone(), "strong"), 0));
    }
    if !i.model.is_empty() {
        v.push(((short_model(&i.model), "strong"), 0));
    }
    let cs = context_style(i.context_pct);
    match i.context_pct {
        Some(p) => {
            v.push(((context_bar(Some(p), 10), cs), 4));
            v.push(((format!("{p}%"), cs), 1));
        }
        None => v.push((("ctx —".into(), "dim"), 1)),
    }
    if i.tokens > 0 {
        v.push(((format!("{} tok", tokens(i.tokens)), "status"), 3));
    }
    if let Some(c) = i.cache_pct {
        v.push(((format!("◎ {c:.1}%"), cache_style(c)), 5));
    }
    if i.compactions > 0 {
        v.push(((format!("⇣{}", i.compactions), compaction_style(i.compactions)), 6));
    }
    let el = match i.elapsed {
        Some(d) => format!("{} {}", if i.live { "⏱" } else { "⏲" }, duration(d)),
        None => "⏲ 0s".into(),
    };
    v.push(((el, "dim"), 2));
    if let (Some(d), false) = (i.idle_since, i.live) {
        v.push(((format!("✓ {}", duration(d)), "dim"), 7));
    }
    if let Some(b) = i.branch.as_ref().filter(|b| !b.is_empty()) {
        v.push(((format!("⎇ {b}"), "status"), 3));
    }
    if let Some(b) = i.battery {
        let t = battery::format(&b);
        if !t.is_empty() {
            v.push(((t, battery::category(&b)), 2));
        }
    }
    if !i.stash.is_empty() {
        v.push(((i.stash.clone(), "strong"), 1));
    }
    v
}

/// Fit into `width` columns (separator ` │ `), dropping high-priority-number segments first.
pub fn fit(i: &Input, width: usize, str_width: impl Fn(&str) -> usize) -> Vec<Seg> {
    let mut segs = segments(i);
    let total = |s: &[(Seg, u8)]| s.iter().map(|((t, _), _)| str_width(t)).sum::<usize>() + s.len().saturating_sub(1) * 3 + 2;
    while total(&segs) > width {
        let Some(worst) = segs.iter().enumerate().filter(|(_, (_, p))| *p > 0).max_by_key(|(i, (_, p))| (*p, *i)).map(|(i, _)| i) else { break };
        segs.remove(worst);
    }
    segs.into_iter().map(|(s, _)| s).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing_and_drawing() {
        assert_eq!(Mode::default(), Mode::Top, "upstream default is the top bar");
        assert_eq!(Mode::from_value(&serde_json::json!(true)), Mode::Top);
        assert_eq!(Mode::from_value(&serde_json::json!(false)), Mode::Off);
        assert_eq!(Mode::from_value(&serde_json::json!("bottom")), Mode::Bottom);
        assert_eq!(Mode::from_value(&serde_json::json!("off")), Mode::Off);
        assert_eq!(Mode::from_value(&serde_json::Value::Null), Mode::Top);
        assert_eq!(Mode::parse("", Mode::Off), Some(Mode::Top), "bare /statusbar turns it on at the top");
        assert_eq!(Mode::parse("toggle", Mode::Top), Some(Mode::Off));
        assert_eq!(Mode::parse("bottom", Mode::Top), Some(Mode::Bottom));
        assert_eq!(Mode::parse("on", Mode::Bottom), Some(Mode::Top));
        assert_eq!(Mode::parse("off", Mode::Bottom), Some(Mode::Off));
        assert_eq!(Mode::parse("sideways", Mode::Top), None);
        assert!(Mode::Top.shown() && Mode::Bottom.shown() && !Mode::Off.shown());
        assert_eq!((Mode::Top.as_str(), Mode::Bottom.as_str(), Mode::Off.as_str()), ("top", "bottom", "off"));
    }

    /// Audit row: git branch, battery, context %, model and tokens all appear in the bar.
    #[test]
    fn bar_lists_branch_battery_context_model_tokens() {
        let i = Input { indicator: "✦".into(), model: "anthropic/claude-sonnet-5-5".into(), context_pct: Some(42), tokens: 12_345, elapsed: Some(Duration::from_secs(5)), live: true, branch: Some("feature/x".into()), battery: Some(Battery { available: true, percent: Some(77), plugged: Some(false) }), ..Default::default() };
        let line: Vec<String> = fit(&i, 400, |s| s.chars().count()).into_iter().map(|s| s.0).collect();
        for want in ["✦", "claude-sonnet-5-5", "[████░░░░░░]", "42%", "12.3k tok", "⏱ 5s", "⎇ feature/x", "🔋 77%"] {
            assert!(line.iter().any(|s| s == want), "missing {want} in {line:?}");
        }
        assert!(context_style(i.context_pct) == "good" && crate::tui::statusbar::segments(&i).len() >= 8);
    }

    #[test]
    fn chat_line_is_plain_and_carries_the_same_facts() {
        assert_eq!(chat_line("openai/gpt-5", Some(42), 1500, Some("main")), "[gpt-5] [████░░░░░░] 42% 1.5k tok ⎇ main");
        assert_eq!(chat_line("echo/m", None, 7, None), "[m] 7 tok", "the provider prefix is dropped");
    }

    #[test]
    fn styles_bars_durations_and_fit() {
        assert_eq!(context_style(Some(96)), "critical");
        assert_eq!(context_style(Some(81)), "bad");
        assert_eq!(context_style(Some(50)), "warn");
        assert_eq!(context_style(Some(10)), "good");
        assert_eq!(context_bar(Some(42), 10), "[████░░░░░░]");
        assert_eq!(duration(Duration::from_secs(119)), "1m 59s");
        assert_eq!(duration(Duration::from_secs(120)), "2m");
        assert_eq!(duration(Duration::from_secs(90061)), "1d 1h 1m");
        assert_eq!(tokens(12_345), "12.3k");
        assert_eq!(short_model("anthropic/claude-sonnet-5-5"), "claude-sonnet-5-5");
        assert_eq!(cache_style(75.0), "good");
        let i = Input { indicator: "✦".into(), model: "a/m".into(), context_pct: Some(42), tokens: 1500, cache_pct: Some(33.3), compactions: 6, elapsed: Some(Duration::from_secs(5)), live: true, branch: Some("main".into()), battery: Some(Battery { available: true, percent: Some(9), plugged: Some(false) }), stash: "📌 1".into(), ..Default::default() };
        let all: Vec<String> = fit(&i, 400, |s| s.chars().count()).into_iter().map(|s| s.0).collect();
        assert!(all.contains(&"⎇ main".to_string()) && all.contains(&"🔋 9%".to_string()) && all.contains(&"⏱ 5s".to_string()) && all.contains(&"◎ 33.3%".to_string()) && all.contains(&"⇣6".to_string()));
        let narrow: Vec<String> = fit(&i, 30, |s| s.chars().count()).into_iter().map(|s| s.0).collect();
        assert!(narrow.contains(&"m".to_string()) && narrow.contains(&"42%".to_string()));
        assert!(!narrow.contains(&"⇣6".to_string()) && !narrow.contains(&"◎ 33.3%".to_string()));
        // git branch from HEAD, detached sha, and a worktree `.git` file.
        let root = std::env::temp_dir().join(format!("ark-sb-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("sub/dir")).unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/feature/x\n").unwrap();
        assert_eq!(git_branch(&root.join("sub/dir")).as_deref(), Some("feature/x"));
        std::fs::write(root.join(".git/HEAD"), "0123456789abcdef\n").unwrap();
        assert_eq!(git_branch(&root).as_deref(), Some("0123456"));
        let wt = root.join("wt");
        std::fs::create_dir_all(root.join(".git/worktrees/wt")).unwrap();
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(root.join(".git/worktrees/wt/HEAD"), "ref: refs/heads/wt-branch\n").unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", root.join(".git/worktrees/wt").display())).unwrap();
        assert_eq!(git_branch(&wt).as_deref(), Some("wt-branch"));
    }
}
