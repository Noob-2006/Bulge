//! Live-work dock above the composer (Hermes `cli_subagent_monitor.py` dock): the active
//! goal, running sub-agents (`● goal · 12s · last: grep`), background processes and
//! queued prompts, with a row budget derived from the terminal height. Fed by the
//! daemon's `dock.snapshot` (`{goal, subagents[], processes[], queued[]}`); Ctrl+T
//! collapses it to one heading line.

use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Dock {
    pub goal: String,
    pub subagents: Vec<Value>,
    pub processes: Vec<Value>,
    pub queued: Vec<String>,
    pub collapsed: bool,
}

fn clip(s: &str, width: usize, sw: &dyn Fn(&str) -> usize) -> String {
    // Leading indentation is layout, not content: keep it.
    let lead = s.len() - s.trim_start_matches(' ').len();
    if lead > 0 {
        return format!("{}{}", " ".repeat(lead.min(width)), clip(&s[lead..], width.saturating_sub(lead), sw));
    }
    let text: String = s.split_whitespace().collect::<Vec<_>>().join(" ").chars().filter(|c| !c.is_control()).collect();
    if sw(&text) <= width {
        return text;
    }
    let mut out = String::new();
    for c in text.chars() {
        let mut next = out.clone();
        next.push(c);
        if sw(&next) > width.saturating_sub(1) {
            break;
        }
        out = next;
    }
    if width > 0 {
        out.push('…');
    }
    out
}

impl Dock {
    pub fn from_snapshot(v: &Value, collapsed: bool) -> Dock {
        let arr = |k: &str| v[k].as_array().cloned().unwrap_or_default();
        Dock {
            goal: v["goal"].as_str().unwrap_or("").to_string(),
            subagents: arr("subagents").into_iter().filter(|s| !matches!(s["status"].as_str(), Some("completed" | "failed" | "cancelled" | "interrupted" | "timeout"))).collect(),
            processes: arr("processes"),
            queued: arr("queued").into_iter().filter_map(|q| q.as_str().map(str::to_string).or_else(|| q["text"].as_str().map(str::to_string))).collect(),
            collapsed,
        }
    }
    pub fn has_rows(&self) -> bool {
        !self.goal.is_empty() || !self.subagents.is_empty() || !self.processes.is_empty() || !self.queued.is_empty()
    }
    fn activity(row: &Value) -> String {
        let secs = row["running_seconds"].as_f64().unwrap_or(0.0) as u64;
        let what = row["last_tool"].as_str().filter(|s| !s.is_empty()).map(|t| format!("last: {t}")).or_else(|| row["status"].as_str().map(str::to_string)).unwrap_or_else(|| "starting".into());
        let tools = row["tool_calls"].as_u64().filter(|n| *n > 0).map(|n| format!(" · {n} tools")).unwrap_or_default();
        format!("{secs}s · {what}{tools}")
    }
    fn counts(&self) -> String {
        let mut p = vec![];
        if !self.subagents.is_empty() {
            p.push(format!("{} live", self.subagents.len()));
        }
        let running = self.processes.iter().filter(|r| r["status"] == "running").count();
        if running > 0 {
            p.push(format!("{running} proc{}", if running == 1 { "" } else { "s" }));
        } else if !self.processes.is_empty() {
            p.push(format!("{} done", self.processes.len()));
        }
        if !self.goal.is_empty() {
            p.push("goal active".into());
        }
        if !self.queued.is_empty() {
            p.push(format!("{} queued", self.queued.len()));
        }
        p.join(" · ")
    }
    /// Lines to paint (empty when there is nothing live).
    pub fn lines(&self, columns: usize, rows: usize, sw: &dyn Fn(&str) -> usize) -> Vec<String> {
        if !self.has_rows() {
            return vec![];
        }
        if self.collapsed {
            let first = self.subagents.first().map(Self::activity).or_else(|| self.processes.first().map(|p| p["command"].as_str().unwrap_or("").to_string())).unwrap_or_else(|| if self.goal.is_empty() { self.queued.first().map(|q| format!("next: {q}")).unwrap_or_default() } else { self.goal.clone() });
            return vec![clip(&format!(" ▸ live work: {} · {first}  (Ctrl+T expand)", self.counts()), columns, sw)];
        }
        let cols = columns.saturating_sub(2);
        let mut lines: Vec<String> = vec![];
        if !self.goal.is_empty() {
            lines.push(clip(&format!(" ◎ goal: {}", self.goal), cols, sw));
        }
        let budget = rows.saturating_sub(10).checked_div(3).unwrap_or(0).clamp(1, 4);
        let agent_budget = if self.processes.is_empty() { budget } else { (budget - (budget / 2).max(1)).max(1) };
        let shown = self.subagents.len().min(agent_budget);
        if !self.subagents.is_empty() {
            lines.push(clip(&format!(" sub-agents ({})  Ctrl+T collapse", self.subagents.len()), cols, sw));
            for r in &self.subagents[..shown] {
                let act = Self::activity(r);
                let goal = r["label"].as_str().filter(|s| !s.is_empty()).or(r["goal"].as_str()).unwrap_or("");
                let gw = cols.saturating_sub(sw(&act) + 5).max(3);
                lines.push(clip(&format!(" ● {} · {act}", clip(goal, gw, sw)), cols, sw));
            }
            if self.subagents.len() > shown {
                lines.push(clip(&format!(" … {} more sub-agents", self.subagents.len() - shown), cols, sw));
            }
        }
        if !self.processes.is_empty() {
            let pshown = self.processes.len().min(budget.saturating_sub(shown).max(1));
            lines.push(clip(&format!(" processes ({})", self.counts()), cols, sw));
            for r in &self.processes[..pshown] {
                let glyph = if r["status"] == "running" { "▶" } else if r["exit_code"].as_i64().unwrap_or(0) == 0 { "✓" } else { "✗" };
                let act = format!("{}s · {}", r["running_seconds"].as_f64().unwrap_or(0.0) as u64, r["status"].as_str().unwrap_or(""));
                let cw = cols.saturating_sub(sw(&act) + 5).max(3);
                lines.push(clip(&format!(" {glyph} {} · {act}", clip(r["command"].as_str().unwrap_or(""), cw, sw)), cols, sw));
            }
            if self.processes.len() > pshown {
                lines.push(clip(&format!(" … {} more processes", self.processes.len() - pshown), cols, sw));
            }
        }
        if !self.queued.is_empty() {
            let qshown = self.queued.len().min(if rows >= 24 { 3 } else { 1 });
            lines.push(clip(&format!(" queued ({})", self.queued.len()), cols, sw));
            for (i, q) in self.queued[..qshown].iter().enumerate() {
                lines.push(clip(&format!("  {}. {q}", i + 1), cols, sw));
            }
            if self.queued.len() > qshown {
                lines.push(clip(&format!("  … {} more queued", self.queued.len() - qshown), cols, sw));
            }
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dock_rows_budget_and_collapse() {
        let sw = |s: &str| s.chars().count();
        assert!(Dock::from_snapshot(&json!({}), false).lines(80, 40, &sw).is_empty());
        let snap = json!({
            "goal": "ship the release",
            "subagents": [
                {"label": "tests", "goal": "run the test-suite", "status": "running", "running_seconds": 12.4, "tool_calls": 3, "last_tool": "shell"},
                {"goal": "write docs", "status": "running", "running_seconds": 2.0},
                {"goal": "old", "status": "completed"}
            ],
            "queued": ["then deploy", "and tell the team"]
        });
        let d = Dock::from_snapshot(&snap, false);
        assert_eq!(d.subagents.len(), 2, "finished children are hidden");
        let l = d.lines(80, 40, &sw);
        assert_eq!(l[0], " ◎ goal: ship the release");
        assert!(l.iter().any(|x| x == " ● tests · 12s · last: shell · 3 tools"));
        assert!(l.iter().any(|x| x == "  2. and tell the team"));
        // Small terminal: one agent row + "more", one queued row.
        let s = d.lines(80, 12, &sw);
        assert!(s.iter().any(|x| x.contains("… 1 more sub-agents")));
        assert!(s.iter().any(|x| x.contains("… 1 more queued")));
        let c = Dock::from_snapshot(&snap, true).lines(200, 40, &sw);
        assert_eq!(c.len(), 1);
        assert!(c[0].contains("2 live · goal active · 2 queued"));
        let narrow = d.lines(20, 40, &sw);
        assert!(narrow.iter().all(|x| sw(x) <= 18));

        // Background processes (`dock.snapshot.processes`) paint with a glyph and their state.
        let procs = Dock::from_snapshot(
            &json!({"processes": [
                {"id": 3, "command": "npm run dev", "status": "running", "running_seconds": 41.7},
                {"id": 4, "command": "cargo build", "status": "exited", "running_seconds": 9.0, "exit_code": 0},
                {"id": 5, "command": "false", "status": "exited", "running_seconds": 1.0, "exit_code": 1}
            ]}),
            false,
        );
        assert_eq!(procs.processes.len(), 3);
        let p = procs.lines(100, 40, &sw);
        assert_eq!(p[0], " processes (1 proc)");
        assert!(p.iter().any(|x| x == " ▶ npm run dev · 41s · running"), "{p:?}");
        assert!(p.iter().any(|x| x == " ✓ cargo build · 9s · exited"), "{p:?}");
        assert!(p.iter().any(|x| x == " ✗ false · 1s · exited"), "{p:?}");
        assert_eq!(procs.lines(100, 40, &sw)[1], " ▶ npm run dev · 41s · running");
        let one = Dock::from_snapshot(&json!({"processes": [{"command": "sleep 1", "status": "running"}]}), true).lines(200, 40, &sw);
        assert!(one[0].contains("▸ live work: 1 proc · sleep 1"), "{one:?}");
    }
}
