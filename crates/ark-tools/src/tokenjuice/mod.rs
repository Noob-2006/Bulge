//! tokenjuice — lean compaction of command results before they reach the model.
//!
//! A port of `tokenjuice@0.8.5` (MIT, vincentkoc/tokenjuice) as embedded by OpenClaw's
//! `extensions/tokenjuice` plugin. It never rewrites or re-runs a command and never
//! changes an exit code: it only shrinks text that already exists, and it answers
//! `None` — "use the raw text" — whenever compaction would not clearly pay off.
//!
//! Ported behaviour (see `tokenjuice` `dist/core/{reduce,text,reduce-formatters}.js`
//! and `dist/rules/**`):
//!
//! - `generic/fallback`: strip ANSI, trim empty edges, collapse duplicate lines,
//!   keep `head..tail` lines and say how many were dropped.
//! - `search/{grep,rg}`, `filesystem/{ls,find}`, `devops/docker-ps`, `system/ps`:
//!   keep the head and tail of a tabular/line listing plus a row count.
//! - `git/diff`: keep file and hunk headers, at most 8 changed lines per hunk and
//!   a `... hunk clipped: N added, M removed lines omitted` marker.
//! - whole-JSON / JSONL: a compact schema-plus-samples summary built with
//!   [`json`]'s JavaScript-semantics value model (key order, number printing).
//! - clips: over-long single lines are cut in the middle with a `sha256:` marker
//!   (`clipMiddleWithHash`), the assembled text is clamped to `budget` with a
//!   `... omitted ...` marker (`clampTextMiddleWithMetadata`).
//! - thresholds: tiny output (≤ 240 chars) is left alone; a reduction that saves
//!   fewer than 120 chars *and* less than 25 % is rejected, mirroring upstream's
//!   `TINY_OUTPUT_MAX_CHARS` / `SMALL_OUTPUT_PASSTHROUGH_*` passthrough rules.
//!
//! Every compacted result starts with one `[tokenjuice …]` line that states the
//! original size, what was dropped and that the text is lossy, so the model always
//! knows it is looking at a reduction rather than at the complete output.
//!
//! Call sites (shell / job / process) use [`reduce_output`] or
//! [`reduce_command_output`]; both return `None` when the caller should keep the
//! original string.

mod json;

use json::J;

/// Upstream `ReduceOptions.maxInlineChars` default.
pub const DEFAULT_BUDGET: usize = 1200;
/// Upstream `TINY_OUTPUT_MAX_CHARS`: nothing smaller is worth a marker line.
pub const TINY_OUTPUT_MAX_CHARS: usize = 240;
/// Upstream `SMALL_OUTPUT_PASSTHROUGH_MIN_SAVED_CHARS`.
pub const MIN_SAVED_CHARS: usize = 120;
/// Upstream `SMALL_OUTPUT_PASSTHROUGH_MAX_RATIO`.
pub const MAX_GAIN_RATIO: f64 = 0.75;
/// Upstream `LONG_SEARCH_LINE_MAX_CHARS`.
pub const MAX_LINE_CHARS: usize = 420;
/// Upstream `GIT_DIFF_CHANGED_LINES_PER_HUNK`.
pub const DIFF_LINES_PER_HUNK: usize = 8;
/// Smallest budget the reducer will compact into: a `[tokenjuice …]` marker line
/// plus a line or two of output. Smaller budgets return `None` (keep the raw text).
pub const MIN_BUDGET: usize = 160;

/// The knobs of the reducer. Defaults are upstream's numbers.
///
/// `max(gain)` gate: a reduction is only returned when it saves at least
/// [`Limits::min_saved_chars`] characters *or* shrinks the text to at most
/// [`Limits::max_gain_ratio`] of its original size.
#[derive(Clone, Debug, PartialEq)]
pub struct Limits {
    /// Hard cap on the characters of the returned text (upstream `maxInlineChars`).
    pub budget: usize,
    /// Hard cap on the number of lines in the returned text.
    pub max_lines: usize,
    /// Lines kept from the start of a listing (`generic/fallback` `summarize.head`).
    pub head: usize,
    /// Lines kept from the end (`generic/fallback` `summarize.tail`).
    pub tail: usize,
    /// Head lines kept from a failing build log (`generic/fallback` `failure.head`).
    pub failure_head: usize,
    /// Tail lines kept from a failing build log (`generic/fallback` `failure.tail`).
    pub failure_tail: usize,
    /// Output at or below this many characters is returned unchanged (`None`).
    pub tiny_max_chars: usize,
    /// Minimum characters a reduction must save when it also fails the ratio gate.
    pub min_saved_chars: usize,
    /// Maximum `compacted / raw` ratio to count as a clear win.
    pub max_gain_ratio: f64,
    /// A single line longer than this is clipped in the middle.
    pub max_line_chars: usize,
    /// Changed lines kept per `git diff` hunk before the hunk is clipped.
    pub diff_lines_per_hunk: usize,
    /// Items sampled from a JSON array.
    pub json_items: usize,
    /// Keys listed for a JSON object.
    pub json_keys: usize,
    /// Nesting depth after which a JSON value is described instead of printed.
    pub json_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            budget: DEFAULT_BUDGET,
            max_lines: 120,
            head: 8,
            tail: 8,
            failure_head: 12,
            failure_tail: 20,
            tiny_max_chars: TINY_OUTPUT_MAX_CHARS,
            min_saved_chars: MIN_SAVED_CHARS,
            max_gain_ratio: MAX_GAIN_RATIO,
            max_line_chars: MAX_LINE_CHARS,
            diff_lines_per_hunk: DIFF_LINES_PER_HUNK,
            json_items: 3,
            json_keys: 12,
            json_depth: 3,
        }
    }
}

impl Limits {
    /// Defaults with a different output budget (0 means [`DEFAULT_BUDGET`]).
    pub fn with_budget(budget: usize) -> Self {
        Limits { budget: if budget == 0 { DEFAULT_BUDGET } else { budget }, ..Limits::default() }
    }
}

/// The reducer family. [`Kind::Auto`] lets [`classify`] / [`classify_command`] decide.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Auto,
    Generic,
    Json,
    /// Tabular or list-shaped output (`ls`, `find`, `docker ps`, `kubectl get`, `ps`).
    Table,
    /// `grep` / `rg` hits (`path:line:text`).
    Search,
    /// A unified diff.
    Diff,
    /// Build/test logs; error and warning lines are preserved.
    Log,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Auto => "auto",
            Kind::Generic => "generic",
            Kind::Json => "json",
            Kind::Table => "table",
            Kind::Search => "search",
            Kind::Diff => "diff",
            Kind::Log => "log",
        }
    }
}

/// Strip ANSI CSI/OSC sequences and stray `ESC` bytes (upstream `stripAnsi`).
pub fn strip_ansi(text: &str) -> String {
    if !text.contains('\u{1b}') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match it.peek().copied() {
            None => {}
            Some('[') => {
                it.next();
                // Parameters/intermediates up to the final byte 0x40..=0x7e.
                for n in it.by_ref() {
                    if ('@'..='~').contains(&n) {
                        break;
                    }
                }
            }
            Some(']') => {
                it.next();
                while let Some(n) = it.next() {
                    if n == '\u{7}' {
                        break;
                    }
                    if n == '\u{1b}' {
                        if it.peek() == Some(&'\\') {
                            it.next();
                        }
                        break;
                    }
                }
            }
            Some(_) => {
                it.next();
            }
        }
    }
    out
}

/// Pick a [`Kind`] from the text alone.
pub fn classify(text: &str) -> Kind {
    let s = strip_ansi(text);
    let t = s.trim();
    if t.is_empty() {
        return Kind::Generic;
    }
    let looks_json = t.starts_with('{') || t.starts_with('[');
    if looks_json && json::parse(t).is_some() {
        return Kind::Json;
    }
    if looks_like_jsonl(&s) {
        return Kind::Json;
    }
    if s.contains("diff --git ") || (s.contains("\n@@ ") && s.lines().any(is_changed_lin)) {
        return Kind::Diff;
    }
    if looks_like_build_log(&s) {
        return Kind::Log;
    }
    if looks_like_search(&s) {
        return Kind::Search;
    }
    if looks_like_table(&s) {
        return Kind::Table;
    }
    Kind::Generic
}

/// Pick a [`Kind`] from the command line (`git diff` → [`Kind::Diff`], `ls` → …).
///
/// A chain of several substantive commands (`cd x && ls && grep y`) has no single
/// family — upstream's `hasMultipleSubstantiveShellCommands` also falls back to the
/// generic reducer there — so it answers [`Kind::Auto`]; setup segments (`cd`,
/// `export`, `mkdir`…) are ignored. Unknown commands answer [`Kind::Auto`] too.
pub fn classify_command(command: &str) -> Kind {
    let segments = split_segments(command);
    let mut chosen: Option<Kind> = None;
    let mut substantive = 0usize;
    for seg in &segments {
        let Some(idx) = segment_program(seg) else { continue };
        let prog = seg[idx];
        let prog = prog.rsplit('/').next().unwrap_or(prog);
        if is_setup_program(prog) {
            continue;
        }
        substantive += 1;
        if substantive > 1 {
            return Kind::Auto;
        }
        chosen = Some(kind_for_program(prog, &seg[idx + 1..]));
    }
    chosen.unwrap_or(Kind::Auto)
}

/// Split a shell command line into its top-level segments (`;`, `&&`, `||`, `|`).
fn split_segments(command: &str) -> Vec<Vec<&str>> {
    let mut segments: Vec<Vec<&str>> = vec![Vec::new()];
    for w in words_and_separators(command) {
        if matches!(w, ";" | "|" | "&" | "(" | ")") {
            segments.push(Vec::new());
        } else if let Some(last) = segments.last_mut() {
            last.push(w);
        }
    }
    segments
}

fn words_and_separators(command: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in command.char_indices() {
        let sep = c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')');
        if sep {
            if let Some(s) = start.take() {
                out.push(&command[s..i]);
            }
            if matches!(c, ';' | '|' | '&' | '(' | ')') {
                out.push(&command[i..i + c.len_utf8()]);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push(&command[s..]);
    }
    out
}

/// Index of the command word in a segment, skipping `VAR=x` assignments and wrappers.
fn segment_program(seg: &[&str]) -> Option<usize> {
    let mut i = 0;
    while i < seg.len() {
        let w = seg[i];
        if w.contains('=') || matches!(w, "sudo" | "env" | "command" | "time" | "nice" | "exec" | "nohup" | "xargs") {
            i += 1;
            while i < seg.len() && (seg[i].starts_with('-') || seg[i].contains('=')) {
                i += 1;
            }
            continue;
        }
        return Some(i);
    }
    None
}

fn is_setup_program(prog: &str) -> bool {
    matches!(
        prog,
        "cd" | "pushd" | "popd" | "export" | "set" | "unset" | "source" | "." | "true" | ":" | "echo" | "printf" | "sleep" | "mkdir" | "rm" | "cp" | "mv" | "touch" | "chmod" | "wait"
    )
}

fn kind_for_program(prog: &str, rest: &[&str]) -> Kind {
    match prog {
        "grep" | "egrep" | "fgrep" | "rg" | "ag" | "ack" => Kind::Search,
        "ls" | "ll" | "find" | "fd" | "tree" | "du" | "df" | "ps" | "stat" => Kind::Table,
        "cargo" | "make" | "ninja" | "npm" | "pnpm" | "yarn" | "tsc" | "tsdown" | "go" | "mvn" | "gradle" | "dotnet" | "javac" | "gcc" | "g++" | "clang" | "rustc" | "pip" | "pytest" | "jest" | "vitest" | "webpack" | "vite" => Kind::Log,
        "git" => {
            if rest.contains(&"grep") {
                Kind::Search
            } else if rest.iter().any(|w| matches!(*w, "diff" | "show" | "format-patch")) {
                Kind::Diff
            } else {
                Kind::Auto
            }
        }
        "docker" | "podman" | "kubectl" | "helm" => Kind::Table,
        _ => Kind::Auto,
    }
}

/// Reduce `text` with the default [`Limits`], keeping the output in its own family.
///
/// `None` means "keep the original": the text is small already, it is not valid
/// UTF-8-friendly line data, or compaction would not save enough to be worth it.
pub fn reduce(text: &str, kind: Kind) -> Option<String> {
    reduce_with(text, kind, &Limits::default())
}

/// Reduce `text` into at most `budget` characters, classifying it automatically.
///
/// This is the one-liner the `shell` / `job` / `process` tools call:
/// `let out = tokenjuice::reduce_output(&out, tokenjuice::DEFAULT_BUDGET).unwrap_or(out);`
pub fn reduce_output(output: &str, budget: usize) -> Option<String> {
    reduce_with(output, Kind::Auto, &Limits::with_budget(budget))
}

/// Reduce the output of `command`, picking the family from the command line first
/// and from the text second.
///
/// Output the model asked to *read* is never rewritten: `cat` / `head` / `tail` /
/// `sed` / `jq` / `yq` / `bat` and `git show <rev>:<path>` return `None`, matching
/// upstream's `isVerbatimConfigInspectionCommand` guard.
pub fn reduce_command_output(command: &str, output: &str, budget: usize) -> Option<String> {
    if is_verbatim_command(command) {
        return None;
    }
    let limits = Limits::with_budget(budget);
    match classify_command(command) {
        Kind::Auto => reduce_with(output, Kind::Auto, &limits),
        k => reduce_with(output, k, &limits),
    }
}

/// Commands whose output must reach the model untouched (upstream
/// `FILE_CONTENT_INSPECTION_COMMANDS` + `git show <blob>`).
pub fn is_verbatim_command(command: &str) -> bool {
    let segments = split_segments(command);
    let Some(seg) = segments.iter().find(|seg| segment_program(seg).is_some()) else {
        return false;
    };
    let Some(idx) = segment_program(seg) else { return false };
    let prog = seg[idx];
    let prog = prog.rsplit('/').next().unwrap_or(prog);
    if matches!(prog, "cat" | "sed" | "head" | "tail" | "nl" | "bat" | "batcat" | "jq" | "yq" | "plutil") {
        return true;
    }
    if prog == "git" {
        let rest = &seg[idx + 1..];
        if let Some(pos) = rest.iter().position(|w| *w == "show") {
            // `git show HEAD:src/lib.rs` prints a file; `git show HEAD` prints a patch.
            return rest[pos + 1..].iter().any(|w| {
                !w.starts_with('-')
                    && match w.split_once(':') {
                        Some((rev, path)) => !rev.is_empty() && !path.is_empty(),
                        None => false,
                    }
            });
        }
    }
    false
}

/// Reduce `text` with explicit [`Limits`].
pub fn reduce_with(text: &str, kind: Kind, limits: &Limits) -> Option<String> {
    let stripped = strip_ansi(text);
    let raw_chars = char_len(&stripped);
    // A budget that cannot hold the marker line plus one line of output is not
    // worth compacting into: the caller keeps the raw text.
    if raw_chars == 0 || raw_chars <= limits.tiny_max_chars || limits.budget < MIN_BUDGET {
        return None;
    }
    let kind = match kind {
        Kind::Auto => classify(&stripped),
        k => k,
    };
    let lines = split_lines(&stripped);
    if lines.is_empty() {
        return None;
    }
    let mut st = Stats { raw_chars, lines_total: trim_empty_edges(&lines).len(), ..Stats::default() };
    let body = match kind {
        Kind::Json => match json_body(&stripped, limits, &mut st) {
            Some(b) => b,
            None => generic_body(&lines, limits, &mut st),
        },
        Kind::Diff => diff_body(&lines, limits, &mut st),
        Kind::Search => search_body(&lines, limits, &mut st),
        Kind::Table => table_body(&lines, limits, &mut st),
        Kind::Log => log_body(&lines, limits, &mut st),
        Kind::Generic | Kind::Auto => generic_body(&lines, limits, &mut st),
    };
    let body = cap_lines(&body, limits.max_lines, &mut st);
    let out = assemble(kind, &st, &body, limits.budget)?;
    let out_chars = char_len(&out);
    if out_chars >= raw_chars {
        return None;
    }
    let saved = raw_chars - out_chars;
    if saved < limits.min_saved_chars && (out_chars as f64 / raw_chars as f64) > limits.max_gain_ratio {
        return None;
    }
    Some(out)
}

// ── stats / assembly ────────────────────────────────────────────────────────

#[derive(Default)]
struct Stats {
    raw_chars: usize,
    lines_total: usize,
    lines_omitted: usize,
    items_total: usize,
    items_omitted: usize,
    collapsed: usize,
    clipped: usize,
    facts: Vec<String>,
}

/// One `[tokenjuice …]` line: original size, what was dropped, and that this is lossy.
fn header(kind: Kind, st: &Stats, out_chars: usize) -> String {
    let mut seg = vec![format!("{}→{} chars", st.raw_chars, out_chars)];
    if st.items_omitted > 0 {
        seg.push(format!("{} of {} items omitted", st.items_omitted, st.items_total.max(st.items_omitted)));
    }
    if st.lines_omitted > 0 && st.lines_total >= 2 {
        seg.push(format!("{} of {} lines omitted", st.lines_omitted, st.lines_total.max(st.lines_omitted)));
    }
    if st.collapsed > 0 {
        seg.push(format!("{} repeated lines collapsed", st.collapsed));
    }
    if st.clipped > 0 {
        seg.push(format!("{} long lines clipped", st.clipped));
    }
    seg.extend(st.facts.iter().cloned());
    format!("[tokenjuice {}] {}; lossy compaction — ask for the raw output if you need the rest", kind.name(), seg.join("; "))
}

/// Header + body, with the body clamped so the whole thing fits `budget`.
fn assemble(kind: Kind, st: &Stats, body: &str, budget: usize) -> Option<String> {
    let head = header(kind, st, char_len(body));
    let head_w = char_len(&head) + 1;
    let avail = budget.saturating_sub(head_w);
    if avail < 48 {
        return None;
    }
    let body = clamp_middle(body, avail);
    // Settle the header's "→N chars" against the size of the whole output; only the
    // digit count moves, so two rounds are enough.
    let mut total = char_len(&body);
    let mut head = header(kind, st, total);
    for _ in 0..3 {
        let next = char_len(&head) + 1 + char_len(&body);
        if next == total {
            break;
        }
        total = next;
        head = header(kind, st, total);
    }
    let head_w = char_len(&head) + 1;
    if head_w + char_len(&body) <= budget {
        return Some(format!("{head}\n{body}"));
    }
    if budget <= head_w + 24 {
        return None;
    }
    Some(format!("{head}\n{}", clamp_middle(&body, budget - head_w)))
}

fn cap_lines(body: &str, max_lines: usize, st: &mut Stats) -> String {
    if max_lines == 0 {
        return body.to_string();
    }
    let lines: Vec<&str> = body.lines().collect();
    if lines.len() <= max_lines {
        return body.to_string();
    }
    let keep = max_lines.saturating_sub(1).max(1);
    let omitted = lines.len() - keep;
    st.lines_omitted += omitted;
    let mut out: Vec<&str> = lines[..keep].to_vec();
    out.push("... more lines omitted ...");
    out.join("\n")
}

// ── line families ───────────────────────────────────────────────────────────

fn generic_body(lines: &[&str], limits: &Limits, st: &mut Stats) -> String {
    let lines = trim_empty_edges(lines);
    st.lines_total = st.lines_total.max(lines.len());
    if lines.is_empty() {
        return "(no output)".into();
    }
    let kept = collapse_runs(&lines, limits, st);
    head_tail(&kept, limits.head, limits.tail, st)
}

fn table_body(lines: &[&str], limits: &Limits, st: &mut Stats) -> String {
    let lines = trim_empty_edges(lines);
    st.lines_total = st.lines_total.max(lines.len());
    if lines.is_empty() {
        return "(no output)".into();
    }
    let (header, rest) = match table_header(&lines) {
        Some(h) => (Some(h.trim_end().to_string()), &lines[1..]),
        None => (None, &lines[..]),
    };
    st.facts.push(format!("{} {}", rest.len(), plural(rest.len(), "row")));
    let kept = collapse_runs(rest, limits, st);
    let body = head_tail(&kept, limits.head, limits.tail, st);
    match header {
        Some(h) => format!("{h}\n{body}"),
        None => body,
    }
}

fn search_body(lines: &[&str], limits: &Limits, st: &mut Stats) -> String {
    let lines = trim_empty_edges(lines);
    st.lines_total = st.lines_total.max(lines.len());
    if lines.is_empty() {
        return "(no output)".into();
    }
    let hits: Vec<&str> = lines.iter().copied().filter(|l| is_search_hit(l)).collect();
    let mut files: Vec<&str> = hits.iter().filter_map(|l| l.split_once(':').map(|(p, _)| p)).collect();
    files.sort_unstable();
    files.dedup();
    let msg = if files.is_empty() {
        format!("{} {}", hits.len(), plural(hits.len(), "match"))
    } else {
        format!("{} in {} {}", hits.len(), files.len(), plural(files.len(), "file"))
    };
    st.facts.push(msg);
    let kept = collapse_runs(&lines, limits, st);
    head_tail(&kept, limits.head, limits.tail, st)
}

fn log_body(lines: &[&str], limits: &Limits, st: &mut Stats) -> String {
    let lines = trim_empty_edges(lines);
    st.lines_total = st.lines_total.max(lines.len());
    if lines.is_empty() {
        return "(no output)".into();
    }
    let mut errors: Vec<String> = Vec::new();
    let mut warnings = 0usize;
    for l in &lines {
        if is_failure_line(l) {
            if l.to_ascii_lowercase().contains("warning") {
                warnings += 1;
            } else {
                errors.push(clip_line(l, limits.max_line_chars, st));
            }
        }
    }
    if errors.is_empty() && warnings == 0 {
        return generic_body(&lines, limits, st);
    }
    st.facts.push(format!("{} {}, {} {}", errors.len(), plural(errors.len(), "error line"), warnings, plural(warnings, "warning line")));
    let mut out = String::new();
    if !errors.is_empty() {
        out.push_str("── errors ──");
        let show = errors.len().min(30);
        for e in &errors[..show] {
            out.push('\n');
            out.push_str(e);
        }
        if errors.len() > show {
            let more = errors.len() - show;
            st.lines_omitted += more;
            out.push_str(&format!("\n... {more} more error lines omitted ..."));
        }
    }
    out.push_str("\n── start and end of the log ──\n");
    let kept = collapse_runs(&lines, limits, st);
    out.push_str(&head_tail(&kept, limits.failure_head, limits.failure_tail, st));
    out
}

fn diff_body(lines: &[&str], limits: &Limits, st: &mut Stats) -> String {
    st.lines_total = st.lines_total.max(lines.len());
    let mut out: Vec<String> = Vec::new();
    let (mut files, mut hunks, mut added, mut removed) = (0usize, 0usize, 0usize, 0usize);
    let mut changed_in_hunk = 0usize;
    let (mut omitted_added, mut omitted_removed) = (0usize, 0usize);
    for line in lines {
        if line.starts_with("@@ ") {
            if omitted_added + omitted_removed > 0 {
                out.push(format!("... hunk clipped: {omitted_added} added, {omitted_removed} removed lines omitted ..."));
                st.lines_omitted += omitted_added + omitted_removed;
                omitted_added = 0;
                omitted_removed = 0;
            }
            hunks += 1;
            changed_in_hunk = 0;
            out.push((*line).to_string());
            continue;
        }
        if line.starts_with("diff --git ") {
            if omitted_added + omitted_removed > 0 {
                out.push(format!("... hunk clipped: {omitted_added} added, {omitted_removed} removed lines omitted ..."));
                st.lines_omitted += omitted_added + omitted_removed;
                omitted_added = 0;
                omitted_removed = 0;
            }
            files += 1;
            changed_in_hunk = 0;
            out.push((*line).to_string());
            continue;
        }
        if !is_changed_lin(line) {
            out.push((*line).to_string());
            continue;
        }
        // Upstream's `added line` / `removed line` counters run over the whole diff,
        // not only over the lines that survive the per-hunk clip.
        if line.starts_with('+') {
            added += 1;
        } else {
            removed += 1;
        }
        if changed_in_hunk < limits.diff_lines_per_hunk {
            changed_in_hunk += 1;
            out.push(clip_line(line, limits.max_line_chars * 3 / 5, st));
        } else if line.starts_with('+') {
            omitted_added += 1;
        } else {
            omitted_removed += 1;
        }
    }
    if omitted_added + omitted_removed > 0 {
        out.push(format!("... hunk clipped: {omitted_added} added, {omitted_removed} removed lines omitted ..."));
        st.lines_omitted += omitted_added + omitted_removed;
    }
    st.facts.push(format!(
        "{} {}, {} {}, +{added} −{removed}",
        files,
        plural(files, "file"),
        hunks,
        plural(hunks, "hunk")
    ));
    out.join("\n")
}

// ── JSON ────────────────────────────────────────────────────────────────────

fn json_body(text: &str, limits: &Limits, st: &mut Stats) -> Option<String> {
    let trimmed = text.trim();
    if let Some(v) = json::parse(trimmed) {
        return Some(summarize_json(&v, limits, st));
    }
    // JSONL: one object per line (`docker inspect`, `gh ... --json` dumps, logs).
    let lines: Vec<&str> = trimmed.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 6 {
        return None;
    }
    let total = lines.len();
    let mut items = Vec::new();
    for l in lines.iter().take(200) {
        let t = l.trim();
        if !(t.starts_with('{') || t.starts_with('[')) {
            return None;
        }
        items.push(json::parse(t)?);
    }
    st.facts.push("JSONL, one value per line".to_string());
    if total > items.len() {
        st.facts.push(format!("first {} of {total} lines parsed", items.len()));
    }
    Some(summarize_json(&J::Arr(items), limits, st))
}

fn summarize_json(v: &J, limits: &Limits, st: &mut Stats) -> String {
    let mut out = String::new();
    match v {
        J::Arr(items) if !items.is_empty() => {
            st.items_total = items.len();
            st.lines_total = st.lines_total.max(1);
            out.push_str(&format!("array of {} {}", items.len(), array_item_kind(items)));
            if let Some(keys) = object_keys(items, 12) {
                if !keys.is_empty() {
                    out.push_str(&format!(", keys: {}", keys.join(", ")));
                }
            }
            let head_n = limits.json_items.min(items.len());
            let tail_n = if items.len() > head_n + 1 { 1 } else { 0 };
            for (i, it) in items.iter().take(head_n).enumerate() {
                out.push_str(&format!("\n  [{i}] {}", describe_json(it, 1, limits)));
            }
            let omitted = items.len() - head_n - tail_n;
            if omitted > 0 {
                st.items_omitted = omitted;
                out.push_str(&format!("\n  ... {omitted} more items omitted ..."));
            }
            for (i, it) in items.iter().skip(items.len() - tail_n).enumerate() {
                out.push_str(&format!("\n  [{}] {}", items.len() - tail_n + i, describe_json(it, 1, limits)));
            }
        }
        J::Obj(m) if !m.is_empty() => {
            st.items_total = m.len();
            out.push_str(&format!("object with {} {}", m.len(), plural(m.len(), "key")));
            for (k, val) in m.iter().take(limits.json_keys) {
                out.push_str(&format!("\n  {}: {}", quote_key(k), describe_json(val, 1, limits)));
            }
            let omitted = m.len().saturating_sub(limits.json_keys);
            if omitted > 0 {
                st.items_omitted = omitted;
                out.push_str(&format!("\n  ... {omitted} more keys omitted ..."));
            }
        }
        other => out.push_str(&describe_json(other, 0, limits)),
    }
    out
}

fn describe_json(v: &J, depth: usize, limits: &Limits) -> String {
    match v {
        J::Null => "null".into(),
        J::Bool(b) => if *b { "true" } else { "false" }.into(),
        J::Num(n) => json::js_num(*n),
        J::Str(s) => quote_str(s, 60),
        J::Arr(items) if items.is_empty() => "[]".into(),
        J::Obj(m) if m.is_empty() => "{}".into(),
        J::Arr(items) => {
            if depth >= limits.json_depth {
                return format!("[{} {}]", items.len(), array_item_kind(items));
            }
            let n = limits.json_items.min(items.len());
            let mut parts: Vec<String> = items.iter().take(n).map(|x| describe_json(x, depth + 1, limits)).collect();
            if items.len() > n {
                parts.push(format!("... {} more", items.len() - n));
            }
            format!("[{}]", parts.join(", "))
        }
        J::Obj(m) => {
            if depth >= limits.json_depth {
                let keys: Vec<&str> = m.iter().take(6).map(|(k, _)| k.as_str()).collect();
                return format!("{{... {} keys: {}}}", m.len(), keys.join(", "));
            }
            let n = limits.json_keys.min(m.len());
            let mut parts: Vec<String> = m
                .iter()
                .take(n)
                .map(|(k, val)| format!("{}: {}", quote_key(k), describe_json(val, depth + 1, limits)))
                .collect();
            if m.len() > n {
                parts.push(format!("... {} more keys", m.len() - n));
            }
            format!("{{{}}}", parts.join(", "))
        }
    }
}

fn array_item_kind(items: &[J]) -> String {
    let kind = |v: &J| match v {
        J::Null => "null",
        J::Bool(_) => "booleans",
        J::Num(_) => "numbers",
        J::Str(_) => "strings",
        J::Arr(_) => "arrays",
        J::Obj(_) => "objects",
    };
    let first = kind(&items[0]);
    if items.iter().all(|v| kind(v) == first) {
        return first.to_string();
    }
    "values".into()
}

fn object_keys(items: &[J], cap: usize) -> Option<Vec<String>> {
    let first = items.first()?;
    if !first.is_record() {
        return None;
    }
    let mut keys: Vec<String> = Vec::new();
    for it in items.iter().take(50) {
        if let J::Obj(m) = it {
            for (k, _) in m {
                if keys.len() < cap && !keys.iter().any(|e| e == k) {
                    keys.push(k.clone());
                }
            }
        }
    }
    Some(keys)
}

fn quote_key(k: &str) -> String {
    if !k.is_empty() && k.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '@') {
        k.to_string()
    } else {
        quote_str(k, 40)
    }
}

fn quote_str(s: &str, max: usize) -> String {
    let total = char_len(s);
    let (body, cut) = if total > max { (take_chars(s, max), true) } else { (s, false) };
    let mut out = String::with_capacity(body.len() + 2);
    out.push('"');
    for c in body.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    if cut {
        out.push('…');
    }
    out.push('"');
    out
}

// ── line helpers ────────────────────────────────────────────────────────────

fn split_lines(text: &str) -> Vec<&str> {
    // `trim_end` also drops the `\r` of CRLF input (upstream `normalizeLines`).
    text.split('\n').map(|l| l.trim_end()).collect()
}

fn trim_empty_edges<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    let mut start = 0;
    let mut end = lines.len();
    while start < end && lines[start].trim().is_empty() {
        start += 1;
    }
    while end > start && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    lines[start..end].to_vec()
}

/// Collapse runs of identical lines into one line plus a `(repeated Nx)` note.
fn collapse_runs(lines: &[&str], limits: &Limits, st: &mut Stats) -> Vec<String> {
    let mut kept: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let mut run = 1;
        while i + run < lines.len() && lines[i + run] == line {
            run += 1;
        }
        if run > 1 && !line.trim().is_empty() {
            st.collapsed += run - 1;
            kept.push(format!("{}  (repeated {}x)", clip_line(line, limits.max_line_chars, st), run));
        } else {
            for _ in 0..run {
                kept.push(clip_line(line, limits.max_line_chars, st));
            }
        }
        i += run;
    }
    kept
}

fn head_tail(lines: &[String], head: usize, tail: usize, st: &mut Stats) -> String {
    if head == 0 && tail == 0 {
        return lines.join("\n");
    }
    if lines.len() <= head.saturating_add(tail) {
        return lines.join("\n");
    }
    let omitted = lines.len() - head - tail;
    st.lines_omitted += omitted;
    let mut out: Vec<String> = lines[..head].to_vec();
    out.push(format!("... {omitted} lines omitted ..."));
    out.extend(lines[lines.len() - tail..].iter().cloned());
    out.join("\n")
}

/// Clip an over-long line in the middle with upstream's hashed marker.
fn clip_line(line: &str, max: usize, st: &mut Stats) -> String {
    let total = char_len(line);
    if total <= max || max < 32 {
        return line.to_string();
    }
    st.clipped += 1;
    let hash = ark_net::crypto::hex(&ark_net::crypto::sha256(line.as_bytes()));
    let marker = format!(" ...[{} chars omitted, sha256:{}]... ", total - max, &hash[..12]);
    let mc = char_len(&marker);
    if max <= mc + 16 {
        return take_chars(line, max).to_string();
    }
    let body = max - mc;
    let head = (body * 55 / 100).max(8);
    let tail = body - head;
    format!("{}{}{}", take_chars(line, head), marker, take_last_chars(line, tail))
}

fn table_header<'a>(lines: &[&'a str]) -> Option<&'a str> {
    let first = *lines.first()?;
    let t = first.trim();
    let words = t.split_whitespace().count();
    if words < 2 {
        return None;
    }
    let letters: Vec<char> = t.chars().filter(|c| c.is_alphabetic()).collect();
    if !letters.is_empty() && letters.iter().all(|c| c.is_uppercase()) {
        Some(first)
    } else {
        None
    }
}

fn is_changed_lin(line: &str) -> bool {
    (line.starts_with('+') || line.starts_with('-')) && !line.starts_with("+++") && !line.starts_with("---")
}

fn is_search_hit(line: &str) -> bool {
    match line.split_once(':') {
        Some((path, rest)) => {
            !path.is_empty()
                && !path.contains(' ')
                && (path.contains('/') || path.contains('.') || path.chars().all(|c| c.is_alphanumeric() || c == '_'))
                && rest.chars().next().is_some_and(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

fn looks_like_search(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 8 {
        return false;
    }
    let hits = lines.iter().filter(|l| is_search_hit(l)).count();
    hits * 3 >= lines.len() * 2
}

fn looks_like_jsonl(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).take(32).collect();
    if lines.len() < 6 {
        return false;
    }
    let objs = lines.iter().filter(|l| l.trim_start().starts_with('{') && l.trim_end().ends_with('}')).count();
    objs * 10 >= lines.len() * 9 && lines.iter().take(6).all(|l| json::parse(l.trim()).is_some())
}

fn looks_like_build_log(text: &str) -> bool {
    let mut build = false;
    let mut failures = 0;
    for l in text.lines() {
        let t = l.trim_start();
        if t.starts_with("Compiling ")
            || t.starts_with("Finished ")
            || t.starts_with("BUILD SUCCESS")
            || t.starts_with("BUILD FAILED")
            || t.starts_with("npm ERR!")
            || t.contains("error[E")
            || t.starts_with("error TS")
            || t.starts_with("make[")
            || t.starts_with("Test Suites:")
            || t.starts_with("FAILED ")
            || t.starts_with("---- ") && t.ends_with(" stdout ----")
        {
            build = true;
        }
        if is_failure_line(l) {
            failures += 1;
        }
    }
    build && failures > 0
}

fn looks_like_table(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 10 {
        return false;
    }
    if table_header(&lines).is_some() {
        return true;
    }
    // `ls -l` / `ps` style: most lines start with a permission, PID or date column.
    let shaped = lines
        .iter()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("-rw")
                || t.starts_with("drw")
                || t.starts_with("lrw")
                || t.split_whitespace().next().is_some_and(|w| w.chars().all(|c| c.is_ascii_digit()))
        })
        .count();
    shaped * 2 >= lines.len()
}

fn is_failure_line(line: &str) -> bool {
    let l = line.trim_start().to_ascii_lowercase();
    l.starts_with("error")
        || l.contains("error[")
        || l.starts_with("warning:")
        || l.starts_with("warn ")
        || l.contains("error ts")
        || l.contains("npm err!")
        || l.contains("panicked at")
        || l.contains("traceback (most recent call last)")
        || l.contains("assertion failed")
        || l.contains(": fatal error")
        || l.contains("cannot find symbol")
        || l.contains("undefined reference")
        || l.contains("test failed")
        || l.contains("tests failed")
        || l.contains("build failed")
        || l.starts_with("fatal:")
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        noun.to_string()
    } else if noun.ends_with('s') || noun.ends_with('x') || noun.ends_with('z') || noun.ends_with("sh") || noun.ends_with("ch") {
        format!("{noun}es")
    } else if noun.ends_with('y') && !noun.ends_with("ay") && !noun.ends_with("ey") {
        format!("{}ies", &noun[..noun.len() - 1])
    } else {
        format!("{noun}s")
    }
}

// ── char-safe primitives ────────────────────────────────────────────────────

fn char_len(s: &str) -> usize {
    s.chars().count()
}

fn take_chars(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn take_last_chars(s: &str, n: usize) -> &str {
    let total = char_len(s);
    if n == 0 {
        return "";
    }
    if n >= total {
        return s;
    }
    match s.char_indices().nth(total - n) {
        Some((i, _)) => &s[i..],
        None => s,
    }
}

fn trim_head_to_line_boundary(text: &str) -> &str {
    match text.rfind('\n') {
        Some(i) if char_len(&text[..i]) * 2 >= char_len(text) => &text[..i],
        _ => text,
    }
}

fn trim_tail_to_line_boundary(text: &str) -> &str {
    match text.find('\n') {
        Some(i) if char_len(&text[i + 1..]) * 2 >= char_len(text) => &text[i + 1..],
        _ => text,
    }
}

/// Clamp `text` to `max` characters. Line-oriented bodies lose whole middle lines
/// (with a `... N more lines omitted ...` marker) instead of being cut mid-line;
/// only a single huge line falls back to a character cut.
fn clamp_middle(text: &str, max: usize) -> String {
    let total = char_len(text);
    if total <= max {
        return text.to_string();
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() >= 6 {
        let mut head_n = lines.len() / 2;
        let mut tail_n = lines.len() - head_n;
        while head_n + tail_n > 2 {
            let omitted = lines.len() - head_n - tail_n;
            let marker = format!("... {omitted} more lines omitted ...");
            let width = |part: &[&str]| part.iter().map(|l| char_len(l) + 1).sum::<usize>();
            let len = width(&lines[..head_n]) + char_len(&marker) + 1 + width(&lines[lines.len() - tail_n..]);
            if len <= max {
                let mut out = String::new();
                for l in &lines[..head_n] {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&marker);
                for l in &lines[lines.len() - tail_n..] {
                    out.push('\n');
                    out.push_str(l);
                }
                return out;
            }
            if head_n >= tail_n {
                head_n -= 1;
            } else {
                tail_n -= 1;
            }
        }
    }
    const MARKER: &str = "\n... omitted ...\n";
    let m = char_len(MARKER);
    if max <= m + 16 {
        return take_chars(text, max).to_string();
    }
    let body = max - m;
    let head = (body * 7).div_ceil(10);
    let tail = body - head;
    let h = trim_head_to_line_boundary(take_chars(text, head));
    let t = trim_tail_to_line_boundary(take_last_chars(text, tail));
    format!("{h}{MARKER}{t}")
}

#[cfg(test)]
mod tests;
