//! Reducer tests, driven by real-world command output shapes (`docker ps`, `ls -l`,
//! `grep`, `git diff`, JSON API dumps) and by the guarantees the tools rely on:
//! small output is untouched, nothing panics, and UTF-8 is never split.

use super::*;

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// A realistic `docker ps` listing: one header row and 40 container rows.
fn docker_ps() -> String {
    let mut s = String::from(
        "CONTAINER ID   IMAGE                     COMMAND                  CREATED        STATUS          PORTS                    NAMES\n",
    );
    for i in 0..40 {
        s.push_str(&format!(
            "{:012x}   ghcr.io/acme/api:latest   \"node server.js\"         {i} hours ago   Up {i} hours     0.0.0.0:808{}->8080/tcp   api-{i}\n",
            0xabc000 + i,
            i % 10
        ));
    }
    s
}

/// A realistic `ls -l` listing with 120 entries.
fn ls_long() -> String {
    let mut s = String::from("total 4820\n");
    for i in 0..120 {
        s.push_str(&format!(
            "-rw-r--r-- 1 noob noob {:>8} Nov  3 19:35 module-{i:03}.rs\n",
            1000 + i * 37
        ));
    }
    s
}

fn grep_hits() -> String {
    let mut s = String::new();
    for i in 0..150 {
        s.push_str(&format!("crates/ark-tools/src/shell.rs:{i}:    let out = run(command);\n"));
    }
    s
}

fn api_dump() -> String {
    let mut s = String::from("[\n");
    for i in 0..200 {
        s.push_str(&format!(
            "  {{\n    \"id\": {i},\n    \"name\": \"service-{i}\",\n    \"created_at\": \"2026-11-01T03:04:05Z\",\n    \"tags\": [\"prod\", \"eu\"],\n    \"enabled\": true\n  }}{}\n",
            if i == 199 { "" } else { "," }
        ));
    }
    s.push(']');
    s
}

fn git_diff() -> String {
    let mut s = String::from("diff --git a/src/lib.rs b/src/lib.rs\nindex 1111111..2222222 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,40 +1,40 @@\n");
    for i in 0..40 {
        s.push_str(&format!("-fn old_line_{i}() {{ /* removed body */ }}\n"));
    }
    for i in 0..40 {
        s.push_str(&format!("+fn new_line_{i}() {{ /* added body */ }}\n"));
    }
    s
}

#[test]
fn small_output_is_left_alone() {
    assert_eq!(reduce("hi\n", Kind::Auto), None);
    assert_eq!(reduce_output("total 0\nfoo\n", DEFAULT_BUDGET), None);
    // 200 chars of unique short lines: below the tiny-output threshold.
    let small: String = (0..20).map(|i| format!("line {i}\n")).collect();
    assert!(chars(&small) < TINY_OUTPUT_MAX_CHARS);
    assert_eq!(reduce(&small, Kind::Generic), None);
    // Empty input.
    assert_eq!(reduce("", Kind::Auto), None);
    assert_eq!(reduce("    \n\n\t\n", Kind::Generic), None);
}

#[test]
fn no_gain_returns_none() {
    // 12 unique short lines: nothing to drop, so the header would only add tokens.
    let text: String = (0..12).map(|i| format!("unique value number {i}\n")).collect();
    assert!(chars(&text) > TINY_OUTPUT_MAX_CHARS);
    assert_eq!(reduce_with(&text, Kind::Generic, &Limits::default()), None);
}

#[test]
fn docker_ps_table_keeps_header_rows_and_says_what_it_dropped() {
    let raw = docker_ps();
    let out = reduce(&raw, Kind::Table).expect("compacted");
    assert!(out.starts_with("[tokenjuice table]"), "{out}");
    assert!(out.contains("CONTAINER ID"), "table header kept: {out}");
    assert!(out.contains("abc000"), "first row kept: {out}");
    assert!(out.contains("lines omitted"), "omission marker: {out}");
    assert!(out.contains("rows"), "row count fact: {out}");
    assert!(chars(&out) < chars(&raw) / 2, "{} vs {}", chars(&out), chars(&raw));
    // Classification from the text and from the command line agree.
    assert_eq!(classify(&raw), Kind::Table);
    assert_eq!(classify_command("docker ps -a"), Kind::Table);
}

#[test]
fn ls_long_is_trimmed_to_head_and_tail() {
    let raw = ls_long();
    let out = reduce(&raw, Kind::Table).expect("compacted");
    assert!(out.contains("total 4820"), "kept the total line: {out}");
    assert!(out.contains("module-000.rs"), "kept the first entry: {out}");
    assert!(out.contains("module-119.rs"), "kept the last entry: {out}");
    assert!(!out.contains("module-060.rs"), "middle dropped: {out}");
    assert!(out.contains("... ") && out.contains(" lines omitted ..."), "{out}");
    assert!(chars(&out) <= DEFAULT_BUDGET);
    assert_eq!(classify_command("ls -la"), Kind::Table);
}

#[test]
fn grep_hits_keep_head_tail_and_match_count() {
    let raw = grep_hits();
    let out = reduce(&raw, Kind::Search).expect("compacted");
    assert!(out.contains("shell.rs:0:"), "{out}");
    assert!(out.contains("shell.rs:149:"), "{out}");
    assert!(out.contains("in 1 file"), "match/file fact: {out}");
    assert!(out.contains("lines omitted"), "{out}");
    assert_eq!(classify(&raw), Kind::Search);
    assert_eq!(classify_command("grep -rn run src/"), Kind::Search);
    assert_eq!(classify_command("rg --line-number foo"), Kind::Search);
}

#[test]
fn repeated_lines_fold_with_a_count() {
    let raw: String = (0..60).map(|_| "warning: unused variable `x`\n").collect();
    let out = reduce(&raw, Kind::Generic).expect("compacted");
    assert!(out.contains("(repeated 60x)"), "{out}");
    assert!(out.contains("repeated lines collapsed"), "{out}");
    assert!(chars(&out) < 200, "{out}");
}

#[test]
fn long_single_line_is_clipped_in_the_middle() {
    let head = "HEAD-MARKER-";
    let tail = "-TAIL-MARKER";
    let filler = "x".repeat(6000);
    let raw = format!("{head}{filler}{tail}");
    let out = reduce(&raw, Kind::Generic).expect("compacted");
    assert!(out.contains(head), "{out}");
    assert!(out.contains(tail), "{out}");
    assert!(out.contains("chars omitted, sha256:"), "{out}");
    assert!(chars(&out) <= DEFAULT_BUDGET, "{} chars", chars(&out));
}

#[test]
fn json_array_is_summarised_with_schema_and_samples() {
    let raw = api_dump();
    let out = reduce(&raw, Kind::Auto).expect("compacted");
    assert!(out.starts_with("[tokenjuice json]"), "{out}");
    assert!(out.contains("array of 200 objects"), "{out}");
    assert!(out.contains("keys: id, name, created_at, tags, enabled"), "{out}");
    assert!(out.contains("[0] "), "{out}");
    assert!(out.contains("\"service-0\""), "{out}");
    assert!(out.contains("[199] "), "{out}");
    assert!(out.contains("\"service-199\""), "{out}");
    assert!(out.contains("more items omitted"), "{out}");
    assert!(!out.contains("service-120"), "middle sample dropped: {out}");
    assert!(chars(&out) < chars(&raw) / 10);
    assert_eq!(classify(&raw), Kind::Json);
}

#[test]
fn json_object_keeps_its_keys() {
    let raw = r#"{
      "total": 128,
      "page": 1,
      "items": [
        {"id": 1, "name": "a"},
        {"id": 2, "name": "b"}
      ],
      "next": null
    }"#;
    // Small object: no gain, so the caller keeps the raw text.
    assert_eq!(reduce(raw, Kind::Json), None);

    let mut big = String::from("{\"total\": 5000, \"items\": [");
    for i in 0..600 {
        big.push_str(&format!("{{\"id\": {i}, \"name\": \"item-{i}\", \"ok\": true}},"));
    }
    big.push_str("{\"id\": 600, \"name\": \"last\", \"ok\": false}]}");
    let out = reduce(&big, Kind::Json).expect("compacted");
    assert!(out.contains("object with 2 keys"), "{out}");
    assert!(out.contains("total: 5000"), "{out}");
    assert!(out.contains("items: ["), "nested array summarised: {out}");
    assert!(out.contains("more"), "{out}");
    assert!(chars(&out) <= DEFAULT_BUDGET);
}

#[test]
fn jsonl_lines_are_summarised() {
    let raw: String = (0..40)
        .map(|i| format!("{{\"level\":\"info\",\"msg\":\"request {i} served\",\"ms\":{i}}}\n"))
        .collect();
    let out = reduce(&raw, Kind::Auto).expect("compacted");
    assert!(out.contains("JSONL"), "{out}");
    assert!(out.contains("array of 40 objects"), "{out}");
    assert!(out.contains("keys: level, msg, ms"), "{out}");
    assert!(chars(&out) < chars(&raw) / 3);
}

#[test]
fn git_diff_keeps_headers_and_clips_hunks() {
    let raw = git_diff();
    let out = reduce(&raw, Kind::Auto).expect("compacted");
    assert!(out.contains("diff --git a/src/lib.rs b/src/lib.rs"), "{out}");
    assert!(out.contains("@@ -1,40 +1,40 @@"), "{out}");
    assert!(out.contains("old_line_0"), "{out}");
    assert!(!out.contains("old_line_30"), "hunk clipped: {out}");
    assert!(out.contains("hunk clipped: 40 added, 32 removed lines omitted"), "{out}");
    assert!(!out.contains("+fn new_line_0"), "only the first changed lines survive: {out}");
    assert!(out.contains("1 file, 1 hunk, +40 −40"), "full-diff counters: {out}");
    assert_eq!(classify(&raw), Kind::Diff);
    assert_eq!(classify_command("git diff HEAD -- crates"), Kind::Diff);
}

#[test]
fn build_log_keeps_error_and_warning_lines() {
    let mut raw = String::from("   Compiling ark-tools v0.1.0\n");
    for i in 0..80 {
        raw.push_str(&format!("warning: unused import `x{i}` in module {i}\n"));
        raw.push_str(&format!("  --> crates/ark-tools/src/mod_{i}.rs:3:5\n"));
    }
    raw.push_str("error[E0308]: mismatched types\n  --> crates/ark-tools/src/shell.rs:42:9\n");
    raw.push_str("Finished `dev` profile in 3.2s\n");
    let out = reduce(&raw, Kind::Log).expect("compacted");
    assert!(out.contains("error[E0308]: mismatched types"), "error preserved: {out}");
    assert!(out.contains("── errors ──"), "{out}");
    assert!(out.contains("start and end of the log"), "{out}");
    assert!(out.contains("Compiling ark-tools"), "{out}");
    assert!(out.contains("Finished `dev` profile"), "{out}");
    assert!(chars(&out) < chars(&raw) / 2);
}

#[test]
fn ansi_escapes_are_stripped_before_anything_else() {
    let mut raw = String::new();
    for i in 0..60 {
        raw.push_str(&format!("\u{1b}[01;34mdir-{i}\u{1b}[0m\n"));
    }
    raw.push_str("\u{1b}]0;title\u{7}done\n");
    let out = reduce(&raw, Kind::Generic).expect("compacted");
    assert!(!out.contains('\u{1b}'), "no escapes left: {out:?}");
    assert!(out.contains("dir-0"), "{out}");
    assert!(out.contains("done"), "{out}");
    assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m"), "red");
    assert_eq!(strip_ansi("a\u{1b}]0;t\u{1b}\\b"), "ab");
    assert_eq!(strip_ansi("plain"), "plain");
}

#[test]
fn utf8_boundaries_are_never_split() {
    // Multi-byte text long enough to be clipped by the middle-clamp.
    let raw: String = (0..400).map(|i| format!("第{i}行：檔案內容很長，這是測試資料 🚀🎯\n")).collect();
    let out = reduce(&raw, Kind::Generic).expect("compacted");
    assert!(!out.contains('\u{fffd}'), "no replacement chars: {out}");
    assert!(out.contains("第0行"), "{out}");
    assert!(out.contains("第399行"), "{out}");
    assert!(chars(&out) <= DEFAULT_BUDGET);

    // A single very long CJK/emoji line: the hash clip must land on char boundaries.
    let line = format!("{}尾巴", "中文🙂".repeat(2000));
    let clipped = reduce(&line, Kind::Generic).expect("compacted");
    assert!(clipped.contains("尾巴"), "{clipped}");
    assert!(chars(&clipped) <= DEFAULT_BUDGET);

    // take/take_last are char-indexed, not byte-indexed.
    assert_eq!(take_chars("😀😀😀", 2), "😀😀");
    assert_eq!(take_last_chars("😀😀😀", 2), "😀😀");
    assert_eq!(take_last_chars("😀😀😀", 9), "😀😀😀");
}

#[test]
fn unparseable_input_does_not_panic() {
    let cases: Vec<String> = vec![
        "{".into(),
        "[1,".into(),
        "{\"a\": 1}".repeat(100),
        "\u{0}\u{1}\u{2}binary\u{7f}".to_string(),
        "[".repeat(600),
        format!("{{\"deep\": {}{}}}", "[".repeat(400), "]".repeat(400)),
        "a\n".repeat(10_000),
        "-".repeat(50_000),
        "diff --git\n@@\n+++\n---\n".to_string(),
        (0..300).map(|i| format!("line {i} 中文\n")).collect(),
    ];
    for c in cases {
        let _ = reduce(&c, Kind::Auto);
        let _ = reduce(&c, Kind::Json);
        let _ = reduce(&c, Kind::Diff);
        let _ = reduce(&c, Kind::Search);
        let _ = reduce(&c, Kind::Table);
        let _ = reduce(&c, Kind::Log);
        let _ = reduce_output(&c, 0);
        let _ = reduce_output(&c, 1);
        let _ = classify(&c);
    }
}

#[test]
fn budget_is_respected() {
    let raw = docker_ps();
    for budget in [200usize, 300, 600, 1200, 4000] {
        let out = reduce_output(&raw, budget).expect("compacted");
        assert!(chars(&out) <= budget, "budget {budget}: {} chars", chars(&out));
    }
    // A budget too small for the marker line keeps the raw text instead.
    assert_eq!(reduce_output(&raw, 60), None);
    assert_eq!(reduce_output(&raw, 1), None);
}

#[test]
fn file_content_inspection_is_never_rewritten() {
    let raw = api_dump();
    // `cat package.json` must reach the model intact, even when it is huge JSON.
    for cmd in [
        "cat package.json",
        "head -n 100 api.json",
        "tail -f out.log",
        "jq .items api.json",
        "sed -n '1,40p' Cargo.toml",
        "sudo cat /etc/hosts",
        "bat --plain src/lib.rs",
        "git show HEAD:crates/ark-tools/src/json.rs",
    ] {
        assert!(is_verbatim_command(cmd), "{cmd}");
        assert_eq!(reduce_command_output(cmd, &raw, DEFAULT_BUDGET), None, "{cmd}");
    }
    // A patch, a listing and a grep hit are compacted as usual.
    assert!(!is_verbatim_command("git show HEAD"));
    assert!(!is_verbatim_command("git diff"));
    assert!(!is_verbatim_command("ls -la"));
    assert!(reduce_command_output("git show HEAD", &git_diff(), DEFAULT_BUDGET).is_some());
}

#[test]
fn classification_covers_the_rule_families() {
    assert_eq!(classify("{\"a\": 1}"), Kind::Json);
    assert_eq!(classify(&api_dump()), Kind::Json);
    assert_eq!(classify(&git_diff()), Kind::Diff);
    assert_eq!(classify(&grep_hits()), Kind::Search);
    assert_eq!(classify(&docker_ps()), Kind::Table);
    assert_eq!(classify(&ls_long()), Kind::Table);
    assert_eq!(classify("error: boom\nwarning: hmm\n"), Kind::Generic);

    assert_eq!(classify_command("git status"), Kind::Auto);
    assert_eq!(classify_command("cargo build --release"), Kind::Log);
    assert_eq!(classify_command("cd /tmp && ls -la"), Kind::Table);
    assert_eq!(classify_command("find . -name '*.rs'"), Kind::Table);
    assert_eq!(classify_command("/usr/bin/grep -r foo ."), Kind::Search);
    assert_eq!(classify_command("git grep needle"), Kind::Search);
    assert_eq!(classify_command("cat README.md"), Kind::Auto);
    assert_eq!(classify_command(""), Kind::Auto);
}

#[test]
fn reduce_command_output_uses_the_command_family() {
    let raw = grep_hits();
    let out = reduce_command_output("grep -rn run crates", &raw, DEFAULT_BUDGET).expect("compacted");
    assert!(out.starts_with("[tokenjuice search]"), "{out}");
    // An unknown command falls back to classifying the text itself.
    let out = reduce_command_output("./tool.sh", &raw, DEFAULT_BUDGET).expect("compacted");
    assert!(out.starts_with("[tokenjuice search]"), "{out}");
    // A command whose family cannot help still gets the generic treatment.
    let raw = ls_long();
    assert!(reduce_command_output("./tools/list.sh", &raw, DEFAULT_BUDGET).is_some());
}

#[test]
fn every_compacted_output_states_the_original_size() {
    let raw = docker_ps();
    let out = reduce(&raw, Kind::Table).unwrap();
    assert!(out.contains(&format!("{}→", chars(&raw))), "{out}");
    assert!(out.contains("lossy compaction"), "{out}");
    assert!(out.lines().next().unwrap().starts_with("[tokenjuice "));
}

#[test]
fn crlf_input_is_normalised() {
    let raw: String = (0..50).map(|i| format!("row {i}\r\n")).collect();
    let out = reduce(&raw, Kind::Generic).expect("compacted");
    assert!(!out.contains('\r'), "{out:?}");
    assert!(out.contains("row 0"), "{out}");
}

#[test]
fn limits_are_honoured() {
    let raw = ls_long();
    let limits = Limits { budget: 500, head: 3, tail: 2, ..Limits::default() };
    let out = reduce_with(&raw, Kind::Table, &limits).expect("compacted");
    assert!(chars(&out) <= 500, "{}", chars(&out));
    let body_start = out.find("total 4820").expect("header row");
    let body = &out[body_start..];
    // head 3 covers `total 4820` + two entries, tail 2 covers the last two.
    assert_eq!(body.lines().filter(|l| l.contains("module-")).count(), 4, "{out}");
}
