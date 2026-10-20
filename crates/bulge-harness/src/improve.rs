//! Offline improver: after a job finishes, the agent reviews what happened and
//! proposes a few durable lessons for its memory — the "learns over use" loop,
//! run between jobs (never mid-task), so it costs no extra tokens during work.
//!
//! This is Harness²'s Propose step, adapted and kept offline: the pure logic
//! (the proposal prompt and the parser for the model's reply) lives here; the
//! model call and the `memory::save` are done by the caller (the CLI/driver),
//! exactly as the completion gate splits logic from I/O.

use crate::memory::Lesson;

/// Instruction appended after a finished job's transcript to elicit lessons.
/// The model must answer with a JSON array (possibly empty) and nothing else.
pub const PROPOSE_LESSONS_PROMPT: &str = "\
The job above is finished. Propose at most three DURABLE lessons for future jobs \
— only things that will generalise, never facts specific to this one task. For each, give:\n\
- cue: the situation it applies to (short, keyword-rich; this is how it is found later)\n\
- lesson: what to do, concretely\n\
- evidence: what in this job shows it (a step, a file, an error, a result)\n\
- confidence: a number in [0,1]\n\
Drop anything you are not sure generalises. If there is nothing durable, return [].\n\
Answer with ONLY a JSON array of objects {cue, lesson, evidence, confidence}, no prose.";

/// A slug derived from a cue: lowercase, alphanumerics kept, runs of anything
/// else collapsed to one `-`, trimmed, capped. Empty cue → "lesson".
pub fn slug(cue: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in cue.chars() {
        if ch.is_ascii_alphanumeric() {
            out.extend(ch.to_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let slug: String = out.trim_matches('-').chars().take(48).collect();
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() { "lesson".into() } else { slug }
}

/// Parse the model's reply into well-formed lessons. Tolerant of surrounding
/// prose: the first top-level `[...]` array is extracted and parsed. Each entry
/// needs a non-empty cue, lesson, and evidence; confidence defaults to 0.5 and
/// is clamped. Ids are slugged from the cue and de-duplicated with a suffix.
///
/// `existing_ids` are ids already in memory, so a proposal never collides with a
/// stored lesson (it gets a fresh `-2`, `-3`, … suffix instead).
pub fn parse_proposed_lessons(reply: &str, existing_ids: &[String]) -> Vec<Lesson> {
    let Some(array) = extract_json_array(reply) else {
        return Vec::new();
    };
    let Ok(values) = serde_json::from_str::<Vec<serde_json::Value>>(&array) else {
        return Vec::new();
    };

    let mut used: std::collections::HashSet<String> = existing_ids.iter().cloned().collect();
    let mut lessons = Vec::new();
    for value in values {
        let cue = string_field(&value, "cue");
        let lesson_text = string_field(&value, "lesson");
        let evidence = string_field(&value, "evidence");
        if cue.is_empty() || lesson_text.is_empty() || evidence.is_empty() {
            continue; // not well-formed; drop it
        }
        let confidence = value.get("confidence").and_then(json_to_f32).unwrap_or(0.5);
        let id = unique_id(slug(&cue), &mut used);
        lessons.push(Lesson::new(id, cue, lesson_text, evidence, confidence));
    }
    lessons
}

fn string_field(value: &serde_json::Value, key: &str) -> String {
    value.get(key).and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
}

fn json_to_f32(value: &serde_json::Value) -> Option<f32> {
    value.as_f64().map(|n| n as f32).or_else(|| value.as_str().and_then(|s| s.trim().parse::<f32>().ok()))
}

fn unique_id(base: String, used: &mut std::collections::HashSet<String>) -> String {
    if used.insert(base.clone()) {
        return base;
    }
    for n in 2.. {
        let candidate = format!("{base}-{n}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("the counter is unbounded")
}

/// Extract the first balanced top-level `[...]` from text, ignoring brackets
/// inside JSON strings. Returns the array substring (including the brackets).
fn extract_json_array(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let start = text.find('[')?;
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, &byte) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start..=offset].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_url_safe_and_bounded() {
        assert_eq!(slug("Running cargo tests!"), "running-cargo-tests");
        assert_eq!(slug("  spaced / slashed  "), "spaced-slashed");
        assert_eq!(slug("***"), "lesson");
        assert!(slug(&"x".repeat(100)).len() <= 48);
    }

    #[test]
    fn parses_a_clean_array() {
        let reply = r#"[
            {"cue": "running cargo tests", "lesson": "use --workspace", "evidence": "step 4 passed", "confidence": 0.8},
            {"cue": "editing TOML", "lesson": "end with a newline", "evidence": "file x", "confidence": "0.6"}
        ]"#;
        let lessons = parse_proposed_lessons(reply, &[]);
        assert_eq!(lessons.len(), 2);
        assert_eq!(lessons[0].id, "running-cargo-tests");
        assert_eq!(lessons[0].confidence, 0.8);
        assert_eq!(lessons[1].confidence, 0.6); // parsed from a string
    }

    #[test]
    fn tolerates_prose_around_the_array() {
        let reply = "Sure! Here are the lessons:\n[{\"cue\":\"a\",\"lesson\":\"b\",\"evidence\":\"c\"}]\nHope that helps.";
        let lessons = parse_proposed_lessons(reply, &[]);
        assert_eq!(lessons.len(), 1);
        assert_eq!(lessons[0].confidence, 0.5); // default
    }

    #[test]
    fn drops_ill_formed_entries() {
        let reply = r#"[
            {"cue": "", "lesson": "x", "evidence": "y"},
            {"cue": "ok", "lesson": "x", "evidence": "y"},
            {"cue": "no evidence", "lesson": "x"}
        ]"#;
        let lessons = parse_proposed_lessons(reply, &[]);
        assert_eq!(lessons.len(), 1);
        assert_eq!(lessons[0].cue, "ok");
    }

    #[test]
    fn empty_array_and_garbage_yield_nothing() {
        assert!(parse_proposed_lessons("[]", &[]).is_empty());
        assert!(parse_proposed_lessons("no json here", &[]).is_empty());
        assert!(parse_proposed_lessons("[not, valid, json", &[]).is_empty());
    }

    #[test]
    fn ids_do_not_collide_with_existing_or_each_other() {
        let reply = r#"[
            {"cue": "cargo tests", "lesson": "a", "evidence": "e"},
            {"cue": "cargo tests", "lesson": "b", "evidence": "e"}
        ]"#;
        let lessons = parse_proposed_lessons(reply, &["cargo-tests".to_string()]);
        assert_eq!(lessons[0].id, "cargo-tests-2");
        assert_eq!(lessons[1].id, "cargo-tests-3");
    }

    #[test]
    fn brackets_inside_strings_do_not_end_the_array() {
        let reply = r#"[{"cue": "arrays [like this]", "lesson": "mind the ]", "evidence": "e"}]"#;
        let lessons = parse_proposed_lessons(reply, &[]);
        assert_eq!(lessons.len(), 1);
        assert_eq!(lessons[0].cue, "arrays [like this]");
    }
}
