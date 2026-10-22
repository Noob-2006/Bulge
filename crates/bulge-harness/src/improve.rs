//! Offline improver: after a job finishes, the agent reviews what happened and
//! proposes a few durable lessons for its memory — the "learns over use" loop,
//! run between jobs (never mid-task), so it costs no extra tokens during work.
//!
//! This is Harness²'s Propose step, adapted and kept offline: the pure logic
//! (the proposal prompt and the parser for the model's reply) lives here; the
//! model call and the `memory::save` are done by the caller (the CLI/driver),
//! exactly as the completion gate splits logic from I/O.

use crate::memory::Lesson;

/// The guardrail text as a macro, so `concat!` can splice it into prompt
/// constants while `DO_NOT_CAPTURE` remains a plain `&str`.
macro_rules! do_not_capture {
    () => {
        "\
Do NOT record any of the following — they poison future runs:\n\
- Environment-specific failures (a missing binary, a path that only exists here, a flaky network).\n\
- Negative tool claims (\"tool X is broken\", \"the API doesn't work\") — they are usually transient or local.\n\
- Transient errors you recovered from, or dead-ends you never resolved, dressed up as advice.\n\
- Anything tied to this one task: specific file names, IDs, dates, PR numbers, or quoted output.\n\
When you do record something, state the rule procedurally and, for a pitfall, give the rule plus ONE short why-clause. \
Fix knowledge in place — never append \"UPDATE: actually …\" to an existing item. \
If the user expressed a preference or frustration (\"stop doing X\", \"too verbose\", \"always do Y\"), \
that is FIRST-CLASS signal worth capturing."
    };
}


/// Guardrail appended to every "propose durable knowledge" prompt. Keeps the
/// self-improvement loop from poisoning its own memory with things that will
/// not generalise. Adapted from Hermes' background-review DO-NOT-CAPTURE block.
pub const DO_NOT_CAPTURE: &str = do_not_capture!();

/// One post-job learning call does all three proposals (lessons, profile,
/// skill): its instruction is new, uncached text on every job, so asking once
/// instead of three times sends it — and the shared transcript prefix — once.
/// The model answers with ONE JSON object; [`parse_proposed_learning`] splits it
/// and hands each part to the existing per-kind parser.
pub const PROPOSE_LEARNING_PROMPT: &str = concat!(
    "\
The job above is finished. Review it once and answer three questions.\n\n\
1. LESSONS — at most three DURABLE lessons for future jobs: only things that will generalise, \
never facts specific to this one task. Each: cue (the situation it applies to; short, \
keyword-rich — this is how it is found later), lesson (what to do, concretely), evidence (what \
in this job shows it: a step, a file, an error, a result), confidence (a number in [0,1]). \
Drop anything you are not sure generalises, and anything an entry in <lessons> above \
already says (even in other words) — repeats bloat memory and teach nothing new.\n\n\
2. PROFILE — what you now durably know, on TWO surfaces: USER.md (target \"user\": who the user \
is and how they want you to work — role, preferences, recurring instructions, things they told \
you to always/never do; one fact per section) and MEMORY.md (target \"env\": durable facts about \
THIS environment — tools, paths, conventions, how the project is built/tested; not user \
preferences). Route each fact to exactly ONE surface. Short keyword-rich section titles, one- or \
two-sentence bodies; to delete an obsolete section set remove=true.\n\n\
3. SKILL — a successful, repeatable procedure usually IS worth a skill. If this job used one \
that would work again on FUTURE, similar jobs, propose ONE: a named, general, multi-step \
procedure (not a one-off, not a single fact — small facts are lessons). Return null if a \
skill in <available_skills> above already covers it. name: short kebab-case; \
description: one line saying when to use it, at most 60 characters (the skill index truncates \
at 60 and anything past it never routes); body: the steps, in Markdown.",
    "\n\n",
    do_not_capture!(),
    "\n\n",
    "Answer with ONLY one JSON object, no prose: {\"lessons\": [{cue, lesson, evidence, confidence}], \
\"profile\": [{target, key, body, remove}], \"skill\": {name, description, body} or null}. \
Use [] / null for anything with nothing durable. Be terse: each lesson, evidence and \
profile body is one sentence; a skill body is at most ten short numbered steps."
);

/// The three proposals parsed from one [`PROPOSE_LEARNING_PROMPT`] reply.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Learning {
    pub lessons: Vec<Lesson>,
    pub profile: Vec<ProfileUpdate>,
    pub skill: Option<crate::workshop::SkillDraft>,
}

/// Parse a combined learning reply. Tolerant of prose around the object; a
/// missing or malformed part just yields nothing for that part (each part goes
/// through its own validating parser).
pub fn parse_proposed_learning(reply: &str, existing_ids: &[String]) -> Learning {
    let Some(value) = crate::workshop::extract_json_object(reply).and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok()) else {
        return Learning::default();
    };
    let part = |key: &str| value.get(key).map(serde_json::Value::to_string).unwrap_or_default();
    Learning {
        lessons: parse_proposed_lessons(&part("lessons"), existing_ids),
        profile: parse_proposed_profile(&part("profile")),
        skill: crate::workshop::parse_proposed_skill(&part("skill")),
    }
}

/// Which profile surface an update targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileTarget {
    User,
    Env,
}

/// One proposed change to a profile file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileUpdate {
    /// `"user"` -> `USER.md`, `"env"` -> `MEMORY.md`.
    pub target: ProfileTarget,
    /// The section title.
    pub key: String,
    /// The section body ("" together with `remove = true` means delete).
    pub body: String,
    pub remove: bool,
}

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

/// Parse the model's reply into profile updates. Tolerant like
/// `parse_proposed_lessons`: the first top-level `[...]` array is extracted and
/// parsed. Each item is `{target, key, body, remove?}`; an unknown target, an
/// empty key, or an empty body without `remove` drops the item.
pub fn parse_proposed_profile(reply: &str) -> Vec<ProfileUpdate> {
    let Some(array) = extract_json_array(reply) else {
        return Vec::new();
    };
    let Ok(values) = serde_json::from_str::<Vec<serde_json::Value>>(&array) else {
        return Vec::new();
    };

    let mut updates = Vec::new();
    for value in values {
        let target = match string_field(&value, "target").as_str() {
            "user" => ProfileTarget::User,
            "env" => ProfileTarget::Env,
            _ => continue, // unknown surface
        };
        let key = string_field(&value, "key");
        if key.is_empty() {
            continue; // a section needs a title
        }
        let body = string_field(&value, "body");
        let remove = value
            .get("remove")
            .and_then(|v| {
                v.as_bool()
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse::<bool>().ok()))
            })
            .unwrap_or(false);
        if body.is_empty() && !remove {
            continue; // nothing to add and nothing to delete
        }
        updates.push(ProfileUpdate { target, key, body, remove });
    }
    updates
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
    fn combined_learning_reply_splits_into_the_three_parsers() {
        let reply = r#"Here you go:
{"lessons": [{"cue": "cargo tests", "lesson": "use --workspace", "evidence": "step 4", "confidence": 0.8}],
 "profile": [{"target": "env", "key": "Build", "body": "cargo build -p x"}],
 "skill": {"name": "Release Checklist", "description": "when cutting a release", "body": "1. test"}}"#;
        let learned = parse_proposed_learning(reply, &[]);
        assert_eq!(learned.lessons.len(), 1);
        assert_eq!(learned.lessons[0].id, "cargo-tests");
        assert_eq!(learned.profile, vec![ProfileUpdate { target: ProfileTarget::Env, key: "Build".into(), body: "cargo build -p x".into(), remove: false }]);
        assert_eq!(learned.skill.expect("skill").name, "release-checklist");

        let nothing = parse_proposed_learning(r#"{"lessons": [], "profile": [], "skill": null}"#, &[]);
        assert_eq!(nothing, Learning::default());
        assert_eq!(parse_proposed_learning("not json", &[]), Learning::default());
        // A malformed part does not take the others down with it.
        let partial = parse_proposed_learning(r#"{"lessons": "oops", "profile": [{"target": "user", "key": "Tone", "body": "terse"}], "skill": null}"#, &[]);
        assert!(partial.lessons.is_empty());
        assert_eq!(partial.profile.len(), 1);
    }

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

    #[test]
    fn profile_updates_route_to_the_right_surface() {
        let reply = r#"Here you go:
        [
            {"target": "user", "key": "Communication", "body": "Prefers terse answers."},
            {"target": "env", "key": "Build", "body": "Use cargo test --workspace."}
        ]"#;
        let updates = parse_proposed_profile(reply);
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].target, ProfileTarget::User);
        assert_eq!(updates[0].key, "Communication");
        assert_eq!(updates[0].body, "Prefers terse answers.");
        assert!(!updates[0].remove);
        assert_eq!(updates[1].target, ProfileTarget::Env);
        assert_eq!(updates[1].key, "Build");
    }

    #[test]
    fn profile_updates_honour_remove_and_drop_bad_items() {
        let reply = r#"[
            {"target": "user", "key": "Old", "body": "", "remove": true},
            {"target": "env", "key": "", "body": "x"},
            {"target": "other", "key": "K", "body": "x"},
            {"target": "user", "key": "Empty", "body": ""}
        ]"#;
        let updates = parse_proposed_profile(reply);
        assert_eq!(updates.len(), 1, "only the well-formed delete survives");
        assert_eq!(updates[0].target, ProfileTarget::User);
        assert_eq!(updates[0].key, "Old");
        assert!(updates[0].remove);
    }

    #[test]
    fn profile_updates_from_non_json_are_empty() {
        assert!(parse_proposed_profile("no json here").is_empty());
        assert!(parse_proposed_profile("[not, valid, json").is_empty());
        assert!(parse_proposed_profile("[]").is_empty());
    }
}
