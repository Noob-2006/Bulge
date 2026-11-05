//! Mixture of Agents (Hermes agent/moa_loop.py, hermes_cli/moa_config.py,
//! moa_cmd.py): for one prompt, several reference models advise in parallel
//! (no tools, they cannot act); the aggregator then runs the normal tool loop
//! as the acting model with their advice as private context, and the session's
//! model is restored afterwards.
//!
//! Presets come from `[moa]` in config.toml and `<config>/moa.toml` (managed by
//! `ark moa set|delete|default`; it wins on conflicts).

use crate::config::Paths;
use crate::context::split_model;
use crate::kernel::{KernelError, Outcome, RunOpts, Runtime};
use crate::projection::project;
use ark_core::{Cancel, Message, ModelRequest, SystemSegment};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DEFAULT_PRESET: &str = "default";

/// One `[moa.presets.<name>]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Preset {
    /// Advisors, `provider/model`; a leading `!` disables one without removing it.
    pub reference_models: Vec<String>,
    /// The acting model (runs every tool step, carries most of the cost).
    pub aggregator: String,
    /// Reasoning effort for the advisors ("" = provider default).
    pub reference_reasoning: String,
}

impl Default for Preset {
    fn default() -> Self {
        Preset { reference_models: vec!["openai/gpt-5.5".into(), "openrouter/deepseek/deepseek-v4-pro".into()], aggregator: "openrouter/anthropic/claude-opus-4.8".into(), reference_reasoning: String::new() }
    }
}

/// `[moa]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MoaConfig {
    pub default_preset: String,
    pub presets: BTreeMap<String, Preset>,
    /// Advisor timeout in seconds; 0 = none (long-thinking advisors legitimately take minutes).
    pub reference_timeout_secs: u64,
    /// "" (off), "display" (redact UI/trace copies) or "full" (also redact advice given to the aggregator).
    pub privacy_filter: String,
    /// Transcript characters shown to each advisor.
    pub reference_context_chars: usize,
}

impl Default for MoaConfig {
    fn default() -> Self {
        MoaConfig { default_preset: DEFAULT_PRESET.into(), presets: BTreeMap::new(), reference_timeout_secs: 0, privacy_filter: String::new(), reference_context_chars: 60_000 }
    }
}

const REFERENCE_SYSTEM: &str = "You are a reference advisor in a Mixture of Agents (MoA) process. You are NOT the acting agent and you do NOT execute anything: you cannot call tools, run commands, browse, or access files, repositories, or URLs, and you should not try to or apologize for being unable to. A separate aggregator/orchestrator model holds those capabilities and will take the actual actions.\n\nCRITICAL: You must NEVER claim or imply that you have executed a command, downloaded a file, accessed a URL, or performed any action. You can only analyze and advise based on the conversation context.\n- Bad: \"I ran curl and got 404.\"\n- Good: \"Based on the error pattern, a curl request to that URL would likely return 404.\"\n\nThe conversation below is the current state of a task handled by that acting agent. Your job is to give your most intelligent analysis of that state: understand the goal, reason about the problem, and advise on what to do next. Surface the best approach, concrete next steps and tool-use strategy, likely pitfalls and risks, and anything the acting agent may have missed or gotten wrong. Assume any referenced files, URLs, or systems exist and reason about them from the context given rather than asking for access.\n\nRespond with your advice directly — no preamble, no disclaimers about tools or access. Advise in prose: never emit a tool call or a JSON tool-call object. Your response is private guidance handed to the aggregator, not an answer shown to the user. NEVER claim to have executed anything.";

pub fn moa_file(paths: &Paths) -> std::path::PathBuf {
    paths.config_dir.join("moa.toml")
}

/// Effective config: `[moa]` with `moa.toml` on top; a missing default preset is Hermes's.
pub fn effective(cfg: &MoaConfig, paths: &Paths) -> MoaConfig {
    let mut c = cfg.clone();
    if let Ok(t) = std::fs::read_to_string(moa_file(paths)) {
        if let Ok(f) = toml::from_str::<MoaConfig>(&t) {
            c.presets.extend(f.presets);
            if f.default_preset != DEFAULT_PRESET {
                c.default_preset = f.default_preset;
            }
        }
    }
    c.presets.entry(DEFAULT_PRESET.into()).or_default();
    c
}

/// Validate a preset before saving (read time stays tolerant, write time is strict).
pub fn validate(p: &Preset) -> Result<(), String> {
    let enabled: Vec<&String> = p.reference_models.iter().filter(|m| !m.starts_with('!')).collect();
    if enabled.is_empty() {
        return Err("a preset needs at least one enabled reference model".into());
    }
    for m in p.reference_models.iter().map(|m| m.trim_start_matches('!')).chain(std::iter::once(p.aggregator.as_str())) {
        if !m.contains('/') {
            return Err(format!("model `{m}` must be provider/model"));
        }
        if m.starts_with("moa/") {
            return Err("the Mixture of Agents provider cannot be used inside a preset (recursive MoA)".into());
        }
    }
    if !p.reference_reasoning.is_empty() && !matches!(p.reference_reasoning.as_str(), "off" | "low" | "medium" | "high") {
        return Err("reference_reasoning: use off, low, medium or high".into());
    }
    Ok(())
}

fn read_file(paths: &Paths) -> MoaConfig {
    std::fs::read_to_string(moa_file(paths)).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
}

fn write_file(paths: &Paths, c: &MoaConfig) -> Result<(), String> {
    let text = format!("# Managed by `ark moa` — Mixture of Agents presets.\n{}", toml::to_string_pretty(c).map_err(|e| e.to_string())?);
    crate::util::atomic_write(&moa_file(paths), text.as_bytes()).map_err(|e| e.to_string())
}

pub fn save_preset(paths: &Paths, name: &str, p: Preset) -> Result<(), String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)) {
        return Err(format!("bad preset name `{name}`"));
    }
    validate(&p)?;
    let mut c = read_file(paths);
    c.presets.insert(name.into(), p);
    write_file(paths, &c)
}

pub fn delete_preset(paths: &Paths, name: &str) -> Result<(), String> {
    let mut c = read_file(paths);
    if c.presets.remove(name).is_none() {
        return Err(format!("preset `{name}` is not in {}", moa_file(paths).display()));
    }
    if c.default_preset == name {
        c.default_preset = DEFAULT_PRESET.into();
    }
    write_file(paths, &c)
}

pub fn set_default(paths: &Paths, name: &str, cfg: &MoaConfig) -> Result<(), String> {
    if !effective(cfg, paths).presets.contains_key(name) {
        return Err(format!("no preset `{name}`"));
    }
    let mut c = read_file(paths);
    c.default_preset = name.into();
    write_file(paths, &c)
}

/// Mask emails and delimited phone numbers (privacy filter).
pub fn redact_pii(s: &str) -> String {
    let email = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap();
    let phone = regex::Regex::new(r"(?:\+?\d{1,3}[ .-])?\(?\d{2,4}\)?[ .-]\d{3,4}[ .-]\d{3,4}\b").unwrap();
    phone.replace_all(&email.replace_all(s, "[email]"), "[phone]").to_string()
}

pub struct Advice {
    pub model: String,
    pub text: String,
    pub ok: bool,
    pub secs: f64,
}

impl Runtime {
    /// Ask every enabled advisor in parallel. Never fails: a failed advisor is a labelled note.
    pub fn moa_references(&self, preset: &Preset, conversation: &[Message], prompt: &str, cancel: &Cancel) -> Vec<Advice> {
        let mc = effective(&self.cfg.moa, &self.paths);
        let transcript = crate::compaction::render_transcript(conversation, 4000);
        let tail: String = {
            let n = transcript.chars().count();
            transcript.chars().skip(n.saturating_sub(mc.reference_context_chars)).collect()
        };
        let user = format!("Conversation so far:\n{tail}\n\nThe user's new request:\n{prompt}");
        let deadline = (mc.reference_timeout_secs > 0).then(|| Instant::now() + Duration::from_secs(mc.reference_timeout_secs));
        let refs: Vec<String> = preset.reference_models.iter().filter(|m| !m.starts_with('!')).cloned().collect();
        std::thread::scope(|s| {
            let hs: Vec<_> = refs
                .iter()
                .map(|m| {
                    let (user, c) = (user.clone(), match deadline { Some(d) => cancel.with_deadline(d), None => cancel.child() });
                    s.spawn(move || {
                        let t = Instant::now();
                        let (pid, name) = split_model(m);
                        let r = self.resolver.provider(pid).and_then(|p| {
                            let req = ModelRequest { model: name.into(), system: vec![SystemSegment { id: "moa-reference".into(), text: REFERENCE_SYSTEM.into(), cache: false }], messages: vec![Message::user(user)], tools: vec![], max_tokens: self.cfg.model.max_tokens, temperature: None, cache_after_message: None, reasoning: Some(preset.reference_reasoning.clone()).filter(|r| !r.is_empty()), options: Default::default() };
                            p.complete(&req, &mut |_| {}, &c).map(|r| r.message.text()).map_err(|e| if c.timed_out() { "timed out".into() } else { e.to_string() })
                        });
                        let secs = (t.elapsed().as_secs_f64() * 10.0).round() / 10.0;
                        match r {
                            Ok(text) if !text.trim().is_empty() => Advice { model: m.clone(), text: self.vault.redact(&text), ok: true, secs },
                            Ok(_) => Advice { model: m.clone(), text: "[failed: empty response]".into(), ok: false, secs },
                            Err(e) => Advice { model: m.clone(), text: format!("[failed: {e}]"), ok: false, secs },
                        }
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap_or(Advice { model: String::new(), text: "[failed: panicked]".into(), ok: false, secs: 0.0 })).collect()
        })
    }

    /// One `/moa` turn on `session`: advise, act with the aggregator, restore the model.
    pub fn moa_turn(self: &Arc<Self>, session: &str, prompt: &str, preset_name: Option<&str>, opts: RunOpts) -> Result<(Outcome, Vec<Advice>), KernelError> {
        if prompt.trim().is_empty() {
            return Err(KernelError::Invalid("usage: /moa <prompt>".into()));
        }
        if self.is_running(session) {
            return Err(KernelError::AlreadyRunning(session.into()));
        }
        let mc = effective(&self.cfg.moa, &self.paths);
        let name = preset_name.filter(|n| !n.is_empty()).unwrap_or(&mc.default_preset).to_string();
        let preset = mc.presets.get(&name).cloned().ok_or_else(|| KernelError::Invalid(format!("no MoA preset `{name}` (ark moa list)")))?;
        validate(&preset).map_err(KernelError::Invalid)?;
        let view = project(&self.store.read(session)?);
        let cancel = opts.cancel.clone().unwrap_or_default();
        let advice = self.moa_references(&preset, &view.messages, prompt, &cancel);
        let ok: Vec<&Advice> = advice.iter().filter(|a| a.ok).collect();
        let full = mc.privacy_filter == "full";
        let joined: Vec<String> = advice.iter().map(|a| format!("### Reference: {}\n{}", a.model, if full { redact_pii(&a.text) } else { a.text.clone() })).collect();
        let context = if ok.is_empty() {
            format!("[Mixture of Agents context — all reference models failed. Proceeding without aggregated guidance.]\nReferences: {}\n\n{}", advice.iter().map(|a| a.model.as_str()).collect::<Vec<_>>().join(", "), joined.join("\n\n"))
        } else {
            format!("[Mixture of Agents reference context]\nPreset: {name}\nAggregator/acting model: {}\nReferences: {}\n\nUse the reference responses below as private context. You are the aggregator and acting model: answer the user directly or call tools as needed.\n\n{}", preset.aggregator, ok.iter().map(|a| a.model.as_str()).collect::<Vec<_>>().join(", "), joined.join("\n\n"))
        };
        let before = view.model.clone();
        self.set_model(session, &preset.aggregator)?;
        let r = self.submit(session, &format!("{prompt}\n\n{context}"), "cli").and_then(|_| self.run(session, opts));
        // Restore the model even when the run failed.
        let restored = self.set_model(session, &before);
        let o = r?;
        restored?;
        Ok((o, advice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_validate_save_and_merge() {
        let r = ark_core::tmp::scratch_path(format!("ark-moa-{}", crate::util::random_hex(8)));
        let paths = Paths { data: r.join("d"), config_dir: r.join("c"), runtime: r.join("r") };
        let cfg = MoaConfig::default();
        let e = effective(&cfg, &paths);
        assert!(e.presets.contains_key(DEFAULT_PRESET) && e.presets[DEFAULT_PRESET].reference_models.len() == 2);
        let p = Preset { reference_models: vec!["a/x".into(), "!b/y".into()], aggregator: "c/z".into(), reference_reasoning: String::new() };
        save_preset(&paths, "fast", p.clone()).unwrap();
        assert!(save_preset(&paths, "bad", Preset { reference_models: vec!["!a/x".into()], ..p.clone() }).unwrap_err().contains("at least one"));
        assert!(save_preset(&paths, "bad", Preset { aggregator: "moa/x".into(), ..p.clone() }).unwrap_err().contains("recursive"));
        assert!(save_preset(&paths, "bad", Preset { aggregator: "noslash".into(), ..p.clone() }).is_err());
        assert!(save_preset(&paths, "b a d", p.clone()).is_err());
        set_default(&paths, "fast", &cfg).unwrap();
        assert!(set_default(&paths, "ghost", &cfg).is_err());
        let e = effective(&cfg, &paths);
        assert_eq!(e.default_preset, "fast");
        assert_eq!(e.presets["fast"], p);
        delete_preset(&paths, "fast").unwrap();
        assert_eq!(effective(&cfg, &paths).default_preset, DEFAULT_PRESET);
        assert!(delete_preset(&paths, "fast").is_err());
    }

    #[test]
    fn pii_filter() {
        let s = redact_pii("mail amy@example.com or call +1 415-555-0100; build 1.2.3 at 10:30 sha deadbeef");
        assert!(s.contains("[email]") && s.contains("[phone]") && s.contains("1.2.3") && s.contains("10:30"), "{s}");
    }
}
