//! `ark moa …` and the `/moa` chat command (Hermes `hermes moa list|configure|delete`,
//! `hermes_cli/moa_cmd.py`, `/moa <prompt>` in `hermes_cli/commands.py`).
//!
//! Presets live in `<config>/moa.toml` (`ark_kernel::moa`), layered over `[moa]` in
//! config.toml. A preset names the reference (advisor) models and the aggregator that
//! actually acts; `/moa <prompt>` asks every advisor in parallel, feeds their advice to
//! the aggregator as private context, runs one turn and restores the session's model.

use super::{one_line, sid, text};
use crate::args::Args;
use crate::slash::{Ctx, Reply};
use ark_kernel::config::{Config, Paths};
use ark_kernel::kernel::RunOpts;
use ark_kernel::moa::{self, Preset, DEFAULT_PRESET};

/// `ark moa list|configure|delete|rm|default|show`.
pub fn cli(a: &Args, paths: &Paths, cfg: &Config) -> Result<String, String> {
    let eff = moa::effective(&cfg.moa, paths);
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => Ok(list(&eff, a.flag("json"))),
        "show" => {
            let name = a.need(1, "preset")?;
            let p = eff.presets.get(name).ok_or_else(|| format!("no MoA preset `{name}` (create it with `ark moa configure {name} --references a/x,b/y --aggregator c/z`)"))?;
            Ok(format!("{name}{}\n{}", if eff.default_preset == name { " (default)" } else { "" }, preset_text(name, p)))
        }
        "configure" | "config" | "set" => {
            let name = a.pos(1).map(String::from).unwrap_or_else(|| eff.default_preset.clone());
            // Updating an existing preset keeps what was not given; creating one needs both slots
            // (there is no interactive picker in a non-tty CLI).
            let base = eff.presets.get(&name).cloned().unwrap_or(Preset { reference_models: Vec::new(), aggregator: String::new(), reference_reasoning: String::new() });
            let references: Vec<String> = match a.val("references") {
                Some(v) => v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                None if base.reference_models.is_empty() => return Err("configure needs --references a/model,b/model (one or more advisor models; prefix ! to disable one)".into()),
                None => base.reference_models.clone(),
            };
            let aggregator = a.val("aggregator").map(String::from).unwrap_or_else(|| base.aggregator.clone());
            if aggregator.trim().is_empty() {
                return Err("configure needs --aggregator provider/model (the model that acts on the advice)".into());
            }
            let p = Preset { reference_models: references, aggregator, reference_reasoning: a.val("reasoning").or(a.val("ref-reasoning")).unwrap_or(&base.reference_reasoning).to_string() };
            moa::save_preset(paths, &name, p.clone())?;
            let mut out = format!("saved MoA preset `{name}`\n{}", preset_text(&name, &p));
            if a.flag("default") {
                moa::set_default(paths, &name, &cfg.moa)?;
                out.push_str(&format!("\nMoA default preset → {name}"));
            }
            out.push_str(&format!("\nconfig: {}", moa::moa_file(paths).display()));
            Ok(out)
        }
        "default" => {
            let name = a.need(1, "preset")?;
            moa::set_default(paths, name, &cfg.moa)?;
            Ok(format!("MoA default preset → {name}"))
        }
        "delete" | "rm" => {
            let name = a.need(1, "preset")?;
            if name == DEFAULT_PRESET {
                return Err(format!("`{DEFAULT_PRESET}` is the built-in preset and cannot be deleted (configure it instead)"));
            }
            moa::delete_preset(paths, name)?;
            Ok(format!("deleted MoA preset `{name}`"))
        }
        other => Err(format!("unknown `moa {other}` (list | configure [name] --references a/x,b/y --aggregator c/z | default <name> | delete <name> | show <name>)")),
    }
}

fn list(eff: &ark_kernel::moa::MoaConfig, json: bool) -> String {
    if json {
        return serde_json::to_string_pretty(&serde_json::json!({"default": eff.default_preset, "presets": eff.presets, "reference_timeout_secs": eff.reference_timeout_secs, "privacy_filter": eff.privacy_filter})).unwrap_or_default();
    }
    let mut lines = vec![format!("Mixture of Agents — default preset: {}", eff.default_preset), String::new()];
    for (name, p) in &eff.presets {
        lines.push(format!("{name}{}", if *name == eff.default_preset { " (default)" } else { "" }));
        for l in preset_text(name, p).lines().skip(1) {
            lines.push(format!("  {l}"));
        }
    }
    lines.push(String::new());
    lines.push("Use it with `/moa <prompt>` in chat (the default preset) or `/moa <preset>: <prompt>`.".into());
    lines.join("\n")
}

fn preset_text(name: &str, p: &Preset) -> String {
    let refs: Vec<String> = p.reference_models.iter().map(|m| if let Some(m) = m.strip_prefix('!') { format!("{m} (off)") } else { m.clone() }).collect();
    let mut out = format!("{name}\n  references: {}\n  aggregator: {}", refs.join(", "), p.aggregator);
    if !p.reference_reasoning.is_empty() {
        out.push_str(&format!("\n  reference reasoning: {}", p.reference_reasoning));
    }
    out
}

/// `/moa [preset:] <prompt>` — advise with the preset's references, then act with the
/// aggregator. The session's model is restored afterwards (`Runtime::moa_turn`).
pub fn cmd_moa(c: &Ctx, a: &str) -> Result<Reply, String> {
    let id = sid(c)?;
    let arg = a.trim();
    if arg.is_empty() {
        let eff = moa::effective(&c.k.cfg_now().moa, &c.k.paths);
        return text(format!("usage: /moa [preset:] <prompt> — advise with {} and act with its aggregator\n{}", eff.default_preset, list(&eff, false)));
    }
    // `preset: prompt` picks a preset; anything else is part of the prompt.
    let (preset, prompt) = match arg.split_once(':') {
        Some((p, rest)) if !p.contains(char::is_whitespace) && !p.is_empty() && moa::effective(&c.k.cfg_now().moa, &c.k.paths).presets.contains_key(p) => (Some(p.to_string()), rest.trim().to_string()),
        _ => (None, arg.to_string()),
    };
    if prompt.is_empty() {
        return Err("usage: /moa [preset:] <prompt>".into());
    }
    let cancel = ark_core::Cancel::new();
    let (o, advice) = c.k.moa_turn(id, &prompt, preset.as_deref(), RunOpts { cancel: Some(cancel), ..Default::default() }).map_err(|e| e.to_string())?;
    let ok = advice.iter().filter(|a| a.ok).count();
    let models: Vec<String> = advice.iter().map(|a| format!("{} ({})", a.model, if a.ok { format!("{}s", a.secs) } else { "failed".into() })).collect();
    let head = format!("moa: {ok}/{} advisor(s): {}", advice.len(), models.join(", "));
    Ok(Reply { text: Some(format!("{head}\n\n{}", one_line(&o.text, 4000))), prompt: None, action: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::kit;

    fn cfg() -> Config {
        Config::default()
    }

    fn a(v: &[&str]) -> Args {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn list_configure_default_delete_roundtrip() {
        let r = ark_core::tmp::scratch_path(format!("ark-moa-cli-{}", ark_kernel::util::random_hex(8)));
        let paths = Paths { data: r.join("d"), config_dir: r.join("c"), runtime: r.join("r") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let c = cfg();
        // The built-in preset is always listed.
        let out = cli(&a(&["list"]), &paths, &c).unwrap();
        assert!(out.contains("default preset: default") && out.contains("reference"), "{out}");
        assert!(cli(&a(&["configure", "fast"]), &paths, &c).unwrap_err().contains("--references"));
        let out = cli(&a(&["configure", "fast", "--references", "a/x,!b/y", "--aggregator", "c/z", "--default"]), &paths, &c).unwrap();
        assert!(out.contains("saved MoA preset `fast`") && out.contains("b/y (off)") && out.contains("default preset → fast"), "{out}");
        let eff = moa::effective(&c.moa, &paths);
        assert_eq!(eff.default_preset, "fast");
        assert!(cli(&a(&["show", "fast"]), &paths, &c).unwrap().contains("aggregator: c/z"));
        assert!(cli(&a(&["default", "ghost"]), &paths, &c).unwrap_err().contains("ghost"));
        assert!(cli(&a(&["delete", "default"]), &paths, &c).unwrap_err().contains("built-in"));
        assert!(cli(&a(&["delete", "fast"]), &paths, &c).unwrap().contains("deleted"));
        assert!(cli(&a(&["nope"]), &paths, &c).unwrap_err().contains("unknown `moa nope`"));
    }

    #[test]
    fn slash_usage_and_a_real_moa_turn_restores_the_model() {
        let t = kit();
        let no_session = crate::slash::Ctx { k: &t.k, ext: None, session: None, workspace: t.ws.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        assert!(cmd_moa(&no_session, "hi").is_err(), "a chat command needs a session");
        let id = t.k.create_session(&t.ws, Some("echo/m"), None, Some("moa")).unwrap();
        let c = crate::slash::Ctx { k: &t.k, ext: None, session: Some(id.clone()), workspace: t.ws.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        assert!(cmd_moa(&c, "").unwrap().text.unwrap().contains("usage: /moa [preset:] <prompt>"));
        assert!(cmd_moa(&c, "   ").unwrap().text.unwrap().contains("usage: /moa [preset:] <prompt>"), "blank prompt explains itself");
        // A real turn: both advisors answer (the testkit provider answers for any model), the
        // aggregator acts, and the session's own model is restored afterwards.
        let text = cmd_moa(&c, "explain the design").unwrap().text.unwrap();
        assert!(text.contains("moa: 2/2 advisor(s)"), "{text}");
        let v = ark_kernel::projection::project(&t.k.store.read(&id).unwrap());
        assert_eq!(v.model, "echo/m", "session model restored after the MoA turn");
        assert!(v.messages.iter().any(|m| m.text().contains("[Mixture of Agents reference context]") && m.text().contains("explain the design")), "advice rides along as private context");
        assert!(v.messages.iter().any(|m| m.role == ark_core::Role::Assistant && m.text().contains("reply:")), "the aggregator answered");
        // A `preset:` prefix that names a saved preset selects it; the turn then runs that
        // preset's advisors (here: one) instead of the default two.
        let r = ark_core::tmp::scratch_path(format!("ark-moa-slash-{}", ark_kernel::util::random_hex(8)));
        let paths = Paths { data: r.join("d"), config_dir: r.join("c"), runtime: r.join("r") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        moa::save_preset(&paths, "one", Preset { reference_models: vec!["a/x".into()], aggregator: "b/y".into(), reference_reasoning: String::new() }).unwrap();
        assert!(cli(&a(&["show", "one"]), &paths, &cfg()).unwrap().contains("aggregator: b/y"));
    }
}
