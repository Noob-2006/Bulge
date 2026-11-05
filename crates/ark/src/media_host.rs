//! ark-media host: one [`Media`] instance for the process, the kernel-backed `Llm` / `Agent`
//! implementations ark-media calls back into (image describe, PDF answers, voice turns,
//! meeting talk-back, phone conversations), the background-job completion sink and the
//! `ark infer|capability`, `ark voice`, `ark stt` and `ark transcripts` subcommands.
//!
//! Everything provider-specific lives in `crates/ark-media`; this module only hands it the
//! kernel (models, sessions, vault) and the terminal.

use ark_core::{Cancel, Message};
use ark_kernel::config::{Config, Paths};
use ark_kernel::context::split_model;
use ark_kernel::kernel::{Kernel, RunOpts};
use ark_kernel::vault::Vault;
use ark_media::{Media, MediaConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The `[media]` table with a vault-backed `{{secret:NAME}}` resolver.
pub fn media(cfg: &Config, vault: Arc<Vault>) -> Arc<Media> {
    let secret: ark_media::config::SecretFn = Arc::new(move |name: &str| {
        let s = vault.substitute(&format!("{{{{secret:{name}}}}}"));
        (!s.contains("{{secret:") && !s.is_empty()).then_some(s)
    });
    Media::new(MediaConfig::new(cfg.media.clone(), secret))
}

/// Wire ark-media into a running kernel: the model callbacks, the per-session image hooks and
/// the background-generation completion sink. Idempotent (the slots are `OnceLock`s).
pub fn install(k: &Kernel, m: &Arc<Media>) {
    ark_media::set_llm(Arc::new(KernelLlm { k: k.clone() }));
    ark_media::set_agent(Arc::new(KernelAgent { k: k.clone() }));
    ark_media::vision::install_tool_hooks(m);
    ark_core::tool::set_image_post(post_tool_images);
    let kk = k.clone();
    ark_media::genrt::set_completion_sink(Arc::new(move |c: ark_media::genrt::Completion| {
        // OpenClaw completion wake: the finished job (with its MEDIA: lines) becomes a queued
        // turn in the session that asked for it; the daemon starts it if it is idle.
        if kk.store.open(&c.session).is_err() {
            return;
        }
        let source = format!("media:{}", c.kind);
        if kk.submit(&c.session, &c.text, &source).is_ok() && !kk.is_running(&c.session) {
            let k3 = kk.clone();
            let sid = c.session.clone();
            std::thread::spawn(move || {
                let _ = k3.run(&sid, RunOpts::default());
            });
        }
    }));
}

/// `ark_core` image hook → ark-media's sanitizer (`vision::post_tool_images`).
#[allow(clippy::ptr_arg)] // the slot is typed `fn(&mut Vec<Block>) -> usize` (`tool::set_image_post`).
fn post_tool_images(blocks: &mut Vec<ark_core::Block>) -> usize {
    ark_media::vision::post_tool_images(blocks)
}

/// `Llm` over `Kernel::sample` (aux model by default; vision via provider capabilities).
struct KernelLlm {
    k: Kernel,
}

impl ark_media::Llm for KernelLlm {
    fn complete(&self, model: Option<&str>, system: &str, messages: Vec<Message>, max_tokens: u32, cancel: &Cancel) -> Result<String, String> {
        let (msg, _, _) = self.k.sample(model, system, messages, vec![], max_tokens.max(1), cancel)?;
        Ok(msg.text())
    }

    fn vision(&self, model: Option<&str>) -> bool {
        // Vision is its own auxiliary task (`[auxiliary.vision]`), not just the `aux` model.
        let m = model.filter(|m| !m.trim().is_empty()).map(|m| self.k.cfg.resolve_model(m).to_string()).unwrap_or_else(|| self.k.cfg.task_model("vision"));
        let (pid, name) = split_model(&m);
        self.k.resolver.provider(pid).is_ok_and(|p| p.caps(name).vision)
    }
}

/// `Agent` over the kernel: one turn in a (new or existing) session, returning its reply text.
struct KernelAgent {
    k: Kernel,
}

impl ark_media::Agent for KernelAgent {
    fn turn(&self, session: Option<&str>, text: &str, source: &str, cancel: &Cancel) -> Result<(String, String), String> {
        let sid = match session.map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) if self.k.store.open(s).is_ok() => s.to_string(),
            _ => {
                let ws = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                let title = match source {
                    "voice" => "voice",
                    "voice-live" => "voice (live)",
                    other => other,
                };
                self.k.create_session(&ws, None, None, Some(title)).map_err(|e| e.to_string())?
            }
        };
        self.k.submit(&sid, text, source).map_err(|e| e.to_string())?;
        let out = self.k.run(&sid, RunOpts { cancel: Some(cancel.clone()), ..Default::default() }).map_err(|e| e.to_string())?;
        Ok((sid, out.text))
    }
}

// ─────────────────────────────── CLI subcommands ───────────────────────────────

/// `ark infer|capability …`, `ark voice …`, `ark stt <file>`, `ark transcripts …`.
/// `argv` excludes the command word. Returns the process exit code.
pub fn cli(cmd: &str, argv: &[String], k: &Kernel, quiet: bool) -> Result<i32, String> {
    let m = media(&k.cfg, k.vault.clone());
    install(k, &m);
    match cmd {
        "infer" | "capability" => {
            let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
            println!("{}", ark_media::understand::cli::cli(&m, argv, &cwd)?);
            Ok(0)
        }
        "voice" => voice(argv, &m, k, quiet),
        "stt" => stt(argv, &m),
        "transcripts" => transcripts(argv, &k.paths),
        other => Err(format!("unknown media command `{other}`")),
    }
}

/// Default build (gen1-306): voice mode, the wake word and GPT-Live are personal-desktop
/// front-ends, compiled only with `--features personal`.
#[cfg(not(feature = "personal"))]
fn voice(_argv: &[String], _m: &Arc<Media>, _k: &Kernel, _quiet: bool) -> Result<i32, String> {
    Err("`ark voice` (voice mode, wake word, GPT-Live) is not part of this build: it is a personal-desktop feature — rebuild with `cargo build -p ark --features personal`. Speech in chats (TTS/STT, Discord voice) works without it.".into())
}

#[cfg(feature = "personal")]
/// `ark voice [status|live] [--continuous] [--wake] [--no-speak] [--no-barge-in] [--session ID] [--max-turns N]`
fn voice(argv: &[String], m: &Arc<Media>, k: &Kernel, quiet: bool) -> Result<i32, String> {
    let word = argv.first().map(String::as_str).unwrap_or("");
    match word {
        "status" => {
            println!("{}", serde_json::to_string_pretty(&ark_media::voice::requirements(m)).unwrap_or_default());
            Ok(0)
        }
        "live" => {
            let f = live_flags(&argv[1..])?;
            let opts = ark_media::realtime::live::LiveOpts::from_config(m).with_flags(f.provider, f.model, f.voice, f.max_seconds);
            let rep = ark_media::realtime::live::run_cli(m, &opts, &Cancel::new())?;
            if !quiet {
                println!("{}", serde_json::json!({"transcript": rep.transcript, "delegations": rep.delegations, "interruptions": rep.interruptions, "errors": rep.errors}));
            }
            Ok(0)
        }
        _ => {
            let f = voice_flags(argv)?;
            let opts = ark_media::voice::VoiceModeOpts::from_flags(m, &f);
            let sum = ark_media::voice::run_cli(m, &opts, &Cancel::new())?;
            if !quiet {
                println!(
                    "{} turn(s){}; session {}",
                    sum.turns,
                    if sum.interrupted > 0 { format!(", {} interruption(s)", sum.interrupted) } else { String::new() },
                    sum.session.as_deref().unwrap_or("(none)")
                );
            }
            let _ = k;
            Ok(0)
        }
    }
}

#[cfg(feature = "personal")]
/// Flags of `ark voice` (Hermes `voice_mode` CLI switches).
fn voice_flags(argv: &[String]) -> Result<ark_media::voice::VoiceFlags, String> {
    let mut f = ark_media::voice::VoiceFlags::default();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        i += 1;
        match a {
            "--continuous" => f.continuous = true,
            "--wake" => f.wake = true,
            "--no-speak" => f.no_speak = true,
            "--no-barge-in" => f.no_barge_in = true,
            "--session" => f.session = Some(argv.get(i).cloned().ok_or("--session needs a session id")?),
            "--max-turns" => f.max_turns = argv.get(i).and_then(|v| v.parse().ok()).ok_or("--max-turns needs a number")?,
            other => return Err(format!("unknown voice option `{other}` (--continuous, --wake, --no-speak, --no-barge-in, --session, --max-turns)")),
        }
        if matches!(a, "--session" | "--max-turns") {
            i += 1;
        }
    }
    Ok(f)
}

#[cfg(feature = "personal")]
struct LiveFlags {
    provider: Option<String>,
    model: Option<String>,
    voice: Option<String>,
    max_seconds: u32,
}

#[cfg(feature = "personal")]
fn live_flags(argv: &[String]) -> Result<LiveFlags, String> {
    let (mut p, mut mo, mut v, mut secs) = (None, None, None, 0u32);
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        i += 1;
        let val = |i: &mut usize| argv.get(*i).cloned().ok_or(format!("{a} needs a value")).inspect(|_| *i += 1);
        match a {
            "--provider" => p = Some(val(&mut i)?),
            "--model" => mo = Some(val(&mut i)?),
            "--voice" => v = Some(val(&mut i)?),
            "--max-seconds" => secs = val(&mut i)?.parse().map_err(|_| "--max-seconds needs a number".to_string())?,
            other => return Err(format!("unknown live option `{other}` (--provider, --model, --voice, --max-seconds)")),
        }
    }
    Ok(LiveFlags { provider: p, model: mo, voice: v, max_seconds: secs })
}

/// `ark stt <file> [--json]`: transcribe one audio file with the configured provider.
fn stt(argv: &[String], m: &Arc<Media>) -> Result<i32, String> {
    let json = argv.iter().any(|a| a == "--json");
    let path = argv.iter().find(|a| !a.starts_with('-')).ok_or("usage: ark stt <audio file> [--json]")?;
    let (provider, t) = ark_media::stt::transcribe_file(m, Path::new(path), &Cancel::new())?;
    if json {
        let segs: Vec<serde_json::Value> = t.segments.iter().map(|s| serde_json::json!({"start": s.start, "end": s.end, "text": s.text, "speaker": s.speaker})).collect();
        println!("{}", serde_json::json!({"provider": provider, "text": t.text, "language": t.language, "duration": t.duration, "segments": segs}));
    } else {
        println!("{provider}: {}", t.text);
    }
    Ok(0)
}

/// `ark transcripts [list]`: the local transcript store (OpenClaw `transcripts` tool).
fn transcripts(argv: &[String], paths: &Paths) -> Result<i32, String> {
    match argv.first().map(String::as_str).unwrap_or("list") {
        "list" => {
            println!("{}", serde_json::to_string_pretty(&ark_media::stt::transcripts::list_json(&paths.data)).unwrap_or_default());
            Ok(0)
        }
        other => Err(format!("unknown transcripts subcommand `{other}` (list)")),
    }
}

/// Self-registration (`ark_core::registry`): `ark infer|capability|voice|stt|transcripts …`
/// (their own flags: `--json`, `--continuous`, `--provider`).
pub fn register_route() {
    ark_core::registry::register_command_route("infer,capability,voice,stt,transcripts", None, route);
}

fn route(cmd: &str, argv: &[String]) -> Result<i32, String> {
    let a = crate::args::Args::parse(&[])?;
    let c = crate::build(&a, crate::approver_for(&a, false)).map_err(|e| e.to_string())?;
    cli(cmd, argv, &c.k, a.flag("quiet"))
}
