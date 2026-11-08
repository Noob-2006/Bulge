//! User command STT providers and plugin-registered providers (Hermes
//! `tools/transcription_command.py`).
//!
//! `[media.stt.providers.<name>]` with `command = "…"`: a shell template with the same
//! quote-aware placeholder grammar as TTS command providers — `{input_path}` (the
//! original file, or 16 kHz mono when `normalize = true`), `{output_path}`,
//! `{output_dir}`, `{format}` (txt|json|srt|vtt), `{language}` (default `en`),
//! `{model}`; the legacy `{{name}}` form and `{{`/`}}` otherwise stay literal. Keys:
//! `command`, `format`/`output_format` (txt), `timeout`/`timeout_seconds` (300 s),
//! `language`, `model`, `normalize` (false), `env_passthrough = []`. The child runs
//! with a credential-free environment. The transcript is the output file, else stdout
//! (curl one-liners).
//!
//! Resolution: built-in name (always wins) > command provider > plugin provider
//! ([`register`]) > "not registered" error.

use super::{SttProvider, SttRequest, Transcript};
use crate::{proc, Media};
use seagent_core::Cancel;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Environment a command provider sees (secrets are not inherited).
const SAFE_ENV: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TERM", "TMPDIR", "TZ", "PULSE_SERVER", "PULSE_RUNTIME_PATH", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"];
pub const FORMATS: &[&str] = &["txt", "json", "srt", "vtt"];

/// `env -i SAFE…` prefix (plus `passthrough` names) for a credential-free child.
pub(crate) fn clean_env(passthrough: &[String]) -> Vec<String> {
    let mut v = vec!["env".to_string(), "-i".into()];
    for k in SAFE_ENV.iter().map(|s| s.to_string()).chain(passthrough.iter().cloned()) {
        if let Ok(val) = std::env::var(&k) {
            v.push(format!("{k}={val}"));
        }
    }
    v
}

/// The quote character open right before byte `pos` of a shell template.
fn quote_context(t: &str, pos: usize) -> Option<char> {
    let mut q: Option<char> = None;
    let mut esc = false;
    let b: Vec<char> = t[..pos].chars().collect();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match q {
            Some('\'') => {
                if c == '\'' {
                    q = None;
                }
            }
            Some('"') => {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    q = None;
                }
            }
            _ => {
                if c == '\'' || c == '"' {
                    q = Some(c);
                } else if c == '\\' {
                    i += 1;
                }
            }
        }
        i += 1;
    }
    q
}

fn quote_for(v: &str, ctx: Option<char>) -> String {
    match ctx {
        Some('\'') => v.replace('\'', "'\\''"),
        Some('"') => v.replace('\\', "\\\\").replace('"', "\\\"").replace('$', "\\$").replace('`', "\\`"),
        _ => format!("'{}'", v.replace('\'', "'\\''")),
    }
}

/// Hermes `render_command_template`: each `{name}` (and the legacy `{{name}}` form) is quoted
/// for the shell context it sits in; a `{{`/`}}` that does not wrap a known name stays literal.
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::new();
    let mut i = 0;
    let bytes = template.as_bytes();
    'outer: while i < template.len() {
        if bytes[i] == b'{' && (i == 0 || bytes[i - 1] != b'$') {
            for (name, val) in vars {
                let double = format!("{{{{{name}}}}}");
                let single = format!("{{{name}}}");
                if template[i..].starts_with(double.as_str()) {
                    out.push_str(&quote_for(val, quote_context(template, i)));
                    i += double.len();
                    continue 'outer;
                }
                if template[i..].starts_with(single.as_str()) {
                    out.push_str(&quote_for(val, quote_context(template, i)));
                    i += single.len();
                    continue 'outer;
                }
            }
            if template[i..].starts_with("{{") {
                out.push('{');
                i += 2;
                continue;
            }
        }
        if template[i..].starts_with("}}") {
            out.push('}');
            i += 2;
            continue;
        }
        let ch = template[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// A `[media.stt.providers.<name>]` command provider.
pub struct Command {
    pub name: String,
    t: toml::Table,
}

impl Command {
    /// The provider config when `name` is a command provider (never a built-in or `none`).
    /// Hermes `_named_provider_config`: `[media.stt.providers.<name>]` (canonical), else
    /// `[media.stt.<name>]` for a non-built-in name.
    pub fn from_config(m: &Media, name: &str) -> Option<Command> {
        if super::BUILTIN.contains(&name) || name == "none" {
            return None;
        }
        let mut t = m.cfg.table(&format!("stt.providers.{name}"));
        if t.is_empty() {
            t = m.cfg.table(&format!("stt.{name}"));
        }
        let ty = t.get("type").and_then(|v| v.as_str()).map(|s| s.trim().to_ascii_lowercase()).unwrap_or_else(|| "command".into());
        let has = t.get("command").and_then(|v| v.as_str()).is_some_and(|c| !c.trim().is_empty());
        ((ty.is_empty() || ty == "command") && has).then(|| Command { name: name.to_string(), t })
    }
    fn s(&self, k: &str) -> Option<String> {
        self.t.get(k).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
    fn format(&self) -> String {
        // Hermes `_command_output_format`: `format` > `output_format`, lowercased, no leading dot.
        self.t.get("format").or_else(|| self.t.get("output_format")).and_then(|v| v.as_str()).map(|f| f.trim().to_ascii_lowercase().trim_start_matches('.').to_string()).filter(|f| FORMATS.contains(&f.as_str())).unwrap_or_else(|| "txt".into())
    }
    fn timeout(&self) -> f64 {
        self.t.get("timeout").or_else(|| self.t.get("timeout_seconds")).and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64)).or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))).filter(|t| *t > 0.0).unwrap_or(300.0)
    }
}

impl SttProvider for Command {
    fn id(&self) -> &str {
        &self.name
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn local(&self) -> bool {
        true
    }
    fn transcribe(&self, m: &Media, req: &SttRequest, cancel: &Cancel) -> Result<Transcript, String> {
        let name = &self.name;
        let template = self.s("command").ok_or_else(|| format!("stt.providers.{name}.command is not configured"))?;
        let dir = super::local::work_dir("cmdp")?;
        let r = (|| {
            let ext = crate::store::ext_for(&req.mime);
            let raw = dir.join(format!("input.{ext}"));
            std::fs::write(&raw, &req.audio).map_err(|e| e.to_string())?;
            let normalize = self.t.get("normalize").and_then(|v| v.as_bool().or_else(|| v.as_str().map(|s| matches!(s, "1" | "true" | "yes" | "on")))).unwrap_or(false);
            let input = if normalize {
                super::local::prepare_wav(req, &dir, cancel).map_err(|e| format!("stt.providers.{name}.normalize: true but the audio could not be normalized for the command provider: {e}"))?
            } else {
                raw
            };
            let fmt = self.format();
            let output = dir.join(format!("transcript.{fmt}"));
            let lang = req.language.clone().or_else(|| self.s("language")).or_else(|| super::configured_language(m, name)).unwrap_or_else(|| "en".into());
            let model = req.model.clone().or_else(|| self.s("model")).unwrap_or_default();
            let line = render(&template, &[("input_path", &input.display().to_string()), ("output_path", &output.display().to_string()), ("output_dir", &dir.display().to_string()), ("format", &fmt), ("language", &lang), ("model", &model)]);
            let pass: Vec<String> = self.t.get("env_passthrough").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
            let mut argv = clean_env(&pass);
            argv.extend(crate::proc::shell_argv(&line));
            let timeout = self.timeout();
            let o = match proc::run(&argv, None, Duration::from_secs_f64(timeout), cancel) {
                Err(e) if e.contains("timed out") => return Err(format!("STT command provider '{name}' timed out after {timeout}s")),
                Err(e) => return Err(format!("STT command provider '{name}' failed: {e}")),
                Ok(o) => o,
            };
            if !o.success() {
                // Hermes `command_failure_detail`: "stderr: …; stdout: …", or "no command output".
                let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
                let parts: Vec<String> = [("stderr", o.stderr.trim()), ("stdout", stdout.as_str())].iter().filter(|(_, t)| !t.is_empty()).map(|(n, t)| format!("{n}: {t}")).collect();
                let detail = if parts.is_empty() { "no command output".to_string() } else { parts.join("; ") };
                return Err(format!("STT command provider '{name}' exited with code {}: {detail}", o.code.unwrap_or(-1)));
            }
            let file = std::fs::read_to_string(&output).map(|s| s.trim_start_matches('\u{feff}').trim().to_string()).unwrap_or_default();
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if file.is_empty() && stdout.is_empty() {
                return Err(format!("Command STT provider wrote no output file at {} and produced no stdout", output.display()));
            }
            let text = if file.is_empty() { stdout } else { file };
            Ok(Transcript { text: if fmt == "json" { json_text(&text) } else { text }, language: Some(lang), ..Default::default() })
        })();
        let _ = std::fs::remove_dir_all(&dir);
        r
    }
}

/// JSON outputs are returned raw by Hermes; we keep the raw text unless it is a
/// `{"text": …}` object, whose text is what callers want.
fn json_text(s: &str) -> String {
    serde_json::from_str::<serde_json::Value>(s).ok().and_then(|v| v["text"].as_str().map(str::to_string)).unwrap_or_else(|| s.to_string())
}

fn registry() -> &'static Mutex<Vec<Arc<dyn SttProvider>>> {
    static R: OnceLock<Mutex<Vec<Arc<dyn SttProvider>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Register a plugin STT provider at runtime (Hermes `TranscriptionProvider`). Plugins
/// may not take a built-in name; a same-name command provider still wins.
pub fn register(p: Arc<dyn SttProvider>) -> Result<(), String> {
    if super::BUILTIN.contains(&p.id()) {
        return Err(format!("STT plugin provider name '{}' is reserved for a built-in provider", p.id()));
    }
    let mut r = registry().lock().unwrap();
    r.retain(|x| x.id() != p.id());
    r.push(p);
    Ok(())
}

pub fn registered() -> Vec<Arc<dyn SttProvider>> {
    registry().lock().unwrap().clone()
}

pub fn find_plugin(id: &str) -> Option<Arc<dyn SttProvider>> {
    registered().into_iter().find(|p| p.id() == id)
}
