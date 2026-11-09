//! User command providers.
//!
//! Hermes `type: command` (`[media.tts.providers.<name>]`): a shell template with
//! quote-aware `{input_path}` / `{text_path}` / `{output_path}` / `{format}` /
//! `{voice}` / `{model}` / `{speed}` placeholders (`{{`/`}}` stay literal), run with a
//! credential-free environment plus `env_passthrough`; keys `command`, `format` (mp3),
//! `timeout` (120 s), `voice_compatible` (false), `max_text_length` (5000), `voice`,
//! `model`, `speed`, `env_passthrough = []`.
//!
//! OpenClaw `tts-local-cli` (`[media.tts.tts-local-cli]`): `command`, `args = []`,
//! `output_format` (mp3|opus|wav), `timeout_ms` (120000), `cwd`, `env = {}`; argv (no
//! shell) with `{{Text}}` `{{OutputPath}}` `{{OutputDir}}` `{{OutputBase}}`; the text
//! goes to stdin unless an argument uses `{{Text}}`; audio comes from a file the CLI
//! wrote in its temp dir or from stdout.

use super::{opt, speech, Speech, TtsProvider, TtsRequest};
use crate::{proc, Media};
use seagent_core::Cancel;
use std::path::Path;
use std::time::Duration;

const FORMATS: &[&str] = &["mp3", "wav", "ogg", "flac", "m4a", "aac", "amr", "opus"];
/// Environment a command provider sees (secrets are not inherited).
const SAFE_ENV: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "TERM", "TMPDIR", "TZ", "DISPLAY", "WAYLAND_DISPLAY", "PULSE_SERVER", "PULSE_RUNTIME_PATH", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"];

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

/// Hermes `render_command_template`.
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::new();
    let mut i = 0;
    let bytes = template.as_bytes();
    'outer: while i < template.len() {
        if bytes[i] == b'{' && (i == 0 || bytes[i - 1] != b'$') {
            for (name, val) in vars {
                let double = format!("{{{{{name}}}}}");
                let single = format!("{{{name}}}");
                for pat in [&double, &single] {
                    if template[i..].starts_with(pat.as_str()) {
                        out.push_str(&quote_for(val, quote_context(template, i)));
                        i += pat.len();
                        continue 'outer;
                    }
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

fn mime_of(fmt: &str) -> &'static str {
    match fmt {
        "opus" | "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "amr" => "audio/amr",
        _ => "audio/mpeg",
    }
}

fn clean_env(passthrough: &[String]) -> Vec<String> {
    let mut v = vec!["env".to_string(), "-i".into()];
    for k in SAFE_ENV.iter().map(|s| s.to_string()).chain(passthrough.iter().cloned()) {
        if let Ok(val) = std::env::var(&k) {
            v.push(format!("{k}={val}"));
        }
    }
    v
}

/// A Hermes `type: command` provider from `[media.tts.providers.<name>]`.
pub struct Command {
    name: String,
    t: toml::Table,
}

impl Command {
    pub fn from_config(m: &Media, name: &str) -> Option<Command> {
        if super::BUILTIN.contains(&name) {
            return None;
        }
        let t = m.cfg.table(&format!("tts.providers.{name}"));
        let ty = t.get("type").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();
        let has = t.get("command").and_then(|v| v.as_str()).is_some_and(|c| !c.trim().is_empty());
        ((ty.is_empty() || ty == "command") && has).then(|| Command { name: name.into(), t })
    }
    fn s(&self, k: &str) -> Option<String> {
        self.t.get(k).map(|v| match v {
            toml::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }
    fn format(&self) -> String {
        let f = self.s("format").or_else(|| self.s("output_format")).unwrap_or_else(|| "mp3".into()).to_ascii_lowercase();
        let f = f.trim_start_matches('.').to_string();
        if FORMATS.contains(&f.as_str()) {
            f
        } else {
            "mp3".into()
        }
    }
}

impl TtsProvider for Command {
    fn id(&self) -> &str {
        &self.name
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn command(&self) -> bool {
        true
    }
    fn voice_compatible(&self, _m: &Media) -> bool {
        self.t.get("voice_compatible").map(|v| matches!(v, toml::Value::Boolean(true)) || v.as_str().is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))).unwrap_or(false)
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<Speech, String> {
        let template = self.s("command").unwrap_or_default();
        // A unique per-call directory (Hermes `tempfile.mkdtemp`): two syntheses can start in
        // the same millisecond and neither may remove the other's files. It holds the user's
        // text, so it is created owner-only (0700).
        let dir = crate::store::temp_dir("tts-cmd")?;
        let fmt = self.format();
        let input = dir.join("input.txt");
        let output = dir.join(format!("speech.{fmt}"));
        std::fs::write(&input, &req.text).map_err(|e| e.to_string())?;
        let speed = req.speed.map(|s| s.to_string()).or_else(|| self.s("speed")).or_else(|| m.cfg.get("tts.speed").map(|v| v.to_string())).unwrap_or_default();
        let (inp, outp) = (input.display().to_string(), output.display().to_string());
        let voice = req.voice.clone().or_else(|| self.s("voice")).unwrap_or_default();
        let model = req.model.clone().or_else(|| self.s("model")).unwrap_or_default();
        let line = render(&template, &[("input_path", &inp), ("text_path", &inp), ("output_path", &outp), ("format", &fmt), ("voice", &voice), ("model", &model), ("speed", &speed)]);
        let timeout = self.t.get("timeout").or_else(|| self.t.get("timeout_seconds")).and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64))).filter(|t| *t > 0.0).unwrap_or(120.0);
        let pass: Vec<String> = self.t.get("env_passthrough").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
        let mut argv = clean_env(&pass);
        argv.extend(crate::proc::shell_argv(&line));
        let r = proc::run(&argv, None, Duration::from_secs_f64(timeout), cancel);
        let res = match r {
            Err(e) if e.contains("timed out") => Err(format!("TTS provider '{}' timed out after {timeout}s", self.name)),
            Err(e) => Err(e),
            Ok(o) if !o.success() => {
                let mut parts = Vec::new();
                if !o.stderr.trim().is_empty() {
                    parts.push(format!("stderr: {}", o.stderr.trim()));
                }
                let so = String::from_utf8_lossy(&o.stdout);
                if !so.trim().is_empty() {
                    parts.push(format!("stdout: {}", so.trim()));
                }
                Err(format!("TTS provider '{}' exited with code {}: {}", self.name, o.code.unwrap_or(-1), if parts.is_empty() { "no command output".into() } else { parts.join("; ") }))
            }
            Ok(_) => std::fs::read(&output).ok().filter(|b| !b.is_empty()).ok_or_else(|| format!("TTS provider '{}' produced no output at {}", self.name, output.display())),
        };
        let _ = std::fs::remove_dir_all(&dir);
        let _ = m;
        Ok(speech(super::bounded(res?, &self.name)?, mime_of(&fmt)))
    }
}

/// Split a command string into argv honouring quotes (OpenClaw `parseCommand`).
fn parse_command(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut cur, mut started, mut q) = (String::new(), false, None::<char>);
    for c in s.trim().chars() {
        match q {
            Some(qc) if c == qc => q = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                started = true;
                q = Some(c);
            }
            None if c == ' ' || c == '\t' => {
                if started {
                    parts.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            None => {
                started = true;
                cur.push(c);
            }
        }
    }
    if started {
        parts.push(cur);
    }
    parts
}

/// `{{ key }}` → context value (case-insensitive key, OpenClaw `applyTemplate`).
fn apply_template(s: &str, ctx: &[(&str, &str)]) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        match rest[i + 2..].find("}}") {
            Some(j) => {
                let key = rest[i + 2..i + 2 + j].trim();
                if key.chars().all(|c| c.is_alphanumeric() || c == '_') && !key.is_empty() {
                    out.push_str(ctx.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| *v).unwrap_or(""));
                } else {
                    out.push_str(&rest[i..i + 4 + j]);
                }
                rest = &rest[i + 4 + j..];
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Emoji / pictographs removed, whitespace collapsed (OpenClaw `stripEmojis`).
pub fn strip_emojis(t: &str) -> String {
    let s: String = t.chars().map(|c| if super::normalize::is_emoji(c) { ' ' } else { c }).collect();
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn detect(b: &[u8]) -> Option<&'static str> {
    match crate::store::sniff(b) {
        "audio/wav" => Some("audio/wav"),
        "audio/mpeg" => Some("audio/mpeg"),
        "audio/ogg" => Some("audio/ogg"),
        _ => None,
    }
}

/// OpenClaw `tts-local-cli`.
pub struct LocalCli;

impl TtsProvider for LocalCli {
    fn id(&self) -> &str {
        "tts-local-cli"
    }
    fn aliases(&self) -> &[&str] {
        &["cli"]
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn configured(&self, m: &Media) -> bool {
        opt(m, "tts-local-cli", "command").is_some()
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, cancel: &Cancel) -> Result<Speech, String> {
        let cfg = m.cfg.table("tts.tts-local-cli");
        let command = opt(m, "tts-local-cli", "command").ok_or("CLI TTS not configured")?;
        let fmt = match opt(m, "tts-local-cli", "output_format").map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("opus") => "opus",
            Some("wav") => "wav",
            _ => "mp3",
        };
        let text = strip_emojis(&req.text);
        if text.is_empty() {
            return Err("CLI TTS: text is empty after removing emojis".into());
        }
        // Unique per call and owner-only: this directory holds the spoken text (0700).
        let dir = crate::store::temp_dir("cli-tts")?;
        let out_path = dir.join(format!("speech.{fmt}"));
        // The template is often a shell line (`sh -c "… > {{OutputPath}}"`): Git Bash on Windows
        // needs `C:/…` (Windows programs accept it too). Unix: the path as is.
        let (op, od) = (seagent_core::platform::shell::path_str(&out_path), seagent_core::platform::shell::path_str(&dir));
        let ctx = [("Text", text.as_str()), ("OutputPath", op.as_str()), ("OutputDir", od.as_str()), ("OutputBase", "speech")];
        let mut base = parse_command(&command);
        if base.is_empty() {
            return Err("CLI TTS: invalid command".into());
        }
        base.extend(cfg.get("args").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect::<Vec<_>>()).unwrap_or_default());
        let uses_text = base.iter().any(|a| {
            let l = a.to_ascii_lowercase().replace(' ', "");
            l.contains("{{text}}")
        });
        let args: Vec<String> = base.iter().map(|a| apply_template(a, &ctx)).collect();
        let mut argv: Vec<String> = Vec::new();
        let env: Vec<(String, String)> = cfg.get("env").and_then(|e| e.as_table()).map(|t| t.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect()).unwrap_or_default();
        let cwd = opt(m, "tts-local-cli", "cwd");
        #[cfg(unix)]
        if let Some(cwd) = cwd.clone() {
            argv.extend(["sh".into(), "-c".into(), "cd \"$0\" && exec \"$@\"".into(), cwd]);
        }
        argv.extend(args);
        let timeout = Duration::from_millis(super::num(m, "tts-local-cli", "timeout_ms").unwrap_or(120_000.0) as u64);
        let stdin = if uses_text { None } else { Some(text.as_bytes()) };
        #[cfg(unix)]
        let r = {
            let _ = &cwd;
            proc::run_env(&argv, stdin, &env, timeout, cancel)
        };
        #[cfg(not(unix))]
        let r = proc::run_env_in(&argv, stdin, &env, cwd.as_deref().map(std::path::Path::new), timeout, cancel);
        let res = (|| {
            let o = r.map_err(|e| if e.contains("timed out") { format!("CLI TTS timed out after {}ms", timeout.as_millis()) } else { format!("CLI TTS failed: {e}") })?;
            if !o.success() {
                return Err(format!("CLI TTS exit {}: {}", o.code.unwrap_or(-1), o.stderr.trim()));
            }
            let files: Vec<_> = std::fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten().map(|e| e.path()).filter(|p| p.extension().and_then(|e| e.to_str()).is_some_and(|e| ["wav", "mp3", "opus", "ogg", "m4a"].contains(&e.to_ascii_lowercase().as_str()))).collect();
            let file = files.iter().find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.contains("speech"))).or(files.first());
            if let Some(f) = file {
                let b = std::fs::read(f).map_err(|e| e.to_string())?;
                let mime = detect(&b).or_else(|| (Path::new(f).extension().and_then(|e| e.to_str()) == Some("m4a")).then_some("audio/mp4")).ok_or_else(|| format!("CLI TTS: unknown format for {}", f.display()))?;
                return Ok((b, mime));
            }
            if !o.stdout.is_empty() {
                let mime = detect(&o.stdout).ok_or("CLI TTS stdout audio format is not recognized; emit WAV, MP3, or Ogg Opus bytes, or write a supported audio file")?;
                return Ok((o.stdout, mime));
            }
            Err("CLI TTS produced no output".into())
        })();
        let _ = std::fs::remove_dir_all(&dir);
        let (b, mime) = res?;
        Ok(speech(super::bounded(b, "CLI TTS")?, mime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_quote_aware() {
        let v = [("output_path", "/t/a b.mp3"), ("voice", "it's")];
        assert_eq!(render("tts -o {output_path} -v {voice}", &v), "tts -o '/t/a b.mp3' -v 'it'\\''s'");
        assert_eq!(render("tts -o \"{output_path}\" '{voice}'", &v), "tts -o \"/t/a b.mp3\" 'it'\\''s'");
        assert_eq!(render("echo {{voice}} ${voice} {{literal}}", &v), "echo 'it'\\''s' ${voice} {literal}");
    }

    #[test]
    fn hermes_command_provider_runs_without_secrets() {
        std::env::set_var("SEAGENT_TTS_TEST_SECRET", "s3cret");
        let m = Media {
            cfg: crate::MediaConfig::from_toml("[tts.providers.say]\ncommand = \"(cat {input_path}; env) > {output_path}\"\nformat = \"wav\"\nvoice_compatible = true\n[tts.providers.bad]\ncommand = \"echo nope >&2; exit 4\"\n[tts.providers.openai]\ncommand = \"x\""),
            http: Default::default(),
        };
        let p = super::super::find(&m, "say").unwrap();
        assert!(p.command() && p.voice_compatible(&m));
        let s = p.synthesize(&m, &TtsRequest::new("spoken words"), &Cancel::new()).unwrap();
        let out = String::from_utf8_lossy(&s.audio.bytes).to_string();
        assert!(out.starts_with("spoken words") && !out.contains("s3cret"), "{out}");
        assert_eq!(s.audio.mime, "audio/wav");
        let e = super::super::find(&m, "bad").unwrap().synthesize(&m, &TtsRequest::new("x"), &Cancel::new()).unwrap_err();
        assert!(e.contains("exited with code 4") && e.contains("stderr: nope"), "{e}");
        // Built-in names cannot be shadowed by a command block.
        assert_eq!(super::super::find(&m, "openai").unwrap().id(), "openai");
    }

    #[test]
    fn local_cli_file_and_stdout_modes() {
        let m = Media { cfg: crate::MediaConfig::from_toml("[tts.tts-local-cli]\ncommand = \"sh -c\"\nargs = [\"printf 'ID3\\\\004x' > {{OutputPath}}\"]\noutput_format = \"mp3\""), http: Default::default() };
        let s = LocalCli.synthesize(&m, &TtsRequest::new("hi 😀"), &Cancel::new()).unwrap();
        assert_eq!(s.audio.mime, "audio/mpeg");
        let m = Media { cfg: crate::MediaConfig::from_toml("[tts.tts-local-cli]\ncommand = \"sh -c 'printf RIFF0000WAVE; cat'\""), http: Default::default() };
        let s = LocalCli.synthesize(&m, &TtsRequest::new("text in"), &Cancel::new()).unwrap();
        assert!(s.audio.bytes.ends_with(b"text in"));
        assert_eq!(s.audio.mime, "audio/wav");
        let m = Media { cfg: crate::MediaConfig::from_toml("[tts.tts-local-cli]\ncommand = \"echo\""), http: Default::default() };
        assert!(LocalCli.synthesize(&m, &TtsRequest::new("x"), &Cancel::new()).unwrap_err().contains("not recognized"));
        assert_eq!(parse_command("a 'b c' \"\" d"), vec!["a", "b c", "", "d"]);
        assert_eq!(strip_emojis("hi 😀 there"), "hi there");
    }
}
