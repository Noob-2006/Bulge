//! Persisted TTS / Talk preferences (OpenClaw `src/tts/tts-settings*.ts` and
//! `tts-preferences.ts`, Hermes `config.yaml` TTS keys).
//!
//! One JSON file at `[media.tts] prefs_path` (default
//! `$ARK_HOME/media/tts-prefs.json`; without `ARK_HOME`, `$XDG_DATA_HOME/ark/media/…`
//! or `~/.local/share/ark/media/…`), written atomically with mode `0600`:
//!
//! ```json
//! {"tts": {"auto": "always", "provider": "edge", "voice": "en-US-AriaNeural",
//!          "persona": null, "talkVoice": "alloy", "maxLength": 1500,
//!          "summarize": true, "speed": 1.0, "voiceMode": false, "voiceTts": true},
//!  "voiceModes": {"discord:1234": "voice_only", "telegram:42": "off"}}
//! ```
//!
//! `voiceModes` holds the per-chat `/voice` / `/tts chat` modes (Hermes `_voice_mode`).
//!
//! Unknown keys written by another tool are preserved, a missing file is the normal
//! first-run state, and an unreadable/corrupt file falls back to the configured
//! defaults instead of failing a reply (`readTtsPrefs` without `forUpdate`).

use crate::Media;
use std::io::Write;
use std::path::{Path, PathBuf};

/// OpenClaw `DEFAULT_MAX_TEXT_LENGTH` for auto replies.
pub const DEFAULT_MAX_LENGTH: usize = 1500;
/// Telegram's upload/caption ceiling: the largest `/tts limit` (OpenClaw commands-tts).
pub const MAX_LIMIT: usize = 4096;
pub const MIN_LIMIT: usize = 100;
/// Accepted `[media.tts] auto` values (OpenClaw `TtsAutoSchema`).
pub const AUTO_MODES: &[&str] = &["off", "always", "inbound", "tagged"];
/// Hermes `_VOICE_MODES`: the per-chat `/voice` modes (`off` never speaks, `voice_only`
/// speaks only replies to a voice note, `all` speaks every reply).
pub const VOICE_MODES: &[&str] = &["off", "voice_only", "all"];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Prefs {
    /// `/tts provider` choice (`None` = `[media.tts] provider`).
    pub provider: Option<String>,
    /// `/tts voice` choice (per-provider voice, overrides `[media.tts.<p>] voice`).
    pub voice: Option<String>,
    /// `/tts persona` choice (`None` = no persona).
    pub persona: Option<String>,
    /// `/voice set` choice: the Talk voice (`[media.talk] voice` when absent).
    pub talk_voice: Option<String>,
    /// off | always | inbound | tagged.
    pub auto: Option<String>,
    /// Auto-reply character limit before summary/truncation.
    pub max_length: Option<usize>,
    /// Summarize long auto replies instead of truncating.
    pub summarize: Option<bool>,
    /// Global speed multiplier (0.25–4.0).
    pub speed: Option<f32>,
    /// `/voice on|off`: CLI voice mode armed (`ark voice` starts the loop).
    pub voice_mode: Option<bool>,
    /// `/voice tts on|off`: read replies aloud.
    pub voice_tts: Option<bool>,
}

impl Prefs {
    /// Whether TTS is on for this profile (`auto != "off"`).
    pub fn enabled(&self, m: &Media) -> bool {
        effective_auto(self, m) != "off"
    }
}

/// `[media.tts] prefs_path`, else `$ARK_HOME/media/tts-prefs.json`, else the XDG data dir.
pub fn path(m: &Media) -> PathBuf {
    if let Some(p) = m.cfg.str("tts.prefs_path") {
        return ark_core::tool::expand_home(&p);
    }
    root().join("media").join("tts-prefs.json")
}

/// ark's data root for state files (`$ARK_HOME`, else XDG/HOME, else the temp dir).
pub fn root() -> PathBuf {
    if let Some(h) = std::env::var_os("ARK_HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    if let Some(d) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(d).join("ark");
    }
    if let Some(h) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h).join(".local").join("share").join("ark");
    }
    std::env::temp_dir().join("ark")
}

fn text(v: &serde_json::Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn number(v: &serde_json::Value, k: &str) -> Option<f64> {
    v.get(k).and_then(|x| x.as_f64().or_else(|| x.as_i64().map(|i| i as f64)))
}

fn boolean(v: &serde_json::Value, k: &str) -> Option<bool> {
    v.get(k).and_then(|x| x.as_bool())
}

/// Parse a preferences document (the `tts` object, or a flat object as a fallback).
pub fn parse(body: &str) -> Prefs {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else { return Prefs::default() };
    let Some(root) = v.as_object() else { return Prefs::default() };
    let t = root.get("tts").filter(|x| x.is_object()).unwrap_or(&v);
    let auto = text(t, "auto").map(|a| a.to_ascii_lowercase()).filter(|a| AUTO_MODES.contains(&a.as_str())).or_else(|| {
        boolean(t, "enabled").map(|b| if b { "always".to_string() } else { "off".to_string() })
    });
    Prefs {
        provider: text(t, "provider").map(|p| p.to_ascii_lowercase()),
        voice: text(t, "voice"),
        persona: text(t, "persona"),
        talk_voice: text(t, "talkVoice").or_else(|| text(t, "talk_voice")),
        auto,
        max_length: number(t, "maxLength").or_else(|| number(t, "max_length")).map(|n| n as usize).filter(|n| *n > 0),
        summarize: boolean(t, "summarize"),
        speed: number(t, "speed").map(|f| f as f32).filter(|f| (0.25..=4.0).contains(f)),
        voice_mode: boolean(t, "voiceMode").or_else(|| boolean(t, "voice_mode")),
        voice_tts: boolean(t, "voiceTts").or_else(|| boolean(t, "voice_tts")),
    }
}

/// Read the preferences for `m`; a missing or corrupt file yields the defaults.
pub fn load(m: &Media) -> Prefs {
    std::fs::read_to_string(path(m)).map(|t| parse(&t)).unwrap_or_default()
}

/// Write `p` atomically (mode 0600), keeping unrelated keys already in the file.
pub fn save(m: &Media, p: &Prefs) -> Result<PathBuf, String> {
    let path = path(m);
    let mut root = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));
    if !root.get("tts").map(|t| t.is_object()).unwrap_or(false) {
        root["tts"] = serde_json::json!({});
    }
    let t = root.get_mut("tts").and_then(|v| v.as_object_mut()).ok_or("tts preferences: `tts` is not an object")?;
    let mut put = |k: &str, v: Option<serde_json::Value>| match v {
        Some(v) => {
            t.insert(k.to_string(), v);
        }
        None => {
            t.remove(k);
        }
    };
    put("provider", p.provider.as_ref().map(|v| serde_json::json!(v)));
    put("voice", p.voice.as_ref().map(|v| serde_json::json!(v)));
    put("persona", p.persona.as_ref().map(|v| serde_json::json!(v)));
    put("talkVoice", p.talk_voice.as_ref().map(|v| serde_json::json!(v)));
    put("auto", p.auto.as_ref().map(|v| serde_json::json!(v)));
    put("maxLength", p.max_length.map(|v| serde_json::json!(v)));
    put("summarize", p.summarize.map(|v| serde_json::json!(v)));
    put("speed", p.speed.map(|v| serde_json::json!(v)));
    put("voiceMode", p.voice_mode.map(|v| serde_json::json!(v)));
    put("voiceTts", p.voice_tts.map(|v| serde_json::json!(v)));
    write_atomic(&path, format!("{}\n", serde_json::to_string_pretty(&root).unwrap_or_else(|_| "{}".into())).as_bytes())?;
    Ok(path)
}

/// Load, change and save in one step (`setTts*` in OpenClaw).
pub fn update(m: &Media, f: impl FnOnce(&mut Prefs)) -> Result<PathBuf, String> {
    let mut p = load(m);
    f(&mut p);
    save(m, &p)
}

pub fn set_provider(m: &Media, provider: Option<&str>) -> Result<PathBuf, String> {
    update(m, |p| p.provider = provider.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()))
}

pub fn set_voice(m: &Media, voice: Option<&str>) -> Result<PathBuf, String> {
    update(m, |p| p.voice = voice.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
}

pub fn set_persona(m: &Media, persona: Option<&str>) -> Result<PathBuf, String> {
    update(m, |p| p.persona = persona.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()))
}

pub fn set_talk_voice(m: &Media, voice: Option<&str>) -> Result<PathBuf, String> {
    update(m, |p| p.talk_voice = voice.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
}

pub fn set_auto(m: &Media, mode: &str) -> Result<PathBuf, String> {
    let mode = mode.trim().to_ascii_lowercase();
    if !AUTO_MODES.contains(&mode.as_str()) {
        return Err(format!("unknown TTS auto mode `{mode}` (off, always, inbound, tagged)"));
    }
    update(m, |p| p.auto = Some(mode.clone()))
}

pub fn set_max_length(m: &Media, n: usize) -> Result<PathBuf, String> {
    if !(MIN_LIMIT..=MAX_LIMIT).contains(&n) {
        return Err(format!("limit must be between {MIN_LIMIT} and {MAX_LIMIT} characters"));
    }
    update(m, |p| p.max_length = Some(n))
}

pub fn set_summarize(m: &Media, on: bool) -> Result<PathBuf, String> {
    update(m, |p| p.summarize = Some(on))
}

pub fn set_speed(m: &Media, speed: f32) -> Result<PathBuf, String> {
    if !(0.25..=4.0).contains(&speed) || !speed.is_finite() {
        return Err("speed must be between 0.25 and 4.0".into());
    }
    update(m, |p| p.speed = Some(speed))
}

pub fn set_voice_mode(m: &Media, on: bool) -> Result<PathBuf, String> {
    update(m, |p| p.voice_mode = Some(on))
}

pub fn set_voice_tts(m: &Media, on: bool) -> Result<PathBuf, String> {
    update(m, |p| p.voice_tts = Some(on))
}

/// Per-chat `/voice` / `/tts chat` modes (Hermes `_voice_mode`, persisted next to the
/// `tts` object as `{"voiceModes": {"<channel>:<chat>": "off" | "voice_only" | "all"}}`).
pub fn chat_modes(m: &Media) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let Some(v) = std::fs::read_to_string(path(m)).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()) else {
        return out;
    };
    let t = v.get("voiceModes").or_else(|| v.get("voice_modes")).and_then(|x| x.as_object());
    for (k, mode) in t.into_iter().flatten() {
        if let Some(s) = mode.as_str().map(str::trim).filter(|s| VOICE_MODES.contains(s)) {
            out.insert(k.clone(), s.to_string());
        }
    }
    out
}

/// The persisted mode for one chat (`None` = no override, the profile default applies).
pub fn chat_mode(m: &Media, chat: &str) -> Option<String> {
    chat_modes(m).get(chat.trim()).cloned()
}

/// Record (or clear, with `None`) one chat's mode. Unknown modes are rejected the way
/// Hermes rejects anything outside `off|voice_only|all`.
pub fn set_chat_mode(m: &Media, chat: &str, mode: Option<&str>) -> Result<PathBuf, String> {
    let chat = chat.trim();
    if chat.is_empty() {
        return Err("a chat key (<channel>:<chat>) is required".into());
    }
    let mode = match mode {
        Some(x) => {
            let x = x.trim().to_ascii_lowercase();
            if !VOICE_MODES.contains(&x.as_str()) {
                return Err(format!("unknown voice mode `{x}` (off, voice_only, all)"));
            }
            Some(x)
        }
        None => None,
    };
    let path = path(m);
    let mut root = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()).filter(|v| v.is_object()).unwrap_or_else(|| serde_json::json!({}));
    if !root.get("voiceModes").map(|t| t.is_object()).unwrap_or(false) {
        root["voiceModes"] = serde_json::json!({});
    }
    let t = root.get_mut("voiceModes").and_then(|v| v.as_object_mut()).ok_or("tts preferences: `voiceModes` is not an object")?;
    match mode {
        Some(mode) => {
            t.insert(chat.to_string(), serde_json::json!(mode));
        }
        None => {
            t.remove(chat);
        }
    }
    write_atomic(&path, format!("{}\n", serde_json::to_string_pretty(&root).unwrap_or_else(|_| "{}".into())).as_bytes())?;
    Ok(path)
}

/// `[media.tts] auto` equivalent of a Hermes per-chat mode (`None` = no override).
pub fn auto_for_chat(m: &Media, chat: &str) -> Option<String> {
    match chat_mode(m, chat)?.as_str() {
        "off" => Some("off".into()),
        "voice_only" => Some("inbound".into()),
        "all" => Some("always".into()),
        _ => None,
    }
}

/// The auto mode actually in force: a persisted choice, else `[media.tts] auto`, else an
/// explicit `/voice tts on|off`, else `off`.
pub fn auto_mode(m: &Media) -> String {
    effective_auto(&load(m), m)
}

fn effective_auto(p: &Prefs, m: &Media) -> String {
    p.auto
        .clone()
        .or_else(|| m.cfg.str("tts.auto"))
        .or_else(|| p.voice_tts.map(|on| if on { "always".to_string() } else { "off".to_string() }))
        .map(|a| a.trim().to_ascii_lowercase())
        .filter(|a| AUTO_MODES.contains(&a.as_str()))
        .unwrap_or_else(|| "off".into())
}

/// Auto-reply limit: prefs, else `[media.tts] max_length` (1500), clamped to 100–4096.
pub fn max_length(m: &Media) -> usize {
    let n = load(m).max_length.or_else(|| m.cfg.get("tts.max_length").and_then(|v| v.as_integer()).filter(|n| *n > 0).map(|n| n as usize)).unwrap_or(DEFAULT_MAX_LENGTH);
    n.clamp(MIN_LIMIT, MAX_LIMIT)
}

/// Whether long auto replies are summarized (prefs, else `[media.tts] summarize`, default on).
pub fn summarize(m: &Media) -> bool {
    load(m).summarize.unwrap_or_else(|| m.cfg.bool_or("tts.summarize", true))
}

/// Whether replies are read aloud in voice mode (prefs, else `[media.voice] speak`, default on).
pub fn voice_tts(m: &Media) -> bool {
    load(m).voice_tts.unwrap_or_else(|| m.cfg.bool_or("voice.speak", true))
}

/// Whether CLI voice mode is armed (prefs `voiceMode`, else `[media.voice] enabled`).
pub fn voice_mode(m: &Media) -> bool {
    load(m).voice_mode.unwrap_or_else(|| m.cfg.bool_or("voice.enabled", false))
}

/// Atomic write with mode 0600 (the temp file is created private, then renamed).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "tts-prefs.json".into());
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let tmp = dir.join(format!(".{name}.{}.{seq}.tmp", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", tmp.display())
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn media(tag: &str) -> (Media, PathBuf) {
        let dir = crate::testutil::temp_dir(tag);
        let prefs = dir.join("nested").join("tts-prefs.json");
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts]\nprefs_path = \"{}\"\n", prefs.display())), http: Default::default() };
        (m, prefs)
    }

    #[test]
    fn round_trip_and_private_mode() {
        let (m, file) = media("prefs-roundtrip");
        assert_eq!(load(&m), Prefs::default(), "missing file = first run");
        assert!(!file.exists());

        let p = Prefs {
            provider: Some("openai".into()),
            voice: Some("nova".into()),
            persona: Some("narrator".into()),
            talk_voice: Some("alloy".into()),
            auto: Some("always".into()),
            max_length: Some(2000),
            summarize: Some(false),
            speed: Some(1.25),
            voice_mode: Some(true),
            voice_tts: Some(false),
        };
        assert_eq!(save(&m, &p).unwrap(), file);
        assert_eq!(load(&m), p);
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "prefs must not be world readable");

        // The JSON keeps OpenClaw's shape (`tts` object, camelCase keys).
        let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(raw["tts"]["provider"], "openai");
        assert_eq!(raw["tts"]["talkVoice"], "alloy");
        assert_eq!(raw["tts"]["maxLength"], 2000);
        assert_eq!(raw["tts"]["voiceMode"], true);
    }

    #[test]
    fn setters_preserve_unknown_keys_and_clear() {
        let (m, file) = media("prefs-setters");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "{\"tts\":{\"provider\":\"edge\",\"enabled\":true,\"future\":42},\"other\":{\"x\":1}}").unwrap();
        set_talk_voice(&m, Some("af_bella")).unwrap();
        set_speed(&m, 2.0).unwrap();
        set_provider(&m, Some("OpenAI")).unwrap();
        let p = load(&m);
        assert_eq!((p.provider.as_deref(), p.talk_voice.as_deref(), p.speed), (Some("openai"), Some("af_bella"), Some(2.0)));
        let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(raw["tts"]["future"], 42, "unknown keys survive a write");
        assert_eq!(raw["other"]["x"], 1);
        // `enabled` is a legacy alias for auto; it stays put but auto wins.
        set_auto(&m, "off").unwrap();
        assert!(!load(&m).enabled(&m));
        set_auto(&m, "inbound").unwrap();
        assert!(load(&m).enabled(&m));
        set_voice(&m, Some("nova")).unwrap();
        set_voice(&m, None).unwrap();
        set_persona(&m, Some("Coach")).unwrap();
        set_persona(&m, Some("  ")).unwrap();
        let p = load(&m);
        assert_eq!((p.voice, p.persona), (None, None), "blank clears the key");
        assert!(set_auto(&m, "sometimes").is_err());
        assert!(set_speed(&m, 9.0).is_err());
        assert!(set_max_length(&m, 5).is_err());
    }

    /// Per-chat modes (Hermes `_voice_mode`): persisted next to `tts`, mapped onto the
    /// `[media.tts] auto` vocabulary, and safe against unknown modes.
    #[test]
    fn chat_modes_persist_and_map_to_auto() {
        let (m, file) = media("prefs-chats");
        assert!(chat_modes(&m).is_empty(), "first run has no overrides");
        assert_eq!(chat_mode(&m, "discord:1"), None);
        set_chat_mode(&m, "discord:1", Some("all")).unwrap();
        set_chat_mode(&m, "telegram:42", Some("off")).unwrap();
        set_chat_mode(&m, "slack:C9", Some("voice_only")).unwrap();
        assert_eq!(chat_mode(&m, "discord:1").as_deref(), Some("all"));
        assert_eq!(auto_for_chat(&m, "discord:1").as_deref(), Some("always"));
        assert_eq!(auto_for_chat(&m, "telegram:42").as_deref(), Some("off"));
        assert_eq!(auto_for_chat(&m, "slack:C9").as_deref(), Some("inbound"));
        assert_eq!(auto_for_chat(&m, "nowhere:1"), None, "no override = profile default");
        // The file keeps the `tts` object and other keys intact.
        let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(raw["voiceModes"]["discord:1"], "all");
        set_provider(&m, Some("edge")).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!((raw["tts"]["provider"].as_str(), raw["voiceModes"]["telegram:42"].as_str()), (Some("edge"), Some("off")));
        assert!(set_chat_mode(&m, "discord:1", Some("sometimes")).is_err());
        assert!(set_chat_mode(&m, "  ", Some("all")).is_err());
        set_chat_mode(&m, "discord:1", None).unwrap();
        assert_eq!(chat_modes(&m).len(), 2, "clearing removes only that chat");
    }

    /// An explicit `/voice tts on|off` is the auto mode when nothing else sets one.
    #[test]
    fn voice_tts_is_the_last_auto_fallback() {
        let (m, _f) = media("prefs-voicetts");
        assert_eq!(auto_mode(&m), "off");
        set_voice_tts(&m, true).unwrap();
        assert_eq!(auto_mode(&m), "always");
        set_voice_tts(&m, false).unwrap();
        assert_eq!(auto_mode(&m), "off");
    }

    #[test]
    fn defaults_and_corrupt_files() {
        let (m, file) = media("prefs-defaults");
        assert_eq!(auto_mode(&m), "off");
        assert_eq!(max_length(&m), DEFAULT_MAX_LENGTH);
        assert!(summarize(&m));
        assert!(voice_tts(&m));
        assert!(!voice_mode(&m));

        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "{not json").unwrap();
        assert_eq!(load(&m), Prefs::default(), "corrupt file falls back to defaults");
        assert_eq!(max_length(&m), DEFAULT_MAX_LENGTH);

        let m2 = Media { cfg: crate::MediaConfig::from_toml("[tts]\nauto = \"tagged\"\nmax_length = 200\nsummarize = false\n[voice]\nspeak = false\nenabled = true\n"), http: Default::default() };
        assert_eq!(auto_mode(&m2), "tagged");
        assert_eq!(max_length(&m2), 200);
        assert!(!summarize(&m2));
        assert!(!voice_tts(&m2));
        assert!(voice_mode(&m2));
        assert_eq!(max_length(&Media { cfg: crate::MediaConfig::from_toml("[tts]\nmax_length = 99999\n"), http: Default::default() }), MAX_LIMIT);
    }
}
