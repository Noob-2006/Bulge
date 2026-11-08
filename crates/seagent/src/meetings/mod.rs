//! Meeting bots: the Hermes `plugins/google_meet` port ([`meet`], [`meet_bot`]) and the
//! Microsoft Teams meeting pipeline ([`teams`], from Hermes `plugins/teams_pipeline`, MIT).
//!
//! Configuration lives in the `[meetings]` table (never a top-level key):
//!
//! ```toml
//! [meetings.google_meet]              # seagent meet / meet_* tools
//! guest_name = "SE Agent Agent"
//! chromium = "/usr/bin/chromium"      # optional; autodetected otherwise
//! cdp_url  = ""                       # attach to an existing DevTools endpoint
//! auth_state = ""                     # Playwright storage-state JSON for signed-in joins
//!
//! [meetings.teams]                    # seagent teams / Teams meeting pipeline
//! tenant_id = "…"
//! client_id = "…"
//! client_secret = "{{secret:MSGRAPH_CLIENT_SECRET}}"
//! [meetings.teams.pipeline]           # pipeline knobs (see [`teams`])
//! transcript_preferred = true
//! ```
//!
//! Everything here is explicit by design: no calendar scanning, no auto-dial, no consent
//! announcement — the agent only acts on URLs/notifications it was handed.

/// Self-registration (`seagent_core::registry`): `seagent meet|teams|teams-pipeline …` take their own
/// flags, so they are dispatched before the binary's argument parser sees `argv`.
pub fn register_route() {
    seagent_core::registry::register_command_route("meet,teams,teams-pipeline", None, cli);
}

#[cfg(test)]
mod fakecdp;
pub mod meet;
pub mod meet_bot;
pub mod teams;

use seagent_core::Cancel;
use seagent_kernel::config::Paths;
use seagent_kernel::vault::Vault;
use seagent_media::tts::TtsRequest;
use seagent_media::{Media, MediaConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The `[meetings]` table from the user config (empty when unset).
pub fn table(paths: &Paths) -> toml::Table {
    std::fs::read_to_string(paths.user_config()).ok().and_then(|s| s.parse::<toml::Table>().ok()).and_then(|t| t.get("meetings").and_then(|m| m.as_table()).cloned()).unwrap_or_default()
}

/// `[meetings.google_meet]` — the knobs [`meet`] and [`meet_bot`] read.
pub fn google_meet_cfg(meetings: &toml::Table) -> toml::Table {
    meetings.get("google_meet").and_then(|v| v.as_table()).cloned().unwrap_or_default()
}

/// The bot process is this executable re-exec'd as `seagent meet bot`.
pub fn manager(paths: &Paths) -> Arc<meet::Manager> {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("seagent"));
    Arc::new(meet::Manager { root: meet::root(&paths.data), bot: vec![exe.display().to_string(), "meet".into(), "bot".into()], env: vec![] })
}

/// `seagent meet …` and `seagent teams …` (dispatched before the binary's own argument parser, since
/// they take their own flags).
pub fn cli(cmd: &str, argv: &[String]) -> Result<i32, String> {
    let paths = Paths::from_env();
    let meetings = table(&paths);
    match cmd {
        "meet" => meet::cli(&manager(&paths), &google_meet_cfg(&meetings), argv),
        "teams" | "teams-pipeline" => teams::cli(&meetings, &paths, argv),
        other => Err(format!("unknown meetings command `{other}`")),
    }
}

/// Advisory cross-process lock on `<path>.lock` (Hermes `_file_lock`): waits up to 10 s, then
/// gives up with upstream's message. `f` runs under the lock; dropping the file releases it.
pub fn with_lock<T>(path: &Path, f: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;
    let lock_path = path.with_file_name(format!("{}.lock", path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
    if let Some(d) = lock_path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let file = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&lock_path)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        #[cfg(unix)]
        {
            // SAFETY: plain flock(2) on a descriptor we own.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(e);
            }
        }
        // std's portable lock (LockFileEx on Windows).
        #[cfg(not(unix))]
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
        if std::time::Instant::now() > deadline {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, format!("Timed out waiting for say queue lock ({})", lock_path.display())));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let out = f();
    drop(file);
    out
}

/// The `[media]` table as an seagent-media [`Media`] (TTS for `meet_say`), `None` when the user has
/// no `[media]` config at all — i.e. no provider could speak anyway.
pub fn media(paths: &Paths) -> Option<Arc<Media>> {
    let mut t: toml::Table = std::fs::read_to_string(paths.user_config()).ok().and_then(|s| s.parse().ok())?;
    let media = t.remove("media")?.as_table().cloned()?;
    let vault = Arc::new(Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty()));
    let secret: seagent_media::config::SecretFn = Arc::new(move |name: &str| {
        let s = vault.substitute(&format!("{{{{secret:{name}}}}}"));
        (!s.contains("{{secret:") && !s.is_empty()).then_some(s)
    });
    Some(Media::new(MediaConfig::new(media, secret)))
}

/// Speak `text` as raw PCM16 mono through the `[media.tts]` chain (the bot writes it to the
/// PulseAudio null-sink; upstream `realtime/` streams OpenAI audio instead).
pub fn pcm_speech(media: &Media, text: &str) -> Result<(Vec<u8>, u32), String> {
    let req = TtsRequest { text: seagent_media::tts::normalize(text), format: Some("pcm".into()), ..Default::default() };
    let (_provider, s) = seagent_media::tts::synthesize(media, &req, &Cancel::new())?;
    let rate = s.sample_rate.unwrap_or(24000);
    if s.audio.mime == "audio/pcm" || s.audio.mime == "audio/l16" {
        return Ok((s.audio.bytes, rate));
    }
    let pcm = seagent_media::audio::decode_to_pcm(&s.audio.bytes, &s.audio.mime, rate, &Cancel::new())?;
    Ok((seagent_media::audio::pcm16_to_bytes(&pcm), rate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_lock_serialises_and_releases() {
        use std::io::Write;
        let dir = seagent_core::tmp::scratch_path(format!("seagent-meet-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = dir.join("say_queue.jsonl");
        let n = with_lock(&q, || {
            std::fs::write(&q, "a\n")?;
            std::fs::OpenOptions::new().append(true).open(&q)?.write_all(b"b\n")
        });
        assert!(n.is_ok(), "{n:?}");
        assert_eq!(std::fs::read_to_string(&q).unwrap(), "a\nb\n");
        assert!(q.with_file_name("say_queue.jsonl.lock").is_file());
        // A second acquisition after the first returned works (the lock was released).
        assert!(with_lock(&q, || Ok(1)).is_ok());
        // The error path propagates the closure's error.
        let e = with_lock(&q, || Err::<(), _>(std::io::Error::other("boom")));
        assert_eq!(e.unwrap_err().to_string(), "boom");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn media_is_none_without_media_config() {
        let dir = seagent_core::tmp::scratch_path(format!("seagent-meet-media-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = Paths { data: dir.join("data"), config_dir: dir.join("config"), runtime: dir.join("run"), ..Default::default() };
        assert!(media(&paths).is_none(), "no config file at all");
        std::fs::create_dir_all(paths.config_dir.clone()).unwrap();
        std::fs::write(paths.user_config(), "[meetings]\n").unwrap();
        assert!(media(&paths).is_none(), "no [media] table");
        std::fs::write(paths.user_config(), "[media.tts]\nprovider = \"edge\"\n").unwrap();
        assert!(media(&paths).is_some());
        assert_eq!(google_meet_cfg(&table(&paths)).len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
