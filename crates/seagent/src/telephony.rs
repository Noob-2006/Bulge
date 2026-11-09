//! Voice for the telephony channel tools: `whatsapp_call` (OpenClaw
//! `extensions/whatsapp/src/agent-tools-{login,call}.ts`, MIT) plays a synthesized message
//! down the call, but the WhatsApp channel lives in `seagent-channel` and cannot reach the model
//! or `[media]` config. The host installs the hook here — where the channels are built — so a
//! real `whatsapp_call` no longer fails with "no text-to-speech provider is configured".
//!
//! The chain is `[media.tts]` through seagent-media (provider → fallback), the same `Media` the
//! voice notes and `meet_say` use; the hook's shape is
//! `(PCM16 mono little-endian, sample rate, provider id)`.

use seagent_kernel::config::Config;
use seagent_kernel::vault::Vault;
use seagent_media::Media;
use std::sync::Arc;

/// Install the `whatsapp_call` speech hook from the loaded `[media]`; the hook when one is
/// installed. No `[media.tts]` = `None`, and the tool keeps its own "no text-to-speech provider
/// is configured" error instead of failing mid-call.
pub fn install(cfg: &Config, vault: &Arc<Vault>) -> Option<seagent_channel::whatsapp::TelephonyTts> {
    if !cfg.media.contains_key("tts") {
        return None;
    }
    install_media(crate::media_host::media(cfg, vault.clone()))
}

/// [`install`] for an already-built [`Media`].
pub fn install_media(m: Arc<Media>) -> Option<seagent_channel::whatsapp::TelephonyTts> {
    let media = m.clone();
    let hook: seagent_channel::whatsapp::TelephonyTts = Arc::new(move |text: &str| speech(&media, text));
    seagent_channel::whatsapp::set_telephony_tts(hook.clone());
    Some(hook)
}

/// Speak `text` as raw PCM16 mono through `[media.tts]` (provider, then `fallback`).
fn speech(m: &Media, text: &str) -> Result<(Vec<u8>, u32, String), String> {
    let req = seagent_media::tts::TtsRequest { text: seagent_media::tts::normalize(text), format: Some("pcm".into()), ..Default::default() };
    let (provider, s) = seagent_media::tts::synthesize(m, &req, &seagent_core::Cancel::new())?;
    let rate = s.sample_rate.unwrap_or(24000);
    let pcm = match s.audio.mime.as_str() {
        "audio/pcm" | "audio/l16" => s.audio.bytes.clone(),
        mime => seagent_media::audio::pcm16_to_bytes(&seagent_media::audio::decode_to_pcm(&s.audio.bytes, mime, rate, &seagent_core::Cancel::new())?),
    };
    Ok((pcm, rate, provider))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn config(media: &str) -> Config {
        Config { media: toml::from_str(media).unwrap(), ..Default::default() }
    }

    /// A stand-in for the OpenAI speech endpoint: one request, one PCM body.
    fn fake_tts() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut head = Vec::new();
                let mut b = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&b[..n]),
                    }
                }
                // Drain the request body first: Windows resets a socket closed with unread bytes.
                if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                    let text = String::from_utf8_lossy(&head[..end]).to_ascii_lowercase();
                    let want: usize = text.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                    let mut have = head.len() - end - 4;
                    while have < want {
                        match s.read(&mut b) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => have += n,
                        }
                    }
                }
                let body: Vec<u8> = vec![0, 0, 1, 0, 2, 0, 3, 0];
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: audio/pcm\r\nx-audio-sample-rate: 16000\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes());
                let _ = s.write_all(&body);
            }
        });
        url
    }

    /// Without `[media.tts]` there is nothing to speak with: no hook is installed.
    #[test]
    fn hook_is_absent_without_a_media_tts_section() {
        let v = Arc::new(Vault::empty());
        assert!(install(&config(""), &v).is_none(), "no [media] at all");
        assert!(install(&config("[stt]\nprovider = \"whisper\"\n"), &v).is_none(), "an stt-only [media] says nothing about speech");
        assert!(install(&config("max_image_bytes = 1000\n"), &v).is_none());
    }

    /// With `[media.tts]` the installed hook speaks through the configured provider and returns
    /// the (PCM16 LE, rate, provider) shape `whatsapp_call` writes into its WAV.
    #[test]
    fn hook_is_installed_and_speaks_through_the_media_tts_chain() {
        let url = fake_tts();
        let cfg = config(&format!("[tts]\nprovider = \"openai\"\n[tts.openai]\nbase_url = \"{url}\"\napi_key = \"k\"\n"));
        let hook = install(&cfg, &Arc::new(Vault::empty())).expect("[media.tts] installs the whatsapp_call hook");
        let (pcm, rate, provider) = hook("hello from seagent").expect("synthesized through the fake provider");
        assert_eq!((rate, provider.as_str(), pcm.len()), (16000, "openai", 8), "PCM16 LE + sample rate + provider");
        assert_eq!(pcm, vec![0, 0, 1, 0, 2, 0, 3, 0]);
    }
}
