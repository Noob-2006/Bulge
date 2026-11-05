//! Realtime providers against scripted local WebSocket servers.

use super::*;
use crate::testutil::ws_server;
use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(super) type Ws = WebSocket<TcpStream>;

pub(super) fn recv(ws: &mut Ws) -> Option<Value> {
    loop {
        match ws.recv_blocking() {
            Ok(Message::Text(t)) => return serde_json::from_str(&t).ok(),
            Ok(Message::Binary(b)) => return Some(json!({"__binary": b.len()})),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

pub(super) fn send(ws: &mut Ws, v: Value) {
    ws.send_text(&v.to_string()).unwrap();
}

pub(super) fn media(extra: &str) -> Media {
    Media { cfg: crate::MediaConfig::from_toml(&format!("[realtime]\nconnect_timeout_ms = 3000\nclose_timeout_ms = 1500\nreconnect_attempts = 1\n{extra}")), http: Default::default() }
}

pub(super) fn provider(id: &str, base: &str) -> String {
    format!("[providers.{id}]\napi_key = \"k\"\nbase_url = \"{base}\"\n")
}

fn collect(s: &mut dyn RealtimeStt, until: impl Fn(&[SttEvent]) -> bool) -> Vec<SttEvent> {
    let end = Instant::now() + Duration::from_secs(3);
    let mut v = Vec::new();
    while Instant::now() < end && !until(&v) {
        v.extend(s.poll().unwrap());
        std::thread::sleep(Duration::from_millis(5));
    }
    v
}

fn finals(v: &[SttEvent]) -> Vec<String> {
    v.iter()
        .filter_map(|e| {
            if let SttEvent::Final(t) = e {
                Some(t.clone())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn a_vanished_transcription_provider_is_reported_not_ignored() {
    // Handshake, one buffered audio frame, then the peer goes away mid-session.
    let url = ws_server(|_, ws| {
        let _ = recv(ws);
        send(ws, json!({"type": "session.updated"}));
        let _ = recv(ws);
    });
    let m = media(&provider("openai", &url));
    let mut s = open_stt(&m, Some("openai"), 24000, None).unwrap();
    let mut err = None;
    for _ in 0..200 {
        s.poll().unwrap();
        if let Err(e) = s.send_audio(&[0i16; 480]) {
            err = Some(e);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let e = err.expect("a vanished provider must surface an error, not silently drop audio");
    assert!(e.contains("session lost its connection") || e.contains("session is closed"), "{e}");
    // The session stays closed, so the caller's fallback (file transcription) is used.
    assert!(s.send_audio(&[0i16; 480]).is_err());
}

#[test]
fn wire_formats_roundtrip() {
    let pcm: Vec<i16> = (0..160)
        .map(|i| ((i as f64 / 8.0).sin() * 8000.0) as i16)
        .collect();
    assert_eq!(Wire::Mulaw.encode(&pcm, 8000).len(), 160);
    assert_eq!(
        Wire::Mulaw.encode(&pcm, 16000).len(),
        80,
        "resampled to 8 kHz"
    );
    assert_eq!(Wire::Pcm16(24000).encode(&pcm, 8000).len(), 960);
    assert_eq!(Wire::F32le(8000).encode(&pcm, 8000).len(), 640);
    for w in [
        Wire::Mulaw,
        Wire::Alaw,
        Wire::Pcm16(8000),
        Wire::S32le(8000),
        Wire::F32le(8000),
    ] {
        let back = w.decode(&w.encode(&pcm, 8000), 8000);
        assert_eq!(back.len(), pcm.len(), "{w:?}");
        assert!(
            back.iter()
                .zip(&pcm)
                .all(|(a, b)| (*a as i32 - *b as i32).abs() < 600),
            "{w:?}"
        );
    }
    assert_eq!(Wire::Pcm16(24000).duration_ms(48000), 1000);
    assert_eq!(Wire::Mulaw.duration_ms(800), 100);
    assert_eq!(
        Wire::Pcm16(24000).openai_format(),
        json!({"type": "audio/pcm", "rate": 24000})
    );
}

#[test]
fn provider_resolution_auto_and_aliases() {
    let m = media(&provider("deepgram", "ws://x"));
    assert_eq!(
        resolve(
            &m,
            STT_PROVIDERS,
            Some("nova-3-streaming"),
            "stt_provider",
            "transcription"
        )
        .unwrap()
        .id,
        "deepgram"
    );
    assert_eq!(
        resolve(
            &m,
            STT_PROVIDERS,
            Some("voxtral-realtime"),
            "stt_provider",
            "transcription"
        )
        .unwrap()
        .id,
        "mistral"
    );
    #[cfg(feature = "personal")]
    assert_eq!(
        resolve(
            &m,
            VOICE_PROVIDERS,
            Some("grok-voice"),
            "voice_provider",
            "voice"
        )
        .unwrap()
        .id,
        "xai"
    );
    #[cfg(feature = "personal")]
    assert_eq!(
        resolve(
            &m,
            VOICE_PROVIDERS,
            Some("gemini"),
            "voice_provider",
            "voice"
        )
        .unwrap()
        .id,
        "google"
    );
    assert!(resolve(
        &m,
        STT_PROVIDERS,
        Some("nope"),
        "stt_provider",
        "transcription"
    )
    .unwrap_err()
    .contains("unknown realtime transcription provider"));
    if ["OPENAI_API_KEY", "XAI_API_KEY"]
        .iter()
        .all(|k| std::env::var(k).is_err())
    {
        assert_eq!(
            resolve(&m, STT_PROVIDERS, None, "stt_provider", "transcription")
                .unwrap()
                .id,
            "deepgram"
        );
    }
    let m2 = media("stt_provider = \"elevenlabs\"\n");
    assert_eq!(
        resolve(&m2, STT_PROVIDERS, None, "stt_provider", "transcription")
            .unwrap()
            .id,
        "elevenlabs"
    );
    if std::env::var("ELEVENLABS_API_KEY").is_err() && std::env::var("XI_API_KEY").is_err() {
        assert_eq!(
            open_stt(&m2, None, 16000, None).err().unwrap(),
            "ElevenLabs API key missing"
        );
    }
}

#[test]
fn openai_transcription_orders_items_and_commits_on_finish() {
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |head, ws| {
        tx.send(json!({"head": head})).unwrap();
        let upd = recv(ws).unwrap();
        tx.send(upd).unwrap();
        send(ws, json!({"type": "session.updated"}));
        let a = recv(ws).unwrap();
        tx.send(a).unwrap();
        send(
            ws,
            json!({"type": "input_audio_buffer.speech_started", "item_id": "i1"}),
        );
        send(
            ws,
            json!({"type": "input_audio_buffer.committed", "item_id": "i1", "previous_item_id": null}),
        );
        send(
            ws,
            json!({"type": "input_audio_buffer.committed", "item_id": "i2", "previous_item_id": "i1"}),
        );
        send(
            ws,
            json!({"type": "conversation.item.input_audio_transcription.delta", "item_id": "i2", "delta": "wor"}),
        );
        send(
            ws,
            json!({"type": "conversation.item.input_audio_transcription.completed", "item_id": "i2", "transcript": "world"}),
        );
        send(
            ws,
            json!({"type": "conversation.item.input_audio_transcription.completed", "item_id": "i1", "transcript": "hello"}),
        );
        // finish(): the client commits its unowned tail.
        loop {
            let Some(v) = recv(ws) else { return };
            if v["type"] == "input_audio_buffer.commit" {
                tx.send(v).unwrap();
                break;
            }
        }
        send(
            ws,
            json!({"type": "input_audio_buffer.committed", "item_id": "i3", "previous_item_id": "i2"}),
        );
        send(
            ws,
            json!({"type": "conversation.item.input_audio_transcription.completed", "item_id": "i3", "transcript": "bye"}),
        );
        let _ = recv(ws);
    });
    let m = media(&format!(
        "[realtime.openai]\nlanguage = \"en\"\n{}",
        provider("openai", &url)
    ));
    let mut s = open_stt(&m, Some("openai-realtime"), 8000, None).unwrap();
    let head = rx.recv().unwrap();
    assert!(head["head"]
        .as_str()
        .unwrap()
        .contains("GET /realtime?intent=transcription"));
    assert!(head["head"]
        .as_str()
        .unwrap()
        .to_ascii_lowercase()
        .contains("authorization: bearer k"));
    let upd = rx.recv().unwrap();
    assert_eq!(upd["type"], "session.update");
    assert_eq!(upd["session"]["type"], "transcription");
    assert_eq!(
        upd["session"]["audio"]["input"]["format"],
        json!({"type": "audio/pcmu"})
    );
    assert_eq!(
        upd["session"]["audio"]["input"]["transcription"],
        json!({"model": "gpt-4o-transcribe", "language": "en"})
    );
    assert_eq!(
        upd["session"]["audio"]["input"]["turn_detection"]["silence_duration_ms"],
        800
    );
    s.send_audio(&vec![1000i16; 1600]).unwrap();
    let a = rx.recv().unwrap();
    assert_eq!(a["type"], "input_audio_buffer.append");
    assert_eq!(
        crate::store::b64_decode(a["audio"].as_str().unwrap())
            .unwrap()
            .len(),
        1600
    );
    let ev = collect(s.as_mut(), |v| finals(v).len() >= 2);
    assert!(ev.contains(&SttEvent::SpeechStarted));
    assert!(ev.contains(&SttEvent::Partial("wor".into())));
    assert_eq!(
        finals(&ev),
        vec!["hello", "world"],
        "completed out of order, delivered in commit order"
    );
    s.send_audio(&vec![1000i16; 1600]).unwrap();
    let tail = s.finish().unwrap();
    assert_eq!(rx.recv().unwrap()["type"], "input_audio_buffer.commit");
    assert_eq!(finals(&tail), vec!["bye"]);
}

#[test]
fn openai_transcription_rejects_before_ready() {
    let url = ws_server(|_, ws| {
        let _ = recv(ws);
        send(
            ws,
            json!({"type": "error", "error": {"message": "invalid api key"}}),
        );
        let _ = recv(ws);
    });
    let m = media(&provider("openai", &url));
    let e = open_stt(&m, Some("openai"), 16000, None).err().unwrap();
    assert_eq!(e, "invalid api key");
}

#[test]
fn deepgram_streams_binary_and_finalizes() {
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |head, ws| {
        tx.send(json!({"head": head})).unwrap();
        let b = recv(ws).unwrap();
        tx.send(b).unwrap();
        send(
            ws,
            json!({"type": "Results", "is_final": true, "channel": {"alternatives": [{"transcript": "hello"}]}}),
        );
        send(
            ws,
            json!({"type": "Results", "is_final": true, "speech_final": true, "channel": {"alternatives": [{"transcript": "there"}]}}),
        );
        send(
            ws,
            json!({"type": "Results", "is_final": false, "channel": {"alternatives": [{"transcript": "pending"}]}}),
        );
        let fin = recv(ws).unwrap();
        tx.send(fin).unwrap();
        send(
            ws,
            json!({"type": "Results", "from_finalize": true, "is_final": true, "channel": {"alternatives": [{"transcript": "tail"}]}}),
        );
        let _ = recv(ws);
    });
    let m = media(&format!(
        "[realtime.deepgram]\nlanguage = \"de\"\n{}",
        provider(
            "deepgram",
            &format!("{}/v1", url.replace("ws://", "http://"))
        )
    ));
    let mut s = open_stt(&m, Some("deepgram"), 16000, None).unwrap();
    let head = rx.recv().unwrap()["head"].as_str().unwrap().to_string();
    assert!(head.starts_with("GET /v1/listen?model=nova-3&encoding=linear16&sample_rate=16000&channels=1&interim_results=true&endpointing=800&language=de "), "{head}");
    assert!(head.to_ascii_lowercase().contains("authorization: token k"));
    s.send_audio(&vec![5i16; 320]).unwrap();
    assert_eq!(rx.recv().unwrap(), json!({"__binary": 640}));
    let ev = collect(s.as_mut(), |v| {
        v.iter()
            .any(|e| matches!(e, SttEvent::Partial(p) if p == "pending"))
    });
    assert!(ev.contains(&SttEvent::SpeechStarted));
    assert!(ev.contains(&SttEvent::Partial("hello".into())));
    assert_eq!(finals(&ev), vec!["hello there"]);
    let tail = s.finish().unwrap();
    assert_eq!(rx.recv().unwrap()["type"], "Finalize");
    assert_eq!(
        finals(&tail),
        vec!["tail"],
        "the finalize result supersedes the interim text"
    );
    let bad = media(&format!(
        "[realtime.deepgram]\nencoding = \"opus\"\n{}",
        provider("deepgram", "https://x")
    ));
    assert!(open_stt(&bad, Some("deepgram"), 16000, None)
        .err()
        .unwrap()
        .contains("Invalid Deepgram realtime transcription encoding: opus"));
    let bad = media(&provider("deepgram", "ftp://x"));
    assert!(open_stt(&bad, Some("deepgram"), 16000, None)
        .err()
        .unwrap()
        .contains("unsupported scheme \"ftp:\""));
}

#[test]
fn elevenlabs_vad_commits_and_dedupes_timestamp_echo() {
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |head, ws| {
        tx.send(json!({"head": head})).unwrap();
        send(ws, json!({"message_type": "session_started"}));
        let c = recv(ws).unwrap();
        tx.send(c).unwrap();
        send(
            ws,
            json!({"message_type": "partial_transcript", "text": "a"}),
        );
        send(
            ws,
            json!({"message_type": "committed_transcript", "text": "alpha"}),
        );
        send(
            ws,
            json!({"message_type": "committed_transcript_with_timestamps", "text": "alpha"}),
        );
        let last = recv(ws).unwrap();
        tx.send(last).unwrap();
        send(
            ws,
            json!({"message_type": "committed_transcript", "text": "beta"}),
        );
        let _ = recv(ws);
    });
    let m = media(&format!("[realtime.elevenlabs]\nvad_threshold = 0.4\nvad_threshold_bad = 5\nmin_speech_duration_ms = 10\n{}", provider("elevenlabs", &url)));
    let mut s = open_stt(&m, Some("scribe-v2-realtime"), 16000, Some("ja")).unwrap();
    let head = rx.recv().unwrap()["head"].as_str().unwrap().to_string();
    assert!(head.starts_with("GET /v1/speech-to-text/realtime?model_id=scribe_v2_realtime&audio_format=pcm_16000&commit_strategy=vad&include_timestamps=false&include_language_detection=false&language_code=ja&vad_threshold=0.4 "), "{head}");
    assert!(head.to_ascii_lowercase().contains("xi-api-key: k"));
    s.send_audio(&vec![9i16; 160]).unwrap();
    let c = rx.recv().unwrap();
    assert_eq!(
        (
            c["message_type"].as_str(),
            c["sample_rate"].as_u64(),
            c.get("commit")
        ),
        (Some("input_audio_chunk"), Some(16000), None)
    );
    assert_eq!(
        crate::store::b64_decode(c["audio_base_64"].as_str().unwrap())
            .unwrap()
            .len(),
        320
    );
    let ev = collect(s.as_mut(), |v| !finals(v).is_empty());
    assert!(ev.contains(&SttEvent::Partial("a".into())));
    let tail = s.finish().unwrap();
    let last = rx.recv().unwrap();
    assert_eq!(
        (last["audio_base_64"].as_str(), last["commit"].as_bool()),
        (Some(""), Some(true))
    );
    let mut all = finals(&ev);
    all.extend(finals(&tail));
    assert_eq!(all, vec!["alpha", "beta"]);
}

#[test]
fn mistral_session_update_segments_and_done() {
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |head, ws| {
        tx.send(json!({"head": head})).unwrap();
        send(ws, json!({"type": "session.created"}));
        let u = recv(ws).unwrap();
        tx.send(u).unwrap();
        let a = recv(ws).unwrap();
        tx.send(a).unwrap();
        send(
            ws,
            json!({"type": "transcription.text.delta", "text": "Bon"}),
        );
        send(
            ws,
            json!({"type": "transcription.text.delta", "text": "jour"}),
        );
        send(
            ws,
            json!({"type": "transcription.segment", "text": "Bonjour"}),
        );
        send(ws, json!({"type": "transcription.text.delta", "text": "."}));
        let f = recv(ws).unwrap();
        let e = recv(ws).unwrap();
        tx.send(json!([f, e])).unwrap();
        send(
            ws,
            json!({"type": "transcription.done", "text": "Bonjour."}),
        );
        let _ = recv(ws);
    });
    let m = media(&provider(
        "mistral",
        &format!("{}/v1", url.replace("ws://", "http://")),
    ));
    let mut s = open_stt(&m, Some("mistral"), 16000, None).unwrap();
    let head = rx.recv().unwrap()["head"].as_str().unwrap().to_string();
    assert!(head.starts_with("GET /v1/audio/transcriptions/realtime?model=voxtral-mini-transcribe-realtime-2602&target_streaming_delay_ms=800 "), "{head}");
    assert_eq!(
        rx.recv().unwrap(),
        json!({"type": "session.update", "session": {"audio_format": {"encoding": "pcm_s16le", "sample_rate": 16000}}})
    );
    s.send_audio(&[1, 2, 3]).unwrap();
    assert_eq!(rx.recv().unwrap()["type"], "input_audio.append");
    let ev = collect(s.as_mut(), |v| !finals(v).is_empty());
    assert!(ev.contains(&SttEvent::Partial("Bonjour".into())));
    assert_eq!(finals(&ev), vec!["Bonjour"]);
    let tail = s.finish().unwrap();
    assert_eq!(
        rx.recv().unwrap(),
        json!([{"type": "input_audio.flush"}, {"type": "input_audio.end"}])
    );
    assert!(
        finals(&tail).is_empty(),
        "punctuation-only pending text only completes the earlier final: {tail:?}"
    );
}

#[test]
fn xai_transcription_partials_finals_and_done() {
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |head, ws| {
        tx.send(json!({"head": head})).unwrap();
        send(ws, json!({"type": "transcript.created"}));
        let b = recv(ws).unwrap();
        tx.send(b).unwrap();
        send(ws, json!({"type": "transcript.partial", "text": "hel"}));
        send(
            ws,
            json!({"type": "transcript.partial", "text": "hello", "is_final": true, "speech_final": true}),
        );
        let d = recv(ws).unwrap();
        tx.send(d).unwrap();
        send(
            ws,
            json!({"type": "transcript.done", "text": "hello again"}),
        );
        let _ = recv(ws);
    });
    let m = media(&provider("xai", &url));
    let mut s = open_stt(&m, Some("grok-stt-streaming"), 8000, Some("en")).unwrap();
    let head = rx.recv().unwrap()["head"].as_str().unwrap().to_string();
    assert!(head.starts_with("GET /stt?sample_rate=8000&encoding=mulaw&interim_results=true&endpointing=800&language=en "), "{head}");
    s.send_audio(&vec![0i16; 160]).unwrap();
    assert_eq!(rx.recv().unwrap(), json!({"__binary": 160}));
    let ev = collect(s.as_mut(), |v| !finals(v).is_empty());
    assert_eq!(
        ev,
        vec![
            SttEvent::SpeechStarted,
            SttEvent::Partial("hel".into()),
            SttEvent::Final("hello".into())
        ]
    );
    let tail = s.finish().unwrap();
    assert_eq!(rx.recv().unwrap(), json!({"type": "audio.done"}));
    assert_eq!(finals(&tail), vec!["hello again"]);
}
