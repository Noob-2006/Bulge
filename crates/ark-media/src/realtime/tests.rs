//! Realtime providers against scripted local WebSocket servers.

use super::*;
use crate::testutil::{temp_dir, ws_server, FakeServer};
use ark_core::Cancel;
use ark_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::{Duration, Instant};

type Ws = WebSocket<TcpStream>;

fn recv(ws: &mut Ws) -> Option<Value> {
    loop {
        match ws.recv_blocking() {
            Ok(Message::Text(t)) => return serde_json::from_str(&t).ok(),
            Ok(Message::Binary(b)) => return Some(json!({"__binary": b.len()})),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

fn send(ws: &mut Ws, v: Value) {
    ws.send_text(&v.to_string()).unwrap();
}

fn media(extra: &str) -> Media {
    Media { cfg: crate::MediaConfig::from_toml(&format!("[realtime]\nconnect_timeout_ms = 3000\nclose_timeout_ms = 1500\nreconnect_attempts = 1\n{extra}")), http: Default::default() }
}

fn provider(id: &str, base: &str) -> String {
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

fn voice_events(
    s: &mut dyn RealtimeVoice,
    until: impl Fn(&[VoiceEvent]) -> bool,
) -> Vec<VoiceEvent> {
    let end = Instant::now() + Duration::from_secs(3);
    let mut v = Vec::new();
    while Instant::now() < end && !until(&v) {
        v.extend(s.poll().unwrap());
        std::thread::sleep(Duration::from_millis(5));
    }
    v
}

fn opts(tools: bool) -> VoiceOpts {
    let t = ToolSchema {
        name: "lookup".into(),
        description: "Look something up".into(),
        input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
    };
    VoiceOpts {
        instructions: "Be brief.".into(),
        voice: None,
        model: None,
        sample_rate: 24000,
        tools: if tools { vec![t] } else { vec![] },
    }
}

#[test]
fn openai_voice_session_audio_tools_and_barge_in() {
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |head, ws| {
        tx.send(json!({"head": head})).unwrap();
        let u = recv(ws).unwrap();
        tx.send(u).unwrap();
        send(ws, json!({"type": "session.updated", "session": {}}));
        let a = recv(ws).unwrap();
        tx.send(a).unwrap();
        // 2 s of assistant audio, then the user starts talking 300 ms in.
        let pcm = crate::audio::pcm16_to_bytes(&vec![100i16; 48000]);
        send(ws, json!({"type": "response.created"}));
        send(
            ws,
            json!({"type": "response.output_audio.delta", "item_id": "a1", "delta": crate::store::b64(&pcm)}),
        );
        send(
            ws,
            json!({"type": "response.output_audio_transcript.done", "transcript": "Hi there"}),
        );
        std::thread::sleep(Duration::from_millis(320));
        send(ws, json!({"type": "input_audio_buffer.speech_started"}));
        let t = recv(ws).unwrap();
        tx.send(t).unwrap();
        send(
            ws,
            json!({"type": "response.done", "response": {"status": "cancelled"}}),
        );
        send(
            ws,
            json!({"type": "conversation.item.input_audio_transcription.completed", "transcript": "look it up"}),
        );
        send(ws, json!({"type": "response.created"}));
        send(
            ws,
            json!({"type": "response.done", "response": {"status": "completed", "output": [
                {"type": "function_call", "id": "fc1", "call_id": "c1", "name": "lookup", "arguments": "{\"q\":\"x\"}", "status": "completed"},
                {"type": "function_call", "id": "fc2", "call_id": "c2", "name": "lookup", "arguments": "[1]"}
            ]}}),
        );
        let bad = recv(ws).unwrap();
        tx.send(bad).unwrap();
        let out = recv(ws).unwrap();
        let create = recv(ws).unwrap();
        tx.send(json!([out, create])).unwrap();
        let _ = recv(ws);
    });
    let m = media(&format!(
        "[realtime.openai_voice]\nvoice = \"marin\"\n{}",
        provider("openai", &url)
    ));
    let mut s = open_voice(&m, Some("openai"), &opts(true)).unwrap();
    assert!(rx.recv().unwrap()["head"]
        .as_str()
        .unwrap()
        .starts_with("GET /realtime?model=gpt-realtime-2.1 "));
    let u = rx.recv().unwrap();
    let sess = &u["session"];
    assert_eq!(
        (
            sess["type"].as_str(),
            sess["model"].as_str(),
            sess["instructions"].as_str()
        ),
        (
            Some("realtime"),
            Some("gpt-realtime-2.1"),
            Some("Be brief.")
        )
    );
    assert_eq!(
        sess["audio"]["input"]["format"],
        json!({"type": "audio/pcm", "rate": 24000})
    );
    assert_eq!(sess["audio"]["output"]["voice"], "marin");
    assert_eq!(
        sess["audio"]["input"]["turn_detection"],
        json!({"type": "server_vad", "threshold": 0.5, "prefix_padding_ms": 300, "silence_duration_ms": 500, "create_response": true, "interrupt_response": true})
    );
    assert_eq!(
        sess["audio"]["input"]["transcription"]["model"],
        "gpt-4o-mini-transcribe"
    );
    assert_eq!(
        (
            sess["tools"][0]["name"].as_str(),
            sess["tool_choice"].as_str()
        ),
        (Some("lookup"), Some("auto"))
    );
    s.send_audio(&vec![7i16; 240]).unwrap();
    let a = rx.recv().unwrap();
    assert_eq!(a["type"], "input_audio_buffer.append");
    assert_eq!(
        crate::store::b64_decode(a["audio"].as_str().unwrap())
            .unwrap()
            .len(),
        480
    );
    let ev = voice_events(s.as_mut(), |v| v.contains(&VoiceEvent::Interrupted));
    assert!(ev
        .iter()
        .any(|e| matches!(e, VoiceEvent::Audio(p) if p.len() == 48000)));
    assert!(ev.contains(&VoiceEvent::Transcript {
        role: "assistant".into(),
        text: "Hi there".into(),
        is_final: true
    }));
    let t = rx.recv().unwrap();
    assert_eq!(
        (
            t["type"].as_str(),
            t["item_id"].as_str(),
            t["content_index"].as_u64()
        ),
        (Some("conversation.item.truncate"), Some("a1"), Some(0))
    );
    let heard = t["audio_end_ms"].as_u64().unwrap();
    assert!((250..2000).contains(&heard), "{heard}");
    let ev = voice_events(s.as_mut(), |v| {
        v.iter().any(|e| matches!(e, VoiceEvent::ToolCall { .. }))
    });
    assert!(ev.contains(&VoiceEvent::Transcript {
        role: "user".into(),
        text: "look it up".into(),
        is_final: true
    }));
    assert!(ev.contains(&VoiceEvent::ToolCall {
        id: "c1".into(),
        name: "lookup".into(),
        args: "{\"q\":\"x\"}".into()
    }));
    assert!(
        !ev.iter()
            .any(|e| matches!(e, VoiceEvent::ToolCall { id, .. } if id == "c2")),
        "non-object args are rejected"
    );
    let bad = rx.recv().unwrap();
    assert_eq!(
        (
            bad["item"]["call_id"].as_str(),
            bad["item"]["output"].as_str()
        ),
        (
            Some("c2"),
            Some("{\"error\":\"Invalid tool arguments: expected a JSON object.\"}")
        )
    );
    assert!(s.tool_result("nope", "{}").is_err());
    s.tool_result("c1", "{\"answer\":42}").unwrap();
    let pair = rx.recv().unwrap();
    assert_eq!(
        pair[0],
        json!({"type": "conversation.item.create", "item": {"type": "function_call_output", "call_id": "c1", "output": "{\"answer\":42}"}})
    );
    assert_eq!(pair[1], json!({"type": "response.create"}));
    s.close();
    let gl = media(&provider("openai", &url));
    let o = VoiceOpts {
        model: Some("gpt-live-1".into()),
        ..opts(false)
    };
    assert!(open_voice(&gl, Some("openai"), &o)
        .err()
        .unwrap()
        .contains("WebRTC only"));
}

#[test]
fn xai_voice_buffers_function_call_arguments() {
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |head, ws| {
        tx.send(json!({"head": head})).unwrap();
        let u = recv(ws).unwrap();
        tx.send(u).unwrap();
        send(ws, json!({"type": "session.updated"}));
        send(ws, json!({"type": "response.created"}));
        send(
            ws,
            json!({"type": "response.function_call_arguments.delta", "item_id": "it1", "call_id": "call1", "name": "lookup", "delta": "{\"q\":"}),
        );
        send(
            ws,
            json!({"type": "response.function_call_arguments.delta", "item_id": "it1", "delta": "\"grok\"}"}),
        );
        send(
            ws,
            json!({"type": "response.function_call_arguments.done", "item_id": "it1"}),
        );
        send(
            ws,
            json!({"type": "response.done", "response": {"status": "completed"}}),
        );
        let t = recv(ws).unwrap();
        let o = recv(ws).unwrap();
        let c = recv(ws).unwrap();
        tx.send(json!([t, o, c])).unwrap();
        let _ = recv(ws);
    });
    let m = media(&provider("xai", &url));
    let mut s = open_voice(
        &m,
        Some("xai"),
        &VoiceOpts {
            sample_rate: 8000,
            ..opts(true)
        },
    )
    .unwrap();
    assert!(rx.recv().unwrap()["head"]
        .as_str()
        .unwrap()
        .starts_with("GET /realtime?model=grok-voice-latest "));
    let u = rx.recv().unwrap()["session"].clone();
    assert_eq!(
        (u["voice"].as_str(), u["output_modalities"][0].as_str()),
        (Some("eve"), Some("audio"))
    );
    assert_eq!(
        u["turn_detection"],
        json!({"type": "server_vad", "threshold": 0.85, "prefix_padding_ms": 333, "silence_duration_ms": 500})
    );
    assert_eq!(
        u["audio"]["input"],
        json!({"format": {"type": "audio/pcmu"}, "transcription": {"model": "grok-transcribe"}})
    );
    let ev = voice_events(s.as_mut(), |v| v.contains(&VoiceEvent::TurnDone));
    assert!(
        ev.contains(&VoiceEvent::ToolCall {
            id: "call1".into(),
            name: "lookup".into(),
            args: "{\"q\":\"grok\"}".into()
        }),
        "{ev:?}"
    );
    // xAI needs every function output before the next response.create.
    s.send_text("never mind").unwrap();
    s.tool_result("call1", "{\"ok\":true}").unwrap();
    let three = rx.recv().unwrap();
    assert_eq!(
        three[0]["item"],
        json!({"type": "message", "role": "user", "content": [{"type": "input_text", "text": "never mind"}]})
    );
    assert_eq!(
        three[1]["item"],
        json!({"type": "function_call_output", "call_id": "call1", "output": "{\"ok\":true}"})
    );
    assert_eq!(three[2], json!({"type": "response.create"}));
}

#[test]
fn gemini_live_setup_audio_transcripts_and_tools() {
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |head, ws| {
        tx.send(json!({"head": head})).unwrap();
        let setup = recv(ws).unwrap();
        tx.send(setup).unwrap();
        ws.send(&Message::Binary(
            json!({"setupComplete": {}}).to_string().into_bytes(),
        ))
        .unwrap();
        let a = recv(ws).unwrap();
        tx.send(a).unwrap();
        let mut seen = vec![];
        loop {
            let v = recv(ws).unwrap();
            let end = v["realtimeInput"]["audioStreamEnd"] == true;
            seen.push(v);
            if end {
                break;
            }
        }
        tx.send(json!(seen)).unwrap();
        let pcm = crate::audio::pcm16_to_bytes(&vec![50i16; 2400]);
        send(
            ws,
            json!({"serverContent": {"inputTranscription": {"text": "what's up"}}}),
        );
        send(
            ws,
            json!({"serverContent": {"modelTurn": {"parts": [{"inlineData": {"mimeType": "audio/pcm;rate=24000", "data": crate::store::b64(&pcm)}}]}, "outputTranscription": {"text": "Not much"}}}),
        );
        send(ws, json!({"serverContent": {"turnComplete": true}}));
        send(
            ws,
            json!({"toolCall": {"functionCalls": [{"id": "f1", "name": "lookup", "args": {"q": "z"}}]}}),
        );
        let r = recv(ws).unwrap();
        tx.send(r).unwrap();
        let t = recv(ws).unwrap();
        tx.send(t).unwrap();
        send(ws, json!({"serverContent": {"interrupted": true}}));
        let _ = recv(ws);
    });
    let m = media(&format!(
        "[providers.google]\napi_key = \"gk\"\nbase_url = \"{}/v1beta\"\n",
        url.replace("ws://", "http://")
    ));
    let mut s = open_voice(&m, Some("gemini-live"), &opts(true)).unwrap();
    let head = rx.recv().unwrap()["head"].as_str().unwrap().to_string();
    assert!(head.starts_with("GET /ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent?key=gk "), "{head}");
    let setup = rx.recv().unwrap()["setup"].clone();
    assert_eq!(setup["model"], "models/gemini-3.1-flash-live-preview");
    assert_eq!(
        setup["generationConfig"],
        json!({"responseModalities": ["AUDIO"], "speechConfig": {"voiceConfig": {"prebuiltVoiceConfig": {"voiceName": "Kore"}}}})
    );
    assert_eq!(
        setup["systemInstruction"],
        json!({"parts": [{"text": "Be brief."}]})
    );
    assert_eq!(
        setup["tools"][0]["functionDeclarations"][0]["name"],
        "lookup"
    );
    assert_eq!(
        (
            setup["inputAudioTranscription"].clone(),
            setup["outputAudioTranscription"].clone()
        ),
        (json!({}), json!({}))
    );
    s.send_audio(&vec![300i16; 480]).unwrap();
    let a = rx.recv().unwrap();
    assert_eq!(
        a["realtimeInput"]["audio"]["mimeType"],
        "audio/pcm;rate=16000"
    );
    assert_eq!(
        crate::store::b64_decode(a["realtimeInput"]["audio"]["data"].as_str().unwrap())
            .unwrap()
            .len(),
        640,
        "24 kHz → 16 kHz"
    );
    for _ in 0..30 {
        s.send_audio(&vec![0i16; 480]).unwrap(); // 20 ms of digital silence each
    }
    let seen = rx.recv().unwrap();
    assert_eq!(
        seen.as_array().unwrap().last().unwrap(),
        &json!({"realtimeInput": {"audioStreamEnd": true}})
    );
    assert_eq!(
        seen.as_array().unwrap().len(),
        26,
        "500 ms of silent frames are streamed, then audioStreamEnd once"
    );
    let ev = voice_events(s.as_mut(), |v| {
        v.iter().any(|e| matches!(e, VoiceEvent::ToolCall { .. }))
    });
    assert_eq!(
        ev[0],
        VoiceEvent::Transcript {
            role: "user".into(),
            text: "what's up".into(),
            is_final: true
        },
        "3.1 sends complete input utterances"
    );
    assert!(ev
        .iter()
        .any(|e| matches!(e, VoiceEvent::Audio(p) if p.len() == 2400)));
    assert!(ev.contains(&VoiceEvent::Transcript {
        role: "assistant".into(),
        text: "Not much".into(),
        is_final: false
    }));
    assert!(ev.contains(&VoiceEvent::Transcript {
        role: "assistant".into(),
        text: "Not much".into(),
        is_final: true
    }));
    assert!(ev.contains(&VoiceEvent::TurnDone));
    assert!(ev.contains(&VoiceEvent::ToolCall {
        id: "f1".into(),
        name: "lookup".into(),
        args: "{\"q\":\"z\"}".into()
    }));
    s.tool_result("f1", "{\"hits\":3}").unwrap();
    assert_eq!(
        rx.recv().unwrap(),
        json!({"toolResponse": {"functionResponses": [{"id": "f1", "name": "lookup", "response": {"output": {"hits": 3}}}]}})
    );
    assert!(
        s.tool_result("f1", "{}").is_err(),
        "each call is answered once"
    );
    s.send_text("hello?").unwrap();
    assert_eq!(
        rx.recv().unwrap(),
        json!({"realtimeInput": {"text": "hello?"}})
    );
    let ev = voice_events(s.as_mut(), |v| v.contains(&VoiceEvent::Interrupted));
    assert!(ev.contains(&VoiceEvent::Interrupted));
    assert!(
        voice::google_ws_url("https://generativelanguage.googleapis.com/v1alpha", "a b")
            .ends_with("v1alpha.GenerativeService.BidiGenerateContent?key=a%20b")
    );
}

#[test]
fn gpt_live_status_session_config_and_webrtc_exchange() {
    let srv = FakeServer::start(|r, _| {
        match r.path.as_str() {
        "/v1/live/sessions" if r.json()["transport"]["sdp"] == "v=0 offer" => (200, vec![], json!({"session": {"id": "sess_1"}, "transport": {"type": "webrtc", "sdp": "v=0 answer"}}).to_string()),
        _ => (400, vec![], "{\"error\":{\"message\":\"bad sdp\"}}".into()),
    }
    });
    let m = media(&format!("[voice]\nvoice_chat_mode = \"gpt_live\"\n[voice.gpt_live]\napi_key = \"lk\"\nbase_url = \"{}/v1\"\nvoice = \"cedar\"\ninstructions = \"Answer in French.\"\n", srv.url));
    let st = live::status(&m);
    assert_eq!(
        st,
        json!({"mode": "gpt-live", "available": true, "reason": null, "model": "gpt-live-1", "voice": "cedar"})
    );
    let hist = json!([{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "earlier"}]}]);
    let c = live::session_config(&m, Some(&hist));
    assert_eq!(c["delegation"], json!({"type": "client"}));
    assert_eq!(c["audio"], json!({"output": {"voice": "cedar"}}));
    assert!(
        c["instructions"]
            .as_str()
            .unwrap()
            .starts_with(live::LIVE_PERSONA)
            && c["instructions"]
                .as_str()
                .unwrap()
                .ends_with("\n\nAnswer in French.")
    );
    assert_eq!(c["input"], hist);
    let ans = live::create_webrtc_session(&m, "v=0 offer", None).unwrap();
    assert_eq!(ans["transport"]["sdp"], "v=0 answer");
    let req = &srv.requests()[0];
    assert_eq!(req.header("authorization"), Some("Bearer lk"));
    assert!(req.json()["session"].get("input").is_none());
    let e = live::create_webrtc_session(&m, "garbage", None).unwrap_err();
    assert!(
        e.starts_with("GPT-Live session creation failed (400): ") && e.contains("bad sdp"),
        "{e}"
    );
    let chained = media("");
    assert_eq!(live::voice_chat_mode(&chained), "chained");
    assert_eq!(live::voice_live_turn_note(""), live::VOICE_LIVE_TURN_NOTE);
    assert!(
        live::voice_live_turn_note("user: book it\nassistant: which day?")
            .ends_with("newest last:\nuser: book it\nassistant: which day?]")
    );
}

#[test]
fn gpt_live_opts_from_config_and_flag_overrides() {
    let m = media("[voice]\nvoice_chat_mode = \"gpt-live\"\n[voice.gpt_live]\napi_key = \"lk\"\nrealtime_provider = \"xai\"\nrealtime_model = \"grok-2-realtime\"\nrealtime_voice = \"eve\"\nsample_rate = 16000\nmax_duration_secs = 12.5\n");
    let o = live::LiveOpts::from_config(&m);
    assert_eq!((o.provider.as_deref(), o.model.as_deref(), o.voice.as_deref()), (Some("xai"), Some("grok-2-realtime"), Some("eve")));
    assert_eq!(o.sample_rate, 16000);
    assert_eq!(o.max_duration, Some(Duration::from_millis(12_500)));
    assert!(!o.stop_on_recorder_end);
    // Flags win over config; absent flags keep it (0 = keep the configured cap).
    let f = live::LiveOpts::from_config(&m).with_flags(Some("google".into()), None, Some("Kore".into()), 0);
    assert_eq!((f.provider.as_deref(), f.model.as_deref(), f.voice.as_deref()), (Some("google"), Some("grok-2-realtime"), Some("Kore")));
    assert_eq!(f.max_duration, Some(Duration::from_millis(12_500)));
    assert_eq!(f.with_flags(None, None, None, 30).max_duration, Some(Duration::from_secs(30)));
    // Nothing configured: provider/model/voice/rate/duration stay at their defaults.
    let d = live::LiveOpts::from_config(&media(""));
    assert_eq!((d.provider, d.model, d.voice, d.sample_rate, d.max_duration), (None, None, None, 0, None));
    assert_eq!(live::status(&m)["mode"], "gpt-live");
}

#[test]
fn gpt_live_terminal_session_delegates_to_the_agent() {
    let dir = temp_dir("gpt-live");
    let out = dir.join("spoken.raw");
    let (tx, rx) = mpsc::channel::<Value>();
    let url = ws_server(move |_, ws| {
        let u = recv(ws).unwrap();
        tx.send(u).unwrap();
        send(ws, json!({"type": "session.updated"}));
        let a = recv(ws).unwrap();
        tx.send(json!({"first": a["type"]})).unwrap();
        send(
            ws,
            json!({"type": "conversation.item.input_audio_transcription.completed", "transcript": "what time is it"}),
        );
        send(ws, json!({"type": "response.created"}));
        send(
            ws,
            json!({"type": "response.done", "response": {"status": "completed", "output": [{"type": "function_call", "id": "x", "call_id": "d1", "name": "delegate_to_agent", "arguments": "{\"request\":\"what time is it\"}"}]}}),
        );
        loop {
            let Some(v) = recv(ws) else { return };
            if v["type"] == "conversation.item.create" {
                tx.send(v).unwrap();
                break;
            }
        }
        let pcm = crate::audio::pcm16_to_bytes(&vec![42i16; 2400]);
        send(ws, json!({"type": "response.created"}));
        send(
            ws,
            json!({"type": "response.output_audio.delta", "item_id": "r2", "delta": crate::store::b64(&pcm)}),
        );
        send(
            ws,
            json!({"type": "response.output_audio_transcript.done", "transcript": "It is noon."}),
        );
        send(
            ws,
            json!({"type": "response.done", "response": {"status": "completed", "output": []}}),
        );
        while recv(ws).is_some() {}
    });
    let m = media(&format!(
        "[voice.gpt_live]\nrecorder = \"head -c 9600 /dev/zero\"\nplayer = \"cat > {}\"\n{}",
        out.display(),
        provider("openai", &url)
    ));
    // The CLI path: `run_with_agent` → delegate closure → one agent turn per tool call.
    struct LiveAgent;
    impl crate::Agent for LiveAgent {
        fn turn(&self, session: Option<&str>, text: &str, source: &str, _c: &Cancel) -> Result<(String, String), String> {
            assert_eq!(session, None);
            assert_eq!(source, "voice-live");
            assert!(
                text.starts_with(live::VOICE_LIVE_TURN_NOTE) && text.contains("user: what time is it") && text.ends_with("what time is it"),
                "{text}"
            );
            Ok(("s-live".to_string(), "It is 12:00.".to_string()))
        }
    }
    let o = live::LiveOpts {
        stop_on_recorder_end: true,
        max_duration: Some(Duration::from_secs(10)),
        ..Default::default()
    };
    let rep = live::run_with_agent(&m, &o, std::sync::Arc::new(LiveAgent), &Cancel::new()).unwrap();
    let u = rx.recv().unwrap();
    assert_eq!(u["session"]["tools"][0]["name"], live::DELEGATE_TOOL);
    assert!(u["session"]["instructions"]
        .as_str()
        .unwrap()
        .starts_with("You are ark"));
    assert_eq!(
        rx.recv().unwrap(),
        json!({"first": "input_audio_buffer.append"})
    );
    let out_item = rx.recv().unwrap();
    assert_eq!(out_item["item"]["call_id"], "d1");
    assert_eq!(
        out_item["item"]["output"],
        json!({"result": "It is 12:00."}).to_string()
    );
    assert_eq!(rep.delegations, 1);
    assert_eq!(
        rep.transcript,
        vec![
            ("user".to_string(), "what time is it".to_string()),
            ("assistant".to_string(), "It is noon.".to_string())
        ]
    );
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(
        std::fs::read(&out).unwrap().len(),
        4800,
        "assistant audio reached the player"
    );
}
