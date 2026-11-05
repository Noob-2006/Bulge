use super::*;
use crate::genrt::test_support::{MP3, PNG};
use crate::testutil::{cfg_for, ctx, FakeServer};

fn raw(ct: &str, b: Vec<u8>) -> (u16, Vec<(String, String)>, Vec<u8>) {
    (200, vec![("content-type".into(), ct.into())], b)
}

fn serve() -> FakeServer {
    let base = Arc::new(std::sync::Mutex::new(String::new()));
    let b2 = base.clone();
    let srv = FakeServer::start_raw(move |r, _| {
        let base = b2.lock().unwrap().clone();
        let hex: String = MP3.iter().map(|b| format!("{b:02x}")).collect();
        match r.path.as_str() {
            "/out/a.mp3" => raw("audio/mpeg", MP3.to_vec()),
            p if p.ends_with(":generateContent") => raw("application/json", json!({"candidates": [{"content": {"parts": [{"text": "la la"}, {"inlineData": {"mimeType": "audio/mpeg", "data": store::b64(MP3)}}]}}]}).to_string().into_bytes()),
            "/fal-ai/minimax-music/v2.6" => raw("application/json", json!({"audio": {"url": format!("{base}/out/a.mp3"), "content_type": "audio/mpeg"}, "seed": 4, "lyrics": "x"}).to_string().into_bytes()),
            p if p.starts_with("/fal-ai/stable-audio-25") || p.starts_with("/fal-ai/ace-step") => raw("application/json", json!({"audio": {"url": format!("{base}/out/a.mp3"), "content_type": "audio/mpeg"}}).to_string().into_bytes()),
            "/v1/music_generation" => raw("text/event-stream", format!("data: {{\"data\":{{\"audio\":\"{}\",\"status\":1}},\"base_resp\":{{\"status_code\":0}}}}\n\ndata: {{\"data\":{{\"audio\":\"{}\",\"status\":1}}}}\n\ndata: {{\"data\":{{\"status\":2}}}}\n\n", &hex[..8], &hex[8..]).into_bytes()),
            "/chat/completions" => {
                let b = store::b64(MP3);
                let (a, c) = b.split_at(5);
                raw("text/event-stream", format!("data: {{\"choices\":[{{\"delta\":{{\"audio\":{{\"data\":\"{a}\",\"transcript\":\"verse \"}}}}}}]}}\n\ndata: {{\"choices\":[{{\"delta\":{{\"audio\":{{\"data\":\"{c}\",\"transcript\":\"one\"}}}}}}]}}\n\ndata: [DONE]\n\n").into_bytes())
            }
            _ => (404, vec![], b"no".to_vec()),
        }
    });
    *base.lock().unwrap() = srv.url.clone();
    srv
}

fn media(id: &str, base: &str, extra: &str) -> Media {
    Media { cfg: cfg_for(id, base, extra), http: Default::default() }
}

fn req(model: &str) -> MusicRequest {
    MusicRequest { prompt: "lofi beat".into(), model: model.into(), timeout: Duration::from_secs(5), ..Default::default() }
}

#[test]
fn providers_request_shapes_and_streams() {
    let srv = serve();
    let c = Cancel::new();
    let mut r = req("lyria-3-clip-preview");
    r.instrumental = Some(true);
    r.images = vec![Source { asset: Asset::new(PNG.to_vec(), "image/png"), role: None }];
    let out = Google.generate(&media("google", &srv.url, ""), &r, &c).unwrap();
    assert_eq!((out.tracks[0].bytes.as_slice(), out.lyrics.clone()), (MP3, vec!["la la".to_string()]));
    let b = srv.requests().into_iter().find(|q| q.path.ends_with(":generateContent")).unwrap();
    assert_eq!(b.header("x-goog-api-key"), Some("k"));
    let j = b.json();
    assert!(j["contents"][0]["parts"][0]["text"].as_str().unwrap().contains("Instrumental only."));
    assert_eq!(j["contents"][0]["parts"][1]["inlineData"]["mimeType"], "image/png");
    r.format = Some("wav".into());
    assert!(Google.generate(&media("google", &srv.url, ""), &r, &c).unwrap_err().contains("supports mp3 output"));

    let mut r = req(FAL_MM);
    r.duration = Some(30);
    let out = Fal.generate(&media("fal", &srv.url, ""), &r, &c).unwrap();
    assert_eq!((out.tracks[0].bytes.as_slice(), out.meta["seed"].clone()), (MP3, json!(4)));
    let j = srv.requests().into_iter().find(|q| q.path == "/fal-ai/minimax-music/v2.6").unwrap();
    assert_eq!(j.header("authorization"), Some("Key k"));
    assert_eq!((j.json()["lyrics_optimizer"].clone(), j.json()["audio_setting"]["format"].clone(), j.json()["duration"].clone()), (json!(true), json!("mp3"), json!(30)));
    let mut sa = req(FAL_SA);
    sa.duration = Some(12);
    assert_eq!(fal_body(&sa).unwrap()["seconds_total"], json!(12));
    sa.lyrics = Some("words".into());
    assert!(fal_body(&sa).unwrap_err().contains("Stable Audio music generation does not support explicit lyrics"));

    let out = Minimax.generate(&media("minimax", &srv.url, ""), &req("music-2.6"), &c).unwrap();
    assert_eq!(out.tracks[0].bytes, MP3, "hex SSE frames are concatenated");
    let mut bad = req("music-2.6");
    bad.lyrics = Some("a".into());
    bad.instrumental = Some(true);
    assert!(Minimax.generate(&media("minimax", &srv.url, ""), &bad, &c).unwrap_err().contains("cannot use lyrics when instrumental"));

    let mut r = req("google/lyria-3-pro-preview");
    r.duration = Some(60);
    r.format = Some("mp3".into());
    let out = OpenRouter.generate(&media("openrouter", &srv.url, ""), &r, &c).unwrap();
    assert_eq!((out.tracks[0].bytes.as_slice(), out.tracks[0].mime.as_str(), out.lyrics.clone()), (MP3, "audio/mpeg", vec!["verse one".to_string()]));
    let j = srv.requests().into_iter().find(|q| q.path == "/chat/completions").unwrap().json();
    assert_eq!((j["stream"].clone(), j["audio"]["format"].clone()), (json!(true), json!("mp3")));
    assert!(j["messages"][0]["content"].as_str().unwrap().contains("Target duration: about 60 seconds."));
}

#[test]
fn runtime_drops_unsupported_and_falls_back() {
    let srv = serve();
    let m = media("minimax", &srv.url, &format!("[providers.fal]\napi_key = \"k\"\nbase_url = \"{}\"\n", srv.url));
    let mut r = req("");
    r.images = vec![Source { asset: Asset::new(PNG.to_vec(), "image/png"), role: None }];
    let cands: Vec<(Arc<dyn MusicProvider>, String)> = vec![(Arc::new(Minimax), "music-2.6".into()), (Arc::new(Fal), FAL_MM.into())];
    let e = generate(&m, &r, &cands, &Cancel::new()).unwrap_err();
    assert!(e.contains("minimax/music-2.6 does not support reference image inputs") && e.contains("fal/fal-ai/minimax-music/v2.6"), "{e}");
    let mut r = req("");
    r.duration = Some(99);
    r.format = Some("wav".into());
    let out = generate(&m, &r, &cands, &Cancel::new()).unwrap();
    assert_eq!(out.provider, "minimax");
    assert!(out.notes.iter().any(|n| n == "ignored unsupported durationSeconds=99") && out.notes.iter().any(|n| n == "ignored unsupported format=wav"), "{:?}", out.notes);
    let fal_only: Vec<(Arc<dyn MusicProvider>, String)> = vec![(Arc::new(Fal), FAL_MM.into())];
    let mut r = req("");
    r.duration = Some(500);
    let out = generate(&m, &r, &fal_only, &Cancel::new()).unwrap();
    assert!(out.notes.iter().any(|n| n.contains("500 → 240")));
}

#[test]
fn music_tool_saves_and_validates() {
    let srv = serve();
    let m = Arc::new(media("minimax", &srv.url, "[music]\nprovider = \"minimax\"\n"));
    let t = MusicGenerate { m: m.clone() };
    let c = ctx("music-tool");
    assert!(t.call(&c, json!({"prompt": "x", "format": "ogg"})).content.contains("format must be one of"));
    let out = t.call(&c, json!({"prompt": "chill", "filename": "song.mp3", "timeoutMs": 10}));
    assert!(!out.is_error, "{}", out.content);
    assert!(out.content.contains("Timeout normalized: requested 10ms; used 120000ms."));
    let p = out.content.lines().find_map(|l| l.strip_prefix("MEDIA:")).unwrap();
    assert!(p.ends_with("song.mp3"));
    assert_eq!(std::fs::read(p).unwrap(), MP3);
    let l = t.call(&c, json!({"action": "list"})).content;
    assert!(l.contains("- minimax (MiniMax) ✓") && l.contains("- comfy (ComfyUI) ✗"), "{l}");
    assert_eq!(providers().len(), 5);
}

/// Google Lyria: a text-only (unblocked) payload is retried once, then the block/finish
/// reason is reported (upstream `resolveTerminalNoAudioReason`).
#[test]
fn google_retries_once_then_reports_block_and_finish_reasons() {
    let c = Cancel::new();
    let text_only = |n: usize| {
        let extra = if n == 0 { json!({}) } else { json!({"finishReason": "SAFETY"}) };
        let mut cand = json!({"content": {"parts": [{"text": "no audio here"}]}});
        if let Some(o) = extra.as_object() {
            for (k, v) in o {
                cand[k.as_str()] = v.clone();
            }
        }
        (200, vec![], json!({"candidates": [cand]}).to_string().into_bytes())
    };
    let srv = FakeServer::start_raw(move |r, n| {
        if r.path.ends_with(":generateContent") {
            text_only(n)
        } else {
            (404, vec![], vec![])
        }
    });
    let e = Google.generate(&media("google", &srv.url, ""), &req("lyria-3-clip-preview"), &c).unwrap_err();
    assert!(e.contains("generation stopped (SAFETY)"), "{e}");
    assert_eq!(srv.requests().len(), 2, "text-only Lyria answers are retried exactly once");

    // A block reason is terminal on the first attempt (never retried).
    let blocked = FakeServer::start_raw(|_, _| (200, vec![], json!({"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}, "candidates": []}).to_string().into_bytes()));
    let e = Google.generate(&media("google", &blocked.url, ""), &req("lyria-3-clip-preview"), &c).unwrap_err();
    assert!(e.contains("prompt blocked (PROHIBITED_CONTENT)"), "{e}");
    assert_eq!(blocked.requests().len(), 1);

    // Neither blocked nor stopped: two empty answers end in "missing audio data".
    let empty = FakeServer::start_raw(|_, _| (200, vec![], json!({"candidates": [{"content": {"parts": [{"text": "hmm"}]}}]}).to_string().into_bytes()));
    let e = Google.generate(&media("google", &empty.url, ""), &req("lyria-3-clip-preview"), &c).unwrap_err();
    assert!(e.contains("response missing audio data"), "{e}");
    assert_eq!(empty.requests().len(), 2);
}

/// MiniMax JSON responses (url or inline hex) and the OpenRouter stream error paths.
#[test]
fn minimax_json_payloads_and_openrouter_stream_errors() {
    let base = Arc::new(std::sync::Mutex::new(String::new()));
    let b2 = base.clone();
    let srv = FakeServer::start_raw(move |r, _| {
        let base = b2.lock().unwrap().clone();
        match r.path.as_str() {
            "/out/a.mp3" => (200, vec![("content-type".into(), "audio/mpeg".into())], MP3.to_vec()),
            "/json/v1/music_generation" => (200, vec![("content-type".into(), "application/json".into())], json!({"base_resp": {"status_code": 0}, "task_id": "t-1", "audio_url": format!("{base}/out/a.mp3"), "lyrics": "6869"}).to_string().into_bytes()),
            "/inline/v1/music_generation" => (200, vec![("content-type".into(), "application/json".into())], format!("{{\"base_resp\":{{\"status_code\":0}},\"audio\":\"{}\"}}", "494433").into_bytes()),
            "/broke/v1/music_generation" => (200, vec![("content-type".into(), "application/json".into())], json!({"base_resp": {"status_code": 1004, "status_msg": "invalid api key"}, "audio": ""}).to_string().into_bytes()),
            "/trunc/v1/music_generation" => (200, vec![("content-type".into(), "text/event-stream".into())], b"data: {\"data\":{\"audio\":\"4944\",\"status\":1}}\n\n".to_vec()),
            "/err/chat/completions" => (200, vec![("content-type".into(), "text/event-stream".into())], b"data: {\"error\":{\"message\":\"boom\"}}\n\n".to_vec()),
            "/trunc/chat/completions" => (200, vec![("content-type".into(), "text/event-stream".into())], b"data: {\"choices\":[{\"delta\":{\"audio\":{\"data\":\"AAAA\"}}}]}\n\n".to_vec()),
            "/empty/chat/completions" => (200, vec![("content-type".into(), "text/event-stream".into())], b"data: [DONE]\n\n".to_vec()),
            _ => (404, vec![], vec![]),
        }
    });
    *base.lock().unwrap() = srv.url.clone();
    let c = Cancel::new();
    let out = Minimax.generate(&media("minimax", &format!("{}/json", srv.url), ""), &req("music-2.6"), &c).unwrap();
    assert_eq!(out.tracks[0].bytes, MP3);
    assert_eq!((out.lyrics.clone(), out.meta["taskId"].clone(), out.meta["audioUrl"].clone()), (vec!["hi".to_string()], json!("t-1"), json!(format!("{}/out/a.mp3", srv.url))));
    let out = Minimax.generate(&media("minimax", &format!("{}/inline", srv.url), ""), &req("music-2.6"), &c).unwrap();
    assert_eq!((out.tracks[0].bytes.as_slice(), out.meta["requestedLyrics"].clone()), (&b"ID3"[..], Value::Null));
    assert!(Minimax.generate(&media("minimax", &format!("{}/broke", srv.url), ""), &req("music-2.6"), &c).unwrap_err().contains("invalid api key (status_code 1004)"));
    assert!(Minimax.generate(&media("minimax", &format!("{}/trunc", srv.url), ""), &req("music-2.6"), &c).unwrap_err().contains("stream ended without completion"));
    assert!(OpenRouter.generate(&media("openrouter", &format!("{}/err", srv.url), ""), &req("google/lyria-3-pro-preview"), &c).unwrap_err().contains("OpenRouter music generation failed: boom"));
    assert!(OpenRouter.generate(&media("openrouter", &format!("{}/trunc", srv.url), ""), &req("google/lyria-3-pro-preview"), &c).unwrap_err().contains("stream ended before completion"));
    assert!(OpenRouter.generate(&media("openrouter", &format!("{}/empty", srv.url), ""), &req("google/lyria-3-pro-preview"), &c).unwrap_err().contains("missing audio data"));
}

/// ComfyUI music workflows are reachable through `music_gen::tools()` (submit → history → view).
#[test]
fn comfy_music_reached_through_the_tool() {
    crate::genrt::test_support::fast_poll();
    let srv = FakeServer::start_raw(|r, _| match r.path.as_str() {
        "/prompt" => (200, vec![], json!({"prompt_id": "job-7"}).to_string().into_bytes()),
        "/history/job-7" => (200, vec![], json!({"job-7": {"outputs": {"9": {"audio": [{"filename": "song.mp3", "subfolder": "", "type": "output"}]}}}}).to_string().into_bytes()),
        p if p.starts_with("/view?") => (200, vec![("content-type".into(), "audio/mpeg".into())], MP3.to_vec()),
        _ => (404, vec![], vec![]),
    });
    let cfg = crate::MediaConfig::from_toml(&format!(
        "[music]\nprovider = \"comfy\"\n[providers.comfy]\nbase_url = \"{}\"\nworkflow = {{ \"6\" = {{ inputs = {{ text = \"\" }} }}, \"9\" = {{ inputs = {{}} }} }}\nprompt_node_id = \"6\"\noutput_node_id = \"9\"\n",
        srv.url
    ));
    let m = Arc::new(Media { cfg, http: Default::default() });
    let t = tools(&m).into_iter().next().unwrap();
    let c = ctx("music-comfy");
    let out = t.call(&c, json!({"prompt": "gentle ambient loop", "provider": "comfy"}));
    assert!(!out.is_error, "{}", out.content);
    let body: Value = serde_json::from_str(out.content.split("\nMEDIA:").next().unwrap()).unwrap();
    assert_eq!((body["provider"].clone(), body["metadata"]["promptId"].clone(), body["metadata"]["outputNodeIds"].clone()), (json!("comfy"), json!("job-7"), json!(["9"])));
    let p = out.content.lines().find_map(|l| l.strip_prefix("MEDIA:")).unwrap();
    assert_eq!(std::fs::read(p).unwrap(), MP3);
    let submit = srv.requests().into_iter().find(|q| q.path == "/prompt").unwrap().json();
    assert_eq!((submit["prompt"]["6"]["inputs"]["text"].clone(), submit["prompt"]["9"]["inputs"].clone()), (json!("gentle ambient loop"), json!({})));
}

/// Every built-in provider resolves through the same registry the tool uses.
#[test]
fn every_music_provider_is_reachable_through_the_tool() {
    let srv = serve();
    let cases: &[(&str, &str)] = &[("google", "lyria-3-clip-preview"), ("fal", FAL_MM), ("minimax", "music-2.6"), ("openrouter", "google/lyria-3-pro-preview")];
    let list = MusicGenerate { m: Arc::new(media("minimax", &srv.url, "")) }.call(&ctx("music-tool-list"), json!({"action": "list"})).content;
    for id in ["google", "fal", "minimax", "openrouter", "comfy"] {
        assert!(list.contains(&format!("- {id} (")), "action=list must offer `{id}`:\n{list}");
    }
    for (id, model) in cases {
        let m = Arc::new(media(id, &srv.url, &format!("[music]\nprovider = \"{id}\"\n")));
        let c = ctx(&format!("music-tool-{id}"));
        let out = MusicGenerate { m }.call(&c, json!({"prompt": "lofi beat", "provider": id, "model": model}));
        assert!(!out.is_error, "{id} through the tool: {}", out.content);
        let v: Value = serde_json::from_str(out.content.split("\nMEDIA:").next().unwrap()).unwrap_or_else(|e| panic!("{id}: {e}: {}", out.content));
        assert_eq!(v["provider"], json!(id), "{}", out.content);
        let p = out.content.lines().find_map(|l| l.strip_prefix("MEDIA:")).unwrap_or_else(|| panic!("{id} saved no track: {}", out.content));
        assert_eq!(std::fs::read(p).unwrap(), MP3, "{id}");
    }
}

#[test]
fn every_provider_is_reachable_through_the_tool_registry() {
    let m = media("minimax", "http://127.0.0.1:1", "");
    for id in ["google", "gemini", "lyria", "fal", "minimax", "openrouter", "comfy", "comfyui"] {
        let c = genrt::candidates(&m, "music", &providers(), Some(id), None).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(c.len(), 1, "{id}");
        assert!(!c[0].1.is_empty(), "{id} has a default model");
    }
    match genrt::candidates(&m, "music", &providers(), Some("nope"), None) {
        Err(e) => assert!(e.contains("Unknown music-generation provider: nope"), "{e}"),
        Ok(_) => panic!("unknown provider must not resolve"),
    }
}

/// The runtime reports dropped lyrics/instrumental and the tool dedupes reference images.
#[test]
fn runtime_drops_lyrics_and_instrumental_and_dedupes_images() {
    let srv = serve();
    let m = media("fal", &srv.url, "");
    let cands: Vec<(Arc<dyn MusicProvider>, String)> = vec![(Arc::new(Fal), FAL_SA.into())];
    let mut r = req("");
    r.lyrics = Some("words".into());
    r.instrumental = Some(true);
    let out = generate(&m, &r, &cands, &Cancel::new()).unwrap();
    assert!(out.notes.iter().any(|n| n == "ignored unsupported lyrics"), "{:?}", out.notes);
    assert!(out.notes.iter().any(|n| n == "ignored unsupported instrumental=true"), "{:?}", out.notes);
    let sent = srv.requests().into_iter().find(|q| q.path == "/fal-ai/stable-audio-25/text-to-audio").unwrap().json();
    assert_eq!((sent["lyrics"].clone(), sent["instrumental"].clone()), (Value::Null, Value::Null));

    let c = ctx("music-dedupe");
    std::fs::write(c.workspace.join("a.png"), PNG).unwrap();
    let t = MusicGenerate { m: Arc::new(media("google", &srv.url, "")) };
    let (deduped, _) = t
        .build(&c, &json!({"prompt": "p", "images": ["a.png", "a.png", "@a.png"], "durationSeconds": 3}))
        .unwrap();
    assert_eq!(deduped.images.len(), 1, "duplicate references collapse like upstream");
    assert_eq!((deduped.duration, deduped.timeout), (Some(3), Duration::from_secs(300)));
    assert!(t.build(&c, &json!({"prompt": "p", "images": ["a.png", "b.png", "c.png", "d.png", "e.png", "f.png", "g.png", "h.png", "i.png", "j.png", "k.png"]})).unwrap_err().contains("maximum is 10"));
}
