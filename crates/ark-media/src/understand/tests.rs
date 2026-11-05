use super::*;
use crate::genrt::test_support::{MP3, MP4, PNG};
use crate::testutil::{ctx, FakeServer};

struct FakeLlm {
    vision: bool,
    seen: std::sync::Mutex<Vec<usize>>,
}

impl crate::Llm for FakeLlm {
    fn complete(&self, _m: Option<&str>, _s: &str, msgs: Vec<Message>, _t: u32, _c: &Cancel) -> Result<String, String> {
        let n = msgs[0].content.iter().filter(|b| matches!(b, Block::Image { .. })).count();
        self.seen.lock().unwrap().push(n);
        Ok(format!("saw {n} image(s)"))
    }
    fn vision(&self, _m: Option<&str>) -> bool {
        self.vision
    }
}

fn server() -> FakeServer {
    FakeServer::start(|r, _| match r.path.as_str() {
        p if p.ends_with(":generateContent") => (200, vec![], json!({"candidates": [{"content": {"parts": [{"text": "A clip of waves."}]}}]}).to_string()),
        "/chat/completions" => {
            let model = serde_json::from_str::<Value>(&r.body).ok().and_then(|v| v["model"].as_str().map(str::to_string)).unwrap_or_default();
            (200, vec![], json!({"model": model, "choices": [{"message": {"content": [{"type": "text", "text": "chat says hi"}]}}]}).to_string())
        }
        "/v1/messages" => (200, vec![], json!({"content": [{"type": "text", "text": "claude sees a square"}]}).to_string()),
        "/clip.mp4" => (200, vec![("content-type".into(), "video/mp4".into())], String::from_utf8_lossy(MP4).into_owned()),
        _ => (500, vec![], "{\"error\":{\"message\":\"model does not support video input\"}}".into()),
    })
}

fn media(toml: &str) -> Media {
    Media { cfg: crate::MediaConfig::from_toml(toml), http: Default::default() }
}

#[test]
fn describers_request_shapes_and_selection() {
    let srv = server();
    let m = media(&format!("[providers.google]\napi_key = \"g\"\nbase_url = \"{0}\"\n[providers.openrouter]\napi_key = \"o\"\nbase_url = \"{0}\"\n[providers.anthropic]\napi_key = \"a\"\nbase_url = \"{0}\"\n[understanding]\nimage_provider = \"anthropic\"\n", srv.url));
    let req = DescribeRequest { bytes: PNG.to_vec(), mime: "image/png".into(), prompt: "what?".into(), model: None, max_tokens: 100 };
    let (p, t) = describe(&m, "image", &req, &Cancel::new()).unwrap();
    assert_eq!((p.as_str(), t.as_str()), ("anthropic", "claude sees a square"));
    let q = srv.requests().into_iter().find(|q| q.path == "/v1/messages").unwrap();
    assert_eq!((q.header("x-api-key"), q.header("anthropic-version")), (Some("a"), Some("2023-06-01")));
    assert_eq!(q.json()["messages"][0]["content"][0]["source"]["media_type"], "image/png");
    // A provider/model override picks that provider.
    let r2 = DescribeRequest { model: Some("openrouter/google/gemini-2.5-flash".into()), ..req.clone() };
    assert_eq!(describe(&m, "image", &r2, &Cancel::new()).unwrap(), ("openrouter".to_string(), "chat says hi".to_string()));
    let c = srv.requests().into_iter().find(|q| q.path == "/chat/completions").unwrap().json();
    assert_eq!((c["model"].as_str(), c["messages"][0]["content"][1]["type"].as_str()), (Some("google/gemini-2.5-flash"), Some("image_url")));
    // Video: auto picks the first configured video describer (Gemini inline_data).
    let v = DescribeRequest { bytes: MP4.to_vec(), mime: "video/mp4".into(), prompt: "p".into(), model: None, max_tokens: 100 };
    assert_eq!(describe(&m, "video", &v, &Cancel::new()).unwrap().0, "google");
    let g = srv.requests().into_iter().find(|q| q.path.ends_with(":generateContent")).unwrap();
    assert_eq!(g.header("x-goog-api-key"), Some("g"));
    assert_eq!(g.json()["contents"][0]["parts"][1]["inline_data"]["mime_type"], "video/mp4");
    assert!(describe(&m, "video", &DescribeRequest { model: Some("anthropic/x".into()), ..v.clone() }, &Cancel::new()).unwrap_err().contains("cannot describe videos"));
    // Custom OpenAI-compatible endpoints from [media.understanding.providers.<id>].
    let local = media(&format!("[understanding]\nimage_provider = \"llamacpp\"\n[understanding.providers.llamacpp]\nbase_url = \"{}\"\nmodel = \"qwen-vl\"\n", srv.url));
    assert_eq!(describe(&local, "image", &req, &Cancel::new()).unwrap(), ("llamacpp".to_string(), "chat says hi".to_string()));
}

#[test]
fn new_providers_are_listed_with_their_defaults() {
    let ds = describers();
    let ids: Vec<&str> = ds.iter().map(|d| d.id()).collect();
    for id in ["google", "openai", "anthropic", "openrouter", "deepinfra", "minimax", "zai", "qwen", "moonshot", "ollama", "llama-cpp"] {
        assert!(ids.contains(&id), "{id} missing from {ids:?}");
    }
    let mut uniq = ids.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(uniq.len(), ids.len(), "duplicate provider ids: {ids:?}");
    let m = media("[providers.deepinfra]\napi_key = \"d\"\n[providers.minimax]\napi_key = \"m\"\n[providers.zai]\napi_key = \"z\"\n[providers.qwen]\napi_key = \"q\"\n[providers.moonshot]\napi_key = \"k\"\n");
    let want: &[(&str, &str)] = &[("deepinfra", "moonshotai/Kimi-K2.6"), ("minimax", "MiniMax-VL-01"), ("zai", "glm-4.6v"), ("qwen", "qwen3.6-plus"), ("moonshot", "kimi-k2.6")];
    for (id, model) in want {
        let d = ds.iter().find(|d| d.id() == *id).unwrap_or_else(|| panic!("{id} missing"));
        assert!(d.configured(&m), "{id} is configured by [providers.{id}] api_key");
        assert_eq!(d.default_model("image"), *model, "{id} image default");
    }
    // Video capability: only the providers that declare a video model.
    for id in ["qwen", "moonshot"] {
        let d = ds.iter().find(|d| d.id() == id).unwrap();
        assert!(d.video(), "{id} declares video");
        assert!(!d.default_model("video").is_empty(), "{id} video default");
    }
    let qwen = ds.iter().find(|d| d.id() == "qwen").unwrap();
    assert_eq!(qwen.default_model("video"), "qwen3.6-plus");
    for id in ["deepinfra", "minimax", "zai", "ollama", "llama-cpp"] {
        assert!(!ds.iter().find(|d| d.id() == id).unwrap().video(), "{id} is image only");
    }
    // Keyless local endpoints: no env vars, no model for ollama, llama.cpp's llama-server model.
    let empty = media("");
    for (id, base, model) in [
        ("ollama", "http://127.0.0.1:11434/v1", ""),
        ("llama-cpp", "http://127.0.0.1:19432/v1", "gemma-4-e4b-it-q4_k_m"),
    ] {
        let d = ds.iter().find(|d| d.id() == id).unwrap();
        assert!(d.env().is_empty(), "{id} needs no API key");
        assert_eq!(d.base(), base, "{id} base");
        assert_eq!(d.default_model("image"), model, "{id} image default");
        assert!(d.local(), "{id} is local");
        assert!(!d.configured(&empty), "{id} must not be auto-configured by default");
    }
    assert!(ds.iter().find(|d| d.id() == "ollama").unwrap().configured(&media("[understanding.providers.ollama]\nmodel = \"qwen3-vl\"\n")), "an explicit provider table opts ollama in");
}

#[test]
fn request_shape_per_provider() {
    let srv = server();
    let req = DescribeRequest { bytes: PNG.to_vec(), mime: "image/png".into(), prompt: "what?".into(), model: None, max_tokens: 100 };
    let cases: &[(&str, &str)] = &[("deepinfra", "moonshotai/Kimi-K2.6"), ("minimax", "MiniMax-VL-01"), ("zai", "glm-4.6v"), ("qwen", "qwen3.6-plus"), ("moonshot", "kimi-k2.6")];
    for (id, model) in cases {
        let m = media(&format!("[understanding]\nimage_provider = \"{id}\"\n[providers.{id}]\napi_key = \"{id}-key\"\nbase_url = \"{}\"\n", srv.url));
        let (p, t) = describe(&m, "image", &req, &Cancel::new()).unwrap();
        assert_eq!((p.as_str(), t.as_str()), (*id, "chat says hi"));
        let q = srv.requests().into_iter().rev().find(|q| q.path == "/chat/completions").unwrap_or_else(|| panic!("{id}: no chat request"));
        let bearer = format!("Bearer {id}-key");
        assert_eq!(q.header("authorization"), Some(bearer.as_str()), "{id} bearer");
        let body = q.json();
        assert_eq!(body["model"], json!(model), "{id} model");
        assert_eq!(body["messages"][0]["content"][1]["type"], json!("image_url"), "{id} image part");
        assert!(body["messages"][0]["content"][1]["image_url"]["url"].as_str().unwrap().starts_with("data:image/png;base64,"), "{id} data url");
    }
}

#[test]
fn local_providers_need_an_explicit_selection_and_model() {
    let srv = server();
    let req = DescribeRequest { bytes: PNG.to_vec(), mime: "image/png".into(), prompt: "p".into(), model: None, max_tokens: 100 };
    // Empty config: the keyless local endpoints must not join the `auto` chain.
    let e = describe_with(&media(""), "image", &req, None, &Cancel::new()).unwrap_err();
    assert!(e.contains("no media-understanding provider available"), "{e}");
    assert!(srv.requests().is_empty(), "nothing is sent");
    // Explicitly selected but no model: a clear, actionable error.
    let m = media("[understanding]\nimage_provider = \"ollama\"\n");
    let e = describe_with(&m, "image", &req, None, &Cancel::new()).unwrap_err();
    assert!(e.contains("ollama image understanding requires a model id"), "{e}");
    assert!(e.contains("[media.understanding] image_model") && e.contains("[media.understanding.providers.ollama] model"), "{e}");
    assert!(srv.requests().is_empty(), "nothing is sent without a model");
    // A provider table supplies the local base URL and the model.
    let m = media(&format!("[understanding]\nimage_provider = \"ollama\"\n[understanding.providers.ollama]\nbase_url = \"{}\"\nmodel = \"qwen3-vl\"\n", srv.url));
    assert_eq!(describe_with(&m, "image", &req, None, &Cancel::new()).unwrap(), ("ollama".to_string(), "chat says hi".to_string()));
    let q = srv.requests().into_iter().find(|q| q.path == "/chat/completions").unwrap();
    assert_eq!(q.header("authorization"), None, "local endpoints need no key");
    assert_eq!(q.json()["model"], json!("qwen3-vl"));
    // The provider table is the opt-in: `auto` may now use the local endpoint (and its default model).
    let m = media(&format!("[understanding.providers.llama-cpp]\nbase_url = \"{}\"\n", srv.url));
    assert_eq!(describe_with(&m, "image", &req, None, &Cancel::new()).unwrap(), ("llama-cpp".to_string(), "chat says hi".to_string()));
    assert_eq!(srv.requests().into_iter().rev().find(|q| q.path == "/chat/completions").unwrap().json()["model"], json!("gemma-4-e4b-it-q4_k_m"));
}

#[test]
fn capability_listing_shows_new_video_providers() {
    let m = Arc::new(media(""));
    let ws = ctx("cli-new-providers").workspace;
    let a = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
    let vp: Value = serde_json::from_str(&cli::cli(&m, &a("video providers --json"), &ws).unwrap()).unwrap();
    let desc = vp["description"].as_array().unwrap();
    for (id, model) in [("qwen", "qwen3.6-plus"), ("moonshot", "kimi-k2.6")] {
        let d = desc.iter().find(|d| d["id"] == id).unwrap_or_else(|| panic!("{id} missing from {desc:?}"));
        assert_eq!(d["defaultModel"], json!(model), "{id} video default");
    }
    let text = cli::cli(&m, &a("video providers"), &ws).unwrap();
    assert!(text.contains("qwen") && text.contains("moonshot"), "{text}");
}

#[test]
fn agent_model_fallback_for_images_and_errors_without_vision() {
    let m = media("");
    let req = DescribeRequest { bytes: PNG.to_vec(), mime: "image/png".into(), prompt: "p".into(), model: None, max_tokens: 10 };
    let l = Arc::new(FakeLlm { vision: true, seen: Default::default() });
    assert_eq!(describe_with(&m, "image", &req, Some(l.clone()), &Cancel::new()).unwrap(), ("agent".to_string(), "saw 1 image(s)".to_string()));
    let blind = Arc::new(FakeLlm { vision: false, seen: Default::default() });
    assert!(describe_with(&m, "image", &req, Some(blind), &Cancel::new()).unwrap_err().contains("no vision input"));
    assert!(describe_with(&m, "image", &req, None, &Cancel::new()).unwrap_err().contains("no media-understanding provider available"));
}

#[test]
fn video_analyze_tool_formats_and_errors() {
    let srv = server();
    let m = Arc::new(media(&format!("[providers.google]\napi_key = \"g\"\nbase_url = \"{}\"\n", srv.url)));
    let t = VideoAnalyze { m: m.clone() };
    let c = ctx("video-analyze");
    std::fs::write(c.workspace.join("a.mp4"), MP4).unwrap();
    std::fs::write(c.workspace.join("a.gif"), b"GIF89a").unwrap();
    let ok = t.call(&c, json!({"video_url": "a.mp4", "question": "what happens?"}));
    let v: Value = serde_json::from_str(&ok.content).unwrap();
    assert_eq!((v["success"].clone(), v["analysis"].clone()), (json!(true), json!("A clip of waves.")));
    let sent = srv.requests().into_iter().find(|q| q.path.ends_with(":generateContent")).unwrap().json();
    assert!(sent["contents"][0]["parts"][0]["text"].as_str().unwrap().starts_with("Fully describe and explain everything happening in this video"));
    let remote = t.call(&c, json!({"video_url": format!("{}/clip.mp4", srv.url), "question": "q"}));
    assert!(!remote.is_error, "{}", remote.content);
    let bad = t.call(&c, json!({"video_url": "a.gif", "question": "q"}));
    assert!(bad.is_error && bad.content.contains("Unsupported video format: '.gif'"), "{}", bad.content);
    // Provider rejects video input → Hermes capability hint.
    let rej = Arc::new(media(&format!("[understanding]\nvideo_provider = \"openrouter\"\n[providers.openrouter]\napi_key = \"o\"\nbase_url = \"{}/x\"\n", srv.url)));
    let out = VideoAnalyze { m: rej }.call(&c, json!({"video_url": "a.mp4", "question": "q"}));
    let v: Value = serde_json::from_str(&out.content).unwrap();
    assert_eq!(v["success"], false);
    assert!(v["analysis"].as_str().unwrap().contains("Ensure you're using a video-capable model"), "{}", out.content);
    assert_eq!(video_error_text("HTTP 402 insufficient credits").split('.').next().unwrap(), "Insufficient credits or payment required");
}

#[test]
fn video_describer_chain_custom_endpoint_and_error_rules() {
    let srv = server();
    let v = DescribeRequest { bytes: MP4.to_vec(), mime: "video/mp4".into(), prompt: "what happens?".into(), model: None, max_tokens: 100 };
    // OpenRouter: the video is sent as a `video_url` data URL to the video model.
    let or = media(&format!("[understanding]\nvideo_provider = \"openrouter\"\n[providers.openrouter]\napi_key = \"o\"\nbase_url = \"{}\"\n", srv.url));
    assert_eq!(describe(&or, "video", &v, &Cancel::new()).unwrap(), ("openrouter".to_string(), "chat says hi".to_string()));
    let sent = srv.requests().into_iter().find(|q| q.path == "/chat/completions").unwrap().json();
    assert_eq!(sent["model"], json!("google/gemini-2.5-flash"));
    assert_eq!(sent["messages"][0]["content"][1]["type"], json!("video_url"));
    assert!(sent["messages"][0]["content"][1]["video_url"]["url"].as_str().unwrap().starts_with("data:video/mp4;base64,"));
    // A custom OpenAI-compatible endpoint with `video = true` is next in the chain.
    let custom = media(&format!("[understanding]\nvideo_provider = \"mine\"\n[understanding.providers.mine]\nbase_url = \"{}\"\nmodel = \"qwen-vl\"\nvideo = true\n", srv.url));
    assert_eq!(describe(&custom, "video", &v, &Cancel::new()).unwrap().0, "mine");
    let sent = srv.requests().into_iter().rev().find(|q| q.path == "/chat/completions").unwrap().json();
    assert_eq!((sent["model"].clone(), sent["messages"][0]["content"][1]["type"].clone()), (json!("qwen-vl"), json!("video_url")));
    // Hermes `_VIDEO_ERROR_RULES`: billing → capability → size, in that order.
    assert!(video_error_text("HTTP 402 payment required").starts_with("Insufficient credits"));
    assert!(video_error_text("model does not support video input").contains("video-capable model"));
    for hint in ["too large", "payload", "HTTP 413", "content_too_large", "request_too_large", "exceeds", "size limit"] {
        assert!(video_error_text(&format!("upload failed: {hint}")).starts_with("The video is too large"), "{hint}");
    }
    assert!(video_error_text("socket closed").starts_with("There was a problem with the request"));
    // Digits inside paths/hex ids are not HTTP status codes (a temp dir like
    // `ark-ff-4029952-x` must not be classified as "402 Payment Required").
    assert!(video_error_text("agent: ffmpeg exited with 183 on /tmp/ark-ff-4029952-x/in.mp4").starts_with("There was a problem with the request"));
    assert!(video_error_text("status 402").starts_with("Insufficient credits"));
    // 50 MB base64 cap (Hermes `_MAX_VIDEO_BASE64_BYTES`).
    assert!(check_video_payload(1024, "video/mp4").is_ok());
    let e = check_video_payload(40 * 1024 * 1024, "video/mp4").unwrap_err();
    assert!(e.contains("(limit 50 MB)") && e.contains("Compress or trim the video and retry"), "{e}");
}

#[test]
fn empty_provider_answer_is_retried_once() {
    let srv = FakeServer::start(|_, n| {
        let text = if n == 0 { "" } else { "second try" };
        (200, vec![], json!({"candidates": [{"content": {"parts": [{"text": text}]}}]}).to_string())
    });
    let m = media(&format!("[understanding]\nimage_provider = \"google\"\n[providers.google]\napi_key = \"g\"\nbase_url = \"{}\"\n", srv.url));
    let req = DescribeRequest { bytes: PNG.to_vec(), mime: "image/png".into(), prompt: "p".into(), model: None, max_tokens: 100 };
    assert_eq!(describe(&m, "image", &req, &Cancel::new()).unwrap(), ("google".to_string(), "second try".to_string()));
    assert_eq!(srv.requests().len(), 2, "an empty answer is retried exactly once");
}

#[test]
fn cli_image_generate_envelope_and_output() {
    crate::genrt::test_support::fast_poll();
    let srv = FakeServer::start_raw(|r, _| match r.path.as_str() {
        "/prompt" => (200, vec![], json!({"prompt_id": "img-1"}).to_string().into_bytes()),
        "/history/img-1" => (200, vec![], json!({"img-1": {"outputs": {"9": {"images": [{"filename": "out.png", "subfolder": "", "type": "output"}]}}}}).to_string().into_bytes()),
        p if p.starts_with("/view?") => (200, vec![("content-type".into(), "image/png".into())], PNG.to_vec()),
        _ => (404, vec![], vec![]),
    });
    let m = Arc::new(media(&format!(
        "[providers.comfy]\nbase_url = \"{}\"\nworkflow = {{ \"6\" = {{ inputs = {{ text = \"\" }} }}, \"9\" = {{ inputs = {{}} }} }}\nprompt_node_id = \"6\"\noutput_node_id = \"9\"\n",
        srv.url
    )));
    let ws = ctx("cli-image").workspace;
    let a = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
    let v: Value = serde_json::from_str(&cli::cli(&m, &a("image generate --prompt a cat --model comfy/workflow --count 1 --output out/cat.png --json"), &ws).unwrap()).unwrap();
    assert_eq!((v["capability"].clone(), v["provider"].clone(), v["outputs"][0]["path"].clone()), (json!("image.generate"), json!("comfy"), json!(ws.join("out/cat.png").display().to_string())));
    assert_eq!(std::fs::read(ws.join("out/cat.png")).unwrap(), PNG);
    let text = cli::cli(&m, &a("image generate --prompt a cat --model comfy/workflow"), &ws).unwrap();
    assert!(text.starts_with("image.generate via local\nprovider: comfy\nmodel: workflow\noutputs: 1\n") && text.ends_with(".png"), "{text}");
}

#[test]
fn capability_cli_end_to_end() {
    let hex: String = MP3.iter().map(|b| format!("{b:02x}")).collect();
    let srv = FakeServer::start_raw(move |r, _| match r.path.as_str() {
        p if p.ends_with(":generateContent") => (200, vec![], json!({"candidates": [{"content": {"parts": [{"text": "A red pixel."}]}}]}).to_string().into_bytes()),
        "/audio/transcriptions" => (200, vec![("content-type".into(), "application/json".into())], b"{\"text\":\"hello from cli\"}".to_vec()),
        "/audio/speech" => (200, vec![("content-type".into(), "audio/mpeg".into())], MP3.to_vec()),
        "/v1/music_generation" => (200, vec![("content-type".into(), "text/event-stream".into())], format!("data: {{\"data\":{{\"audio\":\"{hex}\",\"status\":1}},\"base_resp\":{{\"status_code\":0}}}}\n\ndata: {{\"data\":{{\"status\":2}}}}\n\n").into_bytes()),
        "/models/veo3" => (200, vec![], json!({"status": "completed", "videoUrl": "/x"}).to_string().into_bytes()),
        _ => (404, vec![], vec![]),
    });
    let m = Arc::new(media(&format!("[stt]\nprovider = \"openai\"\n[tts]\nprovider = \"openai\"\n[music]\nprovider = \"minimax\"\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{0}\"\n[providers.google]\napi_key = \"g\"\nbase_url = \"{0}\"\n[providers.minimax]\napi_key = \"m\"\nbase_url = \"{0}\"\n", srv.url)));
    let c = ctx("cli");
    let ws = c.workspace.clone();
    std::fs::write(ws.join("p.png"), PNG).unwrap();
    let wav: Vec<u8> = crate::audio::wav_encode(&vec![100i16; 16000], 16000, 1);
    std::fs::write(ws.join("v.wav"), wav).unwrap();
    let a = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
    assert!(cli::cli(&m, &a("list"), &ws).unwrap().contains("video.generate"));
    let list: Value = serde_json::from_str(&cli::cli(&m, &a("list --json"), &ws).unwrap()).unwrap();
    assert!(list.as_array().unwrap().iter().any(|e| e["id"] == "audio.transcribe" && e["transports"] == json!(["local"])));
    let insp: Value = serde_json::from_str(&cli::cli(&m, &a("inspect --name tts.convert --json"), &ws).unwrap()).unwrap();
    assert_eq!(insp["transports"], json!(["local", "gateway"]));
    // `tts.status` is gateway-managed upstream.
    let st: Value = serde_json::from_str(&cli::cli(&m, &a("inspect --name tts.status --json"), &ws).unwrap()).unwrap();
    assert_eq!((st["transports"].clone(), st["description"].clone()), (json!(["gateway"]), json!("Show gateway-managed TTS state.")));
    // Understanding commands return the OpenClaw capability envelope (text + JSON).
    let d = cli::cli(&m, &a("image describe --file p.png"), &ws).unwrap();
    assert!(d.starts_with("image.describe via local\nprovider: google\noutputs: 1\n") && d.ends_with("A red pixel."), "{d}");
    let dj: Value = serde_json::from_str(&cli::cli(&m, &a("image describe --file p.png --json --timeout-ms 5000"), &ws).unwrap()).unwrap();
    assert_eq!((dj["ok"].clone(), dj["capability"].clone(), dj["outputs"][0]["kind"].clone()), (json!(true), json!("image.describe"), json!("image.description")));
    let many: Value = serde_json::from_str(&cli::cli(&m, &a("image describe-many --file p.png --file p.png --json"), &ws).unwrap()).unwrap();
    assert_eq!((many["outputs"].as_array().unwrap().len(), many["provider"].clone()), (2, json!("google")));
    let tr = cli::cli(&m, &a("audio transcribe --file v.wav"), &ws).unwrap();
    assert!(tr.starts_with("audio.transcribe via local\nprovider: openai\noutputs: 1\n") && tr.ends_with("hello from cli"), "{tr}");
    let tts = cli::cli(&m, &a("tts convert --text hi --output out/hi.mp3 --json"), &ws).unwrap();
    let v: Value = serde_json::from_str(&tts).unwrap();
    assert_eq!((v["capability"].clone(), v["provider"].clone()), (json!("tts.convert"), json!("openai")));
    assert_eq!(v["outputs"][0]["path"], json!(ws.join("out/hi.mp3").display().to_string()));
    assert_eq!(std::fs::read(ws.join("out/hi.mp3")).unwrap(), MP3);
    // `tts convert` model refs/flags (OpenClaw tts convert).
    let tts = cli::cli(&m, &a("tts convert --text hi --model openai/tts-1 --channel general --json"), &ws).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&tts).unwrap()["provider"], json!("openai"));
    assert_eq!(srv.requests().into_iter().rev().find(|q| q.path == "/audio/speech").unwrap().json()["model"], json!("tts-1"));
    assert!(cli::cli(&m, &a("tts convert --text hi --model tts-1"), &ws).unwrap_err().contains("must use the form <provider/model>"));
    assert!(cli::cli(&m, &a("tts convert --text hi --provider minimax --model openai/tts-1"), &ws).unwrap_err().contains("must match the provider in --model"));
    assert!(cli::cli(&m, &a("tts convert --text hi --gateway"), &ws).unwrap_err().contains("needs the agent gateway"));
    // A file-producing command: envelope, --output and ignored overrides.
    let mg = cli::cli(&m, &a("music generate --prompt chill --format wav --output out/track.mp3 --json"), &ws).unwrap();
    let v: Value = serde_json::from_str(&mg).unwrap();
    assert_eq!((v["capability"].clone(), v["transport"].clone(), v["provider"].clone()), (json!("music.generate"), json!("local"), json!("minimax")));
    assert_eq!(v["ignoredOverrides"], json!([{"key": "format", "value": "wav"}]));
    assert_eq!(v["outputs"][0]["path"], json!(ws.join("out/track.mp3").display().to_string()));
    assert_eq!(std::fs::read(ws.join("out/track.mp3")).unwrap(), MP3);
    let vp = cli::cli(&m, &a("video providers"), &ws).unwrap();
    assert!(vp.contains("✗ fal") && vp.contains("pixverse"), "{vp}");
    let vpj: Value = serde_json::from_str(&cli::cli(&m, &a("video providers --json"), &ws).unwrap()).unwrap();
    assert!(vpj["generation"].as_array().is_some_and(|a| !a.is_empty()) && vpj["description"].as_array().is_some_and(|a| a.iter().any(|d| d["id"] == "google")));
    assert!(cli::cli(&m, &a("music generate --prompt chill --background"), &ws).unwrap_err().contains("one-shot command"));
    assert!(cli::cli(&m, &a("music providers --json"), &ws).unwrap().contains("\"id\": \"minimax\""));
    assert!(cli::cli(&m, &a("image describe"), &ws).unwrap_err().contains("missing required option --file"));
    assert!(cli::cli(&m, &a("inspect --name nope"), &ws).unwrap_err().contains("Unknown capability: nope"));
    assert!(cli::cli(&m, &a("bogus thing"), &ws).unwrap_err().starts_with("unknown command"));
    // Non-media domains are owned by the agent runtime: name what to do instead.
    let e = cli::cli(&m, &a("model run --prompt hi"), &ws).unwrap_err();
    assert!(e.contains("not a media capability") && e.contains("agent runtime") && e.contains("ark infer list"), "{e}");
    assert!(cli::cli(&m, &a("web search --query x"), &ws).unwrap_err().contains("web_search / web_fetch"));
}
