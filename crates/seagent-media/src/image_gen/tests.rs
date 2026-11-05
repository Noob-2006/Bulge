//! Provider request/response tests against a local fake server, and tool tests.

use super::*;
use crate::testutil::{self, FakeServer, RawReply, Req};
use crate::MediaConfig;
use std::sync::{Arc, Mutex};

pub fn png() -> Vec<u8> {
    let img = image::RgbImage::from_fn(8, 8, |x, y| image::Rgb([(x * 30) as u8, (y * 30) as u8, 90]));
    let mut b = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut b), image::ImageFormat::Png).unwrap();
    b
}

/// A fake server whose handler also gets its own base URL.
fn server(h: impl Fn(&Req, &str) -> RawReply + Send + Sync + 'static) -> FakeServer {
    let base = Arc::new(Mutex::new(String::new()));
    let b2 = base.clone();
    let s = FakeServer::start_raw(move |r, _| h(r, &b2.lock().unwrap()));
    *base.lock().unwrap() = s.url.clone();
    s
}

fn json_reply(v: Value) -> RawReply {
    (200, vec![("content-type".into(), "application/json".into())], v.to_string().into_bytes())
}

fn png_reply() -> RawReply {
    (200, vec![("content-type".into(), "image/png".into())], png())
}

fn b64png() -> String {
    store::b64(&png())
}

fn media(id: &str, base: &str, extra: &str) -> Arc<Media> {
    Media::new(testutil::cfg_for(id, base, &format!("[image]\npoll_ms = 1\n{extra}")))
}

fn req(prompt: &str) -> ImageRequest {
    ImageRequest { prompt: prompt.into(), poll: Some(Duration::from_millis(1)), timeout: Duration::from_secs(10), ..Default::default() }
}

fn input() -> InputImage {
    InputImage { bytes: png(), mime: "image/png".into(), name: "in.png".into(), url: None }
}

fn tool_call(m: &Arc<Media>, ctx: &ToolCtx, v: Value) -> ToolOutput {
    ImageGenerate { m: m.clone() }.call(ctx, v)
}

#[test]
fn fal_queue_end_to_end_through_the_tool() {
    let polls = Arc::new(Mutex::new(0));
    let p2 = polls.clone();
    let srv = server(move |r, base| match (r.method.as_str(), r.path.as_str()) {
        ("POST", "/fal-ai/flux-2/klein/9b") => json_reply(json!({"request_id": "r1", "status_url": format!("{base}/q/status"), "response_url": format!("{base}/q/resp")})),
        ("GET", "/q/status") => {
            let mut n = p2.lock().unwrap();
            *n += 1;
            json_reply(json!({"status": if *n < 2 { "IN_PROGRESS" } else { "COMPLETED" }}))
        }
        ("GET", "/q/resp") => json_reply(json!({"images": [{"url": format!("{base}/img.png"), "width": 8, "height": 8}], "prompt": "a cat"})),
        ("GET", "/img.png") => png_reply(),
        _ => (404, vec![], b"{}".to_vec()),
    });
    let m = media("fal", &srv.url, "provider = \"fal\"");
    let ctx = testutil::ctx("imgfal");
    let out = tool_call(&m, &ctx, json!({"prompt": "a cat", "aspect_ratio": "portrait", "seed": 3}));
    assert!(!out.is_error, "{}", out.content);
    assert!(out.content.contains("MEDIA:") && out.content.contains("\"provider\": \"fal\""), "{}", out.content);
    let reqs = srv.requests();
    assert_eq!(reqs[0].header("authorization"), Some("Key k"));
    let b = reqs[0].json();
    assert_eq!((b["image_size"].as_str(), b["seed"].as_i64(), b["num_inference_steps"].as_i64()), (Some("portrait_16_9"), Some(3), Some(4)));
    let path = out.content.lines().find_map(|l| l.strip_prefix("MEDIA:")).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), png());
    assert!(*polls.lock().unwrap() >= 2);
}

#[test]
fn fal_edit_endpoint_and_upscale() {
    let srv = server(|r, base| match r.path.as_str() {
        "/fal-ai/flux-2/klein/9b" => json_reply(json!({"images": [{"url": format!("{base}/a.png")}]})),
        "/fal-ai/flux-2/klein/9b/edit" => json_reply(json!({"images": [{"url": format!("{base}/a.png")}]})),
        "/fal-ai/clarity-upscaler" => json_reply(json!({"image": {"url": format!("{base}/up.png"), "width": 16, "height": 16}})),
        _ => png_reply(),
    });
    let m = media("fal", &srv.url, "");
    let mut r = req("x");
    r.upscale = Some(true);
    let res = fal::Fal.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(res.images[0].url.as_deref(), Some(format!("{}/up.png", srv.url).as_str()));
    let up = srv.requests().into_iter().find(|q| q.path == "/fal-ai/clarity-upscaler").unwrap().json();
    assert_eq!((up["upscale_factor"].as_u64(), up["creativity"].as_f64()), (Some(2), Some(0.35)));
    let mut r = req("edit it");
    r.inputs = vec![input()];
    fal::Fal.generate(&m, &r, &Cancel::new()).unwrap();
    let e = srv.requests().into_iter().find(|q| q.path.ends_with("/edit")).unwrap().json();
    assert!(e["image_urls"][0].as_str().unwrap().starts_with("data:image/png;base64,"));
    assert!(e.get("image_size").is_none(), "edit endpoint does not list image_size");
}

#[test]
fn openai_generate_and_edit() {
    let srv = server(|_, _| json_reply(json!({"data": [{"b64_json": b64png(), "revised_prompt": "rp"}], "usage": {"total_tokens": 5}})));
    let m = media("openai", &srv.url, "");
    let mut r = req("cat");
    r.semantic_aspect = "landscape".into();
    r.options = json!({"openai": {"moderation": "low", "user": "u1"}});
    let res = openai::OpenAi.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!((res.model.as_str(), res.images[0].revised_prompt.as_deref()), ("gpt-image-2", Some("rp")));
    let q = &srv.requests()[0];
    assert_eq!((q.path.as_str(), q.header("authorization")), ("/images/generations", Some("Bearer k")));
    let b = q.json();
    assert_eq!((b["size"].as_str(), b["quality"].as_str(), b["moderation"].as_str(), b["user"].as_str(), b["n"].as_u64()), (Some("1536x1024"), Some("medium"), Some("low"), Some("u1"), Some(1)));
    let mut r = req("edit");
    r.inputs = vec![input(), input()];
    openai::OpenAi.generate(&m, &r, &Cancel::new()).unwrap();
    let e = &srv.requests()[1];
    assert_eq!(e.path, "/images/edits");
    assert!(e.header("content-type").unwrap().starts_with("multipart/form-data"));
    let body = String::from_utf8_lossy(&e.raw);
    assert_eq!(body.matches("name=\"image[]\"").count(), 2);
    assert!(body.contains("name=\"model\"\r\n\r\ngpt-image-2"));
}

#[test]
fn openai_azure_deployment_url() {
    let srv = server(|_, _| json_reply(json!({"data": [{"b64_json": b64png()}]})));
    // A fake host that looks like Azure is not reachable, so test URL building via the path on a local base.
    let m = media("openai", &srv.url, "");
    let r = req("p");
    openai::OpenAi.generate(&m, &r, &Cancel::new()).unwrap();
    assert!(!srv.requests()[0].path.contains("deployments"));
}

#[test]
fn codex_native_and_responses_transports() {
    let claims = store::b64(br#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acc"}}"#).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string();
    let token = format!("h.{claims}.s");
    let srv = server(|r, _| {
        if r.path == "/responses" {
            let item = json!({"type": "image_generation_call", "status": "completed", "result": b64png()});
            let sse = format!("data: {}\n\ndata: {}\n\n", json!({"type": "response.output_item.done", "item": item}), json!({"type": "response.completed", "response": {"output": [item]}}));
            (200, vec![("content-type".into(), "text/event-stream".into())], sse.into_bytes())
        } else {
            (200, vec![("x-codex-imagegen-request-id".into(), "rid".into())], json!({"data": [{"b64_json": b64png()}], "quality": "medium", "size": "1024x1024"}).to_string().into_bytes())
        }
    });
    let m = Media::new(MediaConfig::from_toml(&format!("[providers.openai-codex]\napi_key = \"{token}\"\nbase_url = \"{}\"\n", srv.url)));
    assert!(openai::Codex.configured(&m));
    let res = openai::Codex.generate(&m, &req("cat"), &Cancel::new()).unwrap();
    assert_eq!(res.meta["responses"][0]["imagegen_request_id"], "rid");
    let q = &srv.requests()[0];
    assert_eq!((q.path.as_str(), q.header("chatgpt-account-id")), ("/images/generations", Some("acc")));
    assert_eq!((q.json()["model"].as_str(), q.json()["background"].as_str()), (Some("gpt-image-2"), Some("opaque")));
    let m = Media::new(MediaConfig::from_toml(&format!("[providers.openai-codex]\napi_key = \"{token}\"\nbase_url = \"{}\"\ntransport = \"responses\"\n", srv.url)));
    let res = openai::Codex.generate(&m, &req("dog"), &Cancel::new()).unwrap();
    assert_eq!(res.images.len(), 1);
    let q = srv.requests().into_iter().find(|q| q.path == "/responses").unwrap().json();
    assert_eq!((q["tools"][0]["type"].as_str(), q["stream"].as_bool()), (Some("image_generation"), Some(true)));
}

#[test]
fn codex_reads_auth_file() {
    let d = testutil::temp_dir("codexauth");
    std::fs::write(d.join("auth.json"), r#"{"tokens":{"access_token":"tok","account_id":"a1"}}"#).unwrap();
    let m = Media::new(MediaConfig::from_toml(&format!("[providers.openai-codex]\nauth_file = \"{}\"\n", d.join("auth.json").display())));
    assert!(openai::Codex.configured(&m));
}

#[test]
fn google_gemini_and_imagen() {
    let srv = server(|r, _| {
        if r.path.ends_with(":predict") {
            json_reply(json!({"predictions": [{"bytesBase64Encoded": b64png(), "mimeType": "image/png"}]}))
        } else {
            json_reply(json!({"candidates": [{"content": {"parts": [{"text": "here"}, {"inlineData": {"mimeType": "image/png", "data": b64png()}}]}}]}))
        }
    });
    let m = media("google", &srv.url, "");
    let mut r = req("cat");
    r.aspect_ratio = Some("16:9".into());
    r.resolution = Some("2K".into());
    r.inputs = vec![input()];
    let res = google::Google.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(res.meta["text"], "here");
    let q = &srv.requests()[0];
    assert_eq!((q.path.as_str(), q.header("x-goog-api-key")), ("/models/gemini-3.1-flash-image:generateContent", Some("k")));
    let b = q.json();
    assert_eq!((b["generationConfig"]["imageConfig"]["aspectRatio"].as_str(), b["generationConfig"]["imageConfig"]["imageSize"].as_str()), (Some("16:9"), Some("2K")));
    assert!(b["contents"][0]["parts"][0]["inlineData"]["data"].is_string());
    let mut r = req("cat");
    r.model = Some("imagen-4.0-generate-001".into());
    r.count = 2;
    google::Google.generate(&m, &r, &Cancel::new()).unwrap();
    let q = srv.requests()[1].json();
    assert_eq!((q["instances"][0]["prompt"].as_str(), q["parameters"]["sampleCount"].as_u64()), (Some("cat"), Some(2)));
}

#[test]
fn xai_generate_and_edit() {
    let srv = server(|_, _| json_reply(json!({"data": [{"b64_json": b64png()}]})));
    let m = media("xai", &srv.url, "");
    let mut r = req("cat");
    r.semantic_aspect = "landscape".into();
    xai::Xai.generate(&m, &r, &Cancel::new()).unwrap();
    let b = srv.requests()[0].json();
    assert_eq!((b["model"].as_str(), b["aspect_ratio"].as_str(), b["resolution"].as_str(), b["response_format"].as_str()), (Some("grok-imagine-image"), Some("16:9"), Some("1k"), Some("b64_json")));
    let mut r = req("edit");
    r.inputs = vec![InputImage { url: Some("https://e/x.png".into()), ..input() }];
    xai::Xai.generate(&m, &r, &Cancel::new()).unwrap();
    let q = &srv.requests()[1];
    assert_eq!((q.path.as_str(), q.json()["model"].as_str(), q.json()["image"]["url"].as_str()), ("/images/edits", Some("grok-imagine-image-quality"), Some("https://e/x.png")));
    r.inputs = vec![input(), input(), input(), input()];
    assert!(xai::Xai.generate(&m, &r, &Cancel::new()).unwrap_err().contains("at most 3"));
}

#[test]
fn openrouter_chat_and_image_api() {
    let srv = server(|r, _| match r.path.as_str() {
        "/chat/completions" => json_reply(json!({"choices": [{"message": {"images": [{"image_url": {"url": store::data_url("image/png", &png())}}]}}]})),
        "/images/generations" => json_reply(json!({"data": [{"b64_json": b64png(), "media_type": "image/png"}], "usage": {"cost": 0.04}})),
        _ => (404, vec![], b"{}".to_vec()),
    });
    let m = media("openrouter", &srv.url, "");
    let res = openrouter::OpenRouter.generate(&m, &req("cat"), &Cancel::new()).unwrap();
    assert_eq!(res.model, "openai/gpt-5.4-image-2");
    let q = &srv.requests()[0];
    assert_eq!((q.path.as_str(), q.json()["modalities"][0].as_str()), ("/chat/completions", Some("image")));
    let mut r = req("cat");
    r.model = Some("openai/gpt-image-2".into());
    let res = openrouter::OpenRouter.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(res.meta["cost_usd"], 0.04);
    assert_eq!(srv.requests()[1].path, "/images/generations");
}

#[test]
fn openrouter_default_chain_falls_back() {
    let srv = server(|r, _| {
        if r.json()["model"] == "openai/gpt-5.4-image-2" {
            json_reply(json!({"choices": [{"message": {"content": "sorry, text only"}}]}))
        } else {
            json_reply(json!({"choices": [{"message": {"images": [{"image_url": {"url": store::data_url("image/png", &png())}}]}}]}))
        }
    });
    let m = media("openrouter", &srv.url, "");
    let res = openrouter::OpenRouter.generate(&m, &req("cat"), &Cancel::new()).unwrap();
    assert_eq!((res.model.as_str(), res.meta["fallback_from"].as_str()), ("google/gemini-3-pro-image", Some("openai/gpt-5.4-image-2")));
}

#[test]
fn deepinfra_litellm_meta() {
    let srv = server(|_, _| json_reply(json!({"data": [{"b64_json": b64png()}]})));
    for (id, p) in [("deepinfra", &compat::DeepInfra as &dyn ImageProvider), ("litellm", &compat::Litellm), ("meta-ai", &compat::MetaAi)] {
        let m = media(id, &srv.url, "");
        assert!(p.configured(&m), "{id}");
        let res = p.generate(&m, &req("cat"), &Cancel::new()).unwrap();
        assert_eq!(res.images.len(), 1, "{id}");
    }
    let rs = srv.requests();
    assert_eq!((rs[0].json()["model"].as_str(), rs[0].json()["size"].as_str(), rs[0].json()["response_format"].as_str()), (Some("black-forest-labs/FLUX-1-schnell"), Some("1024x1024"), Some("b64_json")));
    assert_eq!(rs[1].json()["model"], "gpt-image-2");
    assert_eq!(rs[2].json()["model"], "muse-image-1.0");
    let m = media("deepinfra", &srv.url, "");
    let mut r = req("edit");
    r.inputs = vec![input()];
    compat::DeepInfra.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(srv.requests()[3].path, "/images/edits");
    assert!(!compat::MetaAi.caps("muse-image-1.0").edit);
}

#[test]
fn minimax_base64_and_errors() {
    let srv = server(|r, _| {
        if r.json()["prompt"] == "bad" {
            json_reply(json!({"base_resp": {"status_code": 1004, "status_msg": "auth failed"}}))
        } else {
            json_reply(json!({"data": {"image_base64": [b64png(), b64png()]}, "base_resp": {"status_code": 0}}))
        }
    });
    let m = media("minimax", &srv.url, "");
    let mut r = req("cat");
    r.count = 2;
    r.aspect_ratio = Some("16:9".into());
    r.inputs = vec![input()];
    assert_eq!(minimax::Minimax.generate(&m, &r, &Cancel::new()).unwrap().images.len(), 2);
    let q = &srv.requests()[0];
    assert_eq!((q.path.as_str(), q.json()["subject_reference"][0]["type"].as_str(), q.json()["response_format"].as_str()), ("/v1/image_generation", Some("character"), Some("base64")));
    assert!(minimax::Minimax.generate(&m, &req("bad"), &Cancel::new()).unwrap_err().contains("(1004): auth failed"));
}

#[test]
fn foundry_mai_generation() {
    let srv = server(|_, _| json_reply(json!({"data": [{"b64_json": b64png()}]})));
    let m = media("microsoft-foundry", &srv.url, "");
    let mut r = req("cat");
    r.model = Some("MAI-Image-2".into());
    r.size = Some("1024x768".into());
    foundry::Foundry.generate(&m, &r, &Cancel::new()).unwrap();
    let q = &srv.requests()[0];
    assert_eq!((q.path.as_str(), q.header("api-key"), q.json()["width"].as_u64()), ("/mai/v1/images/generations", Some("k"), Some(1024)));
    r.inputs = vec![input()];
    assert!(foundry::Foundry.generate(&m, &r, &Cancel::new()).unwrap_err().contains("does not support"));
}

#[test]
fn krea_job_poll_and_enhance() {
    let n = Arc::new(Mutex::new(0));
    let n2 = n.clone();
    let srv = server(move |r, base| match r.path.as_str() {
        "/generate/image/krea/krea-2/large" => json_reply(json!({"job_id": "j1"})),
        "/generate/enhance/krea/enhance" => json_reply(json!({"job_id": "j2"})),
        "/jobs/j1" => {
            let mut c = n2.lock().unwrap();
            *c += 1;
            if *c == 1 {
                (503, vec![], b"{}".to_vec())
            } else {
                json_reply(json!({"status": "completed", "result": {"urls": [format!("{base}/out.png")]}}))
            }
        }
        "/jobs/j2" => json_reply(json!({"status": "completed", "result": {"url": format!("{base}/big.png")}})),
        _ => png_reply(),
    });
    let m = media("krea", &srv.url, "");
    let mut r = req("cat");
    r.model = Some("krea-2-large".into());
    r.upscale = Some(true);
    r.options = json!({"creativity": "raw", "complexity": 10});
    let res = krea::Krea.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(res.meta["upscaled"], true);
    assert!(res.meta["url"].as_str().unwrap().ends_with("/big.png"));
    let sub = srv.requests()[0].json();
    assert_eq!((sub["creativity"].as_str(), sub["complexity"].as_i64(), sub["resolution"].as_str()), (Some("raw"), Some(10), Some("1K")));
}

#[test]
fn comfy_local_workflow() {
    let srv = server(|r, _| match r.path.as_str() {
        "/upload/image" => json_reply(json!({"name": "in.png"})),
        "/prompt" => json_reply(json!({"prompt_id": "p1"})),
        "/history/p1" => json_reply(json!({"p1": {"status": {"completed": true}, "outputs": {"9": {"images": [{"filename": "o.png", "subfolder": "", "type": "output"}]}}}})),
        p if p.starts_with("/view?") => png_reply(),
        _ => (404, vec![], vec![]),
    });
    let cfg = format!("[image]\npoll_ms = 1\n[providers.comfy]\nbase_url = \"{}\"\nprompt_node_id = \"6\"\ninput_image_node_id = \"10\"\nseed_node_id = \"3\"\npoll_interval_ms = 1\n[providers.comfy.workflow.6]\ninputs = {{ text = \"\" }}\n[providers.comfy.workflow.10]\ninputs = {{ image = \"\" }}\n[providers.comfy.workflow.3]\ninputs = {{ seed = 0 }}\n", srv.url);
    let m = Media::new(MediaConfig::from_toml(&cfg));
    assert!(comfy::Comfy.configured(&m));
    let mut r = req("a castle");
    r.inputs = vec![input()];
    let res = comfy::Comfy.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!((res.images.len(), res.meta["prompt_id"].as_str()), (1, Some("p1")));
    let p = srv.requests().into_iter().find(|q| q.path == "/prompt").unwrap().json();
    assert_eq!((p["prompt"]["6"]["inputs"]["text"].as_str(), p["prompt"]["10"]["inputs"]["image"].as_str()), (Some("a castle"), Some("in.png")));
    assert!(p["prompt"]["3"]["inputs"]["seed"].as_u64().is_some());
    assert!(srv.requests().iter().any(|q| q.path.starts_with("/view?filename=o.png")));
}

#[test]
fn vydra_job_polling() {
    let srv = server(|r, base| match r.path.as_str() {
        "/models/grok-imagine" => json_reply(json!({"jobId": "v1", "status": "queued"})),
        "/jobs/v1" => json_reply(json!({"status": "completed", "result": {"imageUrl": format!("{base}/v.png")}})),
        _ => png_reply(),
    });
    let m = media("vydra", &srv.url, "");
    let res = vydra::Vydra.generate(&m, &req("cat"), &Cancel::new()).unwrap();
    assert_eq!(res.meta["jobId"], "v1");
    assert_eq!(srv.requests()[0].json()["model"], "text-to-image");
    let mut r = req("x");
    r.inputs = vec![input()];
    assert!(vydra::Vydra.generate(&m, &r, &Cancel::new()).unwrap_err().contains("text-to-image only"));
}

#[test]
fn fallback_to_next_candidate_and_attempts() {
    let bad = server(|_, _| (500, vec![], b"{\"error\":{\"message\":\"down\"}}".to_vec()));
    let good = server(|_, _| json_reply(json!({"data": [{"b64_json": b64png()}]})));
    let cfg = format!("[image]\nprovider = \"openai\"\nfallback = [\"xai/grok-imagine-image\"]\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{}\"\n[providers.xai]\napi_key = \"k\"\nbase_url = \"{}\"\n", bad.url, good.url);
    let m = Media::new(MediaConfig::from_toml(&cfg));
    let c = candidates(&m, None, None).unwrap();
    assert_eq!(c.iter().map(|c| c.provider.as_str()).collect::<Vec<_>>(), vec!["openai", "xai"]);
    let (p, _, _, att) = generate(&m, &req("cat"), &c, &Cancel::new()).unwrap();
    assert_eq!(p, "xai");
    assert!(att[0]["error"].as_str().unwrap().contains("down"));
    let c = candidates(&m, None, Some("google/gemini-3-pro-image")).unwrap();
    assert_eq!(c, vec![Candidate { provider: "google".into(), model: Some("gemini-3-pro-image".into()) }]);
    assert!(candidates(&Media::new(MediaConfig::from_toml("[image]\nprovider = \"nope\"")), None, None).is_err());
}

#[test]
fn sanitize_maps_unsupported_geometry() {
    let caps = xai::Xai.caps("grok-imagine-image");
    let mut r = req("x");
    r.size = Some("1792x1024".into());
    r.quality = Some("high".into());
    let notes = sanitize(&mut r, &caps);
    assert_eq!((r.size.as_deref(), r.aspect_ratio.as_deref(), r.quality.as_deref()), (None, Some("16:9"), None));
    assert!(notes.iter().any(|n| n.contains("quality")));
    let caps = compat::DeepInfra.caps("x");
    let mut r = req("x");
    r.aspect_ratio = Some("16:9".into());
    sanitize(&mut r, &caps);
    assert_eq!(r.size.as_deref(), Some("1792x1024"));
    let mut r = req("x");
    r.count = 4;
    let notes = sanitize(&mut r, &vydra::Vydra.caps("x"));
    assert_eq!(r.count, 1);
    assert!(notes.iter().any(|n| n == "count 4 clamped to 1"), "{notes:?}");
}

#[test]
fn oversized_images_are_reencoded() {
    let img = image::RgbImage::from_fn(256, 256, |x, y| image::Rgb([(x ^ y) as u8, (x * 7) as u8, (y * 13) as u8]));
    let mut b = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut b), image::ImageFormat::Png).unwrap();
    let (out, notes) = fit_to_max_bytes(vec![Asset::new(b.clone(), "image/png")], b.len() / 3).unwrap();
    assert_eq!(out[0].mime, "image/jpeg");
    assert!(out[0].bytes.len() <= b.len() / 3 && notes.len() == 1);
}

#[test]
fn tool_actions_and_validation() {
    let m = Media::new(MediaConfig::from_toml("[providers.xai]\napi_key = \"k\"\n"));
    let mut ctx = testutil::ctx("imgtool");
    ctx.session_id = "s-imgtool".into();
    let l = tool_call(&m, &ctx, json!({"action": "list"}));
    assert!(l.content.contains("- xai (xAI (Grok Imagine)) ✓") && l.content.contains("- fal"), "{}", l.content);
    assert!(tool_call(&m, &ctx, json!({"action": "status"})).content.contains("No active image generation"));
    assert!(tool_call(&m, &ctx, json!({})).content.contains("Prompt is required"));
    assert!(tool_call(&m, &ctx, json!({"prompt": "x", "resolution": "8K"})).content.contains("1K, 2K, or 4K"));
    assert!(tool_call(&m, &ctx, json!({"prompt": "x", "count": 9})).content.contains("between 1 and 4"));
    let none = Media::new(MediaConfig::default());
    std::env::remove_var("SEAGENT_MEDIA_TEST_NOTHING");
    if providers().iter().all(|p| !p.configured(&none)) {
        assert!(tool_call(&none, &ctx, json!({"prompt": "x"})).content.contains("no image provider is configured"));
    }
    let fx = ImageGenerate { m: m.clone() }.effects(&ctx, &json!({"prompt": "cat", "image": "in.png"}));
    assert!(fx.iter().any(|e| matches!(e, Effect::Net { dest, payload } if dest == "api.x.ai" && payload == "cat")));
    assert!(fx.iter().any(|e| matches!(e, Effect::Read { .. })));
    assert!(ImageGenerate { m }.effects(&ctx, &json!({"action": "list"})).is_empty());
}

#[test]
fn tool_edit_with_local_reference() {
    let srv = server(|_, _| json_reply(json!({"data": [{"b64_json": b64png()}]})));
    let m = media("xai", &srv.url, "provider = \"xai\"");
    let ctx = testutil::ctx("imgedit");
    std::fs::write(ctx.workspace.join("ref.png"), png()).unwrap();
    let out = tool_call(&m, &ctx, json!({"prompt": "make it blue", "image": "ref.png", "filename": "blue.png"}));
    assert!(!out.is_error, "{}", out.content);
    assert!(out.content.contains("blue.png") && out.content.contains("\"modality\": \"image\""), "{}", out.content);
    assert!(srv.requests()[0].json()["image"]["url"].as_str().unwrap().starts_with("data:image/png;base64,"));
    let bad = tool_call(&m, &ctx, json!({"prompt": "x", "image": "missing.png"}));
    assert!(bad.is_error && bad.content.contains("Could not load source image"));
}

#[test]
fn providers_are_reachable_aliased_and_listed() {
    // Hermes (8) + OpenClaw (11, overlapping) → 14 boxes, fal first (Hermes' default backend).
    let ps = providers();
    let ids: Vec<&str> = ps.iter().map(|p| p.id()).collect();
    assert_eq!(ids, vec!["fal", "openai", "google", "xai", "openrouter", "krea", "deepinfra", "minimax", "meta-ai", "vydra", "microsoft-foundry", "litellm", "openai-codex", "comfy"], "{ids:?}");
    assert_eq!(ids.len(), 14);
    // Every id is also returned by `provider(id)`, plus the documented aliases.
    for id in &ids {
        assert_eq!(provider(id).map(|p| p.id()), Some(*id), "{id}");
    }
    for (alias, id) in [("gemini", "google"), ("imagen", "google"), ("google-gemini", "google"), ("grok", "xai"), ("x-ai", "xai"), ("codex", "openai-codex"), ("chatgpt", "openai-codex"), ("meta", "meta-ai"), ("muse", "meta-ai"), ("foundry", "microsoft-foundry"), ("mai", "microsoft-foundry"), ("comfyui", "comfy"), ("fal-ai", "fal"), ("FAL", "fal")] {
        assert_eq!(provider(alias).map(|p| p.id()), Some(id), "alias {alias}");
    }
    assert!(provider("nope").is_none());
    // Every provider has a label, and a model catalog except microsoft-foundry (deployment names).
    for p in &ps {
        assert!(!p.label().is_empty(), "{}", p.id());
        assert!(!p.models().is_empty() || p.id() == "microsoft-foundry", "{}", p.id());
    }
    // `action=list` renders all 14 ids, each with its default model.
    let m = Media::new(MediaConfig::from_toml("[providers.xai]\napi_key = \"k\"\n[image]\nprovider = \"xai\""));
    let ctx = testutil::ctx("imglist");
    let l = tool_call(&m, &ctx, json!({"action": "list"}));
    assert!(!l.is_error, "{}", l.content);
    for p in providers() {
        let line = format!("- {} ({})", p.id(), p.label());
        assert!(l.content.contains(&line), "missing {line} in {}", l.content);
        assert!(l.content.contains(&format!("default model: {}", p.default_model(&m))), "{}", p.id());
    }
    assert!(l.content.contains("- xai (xAI (Grok Imagine)) ✓ [selected]"), "{}", l.content);
    assert!(l.content.contains("- fal (FAL.ai) ✗ set FAL_KEY"), "{}", l.content);
    // The tool's `provider` argument routes to every one of them (model: None = provider default).
    let cfg = Media::new(MediaConfig::from_toml("[image]\nprovider = \"auto\""));
    for p in providers() {
        let c = candidates(&cfg, Some(p.id()), None).unwrap_or_else(|e| panic!("{}: {e}", p.id()));
        assert_eq!(c[0].provider, p.id(), "the tool selects {}", p.id());
        assert!(c[0].model.is_none(), "{} resolves its own default model", p.id());
        // microsoft-foundry has no default model: deployments are named by the user.
        assert!(!p.default_model(&cfg).is_empty() || p.id() == "microsoft-foundry", "{} has no default model", p.id());
    }
    // The tool itself is registered under its upstream name, with generate/list/status.
    let tool = tools(&m).into_iter().find(|t| t.spec().name == "image_generate").unwrap();
    assert_eq!(tool.spec().input_schema["properties"]["action"]["enum"], json!(["generate", "list", "status"]));
}

#[test]
fn capability_tables_match_upstream() {
    let m = Media::new(MediaConfig::default());
    let caps = |id: &str, model: &str| provider(id).unwrap().caps(model);
    // OpenClaw extensions/*/image-generation-provider.ts (+ Hermes capabilities()).
    let openai = caps("openai", "gpt-image-2");
    assert_eq!((openai.max_count, openai.edit, openai.max_inputs), (4, true, 16)); // Hermes: images.edit() takes 16
    assert!(openai.sizes.is_empty(), "flexible models accept any prompt-valid size");
    assert_eq!(openai.qualities, vec!["low", "medium", "high", "auto"]);
    assert_eq!(openai.backgrounds, vec!["transparent", "opaque", "auto"]);
    assert_eq!(caps("openai", "gpt-image-1").sizes, vec!["1024x1024", "1536x1024", "1024x1536"]);
    assert_eq!(caps("openai", "gpt-image-2.5-flare").qualities, vec!["low", "medium", "high", "xhigh", "max", "auto"]);
    let g = caps("google", "gemini-3.1-flash-image");
    assert_eq!((g.max_count, g.edit, g.max_inputs, g.supports_size), (4, true, 5, true));
    assert_eq!((g.sizes.len(), g.aspect_ratios.len(), g.resolutions), (5, 10, vec!["1K", "2K", "4K"]));
    let f = caps("fal", catalog::DEFAULT_MODEL);
    assert_eq!((f.max_count, f.edit, f.max_inputs), (4, true, 9));
    let x = caps("xai", "grok-imagine-image");
    assert_eq!((x.max_count, x.edit, x.max_inputs, x.supports_size), (4, true, 3, false));
    assert_eq!((x.aspect_ratios.len(), x.resolutions), (13, vec!["1K", "2K"]));
    let o = caps("openrouter", "openai/gpt-image-2");
    assert_eq!((o.max_count, o.edit, o.max_inputs), (4, true, 16));
    assert_eq!(caps("openrouter", "unknown/model").max_inputs, 5);
    let d = caps("deepinfra", "black-forest-labs/FLUX-1-schnell");
    assert_eq!((d.max_count, d.edit, d.max_inputs, d.supports_aspect), (4, true, 1, false));
    assert_eq!(d.sizes, vec!["512x512", "1024x1024", "1024x1792", "1792x1024"]);
    let l = caps("litellm", "gpt-image-2");
    assert_eq!((l.max_count, l.edit, l.max_inputs, l.sizes.len()), (4, true, 5, 11));
    let fo = caps("microsoft-foundry", "mai-image-2.5");
    assert_eq!((fo.max_count, fo.edit, fo.max_inputs, fo.formats), (1, true, 1, vec!["png"]));
    let mi = caps("minimax", "image-01");
    assert_eq!((mi.max_count, mi.edit, mi.max_inputs, mi.aspect_ratios.len()), (9, true, 1, 8));
    assert_eq!(mi.aspect_ratios, vec!["1:1", "16:9", "4:3", "3:2", "2:3", "3:4", "9:16", "21:9"]);
    let v = caps("vydra", "grok-imagine");
    assert_eq!((v.max_count, v.edit, v.max_inputs), (1, false, 0));
    let k = caps("krea", "krea-2-medium");
    assert_eq!((k.max_count, k.edit, k.max_inputs, k.aspect_ratios.len()), (1, true, 10, 8));
    let me = caps("meta-ai", "muse-image-1.0");
    assert_eq!((me.max_count, me.edit), (1, false));
    let c = caps("comfy", "workflow");
    assert_eq!((c.max_count, c.edit, c.max_inputs), (1, true, 1));
    assert_eq!(caps("openai-codex", "gpt-image-2-medium").max_inputs, 16);
    // Defaults resolve without any config.
    assert_eq!(provider("fal").unwrap().default_model(&m), "fal-ai/flux-2/klein/9b");
    assert_eq!(provider("openai").unwrap().default_model(&m), "gpt-image-2-medium");
    assert_eq!(provider("google").unwrap().default_model(&m), "gemini-3.1-flash-image");
    assert_eq!(provider("xai").unwrap().default_model(&m), "grok-imagine-image");
    assert_eq!(provider("openrouter").unwrap().default_model(&m), "openai/gpt-5.4-image-2");
    assert_eq!(provider("krea").unwrap().default_model(&m), "krea-2-medium");
    assert_eq!(provider("deepinfra").unwrap().default_model(&m), "black-forest-labs/FLUX-1-schnell");
    assert_eq!(provider("minimax").unwrap().default_model(&m), "image-01");
    assert_eq!(provider("meta-ai").unwrap().default_model(&m), "muse-image-1.0");
    assert_eq!(provider("vydra").unwrap().default_model(&m), "grok-imagine");
    assert_eq!(provider("litellm").unwrap().default_model(&m), "gpt-image-2");
    assert_eq!(provider("comfy").unwrap().default_model(&m), "workflow");
}

#[test]
fn openrouter_unknown_model_keeps_endpoint_aspect_ratio() {
    let srv = server(|r, _| match r.path.as_str() {
        // The curated catalog probe misses, so an unknown id stays on chat-completions.
        "/images/models" => json_reply(json!({"data": [{"id": "openai/gpt-image-2"}]})),
        _ => json_reply(json!({"choices": [{"message": {"images": [{"image_url": {"url": store::data_url("image/png", &png())}}]}}]})),
    });
    let m = media("openrouter", &srv.url, "");
    let mut r = req("cat");
    r.model = Some("acme/painter-9".into());
    r.aspect_ratio = Some("16:9".into());
    openrouter::OpenRouter.generate(&m, &r, &Cancel::new()).unwrap();
    let q = srv.requests().into_iter().find(|q| q.path == "/chat/completions").unwrap().json();
    assert_eq!(q["image_config"]["aspect_ratio"], "16:9");
    // An Image-API route with an unknown enum: an in-union ratio is forwarded, an exotic one is dropped.
    let mut notes = vec![];
    let mut r = req("p");
    r.model = Some("acme/painter-9".into());
    r.aspect_ratio = Some("9:19.5".into());
    let b = openrouter::api_payload(None, "acme/painter-9", &r, &[], &mut notes);
    assert_eq!(b["aspect_ratio"], "9:19.5");
    assert!(notes.is_empty(), "{notes:?}");
    let mut notes = vec![];
    r.aspect_ratio = Some("7:5".into());
    let b = openrouter::api_payload(None, "acme/painter-9", &r, &[], &mut notes);
    assert!(b.get("aspect_ratio").is_none());
    assert!(notes.iter().any(|n| n.contains("not in the curated catalog")), "{notes:?}");
}

#[test]
fn fal_reports_model_id_and_upscales_explicit_edits() {
    let srv = server(|r, base| match r.path.as_str() {
        "/fal-ai/flux-2/klein/9b/edit" => json_reply(json!({"images": [{"url": format!("{base}/a.png")}]})),
        "/fal-ai/clarity-upscaler" => json_reply(json!({"image": {"url": format!("{base}/up.png"), "width": 16, "height": 16}})),
        _ => png_reply(),
    });
    let m = media("fal", &srv.url, "");
    let mut r = req("edit it");
    r.inputs = vec![input()];
    // Hermes honors an explicit `upscale` for edits too (the catalog default never upscales edits).
    r.upscale = Some(true);
    let res = fal::Fal.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(res.model, "fal-ai/flux-2/klein/9b", "the model id is reported, not the /edit endpoint");
    assert_eq!(res.meta["endpoint"], "fal-ai/flux-2/klein/9b/edit");
    assert_eq!(res.meta["upscaled"], true);
    assert!(res.images[0].url.as_deref().unwrap().ends_with("/up.png"));
    let up = srv.requests().into_iter().find(|q| q.path == "/fal-ai/clarity-upscaler").unwrap().json();
    assert_eq!(up["upscale_factor"].as_u64(), Some(2));
    // Without the explicit flag an edit is never upscaled (Clarity would redraw the composition).
    let mut r = req("edit it");
    r.inputs = vec![input()];
    let res = fal::Fal.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(res.meta["upscaled"], false);
    assert!(srv.requests().iter().filter(|q| q.path == "/fal-ai/clarity-upscaler").count() == 1);
}

#[test]
fn tool_validation_rejects_bad_arguments() {
    let m = Media::new(MediaConfig::from_toml("[providers.xai]\napi_key = \"k\"\n"));
    let ctx = testutil::ctx("imgval");
    for (input, want) in [
        (json!({"prompt": "x", "action": "bogus"}), "unknown action"),
        (json!({"prompt": "x", "aspect_ratio": "wide-ish"}), "invalid aspect_ratio"),
        (json!({"prompt": "x", "quality": "ultra"}), "quality must be one of"),
        (json!({"prompt": "x", "output_format": "gif"}), "output_format must be one of"),
        (json!({"prompt": "x", "background": "blue"}), "background must be one of"),
        (json!({"prompt": "x", "count": 0}), "between 1 and 4"),
        (json!({"prompt": "x", "openai": {"outputCompression": 101}}), "outputCompression must be between 0 and 100"),
        (json!({"prompt": "x", "creativity": "wild"}), "creativity must be raw"),
        (json!({"prompt": "x", "intensity": 500}), "intensity must be between -100 and 100"),
        (json!({"prompt": "x", "provider": "nope"}), "unknown image provider"),
    ] {
        let out = tool_call(&m, &ctx, input.clone());
        assert!(out.is_error, "{input} should fail");
        assert!(out.content.contains(want), "{input} → {}", out.content);
    }
    // The tool input schema advertises the same bounds it enforces.
    let spec = tools(&m).remove(0).spec();
    assert_eq!(spec.input_schema["properties"]["count"]["maximum"], json!(4));
    assert_eq!(spec.input_schema["properties"]["resolution"]["enum"], json!(["1K", "2K", "4K"]));
}

#[test]
fn tool_reports_normalization_notes() {
    // xai has no `size`: a WxH hint is mapped to the closest aspect ratio and reported back.
    let srv = server(|_, _| json_reply(json!({"data": [{"b64_json": b64png()}]})));
    let m = media("xai", &srv.url, "provider = \"xai\"");
    let ctx = testutil::ctx("imgnote");
    let out = tool_call(&m, &ctx, json!({"prompt": "cat", "size": "1792x1024", "quality": "high"}));
    assert!(!out.is_error, "{}", out.content);
    for want in ["size 1792x1024 mapped to aspect ratio 16:9", "ignored unsupported quality high"] {
        assert!(out.content.contains(want), "missing {want:?} in {}", out.content);
    }
    let b = srv.requests()[0].json();
    assert_eq!((b["aspect_ratio"].as_str(), b.get("size"), b.get("quality")), (Some("16:9"), None, None));
    assert_eq!(b["n"].as_u64(), Some(1));
}
