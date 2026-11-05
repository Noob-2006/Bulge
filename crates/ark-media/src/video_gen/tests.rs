use super::*;
use crate::genrt::test_support::{fast_poll, MP4, PNG};
use crate::testutil::{cfg_for, ctx, FakeServer, RawReply, Req};

fn mp4() -> RawReply {
    (200, vec![("content-type".into(), "video/mp4".into())], MP4.to_vec())
}

fn j(v: Value) -> RawReply {
    (200, vec![("content-type".into(), "application/json".into())], v.to_string().into_bytes())
}

/// One fake server answering every provider's documented endpoints (links point back at it).
fn serve() -> FakeServer {
    let base = Arc::new(std::sync::Mutex::new(String::new()));
    let b2 = base.clone();
    let srv = FakeServer::start_raw(move |r, n| router(b2.lock().unwrap().clone())(r, n));
    *base.lock().unwrap() = srv.url.clone();
    srv
}

fn router(base: String) -> impl Fn(&Req, usize) -> RawReply {
    move |r, _| {
        let p = r.path.as_str();
        let u = |x: &str| format!("{base}{x}");
        match p {
            _ if p.ends_with(".mp4") || p.contains("/content?") || p.ends_with("/content") || p.contains(":download") => mp4(),
            // fal queue
            "/fal-ai/pixverse/v6/image-to-video" | "/fal-ai/pixverse/v6/text-to-video" | "/bytedance/seedance-2.0/reference-to-video" | "/fal-ai/seedvr/upscale/video" => j(json!({"request_id": "rq1", "status_url": u("/fal/status"), "response_url": u(if p.contains("seedvr") { "/fal/upres" } else { "/fal/res" })})),
            "/fal/status" => j(json!({"status": "COMPLETED"})),
            "/fal/res" => j(json!({"response": {"video": {"url": u("/out/fal.mp4"), "content_type": "video/mp4"}, "seed": 7}})),
            "/fal/upres" => j(json!({"video": {"url": u("/out/fal-up.mp4")}})),
            // xai + zai (both POST /videos/generations; z.AI answers with a task id, xAI with request_id)
            "/videos/generations" | "/videos/edits" | "/videos/extensions" => j(json!({"request_id": "x1", "id": "z1"})),
            "/videos/x1" => j(json!({"status": "done", "model": "grok-imagine-video", "video": {"url": u("/out/xai.mp4"), "duration": 6}})),
            // openrouter / deepinfra / together (POST /videos)
            "/videos" => j(json!({"id": "or1", "status": "queued", "polling_url": u("/videos/or1")})),
            "/videos/or1" => j(json!({"id": "or1", "status": "completed", "succeeded": true, "unsigned_urls": [u("/cdn/or1.mp4")], "data": [{"url": u("/out/di.mp4")}], "outputs": [{"video_url": u("/out/tg.mp4")}]})),
            // google
            "/models/veo-file:predictLongRunning" => j(json!({"name": "operations/opf"})),
            "/operations/opf" => j(json!({"name": "operations/opf", "done": true, "response": {"generatedVideos": [{"video": {"uri": "files/generated-video", "mimeType": "video/mp4"}}]}})),
            _ if p.contains(":predictLongRunning") => j(json!({"name": "operations/op1"})),
            "/operations/op1" => j(json!({"name": "operations/op1", "done": true, "response": {"generateVideoResponse": {"generatedSamples": [{"video": {"uri": u("/files/v1:download?alt=media")}}]}}})),
            // minimax
            "/v1/video_generation" => j(json!({"task_id": "mm1", "base_resp": {"status_code": 0}})),
            _ if p.starts_with("/v1/query/video_generation") => j(json!({"status": "Success", "file_id": "f1", "base_resp": {"status_code": 0}})),
            _ if p.starts_with("/v1/files/retrieve") => j(json!({"file": {"download_url": u("/out/mm.mp4"), "filename": "mm.mp4"}, "base_resp": {"status_code": 0}})),
            // runway
            "/v1/text_to_video" | "/v1/image_to_video" | "/v1/video_to_video" => j(json!({"id": "rw1"})),
            "/v1/tasks/rw1" => j(json!({"status": "SUCCEEDED", "output": [u("/out/rw.mp4")]})),
            // byteplus
            "/contents/generations/tasks" => j(json!({"id": "bp1"})),
            "/contents/generations/tasks/bp1" => j(json!({"status": "succeeded", "content": {"video_url": u("/out/bp.mp4")}})),
            // dashscope
            "/api/v1/services/aigc/video-generation/video-synthesis" => j(json!({"output": {"task_id": "ds1"}, "request_id": "r"})),
            "/api/v1/tasks/ds1" => j(json!({"output": {"task_status": "SUCCEEDED", "results": [{"video_url": u("/out/ds.mp4")}]}})),
            // kie
            "/api/file-base64-upload" => j(json!({"code": 200, "data": {"downloadUrl": u("/in/kie.png")}})),
            "/api/v1/jobs/createTask" => j(json!({"code": 200, "data": {"taskId": "k1"}})),
            _ if p.starts_with("/api/v1/jobs/recordInfo") => j(json!({"code": 200, "data": {"state": "success", "resultJson": json!({"resultUrls": [u("/out/kie.mp4")]}).to_string()}})),
            // pixverse
            "/image/upload" => j(json!({"ErrCode": 0, "Resp": {"img_id": 55}})),
            "/video/text/generate" | "/video/img/generate" => j(json!({"ErrCode": 0, "Resp": {"video_id": 9}})),
            "/video/result/9" => j(json!({"ErrCode": 0, "Resp": {"status": 1, "url": u("/out/pv.mp4")}})),
            // comfy
            "/prompt" => j(json!({"prompt_id": "cf1"})),
            "/history/cf1" => j(json!({"cf1": {"status": {"completed": true}, "outputs": {"9": {"images": [
                {"filename": "preview.png", "subfolder": "", "type": "output"},
                {"filename": "clip.mp4", "subfolder": "", "type": "output"}
            ]}}}})),
            _ if p.starts_with("/view?") => mp4(),
            // zai
            _ if p.starts_with("/async-result/") => j(json!({"task_status": "SUCCESS", "video_result": [{"url": u("/out/zai.mp4")}]})),
            // novita
            _ if p.starts_with("/v3/async/task-result") => j(json!({"task": {"status": "TASK_STATUS_SUCCEED"}, "videos": [{"video_url": u("/out/nv.mp4")}]})),
            _ if p.starts_with("/v3/async/") => j(json!({"task_id": "nv1"})),
            // vydra
            "/models/veo3" => j(json!({"jobId": "vy1", "status": "processing"})),
            "/jobs/vy1" => j(json!({"status": "completed", "videoUrl": u("/out/vy.mp4")})),
            _ => (404, vec![], format!("no route {p}").into_bytes()),
        }
    }
}

fn media(id: &str, base: &str, extra: &str) -> Media {
    Media { cfg: cfg_for(id, base, extra), http: Default::default() }
}

fn req(prompt: &str) -> VideoRequest {
    VideoRequest { prompt: prompt.into(), timeout: Duration::from_secs(10), ..Default::default() }
}

fn img_src(url: Option<&str>, role: Option<&str>) -> Source {
    let mut a = Asset::new(PNG.to_vec(), "image/png");
    a.url = url.map(str::to_string);
    Source { asset: a, role: role.map(str::to_string) }
}

fn last_body(srv: &FakeServer, path: &str) -> Value {
    srv.requests().into_iter().rev().find(|r| r.path.starts_with(path) && r.method == "POST").map(|r| r.json()).unwrap_or_else(|| panic!("no POST {path}: {:?}", srv.requests().iter().map(|r| r.path.clone()).collect::<Vec<_>>()))
}

#[test]
fn fal_family_queue_end_to_end_through_the_tool() {
    fast_poll();
    let srv2 = serve();
    let m = Arc::new(media("fal", &srv2.url, "[video]\nprovider = \"fal\"\nmodel = \"pixverse-v6\"\n"));
    let c = ctx("vgen-fal");
    let img = c.workspace.join("a.png");
    std::fs::write(&img, PNG).unwrap();
    let t = VideoGenerate { m: m.clone() };
    let out = t.call(&c, json!({"prompt": "a cat surfing", "image_url": "a.png", "durationSeconds": 40, "resolution": "720p", "negative_prompt": "blur", "seed": 3, "upscale": true}));
    assert!(!out.is_error, "{}", out.content);
    let body = last_body(&srv2, "/fal-ai/pixverse/v6/image-to-video");
    assert!(body["image_url"].as_str().unwrap().starts_with("data:image/png;base64,"));
    assert_eq!((body["duration"].clone(), body["resolution"].clone(), body["negative_prompt"].clone(), body["seed"].clone()), (json!("15"), json!("720p"), json!("blur"), json!(3)));
    assert!(body.get("aspect_ratio").is_none(), "pixverse family declares no aspect enum");
    let auth = srv2.requests().into_iter().find(|r| r.path.contains("pixverse")).unwrap();
    assert!(auth.header("authorization").unwrap().starts_with("Key "));
    assert!(auth.header("x-idempotency-key").is_some());
    let v: Value = serde_json::from_str(out.content.split("\nMEDIA:").next().unwrap()).unwrap();
    assert_eq!((v["provider"].as_str(), v["model"].as_str(), v["modality"].as_str()), (Some("fal"), Some("pixverse-v6"), Some("image")));
    assert_eq!(v["metadata"]["upscaled"], true, "SeedVR pass ran");
    assert!(out.content.contains("MEDIA:"), "{}", out.content);
    let p = out.content.lines().find_map(|l| l.strip_prefix("MEDIA:")).unwrap();
    assert_eq!(std::fs::read(p).unwrap(), MP4);
}

#[test]
fn fal_families_and_endpoint_payloads() {
    let f = hosted::family_of("fal-ai/veo3.1/image-to-video").unwrap();
    assert_eq!(f.id, "veo3.1");
    assert_eq!(hosted::family_of("minimax/h3").unwrap().id, "minimax-h3");
    assert_eq!(hosted::family_of("fal/kling-v3-pro").unwrap().id, "kling-v3-pro");
    let mut r = req("p");
    r.duration = Some(5);
    r.aspect_ratio = Some("9:16".into());
    r.audio = Some(true);
    let b = hosted::family_payload(f, &r, None);
    assert_eq!((b["duration"].clone(), b["aspect_ratio"].clone(), b["generate_audio"].clone()), (json!("4s"), json!("9:16"), json!(true)), "veo3.1 snaps to its enum (first of equal distances, like Python min) with an `s` suffix");
    let h3 = hosted::family_of("minimax-h3-max").unwrap();
    r.resolution = Some("1080p".into());
    let b = hosted::family_payload(h3, &r, Some("https://x/i.png"));
    assert_eq!((b["resolution"].clone(), b["prompt_expansion_mode"].clone()), (json!("768P"), json!("balanced")));
    assert!(b.get("aspect_ratio").is_none(), "i2v drops aspect_ratio");
    let ltx = hosted::family_of("ltx-2.5").unwrap();
    r.resolution = Some("4k".into());
    r.duration = Some(19);
    assert_eq!(hosted::family_payload(ltx, &r, None)["duration"], json!(10), "1440p/2160p caps LTX 2.5 at 10s");
    // OpenClaw raw endpoints: Seedance reference-to-video takes image/video/audio URL lists.
    let mut r = req("ref");
    r.images = vec![img_src(Some("https://h/a.png"), Some("reference_image"))];
    r.audios = vec![Source { asset: Asset::from_url("https://h/a.mp3", "audio/mpeg"), role: None }];
    r.duration = Some(9);
    let b = hosted::endpoint_payload(&r, "bytedance/seedance-2.0/reference-to-video").unwrap();
    assert_eq!((b["image_urls"][0].clone(), b["audio_urls"][0].clone(), b["duration"].clone()), (json!("https://h/a.png"), json!("https://h/a.mp3"), json!("9")));
    r.images.clear();
    assert!(hosted::endpoint_payload(&r, "bytedance/seedance-2.0/reference-to-video").unwrap_err().contains("at least one image or video"));
    let mut r = req("x");
    r.videos = vec![Source::default()];
    assert!(hosted::endpoint_payload(&r, "fal-ai/minimax/video-01-live").unwrap_err().contains("video reference"));
}

#[test]
fn runtime_guards_snap_and_fall_back() {
    fast_poll();
    let caps = more::Kie.caps("hailuo/2-3-image-to-video-pro");
    let r = req("p");
    assert_eq!(capability_mismatch("kie/hailuo", &caps, &r).unwrap(), "kie/hailuo does not support text-to-video generation; skipping");
    let mut r2 = req("p");
    r2.images = vec![img_src(None, None), img_src(None, None)];
    assert!(capability_mismatch("runway/gen4.5", &more::Runway.caps("gen4.5"), &r2).unwrap().contains("supports at most 1 reference image(s), 2 requested"));
    let mut r3 = req("p");
    r3.options.insert("seed".into(), json!("x"));
    assert_eq!(capability_mismatch("openrouter/m", &hosted::OpenRouter.caps("m"), &r3).unwrap(), "openrouter/m expects providerOptions.seed to be a finite number, got string; skipping");
    r3.options = Map::new();
    r3.options.insert("bogus".into(), json!(1));
    assert!(capability_mismatch("kie/kling", &more::Kie.caps("kling-2.6/text-to-video"), &r3).unwrap().contains("does not accept providerOptions"));
    let mut r4 = req("p");
    r4.duration = Some(20);
    assert!(capability_mismatch("runway/gen4.5", &more::Runway.caps("gen4.5"), &r4).unwrap().contains("supports at most 10s per video, 20s requested"));
    assert_eq!(snap_duration(7, &[4, 6, 8]), 8, "ties go to the longer value");
    assert_eq!(snap_duration(5, &[6, 10]), 6);

    // First candidate is skipped (images unsupported by kie t2v-only? no: runway rejects 2 images), second succeeds and snaps duration.
    let srv = serve();
    let m = media("openrouter", &srv.url, &format!("[providers.google]\napi_key = \"g\"\nbase_url = \"{}\"\n", srv.url));
    let mut rq = req("dog");
    rq.duration = Some(7);
    rq.options.insert("callback_url".into(), json!(5));
    let cands: Vec<(Arc<dyn VideoProvider>, String)> = vec![(Arc::new(hosted::OpenRouter), "google/veo-3.1-fast".into()), (Arc::new(hosted::Google), "veo-3.1-fast-generate-preview".into())];
    rq.options.clear();
    let r = generate(&m, &rq, &cands, &Cancel::new()).unwrap();
    assert_eq!(r.provider, "openrouter");
    assert_eq!(last_body(&srv, "/videos")["duration"], json!(8));
    assert!(r.notes.iter().any(|n| n.contains("durationSeconds 7 → 8")));
    // Provider error → the next candidate runs, attempts are reported.
    let bad = media("openrouter", "http://127.0.0.1:9", &format!("[providers.google]\napi_key = \"g\"\nbase_url = \"{}\"\n", srv.url));
    let r = generate(&bad, &rq, &cands, &Cancel::new()).unwrap();
    assert_eq!((r.provider.as_str(), r.attempts.len()), ("google", 1));
    let none = media("x", "http://127.0.0.1:9", "");
    let e = generate(&none, &rq, &cands[..1], &Cancel::new()).unwrap_err();
    assert!(e.contains("OpenRouter API key missing") || e.contains("failed"), "{e}");
}

#[test]
fn hosted_providers_request_shapes() {
    fast_poll();
    let srv = serve();
    let cancel = Cancel::new();

    // xAI: reference images → reference_images, duration clamp 10, 480p default.
    let m = media("xai", &srv.url, "");
    let mut r = req("ref video");
    r.model = "grok-imagine-video".into();
    r.images = vec![img_src(Some("https://h/1.png"), Some("reference_image")), img_src(Some("https://h/2.png"), Some("reference_image"))];
    r.duration = Some(14);
    let out = hosted::Xai.generate(&m, &r, &cancel).unwrap();
    let b = last_body(&srv, "/videos/generations");
    assert_eq!((b["reference_images"][1]["url"].clone(), b["duration"].clone(), b["resolution"].clone(), b["aspect_ratio"].clone()), (json!("https://h/2.png"), json!(10), json!("480p"), json!("16:9")));
    assert_eq!(out.meta["mode"], "referenceToVideo");
    r.images.push(img_src(None, Some("first_frame")));
    assert!(hosted::Xai.generate(&m, &r, &cancel).unwrap_err().contains("every image role to be reference_image"));
    let mut v15 = req("x");
    v15.model = "grok-imagine-video-1.5".into();
    assert!(hosted::Xai.generate(&m, &v15, &cancel).unwrap_err().contains("exactly one first-frame image"));

    // OpenRouter: frame images and references, content endpoint from our origin.
    let m = media("openrouter", &srv.url, "");
    let mut r = req("or");
    r.model = "google/veo-3.1-fast".into();
    r.images = vec![img_src(Some("https://h/a.png"), None), img_src(Some("https://h/b.png"), None), img_src(Some("https://h/c.png"), Some("reference_image"))];
    r.audio = Some(true);
    let out = hosted::OpenRouter.generate(&m, &r, &cancel).unwrap();
    let b = last_body(&srv, "/videos");
    assert_eq!((b["frame_images"][0]["frame_type"].clone(), b["frame_images"][1]["frame_type"].clone(), b["input_references"][0]["image_url"]["url"].clone(), b["generate_audio"].clone()), (json!("first_frame"), json!("last_frame"), json!("https://h/c.png"), json!(true)));
    assert_eq!(out.videos[0].bytes, MP4);
    assert!(srv.requests().iter().any(|q| q.path == "/videos/or1/content?index=0" && q.header("authorization") == Some("Bearer k")));

    // DeepInfra: seconds bucket 5/8, negative prompt and style from providerOptions.
    let m = media("deepinfra", &srv.url, "");
    let mut r = req("di");
    r.model = "Wan-AI/Wan2.6-T2V".into();
    r.duration = Some(7);
    r.options.insert("negativePrompt".into(), json!("ugly"));
    r.options.insert("style".into(), json!("anime"));
    hosted::DeepInfra.generate(&m, &r, &cancel).unwrap();
    let b = last_body(&srv, "/videos");
    assert_eq!((b["seconds"].clone(), b["negative_prompt"].clone(), b["style"].clone()), (json!(8), json!("ugly"), json!("anime")));

    // Google Veo: predictLongRunning + operation poll + keyed download from the API host.
    let m = media("google", &srv.url, "");
    let mut r = req("veo");
    r.model = "veo-3.1-fast-generate-preview".into();
    r.size = Some("1080x1920".into());
    r.duration = Some(5);
    let out = hosted::Google.generate(&m, &r, &cancel).unwrap();
    let b = last_body(&srv, "/models/veo-3.1-fast-generate-preview:predictLongRunning");
    assert_eq!((b["parameters"]["aspectRatio"].clone(), b["parameters"]["resolution"].clone(), b["parameters"]["durationSeconds"].clone()), (json!("9:16"), json!("1080p"), json!(6)));
    assert_eq!(out.videos[0].bytes, MP4);
    assert!(srv.requests().iter().any(|q| q.path.contains(":download") && q.path.contains("key=k")));
}

#[test]
fn more_providers_request_shapes() {
    fast_poll();
    let srv = serve();
    let cancel = Cancel::new();
    let ok = |r: Result<VideoResult, String>| {
        let r = r.unwrap();
        assert_eq!(r.videos[0].bytes, MP4);
        r
    };

    let m = media("minimax", &srv.url, "");
    let mut r = req("mm");
    r.model = "MiniMax-Hailuo-2.3".into();
    r.duration = Some(9);
    r.resolution = Some("720P".into());
    r.images = vec![img_src(Some("https://h/a.png"), None)];
    let out = ok(more::Minimax.generate(&m, &r, &cancel));
    let b = last_body(&srv, "/v1/video_generation");
    assert_eq!((b["duration"].clone(), b["resolution"].clone(), b["first_frame_image"].clone()), (json!(10), json!("768P"), json!("https://h/a.png")));
    assert_eq!(out.meta["fileName"], "mm.mp4");

    let m = media("runway", &srv.url, "");
    let mut r = req("rw");
    r.model = "gen4_turbo".into();
    assert!(more::Runway.generate(&m, &r, &cancel).unwrap_err().contains("text-to-video does not support model gen4_turbo"));
    r.images = vec![img_src(None, None)];
    r.aspect_ratio = Some("1:1".into());
    ok(more::Runway.generate(&m, &r, &cancel));
    let b = last_body(&srv, "/v1/image_to_video");
    assert_eq!((b["ratio"].clone(), b["duration"].clone()), (json!("960:960"), json!(5)));
    assert!(b["promptImage"].as_str().unwrap().starts_with("data:image/png"));
    assert!(srv.requests().iter().any(|q| q.header("x-runway-version") == Some("2024-11-06")));

    let m = media("byteplus", &srv.url, "");
    let mut r = req("bp");
    r.model = "seedance-1-0-pro-250528".into();
    r.options.insert("draft".into(), json!(true));
    r.options.insert("camera_fixed".into(), json!(false));
    r.watermark = Some(true);
    ok(more::BytePlus.generate(&m, &r, &cancel));
    let b = last_body(&srv, "/contents/generations/tasks");
    assert_eq!((b["resolution"].clone(), b["camera_fixed"].clone(), b["watermark"].clone(), b["content"][0]["type"].clone()), (json!("480p"), json!(false), json!(true), json!("text")));

    let m = media("alibaba", &srv.url, "");
    let mut r = req("wan");
    r.model = "wan2.6-t2v".into();
    r.images = vec![img_src(Some("https://h/i.png"), None)];
    r.resolution = Some("1080P".into());
    ok(more::Dashscope::alibaba().generate(&m, &r, &cancel));
    let b = last_body(&srv, "/api/v1/services/aigc/video-generation/video-synthesis");
    assert_eq!((b["model"].clone(), b["input"]["img_url"].clone(), b["parameters"]["resolution"].clone(), b["parameters"]["duration"].clone()), (json!("wan2.6-i2v"), json!("https://h/i.png"), json!("1080P"), json!(5)), "t2v + one image routes to the i2v sibling");
    assert!(srv.requests().iter().any(|q| q.header("x-dashscope-async") == Some("enable")));
    let mq = Media { cfg: crate::MediaConfig::from_toml(&format!("[providers.qwen]\napi_key = \"sk-sp-123\"\nbase_url = \"{}\"\n", srv.url)), http: Default::default() };
    assert!(more::Dashscope::qwen().generate(&mq, &r, &cancel).unwrap_err().contains("Coding Plan"));
    let mut r2 = req("t2v");
    r2.model = "wan2.6-t2v".into();
    r2.aspect_ratio = Some("9:16".into());
    r2.resolution = Some("720P".into());
    assert_eq!(more::wan_body("Qwen", &r2).unwrap()["parameters"]["size"], json!("720*1280"));

    let mk = Media { cfg: crate::MediaConfig::from_toml(&format!("[providers.kie]\napi_key = \"k\"\nbase_url = \"{0}\"\nupload_base_url = \"{0}\"\n", srv.url)), http: Default::default() };
    let mut r = req("kie video");
    r.model = "kling-2.6/text-to-video".into();
    r.images = vec![img_src(None, None)];
    r.duration = Some(8);
    r.audio = Some(true);
    ok(more::Kie.generate(&mk, &r, &cancel));
    let b = last_body(&srv, "/api/v1/jobs/createTask");
    assert_eq!((b["model"].clone(), b["input"]["image_urls"][0].as_str().map(|s| s.ends_with("/in/kie.png")), b["input"]["duration"].clone(), b["input"]["sound"].clone()), (json!("kling-2.6/image-to-video"), Some(true), json!("10"), json!(true)));

    let m = media("pixverse", &srv.url, "");
    let mut r = req("pv");
    r.model = "pixverse/v6".into();
    r.images = vec![img_src(None, None)];
    r.resolution = Some("480P".into());
    r.options.insert("motionMode".into(), json!("fast"));
    ok(more::PixVerse.generate(&m, &r, &cancel));
    let b = last_body(&srv, "/video/img/generate");
    assert_eq!((b["img_id"].clone(), b["quality"].clone(), b["motion_mode"].clone(), b["model"].clone()), (json!(55), json!("540p"), json!("fast"), json!("v6")));
    assert!(srv.requests().iter().any(|q| q.path == "/image/upload" && q.header("api-key") == Some("k") && q.header("ai-trace-id").is_some()));

    let m = media("together", &srv.url, "");
    let mut r = req("tg");
    r.model = "Wan-AI/wan2.7-t2v".into();
    r.size = Some("1920x1080".into());
    r.duration = Some(4);
    ok(more::Together.generate(&m, &r, &cancel));
    let b = last_body(&srv, "/videos");
    assert_eq!((b["resolution"].clone(), b["ratio"].clone(), b["seconds"].clone()), (json!("1080P"), json!("16:9"), json!("4")));
    r.size = Some("10x10".into());
    assert!(more::Together.generate(&m, &r, &cancel).unwrap_err().contains("does not support size 10x10"));
    assert_eq!(more::Together.default_timeout(), Duration::from_secs(1200), "OpenClaw DEFAULT_OPERATION_TIMEOUT_MS (Wan 2.7 takes ~10 min)");

    let m = media("zai", &srv.url, "");
    let mut r = req("zai");
    r.model = "cogvideox-3".into();
    r.aspect_ratio = Some("9:16".into());
    r.options.insert("fps".into(), json!(24));
    assert!(more::Zai.generate(&m, &r, &cancel).unwrap_err().contains("fps must be 30 or 60"));
    r.options.clear();
    r.options.insert("quality".into(), json!("quality"));
    r.duration = Some(8);
    // /videos/generations is shared with xAI's fake route; Z.AI reads `id`, xAI `request_id`.
    let out = ok(more::Zai.generate(&m, &r, &cancel));
    let b = last_body(&srv, "/videos/generations");
    assert_eq!((b["quality"].clone(), b["fps"].clone(), b["duration"].clone(), b["size"].clone(), b["with_audio"].clone()), (json!("quality"), json!(30), json!(8), json!("720x1280"), json!(false)));
    assert_eq!((out.meta["taskId"].clone(), out.meta["status"].clone()), (json!("z1"), json!("SUCCESS")));
    assert!(srv.requests().iter().any(|q| q.path == "/async-result/z1"), "Z.AI polls its own async-result route");

    let m = media("novita", &srv.url, "");
    let mut r = req("nv");
    r.model = "wan2.6-t2v".into();
    r.aspect_ratio = Some("4:3".into());
    r.resolution = Some("1080P".into());
    r.options.insert("shot_type".into(), json!("single"));
    ok(more::Novita.generate(&m, &r, &cancel));
    let b = last_body(&srv, "/v3/async/wan2.6-t2v");
    assert_eq!((b["parameters"]["size"].clone(), b["parameters"]["shot_type"].clone(), b["parameters"]["prompt_extend"].clone()), (json!("1632*1248"), json!("single"), json!(true)));

    let m = media("vydra", &srv.url, "");
    let mut r = req("vy");
    r.model = "veo3".into();
    ok(more::Vydra.generate(&m, &r, &cancel));
    r.model = "kling".into();
    assert!(more::Vydra.generate(&m, &r, &cancel).unwrap_err().contains("remote image URL"));

    let ids: Vec<&str> = providers().iter().map(|p| p.id()).collect();
    assert_eq!(ids.len(), 17);
    assert!(provider("dashscope").is_some() && provider("grok").is_some() && provider("comfyui").is_some());
    assert!(provider("z-ai").is_some() && provider("novita-ai").is_some() && provider("novitaai").is_some(), "upstream aliases");
}

#[test]
fn xai_edit_extend_tools_require_xai_backend() {
    fast_poll();
    let srv = serve();
    let off = Arc::new(media("xai", &srv.url, ""));
    assert_eq!(tools(&off).len(), 1, "edit/extend only when [media.video] provider = xai");
    let m = Arc::new(media("xai", &srv.url, "[video]\nprovider = \"xai\"\n"));
    let ts = tools(&m);
    assert_eq!(ts.iter().map(|t| t.spec().name).collect::<Vec<_>>(), vec!["video_generate", "xai_video_edit", "xai_video_extend"]);
    // Hermes check_fn is `provider == "xai"` **and** a configured key: no key, no tools.
    if std::env::var("XAI_API_KEY").is_err() {
        let nokey = Arc::new(Media { cfg: crate::MediaConfig::from_toml("[video]\nprovider = \"xai\"\n"), http: Default::default() });
        assert_eq!(tools(&nokey).len(), 1, "without an xAI key only video_generate is registered");
    }
    let c = ctx("xai-ext");
    let ext = &ts[2];
    let bad = ext.call(&c, json!({"prompt": "go on", "video_url": "/local/file.mp4"}));
    assert!(bad.is_error && bad.content.contains("public HTTPS MP4"));
    let out = ext.call(&c, json!({"prompt": "go on", "video_url": "https://cdn/x.mp4", "duration": 30}));
    assert!(!out.is_error, "{}", out.content);
    let b = last_body(&srv, "/videos/extensions");
    assert_eq!((b["duration"].clone(), b["video"]["url"].clone()), (json!(10), json!("https://cdn/x.mp4")));
    let out = ts[1].call(&c, json!({"prompt": "make it night", "video_url": "https://cdn/x.mp4", "duration": true}));
    assert!(!out.is_error, "{}", out.content);
    assert!(last_body(&srv, "/videos/edits").get("duration").is_none());
    assert!(out.content.contains("MEDIA:"));
}

#[test]
fn tool_validation_list_and_background() {
    fast_poll();
    let srv = serve();
    let m = Arc::new(media("vydra", &srv.url, "[video]\nprovider = \"vydra\"\n"));
    let t = VideoGenerate { m: m.clone() };
    let c = ctx("vgen-bg");
    assert!(t.call(&c, json!({"prompt": " "})).content.contains("prompt is required"));
    assert!(t.call(&c, json!({"prompt": "x", "operation": "edit"})).content.contains("provider-specific tool"));
    assert!(t.call(&c, json!({"prompt": "x", "providerOptions": 3})).content.contains("providerOptions must be a JSON object"));
    assert!(t.call(&c, json!({"prompt": "x", "image": "https://h/a.png", "imageRoles": ["a", "b"]})).content.contains("extra roles cannot be aligned"));
    let l = t.call(&c, json!({"action": "list"})).content;
    assert!(l.contains("- vydra (Vydra) ✓ [selected]") && l.contains("- kie (Kie AI)") && l.contains("providerOptions seed:number"), "{l}");
    let started = t.call(&c, json!({"prompt": "bg job", "background": true}));
    assert!(started.content.contains("Started video generation task video-"), "{}", started.content);
    let id = started.content.split_whitespace().find(|w| w.starts_with("video-")).unwrap().to_string();
    for _ in 0..200 {
        if genrt::get_job(&id).map(|j| j.status != "running").unwrap_or(false) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let st = t.call(&c, json!({"action": "status", "job_id": id})).content;
    assert!(st.contains("[succeeded]") && st.contains("MEDIA:"), "{st}");
    let fx = t.effects(&c, &json!({"prompt": "p", "image": "in.png"}));
    assert!(fx.iter().any(|e| matches!(e, Effect::Read { .. })) && fx.iter().any(|e| matches!(e, Effect::Net { .. })));
}

#[test]
fn every_registered_provider_generates_through_the_fake_server() {
    fast_poll();
    let srv = serve();
    let cancel = Cancel::new();
    // One case per provider id: the default (text-to-video) model of every backend.
    let cases: &[(&str, &str)] = &[
        ("fal", "pixverse-v6"),
        ("xai", "grok-imagine-video"),
        ("openrouter", "google/veo-3.1-fast"),
        ("deepinfra", "Pixverse/Pixverse-T2V"),
        ("google", "veo-3.1-fast-generate-preview"),
        ("minimax", "MiniMax-Hailuo-2.3"),
        ("runway", "gen4.5"),
        ("byteplus", "seedance-1-0-pro-250528"),
        ("alibaba", "wan2.6-t2v"),
        ("qwen", "wan2.6-t2v"),
        ("kie", "kling-2.6/text-to-video"),
        ("pixverse", "v6"),
        ("together", "Wan-AI/wan2.7-t2v"),
        ("zai", "cogvideox-3"),
        ("novita", "wan2.6-t2v"),
        ("vydra", "veo3"),
        ("comfy", "workflow"),
    ];
    let ids: Vec<&str> = providers().iter().map(|p| p.id()).collect();
    assert_eq!(cases.iter().map(|c| c.0).collect::<Vec<_>>(), ids, "one exercised case per registered provider");
    for (id, model) in cases {
        let cfg = if *id == "comfy" {
            // ComfyUI is config-only: a workflow + prompt node, no API key.
            format!("[providers.comfy]\nbase_url = \"{}\"\nprompt_node_id = \"6\"\npoll_interval_ms = 1\n[providers.comfy.workflow.6]\ninputs = {{ text = \"\" }}\n", srv.url)
        } else {
            format!("[providers.{id}]\napi_key = \"k\"\nbase_url = \"{}\"\n", srv.url)
        };
        let m = Media { cfg: crate::MediaConfig::from_toml(&cfg), http: Default::default() };
        let p = provider(id).unwrap_or_else(|| panic!("{id} is not reachable through providers()/provider()"));
        assert_eq!(p.id(), *id);
        let mut r = req("a slow wave");
        r.model = (*model).into();
        let res = p.generate(&m, &r, &cancel).unwrap_or_else(|e| panic!("{id} failed: {e}"));
        assert_eq!(res.videos.len(), 1, "{id} returned no single fake video");
        assert_eq!(res.videos[0].bytes, MP4, "{id} did not deliver the fake video bytes");
    }
}

/// Reachability: all 17 providers are listed by `action=list` and each one can be selected
/// through the tool's `provider` argument and returns a saved video (Hermes `video_generate`
/// `model` / OpenClaw `providerOptions`-free path).
#[test]
fn every_provider_is_reachable_through_the_video_generate_tool() {
    fast_poll();
    let srv = serve();
    let cases: &[(&str, &str)] = &[
        ("fal", "pixverse-v6"),
        ("xai", "grok-imagine-video"),
        ("openrouter", "google/veo-3.1-fast"),
        ("deepinfra", "Pixverse/Pixverse-T2V"),
        ("google", "veo-3.1-fast-generate-preview"),
        ("minimax", "MiniMax-Hailuo-2.3"),
        ("runway", "gen4.5"),
        ("byteplus", "seedance-1-0-pro-250528"),
        ("alibaba", "wan2.6-t2v"),
        ("qwen", "wan2.6-t2v"),
        ("kie", "kling-2.6/text-to-video"),
        ("pixverse", "v6"),
        ("together", "Wan-AI/wan2.7-t2v"),
        ("zai", "cogvideox-3"),
        ("novita", "wan2.6-t2v"),
        ("vydra", "veo3"),
        ("comfy", "workflow"),
    ];
    let list = VideoGenerate { m: Arc::new(media("fal", &srv.url, "")) }.call(&ctx("vgen-tool-list"), json!({"action": "list"})).content;
    for (id, _) in cases {
        assert!(list.contains(&format!("- {id} (")), "action=list must offer `{id}`:\n{list}");
    }
    for (id, model) in cases {
        let cfg = if *id == "comfy" {
            format!("[providers.comfy]\nbase_url = \"{}\"\nprompt_node_id = \"6\"\npoll_interval_ms = 1\n[providers.comfy.workflow.6]\ninputs = {{ text = \"\" }}\n", srv.url)
        } else {
            format!("[providers.{id}]\napi_key = \"k\"\nbase_url = \"{}\"\n", srv.url)
        };
        let m = Arc::new(Media { cfg: crate::MediaConfig::from_toml(&cfg), http: Default::default() });
        let c = ctx(&format!("vgen-tool-{id}"));
        let out = VideoGenerate { m }.call(&c, json!({"prompt": "a slow wave", "provider": id, "model": model}));
        assert!(!out.is_error, "{id} through the tool: {}", out.content);
        let v: Value = serde_json::from_str(out.content.split("\nMEDIA:").next().unwrap()).unwrap_or_else(|e| panic!("{id}: {e}: {}", out.content));
        assert_eq!(v["provider"], json!(id), "{}", out.content);
        let p = out.content.lines().find_map(|l| l.strip_prefix("MEDIA:")).unwrap_or_else(|| panic!("{id} saved no file: {}", out.content));
        assert_eq!(std::fs::read(p).unwrap(), MP4, "{id}");
    }
}

#[test]
fn dashscope_r2v_caps_and_qwen_request_shape() {
    fast_poll();
    let srv = serve();
    let cancel = Cancel::new();
    // r2v models take up to 5 reference images / 3 videos and cap at 10s (OpenClaw
    // `dashscopeWanR2vCapabilities` = the video-to-video caps).
    for model in ["wan2.6-r2v", "wan2.6-r2v-flash", "wan2.7-r2v"] {
        let caps = more::Dashscope::qwen().caps(model);
        let mut r = req("refs");
        r.images = vec![img_src(Some("https://h/1.png"), None), img_src(Some("https://h/2.png"), None), img_src(Some("https://h/3.png"), None)];
        assert_eq!(capability_mismatch(&format!("qwen/{model}"), &caps, &r), None, "{model} accepts 3 reference images");
        r.duration = Some(15);
        assert_eq!(caps.i2v.durations.iter().copied().max(), Some(10), "{model} r2v durations are the 2-10s list");
        assert!(caps.i2v.max_images == 5 && caps.i2v.max_videos == 3);
    }
    assert!(more::Dashscope::qwen().caps("wan2.7-r2v").i2v.aspect_ratios.contains(&"16:9".to_string()), "wan2.7 r2v advertises aspect ratios");
    assert!(!more::Dashscope::qwen().caps("wan2.7-r2v").i2v.supports_audio, "wan2.7 r2v has no audio toggle");
    assert!(more::Dashscope::qwen().caps("wan2.6-r2v").i2v.supports_audio);

    // Qwen Cloud: same DashScope wire shape, its own credentials, an r2v reference request.
    let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[providers.qwen]\napi_key = \"qk\"\nbase_url = \"{}\"\n", srv.url)), http: Default::default() };
    let mut r = req("three refs");
    r.model = "wan2.6-r2v".into();
    r.images = vec![img_src(Some("https://h/1.png"), None), img_src(Some("https://h/2.png"), None), img_src(Some("https://h/3.png"), None)];
    r.videos = vec![Source { asset: Asset::from_url("https://h/v.mp4", "video/mp4"), role: None }];
    r.duration = Some(12);
    let out = more::Dashscope::qwen().generate(&m, &r, &cancel).unwrap();
    assert_eq!(out.videos[0].bytes, MP4);
    let b = last_body(&srv, "/api/v1/services/aigc/video-generation/video-synthesis");
    assert_eq!((b["model"].clone(), b["input"]["reference_urls"].clone(), b["parameters"]["duration"].clone()), (json!("wan2.6-r2v"), json!(["https://h/1.png", "https://h/2.png", "https://h/3.png", "https://h/v.mp4"]), json!(12)));
    let q = srv.requests().into_iter().find(|q| q.path.contains("video-synthesis")).unwrap();
    assert_eq!((q.header("authorization"), q.header("x-dashscope-async")), (Some("Bearer qk"), Some("enable")));
    assert_eq!(out.meta["taskId"], "ds1");
}

#[test]
fn comfy_video_workflow_serves_video_outputs() {
    fast_poll();
    let srv = serve();
    let m = Media {
        cfg: crate::MediaConfig::from_toml(&format!("[providers.comfy]\nbase_url = \"{}\"\nprompt_node_id = \"6\"\npoll_interval_ms = 1\n[providers.comfy.workflow.6]\ninputs = {{ text = \"\" }}\n", srv.url)),
        http: Default::default(),
    };
    assert!(more::Comfy.configured(&m));
    let mut r = req("a video of a kite");
    r.model = "workflow".into();
    let out = more::Comfy.generate(&m, &r, &Cancel::new()).unwrap();
    // Only the .mp4 in the `images` output bucket is a video; the preview png is skipped.
    assert_eq!((out.videos.len(), out.videos[0].bytes.clone()), (1, MP4.to_vec()));
    assert_eq!(out.meta["prompt_id"], "cf1");
    let p = srv.requests().into_iter().find(|q| q.path == "/prompt").unwrap().json();
    assert_eq!(p["prompt"]["6"]["inputs"]["text"], "a video of a kite");
    assert!(srv.requests().iter().any(|q| q.path.starts_with("/view?filename=clip.mp4")), "downloads the mp4 through /view");
    assert!(srv.requests().iter().any(|q| q.path == "/history/cf1"), "polls /history/<prompt_id>");
}

#[test]
fn google_files_handle_downloads_through_the_rest_media_endpoint() {
    fast_poll();
    let srv = serve();
    let m = media("google", &srv.url, "");
    let mut r = req("file handle");
    r.model = "veo-file".into();
    let out = hosted::Google.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(out.videos[0].bytes, MP4);
    // A Files API handle (`files/<id>`) is not a host — it becomes {base}/files/<id>:download.
    assert!(srv.requests().iter().any(|q| q.path == "/files/generated-video:download?alt=media&key=k"), "{:?}", srv.requests().iter().map(|q| q.path.clone()).collect::<Vec<_>>());
}

#[test]
fn runway_video_to_video_keeps_the_text_to_video_ratio_rule() {
    let srv = serve();
    let m = media("runway", &srv.url, "");
    let mut r = req("rw v2v");
    r.model = "gen4_aleph".into();
    r.videos = vec![Source { asset: Asset::from_url("https://h/in.mp4", "video/mp4"), role: None }];
    r.aspect_ratio = Some("1:1".into());
    assert!(more::Runway.generate(&m, &r, &Cancel::new()).unwrap_err().contains("only 16:9 or 9:16"), "video-to-video has no input image, so the text-to-video ratio rule applies");
    r.aspect_ratio = Some("9:16".into());
    let out = more::Runway.generate(&m, &r, &Cancel::new()).unwrap();
    assert_eq!(out.videos[0].bytes, MP4);
    let b = last_body(&srv, "/v1/video_to_video");
    assert_eq!((b["ratio"].clone(), b["videoUri"].clone()), (json!("720:1280"), json!("https://h/in.mp4")));
}
