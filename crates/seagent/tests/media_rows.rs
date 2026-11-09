//! Media rows proved end to end through the real binary (`build` / `build_agent` → `media_host`
//! → `seagent_media::tools`): the model asks for `image_generate` and the picture lands on disk,
//! `seagent stt` transcribes through the configured cloud provider, and `/image` in `seagent chat`
//! attaches a local file to the model's next turn. Every provider here is a loopback socket;
//! no API key, no real network.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

/// One request the fake provider saw.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    auth: String,
    body: String,
}

type Reply = (u16, String, Vec<u8>);

/// A scripted HTTP provider: one request per connection, then hang up.
struct Srv {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Srv {
    fn start(h: impl Fn(usize, &str, &str) -> Reply + Send + Sync + 'static) -> Srv {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(vec![]));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut r = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut len = 0usize;
                let mut auth = String::new();
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    if lower.starts_with("authorization:") {
                        auth = h.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
                    }
                }
                let mut body = vec![0u8; len];
                if len > 0 && r.read_exact(&mut body).is_err() {
                    continue;
                }
                let body = String::from_utf8_lossy(&body).to_string();
                let n = {
                    let mut g = s2.lock().unwrap();
                    g.push(Seen { path: path.clone(), auth: auth.clone(), body: body.clone() });
                    g.len() - 1
                };
                let (status, ctype, out) = h(n, &path, &body);
                let head = format!("HTTP/1.1 {status} OK\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", out.len());
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&out);
                let _ = stream.flush();
            }
        });
        Srv { url, seen }
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn sse(events: &[(&str, String)]) -> Reply {
    let mut out = String::new();
    for (e, d) in events {
        out.push_str(&format!("event: {e}\ndata: {d}\n\n"));
    }
    (200, "text/event-stream".into(), out.into_bytes())
}

/// A Responses-API turn that calls one tool.
fn tool_turn(name: &str, call_id: &str, args: &str) -> Reply {
    let item = serde_json::json!({"type": "function_call", "call_id": call_id, "name": name, "arguments": args});
    sse(&[
        ("response.output_item.added", serde_json::json!({"type": "response.output_item.added", "item": item}).to_string()),
        ("response.output_item.done", serde_json::json!({"type": "response.output_item.done", "item": item}).to_string()),
        ("response.completed", serde_json::json!({"type": "response.completed", "response": {"model": "gpt-4o-mini", "usage": {"input_tokens": 5, "output_tokens": 3}}}).to_string()),
    ])
}

/// A Responses-API turn that just answers.
fn text_turn(text: &str) -> Reply {
    sse(&[
        ("response.output_text.delta", serde_json::json!({"type": "response.output_text.delta", "delta": text}).to_string()),
        ("response.completed", serde_json::json!({"type": "response.completed", "response": {"model": "gpt-4o-mini", "usage": {"input_tokens": 5, "output_tokens": 1}}}).to_string()),
    ])
}

/// An 8×8 RGB PNG (image-gen saves it, `read`/`/image` accept it).
const PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAaklEQVR4nBWMQREAQQzCqqRKUBIlVYISlKDo9niSTGaGHTQw3OAhQ4eZZRctLLd4ydJ9QKyQQJywiKge+NV3/jswBPrCc+yh++87fOToPWDWyL98xiamfiBsUP7EBYeE5oGyRf3DV1xSWj4Df0sBxNBRMwAAAABJRU5ErkJggg==";

fn png() -> Vec<u8> {
    // Decode our own constant (no base64 crate in this test target).
    let tbl: Vec<u8> = {
        let mut v = vec![0u8; 256];
        for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
            v[*c as usize] = i as u8;
        }
        v
    };
    let bytes: Vec<u8> = PNG_B64.bytes().filter(|b| *b != b'=').collect();
    let mut out = vec![];
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= (tbl[*c as usize] as u32) << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

fn home(tag: &str) -> PathBuf {
    let d = seagent_core::tmp::scratch_path(format!("seagent-media-rows-{tag}-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(d.join("config")).unwrap();
    std::fs::create_dir_all(d.join("ws")).unwrap();
    d
}

/// The first `n` characters of `s` (never splits a UTF-8 sequence).
fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn config(h: &Path, toml_text: &str) {
    std::fs::write(h.join("config").join("config.toml"), toml_text).unwrap();
}

fn seagent(h: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_seagent"));
    cmd.args(args).env("SEAGENT_HOME", h).env("HOME", h.join("home")).env("SEAGENT_OFFLINE", "1").current_dir(h.join("ws"));
    for k in [
        "OPENAI_API_KEY",
        "VOICE_TOOLS_OPENAI_KEY",
        "ANTHROPIC_API_KEY",
        "XAI_API_KEY",
        "GOOGLE_API_KEY",
        "GROQ_API_KEY",
        "MISTRAL_API_KEY",
        "ELEVENLABS_API_KEY",
        "DEEPINFRA_API_KEY",
        "DEEPGRAM_API_KEY",
    ] {
        cmd.env_remove(k);
    }
    match stdin {
        Some(text) => {
            cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = cmd.spawn().expect("spawn seagent");
            child.stdin.take().unwrap().write_all(text.as_bytes()).ok();
            let out = child.wait_with_output().expect("seagent");
            (out.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
        }
        None => {
            let out = cmd.output().expect("run seagent");
            (out.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
        }
    }
}

/// Rows 1 + 7 (`image_generate`, Hermes `tools/image_generation_tool.py` and OpenClaw
/// `src/agents/tools/image-generate-tool.ts`): the registered tool is offered to the model,
/// the model's call reaches the configured provider and the file lands in the workspace.
#[test]
fn model_calls_image_generate_and_the_picture_is_saved() {
    let h = home("imagegen");
    let img = Srv::start(|_, _path, _body| (200, "application/json".into(), serde_json::json!({"data": [{"b64_json": PNG_B64}]}).to_string().into_bytes()));
    // The model asks for the tool on its first turn, then answers.
    let model = Srv::start(move |n, path, _| {
        if !path.ends_with("/responses") {
            return (404, "text/plain".into(), b"{}".to_vec());
        }
        if n == 0 {
            tool_turn("image_generate", "call_1", r#"{"prompt":"a red fox"}"#)
        } else {
            text_turn("done")
        }
    });
    config(
        &h,
        &format!(
            "[model]\ndefault = \"openai/gpt-4o-mini\"\n\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{m}/v1\"\nformat = \"openai_responses\"\n\n[media.image]\nprovider = \"openai\"\n\n[media.providers.openai]\napi_key = \"k\"\nbase_url = \"{i}\"\n",
            m = model.url,
            i = img.url
        ),
    );
    let (code, text) = seagent(&h, &["run", "draw a fox"], None);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("image_generate"), "the model's tool call ran:\n{text}");

    // The provider got the documented `/images/generations` call with the model's prompt.
    let calls = img.requests();
    assert_eq!(calls.len(), 1, "{calls:?}");
    let call = serde_json::from_str::<serde_json::Value>(&calls[0].body).unwrap();
    assert_eq!(calls[0].path, "/images/generations");
    assert_eq!(calls[0].auth, "Bearer k");
    assert_eq!((call["model"].as_str(), call["prompt"].as_str()), (Some("gpt-image-2"), Some("a red fox")));

    // The saved file is real, and its path went back to the model as a MEDIA: line.
    // Joined per component, as the product spells it (`ws\.seagent\media\images` on Windows).
    let dir = h.join("ws").join(".seagent").join("media").join("images");
    let files: Vec<PathBuf> = std::fs::read_dir(&dir).expect("image dir").map(|e| e.unwrap().path()).collect();
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(std::fs::read(&files[0]).unwrap(), png());
    let turns = model.requests();
    assert!(turns.len() >= 2, "{turns:?}");
    assert!(
        turns[0].body.contains("- image_generate:") || turns[0].body.contains("\"name\":\"image_generate\""),
        "the tool is offered to the model (deferred tool index or full schema):\n{}",
        head(&turns[0].body, 600)
    );
    // The body is JSON and the tool output a JSON string inside it: on Windows the path's
    // backslashes appear escaped once or twice (`C:\\\\Users…`); on Unix nothing changes.
    let esc = |s: &str| {
        let q = serde_json::to_string(s).unwrap();
        q[1..q.len() - 1].to_string()
    };
    let media = esc(&format!("MEDIA:{}", files[0].display()));
    assert!(
        turns[1].body.contains(&media) || turns[1].body.contains(&esc(&media)),
        "the tool result carries the MEDIA line:\n{}",
        head(&turns[1].body, 600)
    );
}

/// Row 2 (`STT 雲端`, Hermes `tools/transcription_cloud.py`): `seagent stt <file>` uploads to the
/// configured cloud provider and prints its transcript.
#[test]
fn stt_cli_transcribes_through_the_cloud_provider() {
    let h = home("stt");
    let srv = Srv::start(|_, _path, _body| (200, "application/json".into(), serde_json::json!({"text": "turn on the lights"}).to_string().into_bytes()));
    config(&h, &format!("[media.stt]\nprovider = \"openai\"\n\n[media.providers.openai]\napi_key = \"k\"\nbase_url = \"{}\"\n", srv.url));
    let wav = h.join("ws/clip.wav");
    // 0.5 s of 16 kHz mono PCM in a WAV container.
    let pcm: Vec<u8> = (0..8000u32).flat_map(|i| ((3000.0 * (i as f64 / 8.0).sin()) as i16).to_le_bytes()).collect();
    let mut body = Vec::new();
    body.extend_from_slice(b"RIFF");
    body.extend_from_slice(&(36 + pcm.len() as u32).to_le_bytes());
    body.extend_from_slice(b"WAVEfmt ");
    body.extend_from_slice(&16u32.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&16000u32.to_le_bytes());
    body.extend_from_slice(&32000u32.to_le_bytes());
    body.extend_from_slice(&2u16.to_le_bytes());
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(b"data");
    body.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
    body.extend_from_slice(&pcm);
    std::fs::write(&wav, &body).unwrap();

    let (code, text) = seagent(&h, &["stt", "clip.wav", "--json"], None);
    assert_eq!(code, 0, "{text}");
    let v: serde_json::Value = serde_json::from_str(text.trim().lines().last().unwrap_or("{}")).unwrap_or_else(|e| panic!("{e}: {text}"));
    assert_eq!(v["provider"], "openai");
    assert_eq!(v["text"], "turn on the lights");
    let calls = srv.requests();
    assert_eq!(calls[0].path, "/audio/transcriptions");
    assert_eq!(calls[0].auth, "Bearer k");
    assert!(calls[0].body.contains("whisper-1") && calls[0].body.contains("name=\"file\""), "{}", calls[0].body);
}

/// Row 8 (OpenClaw media understanding): the provider registry is reachable from the CLI —
/// `seagent infer image describe` sends the picture to the configured describer and prints its
/// answer. The fake is an OpenAI-compatible `/chat/completions` server.
#[test]
fn infer_image_describe_uses_the_configured_provider() {
    let h = home("understand-describe");
    let srv = Srv::start(|_, path, body| {
        assert_eq!(path, "/chat/completions");
        assert!(body.contains("\"image_url\"") && body.contains("data:image/png;base64,"), "the image is inline: {body}");
        (200, "application/json".into(), serde_json::json!({"choices": [{"message": {"content": "a tiny green square"}}]}).to_string().into_bytes())
    });
    config(
        &h,
        &format!(
            "[media.understanding]\nimage_provider = \"zai\"\n\n[media.providers.zai]\napi_key = \"z\"\nbase_url = \"{}\"\n",
            srv.url
        ),
    );
    std::fs::write(h.join("ws/shot.png"), png()).unwrap();
    let (code, text) = seagent(&h, &["infer", "image", "describe", "--file", "shot.png", "--json"], None);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("a tiny green square"), "{text}");
    let calls = srv.requests();
    assert_eq!(calls[0].auth, "Bearer z", "the provider key reached the request");
    assert!(calls[0].body.contains("\"model\":\"glm-4.6v\""), "upstream default model: {}", calls[0].body);
    // `video providers` lists the video-capable describers (google/openrouter/qwen/moonshot).
    let (code, text) = seagent(&h, &["infer", "video", "providers", "--json"], None);
    assert_eq!(code, 0, "{text}");
    for p in ["google", "openrouter", "qwen", "moonshot"] {
        assert!(text.contains(p), "video describer `{p}` missing:\n{text}");
    }
}

/// Row 3 (`/image`, Hermes `hermes_cli/commands.py`): a local file attached in `seagent chat`
/// rides along as an image block on the next message the model sees.
#[test]
fn image_slash_attaches_the_file_to_the_next_chat_message() {
    let h = home("image-slash");
    let srv = Srv::start(|_, _path, _| text_turn("a red fox on white"));
    config(&h, &format!("[model]\ndefault = \"openai/gpt-4o-mini\"\n\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{}/v1\"\nformat = \"openai_responses\"\n", srv.url));
    std::fs::write(h.join("ws/shot.png"), png()).unwrap();
    let b64 = PNG_B64;

    let (code, text) = seagent(&h, &["chat"], Some("/image shot.png\nwhat is on the white background?\n"));
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("image attached to your next message (1 pending)"), "{text}");
    let turns = srv.requests();
    let first = turns.first().unwrap_or_else(|| panic!("no model request:\n{text}"));
    assert!(first.body.contains("what is on the white background?"), "{}", first.body);
    assert!(first.body.contains(&format!("data:image/png;base64,{b64}")), "the image rode along as an image block:\n{}", first.body);
    assert!(first.body.contains("input_image"), "{}", first.body);

    // A missing file reports an error and attaches nothing.
    let h2 = home("image-slash-missing");
    config(&h2, &format!("[model]\ndefault = \"openai/gpt-4o-mini\"\n\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{}/v1\"\nformat = \"openai_responses\"\n", srv.url));
    let (code, text) = seagent(&h2, &["chat"], Some("/image nope.png\nhello\n"));
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("error:") && text.contains("nope.png"), "{text}");
    assert!(!text.contains("image attached"), "{text}");

    // Hermes `_split_path_input`: the rest of the line is the prompt, not part of the path.
    let h3 = home("image-slash-inline-prompt");
    config(&h3, &format!("[model]\ndefault = \"openai/gpt-4o-mini\"\n\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{}/v1\"\nformat = \"openai_responses\"\n", srv.url));
    std::fs::write(h3.join("ws/shot.png"), png()).unwrap();
    let (code, text) = seagent(&h3, &["chat"], Some("/image shot.png what colour is it?\n"));
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("image attached to your next message (1 pending)"), "{text}");
    let turns = srv.requests();
    let req = turns.iter().find(|r| r.body.contains("what colour is it?")).unwrap_or_else(|| panic!("the inline prompt became the message:\n{text}"));
    assert!(req.body.contains("input_image"), "{}", req.body);
    // A quoted path with spaces in it is still one token.
    assert_eq!(seagent_app::clip::split_path_input("\"my shot.png\" describe this"), ("my shot.png".to_string(), "describe this".to_string()));
}

/// Row 9 (OpenClaw `src/talk`): `seagent voice` is the talk-mode entry — one Enter, one recorded
/// take → STT → agent turn → spoken reply. The microphone (`record_command`) and the player
/// (`[media.tts] player`) are local scripts, so no audio device or provider is touched.
#[test]
#[cfg(feature = "personal")] // voice mode is a personal-desktop feature (gen1-306)
fn seagent_voice_runs_one_talk_mode_turn() {
    let h = home("talk");
    let model = Srv::start(|_, _path, _| text_turn("It is noon."));
    // 0.5 s of speech, then 1 s of silence: the take ends on the silence detector.
    let mut pcm: Vec<u8> = (0..8000u32).flat_map(|i| ((4000.0 * (i as f64 * 0.3).sin()) as i16).to_le_bytes()).collect();
    pcm.extend(std::iter::repeat_n(0u8, 32000));
    std::fs::write(h.join("ws/take.pcm"), &pcm).unwrap();
    let log = h.join("ws/played.log");
    let player = h.join("ws/player.sh");
    std::fs::write(&player, format!("#!/bin/sh\ncat \"$1\" >> {}\necho >> {}\n", log.display(), log.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&player, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    config(
        &h,
        &format!(
            "[model]\ndefault = \"openai/gpt-4o-mini\"\n\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{m}/v1\"\nformat = \"openai_responses\"\n\n[media.voice]\nmode = \"ptt\"\nbeep = false\nrecord_command = \"cat {pcm}\"\nsilence_duration = 0.5\nmax_wait = 10.0\n\n[media.stt]\nprovider = \"fake\"\n\n[media.stt.providers.fake]\ncommand = \"echo 'what time is it'\"\n\n[media.tts]\nprovider = \"fake\"\nplayer = \"{player} {{path}}\"\nprefs_path = \"{prefs}\"\n\n[media.tts.providers.fake]\ncommand = \"printf ID3FAKE > {{output_path}}\"\nformat = \"mp3\"\n",
            m = model.url,
            pcm = h.join("ws/take.pcm").display(),
            player = player.display(),
            prefs = h.join("ws/prefs.json").display()
        ),
    );
    // Enter = talk; the run stops after `--max-turns 1`.
    let (code, text) = seagent(&h, &["voice", "--max-turns", "1"], Some("\nq\n"));
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("Voice mode on (press Enter to talk"), "{text}");
    assert!(text.contains("you: what time is it"), "the take was transcribed:\n{text}");
    assert!(text.contains("seagent: It is noon."), "the agent's reply:\n{text}");
    assert!(text.contains("1 turn(s)"), "{text}");
    let played = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(played.contains("ID3FAKE"), "the reply was spoken: {played:?}");
    let turns = model.requests();
    assert_eq!(turns.len(), 1, "one agent turn: {turns:?}");
    assert!(turns[0].body.contains("what time is it"), "{}", &head(&turns[0].body, 400));
}
