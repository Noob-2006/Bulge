use super::*;
use crate::testutil::{cfg_for, temp_dir, FakeServer};

fn media(toml: &str) -> Media {
    Media { cfg: crate::MediaConfig::from_toml(toml), http: Default::default() }
}

fn wav(secs: f64) -> Vec<u8> {
    let s: Vec<i16> = (0..(secs * 16000.0) as usize).map(|i| ((i as f64 * 0.2).sin() * 4000.0) as i16).collect();
    crate::audio::wav_encode(&s, 16000, 1)
}

fn script(dir: &std::path::Path, name: &str, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.display().to_string()
}

#[test]
fn openai_compatible_multipart_language_prompt_and_model_remap() {
    let srv = FakeServer::start(|r, _| match r.path.as_str() {
        "/audio/transcriptions" if r.body.contains("whisper-1") => (200, vec![("content-type".into(), "text/plain".into())], "hello world\n".into()),
        "/audio/transcriptions" => (200, vec![("content-type".into(), "application/json".into())], r#"{"text":" hi there ","language":"en","duration":1.5}"#.into()),
        _ => (404, vec![], String::new()),
    });
    let m = Media { cfg: cfg_for("openai", &srv.url, "[stt]\nprovider = \"openai\"\nlanguage = \"de\"\nprompt = \"Kubernetes, seagent\"\n[stt.openai]\nmodel = \"distil-whisper-large-v3-en\""), http: Default::default() };
    let (p, t) = transcribe(&m, &SttRequest::new(wav(0.5), "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!((p.as_str(), t.text.as_str()), ("openai", "hello world"));
    let r = &srv.requests()[0];
    assert_eq!(r.header("authorization"), Some("Bearer k"));
    for needle in ["name=\"model\"\r\n\r\nwhisper-1", "name=\"response_format\"\r\n\r\ntext", "name=\"language\"\r\n\r\nde", "name=\"prompt\"\r\n\r\nKubernetes, seagent", "filename=\"audio.wav\""] {
        assert!(r.body.contains(needle), "missing {needle:?}");
    }
    // groq: json response, gpt-transcribe uses the languages list.
    let g = Media { cfg: cfg_for("groq", &srv.url, "[stt]\nprovider = \"groq\""), http: Default::default() };
    let (p, t) = transcribe(&g, &SttRequest::new(wav(0.2), "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!((p.as_str(), t.text.as_str(), t.duration), ("groq", "hi there", Some(1.5)));
    assert!(srv.requests()[1].body.contains("whisper-large-v3-turbo"));
    let o = Media { cfg: cfg_for("openai", &srv.url, "[stt]\nprovider = \"openai\"\nlanguage = \"fr\"\n[stt.openai]\nmodel = \"gpt-transcribe\""), http: Default::default() };
    transcribe(&o, &SttRequest::new(wav(0.2), "audio/wav"), &Cancel::new()).unwrap();
    assert!(srv.requests()[2].body.contains("name=\"languages[]\"\r\n\r\nfr"));
}

#[test]
fn mistral_xai_elevenlabs_deepgram_request_shapes() {
    let srv = FakeServer::start(|r, _| {
        let ok = |b: &str| (200, vec![("content-type".to_string(), "application/json".to_string())], b.to_string());
        match r.path.as_str() {
            "/audio/transcriptions" => ok(r#"{"text":"language en <asr_text> bonjour"}"#),
            "/stt" => ok(r#"{"text":"grok text","language":"en","duration":2.0}"#),
            "/speech-to-text" => ok(r#"{"text":"scribe text","language_code":"eng"}"#),
            p if p.starts_with("/listen?") => ok(r#"{"metadata":{"duration":3.0},"results":{"channels":[{"alternatives":[{"transcript":"left"}]},{"alternatives":[{"transcript":"right"}]}]}}"#),
            _ => (500, vec![], r#"{"error":{"message":"nope"}}"#.into()),
        }
    });
    let run = |id: &str, extra: &str| {
        let m = Media { cfg: cfg_for(id, &srv.url, &format!("[stt]\nprovider = \"{id}\"\n{extra}")), http: Default::default() };
        transcribe(&m, &SttRequest::new(wav(0.2), "audio/wav"), &Cancel::new()).unwrap().1
    };
    assert_eq!(run("mistral", "").text, "bonjour");
    let x = run("xai", "language = \"en\"");
    assert_eq!((x.text.as_str(), x.language.as_deref()), ("grok text", Some("en")));
    let e = run("elevenlabs", "[stt.elevenlabs]\nlanguage_code = \"eng\"");
    assert_eq!((e.text.as_str(), e.language.as_deref()), ("scribe text", Some("eng")));
    let d = run("deepgram", "language = \"en\"");
    assert_eq!((d.text.as_str(), d.duration), ("left\n\nright", Some(3.0)));
    let reqs = srv.requests();
    assert!(reqs[0].body.contains("voxtral-mini-latest") && reqs[0].header("authorization") == Some("Bearer k"));
    assert!(reqs[1].body.contains("grok-voice-transcribe-2.0") && reqs[1].body.contains("name=\"format\"\r\n\r\ntrue") && reqs[1].body.contains("name=\"diarize\"\r\n\r\nfalse"));
    assert!(reqs[2].header("xi-api-key") == Some("k") && reqs[2].body.contains("name=\"model_id\"\r\n\r\nscribe_v2") && reqs[2].body.contains("name=\"language_code\"\r\n\r\neng"));
    assert!(reqs[3].path.contains("model=nova-3") && reqs[3].path.contains("language=en") && reqs[3].header("authorization") == Some("Token k") && reqs[3].header("content-type") == Some("audio/wav"));
    // Errors carry the provider message.
    let bad = Media { cfg: cfg_for("openai", &format!("{}/x", srv.url), "[stt]\nprovider = \"openai\""), http: Default::default() };
    let err = transcribe(&bad, &SttRequest::new(wav(0.1), "audio/wav"), &Cancel::new()).unwrap_err();
    assert!(err.contains("OpenAI transcription failed: HTTP 500") && err.contains("nope"), "{err}");
}

#[test]
fn resolution_order_plugins_and_errors() {
    // Auto: the first available provider in `providers()` order (local > local_command > groq >
    // openai > mistral > xai > elevenlabs > deepinfra). The keys for the cloud providers ranked
    // above xAI come from the shell, and a dev/CI box with e.g. OPENAI_API_KEY or MISTRAL_API_KEY
    // exported would legitimately win, so pin that part of the environment first.
    for k in ["GROQ_API_KEY", "OPENAI_API_KEY", "VOICE_TOOLS_OPENAI_KEY", "MISTRAL_API_KEY"] {
        std::env::remove_var(k);
    }
    let m = Media { cfg: cfg_for("elevenlabs", "http://127.0.0.1:9", "[providers.xai]\napi_key = \"x\"\n[stt.local]\npython = \"/nonexistent/python\"\nwhisper_cpp = \"/nonexistent/whisper\""), http: Default::default() };
    // xAI wins unless a local engine happens to be installed (config points at nonexistent ones).
    if ["local", "local_command"].iter().all(|id| !builtin(id).is_some_and(|p| p.available(&m))) {
        assert_eq!(resolve_provider(&m), "xai");
    }
    // Explicit selection without credentials: no silent fallback.
    let e = media("[stt]\nprovider = \"groq\"\n");
    if std::env::var("GROQ_API_KEY").is_err() {
        assert_eq!(resolve_provider(&e), "none");
        assert!(transcribe(&e, &SttRequest::new(wav(0.1), "audio/wav"), &Cancel::new()).unwrap_err().contains("'groq' configured but unavailable"));
    }
    let off = media("[stt]\nenabled = false\n");
    assert!(transcribe(&off, &SttRequest::new(wav(0.1), "audio/wav"), &Cancel::new()).unwrap_err().contains("disabled"));
    let unknown = media("[stt]\nprovider = \"mystery\"\n");
    assert!(transcribe(&unknown, &SttRequest::new(wav(0.1), "audio/wav"), &Cancel::new()).unwrap_err().contains("no built-in, command, or plugin provider registered"));
    // Plugin providers: reserved names rejected, others dispatched.
    struct Plug(&'static str);
    impl SttProvider for Plug {
        fn id(&self) -> &str {
            self.0
        }
        fn env(&self) -> &[&str] {
            &[]
        }
        fn local(&self) -> bool {
            true
        }
        fn transcribe(&self, _m: &Media, req: &SttRequest, _c: &Cancel) -> Result<Transcript, String> {
            Ok(Transcript { text: format!("plugin heard {} bytes, prompt={:?}", req.audio.len(), req.prompt), ..Default::default() })
        }
    }
    assert!(register(Arc::new(Plug("openai"))).unwrap_err().contains("reserved"));
    register(Arc::new(Plug("mystery-plugin"))).unwrap();
    let p = media("[stt]\nprovider = \"mystery-plugin\"\nprompt = \"vocab\"\n");
    let (id, t) = transcribe(&p, &SttRequest::new(vec![1, 2, 3], "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!((id.as_str(), t.text.as_str()), ("mystery-plugin", "plugin heard 3 bytes, prompt=Some(\"vocab\")"));
    // Whisper-family prompt cap keeps the tail.
    let long = "a".repeat(2000) + "TAIL";
    let capped = cap_prompt(Some(long.clone()), "openai").unwrap();
    assert!(capped.len() == 896 && capped.ends_with("TAIL"));
    assert_eq!(cap_prompt(Some(long.clone()), "mistral").unwrap(), long);
    assert!(is_local_url("http://127.0.0.1:8000/v1") && is_local_url("http://172.20.0.2/v1") && !is_local_url("https://api.openai.com/v1"));
    assert_eq!(local::normalize_language(Some("繁體中文")).as_deref(), Some("zh"));
    assert_eq!(local::normalize_language(Some("pt_BR")).as_deref(), Some("pt"));
    assert_eq!(local::normalize_language(Some("English")), None);
    assert_eq!(local::normalize_model(Some("whisper-1")), "base");
}

#[test]
fn command_provider_placeholders_env_scrub_and_failures() {
    let d = temp_dir("stt-cmd");
    let m = media(&format!(
        "[stt]\nprovider = \"mycli\"\nlanguage = \"ja\"\n[stt.providers.mycli]\ncommand = \"printf '%s|%s|%s' {{format}} {{language}} {{model}} > {{output_path}}; env >> {{output_dir}}/env.txt; cp {{output_dir}}/env.txt {}/env.txt\"\nmodel = \"tiny\"\n[stt.providers.curl]\ncommand = \"echo from stdout\"\n[stt.providers.slow]\ncommand = \"sleep 5\"\ntimeout = 0.2\n[stt.providers.boom]\ncommand = \"echo bad >&2; exit 4\"\n[stt.providers.norm]\ncommand = \"head -c 4 {{input_path}} > {{output_path}}\"\nnormalize = true\n",
        d.display()
    ));
    let (id, t) = transcribe(&m, &SttRequest::new(wav(0.1), "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!((id.as_str(), t.text.as_str()), ("mycli", "txt|ja|tiny"));
    let env = std::fs::read_to_string(d.join("env.txt")).unwrap();
    assert!(env.contains("PATH=") && !env.contains("CARGO_"), "secrets/unknown env must not reach the child");
    let req = SttRequest::new(b"OggS-not-really".to_vec(), "audio/ogg");
    assert_eq!(transcribe_with(&m, "curl", &req, &Cancel::new()).unwrap().1.text, "from stdout");
    assert!(transcribe_with(&m, "slow", &req, &Cancel::new()).unwrap_err().contains("timed out after 0.2s"));
    let e = transcribe_with(&m, "boom", &req, &Cancel::new()).unwrap_err();
    assert!(e.contains("exited with code 4") && e.contains("bad"), "{e}");
    // normalize = true hands the command 16 kHz WAV (the input already is WAV here).
    assert_eq!(transcribe_with(&m, "norm", &SttRequest::new(wav(0.1), "audio/wav"), &Cancel::new()).unwrap().1.text, "RIFF");
    // A command block can never shadow a built-in.
    assert!(command::Command::from_config(&media("[stt.providers.openai]\ncommand = \"x\""), "openai").is_none());
}

#[test]
fn local_command_and_faster_whisper_helper() {
    let d = temp_dir("stt-local");
    // A whisper-CLI-shaped template: writes <output_dir>/<name>.txt.
    let fake = script(&d, "whisper", "echo \"lang=$2 model=$3\" > \"$1/out.txt\"");
    let m = media(&format!("[stt]\nprovider = \"local_command\"\nlanguage = \"繁體中文\"\n[stt.local]\nmodel = \"whisper-1\"\ncommand = \"{fake} {{output_dir}} {{language}} {{model}} {{input_path}}\"\npython = \"/nonexistent/python\"\n"));
    let (id, t) = transcribe(&m, &SttRequest::new(wav(0.2), "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!((id.as_str(), t.text.as_str()), ("local_command", "lang=zh model=base"));
    // faster-whisper through the Python child: kwargs carry the hardening knobs.
    let py = script(&d, "python", &format!("case \"$2\" in *find_spec*) exit 0;; esac\nprintf '%s' \"$3\" > {}/args.json\necho '{{\"text\":\"local words\",\"language\":\"en\",\"duration\":0.2,\"segments\":[{{\"start\":0,\"end\":0.2,\"text\":\"local words\"}}]}}'", d.display()));
    let f = media(&format!("[stt]\nprovider = \"local\"\nprompt = \"seagent\"\n[stt.local]\npython = \"{py}\"\nvad_min_silence_ms = 700\nno_speech_prob_threshold = 0.5\nlanguage = \"en-US\"\n"));
    assert_eq!(resolve_provider(&f), "local");
    let (id, t) = transcribe(&f, &SttRequest::new(wav(0.2), "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!((id.as_str(), t.text.as_str(), t.segments.len()), ("local", "local words", 1));
    let a: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(d.join("args.json")).unwrap()).unwrap();
    let kw = &a["kwargs"];
    assert_eq!((kw["beam_size"].as_i64(), kw["condition_on_previous_text"].as_bool(), kw["vad_filter"].as_bool()), (Some(5), Some(false), Some(true)));
    assert_eq!((kw["vad_parameters"]["min_silence_duration_ms"].as_i64(), kw["no_speech_threshold"].as_f64(), kw["language"].as_str(), kw["initial_prompt"].as_str()), (Some(700), Some(0.5), Some("en"), Some("seagent")));
    assert_eq!((a["model"].as_str(), a["device"].as_str()), (Some("base"), Some("auto")));
    // Local fallback never goes to the cloud.
    let none = media("[stt.local]\npython = \"/nonexistent/python\"\nwhisper_cpp = \"/nonexistent/w\"\n");
    if crate::proc::which("whisper").is_none() {
        assert!(transcribe_local_fallback(&none, &SttRequest::new(wav(0.1), "audio/wav"), &Cancel::new()).unwrap_err().contains("No installed local STT backend"));
    }
}

#[test]
fn whisper_cpp_managed_models_are_downloaded_once_and_verified() {
    let d = temp_dir("stt-wcpp");
    let (model, vad) = (b"fake ggml base model".to_vec(), b"fake silero vad".to_vec());
    let hex = |b: &[u8]| seagent_net::crypto::sha256(b).iter().map(|x| format!("{x:02x}")).collect::<String>();
    let (mb, vb) = (model.clone(), vad.clone());
    let srv = FakeServer::start_raw(move |r, _| match r.path.as_str() {
        "/ggml-base.bin" => (200, vec![], mb.clone()),
        "/vad.bin" => (200, vec![], vb.clone()),
        _ => (404, vec![], vec![]),
    });
    // whisper.cpp CLI stand-in: honours -m / -l / -of and writes <of>.txt.
    // `--help` advertises VAD, like a whisper.cpp built with it; `--vad` is then
    // passed. Without the flag in `--help` seagent must leave it out (1.7.4 builds
    // without VAD exit 1 on `unknown argument: --vad`).
    let bin = script(&d, "whisper-cli", "while [ $# -gt 0 ]; do case \"$1\" in --help) echo \"usage: whisper-cli --vad -vm FILE -vsd N\"; exit 0;; -m) M=$2;; -l) L=$2;; -of) OF=$2;; -vm) VM=$2;; esac; shift; done\n[ -f \"$M\" ] && [ -f \"$VM\" ] || exit 9\necho \"cpp $L\" > \"$OF.txt\"");
    let cfg = |sha: &str| format!("[stt]\nprovider = \"local_command\"\n[stt.local]\npython = \"/nonexistent/python\"\nwhisper_cpp = \"{bin}\"\nmodels_dir = \"{}\"\nwhisper_cpp_model = {{ name = \"ggml-base.bin\", url = \"{u}/ggml-base.bin\", sha256 = \"{sha}\" }}\nwhisper_cpp_vad = {{ name = \"vad.bin\", url = \"{u}/vad.bin\", sha256 = \"{}\" }}\n", d.join("models").display(), hex(&vad), u = srv.url);
    let m = media(&cfg(&hex(&model)));
    assert!(local::whisper_cpp_command(&m).unwrap().contains("--vad -vm"));
    // A build that does not advertise VAD gets no VAD flags at all.
    let novad = script(&d, "whisper-novad", "while [ $# -gt 0 ]; do case \"$1\" in --help) echo \"usage: whisper-cli\"; exit 0;; esac; shift; done\nexit 0");
    let m_novad = media(&format!("[stt]\nprovider = \"local_command\"\n[stt.local]\nwhisper_cpp = \"{novad}\"\n"));
    let cmd = local::whisper_cpp_command(&m_novad).unwrap();
    assert!(!cmd.contains("--vad") && cmd.contains("-otxt"), "{cmd}");
    let (id, t) = transcribe(&m, &SttRequest::new(wav(0.2), "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!((id.as_str(), t.text.as_str()), ("local_command", "cpp en"));
    assert_eq!(srv.requests().len(), 2);
    transcribe(&m, &SttRequest::new(wav(0.2), "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!(srv.requests().len(), 2, "a verified cache is not downloaded again");
    // A tampered download is refused.
    let bad = media(&cfg(&"0".repeat(64)).replace(&d.join("models").display().to_string(), &d.join("m2").display().to_string()));
    let e = transcribe(&bad, &SttRequest::new(wav(0.2), "audio/wav"), &Cancel::new()).unwrap_err();
    assert!(e.contains("failed SHA-256 verification"), "{e}");
    assert!(!d.join("m2").join("ggml-base.bin").exists());
    // The pinned default set is Hermes'.
    assert_eq!(local::WHISPER_CPP_MODELS[0].2, "60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe");
}

#[test]
fn oversized_audio_is_reencoded_and_split_at_the_duration_cap() {
    if crate::audio::ffmpeg().is_none() || crate::audio::ffprobe().is_none() {
        return;
    }
    let srv = FakeServer::start(|_, n| (200, vec![("content-type".into(), "text/plain".into())], format!("part{}", n + 1)));
    // whisper-1 caps one request at 600 s: 700 s of audio goes up in two segments.
    let m = Media { cfg: cfg_for("openai", &srv.url, "[stt]\nprovider = \"openai\""), http: Default::default() };
    let (_, t) = transcribe(&m, &SttRequest::new(wav(700.0), "audio/wav"), &Cancel::new()).unwrap();
    assert_eq!(t.text, "part1 part2");
    let reqs = srv.requests();
    assert_eq!(reqs.len(), 2);
    assert!(reqs.iter().all(|r| r.body.contains("filename=\"part00")));
}

#[test]
fn command_template_double_brace_format_alias_and_failure_detail() {
    // Hermes `render_command_template`: the legacy `{{name}}` form is a placeholder too,
    // while `{{`/`}}` not wrapping a known name stay literal.
    let vars = [("input_path", "/tmp/a b.wav"), ("format", "txt")];
    assert_eq!(command::render("run {{input_path}}", &vars), "run '/tmp/a b.wav'");
    assert_eq!(command::render("run {input_path}", &vars), "run '/tmp/a b.wav'");
    assert_eq!(command::render("lit {{unknown}} {", &vars), "lit {unknown} {");
    assert_eq!(command::render("\"{{format}}\"", &vars), "\"txt\"");

    let d = temp_dir("stt-cmd2");
    // A stand-in provider binary: writes `{"text":"hi"}` to the {output_path} it is handed.
    let bin = script(&d, "j.sh", &format!("printf '{{\"text\":\"hi\"}}' > \"$1\"; printf '%s' \"$1\" > {}/seen.txt", d.display()));
    let m = media(&format!(
        "[stt]\n[stt.providers.j]\ncommand = \"{bin} {{{{output_path}}}}\"\noutput_format = \".JSON\"\n[stt.providers.quiet]\ncommand = \"exit 7\"\n[stt.providers.both]\ncommand = \"echo out; echo bad >&2; exit 5\"\n[stt.providers.strtimeout]\ncommand = \"sleep 5\"\ntimeout = \"0.2\"\n"
    ));
    let req = SttRequest::new(wav(0.1), "audio/wav");
    // `output_format`, lowercased with the leading dot stripped -> transcript.json; JSON
    // output is decoded to its `text` field.
    let t = transcribe_with(&m, "j", &req, &Cancel::new()).unwrap().1;
    assert_eq!(t.text, "hi");
    let seen = std::fs::read_to_string(d.join("seen.txt")).unwrap();
    assert!(seen.ends_with("transcript.json"), "{seen}");
    // `command_failure_detail`: "stderr: …; stdout: …", or "no command output".
    let e = transcribe_with(&m, "both", &req, &Cancel::new()).unwrap_err();
    assert!(e.contains("exited with code 5: stderr: bad; stdout: out"), "{e}");
    let e = transcribe_with(&m, "quiet", &req, &Cancel::new()).unwrap_err();
    assert!(e.contains("exited with code 7: no command output"), "{e}");
    // A string timeout is accepted like Hermes' `float(raw)`.
    let e = transcribe_with(&m, "strtimeout", &req, &Cancel::new()).unwrap_err();
    assert!(e.contains("timed out after 0.2s"), "{e}");
    // `[media.stt.<name>]` without a `providers` table is a command provider too, `type = ""` included.
    let flat = media("[stt]\n[stt.flat]\ncommand = \"echo flat\"\ntype = \"\"\n");
    assert_eq!(transcribe_with(&flat, "flat", &req, &Cancel::new()).unwrap().1.text, "flat");
    assert!(command::Command::from_config(&media("[stt]\n[stt.off]\ncommand = \"echo x\"\ntype = \"http\"\n"), "off").is_none());
}

#[test]
fn faster_whisper_helper_apple_cpu_pin_and_network_error_text() {
    let s = local::helper_script();
    // Apple Silicon (incl. Rosetta, where machine() says x86_64) pins CPU/int8, and
    // KMP_DUPLICATE_LIB_OK is set BEFORE the ctranslate2 import (upstream order).
    assert!(s.contains("sysctl.proc_translated") && s.contains("hw.optional.arm64"), "Rosetta detection missing");
    let kmp = s.find("KMP_DUPLICATE_LIB_OK").unwrap();
    let import = s.find("from faster_whisper import").unwrap();
    assert!(kmp < import, "KMP_DUPLICATE_LIB_OK must precede the import");
    // Only a cache miss triggers the Hub download; other load errors propagate untouched.
    assert!(s.contains("except (OSError, RuntimeError)"), "cache-miss handler is too broad");
    // The download failure hint matches upstream (mirror + hf-xet).
    assert!(s.contains("HF_ENDPOINT") && s.contains("HF_HUB_DISABLE_XET=1"));
}

#[test]
fn streaming_language_alias_and_provider_selection() {
    // Hermes resolves elevenlabs' `language_code` for live sessions too.
    let m = media("[stt]\nstreaming = true\nprovider = \"elevenlabs\"\nlanguage = \"de\"\n[stt.elevenlabs]\nlanguage_code = \"eng\"\n");
    assert_eq!(stream::session_language(&m, "elevenlabs", None).as_deref(), Some("eng"));
    assert_eq!(stream::session_language(&m, "elevenlabs", Some("ja")).as_deref(), Some("ja"));
    assert_eq!(stream::session_language(&m, "openai", None).as_deref(), Some("de"));
    // Only streaming providers get a live session; local/command providers fall back to the file.
    let local_cfg = media("[stt]\nprovider = \"local\"\nstreaming = true\n[stt.local]\npython = \"/nonexistent/python\"\nwhisper_cpp = \"/nonexistent/w\"\n");
    assert_eq!(stream::streaming_provider(&local_cfg), None);
    assert!(stream::streaming_enabled(&m));
    let openai_cfg = Media { cfg: cfg_for("openai", "http://127.0.0.1:9", "[stt]\nprovider = \"openai\"\nstreaming = true\n"), http: Default::default() };
    assert_eq!(stream::streaming_provider(&openai_cfg).as_deref(), Some("openai"));
}

#[test]
fn local_language_normalisation_matches_hermes() {
    // `_normalize_local_stt_language`: the zh aliases map to "zh", region suffixes are dropped,
    // only 2-letter codes (plus haw/yue) survive, everything else is a fallback-safe None.
    for (raw, want) in [
        ("zh-TW", Some("zh")), ("ZH_tw", Some("zh")), ("繁體中文", Some("zh")), ("繁体中文", Some("zh")),
        ("简体中文", Some("zh")), ("簡體中文", Some("zh")), ("en-US", Some("en")), ("yue", Some("yue")),
        ("haw", Some("haw")), ("chinese", None), ("whisper-ish!", None), ("", None),
    ] {
        assert_eq!(local::normalize_language(Some(raw)).as_deref(), want, "{raw:?}");
    }
    assert_eq!(local::normalize_language(None), None);
    // Cloud-only names remap to the default local size; unknown local sizes pass through.
    for (raw, want) in [("whisper-1", "base"), ("gpt-transcribe", "base"), ("distil-whisper-large-v3-en", "base"), ("whisper-large-v3", "base"), ("small", "small"), ("large-v3", "large-v3")] {
        assert_eq!(local::normalize_model(Some(raw)), want, "{raw:?}");
    }
    assert_eq!(local::normalize_model(None), "base");
}
