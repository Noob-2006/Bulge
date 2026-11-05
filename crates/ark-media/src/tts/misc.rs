//! OpenClaw speech providers with their own wire formats: Azure Speech (SSML),
//! Inworld (NDJSON base64 stream), Fish Audio, Gradium, Volcengine / BytePlus Seed
//! Speech (JSON frames or legacy `code 3000`), Xiaomi MiMo (chat-completions audio),
//! Vydra (JSON → hosted audio URL).

use super::{bounded, num, opt, speech, Speech, TtsProvider, TtsRequest};
use crate::http::host_of;
use crate::Media;
use ark_core::Cancel;
use serde_json::{json, Value};

fn xml_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn xml_attr(s: &str) -> String {
    xml_text(s).replace('"', "&quot;").replace('\'', "&apos;")
}

/// Azure AI Speech REST (`/cognitiveservices/v1`, `X-Microsoft-OutputFormat`).
/// `[media.tts.azure-speech]` region / endpoint, voice = "en-US-JennyNeural", lang,
/// output_format, voice_note_output_format.
pub struct Azure;

const AZURE_ENV: &[&str] = &["AZURE_SPEECH_KEY", "AZURE_SPEECH_API_KEY", "SPEECH_KEY"];

impl Azure {
    fn base(m: &Media) -> Result<String, String> {
        let c = m.creds("azure-speech", AZURE_ENV, "");
        let configured = opt(m, "azure-speech", "base_url").or_else(|| opt(m, "azure-speech", "endpoint")).or_else(|| (!c.base.is_empty()).then(|| c.base.clone()));
        let region = opt(m, "azure-speech", "region").or_else(|| std::env::var("AZURE_SPEECH_REGION").ok()).or_else(|| std::env::var("SPEECH_REGION").ok()).filter(|r| !r.trim().is_empty());
        let endpoint = configured.or_else(|| if region.is_none() { std::env::var("AZURE_SPEECH_ENDPOINT").ok().filter(|e| !e.is_empty()) } else { None });
        match (endpoint, region) {
            (Some(e), _) => {
                let e = e.trim_end_matches('/');
                Ok(e.strip_suffix("/cognitiveservices/v1").unwrap_or(e).to_string())
            }
            (None, Some(r)) => Ok(format!("https://{}.tts.speech.microsoft.com", r.trim())),
            _ => Err("Azure Speech region or endpoint missing".into()),
        }
    }
}

fn azure_mime(fmt: &str) -> &'static str {
    let f = fmt.to_ascii_lowercase();
    if f.contains("mp3") {
        "audio/mpeg"
    } else if f.starts_with("ogg-") {
        "audio/ogg"
    } else if f.starts_with("webm-") {
        "audio/webm"
    } else if f.starts_with("riff-") {
        "audio/wav"
    } else if f.starts_with("raw-") && f.contains("16bit") {
        "audio/pcm"
    } else if f.starts_with("amr-") {
        "audio/amr"
    } else {
        "application/octet-stream"
    }
}

impl TtsProvider for Azure {
    fn id(&self) -> &str {
        "azure-speech"
    }
    fn aliases(&self) -> &[&str] {
        &["azure"]
    }
    fn env(&self) -> &[&str] {
        AZURE_ENV
    }
    fn configured(&self, m: &Media) -> bool {
        m.cfg.configured("azure-speech", AZURE_ENV) && Self::base(m).is_ok()
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Self::base(m).ok().map(|b| host_of(&b))
    }
    fn voices(&self, m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        let c = m.creds("azure-speech", AZURE_ENV, "");
        let v = m.http.get_json(&format!("{}/cognitiveservices/voices/list", Self::base(m)?), &c.header_key("ocp-apim-subscription-key")).map_err(|e| format!("Azure Speech voices API error: {e}"))?;
        Ok(v.as_array().into_iter().flatten().filter(|x| x["IsDeprecated"] != json!(true) && x["IsDeprecated"] != json!("true") && !matches!(x["Status"].as_str().map(|s| s.to_ascii_lowercase()).as_deref(), Some("deprecated" | "retired" | "disabled"))).filter_map(|x| x["ShortName"].as_str().map(str::to_string)).collect())
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds("azure-speech", AZURE_ENV, "");
        c.key().map_err(|_| "Azure Speech API key missing".to_string())?;
        let base = Self::base(m)?;
        let voice = req.voice.clone().or_else(|| opt(m, "azure-speech", "voice")).unwrap_or_else(|| "en-US-JennyNeural".into());
        let lang = req.language.clone().or_else(|| opt(m, "azure-speech", "lang")).unwrap_or_else(|| "en-US".into());
        let fmt = if req.voice_note() {
            opt(m, "azure-speech", "voice_note_output_format").unwrap_or_else(|| "ogg-24khz-16bit-mono-opus".into())
        } else if req.format.as_deref() == Some("pcm") {
            "raw-24khz-16bit-mono-pcm".into()
        } else {
            opt(m, "azure-speech", "output_format").unwrap_or_else(|| "audio-24khz-48kbitrate-mono-mp3".into())
        };
        let ssml = format!("<speak version=\"1.0\" xmlns=\"http://www.w3.org/2001/10/synthesis\" xml:lang=\"{}\"><voice name=\"{}\">{}</voice></speak>", xml_attr(&lang), xml_attr(&voice), xml_text(&req.text));
        let mut h = c.header_key("ocp-apim-subscription-key");
        h.push(("x-microsoft-outputformat".into(), fmt.clone()));
        h.push(("user-agent".into(), "ark".into()));
        let r = m.http.send("POST", &format!("{base}/cognitiveservices/v1"), &h, Some(("application/ssml+xml", ssml.as_bytes())))?.check("Azure Speech TTS API error")?;
        let mut s = speech(bounded(r.body, "Azure Speech")?, azure_mime(&fmt));
        if azure_mime(&fmt) == "audio/pcm" {
            s.audio.mime = "audio/pcm".into();
            s.sample_rate = Some(24000);
        }
        Ok(s)
    }
}

/// Inworld TTS (`/tts/v1/voice:stream`, `Authorization: Basic <key>`, NDJSON chunks).
pub struct Inworld;

impl Inworld {
    fn base(m: &Media) -> String {
        m.creds("inworld", &["INWORLD_API_KEY"], "https://api.inworld.ai").base.trim_end_matches('/').to_string()
    }
}

impl TtsProvider for Inworld {
    fn id(&self) -> &str {
        "inworld"
    }
    fn env(&self) -> &[&str] {
        &["INWORLD_API_KEY"]
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&Self::base(m)))
    }
    fn voices(&self, m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        let c = m.creds("inworld", self.env(), "https://api.inworld.ai");
        let lang = opt(m, "inworld", "language").map(|l| format!("?languages={}", ark_net::urlencode(&l))).unwrap_or_default();
        let v = m.http.get_json(&format!("{}/voices/v1/voices{lang}", Self::base(m)), &[("authorization".into(), format!("Basic {}", c.key()?))]).map_err(|e| format!("Inworld voices API error: {e}"))?;
        Ok(v["voices"].as_array().into_iter().flatten().filter_map(|x| x["voiceId"].as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds("inworld", self.env(), "https://api.inworld.ai");
        let key = c.key().map_err(|_| "Inworld API key missing".to_string())?;
        let (enc, mime) = if req.voice_note() {
            ("OGG_OPUS", "audio/ogg")
        } else if req.format.as_deref() == Some("pcm") {
            ("PCM", "audio/pcm")
        } else {
            ("MP3", "audio/mpeg")
        };
        let mut ac = json!({"audioEncoding": enc});
        if let Some(r) = num(m, "inworld", "sample_rate") {
            ac["sampleRateHertz"] = json!(r as u64);
        }
        let body = json!({"text": req.text, "voiceId": req.voice.clone().or_else(|| opt(m, "inworld", "voice_id")).unwrap_or_else(|| "Sarah".into()),
            "modelId": req.model.clone().or_else(|| opt(m, "inworld", "model_id")).unwrap_or_else(|| "inworld-tts-1.5-max".into()), "audioConfig": ac});
        let r = m.http.post_json_bytes(&format!("{}/tts/v1/voice:stream", Self::base(m)), &[("authorization".into(), format!("Basic {key}"))], &body).map_err(|e| format!("Inworld TTS API error: {e}"))?;
        let mut audio = Vec::new();
        for line in String::from_utf8_lossy(&r.body).lines().map(str::trim).filter(|l| !l.is_empty()) {
            let v: Value = serde_json::from_str(line).map_err(|_| format!("Inworld TTS stream parse error: unexpected non-JSON line: {}", crate::http::excerpt(line, 80)))?;
            if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
                return Err(format!("Inworld TTS stream error ({}): {}", e["code"], e["message"].as_str().unwrap_or("")));
            }
            if let Some(a) = v["result"]["audioContent"].as_str() {
                audio.extend(crate::store::b64_decode(a).map_err(|_| "Inworld TTS returned malformed base64 audio data")?);
            }
        }
        let mut s = speech(bounded(audio, "Inworld TTS")?, mime);
        if mime == "audio/pcm" {
            s.audio.mime = mime.into();
            s.sample_rate = Some(num(m, "inworld", "sample_rate").map(|r| r as u32).unwrap_or(24000));
        }
        Ok(s)
    }
}

const FISH_MODELS: &[&str] = &["drama-3", "drama-3-preview", "s2.1-pro-free", "s2.1-pro", "s2-pro", "s1"];

/// Fish Audio (`/v1/tts`, `model` header). `[media.tts.fish-audio]` model = "s2.1-pro",
/// reference_id (voice), latency = "balanced", speed (0.5–2), temperature, top_p, normalize.
pub struct FishAudio;

impl TtsProvider for FishAudio {
    fn id(&self) -> &str {
        "fish-audio"
    }
    fn aliases(&self) -> &[&str] {
        &["fish"]
    }
    fn env(&self) -> &[&str] {
        &["FISH_AUDIO_API_KEY", "FISH_API_KEY"]
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&m.creds("fish-audio", self.env(), "https://api.fish.audio").base))
    }
    fn voices(&self, m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        let c = m.creds("fish-audio", self.env(), "https://api.fish.audio");
        let mut out = Vec::new();
        for (selfq, page) in [(true, 1), (false, 1)] {
            let q = if selfq { "self=true" } else { "sort_by=score" };
            let v = m.http.get_json(&c.url(&format!("/model?type=tts&page_size=100&page_number={page}&{q}")), &c.bearer()).map_err(|e| format!("Fish Audio voices API error: {e}"))?;
            out.extend(v["items"].as_array().into_iter().flatten().filter_map(|x| x["_id"].as_str().map(|id| match x["title"].as_str() {
                Some(t) => format!("{id} ({t})"),
                None => id.to_string(),
            })));
        }
        out.dedup();
        Ok(out)
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds("fish-audio", self.env(), "https://api.fish.audio");
        c.key().map_err(|_| "Fish Audio API key missing".to_string())?;
        let model = req.model.clone().or_else(|| opt(m, "fish-audio", "model")).unwrap_or_else(|| "s2.1-pro".into());
        if !FISH_MODELS.contains(&model.as_str()) {
            return Err(format!("invalid Fish Audio model \"{model}\""));
        }
        let latency = opt(m, "fish-audio", "latency").unwrap_or_else(|| "balanced".into()).to_ascii_lowercase();
        if !["low", "balanced", "normal"].contains(&latency.as_str()) {
            return Err(format!("invalid Fish Audio latency \"{latency}\""));
        }
        let (fmt, rate, mime) = if req.voice_note() { ("opus", 48000, "audio/ogg") } else if req.format.as_deref() == Some("pcm") { ("pcm", 24000, "audio/pcm") } else { ("mp3", 44100, "audio/mpeg") };
        let mut body = json!({"text": req.text, "format": fmt, "sample_rate": rate, "latency": latency});
        if let Some(r) = req.voice.clone().or_else(|| opt(m, "fish-audio", "reference_id")).or_else(|| opt(m, "fish-audio", "voice_id")) {
            body["reference_id"] = json!(r);
        }
        if let Some(s) = super::speed(m, "fish-audio", req).filter(|s| (0.5..=2.0).contains(s)) {
            body["prosody"] = json!({"speed": s});
        }
        for (k, jk) in [("temperature", "temperature"), ("top_p", "top_p")] {
            if let Some(v) = num(m, "fish-audio", k) {
                body[jk] = json!(v);
            }
        }
        if let Some(n) = super::flag(m, "fish-audio", "normalize") {
            body["normalize"] = json!(n);
        }
        let mut h = c.bearer();
        h.push(("model".into(), model));
        let r = m.http.post_json_bytes(&c.url("/v1/tts"), &h, &body).map_err(|e| format!("Fish Audio TTS API error: {e}"))?;
        let mut s = speech(bounded(r.body, "Fish Audio")?, mime);
        if fmt == "pcm" {
            s.audio.mime = mime.into();
            s.sample_rate = Some(rate);
        }
        Ok(s)
    }
}

pub const GRADIUM_VOICES: &[(&str, &str)] = &[("YTpq7expH9539ERJ", "Emma"), ("LFZvm12tW_z0xfGo", "Kent"), ("Eu9iL_CYe8N-Gkx_", "Tiffany"), ("2H4HY2CBNyJHBCrP", "Christina"), ("jtEKaLYNn6iif5PR", "Sydney"), ("KWJiFWu2O9nMPYcR", "John"), ("3jUdJyOi9pgbxBTK", "Arthur")];

/// Gradium (`/api/post/speech/tts`, `x-api-key`). The key only ever goes to
/// `https://api.gradium.ai` (OpenClaw transport allowlist) unless
/// `[media.providers.gradium] allow_custom_base_url = true`.
pub struct Gradium;

impl Gradium {
    fn base(m: &Media) -> Result<String, String> {
        let c = m.creds("gradium", &["GRADIUM_API_KEY"], "https://api.gradium.ai");
        let b = c.base.trim_end_matches('/').to_string();
        let custom = c.extra.get("allow_custom_base_url").and_then(|v| v.as_bool()).unwrap_or(false);
        if !custom && (!b.starts_with("https://") || !host_of(&b).eq_ignore_ascii_case("api.gradium.ai")) {
            return Err("Gradium baseUrl must use https and target api.gradium.ai".into());
        }
        Ok(b)
    }
}

impl TtsProvider for Gradium {
    fn id(&self) -> &str {
        "gradium"
    }
    fn env(&self) -> &[&str] {
        &["GRADIUM_API_KEY"]
    }
    fn configured(&self, m: &Media) -> bool {
        m.cfg.configured("gradium", self.env()) && Self::base(m).is_ok()
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Self::base(m).ok().map(|b| host_of(&b))
    }
    fn voices(&self, _m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        Ok(GRADIUM_VOICES.iter().map(|(id, n)| format!("{id} ({n})")).collect())
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds("gradium", self.env(), "https://api.gradium.ai");
        c.key().map_err(|_| "Gradium API key missing".to_string())?;
        let base = Self::base(m)?;
        let (fmt, mime) = if req.voice_note() { ("opus", "audio/ogg") } else { ("wav", "audio/wav") };
        let body = json!({"text": req.text, "voice_id": req.voice.clone().or_else(|| opt(m, "gradium", "voice_id")).unwrap_or_else(|| GRADIUM_VOICES[0].0.into()),
            "only_audio": true, "output_format": fmt, "json_config": "{\"padding_bonus\":0}"});
        let r = m.http.post_json_bytes(&format!("{base}/api/post/speech/tts"), &c.header_key("x-api-key"), &body).map_err(|e| format!("Gradium API error: {e}"))?;
        Ok(speech(bounded(r.body, "Gradium TTS")?, mime))
    }
}

const VOLC_VOICES: &[&str] = &[
    "en_female_anna_mars_bigtts", "en_male_adam_mars_bigtts", "en_female_sarah_mars_bigtts", "en_male_smith_mars_bigtts", "zh_female_cancan_mars_bigtts", "zh_female_qingxinnvsheng_mars_bigtts", "zh_female_linjia_mars_bigtts", "zh_male_wennuanahu_moon_bigtts",
    "zh_male_shaonianzixin_moon_bigtts", "zh_female_shuangkuaisisi_moon_bigtts",
];

/// Volcengine / BytePlus Seed Speech. API key → Seed unidirectional HTTP (JSON frames,
/// `code 0` chunks, `20000000` = done); legacy app id + token → `openspeech` v1 (`code 3000`).
pub struct Volcengine;

const VOLC_ENV: &[&str] = &["VOLCENGINE_TTS_API_KEY", "BYTEPLUS_SEED_SPEECH_API_KEY"];

impl Volcengine {
    fn legacy(m: &Media) -> (Option<String>, Option<String>) {
        let e = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        (opt(m, "volcengine", "app_id").or_else(|| e("VOLCENGINE_TTS_APPID")), opt(m, "volcengine", "token").map(|t| m.cfg.substitute(&t)).or_else(|| e("VOLCENGINE_TTS_TOKEN")))
    }
}

fn volc_frame(v: &Value) -> (Option<i64>, Option<String>, Option<String>) {
    let code = v["code"].as_i64().or_else(|| v["header"]["code"].as_i64());
    let msg = v["message"].as_str().or_else(|| v["header"]["message"].as_str()).map(str::to_string);
    (code, msg, v["data"].as_str().map(str::to_string))
}

impl TtsProvider for Volcengine {
    fn id(&self) -> &str {
        "volcengine"
    }
    fn aliases(&self) -> &[&str] {
        &["bytedance", "doubao"]
    }
    fn env(&self) -> &[&str] {
        VOLC_ENV
    }
    fn configured(&self, m: &Media) -> bool {
        let (a, t) = Self::legacy(m);
        m.cfg.configured("volcengine", VOLC_ENV) || (a.is_some() && t.is_some())
    }
    fn voices(&self, _m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        Ok(VOLC_VOICES.iter().map(|s| s.to_string()).collect())
    }
    fn dest(&self, m: &Media) -> Option<String> {
        let key = m.creds("volcengine", VOLC_ENV, "").key;
        Some(host_of(&opt(m, "volcengine", "base_url").or_else(|| std::env::var("VOLCENGINE_TTS_BASE_URL").ok()).unwrap_or_else(|| if key.is_some() { SEED_URL.into() } else { LEGACY_URL.into() })))
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let c = m.creds("volcengine", VOLC_ENV, "");
        let (app, token) = Self::legacy(m);
        if c.key.is_none() && (app.is_none() || token.is_none()) {
            return Err("Volcengine TTS credentials missing. Set VOLCENGINE_TTS_API_KEY, BYTEPLUS_SEED_SPEECH_API_KEY, or legacy VOLCENGINE_TTS_APPID and VOLCENGINE_TTS_TOKEN.".into());
        }
        let encoding = if req.voice_note() { "ogg_opus" } else { "mp3" };
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let voice = req.voice.clone().or_else(|| opt(m, "volcengine", "voice")).or_else(|| env("VOLCENGINE_TTS_VOICE")).unwrap_or_else(|| "en_female_anna_mars_bigtts".into());
        let speed = super::speed(m, "volcengine", req).map(|s| s.clamp(0.2, 3.0)).unwrap_or(1.0);
        let emotion = opt(m, "volcengine", "emotion");
        let base = opt(m, "volcengine", "base_url").or_else(|| (!c.base.is_empty()).then(|| c.base.clone())).or_else(|| env("VOLCENGINE_TTS_BASE_URL")).unwrap_or_else(|| if c.key.is_some() { SEED_URL.into() } else { LEGACY_URL.into() });
        let mime = if encoding == "ogg_opus" { "audio/ogg" } else { "audio/mpeg" };
        if let Some(key) = &c.key {
            let mut rp = json!({"text": req.text, "speaker": voice, "audio_params": {"format": encoding, "sample_rate": 24000}});
            if (speed - 1.0).abs() > f64::EPSILON {
                rp["speed_ratio"] = json!(speed);
            }
            if let Some(e) = &emotion {
                rp["emotion"] = json!(e);
            }
            let h = vec![
                ("x-api-key".to_string(), key.clone()),
                ("x-api-resource-id".into(), opt(m, "volcengine", "resource_id").or_else(|| env("VOLCENGINE_TTS_RESOURCE_ID")).unwrap_or_else(|| "seed-tts-1.0".into())),
                ("x-api-app-key".into(), opt(m, "volcengine", "app_key").or_else(|| env("VOLCENGINE_TTS_APP_KEY")).unwrap_or_else(|| "aGjiRDfUWi".into())),
            ];
            let b = serde_json::to_vec(&json!({"user": {"uid": "ark"}, "req_params": rp})).unwrap_or_default();
            let r = m.http.send("POST", &base, &h, Some(("application/json", &b)))?;
            let text = r.text();
            let frames: Vec<Value> = match serde_json::from_str::<Value>(text.trim()) {
                Ok(v) => vec![v],
                Err(_) => text.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l.strip_prefix("data:").unwrap_or(l).trim()).map_err(|e| format!("BytePlus Seed Speech TTS: failed to parse response JSON: {e}"))).collect::<Result<_, _>>()?,
            };
            let mut audio = Vec::new();
            for f in &frames {
                match volc_frame(f) {
                    (Some(0), _, Some(d)) => audio.extend(crate::store::b64_decode(&d).map_err(|_| "BytePlus Seed Speech TTS returned malformed base64 audio data")?),
                    (Some(0), _, None) | (Some(20000000), _, _) => {}
                    (code, msg, _) => return Err(format!("BytePlus Seed Speech TTS error {}: {}", code.unwrap_or(r.status as i64), msg.unwrap_or_else(|| "unknown".into()))),
                }
            }
            if !r.ok() || audio.is_empty() {
                return Err(format!("BytePlus Seed Speech TTS error {}: no audio data", r.status));
            }
            return Ok(speech(bounded(audio, "BytePlus Seed Speech")?, mime));
        }
        let (app, token) = (app.unwrap_or_default(), token.unwrap_or_default());
        let mut audio = json!({"voice_type": voice, "encoding": encoding, "speed_ratio": speed, "volume_ratio": 1, "pitch_ratio": 1});
        if let Some(e) = &emotion {
            audio["emotion"] = json!(e);
        }
        let body = json!({"app": {"appid": app, "token": token, "cluster": opt(m, "volcengine", "cluster").or_else(|| env("VOLCENGINE_TTS_CLUSTER")).unwrap_or_else(|| "volcano_tts".into())},
            "user": {"uid": "ark"}, "audio": audio,
            "request": {"reqid": ark_net::crypto::hex(&ark_net::crypto::random_bytes(16)), "text": req.text, "text_type": "plain", "operation": "query"}});
        let b = serde_json::to_vec(&body).unwrap_or_default();
        let r = m.http.send("POST", &base, &[("authorization".into(), format!("Bearer;{token}"))], Some(("application/json", &b)))?;
        let v: Value = serde_json::from_slice(&r.body).map_err(|e| format!("Volcengine TTS: failed to parse response JSON: {e}"))?;
        match volc_frame(&v) {
            (Some(3000), _, Some(d)) if r.ok() => Ok(speech(bounded(crate::store::b64_decode(&d).map_err(|_| "Volcengine TTS returned malformed base64 audio data")?, "Volcengine")?, mime)),
            (code, msg, _) => Err(format!("Volcengine TTS error {}: {}", code.unwrap_or(r.status as i64), msg.unwrap_or_else(|| "unknown".into()))),
        }
    }
}

const SEED_URL: &str = "https://voice.ap-southeast-1.bytepluses.com/api/v3/tts/unidirectional";
const LEGACY_URL: &str = "https://openspeech.bytedance.com/api/v1/tts";

const XIAOMI_VOICES: &[&str] = &["mimo_default", "default_zh", "default_en", "Mia", "Chloe", "Milo", "Dean"];

/// Xiaomi MiMo TTS: chat completions with `audio: {format, voice}`; the voice-design model
/// takes a style prompt instead of a voice.
pub struct Xiaomi;

impl TtsProvider for Xiaomi {
    fn id(&self) -> &str {
        "xiaomi"
    }
    fn env(&self) -> &[&str] {
        &["XIAOMI_API_KEY"]
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&m.creds("xiaomi", self.env(), "https://api.xiaomimimo.com/v1").base))
    }
    fn voices(&self, _m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        Ok(XIAOMI_VOICES.iter().map(|s| s.to_string()).collect())
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let base_env = env("XIAOMI_BASE_URL");
        let c = m.creds("xiaomi", self.env(), base_env.as_deref().unwrap_or("https://api.xiaomimimo.com/v1"));
        c.key().map_err(|_| "Xiaomi API key missing".to_string())?;
        let model = req.model.clone().or_else(|| opt(m, "xiaomi", "model")).or_else(|| env("XIAOMI_TTS_MODEL")).unwrap_or_else(|| "mimo-v2.5-tts".into());
        let voice = req.voice.clone().or_else(|| opt(m, "xiaomi", "voice")).or_else(|| env("XIAOMI_TTS_VOICE")).unwrap_or_else(|| "mimo_default".into());
        let fmt = match opt(m, "xiaomi", "format").or_else(|| env("XIAOMI_TTS_FORMAT")).as_deref() {
            Some("wav") => "wav",
            _ => "mp3",
        };
        let design = model == "mimo-v2.5-tts-voicedesign";
        let style = req.instructions.clone().or_else(|| opt(m, "xiaomi", "style")).or_else(|| design.then(|| "Warm, natural, and friendly voice with clear pronunciation and conversational pacing.".into()));
        let mut messages = Vec::new();
        if let Some(s) = style {
            messages.push(json!({"role": "user", "content": s}));
        }
        messages.push(json!({"role": "assistant", "content": req.text}));
        let audio = if design { json!({"format": fmt}) } else { json!({"format": fmt, "voice": voice}) };
        let v = m.http.post_json(&c.url("/chat/completions"), &c.header_key("api-key"), &json!({"model": model, "messages": messages, "audio": audio})).map_err(|e| format!("Xiaomi TTS API error: {e}"))?;
        let data = v["choices"][0]["message"]["audio"]["data"].as_str().filter(|s| !s.trim().is_empty()).ok_or("Xiaomi TTS API returned no audio data")?;
        let bytes = crate::store::b64_decode(data).map_err(|_| "Xiaomi TTS API returned malformed base64 audio data")?;
        Ok(speech(bounded(bytes, "Xiaomi TTS")?, if fmt == "wav" { "audio/wav" } else { "audio/mpeg" }))
    }
}

/// Vydra (`POST /models/<model>` → JSON carrying the hosted audio URL, then download).
pub struct Vydra;

fn vydra_urls(v: &Value, depth: usize, out: &mut Vec<String>) {
    if depth > 5 {
        return;
    }
    match v {
        Value::Array(a) => a.iter().for_each(|x| vydra_urls(x, depth + 1, out)),
        Value::Object(o) => {
            for k in ["audioUrl", "audioUrls", "resultUrl", "resultUrls", "outputUrl", "outputUrls", "url", "urls"] {
                match o.get(k) {
                    Some(Value::String(s)) if s.starts_with("http") => out.push(s.clone()),
                    Some(Value::Array(a)) => out.extend(a.iter().filter_map(|x| x.as_str()).filter(|s| s.starts_with("http")).map(str::to_string)),
                    _ => {}
                }
            }
            for k in ["output", "outputs", "result", "results", "data", "asset", "assets"] {
                if let Some(x) = o.get(k) {
                    vydra_urls(x, depth + 1, out);
                }
            }
        }
        _ => {}
    }
}

impl TtsProvider for Vydra {
    fn id(&self) -> &str {
        "vydra"
    }
    fn env(&self) -> &[&str] {
        &["VYDRA_API_KEY"]
    }
    fn dest(&self, m: &Media) -> Option<String> {
        Some(host_of(&m.creds("vydra", self.env(), "https://www.vydra.ai/api/v1").base))
    }
    fn voices(&self, _m: &Media, _c: &Cancel) -> Result<Vec<String>, String> {
        Ok(vec!["21m00Tcm4TlvDq8ikWAM (Rachel)".into()])
    }
    fn synthesize(&self, m: &Media, req: &TtsRequest, _cancel: &Cancel) -> Result<Speech, String> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let c = m.creds("vydra", self.env(), env("VYDRA_BASE_URL").as_deref().unwrap_or("https://www.vydra.ai/api/v1"));
        c.key().map_err(|_| "Vydra API key missing".to_string())?;
        let model = req.model.clone().or_else(|| opt(m, "vydra", "model")).or_else(|| env("VYDRA_TTS_MODEL")).unwrap_or_else(|| "elevenlabs/tts".into());
        let voice = req.voice.clone().or_else(|| opt(m, "vydra", "voice_id")).or_else(|| env("VYDRA_TTS_VOICE_ID")).unwrap_or_else(|| "21m00Tcm4TlvDq8ikWAM".into());
        let v = m.http.post_json(&c.url(&format!("/models/{model}")), &c.bearer(), &json!({"text": req.text, "voice_id": voice})).map_err(|e| format!("Vydra speech synthesis failed: {e}"))?;
        let mut urls = Vec::new();
        vydra_urls(&v, 0, &mut urls);
        let url = urls.into_iter().next().ok_or("Vydra speech synthesis response missing audio URL")?;
        // The key travels with the download only to Vydra's own origin.
        let same = host_of(&url) == host_of(&c.base);
        let auth = if same { c.bearer() } else { vec![] };
        let (bytes, ct) = m.download(&url, &auth)?;
        let mime = if ct.contains("wav") || url.ends_with(".wav") { "audio/wav" } else { "audio/mpeg" };
        Ok(speech(bounded(bytes, "Vydra")?, mime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeServer;
    use crate::tts::testkit::media;

    #[test]
    fn azure_ssml_request() {
        let srv = FakeServer::start_raw(|r, _| {
            if r.path.ends_with("/voices/list") {
                (200, vec![], br#"[{"ShortName":"en-US-A"},{"ShortName":"old","Status":"Deprecated"}]"#.to_vec())
            } else {
                (200, vec![], b"OggS\0".to_vec())
            }
        });
        let m = media("azure-speech", &format!("{}/cognitiveservices/v1", srv.url), "[tts.azure-speech]\nvoice = \"en-US-Ava\"");
        let mut req = TtsRequest::new("a < b");
        req.format = Some("opus".into());
        let s = Azure.synthesize(&m, &req, &Cancel::new()).unwrap();
        assert_eq!(s.audio.mime, "audio/ogg");
        let r = &srv.requests()[0];
        assert_eq!((r.path.as_str(), r.header("ocp-apim-subscription-key"), r.header("x-microsoft-outputformat")), ("/cognitiveservices/v1", Some("k"), Some("ogg-24khz-16bit-mono-opus")));
        assert!(r.body.contains("<voice name=\"en-US-Ava\">a &lt; b</voice>"), "{}", r.body);
        assert_eq!(Azure.voices(&m, &Cancel::new()).unwrap(), vec!["en-US-A"]);
        let none = Media { cfg: crate::MediaConfig::from_toml("[providers.azure-speech]\napi_key = \"k\""), http: Default::default() };
        if std::env::var("AZURE_SPEECH_REGION").is_err() && std::env::var("SPEECH_REGION").is_err() && std::env::var("AZURE_SPEECH_ENDPOINT").is_err() {
            assert!(Azure.synthesize(&none, &TtsRequest::new("x"), &Cancel::new()).unwrap_err().contains("region"));
        }
    }

    #[test]
    fn inworld_ndjson_stream() {
        let a = crate::store::b64(b"ID3");
        let b = crate::store::b64(b"\x04x");
        let srv = FakeServer::start(move |_, _| (200, vec![], format!("{{\"result\":{{\"audioContent\":\"{a}\"}}}}\n{{\"result\":{{\"audioContent\":\"{b}\"}}}}\n")));
        let m = media("inworld", &srv.url, "");
        let s = Inworld.synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap();
        assert_eq!(s.audio.bytes, b"ID3\x04x");
        let r = &srv.requests()[0];
        assert_eq!((r.path.as_str(), r.header("authorization")), ("/tts/v1/voice:stream", Some("Basic k")));
        assert_eq!(r.json()["audioConfig"]["audioEncoding"], "MP3");
        let err = FakeServer::start(|_, _| (200, vec![], "{\"error\":{\"code\":3,\"message\":\"bad voice\"}}\n".into()));
        let m = media("inworld", &err.url, "");
        assert!(Inworld.synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap_err().contains("bad voice"));
    }

    #[test]
    fn fish_audio_request() {
        let srv = FakeServer::start_raw(|_, _| (200, vec![], b"OggS\0".to_vec()));
        let m = media("fish-audio", &srv.url, "[tts.fish-audio]\nreference_id = \"ref1\"\nspeed = 1.2");
        let mut req = TtsRequest::new("hello");
        req.format = Some("opus".into());
        Fish::check(&m, &req, &srv);
        let bad = media("fish-audio", &srv.url, "[tts.fish-audio]\nmodel = \"nope\"");
        assert!(FishAudio.synthesize(&bad, &TtsRequest::new("x"), &Cancel::new()).unwrap_err().contains("invalid Fish Audio model"));
    }

    struct Fish;
    impl Fish {
        fn check(m: &Media, req: &TtsRequest, srv: &FakeServer) {
            FishAudio.synthesize(m, req, &Cancel::new()).unwrap();
            let r = &srv.requests()[0];
            assert_eq!((r.path.as_str(), r.header("model"), r.header("authorization")), ("/v1/tts", Some("s2.1-pro"), Some("Bearer k")));
            let b = r.json();
            assert_eq!((b["format"].as_str(), b["reference_id"].as_str(), b["prosody"]["speed"].as_f64(), b["sample_rate"].as_u64()), (Some("opus"), Some("ref1"), Some(1.2), Some(48000)));
        }
    }

    #[test]
    fn gradium_host_guard_and_request() {
        let srv = FakeServer::start_raw(|_, _| (200, vec![], b"RIFF\0\0\0\0WAVEfmt ".to_vec()));
        let m = media("gradium", &srv.url, "");
        assert!(Gradium.synthesize(&m, &TtsRequest::new("x"), &Cancel::new()).unwrap_err().contains("api.gradium.ai"));
        let m = Media { cfg: crate::MediaConfig::from_toml(&format!("[providers.gradium]\napi_key = \"k\"\nbase_url = \"{}\"\nallow_custom_base_url = true", srv.url)), http: Default::default() };
        let s = Gradium.synthesize(&m, &TtsRequest::new("x"), &Cancel::new()).unwrap();
        assert_eq!(s.audio.mime, "audio/wav");
        let r = &srv.requests()[0];
        assert_eq!((r.path.as_str(), r.header("x-api-key")), ("/api/post/speech/tts", Some("k")));
        assert_eq!((r.json()["voice_id"].as_str(), r.json()["output_format"].as_str()), (Some("YTpq7expH9539ERJ"), Some("wav")));
    }

    #[test]
    fn volcengine_seed_frames_and_legacy() {
        let a = crate::store::b64(b"ID3");
        let srv = FakeServer::start(move |r, _| {
            if r.header("x-api-key").is_some() {
                (200, vec![], format!("{{\"code\":0,\"data\":\"{a}\"}}\n{{\"code\":20000000,\"message\":\"ok\"}}\n"))
            } else {
                (200, vec![], format!("{{\"code\":3000,\"message\":\"Success\",\"data\":\"{a}\"}}"))
            }
        });
        let m = media("volcengine", &srv.url, "[tts.volcengine]\nspeed = 1.3");
        let s = Volcengine.synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap();
        assert_eq!(s.audio.bytes, b"ID3");
        let r = &srv.requests()[0];
        assert_eq!((r.header("x-api-resource-id"), r.header("x-api-app-key")), (Some("seed-tts-1.0"), Some("aGjiRDfUWi")));
        assert_eq!((r.json()["req_params"]["speaker"].as_str(), r.json()["req_params"]["speed_ratio"].as_f64()), (Some("en_female_anna_mars_bigtts"), Some(1.3)));
        let legacy = Media { cfg: crate::MediaConfig::from_toml(&format!("[tts.volcengine]\napp_id = \"a1\"\ntoken = \"t1\"\nbase_url = \"{}\"", srv.url)), http: Default::default() };
        if std::env::var("VOLCENGINE_TTS_API_KEY").is_err() && std::env::var("BYTEPLUS_SEED_SPEECH_API_KEY").is_err() {
            Volcengine.synthesize(&legacy, &TtsRequest::new("hi"), &Cancel::new()).unwrap();
            let r = &srv.requests()[1];
            assert_eq!(r.header("authorization"), Some("Bearer;t1"));
            assert_eq!((r.json()["app"]["cluster"].as_str(), r.json()["request"]["operation"].as_str()), (Some("volcano_tts"), Some("query")));
        }
    }

    #[test]
    fn xiaomi_chat_audio() {
        let a = crate::store::b64(b"ID3");
        let srv = FakeServer::start(move |_, _| (200, vec![], format!("{{\"choices\":[{{\"message\":{{\"audio\":{{\"data\":\"{a}\"}}}}}}]}}")));
        let m = media("xiaomi", &srv.url, "");
        Xiaomi.synthesize(&m, &TtsRequest::new("hello"), &Cancel::new()).unwrap();
        let r = &srv.requests()[0];
        assert_eq!((r.path.as_str(), r.header("api-key")), ("/chat/completions", Some("k")));
        let b = r.json();
        assert_eq!((b["messages"][0]["role"].as_str(), b["audio"]["voice"].as_str()), (Some("assistant"), Some("mimo_default")));
    }

    #[test]
    fn vydra_url_then_download() {
        let srv = FakeServer::start_raw(|r, _| {
            if r.path.starts_with("/models/") {
                let host = r.header("host").unwrap_or("").to_string();
                (200, vec![], format!("{{\"data\":{{\"audioUrl\":\"http://{host}/files/a.mp3\"}}}}").into_bytes())
            } else {
                (200, vec![("content-type".into(), "audio/mpeg".into())], b"ID3\x04".to_vec())
            }
        });
        let m = media("vydra", &srv.url, "");
        let s = Vydra.synthesize(&m, &TtsRequest::new("hi"), &Cancel::new()).unwrap();
        assert_eq!(s.audio.bytes, b"ID3\x04");
        let rs = srv.requests();
        assert_eq!(rs[0].path, "/models/elevenlabs/tts");
        assert_eq!(rs[1].header("authorization"), Some("Bearer k"));
    }
}
