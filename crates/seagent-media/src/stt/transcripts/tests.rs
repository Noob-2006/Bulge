use super::sources::{find_source, Microphone};
use super::*;
use crate::testutil::ctx;
use crate::voice::record::VecSource;
use seagent_core::{Cancel, ToolCtx};
use serde_json::json;

fn call(t: &dyn Tool, c: &ToolCtx, v: serde_json::Value) -> seagent_core::ToolOutput {
    t.call(c, v)
}

fn out_line<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines().find_map(|l| l.strip_prefix(key)).unwrap_or("").trim()
}

#[test]
fn import_summarize_list_show() {
    let m = Arc::new(Media::new(crate::MediaConfig::from_toml("[transcripts]\nmodel_summary = false\n")));
    let tool = &tools(&m)[0];
    assert_eq!(tool.spec().name, "transcripts");
    let c = ctx("transcripts");
    let text = "Alice: We decided to ship the beta on Friday.\nBob: I will fix the login bug, that is a blocker.\n\nAlice: Next step is to send the notes.\n[BLANK_AUDIO]";
    let r = call(tool.as_ref(), &c, json!({"action": "import", "title": "Planning", "transcript": text}));
    assert!(!r.is_error, "{}", r.content);
    let sel = out_line(&r.content, "Selector:").to_string();
    assert!(sel.len() > 11 && sel.contains("/transcript-"), "{sel}");
    assert!(r.content.contains("Utterances: 4"));
    let notes = std::fs::read_to_string(out_line(&r.content, "Summary:")).unwrap();
    assert!(notes.starts_with("# Planning"));
    assert!(notes.contains("## Decisions\n- Alice: We decided to ship the beta on Friday."), "{notes}");
    assert!(notes.contains("## Risks\n- Bob: I will fix the login bug, that is a blocker."));
    assert!(notes.contains("- Alice\n- Bob"), "participants");
    assert!(notes.contains("- Alice: Next step is to send the notes."), "action items");
    assert!(!notes.contains("BLANK_AUDIO"), "engine artifacts are dropped from notes");
    let l = call(tool.as_ref(), &c, json!({"action": "list"}));
    assert!(l.content.contains("Planning  (4 utterances, Alice, Bob)  selector: ") && l.content.contains(&sel), "{}", l.content);
    let s = call(tool.as_ref(), &c, json!({"action": "show", "selector": sel}));
    assert!(s.content.starts_with("# Planning"));
    let sum = call(tool.as_ref(), &c, json!({"action": "summarize", "selector": sel}));
    assert!(sum.content.contains("Transcripts summarized") && sum.content.contains("We decided to ship"));
    // Parameter rules.
    assert!(call(tool.as_ref(), &c, json!({"action": "list", "selector": sel})).content.contains("selector is only supported"));
    assert!(call(tool.as_ref(), &c, json!({"action": "show", "selector": sel, "sessionId": "x"})).content.contains("Provide exactly one of selector or sessionId"));
    assert!(call(tool.as_ref(), &c, json!({"action": "show"})).content.contains("Provide exactly one of selector or sessionId"));
    assert!(call(tool.as_ref(), &c, json!({"action": "list", "limit": 99})).content.contains("limit must be an integer from 1 to 50"));
    assert!(call(tool.as_ref(), &c, json!({"action": "import"})).is_error);
    assert!(call(tool.as_ref(), &c, json!({"action": "start", "providerId": "manual-transcript"})).content.contains("cannot start live capture"));
    assert!(call(tool.as_ref(), &c, json!({"action": "dance"})).content.contains("unsupported transcripts action"));
    let off = Arc::new(Media::new(crate::MediaConfig::from_toml("[transcripts]\nenabled = false\n")));
    assert!(call(tools(&off)[0].as_ref(), &c, json!({"action": "status"})).is_error);
}

struct Notes;
impl crate::Llm for Notes {
    fn complete(&self, _m: Option<&str>, system: &str, msgs: Vec<seagent_core::Message>, _t: u32, _c: &Cancel) -> Result<String, String> {
        assert!(system.contains("untrusted source material"));
        assert!(msgs[0].text().contains("Transcript:\nSpeaker: hello team"));
        Ok("<think>hmm</think>Here you go:\n```json\n{\"overview\": \"Short sync.\", \"decisions\": [\"Ship it\"], \"actionItems\": [], \"risks\": [\"none\", \"\"]}\n```".into())
    }
    fn vision(&self, _m: Option<&str>) -> bool {
        false
    }
}

#[test]
fn model_notes_parse_and_fall_back() {
    let s = Session { session_id: "s1".into(), started_at: store::now_iso(), ..Default::default() };
    let us = vec![Utterance { id: "1".into(), text: "hello team".into(), speaker: Some("Speaker".into()), r#final: true, ..Default::default() }];
    let base = summary::summarize(&s, &us);
    assert_eq!(base["source"], "heuristic");
    let n = summary::model_notes_with(&Notes, &s, &base, &Cancel::new()).unwrap();
    assert_eq!((n["overview"].as_str(), n["source"].as_str()), (Some("Short sync."), Some("model")));
    assert_eq!(n["risks"], json!(["none"]));
    // Empty transcripts never reach the model.
    assert!(summary::model_notes_with(&Notes, &s, &summary::summarize(&s, &[]), &Cancel::new()).is_none());
    assert_eq!(store::iso(0, 5), "1970-01-01T00:00:00.005Z");
    assert_eq!(store::iso(1_793_700_000, 0), "2026-11-03T10:00:00.000Z");
    assert_eq!(store::safe_segment("../../etc"), "_.._etc");
}

#[test]
fn cli_entry_points_are_stable() {
    // `seagent stt <file>` → stt::transcribe_file; `seagent transcripts list` → list_json.
    let d = crate::testutil::temp_dir("tr-cli");
    let m = Arc::new(Media::new(crate::MediaConfig::from_toml("[stt]\nprovider = \"echo\"\n[stt.providers.echo]\ncommand = \"echo hello from the cli\"\n")));
    let wav = d.join("clip.wav");
    std::fs::write(&wav, crate::audio::wav_encode(&vec![10; 1600], 16000, 1)).unwrap();
    let (prov, t) = crate::stt::transcribe_file(&m, &wav, &Cancel::new()).unwrap();
    assert_eq!((prov.as_str(), t.text.as_str()), ("echo", "hello from the cli"));
    assert!(crate::stt::transcribe_file(&m, &d.join("nope.wav"), &Cancel::new()).unwrap_err().starts_with("Audio file not found:"));
    // list_json over a home holding one imported session.
    let home = d.join("home");
    let st = store::Store::new(&home);
    let s = Session { session_id: "transcript-a".into(), started_at: store::now_iso(), source: SourceLocator { provider_id: "manual-transcript".into(), ..Default::default() }, ..Default::default() };
    st.write_session(&s).unwrap();
    st.append(&s, &Utterance { id: "1".into(), text: "hi there".into(), ..Default::default() }, 10).unwrap();
    let v = list_json(&home);
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!((v[0]["sessionId"].as_str(), v[0]["utteranceCount"].as_u64(), v[0]["providerId"].as_str()), (Some("transcript-a"), Some(1), Some("manual-transcript")));
    assert!(v[0]["selector"].as_str().unwrap().ends_with("/transcript-a"));
    assert!(list_json(&d.join("empty")).as_array().unwrap().is_empty());
}

#[test]
fn audio_file_import_and_live_microphone_capture() {
    let d = crate::testutil::temp_dir("tr-src");
    let cfg = "[stt]\nprovider = \"echo\"\n[stt.providers.echo]\ncommand = \"echo utterance heard\"\n[transcripts]\nmodel_summary = false\n[transcripts.microphone]\nspeaker = \"Host\"\n[voice]\nsilence_duration = 0.5\nmax_wait = 1.0\n".to_string();
    let m = Arc::new(Media::new(crate::MediaConfig::from_toml(&cfg)));
    let tool = &tools(&m)[0];
    let c = ctx("tr-live");
    let wavp = d.join("call.wav");
    std::fs::write(&wavp, crate::audio::wav_encode(&vec![100; 1600], 16000, 1)).unwrap();
    let r = call(tool.as_ref(), &c, json!({"action": "import", "providerId": "audio-file", "transcript": wavp.display().to_string(), "speakerLabel": "Caller"}));
    assert!(!r.is_error && r.content.contains("Utterances: 1"), "{}", r.content);
    assert!(std::fs::read_to_string(out_line(&r.content, "Summary:")).unwrap().contains("- Caller: utterance heard"));
    assert!(tool.effects(&c, &json!({"action": "import", "providerId": "audio-file", "transcript": "call.wav"})).iter().any(|e| matches!(e, seagent_core::Effect::Read { .. })));
    // Live capture: two spoken takes separated by silence, then the source ends.
    let tone = |s: f64, a: f64| (0..(s * 16000.0) as usize).map(|i| ((i as f64 * 0.3).sin() * a) as i16).collect::<Vec<_>>();
    let pcm = [tone(0.8, 3000.0), tone(0.8, 0.0), tone(0.8, 3000.0), tone(0.8, 0.0)].concat();
    register_source(Arc::new(Microphone { open: Arc::new(move |_m: &Media| Ok(Box::new(VecSource::new(pcm.clone())) as Box<dyn crate::voice::record::PcmSource>)) }));
    assert!(find_source("mic").is_some());
    let r = call(tool.as_ref(), &c, json!({"action": "start", "title": "Standup"}));
    assert!(!r.is_error && r.content.contains("Local Microphone"), "{}", r.content);
    let sel = out_line(&r.content, "Selector:").to_string();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let st = call(tool.as_ref(), &c, json!({"action": "status"}));
    assert!(st.content.contains("Active sessions: 1") && st.content.contains(&format!("active: {sel}")), "{}", st.content);
    let stop = call(tool.as_ref(), &c, json!({"action": "stop", "selector": sel}));
    assert!(stop.content.contains("Utterances: 2"), "{}", stop.content);
    let notes = std::fs::read_to_string(out_line(&stop.content, "Summary:")).unwrap();
    assert!(notes.contains("- Host: utterance heard\n- Host: utterance heard"), "{notes}");
    assert!(call(tool.as_ref(), &c, json!({"action": "stop", "selector": sel})).content.contains("no longer active"));
    register_source(Arc::new(Microphone::default()));
}
