use super::*;
use crate::testutil::{temp_dir, ws_server, FakeServer};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A fake DevTools endpoint: HTTP target management + a page socket answering evaluate.
fn fake_devtools(
    status: impl Fn(usize, &str) -> Value + Send + Sync + 'static,
) -> (FakeServer, Arc<AtomicUsize>) {
    fake_devtools_at("https://acme.zoom.us/j/123456789", status)
}

/// The same fake endpoint, with the tab it hands out reporting `page_url`.
fn fake_devtools_at(
    page_url: &str,
    status: impl Fn(usize, &str) -> Value + Send + Sync + 'static,
) -> (FakeServer, Arc<AtomicUsize>) {
    let page_url = page_url.to_string();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let ws = ws_server(move |_head, sock| {
        while let Ok(m) = sock.recv_blocking() {
            let seagent_net::ws::Message::Text(t) = m else {
                break;
            };
            let v: Value = serde_json::from_str(&t).unwrap();
            let expr = v["params"]["expression"].as_str().unwrap_or("");
            let result = match v["method"].as_str().unwrap_or("") {
                "Runtime.evaluate" if expr.contains("st.lines.slice()") => {
                    json!({"result": {"type": "object", "value": {"lines": [
                    {"speaker": "Alice", "text": "Hello", "at": 1}, {"speaker": "Alice", "text": "Hello everyone", "at": 2}, {"speaker": "Bob", "text": "Hi Alice", "at": 3}], "captioning": true}}})
                }
                "Runtime.evaluate"
                    if expr.contains("leaveAction") && !expr.contains("autoJoin") =>
                {
                    json!({"result": {"type": "object", "value": {"departed": true, "leaveAction": "leave"}}})
                }
                "Runtime.evaluate" => {
                    let i = n2.fetch_add(1, Ordering::SeqCst);
                    json!({"result": {"type": "object", "value": status(i, expr)}})
                }
                _ => json!({}),
            };
            let _ = sock.send_text(&json!({"id": v["id"], "result": result}).to_string());
        }
    });
    let ws2 = ws.clone();
    let http = FakeServer::start(move |r, _| {
        let page = json!({"id": "T1", "type": "page", "url": page_url.clone(), "title": "meeting", "webSocketDebuggerUrl": format!("{ws2}/devtools/page/T1")});
        match r.path.split('?').next().unwrap() {
            "/json/version" => (200, vec![], json!({"Browser": "Chrome/140", "webSocketDebuggerUrl": format!("{ws2}/devtools/browser/B")}).to_string()),
            "/json/list" => (200, vec![], "[]".into()),
            "/json/new" => {
                assert_eq!(r.method, "PUT");
                (200, vec![], page.to_string())
            }
            _ => (200, vec![], "{}".into()),
        }
    });
    (http, n)
}

fn media(extra: &str) -> Arc<Media> {
    Media::new(crate::MediaConfig::from_toml(extra))
}

fn call(m: &Arc<Media>, p: Platform, v: Value) -> Value {
    let out = MeetingTool {
        m: m.clone(),
        platform: p,
    }
    .call(&crate::testutil::ctx("meet"), v);
    serde_json::from_str(&out.content).unwrap()
}

#[test]
fn zoom_join_transcript_leave_over_fake_cdp() {
    let (http, polls) = fake_devtools(|i, expr| {
        assert!(
            expr.contains("button.preview-join-button"),
            "zoom selectors in the script"
        );
        if expr.contains("\"readOnly\":true") {
            return json!({"inCall": true, "captioning": true, "micMuted": true, "notes": []});
        }
        if i == 0 {
            json!({"inCall": false, "notes": ["Entered the guest name.", "Clicked join."]})
        } else {
            json!({"inCall": true, "captioning": true, "micMuted": true, "notes": ["Turned on live captions for the transcript."]})
        }
    });
    let m = media(&format!(
        "[meeting]\ncdp_url = \"{}\"\nguest_name = \"seagent bot\"\njoin_timeout_secs = 10\n",
        http.url
    ));
    assert!(call(
        &m,
        Platform::Zoom,
        json!({"action": "join", "url": "https://acme.zoom.us/s/1"})
    )["error"]
        .as_str()
        .unwrap()
        .contains("zoom.us/j/"));
    let r = call(
        &m,
        Platform::Zoom,
        json!({"action": "join", "url": "https://acme.zoom.us/j/123456789?pwd=abc"}),
    );
    let s = &r["session"];
    assert_eq!(
        (
            s["state"].as_str(),
            s["mode"].as_str(),
            s["platform"].as_str()
        ),
        (Some("active"), Some("transcribe"), Some("zoom-meetings")),
        "{r}"
    );
    assert!(s["notes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n == "Clicked join."));
    assert!(polls.load(Ordering::SeqCst) >= 2);
    let script_params = http.requests().iter().any(|q| {
        q.path
            .starts_with("/json/new?https%3A%2F%2Facme.zoom.us%2Fj%2F123456789")
    });
    assert!(
        script_params,
        "{:?}",
        http.requests()
            .iter()
            .map(|r| r.path.clone())
            .collect::<Vec<_>>()
    );
    // A second join of the same meeting reuses the session.
    assert_eq!(
        call(
            &m,
            Platform::Zoom,
            json!({"action": "join", "url": "https://other.zoom.us/j/123456789"})
        )["reused"],
        true
    );
    let st = call(&m, Platform::Zoom, json!({"action": "status"}));
    assert_eq!(st["state"], "active");
    let t = call(&m, Platform::Zoom, json!({"action": "transcript"}));
    let lines: Vec<String> = t["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            format!(
                "{}: {}",
                l["speaker"].as_str().unwrap(),
                l["text"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        lines,
        vec!["Alice: Hello everyone", "Bob: Hi Alice"],
        "growing captions collapse"
    );
    let e = call(
        &m,
        Platform::Zoom,
        json!({"action": "speak", "message": "hi"}),
    );
    assert!(e["error"].as_str().unwrap().contains("observe-only"));
    let l = call(&m, Platform::Zoom, json!({"action": "leave"}));
    assert_eq!(
        (l["left"].as_bool(), l["departed"].as_bool()),
        (Some(true), Some(true))
    );
    assert!(http.requests().iter().any(|q| q.path == "/json/close/T1"));
    assert!(
        call(&m, Platform::Zoom, json!({"action": "status"}))["error"]
            .as_str()
            .unwrap()
            .contains("no active")
    );
    assert_eq!(
        call(&m, Platform::Zoom, json!({"action": "sessions"}))["sessions"][0]["state"],
        "ended"
    );
}

#[test]
fn manual_actions_stop_the_join_and_agent_mode_speaks() {
    let (http, _) = fake_devtools(|_, expr| {
        if expr.contains("teams") || expr.contains("prejoin-join-button") {
            json!({"inCall": false, "manualAction": {"reason": "teams-login-required", "message": "Sign in"}, "notes": []})
        } else {
            json!({"inCall": true, "notes": []})
        }
    });
    let tts = FakeServer::start_raw(|_, _| {
        let pcm: Vec<i16> = vec![100; 4800];
        (
            200,
            vec![("content-type".into(), "audio/wav".into())],
            crate::audio::wav_encode(&pcm, 24000, 1),
        )
    });
    let out = temp_dir("meet-say");
    let m = media(&format!("[meeting]\ncdp_url = \"{}\"\njoin_timeout_secs = 5\nplayer = \"cp {{path}} {}/said-{{sink}}.wav\"\n[tts]\nprovider = \"openai\"\n[providers.openai]\napi_key = \"k\"\nbase_url = \"{}\"\n", http.url, out.display(), tts.url));
    let r = call(
        &m,
        Platform::Teams,
        json!({"action": "join", "url": "https://teams.live.com/meet/9876abc?p=x"}),
    );
    assert_eq!(r["session"]["state"], "waiting", "{r}");
    assert_eq!(
        r["session"]["manualAction"]["reason"],
        "teams-login-required"
    );
    // Agent mode (talk-back): speech goes to the configured sink through the player.
    let r = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "join", "url": "https://meet.google.com/abc-defg-hij", "mode": "agent"}),
    );
    assert_eq!(r["session"]["state"], "active", "{r}");
    let id = r["session"]["sessionId"].as_str().unwrap().to_string();
    let sp = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "speak", "sessionId": id, "message": "Hello everyone"}),
    );
    assert_eq!(sp["spoken"], true, "{sp}");
    let wav = std::fs::read(out.join("said-seagent_meeting.wav")).unwrap();
    let p = crate::audio::wav_decode(&wav).unwrap();
    assert_eq!(p.sample_rate, 48000);
    assert!(call(
        &m,
        Platform::Zoom,
        json!({"action": "join", "url": "https://acme.zoom.us/j/123456789", "mode": "loud"})
    )["error"]
        .as_str()
        .unwrap()
        .contains("transcribe or agent"));
    assert!(call(
        &m,
        Platform::SlackHuddle,
        json!({"action": "join", "url": "U123"})
    )["error"]
        .as_str()
        .unwrap()
        .contains("huddle link"));
    assert!(call(
        &m,
        Platform::Zoom,
        json!({"action": "join", "transport": "twilio", "dialInNumber": "+1"})
    )["error"]
        .as_str()
        .unwrap()
        .contains("only available for Google Meet"));
    let ss = call(&m, Platform::GoogleMeet, json!({"action": "setup_status"}));
    assert_eq!(ss["checks"].as_array().unwrap().len(), 3);
}

#[test]
fn meet_create_uses_the_meet_api() {
    let api = FakeServer::start(|r, _| {
        assert_eq!(r.header("authorization"), Some("Bearer tok"));
        (200, vec![], json!({"name": "spaces/abc", "meetingUri": "https://meet.google.com/abc-defg-hij", "meetingCode": "abc-defg-hij"}).to_string())
    });
    let m = media(&format!(
        "[providers.google-meet]\napi_key = \"tok\"\nbase_url = \"{}\"\n",
        api.url
    ));
    let r = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "create", "join": false, "accessType": "trusted"}),
    );
    assert_eq!(r["meetingUri"], "https://meet.google.com/abc-defg-hij");
    assert_eq!(api.requests()[0].path, "/spaces");
    assert_eq!(api.requests()[0].json()["config"]["accessType"], "TRUSTED");
    // Both policy knobs travel in one `config` object; values are case- and dash-insensitive.
    let r = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "create", "join": false, "accessType": "trusted", "entryPointAccess": "creator-app-only"}),
    );
    assert_eq!(r["meetingUri"], "https://meet.google.com/abc-defg-hij", "{r}");
    assert_eq!(
        api.requests()[1].json(),
        json!({"config": {"accessType": "TRUSTED", "entryPointAccess": "CREATOR_APP_ONLY"}})
    );
    // No policy at all: an empty body, as upstream sends `{}`.
    let _ = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "create", "join": false}),
    );
    assert_eq!(api.requests()[2].json(), json!({}));
    let none = media("");
    std::env::remove_var("GOOGLE_MEET_ACCESS_TOKEN");
    assert!(
        call(&none, Platform::GoogleMeet, json!({"action": "create"}))["error"]
            .as_str()
            .unwrap()
            .contains("access token")
    );
}

#[test]
fn meet_create_validates_the_space_policy_before_any_request() {
    let api = FakeServer::start(|_, _| (200, vec![], "{}".to_string()));
    let m = media(&format!(
        "[providers.google-meet]\napi_key = \"tok\"\nbase_url = \"{}\"\n",
        api.url
    ));
    for (input, msg) in [
        (
            json!({"action": "create", "join": false, "accessType": "open_to_all"}),
            "Invalid Google Meet accessType. Expected OPEN, TRUSTED, or RESTRICTED.",
        ),
        (
            json!({"action": "create", "join": false, "entryPointAccess": "CREATOR"}),
            "Invalid Google Meet entryPointAccess. Expected ALL or CREATOR_APP_ONLY.",
        ),
    ] {
        let r = call(&m, Platform::GoogleMeet, input);
        assert_eq!(r["error"].as_str(), Some(msg), "{r}");
    }
    assert!(
        api.requests().is_empty(),
        "validation must fail before HTTP: {:?}",
        api.requests()
            .iter()
            .map(|q| q.path.clone())
            .collect::<Vec<_>>()
    );
    // `create` exists for Google Meet only.
    for p in [Platform::Teams, Platform::Zoom, Platform::SlackHuddle] {
        let r = call(&m, p, json!({"action": "create"}));
        assert_eq!(
            r["error"].as_str(),
            Some("create is only available for Google Meet"),
            "{r}"
        );
    }
    assert!(api.requests().is_empty());
}

#[test]
fn meet_dial_in_pin_is_normalized() {
    assert_eq!(meet_pin("1234").unwrap(), "1234");
    assert_eq!(meet_pin("1234#").unwrap(), "1234", "a trailing # is accepted");
    assert_eq!(meet_pin(" 123 4 # ").unwrap(), "1234");
    for bad in ["", "#", "12a", "1234##", "#1234"] {
        assert_eq!(
            meet_pin(bad).unwrap_err(),
            "pin must be the Meet dial-in PIN digits",
            "{bad}"
        );
    }
    // The bad PIN is rejected before any phone provider is touched.
    let unconfigured = media("");
    let r = call(
        &unconfigured,
        Platform::GoogleMeet,
        json!({"action": "join", "transport": "twilio", "dialInNumber": "+15550002222", "pin": "12a"}),
    );
    assert_eq!(
        r["error"].as_str(),
        Some("pin must be the Meet dial-in PIN digits"),
        "{r}"
    );
    let api = FakeServer::start(|r, _| {
        if r.path.ends_with("/Calls.json") {
            (201, vec![], r#"{"sid":"CA1","status":"queued"}"#.to_string())
        } else {
            (200, vec![], r#"{"sid":"CA1"}"#.to_string())
        }
    });
    let m = media(&format!(
        "[meeting]\nguest_name = \"seagent bot\"\n[phone]\nprovider = \"twilio\"\nfrom_number = \"+15550001111\"\npublic_url = \"https://pub.example/voice/webhook\"\nresponse_timeout_secs = 2\nauto_respond = false\n[phone.serve]\nbind = \"127.0.0.1:0\"\n[providers.twilio]\naccount_sid = \"AC1\"\napi_key = \"tok\"\nbase_url = \"{}\"\n",
        api.url
    ));
    let r = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "join", "transport": "twilio", "dialInNumber": "+15550002222", "pin": "1234#"}),
    );
    assert_eq!(r["session"]["transport"], "twilio", "{r}");
    assert_eq!(r["session"]["state"], "active", "{r}");
    let dialed = api.requests();
    assert_eq!(dialed.len(), 1, "{dialed:?}");
    assert!(
        dialed[0].path.ends_with("/Calls.json"),
        "{}",
        dialed[0].path
    );
    assert!(
        dialed[0].body.contains("To=%2B15550002222"),
        "{}",
        dialed[0].body
    );
    assert!(!dialed[0].body.contains("ww1234##"), "{}", dialed[0].body);
}

#[test]
fn tools_expose_one_spec_per_platform() {
    let m = media("");
    let ts = tools(&m);
    assert_eq!(ts.len(), 4);
    assert_eq!(
        ts.iter().map(|t| t.spec().name).collect::<Vec<_>>(),
        vec![
            "google_meet",
            "teams_meetings",
            "zoom_meetings",
            "slack_huddles"
        ]
    );
    assert_eq!(
        platforms::ALL.iter().map(|p| p.id()).collect::<Vec<_>>(),
        vec!["google-meet", "teams-meetings", "zoom-meetings", "slack-huddles"]
    );
    let urls = [
        "https://meet.google.com/abc-defg-hij",
        "https://teams.live.com/meet/9876abc?p=x",
        "https://acme.zoom.us/j/123456789",
        "https://app.slack.com/huddle/T0123ABCDE/C0123ABCDE",
    ];
    for (i, t) in ts.iter().enumerate() {
        let spec = t.spec();
        let meet = spec.name == "google_meet";
        assert_eq!(spec.input_schema["type"], "object", "{}", spec.name);
        let actions: Vec<&str> = spec.input_schema["properties"]["action"]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{} action enum", spec.name))
            .iter()
            .filter_map(|a| a.as_str())
            .collect();
        for k in ["create", "entryPointAccess", "dialInNumber", "pin"] {
            let listed =
                actions.contains(&k) || spec.input_schema["properties"].get(k).is_some();
            assert_eq!(listed, meet, "`{k}` in {}", spec.name);
        }
        assert!(
            actions.contains(&"join")
                && actions.contains(&"transcript")
                && actions.contains(&"leave"),
            "{} actions: {actions:?}",
            spec.name
        );
        if meet {
            assert_eq!(
                spec.input_schema["properties"]["accessType"]["enum"],
                json!(["OPEN", "TRUSTED", "RESTRICTED"])
            );
            assert_eq!(
                spec.input_schema["properties"]["entryPointAccess"]["enum"],
                json!(["ALL", "CREATOR_APP_ONLY"])
            );
        }
        let ctx = crate::testutil::ctx("meet-spec");
        assert_eq!(
            t.effects(&ctx, &json!({"action": "join", "url": urls[i]})),
            vec![Effect::Net {
                dest: crate::http::host_of(urls[i]),
                payload: urls[i].into()
            }],
            "{} join effects",
            spec.name
        );
        assert_eq!(
            t.effects(
                &ctx,
                &json!({"action": "speak", "sessionId": "s1", "message": "hi"})
            ),
            vec![Effect::Send {
                channel: format!("{}:s1", platforms::ALL[i].id()),
                payload: "hi".into()
            }],
            "{} speak effects",
            spec.name
        );
    }
}

/// The calls surface is reachable from the one registry the host wires: `seagent_media::tools`
/// must carry `voice_call` plus the four meeting tools (director wiring depends on it).
#[test]
fn media_tools_include_the_calls_surface() {
    let m = crate::Media::new(crate::MediaConfig::default());
    let names: Vec<String> = crate::tools(&m).iter().map(|t| t.spec().name).collect();
    for want in [
        "voice_call",
        "google_meet",
        "teams_meetings",
        "zoom_meetings",
        "slack_huddles",
    ] {
        assert!(names.iter().any(|n| n == want), "missing {want} in {names:?}");
    }
    assert_eq!(crate::phone::tools(&m).len(), 1);
    assert_eq!(tools(&m).len(), 4);
}

/// `effects()` must name where the data actually goes: Meet `create` posts to the REST API
/// (not the meeting URL), dial-in places a phone call, and a plain join only navigates.
#[test]
fn effects_name_the_real_destination() {
    let m = media("");
    let ts = tools(&m);
    let meet = ts
        .iter()
        .find(|t| t.spec().name == "google_meet")
        .expect("google_meet");
    let ctx = crate::testutil::ctx("meet-effects");
    assert_eq!(
        meet.effects(
            &ctx,
            &json!({"action": "create", "accessType": "TRUSTED", "entryPointAccess": "ALL"})
        ),
        vec![Effect::Net {
            dest: "meet.googleapis.com".into(),
            payload: "spaces.create accessType=TRUSTED entryPointAccess=ALL".into()
        }]
    );
    assert_eq!(
        meet.effects(
            &ctx,
            &json!({"action": "join", "transport": "twilio", "dialInNumber": "+15550001234", "pin": "1234"})
        ),
        vec![Effect::Send {
            channel: "phone:+15550001234".into(),
            payload: "Google Meet dial-in, PIN 1234".into()
        }]
    );
    // A join without a URL falls back to the platform's own host, never an empty dest.
    assert_eq!(
        meet.effects(&ctx, &json!({"action": "join"})),
        vec![Effect::Net {
            dest: "meet.google.com".into(),
            payload: "".into()
        }]
    );
    assert_eq!(
        meet.effects(&ctx, &json!({"action": "setup"})),
        vec![Effect::Exec {
            command: "pactl load-module module-null-sink sink_name=seagent_meeting".into()
        }]
    );
    // Read-only actions leave the machine alone.
    for a in ["status", "transcript", "sessions", "setup_status", "leave"] {
        assert!(
            meet.effects(&ctx, &json!({"action": a})).is_empty(),
            "{a} has no effect"
        );
    }
}

/// Teams end to end through the page scripts, against a fake DevTools endpoint that plays a
/// guest prejoin → in call (captions on) → transcript → leave.
#[test]
fn teams_join_captions_leave_over_fake_cdp() {
    let (http, _) = fake_devtools_at("https://teams.live.com/meet/9876abc?p=x", |i, expr| {
        assert!(
            expr.contains("prejoin-join-button"),
            "Teams join selector in the script"
        );
        assert!(
            expr.contains("hangup-button"),
            "Teams leave selector in the script"
        );
        assert!(
            expr.contains("closed-captions-button"),
            "Teams captions selector in the script"
        );
        assert!(
            expr.contains("closed-caption-renderer-wrapper") && expr.contains("captionAuthor"),
            "Teams caption row selectors in the script"
        );
        if expr.contains("\"autoJoin\":true") {
            assert!(
                expr.contains("\"guestName\":\"seagent bot\""),
                "the guest name reaches the prejoin"
            );
        }
        if expr.contains("\"readOnly\":true") {
            return json!({"inCall": true, "captioning": true, "notes": []});
        }
        if i == 0 {
            json!({"inCall": false, "notes": ["Entered the guest name.", "Clicked join."]})
        } else {
            json!({"inCall": true, "captioning": true, "notes": ["Turned on live captions for the transcript."]})
        }
    });
    let m = media(&format!(
        "[meeting]\ncdp_url = \"{}\"\nguest_name = \"seagent bot\"\njoin_timeout_secs = 10\n",
        http.url
    ));
    let r = call(
        &m,
        Platform::Teams,
        json!({"action": "join", "url": "https://teams.live.com/meet/9876abc?p=x"}),
    );
    let s = &r["session"];
    assert_eq!(
        (s["state"].as_str(), s["platform"].as_str()),
        (Some("active"), Some("teams-meetings")),
        "{r}"
    );
    let notes: Vec<&str> = s["notes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n.as_str())
        .collect();
    assert!(
        notes.contains(&"Entered the guest name.") && notes.contains(&"Clicked join."),
        "{notes:?}"
    );
    assert!(
        notes.contains(&"Turned on live captions for the transcript."),
        "{notes:?}"
    );
    let t = call(&m, Platform::Teams, json!({"action": "transcript"}));
    assert_eq!(
        t["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| format!(
                "{}: {}",
                l["speaker"].as_str().unwrap(),
                l["text"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        vec!["Alice: Hello everyone", "Bob: Hi Alice"]
    );
    let l = call(&m, Platform::Teams, json!({"action": "leave"}));
    assert_eq!(
        (l["left"].as_bool(), l["departed"].as_bool()),
        (Some(true), Some(true)),
        "{l}"
    );
    assert!(http.requests().iter().any(|q| q.path == "/json/close/T1"));
}

/// Google Meet end to end: join-now → in call (leave call button) → captions → transcript → leave.
#[test]
fn meet_join_captions_leave_over_fake_cdp() {
    let (http, _) = fake_devtools_at("https://meet.google.com/abc-defg-hij?hl=en", |i, expr| {
        assert!(
            expr.contains("join now|ask to join"),
            "Meet join labels in the script"
        );
        assert!(
            expr.contains("leave call"),
            "Meet leave selector in the script"
        );
        assert!(
            expr.contains("captionRenderer") && expr.contains("lobbyText"),
            "Meet caption region selector in the script"
        );
        if expr.contains("\"readOnly\":true") {
            return json!({"inCall": true, "captioning": true, "notes": []});
        }
        if i == 0 {
            json!({"inCall": false, "notes": ["Clicked join."]})
        } else {
            json!({"inCall": true, "captioning": true, "notes": ["Turned on live captions for the transcript."]})
        }
    });
    let m = media(&format!(
        "[meeting]\ncdp_url = \"{}\"\nguest_name = \"seagent bot\"\njoin_timeout_secs = 10\n",
        http.url
    ));
    let r = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "join", "url": "https://meet.google.com/abc-defg-hij"}),
    );
    let s = &r["session"];
    assert_eq!(
        (s["state"].as_str(), s["platform"].as_str(), s["transport"].as_str()),
        (Some("active"), Some("google-meet"), Some("chrome")),
        "{r}"
    );
    let t = call(&m, Platform::GoogleMeet, json!({"action": "transcript"}));
    assert_eq!(
        t["lines"].as_array().unwrap().len(),
        2,
        "growing captions collapse"
    );
    let l = call(&m, Platform::GoogleMeet, json!({"action": "leave"}));
    assert_eq!(l["departed"], true, "{l}");
    assert!(http.requests().iter().any(|q| q.path == "/json/close/T1"));
}

/// A Meet lobby page keeps polling and reports a manual action, not an error.
#[test]
fn meet_admission_waiting_is_not_an_error() {
    let (http, _) = fake_devtools_at("https://meet.google.com/abc-defg-hij?hl=en", |_, expr| {
        // The page says "asking to be let in"; the script's own lobby text covers it.
        assert!(
            expr.contains("asking to be let in"),
            "Meet lobby text in the script"
        );
        json!({"inCall": false, "lobbyWaiting": true, "manualAction": {"reason": "meet-admission-required", "message": "Waiting for the host to admit the bot."}, "notes": []})
    });
    let m = media(&format!(
        "[meeting]\ncdp_url = \"{}\"\njoin_timeout_secs = 2\n",
        http.url
    ));
    let started = std::time::Instant::now();
    let r = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "join", "url": "https://meet.google.com/abc-defg-hij"}),
    );
    assert_eq!(r["session"]["state"], "waiting", "{r}");
    assert_eq!(
        r["session"]["manualAction"]["reason"],
        "meet-admission-required",
        "{r}"
    );
    assert_eq!(r["session"]["health"]["lobbyWaiting"], true, "{r}");
    assert!(r["error"].is_null(), "{r}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the admission wait is bounded by join_timeout_secs"
    );
}

/// A Meet page that already shows the post-call screen ("You left the meeting") fails the join
/// with the upstream message.
#[test]
fn meet_ended_page_fails_the_join() {
    let (http, _) = fake_devtools_at("https://meet.google.com/abc-defg-hij?hl=en", |_, expr| {
        assert!(
            expr.contains("you left the meeting"),
            "Meet post-call text in the script"
        );
        json!({"inCall": false, "meetingEnded": true, "title": "You left the meeting", "notes": []})
    });
    let m = media(&format!(
        "[meeting]\ncdp_url = \"{}\"\njoin_timeout_secs = 5\n",
        http.url
    ));
    let r = call(
        &m,
        Platform::GoogleMeet,
        json!({"action": "join", "url": "https://meet.google.com/abc-defg-hij"}),
    );
    assert_eq!(
        r["error"].as_str(),
        Some("The Google Meet has already ended."),
        "{r}"
    );
}

/// Slack huddle: preview modal → join → in call → leave.
#[test]
fn slack_huddle_join_and_leave_over_fake_cdp() {
    let url = "https://app.slack.com/huddle/T0123ABCDE/C0123ABCDE";
    let (http, _) = fake_devtools_at(url, |i, expr| {
        assert!(
            expr.contains("huddle_join_preview_modal_go"),
            "Slack huddle join selector in the script"
        );
        assert!(
            expr.contains("huddle_toolbar__leave_button"),
            "Slack huddle leave selector in the script"
        );
        assert!(
            expr.contains("huddle_sidebar_footer"),
            "Slack in-call surface selector in the script"
        );
        if expr.contains("\"readOnly\":true") {
            return json!({"inCall": true, "notes": []});
        }
        if i == 0 {
            json!({"inCall": false, "notes": ["Clicked join."]})
        } else {
            json!({"inCall": true, "notes": ["Joined the huddle."]})
        }
    });
    let m = media(&format!(
        "[meeting]\ncdp_url = \"{}\"\nguest_name = \"seagent bot\"\njoin_timeout_secs = 10\n",
        http.url
    ));
    let r = call(&m, Platform::SlackHuddle, json!({"action": "join", "url": url}));
    let s = &r["session"];
    assert_eq!(
        (s["state"].as_str(), s["platform"].as_str()),
        (Some("active"), Some("slack-huddles")),
        "{r}"
    );
    assert!(
        s["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == "Clicked join."),
        "{r}"
    );
    let l = call(&m, Platform::SlackHuddle, json!({"action": "leave"}));
    assert_eq!(l["departed"], true, "{l}");
    assert!(http.requests().iter().any(|q| q.path == "/json/close/T1"));
}

#[test]
fn page_scripts_parse_in_node() {
    let Some(node) = crate::proc::which("node") else {
        return;
    };
    for p in platforms::ALL {
        let d = p.dom();
        for (name, src) in [
            (
                "status",
                scripts::status(
                    &d,
                    &json!({"autoJoin": true, "guestName": "a\"b", "prefix": p.reason_prefix()}),
                ),
            ),
            ("leave", scripts::leave(&d)),
            ("transcript", scripts::transcript(true)),
        ] {
            let file = temp_dir("meet-js").join(format!("{}-{name}.js", p.id()));
            std::fs::write(&file, format!("const f = {src};\n")).unwrap();
            let o = std::process::Command::new(&node)
                .arg("--check")
                .arg(&file)
                .output()
                .unwrap();
            assert!(
                o.status.success(),
                "{} {name}: {}",
                p.id(),
                String::from_utf8_lossy(&o.stderr)
            );
        }
    }
}

/// End to end in a real headless Chromium when one is installed: a local page shaped like
/// Zoom's web client (guest name, join, leave, live captions) is joined, its captions read
/// and left — the generated scripts drive the real DOM.
///
/// The join runs the production launch path ([`cdp::launch`] picks a fresh profile, waits for
/// DevTools and refuses to adopt a browser it did not start). A port that turns out to be
/// taken between picking it and the browser binding it is retried on a new port; only a host
/// where the browser cannot start at all makes the test step aside.
#[test]
fn real_chromium_drives_a_zoom_shaped_page() {
    let Some(exe) = cdp::find_chrome("") else {
        eprintln!("skipping: no Chromium-family browser installed");
        return;
    };
    let page = r#"<!doctype html><html><body>
<div id="pre"><input id="input-for-name"><button id="preview-video-control-button" aria-label="Stop Video">cam</button><button class="preview-join-button" onclick="join()">Join</button></div>
<script>
window.joinedAs = "";
function join() {
  window.joinedAs = document.getElementById("input-for-name").value;
  document.body.innerHTML = '<button aria-label="Leave" onclick="leave()">Leave</button><a aria-label="Show Captions" role="button" onclick="caps()">cc</a><div id="box"></div>';
}
function caps() {
  document.getElementById("box").innerHTML = '<div class="live-transcription-subtitle__box"><div id="live-transcription-subtitle"><span class="live-transcription-subtitle__speaker">Alice</span><span class="live-transcription-subtitle__item">Welcome everyone</span></div></div>';
  setTimeout(() => { document.querySelector(".live-transcription-subtitle__item").textContent = "Welcome everyone to standup"; }, 200);
}
function leave() { document.body.innerHTML = '<div class="meeting-ended">You left the meeting</div>'; }
</script></body></html>"#;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/j/123456789",
        l.local_addr().unwrap().port()
    );
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut b = [0u8; 4096];
            let _ = std::io::Read::read(&mut s, &mut b);
            let _ = std::io::Write::write_all(&mut s, format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}", page.len()).as_bytes());
        }
    });
    let mut last = String::new();
    for attempt in 1..=3 {
        let e = match drive_zoom_page(&exe, &url) {
            Ok(()) => return,
            Err(e) => e,
        };
        last = e;
        // Only a browser that cannot come up here (or a port that got taken) is worth another
        // port; a behavioural failure is the test's own and must not be masked.
        let startup = last.contains("exited")
            || last.contains("did not open DevTools")
            || last.contains("bound DevTools on port")
            || last.contains("already listening");
        if !(startup || last.contains("could not open a tab")) {
            break;
        }
        if attempt < 3 {
            eprintln!("attempt {attempt}: {last}; retrying on a fresh port");
            continue;
        }
        if startup {
            eprintln!("skipping: no usable browser here ({last})");
            return;
        }
        break;
    }
    panic!("the meeting bot could not drive a real browser: {last}");
}

/// One full join/captions/leave run against `url` in a freshly launched browser.
/// Browser-startup problems come back as `Err` (the caller retries on another port);
/// every behavioural failure is an assertion.
fn drive_zoom_page(exe: &std::path::Path, url: &str) -> Result<(), String> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let prof = temp_dir("meet-chrome");
    let m = media(&format!("[meeting]\nport = {port}\nheadless = true\nexecutable = \"{}\"\nprofile_dir = \"{}\"\nguest_name = \"seagent bot\"\njoin_timeout_secs = 20\n", exe.display(), prof.display()));
    let mt = meetings(&m);
    let r = mt.join_url(Platform::Zoom, url, "transcribe", &Cancel::new())?;
    // The join launched this browser (that is the code under test); close exactly it when the
    // test ends, including on a failed assertion.
    let _owned = OwnedBrowser(Cdp::new(&format!("http://127.0.0.1:{port}")), cdp::launched_pgid(port));
    let s = &r["session"];
    assert_eq!(s["state"], "active", "{r}");
    let id = s["sessionId"].as_str().unwrap().to_string();
    let tab = mt.get(&id).unwrap().tab.unwrap();
    let c = mt.devtools().unwrap();
    assert_eq!(
        c.eval(&tab, "async () => window.joinedAs", Duration::from_secs(5))
            .unwrap(),
        "seagent bot"
    );
    // Captions were enabled by the status script; wait for the observer to see the update.
    let mut lines = vec![];
    for _ in 0..30 {
        let _ = mt.status(&id);
        lines = mt.refresh_transcript(&id, false).unwrap();
        if lines
            .iter()
            .any(|l| l.text == "Welcome everyone to standup")
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        lines
            .iter()
            .map(|l| (l.speaker.as_str(), l.text.as_str()))
            .collect::<Vec<_>>(),
        vec![("Alice", "Welcome everyone to standup")]
    );
    let left = mt.leave(&id).unwrap();
    assert_eq!(left["departed"], true, "{left}");
    eprintln!(
        "real Chromium meeting join/captions/leave verified with {}",
        exe.display()
    );
    Ok(())
}

/// Closes the browser this test started when it goes out of scope. Only ever used for a
/// browser launched by [`cdp::launch`], which refuses to adopt an endpoint it did not start.
/// `Browser.close` first (clean profile shutdown); then the process group the launcher
/// recorded is terminated, so a hung or crashed browser is not left behind either (new-001).
struct OwnedBrowser(Cdp, Option<i32>);

impl Drop for OwnedBrowser {
    fn drop(&mut self) {
        if let Ok(v) = self.0.version() {
            if let Some(ws) = v["webSocketDebuggerUrl"].as_str() {
                let _ = Cdp::command(ws, "Browser.close", json!({}), Duration::from_secs(5));
            }
        }
        if let Some(pgid) = self.1 {
            if !seagent_core::proc::wait_until(Duration::from_secs(5), || !seagent_core::proc::group_alive(pgid)) {
                seagent_core::proc::kill_group(pgid, Duration::from_secs(2));
            }
        }
    }
}

/// The reported failure: another process holds the meeting port (a test's fake server, a
/// stray service) so Chrome cannot bind 127.0.0.1, silently falls back to another address and
/// the launcher "succeeds" against the squatter — the join then died with "DevTools did not
/// return the new tab", and the launcher's `Browser.close` would have closed a browser it did
/// not own. The port owner is never adopted, and only the browser we spawned is stopped.
#[test]
fn a_squatter_on_the_devtools_port_is_not_adopted() {
    let Some(exe) = cdp::find_chrome("") else {
        eprintln!("skipping: no Chromium-family browser installed");
        return;
    };
    let squatter = FakeServer::start(|_, _| (200, vec![], "{}".to_string()));
    let port = squatter
        .url
        .rsplit(':')
        .next()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let prof = temp_dir("meet-squat-chrome");
    let started = std::time::Instant::now();
    let r = cdp::launch(&exe, port, &prof, true);
    let e = r.expect_err("a port owned by another server must not be adopted");
    assert!(
        e.contains("not 127.0.0.1") || e.contains("exited") || e.contains("did not open DevTools"),
        "{e}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "{e}");
    // Nothing looked like a browser to the CDP client, so no tab was ever opened there.
    assert!(
        squatter
            .requests()
            .iter()
            .all(|r| r.path.starts_with("/json/")),
        "{:?}",
        squatter
            .requests()
            .iter()
            .map(|r| r.path.clone())
            .collect::<Vec<_>>()
    );
    assert!(Cdp::new(&squatter.url).version().is_err());
}

/// Anything answering on the meeting port is not automatically a browser: `/json/version`
/// must carry a DevTools banner. (A `{}` from some other server used to count as "Chrome is
/// up", and the join then died later with "DevTools did not return the new tab".)
#[test]
fn a_foreign_server_on_the_port_is_not_a_devtools_browser() {
    let squatter = FakeServer::start(|_, _| (200, vec![], "{}".to_string()));
    let c = Cdp::new(&squatter.url);
    let e = c.version().expect_err("a `{}` server is not DevTools");
    assert!(e.contains("not a Chrome DevTools endpoint"), "{e}");
    assert!(c.tabs().unwrap().is_empty());
    let e = c.open("http://127.0.0.1:9/j/1").expect_err("no tab there");
    assert!(e.contains("could not open a tab"), "{e}");
    assert!(
        squatter
            .requests()
            .iter()
            .all(|r| r.path.starts_with("/json/")),
        "{:?}",
        squatter
            .requests()
            .iter()
            .map(|r| r.path.clone())
            .collect::<Vec<_>>()
    );
}
