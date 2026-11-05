//! Telephony carriers (OpenClaw `extensions/voice-call/src/providers/{twilio,telnyx,plivo,mock}.ts`, MIT):
//! Twilio Programmable Voice (REST + TwiML + Media Streams), Telnyx Call Control v2
//! (REST actions + JSON webhooks + media streaming), Plivo Voice API (REST + XML +
//! GetInput speech), and a no-network mock for development.

use super::security::{self, Params};
use crate::http::Http;
use crate::Media;
use serde_json::{json, Value};

/// What a carrier webhook meant, normalized across providers.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Ringing,
    Answered,
    Active,
    /// Recognized caller speech (carrier ASR: Twilio Gather, Telnyx transcription, Plivo GetInput).
    Speech {
        text: String,
        is_final: bool,
    },
    Dtmf(String),
    Ended(String),
    /// A queued `<Say>`/speak finished (Telnyx `call.speak.ended`).
    SpeakEnded,
}

/// One inbound webhook request.
#[derive(Debug, Clone, Default)]
pub struct Webhook {
    pub method: String,
    /// The public URL the carrier signed (public origin + path + query).
    pub url: String,
    pub query: Params,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Webhook {
    pub fn q(&self, k: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }
    pub fn form(&self) -> Params {
        ark_net::parse_query(&self.body)
    }
}

/// Parsed webhook: our call id (when the carrier echoes it), the carrier's call id, events.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parsed {
    pub call_id: Option<String>,
    pub provider_call_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub inbound: bool,
    pub events: Vec<Event>,
    /// Replay-guard key from signature verification.
    pub replay_key: Option<String>,
}

pub fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub const EMPTY_TWIML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><Response></Response>"#;

/// Credentials + endpoints for the configured carrier.
#[derive(Debug, Clone, Default)]
pub struct Carrier {
    pub id: String,
    /// REST base (Twilio `…/2010-04-01/Accounts/<sid>`, Telnyx `…/v2`, Plivo `…/v1/Account/<id>`).
    pub base: String,
    /// Twilio account SID / Plivo auth id.
    pub account: String,
    /// Twilio/Plivo auth token, Telnyx API key.
    pub secret: String,
    pub connection_id: String,
    pub public_key: String,
    pub skip_verification: bool,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl Carrier {
    /// From `[media.providers.<id>]` + the carrier's documented env vars.
    pub fn from_config(m: &Media, id: &str) -> Result<Carrier, String> {
        let skip = m.cfg.bool_or("phone.skip_signature_verification", false);
        let extra =
            |c: &crate::Creds, k: &str, e: &str| c.str(k).or_else(|| env(e)).unwrap_or_default();
        match id {
            "twilio" => {
                let c = m.creds("twilio", &["TWILIO_AUTH_TOKEN"], "");
                let sid = extra(&c, "account_sid", "TWILIO_ACCOUNT_SID");
                if sid.is_empty() || c.key.is_none() {
                    return Err("Twilio needs account_sid and an auth token ([media.providers.twilio] account_sid / api_key, or TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN)".into());
                }
                let host = match c
                    .str("region")
                    .or_else(|| m.cfg.str("phone.twilio.region"))
                    .as_deref()
                    .unwrap_or("us1")
                {
                    "us1" => "api.twilio.com",
                    "ie1" => "api.dublin.ie1.twilio.com",
                    "au1" => "api.sydney.au1.twilio.com",
                    r => return Err(format!("unsupported Twilio region `{r}` (us1, ie1, au1)")),
                };
                let base = if c.base.is_empty() {
                    format!("https://{host}/2010-04-01/Accounts/{sid}")
                } else {
                    format!("{}/2010-04-01/Accounts/{sid}", c.base.trim_end_matches('/'))
                };
                Ok(Carrier {
                    id: id.into(),
                    base,
                    account: sid,
                    secret: c.key.unwrap(),
                    skip_verification: skip,
                    ..Default::default()
                })
            }
            "telnyx" => {
                let c = m.creds("telnyx", &["TELNYX_API_KEY"], "https://api.telnyx.com/v2");
                let key = c.key.clone().ok_or(
                    "Telnyx needs an API key ([media.providers.telnyx] api_key or TELNYX_API_KEY)",
                )?;
                let conn = extra(&c, "connection_id", "TELNYX_CONNECTION_ID");
                if conn.is_empty() {
                    return Err("Telnyx needs connection_id ([media.providers.telnyx] connection_id or TELNYX_CONNECTION_ID)".into());
                }
                let pk = extra(&c, "public_key", "TELNYX_PUBLIC_KEY");
                if pk.is_empty() && !skip {
                    return Err("Telnyx requires public_key (or TELNYX_PUBLIC_KEY) unless [media.phone] skip_signature_verification = true".into());
                }
                Ok(Carrier {
                    id: id.into(),
                    base: c.base.trim_end_matches('/').into(),
                    secret: key,
                    connection_id: conn,
                    public_key: pk,
                    skip_verification: skip,
                    ..Default::default()
                })
            }
            "plivo" => {
                let c = m.creds("plivo", &["PLIVO_AUTH_TOKEN"], "https://api.plivo.com");
                let auth_id = extra(&c, "auth_id", "PLIVO_AUTH_ID");
                if auth_id.is_empty() || c.key.is_none() {
                    return Err("Plivo needs auth_id and an auth token ([media.providers.plivo] auth_id / api_key, or PLIVO_AUTH_ID / PLIVO_AUTH_TOKEN)".into());
                }
                Ok(Carrier {
                    id: id.into(),
                    base: format!("{}/v1/Account/{auth_id}", c.base.trim_end_matches('/')),
                    account: auth_id,
                    secret: c.key.unwrap(),
                    skip_verification: skip,
                    ..Default::default()
                })
            }
            "mock" => Ok(Carrier {
                id: id.into(),
                skip_verification: true,
                ..Default::default()
            }),
            other => Err(format!(
                "unknown voice-call provider `{other}` (twilio, telnyx, plivo, mock)"
            )),
        }
    }

    fn basic(&self) -> Vec<(String, String)> {
        vec![(
            "Authorization".into(),
            format!(
                "Basic {}",
                ark_net::crypto::b64(format!("{}:{}", self.account, self.secret).as_bytes())
            ),
        )]
    }

    fn bearer(&self) -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bearer {}", self.secret))]
    }

    fn twilio(&self, http: &Http, path: &str, form: &[(&str, &str)]) -> Result<Value, String> {
        http.post_form(&format!("{}{path}", self.base), &self.basic(), form)
            .map_err(|e| format!("Twilio API error: {e}"))?
            .json()
    }

    fn telnyx(
        &self,
        http: &Http,
        path: &str,
        body: &Value,
        allow_404: bool,
    ) -> Result<Value, String> {
        let b = serde_json::to_vec(body).unwrap_or_default();
        let r = http.send(
            "POST",
            &format!("{}{path}", self.base),
            &self.bearer(),
            Some(("application/json", &b)),
        )?;
        if allow_404 && r.status == 404 {
            return Ok(Value::Null);
        }
        r.check("Telnyx API error")?.json()
    }

    fn plivo(
        &self,
        http: &Http,
        method: &str,
        path: &str,
        body: Option<&Value>,
        allow_404: bool,
    ) -> Result<Value, String> {
        let b = body.map(|v| serde_json::to_vec(v).unwrap_or_default());
        let r = http.send(
            method,
            &format!("{}{path}", self.base),
            &self.basic(),
            b.as_deref().map(|b| ("application/json", b)),
        )?;
        if allow_404 && r.status == 404 {
            return Ok(Value::Null);
        }
        r.check("Plivo API error")?.json()
    }

    /// Start an outbound call. `webhook` already carries `?callId=…`. `twiml` = inline TwiML
    /// (Twilio) / first answer XML (Plivo, served on the answer webhook); Telnyx acts on events.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate(
        &self,
        http: &Http,
        call_id: &str,
        from: &str,
        to: &str,
        webhook: &str,
        twiml: Option<&str>,
        stream_url: Option<&str>,
    ) -> Result<String, String> {
        match self.id.as_str() {
            "twilio" => {
                let status = format!("{webhook}&type=status");
                let mut form: Vec<(&str, &str)> = vec![
                    ("To", to),
                    ("From", from),
                    ("StatusCallback", &status),
                    ("StatusCallbackMethod", "POST"),
                ];
                for ev in ["initiated", "ringing", "answered", "completed"] {
                    form.push(("StatusCallbackEvent", ev));
                }
                form.push(("Timeout", "30"));
                match twiml {
                    Some(t) => form.push(("Twiml", t)),
                    None => form.extend([("Url", webhook), ("Method", "POST")]),
                }
                let v = self.twilio(http, "/Calls.json", &form)?;
                v["sid"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "Twilio call create returned no sid".into())
            }
            "telnyx" => {
                let mut body = json!({"connection_id": self.connection_id, "to": to, "from": from, "webhook_url": webhook, "webhook_url_method": "POST", "client_state": ark_net::crypto::b64(call_id.as_bytes()), "timeout_secs": 30});
                if let Some(s) = stream_url {
                    for (k, v) in [
                        ("stream_url", json!(s)),
                        ("stream_track", json!("inbound_track")),
                        ("stream_codec", json!("PCMU")),
                        ("stream_bidirectional_mode", json!("rtp")),
                        ("stream_bidirectional_codec", json!("PCMU")),
                        ("stream_bidirectional_sampling_rate", json!(8000)),
                        ("stream_bidirectional_target_legs", json!("self")),
                    ] {
                        body[k] = v;
                    }
                }
                let v = self.telnyx(http, "/calls", &body, false)?;
                v["data"]["call_control_id"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "Telnyx call create returned no call_control_id".into())
            }
            "plivo" => {
                let w = format!("{webhook}&provider=plivo");
                let body = json!({"from": plivo_number(from), "to": plivo_number(to), "answer_url": format!("{w}&flow=answer"), "answer_method": "POST", "hangup_url": format!("{w}&flow=hangup"), "hangup_method": "POST", "hangup_on_ring": 30});
                let v = self.plivo(http, "POST", "/Call/", Some(&body), false)?;
                let ru = if v["request_uuid"].is_array() {
                    v["request_uuid"][0].clone()
                } else {
                    v["request_uuid"].clone()
                };
                ru.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "Plivo call create returned no request_uuid".into())
            }
            _ => Ok(format!("mock-{call_id}")),
        }
    }

    pub fn hangup(&self, http: &Http, pcid: &str) -> Result<(), String> {
        match self.id.as_str() {
            "twilio" => self
                .twilio(
                    http,
                    &format!("/Calls/{pcid}.json"),
                    &[("Status", "completed")],
                )
                .map(|_| ()),
            "telnyx" => self
                .telnyx(
                    http,
                    &format!("/calls/{pcid}/actions/hangup"),
                    &json!({"command_id": ark_net::crypto::random_token(12)}),
                    true,
                )
                .map(|_| ()),
            "plivo" => self
                .plivo(http, "DELETE", &format!("/Call/{pcid}/"), None, true)
                .map(|_| ()),
            _ => Ok(()),
        }
    }

    /// Replace a live Twilio call's TwiML (speak / listen / DTMF), or Plivo transfer to `url`.
    pub fn update_live(
        &self,
        http: &Http,
        pcid: &str,
        twiml: &str,
        plivo_url: Option<&str>,
    ) -> Result<(), String> {
        match self.id.as_str() {
            "twilio" => self
                .twilio(http, &format!("/Calls/{pcid}.json"), &[("Twiml", twiml)])
                .map(|_| ()),
            "plivo" => {
                let u = plivo_url.ok_or("Plivo transfer needs a webhook URL")?;
                self.plivo(
                    http,
                    "POST",
                    &format!("/Call/{pcid}/"),
                    Some(&json!({"legs": "aleg", "aleg_url": u, "aleg_method": "POST"})),
                    false,
                )
                .map(|_| ())
            }
            _ => Ok(()),
        }
    }

    /// Telnyx call-control actions (`speak`, `transcription_start`, `send_dtmf`, `answer`).
    pub fn telnyx_action(
        &self,
        http: &Http,
        pcid: &str,
        action: &str,
        mut body: Value,
    ) -> Result<(), String> {
        if self.id != "telnyx" {
            return Ok(());
        }
        body["command_id"] = json!(ark_net::crypto::random_token(12));
        self.telnyx(
            http,
            &format!("/calls/{pcid}/actions/{action}"),
            &body,
            false,
        )
        .map(|_| ())
    }

    /// Verify and parse a webhook. Errors are signature failures (answer 401).
    pub fn parse(&self, w: &Webhook, now_s: u64) -> Result<Parsed, String> {
        match self.id.as_str() {
            "twilio" => {
                let form = w.form();
                let key = if self.skip_verification {
                    None
                } else {
                    Some(security::verify_twilio(
                        &self.secret,
                        &w.headers,
                        &w.url,
                        &form,
                    )?)
                };
                let g = |k: &str| {
                    form.iter()
                        .find(|(n, _)| n == k)
                        .map(|(_, v)| v.clone())
                        .filter(|v| !v.is_empty())
                };
                let mut p = Parsed {
                    call_id: w.q("callId").map(str::to_string),
                    provider_call_id: g("CallSid"),
                    from: g("From"),
                    to: g("To"),
                    inbound: g("Direction").as_deref() == Some("inbound"),
                    replay_key: key,
                    ..Default::default()
                };
                if let Some(s) = g("SpeechResult") {
                    p.events.push(Event::Speech {
                        text: s,
                        is_final: true,
                    });
                }
                if let Some(d) = g("Digits") {
                    p.events.push(Event::Dtmf(d));
                }
                match g("CallStatus").as_deref() {
                    Some("ringing") => p.events.push(Event::Ringing),
                    Some("in-progress") if p.events.is_empty() => p.events.push(Event::Answered),
                    Some(s @ ("completed" | "busy" | "no-answer" | "failed" | "canceled")) => {
                        p.events.push(Event::Ended(s.into()))
                    }
                    _ => {}
                }
                Ok(p)
            }
            "telnyx" => {
                let key = if self.skip_verification {
                    None
                } else {
                    Some(security::verify_telnyx(
                        &self.public_key,
                        &w.headers,
                        &w.body,
                        now_s,
                    )?)
                };
                let v: Value = serde_json::from_str(&w.body).map_err(|_| "bad JSON".to_string())?;
                let d = &v["data"];
                let pl = &d["payload"];
                let cs = pl["client_state"].as_str().map(|s| {
                    ark_net::crypto::b64_decode(s)
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_else(|| s.to_string())
                });
                let mut p = Parsed {
                    call_id: cs,
                    provider_call_id: pl["call_control_id"].as_str().map(str::to_string),
                    from: pl["from"].as_str().map(str::to_string),
                    to: pl["to"].as_str().map(str::to_string),
                    inbound: pl["direction"] == "incoming" || pl["direction"] == "inbound",
                    replay_key: key,
                    ..Default::default()
                };
                let ev = match d["event_type"].as_str().unwrap_or("") {
                    "call.initiated" => None,
                    "call.ringing" => Some(Event::Ringing),
                    "call.answered" => Some(Event::Answered),
                    "call.bridged" => Some(Event::Active),
                    "call.speak.ended" => Some(Event::SpeakEnded),
                    "call.transcription" => {
                        let td = &pl["transcription_data"];
                        let t = td["transcript"]
                            .as_str()
                            .or(pl["transcription"].as_str())
                            .unwrap_or("")
                            .to_string();
                        (!t.trim().is_empty()).then(|| Event::Speech {
                            text: t,
                            is_final: td["is_final"]
                                .as_bool()
                                .or(pl["is_final"].as_bool())
                                .unwrap_or(true),
                        })
                    }
                    "call.hangup" => Some(Event::Ended(
                        match pl["hangup_cause"].as_str().unwrap_or("") {
                            "user_busy" | "busy" => "busy".into(),
                            "no_answer" | "timeout" => "no-answer".into(),
                            "call_rejected" | "rejected" => "rejected".into(),
                            "" | "normal_clearing" | "originator_cancel" => "completed".into(),
                            c => c.to_string(),
                        },
                    )),
                    "call.dtmf.received" => {
                        Some(Event::Dtmf(pl["digit"].as_str().unwrap_or("").into()))
                    }
                    _ => None,
                };
                p.events.extend(ev);
                Ok(p)
            }
            "plivo" => {
                let form = w.form();
                let key = if self.skip_verification {
                    None
                } else {
                    Some(security::verify_plivo(
                        &self.secret,
                        &w.headers,
                        &w.method,
                        &w.url,
                        &form,
                    )?)
                };
                let g = |k: &str| {
                    form.iter()
                        .find(|(n, _)| n == k)
                        .map(|(_, v)| v.clone())
                        .filter(|v| !v.is_empty())
                };
                let mut p = Parsed {
                    call_id: w.q("callId").map(str::to_string),
                    provider_call_id: g("CallUUID").or_else(|| g("RequestUUID")),
                    from: g("From"),
                    to: g("To"),
                    inbound: g("Direction").as_deref() == Some("inbound"),
                    replay_key: key,
                    ..Default::default()
                };
                if let Some(d) = g("Digits") {
                    p.events.push(Event::Dtmf(d));
                } else if let Some(t) = g("Speech")
                    .or_else(|| g("SpeechResult"))
                    .or_else(|| g("UnstableSpeech").filter(|_| false))
                {
                    p.events.push(Event::Speech {
                        text: t,
                        is_final: true,
                    });
                } else {
                    match g("CallStatus").as_deref() {
                        Some("ringing") => p.events.push(Event::Ringing),
                        Some("in-progress") => p.events.push(Event::Answered),
                        Some(s @ ("completed" | "busy" | "no-answer" | "failed")) => {
                            p.events.push(Event::Ended(s.into()))
                        }
                        _ if g("Event").as_deref() == Some("StartApp")
                            && p.provider_call_id.is_some() =>
                        {
                            p.events.push(Event::Answered)
                        }
                        _ => {}
                    }
                }
                Ok(p)
            }
            _ => {
                // mock: JSON {"callId","event","text"}.
                let v: Value = serde_json::from_str(&w.body).unwrap_or_default();
                let mut p = Parsed {
                    call_id: v["callId"].as_str().map(str::to_string),
                    ..Default::default()
                };
                p.events.extend(match v["event"].as_str().unwrap_or("") {
                    "answered" => Some(Event::Answered),
                    "speech" => Some(Event::Speech {
                        text: v["text"].as_str().unwrap_or("").into(),
                        is_final: true,
                    }),
                    "dtmf" => Some(Event::Dtmf(v["text"].as_str().unwrap_or("").into())),
                    "ended" => Some(Event::Ended("completed".into())),
                    _ => None,
                });
                Ok(p)
            }
        }
    }
}

/// Plivo wants digits without `+`.
pub fn plivo_number(n: &str) -> String {
    n.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// TwiML: say (Polly voice), then listen for speech posting to `action`.
pub fn twiml_say_gather(text: &str, voice: &str, lang: &str, action: &str) -> String {
    let say = if text.trim().is_empty() {
        String::new()
    } else {
        format!(
            "<Say voice=\"{}\" language=\"{}\">{}</Say>",
            escape_xml(voice),
            escape_xml(lang),
            escape_xml(text)
        )
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Response>{say}<Gather input="speech" speechTimeout="auto" language="{}" action="{}" method="POST"><Say>.</Say></Gather><Redirect method="POST">{}</Redirect></Response>"#,
        escape_xml(lang),
        escape_xml(action),
        escape_xml(action)
    )
}

pub fn twiml_say_hangup(text: &str, voice: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="{}">{}</Say><Hangup/></Response>"#,
        escape_xml(voice),
        escape_xml(text)
    )
}

/// Media Streams: `<Connect><Stream>`; the token travels as a `<Parameter>` (Twilio strips WS query strings).
pub fn twiml_stream(stream_url: &str, token: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Response><Connect><Stream url="{}"><Parameter name="token" value="{}" /></Stream></Connect></Response>"#,
        escape_xml(stream_url),
        escape_xml(token)
    )
}

pub fn twiml_dtmf(digits: &str, redirect: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Response><Play digits="{}"/><Redirect method="POST">{}</Redirect></Response>"#,
        escape_xml(digits),
        escape_xml(redirect)
    )
}

/// Plivo XML: speak, then GetInput speech posting to `action` (or hang up).
pub fn plivo_xml(text: &str, lang: &str, action: Option<&str>) -> String {
    let speak = if text.trim().is_empty() {
        String::new()
    } else {
        format!(
            "<Speak language=\"{}\">{}</Speak>",
            escape_xml(lang),
            escape_xml(text)
        )
    };
    match action {
        Some(a) => format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><Response>{speak}<GetInput inputType="speech" method="POST" action="{}" language="{}" executionTimeout="30" speechEndTimeout="2" redirect="false"></GetInput></Response>"#,
            escape_xml(a),
            escape_xml(lang)
        ),
        None => format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><Response>{speak}<Hangup/></Response>"#
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twiml_shapes_escape() {
        let t = twiml_say_gather(
            "a < b & \"c\"",
            "Polly.Joanna",
            "en-US",
            "https://h/w?callId=1&type=gather",
        );
        assert!(
            t.contains(
                "<Say voice=\"Polly.Joanna\" language=\"en-US\">a &lt; b &amp; &quot;c&quot;</Say>"
            ),
            "{t}"
        );
        assert!(
            t.contains("<Gather input=\"speech\"")
                && t.contains("action=\"https://h/w?callId=1&amp;type=gather\"")
        );
        assert!(twiml_say_hangup("bye", "alice").ends_with("<Hangup/></Response>"));
        assert!(twiml_stream("wss://h/voice/stream", "tok")
            .contains("<Parameter name=\"token\" value=\"tok\" />"));
        assert!(plivo_xml("hi", "en-US", None)
            .contains("<Speak language=\"en-US\">hi</Speak><Hangup/>"));
        assert!(plivo_xml("hi", "en-US", Some("https://h/w"))
            .contains("<GetInput inputType=\"speech\""));
        assert_eq!(plivo_number("+1 (555) 000-1234"), "15550001234");
    }

    #[test]
    fn telnyx_parse_events() {
        let c = Carrier {
            id: "telnyx".into(),
            skip_verification: true,
            ..Default::default()
        };
        let w = |b: Value| Webhook {
            method: "POST".into(),
            body: b.to_string(),
            ..Default::default()
        };
        let cs = ark_net::crypto::b64(b"call-1");
        let p = c.parse(&w(json!({"data": {"event_type": "call.transcription", "payload": {"call_control_id": "cc", "client_state": cs, "transcription_data": {"transcript": "hello there", "is_final": true}}}})), 0).unwrap();
        assert_eq!(
            (p.call_id.as_deref(), p.provider_call_id.as_deref()),
            (Some("call-1"), Some("cc"))
        );
        assert_eq!(
            p.events,
            vec![Event::Speech {
                text: "hello there".into(),
                is_final: true
            }]
        );
        let p = c.parse(&w(json!({"data": {"event_type": "call.hangup", "payload": {"hangup_cause": "user_busy"}}})), 0).unwrap();
        assert_eq!(p.events, vec![Event::Ended("busy".into())]);
        assert!(c
            .parse(
                &Webhook {
                    body: "nope".into(),
                    ..Default::default()
                },
                0
            )
            .is_err());
    }
}
