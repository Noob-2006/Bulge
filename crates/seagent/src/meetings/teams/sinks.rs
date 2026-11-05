//! Output sinks for the Teams pipeline (Hermes `plugins/teams_pipeline/pipeline.py`'s
//! `NotionWriter` / `LinearWriter`, MIT).
//!
//! Notion creates a page in a database (or updates an existing page's properties on a re-run);
//! Linear creates an issue (or updates it). Both need an API key from the sink config
//! (`api_key`, `{{secret:NAME}}`-resolved) or the upstream env var.
//!
//! Teams delivery is implemented here (incoming webhook, or a Graph chat/channel message) per
//! upstream `plugins/platforms/teams/summary_writer.py`; a host may instead inject an
//! `seagent_channel` msteams adapter as the sink.

use super::pipeline::render_summary_markdown;
use super::models::SummaryPayload;
use seagent_tools::web::http::{enc, post_json};
use serde_json::{json, Map, Value};

pub const NOTION_API_BASE: &str = "https://api.notion.com/v1";
pub const NOTION_API_VERSION: &str = "2025-09-03";
pub const LINEAR_API_URL: &str = "https://api.linear.app/graphql";
const TIMEOUT: u64 = 30;

fn field(config: &Map<String, Value>, key: &str, camel: &str) -> Option<String> {
    config.get(key).or_else(|| config.get(camel)).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// `config.api_key`, else the sink's env var; an unresolved `{{secret:…}}` counts as missing.
fn api_key(config: &Map<String, Value>, env_var: &str) -> Option<String> {
    let from_cfg = field(config, "api_key", "apiKey").filter(|k| !k.contains("{{secret:"));
    from_cfg.or_else(|| std::env::var(env_var).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
}

fn base(config: &Map<String, Value>, default: &str) -> String {
    field(config, "base_url", "baseUrl").unwrap_or_else(|| default.to_string()).trim_end_matches('/').to_string()
}

/// `{"rich_text": [{"text": {"content": …}}]}`.
fn rich_text(content: &str) -> Value {
    json!({"rich_text": [{"text": {"content": content}}]})
}

fn notion_properties(payload: &SummaryPayload, config: &Map<String, Value>) -> Value {
    let title = payload.title.clone().unwrap_or_else(|| format!("Meeting {}", payload.meeting_ref.meeting_id));
    let title_prop = field(config, "title_property", "titleProperty").unwrap_or_else(|| "Name".into());
    let mut props = Map::new();
    props.insert(title_prop, json!({"title": [{"text": {"content": title}}]}));
    if let Some(p) = field(config, "summary_property", "summaryProperty") {
        let summary: String = payload.summary.clone().unwrap_or_default().chars().take(1900).collect();
        props.insert(p, rich_text(&summary));
    }
    if let Some(p) = field(config, "meeting_id_property", "meetingIdProperty") {
        props.insert(p, rich_text(&payload.meeting_ref.meeting_id));
    }
    Value::Object(props)
}

fn notion_blocks(payload: &SummaryPayload) -> Vec<Value> {
    let bullets = |items: &[String]| -> String {
        if items.is_empty() {
            "- None".into()
        } else {
            items.iter().map(|i| format!("- {i}")).collect::<Vec<_>>().join("\n")
        }
    };
    let sections = [
        ("Summary", payload.summary.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "None".into())),
        ("Key Decisions", bullets(&payload.key_decisions)),
        ("Action Items", bullets(&payload.action_items)),
        ("Risks", bullets(&payload.risks)),
    ];
    sections
        .iter()
        .flat_map(|(heading, body)| {
            [json!({"object": "block", "type": "heading_2", "heading_2": rich_text(heading)}), json!({"object": "block", "type": "paragraph", "paragraph": rich_text(body)})]
        })
        .collect()
}

/// Create or update the Notion page for one meeting.
pub fn notion_write(payload: &SummaryPayload, config: &Map<String, Value>, existing: Option<&Value>) -> Result<Value, String> {
    let key = api_key(config, "NOTION_API_KEY").ok_or("NOTION_API_KEY is not configured.")?;
    let database_id = field(config, "database_id", "databaseId").unwrap_or_default();
    let page_id = existing.and_then(|e| e.get("page_id")).and_then(Value::as_str).map(str::to_string);
    if database_id.is_empty() && page_id.is_none() {
        return Err("Notion sink requires database_id or an existing page_id.".into());
    }
    let headers: Vec<(&str, String)> = vec![("Authorization", format!("Bearer {key}")), ("Notion-Version", NOTION_API_VERSION.to_string()), ("Content-Type", "application/json".to_string())];
    let properties = notion_properties(payload, config);
    let url = format!("{}/pages", base(config, NOTION_API_BASE));
    // Re-runs update the existing page's properties only; body blocks are written once on create.
    let body = match &page_id {
        Some(_) => json!({"properties": properties}),
        None => json!({"parent": {"database_id": database_id}, "properties": properties, "children": notion_blocks(payload)}),
    };
    let (u, r) = match &page_id {
        Some(id) => (format!("{url}/{id}"), super::graph::http_json("PATCH", &format!("{url}/{id}"), &headers, Some(&body), TIMEOUT)),
        None => (url.clone(), post_json(&url, &headers, &body, TIMEOUT)),
    };
    let r = r.map_err(|e| format!("Notion write failed: {e}"))?;
    if r.status >= 400 {
        return Err(format!("Notion write failed ({}): {}", r.status, r.body.trim()));
    }
    let v: Value = r.json().map_err(|_| format!("Notion write failed: {u} returned non-JSON"))?;
    Ok(json!({"page_id": v.get("id").cloned().unwrap_or(Value::Null), "url": v.get("url").cloned().unwrap_or(Value::Null)}))
}

const LINEAR_UPDATE: &str = "mutation($id: String!, $input: IssueUpdateInput!) { issueUpdate(id: $id, input: $input) { success issue { id identifier url } } }";
const LINEAR_CREATE: &str = "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }";

/// Create or update the Linear issue for one meeting.
pub fn linear_write(payload: &SummaryPayload, config: &Map<String, Value>, existing: Option<&Value>) -> Result<Value, String> {
    let key = api_key(config, "LINEAR_API_KEY").ok_or("LINEAR_API_KEY is not configured.")?;
    let headers: Vec<(&str, String)> = vec![("Authorization", key), ("Content-Type", "application/json".to_string())];
    let team_id = field(config, "team_id", "teamId").unwrap_or_default();
    let issue_input = json!({
        "title": payload.title.clone().unwrap_or_else(|| format!("Meeting Summary: {}", payload.meeting_ref.meeting_id)),
        "description": render_summary_markdown(payload),
    });
    let body = match existing.and_then(|e| e.get("issue_id")).and_then(Value::as_str) {
        Some(id) => json!({"query": LINEAR_UPDATE, "variables": {"id": id, "input": issue_input}}),
        None if team_id.is_empty() => return Err("Linear sink requires team_id when creating a new issue.".into()),
        None => {
            let mut input = issue_input;
            input["teamId"] = json!(team_id);
            json!({"query": LINEAR_CREATE, "variables": {"input": input}})
        }
    };
    let r = post_json(&base(config, LINEAR_API_URL), &headers, &body, TIMEOUT).map_err(|e| format!("Linear write failed: {e}"))?;
    if r.status >= 400 {
        return Err(format!("Linear write failed ({}): {}", r.status, r.body.trim()));
    }
    let v: Value = r.json().map_err(|_| "Linear write failed: response was not JSON".to_string())?;
    let issue = v.get("data").and_then(|d| d.get("issueUpdate").or_else(|| d.get("issueCreate"))).and_then(|m| m.get("issue"));
    let Some(issue) = issue.filter(|i| i.get("id").and_then(Value::as_str).is_some()) else {
        return Err(format!("Linear write failed: {v}"));
    };
    Ok(json!({"issue_id": issue.get("id").cloned().unwrap_or(Value::Null), "identifier": issue.get("identifier").cloned().unwrap_or(Value::Null), "url": issue.get("url").cloned().unwrap_or(Value::Null)}))
}

// ---------------------------------------------------------------------------------------------
// Teams delivery (upstream `plugins/platforms/teams/summary_writer.py`, MIT)
// ---------------------------------------------------------------------------------------------

const SUMMARY_HEADING: &str = "Summary";
const EMPTY_SUMMARY: &str = "No summary available.";
const NONE_ITEM: &str = "None";
/// The three list sections, in upstream's `_LIST_SECTIONS` order.
const LIST_SECTIONS: [&str; 3] = ["Key Decisions", "Action Items", "Risks"];

/// Upstream `_ENV_KEYS`, minus `access_token` (see [`teams_write`]).
const TEAMS_ENV_KEYS: [(&str, &str); 5] = [
    ("delivery_mode", "TEAMS_DELIVERY_MODE"),
    ("incoming_webhook_url", "TEAMS_INCOMING_WEBHOOK_URL"),
    ("team_id", "TEAMS_TEAM_ID"),
    ("channel_id", "TEAMS_CHANNEL_ID"),
    ("chat_id", "TEAMS_CHAT_ID"),
];

/// HTML-escape the characters `html.escape(quote=True)` covers (`& < > " '`); no new dependency.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Upstream `_render_summary_html`: `<h2>{title}</h2><h3>Summary</h3><p>{summary}</p>`, then a
/// `<h3>` heading plus `<ul>`/`<p>None</p>` block per list section. Headings are the English
/// strings `render_summary_markdown` uses (seagent hardcodes what upstream resolves via `t()`).
pub fn render_summary_html(p: &SummaryPayload) -> String {
    let summary = p.summary.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(EMPTY_SUMMARY);
    let title = p.title.clone().filter(|t| !t.is_empty()).unwrap_or_else(|| format!("Meeting {}", p.meeting_ref.meeting_id));
    let mut out = format!("<h2>{}</h2><h3>{}</h3><p>{}</p>", esc(&title), esc(SUMMARY_HEADING), esc(summary));
    let items = [&p.key_decisions, &p.action_items, &p.risks];
    for (heading, list) in LIST_SECTIONS.iter().zip(items) {
        // Upstream keeps an item when `str(item).strip()` is non-empty, and renders it as-is.
        let lis: String = list.iter().filter(|i| !i.trim().is_empty()).map(|i| format!("<li>{}</li>", esc(i))).collect();
        let block = if lis.is_empty() { format!("<p>{}</p>", esc(NONE_ITEM)) } else { format!("<ul>{lis}</ul>") };
        out.push_str(&format!("<h3>{}</h3>", esc(heading)));
        out.push_str(&block);
    }
    out
}

/// Upstream `_parse_bool` (`force_resend` may arrive as a JSON bool or an env-style string).
fn bool_field(config: &Map<String, Value>, key: &str) -> bool {
    match config.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        Some(Value::String(s)) => matches!(s.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        _ => false,
    }
}

/// Upstream `_resolve_delivery_config`: the caller's `teams_delivery` table wins, and each env key
/// only fills a value the config left empty.
fn teams_delivery_config(config: &Map<String, Value>) -> Map<String, Value> {
    let mut merged = config.clone();
    for (key, env) in TEAMS_ENV_KEYS {
        let set = matches!(merged.get(key).and_then(Value::as_str).map(str::trim), Some(v) if !v.is_empty());
        if !set {
            if let Ok(v) = std::env::var(env) {
                let v = v.trim();
                if !v.is_empty() {
                    merged.insert(key.to_string(), json!(v));
                }
            }
        }
    }
    merged
}

/// Deliver a meeting summary to Teams (upstream `TeamsSummaryWriter.write_summary` in
/// `plugins/platforms/teams/summary_writer.py`, MIT): an incoming-webhook message with the
/// markdown summary, or an HTML `chatMessage` in a Graph chat / channel.
///
/// `existing` short-circuits unless `force_resend` is set, so a pipeline re-run does not post
/// twice. Deliberate divergence from upstream: there is no `access_token`/`TEAMS_GRAPH_ACCESS_TOKEN`
/// key, because seagent's Graph client always does a client-credentials exchange
/// (`[meetings.teams]` + `MSGRAPH_*`); graph mode therefore needs an injected [`super::graph::Client`].
pub fn teams_write(payload: &SummaryPayload, config: &Map<String, Value>, existing: Option<&Value>, client: Option<&super::graph::Client>) -> Result<Value, String> {
    let merged = teams_delivery_config(config);
    if !bool_field(&merged, "force_resend") {
        if let Some(record) = existing {
            return Ok(record.clone());
        }
    }
    let mut mode = field(&merged, "delivery_mode", "mode").map(|m| m.to_lowercase()).unwrap_or_default();
    if mode.is_empty() {
        if field(&merged, "incoming_webhook_url", "incomingWebhookUrl").is_some() {
            mode = "incoming_webhook".into();
        } else if field(&merged, "chat_id", "chatId").is_some() || (field(&merged, "team_id", "teamId").is_some() && field(&merged, "channel_id", "channelId").is_some()) {
            mode = "graph".into();
        }
    }
    match mode.as_str() {
        "incoming_webhook" => {
            let url = field(&merged, "incoming_webhook_url", "incomingWebhookUrl").ok_or("TEAMS_INCOMING_WEBHOOK_URL is required for incoming_webhook mode.")?;
            let body = json!({"text": render_summary_markdown(payload)});
            let r = post_json(&url, &[("Content-Type", "application/json".to_string())], &body, 20).map_err(|e| format!("Teams incoming webhook failed: {e}"))?;
            if r.status >= 400 {
                return Err(format!("Teams incoming webhook failed ({}): {}", r.status, r.body.trim()));
            }
            Ok(json!({"delivery_mode": "incoming_webhook", "webhook_url": url, "status_code": r.status, "delivered": true}))
        }
        "graph" => {
            let client = client.ok_or("Teams Graph delivery needs Microsoft Graph credentials ([meetings.teams]).")?;
            let mut record = json!({"delivery_mode": "graph"});
            let record_obj = record.as_object_mut().expect("object literal");
            let path = if let Some(chat_id) = field(&merged, "chat_id", "chatId") {
                record_obj.insert("target_type".into(), json!("chat"));
                record_obj.insert("chat_id".into(), json!(chat_id));
                format!("/chats/{}/messages", enc(&chat_id))
            } else {
                let team_id = field(&merged, "team_id", "teamId").unwrap_or_default();
                let channel_id = field(&merged, "channel_id", "channelId").unwrap_or_default();
                if team_id.is_empty() || channel_id.is_empty() {
                    return Err("Graph delivery mode requires chat_id, or both team_id and channel_id.".into());
                }
                record_obj.insert("target_type".into(), json!("channel"));
                record_obj.insert("team_id".into(), json!(team_id));
                record_obj.insert("channel_id".into(), json!(channel_id));
                format!("/teams/{}/channels/{}/messages", enc(&team_id), enc(&channel_id))
            };
            let body = json!({"body": {"contentType": "html", "content": render_summary_html(payload)}});
            let v = client.post_json(&path, &body).map_err(|e| format!("Teams delivery failed: {e}"))?;
            record_obj.insert("message_id".into(), v.get("id").cloned().unwrap_or(Value::Null));
            record_obj.insert("web_url".into(), v.get("webUrl").cloned().unwrap_or(Value::Null));
            Ok(record)
        }
        _ => Err("Teams delivery_mode must be 'incoming_webhook' or 'graph'.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meetings::teams::models::TeamsMeetingRef;
    use std::io::{BufRead, Read, Write};
    use std::sync::{Arc, Mutex};

    fn payload() -> SummaryPayload {
        SummaryPayload {
            meeting_ref: TeamsMeetingRef { meeting_id: "M1".into(), ..Default::default() },
            title: Some("Weekly".into()),
            summary: Some("we shipped".into()),
            key_decisions: vec!["ship it".into()],
            ..Default::default()
        }
    }

    #[test]
    fn sinks_require_their_api_keys_with_upstream_messages() {
        let cfg: Map<String, Value> = [("database_id".to_string(), json!("db"))].into_iter().collect();
        let e = std::env::var("NOTION_API_KEY").ok();
        if e.is_none() {
            assert_eq!(notion_write(&payload(), &cfg, None).unwrap_err(), "NOTION_API_KEY is not configured.");
        }
        if std::env::var("LINEAR_API_KEY").is_err() {
            assert_eq!(linear_write(&payload(), &Map::new(), None).unwrap_err(), "LINEAR_API_KEY is not configured.");
        }
        // An unresolved secret placeholder is not a key either.
        let cfg: Map<String, Value> = [("api_key".to_string(), json!("{{secret:NOPE}}")), ("database_id".to_string(), json!("db"))].into_iter().collect();
        if std::env::var("NOTION_API_KEY").is_err() {
            assert!(notion_write(&payload(), &cfg, None).unwrap_err().contains("not configured"));
        }
    }

    #[test]
    fn notion_properties_and_blocks_follow_config() {
        let cfg: Map<String, Value> = [("title_property".to_string(), json!("Title")), ("summary_property".to_string(), json!("Summary")), ("meeting_id_property".to_string(), json!("Meeting"))]
            .into_iter()
            .collect();
        let props = notion_properties(&payload(), &cfg);
        assert_eq!(props["Title"]["title"][0]["text"]["content"], "Weekly");
        assert_eq!(props["Summary"]["rich_text"][0]["text"]["content"], "we shipped");
        assert_eq!(props["Meeting"]["rich_text"][0]["text"]["content"], "M1");
        let blocks = notion_blocks(&payload());
        assert_eq!(blocks.len(), 8, "four headings, four paragraphs");
        assert_eq!(blocks[1]["paragraph"]["rich_text"][0]["text"]["content"], "we shipped");
        assert!(render_summary_markdown(&payload()).contains("## Key Decisions\n- ship it"));
    }

    // -- Teams delivery ---------------------------------------------------------------------

    /// `(path, body)` for every request the fake server saw.
    type Hits = Arc<Mutex<Vec<(String, String)>>>;

    /// Serve `respond(path, body)` on a local port for the life of the test process.
    fn serve(respond: impl Fn(&str, &str) -> (u16, Value) + Send + 'static) -> (String, Hits) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let hits: Hits = Arc::new(Mutex::new(Vec::new()));
        let h = hits.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut r = std::io::BufReader::new(s.try_clone().unwrap());
                let mut head = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    let done = line == "\r\n" || line == "\n";
                    head.push_str(&line);
                    if done {
                        break;
                    }
                }
                if head.is_empty() {
                    continue;
                }
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
                let body = String::from_utf8_lossy(&body).into_owned();
                let path = head.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
                h.lock().unwrap().push((path.clone(), body.clone()));
                let (status, payload) = respond(&path, &body);
                let payload = payload.to_string();
                let resp = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}", payload.len());
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (url, hits)
    }

    fn captured(h: &Hits) -> Vec<(String, String)> {
        h.lock().unwrap().clone()
    }

    fn cfg_with(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn teams_incoming_webhook_delivery_posts_the_summary_markdown() {
        let (url, hits) = serve(|_, _| (200, json!({})));
        let webhook = format!("{url}/webhook/abc");
        let cfg = cfg_with(vec![("delivery_mode", json!("incoming_webhook")), ("incoming_webhook_url", json!(webhook))]);

        let record = teams_write(&payload(), &cfg, None, None).unwrap();
        assert_eq!(record["delivered"], json!(true));
        assert_eq!(record["delivery_mode"], json!("incoming_webhook"));
        assert_eq!(record["webhook_url"], json!(webhook));
        assert_eq!(record["status_code"], json!(200));
        let seen = captured(&hits);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "/webhook/abc");
        let body: Value = serde_json::from_str(&seen[0].1).unwrap();
        let text = body["text"].as_str().unwrap();
        assert!(text.contains("we shipped"), "{text}");
        assert!(text.contains("## Action Items"), "{text}");

        // A re-run with the stored record is a no-op (upstream returns the existing record).
        let again = teams_write(&payload(), &cfg, Some(&record), None).unwrap();
        assert_eq!(again, record);
        assert_eq!(captured(&hits).len(), 1, "the existing record must not be delivered twice");

        // `force_resend` overrides that.
        let forced = cfg_with(vec![("delivery_mode", json!("incoming_webhook")), ("incoming_webhook_url", json!(webhook)), ("force_resend", json!("true"))]);
        let resent = teams_write(&payload(), &forced, Some(&record), None).unwrap();
        assert_eq!(resent["delivered"], json!(true));
        assert_eq!(captured(&hits).len(), 2, "force_resend posts again");
    }

    #[test]
    fn teams_graph_delivery_posts_html_to_the_chat_or_channel() {
        let (url, hits) = serve(|path, _| {
            if path.contains("/oauth2/v2.0/token") {
                (200, json!({"access_token": "tok", "expires_in": 3600}))
            } else {
                (201, json!({"id": "m1", "webUrl": "https://teams.test/m1"}))
            }
        });
        let creds = super::super::graph::Credentials::from_parts(Some("contoso".into()), Some("app".into()), Some("s3cret".into()), None, Some(format!("{url}/oauth2/v2.0/token"))).unwrap();
        let client = super::super::graph::Client::new(creds, &format!("{url}/v1.0"));

        let mut p = payload();
        p.risks = vec!["<b>blocked</b> on legal".into()];
        let cfg = cfg_with(vec![("delivery_mode", json!("graph")), ("chat_id", json!("19:chat/one"))]);
        let record = teams_write(&p, &cfg, None, Some(&client)).unwrap();

        assert_eq!(record["delivery_mode"], json!("graph"));
        assert_eq!(record["target_type"], json!("chat"));
        assert_eq!(record["chat_id"], json!("19:chat/one"));
        assert_eq!(record["message_id"], json!("m1"));
        assert_eq!(record["web_url"], json!("https://teams.test/m1"));

        let seen = captured(&hits);
        let posted = seen.iter().find(|(path, _)| path.ends_with("/messages")).expect("a message POST");
        assert_eq!(posted.0, "/v1.0/chats/19%3Achat%2Fone/messages");
        let body: Value = serde_json::from_str(&posted.1).unwrap();
        assert_eq!(body["body"]["contentType"], json!("html"));
        let content = body["body"]["content"].as_str().unwrap();
        assert!(content.contains("<h2>Weekly</h2>"), "{content}");
        assert!(content.contains("&lt;b&gt;blocked&lt;/b&gt; on legal"), "{content}");

        // Channel targets use team_id + channel_id.
        let cfg = cfg_with(vec![("delivery_mode", json!("graph")), ("team_id", json!("t1")), ("channel_id", json!("c1"))]);
        let record = teams_write(&payload(), &cfg, None, Some(&client)).unwrap();
        assert_eq!(record["target_type"], json!("channel"));
        assert_eq!(record["team_id"], json!("t1"));
        assert_eq!(record["channel_id"], json!("c1"));
        let seen = captured(&hits);
        assert!(seen.iter().any(|(path, _)| path == "/v1.0/teams/t1/channels/c1/messages"), "{seen:?}");
    }

    #[test]
    fn render_summary_html_matches_upstream_sections() {
        let mut p = payload();
        p.summary = Some("  ".into());
        p.title = None;
        let html = render_summary_html(&p);
        assert_eq!(
            html,
            "<h2>Meeting M1</h2><h3>Summary</h3><p>No summary available.</p>\
             <h3>Key Decisions</h3><ul><li>ship it</li></ul>\
             <h3>Action Items</h3><p>None</p>\
             <h3>Risks</h3><p>None</p>"
        );
        let mut p = payload();
        p.summary = Some("Tom & Jerry <say \"hi\">'s".into());
        assert!(render_summary_html(&p).contains("<p>Tom &amp; Jerry &lt;say &quot;hi&quot;&gt;&#x27;s</p>"));
    }

    #[test]
    fn teams_delivery_errors_match_upstream() {
        // incoming_webhook without a URL (an env fallback would make it reachable, so skip then).
        let cfg = cfg_with(vec![("delivery_mode", json!("incoming_webhook"))]);
        if std::env::var("TEAMS_INCOMING_WEBHOOK_URL").is_err() {
            assert_eq!(teams_write(&payload(), &cfg, None, None).unwrap_err(), "TEAMS_INCOMING_WEBHOOK_URL is required for incoming_webhook mode.");
        }
        // graph without an injected client.
        let cfg = cfg_with(vec![("delivery_mode", json!("graph")), ("chat_id", json!("c1"))]);
        assert_eq!(teams_write(&payload(), &cfg, None, None).unwrap_err(), "Teams Graph delivery needs Microsoft Graph credentials ([meetings.teams]).");
        // graph with only team_id: rejected before any request is sent.
        let creds = super::super::graph::Credentials::from_parts(Some("contoso".into()), Some("app".into()), Some("s3cret".into()), None, None).unwrap();
        let client = super::super::graph::Client::new(creds, "http://127.0.0.1:9/v1.0");
        let cfg = cfg_with(vec![("delivery_mode", json!("graph")), ("team_id", json!("t1"))]);
        assert_eq!(teams_write(&payload(), &cfg, None, Some(&client)).unwrap_err(), "Graph delivery mode requires chat_id, or both team_id and channel_id.");
        // unknown mode.
        let cfg = cfg_with(vec![("delivery_mode", json!("carrier_pigeon"))]);
        assert_eq!(teams_write(&payload(), &cfg, None, None).unwrap_err(), "Teams delivery_mode must be 'incoming_webhook' or 'graph'.");
    }
}
