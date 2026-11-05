//! Meeting platforms (OpenClaw `extensions/{google-meet,teams-meetings,zoom-meetings,slack-huddles}`,
//! MIT): URL validation/normalization (which meeting a URL means, for tab reuse) and the
//! DOM knowledge the page scripts use (selectors transcribed from each extension's
//! `*-selectors.ts`, plus label patterns for UIs without stable ids).

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    GoogleMeet,
    Teams,
    Zoom,
    SlackHuddle,
}

pub const ALL: [Platform; 4] = [
    Platform::GoogleMeet,
    Platform::Teams,
    Platform::Zoom,
    Platform::SlackHuddle,
];

fn parse_https(u: &str) -> Option<(String, String, String)> {
    let rest = u.trim().strip_prefix("https://")?;
    let (auth, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if auth.contains('@') || auth.contains(':') || auth.is_empty() {
        return None; // no userinfo, no explicit port
    }
    let tail = tail.split('#').next().unwrap_or("");
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    Some((
        auth.to_ascii_lowercase(),
        if path.is_empty() {
            "/".into()
        } else {
            path.to_string()
        },
        query.to_string(),
    ))
}

fn q(query: &str, k: &str) -> Option<String> {
    seagent_net::parse_query(query)
        .into_iter()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v)
}

fn digits(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

fn upper_id(s: &str, first: &[u8], min_rest: usize) -> bool {
    s.len() > min_rest
        && first.contains(&s.as_bytes()[0])
        && s.bytes()
            .skip(1)
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

impl Platform {
    pub fn id(self) -> &'static str {
        match self {
            Platform::GoogleMeet => "google-meet",
            Platform::Teams => "teams-meetings",
            Platform::Zoom => "zoom-meetings",
            Platform::SlackHuddle => "slack-huddles",
        }
    }
    pub fn tool(self) -> &'static str {
        match self {
            Platform::GoogleMeet => "google_meet",
            Platform::Teams => "teams_meetings",
            Platform::Zoom => "zoom_meetings",
            Platform::SlackHuddle => "slack_huddles",
        }
    }
    pub fn display(self) -> &'static str {
        match self {
            Platform::GoogleMeet => "Google Meet",
            Platform::Teams => "Microsoft Teams",
            Platform::Zoom => "Zoom",
            Platform::SlackHuddle => "Slack huddle",
        }
    }
    /// The host a session joins when the tool call carries no URL (Meet API `create`, dial-in).
    pub fn host(self) -> &'static str {
        match self {
            Platform::GoogleMeet => "meet.google.com",
            Platform::Teams => "teams.microsoft.com",
            Platform::Zoom => "zoom.us",
            Platform::SlackHuddle => "app.slack.com",
        }
    }
    /// Prefix of manual-action reasons (`zoom-passcode-required`, …).
    pub fn reason_prefix(self) -> &'static str {
        match self {
            Platform::GoogleMeet => "meet",
            Platform::Teams => "teams",
            Platform::Zoom => "zoom",
            Platform::SlackHuddle => "slack",
        }
    }

    /// The meeting a URL identifies (tab reuse key), or `None` when it is not this platform's.
    pub fn identity(self, url: &str) -> Option<String> {
        match self {
            Platform::GoogleMeet => {
                let (host, path, _) = parse_https(url)?;
                if host != "meet.google.com" {
                    return None;
                }
                let code = path
                    .trim_start_matches('/')
                    .trim_end_matches('/')
                    .to_ascii_lowercase();
                let parts: Vec<&str> = code.split('-').collect();
                (parts.len() == 3
                    && [3, 4, 3]
                        .iter()
                        .zip(&parts)
                        .all(|(n, p)| p.len() == *n && p.bytes().all(|b| b.is_ascii_lowercase())))
                .then(|| format!("https://meet.google.com/{code}"))
            }
            Platform::Zoom => {
                let (host, path, query) = parse_https(url)?;
                if !(host == "zoom.us" || host.ends_with(".zoom.us")) {
                    return None;
                }
                let seg: Vec<&str> = path.trim_matches('/').split('/').collect();
                let id = match seg.as_slice() {
                    ["j", id] if digits(id, 9, 11) => id.to_string(),
                    ["wc", id, "join"] if host == "app.zoom.us" && digits(id, 9, 11) => {
                        id.to_string()
                    }
                    _ => return None,
                };
                let _ = query;
                Some(format!("zoom:{id}"))
            }
            Platform::Teams => {
                let (host, path, query) = parse_https(url)?;
                if host == "teams.microsoft.com" {
                    let rest = path
                        .strip_prefix("/l/meetup-join/")
                        .or_else(|| path.strip_prefix("/L/meetup-join/"))?;
                    let thread = seagent_net::urldecode(rest.split('/').next()?);
                    let ok = thread.starts_with("19:")
                        && (thread.to_ascii_lowercase().ends_with("@thread.v2")
                            || thread.to_ascii_lowercase().ends_with("@thread.tacv2"));
                    return ok.then(|| format!("teams-work:{thread}"));
                }
                if host == "teams.live.com" {
                    let code = path.strip_prefix("/meet/")?.trim_end_matches('/');
                    if code.is_empty()
                        || !code
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    {
                        return None;
                    }
                    return Some(format!(
                        "teams-consumer:{}:p:{}",
                        code.to_ascii_lowercase(),
                        seagent_net::urlencode(&q(&query, "p").unwrap_or_default())
                    ));
                }
                None
            }
            Platform::SlackHuddle => slack_identity(url).map(|(t, c)| {
                format!(
                    "slack:{}{c}",
                    t.map(|t| format!("{t}/")).unwrap_or_default()
                )
            }),
        }
    }

    /// Validate and normalize a user-supplied URL (errors mirror upstream's messages).
    pub fn normalize(self, input: &str) -> Result<String, String> {
        let v = input.trim();
        if v.is_empty() {
            return Err(format!(
                "{} URL is required",
                match self {
                    Platform::GoogleMeet => "Google Meet",
                    Platform::Teams => "Microsoft Teams meeting",
                    Platform::Zoom => "Zoom meeting",
                    Platform::SlackHuddle => "Slack huddle",
                }
            ));
        }
        if self == Platform::SlackHuddle {
            let (team, ch) = slack_identity(v).ok_or("Use a Slack Copy huddle link (https://app.slack.com/huddle/TEAM/CHANNEL), an uppercase channel id such as C0123ABCD or channel:C0123ABCD, or team:T0123ABCD:channel:C0123ABCD. Message permalinks, user ids, and slack:// links are not huddle links.")?;
            return Ok(format!(
                "https://app.slack.com/huddle/{}{ch}",
                team.map(|t| format!("{t}/")).unwrap_or_default()
            ));
        }
        if self.identity(v).is_none() {
            return Err(match self {
                Platform::GoogleMeet => "Google Meet URL must look like https://meet.google.com/abc-defg-hij".into(),
                Platform::Teams => "Microsoft Teams meeting URL must use https://teams.microsoft.com/l/meetup-join/... or https://teams.live.com/meet/<id>".into(),
                Platform::Zoom => "Zoom meeting URL must use https://<account>.zoom.us/j/<meeting-id>".into(),
                Platform::SlackHuddle => unreachable!(),
            });
        }
        let mut u = v.split('#').next().unwrap_or(v).to_string();
        if self == Platform::GoogleMeet {
            // Meet automation matches English UI labels: pin hl=en, keep other params.
            let (base, query) = u
                .split_once('?')
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .unwrap_or((u.clone(), String::new()));
            let mut pairs: Vec<(String, String)> = seagent_net::parse_query(&query)
                .into_iter()
                .filter(|(k, _)| k != "hl")
                .collect();
            pairs.push(("hl".into(), "en".into()));
            let refs: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect();
            u = format!("{base}?{}", seagent_net::form_encode(&refs));
        }
        Ok(u)
    }

    pub fn same_meeting(self, a: &str, b: &str) -> bool {
        matches!((self.identity(a), self.identity(b)), (Some(x), Some(y)) if x == y)
    }

    /// Selectors + label patterns for the page scripts.
    pub fn dom(self) -> Value {
        match self {
            Platform::GoogleMeet => json!({
                "guestName": ["input[aria-label*=\"your name\" i]", "input[placeholder*=\"your name\" i]"],
                "join": [], "joinText": "join now|ask to join",
                "continueInBrowser": [],
                "microphone": [], "micText": "^\\s*turn (?:off|on) microphone\\b",
                "camera": [], "cameraText": "^\\s*turn (?:off|on) camera\\b",
                "leave": ["button[aria-label*=\"leave call\" i]"], "leaveText": "leave call",
                "leaveConfirmation": [], "leaveConfirmText": "\\bleave meeting\\b",
                "postCallText": "you left the meeting|you.?ve left the meeting|removed from the meeting|you were removed|call ended|meeting ended|return to home screen",
                "lobby": [], "lobbyText": "asking to be let in|you.?ll join when someone lets you in|waiting to be let in|ask to join",
                "signIn": [], "signInText": "use your google account|to continue to google meet|choose an account|sign in to (join|continue)",
                "signInHosts": ["accounts.google.com"],
                "passcode": [], "captcha": [],
                "permissionText": "permission needed|microphone problem|allow.*(microphone|camera)|blocked.*(microphone|camera)",
                "moreActions": [], "captions": [], "captionsText": "turn on captions|show captions",
                "captionsOnText": "turn off captions|hide captions",
                "captionRenderer": ["[role=\"region\"][aria-label*=\"aption\" i]", "[aria-live=\"polite\"][role=\"region\"]", "div[aria-live=\"polite\"]"],
                "captionRows": [], "captionAuthor": [], "captionText": []
            }),
            Platform::Teams => json!({
                "continueInBrowser": ["[data-tid=\"joinOnWeb\"]", "[data-tid=\"joinOnWebButton\"]", "button[data-tid=\"continue-on-browser\"]"],
                "continueText": "continue on this browser|join on the web instead",
                "guestName": ["input[data-tid=\"prejoin-display-name-input\"]", "[data-tid=\"prejoin-display-name-input\"] input", "input[data-tid=\"guest-name-input\"]"],
                "join": ["button[data-tid=\"prejoin-join-button\"]", "[data-tid=\"prejoin-join-button\"] button", "button[data-tid=\"join-now\"]", "button[data-tid=\"join-button\"]"], "joinText": "^\\s*(join now|ask to join|join meeting)\\s*$",
                "microphone": ["button[data-tid=\"toggle-mute\"]", "[data-tid=\"toggle-mute\"] button", "input[data-tid=\"toggle-mute\"]", "[data-tid=\"toggle-mute\"][role=\"switch\"]", "button[data-tid=\"microphone-button\"]"],
                "camera": ["button[data-tid=\"toggle-video\"]", "[data-tid=\"toggle-video\"] button", "input[data-tid=\"toggle-video\"]", "[data-tid=\"toggle-video\"][role=\"switch\"]", "button[data-tid=\"camera-button\"]"],
                "leave": ["button#hangup-button", "button[data-tid=\"call-hangup\"]", "[data-tid=\"call-hangup\"] button", "button[data-tid=\"hangup-button\"]", "button[data-tid=\"call-hangup-button\"]"], "leaveText": "^leave$",
                "leaveConfirmation": ["button[data-tid=\"confirm-leave-button\"]", "button[data-tid=\"leave-meeting-confirm\"]", "button[data-tid=\"leave-call-confirm\"]"],
                "postCall": ["button[data-tid=\"anon-meeting-end-screen-rejoin-button\"]", "[data-tid=\"call-ended-screen\"]", "[data-tid=\"post-call-screen\"]", "button[data-tid=\"prejoin-rejoin-button\"]"],
                "lobby": ["[data-tid=\"lobby-screen\"]", "[data-tid=\"lobby-waiting-screen\"]"], "lobbyText": "someone in the meeting should let you in soon|someone will let you in shortly|waiting for someone to let you in|when someone admits you|you.?re in the lobby|we.?ve let people in the meeting know you.?re waiting",
                "signIn": ["button[data-tid=\"signin-button\"]", "button[data-tid=\"sign-in-button\"]", "[data-tid=\"auth-signin\"]"], "signInHosts": ["login.microsoftonline.com"],
                "passcode": ["input[data-tid=\"meeting-passcode-input\"]"],
                "captcha": [],
                "permissionPrompt": ["[data-tid=\"device-permission-prompt\"]", "[data-tid=\"media-permission-prompt\"]", "[data-tid=\"browser-permission-error\"]"],
                "moreActions": ["button[aria-label=\"More\"]"],
                "captions": ["button#closed-captions-button", "[role=\"menuitem\"][title*=\"captions\" i]"], "captionsText": "turn on live captions|show live captions",
                "captionsOff": ["button[data-tid=\"closed-captions-turn-off-button\"]", "button#captions-panel-dismiss-button"],
                "captionRenderer": ["[data-tid=\"closed-caption-renderer-wrapper\"]"],
                "captionRows": ["div[role=\"log\"] > *", "[data-tid=\"closed-caption-v2-virtual-list-content\"] > *"],
                "captionAuthor": ["[data-tid=\"author\"]"], "captionText": ["[data-tid=\"closed-caption-text\"]"]
            }),
            Platform::Zoom => json!({
                "continueInBrowser": [], "continueText": "join from your browser|join from browser",
                "guestName": ["input#input-for-name"],
                "join": ["button.preview-join-button"], "joinText": "^join$",
                "microphone": ["button#preview-audio-control-button", "button[aria-label=\"mute my microphone\" i]", "button[aria-label=\"unmute my microphone\" i]"],
                "camera": ["button#preview-video-control-button", "button.send-video-container__btn"],
                "leave": ["button[aria-label=\"Leave\" i]"], "leaveText": "^leave$",
                "leaveConfirmation": ["button.leave-meeting-options__btn", "button.zm-btn--danger", "button[aria-label=\"Leave Meeting\" i]"], "leaveConfirmText": "^leave meeting$",
                "postCall": [".meeting-ended", ".post-meeting", ".leave-meeting-page"], "postCallText": "meeting has been ended by host|you left the meeting|meeting has ended",
                "lobby": [".waiting-room-container", "[class*=\"waiting-room\"]", "[class*=\"waitingRoom\"]"], "lobbyText": "please wait, the meeting host will let you in soon|waiting for the host",
                "signIn": ["a[href*=\"/signin\"]", "button[aria-label*=\"sign in\" i]"],
                "passcode": ["input[type=\"password\"]", "input[id*=\"passcode\" i]", "input[name*=\"passcode\" i]", "input[aria-label*=\"passcode\" i]"],
                "captcha": ["iframe[src*=\"recaptcha\" i]", "iframe[title*=\"captcha\" i]", ".g-recaptcha", "[data-sitekey]", "[class*=\"captcha\" i]"],
                "permissionPrompt": [".pepc-permission-dialog"],
                "moreActions": ["button.more-button", ".footer-more-button button"],
                "captions": ["a[aria-label*=\"Show Captions\" i]", "a[aria-label=\"Captions\" i]", "[role=\"button\"][aria-label=\"Captions\" i]"],
                "captionsOff": ["a[aria-label*=\"Hide Captions\" i]"],
                "captionRenderer": [".live-transcription-subtitle__box"],
                "captionRows": ["#live-transcription-subtitle"],
                "captionAuthor": [".zmu-data-selector-item__icon", ".live-transcription-subtitle__speaker", "[class*=\"transcription\"][class*=\"speaker\"]"],
                "captionText": [".live-transcription-subtitle__item", ".live-transcription-subtitle__text", "[class*=\"transcription\"][class*=\"text\"]", ".live-transcription-subtitle__box"],
                "frame": "#webclient"
            }),
            Platform::SlackHuddle => json!({
                "continueInBrowser": [], "guestName": [],
                "preview": ["[data-qa=\"huddle_join_preview_modal\"]"],
                "join": ["[data-qa=\"huddle_join_preview_modal_go\"]"], "joinText": "^join( huddle)?$|^start huddle$",
                "confirmation": ["[data-qa=\"huddle_join_modal\"]", "[data-qa=\"huddle_in_thread_speed_bump_modal\"]"],
                "multiDevice": ["[data-qa=\"huddle_multi_device_modal_switch_device\"]", "[data-qa=\"huddle_multi_device_modal_use_both_device\"]"],
                "previewMicrophone": ["[data-qa=\"huddle_join_preview_mic_button\"]"],
                "microphone": ["button[role=\"switch\"][aria-label=\"Microphone\"]", "[data-qa=\"huddle_sidebar_footer_mute_button\"]", "[data-qa=\"segmented-mute-button-main\"]", "button[aria-describedby=\"microphone-info\"]"],
                "mutedIcon": ["[data-qa=\"huddle_mic_icon_mute\"]"], "unmutedIcon": ["[data-qa=\"huddle_mic_icon_unmute\"]"],
                "camera": [],
                "leave": ["[data-qa=\"huddle_toolbar__leave_button\"]", "[data-qa=\"huddle_mini_player_leave_button\"]"],
                "inCall": ["[data-qa=\"huddle_toolbar__leave_button\"]", "[data-qa=\"huddle_mini_player_leave_button\"]", "[data-qa=\"huddle_sidebar_footer\"]", "[data-qa=\"huddle_toolbar_buttons_center\"]"],
                "leaveConfirmation": [],
                "lobby": [], "signIn": ["form[action*=\"signin\"]", "input[name=\"email\"]", "input[type=\"password\"]"],
                "passcode": [], "captcha": [],
                "moreActions": [], "captions": [], "captionsText": "turn on captions|show captions",
                "captionRenderer": [".p-huddle_closed_captions", ".p-huddle_closed_caption_event__event_text", "[data-qa=\"huddle_transcribe_event\"]"],
                "captionRows": [".p-huddle_closed_caption_event__wrapper", "[data-qa=\"huddle_transcribe_event\"]"],
                "captionAuthor": [".p-huddle_closed_caption_event__member_name"],
                "captionText": [".p-huddle_closed_caption_event__event_text span[data-qa=\"huddle_closed_caption_event\"]", "[data-qa=\"huddle_transcribe_event\"]"]
            }),
        }
    }
}

/// Slack huddle identity: `(team, channel)` from a huddle link, `C…`, `channel:C…` or `team:T…:channel:C…`.
fn slack_identity(input: &str) -> Option<(Option<String>, String)> {
    let v = input.trim();
    let ch = v.strip_prefix("slack:").unwrap_or(v);
    let ch = ch
        .strip_prefix("channel:")
        .or_else(|| ch.strip_prefix("Channel:"))
        .unwrap_or(ch);
    if upper_id(ch, b"CGD", 8) {
        return Some((None, ch.into()));
    }
    let q = v.strip_prefix("slack:").unwrap_or(v);
    if let Some(rest) = q.strip_prefix("team:") {
        let (team, ch) = rest.split_once(":channel:")?;
        if upper_id(team, b"TE", 8) && upper_id(ch, b"CGD", 8) {
            return Some((Some(team.into()), ch.into()));
        }
        return None;
    }
    let (host, path, _) = parse_https(v)?;
    if !(host.ends_with(".slack.com")
        && host.split('.').count() == 3
        && host
            .split('.')
            .next()
            .is_some_and(|h| h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')))
    {
        return None;
    }
    let seg: Vec<&str> = path.trim_matches('/').split('/').collect();
    match seg.as_slice() {
        ["huddle", ch] if upper_id(ch, b"CGD", 8) => Some((None, ch.to_string())),
        ["huddle", team, ch] if upper_id(team, b"TE", 8) && upper_id(ch, b"CGD", 8) => {
            Some((Some(team.to_string()), ch.to_string()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_follow_upstream_rules() {
        let g = Platform::GoogleMeet;
        assert_eq!(
            g.identity("https://meet.google.com/ABC-defg-hij/?authuser=1")
                .as_deref(),
            Some("https://meet.google.com/abc-defg-hij")
        );
        assert_eq!(
            g.normalize("https://meet.google.com/abc-defg-hij?authuser=1&hl=de#x")
                .unwrap(),
            "https://meet.google.com/abc-defg-hij?authuser=1&hl=en"
        );
        assert!(g.normalize("http://meet.google.com/abc-defg-hij").is_err());
        assert!(g.normalize("https://meet.google.com/abcd-efg-hij").is_err());
        let z = Platform::Zoom;
        assert_eq!(
            z.identity("https://acme.zoom.us/j/123456789?pwd=x")
                .as_deref(),
            Some("zoom:123456789")
        );
        assert_eq!(
            z.identity("https://app.zoom.us/wc/12345678901/join")
                .as_deref(),
            Some("zoom:12345678901")
        );
        assert!(
            z.identity("https://evilzoom.us/j/123456789").is_none()
                && z.identity("https://acme.zoom.us:8443/j/123456789")
                    .is_none()
        );
        assert_eq!(
            z.normalize("https://acme.zoom.us/j/123456789?pwd=abc#frag")
                .unwrap(),
            "https://acme.zoom.us/j/123456789?pwd=abc"
        );
        assert!(z
            .normalize("https://acme.zoom.us/s/123")
            .unwrap_err()
            .contains("zoom.us/j/"));
        assert!(z.same_meeting(
            "https://a.zoom.us/j/123456789?pwd=1",
            "https://app.zoom.us/wc/123456789/join"
        ));
        let t = Platform::Teams;
        assert_eq!(t.identity("https://teams.microsoft.com/l/meetup-join/19%3ameeting_abc%40thread.v2/0?context=x").as_deref(), Some("teams-work:19:meeting_abc@thread.v2"));
        assert_eq!(
            t.identity("https://teams.live.com/meet/9876Abc?p=Pass1")
                .as_deref(),
            Some("teams-consumer:9876abc:p:Pass1")
        );
        assert!(t.normalize("https://teams.microsoft.com/l/chat/1").is_err());
        let s = Platform::SlackHuddle;
        assert_eq!(
            s.normalize("https://app.slack.com/huddle/T0123ABCDE/C0123ABCDE")
                .unwrap(),
            "https://app.slack.com/huddle/T0123ABCDE/C0123ABCDE"
        );
        assert_eq!(
            s.normalize("channel:C0123ABCD").unwrap(),
            "https://app.slack.com/huddle/C0123ABCD"
        );
        assert_eq!(
            s.normalize("team:T0123ABCD:channel:G0123ABCD").unwrap(),
            "https://app.slack.com/huddle/T0123ABCD/G0123ABCD"
        );
        assert!(s
            .normalize("U0123ABCD")
            .unwrap_err()
            .contains("huddle link"));
        assert!(s
            .normalize("https://acme.slack.com/archives/C0123ABCD/p123")
            .is_err());
        for p in ALL {
            assert!(p.dom()["leave"].is_array(), "{}", p.id());
        }
    }
}
