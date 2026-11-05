//! In-page automation scripts (OpenClaw `src/meeting-bot/{status-prejoin-source,status-call-source,
//! page-script-source}.ts` and each platform's page scripts, MIT), generated from the
//! platform's selectors: pre-join (guest name, camera off, microphone per mode, continue in
//! browser, join), state detection (in call, lobby, sign-in / passcode / captcha / permission
//! manual actions, call ended), live captions (enable + MutationObserver archive), leave.
//! Every script is an async arrow function returning JSON.

use serde_json::{json, Value};

const HELPERS: &str = r#"
  const S = __SELECTORS__;
  const P = __PARAMS__;
  const doc = (S.frame && document.querySelector(S.frame)?.contentDocument) || document;
  const text = (n) => (n?.innerText || n?.textContent || "").trim();
  const label = (n) => [n?.getAttribute?.("aria-label"), n?.getAttribute?.("data-tooltip"), n?.getAttribute?.("title"), text(n)].filter(Boolean).join(" ").trim();
  const sel = (k) => Array.isArray(S[k]) ? S[k] : [];
  const firstRaw = (k) => { for (const s of sel(k)) { try { const n = doc.querySelector(s); if (n) return n; } catch {} } return undefined; };
  const asButton = (n) => n && (n.matches?.("button,input,[role=button],[role=switch],a") ? n : (n.querySelector?.("button") || n.closest?.("button") || n));
  const first = (k) => asButton(firstRaw(k));
  const rx = (k) => S[k] ? new RegExp(S[k], "i") : undefined;
  const buttons = () => [...doc.querySelectorAll("button,[role=button],a[role=button]")].filter((b) => !b.disabled);
  const byText = (k) => { const r = rx(k); return r ? buttons().find((b) => r.test(label(b))) : undefined; };
  const control = (selKey, textKey) => first(selKey) || byText(textKey);
  const toggleState = (n, kind) => {
    if (!n) return undefined;
    const pressed = String(n.getAttribute?.("aria-pressed") || "").toLowerCase();
    if (pressed === "true") return "on";
    if (pressed === "false") return "off";
    const checked = String(n.getAttribute?.("aria-checked") ?? n.checked ?? "").toLowerCase();
    if (checked === "true") return "on";
    if (checked === "false") return "off";
    const v = label(n).toLowerCase();
    const noun = kind === "camera" ? "(?:camera|video)" : "(?:microphone|mic)";
    if (new RegExp(`\\b(?:turn (?:your |my )?${noun} off|turn off (?:your |my )?${noun}|stop video|mute (?:your |my )?${noun}|disable (?:your |my )?${noun})\\b|^mute$`).test(v)) return "on";
    if (new RegExp(`\\b(?:turn (?:your |my )?${noun} on|turn on (?:your |my )?${noun}|start video|unmute (?:your |my )?${noun}|enable (?:your |my )?${noun})\\b|^unmute$`).test(v)) return "off";
    return undefined;
  };
  const waitForUi = () => new Promise((r) => setTimeout(r, 150));
  const pageText = text(doc.body).toLowerCase();
"#;

fn fill(src: &str, dom: &Value, params: &Value) -> String {
    src.replace("__SELECTORS__", &dom.to_string())
        .replace("__PARAMS__", &params.to_string())
}

/// Pre-join + status. `params`: `autoJoin`, `guestName`, `allowMicrophone`, `captureCaptions`,
/// `readOnly`, `prefix` (manual-action reason prefix), `sessionId`.
pub fn status(dom: &Value, params: &Value) -> String {
    let body = r#"
  const notes = [];
  const manual = (reason, message) => ({ reason: `${P.prefix}-${reason}`, message });
  const mutate = !P.readOnly;
  const leaveBtn = control("leave", "leaveText");
  const inCallMarker = firstRaw("inCall");
  let inCall = Boolean(leaveBtn || inCallMarker);
  if (mutate && P.autoJoin && !inCall) {
    const cont = control("continueInBrowser", "continueText");
    if (cont) { cont.click(); notes.push("Continued in the browser."); await waitForUi(); }
    for (const k of ["multiDevice", "confirmation"]) { const b = first(k); if (b && k === "multiDevice") { b.click(); await waitForUi(); } }
    const name = firstRaw("guestName");
    if (name && P.guestName && !name.value) {
      name.focus();
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
      setter ? setter.call(name, P.guestName) : (name.value = P.guestName);
      name.dispatchEvent(new Event("input", { bubbles: true }));
      name.dispatchEvent(new Event("change", { bubbles: true }));
      notes.push("Entered the guest name.");
    }
    const cam = control("camera", "cameraText");
    if (toggleState(cam, "camera") === "on") { cam.click(); notes.push("Turned the camera off."); await waitForUi(); }
  }
  const mic = control("microphone", "micText") || first("previewMicrophone");
  let micState = toggleState(mic, "mic");
  if (micState === undefined && (firstRaw("mutedIcon") || firstRaw("unmutedIcon"))) micState = firstRaw("mutedIcon") ? "off" : "on";
  if (mutate && mic) {
    if (P.allowMicrophone && micState === "off") { mic.click(); notes.push("Unmuted the microphone."); await waitForUi(); micState = "on"; }
    if (!P.allowMicrophone && micState === "on") { mic.click(); notes.push("Muted the microphone (observe-only mode)."); await waitForUi(); micState = "off"; }
  }
  if (mutate && P.autoJoin && !inCall) {
    const join = control("join", "joinText");
    if (join) { join.click(); notes.push("Clicked join."); await waitForUi(); }
  }
  inCall = Boolean(control("leave", "leaveText") || firstRaw("inCall"));
  const host = location.hostname.toLowerCase();
  const postCall = !inCall && Boolean(firstRaw("postCall") || (rx("postCallText") && rx("postCallText").test(pageText)));
  const lobbyWaiting = !inCall && Boolean(firstRaw("lobby") || (rx("lobbyText") && rx("lobbyText").test(pageText)));
  let manualAction;
  if (!inCall && (sel("signInHosts").includes(host) || firstRaw("signIn") || (rx("signInText") && rx("signInText").test(pageText)))) manualAction = manual("login-required", "Sign in to the meeting account in the bot's browser profile, then retry.");
  else if (!inCall && firstRaw("captcha")) manualAction = manual("captcha-required", "The meeting page shows a CAPTCHA; solve it in the bot's browser.");
  else if (!inCall && firstRaw("passcode")) manualAction = manual("passcode-required", "The meeting needs a passcode; pass a URL that includes it.");
  else if (!inCall && (firstRaw("permissionPrompt") || (rx("permissionText") && rx("permissionText").test(pageText)))) manualAction = manual("permission-required", "Allow microphone/camera for the meeting site in the bot's browser.");
  else if (lobbyWaiting) manualAction = manual("admission-required", "Waiting for the host to admit the bot.");
  let captioning = Boolean(firstRaw("captionRenderer"));
  if (mutate && inCall && P.captureCaptions && !captioning) {
    let cb = control("captions", "captionsText");
    if (!cb && first("moreActions")) { first("moreActions").click(); await waitForUi(); cb = control("captions", "captionsText"); }
    if (cb && !(rx("captionsOnText") && rx("captionsOnText").test(label(cb))) && cb.getAttribute?.("aria-checked") !== "true") { cb.click(); notes.push("Turned on live captions for the transcript."); await waitForUi(); }
    captioning = Boolean(firstRaw("captionRenderer")) || Boolean(firstRaw("captionsOff"));
  }
  if (inCall && P.captureCaptions && !globalThis.__arkMeeting?.observer) {
    const st = (globalThis.__arkMeeting = globalThis.__arkMeeting || { lines: [], sessionId: P.sessionId });
    const collect = () => {
      const rows = sel("captionRows").flatMap((s) => { try { return [...doc.querySelectorAll(s)]; } catch { return []; } });
      const nodes = rows.length ? rows : sel("captionRenderer").flatMap((s) => { try { return [...doc.querySelectorAll(s)]; } catch { return []; } });
      for (const row of nodes) {
        const a = sel("captionAuthor").map((s) => row.querySelector?.(s)).find(Boolean);
        const t = sel("captionText").map((s) => row.querySelector?.(s)).find(Boolean);
        const speaker = text(a) || "";
        let said = text(t || row);
        if (speaker && said.startsWith(speaker)) said = said.slice(speaker.length).trim();
        if (!said || /^(turn on captions|turn off captions|captions)$/i.test(said)) continue;
        const last = st.lines[st.lines.length - 1];
        if (last && last.speaker === speaker && (said.startsWith(last.text) || last.text.startsWith(said))) { if (said.length > last.text.length) { last.text = said; last.at = Date.now(); } continue; }
        if (st.lines.some((l) => l.speaker === speaker && l.text === said)) continue;
        st.lines.push({ speaker, text: said, at: Date.now() });
      }
    };
    st.observer = new MutationObserver(collect);
    st.observer.observe(doc.body, { childList: true, subtree: true, characterData: true });
    collect();
  }
  return { inCall, lobbyWaiting, meetingEnded: postCall, micMuted: micState === undefined ? undefined : micState === "off", captioning, manualAction, notes, url: location.href, title: document.title };
"#;
    format!("async () => {{{}{}}}", fill(HELPERS, dom, params), body)
}

/// Captions archived since join (`finalize` also stops the observer).
pub fn transcript(finalize: bool) -> String {
    format!(
        r#"async () => {{
  const st = globalThis.__arkMeeting;
  if (!st) return {{ lines: [], captioning: false }};
  const lines = st.lines.slice();
  if ({finalize}) {{ st.observer?.disconnect?.(); st.observer = undefined; }}
  return {{ lines, captioning: Boolean(st.observer) }};
}}"#
    )
}

/// Leave: click leave, confirm, report whether the page shows we left.
pub fn leave(dom: &Value) -> String {
    let body = r#"
  const lb = control("leave", "leaveText");
  if (lb) { lb.click(); await waitForUi(); await waitForUi(); }
  const confirm = control("leaveConfirmation", "leaveConfirmText");
  if (confirm) { confirm.click(); await waitForUi(); }
  globalThis.__arkMeeting?.observer?.disconnect?.();
  const stillIn = Boolean(control("leave", "leaveText") || firstRaw("inCall"));
  return { departed: !stillIn, leaveAction: confirm ? "confirm" : (lb ? "leave" : undefined) };
"#;
    format!("async () => {{{}{}}}", fill(HELPERS, dom, &json!({})), body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_embed_selectors_and_params() {
        let dom = crate::meeting::platforms::Platform::Zoom.dom();
        let s = status(
            &dom,
            &json!({"autoJoin": true, "guestName": "seagent bot", "allowMicrophone": false, "captureCaptions": true, "prefix": "zoom"}),
        );
        assert!(s.starts_with("async () => {") && s.trim_end().ends_with('}'));
        assert!(
            s.contains("button.preview-join-button") && s.contains("\"guestName\":\"seagent bot\"")
        );
        assert!(!s.contains("__SELECTORS__") && !s.contains("__PARAMS__"));
        assert!(leave(&dom).contains("leave-meeting-options__btn"));
        assert!(transcript(true).contains("disconnect"));
        // Balanced braces (cheap syntax sanity; node runs them in the e2e test when present).
        for src in [s, leave(&dom), transcript(false)] {
            assert_eq!(src.matches('{').count(), src.matches('}').count());
        }
    }
}
