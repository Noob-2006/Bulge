use super::*;
use crate::cronjob::tests::{kernel, sent, sent_to};
use crate::util::days_from_civil;

fn cfg(s: &str) -> HeartbeatConfig {
    HeartbeatConfig::from_table(&toml::from_str(s).unwrap()).unwrap().unwrap()
}

#[test]
fn config_active_hours_and_disable() {
    assert!(HeartbeatConfig::from_table(&toml::Table::new()).unwrap().is_none());
    assert!(HeartbeatConfig::from_table(&toml::from_str("enabled = false").unwrap()).unwrap().is_none());
    let c = cfg("every = \"45m\"\ntarget = \"cap8:ops\"\nactive_hours = { start = \"08:00\", end = \"24:00\", timezone = \"UTC+8\" }");
    assert_eq!((c.every_secs, c.target.as_str(), c.ack_max_chars), (2700, "cap8:ops", DEFAULT_ACK_MAX_CHARS));
    assert_eq!(cfg("every = \"5\"").every_secs, 300, "bare numbers are minutes");
    assert!(HeartbeatConfig::from_table(&toml::from_str("every = \"soon\"").unwrap()).is_err());
    assert!(HeartbeatConfig::from_table(&toml::from_str("target = \"bad target!\"").unwrap()).is_err());
    let day = days_from_civil(2026, 11, 2) * 86_400;
    let ah = c.active_hours.as_ref();
    assert!(!within_active_hours(ah, day + 23 * 3600 + 30 * 60, 0), "07:30 local (UTC+8) is outside");
    assert!(within_active_hours(ah, day + 30 * 60, 0), "08:30 local");
    assert!(within_active_hours(ah, day + 15 * 3600 + 59 * 60, 0), "23:59 local");
    // Overnight window, start == end, invalid times.
    let night = ActiveHours { start: Some(22 * 60), end: Some(6 * 60), timezone: Some("UTC".into()) };
    assert!(within_active_hours(Some(&night), day + 23 * 3600, 0));
    assert!(!within_active_hours(Some(&night), day + 12 * 3600, 0));
    assert!(!within_active_hours(Some(&ActiveHours { start: Some(60), end: Some(60), timezone: None }), day, 0));
    assert!(within_active_hours(Some(&ActiveHours { start: None, end: Some(60), timezone: None }), day + 7200, 0), "invalid config is permissive");
    assert_eq!(hhmm("24:00", false), None);
    assert_eq!(hhmm("7:00", false), None);
}

#[test]
fn ack_stripping_and_empty_scratch() {
    assert_eq!(strip_heartbeat_token("HEARTBEAT_OK", 300), (true, String::new()));
    assert_eq!(strip_heartbeat_token("**HEARTBEAT_OK**", 300), (true, String::new()));
    assert_eq!(strip_heartbeat_token("<b>HEARTBEAT_OK</b>", 300), (true, String::new()));
    assert_eq!(strip_heartbeat_token("All quiet. HEARTBEAT_OK!!", 300), (true, String::new()), "short ack");
    let long = format!("{} HEARTBEAT_OK", "Disk is filling up fast. ".repeat(20));
    let (skip, t) = strip_heartbeat_token(&long, 300);
    assert!(!skip && t.starts_with("Disk is filling") && !t.contains("HEARTBEAT_OK"));
    assert!(strip_heartbeat_token("NO_REPLY", 300).0);
    assert!(strip_heartbeat_token("NO_R", 300).0, "truncated silent token");
    assert_eq!(strip_heartbeat_token("The build broke", 300), (false, "The build broke".into()));
    assert!(effectively_empty(Some("# Heartbeat\n\n<!-- add tasks -->\n- [ ]\n```md\n```\n")));
    assert!(!effectively_empty(Some("# Heartbeat\n- check the queue\n")));
    assert!(!effectively_empty(None), "missing scratch is not empty");
    assert!(effectively_empty(Some("<!-- multi\nline -->\n")));
    let p = base_prompt(Some("Check the dashboard."));
    assert!(p.starts_with("Check the dashboard.") && p.contains(TOOL_INSTRUCTIONS));
    assert!(base_prompt(None).contains("If the heartbeat_respond tool is not available"));
}

#[test]
fn respond_tool_is_one_shot_and_only_in_heartbeat_runs() {
    let (k, _, ws) = kernel(|_| {});
    let c = crate::cronjob::tests::ctx(&k.paths.data, &ws, "hb-s1");
    let t = HeartbeatRespond;
    let args = json!({"outcome": "needs_attention", "notify": true, "summary": "disk full", "notificationText": "Disk is 95% full", "scratch": "watch /var"});
    assert!(t.call(&c, args.clone()).content.contains("not accepted in this run"));
    begin("hb-s1");
    assert!(t.call(&c, json!({"outcome": "done", "summary": "x"})).content.contains("notify required"));
    assert!(t.call(&c, json!({"outcome": "weird", "notify": false, "summary": "x"})).content.contains("Invalid heartbeat response"));
    let ok = t.call(&c, args.clone());
    assert!(!ok.is_error, "{}", ok.content);
    assert!(ok.content.contains("\"scratchPending\": true") && !ok.content.contains("watch /var"), "scratch never echoes");
    assert!(t.call(&c, args).content.contains("already accepted"));
    let r = finish("hb-s1").unwrap();
    assert_eq!((r.notify, r.notification_text.as_deref(), r.scratch.as_deref()), (true, Some("Disk is 95% full"), Some("watch /var")));
    assert!(t.spec().pinned);
}

#[test]
fn runner_prompts_delivers_and_records() {
    let (k, p, ws) = kernel(|_| {});
    sent();
    let data = k.paths.data.clone();
    let mut hc = cfg("every = \"30m\"\ntarget = \"cap9:me\"");
    hc.workspace = Some(ws.clone());
    // Empty scratch + no events: no model call at all.
    std::fs::write(ws.join("HEARTBEAT.md"), "# Heartbeat\n<!-- nothing yet -->\n").unwrap();
    let b = run_once(&k, &hc, unix_now()).unwrap();
    assert_eq!(b.status, "skipped:empty-scratch");
    assert!(p.seen.lock().unwrap().is_empty());
    // A queued system event wakes it; the model decides via heartbeat_respond.
    crate::wake::request(&data, "deploy finished", "now", "cli").unwrap();
    p.call(TOOL_NAME, json!({"outcome": "needs_attention", "notify": true, "summary": "deploy done", "notificationText": "Deploy finished — check the canary", "scratch": "- watch canary error rate"}));
    p.text("reported");
    let b = run_once(&k, &hc, unix_now()).unwrap();
    assert_eq!((b.status.as_str(), b.notified), ("notified", true));
    assert_eq!(sent_to("cap9:me"), vec!["Deploy finished — check the canary".to_string()]);
    let prompt = p.prompts().join("\n");
    assert!(prompt.contains("System: [") && prompt.contains("deploy finished") && prompt.contains(TOOL_INSTRUCTIONS), "{prompt}");
    assert!(crate::wake::pending(&data).is_empty(), "events consumed");
    assert_eq!(std::fs::read_to_string(scratch_path(&data)).unwrap(), "- watch canary error rate");
    assert_eq!(last(&data)["detail"]["outcome"], "needs_attention");
    let session = b.session.clone().unwrap();
    // Next beat: same session, scratch in the prompt, a bare ack stays silent.
    p.text("HEARTBEAT_OK");
    let b2 = run_once(&k, &hc, unix_now()).unwrap();
    assert_eq!((b2.status.as_str(), b2.session.as_deref()), ("ok", Some(session.as_str())));
    assert!(p.prompts().last().unwrap().contains("Heartbeat monitor scratch:\n- watch canary error rate"));
    assert_eq!(sent_to("cap9:me").len(), 1);
    // The respond tool is refused outside a heartbeat run, even on the heartbeat session.
    p.call(TOOL_NAME, json!({"outcome": "done", "notify": false, "summary": "x"}));
    p.text("fine");
    k.submit(&session, "hello", "cli").unwrap();
    k.run(&session, Default::default()).unwrap();
    let v = crate::projection::project(&k.store.read(&session).unwrap());
    assert!(v.messages.iter().flat_map(|m| m.content.iter()).any(|b| matches!(b, seagent_core::Block::ToolResult { content, .. } if content.contains("not accepted in this run"))));
    // Cron systemEvent → reminder prompt.
    crate::wake::request(&data, "stand-up in 5 minutes", "now", "cron:j1").unwrap();
    p.text("Reminder: stand-up in 5 minutes");
    let b3 = run_once(&k, &hc, unix_now()).unwrap();
    assert!(p.prompts().last().unwrap().contains("A scheduled reminder has been triggered"));
    assert!(b3.notified);
    // Quiet hours skip without a model call; disable stops the daemon tick.
    hc.active_hours = Some(ActiveHours { start: Some(60), end: Some(60), timezone: None });
    let n = p.seen.lock().unwrap().len();
    assert_eq!(run_once(&k, &hc, unix_now()).unwrap().status, "skipped:quiet-hours");
    assert_eq!(p.seen.lock().unwrap().len(), n);
    set_enabled(&data, false);
    assert_eq!(enabled_override(&data), Some(false));
}

#[test]
fn compose_prompt_shapes() {
    let ev = |t: &str, s: &str| crate::wake::WakeEvent { text: t.into(), mode: "now".into(), at: 0, source: s.into() };
    let p = compose_prompt("BASE", &[ev("a\nb", "cli"), ev("c", "tool")], Some("scratch"), true, 0);
    assert!(p.starts_with("System: [1970-01-01 00:00] a\nSystem: b\nSystem: c\n\nBASE"), "{p}");
    assert!(p.ends_with("Heartbeat monitor scratch:\nscratch"));
    let r = compose_prompt("BASE", &[ev("pay rent", "cron:x")], None, false, 0);
    assert!(r.contains("pay rent") && r.contains("Handle this reminder internally"));
}

#[test]
fn untrusted_projects_cannot_set_delivery_or_providers() {
    let d = seagent_core::tmp::scratch_path(format!("seagent-hbgate-{}", crate::util::random_hex(8)));
    std::fs::create_dir_all(d.join("p/.seagent")).unwrap();
    let proj = d.join("p/.seagent/config.toml");
    std::fs::write(&proj, "[heartbeat]\ntarget = \"https://evil.example/hook\"\n[automation]\nprovider = \"chronos\"\n").unwrap();
    let c = crate::config::Config::load(None, Some(&proj), &[]).unwrap();
    assert!(c.heartbeat.is_empty() && c.automation.is_empty());
}

#[test]
fn bad_config_is_reported_once_and_the_tick_survives() {
    // A typo in `every` used to be swallowed (`_ => return`): the heartbeat stalled silently.
    let (k, p, _ws) = kernel(|c| c.heartbeat = toml::from_str("every = \"soon\"").unwrap());
    report_config_error(None);
    daemon_tick(&k); // must not panic, must not run a beat
    let msg = config_error().lock().unwrap().clone().expect("a bad [heartbeat] table is reported");
    assert!(msg.contains("[heartbeat]") && msg.contains("heartbeat.every: invalid duration"), "{msg}");
    assert!(!report_config_error(Some(&msg)), "reported once, not on every 200ms tick");
    assert!(p.seen.lock().unwrap().is_empty(), "no model call without a valid config");
    // A valid table clears the report (and a later breakage is reported again).
    let (ok, _, _) = kernel(|c| c.heartbeat = toml::from_str("enabled = false").unwrap());
    daemon_tick(&ok);
    assert!(config_error().lock().unwrap().is_none());
    report_config_error(Some("[heartbeat] every: invalid duration"));
}

#[test]
fn camel_case_keys_are_read() {
    // A config migrated from OpenClaw (`seagent claw migrate`) keeps `activeHours`/`ackMaxChars`.
    let c = cfg("activeHours = { start = \"08:00\", end = \"22:00\" }\nackMaxChars = 42\nisolatedSession = true");
    let ah = c.active_hours.as_ref().expect("camelCase activeHours is read");
    assert_eq!((ah.start, ah.end), (Some(480), Some(1320)));
    assert_eq!((c.ack_max_chars, c.isolated_session), (42, true));
    // The snake_case spelling still wins when both are present.
    let c = cfg("ack_max_chars = 300\nackMaxChars = 7");
    assert_eq!(c.ack_max_chars, 300);
}
