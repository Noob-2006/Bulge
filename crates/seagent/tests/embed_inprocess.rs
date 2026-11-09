//! The in-process agent (`seagent::embed`, what the iOS app links) run for real on Linux: the
//! full daemon assembly inside this test process, no control socket, the App Server on a
//! loopback port, setup link then token console, a background pass, stop and restart.
//! Its own test binary because it sets process-wide state (`SEAGENT_HOME`).

use seagent::embed::{self, background_pass, console, running, start, stop, Options, Pass};
use seagent_kernel::config::Paths;
use std::time::Duration;

/// The real thing on Linux: the full daemon assembly in this test process, no socket, the
/// App Server on a loopback port, the setup link first, the token console after setup, a
/// background pass, and a clean stop that a second start can follow.
#[test]
fn the_whole_agent_runs_in_process_and_stops() {
    let home = seagent_core::tmp::TempDir::new("seagent-embed");
    std::env::set_var("SEAGENT_OFFLINE", "1");
    let opts = Options { home: home.path().to_path_buf(), vault_key: Some("11".repeat(32)), set: vec!["app.listen=\"127.0.0.1:0\"".into(), "schedule.tick_secs=1".into()], ..Default::default() };
    let c = start(opts.clone()).expect("embedded agent starts");
    assert!(running());
    assert!(c.base.starts_with("http://127.0.0.1:") && !c.base.ends_with(":0"), "{c:?}");
    assert!(c.setup && c.url.starts_with(&format!("{}/setup#token=", c.base)), "{c:?}");
    let paths = Paths::from_env();
    assert!(paths.config_dir.starts_with(home.path()) && paths.data.starts_with(home.path()), "everything under SEAGENT_HOME: {paths:?}");
    assert!(!paths.socket().exists(), "no control socket in-process");
    // The App Server answers HTTP (the console the WebView loads).
    let addr: std::net::SocketAddr = c.base.trim_start_matches("http://").parse().unwrap();
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    std::io::Write::write_all(&mut s, b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = std::io::Read::read_to_string(&mut s, &mut resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    // Once setup is done the console URL carries the app token instead.
    embed::mark_setup_done_for_tests();
    let c2 = console().unwrap();
    assert!(!c2.setup && c2.url.starts_with(&format!("{}/#token=", c.base)) && c2.url.len() > c.base.len() + 10, "{c2:?}");
    // A background pass with nothing scheduled returns after one tick with nothing due.
    let t = std::time::Instant::now();
    let p = background_pass(Duration::from_secs(5));
    assert_eq!(p, Pass { unfinished: false, next_due: None });
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    // Idempotent start while running.
    assert_eq!(start(opts.clone()).unwrap().base, c.base);
    assert!(stop(Duration::from_secs(20)), "stops within the drain window");
    assert!(!running());
    // And it can come back in the same process (the app returning to the foreground).
    let c3 = start(opts).expect("restart in-process");
    assert!(!c3.setup);
    assert!(stop(Duration::from_secs(20)));
}
