//! The web UI, embedded in the binary (no files to install). The same page is the
//! desktop app (installable PWA / `seagent app open` in an app window) and the phone app.

use seagent_net::httpd::Response;

const INDEX: &str = include_str!("../../../ui/web/index.html");

/// Every other file of the UI: (URL path, content type, source path under `ui/`, contents).
const FILES: &[(&str, &str, &str, &str)] = &[
    ("/ui/app.js", JS, "web/app.js", include_str!("../../../ui/web/app.js")),
    ("/ui/ops.js", JS, "web/ops.js", include_str!("../../../ui/web/ops.js")),
    ("/ui/work.js", JS, "web/work.js", include_str!("../../../ui/web/work.js")),
    ("/ui/live_view.js", JS, "web/live_view.js", include_str!("../../../ui/web/live_view.js")),
    ("/ui/live_view.css", CSS, "web/live_view.css", include_str!("../../../ui/web/live_view.css")),
    ("/ui/surfaces.js", JS, "web/surfaces.js", include_str!("../../../ui/web/surfaces.js")),
    ("/ui/pages.js", JS, "web/pages.js", include_str!("../../../ui/web/pages.js")),
    ("/ui/app.css", CSS, "web/app.css", include_str!("../../../ui/web/app.css")),
    ("/ui/pages.css", CSS, "web/pages.css", include_str!("../../../ui/web/pages.css")),
    ("/ui/theme.css", CSS, "theme.css", include_str!("../../../ui/theme.css")),
    ("/ui/star.svg", SVG, "star.svg", include_str!("../../../ui/star.svg")),
    ("/ui/icon.svg", SVG, "icon.svg", include_str!("../../../ui/icon.svg")),
    ("/manifest.webmanifest", "application/manifest+json", "web/manifest.webmanifest", include_str!("../../../ui/web/manifest.webmanifest")),
    ("/sw.js", JS, "web/sw.js", include_str!("../../../ui/web/sw.js")),
    // First-run setup wizard (`GET /setup`); its RPC (`POST /setup/rpc`) is a host route.
    ("/setup", "text/html; charset=utf-8", "web/setup.html", include_str!("../../../ui/web/setup.html")),
    ("/ui/setup.js", JS, "web/setup.js", include_str!("../../../ui/web/setup.js")),
];
/// Binary files (PWA icons: Android needs 192/512 PNGs and a maskable one, iOS an opaque
/// 180×180 apple-touch-icon; generated from `ui/icon.svg` like the desktop app's icons).
const BINARY: &[(&str, &str, &[u8])] = &[
    ("/ui/icons/icon-192.png", PNG, include_bytes!("../../../ui/web/icons/icon-192.png")),
    ("/ui/icons/icon-512.png", PNG, include_bytes!("../../../ui/web/icons/icon-512.png")),
    ("/ui/icons/icon-maskable-512.png", PNG, include_bytes!("../../../ui/web/icons/icon-maskable-512.png")),
    ("/ui/icons/apple-touch-icon.png", PNG, include_bytes!("../../../ui/web/icons/apple-touch-icon.png")),
    // iOS asks for this path on its own when no link tag is honoured.
    ("/apple-touch-icon.png", PNG, include_bytes!("../../../ui/web/icons/apple-touch-icon.png")),
];
const PNG: &str = "image/png";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const SVG: &str = "image/svg+xml";

/// `SEAGENT_UI_DIR=<checkout>/ui`: serve the UI files from disk instead of the embedded copy, so
/// a UI change shows on reload without rebuilding (development and custom branding).
fn from_disk(rel: &str) -> Option<String> {
    let dir = std::env::var_os("SEAGENT_UI_DIR").filter(|d| !d.is_empty())?;
    std::fs::read_to_string(std::path::Path::new(&dir).join(rel)).ok()
}

/// Strict CSP: only our own scripts/styles, WebSocket back to the same origin.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; frame-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// The page itself also allows scripts carrying a per-response nonce: MCP App views
/// render in `srcdoc` iframes, which inherit this policy, so their inline scripts are
/// re-tagged with the nonce (the iframe is sandboxed to an opaque origin; the view's
/// own, stricter CSP from `_meta.ui.csp` applies on top).
fn index_csp(nonce: &str) -> String {
    CSP.replacen("script-src 'self'", &format!("script-src 'self' 'nonce-{nonce}'"), 1)
}

pub fn serve(path: &str) -> Response {
    if matches!(path, "/" | "/ui/" | "/ui/index.html") {
        let nonce = seagent_net::crypto::random_token(18);
        let index = from_disk("web/index.html");
        let page = index.as_deref().unwrap_or(INDEX).replace("<script src=", &format!("<script nonce=\"{nonce}\" src="));
        return Response::new(200, "text/html; charset=utf-8", page.into_bytes())
            .with_header("content-security-policy", &index_csp(&nonce))
            .with_header("x-content-type-options", "nosniff")
            .with_header("referrer-policy", "no-referrer")
            .with_header("cache-control", "no-cache");
    }
    if let Some((_, ctype, bytes)) = BINARY.iter().find(|f| f.0 == path) {
        return Response::new(200, ctype, bytes.to_vec()).with_header("x-content-type-options", "nosniff").with_header("cache-control", "public, max-age=86400");
    }
    let Some((_, ctype, rel, embedded)) = FILES.iter().find(|f| f.0 == path) else {
        return Response::text(404, "not found");
    };
    let body = from_disk(rel).unwrap_or_else(|| embedded.to_string());
    Response::new(200, ctype, body.into_bytes())
        .with_header("content-security-policy", CSP)
        .with_header("x-content-type-options", "nosniff")
        .with_header("referrer-policy", "no-referrer")
        .with_header("cache-control", "no-cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_wizard_page_is_served_with_the_strict_policy() {
        let r = serve("/setup");
        assert_eq!(r.status, 200);
        let csp = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-security-policy")).map(|(_, v)| v.clone()).unwrap_or_default();
        assert!(csp.contains("script-src 'self';") && csp.contains("frame-ancestors 'none'"), "{csp}");
        let html = match r.body {
            seagent_net::httpd::Body::Bytes(b) => String::from_utf8(b).unwrap(),
            _ => panic!("bytes"),
        };
        assert!(html.contains("/ui/setup.js") && html.contains("/ui/theme.css") && !html.contains("<script>"), "no inline script");
        let js = serve("/ui/setup.js");
        assert_eq!(js.status, 200);
        let js = match js.body {
            seagent_net::httpd::Body::Bytes(b) => String::from_utf8(b).unwrap(),
            _ => panic!("bytes"),
        };
        for m in ["setup.status", "setup.test_provider", "setup.apply", "x-seagent-setup-token", "/setup/rpc"] {
            assert!(js.contains(m), "setup.js lacks {m}");
        }
    }

    #[test]
    fn operations_views_are_served() {
        let body = |r: Response| match r.body {
            seagent_net::httpd::Body::Bytes(b) => String::from_utf8(b).unwrap(),
            _ => panic!("bytes"),
        };
        let index = body(serve("/"));
        for id in ["view-ops", "view-agents", "view-devices", "view-approvals", "view-audit", "view-security", "data-view=\"security\"", "src=\"/ui/ops.js\"", "id=\"palette\""] {
            assert!(index.contains(id), "{id} missing from index.html");
        }
        let ops = body(serve("/ui/ops.js"));
        assert!(ops.contains("ui.ops.status") && ops.contains("audit.verify") && ops.contains("ui.fleet"));
        // The approvals page lists/revokes standing grants and edits exec policy; the
        // security page renders the same posture the CLI audit reports.
        assert!(ops.contains("ui.approvals.grants.list") && ops.contains("ui.approvals.grant.revoke") && ops.contains("ui.exec.policy.set"));
        assert!(ops.contains("VIEWS.security") && ops.contains("ui.security.status"));
        assert!(body(serve("/ui/app.js")).contains("gate.answer"));
        // The service worker's offline shell lists every UI file.
        let sw = body(serve("/sw.js"));
        for f in FILES.iter().map(|f| f.0).filter(|p| p.starts_with("/ui/") && !p.ends_with(".svg") && *p != "/ui/setup.js") {
            assert!(sw.contains(f), "sw.js shell misses {f}");
        }
    }

    #[test]
    fn control_pages_are_served_and_linked() {
        let body = |r: Response| match r.body {
            seagent_net::httpd::Body::Bytes(b) => String::from_utf8(b).unwrap(),
            _ => panic!("bytes"),
        };
        let js = serve("/ui/pages.js");
        assert_eq!(js.status, 200);
        let js = body(js);
        for page in ["channels", "skill-workshop", "cron", "usage", "config", "secrets", "terminal", "workboard", "memory-import", "meetings", "worktrees", "cloud-workers", "custodian", "labs", "profile", "cluster.status", "cluster.policy.publish"] {
            assert!(js.contains(page), "page {page} missing");
        }
        assert_eq!(serve("/ui/pages.css").status, 200);
        let index = body(serve("/"));
        assert!(index.contains("src=\"/ui/pages.js\"") && index.contains("/ui/pages.css") && index.contains("id=\"showControl\""));
    }

    #[test]
    fn pwa_icons_are_served_and_listed_in_the_manifest() {
        for (p, _, _) in BINARY {
            let r = serve(p);
            assert_eq!(r.status, 200, "{p}");
            let b = match r.body {
                seagent_net::httpd::Body::Bytes(b) => b,
                _ => panic!("bytes"),
            };
            assert_eq!(&b[..8], b"\x89PNG\r\n\x1a\n", "{p}");
        }
        let m: serde_json::Value = serde_json::from_str(FILES.iter().find(|f| f.0 == "/manifest.webmanifest").unwrap().3).unwrap();
        let icons = m["icons"].as_array().unwrap();
        for (src, sizes) in [("/ui/icons/icon-192.png", "192x192"), ("/ui/icons/icon-512.png", "512x512"), ("/ui/icons/icon-maskable-512.png", "512x512")] {
            assert!(icons.iter().any(|i| i["src"] == src && i["sizes"] == sizes), "{src}");
        }
        assert!(icons.iter().any(|i| i["purpose"] == "maskable"));
        assert!(INDEX.contains("apple-touch-icon"));
    }

    #[test]
    fn index_carries_a_fresh_script_nonce() {
        let a = serve("/");
        let b = serve("/");
        let csp = |r: &Response| r.headers.iter().find(|(k, _)| k == "content-security-policy").map(|(_, v)| v.clone()).unwrap();
        let (ca, cb) = (csp(&a), csp(&b));
        assert!(ca.contains("'nonce-") && ca != cb, "{ca}");
        let n = ca.split("'nonce-").nth(1).unwrap().split('\'').next().unwrap();
        let body = match &a.body {
            seagent_net::httpd::Body::Bytes(b) => String::from_utf8(b.clone()).unwrap(),
            _ => panic!("bytes"),
        };
        assert!(body.contains(&format!("<script nonce=\"{n}\" src=\"/ui/app.js\"")));
        assert!(!csp(&serve("/ui/app.js")).contains("nonce"));
    }
}
