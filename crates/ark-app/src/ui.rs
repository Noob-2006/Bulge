//! The web UI, embedded in the binary (no files to install). The same page is the
//! desktop app (installable PWA / `ark app open` in an app window) and the phone app.

use ark_net::httpd::Response;

const INDEX: &str = include_str!("../../../ui/web/index.html");
const APP_JS: &str = include_str!("../../../ui/web/app.js");
const SURFACES_JS: &str = include_str!("../../../ui/web/surfaces.js");
const APP_CSS: &str = include_str!("../../../ui/web/app.css");
const PAGES_JS: &str = include_str!("../../../ui/web/pages.js");
const PAGES_CSS: &str = include_str!("../../../ui/web/pages.css");
const THEME: &str = include_str!("../../../ui/theme.css");
const STAR: &str = include_str!("../../../ui/star.svg");
const ICON: &str = include_str!("../../../ui/icon.svg");
const MANIFEST: &str = include_str!("../../../ui/web/manifest.webmanifest");
const SW: &str = include_str!("../../../ui/web/sw.js");

/// Strict CSP: only our own scripts/styles, WebSocket back to the same origin.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-src 'self' https:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// The page itself also allows scripts carrying a per-response nonce: MCP App views
/// render in `srcdoc` iframes, which inherit this policy, so their inline scripts are
/// re-tagged with the nonce (the iframe is sandboxed to an opaque origin; the view's
/// own, stricter CSP from `_meta.ui.csp` applies on top).
fn index_csp(nonce: &str) -> String {
    CSP.replacen("script-src 'self'", &format!("script-src 'self' 'nonce-{nonce}'"), 1)
}

pub fn serve(path: &str) -> Response {
    if matches!(path, "/" | "/ui/" | "/ui/index.html") {
        let nonce = ark_net::crypto::random_token(18);
        let page = INDEX.replace("<script src=", &format!("<script nonce=\"{nonce}\" src="));
        return Response::new(200, "text/html; charset=utf-8", page.into_bytes())
            .with_header("content-security-policy", &index_csp(&nonce))
            .with_header("x-content-type-options", "nosniff")
            .with_header("referrer-policy", "no-referrer")
            .with_header("cache-control", "no-cache");
    }
    let (ctype, body) = match path {
        "/ui/app.js" => ("text/javascript; charset=utf-8", APP_JS),
        "/ui/surfaces.js" => ("text/javascript; charset=utf-8", SURFACES_JS),
        "/ui/app.css" => ("text/css; charset=utf-8", APP_CSS),
        "/ui/pages.js" => ("text/javascript; charset=utf-8", PAGES_JS),
        "/ui/pages.css" => ("text/css; charset=utf-8", PAGES_CSS),
        "/ui/theme.css" => ("text/css; charset=utf-8", THEME),
        "/ui/star.svg" => ("image/svg+xml", STAR),
        "/ui/icon.svg" => ("image/svg+xml", ICON),
        "/manifest.webmanifest" => ("application/manifest+json", MANIFEST),
        "/sw.js" => ("text/javascript; charset=utf-8", SW),
        _ => return Response::text(404, "not found"),
    };
    Response::new(200, ctype, body.as_bytes().to_vec())
        .with_header("content-security-policy", CSP)
        .with_header("x-content-type-options", "nosniff")
        .with_header("referrer-policy", "no-referrer")
        .with_header("cache-control", "no-cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_pages_are_served_and_linked() {
        let body = |r: Response| match r.body {
            ark_net::httpd::Body::Bytes(b) => String::from_utf8(b).unwrap(),
            _ => panic!("bytes"),
        };
        let js = serve("/ui/pages.js");
        assert_eq!(js.status, 200);
        let js = body(js);
        for page in ["channels", "skill-workshop", "cron", "usage", "config", "secrets", "terminal", "workboard", "memory-import", "meetings", "worktrees", "cloud-workers", "custodian", "labs", "profile"] {
            assert!(js.contains(page), "page {page} missing");
        }
        assert_eq!(serve("/ui/pages.css").status, 200);
        let index = body(serve("/"));
        assert!(index.contains("src=\"/ui/pages.js\"") && index.contains("/ui/pages.css") && index.contains("id=\"showControl\""));
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
            ark_net::httpd::Body::Bytes(b) => String::from_utf8(b.clone()).unwrap(),
            _ => panic!("bytes"),
        };
        assert!(body.contains(&format!("<script nonce=\"{n}\" src=\"/ui/app.js\"")));
        assert!(!csp(&serve("/ui/app.js")).contains("nonce"));
    }
}
