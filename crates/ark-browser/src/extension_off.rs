//! Stand-in for the browser-extension relay in a default build (gen1-306): the relay drives
//! the user's own signed-in Chrome, a personal-desktop feature compiled only with
//! `--features personal`. Every entry point says so instead of failing obscurely.

use crate::config::BrowserConfig;
use serde_json::{json, Value};
use std::path::Path;

pub const DEFAULT_PORT: u16 = 18792;
pub const UNAVAILABLE: &str = "the browser-extension relay is not part of this build (a personal-desktop feature): rebuild ark with `--features personal`, or use browser.backend = \"local\" / \"cdp\"";

pub fn token(_dir: &Path) -> Result<String, String> {
    Err(UNAVAILABLE.into())
}

pub fn relay(_cfg: &BrowserConfig, _dir: &Path) -> Result<(String, String), String> {
    Err(UNAVAILABLE.into())
}

pub fn status() -> Value {
    json!({"available": false, "listening": null, "extension_connected": false, "reason": UNAVAILABLE})
}

pub fn listen(_cfg: &BrowserConfig, _dir: &Path) -> Result<u16, String> {
    Err(UNAVAILABLE.into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn default_build_has_no_extension_relay() {
        assert!(super::relay(&Default::default(), std::path::Path::new("/nonexistent")).unwrap_err().contains("--features personal"));
        assert_eq!(super::status()["available"], false);
    }
}
