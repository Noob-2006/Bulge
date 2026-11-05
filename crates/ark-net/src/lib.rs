//! ark-net: blocking network plumbing shared by channels, MCP OAuth and the
//! app server — TLS/TCP streams, WebSocket, a small HTTP server, crypto
//! helpers. Built only from crates ureq already brings in.

pub mod crypto;
pub mod http;
pub mod httpd;
pub mod stream;
pub mod ws;

pub use stream::{form_encode, parse_query, urldecode, urlencode, Stream, Url};
