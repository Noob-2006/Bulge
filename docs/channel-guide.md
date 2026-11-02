# Writing an ark channel

Every chat platform is one module `crates/ark-channel/src/<module>.rs` exposing

```rust
pub fn build(ctx: &crate::config::Ctx, s: &serde_json::Map<String, serde_json::Value>) -> Result<Arc<dyn Channel>, String>
```

already registered in `config::registry()`. `crates/ark-channel/src/telegram.rs` is the
reference implementation: copy its structure (settings struct, builder, error mapping,
inbound parsing, `Channel` impl, tests with `FakeServer`).

## Rules

- Rust std threads only, no async, no new crates. Available: `serde`, `serde_json`, `ureq`,
  `libc`, `ring` (HMAC, SHA, Ed25519, ECDSA P-256, RSA verify/sign, AES-GCM, ChaCha20-Poly1305,
  X25519, HKDF, PBKDF2), `base64`, `ark_net` (see below), `ark_core::Cancel`.
- Every blocking wait observes `Cancel` (poll must return within ~100 ms of cancel) and
  every socket has a timeout. `poll` blocks at most `poll_timeout_secs` (default 25) and
  returns `Ok(vec![])` on timeout.
- Never put tokens in error messages (use `crate::http::redact` if a URL carries one).
- Settings: a `#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Settings` parsed with
  `ctx.settings(s)?`; resolve secrets with `ctx.secret("field", &raw)?` / `ctx.opt_secret`.
  Per-channel state files: `ctx.state("suffix.json")`, written with `crate::write_atomic`.
  Shared fields (`allow`, `dm_policy`, `group_policy`, `groups`, `require_mention`,
  `session_per`, `default_chat`, `privacy_notice`, `ai_label`) are handled by the host — do not
  parse them.
- Inbound (`Inbound`): set `chat`, `chat_type`, `chat_name`, `thread`, `sender`,
  `sender_name`, `is_bot`, `text`, `message_id` (unique per delivery; suffix edits),
  `ts`, `media` (with `id`/`url` so `fetch_media` can download), `reply` (with `is_own`
  when replying to the bot), `mentioned` (explicit @mention of the bot), `callback`
  (button presses), `edited`. Drop the bot's own messages. Dedup is the router's job,
  but a platform that redelivers must give the same `message_id`.
- Outbound: `send` returns `Sent { ids }`. Honour `reply_to`, `thread`, `media`
  (local `path` → upload, `url` → by reference), `buttons` (map to the platform's
  buttons/cards/keyboards; fall back to numbered text options when the platform has
  none), `format` (Markdown → `crate::markup::convert(text, Markup::X)`), `silent`.
  If `send` is called with text longer than the platform limit, split with
  `crate::chunk::split` (the host usually splits already using `caps()`).
- Implement every optional method the platform supports: `caps`, `edit`, `delete`,
  `typing`, `react`, `ack_callback`, `fetch_media`, `stop`. `caps()` must be truthful.
- Errors: map HTTP status with `crate::http::classify` (401/403 → Auth, 404/410 →
  NotFound, 429 → RateLimited with retry_after, 5xx → Network, other 4xx → Protocol).
  Platform-specific "chat gone / bot removed / blocked" → `NotFound`. Bad token → `Auth`.
- Webhook-style receivers: listen with `ark_net::httpd::Server::bind(listen, Opts::default(), handler)`,
  verify the platform signature with `ark_net::crypto` (constant-time `ct_eq`), answer the
  platform's verification handshake, push parsed updates into an `mpsc` channel that
  `poll` drains. Reject bad signatures with 401 before parsing.
- WebSocket gateways: `ark_net::ws::WebSocket::connect(url, headers, timeout)`; set a short
  read timeout (`set_read_timeout(Some(200ms))`) and loop `recv()` (returns `Ok(None)` on
  timeout) so heartbeats and cancel are handled on one thread. Reconnect/resume with
  backoff inside a background thread; `poll` drains an `mpsc` queue.
- External daemons/sidecars (signal-cli, imsg, BlueBubbles, Node bridges): talk to them over
  their HTTP/JSON-RPC/stdio API exactly as upstream does. Node bridge scripts go in
  `bridges/<name>/` (new files) with a README; never auto-install packages.

## Helpers

- `crate::http::Http::new(timeout).bearer(tok).with_header(k, v)`;
  `.json(method, url, Payload::Json(&v) | Form(&[(k,v)]) | Multipart(&[(name, filename, ctype, bytes)]) | Raw(ctype, bytes) | None) -> Result<Value, ChannelError>`;
  `.call(...) -> Resp { status, retry_after, body }` for custom handling.
  `crate::http::get_bytes(url, headers, max)`.
- `ark_net::crypto`: `sha256`, `sha1`, `hmac_sha256`, `hmac_sha1`, `ct_eq`, `ed25519_verify`,
  `random_bytes`, `random_token`, `b64`/`b64_decode`, `b64url`/`b64url_decode`, `hex`/`hex_decode`,
  `Aes::new(key).cbc_encrypt/cbc_decrypt/encrypt_block/decrypt_block` (ECB = per-block).
- `ark_net::{urlencode, urldecode, parse_query, form_encode, Url}`, `ark_net::stream::Stream`
  (TCP/TLS client with timeouts, for IRC/IMAP/SMTP; `stream.starttls(host)` upgrades a plain
  connection after the protocol's STARTTLS command).
- `crate::markup::convert(md, Markup::{TelegramHtml, SlackMrkdwn, MatrixHtml, DiscordMarkdown, Plain})`.
- `crate::chunk::split(text, max, LenUnit)`, `crate::sleep_cancellable(d, cancel)`.
- Tests: `crate::testutil::{FakeServer, temp_dir}` — `FakeServer::start(|req, n| (status, headers, body))`
  records requests (`req.path`, `req.json()`, `req.header()`); for WebSocket servers use
  `std::net::TcpListener` + `ark_net::ws::{read_head, WebSocket::accept}` in a thread.

## Tests (required, per channel)

Real tests against a fake platform server, not happy-path only:
1. Inbound parsing for every message kind the platform sends (text, media, group vs DM,
   thread, reply-to-bot, mention, edit, button callback, bot's own message dropped).
2. Outbound request shape (exact endpoint, auth header, body fields for reply/thread/buttons/media/format).
3. Error mapping (bad token → Auth, rate limit with retry_after, 5xx retry, chat gone → NotFound).
4. Signature / handshake verification for webhook receivers (good, bad, missing, replayed if the platform uses timestamps).
5. Cancel returns promptly from a blocked poll; reconnect after a dropped WebSocket.

Run `cargo test -p ark-channel <module>` and `cargo clippy -p ark-channel --all-targets` (0 warnings).
