//! Send-path image handling, applied to the per-request copy of the conversation just before a
//! provider call: retire old tool-result images (Hermes `agent/image_eviction_policy.py`) and
//! stand in text for images when the resolved model has no vision (Hermes
//! `agent/vision_message_prep.py`).
//!
//! In seagent a tool's image rides as `Block::Image` next to the `ToolResult` blocks of a user
//! message (see the kernel's `IMAGE_TOOLS` handling): such a message is an image *carrier*;
//! images in messages without tool results are uploads (*reserved* — they count against the
//! ceiling but are never rewritten).
//!
//! Why the eviction trigger is a provider limit and not a keep-newest count: retiring an image
//! edits a message the provider has already cached, and prompt caches match on an exact byte
//! prefix. A keep-newest-N window retires one more message on every new image, so every turn is
//! a full-prefix miss. Holding the images until the request would cross a real API limit and
//! then retiring a batch costs one slower turn per batch and nothing below the limit.
//!
//! 20 is the documented threshold at which Anthropic applies a stricter per-image dimension cap
//! (2000 px) to EVERY image in the request, tool-result images included. Crossing it costs
//! nothing by itself: it only matters when some image actually exceeds 2000 px on a side, and
//! seagent already shrinks the images it embeds far below that. So the block ceiling is CONDITIONAL
//! on the request's measured dimensions: the strict 20 applies only when some image exceeds
//! `MANY_IMAGE_DIMENSION_LIMIT` (or cannot be measured), otherwise the hard count
//! `OUTBOUND_IMAGE_HARD_LIMIT`. The 24 MB byte budget guards the request-size limit, with
//! headroom for text. Classification reads image HEADERS only — never a full decode.

use seagent_core::{Block, Message, ModelRequest, Role};
#[cfg(test)]
use base64::Engine;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

// The eviction policy, the header probe and the latch table are `seagent_core::imageevict` (the one
// implementation, shared with seagent-media's vision hooks); this module is the kernel's adapter.
pub use seagent_core::imageevict::{all_within_many_image_limit, block_limit, latched_retire_count, within_many_image_limit, Policy};

pub const OUTBOUND_IMAGE_LIMIT: usize = seagent_core::imageevict::OUTBOUND_IMAGE_LIMIT;
/// Hard per-request image count: the ceiling once the many-image stricter cap is provably not
/// live (see the module docs). Deliberately not 600 — the byte budget binds first for a
/// 200K-context transcript, and the byte ceiling needs no context knowledge to be safe.
pub const OUTBOUND_IMAGE_HARD_LIMIT: usize = seagent_core::imageevict::OUTBOUND_IMAGE_HARD_LIMIT;
pub const OUTBOUND_IMAGE_BUDGET_BYTES: usize = seagent_core::imageevict::OUTBOUND_IMAGE_BUDGET_BYTES;
pub const IMAGE_EVICTION_BATCH: usize = seagent_core::imageevict::IMAGE_EVICTION_BATCH;
/// Satisfiability floor — see [`seagent_core::imageevict::retire_count`].
pub const OUTBOUND_IMAGE_FLOOR: usize = seagent_core::imageevict::OUTBOUND_IMAGE_FLOOR;
/// Anthropic's stricter many-image per-side cap (px).
pub const MANY_IMAGE_DIMENSION_LIMIT: u32 = seagent_core::imageevict::MANY_IMAGE_DIMENSION_LIMIT;
/// What a retired image becomes (upstream's wording in both send-path passes: Hermes
/// `anthropic_message_convert` and `context_compressor._strip_images_from_tool_msg`). The bytes
/// must stay identical across requests or the cached prefix is rewritten.
pub const RETIRED_PLACEHOLDER: &str = "[screenshot removed to save context]";

// ───────────────────────── image headers ─────────────────────────

/// `(width, height)` for PNG / JPEG bytes, or `None` when unreadable (the shared header parse).
pub fn dimensions_from_bytes(raw: &[u8]) -> Option<(u32, u32)> {
    seagent_core::imageevict::dimensions_from_bytes(raw)
}

/// Longest side (px) of a `data:` URL or bare-base64 image, or `None` when it cannot be read.
///
/// Decodes only the leading base64 prefix, so classifying a request with dozens of images costs
/// a few header reads, not a full decode of every payload.
pub fn max_side_from_data(data: &str) -> Option<u32> {
    seagent_core::imageevict::max_side_from_data(data)
}

// ───────────────────────── retire count ─────────────────────────

/// How many of the OLDEST image-bearing tool results to retire for a request classified by
/// [`all_within_many_image_limit`] (see [`seagent_core::imageevict::retire_count`] for the policy).
pub fn retire_count(blocks_newest_first: &[usize], reserved_blocks: usize, bytes_newest_first: Option<&[usize]>, reserved_bytes: usize, many_image_safe: bool) -> usize {
    retire_count_with(blocks_newest_first, reserved_blocks, bytes_newest_first, reserved_bytes, Policy::for_request(many_image_safe))
}

/// [`seagent_core::imageevict::retire_count`] with explicit tunables.
pub fn retire_count_with(blocks_newest_first: &[usize], reserved_blocks: usize, bytes_newest_first: Option<&[usize]>, reserved_bytes: usize, p: Policy) -> usize {
    seagent_core::imageevict::retire_count(blocks_newest_first, reserved_blocks, bytes_newest_first, reserved_bytes, &p)
}

// ───────────────────────── carriers ─────────────────────────

/// The session latch table of the kernel's send path. The kernel keeps its own instance: the
/// media hooks latch the same tool ids for their own pass.
fn latches() -> &'static seagent_core::imageevict::Latches {
    static L: OnceLock<seagent_core::imageevict::Latches> = OnceLock::new();
    L.get_or_init(|| seagent_core::imageevict::Latches::new(256))
}

/// Run `f` on `session`'s latch set (see [`seagent_core::imageevict::Latches`]).
fn with_latch<R>(session: &str, f: impl FnOnce(&mut HashSet<String>) -> R) -> R {
    latches().with(session, f)
}

/// Forget a session's latch (new session / compaction rotation — both rewrite the prefix).
pub fn forget_session(session: &str) {
    latches().forget(session);
}

/// Drop every latch (tests).
pub fn clear_latch() {
    latches().clear();
}

// ───────────────────────── eviction ─────────────────────────

/// Retire old tool-result images from `messages` in place; returns how many carriers were
/// retired. `session` keys the latch (see [`latched_retire_count`]).
pub fn evict_tool_images(messages: &mut [Message], session: &str) -> usize {
    with_latch(session, |set| seagent_core::imageevict::evict(messages, RETIRED_PLACEHOLDER, Some(set)))
}

// ───────────────────────── non-vision fallback ─────────────────────────

/// 20 MB of base64 ≈ 15 MB decoded: prevents OOM from an oversized payload, and marks the
/// image as undescribable rather than forwarding it to a model that cannot see it.
pub const MAX_DATA_URL_BASE64_BYTES: usize = 20 * 1024 * 1024;
const DEFAULT_IMAGE_MEDIA_TYPE: &str = "image/jpeg";

const NO_SOURCE: &str = "[An image was attached but no image source was available.]";
const MULTIMODAL_ONLY: &str = "[A multimodal message was converted to text for Anthropic compatibility.]";

/// `[{role} attached an image. Here's what it contains:\n{description}]` — the upstream note
/// shape. seagent does not run a vision model from the kernel, so the description says why.
fn placeholder_note(role_label: &str, data: &str) -> String {
    let description = if data.is_empty() {
        return NO_SOURCE.to_string();
    } else if data.len() > MAX_DATA_URL_BASE64_BYTES {
        "Image analysis failed: the data-URL payload is too large to describe."
    } else {
        "Image analysis unavailable: the active model does not accept image input."
    };
    format!("[The {role_label} attached an image. Here's what it contains:\n{description}]")
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x100000001b3))
}

fn placeholder_cache() -> &'static Mutex<HashMap<u64, String>> {
    static CACHE: OnceLock<Mutex<HashMap<u64, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The text stand-in for one image, memoised per image (keyed on media type + payload) so the
/// same picture always produces the same bytes: a cache-friendly, stable prefix.
pub fn placeholder_for(media_type: &str, data: &str, role_label: &str) -> String {
    let mut key_bytes = Vec::with_capacity(media_type.len() + 1 + data.len());
    key_bytes.extend_from_slice(if media_type.is_empty() { DEFAULT_IMAGE_MEDIA_TYPE } else { media_type }.as_bytes());
    key_bytes.push(0);
    key_bytes.extend_from_slice(data.as_bytes());
    let key = fnv1a(&key_bytes) ^ fnv1a(role_label.as_bytes());
    {
        let cache = placeholder_cache().lock().unwrap();
        if let Some(hit) = cache.get(&key) {
            return hit.clone();
        }
    }
    let note = placeholder_note(role_label, data);
    let mut cache = placeholder_cache().lock().unwrap();
    if cache.len() < 512 {
        cache.insert(key, note.clone());
    }
    note
}

/// Entries in the per-image placeholder cache (tests / diagnostics).
pub fn placeholder_cache_len() -> usize {
    placeholder_cache().lock().unwrap().len()
}

pub fn clear_placeholder_cache() {
    placeholder_cache().lock().unwrap().clear();
}

fn role_label(m: &Message) -> &'static str {
    if m.content.iter().any(|b| matches!(b, Block::ToolResult { .. })) {
        "tool result"
    } else if m.role == Role::Assistant {
        "assistant"
    } else {
        "user"
    }
}

/// Replace every image part with its textual stand-in; returns how many were replaced.
/// Tool-result images are handled exactly like user uploads (the message keeps its text).
pub fn replace_images_with_text(messages: &mut [Message]) -> usize {
    let mut n = 0;
    for m in messages.iter_mut() {
        let label = role_label(m);
        let mut replaced = false;
        for b in m.content.iter_mut() {
            if let Block::Image { media_type, data } = b {
                let note = placeholder_for(media_type, data, label);
                *b = Block::text(note);
                replaced = true;
                n += 1;
            }
        }
        if replaced && m.content.iter().all(|b| matches!(b, Block::Text { text } if text.trim().is_empty())) {
            m.content.push(Block::text(MULTIMODAL_ONLY));
        }
    }
    n
}

/// Is this request carrying any image at all?
pub fn has_images(messages: &[Message]) -> bool {
    messages.iter().any(|m| m.content.iter().any(|b| matches!(b, Block::Image { .. })))
}

/// Prepare the per-request copy of the conversation for one provider attempt: when the resolved
/// model has no vision, images become text stand-ins; otherwise old tool-result images are
/// retired per the eviction policy. Both steps are idempotent and leave a request without
/// images untouched, so this is safe to call once per provider attempt on the same request.
pub fn prepare_in_place(req: &mut ModelRequest, vision: bool, session: &str) {
    if !has_images(&req.messages) {
        return;
    }
    if vision {
        evict_tool_images(&mut req.messages, session);
    } else {
        replace_images_with_text(&mut req.messages);
    }
}

/// [`prepare_in_place`] on an owned request (tests, callers holding a fresh copy).
pub fn prepare_for_send(mut req: ModelRequest, vision: bool, session: &str) -> ModelRequest {
    prepare_in_place(&mut req, vision, session);
    req
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &str = "image/png";

    /// The latch and the placeholder cache are process-wide; tests that reset them take a lock.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(&[0, 0, 0, 13]);
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 6, 0, 0, 0]);
        v
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn jpeg(w: u16, h: u16) -> Vec<u8> {
        let mut v = vec![0xff, 0xd8];
        v.extend_from_slice(&[0xff, 0xe0, 0x00, 0x04, 0x00, 0x00]); // APP0, length 4
        v.extend_from_slice(&[0xff, 0xc0, 0x00, 0x11, 0x08]); // SOF0, length 17, precision 8
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        v.extend_from_slice(&[0xff, 0xd9]);
        v
    }

    fn carrier(id: &str, data: &str) -> Message {
        Message {
            role: Role::User,
            content: vec![Block::ToolResult { tool_use_id: id.into(), content: format!("read {id}"), is_error: false }, Block::Image { media_type: PNG.into(), data: data.into() }],
        }
    }

    fn upload(data: &str) -> Message {
        Message { role: Role::User, content: vec![Block::text("look"), Block::Image { media_type: PNG.into(), data: data.into() }] }
    }

    fn req(messages: Vec<Message>) -> ModelRequest {
        ModelRequest { model: "m".into(), system: vec![], messages, tools: vec![], max_tokens: 100, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() }
    }

    #[test]
    fn reads_png_and_jpeg_dimensions_from_a_header_prefix_only() {
        let _g = lock();
        assert_eq!(dimensions_from_bytes(&png(1920, 1080)), Some((1920, 1080)));
        assert_eq!(dimensions_from_bytes(&jpeg(800, 600)), Some((800, 600)));
        assert_eq!(dimensions_from_bytes(b"GIF89a"), None);
        // data: URL, bare base64 and a remote URL.
        assert_eq!(max_side_from_data(&format!("data:{PNG};base64,{}", b64(&png(2100, 900)))), Some(2100));
        assert_eq!(max_side_from_data(&b64(&png(100, 100))), Some(100));
        assert_eq!(max_side_from_data("https://example.com/a.png"), None);
        assert_eq!(max_side_from_data(""), None);
    }

    #[test]
    fn many_image_ceiling_is_conditional_on_measured_dimensions() {
        let _g = lock();
        let small = b64(&png(1568, 800));
        let big = b64(&png(2400, 1200));
        assert_eq!(block_limit(all_within_many_image_limit([small.as_str()])), OUTBOUND_IMAGE_HARD_LIMIT);
        assert_eq!(block_limit(all_within_many_image_limit([small.as_str(), big.as_str()])), OUTBOUND_IMAGE_LIMIT);
        // An unmeasurable payload is NOT safe: the strict trigger stays live.
        assert_eq!(block_limit(all_within_many_image_limit(["!!!not-base64!!!"])), OUTBOUND_IMAGE_LIMIT);
    }

    #[test]
    fn retire_count_advances_in_whole_batches_and_stops_at_the_limit() {
        let _g = lock();
        let small = b64(&png(800, 600));
        let safe = retire_count_with(&[1; 12], 0, None, 0, Policy { limit: 100, budget: OUTBOUND_IMAGE_BUDGET_BYTES, batch: 8, floor: 3 });
        assert_eq!(safe, 0, "under the hard ceiling nothing is retired");
        // 40 carriers, strict 20 ceiling: quanta of 8 until the request fits (24 retired, 16 kept),
        // never the exact overshoot (20) that a per-image frontier would produce.
        let strict = retire_count_with(&[1; 40], 0, None, 0, Policy { limit: 20, budget: OUTBOUND_IMAGE_BUDGET_BYTES, batch: 8, floor: 3 });
        assert_eq!(strict, 24);
        // One image over the ceiling does not move the frontier at all until a batch is due.
        assert_eq!(retire_count_with(&[1; 20], 1, None, 0, Policy { limit: 20, budget: OUTBOUND_IMAGE_BUDGET_BYTES, batch: 8, floor: 3 }), 8);
        assert_eq!(retire_count_with(&[1; 20], 0, None, 0, Policy { limit: 20, budget: OUTBOUND_IMAGE_BUDGET_BYTES, batch: 8, floor: 3 }), 0);
        // Uploads alone over the ceiling: settle at the satisfiability floor, in quanta.
        let floored = retire_count_with(&[1; 40], 30, None, 0, Policy { limit: 20, budget: OUTBOUND_IMAGE_BUDGET_BYTES, batch: 8, floor: 8 });
        assert_eq!(floored, 32);
        assert!(!small.is_empty());
    }

    #[test]
    fn byte_budget_binds_before_the_count_does() {
        let _g = lock();
        // Four carriers of 8 MB each with a 24 MB budget: only two fit.
        let sizes = [8_000_000usize; 4];
        let p = Policy { limit: 100, budget: OUTBOUND_IMAGE_BUDGET_BYTES, batch: 8, floor: 3 };
        let retire = retire_count_with(&[1; 4], 0, Some(&sizes), 0, p);
        assert_eq!(retire, 1, "one 8 MB carrier has to go to fit 24 MB");
        // Reserved uploads over the budget always retire at least something.
        assert!(retire_count_with(&[1; 4], 0, Some(&sizes), 30_000_000, p) > 0);
    }

    #[test]
    fn retired_placeholder_matches_upstream_wording() {
        // Hermes replaces a retired block with exactly this text in both send-path passes
        // (`anthropic_message_convert._evict_old_screenshots`, `context_compressor._strip_images_from_tool_msg`).
        assert_eq!(RETIRED_PLACEHOLDER, "[screenshot removed to save context]");
    }

    #[test]
    fn eviction_retires_old_carriers_and_keeps_the_newest_below_the_ceiling() {
        let _g = lock();
        clear_latch();
        let img = b64(&png(900, 500)); // within the many-image cap → hard ceiling 100
        let mut msgs: Vec<Message> = (0..30).map(|i| carrier(&format!("t{i}"), &img)).collect();
        msgs.push(Message::user("go on"));
        assert_eq!(evict_tool_images(&mut msgs, "s1"), 0, "30 images are far below the hard ceiling");
        // Strict ceiling (unmeasurable images): the frontier moves only in batches.
        let mut small: Vec<Message> = (0..30).map(|i| carrier(&format!("u{i}"), "AAAA")).collect();
        assert_eq!(evict_tool_images(&mut small, "s2"), 16, "quanta of 8 until it fits: 14 kept, under the strict 20");
        let retired: Vec<usize> = (0..30).filter(|&i| small[i].content.iter().any(|b| matches!(b, Block::Text { text } if text == RETIRED_PLACEHOLDER))).collect();
        assert_eq!(retired, (0..16).collect::<Vec<_>>(), "the OLDEST carriers up to the frontier");
        assert!(small[16..].iter().all(|m| m.content.iter().any(|b| matches!(b, Block::Image { .. }))), "nothing newer than the frontier is touched");
        assert!(small[0].content.iter().any(|b| matches!(b, Block::ToolResult { .. })), "the tool result text stays");
    }

    #[test]
    fn latch_never_restores_a_retired_image_when_uploads_disappear() {
        let _g = lock();
        clear_latch();
        let mut msgs: Vec<Message> = (0..9).map(|i| carrier(&format!("t{i}"), "AAAA")).collect();
        for _ in 0..15 {
            msgs.push(upload("AAAA")); // uploads fill the strict ceiling: 9 images can't fit in 20 with 15 uploads
        }
        // 15 uploads + 9 carriers under the strict ceiling of 20: two quanta, four carriers retired.
        assert_eq!(evict_tool_images(&mut msgs, "sess"), 4);
        // The uploads leave the replay window: the per-request decision would restore everything.
        let mut shrunk: Vec<Message> = (0..9).map(|i| carrier(&format!("t{i}"), "AAAA")).collect();
        assert_eq!(evict_tool_images(&mut shrunk, "other"), 0, "without the uploads nothing needs retiring");
        assert_eq!(evict_tool_images(&mut shrunk, "sess"), 4, "the latch widens the retire count back");
        assert!(shrunk[0].content.iter().all(|b| !matches!(b, Block::Image { .. })), "the old screenshot stays retired");
        forget_session("sess");
    }

    #[test]
    fn non_vision_models_get_text_stand_ins_for_user_and_tool_images() {
        let _g = lock();
        clear_placeholder_cache();
        let mut r = req(vec![upload(&b64(&png(10, 10))), carrier("t1", &b64(&png(20, 20)))]);
        r = prepare_for_send(r, false, "s");
        assert!(!has_images(&r.messages));
        let texts: Vec<String> = r.messages.iter().flat_map(|m| m.content.iter().filter_map(|b| match b { Block::Text { text } => Some(text.clone()), _ => None })).collect();
        assert!(texts.iter().any(|t| t.starts_with("[The user attached an image. Here's what it contains:")), "{texts:?}");
        assert!(texts.iter().any(|t| t.starts_with("[The tool result attached an image. Here's what it contains:")), "{texts:?}");
        assert_eq!(placeholder_cache_len(), 2, "one cached stand-in per image");
        // Same image → byte-identical text (cache-friendly prefix).
        let again = replace_images_with_text(&mut req(vec![upload(&b64(&png(10, 10)))]).messages);
        assert_eq!(again, 1);
        assert_eq!(placeholder_cache_len(), 2);
    }

    #[test]
    fn vision_models_keep_their_images() {
        let _g = lock();
        let img = b64(&png(10, 10));
        let r = prepare_for_send(req(vec![upload(&img), carrier("t1", &img)]), true, "s");
        assert!(has_images(&r.messages));
        assert_eq!(r.messages.iter().flat_map(|m| m.content.iter()).filter(|b| matches!(b, Block::Image { .. })).count(), 2);
    }

    #[test]
    fn oversized_payloads_and_missing_sources_get_their_own_wording() {
        let _g = lock();
        clear_placeholder_cache();
        assert_eq!(placeholder_note("user", ""), NO_SOURCE);
        let big = "A".repeat(MAX_DATA_URL_BASE64_BYTES + 1);
        assert!(placeholder_note("user", &big).contains("too large"));
        let mut m = vec![Message { role: Role::User, content: vec![Block::Image { media_type: PNG.into(), data: String::new() }] }];
        replace_images_with_text(&mut m);
        assert_eq!(m[0].content, vec![Block::text(NO_SOURCE)]);
    }
}
