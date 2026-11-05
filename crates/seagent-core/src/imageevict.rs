//! Send-path image eviction (Hermes `agent/image_eviction_policy.py` +
//! `context_compressor.evict_stale_outbound_tool_images`).
//!
//! Old tool-result images are retired from the per-request copy of the conversation only when
//! the request would cross a real provider limit, in batches, so the cached prompt prefix is
//! rewritten once per batch instead of on every new screenshot. The block ceiling is 20 when any
//! image exceeds Anthropic's 2000 px many-image cap (or cannot be measured), otherwise the hard
//! 100; a 24 MB byte budget guards the request-size limit. User uploads count against the
//! ceiling but are never rewritten.
//!
//! This is the single implementation of the policy, the header probe and the per-session latch.
//! The two send paths are thin adapters: `seagent-media::vision::evict` (the vision tool hooks) and
//! `seagent_kernel::imgprep` (the kernel's pre-provider pass). They differ only in the wording of the
//! retired-image placeholder and in which surface names its own latch table.
//!
//! In seagent, tool images ride as `Block::Image` next to the `ToolResult` blocks of a user
//! message: such a message is a *carrier*; images in messages without tool results are
//! uploads (*reserved* — they count against the ceiling but are never rewritten).

use crate::types::{Block, Message};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Provider image ceiling while the many-image rule is live.
pub const OUTBOUND_IMAGE_LIMIT: usize = 20;
/// Hard per-request image count: the ceiling once the many-image stricter cap is provably not
/// live (see the module docs). Deliberately not 600 — the byte budget binds first for a
/// 200K-context transcript, and the byte ceiling needs no context knowledge to be safe.
pub const OUTBOUND_IMAGE_HARD_LIMIT: usize = 100;
pub const OUTBOUND_IMAGE_BUDGET_BYTES: usize = 24_000_000;
pub const IMAGE_EVICTION_BATCH: usize = 8;
/// Satisfiability floor — sheltered only when reserved uploads alone breach the block ceiling.
pub const OUTBOUND_IMAGE_FLOOR: usize = 3;
/// Anthropic's stricter many-image per-side cap (px).
pub const MANY_IMAGE_DIMENSION_LIMIT: u32 = 2000;

/// Bytes of an embedded image to decode when reading its header. PNG IHDR ends at byte 24; a
/// JPEG SOF marker lives within the first few KB. ~32 KB of base64 is generous headroom.
pub const DIMENSION_PROBE_CHARS: usize = 32 * 1024;
const JPEG_SOF_MARKERS: [u8; 13] = [0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF];

// ───────────────────────── image headers ─────────────────────────

/// `(width, height)` for PNG / JPEG bytes, or `None` when unreadable. PNG: IHDR. JPEG: walk
/// segments (skipping 0xFF fill bytes) to the first SOF marker; stop at SOS.
pub fn dimensions_from_bytes(raw: &[u8]) -> Option<(u32, u32)> {
    if raw.starts_with(b"\x89PNG\r\n\x1a\n") && raw.len() >= 24 {
        let w = u32::from_be_bytes(raw[16..20].try_into().ok()?);
        let h = u32::from_be_bytes(raw[20..24].try_into().ok()?);
        return Some((w, h));
    }
    if raw.starts_with(&[0xff, 0xd8]) && raw.len() > 4 {
        let mut i = 2usize;
        while i + 9 < raw.len() {
            if raw[i] != 0xFF {
                i += 1;
                continue;
            }
            let mut marker = raw[i + 1];
            i += 2;
            while marker == 0xFF && i < raw.len() {
                marker = raw[i];
                i += 1;
            }
            if marker == 0xD8 || marker == 0xD9 {
                continue;
            }
            if marker == 0xDA || i + 2 > raw.len() {
                break;
            }
            let segment_len = u16::from_be_bytes([raw[i], raw[i + 1]]) as usize;
            if segment_len < 2 || i + segment_len > raw.len() {
                break;
            }
            if JPEG_SOF_MARKERS.contains(&marker) && segment_len >= 7 {
                let h = u16::from_be_bytes([raw[i + 3], raw[i + 4]]) as u32;
                let w = u16::from_be_bytes([raw[i + 5], raw[i + 6]]) as u32;
                return Some((w, h));
            }
            i += segment_len;
        }
    }
    None
}

/// The base64 payload of a `data:` URL (base64 form only) or of a bare payload.
fn payload(data: &str) -> Option<&str> {
    match data.strip_prefix("data:") {
        Some(rest) => {
            let (head, body) = rest.split_once(',')?;
            head.contains(";base64").then_some(body)
        }
        None if !data.is_empty() => Some(data),
        None => None,
    }
}

fn b64_value(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as u32),
        b'a'..=b'z' => Some((b - b'a') as u32 + 26),
        b'0'..=b'9' => Some((b - b'0') as u32 + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Lenient base64 decode (standard or URL-safe alphabet, padding and whitespace ignored);
/// `None` when the text holds a character outside both alphabets.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 3);
    let (mut acc, mut n) = (0u32, 0u32);
    for b in s.bytes() {
        if b.is_ascii_whitespace() || b == b'=' {
            continue;
        }
        acc = (acc << 6) | b64_value(b)?;
        n += 1;
        if n == 4 {
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
            n = 0;
        }
    }
    match n {
        0 => {}
        2 => out.push((acc >> 4) as u8),
        3 => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
        _ => return None,
    }
    Some(out)
}

/// The leading bytes of an image payload: a header-sized prefix of `data:` URL / bare base64,
/// decoded. Classifying a request with dozens of images costs a few header reads, never a full
/// decode of every payload.
pub fn header_prefix(data: &str) -> Option<Vec<u8>> {
    let payload = payload(data)?.trim();
    let mut end = payload.len().min(DIMENSION_PROBE_CHARS);
    while end > 0 && !payload.is_char_boundary(end) {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    b64_decode(&payload[..end])
}

/// Longest side (px) of a `data:` URL or bare-base64 image, or `None` when it cannot be read.
pub fn max_side_from_data(data: &str) -> Option<u32> {
    dimensions_from_bytes(&header_prefix(data)?).map(|(w, h)| w.max(h))
}

/// True only when the image's longest side is known and within [`MANY_IMAGE_DIMENSION_LIMIT`]:
/// unknown dimensions are NOT safe, so the caller keeps the strict trigger.
pub fn within_many_image_limit(data: &str) -> bool {
    max_side_from_data(data).is_some_and(|s| s <= MANY_IMAGE_DIMENSION_LIMIT)
}

/// True when EVERY image in the request is a readable image within the many-image limit (the
/// Anthropic rule is per request, so one offender holds every image to the stricter cap).
pub fn all_within_many_image_limit<'a>(datas: impl IntoIterator<Item = &'a str>) -> bool {
    datas.into_iter().all(within_many_image_limit)
}

/// Block ceiling for a request: the strict 20 unless every image is within the many-image cap.
pub fn block_limit(many_image_safe: bool) -> usize {
    if many_image_safe {
        OUTBOUND_IMAGE_HARD_LIMIT
    } else {
        OUTBOUND_IMAGE_LIMIT
    }
}

// ───────────────────────── retire count ─────────────────────────

/// Tunables of one eviction pass (upstream defaults, see [`Policy::for_request`]).
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub limit: usize,
    pub budget: usize,
    pub batch: usize,
    pub floor: usize,
}

impl Policy {
    pub fn for_request(many_image_safe: bool) -> Policy {
        Policy { limit: block_limit(many_image_safe), budget: OUTBOUND_IMAGE_BUDGET_BYTES, batch: IMAGE_EVICTION_BATCH, floor: OUTBOUND_IMAGE_FLOOR }
    }
}

/// How many of the OLDEST carriers to retire (Hermes `outbound_image_retire_count`): a step
/// function of the overshoot, maximised over every replay-window suffix.
///
/// `blocks_newest_first` is the image-block count per carrier, newest first; `reserved_blocks`
/// counts images the pass must never rewrite (uploads). The byte dimension is active only when
/// `bytes_newest_first` is given.
///
/// The count is a STEP FUNCTION of the overshoot, because the pass is recomputed on every
/// request: an exact `count - limit` target moves the frontier on every new image, and a fixed
/// one-batch retire stops enforcing the limit after the first batch. The quantum is `batch`
/// capped at `window - floor`, where `window` is how many newest carriers fit under the
/// ceiling; a wider quantum would step past the newest frames on every advance.
///
/// The floor is a SATISFIABILITY floor: it shelters the newest frames only when reserved
/// uploads alone breach the block ceiling (no retirement can fix that), and never under byte
/// pressure — the request-size limit is hard and the provider answers 413.
pub fn retire_count(blocks_newest_first: &[usize], reserved_blocks: usize, bytes_newest_first: Option<&[usize]>, reserved_bytes: usize, p: &Policy) -> usize {
    let total = blocks_newest_first.len();
    (1..=total)
        .map(|m| retire_for_request(&blocks_newest_first[total - m..], reserved_blocks, bytes_newest_first.map(|s| &s[total - m..]), reserved_bytes, p))
        .max()
        .unwrap_or(0)
}

fn retire_for_request(blocks: &[usize], reserved_blocks: usize, sizes: Option<&[usize]>, reserved_bytes: usize, p: &Policy) -> usize {
    let total = blocks.len();
    let mut kept_blocks = vec![0usize; total + 1];
    let mut kept_bytes = vec![0usize; total + 1];
    for i in 0..total {
        kept_blocks[i + 1] = kept_blocks[i] + blocks[i];
        kept_bytes[i + 1] = kept_bytes[i] + sizes.map(|s| s[i]).unwrap_or(0);
    }
    let bytes_fit = |kept: usize| sizes.is_none() || reserved_bytes + kept_bytes[kept] <= p.budget;
    let fits = |kept: usize| reserved_blocks + kept_blocks[kept] <= p.limit && bytes_fit(kept);
    if fits(total) {
        return 0;
    }
    let floor = p.floor.min(total);
    if !fits(0) && bytes_fit(floor) {
        // Reserved uploads alone breach the block ceiling: shelter the floor but keep advancing
        // in whole quanta, narrowed by how many carriers the byte budget lets us keep.
        let byte_window = (floor..=total).filter(|&k| bytes_fit(k)).max().unwrap_or(floor);
        let quantum = p.batch.min(byte_window - floor + 1).max(1);
        let excess = total - floor;
        return excess - excess % quantum;
    }
    let window = if fits(0) { (0..=total).filter(|&k| fits(k)).max().unwrap_or(0) } else { 0 };
    let quantum = p.batch.min(window.saturating_sub(floor)).max(1);
    let mut retire = 0;
    while retire < total {
        retire = (retire + quantum).min(total);
        if fits(total - retire) {
            break;
        }
    }
    retire
}

/// Widen `retire` so every carrier up to the newest previously retired one stays retired, then
/// record the carriers being retired (Hermes `latched_retire_count`). A request that drops an
/// upload relaxes the ceiling, and re-deciding from scratch would restore screenshots an earlier
/// request already retired, rewriting the cached prefix back.
pub fn latched_retire_count(retire: usize, ids_newest_first: &[Option<String>], retired: Option<&mut HashSet<String>>) -> usize {
    let Some(set) = retired else { return retire };
    let total = ids_newest_first.len();
    let retire = match ids_newest_first.iter().position(|id| id.as_ref().is_some_and(|i| set.contains(i))) {
        Some(n) => retire.max(total - n),
        None => retire,
    };
    for id in ids_newest_first[total - retire.min(total)..].iter().flatten() {
        set.insert(id.clone());
    }
    retire
}

// ───────────────────────── carriers ─────────────────────────

/// The image payloads of one message, oldest first.
pub fn images(m: &Message) -> Vec<&str> {
    m.content.iter().filter_map(|b| if let Block::Image { data, .. } = b { Some(data.as_str()) } else { None }).collect()
}

/// An image-bearing tool result: a message that carries both `ToolResult` blocks and images.
pub fn is_carrier(m: &Message) -> bool {
    m.content.iter().any(|b| matches!(b, Block::ToolResult { .. })) && m.content.iter().any(|b| matches!(b, Block::Image { .. }))
}

/// The message's carrier id: the tool call it answers (upstream keys the latch on tool-call ids).
pub fn carrier_id(m: &Message) -> Option<String> {
    m.content.iter().rev().find_map(|b| match b {
        Block::ToolResult { tool_use_id, .. } => Some(tool_use_id.clone()),
        _ => None,
    })
}

// ───────────────────────── eviction ─────────────────────────

/// Retire stale tool-result images from `messages` (a per-request copy — never persisted
/// history), replacing every image block of the oldest `retire` carriers with `placeholder`.
/// `retired` latches the frontier per session. Returns the carriers rewritten.
pub fn evict(messages: &mut [Message], placeholder: &str, retired: Option<&mut HashSet<String>>) -> usize {
    let mut carriers: Vec<usize> = Vec::new();
    let (mut reserved_blocks, mut reserved_bytes, mut any_image) = (0usize, 0usize, false);
    for (i, m) in messages.iter().enumerate() {
        let imgs = images(m);
        if imgs.is_empty() {
            continue;
        }
        any_image = true;
        if is_carrier(m) {
            carriers.push(i);
        } else {
            reserved_blocks += imgs.len();
            reserved_bytes += imgs.iter().map(|d| d.len()).sum::<usize>();
        }
    }
    if !any_image || carriers.is_empty() {
        return 0;
    }
    let many_image_safe = all_within_many_image_limit(messages.iter().flat_map(images));
    let blocks: Vec<usize> = carriers.iter().rev().map(|&i| images(&messages[i]).len()).collect();
    let bytes: Vec<usize> = carriers.iter().rev().map(|&i| images(&messages[i]).iter().map(|d| d.len()).sum()).collect();
    let ids: Vec<Option<String>> = carriers.iter().rev().map(|&i| carrier_id(&messages[i])).collect();
    let retire = retire_count(&blocks, reserved_blocks, Some(&bytes), reserved_bytes, &Policy::for_request(many_image_safe));
    let retire = latched_retire_count(retire, &ids, retired);
    let mut pruned = 0;
    for &i in &carriers[..retire.min(carriers.len())] {
        let mut changed = false;
        for b in messages[i].content.iter_mut() {
            if matches!(b, Block::Image { .. }) {
                *b = Block::text(placeholder);
                changed = true;
            }
        }
        pruned += changed as usize;
    }
    pruned
}

// ───────────────────────── per-session latch ─────────────────────────

/// One send path's per-session latch table: the tool-call ids whose images it already retired.
///
/// Each caller owns its own instance, so the media hooks and the kernel pass never share a
/// frontier; both get the same bounded-table behaviour (a long-lived daemon must not grow one
/// map per chat, and a dropped entry only re-decides the frontier from scratch).
pub struct Latches {
    map: Mutex<HashMap<String, HashSet<String>>>,
    limit: usize,
}

impl Latches {
    /// `limit`: sessions kept before the table is dropped wholesale.
    pub fn new(limit: usize) -> Latches {
        Latches { map: Mutex::new(HashMap::new()), limit }
    }

    /// Run `f` on `session`'s latch set.
    pub fn with<R>(&self, session: &str, f: impl FnOnce(&mut HashSet<String>) -> R) -> R {
        let mut g = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() > self.limit && !g.contains_key(session) {
            g.clear();
        }
        f(g.entry(session.to_string()).or_default())
    }

    /// Forget a session's latch (new session / compaction rotation — both rewrite the prefix).
    pub fn forget(&self, session: &str) {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).remove(session);
    }

    /// Drop every latch.
    pub fn clear(&self) {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Sessions that currently hold a latch (diagnostics / tests).
    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carrier(id: &str, data: &str) -> Message {
        Message {
            role: crate::types::Role::User,
            content: vec![Block::ToolResult { tool_use_id: id.into(), content: "shot".into(), is_error: false }, Block::Image { media_type: "image/png".into(), data: data.into() }],
        }
    }

    fn upload(data: &str) -> Message {
        Message { role: crate::types::Role::User, content: vec![Block::text("look"), Block::Image { media_type: "image/png".into(), data: data.into() }] }
    }

    #[test]
    fn retire_count_is_a_step_function_of_the_overshoot() {
        let p = Policy { limit: 20, budget: usize::MAX, batch: 8, floor: 3 };
        assert_eq!(retire_count(&[1; 20], 0, None, 0, &p), 0);
        assert_eq!(retire_count(&[1; 21], 0, None, 0, &p), 8, "one whole batch, not the exact overshoot");
        assert_eq!(retire_count(&[1; 40], 0, None, 0, &p), 24, "quanta of 8 until the request fits");
        // Reserved uploads alone breach the ceiling: settle at the satisfiability floor.
        assert_eq!(retire_count(&[1; 40], 30, None, 0, &Policy { limit: 20, budget: usize::MAX, batch: 8, floor: 8 }), 32);
        // The byte budget binds before the count does.
        let sizes = [8_000_000usize; 4];
        assert_eq!(retire_count(&[1; 4], 0, Some(&sizes), 0, &Policy { limit: 100, budget: OUTBOUND_IMAGE_BUDGET_BYTES, batch: 8, floor: 3 }), 1);
    }

    #[test]
    fn header_probe_reads_a_png_without_decoding_the_payload() {
        // A 2000x600 PNG header, base64 (IHDR only: the probe never needs pixels).
        let png = "iVBORw0KGgoAAAANSUhEUgAAB9AAAAJYCAYAAAA=";
        assert_eq!(max_side_from_data(png), Some(2000));
        assert_eq!(max_side_from_data(&format!("data:image/png;base64,{png}")), Some(2000));
        assert_eq!(max_side_from_data("data:image/png,notbase64"), None, "a non-base64 data URL is unmeasurable");
        assert_eq!(max_side_from_data("https://example.com/a.png"), None);
        assert_eq!(max_side_from_data("AAAA"), None, "too short for a header");
        assert_eq!(max_side_from_data(""), None);
        assert!(all_within_many_image_limit([png]));
        assert!(!all_within_many_image_limit(["!!!not-base64!!!"]), "unmeasurable images keep the strict ceiling");
        assert_eq!(block_limit(true), OUTBOUND_IMAGE_HARD_LIMIT);
        assert_eq!(block_limit(false), OUTBOUND_IMAGE_LIMIT);
    }

    #[test]
    fn eviction_retires_the_oldest_carriers_in_batches_and_keeps_uploads() {
        // Unmeasurable payloads keep the strict 20-image ceiling live.
        let mut msgs: Vec<Message> = (0..25).map(|i| carrier(&format!("t{i}"), "AAAA")).collect();
        msgs.insert(0, upload("AAAA"));
        let mut latch = HashSet::new();
        assert_eq!(evict(&mut msgs, "[retired]", Some(&mut latch)), 8, "the oldest batch of carriers");
        assert!(matches!(msgs[0].content[1], Block::Image { .. }), "an upload is never rewritten");
        assert!(matches!(&msgs[1].content[1], Block::Text { text } if text == "[retired]"));
        assert!(matches!(msgs[9].content[1], Block::Image { .. }), "nothing newer than the frontier is touched");
        assert!(latch.contains("t0") && latch.contains("t7") && !latch.contains("t8"));
        // A smaller replay window still keeps the latched carriers retired.
        let mut fewer: Vec<Message> = (0..9).map(|i| carrier(&format!("t{i}"), "AAAA")).collect();
        assert_eq!(evict(&mut fewer, "[retired]", Some(&mut latch)), 8);
        assert!(fewer[0].content.iter().all(|b| !matches!(b, Block::Image { .. })), "the latched frontier widens the count back");
    }

    #[test]
    fn the_latch_table_is_per_session_and_bounded() {
        let latches = Latches::new(1);
        latches.with("a", |set| set.insert("t0".into()));
        latches.with("b", |set| set.insert("t1".into()));
        assert_eq!(latches.len(), 2);
        assert!(latches.with("a", |set| set.contains("t0")));
        // Growing past the limit with a new session drops the table (a lost latch re-decides).
        latches.with("c", |set| set.insert("t2".into()));
        assert_eq!(latches.len(), 1);
        latches.forget("c");
        assert!(latches.is_empty());
    }
}
