//! Send-path image eviction (Hermes `agent/image_eviction_policy.py` +
//! `context_compressor.evict_stale_outbound_tool_images`) — the media hooks' adapter over the one
//! implementation in [`seagent_core::imageevict`].
//!
//! Old tool-result images are retired from the per-request copy of the conversation only when
//! the request would cross a real provider limit, in batches, so the cached prompt prefix is
//! rewritten once per batch instead of on every new screenshot. The block ceiling is 20 when any
//! image exceeds Anthropic's 2000 px many-image cap (or cannot be measured), otherwise the hard
//! 100; a 24 MB byte budget guards the request-size limit. User uploads count against the
//! ceiling but are never rewritten.
//!
//! In seagent, tool images ride as `Block::Image` next to the `ToolResult` blocks of a user
//! message (see the kernel's `IMAGE_TOOLS` handling): such a message is a *carrier*; images in
//! user messages without tool results are uploads (*reserved*).

use seagent_core::Message;
#[cfg(test)]
use seagent_core::{Block, Role};
use std::collections::HashSet;

pub use seagent_core::imageevict::{
    all_within_many_image_limit, block_limit, latched_retire_count, retire_count, Policy, IMAGE_EVICTION_BATCH, MANY_IMAGE_DIMENSION_LIMIT, OUTBOUND_IMAGE_BUDGET_BYTES, OUTBOUND_IMAGE_FLOOR,
    OUTBOUND_IMAGE_HARD_LIMIT, OUTBOUND_IMAGE_LIMIT,
};

/// What a retired image becomes in this crate's send path.
pub const RETIRED_PLACEHOLDER: &str = "[image omitted: retired from the request to stay under provider image limits]";

/// Longest side of a bare-base64 or `data:` image, decoding only a header prefix. The prefix
/// decode is shared ([`seagent_core::imageevict::header_prefix`]); media additionally recognises the
/// formats the `image` crate sniffs (GIF / WebP / BMP), which the shared PNG/JPEG header parse
/// does not.
pub fn max_side_from_data(data: &str) -> Option<u32> {
    seagent_core::imageevict::header_prefix(data).and_then(|raw| super::prep::dimensions(&raw)).map(|(w, h)| w.max(h))
}

/// Retire stale tool-result images from `messages` (a per-request copy — never persisted
/// history). `retired` latches the frontier per session. Returns the messages rewritten.
pub fn evict(messages: &mut [Message], retired: Option<&mut HashSet<String>>) -> usize {
    seagent_core::imageevict::evict(messages, RETIRED_PLACEHOLDER, retired)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(side: u32) -> String {
        crate::store::b64(&super::super::prep::test_png(side, 1))
    }

    fn carrier(id: &str, n: usize) -> Message {
        let mut c = vec![Block::ToolResult { tool_use_id: id.into(), content: "shot".into(), is_error: false }];
        c.extend((0..n).map(|_| Block::Image { media_type: "image/png".into(), data: img(10) }));
        Message { role: Role::User, content: c }
    }

    #[test]
    fn retire_count_is_a_step_function() {
        let p = Policy { limit: 20, budget: usize::MAX, batch: 8, floor: 3 };
        assert_eq!(retire_count(&[1; 20], 0, None, 0, &p), 0);
        // 21 carriers: retire a whole batch, and keep that frontier while images keep coming.
        assert_eq!(retire_count(&[1; 21], 0, None, 0, &p), 8);
        assert_eq!(retire_count(&[1; 25], 0, None, 0, &p), 8);
        assert_eq!(retire_count(&[1; 29], 0, None, 0, &p), 16);
        // Byte pressure binds even below the block ceiling.
        let pb = Policy { limit: 100, budget: 10, batch: 8, floor: 3 };
        assert!(retire_count(&[1; 5], 0, Some(&[4; 5]), 0, &pb) >= 3);
        // Uploads alone breach the ceiling: retire in whole quanta down toward the floor.
        assert_eq!(retire_count(&[1; 10], 25, None, 0, &p), 0);
        assert_eq!(retire_count(&[1; 12], 25, None, 0, &p), 8);
    }

    #[test]
    fn strict_twenty_when_a_side_exceeds_two_thousand_pixels() {
        // Anthropic applies a stricter many-image cap to every image once one is >2000 px.
        let big = crate::store::b64(&super::super::prep::test_png(2100, 4));
        let small = crate::store::b64(&super::super::prep::test_png(1999, 4));
        assert_eq!(max_side_from_data(&big), Some(2100));
        let mk = |data: &str| Message {
            role: Role::User,
            content: vec![Block::ToolResult { tool_use_id: "t".into(), content: String::new(), is_error: false }, Block::Image { media_type: "image/png".into(), data: data.to_string() }],
        };
        // 25 carriers of small images stay under the hard 100 ceiling.
        let mut smalls: Vec<Message> = (0..25).map(|_| mk(&small)).collect();
        assert_eq!(evict(&mut smalls, None), 0);
        // One oversized image puts the strict 20 ceiling in force → one batch of 8 retires.
        let mut mixed: Vec<Message> = (0..25).map(|_| mk(&small)).collect();
        mixed[12] = mk(&big);
        assert_eq!(evict(&mut mixed, None), 8);
        assert!(matches!(&mixed[0].content[1], Block::Text { text } if text == RETIRED_PLACEHOLDER));
        assert!(matches!(&mixed[12].content[1], Block::Image { .. }), "newest survives");
    }

    #[test]
    fn evict_retires_oldest_tool_images_and_latches() {
        assert_eq!(max_side_from_data(&img(40)), Some(40));
        assert_eq!(max_side_from_data("data:image/png;base64,".to_string().as_str()), None);
        let mut msgs: Vec<Message> = (0..25).map(|i| carrier(&format!("t{i}"), 1)).collect();
        // A user upload is reserved, never rewritten.
        msgs.insert(0, Message { role: Role::User, content: vec![Block::text("look"), Block::Image { media_type: "image/png".into(), data: img(10) }] });
        let mut latch = HashSet::new();
        // Small images: the hard 100 ceiling applies, nothing to do.
        assert_eq!(evict(&mut msgs.clone(), Some(&mut latch)), 0);
        // An unmeasurable image keeps the strict 20 ceiling live.
        msgs.push(Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "big".into(), content: String::new(), is_error: false }, Block::Image { media_type: "image/png".into(), data: "AAAA".into() }] });
        let mut copy = msgs.clone();
        let n = evict(&mut copy, Some(&mut latch));
        assert_eq!(n, 8);
        assert!(matches!(copy[0].content[1], Block::Image { .. }), "upload kept");
        assert!(matches!(&copy[1].content[1], Block::Text { text } if text == RETIRED_PLACEHOLDER));
        assert!(latch.contains("t0") && latch.contains("t7") && !latch.contains("t8"));
        // Latched: a later request that would fit still keeps those retired.
        let mut fewer: Vec<Message> = msgs.iter().take(26).cloned().collect();
        assert_eq!(evict(&mut fewer, Some(&mut latch)), 8);
    }
}
