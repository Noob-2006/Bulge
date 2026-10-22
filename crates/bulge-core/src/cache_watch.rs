//! Prefix-cache break detection.
//!
//! Every request the driver (and its side calls) sends should extend the
//! previous one byte-for-byte; the provider then reports nearly the whole
//! previous prompt as cache hits. [`CacheWatch`] fingerprints each request,
//! compares it with its predecessor, and when the reported cache hits fall well
//! short of what an intact prefix should have earned, names the cause: the
//! system prompt changed, the tool list changed, a specific earlier message was
//! rewritten (e.g. by pruning or compaction), messages were dropped — or nothing
//! changed on our side (provider eviction or a cache not yet written).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use bulge_llm::{ContentBlock, GenerateRequest, Message, TokenUsage};

/// A drop smaller than this many tokens is never reported (cache granularity
/// and rounding are tens of tokens; small dips are noise).
const MIN_LOSS_TOKENS: u64 = 512;
/// Report only when hits fall below this fraction of the expected prefix.
const MIN_HIT_FRACTION: f64 = 0.9;
/// Recent requests remembered as possible cache anchors.
const ANCHORS: usize = 6;

/// Why a request lost (part of) the cached prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakCause {
    /// The system prompt bytes differ from the previous request.
    SystemChanged,
    /// The tool list differs (added, removed, reordered, or a schema changed).
    ToolsChanged,
    /// Message `index` (0 = first after the system prompt) differs. `pruned`
    /// is true when the new copy carries a pruning marker (a declared rewrite).
    MessageRewritten { index: usize, role: String, pruned: bool },
    /// The request is shorter than its predecessor (e.g. a compaction replaced
    /// earlier messages with a summary).
    MessagesDropped { before: usize, after: usize },
    /// The request extends its predecessor exactly; the provider still missed
    /// (evicted, not yet stored, or a concurrent request raced it).
    Provider,
}

impl BreakCause {
    /// A short machine-friendly tag (logged as the event's `cause`).
    pub fn tag(&self) -> &'static str {
        match self {
            BreakCause::SystemChanged => "system_changed",
            BreakCause::ToolsChanged => "tools_changed",
            BreakCause::MessageRewritten { pruned: true, .. } => "pruned",
            BreakCause::MessageRewritten { .. } => "message_rewritten",
            BreakCause::MessagesDropped { .. } => "messages_dropped",
            BreakCause::Provider => "provider",
        }
    }

    /// A one-line human explanation.
    pub fn describe(&self) -> String {
        match self {
            BreakCause::SystemChanged => "system prompt changed since the previous request".into(),
            BreakCause::ToolsChanged => "tool list changed since the previous request".into(),
            BreakCause::MessageRewritten { index, role, pruned: true } => {
                format!("message #{index} ({role}) was trimmed by pruning")
            }
            BreakCause::MessageRewritten { index, role, .. } => format!("message #{index} ({role}) was rewritten"),
            BreakCause::MessagesDropped { before, after } => {
                format!("history shrank from {before} to {after} messages (compaction?)")
            }
            BreakCause::Provider => "request extended the previous one exactly; provider-side miss".into(),
        }
    }
}

/// One detected break.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheBreak {
    /// Prompt tokens of the previous request (what an intact prefix would hit).
    pub expected: u64,
    /// Cache hits the provider actually reported.
    pub cached: u64,
    pub cause: BreakCause,
}

/// What [`CacheWatch`] remembers about one request. Take it with
/// [`fingerprint`] before the request is sent, record it with the usage after.
#[derive(Debug, Clone)]
pub struct Fingerprint {
    system: u64,
    tools: u64,
    /// Per-message digests, excluding the leading system message.
    messages: Vec<u64>,
    roles: Vec<String>,
    /// Whether each message carries a pruning marker (a declared rewrite).
    pruned: Vec<bool>,
}

/// Tracks the recent requests of one conversation.
#[derive(Debug, Default)]
pub struct CacheWatch {
    /// Most recent last: (fingerprint, prompt tokens it was billed for).
    anchors: Vec<(Fingerprint, u64)>,
}

impl CacheWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `request` with the `usage` it got back; returns a break when the
    /// cache hits fell materially short of the previous request's prompt.
    pub fn observe(&mut self, request: &GenerateRequest, usage: &TokenUsage) -> Option<CacheBreak> {
        self.record(fingerprint(request), usage)
    }

    /// [`Self::observe`] for a request already moved into the backend.
    ///
    /// The expectation is the previous request's prompt when this request extends
    /// it. When only the previous request's *final* message differs, the two are
    /// siblings branching off a shared prefix (e.g. successive post-job prompts):
    /// that is by design, so the expectation falls back to the largest recent
    /// request that this one does extend.
    pub fn record(&mut self, current: Fingerprint, usage: &TokenUsage) -> Option<CacheBreak> {
        let prompt = usage.input_tokens + usage.cache_read_tokens;
        let verdict = self.anchors.last().and_then(|(previous, previous_prompt)| {
            let cause = diagnose(previous, &current);
            let sibling = matches!(cause, BreakCause::MessageRewritten { index, .. } if index + 1 == previous.messages.len());
            let (expected, cause) = if cause == BreakCause::Provider {
                (*previous_prompt, cause)
            } else if sibling {
                let base = self.anchors.iter().filter(|(a, _)| extends(&current, a)).map(|(_, p)| *p).max()?;
                (base, BreakCause::Provider)
            } else {
                (*previous_prompt, cause)
            };
            let shortfall = expected.saturating_sub(usage.cache_read_tokens);
            let material = shortfall >= MIN_LOSS_TOKENS && (usage.cache_read_tokens as f64) < expected as f64 * MIN_HIT_FRACTION;
            material.then_some(CacheBreak { expected, cached: usage.cache_read_tokens, cause })
        });
        // A usage with no prompt accounting (errored call) is not an anchor.
        if prompt > 0 {
            if self.anchors.len() == ANCHORS {
                self.anchors.remove(0);
            }
            self.anchors.push((current, prompt));
        }
        verdict
    }
}

/// Find the first difference between two consecutive requests.
fn diagnose(previous: &Fingerprint, current: &Fingerprint) -> BreakCause {
    if previous.system != current.system {
        return BreakCause::SystemChanged;
    }
    if previous.tools != current.tools {
        return BreakCause::ToolsChanged;
    }
    if let Some(index) = previous.messages.iter().zip(&current.messages).position(|(a, b)| a != b) {
        return BreakCause::MessageRewritten { index, role: current.roles[index].clone(), pruned: current.pruned[index] };
    }
    if current.messages.len() < previous.messages.len() {
        return BreakCause::MessagesDropped { before: previous.messages.len(), after: current.messages.len() };
    }
    BreakCause::Provider
}

/// Whether `current` is `anchor` plus zero or more appended messages.
fn extends(current: &Fingerprint, anchor: &Fingerprint) -> bool {
    current.system == anchor.system
        && current.tools == anchor.tools
        && current.messages.len() >= anchor.messages.len()
        && current.messages[..anchor.messages.len()] == anchor.messages[..]
}

fn is_system(message: &Message) -> bool {
    message.role == bulge_llm::Role::System
}

/// Fingerprint a request (cheap: one digest per message).
pub fn fingerprint(request: &GenerateRequest) -> Fingerprint {
    let mut messages = request.messages.iter();
    let system = match request.messages.first() {
        Some(first) if is_system(first) => {
            messages.next();
            digest(first)
        }
        _ => 0,
    };
    let rest: Vec<&Message> = messages.collect();
    Fingerprint {
        system,
        tools: digest(&request.tools),
        messages: rest.iter().map(digest).collect(),
        roles: rest.iter().map(|m| serde_json::to_value(m.role).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()).collect(),
        pruned: rest
            .iter()
            .map(|m| m.content.iter().any(|b| matches!(b, ContentBlock::Text { text } if text.contains(crate::context::PRUNE_MARKER_TAIL))))
            .collect(),
    }
}

/// Stable digest of a value's serialized form. `DefaultHasher::new()` uses fixed
/// keys, so digests are comparable across requests within a process.
fn digest<T: serde::Serialize>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    serde_json::to_string(value).unwrap_or_default().hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulge_llm::{Purpose, Role, ToolSchema};

    fn request(system: &str, tools: usize, messages: Vec<Message>) -> GenerateRequest {
        let mut all = vec![Message::text(Role::System, system)];
        all.extend(messages);
        GenerateRequest {
            model: "m".into(),
            messages: all,
            tools: (0..tools)
                .map(|i| ToolSchema { name: format!("t{i}"), description: "d".into(), parameters: serde_json::json!({}), defer_loading: false })
                .collect(),
            max_tokens: None,
            temperature: None,
            stop: Vec::new(),
            reasoning_effort: None,
            purpose: Purpose::Conversation,
        }
    }

    fn usage(miss: u64, hit: u64) -> TokenUsage {
        TokenUsage { input_tokens: miss, cache_read_tokens: hit, ..Default::default() }
    }

    fn user(text: &str) -> Message {
        Message::text(Role::User, text)
    }

    #[test]
    fn an_intact_extension_with_full_hits_is_quiet() {
        let mut watch = CacheWatch::new();
        assert_eq!(watch.observe(&request("s", 2, vec![user("a")]), &usage(4000, 0)), None, "first request has nothing to compare");
        assert_eq!(watch.observe(&request("s", 2, vec![user("a"), user("b")]), &usage(300, 3968)), None);
    }

    #[test]
    fn each_cause_is_named() {
        let base = || vec![user("a"), Message::tool_result("c1", "long output", false), user("recent")];
        let cases = [
            (request("s2", 2, base()), BreakCause::SystemChanged),
            (request("s", 3, base()), BreakCause::ToolsChanged),
            (
                request("s", 2, vec![user("a"), Message::tool_result("c1", "long\n[... 9 chars pruned ...]\nput", false), user("recent")]),
                BreakCause::MessageRewritten { index: 1, role: "tool".into(), pruned: true },
            ),
            (request("s", 2, vec![user("summary")]), BreakCause::MessageRewritten { index: 0, role: "user".into(), pruned: false }),
            (request("s", 2, vec![user("a")]), BreakCause::MessagesDropped { before: 3, after: 1 }),
            (request("s", 2, { let mut m = base(); m.push(user("next")); m }), BreakCause::Provider),
        ];
        for (next, cause) in cases {
            let mut watch = CacheWatch::new();
            watch.observe(&request("s", 2, base()), &usage(5000, 0));
            let found = watch.observe(&next, &usage(5000, 128)).expect("a material drop is reported");
            assert_eq!(found, CacheBreak { expected: 5000, cached: 128, cause });
        }
    }

    #[test]
    fn sibling_branches_off_a_shared_prefix_are_not_breaks() {
        let shared = || vec![user("task"), user("reply")];
        let with = |last: &str| request("s", 2, { let mut m = shared(); m.push(user(last)); m });
        let mut watch = CacheWatch::new();
        watch.observe(&request("s", 2, shared()), &usage(4000, 0));
        watch.observe(&with("extract lessons"), &usage(500, 3968));
        // Second post-job prompt: replaces the first one's final message.
        assert_eq!(watch.observe(&with("update the profile"), &usage(500, 3968)), None);
        // …but losing the shared base too is still reported (as a provider miss).
        let found = watch.observe(&with("propose a skill"), &usage(4400, 128)).expect("base lost");
        assert_eq!((found.expected, found.cause), (4000, BreakCause::Provider));
    }

    #[test]
    fn small_or_proportionally_minor_drops_are_ignored() {
        let mut watch = CacheWatch::new();
        watch.observe(&request("s", 2, vec![user("a")]), &usage(3000, 0));
        // 2900 of 3000 hit: within granularity.
        assert_eq!(watch.observe(&request("s2", 2, vec![user("a")]), &usage(100, 2900)), None);
        // A tiny prompt can never lose a material amount.
        let mut small = CacheWatch::new();
        small.observe(&request("s", 2, vec![user("a")]), &usage(300, 0));
        assert_eq!(small.observe(&request("s2", 2, vec![user("a")]), &usage(300, 0)), None);
    }
}
