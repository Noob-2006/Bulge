//! Reasoning ("thinking") levels across providers. One canonical ladder (Hermes
//! `agent/reasoning_effort.py` EFFORT_LADDER; OpenClaw `thinking.shared.ts` levels),
//! user spellings normalised, and clamping to what each wire accepts: the level
//! verbatim when supported, else the nearest *weaker* one, else the weakest offered.

/// Weakest → strongest. `off` disables reasoning where the wire can.
pub const LADDER: &[&str] = &["off", "minimal", "low", "medium", "high", "xhigh", "max"];

/// OpenAI-compatible chat servers (OpenRouter, DeepSeek, vLLM…): the widest set.
pub const CHAT_WIRE: &[&str] = &["off", "minimal", "low", "medium", "high", "xhigh", "max"];
/// OpenAI / Codex Responses: no `minimal`; `max` only on the newest tiers (configurable).
pub const RESPONSES_WIRE: &[&str] = &["off", "low", "medium", "high", "xhigh"];
/// xAI Grok.
pub const XAI_WIRE: &[&str] = &["low", "medium", "high"];
/// Budget-based wires (Anthropic, Gemini, Bedrock): every level maps to a token budget.
pub const BUDGET_WIRE: &[&str] = LADDER;
/// Claude 4.6+ / 5.x: `thinking: {type: "adaptive"}` + `output_config.effort`; budgets are
/// rejected (400) and newer models cannot turn thinking off, so `off` clamps to `low`.
pub const ADAPTIVE_WIRE: &[&str] = &["low", "medium", "high", "xhigh", "max"];

/// Claude models that take adaptive thinking instead of `budget_tokens`: 4.6 and later,
/// every 5.x and Fable/Mythos model. Accepts provider prefixes (`anthropic/`, Bedrock
/// `anthropic.`, `us.anthropic.`) and date suffixes.
pub fn claude_adaptive(model: &str) -> bool {
    let m = model.rsplit('/').next().unwrap_or(model);
    let m = m.rsplit_once("anthropic.").map(|(_, r)| r).unwrap_or(m);
    if m.starts_with("claude-fable") || m.starts_with("claude-mythos") {
        return true;
    }
    if !m.starts_with("claude-") {
        return false;
    }
    let mut nums = m
        .split(['-', '@', ':'])
        .filter_map(|p| p.parse::<u32>().ok())
        .filter(|n| *n < 100);
    match (nums.next(), nums.next()) {
        (Some(major), _) if major >= 5 => true,
        (Some(4), Some(minor)) => minor >= 6,
        _ => false,
    }
}

/// Canonical level for a user spelling, or None when unknown. `default`/`inherit`/
/// `clear` → `Some("")` (clear the session override).
pub fn normalize(raw: &str) -> Option<&'static str> {
    let k = raw.trim().to_lowercase();
    let collapsed: String = k
        .chars()
        .filter(|c| !matches!(c, ' ' | '_' | '-'))
        .collect();
    Some(match collapsed.as_str() {
        "" | "default" | "inherit" | "inherited" | "clear" | "reset" | "unpin" => "",
        "off" | "none" | "no" | "false" | "0" | "disable" | "disabled" => "off",
        "minimal" | "min" | "think" => "minimal",
        "low" | "on" | "enable" | "enabled" | "thinkhard" => "low",
        "medium" | "mid" | "med" | "thinkharder" | "harder" | "adaptive" | "auto" => "medium",
        "high" | "ultrathink" | "thinkhardest" | "highest" => "high",
        "xhigh" | "extrahigh" => "xhigh",
        "max" | "maximum" | "ultra" => "max",
        _ => return None,
    })
}

fn rank(l: &str) -> Option<usize> {
    LADDER.iter().position(|x| *x == l)
}

/// Clamp `level` to `allowed` (in any order). None when nothing is sendable or
/// the level is unknown.
pub fn clamp<'a>(level: &str, allowed: &[&'a str]) -> Option<&'a str> {
    let want = rank(normalize(level).filter(|l| !l.is_empty())?)?;
    if let Some(a) = allowed.iter().find(|a| rank(a) == Some(want)) {
        return Some(a);
    }
    let weaker = allowed
        .iter()
        .filter_map(|a| rank(a).map(|r| (r, *a)))
        .filter(|(r, _)| *r < want)
        .max_by_key(|(r, _)| *r);
    if let Some((r, a)) = weaker {
        // Never turn a request for reasoning into "off" just because the next weaker is off.
        if r > 0 || want == 0 {
            return Some(a);
        }
    }
    if want == 0 {
        // "off" on a wire that cannot disable reasoning: send nothing.
        return None;
    }
    allowed
        .iter()
        .filter_map(|a| rank(a).map(|r| (r, *a)))
        .filter(|(r, _)| *r > 0)
        .min_by_key(|(r, _)| *r)
        .map(|(_, a)| a)
}

/// Thinking token budget for budget-based wires (None = off / provider default).
pub fn budget(level: &str) -> Option<u32> {
    match normalize(level)? {
        "minimal" => Some(1024),
        "low" => Some(2048),
        "medium" => Some(8192),
        "high" => Some(24576),
        "xhigh" => Some(32768),
        "max" => Some(63999),
        _ => None,
    }
}

/// The values `/think` accepts, for help text.
pub fn help() -> String {
    LADDER.join("|")
}

// ───────────────────────── capability detection ─────────────────────────
//
// Which optional reasoning parameter an endpoint accepts is derived from metadata, never from
// a hardcoded list of model ids: (a) explicit metadata (models.dev `reasoning`, the provider
// preset's wire format) when present, (b) the family and version number a release id belongs
// to, so a new model of a known family needs no code change, (c) nothing at all for ids we do
// not recognise. An unknown parameter is a 400; an omitted one never is.

/// Model family: decides what an unrecognised release id falls back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Anthropic,
    OpenAi,
    Xai,
    Gemini,
    DeepSeek,
    Unknown,
}

/// The wire shape of the optional reasoning parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Anthropic ≤4.5 / Bedrock: `thinking: {type: "enabled", budget_tokens}`.
    Budget,
    /// Claude 4.6+/5.x: `thinking: {type: "adaptive"}` + `output_config.effort`.
    Adaptive,
    /// OpenAI-compatible chat: `reasoning_effort: "<level>"`.
    Effort,
    /// OpenAI / xAI Responses: `reasoning: {effort, summary}`.
    ResponsesEffort,
    /// Gemini: `generationConfig.thinkingConfig.thinkingBudget`.
    ThinkingConfig,
    /// Nothing is sendable for this model: omit the parameter entirely.
    None,
}

impl Shape {
    /// The request field this shape writes (`""` when nothing is sent), for logs and errors.
    pub fn parameter(self) -> &'static str {
        match self {
            Shape::Budget => "thinking.budget_tokens",
            Shape::Adaptive => "thinking.adaptive+output_config.effort",
            Shape::Effort => "reasoning_effort",
            Shape::ResponsesEffort => "reasoning.effort",
            Shape::ThinkingConfig => "generationConfig.thinkingConfig",
            Shape::None => "",
        }
    }

    /// Whether `temperature` may still be sent next to the reasoning parameter. Anthropic
    /// thinking (budget and adaptive) rejects it; Gemini and the OpenAI families take both.
    /// Unchanged from the per-adapter rules these shapes were extracted from.
    pub fn sends_temperature(self) -> bool {
        !matches!(self, Shape::Budget | Shape::Adaptive)
    }
}

/// Where a [`Support`] verdict came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A metadata field said so (models.dev capability, endpoint dialect, provider family).
    Metadata,
    /// Derived from the model id's family and version number.
    Family,
    /// Nothing recognised it: no optional parameter is safe to send.
    Unknown,
}

/// Explicit metadata for one model. Every field is optional; absent fields fall through to
/// family derivation. `family`/`shape` normally come from the provider preset, `reasoning`
/// from models.dev (via `modelsdb::registry_entry`), and `shape` may be overridden by the
/// adapter that owns the endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hints {
    pub family: Option<Family>,
    pub shape: Option<Shape>,
    /// models.dev `reasoning`: `Some(false)` suppresses every optional parameter.
    pub reasoning: Option<bool>,
}

/// What a model accepts: the shape, the levels it allows and whether this was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Support {
    pub family: Family,
    pub shape: Shape,
    /// Levels the shape accepts, weakest → strongest (`&[]` when nothing is sent).
    pub levels: &'static [&'static str],
    pub origin: Origin,
}

impl Support {
    fn new(family: Family, shape: Shape, origin: Origin) -> Support {
        Support {
            family,
            shape,
            levels: levels(family, shape),
            origin,
        }
    }

    /// False when nothing recognised the model: a caller should retry once without the
    /// reasoning parameter if the first request came back 400.
    pub fn verified(self) -> bool {
        self.origin != Origin::Unknown
    }

    /// Opposite of [`Support::verified`], for the retry-once-without-parameters path.
    pub fn unverified(self) -> bool {
        !self.verified()
    }

    /// Whether any optional reasoning parameter may be sent at all.
    pub fn sends_reasoning(self) -> bool {
        self.shape != Shape::None
    }

    /// Whether `temperature` may be sent next to the reasoning parameter.
    pub fn sends_temperature(self) -> bool {
        self.shape.sends_temperature()
    }
}

/// [`detect_with`] without metadata: id-only detection.
pub fn detect(model: &str) -> Support {
    detect_with(model, None)
}

/// The reasoning parameter a model accepts, metadata first, family derivation second, and
/// nothing (flagged [`Origin::Unknown`]) when both miss. Never guesses a parameter for an id
/// it cannot place, so a freshly released model cannot 400 on an unsupported field.
pub fn detect_with(model: &str, hints: Option<&Hints>) -> Support {
    let h = hints.copied().unwrap_or_default();
    let family = h.family.unwrap_or_else(|| family_of(model));
    let derived = shape_of(family, model);

    // (a) models.dev capability: it decides, even against the id's family.
    if h.reasoning == Some(false) {
        return Support::new(family, Shape::None, Origin::Metadata);
    }
    if h.reasoning == Some(true) {
        // Capable: trust the endpoint's shape, else the family's, else send nothing.
        let shape = h.shape.filter(|s| *s != Shape::None).unwrap_or(derived);
        return Support::new(family, shape, Origin::Metadata);
    }

    // (b) family + version derivation. An endpoint hint only swaps the dialect
    // (`reasoning_effort` ↔ `reasoning.effort`); it never turns a Claude id into an
    // OpenAI-style parameter just because a gateway speaks that dialect.
    if derived != Shape::None {
        let shape = h
            .shape
            .filter(|s| same_dialect(*s, derived))
            .unwrap_or(derived);
        return Support::new(family, shape, Origin::Family);
    }

    // (c) nothing recognised: no optional parameter, and say so.
    let origin = match family {
        Family::Unknown => Origin::Unknown,
        _ => Origin::Family,
    };
    Support::new(family, Shape::None, origin)
}

fn levels(family: Family, shape: Shape) -> &'static [&'static str] {
    match shape {
        Shape::Adaptive => ADAPTIVE_WIRE,
        Shape::Budget | Shape::ThinkingConfig => BUDGET_WIRE,
        Shape::Effort if family == Family::Xai => XAI_WIRE,
        Shape::Effort => CHAT_WIRE,
        Shape::ResponsesEffort => RESPONSES_WIRE,
        Shape::None => &[],
    }
}

/// Shapes that differ only in the endpoint dialect (same model-family reasoning model), so a
/// provider hint may swap one for the other but not across families.
fn same_dialect(a: Shape, b: Shape) -> bool {
    let dialect = |s: Shape| match s {
        Shape::Budget | Shape::Adaptive => 1,
        Shape::Effort | Shape::ResponsesEffort => 2,
        Shape::ThinkingConfig => 3,
        Shape::None => 0,
    };
    a == b || (dialect(a) == dialect(b) && dialect(a) != 0)
}

/// The family a provider is known by, from seagent preset ids (`anthropic`, `openai-chat`,
/// `gemini`, `xai`, `deepseek`…) or models.dev provider ids (`google`, `openai`, `xai`…).
/// Cloud resellers (`bedrock`, `vertex`, `openrouter`) serve several families: they return
/// `None` so the model id decides.
pub fn family_from_provider(id: &str) -> Option<Family> {
    let id = id.trim().to_lowercase();
    if id.starts_with("anthropic") || id.starts_with("claude") {
        return Some(Family::Anthropic);
    }
    if id.starts_with("openai")
        || id.starts_with("codex")
        || id == "chatgpt"
        || id == "azure"
        || id.starts_with("azure-")
    {
        return Some(Family::OpenAi);
    }
    if id.starts_with("xai") || id == "grok" {
        return Some(Family::Xai);
    }
    if id.starts_with("gemini") || id == "google" || id.starts_with("google-") {
        return Some(Family::Gemini);
    }
    if id.starts_with("deepseek") {
        return Some(Family::DeepSeek);
    }
    None
}

/// Family from a model id alone: prefix/segment match, independent of the version number.
pub fn family_of(model: &str) -> Family {
    let m = canonical(model);
    if m.starts_with("claude")
        || matches!(m.as_str(), "sonnet" | "opus" | "haiku" | "fable" | "mythos")
    {
        return Family::Anthropic;
    }
    if m.starts_with("gemini") {
        return Family::Gemini;
    }
    if m.starts_with("grok") {
        return Family::Xai;
    }
    if m.contains("deepseek") {
        return Family::DeepSeek;
    }
    if m.starts_with("gpt") || m.starts_with("chatgpt") || m.starts_with("codex") || o_series(&m) {
        return Family::OpenAi;
    }
    Family::Unknown
}

/// The reasoning parameter an id of `family` uses, from its version number: a new release of
/// a known family needs no edit, an unrecognised id of that family still gets `None`.
pub fn shape_of(family: Family, model: &str) -> Shape {
    let m = canonical(model);
    match family {
        // Budget thinking up to 4.5; 4.6+, every 5.x and Fable/Mythos take adaptive thinking.
        Family::Anthropic => {
            if claude_adaptive(&m) || matches!(m.as_str(), "sonnet" | "opus" | "haiku") {
                Shape::Adaptive
            } else {
                Shape::Budget
            }
        }
        // thinkingConfig from 2.5 on (and every later major); gemini 1.x/2.0 take none.
        Family::Gemini => {
            if version_at_least(&m, "gemini-", 2, 5) || m.contains("thinking") {
                Shape::ThinkingConfig
            } else {
                Shape::None
            }
        }
        Family::Xai => Shape::Effort,
        Family::DeepSeek => Shape::Effort,
        Family::OpenAi => {
            if openai_reasoning(&m) {
                Shape::Effort
            } else {
                Shape::None
            }
        }
        Family::Unknown => Shape::None,
    }
}

/// Provider/Bedrock-agnostic form of a model id: lowercase, last path segment, no
/// `us.`/`anthropic.`/`amazon.`/`meta.` decoration, no `:0` / `@date` suffix.
fn canonical(model: &str) -> String {
    let mut m = model.trim().to_lowercase();
    if let Some((_, last)) = m.rsplit_once('/') {
        m = last.to_string();
    }
    for p in ["us.", "eu.", "apac.", "global."] {
        if let Some(r) = m.strip_prefix(p) {
            if r.starts_with("anthropic.") || r.starts_with("amazon.") || r.starts_with("meta.") {
                m = r.to_string();
            }
        }
    }
    for p in ["anthropic.", "amazon.", "meta."] {
        if let Some(i) = m.find(p) {
            m = m[i + p.len()..].to_string();
            break;
        }
    }
    m.split(['@', ':']).next().unwrap_or("").to_string()
}

/// `o1`/`o3`/`o4`… reasoning series (but not `opus`, `o200k`).
fn o_series(m: &str) -> bool {
    let b = m.as_bytes();
    b.len() >= 2
        && b[0] == b'o'
        && b[1].is_ascii_digit()
        && (b.len() == 2 || !b[2].is_ascii_alphanumeric())
}

/// OpenAI reasoning tiers: `gpt-5` and later, the `o*` series and codex models; `gpt-4o` and
/// older take no reasoning parameter.
fn openai_reasoning(m: &str) -> bool {
    m.contains("codex")
        || o_series(m)
        || (m.starts_with("gpt-") && version_at_least(m, "gpt-", 5, 0))
}

/// True when `m` is `<prefix><major>[.<minor>]…` with a version at least `major.minor`.
fn version_at_least(m: &str, prefix: &str, major: u32, minor: u32) -> bool {
    let Some(rest) = m.strip_prefix(prefix) else {
        return false;
    };
    match parse_version(rest) {
        (Some(v), _) if v != major => v > major,
        (Some(_), min) => min.unwrap_or(0) >= minor,
        (None, _) => false,
    }
}

/// Leading `major[.minor]` of a version string.
fn parse_version(s: &str) -> (Option<u32>, Option<u32>) {
    let num = |t: &str| t.parse::<u32>().ok();
    let n = s.chars().take_while(|c| c.is_ascii_digit()).count();
    let major = num(&s[..n]);
    let minor = s[n..].strip_prefix('.').and_then(|r| {
        let k = r.chars().take_while(|c| c.is_ascii_digit()).count();
        num(&r[..k])
    });
    (major, minor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings() {
        assert_eq!(normalize("Think Harder"), Some("medium"));
        assert_eq!(normalize("ultrathink"), Some("high"));
        assert_eq!(normalize("x-high"), Some("xhigh"));
        assert_eq!(normalize("none"), Some("off"));
        assert_eq!(normalize("inherit"), Some(""));
        assert_eq!(normalize("loud"), None);
    }

    #[test]
    fn clamping_prefers_weaker_never_off() {
        assert_eq!(
            clamp("minimal", RESPONSES_WIRE),
            Some("low"),
            "no weaker non-off level: weakest supported"
        );
        assert_eq!(clamp("max", RESPONSES_WIRE), Some("xhigh"));
        assert_eq!(clamp("xhigh", XAI_WIRE), Some("high"));
        assert_eq!(
            clamp("off", XAI_WIRE),
            None,
            "xAI cannot disable: send nothing"
        );
        assert_eq!(clamp("off", RESPONSES_WIRE), Some("off"));
        assert_eq!(clamp("medium", &["high", "max"]), Some("high"));
        assert_eq!(clamp("high", CHAT_WIRE), Some("high"));
        assert_eq!(clamp("bogus", CHAT_WIRE), None);
    }

    #[test]
    fn budgets_rise_with_level() {
        let b: Vec<u32> = ["minimal", "low", "medium", "high", "xhigh", "max"]
            .iter()
            .map(|l| budget(l).unwrap())
            .collect();
        assert!(b.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(budget("off"), None);
    }
}

#[cfg(test)]
mod adaptive_tests {
    use super::claude_adaptive;

    #[test]
    fn adaptive_only_for_claude_4_6_and_later() {
        for m in [
            "claude-opus-5-5",
            "anthropic/claude-sonnet-5-5",
            "claude-haiku-5-5",
            "claude-fable-5-1",
            "claude-opus-4-6",
            "anthropic.claude-opus-5-5",
            "us.anthropic.claude-sonnet-4-6",
        ] {
            assert!(claude_adaptive(m), "{m}");
        }
        for m in [
            "claude-haiku-4-5",
            "claude-sonnet-4-5-20250929",
            "claude-3-7-sonnet-20250219",
            "claude-opus-4-1",
            "claude-sonnet-4-20250514",
            "claude-opus-4-5@20251101",
            "gpt-5.5",
        ] {
            assert!(!claude_adaptive(m), "{m}");
        }
    }
}

#[cfg(test)]
mod detect_tests {
    use super::*;

    #[test]
    fn reasoning_unknown_future_id_of_known_family_keeps_family_shape() {
        // Nobody has added these ids; the family + version derivation is what answers.
        for m in [
            "claude-opus-6-7",
            "claude-sonnet-9-2-20270101",
            "anthropic/claude-haiku-7",
        ] {
            let s = detect(m);
            assert_eq!(s.family, Family::Anthropic, "{m}");
            assert_eq!(s.shape, Shape::Adaptive, "{m}");
            assert_eq!(s.levels, ADAPTIVE_WIRE, "{m}");
            assert!(s.verified() && s.sends_reasoning(), "{m}");
        }
        assert_eq!(detect("claude-opus-3-5").shape, Shape::Budget);
        assert_eq!(detect("gpt-5.9-turbo").shape, Shape::Effort);
        assert_eq!(detect("gpt-6").shape, Shape::Effort);
        assert_eq!(detect("o5-mini").shape, Shape::Effort);
        assert_eq!(detect("gemini-4.0-pro").shape, Shape::ThinkingConfig);
    }

    #[test]
    fn reasoning_unknown_model_gets_no_parameter_and_is_unverified() {
        for m in ["acme-neo-9000", "llama-9-ultra", "qwen9-max", "sonar-9"] {
            let s = detect(m);
            assert_eq!(s.family, Family::Unknown, "{m}");
            assert_eq!(s.shape, Shape::None, "{m}");
            assert!(!s.sends_reasoning(), "{m}: must not send a parameter");
            assert_eq!(s.shape.parameter(), "", "{m}");
            assert!(s.levels.is_empty(), "{m}");
            assert!(
                s.unverified(),
                "{m}: caller must be able to retry without params"
            );
            assert_eq!(s.origin, Origin::Unknown, "{m}");
        }
    }

    #[test]
    fn reasoning_metadata_beats_prefix_guessing() {
        // models.dev says this id is a reasoning model and the endpoint speaks
        // `reasoning_effort`: that wins over the `claude-` prefix.
        let gateway = Hints {
            family: Some(Family::OpenAi),
            shape: Some(Shape::Effort),
            reasoning: Some(true),
        };
        let s = detect_with("claude-opus-9-1", Some(&gateway));
        assert_eq!(s.shape, Shape::Effort);
        assert_eq!(s.origin, Origin::Metadata);
        assert!(s.sends_reasoning());

        // models.dev says the model has no reasoning: no parameter, even for a Claude id.
        let plain = Hints {
            reasoning: Some(false),
            ..Default::default()
        };
        let s = detect_with("claude-opus-5-5", Some(&plain));
        assert_eq!(s.shape, Shape::None);
        assert_eq!(s.origin, Origin::Metadata);
        assert!(s.verified(), "metadata answered, nothing to retry");
    }

    #[test]
    fn reasoning_anthropic_ids_never_get_reasoning_effort() {
        for m in [
            "claude-opus-5-5",
            "claude-3-5-sonnet-20241022",
            "us.anthropic.claude-sonnet-4-6",
            "anthropic.claude-haiku-4-5",
            "sonnet",
        ] {
            let s = detect(m);
            assert_eq!(s.family, Family::Anthropic, "{m}");
            assert_ne!(s.shape, Shape::Effort, "{m}");
            assert_ne!(s.shape, Shape::ResponsesEffort, "{m}");
            assert_ne!(s.shape.parameter(), "reasoning_effort", "{m}");
        }
    }

    #[test]
    fn reasoning_gemini_ids_use_thinking_config() {
        let s = detect("gemini-2.5-pro");
        assert_eq!((s.family, s.shape), (Family::Gemini, Shape::ThinkingConfig));
        assert_eq!(s.shape.parameter(), "generationConfig.thinkingConfig");
        assert_eq!(s.levels, BUDGET_WIRE);
        assert_eq!(
            detect("gemini-2.0-flash-thinking-exp").shape,
            Shape::ThinkingConfig
        );
        assert_eq!(detect("gemini-1.5-pro").shape, Shape::None);
    }

    #[test]
    fn reasoning_openai_reasoning_tiers_get_effort() {
        for m in ["gpt-5", "gpt-5.5-codex", "o1", "o3-mini", "o4-mini"] {
            let s = detect(m);
            assert_eq!((s.family, s.shape), (Family::OpenAi, Shape::Effort), "{m}");
            assert_eq!(s.shape.parameter(), "reasoning_effort", "{m}");
        }
        for m in ["gpt-4o", "gpt-4.1", "gpt-4-turbo"] {
            let s = detect(m);
            assert_eq!(s.family, Family::OpenAi, "{m}");
            assert_eq!(
                s.shape,
                Shape::None,
                "{m}: pre-5 GPT takes no reasoning parameter"
            );
            assert!(!s.sends_reasoning(), "{m}");
        }
    }

    #[test]
    fn reasoning_temperature_suppression_follows_thinking() {
        for m in [
            "claude-opus-5-5",
            "claude-sonnet-4-5",
            "us.anthropic.claude-opus-4-5-20251101-v1:0",
        ] {
            assert!(
                !detect(m).sends_temperature(),
                "{m}: thinking rejects temperature"
            );
        }
        for m in ["gemini-2.5-pro", "gpt-5", "gpt-4o", "acme-neo-9000"] {
            assert!(detect(m).sends_temperature(), "{m}");
        }
    }

    #[test]
    fn reasoning_bedrock_and_prefixed_ids_resolve() {
        let s = detect("us.anthropic.claude-opus-4-5-20251101-v1:0");
        assert_eq!(s.family, Family::Anthropic);
        assert_eq!(s.shape, Shape::Budget, "4.5 still takes budget_tokens");
        let s = detect("anthropic/claude-sonnet-4-6");
        assert_eq!(s.shape, Shape::Adaptive);
        assert_eq!(detect("xai/grok-4").levels, XAI_WIRE);
    }

    #[test]
    fn reasoning_endpoint_hint_swaps_dialect_only() {
        // Same family, other dialect: the Responses wire wins over the chat default.
        let responses = Hints {
            shape: Some(Shape::ResponsesEffort),
            ..Default::default()
        };
        let s = detect_with("gpt-5.5", Some(&responses));
        assert_eq!(s.shape, Shape::ResponsesEffort);
        assert_eq!(s.levels, RESPONSES_WIRE);
        // Cross-family: a gateway speaking `reasoning_effort` must not rewrite a Claude id.
        let chat = Hints {
            shape: Some(Shape::Effort),
            ..Default::default()
        };
        let s = detect_with("claude-opus-5-5", Some(&chat));
        assert_eq!(
            s.shape,
            Shape::Adaptive,
            "model family wins over endpoint hint"
        );
    }
}
