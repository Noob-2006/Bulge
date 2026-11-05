//! `skills_search`: ranked lexical search over the skills this host offers (OpenClaw
//! `agents/installed-skill-catalog.ts` + `agents/tool-search-ranking.ts`, MIT).
//!
//! BM25 over name + description (weighted ×2) plus the SKILL.md body when it can be read
//! (bounded per skill so a huge reference set cannot stall a search), an exact-name hit first,
//! a short result list (default 5, at most 20) and a character budget. Only the eligible catalog
//! is searched — a skill whose requirements are unmet is not a result (upstream searches
//! "installed, eligible skills"); its metadata never enters the index.

use crate::skill::Skill;
use std::collections::HashMap;

/// OpenClaw limits.
pub const MAX_QUERY_CHARS: usize = 1_000;
pub const DEFAULT_LIMIT: usize = 5;
pub const MAX_RESULTS: usize = 20;
pub const MAX_DESCRIPTION_CHARS: usize = 512;
pub const MAX_RESULT_CHARS: usize = 16_000;
pub const MAX_BODY_BYTES: usize = 16 * 1024;
const BM25_K1: f64 = 1.2;
const BM25_B: f64 = 0.75;

/// Filler dropped from both sides; capability verbs ("get", "list") stay.
const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can", "do", "for", "from", "had", "has", "have",
    "here", "how", "i", "if", "in", "into", "is", "it", "its", "me", "my", "no", "not", "of", "on", "or", "our",
    "so", "that", "the", "their", "them", "then", "there", "these", "they", "this", "to", "up", "us", "was",
    "we", "were", "what", "when", "where", "which", "who", "why", "will", "with", "you", "your",
];

/// Words of a document: `snake_case` stays whole, `camelCase` parts are added, so
/// `gh-issues` matches `gh`, `issues` and `issue`.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
        if raw.is_empty() {
            continue;
        }
        for part in split_case(raw) {
            let lower = part.to_lowercase();
            if !STOPWORDS.contains(&lower.as_str()) {
                out.push(lower);
            }
        }
    }
    out
}

/// Split at a lowercase→uppercase (or digit→uppercase) boundary: `readFile` → `read`, `File`.
fn split_case(s: &str) -> Vec<&str> {
    let mut bounds = vec![0usize];
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    for w in chars.windows(2) {
        let (i, c) = w[0];
        let next = w[1].1;
        if next.is_uppercase() && (c.is_lowercase() || c.is_numeric()) {
            bounds.push(i + c.len_utf8());
        }
    }
    bounds.push(s.len());
    bounds.windows(2).map(|b| &s[b[0]..b[1]]).filter(|p| !p.is_empty()).collect()
}

/// Plural collapse only (`policies` → `policy`, `tools` → `tool`); full stemming would conflate.
fn stem(word: &str) -> String {
    if word.len() > 4 && word.ends_with("ies") {
        format!("{}y", &word[..word.len() - 3])
    } else if word.len() > 4 && word.ends_with('s') && !word.ends_with("ss") && !word.ends_with("us") {
        word[..word.len() - 1].to_string()
    } else {
        word.to_string()
    }
}

fn terms(text: &str) -> Vec<String> {
    tokenize(text).iter().map(|w| stem(w)).collect()
}

struct Index {
    /// term → (document, frequency)
    postings: HashMap<String, Vec<(usize, usize)>>,
    lengths: Vec<usize>,
    average: f64,
}

impl Index {
    fn build(documents: &[String]) -> Index {
        let mut postings: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        let mut lengths = Vec::with_capacity(documents.len());
        let mut total = 0usize;
        for (i, doc) in documents.iter().enumerate() {
            let t = terms(doc);
            lengths.push(t.len());
            total += t.len();
            let mut seen: HashMap<String, usize> = HashMap::new();
            for term in t {
                *seen.entry(term).or_insert(0) += 1;
            }
            for (term, n) in seen {
                postings.entry(term).or_default().push((i, n));
            }
        }
        let average = if documents.is_empty() { 0.0 } else { total as f64 / documents.len() as f64 };
        Index { postings, lengths, average }
    }

    /// Okapi BM25; idf from this index's own document count.
    fn score(&self, query: &[String]) -> Vec<(usize, f64)> {
        let n = self.lengths.len();
        if n == 0 || query.is_empty() {
            return Vec::new();
        }
        let mut scores: HashMap<usize, f64> = HashMap::new();
        for (term, weight) in query.iter().fold(HashMap::new(), |mut m: HashMap<&String, f64>, t| {
            *m.entry(t).or_insert(0.0) += 1.0;
            m
        }) {
            let Some(matches) = self.postings.get(term) else { continue };
            let df = matches.len() as f64;
            let idf = (1.0 + (n as f64 - df + 0.5) / (df + 0.5)).ln();
            for (doc, freq) in matches {
                let len = self.lengths[*doc] as f64;
                let norm = if self.average > 0.0 { len / self.average } else { 1.0 };
                let f = *freq as f64;
                let s = weight * (idf * (f * (BM25_K1 + 1.0))) / (f + BM25_K1 * (1.0 - BM25_B + BM25_B * norm));
                *scores.entry(*doc).or_insert(0.0) += s;
            }
        }
        let mut v: Vec<(usize, f64)> = scores.into_iter().filter(|(_, s)| *s > 0.0).collect();
        v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));
        v
    }
}

/// One search result (`{name, description, location}`, OpenClaw).
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub name: String,
    pub description: String,
    pub location: String,
}

/// First `MAX_BODY_BYTES` of the body (frontmatter dropped, cut on a char boundary).
fn body_prefix(sk: &Skill) -> String {
    let Ok(bytes) = std::fs::read(&sk.file) else { return String::new() };
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_BODY_BYTES * 2)]);
    let body = crate::yaml::frontmatter(&text).1;
    let mut cut = body.len().min(MAX_BODY_BYTES);
    while cut < body.len() && !body.is_char_boundary(cut) {
        cut += 1;
    }
    body[..cut].to_string()
}

/// Rank the catalog for `query`. `(hits, has_more)`; errors are the upstream input messages.
pub fn search(cat: &[Skill], query: &str, limit: Option<usize>) -> Result<(Vec<Hit>, bool), String> {
    let needle = query.trim();
    if needle.is_empty() || needle.chars().count() > MAX_QUERY_CHARS {
        return Err(format!("query must contain 1-{MAX_QUERY_CHARS} characters."));
    }
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_RESULTS {
        return Err(format!("limit must be an integer between 1 and {MAX_RESULTS}."));
    }
    // Metadata at double weight, then the body: a name/description hit should beat an incidental
    // mention deep in one skill's procedure (upstream `score * 2`).
    let meta: Vec<String> = cat.iter().map(|s| format!("{} {}", s.name, s.description)).collect();
    let bodies: Vec<String> = cat.iter().map(body_prefix).collect();
    let meta_index = Index::build(&meta);
    let body_index = Index::build(&bodies);
    let q = terms(needle);
    let mut scores: Vec<(usize, f64)> = meta_index.score(&q).into_iter().map(|(i, s)| (i, s * 2.0)).collect();
    let mut by_doc: HashMap<usize, f64> = scores.drain(..).collect();
    for (i, s) in body_index.score(&q) {
        *by_doc.entry(i).or_insert(0.0) += s;
    }
    let exact = cat
        .iter()
        .position(|s| s.name == needle)
        .or_else(|| cat.iter().position(|s| s.name.eq_ignore_ascii_case(needle)));
    let mut ranked: Vec<(usize, f64)> = by_doc.into_iter().collect();
    ranked.sort_by(|a, b| {
        let (a_exact, b_exact) = (Some(a.0) == exact, Some(b.0) == exact);
        b_exact.cmp(&a_exact).then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)).then(cat[a.0].name.cmp(&cat[b.0].name))
    });
    let total = ranked.len();
    let mut hits = Vec::new();
    let mut chars = 0usize;
    for (i, _) in ranked.into_iter().take(limit) {
        let s = &cat[i];
        hits.push(Hit {
            name: s.name.clone(),
            description: s.description.chars().take(MAX_DESCRIPTION_CHARS).collect(),
            location: s.file.display().to_string(),
        });
        chars += hits.last().map(|h| h.name.len() + h.description.len() + h.location.len()).unwrap_or(0);
        if chars > MAX_RESULT_CHARS {
            hits.pop();
            break;
        }
    }
    let has_more = total > hits.len();
    Ok((hits, has_more))
}

/// `skills_search` output: metadata only, `has_more` and the way to read one.
pub fn render(query: &str, hits: &[Hit], has_more: bool) -> String {
    if hits.is_empty() {
        return format!("no skill matches \"{query}\" (try `skill action=list` to see the whole catalog)");
    }
    let mut out = format!("{} match(es) for \"{query}\" (read one with `skill action=view name=<name>`):\n", hits.len());
    for h in hits {
        out.push_str(&format!("  - {}: {} ({})\n", h.name, h.description, h.location));
    }
    if has_more {
        out.push_str("(more matches exist; narrow the query)");
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skill::{Source, Skill};
    use std::path::PathBuf;

    fn fixture(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-search-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn skill(root: &std::path::Path, name: &str, description: &str, body: &str) -> Skill {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), format!("---\nname: {name}\ndescription: {description}\n---\n{body}\n")).unwrap();
        Skill::load(&dir, root, Source::User).unwrap()
    }

    #[test]
    fn ranks_name_description_and_body_and_bounds_results() {
        let d = fixture("a");
        let cat = vec![
            skill(&d, "deploy-aws", "Ship an AWS stack", "Run terraform apply after the plan review."),
            skill(&d, "review-code", "Review a pull request", "Check that deploy scripts changed are re-reviewed."),
            skill(&d, "notes", "Take meeting notes", "Write down decisions."),
            skill(&d, "terraform", "Provision infrastructure", "terraform fmt then plan."),
        ];
        // A name/description hit outranks an incidental body mention.
        let (hits, more) = search(&cat, "deploy aws", None).unwrap();
        assert_eq!(hits[0].name, "deploy-aws", "{hits:?}");
        assert!(hits.iter().any(|h| h.name == "review-code") && !more, "body text is searched: {hits:?}");
        assert_eq!(hits[0].location, d.join("deploy-aws/SKILL.md").display().to_string());
        // Exact name first even when another document scores higher.
        let (hits, _) = search(&cat, "terraform", Some(2)).unwrap();
        assert_eq!(hits[0].name, "terraform", "{hits:?}");
        assert!(hits.len() <= 2, "limit is honoured");
        // Plural stems match; underscores and camelCase are split.
        let (hits, _) = search(&cat, "decisions", None).unwrap();
        assert_eq!(hits[0].name, "notes", "{hits:?}");
        let (hits, _) = search(&cat, "deployAws", None).unwrap();
        assert_eq!(hits[0].name, "deploy-aws", "{hits:?}");
        // Nothing matches: no hits, no error.
        assert!(search(&cat, "kubernetes helm chart", None).unwrap().0.is_empty());
        // Input bounds are the upstream ones.
        assert!(search(&cat, "   ", None).unwrap_err().contains("1-1000 characters"));
        assert!(search(&cat, &"x".repeat(1001), None).is_err());
        assert!(search(&cat, "x", Some(0)).is_err() && search(&cat, "x", Some(21)).is_err());
        // hasMore when the catalog holds more matches than the limit.
        let (hits, more) = search(&cat, "the", None).unwrap();
        assert!(hits.is_empty() && !more, "stopwords alone match nothing");
        let text = render("deploy aws", &search(&cat, "deploy aws", None).unwrap().0, false);
        assert!(text.starts_with("2 match(es) for \"deploy aws\"") && text.contains("- deploy-aws: Ship an AWS stack ("), "{text}");
        assert!(render("zzz", &[], false).contains("no skill matches"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn body_index_is_bounded_and_tokenizer_keeps_identifiers() {
        let d = fixture("b");
        let big = format!("{}NEEDLE_AT_THE_END", "x ".repeat(20_000));
        let cat = vec![skill(&d, "big", "big skill", &big)];
        assert!(search(&cat, "needle", None).unwrap().0.is_empty(), "the body cut keeps search bounded");
        assert_eq!(tokenize("gh-issues skills_list readFile foo_bar"), ["gh", "issues", "skills_list", "read", "file", "foo_bar"]);
        assert_eq!(stem("policies"), "policy");
        assert_eq!(stem("class"), "class", "a doubled s is not a plural");
        let _ = std::fs::remove_dir_all(&d);
    }
}
