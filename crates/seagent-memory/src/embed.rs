//! Embedding providers (OpenClaw `embeddingProviders`, MIT): openai, gemini, mistral, voyage,
//! bedrock (SigV4), deepinfra, github-copilot (user-endpoint token validation + model
//! discovery), llama-cpp, lmstudio, ollama, omlx, generic openai-compatible, plus `local`
//! (hashed bag-of-words, no network). Vectors are sanitized and L2-normalized; batches split
//! on provider batch-size errors; 429/5xx retried by `util::send_retry`.

use crate::settings::EmbeddingSettings;
use crate::sigv4;
use crate::util::{self, json_headers, post_json_retry, resolve_value, Retry, Subst};
use base64::Engine;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Query,
    Document,
}

pub trait Embedder: Send + Sync {
    fn id(&self) -> String;
    fn model(&self) -> String;
    /// Inputs per request.
    fn max_batch(&self) -> usize {
        96
    }
    fn embed(&self, texts: &[String], kind: Kind, retry: Retry) -> Result<Vec<Vec<f32>>, String>;
    /// Multimodal file embedding (only Gemini Embedding 2).
    fn embed_media(&self, _mime: &str, _data: &[u8], _label: &str) -> Result<Vec<f32>, String> {
        Err(format!("embedding provider `{}` does not support multimodal inputs", self.id()))
    }
}

pub fn normalize(v: &[f64]) -> Vec<f32> {
    let s: Vec<f64> = v.iter().map(|x| if x.is_finite() { *x } else { 0.0 }).collect();
    let m = s.iter().map(|x| x * x).sum::<f64>().sqrt();
    if m < 1e-10 {
        return s.iter().map(|x| *x as f32).collect();
    }
    s.iter().map(|x| (x / m) as f32).collect()
}

fn floats(v: &Value, what: &str) -> Result<Vec<f64>, String> {
    let a = v.as_array().ok_or_else(|| format!("{what}: embedding is not an array"))?;
    a.iter().map(|x| x.as_f64().ok_or_else(|| format!("{what}: embedding contains a non-number value"))).collect()
}

pub fn cosine(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let (mut d, mut x, mut y) = (0f64, 0f64, 0f64);
    for i in 0..a.len() {
        d += a[i] as f64 * b[i] as f64;
        x += a[i] as f64 * a[i] as f64;
        y += b[i] as f64 * b[i] as f64;
    }
    if x == 0.0 || y == 0.0 {
        0.0
    } else {
        d / (x.sqrt() * y.sqrt())
    }
}

/// Provider batch-size complaints that a smaller batch fixes (OpenClaw SPLITTABLE_…_RE).
fn splittable(msg: &str) -> bool {
    regex::Regex::new(r"(?i)(request_headers_too_large|request header fields too large|connection (reset|aborted)|embeddings api input limit exceeded|max input length is|batch size is invalid|input array max\s+\d+|input\s*数组最大不得超过)").unwrap().is_match(msg)
}

/// Embed in provider-sized batches, halving a batch the provider rejects as too large.
pub fn embed_all(e: &dyn Embedder, texts: &[String], kind: Kind, retry: Retry) -> Result<Vec<Vec<f32>>, String> {
    let mut out = Vec::with_capacity(texts.len());
    for chunk in texts.chunks(e.max_batch().max(1)) {
        out.extend(embed_split(e, chunk, kind, retry)?);
    }
    Ok(out)
}

fn embed_split(e: &dyn Embedder, texts: &[String], kind: Kind, retry: Retry) -> Result<Vec<Vec<f32>>, String> {
    match e.embed(texts, kind, retry) {
        Err(m) if texts.len() > 1 && splittable(&m) => {
            let mid = texts.len() / 2;
            let mut a = embed_split(e, &texts[..mid], kind, retry)?;
            a.extend(embed_split(e, &texts[mid..], kind, retry)?);
            Ok(a)
        }
        other => other,
    }
}

// ───────────────────────── OpenAI-compatible family ─────────────────────────

pub struct OpenAiCompat {
    pub id: String,
    pub url: String,
    pub model: String,
    pub headers: Vec<(String, String)>,
    pub dimensions: Option<usize>,
    pub input_type: Option<String>,
    pub query_input_type: Option<String>,
    pub document_input_type: Option<String>,
    /// Voyage: `input_type` = query | document.
    pub voyage_input_type: bool,
    /// One request for a batch of queries (DeepInfra); others embed queries one by one.
    pub batch_queries: bool,
    pub max_batch: usize,
    pub timeout: Duration,
}

impl OpenAiCompat {
    fn body(&self, input: &[String], kind: Kind) -> Value {
        let mut b = Map::new();
        b.insert("model".into(), json!(self.model));
        b.insert("input".into(), json!(input));
        if let Some(d) = self.dimensions {
            b.insert("dimensions".into(), json!(d));
        }
        let explicit = if kind == Kind::Query { &self.query_input_type } else { &self.document_input_type };
        if let Some(t) = explicit.as_ref().or(self.input_type.as_ref()).map(|s| s.trim()).filter(|s| !s.is_empty()) {
            b.insert("input_type".into(), json!(t));
        } else if self.voyage_input_type {
            b.insert("input_type".into(), json!(if kind == Kind::Query { "query" } else { "document" }));
        }
        Value::Object(b)
    }
    fn many(&self, input: &[String], kind: Kind, retry: Retry) -> Result<Vec<Vec<f32>>, String> {
        let prefix = format!("{} embeddings failed (model: {}, batch size: {})", self.id, self.model, input.len());
        let v = post_json_retry(&self.url, &json_headers(&self.headers), &self.body(input, kind), self.timeout, retry, &prefix)?;
        parse_openai_data(&v, input.len(), &prefix)
    }
}

pub fn parse_openai_data(v: &Value, n: usize, prefix: &str) -> Result<Vec<Vec<f32>>, String> {
    let data = v["data"].as_array().ok_or_else(|| format!("{prefix}: response missing data[]"))?;
    if data.len() != n {
        return Err(format!("{prefix}: expected {n} embeddings, received {}", data.len()));
    }
    let mut out: Vec<Option<Vec<f32>>> = vec![None; n];
    for (pos, d) in data.iter().enumerate() {
        let i = d["index"].as_u64().map(|i| i as usize).unwrap_or(pos);
        if i >= n || out[i].is_some() {
            return Err(format!("{prefix}: response contains an invalid or duplicate index"));
        }
        out[i] = Some(normalize(&floats(&d["embedding"], prefix)?));
    }
    out.into_iter().map(|o| o.ok_or_else(|| format!("{prefix}: response missing vectors for some inputs"))).collect()
}

impl Embedder for OpenAiCompat {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn model(&self) -> String {
        self.model.clone()
    }
    fn max_batch(&self) -> usize {
        self.max_batch
    }
    fn embed(&self, texts: &[String], kind: Kind, retry: Retry) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() {
            return Ok(vec![]);
        }
        if kind == Kind::Query && !self.batch_queries {
            return texts.iter().map(|t| self.many(std::slice::from_ref(t), kind, retry).map(|mut v| v.remove(0))).collect();
        }
        self.many(texts, kind, retry)
    }
}

// ───────────────────────── Gemini ─────────────────────────

const GEMINI_TASK_PREFIX: &[(&str, &str)] = &[("RETRIEVAL_QUERY", "task: search result | query:"), ("RETRIEVAL_DOCUMENT", "title: none | text:")];

pub struct Gemini {
    pub base: String,
    pub model: String,
    pub headers: Vec<(String, String)>,
    pub dimensions: Option<usize>,
    pub timeout: Duration,
}

fn gemini_model(m: &str) -> String {
    let mut m = m.trim().to_string();
    for p in ["models/gemini/", "models/google/", "models/", "gemini/", "google/"] {
        if let Some(r) = m.strip_prefix(p) {
            m = r.to_string();
            break;
        }
    }
    if m.is_empty() {
        "gemini-embedding-001".into()
    } else {
        m
    }
}

pub fn is_gemini_embedding2(model: &str) -> bool {
    matches!(gemini_model(model).as_str(), "gemini-embedding-2" | "gemini-embedding-2-preview")
}

impl Gemini {
    fn dims(&self) -> Option<usize> {
        if is_gemini_embedding2(&self.model) {
            return Some(self.dimensions.unwrap_or(3072));
        }
        if self.model == "gemini-embedding-001" {
            self.dimensions
        } else {
            None
        }
    }
    fn request(&self, parts: Value, task: &str, text_only: bool, with_model: bool) -> Value {
        let mut parts = parts;
        let mut req = if with_model { json!({"model": format!("models/{}", self.model)}) } else { json!({}) };
        if self.model == "gemini-embedding-2" {
            if text_only {
                if let Some(t) = parts[0]["text"].as_str() {
                    let pre = GEMINI_TASK_PREFIX.iter().find(|(k, _)| *k == task).map(|(_, p)| *p).unwrap_or("");
                    parts[0]["text"] = json!(format!("{pre} {t}"));
                }
            }
        } else {
            req["taskType"] = json!(task);
        }
        req["content"] = json!({"parts": parts});
        if let Some(d) = self.dims() {
            req["outputDimensionality"] = json!(d);
        }
        req
    }
    fn check(&self, v: Vec<f64>) -> Result<Vec<f32>, String> {
        if let Some(d) = self.dims() {
            if v.len() != d {
                return Err(format!("gemini embeddings failed: expected {d} dimensions, received {}", v.len()));
            }
        }
        Ok(normalize(&v))
    }
    fn url(&self, verb: &str) -> String {
        format!("{}/models/{}:{verb}", self.base.trim_end_matches('/'), self.model)
    }
}

impl Embedder for Gemini {
    fn id(&self) -> String {
        "gemini".into()
    }
    fn model(&self) -> String {
        self.model.clone()
    }
    fn max_batch(&self) -> usize {
        100
    }
    fn embed(&self, texts: &[String], kind: Kind, retry: Retry) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() {
            return Ok(vec![]);
        }
        let h = json_headers(&self.headers);
        if kind == Kind::Query {
            return texts
                .iter()
                .map(|t| {
                    if t.trim().is_empty() {
                        return Ok(vec![]);
                    }
                    let v = post_json_retry(&self.url("embedContent"), &h, &self.request(json!([{"text": t}]), "RETRIEVAL_QUERY", true, false), self.timeout, retry, "gemini embeddings failed")?;
                    self.check(floats(&v["embedding"]["values"], "gemini embeddings failed")?)
                })
                .collect();
        }
        let reqs: Vec<Value> = texts.iter().map(|t| self.request(json!([{"text": t}]), "RETRIEVAL_DOCUMENT", true, true)).collect();
        let v = post_json_retry(&self.url("batchEmbedContents"), &h, &json!({"requests": reqs}), self.timeout, retry, "gemini embeddings failed")?;
        let embs = v["embeddings"].as_array().filter(|a| a.len() == texts.len()).ok_or("gemini embeddings failed: malformed batch response")?;
        embs.iter().map(|e| self.check(floats(&e["values"], "gemini embeddings failed")?)).collect()
    }
    fn embed_media(&self, mime: &str, data: &[u8], label: &str) -> Result<Vec<f32>, String> {
        if !is_gemini_embedding2(&self.model) {
            return Err(format!("gemini model `{}` does not support multimodal embeddings; use gemini-embedding-2", self.model));
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let parts = json!([{"text": label}, {"inlineData": {"mimeType": mime, "data": b64}}]);
        let req = json!({"requests": [self.request(parts, "RETRIEVAL_DOCUMENT", false, true)]});
        let v = post_json_retry(&self.url("batchEmbedContents"), &json_headers(&self.headers), &req, self.timeout, util::RETRY_INDEX, "gemini embeddings failed")?;
        self.check(floats(&v["embeddings"][0]["values"], "gemini embeddings failed")?)
    }
}

// ───────────────────────── Ollama ─────────────────────────

pub struct Ollama {
    pub base: String,
    pub model: String,
    pub headers: Vec<(String, String)>,
    pub dimensions: Option<usize>,
    pub timeout: Duration,
}

const OLLAMA_QUERY_TEMPLATES: &[(&str, &str)] = &[
    ("qwen3-embedding", "Instruct: Given a user query, retrieve relevant memory notes and documents\nQuery:{query}"),
    ("nomic-embed-text", "search_query: {query}"),
    ("mxbai-embed-large", "Represent this sentence for searching relevant passages: {query}"),
];

pub fn ollama_query_text(model: &str, q: &str) -> String {
    let m = model.trim().to_lowercase();
    let m = m.rsplit('/').next().unwrap_or(&m).to_string();
    OLLAMA_QUERY_TEMPLATES.iter().find(|(p, _)| m.starts_with(p)).map(|(_, t)| t.replace("{query}", q)).unwrap_or_else(|| q.to_string())
}

impl Embedder for Ollama {
    fn id(&self) -> String {
        "ollama".into()
    }
    fn model(&self) -> String {
        self.model.clone()
    }
    fn embed(&self, texts: &[String], kind: Kind, retry: Retry) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() {
            return Ok(vec![]);
        }
        let input: Vec<String> = if kind == Kind::Query { texts.iter().map(|t| ollama_query_text(&self.model, t)).collect() } else { texts.to_vec() };
        let url = format!("{}/api/embed", self.base.trim_end_matches('/'));
        let v = post_json_retry(&url, &json_headers(&self.headers), &json!({"model": self.model, "input": input}), self.timeout, retry, "Ollama embed").map_err(|e| {
            if e.contains("HTTP 404") && regex::Regex::new(r"(?i)model.*not found").unwrap().is_match(&e) {
                format!("{e} Run `ollama pull {}` on the configured Ollama host.", self.model)
            } else {
                e
            }
        })?;
        let embs = v["embeddings"].as_array().ok_or("Ollama embed response missing embeddings[]")?;
        if embs.len() != texts.len() {
            return Err(format!("Ollama embed response returned {} embeddings for {} inputs", embs.len(), texts.len()));
        }
        embs.iter()
            .map(|e| {
                let mut f = floats(e, "Ollama embed response")?;
                if let Some(d) = self.dimensions {
                    f.truncate(d);
                }
                if f.is_empty() {
                    return Err("Ollama embed response contains an empty embedding".to_string());
                }
                Ok(normalize(&f))
            })
            .collect()
    }
}

// ───────────────────────── Bedrock ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BedrockFamily {
    TitanV1,
    TitanV2,
    CohereV3,
    CohereV4,
    Nova,
    TwelveLabs,
}

pub fn bedrock_family(model: &str) -> BedrockFamily {
    let id = regex::Regex::new(r"^(us|eu|ap|apac|au|jp|global)\.").unwrap().replace(&model.to_lowercase(), "").into_owned();
    if id.starts_with("amazon.titan-embed-text-v2") {
        BedrockFamily::TitanV2
    } else if id.starts_with("amazon.titan-embed") {
        BedrockFamily::TitanV1
    } else if id.starts_with("amazon.nova") {
        BedrockFamily::Nova
    } else if id.starts_with("cohere.embed-v4") {
        BedrockFamily::CohereV4
    } else if id.starts_with("cohere.embed") {
        BedrockFamily::CohereV3
    } else if id.starts_with("twelvelabs") {
        BedrockFamily::TwelveLabs
    } else {
        BedrockFamily::TitanV1
    }
}

pub enum BedrockAuth {
    SigV4(sigv4::Credentials),
    /// Bedrock API key (`AWS_BEARER_TOKEN_BEDROCK`).
    Bearer(String),
}

pub struct Bedrock {
    pub endpoint: String,
    pub region: String,
    pub model: String,
    pub dimensions: Option<usize>,
    pub auth: BedrockAuth,
    pub timeout: Duration,
}

impl Bedrock {
    fn body(&self, fam: BedrockFamily, text: &str) -> Value {
        match fam {
            BedrockFamily::TitanV2 => match self.dimensions {
                Some(d) => json!({"inputText": text, "dimensions": d, "normalize": true}),
                None => json!({"inputText": text}),
            },
            BedrockFamily::Nova => json!({"taskType": "SINGLE_EMBEDDING", "singleEmbeddingParams": {"embeddingPurpose": "GENERIC_INDEX", "embeddingDimension": self.dimensions.unwrap_or(1024), "text": {"truncationMode": "END", "value": text}}}),
            BedrockFamily::TwelveLabs => json!({"inputType": "text", "text": {"inputText": text}}),
            _ => json!({"inputText": text}),
        }
    }
    fn invoke(&self, body: &Value, retry: Retry) -> Result<Value, String> {
        let enc = sigv4::uri_encode(&self.model, false);
        let path = format!("/model/{enc}/invoke");
        let url = format!("{}{path}", self.endpoint.trim_end_matches('/'));
        let payload = serde_json::to_vec(body).unwrap_or_default();
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string()), ("Accept".to_string(), "application/json".to_string())];
        match &self.auth {
            BedrockAuth::Bearer(t) => headers.push(("Authorization".into(), format!("Bearer {t}"))),
            BedrockAuth::SigV4(c) => {
                let host = self.endpoint.split("://").nth(1).unwrap_or(&self.endpoint).trim_end_matches('/').to_string();
                let signed = sigv4::sign("POST", &host, &path, "", &headers, &payload, c, &self.region, "bedrock", &sigv4::amz_date(util::now_ms()));
                headers.extend(signed);
            }
        }
        let v = post_json_retry(&url, &headers, body, self.timeout, retry, "Amazon Bedrock embeddings")?;
        if !v.is_object() {
            return Err("Amazon Bedrock embedding response returned malformed JSON".into());
        }
        Ok(v)
    }
}

impl Embedder for Bedrock {
    fn id(&self) -> String {
        "bedrock".into()
    }
    fn model(&self) -> String {
        self.model.clone()
    }
    fn max_batch(&self) -> usize {
        if matches!(bedrock_family(&self.model), BedrockFamily::CohereV3 | BedrockFamily::CohereV4) {
            96
        } else {
            1
        }
    }
    fn embed(&self, texts: &[String], kind: Kind, retry: Retry) -> Result<Vec<Vec<f32>>, String> {
        let fam = bedrock_family(&self.model);
        let bad = || "Amazon Bedrock embedding response returned malformed JSON".to_string();
        if matches!(fam, BedrockFamily::CohereV3 | BedrockFamily::CohereV4) {
            let mut out = Vec::new();
            let groups: Vec<Vec<String>> = if kind == Kind::Query { texts.iter().map(|t| vec![t.clone()]).collect() } else { vec![texts.to_vec()] };
            for g in groups {
                let mut b = json!({"texts": g, "input_type": if kind == Kind::Query { "search_query" } else { "search_document" }, "truncate": "END"});
                if fam == BedrockFamily::CohereV4 {
                    b["embedding_types"] = json!(["float"]);
                    if let Some(d) = self.dimensions {
                        b["output_dimension"] = json!(d);
                    }
                }
                let v = self.invoke(&b, retry)?;
                let e = if fam == BedrockFamily::CohereV4 && !v["embeddings"].is_array() { &v["embeddings"]["float"] } else { &v["embeddings"] };
                for x in e.as_array().ok_or_else(bad)? {
                    out.push(normalize(&floats(x, "Amazon Bedrock embedding response").map_err(|_| bad())?));
                }
            }
            return Ok(out);
        }
        texts
            .iter()
            .map(|t| {
                if t.trim().is_empty() {
                    return Ok(vec![]);
                }
                let v = self.invoke(&self.body(fam, t), retry)?;
                let e = match fam {
                    BedrockFamily::Nova => &v["embeddings"][0]["embedding"],
                    BedrockFamily::TwelveLabs if v["data"].is_array() => &v["data"][0]["embedding"],
                    BedrockFamily::TwelveLabs if v["data"].is_object() => &v["data"]["embedding"],
                    _ => &v["embedding"],
                };
                Ok(normalize(&floats(e, "Amazon Bedrock embedding response").map_err(|_| bad())?))
            })
            .collect()
    }
}

// ───────────────────────── GitHub Copilot ─────────────────────────

const COPILOT_PREFERRED: &[&str] = &["text-embedding-3-small", "text-embedding-3-large", "text-embedding-ada-002"];
pub const COPILOT_DEFAULT_API: &str = "https://api.individual.githubcopilot.com";

fn copilot_headers(token: &str, extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut h = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Editor-Version".to_string(), "vscode/1.99.0".to_string()),
        ("Editor-Plugin-Version".to_string(), "copilot-chat/0.26.0".to_string()),
        ("User-Agent".to_string(), "GitHubCopilotChat/0.26.0".to_string()),
        ("Openai-Organization".to_string(), "github-copilot".to_string()),
    ];
    h.extend(extra.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("copilot-integration-id")).cloned());
    h.push(("Copilot-Integration-Id".into(), "copilot-developer-cli".into()));
    h.push(("Authorization".into(), format!("Bearer {token}")));
    h
}

/// Validate the GitHub token at `{user_url}` and return the trusted Copilot API base
/// (`endpoints.api`), falling back to the public default.
pub fn copilot_api_base(user_url: &str, token: &str, domain: &str) -> Result<String, String> {
    let r = util::http("GET", user_url, &[("Accept".into(), "application/json".into()), ("Authorization".into(), format!("Bearer {token}"))], None, Duration::from_secs(30))?;
    if !r.ok() {
        return Err(format!("GitHub Copilot user response HTTP {}", r.status));
    }
    let v = r.json().map_err(|_| "Unexpected response from GitHub Copilot user endpoint".to_string())?;
    if !v.is_object() {
        return Err("Unexpected response from GitHub Copilot user endpoint".into());
    }
    let api = &v["endpoints"]["api"];
    if api.is_null() || api == "" {
        return Ok(if domain == "github.com" { COPILOT_DEFAULT_API.into() } else { format!("https://copilot-api.{domain}") });
    }
    let api = api.as_str().filter(|s| !s.trim().is_empty()).ok_or("GitHub Copilot user response has an invalid endpoints.api URL")?;
    let rest = api.strip_prefix("https://").ok_or("GitHub Copilot user response has an untrusted endpoints.api URL")?;
    let host = rest.split('/').next().unwrap_or("").to_lowercase();
    let trusted = host == "copilot-proxy.githubusercontent.com" || host.ends_with(".githubcopilot.com") || (domain != "github.com" && (host == domain || host.ends_with(&format!(".{domain}"))));
    if !trusted || host.contains('@') || rest.contains('?') || rest.contains('#') {
        return Err("GitHub Copilot user response has an untrusted endpoints.api URL".into());
    }
    Ok(api.trim_end_matches('/').to_string())
}

pub fn copilot_models(base: &str, token: &str, extra: &[(String, String)]) -> Result<Vec<String>, String> {
    let h = copilot_headers(token, extra);
    let r = util::http("GET", &format!("{}/models", base.trim_end_matches('/')), &h, None, Duration::from_secs(30))?;
    if !r.ok() {
        return Err(format!("GitHub Copilot model discovery HTTP {}: {}", r.status, util::redact(&util::clip(&r.text(), 8192), &h)));
    }
    let v = r.json()?;
    Ok(v["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|m| {
            let id = m["id"].as_str()?.trim().to_string();
            let eps = m["supported_endpoints"].as_array().map(|a| a.iter().any(|e| e.as_str().is_some_and(|s| s.contains("embeddings")))).unwrap_or(false);
            (!id.is_empty() && (eps || id.to_lowercase().contains("embedding"))).then_some(id)
        })
        .collect())
}

pub fn copilot_pick(available: &[String], user: &str) -> Result<String, String> {
    let user = user.trim().trim_start_matches("github-copilot/");
    if available.is_empty() {
        return Err("No embedding models available from GitHub Copilot".into());
    }
    if !user.is_empty() {
        return if available.iter().any(|a| a == user) { Ok(user.to_string()) } else { Err(format!("GitHub Copilot embedding model \"{user}\" is not available. Available: {}", available.join(", "))) };
    }
    Ok(COPILOT_PREFERRED.iter().find(|p| available.iter().any(|a| a == *p)).map(|s| s.to_string()).unwrap_or_else(|| available[0].clone()))
}

pub fn copilot(base: &str, token: &str, model: &str, extra: &[(String, String)], timeout: Duration) -> Result<OpenAiCompat, String> {
    let models = copilot_models(base, token, extra)?;
    let model = copilot_pick(&models, model)?;
    Ok(OpenAiCompat { id: "github-copilot".into(), url: format!("{}/embeddings", base.trim_end_matches('/')), model, headers: copilot_headers(token, extra).into_iter().filter(|(k, _)| k != "Content-Type").collect(), dimensions: None, input_type: None, query_input_type: None, document_input_type: None, voyage_input_type: false, batch_queries: false, max_batch: 96, timeout })
}

// ───────────────────────── local hashed embedding ─────────────────────────

/// Feature-hashed token counts (256 dims). Deterministic, no network; lexical, not semantic.
pub struct LocalHash;
pub const LOCAL_DIMS: usize = 256;

pub fn local_vector(text: &str) -> Vec<f32> {
    let mut v = vec![0f64; LOCAL_DIMS];
    for t in util::tokens(text) {
        let h = ring::digest::digest(&ring::digest::SHA256, t.as_bytes());
        let b = h.as_ref();
        let i = u16::from_le_bytes([b[0], b[1]]) as usize % LOCAL_DIMS;
        v[i] += if b[2] & 1 == 0 { 1.0 } else { -1.0 };
    }
    normalize(&v)
}

impl Embedder for LocalHash {
    fn id(&self) -> String {
        "local".into()
    }
    fn model(&self) -> String {
        "hash-256".into()
    }
    fn max_batch(&self) -> usize {
        1024
    }
    fn embed(&self, texts: &[String], _: Kind, _: Retry) -> Result<Vec<Vec<f32>>, String> {
        Ok(texts.iter().map(|t| local_vector(t)).collect())
    }
}

// ───────────────────────── factory ─────────────────────────

pub fn supports_multimodal(s: &EmbeddingSettings) -> bool {
    matches!(s.provider.as_str(), "gemini" | "google") && is_gemini_embedding2(&s.model)
}

fn bearer(key: &str) -> Vec<(String, String)> {
    if key.is_empty() {
        vec![]
    } else {
        vec![("Authorization".into(), format!("Bearer {}", key.trim_start_matches("Bearer ").trim()))]
    }
}

/// Resolve the configured provider. `Ok(None)` = FTS-only (provider `none`, or `auto` with no key).
pub fn build(s: &EmbeddingSettings, subst: &Subst) -> Result<Option<Arc<dyn Embedder>>, String> {
    let provider = s.provider.trim().to_lowercase();
    let timeout = Duration::from_secs(s.timeout_secs.max(1));
    let mut extra = util::headers_from(&s.headers, subst);
    let key = |envs: &[&str]| resolve_value(subst, &s.api_key, envs);
    let base = |def: &str| if s.base_url.trim().is_empty() { def.to_string() } else { subst(s.base_url.trim()).trim_end_matches('/').to_string() };
    let model = |def: &str| if s.model.trim().is_empty() { def.to_string() } else { s.model.trim().to_string() };
    let compat = |id: &str, url: String, model: String, headers: Vec<(String, String)>| OpenAiCompat {
        id: id.into(),
        url: format!("{url}/embeddings"),
        model,
        headers,
        dimensions: s.dimensions,
        input_type: s.input_type.clone(),
        query_input_type: s.query_input_type.clone(),
        document_input_type: s.document_input_type.clone(),
        voyage_input_type: id == "voyage",
        batch_queries: id == "deepinfra",
        max_batch: if s.max_batch > 0 { s.max_batch } else { 96 },
        timeout,
    };
    let need = |k: String, what: &str, env: &str| if k.is_empty() { Err(format!("No API key found for provider {what}: set [memory.search.embedding] api_key or {env}")) } else { Ok(k) };
    let e: Arc<dyn Embedder> = match provider.as_str() {
        "none" | "off" | "" => return Ok(None),
        "auto" => {
            let k = key(&["OPENAI_API_KEY"]);
            if k.is_empty() {
                return Ok(None);
            }
            let mut h = bearer(&k);
            h.extend(extra);
            Arc::new(compat("openai", base("https://api.openai.com/v1"), model("text-embedding-3-small"), h))
        }
        "openai" | "openai-compatible" | "mistral" | "voyage" | "deepinfra" | "lmstudio" | "omlx" | "llama-cpp" | "llamacpp" => {
            let (id, url, m, envs, required): (&str, &str, &str, &[&str], bool) = match provider.as_str() {
                "openai" => ("openai", "https://api.openai.com/v1", "text-embedding-3-small", &["OPENAI_API_KEY"], true),
                "mistral" => ("mistral", "https://api.mistral.ai/v1", "mistral-embed", &["MISTRAL_API_KEY"], true),
                "voyage" => ("voyage", "https://api.voyageai.com/v1", "voyage-4-large", &["VOYAGE_API_KEY"], true),
                "deepinfra" => ("deepinfra", "https://api.deepinfra.com/v1/openai", "BAAI/bge-m3", &["DEEPINFRA_API_KEY"], true),
                "lmstudio" => ("lmstudio", "http://localhost:1234/v1", "text-embedding-nomic-embed-text-v1.5", &["LM_API_TOKEN"], false),
                "omlx" => ("omlx", "http://127.0.0.1:8000/v1", "", &["OMLX_API_KEY"], false),
                "openai-compatible" => ("openai-compatible", "", "", &[], false),
                _ => ("llama-cpp", "http://127.0.0.1:19432/v1", "embeddinggemma-300m-qat-q8_0", &[], false),
            };
            let url = base(url);
            if url.is_empty() {
                return Err("openai-compatible embeddings need [memory.search.embedding] base_url".into());
            }
            let m = model(m);
            if m.is_empty() {
                return Err(format!("{id} embeddings need [memory.search.embedding] model"));
            }
            let m = m.strip_prefix(&format!("{id}/")).map(str::to_string).unwrap_or(m);
            let mut k = key(envs);
            if id == "omlx" && k.is_empty() {
                k = "omlx-local".into();
            }
            if required {
                k = need(k, id, envs[0])?;
            }
            let mut h = bearer(&k);
            h.append(&mut extra);
            Arc::new(compat(id, url, m, h))
        }
        "gemini" | "google" => {
            let k = need(key(&["GEMINI_API_KEY", "GOOGLE_API_KEY"]), "google", "GEMINI_API_KEY")?;
            let mut h = if k.starts_with('{') {
                let tok = serde_json::from_str::<Value>(&k).ok().and_then(|v| v["token"].as_str().map(str::to_string)).unwrap_or_default();
                bearer(&tok)
            } else {
                vec![("x-goog-api-key".into(), k)]
            };
            h.append(&mut extra);
            let mut b = base("https://generativelanguage.googleapis.com/v1beta");
            if let Some(i) = b.find("/openai") {
                b.truncate(i);
            }
            Arc::new(Gemini { base: b, model: gemini_model(&s.model), headers: h, dimensions: s.dimensions, timeout })
        }
        "ollama" => {
            let k = key(&["OLLAMA_API_KEY"]);
            let mut h = bearer(&k);
            h.append(&mut extra);
            Arc::new(Ollama { base: base("http://127.0.0.1:11434"), model: model("nomic-embed-text"), headers: h, dimensions: s.dimensions, timeout })
        }
        "bedrock" | "amazon-bedrock" => {
            let region = if !s.region.is_empty() {
                s.region.clone()
            } else if let Some(r) = regex::Regex::new(r"bedrock-runtime(?:-fips)?\.([a-z0-9-]+)\.").unwrap().captures(&s.base_url) {
                r[1].to_string()
            } else {
                std::env::var("AWS_REGION").or_else(|_| std::env::var("AWS_DEFAULT_REGION")).unwrap_or_else(|_| "us-east-1".into())
            };
            let bearer_key = key(&["AWS_BEARER_TOKEN_BEDROCK"]);
            let auth = if !bearer_key.is_empty() {
                BedrockAuth::Bearer(bearer_key)
            } else {
                BedrockAuth::SigV4(sigv4::Credentials::from_env().ok_or("No API key found for provider bedrock: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, ~/.aws/credentials or AWS_BEARER_TOKEN_BEDROCK")?)
            };
            Arc::new(Bedrock { endpoint: base(&format!("https://bedrock-runtime.{region}.amazonaws.com")), region, model: model("amazon.titan-embed-text-v2:0"), dimensions: s.dimensions, auth, timeout })
        }
        "github-copilot" | "copilot" => {
            let explicit = subst(s.api_key.trim());
            if !s.base_url.trim().is_empty() {
                if explicit.is_empty() {
                    return Err("GitHub Copilot memory custom baseUrl requires an explicit memory.search.embedding.api_key".into());
                }
                Arc::new(copilot(&base(""), &explicit, &s.model, &extra, timeout)?)
            } else {
                let tok = if explicit.is_empty() { key(&["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]) } else { explicit };
                if tok.is_empty() {
                    return Err("No GitHub token available for Copilot embedding provider".into());
                }
                let domain = std::env::var("GITHUB_COPILOT_DOMAIN").unwrap_or_else(|_| "github.com".into());
                let api = copilot_api_base(&format!("https://api.{domain}/copilot_internal/user"), &tok, &domain)?;
                Arc::new(copilot(&api, &tok, &s.model, &extra, timeout)?)
            }
        }
        "local" | "hash" => Arc::new(LocalHash),
        other => return Err(format!("unknown embedding provider `{other}`; use openai, gemini, mistral, voyage, bedrock, deepinfra, github-copilot, llama-cpp, lmstudio, ollama, omlx, openai-compatible, local or none")),
    };
    Ok(Some(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testutil::fake;
    use crate::util::RETRY_QUERY;

    fn subst() -> Subst {
        Arc::new(|s: &str| s.replace("{{secret:K}}", "sk-test-key"))
    }
    fn settings(provider: &str, base: &str) -> EmbeddingSettings {
        EmbeddingSettings { provider: provider.into(), base_url: base.into(), api_key: "{{secret:K}}".into(), ..Default::default() }
    }
    fn vecs(n: usize, dim: usize) -> Value {
        json!({"data": (0..n).rev().map(|i| json!({"index": i, "embedding": (0..dim).map(|j| (i + j + 1) as f64).collect::<Vec<_>>()})).collect::<Vec<_>>()})
    }

    #[test]
    fn openai_family_request_and_ordering() {
        for (provider, model, auth) in [("openai", "text-embedding-3-small", true), ("mistral", "mistral-embed", true), ("deepinfra", "BAAI/bge-m3", true), ("lmstudio", "text-embedding-nomic-embed-text-v1.5", true), ("llama-cpp", "embeddinggemma-300m-qat-q8_0", true)] {
            let f = fake(|r, _| (200, vecs(r.json()["input"].as_array().unwrap().len(), 3).to_string()));
            let mut s = settings(provider, &f.url);
            s.dimensions = Some(3);
            let e = build(&s, &subst()).unwrap().unwrap();
            let v = e.embed(&["a".into(), "b".into()], Kind::Document, RETRY_QUERY).unwrap();
            assert_eq!(v.len(), 2);
            assert!(v[0][0] < v[1][0], "{provider}: vectors put back in request order by index");
            assert!((v[0].iter().map(|x| x * x).sum::<f32>() - 1.0).abs() < 1e-5, "normalized");
            let r = f.reqs.lock().unwrap()[0].clone();
            assert_eq!(r.path, "/embeddings");
            assert_eq!(r.json()["model"], model);
            assert_eq!(r.json()["dimensions"], 3);
            assert_eq!(r.header("authorization").is_some(), auth);
            assert_eq!(r.header("authorization").unwrap(), "Bearer sk-test-key");
        }
    }

    #[test]
    fn voyage_input_types_and_query_batching() {
        let f = fake(|r, _| (200, vecs(r.json()["input"].as_array().unwrap().len(), 2).to_string()));
        let e = build(&settings("voyage", &f.url), &subst()).unwrap().unwrap();
        e.embed(&["q1".into(), "q2".into()], Kind::Query, RETRY_QUERY).unwrap();
        e.embed(&["d".into()], Kind::Document, RETRY_QUERY).unwrap();
        let reqs = f.reqs.lock().unwrap();
        assert_eq!(reqs.len(), 3, "queries are embedded one per request");
        assert_eq!(reqs[0].json()["input_type"], "query");
        assert_eq!(reqs[2].json()["input_type"], "document");
        assert_eq!(reqs[0].json()["model"], "voyage-4-large");
    }

    #[test]
    fn missing_key_and_auto() {
        let s = EmbeddingSettings { provider: "mistral".into(), ..Default::default() };
        if std::env::var("MISTRAL_API_KEY").is_err() {
            assert!(build(&s, &subst()).err().unwrap().contains("No API key"));
        }
        assert!(build(&EmbeddingSettings { provider: "none".into(), ..Default::default() }, &subst()).unwrap().is_none());
        assert!(build(&EmbeddingSettings { provider: "omlx".into(), ..Default::default() }, &subst()).err().unwrap().contains("model"));
        assert!(build(&EmbeddingSettings { provider: "nope".into(), ..Default::default() }, &subst()).err().unwrap().contains("unknown"));
    }

    #[test]
    fn splits_batches_on_limit_errors_and_retries_429() {
        let f = fake(|r, n| {
            let k = r.json()["input"].as_array().unwrap().len();
            if n == 0 {
                (429, "{}".into())
            } else if k > 2 {
                (400, r#"{"error":{"message":"input array max 2"}}"#.into())
            } else {
                (200, vecs(k, 2).to_string())
            }
        });
        let e = build(&settings("openai", &f.url), &subst()).unwrap().unwrap();
        let texts: Vec<String> = (0..5).map(|i| format!("t{i}")).collect();
        let v = embed_all(e.as_ref(), &texts, Kind::Document, RETRY_QUERY).unwrap();
        assert_eq!(v.len(), 5);
        assert!(f.reqs.lock().unwrap().len() >= 4);
    }

    #[test]
    fn gemini_query_batch_and_multimodal() {
        let f = fake(|r, _| {
            if r.path.ends_with(":embedContent") {
                (200, json!({"embedding": {"values": [1.0, 2.0, 2.0]}}).to_string())
            } else {
                let n = r.json()["requests"].as_array().unwrap().len();
                (200, json!({"embeddings": (0..n).map(|_| json!({"values": [0.0, 3.0, 4.0]})).collect::<Vec<_>>()}).to_string())
            }
        });
        let mut s = settings("gemini", &f.url);
        s.dimensions = Some(3);
        s.model = "gemini-embedding-001".into();
        let e = build(&s, &subst()).unwrap().unwrap();
        let q = e.embed(&["hi".into()], Kind::Query, RETRY_QUERY).unwrap();
        assert!((q[0][0] - 1.0 / 3.0).abs() < 1e-6);
        e.embed(&["a".into(), "b".into()], Kind::Document, RETRY_QUERY).unwrap();
        let reqs = f.reqs.lock().unwrap().clone();
        assert_eq!(reqs[0].path, "/models/gemini-embedding-001:embedContent");
        assert_eq!(reqs[0].header("x-goog-api-key").unwrap(), "sk-test-key");
        assert_eq!(reqs[0].json()["taskType"], "RETRIEVAL_QUERY");
        assert_eq!(reqs[1].json()["requests"][1]["taskType"], "RETRIEVAL_DOCUMENT");
        assert_eq!(reqs[1].json()["requests"][0]["outputDimensionality"], 3);
        assert!(e.embed_media("image/png", b"x", "Image file: a.png").unwrap_err().contains("gemini-embedding-2"));
        // Dimension mismatch is an error.
        s.dimensions = Some(5);
        let e = build(&s, &subst()).unwrap().unwrap();
        assert!(e.embed(&["hi".into()], Kind::Query, RETRY_QUERY).unwrap_err().contains("expected 5 dimensions"));
        // Embedding 2: task prefix in text, inline media parts.
        let f = fake(|_, _| (200, json!({"embeddings": [{"values": vec![1.0; 3072]}], "embedding": {"values": vec![1.0; 3072]}}).to_string()));
        let mut s = settings("gemini", &f.url);
        s.model = "gemini-embedding-2".into();
        let e = build(&s, &subst()).unwrap().unwrap();
        e.embed(&["hello".into()], Kind::Query, RETRY_QUERY).unwrap();
        e.embed_media("image/png", b"PNG", "Image file: pic.png").unwrap();
        let reqs = f.reqs.lock().unwrap().clone();
        assert_eq!(reqs[0].json()["content"]["parts"][0]["text"], "task: search result | query: hello");
        assert!(reqs[0].json().get("taskType").is_none());
        assert_eq!(reqs[1].json()["requests"][0]["content"]["parts"][1]["inlineData"]["mimeType"], "image/png");
        assert_eq!(reqs[1].json()["requests"][0]["outputDimensionality"], 3072);
    }

    #[test]
    fn ollama_templates_and_truncation() {
        let f = fake(|r, _| {
            let n = r.json()["input"].as_array().unwrap().len();
            (200, json!({"embeddings": (0..n).map(|_| json!([3.0, 4.0, 9.0])).collect::<Vec<_>>(), "prompt_eval_count": 3}).to_string())
        });
        let mut s = settings("ollama", &f.url);
        s.dimensions = Some(2);
        let e = build(&s, &subst()).unwrap().unwrap();
        let v = e.embed(&["what".into()], Kind::Query, RETRY_QUERY).unwrap();
        assert_eq!(v[0], vec![0.6, 0.8]);
        let r = f.reqs.lock().unwrap()[0].clone();
        assert_eq!(r.path, "/api/embed");
        assert_eq!(r.json()["input"][0], "search_query: what");
        let f = fake(|_, _| (404, r#"{"error":"model \"nomic-embed-text\" not found, try pulling it first"}"#.into()));
        let e = build(&settings("ollama", &f.url), &subst()).unwrap().unwrap();
        assert!(e.embed(&["x".into()], Kind::Document, RETRY_QUERY).unwrap_err().contains("ollama pull nomic-embed-text"));
    }

    #[test]
    fn bedrock_titan_and_cohere_signed() {
        let f = fake(|r, _| {
            if r.path.contains("cohere") {
                let n = r.json()["texts"].as_array().unwrap().len();
                (200, json!({"embeddings": {"float": (0..n).map(|_| json!([1.0, 0.0])).collect::<Vec<_>>()}}).to_string())
            } else {
                (200, json!({"embedding": [0.0, 2.0]}).to_string())
            }
        });
        let mk = |model: &str| Bedrock { endpoint: f.url.clone(), region: "us-west-2".into(), model: model.into(), dimensions: Some(256), auth: BedrockAuth::SigV4(sigv4::Credentials { access_key: "AKID".into(), secret_key: "SECRET".into(), session_token: None }), timeout: Duration::from_secs(5) };
        let t = mk("amazon.titan-embed-text-v2:0");
        assert_eq!(t.max_batch(), 1);
        assert_eq!(t.embed(&["hi".into()], Kind::Document, RETRY_QUERY).unwrap()[0], vec![0.0, 1.0]);
        let c = mk("cohere.embed-v4:0");
        assert_eq!(c.embed(&["a".into(), "b".into()], Kind::Document, RETRY_QUERY).unwrap().len(), 2);
        let reqs = f.reqs.lock().unwrap().clone();
        assert_eq!(reqs[0].path, "/model/amazon.titan-embed-text-v2%3A0/invoke");
        assert_eq!(reqs[0].json(), json!({"inputText": "hi", "dimensions": 256, "normalize": true}));
        let auth = reqs[0].header("authorization").unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/") && auth.contains("/us-west-2/bedrock/aws4_request"), "{auth}");
        assert!(reqs[0].header("x-amz-date").is_some());
        assert_eq!(reqs[1].json()["input_type"], "search_document");
        assert_eq!(reqs[1].json()["embedding_types"], json!(["float"]));
        assert_eq!(bedrock_family("us.amazon.nova-2-multimodal-embeddings-v1:0"), BedrockFamily::Nova);
        let b = Bedrock { auth: BedrockAuth::Bearer("bk".into()), ..mk("amazon.titan-embed-text-v1") };
        b.embed(&["x".into()], Kind::Query, RETRY_QUERY).unwrap();
        assert_eq!(f.reqs.lock().unwrap()[2].header("authorization").unwrap(), "Bearer bk");
    }

    #[test]
    fn copilot_discovery_and_trust() {
        let f = fake(|r, _| match r.path.as_str() {
            "/user" => (200, json!({"endpoints": {"api": "https://api.individual.githubcopilot.com"}}).to_string()),
            "/evil" => (200, json!({"endpoints": {"api": "https://evil.example.com"}}).to_string()),
            "/models" => (200, json!({"data": [{"id": "gpt-4o"}, {"id": "text-embedding-3-small", "supported_endpoints": ["/v1/embeddings"]}, {"id": "my-embedding-x"}]}).to_string()),
            _ => (200, vecs(1, 2).to_string()),
        });
        assert_eq!(copilot_api_base(&format!("{}/user", f.url), "gho_x", "github.com").unwrap(), COPILOT_DEFAULT_API);
        assert!(copilot_api_base(&format!("{}/evil", f.url), "gho_x", "github.com").unwrap_err().contains("untrusted"));
        let e = build(&EmbeddingSettings { provider: "github-copilot".into(), base_url: f.url.clone(), api_key: "gho_x".into(), ..Default::default() }, &subst()).unwrap().unwrap();
        assert_eq!(e.model(), "text-embedding-3-small");
        e.embed(&["q".into()], Kind::Query, RETRY_QUERY).unwrap();
        let reqs = f.reqs.lock().unwrap().clone();
        let emb = reqs.iter().find(|r| r.path == "/embeddings").unwrap();
        assert_eq!(emb.header("copilot-integration-id").unwrap(), "copilot-developer-cli");
        assert_eq!(emb.header("authorization").unwrap(), "Bearer gho_x");
        assert!(copilot_pick(&["a-embedding".into()], "zzz").unwrap_err().contains("not available"));
        assert!(build(&EmbeddingSettings { provider: "github-copilot".into(), base_url: f.url.clone(), ..Default::default() }, &subst()).err().unwrap().contains("explicit"));
    }

    #[test]
    fn local_hash_is_deterministic() {
        let a = local_vector("prefers aisle seats");
        assert_eq!(a, local_vector("prefers aisle seats"));
        assert!(cosine(&a, &local_vector("aisle seats preferred")) > cosine(&a, &local_vector("quantum chromodynamics")));
    }
}
