//! OpenAI native web search (Hermes `plugins/web/openai_native`): OpenAI's server-executed
//! `web_search` Responses tool. Hermes swaps it into the Codex Responses transport; ark cannot
//! rewrite the model transport's tools, so this provider makes the Responses call itself
//! (`POST /responses`, `tools: [{"type":"web_search"}]`) and returns the grounded answer.
//! Never auto-selected (as upstream).

use super::{responses_text_and_citations, SearchOutput, SearchRequest, WebProvider};
use crate::web::http::{self, WebCtx};
use serde_json::json;

pub struct OpenAiNative;

const ENV: &[&str] = &["OPENAI_API_KEY"];
const DEFAULT_BASE: &str = "https://api.openai.com/v1";
const DEFAULT_MODEL: &str = "gpt-5.5-mini";

impl WebProvider for OpenAiNative {
    fn id(&self) -> &'static str {
        "openai-native"
    }
    fn label(&self) -> &'static str {
        "OpenAI Native Web Search"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["openai"]
    }
    fn env_vars(&self) -> &'static [&'static str] {
        ENV
    }
    fn configured(&self, c: &WebCtx) -> bool {
        c.key("openai-native", ENV).is_some()
    }
    fn auto_detect(&self) -> bool {
        false
    }
    fn endpoint(&self, c: &WebCtx) -> String {
        format!("{}/responses", c.base_url("openai-native", Some("OPENAI_BASE_URL"), DEFAULT_BASE))
    }
    fn signup_url(&self) -> &'static str {
        "https://platform.openai.com/api-keys"
    }
    fn search(&self, c: &WebCtx, r: &SearchRequest) -> Result<SearchOutput, String> {
        let key = c.key("openai-native", ENV).ok_or("openai-native web search needs OPENAI_API_KEY or [web.providers.openai-native] api_key. For keyless search pick another backend.")?;
        let mut tool = json!({"type": "web_search"});
        if let Some(ctx) = c.opt("openai-native", "search_context_size") {
            tool["search_context_size"] = json!(ctx);
        }
        let model = c.opt("openai-native", "model").unwrap_or_else(|| DEFAULT_MODEL.into());
        let body = json!({"model": model, "input": r.query, "tools": [tool], "tool_choice": "auto", "store": false});
        c.check_cancel()?;
        let resp = http::post_json(&self.endpoint(c), &[super::bearer(&key)], &body, c.timeout("openai-native").max(60)).map_err(|e| format!("OpenAI web search failed: {e}"))?;
        if !resp.ok() {
            return Err(http::api_error("OpenAI", &resp, Some(&key)));
        }
        let (content, citations) = responses_text_and_citations(&resp.json()?);
        if content.is_empty() {
            return Err("OpenAI web search returned no answer text.".into());
        }
        Ok(SearchOutput::Answer { content, citations })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::{wctx, FakeServer};

    #[test]
    fn responses_call() {
        let s = FakeServer::start(vec![("POST /responses", 200, "application/json", json!({"output":[{"type":"web_search_call","status":"completed"},{"type":"message","content":[{"type":"output_text","text":"It is sunny.","annotations":[{"type":"url_citation","url":"https://w.com","title":"Weather"}]}]}]}).to_string())]);
        let c = wctx(json!({"providers":{"openai-native":{"base_url":s.url.clone(),"model":"gpt-x","search_context_size":"low"}}}), &[("OPENAI_API_KEY", "sk-test-0000000000")]);
        let SearchOutput::Answer { content, citations } = OpenAiNative.search(&c, &SearchRequest { query: "weather".into(), count: 5, ..Default::default() }).unwrap() else { panic!() };
        assert_eq!((content.as_str(), citations[0].title.as_deref()), ("It is sunny.", Some("Weather")));
        let b = s.last().json();
        assert_eq!((b["model"].as_str(), b["tools"][0]["type"].as_str(), b["tools"][0]["search_context_size"].as_str()), (Some("gpt-x"), Some("web_search"), Some("low")));
        assert!(!OpenAiNative.auto_detect());
        assert!(OpenAiNative.search(&wctx(json!({}), &[]), &SearchRequest::default()).unwrap_err().contains("OPENAI_API_KEY"));
    }
}
