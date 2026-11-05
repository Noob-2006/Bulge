//! OpenAI-compatible image endpoints: DeepInfra (`/v1/openai`), LiteLLM proxy, Meta
//! Model API (`muse-image`).

use super::common::{openai_size_for, require_key, Compat};
use super::{Caps, ImageProvider, ImageRequest, ImageResult};
use crate::Media;
use ark_core::Cancel;
use serde_json::json;

pub struct DeepInfra;
pub struct Litellm;
pub struct MetaAi;

const DI_ENV: &[&str] = &["DEEPINFRA_API_KEY"];
const DI_BASE: &str = "https://api.deepinfra.com/v1/openai";
const DI_MODELS: &[&str] = &["black-forest-labs/FLUX-1-schnell", "black-forest-labs/FLUX-1-dev", "Qwen/Qwen-Image-Max", "stabilityai/sdxl-turbo"];
const DI_SIZES: &[&str] = &["512x512", "1024x1024", "1024x1792", "1792x1024"];

fn di_size(req: &ImageRequest) -> String {
    req.size.clone().unwrap_or_else(|| match req.semantic_aspect.as_str() {
        "landscape" => "1792x1024".into(),
        "portrait" => "1024x1792".into(),
        _ => "1024x1024".into(),
    })
}

impl ImageProvider for DeepInfra {
    fn id(&self) -> &'static str {
        "deepinfra"
    }
    fn label(&self) -> &'static str {
        "DeepInfra"
    }
    fn env(&self) -> &'static [&'static str] {
        DI_ENV
    }
    fn default_base(&self) -> &'static str {
        DI_BASE
    }
    fn default_model(&self, m: &Media) -> String {
        std::env::var("DEEPINFRA_IMAGE_MODEL").ok().filter(|s| !s.trim().is_empty()).or_else(|| m.cfg.str("providers.deepinfra.model")).unwrap_or_else(|| DI_MODELS[0].into())
    }
    fn models(&self) -> Vec<String> {
        DI_MODELS.iter().map(|s| s.to_string()).collect()
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 4, edit: true, max_inputs: 1, supports_size: true, sizes: DI_SIZES.to_vec(), ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let c = m.creds("deepinfra", DI_ENV, DI_BASE);
        require_key(&c, DI_ENV)?;
        let model = super::common::model_or(req, &self.default_model(m)).trim_start_matches("deepinfra/").to_string();
        let compat = Compat { label: "DeepInfra", creds: &c, headers: c.bearer(), edit_field: "image", default_mime: "image/jpeg" };
        let size = di_size(req);
        let v = if req.is_edit() {
            if req.inputs.len() > 1 {
                return Err("DeepInfra image editing supports one reference image.".into());
            }
            compat.edit(m, &[("model", model.clone()), ("prompt", req.prompt.clone()), ("n", "1".into()), ("size", size.clone()), ("response_format", "b64_json".into())], req)?
        } else {
            compat.generate(m, &json!({"model": model, "prompt": req.prompt, "n": req.count, "size": size, "response_format": "b64_json"}))?
        };
        compat.result(&v, &model).map_err(|_| "DeepInfra image response did not include generated image data".to_string())
    }
}

const LL_ENV: &[&str] = &["LITELLM_API_KEY"];
const LL_BASE: &str = "http://localhost:4000";
const LL_SIZES: &[&str] = &["256x256", "512x512", "1024x1024", "1024x1536", "1024x1792", "1536x1024", "1792x1024", "2048x2048", "2048x1152", "3840x2160", "2160x3840"];

impl ImageProvider for Litellm {
    fn id(&self) -> &'static str {
        "litellm"
    }
    fn label(&self) -> &'static str {
        "LiteLLM"
    }
    fn env(&self) -> &'static [&'static str] {
        LL_ENV
    }
    fn default_base(&self) -> &'static str {
        LL_BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.litellm.model").unwrap_or_else(|| "gpt-image-2".into())
    }
    fn models(&self) -> Vec<String> {
        vec!["gpt-image-2".into()]
    }
    fn configured(&self, m: &Media) -> bool {
        let c = m.creds("litellm", LL_ENV, "");
        c.key.is_some() || !c.base.is_empty()
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 4, edit: true, max_inputs: 5, supports_size: true, sizes: LL_SIZES.to_vec(), ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let c = m.creds("litellm", LL_ENV, LL_BASE);
        let local = ["localhost", "127.", "[::1]", "host.docker.internal"].iter().any(|h| crate::http::host_of(&c.base).starts_with(h));
        if c.key.is_none() && !local {
            return Err("LiteLLM API key missing".into());
        }
        let model = super::common::model_or(req, &self.default_model(m));
        let size = req.size.clone().unwrap_or_else(|| "1024x1024".into());
        let compat = Compat { label: "LiteLLM", creds: &c, headers: c.bearer(), edit_field: "image", default_mime: "image/png" };
        let v = if req.is_edit() {
            compat.edit(m, &[("model", model.clone()), ("prompt", req.prompt.clone()), ("n", req.count.to_string()), ("size", size)], req)?
        } else {
            compat.generate(m, &json!({"model": model, "prompt": req.prompt, "n": req.count, "size": size}))?
        };
        compat.result(&v, &model)
    }
}

const META_ENV: &[&str] = &["MODEL_API_KEY", "META_API_KEY", "META_MODEL_API_KEY"];
const META_BASE: &str = "https://api.meta.ai/v1";

impl ImageProvider for MetaAi {
    fn id(&self) -> &'static str {
        "meta-ai"
    }
    fn label(&self) -> &'static str {
        "Meta Model API"
    }
    fn env(&self) -> &'static [&'static str] {
        META_ENV
    }
    fn default_base(&self) -> &'static str {
        META_BASE
    }
    fn default_model(&self, m: &Media) -> String {
        m.cfg.str("providers.meta-ai.model").or_else(|| std::env::var("META_IMAGE_MODEL").ok().filter(|s| s == "muse-image-1.0")).unwrap_or_else(|| "muse-image-1.0".into())
    }
    fn models(&self) -> Vec<String> {
        vec!["muse-image-1.0".into()]
    }
    fn caps(&self, _model: &str) -> Caps {
        Caps { max_count: 1, edit: false, supports_size: true, sizes: vec!["1024x1024", "1536x1024", "1024x1536"], ..Caps::default() }
    }
    fn generate(&self, m: &Media, req: &ImageRequest, _cancel: &Cancel) -> Result<ImageResult, String> {
        let base = std::env::var("META_BASE_URL").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| META_BASE.into());
        let c = m.creds("meta-ai", META_ENV, &base);
        require_key(&c, &["META_MODEL_API_KEY"])?;
        let model = super::common::model_or(req, &self.default_model(m));
        let size = req.size.clone().unwrap_or_else(|| openai_size_for(&req.semantic_aspect).into());
        let compat = Compat { label: "Meta", creds: &c, headers: c.bearer(), edit_field: "image", default_mime: "image/webp" };
        let v = compat.generate(m, &json!({"model": model, "prompt": req.prompt, "size": size, "n": 1}))?;
        let mut r = compat.result(&v, &model)?;
        r.meta = json!({"size": size});
        Ok(r)
    }
}
