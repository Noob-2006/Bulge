//! FAL image model catalog + Clarity upscaler constants, transcribed from Hermes
//! `tools/image_generation_catalog.py` (MIT). Each entry maps the semantic aspect
//! (landscape/square/portrait) to the model's native size spec; `supports` /
//! `edit_supports` whitelist the payload keys so models never get rejected params.

use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SizeStyle {
    /// FAL `image_size` preset enum (or explicit `{width,height}`).
    Preset,
    /// `aspect_ratio` enum.
    Aspect,
    /// Literal "WxH" in `image_size`.
    Literal,
}

pub struct FalModel {
    pub id: &'static str,
    pub display: &'static str,
    pub speed: &'static str,
    pub strengths: &'static str,
    pub price: &'static str,
    pub style: SizeStyle,
    /// landscape, square, portrait.
    pub sizes: [Value; 3],
    pub defaults: Value,
    pub supports: &'static [&'static str],
    pub edit_endpoint: Option<&'static str>,
    pub edit_supports: &'static [&'static str],
    pub max_refs: usize,
    pub edit_image_param: &'static str,
}

impl FalModel {
    pub fn size_for(&self, aspect: &str) -> &Value {
        match aspect {
            "landscape" => &self.sizes[0],
            "portrait" => &self.sizes[2],
            _ => &self.sizes[1],
        }
    }
}

pub const DEFAULT_MODEL: &str = "fal-ai/flux-2/klein/9b";
pub const UPSCALER_MODEL: &str = "fal-ai/clarity-upscaler";
pub const UPSCALER_FACTOR: u32 = 2;
pub const UPSCALER_DEFAULT_PROMPT: &str = "masterpiece, best quality, highres";
pub const UPSCALER_NEGATIVE_PROMPT: &str = "(worst quality, low quality, normal quality:2)";
pub const UPSCALER_CREATIVITY: f64 = 0.35;
pub const UPSCALER_RESEMBLANCE: f64 = 0.6;
pub const UPSCALER_GUIDANCE_SCALE: f64 = 4.0;
pub const UPSCALER_NUM_INFERENCE_STEPS: u32 = 18;

fn preset() -> [Value; 3] {
    [json!("landscape_16_9"), json!("square_hd"), json!("portrait_16_9")]
}
fn aspect() -> [Value; 3] {
    [json!("16:9"), json!("1:1"), json!("9:16")]
}
fn preset43() -> [Value; 3] {
    [json!("landscape_4_3"), json!("square_hd"), json!("portrait_4_3")]
}

#[allow(clippy::too_many_arguments)]
fn model(id: &'static str, display: &'static str, speed: &'static str, strengths: &'static str, price: &'static str, style: SizeStyle, sizes: [Value; 3], defaults: Value, supports: &'static [&'static str], edit: Option<(&'static str, &'static [&'static str], usize)>) -> FalModel {
    let (edit_endpoint, edit_supports, max_refs) = match edit {
        Some((e, s, n)) => (Some(e), s, n),
        None => (None, &[][..], 0),
    };
    FalModel { id, display, speed, strengths, price, style, sizes, defaults, supports, edit_endpoint, edit_supports, max_refs, edit_image_param: "image_urls" }
}

pub fn models() -> Vec<FalModel> {
    use SizeStyle::*;
    let mut v = vec![
        model("fal-ai/flux-2/klein/9b", "FLUX 2 Klein 9B", "<1s", "Fast, crisp text", "$0.006/MP", Preset, preset(),
            json!({"num_inference_steps": 4, "output_format": "png", "enable_safety_checker": false}),
            &["prompt", "image_size", "num_inference_steps", "seed", "output_format", "enable_safety_checker"],
            Some(("fal-ai/flux-2/klein/9b/edit", &["prompt", "image_urls", "num_inference_steps", "seed", "output_format", "enable_safety_checker"], 9))),
        model("fal-ai/flux-2-pro", "FLUX 2 Pro", "~6s", "Studio photorealism", "$0.03/MP", Preset, preset(),
            json!({"num_inference_steps": 50, "guidance_scale": 4.5, "num_images": 1, "output_format": "png", "enable_safety_checker": false, "safety_tolerance": "5", "sync_mode": true}),
            &["prompt", "image_size", "num_inference_steps", "guidance_scale", "num_images", "output_format", "enable_safety_checker", "safety_tolerance", "sync_mode", "seed"],
            Some(("fal-ai/flux-2-pro/edit", &["prompt", "image_urls", "num_inference_steps", "guidance_scale", "num_images", "output_format", "enable_safety_checker", "safety_tolerance", "sync_mode", "seed"], 9))),
        model("fal-ai/z-image/turbo", "Z-Image Turbo", "~2s", "Bilingual EN/CN, 6B", "$0.005/MP", Preset, preset(),
            json!({"num_inference_steps": 8, "num_images": 1, "output_format": "png", "enable_safety_checker": false, "enable_prompt_expansion": false}),
            &["prompt", "image_size", "num_inference_steps", "num_images", "seed", "output_format", "enable_safety_checker", "enable_prompt_expansion"], None),
        model("fal-ai/nano-banana-pro", "Nano Banana Pro (Gemini 3 Pro Image)", "~8s", "Gemini 3 Pro, reasoning depth, text rendering", "$0.15/image (1K)", Aspect, aspect(),
            json!({"num_images": 1, "output_format": "png", "safety_tolerance": "5", "resolution": "1K"}),
            &["prompt", "aspect_ratio", "num_images", "output_format", "safety_tolerance", "seed", "sync_mode", "resolution", "enable_web_search", "limit_generations"],
            Some(("fal-ai/nano-banana-pro/edit", &["prompt", "image_urls", "aspect_ratio", "num_images", "output_format", "safety_tolerance", "seed", "sync_mode", "resolution", "enable_web_search", "limit_generations"], 2))),
        model("fal-ai/nano-banana-2", "Nano Banana 2 (Gemini 3.1 Flash Image)", "~3s", "Fast reasoning, multilingual text, infographics", "Lower-cost Flash tier", Aspect, aspect(),
            json!({"num_images": 1, "output_format": "png", "safety_tolerance": "4", "resolution": "1K", "limit_generations": true}),
            &["prompt", "aspect_ratio", "num_images", "output_format", "safety_tolerance", "seed", "sync_mode", "system_prompt", "resolution", "enable_web_search", "limit_generations", "thinking_level"],
            Some(("fal-ai/nano-banana-2/edit", &["prompt", "image_urls", "aspect_ratio", "num_images", "output_format", "safety_tolerance", "seed", "sync_mode", "system_prompt", "resolution", "enable_web_search", "limit_generations", "thinking_level"], 14))),
        model("fal-ai/gpt-image-1.5", "GPT Image 1.5", "~15s", "Prompt adherence", "$0.034/image", Literal, [json!("1536x1024"), json!("1024x1024"), json!("1024x1536")],
            json!({"quality": "medium", "num_images": 1, "output_format": "png"}),
            &["prompt", "image_size", "quality", "num_images", "output_format", "background", "sync_mode"],
            Some(("fal-ai/gpt-image-1.5/edit", &["prompt", "image_urls", "image_size", "quality", "num_images", "output_format", "sync_mode"], 16))),
        model("fal-ai/gpt-image-2", "GPT Image 2", "~20s", "SOTA text rendering + CJK, world-aware photorealism", "$0.04–0.06/image", Preset, preset43(),
            json!({"quality": "medium", "num_images": 1, "output_format": "png"}),
            &["prompt", "image_size", "quality", "num_images", "output_format", "sync_mode"],
            Some(("openai/gpt-image-2/edit", &["prompt", "image_urls", "quality", "num_images", "output_format", "sync_mode", "mask_image_url"], 16))),
    ];
    for (id, edit, display, speed, strengths) in [
        ("openai/gpt-image-2.5/flare/text-to-image", "openai/gpt-image-2.5/flare/edit", "GPT Image 2.5 Flare", "Fast", "Everyday creation, natural lighting and textures"),
        ("openai/gpt-image-2.5/sunburst/text-to-image", "openai/gpt-image-2.5/sunburst/edit", "GPT Image 2.5 Sunburst", "Slower", "Precision editing, subject and composition consistency"),
    ] {
        v.push(model(id, display, speed, strengths, "Token-based pricing", Preset, preset43(),
            json!({"quality": "medium", "num_images": 1, "output_format": "png"}),
            &["prompt", "image_size", "quality", "num_images", "output_format", "background", "output_compression", "sync_mode"],
            Some((edit, &["prompt", "image_urls", "image_size", "quality", "num_images", "output_format", "background", "output_compression", "sync_mode", "mask_url", "input_fidelity"], 16))));
    }
    v.extend([
        model("fal-ai/ideogram/v3", "Ideogram V3", "~5s", "Best typography", "$0.03-0.09/image", Preset, preset(),
            json!({"rendering_speed": "BALANCED", "expand_prompt": true, "style": "AUTO"}),
            &["prompt", "image_size", "rendering_speed", "expand_prompt", "style", "seed"],
            Some(("fal-ai/ideogram/v3/edit", &["prompt", "image_urls", "rendering_speed", "expand_prompt", "style", "seed"], 1))),
        model("fal-ai/recraft/v4/pro/text-to-image", "Recraft V4 Pro", "~8s", "Design, brand systems, production-ready", "$0.25/image", Preset, preset(),
            json!({"enable_safety_checker": false}), &["prompt", "image_size", "enable_safety_checker", "colors", "background_color"], None),
        model("fal-ai/qwen-image", "Qwen Image", "~12s", "LLM-based, complex text", "$0.02/MP", Preset, preset(),
            json!({"num_inference_steps": 30, "guidance_scale": 2.5, "num_images": 1, "output_format": "png", "acceleration": "regular"}),
            &["prompt", "image_size", "num_inference_steps", "guidance_scale", "num_images", "output_format", "acceleration", "seed", "sync_mode"],
            Some(("fal-ai/qwen-image-2/pro/edit", &["prompt", "image_urls", "num_inference_steps", "guidance_scale", "num_images", "output_format", "acceleration", "seed", "sync_mode"], 3))),
        model("fal-ai/krea/v2/medium/text-to-image", "Krea 2 Medium", "~15-25s", "Illustration, anime, painting, expressive/artistic styles", "$0.030 (text) / $0.035 (style refs)", Aspect, aspect(),
            json!({"creativity": "medium"}), &["prompt", "aspect_ratio", "creativity", "seed", "image_style_references"], None),
        model("fal-ai/krea/v2/large/text-to-image", "Krea 2 Large", "~25-60s", "Photorealism, raw textured looks (motion blur, grain, film)", "$0.060 (text) / $0.065 (style refs)", Aspect, aspect(),
            json!({"creativity": "medium"}), &["prompt", "aspect_ratio", "creativity", "seed", "image_style_references"], None),
        model("bytedance/seedream/v5/pro/text-to-image", "Seedream 5.0 Pro", "~10s", "ByteDance flagship, dense layouts, native text in 14 languages", "$0.0675/image (≤1536²)", Preset,
            [json!({"width": 2048, "height": 1152}), json!({"width": 1536, "height": 1536}), json!({"width": 1152, "height": 2048})],
            json!({"num_images": 1, "output_format": "png", "enable_safety_checker": false}),
            &["prompt", "image_size", "num_images", "output_format", "sync_mode", "enable_safety_checker"],
            Some(("bytedance/seedream/v5/pro/edit", &["prompt", "image_urls", "image_size", "num_images", "output_format", "sync_mode", "enable_safety_checker"], 10))),
        model("bytedance/seedream/v5/lite/text-to-image", "Seedream 5.0 Lite", "~5s", "Fast/cheap Seedream tier, high-res output", "$0.035/image", Preset, preset(),
            json!({"num_images": 1, "enable_safety_checker": false}), &["prompt", "image_size", "num_images", "max_images", "sync_mode", "enable_safety_checker"], None),
        model("ideogram/v4/instant", "Ideogram V4 (Instant)", "<1s", "Latest Ideogram typography, posters/logos, instant", "$0.0075/MP", Preset, preset(),
            json!({"expansion_model": "Medium", "output_format": "png", "enable_safety_checker": false}),
            &["prompt", "image_size", "expansion_model", "num_images", "seed", "sync_mode", "enable_safety_checker", "output_format"], None),
        model("ideogram/v4/fast", "Ideogram V4 (Fast)", "~1s", "Ideogram V4 quality tiers via rendering_speed", "$0.005-0.018/MP", Preset, preset(),
            json!({"expansion_model": "Medium", "rendering_speed": "BALANCED"}), &["prompt", "image_size", "expansion_model", "rendering_speed", "num_images", "seed", "sync_mode"], None),
        model("alibaba/qwen-image-3/text-to-image", "Qwen Image 3", "~8s", "Complex CN/EN text rendering, prompt-guided resolution", "$0.04 (1K) / $0.075 (2K) per image", Preset, preset(),
            json!({"num_images": 1, "output_format": "png", "enable_prompt_expansion": false, "enable_safety_checker": false}),
            &["prompt", "negative_prompt", "image_size", "num_images", "seed", "sync_mode", "output_format", "enable_prompt_expansion", "enable_safety_checker"],
            Some(("alibaba/qwen-image-3/edit", &["prompt", "image_urls", "negative_prompt", "num_images", "seed", "sync_mode", "output_format", "enable_prompt_expansion", "enable_safety_checker"], 3))),
        model("microsoft/mai-image-2.5-pro", "MAI Image 2.5 Pro", "~10s", "Microsoft flagship, hero imagery, precise typography", "~$0.17/image", Aspect, aspect(),
            json!({"num_images": 1, "output_format": "png"}), &["prompt", "aspect_ratio", "num_images", "output_format", "sync_mode"], None),
        model("google/nano-banana-2-lite", "Nano Banana 2 Lite", "<2s", "Gemini image family, sub-2s, 14 aspect ratios incl. extreme", "~$0.04/image (1K fixed)", Aspect, aspect(),
            json!({"num_images": 1, "output_format": "png", "safety_tolerance": "5"}),
            &["prompt", "aspect_ratio", "num_images", "seed", "output_format", "safety_tolerance", "sync_mode", "system_prompt", "limit_generations", "thinking_level"],
            Some(("google/nano-banana-2-lite/edit", &["prompt", "image_urls", "aspect_ratio", "num_images", "seed", "output_format", "safety_tolerance", "sync_mode", "system_prompt"], 4))),
        model("fal-ai/recraft/v4.1/text-to-image", "Recraft V4.1", "~8s", "Design-first raster, brand systems, editorial", "$0.035/image", Preset, preset(),
            json!({"enable_safety_checker": false}), &["prompt", "image_size", "enable_safety_checker", "colors", "background_color"], None),
        model("xai/grok-imagine-image/v2.0/text-to-image", "Grok Imagine Image 2.0", "~5s", "xAI. Design-grade typography/layout, instruction following", "$0.06/image (1K medium)", Aspect, aspect(),
            json!({"num_images": 1, "output_format": "png", "resolution": "1k", "quality": "medium"}),
            &["prompt", "aspect_ratio", "num_images", "output_format", "resolution", "quality", "sync_mode"],
            Some(("xai/grok-imagine-image/v2.0/edit", &["prompt", "image_urls", "num_images", "output_format", "resolution", "quality", "sync_mode"], 3))),
    ]);
    let mut kling = model("fal-ai/kling-image/v3/text-to-image", "Kling Image v3", "~10s", "Kuaishou. Realistic detail, cheap native 2K, wide AR set", "$0.028/image", Aspect, aspect(),
        json!({"num_images": 1, "output_format": "png", "resolution": "2K"}),
        &["prompt", "aspect_ratio", "num_images", "output_format", "resolution", "negative_prompt", "sync_mode"],
        Some(("fal-ai/kling-image/v3/image-to-image", &["prompt", "image_url", "aspect_ratio", "num_images", "output_format", "resolution", "sync_mode"], 1)));
    kling.edit_image_param = "image_url";
    v.push(kling);
    v.push(model("meta/muse-image/text-to-image", "Meta Muse Image", "~5s", "Meta. Realism + typography at commodity price", "$0.01/image", Aspect, aspect(),
        json!({"num_images": 1, "output_format": "png"}), &["prompt", "aspect_ratio", "num_images", "output_format", "sync_mode"],
        Some(("meta/muse-image/edit", &["prompt", "image_urls", "num_images", "output_format", "sync_mode"], 10))));
    v
}

pub fn find(id: &str) -> Option<FalModel> {
    models().into_iter().find(|m| m.id == id)
}
