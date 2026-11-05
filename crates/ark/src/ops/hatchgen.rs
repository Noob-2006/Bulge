//! `/hatch` image backend: `ark_app::tui::pets::SpriteGen` over ark-media's image
//! providers (`[media.image]` provider/model, then fallbacks; Hermes `agent/pet/generate/
//! imagegen.py`). Row strips need a provider that accepts reference images (OpenAI
//! gpt-image, Gemini, fal, Krea, xAI…); a transparent background is requested and dropped
//! when the model rejects it.

use ark_app::tui::pets::SpriteGen;
use ark_core::Cancel;
use ark_kernel::config::Paths;
use ark_kernel::kernel::Kernel;
use ark_kernel::vault::Vault;
use ark_media::image_gen::{self, Candidate, ImageRequest, ImageResult, InputImage};
use ark_media::{Media, MediaConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct MediaSprites {
    media: Arc<Media>,
    cands: Vec<Candidate>,
    transparent: AtomicBool,
}

fn media_table(paths: &Paths) -> toml::Table {
    std::fs::read_to_string(paths.user_config()).ok().and_then(|s| s.parse::<toml::Table>().ok()).and_then(|t| t.get("media").and_then(|m| m.as_table()).cloned()).unwrap_or_default()
}

fn build(paths: &Paths, vault: Arc<Vault>) -> Result<Box<dyn SpriteGen>, String> {
    let preferred = std::env::var("ARK_PET_IMAGE_PROVIDER").ok().filter(|s| !s.trim().is_empty());
    build_with(media_table(paths), vault, preferred.as_deref())
}

/// Build over an explicit `[media]` table (the testable half of [`build`]).
fn build_with(table: toml::Table, vault: Arc<Vault>, preferred: Option<&str>) -> Result<Box<dyn SpriteGen>, String> {
    let secret: ark_media::config::SecretFn = Arc::new(move |name: &str| {
        let s = vault.substitute(&format!("{{{{secret:{name}}}}}"));
        (!s.contains("{{secret:") && !s.is_empty()).then_some(s)
    });
    let media = Media::new(MediaConfig::new(table, secret));
    let cands = image_gen::candidates(&media, preferred, None)?;
    if cands.is_empty() {
        return Err("Pet generation needs an image backend that supports reference images: configure [media.image] (e.g. provider = \"openai\" with gpt-image) and its API key.".into());
    }
    Ok(Box::new(MediaSprites { media, cands, transparent: AtomicBool::new(true) }))
}

pub fn from_kernel(k: &Kernel) -> Result<Box<dyn SpriteGen>, String> {
    build(&k.paths, k.vault.clone())
}

pub fn from_paths(paths: &Paths) -> Result<Box<dyn SpriteGen>, String> {
    build(paths, Arc::new(Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty())))
}

fn rejected_background(e: &str) -> bool {
    let l = e.to_lowercase();
    l.contains("background") && (l.contains("not supported") || l.contains("transparent"))
}

/// The provider request for one image: strips are 3:2 landscape, the base is square, and a
/// reference image (the keyed base) rides along for every animation row.
fn request_for(prompt: &str, reference: Option<&[u8]>, aspect: &str) -> ImageRequest {
    let mut req = ImageRequest { prompt: prompt.to_string(), semantic_aspect: aspect.to_string(), aspect_ratio: Some(if aspect == "landscape" { "3:2" } else { "1:1" }.into()), output_format: Some("png".into()), ..Default::default() };
    if let Some(r) = reference {
        req.inputs = vec![InputImage { bytes: r.to_vec(), mime: "image/png".into(), name: "base.png".into(), url: None }];
    }
    req
}

/// Ask for a transparent background; when the model rejects it, retry opaque and remember
/// that for the rest of the hatch (one wasted call instead of one per row).
fn run_keyed(req: &mut ImageRequest, transparent: &AtomicBool, run: &dyn Fn(&ImageRequest) -> Result<ImageResult, String>) -> Result<ImageResult, String> {
    if transparent.load(Ordering::Relaxed) {
        req.background = Some("transparent".into());
    }
    match run(req) {
        Err(e) if req.background.is_some() && rejected_background(&e) => {
            transparent.store(false, Ordering::Relaxed);
            req.background = None;
            run(req)
        }
        r => r,
    }
}

/// Inline bytes win; URL-only providers are downloaded.
fn pick_image(res: ImageResult, fetch: &dyn Fn(&str) -> Result<Vec<u8>, String>) -> Result<Vec<u8>, String> {
    let img = res.images.into_iter().next().ok_or("provider returned no image")?;
    if !img.bytes.is_empty() {
        return Ok(img.bytes);
    }
    let url = img.url.ok_or("provider returned no image")?;
    fetch(&url)
}

fn fetch_url(url: &str) -> Result<Vec<u8>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(60))).build().into();
    let mut r = agent.get(url).call().map_err(|e| format!("could not fetch generated image: {e}"))?;
    r.body_mut().with_config().limit(64 << 20).read_to_vec().map_err(|e| e.to_string())
}

impl SpriteGen for MediaSprites {
    fn generate(&self, prompt: &str, reference: Option<&[u8]>, aspect: &str) -> Result<Vec<u8>, String> {
        let mut req = request_for(prompt, reference, aspect);
        let res = run_keyed(&mut req, &self.transparent, &|r| image_gen::generate(&self.media, r, &self.cands, &Cancel::new()).map(|x| x.1))?;
        pick_image(res, &fetch_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_media::store::Asset;

    fn asset(bytes: &[u8], url: Option<&str>) -> Asset {
        Asset { bytes: bytes.to_vec(), url: url.map(str::to_string), ..Default::default() }
    }

    fn image_result(bytes: &[u8]) -> ImageResult {
        ImageResult { images: vec![asset(bytes, None)], model: "m".into(), meta: serde_json::json!({}) }
    }

    #[test]
    fn no_image_provider_is_a_clear_error() {
        // Deterministic: name a provider that does not exist, so no real key can make it pass.
        let err = |r: Result<Box<dyn SpriteGen>, String>| match r {
            Ok(_) => panic!("expected a clear setup error, got an image backend"),
            Err(e) => e,
        };
        let v: Arc<Vault> = Arc::new(Vault::empty());
        let t: toml::Table = "[image]\nprovider = \"nope\"\n".parse().unwrap();
        let e = err(build_with(t, v.clone(), None));
        assert!(e.contains("not a known image provider"), "{e}");
        assert!(e.contains("[media.image]"), "the error names the setting to fix: {e}");
        // `ARK_PET_IMAGE_PROVIDER=nope` takes the explicit path and is equally clear.
        let e = err(build_with(toml::Table::new(), v, Some("nope")));
        assert!(e.contains("unknown image provider `nope`"), "{e}");
        assert!(rejected_background("400: background 'transparent' is not supported for this model"));
        assert!(!rejected_background("rate limited"));
    }

    #[test]
    fn requests_ask_for_transparency_and_retry_opaque_once() {
        let req = request_for("row", Some(b"png-bytes"), "landscape");
        assert_eq!(req.semantic_aspect, "landscape");
        assert_eq!(req.aspect_ratio.as_deref(), Some("3:2"));
        assert_eq!(req.output_format.as_deref(), Some("png"));
        assert_eq!(req.inputs.len(), 1);
        assert_eq!(req.inputs[0].mime, "image/png");
        assert_eq!(req.inputs[0].bytes, b"png-bytes");
        let square = request_for("base", None, "square");
        assert_eq!(square.aspect_ratio.as_deref(), Some("1:1"));
        assert!(square.inputs.is_empty());

        let calls = std::sync::Mutex::new(vec![]);
        let run = |r: &ImageRequest| {
            calls.lock().unwrap().push(r.background.clone());
            if r.background.is_some() {
                Err("400: background 'transparent' is not supported for this model".to_string())
            } else {
                Ok(image_result(b"opaque png"))
            }
        };
        let flag = AtomicBool::new(true);
        let mut req = request_for("row", None, "landscape");
        assert_eq!(run_keyed(&mut req, &flag, &run).unwrap().images[0].bytes, b"opaque png");
        assert_eq!(*calls.lock().unwrap(), vec![Some("transparent".into()), None], "exactly one downgrade retry");
        assert!(!flag.load(Ordering::Relaxed), "the downgrade sticks");

        // Following rows start opaque: one call, no wasted rejection.
        let mut next = request_for("next", None, "landscape");
        run_keyed(&mut next, &flag, &run).unwrap();
        assert_eq!(calls.lock().unwrap().len(), 3);
        assert_eq!(calls.lock().unwrap()[2], None);

        // Unrelated errors are neither retried nor stick.
        let keep = AtomicBool::new(true);
        let mut third = request_for("row", None, "square");
        assert!(run_keyed(&mut third, &keep, &|_: &ImageRequest| Err("rate limited".to_string())).is_err());
        assert!(keep.load(Ordering::Relaxed));
    }

    #[test]
    fn image_bytes_prefer_inline_then_url() {
        let fetched = std::sync::Mutex::new(vec![]);
        let fetch = |u: &str| {
            fetched.lock().unwrap().push(u.to_string());
            Ok(vec![9, 9])
        };
        assert_eq!(pick_image(image_result(&[1, 2]), &fetch).unwrap(), vec![1, 2]);
        assert!(fetched.lock().unwrap().is_empty(), "inline bytes need no download");

        let res = ImageResult { images: vec![asset(&[], Some("https://cdn.example/p.png"))], model: "m".into(), meta: serde_json::json!({}) };
        assert_eq!(pick_image(res, &fetch).unwrap(), vec![9, 9]);
        assert_eq!(*fetched.lock().unwrap(), vec!["https://cdn.example/p.png".to_string()]);

        let res = ImageResult { images: vec![asset(&[], None)], model: "m".into(), meta: serde_json::json!({}) };
        assert!(pick_image(res, &fetch).unwrap_err().contains("no image"));
        let empty = ImageResult { images: vec![], model: "m".into(), meta: serde_json::json!({}) };
        assert!(pick_image(empty, &fetch).unwrap_err().contains("no image"));
    }
}
