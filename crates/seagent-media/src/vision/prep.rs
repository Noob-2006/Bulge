//! Image preparation before pixels reach a model: format normalization (SVG/BMP/HEIC/AVIF
//! → PNG), full-decode validation, region crops, the Hermes history-embed resize ladder
//! (`tools/vision_tools.py::_resize_image_for_vision`) and the OpenClaw sanitizer
//! (`src/agents/tool-images.ts::resizeImageBase64IfNeeded`, `image-sanitization.ts`).
//!
//! A tool image is baked into immutable history and re-sent every turn, so an unsupported
//! media type or a truncated payload would wedge the session with a 400 on every resume.

use seagent_core::Cancel;
use image::{DynamicImage, GenericImageView, ImageFormat};
use std::io::Cursor;
use std::time::Duration;

/// Formats every major provider decodes (Anthropic's list; OpenAI/Gemini accept these too).
pub const SUPPORTED: &[&str] = &["image/jpeg", "image/png", "image/gif", "image/webp"];
/// OpenClaw `DEFAULT_IMAGE_MAX_DIMENSION_PX` / `DEFAULT_IMAGE_MAX_BYTES`.
pub const DEFAULT_MAX_DIMENSION_PX: u32 = 1200;
pub const DEFAULT_MAX_BYTES: usize = 5 * 1024 * 1024;
/// OpenClaw `MAX_IMAGE_INPUT_BYTES`: decoded-size ceiling before any decode is attempted.
pub const MAX_INPUT_BYTES: usize = 10 * 1024 * 1024;
/// OpenClaw `MAX_IMAGE_INPUT_PIXELS`.
pub const MAX_INPUT_PIXELS: u64 = 25_000_000;
/// OpenClaw `IMAGE_REDUCE_QUALITY_STEPS`.
pub const QUALITY_STEPS: &[u8] = &[85, 75, 65, 55, 45, 35];
/// Hermes `_VISION_MAX_VALIDATED_FRAME_COUNT` / `_VISION_MAX_VALIDATED_AGGREGATE_PIXELS`.
pub const MAX_VALIDATED_FRAMES: usize = 100;
pub const MAX_VALIDATED_PIXELS: u64 = 100_000_000;

/// `(orig_w, orig_h, new_w, new_h)` when an image was downscaled.
pub type Scale = (u32, u32, u32, u32);

fn fmt_of(mime: &str) -> Option<ImageFormat> {
    Some(match mime {
        "image/png" => ImageFormat::Png,
        "image/jpeg" | "image/jpg" => ImageFormat::Jpeg,
        "image/gif" => ImageFormat::Gif,
        "image/webp" => ImageFormat::WebP,
        "image/bmp" => ImageFormat::Bmp,
        _ => return None,
    })
}

/// Decode with the format sniffed from the bytes (falls back to `mime`).
pub fn decode(bytes: &[u8], mime: &str) -> Result<DynamicImage, String> {
    let mut r = image::ImageReader::new(Cursor::new(bytes));
    r.set_format(match image::guess_format(bytes).ok().or_else(|| fmt_of(mime)) {
        Some(f) => f,
        None => return Err(format!("unsupported image format {mime}")),
    });
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(512 * 1024 * 1024);
    r.limits(limits);
    r.decode().map_err(|e| e.to_string())
}

/// `(width, height)` from the header only (PNG IHDR, JPEG SOF; other formats via the decoder's
/// header probe). Hermes `image_dimensions_from_bytes`.
pub fn dimensions(raw: &[u8]) -> Option<(u32, u32)> {
    if raw.starts_with(b"\x89PNG\r\n\x1a\n") && raw.len() >= 24 {
        return Some((u32::from_be_bytes(raw[16..20].try_into().ok()?), u32::from_be_bytes(raw[20..24].try_into().ok()?)));
    }
    if raw.starts_with(&[0xff, 0xd8]) && raw.len() > 4 {
        const SOF: &[u8] = &[0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF];
        let mut i = 2;
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
            let len = u16::from_be_bytes([raw[i], raw[i + 1]]) as usize;
            if len < 2 || i + len > raw.len() {
                break;
            }
            if SOF.contains(&marker) && len >= 7 {
                return Some((u16::from_be_bytes([raw[i + 5], raw[i + 6]]) as u32, u16::from_be_bytes([raw[i + 3], raw[i + 4]]) as u32));
            }
            i += len;
        }
        return None;
    }
    image::ImageReader::new(Cursor::new(raw)).with_guessed_format().ok()?.into_dimensions().ok()
}

/// Length of `data:<mime>;base64,<payload>` for `n` raw bytes.
pub fn data_url_len(mime: &str, n: usize) -> usize {
    "data:;base64,".len() + mime.len() + n.div_ceil(3) * 4
}

fn encode(img: &DynamicImage, png: bool, quality: u8) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    if png {
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png).map_err(|e| e.to_string())?;
    } else {
        let rgb = img.to_rgb8();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, quality).encode_image(&rgb).map_err(|e| e.to_string())?;
    }
    Ok(buf)
}

pub fn to_png(img: &DynamicImage) -> Result<Vec<u8>, String> {
    encode(img, true, 0)
}

fn run_converter(argv: &[String], out: &std::path::Path) -> bool {
    let ok = crate::proc::run(argv, None, Duration::from_secs(30), &Cancel::new()).map(|o| o.success()).unwrap_or(false);
    ok && std::fs::metadata(out).map(|m| m.len() > 0).unwrap_or(false)
}

/// SVG → PNG through rsvg-convert or inkscape (Hermes `_rasterize_svg_to_png`).
pub fn rasterize_svg(svg: &[u8]) -> Option<Vec<u8>> {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = scratch_dir();
    let stem = dir.join(format!("{}-{}", crate::store::stem("svg"), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let (inp, out) = (stem.with_extension("svg"), stem.with_extension("png"));
    std::fs::write(&inp, svg).ok()?;
    let mut res = None;
    let cmds: [(&str, Vec<String>); 2] = [
        ("rsvg-convert", vec!["-o".into(), out.display().to_string(), inp.display().to_string()]),
        ("inkscape", vec![inp.display().to_string(), "--export-type=png".into(), format!("--export-filename={}", out.display())]),
    ];
    for (bin, args) in cmds {
        if let Some(p) = crate::proc::which(bin) {
            let mut argv = vec![p.display().to_string()];
            argv.extend(args);
            if run_converter(&argv, &out) {
                res = std::fs::read(&out).ok();
                break;
            }
        }
    }
    let _ = std::fs::remove_file(&inp);
    let _ = std::fs::remove_file(&out);
    res
}

fn scratch_dir() -> std::path::PathBuf {
    let d = std::env::var_os("TMPDIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir).join(format!("seagent-vision-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = seagent_core::platform::fs_private::set_private(&d);
    d
}

/// Ensure a provider-supported format (Hermes `_normalize_to_supported_image`): supported
/// input is returned unchanged; SVG is rasterized; BMP (and anything the decoder reads)
/// re-encodes as PNG; HEIC/AVIF go through ffmpeg when installed.
pub fn normalize(bytes: &[u8], mime: &str) -> Result<(Vec<u8>, String), String> {
    let sniffed = crate::store::sniff(bytes);
    let mime = if sniffed != "application/octet-stream" { sniffed } else { mime };
    if SUPPORTED.contains(&mime) {
        return Ok((bytes.to_vec(), mime.to_string()));
    }
    if mime == "image/svg+xml" {
        return rasterize_svg(bytes).map(|b| (b, "image/png".to_string())).ok_or_else(|| {
            "This is an SVG, which vision models cannot read directly, and no SVG rasterizer is installed (tried rsvg-convert, inkscape). Convert the SVG to PNG first — e.g. open it in a browser and screenshot it — then retry on the PNG.".to_string()
        });
    }
    if let Ok(img) = decode(bytes, mime) {
        return Ok((to_png(&img)?, "image/png".into()));
    }
    if matches!(mime, "image/heic" | "image/avif") {
        let ext = if mime == "image/heic" { "heic" } else { "avif" };
        if let Ok(png) = crate::audio::ffmpeg_transcode(bytes, ext, &["-frames:v", "1", "-f", "image2", "-c:v", "png"], &Cancel::new()) {
            if decode(&png, "image/png").is_ok() {
                return Ok((png, "image/png".into()));
            }
        }
        return Err(if mime == "image/heic" {
            "This is a HEIC/HEIF image (common for iPhone photos), which vision models cannot read directly, and no HEIF decoder is available. Install ffmpeg with libheif support, or convert the image to PNG/JPEG first.".into()
        } else {
            "This is an AVIF image, which vision models cannot read directly, and no AV1 decoder is available. Install ffmpeg with an AV1 decoder, or convert the image to PNG/JPEG first.".into()
        });
    }
    Err(format!("Image format '{mime}' is not supported by the vision API and could not be converted to PNG. Convert it to PNG or JPEG and try again."))
}

/// Error unless every frame decodes (Hermes `_validate_raster_image_decodable`): header sniffing
/// cannot tell a truncated download from a valid image. Animations are bounded by frame count
/// and aggregate pixels.
pub fn validate_decodable(bytes: &[u8], mime: &str) -> Result<(), String> {
    if image::guess_format(bytes).ok() == Some(ImageFormat::Gif) {
        use image::AnimationDecoder;
        let dec = image::codecs::gif::GifDecoder::new(Cursor::new(bytes)).map_err(|e| format!("Image could not be fully decoded: {e}"))?;
        let mut pixels: u64 = 0;
        for (n, frame) in dec.into_frames().enumerate() {
            let n = n + 1;
            if n > MAX_VALIDATED_FRAMES {
                return Err(format!("Image validation rejected animation: frame {n} exceeds the maximum {MAX_VALIDATED_FRAMES} validated frames."));
            }
            let f = frame.map_err(|e| format!("Image could not be fully decoded: {e}"))?;
            let next = pixels + f.buffer().width() as u64 * f.buffer().height() as u64;
            if next > MAX_VALIDATED_PIXELS {
                return Err(format!("Image validation rejected animation: aggregate decoded pixel count would reach {next} at frame {n}, exceeding the maximum {MAX_VALIDATED_PIXELS}."));
            }
            pixels = next;
        }
        return Ok(());
    }
    decode(bytes, mime).map(|_| ()).map_err(|e| format!("Image could not be fully decoded: {e}"))
}

/// Crop to `[x1, y1, x2, y2]` in original pixels, clamped to the bounds, BEFORE any downscale
/// so the crop keeps the full resolution budget (Hermes `_crop_image_region`, from qwen-code
/// zoom-image.ts). Returns PNG bytes and the crop origin.
pub fn crop(bytes: &[u8], mime: &str, region: &[i64]) -> Result<(Vec<u8>, (u32, u32)), String> {
    if region.len() != 4 {
        return Err("Invalid region: expected [x1, y1, x2, y2] as four numbers (pixel coordinates in the original image).".into());
    }
    let img = decode(bytes, mime).map_err(|e| format!("Failed to crop region: {e}"))?;
    let (w, h) = img.dimensions();
    let c = |v: i64, b: u32| v.clamp(0, b as i64) as u32;
    let (x1, y1, x2, y2) = (c(region[0], w), c(region[1], h), c(region[2], w), c(region[3], h));
    if x2 <= x1 || y2 <= y1 {
        return Err(format!(
            "Invalid region [{}, {}, {}, {}]: crops to zero area after clamping to the image bounds. The image is {w}x{h} px — pick x1<x2 and y1<y2 inside [0, 0, {w}, {h}].",
            region[0], region[1], region[2], region[3]
        ));
    }
    Ok((to_png(&img.crop_imm(x1, y1, x2 - x1, y2 - y1))?, (x1, y1)))
}

/// Hermes `_resize_image_for_vision`: halve dimensions (aspect-preserving, 64 px floor) up to 4
/// times; JPEG also walks a 85/70/50 quality ladder per step, until the data URL fits
/// `max_data_url` and the long edge fits `max_dim`. PNG stays PNG unless `force_jpeg` (halving a
/// dense screenshot's PNG destroys text). Returns the best attempt when nothing fits.
pub fn resize_for_vision(bytes: &[u8], mime: &str, max_data_url: usize, max_dim: Option<u32>, force_jpeg: bool) -> (Vec<u8>, String, Option<Scale>) {
    let over_dim = |d: Option<(u32, u32)>| max_dim.is_some_and(|m| d.is_some_and(|(w, h)| w.max(h) > m));
    if data_url_len(mime, bytes.len()) <= max_data_url && !over_dim(dimensions(bytes)) {
        return (bytes.to_vec(), mime.to_string(), None);
    }
    let Ok(mut img) = decode(bytes, mime) else { return (bytes.to_vec(), mime.to_string(), None) };
    let png = mime == "image/png" && !force_jpeg;
    let out_mime = if png { "image/png" } else { "image/jpeg" };
    let qualities: &[u8] = if png { &[0] } else { &[85, 70, 50] };
    let orig = img.dimensions();
    let mut prev = orig;
    let mut best: Option<Vec<u8>> = None;
    for attempt in 0..5 {
        if attempt > 0 {
            let (w, h) = img.dimensions();
            let (mut nw, mut nh) = (((w as f64 * 0.5) as u32).max(64), ((h as f64 * 0.5) as u32).max(64));
            if nw == 64 && w > 0 {
                nh = ((h as f64 * (64.0 / w as f64)) as u32).max(64);
            } else if nh == 64 && h > 0 {
                nw = ((w as f64 * (64.0 / h as f64)) as u32).max(64);
            }
            if (nw, nh) == prev {
                break;
            }
            img = img.resize_exact(nw, nh, image::imageops::FilterType::Lanczos3);
            prev = (nw, nh);
        }
        let dims_ok = max_dim.is_none_or(|m| img.width().max(img.height()) <= m);
        for &q in qualities {
            let Ok(b) = encode(&img, png, q) else { continue };
            let fits = data_url_len(out_mime, b.len()) <= max_data_url && dims_ok;
            best = Some(b);
            if fits {
                let d = img.dimensions();
                return (best.unwrap(), out_mime.into(), (d != orig).then_some((orig.0, orig.1, d.0, d.1)));
            }
        }
    }
    let d = img.dimensions();
    match best {
        Some(b) => (b, out_mime.into(), (d != orig).then_some((orig.0, orig.1, d.0, d.1))),
        None => (bytes.to_vec(), mime.to_string(), None),
    }
}

/// OpenClaw `buildImageResizeSideGrid`.
pub fn side_grid(max_side: u32, side_start: u32) -> Vec<u32> {
    let mut v: Vec<u32> = Vec::new();
    for x in [side_start, 1800, 1600, 1400, 1200, 1000, 800] {
        let x = x.min(max_side);
        if x > 0 && !v.contains(&x) {
            v.push(x);
        }
    }
    v.sort_unstable_by(|a, b| b.cmp(a));
    v
}

fn short_bytes(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{:.2}MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1}KB", n as f64 / 1024.0)
    } else {
        format!("{n}B")
    }
}

/// OpenClaw image sanitization (`resizeImageBase64IfNeeded`): images within `max_dim` px per
/// side, `max_bytes` and 25 MP pass through unchanged (after an optional full-decode check);
/// others are re-encoded as JPEG walking the side grid × quality ladder until they fit.
pub fn sanitize(bytes: &[u8], mime: &str, max_dim: u32, max_bytes: usize, verify: bool) -> Result<(Vec<u8>, String), String> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(format!("image exceeds input size limit ({})", short_bytes(MAX_INPUT_BYTES)));
    }
    if bytes.is_empty() {
        return Err("empty image payload".into());
    }
    let sniffed = crate::store::sniff(bytes);
    let mime = if sniffed.starts_with("image/") { sniffed } else { mime };
    let meta = dimensions(bytes);
    let within = meta.is_some_and(|(w, h)| w > 0 && h > 0 && w <= max_dim && h <= max_dim && (w as u64 * h as u64) <= MAX_INPUT_PIXELS) && bytes.len() <= max_bytes;
    if within && SUPPORTED.contains(&mime) {
        if verify {
            validate_decodable(bytes, mime)?;
        }
        return Ok((bytes.to_vec(), mime.to_string()));
    }
    if let Some((w, h)) = meta {
        if w as u64 * h as u64 > MAX_INPUT_PIXELS * 4 {
            return Err(format!("image has too many pixels ({w}x{h})"));
        }
    }
    let img = decode(bytes, mime)?;
    let max_side = meta.map(|(w, h)| w.max(h)).unwrap_or(max_dim);
    let start = if max_side > 0 { max_dim.min(max_side) } else { max_dim };
    let mut smallest: Option<usize> = None;
    for side in side_grid(max_dim, start) {
        let scaled = if img.width().max(img.height()) > side { img.resize(side, side, image::imageops::FilterType::Lanczos3) } else { img.clone() };
        for &q in QUALITY_STEPS {
            let out = encode(&scaled, false, q)?;
            smallest = Some(smallest.map_or(out.len(), |s| s.min(out.len())));
            if out.len() <= max_bytes {
                return Ok((out, "image/jpeg".into()));
            }
        }
    }
    Err(format!("Image could not be reduced below {} (got {})", short_bytes(max_bytes), short_bytes(smallest.unwrap_or(bytes.len()))))
}

/// Hermes `_build_scale_note`: how to map reported coordinates back to the original image.
pub fn scale_note(scale: Option<Scale>, crop: Option<(u32, u32)>) -> Option<String> {
    let mut parts = Vec::new();
    if let Some((ow, oh, nw, nh)) = scale {
        let fx = if nw > 0 { ow as f64 / nw as f64 } else { 1.0 };
        let fy = if nh > 0 { oh as f64 / nh as f64 } else { 1.0 };
        let axes = if format!("{fx:.2}") == format!("{fy:.2}") { format!("any coordinates you report by {fx:.2}") } else { format!("any x coordinates you report by {fx:.2} and any y coordinates by {fy:.2}") };
        parts.push(format!("Image downscaled from {ow}x{oh} to {nw}x{nh} for vision; multiply {axes} to map back to the original image."));
    }
    if let Some((x, y)) = crop {
        parts.push(format!("Analysis was performed on a cropped region of the original image starting at offset ({x}, {y}); coordinates are relative to that crop origin — add the offset to map back to the full image."));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

#[cfg(test)]
pub(crate) fn test_png(w: u32, h: u32) -> Vec<u8> {
    let img = image::RgbImage::from_fn(w, h, |x, y| image::Rgb([(x * 7 % 256) as u8, (y * 13 % 256) as u8, ((x ^ y) % 256) as u8]));
    to_png(&DynamicImage::ImageRgb8(img)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_dimensions_png_and_jpeg() {
        let png = test_png(31, 17);
        assert_eq!(dimensions(&png), Some((31, 17)));
        let jpg = encode(&decode(&png, "image/png").unwrap(), false, 80).unwrap();
        assert_eq!(dimensions(&jpg), Some((31, 17)));
        assert_eq!(dimensions(b"nope"), None);
    }

    #[test]
    fn sanitize_passes_small_and_shrinks_large() {
        let small = test_png(100, 50);
        let (b, m) = sanitize(&small, "image/png", 1200, DEFAULT_MAX_BYTES, true).unwrap();
        assert_eq!((b.len(), m.as_str()), (small.len(), "image/png"));
        let big = test_png(2400, 600);
        let (b, m) = sanitize(&big, "image/png", 1200, DEFAULT_MAX_BYTES, true).unwrap();
        assert_eq!(m, "image/jpeg");
        let (w, h) = dimensions(&b).unwrap();
        assert!(w <= 1200 && h <= 1200, "{w}x{h}");
        assert!(sanitize(b"\x89PNG\r\n\x1a\ngarbage-garbage-garbage", "image/png", 1200, 1000, true).is_err());
        let e = sanitize(&test_png(800, 800), "image/png", 1200, 200, false).unwrap_err();
        assert!(e.starts_with("Image could not be reduced below 200B"), "{e}");
        assert_eq!(side_grid(1200, 900), vec![1200, 1000, 900, 800]);
        assert!(side_grid(0, 0).is_empty());
    }

    #[test]
    fn normalize_crop_resize_and_notes() {
        // BMP is decodable but unsupported by providers → PNG.
        let img = decode(&test_png(10, 10), "image/png").unwrap();
        let mut bmp = Vec::new();
        img.write_to(&mut Cursor::new(&mut bmp), ImageFormat::Bmp).unwrap();
        let (b, m) = normalize(&bmp, "image/bmp").unwrap();
        assert_eq!((m.as_str(), dimensions(&b)), ("image/png", Some((10, 10))));
        assert!(normalize(b"\x00\x01junk", "image/tiff").unwrap_err().contains("not supported"));
        let (c, off) = crop(&test_png(100, 80), "image/png", &[10, 20, 500, 60]).unwrap();
        assert_eq!((dimensions(&c), off), (Some((90, 40)), (10, 20)));
        assert!(crop(&test_png(10, 10), "image/png", &[5, 5, 5, 9]).unwrap_err().contains("zero area"));
        let big = test_png(3000, 1000);
        let (b, m, s) = resize_for_vision(&big, "image/png", 256 * 1024, Some(1568), true);
        assert_eq!(m, "image/jpeg");
        assert!(data_url_len(&m, b.len()) <= 256 * 1024);
        let (ow, oh, nw, nh) = s.unwrap();
        assert_eq!((ow, oh), (3000, 1000));
        assert!(nw.max(nh) <= 1568);
        let note = scale_note(s, Some((3, 4))).unwrap();
        assert!(note.contains("downscaled from 3000x1000") && note.contains("offset (3, 4)"), "{note}");
        let (same, _, none) = resize_for_vision(&test_png(20, 20), "image/png", 1 << 20, Some(1568), true);
        assert!(none.is_none() && same == test_png(20, 20));
        assert!(validate_decodable(&test_png(4, 4), "image/png").is_ok());
        assert!(validate_decodable(&test_png(40, 40)[..60], "image/png").is_err());
    }
}
