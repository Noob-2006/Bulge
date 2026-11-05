//! Media bytes: the `Asset` every provider returns, MIME sniffing and extension
//! tables, `data:` URLs, saving generated files, and the `MEDIA:<path>` reply
//! directive channels turn into attachments (`[[audio_as_voice]]` = voice bubble).

use base64::Engine;
use std::path::{Path, PathBuf};

/// One generated or loaded media file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Asset {
    pub bytes: Vec<u8>,
    pub mime: String,
    /// Provider-hosted URL (some providers return only that; `bytes` may then be empty).
    pub url: Option<String>,
    /// Prompt as rewritten by the provider (DALL·E / gpt-image `revised_prompt`).
    pub revised_prompt: Option<String>,
    pub meta: serde_json::Value,
}

impl Asset {
    pub fn new(bytes: Vec<u8>, mime: &str) -> Self {
        let mime = if mime.is_empty() || mime == "application/octet-stream" { sniff(&bytes).to_string() } else { mime.to_string() };
        Asset { bytes, mime, ..Default::default() }
    }
    pub fn from_url(url: &str, mime: &str) -> Self {
        Asset { url: Some(url.to_string()), mime: mime.to_string(), ..Default::default() }
    }
    pub fn from_b64(b64: &str, mime: &str) -> Result<Self, String> {
        Ok(Asset::new(b64_decode(b64)?, mime))
    }
}

pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(s.as_bytes()).or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=').as_bytes())).or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=').as_bytes())).map_err(|e| format!("bad base64: {e}"))
}

pub fn data_url(mime: &str, data: &[u8]) -> String {
    format!("data:{mime};base64,{}", b64(data))
}

/// `(mime, bytes)` of a `data:<mime>;base64,<…>` URL.
pub fn decode_data_url(u: &str) -> Option<(String, Vec<u8>)> {
    let rest = u.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let mime = meta.split(';').next().unwrap_or("").to_string();
    if meta.ends_with(";base64") {
        Some((mime, b64_decode(data).ok()?))
    } else {
        Some((mime, seagent_net::urldecode(data).into_bytes()))
    }
}

/// MIME type from magic bytes ("application/octet-stream" when unknown).
pub fn sniff(b: &[u8]) -> &'static str {
    let starts = |p: &[u8]| b.starts_with(p);
    if starts(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if starts(&[0xff, 0xd8, 0xff]) {
        "image/jpeg"
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        "image/gif"
    } else if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        "image/webp"
    } else if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WAVE" {
        "audio/wav"
    } else if b.len() >= 12 && &b[4..8] == b"ftyp" {
        let brand = &b[8..12];
        if brand == b"heic" || brand == b"heix" || brand == b"mif1" {
            "image/heic"
        } else if brand == b"avif" {
            "image/avif"
        } else if brand.starts_with(b"M4A") {
            "audio/mp4"
        } else if brand == b"qt  " {
            "video/quicktime"
        } else {
            "video/mp4"
        }
    } else if starts(b"OggS") {
        if b.len() > 36 && b[28..36].starts_with(b"OpusHead") {
            "audio/ogg"
        } else if b.windows(6).take(64).any(|w| w == b"theora") {
            "video/ogg"
        } else {
            "audio/ogg"
        }
    } else if starts(b"ID3") || (b.len() > 1 && b[0] == 0xff && (b[1] & 0xe0) == 0xe0 && (b[1] & 0x06) != 0) {
        "audio/mpeg"
    } else if starts(b"fLaC") {
        "audio/flac"
    } else if starts(&[0x1a, 0x45, 0xdf, 0xa3]) {
        if b.windows(4).take(64).any(|w| w == b"webm") {
            "video/webm"
        } else {
            "video/x-matroska"
        }
    } else if starts(b"%PDF-") {
        "application/pdf"
    } else if starts(b"PK\x03\x04") {
        "application/zip"
    } else if starts(b"#!AMR") {
        "audio/amr"
    } else if b.len() > 1 && b[0] == 0xff && (b[1] & 0xf6) == 0xf0 {
        "audio/aac"
    } else if starts(b"<svg") || (starts(b"<?xml") && b.windows(4).take(512).any(|w| w == b"<svg")) {
        "image/svg+xml"
    } else {
        "application/octet-stream"
    }
}

pub fn ext_for(mime: &str) -> &'static str {
    match mime.split(';').next().unwrap_or("").trim() {
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/heic" => "heic",
        "image/avif" => "avif",
        "image/svg+xml" => "svg",
        "audio/mpeg" | "audio/mp3" => "mp3",
        "audio/wav" | "audio/x-wav" | "audio/wave" => "wav",
        "audio/ogg" | "audio/opus" => "ogg",
        "audio/flac" => "flac",
        "audio/aac" => "aac",
        "audio/mp4" | "audio/m4a" | "audio/x-m4a" => "m4a",
        "audio/amr" => "amr",
        "audio/webm" => "weba",
        "audio/pcm" | "audio/l16" => "pcm",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "video/quicktime" => "mov",
        "video/x-matroska" => "mkv",
        "video/ogg" => "ogv",
        "application/pdf" => "pdf",
        "application/json" => "json",
        "text/plain" => "txt",
        _ => "bin",
    }
}

pub fn mime_for_path(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic" | "heif") => "image/heic",
        Some("avif") => "image/avif",
        Some("bmp") => "image/bmp",
        Some("svg") => "image/svg+xml",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("ogg" | "oga" | "opus") => "audio/ogg",
        Some("flac") => "audio/flac",
        Some("aac") => "audio/aac",
        Some("m4a") => "audio/mp4",
        Some("amr") => "audio/amr",
        Some("weba") => "audio/webm",
        Some("pcm") => "audio/pcm",
        Some("mp4" | "m4v") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mov") => "video/quicktime",
        Some("mkv") => "video/x-matroska",
        Some("avi") => "video/x-msvideo",
        Some("pdf") => "application/pdf",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        Some("ipynb") => "application/x-ipynb+json",
        Some("txt" | "md" | "csv" | "log") => "text/plain",
        _ => "application/octet-stream",
    }
}

/// Coarse class of a MIME type: "image", "audio", "video" or "document".
pub fn class_of(mime: &str) -> &'static str {
    match mime.split('/').next().unwrap_or("") {
        "image" => "image",
        "audio" => "audio",
        "video" => "video",
        _ => "document",
    }
}

/// Read a local file or fetch an http(s)/data: URL; returns `(bytes, mime)`.
///
/// Remote fetches go through [`crate::http::Http::download`], i.e. the url-safety policy
/// built from `m.cfg`: a document/video/image URL cannot reach cloud metadata, and private
/// addresses only when the operator allowed them (or configured that host as a provider).
pub fn load(src: &str, workspace: &Path, m: &crate::Media, max: usize) -> Result<(Vec<u8>, String), String> {
    let (bytes, mime) = if src.starts_with("data:") {
        decode_data_url(src).map(|(m, b)| (b, m)).ok_or("malformed data: URL")?
    } else if src.starts_with("http://") || src.starts_with("https://") {
        let (b, ct) = m.http.download(&m.cfg, src, &[])?;
        (b, ct)
    } else {
        let p = resolve(src, workspace);
        let meta = std::fs::metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if meta.len() as usize > max {
            return Err(format!("{}: {} bytes exceeds the {max}-byte limit", p.display(), meta.len()));
        }
        let b = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let m = mime_for_path(&p);
        (b, m.to_string())
    };
    if bytes.len() > max {
        return Err(format!("{} bytes exceeds the {max}-byte limit", bytes.len()));
    }
    let sniffed = sniff(&bytes);
    let mime = if mime.is_empty() || (sniffed != "application/octet-stream" && (mime == "application/octet-stream" || class_of(&mime) == class_of(sniffed))) { sniffed.to_string() } else { mime };
    Ok((bytes, mime))
}

pub fn resolve(p: &str, workspace: &Path) -> PathBuf {
    let p = p.strip_prefix("file://").unwrap_or(p);
    let p = seagent_core::tool::expand_home(p);
    if p.is_absolute() {
        p
    } else {
        workspace.join(p)
    }
}

/// Save `asset` under `<dir>/<stem>.<ext>`, never overwriting; returns the path.
pub fn save(dir: &Path, stem: &str, asset: &Asset) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let ext = ext_for(&asset.mime);
    let safe: String = stem.chars().map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_') { c } else { '_' }).take(80).collect();
    let mut p = dir.join(format!("{safe}.{ext}"));
    let mut n = 1;
    while p.exists() {
        p = dir.join(format!("{safe}-{n}.{ext}"));
        n += 1;
    }
    std::fs::write(&p, &asset.bytes).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(p)
}

/// `<kind>-<unix ms>-<seq>-<rand>` file stem for generated media.
///
/// The millisecond clock alone is not unique: two decodes/syntheses starting in the same
/// millisecond used to produce the same stem, hence the same `seagent-ff-…` work directory, and
/// whichever finished first deleted the other's `in.wav`/`out.bin` mid-run. A process-wide
/// counter plus 8 random bytes (so separate processes cannot collide either) keeps every
/// stem — and every path or temp dir built from it — unique.
pub fn stem(kind: &str) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Both suffixes are fixed-width hex: a 3-digit run such as `402` can then never be a
    // whole `-`-delimited segment of a temp path (ffmpeg error text is scanned for bare
    // HTTP codes like `402`/`413`, see `understand::video_error_text`).
    format!("{kind}-{ms}-{seq:08x}-{}", random_hex())
}

/// Eight random bytes as hex (`/dev/urandom`, clock+pid fallback when it is unavailable).
fn random_hex() -> String {
    use std::io::Read;
    let mut b = [0u8; 8];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok();
    if !ok || b == [0u8; 8] {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
        b = (t ^ ((std::process::id() as u64) << 32)).to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A unique work directory for one call that shells out (`seagent-<tag>-<pid>-<stem>`), created
/// owner-only: these directories hold raw audio, video frames and transcripts of private
/// conversations, so they must not be world-readable like `create_dir_all`'s default.
pub fn temp_dir(tag: &str) -> Result<PathBuf, String> {
    let d = std::env::temp_dir().join(format!("seagent-{tag}-{}-{}", std::process::id(), stem("x")));
    private_dir(&d)?;
    Ok(d)
}

/// Create `dir` with mode 0700 (umask may only tighten it).
pub fn private_dir(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| format!("{}: {e}", dir.display()))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
    }
}

pub const VOICE_DIRECTIVE: &str = "[[audio_as_voice]]";

/// `MEDIA:<path>` lines for `paths`, prefixed by the voice directive when asked.
pub fn media_tags(paths: &[PathBuf], voice: bool) -> String {
    let tags: Vec<String> = paths.iter().map(|p| format!("MEDIA:{}", p.display())).collect();
    if voice {
        format!("{VOICE_DIRECTIVE}\n{}", tags.join("\n"))
    } else {
        tags.join("\n")
    }
}

/// A file the reply asks the channel to attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub path: String,
    /// Deliver audio as a voice bubble.
    pub voice: bool,
}

/// Split a reply into its text and the `MEDIA:` attachments it names. Only whole lines
/// (optionally in backticks/quotes) count, so prose mentioning "MEDIA:" stays text.
pub fn extract_directives(text: &str) -> (String, Vec<Directive>) {
    let voice = text.contains(VOICE_DIRECTIVE);
    let mut out = Vec::new();
    let mut kept = Vec::new();
    for line in text.lines() {
        let t = line.trim().trim_matches(|c| c == '`' || c == '"' || c == '\'').trim();
        if t == VOICE_DIRECTIVE {
            continue;
        }
        if let Some(p) = t.strip_prefix("MEDIA:") {
            let p = p.trim().trim_matches(|c| c == '`' || c == '"' || c == '\'');
            if !p.is_empty() && !p.contains(char::is_whitespace) || Path::new(p).exists() {
                if !out.iter().any(|d: &Directive| d.path == p) {
                    out.push(Directive { path: p.to_string(), voice });
                }
                continue;
            }
        }
        kept.push(line);
    }
    let mut clean = kept.join("\n");
    clean = clean.replace(VOICE_DIRECTIVE, "");
    (clean.trim().to_string(), out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_and_ext() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\nxxxx"), "image/png");
        assert_eq!(sniff(&[0xff, 0xd8, 0xff, 0xe0]), "image/jpeg");
        assert_eq!(sniff(b"RIFF\0\0\0\0WAVEfmt "), "audio/wav");
        assert_eq!(sniff(b"ID3\x04"), "audio/mpeg");
        assert_eq!(sniff(b"\0\0\0\x18ftypmp42"), "video/mp4");
        assert_eq!(sniff(b"%PDF-1.7"), "application/pdf");
        assert_eq!(ext_for("audio/ogg; codecs=opus"), "ogg");
        assert_eq!(mime_for_path(Path::new("a/B.JPG")), "image/jpeg");
        assert_eq!(class_of("video/mp4"), "video");
    }

    #[test]
    fn data_urls_roundtrip() {
        let u = data_url("image/png", b"abc");
        assert_eq!(decode_data_url(&u), Some(("image/png".into(), b"abc".to_vec())));
        assert_eq!(decode_data_url("data:text/plain,hi%20there").unwrap().1, b"hi there");
        assert_eq!(b64_decode("YWJj").unwrap(), b"abc");
        assert_eq!(b64_decode("YWI").unwrap(), b"ab");
    }

    #[test]
    fn save_never_overwrites() {
        let d = crate::testutil::temp_dir("store");
        let a = Asset::new(b"\x89PNG\r\n\x1a\n".to_vec(), "");
        let p1 = save(&d, "img", &a).unwrap();
        let p2 = save(&d, "img", &a).unwrap();
        assert_eq!(p1.file_name().unwrap(), "img.png");
        assert_eq!(p2.file_name().unwrap(), "img-1.png");
    }

    #[test]
    fn stems_and_temp_dirs_are_unique_within_a_millisecond() {
        // Same millisecond, different ids: a plain `<kind>-<ms>` stem made two decodes share
        // `in.wav`/`out.bin` and one `remove_dir_all` delete the other's directory.
        let stems: Vec<String> = (0..64).map(|_| stem("x")).collect();
        assert_eq!(stems.iter().collect::<std::collections::HashSet<_>>().len(), stems.len(), "{stems:?}");
        let dirs: Vec<PathBuf> = (0..16).map(|_| temp_dir("ff").unwrap()).collect();
        assert_eq!(dirs.iter().collect::<std::collections::HashSet<_>>().len(), dirs.len(), "{dirs:?}");
        // Owner-only: the directories hold private audio/video and the spoken text.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dirs[0]).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode & 0o077, 0, "{:?} is reachable by group/other (mode {mode:o})", dirs[0]);
        }
        for d in dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn directives_split_reply() {
        let (t, d) = extract_directives("Here you go.\n[[audio_as_voice]]\nMEDIA:/tmp/a.ogg\n`MEDIA:/tmp/b.png`\nThe MEDIA: tag is explained above.");
        assert_eq!(t, "Here you go.\nThe MEDIA: tag is explained above.");
        assert_eq!(d, vec![Directive { path: "/tmp/a.ogg".into(), voice: true }, Directive { path: "/tmp/b.png".into(), voice: true }]);
        assert_eq!(media_tags(&[PathBuf::from("/x.mp3")], true), "[[audio_as_voice]]\nMEDIA:/x.mp3");
    }
}
