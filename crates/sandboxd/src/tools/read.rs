//! Paged file / directory reading for the model.
//! MARK: M14 — transcribed by dsh; see marks/M14-read.md.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    /// `text` is numbered `N: line` (1-based). `next_offset` is set when more lines remain.
    Text { text: String, total_lines: usize, next_offset: Option<usize> },
    /// Sorted entries; directories end with `/`.
    Directory { entries: Vec<String>, total: usize, next_offset: Option<usize> },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("binary file: {0}")]
    Binary(String),
    #[error("offset {offset} is past the end ({total} lines)")]
    OffsetPastEnd { offset: usize, total: usize },
    #[error("io: {0}")]
    Io(String),
}

pub const DEFAULT_LIMIT: usize = 2000;
/// Longer lines are cut and marked so one minified line cannot flood context.
pub const MAX_LINE_CHARS: usize = 2000;

/// How many leading bytes are inspected for media signatures, NUL bytes and
/// the proportion of non-text bytes.
const SNIFF_BYTES: usize = 8 * 1024;
/// A prefix with more than this percentage of control bytes is binary.
const MAX_NON_TEXT_PERCENT: usize = 30;
/// Appended to lines longer than [`MAX_LINE_CHARS`].
const LINE_TRUNCATION_SUFFIX: &str = "… [line truncated]";
/// Enough bytes to always decode at least `MAX_LINE_CHARS` characters
/// (UTF-8 uses at most four bytes per character), plus room for a partial
/// character at the cut so the retained prefix stays usable.
const LINE_KEEP_BYTES: usize = MAX_LINE_CHARS * 4 + 4;

/// `offset` is 1-based (default 1); `limit` defaults to and is capped at `DEFAULT_LIMIT`.
pub fn read_page(path: &Path, offset: Option<usize>, limit: Option<usize>) -> Result<Page, ReadError> {
    let metadata = fs::metadata(path).map_err(|error| io_error(path, &error))?;
    if metadata.is_dir() {
        read_directory(path, offset, limit)
    } else if metadata.is_file() {
        read_text(path, offset, limit)
    } else {
        Err(ReadError::Io(format!("unsupported file type: {}", path.display())))
    }
}

fn normalize_offset(offset: Option<usize>) -> usize {
    offset.filter(|value| *value > 0).unwrap_or(1)
}

fn normalize_limit(limit: Option<usize>) -> usize {
    limit.filter(|value| *value > 0).unwrap_or(DEFAULT_LIMIT).min(DEFAULT_LIMIT)
}

fn io_error(path: &Path, error: &io::Error) -> ReadError {
    if error.kind() == io::ErrorKind::NotFound {
        ReadError::NotFound(path.display().to_string())
    } else {
        ReadError::Io(error.to_string())
    }
}

/// Direct children, directories first (matching the reference), each group
/// ordered by name. Symlinks are listed by their link name; directories get a
/// trailing `/`.
fn read_directory(path: &Path, offset: Option<usize>, limit: Option<usize>) -> Result<Page, ReadError> {
    let offset = normalize_offset(offset);
    let limit = normalize_limit(limit);

    let mut all = Vec::new();
    for entry in fs::read_dir(path).map_err(|error| io_error(path, &error))? {
        let entry = entry.map_err(|error| io_error(path, &error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_directory = entry.file_type().map_err(|error| io_error(path, &error))?.is_dir();
        all.push((name, is_directory));
    }
    all.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    let total = all.len();
    let start = offset.saturating_sub(1);
    let entries = all
        .iter()
        .skip(start)
        .take(limit)
        .map(|(name, is_directory)| if *is_directory { format!("{name}/") } else { name.clone() })
        .collect::<Vec<_>>();
    let next_offset = (start.saturating_add(entries.len()) < total).then(|| offset.saturating_add(entries.len()));

    Ok(Page::Directory { entries, total, next_offset })
}

fn read_text(path: &Path, offset: Option<usize>, limit: Option<usize>) -> Result<Page, ReadError> {
    let offset = normalize_offset(offset);
    let limit = normalize_limit(limit);

    let mut file = File::open(path).map_err(|error| io_error(path, &error))?;
    let mut head = Vec::with_capacity(SNIFF_BYTES);
    (&file)
        .take(SNIFF_BYTES as u64)
        .read_to_end(&mut head)
        .map_err(|error| io_error(path, &error))?;
    if looks_binary(&head) {
        return Err(ReadError::Binary(path.display().to_string()));
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| io_error(path, &error))?;

    let mut reader = BufReader::new(file);
    let mut total_lines = 0usize;
    let mut numbered = Vec::new();
    while let Some(line) = read_line_capped(&mut reader).map_err(|error| io_error(path, &error))? {
        total_lines = total_lines.saturating_add(1);
        if total_lines >= offset && numbered.len() < limit {
            numbered.push(format!("{total_lines}: {}", clamp_line(&line)));
        }
    }

    // An empty file is readable from offset 1 (but not from a later offset).
    if offset > total_lines.max(1) {
        return Err(ReadError::OffsetPastEnd { offset, total: total_lines });
    }
    let next_offset = if offset.saturating_add(numbered.len()) <= total_lines {
        Some(offset.saturating_add(numbered.len()))
    } else {
        None
    };

    Ok(Page::Text { text: numbered.join("\n"), total_lines, next_offset })
}

/// The format of a line as read from disk: no newline, no trailing `\r`, and
/// lossily decoded if it is not valid UTF-8. Only the prefix needed to render
/// a clamped line is retained, so a single enormous line is not buffered whole.
fn read_line_capped(reader: &mut BufReader<File>) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let content = &available[..newline];
            let room = LINE_KEEP_BYTES.saturating_sub(bytes.len());
            bytes.extend_from_slice(&content[..content.len().min(room)]);
            reader.consume(newline + 1);
            break;
        }
        let length = available.len();
        let room = LINE_KEEP_BYTES.saturating_sub(bytes.len());
        bytes.extend_from_slice(&available[..length.min(room)]);
        reader.consume(length);
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// Clamp at a UTF-8 character boundary and mark the cut.
fn clamp_line(line: &str) -> String {
    let mut characters = line.chars();
    let clamped = characters.by_ref().take(MAX_LINE_CHARS).collect::<String>();
    if characters.next().is_some() {
        format!("{clamped}{LINE_TRUNCATION_SUFFIX}")
    } else {
        clamped
    }
}

/// Images and PDFs are media, not text; this tool cannot present them, so they
/// are reported as binary rather than dumped into the context.
fn is_media(head: &[u8]) -> bool {
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
    head.starts_with(PNG)
        || head.starts_with(&[0xFF, 0xD8, 0xFF])
        || head.starts_with(b"GIF87a")
        || head.starts_with(b"GIF89a")
        || (head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WEBP")
        || head.starts_with(b"%PDF-")
}

fn is_text_byte(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r' || byte == b'\t' || (0x20..=0x7E).contains(&byte) || byte >= 0x80
}

fn looks_binary(head: &[u8]) -> bool {
    if is_media(head) || head.contains(&0) {
        return true;
    }
    if head.is_empty() {
        return false;
    }
    let non_text = head.iter().filter(|byte| !is_text_byte(**byte)).count();
    non_text * 100 > head.len() * MAX_NON_TEXT_PERCENT
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bulge-m14-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("write test file");
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn reads_a_small_text_file_with_line_numbers() {
        let dir = TestDir::new();
        let file = dir.write("small.txt", "alpha\nbeta\n");

        assert_eq!(
            read_page(&file, None, None).expect("read page"),
            Page::Text {
                text: "1: alpha\n2: beta".to_owned(),
                total_lines: 2,
                next_offset: None,
            }
        );
    }

    #[test]
    fn pages_with_one_based_offsets_and_crlf_lines() {
        let dir = TestDir::new();
        let file = dir.write("lines.txt", "one\r\ntwo\nthree\n");

        assert_eq!(
            read_page(&file, Some(2), Some(1)).expect("read middle page"),
            Page::Text {
                text: "2: two".to_owned(),
                total_lines: 3,
                next_offset: Some(3),
            }
        );
        assert_eq!(
            read_page(&file, Some(3), Some(1)).expect("read last page"),
            Page::Text {
                text: "3: three".to_owned(),
                total_lines: 3,
                next_offset: None,
            }
        );
        // A zero offset means the default 1, matching the reference.
        assert_eq!(
            read_page(&file, Some(0), Some(1)).expect("read first page"),
            Page::Text {
                text: "1: one".to_owned(),
                total_lines: 3,
                next_offset: Some(2),
            }
        );
    }

    #[test]
    fn trailing_newline_does_not_create_an_extra_line() {
        let dir = TestDir::new();
        let file = dir.write("blank.txt", "alpha\n\n");

        assert_eq!(
            read_page(&file, None, Some(2)).expect("read page"),
            Page::Text {
                text: "1: alpha\n2: ".to_owned(),
                total_lines: 2,
                next_offset: None,
            }
        );
    }

    #[test]
    fn default_limit_is_capped_at_default_limit() {
        let dir = TestDir::new();
        let content = (0..DEFAULT_LIMIT + 5)
            .map(|index| format!("line-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let file = dir.write("many.txt", content);

        match read_page(&file, None, None).expect("read capped page") {
            Page::Text { text, total_lines, next_offset } => {
                assert_eq!(total_lines, DEFAULT_LIMIT + 5);
                assert_eq!(next_offset, Some(DEFAULT_LIMIT + 1));
                assert_eq!(text.lines().count(), DEFAULT_LIMIT);
                assert!(text.starts_with("1: line-0\n2: line-1\n"));
                assert!(text.ends_with(&format!("{DEFAULT_LIMIT}: line-{}", DEFAULT_LIMIT - 1)));
            }
            page => panic!("expected text page, got {page:?}"),
        }

        let file = dir.write("few.txt", "a\nb\nc\n");
        match read_page(&file, None, Some(usize::MAX)).expect("read clamped limit") {
            Page::Text { text, total_lines, next_offset } => {
                assert_eq!(text, "1: a\n2: b\n3: c");
                assert_eq!(total_lines, 3);
                assert_eq!(next_offset, None);
            }
            page => panic!("expected text page, got {page:?}"),
        }
    }

    #[test]
    fn truncates_long_ascii_lines() {
        let dir = TestDir::new();
        let long = "a".repeat(MAX_LINE_CHARS + 10);
        let file = dir.write("long.txt", &long);

        let page = read_page(&file, None, None).expect("read long line");
        let expected = format!("1: {}{LINE_TRUNCATION_SUFFIX}", "a".repeat(MAX_LINE_CHARS));
        assert_eq!(
            page,
            Page::Text {
                text: expected,
                total_lines: 1,
                next_offset: None,
            }
        );
    }

    #[test]
    fn truncates_long_multibyte_lines_without_splitting_characters() {
        let dir = TestDir::new();
        let long = "中".repeat(MAX_LINE_CHARS + 5);
        let file = dir.write("long-cjk.txt", long);

        let page = read_page(&file, None, None).expect("read long multibyte line");
        let expected = format!("1: {}{LINE_TRUNCATION_SUFFIX}", "中".repeat(MAX_LINE_CHARS));
        assert_eq!(
            page,
            Page::Text {
                text: expected,
                total_lines: 1,
                next_offset: None,
            }
        );

        let exact = dir.write("exact.txt", "中".repeat(MAX_LINE_CHARS));
        let expected = format!("1: {}", "中".repeat(MAX_LINE_CHARS));
        assert_eq!(
            read_page(&exact, None, None).expect("read exact line"),
            Page::Text {
                text: expected,
                total_lines: 1,
                next_offset: None,
            }
        );
    }

    #[test]
    fn reads_chinese_lines() {
        let dir = TestDir::new();
        let file = dir.write("chinese.txt", "第一行\n第二行\n第三行\n");

        assert_eq!(
            read_page(&file, Some(2), Some(2)).expect("read chinese page"),
            Page::Text {
                text: "2: 第二行\n3: 第三行".to_owned(),
                total_lines: 3,
                next_offset: None,
            }
        );
    }

    #[test]
    fn reads_an_empty_file_only_from_offset_one() {
        let dir = TestDir::new();
        let file = dir.write("empty.txt", b"");

        assert_eq!(
            read_page(&file, None, None).expect("read empty file"),
            Page::Text { text: String::new(), total_lines: 0, next_offset: None }
        );
        assert_eq!(
            read_page(&file, Some(1), None).expect("read empty file at offset one"),
            Page::Text { text: String::new(), total_lines: 0, next_offset: None }
        );
        assert_eq!(
            read_page(&file, Some(2), None),
            Err(ReadError::OffsetPastEnd { offset: 2, total: 0 })
        );
    }

    #[test]
    fn reports_an_offset_past_the_end() {
        let dir = TestDir::new();
        let file = dir.write("short.txt", "one\n");

        assert_eq!(
            read_page(&file, Some(2), None),
            Err(ReadError::OffsetPastEnd { offset: 2, total: 1 })
        );
    }

    #[test]
    fn rejects_nul_and_control_byte_binary_files() {
        let dir = TestDir::new();
        let nul = dir.write("archive.dat", b"abc\0def");
        assert_eq!(
            read_page(&nul, None, None),
            Err(ReadError::Binary(nul.display().to_string()))
        );

        let control = dir.write("control.dat", [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            read_page(&control, None, None),
            Err(ReadError::Binary(control.display().to_string()))
        );
    }

    #[test]
    fn rejects_images_and_pdfs_as_binary() {
        let dir = TestDir::new();
        let png = dir.write("image.png", b"\x89PNG\r\n\x1a\nrest");
        assert_eq!(
            read_page(&png, None, None),
            Err(ReadError::Binary(png.display().to_string()))
        );

        let pdf = dir.write("document.pdf", b"%PDF-1.7\ncontent");
        assert_eq!(
            read_page(&pdf, None, None),
            Err(ReadError::Binary(pdf.display().to_string()))
        );
    }

    #[test]
    fn reads_malformed_utf8_lossily() {
        let dir = TestDir::new();
        let file = dir.write("malformed.txt", [0x68, 0x69, 0x80]);

        assert_eq!(
            read_page(&file, None, None).expect("read malformed text"),
            Page::Text {
                text: "1: hi\u{FFFD}".to_owned(),
                total_lines: 1,
                next_offset: None,
            }
        );
    }

    #[test]
    fn lists_directories_first_with_a_slash_suffix_and_pages_them() {
        let dir = TestDir::new();
        fs::create_dir(dir.path().join("z")).expect("create z");
        fs::create_dir(dir.path().join("a")).expect("create a");
        dir.write("b.txt", b"");

        assert_eq!(
            read_page(dir.path(), None, None).expect("list directory"),
            Page::Directory {
                entries: vec!["a/".to_owned(), "z/".to_owned(), "b.txt".to_owned()],
                total: 3,
                next_offset: None,
            }
        );
        assert_eq!(
            read_page(dir.path(), Some(2), Some(1)).expect("page directory"),
            Page::Directory {
                entries: vec!["z/".to_owned()],
                total: 3,
                next_offset: Some(3),
            }
        );
        assert_eq!(
            read_page(dir.path(), Some(3), Some(1)).expect("page last entry"),
            Page::Directory {
                entries: vec!["b.txt".to_owned()],
                total: 3,
                next_offset: None,
            }
        );
        assert_eq!(
            read_page(dir.path(), Some(10), None).expect("page past directory end"),
            Page::Directory { entries: Vec::new(), total: 3, next_offset: None }
        );
    }

    #[test]
    fn reports_missing_paths_as_not_found() {
        let dir = TestDir::new();
        let missing = dir.path().join("missing.txt");

        assert_eq!(
            read_page(&missing, None, None),
            Err(ReadError::NotFound(missing.display().to_string()))
        );
    }
}
