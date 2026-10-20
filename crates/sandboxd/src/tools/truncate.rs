//! Bound tool output for the model; spill the full text to a file.
//! MARK: M13 — transcribed by dsh; see marks/M13-truncate.md.

use std::collections::hash_map::RandomState;
use std::fs::{self, OpenOptions, Permissions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_lines: usize,
    pub max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_lines: 2000,
            max_bytes: 50 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounded {
    /// Text to show the model (head + gap + tail + notice when truncated).
    pub text: String,
    pub truncated: bool,
    /// Where the full text was written, when truncated.
    pub spill_path: Option<PathBuf>,
    pub total_lines: usize,
    pub total_bytes: usize,
}

/// Marker overhead that may sit on top of `max_bytes` without making the
/// displayed text exceed its documented hard cap.
const MARKER_ALLOWANCE: usize = 512;

/// Largest index at or below `max` that lies on a UTF-8 character boundary.
fn floor_char_boundary(text: &str, max: usize) -> usize {
    let mut index = max.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Smallest index at or above `min` that lies on a UTF-8 character boundary.
fn ceil_char_boundary(text: &str, min: usize) -> usize {
    let mut index = min.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// One random 64-bit value rendered as exactly 16 lowercase hex digits.
fn random_hex_16() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.write_u128(nanos);
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u32(std::process::id());
    format!("{:016x}", hasher.finish())
}

/// Write `text` to a fresh owner-only spill file and return its path.
fn write_spill(text: &str, spill_dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(spill_dir)?;
    for _ in 0..64 {
        let path = spill_dir.join(format!("tool-{}.txt", random_hex_16()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                if let Err(error) = file.set_permissions(Permissions::from_mode(0o600)) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                if let Err(error) = file.write_all(text.as_bytes()) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique spill file",
    ))
}

/// Byte length of the last `count` logical lines, counting their separators.
fn tail_bytes(lines: &[&str], count: usize) -> usize {
    if count == 0 {
        return 0;
    }
    let start = lines.len() - count;
    lines[start..].iter().map(|line| line.len()).sum::<usize>() + (count - 1)
}

/// Largest whole number of trailing lines that fits `budget`.
fn largest_tail(lines: &[&str], max_count: usize, budget: usize) -> usize {
    let mut low = 0;
    let mut high = max_count.min(lines.len());
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if tail_bytes(lines, middle) <= budget {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low
}

/// Pick whole leading lines within both budgets. When the first line alone is
/// too large, keep a character-boundary prefix of it instead.
fn take_head(lines: &[&str], max_lines: usize, max_bytes: usize) -> (usize, Option<String>) {
    let mut count = 0;
    let mut bytes: usize = 0;
    while count < lines.len() && count < max_lines {
        let separator = usize::from(count > 0);
        let candidate = bytes
            .saturating_add(separator)
            .saturating_add(lines[count].len());
        if candidate > max_bytes {
            break;
        }
        bytes = candidate;
        count += 1;
    }
    if count == 0 && max_lines > 0 && max_bytes > 0 {
        let line = lines[0];
        let take = floor_char_boundary(line, max_bytes);
        if take > 0 {
            return (0, Some(line[..take].to_owned()));
        }
    }
    (count, None)
}

/// If `text` fits `limits`, return it unchanged. Otherwise write the full text
/// to a new owner-only file in `spill_dir` and return head + tail within the
/// limits plus a notice naming the file and how to read it.
pub fn bound_output(text: &str, limits: Limits, spill_dir: &Path) -> std::io::Result<Bounded> {
    let total_bytes = text.len();
    // A trailing newline terminates the last line; it does not start another.
    let mut lines: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    let total_lines = lines.len();

    if total_lines <= limits.max_lines && total_bytes <= limits.max_bytes {
        return Ok(Bounded {
            text: text.to_owned(),
            truncated: false,
            spill_path: None,
            total_lines,
            total_bytes,
        });
    }

    let spill_path = write_spill(text, spill_dir)?;
    let notice = format!(
        "[full output ({} lines, {} bytes) saved to {} — use read with offset/limit or grep on this path]",
        total_lines,
        total_bytes,
        spill_path.display()
    );

    // Gap and notice are mandatory. They may consume the 512-byte marker
    // allowance; only the excess has to come out of the content budget.
    let widest_gap = format!(
        "[... {} lines / {} bytes omitted ...]",
        total_lines, total_bytes
    );
    let marker_bytes = widest_gap.len() + notice.len() + 3;
    let content_budget = limits
        .max_bytes
        .saturating_sub(marker_bytes.saturating_sub(MARKER_ALLOWANCE));

    let head_line_budget = limits.max_lines.div_ceil(2);
    let tail_line_budget = limits.max_lines / 2;
    let head_byte_budget = content_budget.div_ceil(2);
    let tail_byte_budget = content_budget / 2;

    let (head_count, head_part) = take_head(&lines, head_line_budget, head_byte_budget);
    let head_text = match &head_part {
        Some(part) => part.clone(),
        None => lines[..head_count].join("\n"),
    };
    let head_consumed = head_count + usize::from(head_part.is_some());

    // Whole trailing lines first; a binary search finds the largest count that
    // fits. If even one line does not fit, keep a suffix of the last line.
    let tail_available = total_lines.saturating_sub(head_consumed);
    let tail_max = tail_line_budget.min(tail_available);
    let tail_count = largest_tail(&lines, tail_max, tail_byte_budget);
    let mut tail_part = None;
    if tail_count == 0 && tail_line_budget > 0 && tail_byte_budget > 0 && total_lines > 0 {
        let index = total_lines - 1;
        if index >= head_count {
            let line = lines[index];
            let already_shown = match &head_part {
                Some(part) if index == head_count => part.len(),
                _ => 0,
            };
            let desired = line.len().saturating_sub(tail_byte_budget);
            let start = ceil_char_boundary(line, desired.max(already_shown));
            if start < line.len() {
                tail_part = Some(line[start..].to_owned());
            }
        }
    }
    let tail_text = match &tail_part {
        Some(part) => part.clone(),
        None => lines[total_lines - tail_count..].join("\n"),
    };

    // Partially shown lines count as omitted lines, so never subtract the
    // edge fragments from `total_lines`.
    let omitted_lines = total_lines
        .saturating_sub(head_count)
        .saturating_sub(tail_count);
    let shown_bytes = head_text.len().saturating_add(tail_text.len());
    let omitted_bytes = total_bytes.saturating_sub(shown_bytes);
    let gap = format!("[... {omitted_lines} lines / {omitted_bytes} bytes omitted ...]");

    let mut bounded = String::new();
    if !head_text.is_empty() {
        bounded.push_str(&head_text);
        bounded.push('\n');
    }
    bounded.push_str(&gap);
    bounded.push('\n');
    if !tail_text.is_empty() {
        bounded.push_str(&tail_text);
        bounded.push('\n');
    }
    bounded.push_str(&notice);

    debug_assert!(shown_bytes <= total_bytes);
    debug_assert!(bounded.len() <= limits.max_bytes.saturating_add(MARKER_ALLOWANCE));

    Ok(Bounded {
        text: bounded,
        truncated: true,
        spill_path: Some(spill_path),
        total_lines,
        total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bulge-m13-{}-{}",
                std::process::id(),
                random_hex_16()
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn numbered_lines(count: usize) -> String {
        (0..count)
            .map(|i| format!("line-{i:03}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn numbered_line(index: usize) -> String {
        format!("line-{index:03}")
    }

    fn between_markers(text: &str) -> (&str, &str, &str) {
        let (head, rest) = text.split_once('\n').expect("head separator");
        let (gap, rest) = rest.split_once('\n').expect("gap separator");
        let (tail, _notice) = rest.split_once('\n').expect("tail separator");
        (head, gap, tail)
    }

    #[test]
    fn within_limits_is_returned_unchanged() {
        let dir = TempDir::new();
        let text = "alpha\nbeta\n";
        let bounded = bound_output(
            text,
            Limits {
                max_lines: 10,
                max_bytes: 100,
            },
            dir.path(),
        )
        .expect("bound output");

        assert!(!bounded.truncated);
        assert_eq!(bounded.text, text);
        assert_eq!(bounded.spill_path, None);
        assert_eq!(bounded.total_lines, 2);
        assert_eq!(bounded.total_bytes, text.len());
        assert!(fs::read_dir(dir.path()).expect("read dir").next().is_none());
    }

    #[test]
    fn exact_limits_are_not_truncated() {
        let dir = TempDir::new();
        let text = "a\nb\nc";
        let limits = Limits {
            max_lines: 3,
            max_bytes: text.len(),
        };
        let bounded = bound_output(text, limits, dir.path()).expect("bound output");

        assert!(!bounded.truncated);
        assert_eq!(bounded.text, text);
        assert_eq!(bounded.spill_path, None);
        assert_eq!(bounded.total_lines, 3);
    }

    #[test]
    fn trailing_newline_does_not_add_a_line() {
        let dir = TempDir::new();
        let text = "a\nb\n";
        let bounded = bound_output(
            text,
            Limits {
                max_lines: 2,
                max_bytes: 100,
            },
            dir.path(),
        )
        .expect("bound output");
        assert_eq!(bounded.total_lines, 2);
        assert!(!bounded.truncated);
    }

    #[test]
    fn line_limit_keeps_head_and_tail_without_overlap() {
        let dir = TempDir::new();
        let text = numbered_lines(100);
        let limits = Limits {
            max_lines: 10,
            max_bytes: 10_000,
        };
        let bounded = bound_output(&text, limits, dir.path()).expect("bound output");

        assert!(bounded.truncated);
        assert_eq!(bounded.total_lines, 100);
        assert_eq!(bounded.total_bytes, text.len());
        let spill = bounded.spill_path.as_ref().expect("spill path");
        assert_eq!(fs::read_to_string(spill).expect("read spill"), text);

        let head = (0..5).map(numbered_line).collect::<Vec<_>>().join("\n");
        let tail = (95..100).map(numbered_line).collect::<Vec<_>>().join("\n");
        let expected = format!(
            "{head}\n[... 90 lines / 811 bytes omitted ...]\n{tail}\n\
             [full output (100 lines, 899 bytes) saved to {} — use read with offset/limit or grep on this path]",
            spill.display()
        );
        assert_eq!(bounded.text, expected);
        assert!(bounded.text.len() <= limits.max_bytes + MARKER_ALLOWANCE);
    }

    #[test]
    fn byte_limit_truncates_within_budget() {
        let dir = TempDir::new();
        let text = (0..50)
            .map(|i| format!("{i:04}-{}", "x".repeat(95)))
            .collect::<Vec<_>>()
            .join("\n");
        let limits = Limits {
            max_lines: 1000,
            max_bytes: 1000,
        };
        let bounded = bound_output(&text, limits, dir.path()).expect("bound output");

        assert!(bounded.truncated);
        assert_eq!(bounded.total_lines, 50);
        assert_eq!(bounded.total_bytes, text.len());
        assert!(bounded.text.len() <= limits.max_bytes + MARKER_ALLOWANCE);
        assert_eq!(
            fs::read_to_string(bounded.spill_path.as_ref().expect("spill path"))
                .expect("read spill"),
            text
        );

        let head = (0..4)
            .map(|i| format!("{i:04}-{}", "x".repeat(95)))
            .collect::<Vec<_>>()
            .join("\n");
        let tail = (46..50)
            .map(|i| format!("{i:04}-{}", "x".repeat(95)))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(bounded.text.starts_with(&format!(
            "{head}\n[... 42 lines / 4243 bytes omitted ...]\n{tail}\n"
        )));
    }

    #[test]
    fn single_overlong_line_is_cut_at_char_boundaries() {
        let dir = TempDir::new();
        let text = "é".repeat(300);
        let limits = Limits {
            max_lines: 10,
            max_bytes: 101,
        };
        let bounded = bound_output(&text, limits, dir.path()).expect("bound output");

        assert!(bounded.truncated);
        assert_eq!(bounded.total_lines, 1);
        assert!(bounded.text.len() <= limits.max_bytes + MARKER_ALLOWANCE);
        assert_eq!(
            fs::read_to_string(bounded.spill_path.as_ref().expect("spill path"))
                .expect("read spill"),
            text
        );

        let (head, gap, tail) = between_markers(&bounded.text);
        assert_eq!(head, "é".repeat(25));
        assert_eq!(gap, "[... 1 lines / 500 bytes omitted ...]");
        assert_eq!(tail, "é".repeat(25));
    }

    #[test]
    fn multibyte_text_is_never_split() {
        let dir = TempDir::new();
        let text = "aé中".repeat(100);
        let limits = Limits {
            max_lines: 4,
            max_bytes: 101,
        };
        let bounded = bound_output(&text, limits, dir.path()).expect("bound output");

        assert!(bounded.truncated);
        assert!(bounded.text.len() <= limits.max_bytes + MARKER_ALLOWANCE);
        assert_eq!(
            fs::read_to_string(bounded.spill_path.as_ref().expect("spill path"))
                .expect("read spill"),
            text
        );

        let (head, gap, tail) = between_markers(&bounded.text);
        assert!(text.starts_with(head));
        assert!(text.ends_with(tail));
        assert!(head.len() + tail.len() <= text.len());
        assert!(head.chars().all(|c| matches!(c, 'a' | 'é' | '中')));
        assert!(tail.chars().all(|c| matches!(c, 'a' | 'é' | '中')));
        assert!(gap.contains("bytes omitted"));
    }

    #[test]
    fn spill_file_is_owner_only_and_named_like_a_tool_spill() {
        let dir = TempDir::new();
        let spill_dir = dir.path().join("nested").join("spill");
        let text = numbered_lines(200);
        let limits = Limits {
            max_lines: 20,
            max_bytes: 5000,
        };
        let bounded = bound_output(&text, limits, &spill_dir).expect("bound output");

        let path = bounded.spill_path.expect("spill path");
        assert!(path.starts_with(&spill_dir));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("utf-8 file name");
        let stem = name
            .strip_prefix("tool-")
            .and_then(|name| name.strip_suffix(".txt"));
        let stem = stem.expect("tool-<hex>.txt name");
        assert_eq!(stem.len(), 16);
        assert!(
            stem.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(fs::read_to_string(&path).expect("read spill"), text);

        let mode = fs::metadata(&path)
            .expect("spill metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn separate_calls_get_distinct_spill_files() {
        let dir = TempDir::new();
        let text = numbered_lines(100);
        let limits = Limits {
            max_lines: 5,
            max_bytes: 1000,
        };
        let first = bound_output(&text, limits, dir.path()).expect("first bound output");
        let second = bound_output(&text, limits, dir.path()).expect("second bound output");

        let first_path = first.spill_path.expect("first spill path");
        let second_path = second.spill_path.expect("second spill path");
        assert_ne!(first_path, second_path);
        assert_eq!(
            fs::read_to_string(&first_path).expect("read first spill"),
            text
        );
        assert_eq!(
            fs::read_to_string(&second_path).expect("read second spill"),
            text
        );
    }

    #[test]
    fn trailing_newline_is_not_a_line_when_truncated() {
        let dir = TempDir::new();
        let text = format!("{}\n", numbered_lines(20));
        let limits = Limits {
            max_lines: 10,
            max_bytes: 10_000,
        };
        let bounded = bound_output(&text, limits, dir.path()).expect("bound output");

        assert!(bounded.truncated);
        assert_eq!(bounded.total_lines, 20);
        assert!(bounded.text.contains("[... 10 lines /"));
    }
}
