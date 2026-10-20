//! Glob matching for permission rules (`*` any run, `?` one char), ported from
//! opencode's matcher. Backslashes are normalized to `/`, and a pattern ending
//! in ` *` also matches the bare prefix (so `git *` matches `git`).

/// Match `input` against `pattern`.
pub fn matches(input: &str, pattern: &str) -> bool {
    let input = input.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");
    if glob(input.as_bytes(), pattern.as_bytes()) {
        return true;
    }
    // Trailing " *" is optional: `git *` also matches `git`.
    if let Some(prefix) = pattern.strip_suffix(" *") {
        return glob(input.as_bytes(), prefix.as_bytes());
    }
    false
}

/// Iterative glob with `*` and `?`, O(n*m) worst case, no backtracking blowup.
fn glob(input: &[u8], pattern: &[u8]) -> bool {
    let (mut i, mut p) = (0usize, 0usize);
    let (mut star_p, mut star_i): (Option<usize>, usize) = (None, 0);
    while i < input.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == input[i]) {
            i += 1;
            p += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_p = Some(p);
            star_i = i;
            p += 1;
        } else if let Some(sp) = star_p {
            p = sp + 1;
            star_i += 1;
            i = star_i;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn literals_and_stars() {
        assert!(matches("read", "read"));
        assert!(matches("anything", "*"));
        assert!(matches("src/main.rs", "src/*"));
        assert!(matches("src/a/b.rs", "src/*"));
        assert!(!matches("other/x", "src/*"));
        assert!(matches("file.env", "*.env"));
    }

    #[test]
    fn question_mark_matches_one() {
        assert!(matches("a", "?"));
        assert!(!matches("ab", "?"));
    }

    #[test]
    fn trailing_space_star_is_optional() {
        assert!(matches("git status", "git *"));
        assert!(matches("git", "git *"));
        assert!(!matches("gitk", "git *"));
    }

    #[test]
    fn backslashes_normalize() {
        assert!(matches("a\\b\\c", "a/b/*"));
    }
}
