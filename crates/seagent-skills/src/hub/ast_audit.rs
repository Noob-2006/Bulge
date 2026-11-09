//! Deep audit of a skill's Python files (Hermes `tools/skills_ast_audit.py`, MIT) — an opt-in
//! diagnostic (`seagent skills audit --deep`), not a security gate. Flags dynamic import and
//! dynamic attribute access for human review: `importlib.import_module()`, `__import__` /
//! `getattr` with a non-literal name argument, `obj.__dict__[<computed>]`, and importing
//! `importlib` (including `from importlib.machinery.abc import …`). Hermes walks the Python AST;
//! seagent tokenizes the source (strings and comments are understood, so a pattern inside a string
//! literal or comment never fires — while an f-string's `{…}` interpolation is still seen as
//! computed, like an AST `JoinedStr`) and inspects the same call shapes.

use std::path::Path;

/// (file, line, pattern id, description)
pub type Finding = (String, usize, &'static str, String);

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Str,
    /// An f-string: its interpolations make it a computed value, not a literal.
    FStr,
    Num,
    Op(char),
}

/// Python tokens with their line numbers (strings — incl. triple-quoted and prefixed — collapse to `Str`;
/// an `f` prefix yields `FStr` so interpolated values are not mistaken for literals).
fn tokenize(src: &str) -> Vec<(Tok, usize)> {
    let b: Vec<char> = src.chars().collect();
    let (mut i, mut line, mut out) = (0usize, 1usize, Vec::new());
    let mut prefix = String::new();
    while i < b.len() {
        let c = b[i];
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c == '#' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c.is_whitespace() || c == '\\' {
            i += 1;
        } else if c == '"' || c == '\'' {
            let start = line;
            let fstring = prefix.to_ascii_lowercase().contains('f');
            prefix.clear();
            let triple = i + 2 < b.len() && b[i + 1] == c && b[i + 2] == c;
            i += if triple { 3 } else { 1 };
            while i < b.len() {
                if b[i] == '\\' {
                    i += 2;
                    continue;
                }
                if b[i] == '\n' {
                    line += 1;
                    if !triple {
                        break;
                    }
                }
                if b[i] == c && (!triple || (i + 2 < b.len() && b[i + 1] == c && b[i + 2] == c)) {
                    i += if triple { 3 } else { 1 };
                    break;
                }
                i += 1;
            }
            out.push((if fstring { Tok::FStr } else { Tok::Str }, start));
        } else if c.is_alphabetic() || c == '_' {
            let s = i;
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_') {
                i += 1;
            }
            let w: String = b[s..i].iter().collect();
            // String prefixes (r'', b"", f'', rb'' …) glue onto the following quote.
            if i < b.len() && (b[i] == '"' || b[i] == '\'') && w.len() <= 2 && w.chars().all(|x| "rRbBfFuU".contains(x)) {
                prefix = w;
                continue;
            }
            out.push((Tok::Name(w), line));
        } else if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_alphanumeric() || b[i] == '.' || b[i] == '_') {
                i += 1;
            }
            out.push((Tok::Num, line));
        } else {
            out.push((Tok::Op(c), line));
            i += 1;
        }
    }
    out
}

/// Tokens of argument `n` of the call whose `(` is at `open`.
fn arg(t: &[(Tok, usize)], open: usize, n: usize) -> Option<Vec<Tok>> {
    let (mut depth, mut idx, mut cur, mut i) = (0i32, 0usize, Vec::new(), open + 1);
    while i < t.len() {
        match &t[i].0 {
            Tok::Op('(' | '[' | '{') => {
                depth += 1;
                cur.push(t[i].0.clone());
            }
            Tok::Op(')' | ']' | '}') if depth == 0 => return (idx == n && !cur.is_empty()).then_some(cur),
            Tok::Op(')' | ']' | '}') => {
                depth -= 1;
                cur.push(t[i].0.clone());
            }
            Tok::Op(',') if depth == 0 => {
                if idx == n {
                    return Some(cur);
                }
                idx += 1;
                cur.clear();
            }
            x => cur.push(x.clone()),
        }
        i += 1;
    }
    None
}

/// A literal argument: one string/number token, implicit string concatenation, or a Python constant
/// keyword (upstream `isinstance(arg, ast.Constant)`). Anything else — including an f-string — is computed.
fn literal(a: &[Tok]) -> bool {
    match a {
        [Tok::Str | Tok::Num] => true,
        [Tok::Name(n)] => matches!(n.as_str(), "True" | "False" | "None"),
        _ => !a.is_empty() && a.iter().all(|t| matches!(t, Tok::Str)),
    }
}

pub fn scan_source(src: &str, rel: &str) -> Vec<Finding> {
    let t = tokenize(src);
    let mut f = Vec::new();
    let name = |i: usize| match t.get(i) {
        Some((Tok::Name(n), _)) => Some(n.as_str()),
        _ => None,
    };
    for i in 0..t.len() {
        let line = t[i].1;
        let prev_dot = i > 0 && t[i - 1].0 == Tok::Op('.');
        match name(i) {
            Some("import_module") if prev_dot && t.get(i + 1).is_some_and(|x| x.0 == Tok::Op('(')) => f.push((rel.to_string(), line, "dynamic_import", "importlib.import_module() — loads arbitrary modules at runtime".to_string())),
            Some(n @ ("__import__" | "getattr")) if !prev_dot && t.get(i + 1).is_some_and(|x| x.0 == Tok::Op('(')) => {
                let (k, pid, desc) = if n == "__import__" { (0, "dynamic_import_computed", "__import__ with non-literal module name") } else { (1, "dynamic_getattr", "getattr with non-literal attribute name") };
                if arg(&t, i + 1, k).is_some_and(|a| !literal(&a)) {
                    f.push((rel.to_string(), line, pid, desc.to_string()));
                }
            }
            Some("__dict__") if prev_dot && t.get(i + 1).is_some_and(|x| x.0 == Tok::Op('[')) => {
                let constant = matches!(t.get(i + 2), Some((Tok::Str | Tok::Num, _))) && matches!(t.get(i + 3), Some((Tok::Op(']'), _)));
                if !constant {
                    f.push((rel.to_string(), line, "dict_access", "__dict__[<computed>] — dynamic attribute access".to_string()));
                }
            }
            Some("import") if !prev_dot => {
                // Module path directly before `import`: `from A.B.C import …`. Walk back over
                // `Name ('.' Name)*` (newlines are not tokens, so every path token must be on this line).
                let (mut start, mut k) = (i, i);
                while k >= 1 {
                    match name(k - 1) {
                        Some(_) => {
                            start = k - 1;
                            if start >= 2 && t[start - 1].0 == Tok::Op('.') {
                                k = start - 1;
                            } else {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                let from_import = start < i && start >= 1 && name(start - 1) == Some("from") && (start..i).all(|x| t[x].1 == line);
                if from_import {
                    let module = (start..i).filter_map(&name).collect::<Vec<_>>().join(".");
                    if module == "importlib" || module.starts_with("importlib.") {
                        f.push((rel.to_string(), line, "importlib_import", format!("from {module} import ... — enables dynamic module loading")));
                    }
                } else {
                    let mut j = i + 1;
                    while j < t.len() && t[j].1 == line {
                        let after_sep = matches!(t[j - 1].0, Tok::Op(',')) || j == i + 1;
                        if after_sep && name(j) == Some("importlib") {
                            let m = if t.get(j + 1).is_some_and(|x| x.0 == Tok::Op('.')) { format!("importlib.{}", name(j + 2).unwrap_or("")) } else { "importlib".to_string() };
                            f.push((rel.to_string(), line, "importlib_import", format!("import {m} — enables dynamic module loading")));
                        }
                        j += 1;
                    }
                }
            }
            _ => {}
        }
    }
    f
}

pub fn scan_path(p: &Path) -> Vec<Finding> {
    if p.is_file() {
        return if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("py")) { scan_source(&String::from_utf8_lossy(&std::fs::read(p).unwrap_or_default()), &p.file_name().unwrap().to_string_lossy()) } else { vec![] };
    }
    let mut files = Vec::new();
    fn walk(d: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let p = e.path();
            let n = e.file_name().to_string_lossy().to_string();
            // Entry type, not `Path::is_dir`: a symlinked directory is not followed (upstream rglob
            // does not either), so a self-referential link cannot recurse forever.
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                if !matches!(n.as_str(), "__pycache__" | ".venv" | "venv" | "node_modules") {
                    walk(&p, out);
                }
            } else if p.extension().is_some_and(|e| e == "py") {
                out.push(p);
            }
        }
    }
    walk(p, &mut files);
    files.sort();
    files.iter().flat_map(|f| scan_source(&String::from_utf8_lossy(&std::fs::read(f).unwrap_or_default()), &seagent_core::platform::layout::model_path(f.strip_prefix(p).unwrap()))).collect()
}

pub fn format(f: &[Finding], name: &str) -> String {
    let head = if name.is_empty() { "AST deep scan".to_string() } else { format!("AST deep scan: {name}") };
    if f.is_empty() {
        return format!("{head}\n  No dynamic import/access patterns detected.");
    }
    let mut v: Vec<&Finding> = f.iter().collect();
    v.sort();
    let mut l = vec![head, format!("  {} finding(s):", f.len())];
    let mut cur = "";
    for (file, line, pid, desc) in v {
        if file != cur {
            cur = file;
            l.push(format!("  {file}"));
        }
        l.push(format!("    L{line}  {pid}  — {desc}"));
    }
    l.push(String::new());
    l.push("  Note: diagnostic hints for human review, not security verdicts.".into());
    l.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_dynamic_patterns_not_literals_strings_or_comments() {
        let src = "import os, importlib\nfrom importlib import util\nm = importlib.import_module(name)\n__import__('os')\n__import__(mod)\ngetattr(o, 'x')\ngetattr(o, attr, None)\nx = obj.__dict__[k]\ny = obj.__dict__['k']\n# getattr(o, a)\ns = \"__import__(x)\"\nt = '''\ngetattr(o, b)\n'''\nimport importlib.util\n";
        let f = scan_source(src, "a.py");
        let got: Vec<(usize, &str)> = f.iter().map(|x| (x.1, x.2)).collect();
        assert_eq!(got, vec![(1, "importlib_import"), (2, "importlib_import"), (3, "dynamic_import"), (5, "dynamic_import_computed"), (7, "dynamic_getattr"), (8, "dict_access"), (15, "importlib_import")]);
        assert!(f[6].3.contains("importlib.util"));
        let r = format(&f, "s");
        assert!(r.contains("7 finding(s)") && r.contains("L3  dynamic_import"));
        assert!(format(&[], "s").contains("No dynamic"));
    }

    /// An f-string is never an AST `Constant` upstream (it is a `JoinedStr`), even with no
    /// placeholders, so it counts as computed; `True`/`None` are constants there and stay literal.
    #[test]
    fn fstrings_are_computed_and_constant_keywords_are_literal() {
        let src = concat!(
            "getattr(o, f\"{name}\")\n",
            "__import__(f'{mod}')\n",
            "x = obj.__dict__[f\"{k}\"]\n",
            "getattr(o, f\"plain\")\n",
            "getattr(o, True)\n",
            "getattr(o, None)\n",
            "getattr(o, 'x' 'y')\n",
        );
        let got: Vec<(usize, &str)> = scan_source(src, "a.py").iter().map(|x| (x.1, x.2)).collect();
        assert_eq!(got, vec![(1, "dynamic_getattr"), (2, "dynamic_import_computed"), (3, "dict_access"), (4, "dynamic_getattr")]);
    }

    /// Upstream `_is_importlib` accepts any dotted path, so a 3+ level `from importlib.a.b import …`
    /// must be reported with the full module name (and non-importlib `from` imports must stay clean).
    #[test]
    fn dotted_from_importlib_paths() {
        let src = concat!(
            "from importlib.machinery.abc import loader\n",
            "from importlib import metadata\n",
            "from package.sub import thing\n",
            "from . import sibling\n",
            "import os\n",
        );
        let f = scan_source(src, "a.py");
        let got: Vec<(usize, &str)> = f.iter().map(|x| (x.1, x.2)).collect();
        assert_eq!(got, vec![(1, "importlib_import"), (2, "importlib_import")]);
        assert!(f[0].3.contains("from importlib.machinery.abc import"), "{}", f[0].3);
        assert!(f[1].3.contains("from importlib import"), "{}", f[1].3);
    }

    /// A non-Python file, a missing path and a symlink loop must not panic, hang or report anything.
    #[test]
    fn scan_path_ignores_non_python_and_does_not_follow_symlink_loops() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-ast-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("pkg")).unwrap();
        std::fs::write(d.join("pkg/ok.py"), "m = __import__(name)\n").unwrap();
        std::fs::write(d.join("pkg/notes.md"), "__import__(name)\n").unwrap();
        std::fs::write(d.join("pkg/data.txt"), "__import__(name)\n").unwrap();
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink(&d, d.join("pkg/loop"));
        #[cfg(windows)]
        let _ = std::os::windows::fs::symlink_dir(&d, d.join("pkg/loop"));
        let f = scan_path(&d);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].0, "pkg/ok.py");
        assert!(scan_path(&d.join("pkg/notes.md")).is_empty());
        assert!(scan_path(&d.join("missing.py")).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
