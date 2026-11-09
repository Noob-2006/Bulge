//! `grep` for the SE Agent iOS WASI tool set: the POSIX options plus the common GNU ones agents
//! type (`-r`, `-o`, `-A/-B/-C`, `--include`, `-m`). Patterns are POSIX basic (default, `-G`),
//! extended (`-E`) or fixed strings (`-F`); basic expressions are translated to the `regex`
//! crate's syntax. Exit status: 0 a line matched, 1 none did, 2 an error (POSIX).

use regex::bytes::{Regex, RegexBuilder};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

#[derive(Default)]
struct Opts {
    mode: char, // 'G', 'E', 'F'
    patterns: Vec<String>,
    icase: bool,
    invert: bool,
    number: bool,
    count: bool,
    list: bool,
    list_none: bool,
    no_name: bool,
    with_name: bool,
    only: bool,
    quiet: bool,
    silent: bool,
    word: bool,
    line: bool,
    recursive: bool,
    after: usize,
    before: usize,
    max: Option<usize>,
    include: Vec<String>,
    exclude: Vec<String>,
    exclude_dir: Vec<String>,
}

fn usage(msg: &str) -> ! {
    eprintln!("grep: {msg}\nUsage: grep [-EFGHhiLlnoqrsvwxc] [-A N] [-B N] [-C N] [-m N] [-e PATTERN]... [-f FILE] [PATTERN] [FILE...]");
    std::process::exit(2)
}

/// POSIX basic regular expression → `regex` syntax.
fn bre(p: &str) -> String {
    let c: Vec<char> = p.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut in_class = false;
    while i < c.len() {
        let ch = c[i];
        if in_class {
            if ch == ']' && !out.ends_with('[') && !out.ends_with("[^") {
                in_class = false;
            }
            if ch == '\\' || (ch == '[' && c.get(i + 1) != Some(&':')) {
                out.push('\\');
            }
            out.push(ch);
            i += 1;
            continue;
        }
        match ch {
            '\\' if i + 1 < c.len() => {
                let n = c[i + 1];
                match n {
                    '(' | ')' | '{' | '}' | '|' | '+' | '?' => out.push(n),
                    '<' | '>' => out.push_str("\\b"),
                    _ => {
                        out.push('\\');
                        out.push(n);
                    }
                }
                i += 2;
                continue;
            }
            '(' | ')' | '{' | '}' | '|' | '+' | '?' => {
                out.push('\\');
                out.push(ch);
            }
            '*' if out.is_empty() || out.ends_with('^') || out.ends_with('(') => out.push_str("\\*"),
            '[' => {
                in_class = true;
                out.push('[');
                if c.get(i + 1) == Some(&'^') {
                    out.push('^');
                    i += 1;
                }
                if c.get(i + 1) == Some(&']') {
                    out.push_str("\\]");
                    i += 1;
                }
            }
            _ => out.push(ch),
        }
        i += 1;
    }
    out
}

/// ERE → `regex`: `\<`/`\>` become word boundaries; the rest is compatible.
fn ere(p: &str) -> String {
    p.replace("\\<", "\\b").replace("\\>", "\\b")
}

fn build(o: &Opts) -> Regex {
    let alts: Vec<String> = o
        .patterns
        .iter()
        .map(|p| match o.mode {
            'F' => regex::escape(p),
            'E' => ere(p),
            _ => bre(p),
        })
        .map(|p| if o.line { format!("^(?:{p})$") } else if o.word { format!("\\b(?:{p})\\b") } else { format!("(?:{p})") })
        .collect();
    RegexBuilder::new(&alts.join("|")).case_insensitive(o.icase).unicode(false).build().unwrap_or_else(|e| usage(&format!("bad pattern: {e}")))
}

fn glob(p: &str, s: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => (0..=s.len()).any(|k| go(&p[1..], &s[k..])),
            Some(b'?') => !s.is_empty() && go(&p[1..], &s[1..]),
            Some(c) => s.first() == Some(c) && go(&p[1..], &s[1..]),
        }
    }
    go(p.as_bytes(), s.as_bytes())
}

struct Run<'a> {
    o: &'a Opts,
    re: Regex,
    out: io::BufWriter<io::Stdout>,
    matched: bool,
    error: bool,
    names: bool,
}

impl Run<'_> {
    fn file(&mut self, path: &str, data: &[u8]) {
        let o = self.o;
        let binary = data.iter().take(8192).any(|b| *b == 0);
        let mut lines: Vec<&[u8]> = data.split(|b| *b == b'\n').collect();
        if data.ends_with(b"\n") {
            lines.pop();
        }
        let mut count = 0usize;
        let mut last_printed: Option<usize> = None;
        let mut after_left = 0usize;
        let prefix = |w: &mut io::BufWriter<io::Stdout>, n: usize, sep: u8, names: bool| {
            if names {
                let _ = w.write_all(path.as_bytes());
                let _ = w.write_all(&[sep]);
            }
            if o.number {
                let _ = write!(w, "{}{}", n + 1, sep as char);
            }
        };
        for (i, l) in lines.iter().enumerate() {
            let hit = self.re.is_match(l) != o.invert;
            if hit {
                count += 1;
                self.matched = true;
                if o.quiet {
                    return;
                }
                if o.list || o.list_none || o.count {
                    if o.max.is_some_and(|m| count >= m) {
                        break;
                    }
                    continue;
                }
                if binary {
                    let _ = writeln!(self.out, "Binary file {path} matches");
                    return;
                }
                if o.before > 0 || o.after > 0 {
                    let from = i.saturating_sub(o.before);
                    let start = match last_printed {
                        Some(lp) if lp + 1 >= from => lp + 1,
                        Some(_) => {
                            let _ = self.out.write_all(b"--\n");
                            from
                        }
                        None => from,
                    };
                    for (j, cl) in lines.iter().enumerate().take(i).skip(start) {
                        prefix(&mut self.out, j, b'-', self.names);
                        let _ = self.out.write_all(cl);
                        let _ = self.out.write_all(b"\n");
                    }
                }
                if o.only && !o.invert {
                    for m in self.re.find_iter(l) {
                        if m.as_bytes().is_empty() {
                            continue;
                        }
                        prefix(&mut self.out, i, b':', self.names);
                        let _ = self.out.write_all(m.as_bytes());
                        let _ = self.out.write_all(b"\n");
                    }
                } else {
                    prefix(&mut self.out, i, b':', self.names);
                    let _ = self.out.write_all(l);
                    let _ = self.out.write_all(b"\n");
                }
                last_printed = Some(i);
                after_left = o.after;
                if o.max.is_some_and(|m| count >= m) {
                    break;
                }
            } else if after_left > 0 && !o.quiet && !o.count && !o.list && !o.list_none {
                after_left -= 1;
                prefix(&mut self.out, i, b'-', self.names);
                let _ = self.out.write_all(l);
                let _ = self.out.write_all(b"\n");
                last_printed = Some(i);
            }
        }
        if o.count {
            if self.names {
                let _ = write!(self.out, "{path}:");
            }
            let _ = writeln!(self.out, "{count}");
        }
        if o.list && count > 0 {
            let _ = writeln!(self.out, "{path}");
        }
        if o.list_none && count == 0 {
            let _ = writeln!(self.out, "{path}");
        }
    }

    fn path(&mut self, p: &str, top: bool) {
        let o = self.o;
        let md = match std::fs::metadata(p) {
            Ok(m) => m,
            Err(e) => {
                if !o.silent {
                    eprintln!("grep: {p}: {}", msg(&e));
                }
                self.error = true;
                return;
            }
        };
        if md.is_dir() {
            if !o.recursive {
                if !o.silent {
                    eprintln!("grep: {p}: Is a directory");
                }
                return;
            }
            let base = Path::new(p).file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !top && o.exclude_dir.iter().any(|g| glob(g, base)) {
                return;
            }
            let mut names: Vec<String> = match std::fs::read_dir(p) {
                Ok(rd) => rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect(),
                Err(e) => {
                    eprintln!("grep: {p}: {}", msg(&e));
                    self.error = true;
                    return;
                }
            };
            names.sort();
            for n in names {
                let child = if p.ends_with('/') { format!("{p}{n}") } else { format!("{p}/{n}") };
                self.path(&child, false);
            }
            return;
        }
        let base = Path::new(p).file_name().and_then(|n| n.to_str()).unwrap_or(p);
        if !top && (!o.include.is_empty() && !o.include.iter().any(|g| glob(g, base)) || o.exclude.iter().any(|g| glob(g, base))) {
            return;
        }
        match std::fs::read(p) {
            Ok(d) => self.file(p, &d),
            Err(e) => {
                if !o.silent {
                    eprintln!("grep: {p}: {}", msg(&e));
                }
                self.error = true;
            }
        }
    }
}

fn msg(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "No such file or directory".into(),
        io::ErrorKind::PermissionDenied => "Permission denied".into(),
        _ => e.to_string(),
    }
}

fn num(v: Option<String>, flag: &str) -> usize {
    v.and_then(|s| s.parse().ok()).unwrap_or_else(|| usage(&format!("{flag} needs a number")))
}

fn main() {
    let mut o = Opts { mode: 'G', ..Default::default() };
    let mut args = std::env::args().skip(1);
    let mut rest: Vec<String> = vec![];
    let mut have_e = false;
    let mut opts_done = false;
    while let Some(a) = args.next() {
        if opts_done || a == "-" || !a.starts_with('-') {
            rest.push(a);
            continue;
        }
        if a == "--" {
            opts_done = true;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (k, v) = match long.split_once('=') {
                Some((k, v)) => (k, Some(v.to_string())),
                None => (long, None),
            };
            match k {
                "include" => o.include.push(v.unwrap_or_else(|| args.next().unwrap_or_default())),
                "exclude" => o.exclude.push(v.unwrap_or_else(|| args.next().unwrap_or_default())),
                "exclude-dir" => o.exclude_dir.push(v.unwrap_or_else(|| args.next().unwrap_or_default())),
                "color" | "colour" => {}
                "ignore-case" => o.icase = true,
                "invert-match" => o.invert = true,
                "line-number" => o.number = true,
                "count" => o.count = true,
                "files-with-matches" => o.list = true,
                "files-without-match" => o.list_none = true,
                "only-matching" => o.only = true,
                "quiet" | "silent" => o.quiet = true,
                "no-messages" => o.silent = true,
                "word-regexp" => o.word = true,
                "line-regexp" => o.line = true,
                "recursive" | "dereference-recursive" => o.recursive = true,
                "extended-regexp" => o.mode = 'E',
                "fixed-strings" => o.mode = 'F',
                "basic-regexp" => o.mode = 'G',
                "no-filename" => o.no_name = true,
                "with-filename" => o.with_name = true,
                "regexp" => {
                    o.patterns.push(v.unwrap_or_else(|| args.next().unwrap_or_default()));
                    have_e = true;
                }
                "max-count" => o.max = Some(num(v.or_else(|| args.next()), "--max-count")),
                "context" => {
                    let n = num(v.or_else(|| args.next()), "--context");
                    o.after = n;
                    o.before = n;
                }
                "after-context" => o.after = num(v.or_else(|| args.next()), "--after-context"),
                "before-context" => o.before = num(v.or_else(|| args.next()), "--before-context"),
                other => usage(&format!("unknown option --{other}")),
            }
            continue;
        }
        let flags: Vec<char> = a[1..].chars().collect();
        let mut k = 0;
        while k < flags.len() {
            let f = flags[k];
            // Options taking a value: the rest of this word, or the next argument.
            let mut value = || -> String {
                let inline: String = flags[k + 1..].iter().collect();
                k = flags.len();
                if inline.is_empty() {
                    args.next().unwrap_or_else(|| usage(&format!("-{f} needs an argument")))
                } else {
                    inline
                }
            };
            match f {
                'E' => o.mode = 'E',
                'F' => o.mode = 'F',
                'G' => o.mode = 'G',
                'i' | 'y' => o.icase = true,
                'v' => o.invert = true,
                'n' => o.number = true,
                'c' => o.count = true,
                'l' => o.list = true,
                'L' => o.list_none = true,
                'h' => o.no_name = true,
                'H' => o.with_name = true,
                'o' => o.only = true,
                'q' => o.quiet = true,
                's' => o.silent = true,
                'w' => o.word = true,
                'x' => o.line = true,
                'r' | 'R' => o.recursive = true,
                'I' | 'a' | 'U' => {}
                'e' => {
                    o.patterns.push(value());
                    have_e = true;
                }
                'f' => {
                    let p = value();
                    match std::fs::read_to_string(&p) {
                        Ok(s) => o.patterns.extend(s.lines().map(String::from)),
                        Err(e) => usage(&format!("{p}: {}", msg(&e))),
                    }
                    have_e = true;
                }
                'm' => o.max = Some(num(Some(value()), "-m")),
                'A' => o.after = num(Some(value()), "-A"),
                'B' => o.before = num(Some(value()), "-B"),
                'C' => {
                    let n = num(Some(value()), "-C");
                    o.after = n;
                    o.before = n;
                }
                d if d.is_ascii_digit() => {
                    let n: String = flags[k..].iter().take_while(|c| c.is_ascii_digit()).collect();
                    k += n.len() - 1;
                    let n = n.parse().unwrap_or(0);
                    o.after = n;
                    o.before = n;
                }
                other => usage(&format!("invalid option -- '{other}'")),
            }
            k += 1;
        }
    }
    if !have_e {
        if rest.is_empty() {
            usage("no pattern given");
        }
        o.patterns.push(rest.remove(0));
    }
    if rest.is_empty() && o.recursive {
        rest.push(".".into());
    }
    let names = !o.no_name && (o.with_name || rest.len() > 1 || o.recursive);
    let re = build(&o);
    let mut run = Run { o: &o, re, out: io::BufWriter::new(io::stdout()), matched: false, error: false, names };
    if rest.is_empty() {
        let mut d = Vec::new();
        let _ = io::stdin().lock().read_to_end(&mut d);
        run.file("(standard input)", &d);
    } else {
        for p in &rest {
            if p == "-" {
                let mut d = Vec::new();
                let _ = io::stdin().lock().fill_buf().map(|_| ());
                let _ = io::stdin().read_to_end(&mut d);
                run.file("(standard input)", &d);
            } else {
                run.path(p, true);
            }
            if run.matched && o.quiet {
                break;
            }
        }
    }
    let _ = run.out.flush();
    std::process::exit(if run.matched { 0 } else if run.error { 2 } else { 1 })
}
