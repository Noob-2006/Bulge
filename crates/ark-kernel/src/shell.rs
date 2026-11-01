//! Minimal POSIX-ish shell command analyser for the gates. It does not need to
//! execute anything: it splits a command line into simple commands (argv after
//! quote removal, with wrappers like `env`/`nohup`/`timeout` stripped and
//! `bash -c` / `$(...)` recursed into) plus redirection targets.

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Simple {
    pub argv: Vec<String>,
    /// Files written via `>`, `>>`, `&>`, `2>`…
    pub writes: Vec<String>,
    /// Index of the pipeline this command belongs to, and its position in it.
    pub pipeline: usize,
    pub stage: usize,
}

impl Simple {
    pub fn name(&self) -> &str {
        self.argv.first().map(|s| s.rsplit('/').next().unwrap_or(s)).unwrap_or("")
    }
    pub fn has(&self, flag: &str) -> bool {
        self.argv.iter().skip(1).any(|a| a == flag)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    /// `;` `&&` `||` `&` newline — ends a pipeline.
    Sep,
    Pipe,
    Redirect { write: bool },
}

const MAX_DEPTH: usize = 6;

pub fn parse(cmd: &str) -> Vec<Simple> {
    let mut out = Vec::new();
    let mut pipeline_id = 0;
    parse_into(cmd, 0, &mut out, &mut pipeline_id);
    out
}

fn parse_into(cmd: &str, depth: usize, out: &mut Vec<Simple>, pipeline_id: &mut usize) {
    if depth > MAX_DEPTH {
        // Pathological nesting: surface as an opaque command so gates still see it.
        out.push(Simple { argv: vec!["<nested>".into(), cmd.into()], ..Default::default() });
        return;
    }
    let (toks, subs) = lex(cmd);
    for s in subs {
        parse_into(&s, depth + 1, out, pipeline_id);
    }
    let mut cur = Simple { pipeline: *pipeline_id, ..Default::default() };
    let mut it = toks.into_iter().peekable();
    let mut stage = 0;
    let flush = |cur: &mut Simple, out: &mut Vec<Simple>, depth: usize, pipeline_id: &mut usize| {
        if cur.argv.is_empty() && cur.writes.is_empty() {
            return;
        }
        let mut s = std::mem::take(cur);
        strip_wrappers(&mut s.argv);
        // `bash -c '...'`, `sh -c`, `eval ...` → analyse the inner script too.
        let inner = match s.name() {
            "bash" | "sh" | "zsh" | "dash" | "ksh" => s.argv.iter().position(|a| a == "-c" || (a.starts_with('-') && a.ends_with('c') && !a.starts_with("--"))).and_then(|i| s.argv.get(i + 1)).cloned(),
            "eval" => Some(s.argv[1..].join(" ")),
            _ => None,
        };
        out.push(s);
        if let Some(inner) = inner {
            *pipeline_id += 1;
            parse_into(&inner, depth + 1, out, pipeline_id);
        }
    };
    while let Some(t) = it.next() {
        match t {
            Tok::Word(w) => {
                // Leading VAR=value assignments are not the command.
                if cur.argv.is_empty() && is_assignment(&w) {
                    continue;
                }
                cur.argv.push(w)
            }
            Tok::Redirect { write } => {
                if let Some(Tok::Word(target)) = it.next() {
                    if write {
                        cur.writes.push(target);
                    }
                }
            }
            Tok::Pipe => {
                cur.stage = stage;
                flush(&mut cur, out, depth, pipeline_id);
                stage += 1;
                cur.pipeline = *pipeline_id;
            }
            Tok::Sep => {
                cur.stage = stage;
                flush(&mut cur, out, depth, pipeline_id);
                *pipeline_id += 1;
                stage = 0;
                cur.pipeline = *pipeline_id;
            }
        }
    }
    cur.stage = stage;
    flush(&mut cur, out, depth, pipeline_id);
    *pipeline_id += 1;
}

fn is_assignment(w: &str) -> bool {
    match w.find('=') {
        Some(i) if i > 0 => w[..i].chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !w.starts_with(|c: char| c.is_ascii_digit()),
        _ => false,
    }
}

/// Strip command prefixes that just run another command.
fn strip_wrappers(argv: &mut Vec<String>) {
    loop {
        let Some(first) = argv.first() else { return };
        let name = first.rsplit('/').next().unwrap_or(first).to_string();
        let skip = match name.as_str() {
            "command" | "builtin" | "exec" | "nohup" | "time" | "then" | "do" | "else" | "!" | "{" | "(" => 1 + count_flags(&argv[1..], &[]),
            "env" => {
                let mut i = 1;
                while i < argv.len() && (argv[i].starts_with('-') || is_assignment(&argv[i])) {
                    i += if argv[i] == "-u" || argv[i] == "-C" { 2 } else { 1 };
                }
                i
            }
            "nice" | "ionice" | "chrt" | "stdbuf" | "taskset" => 1 + count_flags(&argv[1..], &["-n", "-c", "-p"]),
            "timeout" => {
                let i = 1 + count_flags(&argv[1..], &["-s", "-k", "--signal", "--kill-after"]);
                i + 1 // the duration
            }
            "xargs" => 1 + count_flags(&argv[1..], &["-I", "-n", "-P", "-L", "-d", "-a", "-E", "-s"]),
            _ => 0,
        };
        // Nothing after the wrapper: the wrapper itself is the command (`env`, `time`).
        if skip == 0 || skip >= argv.len() {
            return;
        }
        argv.drain(..skip);
    }
}

fn count_flags(args: &[String], with_value: &[&str]) -> usize {
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') && args[i] != "-" {
        i += if with_value.contains(&args[i].as_str()) { 2 } else { 1 };
    }
    i.min(args.len())
}

/// Tokenise, performing quote removal. Returns tokens plus the contents of every
/// `$(...)` / backtick substitution (analysed separately).
fn lex(s: &str) -> (Vec<Tok>, Vec<String>) {
    let chars: Vec<char> = s.chars().collect();
    let mut toks = Vec::new();
    let mut subs = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut i = 0;
    let end_word = |word: &mut String, in_word: &mut bool, toks: &mut Vec<Tok>| {
        if *in_word {
            toks.push(Tok::Word(std::mem::take(word)));
            *in_word = false;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                if let Some(&n) = chars.get(i + 1) {
                    if n != '\n' {
                        word.push(n);
                        in_word = true;
                    }
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            '\'' => {
                in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    word.push(chars[i]);
                    i += 1;
                }
                i += 1;
                continue;
            }
            '"' => {
                in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() && matches!(chars[i + 1], '"' | '\\' | '$' | '`') {
                        word.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    if chars[i] == '$' && chars.get(i + 1) == Some(&'(') {
                        let (inner, next) = balanced(&chars, i + 2);
                        subs.push(inner.clone());
                        word.push_str(&format!("$({inner})"));
                        i = next;
                        continue;
                    }
                    if chars[i] == '`' {
                        let (inner, next) = backtick(&chars, i + 1);
                        subs.push(inner);
                        i = next;
                        continue;
                    }
                    word.push(chars[i]);
                    i += 1;
                }
                i += 1;
                continue;
            }
            '$' if chars.get(i + 1) == Some(&'(') && chars.get(i + 2) != Some(&'(') => {
                let (inner, next) = balanced(&chars, i + 2);
                subs.push(inner.clone());
                word.push_str(&format!("$({inner})"));
                in_word = true;
                i = next;
                continue;
            }
            '`' => {
                let (inner, next) = backtick(&chars, i + 1);
                subs.push(inner);
                in_word = true;
                i = next;
                continue;
            }
            '<' if chars.get(i + 1) == Some(&'(') || chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') => {
                if chars.get(i + 1) == Some(&'(') {
                    // Process substitution <(cmd)
                    let (inner, next) = balanced(&chars, i + 2);
                    subs.push(inner);
                    i = next;
                } else {
                    // Here-doc: skip the delimiter word; body lines are data, not commands.
                    end_word(&mut word, &mut in_word, &mut toks);
                    i += 2;
                    if chars.get(i) == Some(&'-') {
                        i += 1;
                    }
                    while i < chars.len() && chars[i] == ' ' {
                        i += 1;
                    }
                    let mut delim = String::new();
                    while i < chars.len() && !chars[i].is_whitespace() && !";|&".contains(chars[i]) {
                        if !"'\"".contains(chars[i]) {
                            delim.push(chars[i]);
                        }
                        i += 1;
                    }
                    // Skip to end of line, then the body until a line equal to delim.
                    let rest: String = chars[i..].iter().collect();
                    if let Some(nl) = rest.find('\n') {
                        let body = &rest[nl + 1..];
                        let mut consumed = nl + 1;
                        for line in body.split_inclusive('\n') {
                            consumed += line.len();
                            if line.trim() == delim {
                                break;
                            }
                        }
                        let rest_chars = rest[..consumed.min(rest.len())].chars().count();
                        i += rest_chars;
                        toks.push(Tok::Sep);
                    } else {
                        i = chars.len();
                    }
                }
                continue;
            }
            '>' | '<' => {
                end_word_redirect_fd(&mut word, &mut in_word, &mut toks);
                let write = c == '>';
                i += 1;
                while i < chars.len() && matches!(chars[i], '>' | '|' | '&') {
                    if chars[i] == '&' && chars.get(i + 1).is_some_and(|c| c.is_ascii_digit() || *c == '-') {
                        // 2>&1 style dup: no file target.
                        i += 1;
                        while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '-') {
                            i += 1;
                        }
                        toks.push(Tok::Redirect { write: false });
                        toks.push(Tok::Word(String::new()));
                        break;
                    }
                    i += 1;
                }
                if !matches!(toks.last(), Some(Tok::Word(w)) if w.is_empty()) {
                    toks.push(Tok::Redirect { write });
                }
                continue;
            }
            '&' if chars.get(i + 1) == Some(&'>') => {
                end_word(&mut word, &mut in_word, &mut toks);
                i += 2;
                if chars.get(i) == Some(&'>') {
                    i += 1;
                }
                toks.push(Tok::Redirect { write: true });
                continue;
            }
            '|' => {
                end_word(&mut word, &mut in_word, &mut toks);
                if chars.get(i + 1) == Some(&'|') {
                    toks.push(Tok::Sep);
                    i += 2;
                } else {
                    toks.push(Tok::Pipe);
                    i += if chars.get(i + 1) == Some(&'&') { 2 } else { 1 };
                }
                continue;
            }
            ';' | '&' | '\n' => {
                end_word(&mut word, &mut in_word, &mut toks);
                toks.push(Tok::Sep);
                i += if c == '&' && chars.get(i + 1) == Some(&'&') { 2 } else { 1 };
                continue;
            }
            '(' | ')' | '{' | '}' if !in_word => {
                toks.push(Tok::Sep);
                i += 1;
                continue;
            }
            '#' if !in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            c if c.is_whitespace() => {
                end_word(&mut word, &mut in_word, &mut toks);
                i += 1;
                continue;
            }
            _ => {
                word.push(c);
                in_word = true;
                i += 1;
            }
        }
    }
    end_word(&mut word, &mut in_word, &mut toks);
    (toks, subs)
}

/// `2>` — drop a pure-digit fd number word before a redirect.
fn end_word_redirect_fd(word: &mut String, in_word: &mut bool, toks: &mut Vec<Tok>) {
    if *in_word {
        if !word.chars().all(|c| c.is_ascii_digit()) {
            toks.push(Tok::Word(std::mem::take(word)));
        } else {
            word.clear();
        }
        *in_word = false;
    }
}

fn balanced(chars: &[char], mut i: usize) -> (String, usize) {
    let start = i;
    let mut depth = 1;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => match c {
                '\'' | '"' => quote = Some(c),
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return (chars[start..i].iter().collect(), i + 1);
                    }
                }
                _ => {}
            },
        }
        i += 1;
    }
    (chars[start..].iter().collect(), chars.len())
}

fn backtick(chars: &[char], mut i: usize) -> (String, usize) {
    let start = i;
    while i < chars.len() && chars[i] != '`' {
        i += 1;
    }
    (chars[start..i.min(chars.len())].iter().collect(), (i + 1).min(chars.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(cmd: &str) -> Vec<String> {
        parse(cmd).iter().map(|s| s.name().to_string()).collect()
    }

    #[test]
    fn splits_operators_and_pipes() {
        assert_eq!(names("ls -la && cat a | grep x; echo hi || true & wait"), ["ls", "cat", "grep", "echo", "true", "wait"]);
        let p = parse("cat a | grep x | wc -l");
        assert_eq!(p.iter().map(|s| (s.pipeline, s.stage)).collect::<Vec<_>>(), vec![(0, 0), (0, 1), (0, 2)]);
    }

    #[test]
    fn quote_removal_and_escapes() {
        let p = parse(r#"echo "a b" 'c d' e\ f "x\"y""#);
        assert_eq!(p[0].argv, ["echo", "a b", "c d", "e f", "x\"y"]);
        // Quoted operators are data.
        assert_eq!(names("echo 'a && sudo rm' \"| sudo x\""), ["echo"]);
    }

    #[test]
    fn strips_wrappers_and_assignments() {
        assert_eq!(names("FOO=1 BAR=2 sudo ls"), ["sudo"]);
        assert_eq!(names("env -i PATH=/x nohup nice -n 5 timeout -s 9 10 sudo id"), ["sudo"]);
        assert_eq!(names("/usr/bin/sudo -u root id"), ["sudo"]);
        assert_eq!(names("xargs -I{} sudo rm {}"), ["sudo"]);
        assert_eq!(names("timeout"), ["timeout"]);
        assert_eq!(names("env"), ["env"]);
    }

    #[test]
    fn recurses_into_shell_c_eval_and_substitutions() {
        assert!(names("bash -c 'echo hi && sudo reboot'").contains(&"sudo".to_string()));
        assert!(names("sh -lc \"sudo id\"").contains(&"sudo".to_string()));
        assert!(names("eval sudo id").contains(&"sudo".to_string()));
        assert!(names("echo $(sudo cat /etc/shadow)").contains(&"sudo".to_string()));
        assert!(names("echo \"`sudo id`\"").contains(&"sudo".to_string()));
        assert!(names("diff <(sudo cat a) b").contains(&"sudo".to_string()));
    }

    #[test]
    fn redirections() {
        let p = parse("echo x > /etc/hosts 2>&1; cat a >> out.txt; cmd &> log; foo 2>/dev/null");
        assert_eq!(p[0].writes, ["/etc/hosts"]);
        assert_eq!(p[0].argv, ["echo", "x"]);
        assert_eq!(p[1].writes, ["out.txt"]);
        assert_eq!(p[2].writes, ["log"]);
        assert_eq!(p[3].writes, ["/dev/null"]);
        assert_eq!(p[3].argv, ["foo"]);
    }

    #[test]
    fn heredoc_body_is_not_commands() {
        let p = parse("cat <<'EOF' > f.txt\nsudo rm -rf /\nEOF\necho done");
        assert_eq!(p.iter().map(|s| s.name()).collect::<Vec<_>>(), ["cat", "echo"]);
    }

    #[test]
    fn comments_and_garbage_do_not_panic() {
        assert_eq!(names("ls # sudo rm"), ["ls"]);
        for junk in ["", "'unterminated", "\"open", "$(", "`", "a |", "&&&", ">>>", "\\", "<(", "<<", "((x))", "$((1+2))"] {
            let _ = parse(junk);
        }
        // Deep nesting is bounded.
        let deep = "bash -c ".repeat(20) + "id";
        let _ = parse(&deep);
    }
}
