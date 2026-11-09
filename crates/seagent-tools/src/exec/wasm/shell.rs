//! The POSIX-ish shell of the `wasm` backend, interpreted in-process. A POSIX shell compiled to
//! WASI cannot work there: `dash`, busybox `ash` and bash need `fork`/`exec` for every pipeline,
//! subshell and external command, and WASI preview 1 has neither. So the shell language is
//! interpreted here — on the host side, never touching anything but the [`Policy`] roots — and
//! every external command (`ls`, `grep`, `python3`, …) runs as its own WASI module in the
//! interpreter ([`Tools`]). Subshells and command substitutions are interpreter clones;
//! pipelines run their stages one after another through in-memory buffers.
//!
//! Supported: `;` `&&` `||` `|` `!`, `( … )` `{ …; }`, `if`/`elif`/`else`, `for`, `while`,
//! `until`, `case`, functions, `[[ … ]]`, redirections (`<` `>` `>>` `2>` `2>&1` `>&2` `&>`
//! `<<EOF` `<<-` `<<<`), quoting, `$VAR` `${VAR:-x}` `${#VAR}` `${VAR%pat}` `$(…)` `` `…` ``
//! `$((…))` `$?` `$$` `$#` `$@`, globs, and the builtins listed in [`BUILTINS`]. `&` runs the
//! job in the foreground (there is no job control). Anything else is reported, not guessed.

use super::policy::{join, normalize, Policy};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Write};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// Bytes a pipeline stage or command substitution may buffer.
const MAX_BUFFER: usize = 64 << 20;

/// Builtins (run in the interpreter; everything else is a WASI tool).
pub const BUILTINS: &[&str] = &[
    ":", ".", "[", "alias", "break", "builtin", "cd", "command", "continue", "echo", "eval", "exec", "exit", "export", "false", "hash", "local", "printf", "pwd", "read", "readonly", "return", "set", "shift", "sleep", "source",
    "test", "trap", "true", "type", "ulimit", "umask", "unalias", "unset", "wait", "mv", "rm", "xargs",
];

// ───────────── streams ─────────────

/// A readable stream with a shared position (a `while read` loop and the tools inside it
/// consume the same input).
#[derive(Clone)]
pub enum In {
    Null,
    Shared(Arc<Mutex<(Vec<u8>, usize)>>),
    Live(Arc<Live>),
}

/// The child's stdin pipe (`process write`).
pub struct Live {
    pub rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    pub buf: Mutex<Vec<u8>>,
    pub kill: Arc<AtomicBool>,
}

impl In {
    pub fn bytes(b: Vec<u8>) -> In {
        In::Shared(Arc::new(Mutex::new((b, 0))))
    }
    pub fn reader(&self) -> Box<dyn Read + Send> {
        Box::new(InReader(self.clone()))
    }
}

struct InReader(In);

impl Read for InReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match &self.0 {
            In::Null => Ok(0),
            In::Shared(s) => {
                let mut g = s.lock().unwrap();
                let (data, pos) = &mut *g;
                let n = out.len().min(data.len() - *pos);
                out[..n].copy_from_slice(&data[*pos..*pos + n]);
                *pos += n;
                Ok(n)
            }
            In::Live(l) => {
                loop {
                    {
                        let mut b = l.buf.lock().unwrap();
                        if !b.is_empty() {
                            let n = out.len().min(b.len());
                            out[..n].copy_from_slice(&b[..n]);
                            b.drain(..n);
                            return Ok(n);
                        }
                    }
                    if l.kill.load(Ordering::SeqCst) {
                        return Ok(0);
                    }
                    match l.rx.lock().unwrap().recv_timeout(Duration::from_millis(50)) {
                        Ok(chunk) => l.buf.lock().unwrap().extend_from_slice(&chunk),
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
                    }
                }
            }
        }
    }
}

/// A byte sink (the child's merged output).
pub type SinkFn = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Where output goes.
#[derive(Clone)]
pub enum Out {
    Null,
    Sink(SinkFn),
    Buf(Arc<Mutex<Vec<u8>>>),
    File(Arc<Mutex<File>>),
}

impl Out {
    pub fn put(&self, b: &[u8]) {
        match self {
            Out::Null => {}
            Out::Sink(f) => f(b),
            Out::Buf(v) => {
                let mut v = v.lock().unwrap();
                let room = MAX_BUFFER.saturating_sub(v.len());
                v.extend_from_slice(&b[..b.len().min(room)]);
            }
            Out::File(f) => {
                let _ = f.lock().unwrap().write_all(b);
            }
        }
    }
    pub fn writer(&self) -> Box<dyn Write + Send> {
        Box::new(OutWriter(self.clone()))
    }
}

struct OutWriter(Out);

impl Write for OutWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.put(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct Io {
    pub stdin: In,
    pub stdout: Out,
    pub stderr: Out,
}

/// How the shell runs an external command (a WASI module): implemented by the backend.
pub trait Tools {
    /// Is `name` a known tool (for `command -v` / `type`)?
    fn find(&self, name: &str, cwd: &str) -> Option<String>;
    /// Run it; `None` = no such tool (exit 127 with "command not found").
    fn run(&self, argv: &[String], env: &[(String, String)], cwd: &str, io: &Io) -> Option<i32>;
}

// ───────────── syntax ─────────────

#[derive(Debug, Clone, PartialEq)]
enum Part {
    /// Unquoted literal (globs and tilde apply).
    Lit(String),
    /// Quoted literal.
    Q(String),
    Var { name: String, op: Option<(String, Word)>, quoted: bool, len: bool },
    Sub(String, bool),
    Arith(String, bool),
    Tilde(String),
}

type Word = Vec<Part>;

#[derive(Debug, Clone, PartialEq)]
enum ROp {
    In,
    Out,
    Append,
    Dup,
    Both,
    BothAppend,
    Here(String, bool),
}

#[derive(Debug, Clone, PartialEq)]
struct Redir {
    fd: i32,
    op: ROp,
    target: Word,
}

#[derive(Debug, Clone, PartialEq)]
enum Cmd {
    Simple { assigns: Vec<(String, Word)>, words: Vec<Word>, redirs: Vec<Redir> },
    Pipe { neg: bool, cmds: Vec<Cmd> },
    AndOr(Box<Cmd>, Vec<(bool, Cmd)>),
    Seq(Vec<Cmd>),
    Sub(Box<Cmd>, Vec<Redir>),
    Group(Box<Cmd>, Vec<Redir>),
    If(Vec<(Cmd, Cmd)>, Option<Box<Cmd>>, Vec<Redir>),
    For(String, Option<Vec<Word>>, Box<Cmd>, Vec<Redir>),
    While(bool, Box<Cmd>, Box<Cmd>, Vec<Redir>),
    Case(Word, Vec<(Vec<Word>, Cmd)>, Vec<Redir>),
    Func(String, Rc<Cmd>),
    Cond(Vec<Word>),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(Word, String),
    Op(String, i32),
    Nl,
    Eof,
}

struct Lexer {
    s: Vec<char>,
    i: usize,
    back: Vec<Tok>,
}

fn is_meta(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>')
}

fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(c) if c.is_ascii_alphabetic() || c == '_') && c.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Lexer {
    fn new(src: &str) -> Lexer {
        Lexer { s: src.chars().collect(), i: 0, back: vec![] }
    }
    fn peek_c(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }
    fn starts(&self, p: &str) -> bool {
        p.chars().enumerate().all(|(k, c)| self.peek_c(k) == Some(c))
    }
    fn unread(&mut self, t: Tok) {
        self.back.push(t);
    }
    fn peek(&mut self) -> Result<Tok, String> {
        let t = self.next()?;
        self.back.push(t.clone());
        Ok(t)
    }
    fn next(&mut self) -> Result<Tok, String> {
        if let Some(t) = self.back.pop() {
            return Ok(t);
        }
        loop {
            match self.peek_c(0) {
                Some(' ' | '\t' | '\r') => self.i += 1,
                Some('\\') if self.peek_c(1) == Some('\n') => self.i += 2,
                Some('#') => {
                    while self.peek_c(0).is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                }
                _ => break,
            }
        }
        let Some(c) = self.peek_c(0) else { return Ok(Tok::Eof) };
        if c == '\n' {
            self.i += 1;
            return Ok(Tok::Nl);
        }
        // An IO number: digits directly before a redirection operator.
        if c.is_ascii_digit() {
            let mut k = 0;
            while self.peek_c(k).is_some_and(|c| c.is_ascii_digit()) {
                k += 1;
            }
            if matches!(self.peek_c(k), Some('<' | '>')) {
                let n: i32 = self.s[self.i..self.i + k].iter().collect::<String>().parse().unwrap_or(1);
                self.i += k;
                let op = self.op().ok_or("bad redirection")?;
                return Ok(Tok::Op(op, n));
            }
        }
        if let Some(op) = self.op() {
            return Ok(Tok::Op(op, -1));
        }
        self.word()
    }
    fn op(&mut self) -> Option<String> {
        for o in ["&>>", "<<<", "<<-", "&&", "||", ";;", "<<", ">>", ">&", "<&", ">|", "&>", "|&", ";", "&", "|", "(", ")", "<", ">"] {
            if self.starts(o) {
                self.i += o.len();
                return Some(o.to_string());
            }
        }
        None
    }
    fn word(&mut self) -> Result<Tok, String> {
        let start = self.i;
        let mut parts: Word = vec![];
        let mut lit = String::new();
        let flush = |lit: &mut String, parts: &mut Word| {
            if !lit.is_empty() {
                parts.push(Part::Lit(std::mem::take(lit)));
            }
        };
        if self.peek_c(0) == Some('~') {
            self.i += 1;
            let mut user = String::new();
            while self.peek_c(0).is_some_and(|c| !is_meta(c) && c != '/' && c != '"' && c != '\'') {
                user.push(self.s[self.i]);
                self.i += 1;
            }
            parts.push(Part::Tilde(user));
        }
        while let Some(c) = self.peek_c(0) {
            if is_meta(c) {
                break;
            }
            match c {
                '\'' => {
                    flush(&mut lit, &mut parts);
                    self.i += 1;
                    let mut q = String::new();
                    loop {
                        match self.peek_c(0) {
                            None => return Err("unterminated '".into()),
                            Some('\'') => {
                                self.i += 1;
                                break;
                            }
                            Some(c) => {
                                q.push(c);
                                self.i += 1;
                            }
                        }
                    }
                    parts.push(Part::Q(q));
                }
                '"' => {
                    flush(&mut lit, &mut parts);
                    self.i += 1;
                    let inner = self.dquote()?;
                    if inner.is_empty() {
                        parts.push(Part::Q(String::new()));
                    }
                    parts.extend(inner);
                }
                '\\' => {
                    flush(&mut lit, &mut parts);
                    self.i += 1;
                    if let Some(n) = self.peek_c(0) {
                        self.i += 1;
                        parts.push(Part::Q(n.to_string()));
                    }
                }
                '$' => {
                    flush(&mut lit, &mut parts);
                    let p = self.dollar(false)?;
                    parts.push(p);
                }
                '`' => {
                    flush(&mut lit, &mut parts);
                    self.i += 1;
                    let src = self.backtick()?;
                    parts.push(Part::Sub(src, false));
                }
                _ => {
                    lit.push(c);
                    self.i += 1;
                }
            }
        }
        flush(&mut lit, &mut parts);
        let raw: String = self.s[start..self.i].iter().collect();
        Ok(Tok::Word(parts, raw))
    }
    fn dquote(&mut self) -> Result<Word, String> {
        let mut parts = vec![];
        let mut q = String::new();
        loop {
            let Some(c) = self.peek_c(0) else { return Err("unterminated \"".into()) };
            match c {
                '"' => {
                    self.i += 1;
                    break;
                }
                '\\' => {
                    let n = self.peek_c(1);
                    if matches!(n, Some('$' | '`' | '"' | '\\' | '\n')) {
                        if n != Some('\n') {
                            q.push(n.unwrap_or('\\'));
                        }
                        self.i += 2;
                    } else {
                        q.push('\\');
                        self.i += 1;
                    }
                }
                '$' => {
                    if !q.is_empty() {
                        parts.push(Part::Q(std::mem::take(&mut q)));
                    }
                    let p = self.dollar(true)?;
                    parts.push(p);
                }
                '`' => {
                    if !q.is_empty() {
                        parts.push(Part::Q(std::mem::take(&mut q)));
                    }
                    self.i += 1;
                    let src = self.backtick()?;
                    parts.push(Part::Sub(src, true));
                }
                c => {
                    q.push(c);
                    self.i += 1;
                }
            }
        }
        if !q.is_empty() {
            parts.push(Part::Q(q));
        }
        Ok(parts)
    }
    fn backtick(&mut self) -> Result<String, String> {
        let mut out = String::new();
        loop {
            match self.peek_c(0) {
                None => return Err("unterminated `".into()),
                Some('`') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some('\\') if matches!(self.peek_c(1), Some('`' | '\\' | '$')) => {
                    out.push(self.s[self.i + 1]);
                    self.i += 2;
                }
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }
    /// The source between `open` (already consumed) and its matching `)`, skipping quotes.
    fn balanced(&mut self, depth0: usize) -> Result<String, String> {
        let mut depth = depth0;
        let start = self.i;
        while let Some(c) = self.peek_c(0) {
            match c {
                '\'' => {
                    self.i += 1;
                    while self.peek_c(0).is_some_and(|c| c != '\'') {
                        self.i += 1;
                    }
                }
                '"' => {
                    self.i += 1;
                    while let Some(c) = self.peek_c(0) {
                        if c == '\\' {
                            self.i += 1;
                        } else if c == '"' {
                            break;
                        }
                        self.i += 1;
                    }
                }
                '\\' => self.i += 1,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        let s: String = self.s[start..self.i].iter().collect();
                        self.i += 1;
                        return Ok(s);
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
        Err("unterminated $(".into())
    }
    fn dollar(&mut self, quoted: bool) -> Result<Part, String> {
        self.i += 1; // `$`
        match self.peek_c(0) {
            Some('(') if self.peek_c(1) == Some('(') => {
                self.i += 2;
                let s = self.balanced(2)?;
                // `$(( … ))`: the inner text without the last `)`.
                let inner = s.strip_suffix(')').unwrap_or(&s).to_string();
                Ok(Part::Arith(inner, quoted))
            }
            Some('(') => {
                self.i += 1;
                Ok(Part::Sub(self.balanced(1)?, quoted))
            }
            Some('{') => {
                self.i += 1;
                let mut body = String::new();
                let mut depth = 1;
                loop {
                    match self.peek_c(0) {
                        None => return Err("unterminated ${".into()),
                        Some('{') => depth += 1,
                        Some('}') => {
                            depth -= 1;
                            if depth == 0 {
                                self.i += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    body.push(self.s[self.i]);
                    self.i += 1;
                }
                param(&body, quoted)
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                let mut name = String::new();
                while self.peek_c(0).is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                    name.push(self.s[self.i]);
                    self.i += 1;
                }
                Ok(Part::Var { name, op: None, quoted, len: false })
            }
            Some(c) if c.is_ascii_digit() || "?$#@*!-".contains(c) => {
                self.i += 1;
                Ok(Part::Var { name: c.to_string(), op: None, quoted, len: false })
            }
            _ => Ok(if quoted { Part::Q("$".into()) } else { Part::Lit("$".into()) }),
        }
    }
    /// Remove a here-document body (lines after the current one, up to `delim`).
    fn heredoc(&mut self, delim: &str, strip: bool) -> Result<String, String> {
        let mut k = self.i;
        while k < self.s.len() && self.s[k] != '\n' {
            k += 1;
        }
        if k >= self.s.len() {
            return Err(format!("here-document `{delim}` has no body"));
        }
        let body_start = k + 1;
        let mut pos = body_start;
        let mut body = String::new();
        loop {
            if pos >= self.s.len() {
                break;
            }
            let mut e = pos;
            while e < self.s.len() && self.s[e] != '\n' {
                e += 1;
            }
            let line: String = self.s[pos..e].iter().collect();
            let cmp = if strip { line.trim_start_matches('\t').to_string() } else { line.clone() };
            pos = (e + 1).min(self.s.len());
            if cmp.trim_end_matches('\r') == delim {
                break;
            }
            body.push_str(if strip { cmp.as_str() } else { line.as_str() });
            body.push('\n');
        }
        self.s.drain(body_start..pos);
        Ok(body)
    }
}

fn param(body: &str, quoted: bool) -> Result<Part, String> {
    if let Some(n) = body.strip_prefix('#').filter(|n| !n.is_empty() && (is_name(n) || n.chars().all(|c| c.is_ascii_digit()) || *n == "@" || *n == "*")) {
        return Ok(Part::Var { name: n.into(), op: None, quoted, len: true });
    }
    let name_len = body.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(body.len()).max(if body.starts_with(['?', '$', '#', '@', '*', '!', '-']) { 1 } else { 0 });
    let (name, rest) = body.split_at(name_len);
    if name.is_empty() {
        return Err(format!("${{{body}}}: bad substitution"));
    }
    if rest.is_empty() {
        return Ok(Part::Var { name: name.into(), op: None, quoted, len: false });
    }
    for op in [":-", ":=", ":+", ":?", "%%", "##", "-", "=", "+", "?", "%", "#"] {
        if let Some(arg) = rest.strip_prefix(op) {
            let mut lx = Lexer::new(arg);
            let w = match lx.word()? {
                Tok::Word(w, _) => w,
                _ => vec![],
            };
            // The rest after the word (spaces inside `${x:-a b}`) is kept literally.
            let tail: String = lx.s[lx.i..].iter().collect();
            let mut w = w;
            if !tail.is_empty() {
                w.push(Part::Q(tail));
            }
            return Ok(Part::Var { name: name.into(), op: Some((op.into(), w)), quoted, len: false });
        }
    }
    Err(format!("${{{body}}}: bad substitution"))
}

// ───────────── parser ─────────────

struct Parser {
    lx: Lexer,
}

fn word_text(w: &Word) -> Option<&str> {
    match w.as_slice() {
        [Part::Lit(s)] => Some(s.as_str()),
        _ => None,
    }
}

fn is_reserved(t: &Tok, set: &[&str]) -> bool {
    matches!(t, Tok::Word(w, _) if word_text(w).is_some_and(|s| set.contains(&s)))
}

impl Parser {
    fn parse(src: &str) -> Result<Cmd, String> {
        let mut p = Parser { lx: Lexer::new(src) };
        let c = p.list(&[])?;
        match p.lx.next()? {
            Tok::Eof => Ok(c),
            t => Err(format!("syntax error near {}", show(&t))),
        }
    }
    fn skip_nl(&mut self) -> Result<(), String> {
        while self.lx.peek()? == Tok::Nl {
            self.lx.next()?;
        }
        Ok(())
    }
    fn list(&mut self, stop: &[&str]) -> Result<Cmd, String> {
        let mut items = vec![];
        loop {
            self.skip_nl()?;
            let t = self.lx.peek()?;
            if t == Tok::Eof || is_reserved(&t, stop) || matches!(&t, Tok::Op(o, _) if o == ")" || o == ";;") {
                break;
            }
            items.push(self.and_or()?);
            match self.lx.peek()? {
                Tok::Op(o, _) if o == ";" || o == "&" => {
                    self.lx.next()?;
                }
                Tok::Nl => {}
                _ => break,
            }
        }
        Ok(if items.len() == 1 { items.pop().unwrap() } else { Cmd::Seq(items) })
    }
    fn and_or(&mut self) -> Result<Cmd, String> {
        let first = self.pipeline()?;
        let mut rest = vec![];
        loop {
            match self.lx.peek()? {
                Tok::Op(o, _) if o == "&&" || o == "||" => {
                    self.lx.next()?;
                    self.skip_nl()?;
                    rest.push((o == "&&", self.pipeline()?));
                }
                _ => break,
            }
        }
        Ok(if rest.is_empty() { first } else { Cmd::AndOr(Box::new(first), rest) })
    }
    fn pipeline(&mut self) -> Result<Cmd, String> {
        let mut neg = false;
        if is_reserved(&self.lx.peek()?, &["!"]) {
            self.lx.next()?;
            neg = true;
        }
        let mut cmds = vec![self.command()?];
        loop {
            match self.lx.peek()? {
                Tok::Op(o, _) if o == "|" || o == "|&" => {
                    self.lx.next()?;
                    self.skip_nl()?;
                    cmds.push(self.command()?);
                }
                _ => break,
            }
        }
        Ok(if cmds.len() == 1 && !neg { cmds.pop().unwrap() } else { Cmd::Pipe { neg, cmds } })
    }
    fn expect_word(&mut self, w: &str) -> Result<(), String> {
        self.skip_nl()?;
        let t = self.lx.next()?;
        if is_reserved(&t, &[w]) {
            Ok(())
        } else {
            Err(format!("syntax error: expected `{w}`, found {}", show(&t)))
        }
    }
    fn redirs(&mut self) -> Result<Vec<Redir>, String> {
        let mut r = vec![];
        while let Tok::Op(o, fd) = self.lx.peek()? {
            if !is_redir(&o) {
                break;
            }
            self.lx.next()?;
            r.push(self.redir(&o, fd)?);
        }
        Ok(r)
    }
    fn command(&mut self) -> Result<Cmd, String> {
        let t = self.lx.next()?;
        let compound = match &t {
            Tok::Word(w, _) => match word_text(w) {
                Some("{") => {
                    let body = self.list(&["}"])?;
                    self.expect_word("}")?;
                    Some(Cmd::Group(Box::new(body), vec![]))
                }
                Some("if") => {
                    let mut arms = vec![];
                    let mut els = None;
                    let c = self.list(&["then"])?;
                    self.expect_word("then")?;
                    let b = self.list(&["elif", "else", "fi"])?;
                    arms.push((c, b));
                    loop {
                        self.skip_nl()?;
                        let t = self.lx.next()?;
                        match &t {
                            Tok::Word(w, _) if word_text(w) == Some("elif") => {
                                let c = self.list(&["then"])?;
                                self.expect_word("then")?;
                                let b = self.list(&["elif", "else", "fi"])?;
                                arms.push((c, b));
                            }
                            Tok::Word(w, _) if word_text(w) == Some("else") => {
                                els = Some(Box::new(self.list(&["fi"])?));
                                self.expect_word("fi")?;
                                break;
                            }
                            Tok::Word(w, _) if word_text(w) == Some("fi") => break,
                            other => return Err(format!("syntax error in if: {}", show(other))),
                        }
                    }
                    Some(Cmd::If(arms, els, vec![]))
                }
                Some(k @ ("while" | "until")) => {
                    let until = k == "until";
                    let c = self.list(&["do"])?;
                    self.expect_word("do")?;
                    let b = self.list(&["done"])?;
                    self.expect_word("done")?;
                    Some(Cmd::While(until, Box::new(c), Box::new(b), vec![]))
                }
                Some("for") => {
                    let name = match self.lx.next()? {
                        Tok::Word(w, _) => word_text(&w).filter(|n| is_name(n)).map(String::from).ok_or("for: bad variable name")?,
                        t => return Err(format!("for: unexpected {}", show(&t))),
                    };
                    let mut items = None;
                    self.skip_nl()?;
                    if is_reserved(&self.lx.peek()?, &["in"]) {
                        self.lx.next()?;
                        let mut v = vec![];
                        while let Tok::Word(w, _) = self.lx.peek()? {
                            self.lx.next()?;
                            v.push(w);
                        }
                        items = Some(v);
                    }
                    if let Tok::Op(o, _) = self.lx.peek()? {
                        if o == ";" {
                            self.lx.next()?;
                        }
                    }
                    self.expect_word("do")?;
                    let b = self.list(&["done"])?;
                    self.expect_word("done")?;
                    Some(Cmd::For(name, items, Box::new(b), vec![]))
                }
                Some("case") => {
                    let w = match self.lx.next()? {
                        Tok::Word(w, _) => w,
                        t => return Err(format!("case: unexpected {}", show(&t))),
                    };
                    self.skip_nl()?;
                    self.expect_word("in")?;
                    let mut arms = vec![];
                    loop {
                        self.skip_nl()?;
                        let t = self.lx.next()?;
                        if is_reserved(&t, &["esac"]) {
                            break;
                        }
                        let mut pats = vec![];
                        let mut t = t;
                        if matches!(&t, Tok::Op(o, _) if o == "(") {
                            t = self.lx.next()?;
                        }
                        loop {
                            match t {
                                Tok::Word(w, _) => pats.push(w),
                                other => return Err(format!("case: bad pattern {}", show(&other))),
                            }
                            match self.lx.next()? {
                                Tok::Op(o, _) if o == "|" => t = self.lx.next()?,
                                Tok::Op(o, _) if o == ")" => break,
                                other => return Err(format!("case: expected `)`, found {}", show(&other))),
                            }
                        }
                        let body = self.list(&["esac"])?;
                        arms.push((pats, body));
                        self.skip_nl()?;
                        match self.lx.peek()? {
                            Tok::Op(o, _) if o == ";;" => {
                                self.lx.next()?;
                            }
                            _ => {}
                        }
                    }
                    Some(Cmd::Case(w, arms, vec![]))
                }
                Some("[[") => {
                    let mut args = vec![];
                    loop {
                        match self.lx.next()? {
                            Tok::Word(w, _) if word_text(&w) == Some("]]") => break,
                            Tok::Word(w, _) => args.push(w),
                            Tok::Op(o, _) if o == "&&" => args.push(vec![Part::Q("-a".into())]),
                            Tok::Op(o, _) if o == "||" => args.push(vec![Part::Q("-o".into())]),
                            Tok::Op(o, _) if o == "(" || o == ")" || o == "<" || o == ">" => args.push(vec![Part::Q(o)]),
                            t => return Err(format!("[[: unexpected {}", show(&t))),
                        }
                    }
                    Some(Cmd::Cond(args))
                }
                Some("function") => {
                    let name = match self.lx.next()? {
                        Tok::Word(w, _) => word_text(&w).map(String::from).ok_or("function: bad name")?,
                        t => return Err(format!("function: unexpected {}", show(&t))),
                    };
                    if let Tok::Op(o, _) = self.lx.peek()? {
                        if o == "(" {
                            self.lx.next()?;
                            self.lx.next()?;
                        }
                    }
                    self.skip_nl()?;
                    let body = self.command()?;
                    return Ok(Cmd::Func(name, Rc::new(body)));
                }
                _ => None,
            },
            Tok::Op(o, _) if o == "(" => {
                let body = self.list(&[])?;
                match self.lx.next()? {
                    Tok::Op(o, _) if o == ")" => {}
                    t => return Err(format!("syntax error: expected `)`, found {}", show(&t))),
                }
                Some(Cmd::Sub(Box::new(body), vec![]))
            }
            _ => None,
        };
        if let Some(mut c) = compound {
            let r = self.redirs()?;
            match &mut c {
                Cmd::Group(_, x) | Cmd::Sub(_, x) | Cmd::If(_, _, x) | Cmd::For(_, _, _, x) | Cmd::While(_, _, _, x) | Cmd::Case(_, _, x) => *x = r,
                _ => {}
            }
            return Ok(c);
        }
        // A function definition: NAME ( ) body
        if let Tok::Word(w, _) = &t {
            if let Some(name) = word_text(w).filter(|n| is_name(n)) {
                if let Tok::Op(o, _) = self.lx.peek()? {
                    if o == "(" {
                        self.lx.next()?;
                        match self.lx.next()? {
                            Tok::Op(c, _) if c == ")" => {}
                            t => return Err(format!("syntax error: expected `)` after `{name}(`, found {}", show(&t))),
                        }
                        self.skip_nl()?;
                        let body = self.command()?;
                        return Ok(Cmd::Func(name.to_string(), Rc::new(body)));
                    }
                }
            }
        }
        self.lx.unread(t);
        self.simple()
    }
    fn redir(&mut self, op: &str, fd: i32) -> Result<Redir, String> {
        let target = match self.lx.next()? {
            Tok::Word(w, _) => w,
            t => return Err(format!("syntax error: redirection `{op}` needs a target, found {}", show(&t))),
        };
        Ok(match op {
            "<" => Redir { fd: if fd < 0 { 0 } else { fd }, op: ROp::In, target },
            ">" | ">|" => Redir { fd: if fd < 0 { 1 } else { fd }, op: ROp::Out, target },
            ">>" => Redir { fd: if fd < 0 { 1 } else { fd }, op: ROp::Append, target },
            ">&" | "<&" => {
                let dflt = if op == ">&" { 1 } else { 0 };
                Redir { fd: if fd < 0 { dflt } else { fd }, op: ROp::Dup, target }
            }
            "&>" => Redir { fd: 1, op: ROp::Both, target },
            "&>>" => Redir { fd: 1, op: ROp::BothAppend, target },
            "<<<" => Redir { fd: if fd < 0 { 0 } else { fd }, op: ROp::Here(String::new(), true), target },
            "<<" | "<<-" => {
                let quoted = target.iter().any(|p| matches!(p, Part::Q(_)));
                let delim: String = target.iter().map(|p| match p {
                    Part::Lit(s) | Part::Q(s) => s.clone(),
                    _ => String::new(),
                }).collect();
                let body = self.lx.heredoc(&delim, op == "<<-")?;
                Redir { fd: if fd < 0 { 0 } else { fd }, op: ROp::Here(body, !quoted), target: vec![] }
            }
            other => return Err(format!("unsupported redirection `{other}`")),
        })
    }
    fn simple(&mut self) -> Result<Cmd, String> {
        let mut assigns = vec![];
        let mut words = vec![];
        let mut redirs = vec![];
        loop {
            match self.lx.peek()? {
                Tok::Op(o, fd) if is_redir(&o) => {
                    self.lx.next()?;
                    redirs.push(self.redir(&o, fd)?);
                }
                Tok::Word(w, raw) => {
                    self.lx.next()?;
                    if words.is_empty() {
                        if let Some((name, val)) = split_assign(&w, &raw) {
                            assigns.push((name, val));
                            continue;
                        }
                    }
                    words.push(w);
                }
                _ => break,
            }
        }
        if assigns.is_empty() && words.is_empty() && redirs.is_empty() {
            let t = self.lx.next()?;
            return Err(format!("syntax error near {}", show(&t)));
        }
        Ok(Cmd::Simple { assigns, words, redirs })
    }
}

fn is_redir(o: &str) -> bool {
    matches!(o, "<" | ">" | ">>" | ">&" | "<&" | ">|" | "&>" | "&>>" | "<<" | "<<-" | "<<<")
}

fn show(t: &Tok) -> String {
    match t {
        Tok::Word(_, raw) => format!("`{raw}`"),
        Tok::Op(o, _) => format!("`{o}`"),
        Tok::Nl => "newline".into(),
        Tok::Eof => "end of input".into(),
    }
}

/// `NAME=value` at the start of a simple command (the name part must be a plain literal).
fn split_assign(w: &Word, _raw: &str) -> Option<(String, Word)> {
    let Some(Part::Lit(first)) = w.first() else { return None };
    let eq = first.find('=')?;
    let name = &first[..eq];
    if !is_name(name) {
        return None;
    }
    let mut val: Word = vec![];
    let rest = &first[eq + 1..];
    if !rest.is_empty() {
        val.push(Part::Lit(rest.to_string()));
    }
    val.extend(w[1..].iter().cloned());
    Some((name.to_string(), val))
}

// ───────────── glob / patterns ─────────────

/// `fnmatch`: `*`, `?`, `[abc]`, `[a-z]`, `[!x]`, `\` escapes.
pub fn fnmatch(pat: &str, s: &str) -> bool {
    fn go(p: &[char], s: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some('*') => (0..=s.len()).any(|k| go(&p[1..], &s[k..])),
            Some('?') => !s.is_empty() && go(&p[1..], &s[1..]),
            Some('[') => {
                let Some(close) = p.iter().skip(2).position(|c| *c == ']').map(|i| i + 2) else { return !s.is_empty() && s[0] == '[' && go(&p[1..], &s[1..]) };
                if s.is_empty() {
                    return false;
                }
                let set = &p[1..close];
                let (neg, set) = match set.first() {
                    Some('!' | '^') => (true, &set[1..]),
                    _ => (false, set),
                };
                let mut hit = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        hit |= set[i] <= s[0] && s[0] <= set[i + 2];
                        i += 3;
                    } else {
                        hit |= set[i] == s[0];
                        i += 1;
                    }
                }
                hit != neg && go(&p[close + 1..], &s[1..])
            }
            Some('\\') if p.len() > 1 => !s.is_empty() && s[0] == p[1] && go(&p[2..], &s[1..]),
            Some(c) => !s.is_empty() && s[0] == *c && go(&p[1..], &s[1..]),
        }
    }
    let (p, s): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    go(&p, &s)
}

fn has_glob(p: &str) -> bool {
    let mut esc = false;
    for c in p.chars() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' => esc = true,
            '*' | '?' | '[' => return true,
            _ => {}
        }
    }
    false
}

fn unescape(p: &str) -> String {
    let mut out = String::new();
    let mut esc = false;
    for c in p.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else {
            out.push(c);
        }
    }
    out
}

fn escape_glob(s: &str) -> String {
    s.chars().flat_map(|c| if "*?[]\\".contains(c) { vec!['\\', c] } else { vec![c] }).collect()
}

// ───────────── the interpreter ─────────────

pub enum Flow {
    Exit(i32),
    Break(u32),
    Continue(u32),
    Return(i32),
}

type X = Result<i32, Flow>;

/// One field during expansion: its text and the glob pattern form (quoted parts escaped).
#[derive(Default, Clone)]
struct Field {
    text: String,
    pat: String,
    glob: bool,
    quoted: bool,
}

#[derive(Clone)]
pub struct Shell<'a> {
    pub vars: BTreeMap<String, String>,
    pub exported: BTreeSet<String>,
    pub cwd: String,
    pub params: Vec<String>,
    funcs: HashMap<String, Rc<Cmd>>,
    pub last: i32,
    errexit: bool,
    nounset: bool,
    cond: u32,
    pub policy: &'a Policy,
    pub tools: &'a dyn Tools,
    pub kill: Arc<AtomicBool>,
    pub pid: u32,
}

impl<'a> Shell<'a> {
    pub fn new(policy: &'a Policy, tools: &'a dyn Tools, env: &[(String, String)], cwd: &str, kill: Arc<AtomicBool>, pid: u32) -> Shell<'a> {
        let mut vars = BTreeMap::new();
        let mut exported = BTreeSet::new();
        for (k, v) in env {
            if is_name(k) {
                vars.insert(k.clone(), v.clone());
                exported.insert(k.clone());
            }
        }
        vars.insert("PWD".into(), cwd.to_string());
        exported.insert("PWD".into());
        Shell { vars, exported, cwd: normalize(cwd), params: vec![], funcs: HashMap::new(), last: 0, errexit: false, nounset: false, cond: 0, policy, tools, kill, pid }
    }

    /// Parse and run `src`; returns the exit status.
    pub fn run_script(&mut self, src: &str, io: &Io) -> i32 {
        match Parser::parse(src) {
            Err(e) => {
                io.stderr.put(format!("sh: {e}\n").as_bytes());
                2
            }
            Ok(c) => match self.run(&c, io) {
                Ok(n) | Err(Flow::Exit(n)) | Err(Flow::Return(n)) => n,
                Err(Flow::Break(_) | Flow::Continue(_)) => self.last,
            },
        }
    }

    fn killed(&self) -> bool {
        self.kill.load(Ordering::SeqCst)
    }

    fn get(&self, name: &str) -> Option<String> {
        match name {
            "?" => Some(self.last.to_string()),
            "$" => Some(self.pid.to_string()),
            "#" => Some(self.params.len().to_string()),
            "0" => Some("sh".into()),
            "!" => Some(String::new()),
            "-" => Some(if self.errexit { "e".into() } else { String::new() }),
            "@" | "*" => Some(self.params.join(" ")),
            n if n.chars().all(|c| c.is_ascii_digit()) => n.parse::<usize>().ok().and_then(|i| self.params.get(i.wrapping_sub(1)).cloned()),
            n => self.vars.get(n).cloned(),
        }
    }

    fn set(&mut self, name: &str, v: String) {
        if name == "PWD" {
            self.cwd = normalize(&v);
        }
        self.vars.insert(name.to_string(), v);
    }

    pub fn env(&self) -> Vec<(String, String)> {
        self.exported.iter().filter_map(|k| self.vars.get(k).map(|v| (k.clone(), v.clone()))).collect()
    }

    fn status(&mut self, n: i32) -> X {
        self.last = n;
        if n != 0 && self.errexit && self.cond == 0 {
            return Err(Flow::Exit(n));
        }
        Ok(n)
    }

    fn run(&mut self, c: &Cmd, io: &Io) -> X {
        if self.killed() {
            return Err(Flow::Exit(137));
        }
        match c {
            Cmd::Simple { assigns, words, redirs } => self.simple(assigns, words, redirs, io),
            Cmd::Seq(v) => {
                let mut n = 0;
                for c in v {
                    n = self.run(c, io)?;
                }
                Ok(n)
            }
            Cmd::AndOr(first, rest) => {
                self.cond += 1;
                let r = self.run(first, io);
                self.cond -= 1;
                let mut n = r?;
                for (i, (and, c)) in rest.iter().enumerate() {
                    if (n == 0) == *and {
                        let last = i == rest.len() - 1;
                        if !last {
                            self.cond += 1;
                        }
                        let r = self.run(c, io);
                        if !last {
                            self.cond -= 1;
                        }
                        n = r?;
                    }
                }
                self.last = n;
                Ok(n)
            }
            Cmd::Pipe { neg, cmds } => {
                let mut input = io.stdin.clone();
                let mut n = 0;
                if *neg {
                    self.cond += 1;
                }
                for (i, c) in cmds.iter().enumerate() {
                    let last = i == cmds.len() - 1;
                    let buf = Arc::new(Mutex::new(Vec::new()));
                    let stage = Io { stdin: input.clone(), stdout: if last { io.stdout.clone() } else { Out::Buf(buf.clone()) }, stderr: io.stderr.clone() };
                    // Each stage runs in its own interpreter copy, like a subshell.
                    let mut sub = self.clone();
                    let r = sub.run(c, &stage);
                    n = match r {
                        Ok(n) | Err(Flow::Exit(n)) | Err(Flow::Return(n)) => n,
                        Err(_) => sub.last,
                    };
                    if self.killed() {
                        if *neg {
                            self.cond -= 1;
                        }
                        return Err(Flow::Exit(137));
                    }
                    let data = std::mem::take(&mut *buf.lock().unwrap());
                    input = In::bytes(data);
                }
                if *neg {
                    self.cond -= 1;
                    n = (n == 0) as i32;
                    self.last = n;
                    return Ok(n);
                }
                self.status(n)
            }
            Cmd::Sub(body, redirs) => {
                let io = self.redirect(redirs, io)?;
                let mut sub = self.clone();
                let n = match sub.run(body, &io) {
                    Ok(n) | Err(Flow::Exit(n)) | Err(Flow::Return(n)) => n,
                    Err(_) => sub.last,
                };
                if self.killed() {
                    return Err(Flow::Exit(137));
                }
                self.status(n)
            }
            Cmd::Group(body, redirs) => {
                let io = self.redirect(redirs, io)?;
                self.run(body, &io)
            }
            Cmd::If(arms, els, redirs) => {
                let io = self.redirect(redirs, io)?;
                for (c, b) in arms {
                    self.cond += 1;
                    let r = self.run(c, &io);
                    self.cond -= 1;
                    if r? == 0 {
                        return self.run(b, &io);
                    }
                }
                match els {
                    Some(e) => self.run(e, &io),
                    None => {
                        self.last = 0;
                        Ok(0)
                    }
                }
            }
            Cmd::For(name, items, body, redirs) => {
                let io = self.redirect(redirs, io)?;
                let list: Vec<String> = match items {
                    Some(ws) => {
                        let mut v = vec![];
                        for w in ws {
                            v.extend(self.expand(w, &io)?);
                        }
                        v
                    }
                    None => self.params.clone(),
                };
                let mut n = 0;
                for item in list {
                    if self.killed() {
                        return Err(Flow::Exit(137));
                    }
                    self.set(name, item);
                    match self.run(body, &io) {
                        Ok(x) => n = x,
                        Err(Flow::Break(k)) => {
                            if k > 1 {
                                return Err(Flow::Break(k - 1));
                            }
                            break;
                        }
                        Err(Flow::Continue(k)) => {
                            if k > 1 {
                                return Err(Flow::Continue(k - 1));
                            }
                        }
                        Err(f) => return Err(f),
                    }
                }
                self.last = n;
                Ok(n)
            }
            Cmd::While(until, cond, body, redirs) => {
                let io = self.redirect(redirs, io)?;
                let mut n = 0;
                loop {
                    if self.killed() {
                        return Err(Flow::Exit(137));
                    }
                    self.cond += 1;
                    let r = self.run(cond, &io);
                    self.cond -= 1;
                    if (r? == 0) == *until {
                        break;
                    }
                    match self.run(body, &io) {
                        Ok(x) => n = x,
                        Err(Flow::Break(k)) => {
                            if k > 1 {
                                return Err(Flow::Break(k - 1));
                            }
                            break;
                        }
                        Err(Flow::Continue(k)) => {
                            if k > 1 {
                                return Err(Flow::Continue(k - 1));
                            }
                        }
                        Err(f) => return Err(f),
                    }
                }
                self.last = n;
                Ok(n)
            }
            Cmd::Case(w, arms, redirs) => {
                let io = self.redirect(redirs, io)?;
                let subject = self.expand_one(w, &io)?;
                for (pats, body) in arms {
                    for p in pats {
                        let pat = self.pattern(p, &io)?;
                        if fnmatch(&pat, &subject) {
                            return self.run(body, &io);
                        }
                    }
                }
                self.last = 0;
                Ok(0)
            }
            Cmd::Func(name, body) => {
                self.funcs.insert(name.clone(), body.clone());
                self.last = 0;
                Ok(0)
            }
            Cmd::Cond(args) => {
                let mut v = vec![];
                for (i, w) in args.iter().enumerate() {
                    // The right side of `==` / `!=` is a pattern in `[[ ]]`.
                    let is_rhs = i > 0 && args.get(i - 1).and_then(|p| word_text(p)).is_some_and(|o| o == "==" || o == "=" || o == "!=");
                    if is_rhs {
                        v.push(format!("\u{1}{}", self.pattern(w, io)?));
                    } else {
                        v.push(self.expand_one(w, io)?);
                    }
                }
                let n = match self.test(&v, true) {
                    Ok(b) => (!b) as i32,
                    Err(e) => {
                        io.stderr.put(format!("sh: [[: {e}\n").as_bytes());
                        2
                    }
                };
                self.status(n)
            }
        }
    }

    // ── expansion ──

    fn expand_one(&mut self, w: &Word, io: &Io) -> Result<String, Flow> {
        let f = self.fields(w, io, false)?;
        Ok(f.into_iter().map(|f| f.text).collect::<Vec<_>>().join(" "))
    }

    /// A word as a pattern (`case`, `[[ == ]]`, `${x%pat}`): quoted parts match literally.
    fn pattern(&mut self, w: &Word, io: &Io) -> Result<String, Flow> {
        let f = self.fields(w, io, false)?;
        Ok(f.into_iter().map(|f| f.pat).collect::<Vec<_>>().join(" "))
    }

    /// Full expansion: parameters, substitutions, field splitting, globs.
    fn expand(&mut self, w: &Word, io: &Io) -> Result<Vec<String>, Flow> {
        let fields = self.fields(w, io, true)?;
        let mut out = vec![];
        for f in fields {
            if f.glob && has_glob(&f.pat) {
                let hits = self.glob(&f.pat);
                if hits.is_empty() {
                    out.push(unescape(&f.pat));
                } else {
                    out.extend(hits);
                }
            } else {
                out.push(f.text);
            }
        }
        Ok(out)
    }

    fn fields(&mut self, w: &Word, io: &Io, split: bool) -> Result<Vec<Field>, Flow> {
        let mut out: Vec<Field> = vec![];
        let mut cur = Field::default();
        let mut any = false;
        let push_text = |cur: &mut Field, s: &str, glob: bool| {
            cur.text.push_str(s);
            cur.pat.push_str(&if glob { s.to_string() } else { escape_glob(s) });
            cur.glob |= glob;
        };
        for p in w {
            match p {
                Part::Lit(s) => {
                    any = true;
                    push_text(&mut cur, s, true);
                }
                Part::Q(s) => {
                    any = true;
                    cur.quoted = true;
                    push_text(&mut cur, s, false);
                }
                Part::Tilde(user) => {
                    any = true;
                    let home = if user.is_empty() { self.get("HOME").unwrap_or_else(|| "/tmp".into()) } else { format!("~{user}") };
                    push_text(&mut cur, &home, false);
                }
                Part::Var { name, quoted, .. } if (name == "@" || name == "*") && *quoted && name == "@" => {
                    // "$@": one field per parameter.
                    let ps = self.params.clone();
                    for (i, v) in ps.iter().enumerate() {
                        if i > 0 {
                            out.push(std::mem::take(&mut cur));
                        }
                        push_text(&mut cur, v, false);
                        cur.quoted = true;
                    }
                    any = true;
                }
                Part::Var { name, op, quoted, len } => {
                    let v = self.param_value(name, op, *len, io)?;
                    any = true;
                    self.add_value(&mut out, &mut cur, &v, *quoted, split);
                }
                Part::Sub(src, quoted) => {
                    let v = self.substitute(src, io)?;
                    any = true;
                    self.add_value(&mut out, &mut cur, &v, *quoted, split);
                }
                Part::Arith(src, quoted) => {
                    let v = match self.arith_str(src, io) {
                        Ok(n) => n.to_string(),
                        Err(e) => {
                            io.stderr.put(format!("sh: $(({src})): {e}\n").as_bytes());
                            return Err(Flow::Exit(1));
                        }
                    };
                    any = true;
                    self.add_value(&mut out, &mut cur, &v, *quoted, split);
                }
            }
        }
        if any && (!cur.text.is_empty() || cur.quoted || !split || out.is_empty() && w.iter().any(|p| matches!(p, Part::Q(_)))) {
            out.push(cur);
        }
        if !split && out.is_empty() {
            out.push(Field::default());
        }
        Ok(out)
    }

    fn add_value(&self, out: &mut Vec<Field>, cur: &mut Field, v: &str, quoted: bool, split: bool) {
        if quoted || !split {
            cur.text.push_str(v);
            cur.pat.push_str(&escape_glob(v));
            if quoted {
                cur.quoted = true;
            }
            return;
        }
        let ifs = self.vars.get("IFS").cloned().unwrap_or_else(|| " \t\n".into());
        let mut first = true;
        let starts_ws = v.starts_with(|c: char| ifs.contains(c));
        for piece in v.split(|c: char| ifs.contains(c)) {
            if piece.is_empty() {
                continue;
            }
            if (!first || starts_ws) && (!cur.text.is_empty() || cur.quoted) {
                out.push(std::mem::take(cur));
            }
            cur.text.push_str(piece);
            cur.pat.push_str(&escape_glob(piece));
            first = false;
        }
        if v.ends_with(|c: char| ifs.contains(c)) && (!cur.text.is_empty() || cur.quoted) {
            out.push(std::mem::take(cur));
        }
    }

    fn param_value(&mut self, name: &str, op: &Option<(String, Word)>, len: bool, io: &Io) -> Result<String, Flow> {
        let val = self.get(name);
        if len {
            return Ok(val.map(|v| v.chars().count()).unwrap_or(0).to_string());
        }
        let Some((op, w)) = op else {
            if val.is_none() && self.nounset && is_name(name) {
                io.stderr.put(format!("sh: {name}: unbound variable\n").as_bytes());
                return Err(Flow::Exit(1));
            }
            return Ok(val.unwrap_or_default());
        };
        let empty = val.as_deref().is_none_or(str::is_empty);
        let unset = val.is_none();
        Ok(match op.as_str() {
            ":-" => if empty { self.expand_one(w, io)? } else { val.unwrap_or_default() },
            "-" => if unset { self.expand_one(w, io)? } else { val.unwrap_or_default() },
            ":=" | "=" => {
                if (op == ":=" && empty) || (op == "=" && unset) {
                    let v = self.expand_one(w, io)?;
                    self.set(name, v.clone());
                    v
                } else {
                    val.unwrap_or_default()
                }
            }
            ":+" => if empty { String::new() } else { self.expand_one(w, io)? },
            "+" => if unset { String::new() } else { self.expand_one(w, io)? },
            ":?" | "?" => {
                if (op == ":?" && empty) || (op == "?" && unset) {
                    let m = self.expand_one(w, io)?;
                    io.stderr.put(format!("sh: {name}: {}\n", if m.is_empty() { "parameter not set" } else { &m }).as_bytes());
                    return Err(Flow::Exit(1));
                }
                val.unwrap_or_default()
            }
            "%" | "%%" | "#" | "##" => {
                let v = val.unwrap_or_default();
                let pat = self.pattern(w, io)?;
                let chars: Vec<char> = v.chars().collect();
                let n = chars.len();
                let s = |a: usize, b: usize| chars[a..b].iter().collect::<String>();
                match op.as_str() {
                    "%" => (0..=n).rev().find(|k| fnmatch(&pat, &s(*k, n))).map(|k| s(0, k)).unwrap_or(v),
                    "%%" => (0..=n).find(|k| fnmatch(&pat, &s(*k, n))).map(|k| s(0, k)).unwrap_or(v),
                    "#" => (0..=n).find(|k| fnmatch(&pat, &s(0, *k))).map(|k| s(k, n)).unwrap_or(v),
                    _ => (0..=n).rev().find(|k| fnmatch(&pat, &s(0, *k))).map(|k| s(k, n)).unwrap_or(v),
                }
            }
            _ => val.unwrap_or_default(),
        })
    }

    /// `$(…)`: run in an interpreter copy, capture stdout, strip trailing newlines.
    fn substitute(&mut self, src: &str, io: &Io) -> Result<String, Flow> {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sub_io = Io { stdin: io.stdin.clone(), stdout: Out::Buf(buf.clone()), stderr: io.stderr.clone() };
        let mut sub = self.clone();
        let n = sub.run_script(src, &sub_io);
        self.last = n;
        if self.killed() {
            return Err(Flow::Exit(137));
        }
        let out = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
        Ok(out.trim_end_matches('\n').to_string())
    }

    fn glob(&self, pat: &str) -> Vec<String> {
        let abs = pat.starts_with('/');
        let mut bases: Vec<String> = vec![if abs { "/".into() } else { String::new() }];
        let comps: Vec<&str> = pat.split('/').filter(|c| !c.is_empty()).collect();
        for (i, comp) in comps.iter().enumerate() {
            let last = i == comps.len() - 1;
            let mut next = vec![];
            for b in &bases {
                if !has_glob(comp) {
                    let lit = unescape(comp);
                    next.push(if b.is_empty() { lit } else if b == "/" { format!("/{lit}") } else { format!("{b}/{lit}") });
                    continue;
                }
                let dir_guest = if b.is_empty() { self.cwd.clone() } else { join(&self.cwd, b) };
                let Ok((host, _)) = self.policy.host(&dir_guest, false, true) else { continue };
                let Ok(rd) = std::fs::read_dir(&host) else { continue };
                let mut names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| !n.starts_with('.') || comp.starts_with('.')).filter(|n| fnmatch(comp, n)).collect();
                names.sort();
                for n in names {
                    let p = if b.is_empty() { n } else if b == "/" { format!("/{n}") } else { format!("{b}/{n}") };
                    if !last {
                        let g = join(&self.cwd, &p);
                        if !self.policy.host(&g, false, true).map(|(h, _)| h.is_dir()).unwrap_or(false) {
                            continue;
                        }
                    }
                    next.push(p);
                }
            }
            bases = next;
        }
        bases.retain(|p| self.policy.host(&join(&self.cwd, p), false, false).map(|(h, _)| std::fs::symlink_metadata(h).is_ok()).unwrap_or(false));
        bases
    }

    // ── redirections ──

    fn open_out(&self, target: &str, append: bool) -> Result<Out, String> {
        match target {
            "/dev/null" => return Ok(Out::Null),
            "/dev/stdout" | "/dev/stderr" | "/dev/tty" => return Err(String::new()),
            _ => {}
        }
        let g = join(&self.cwd, target);
        let (host, _) = self.policy.host(&g, true, true).map_err(|e| format!("{target}: {}", errno_text(e)))?;
        let f = std::fs::OpenOptions::new().create(true).write(true).append(append).truncate(!append).open(&host).map_err(|e| format!("{target}: {e}"))?;
        Ok(Out::File(Arc::new(Mutex::new(f))))
    }

    fn redirect(&mut self, redirs: &[Redir], io: &Io) -> Result<Io, Flow> {
        let mut io = io.clone();
        for r in redirs {
            // A here-document has no target word (`<<<word` does).
            let target = if r.target.is_empty() { String::new() } else { self.expand_one(&r.target, &io)? };
            let res: Result<(), String> = (|| {
                match &r.op {
                    ROp::In => {
                        if target == "/dev/null" {
                            io.stdin = In::Null;
                        } else {
                            let g = join(&self.cwd, &target);
                            let (host, _) = self.policy.host(&g, false, true).map_err(|e| format!("{target}: {}", errno_text(e)))?;
                            io.stdin = In::bytes(std::fs::read(&host).map_err(|e| format!("{target}: {e}"))?);
                        }
                    }
                    ROp::Out | ROp::Append => {
                        let o = match self.open_out(&target, r.op == ROp::Append) {
                            Ok(o) => o,
                            Err(e) if e.is_empty() => if target == "/dev/stderr" { io.stderr.clone() } else { io.stdout.clone() },
                            Err(e) => return Err(e),
                        };
                        match r.fd {
                            2 => io.stderr = o,
                            _ => io.stdout = o,
                        }
                    }
                    ROp::Both | ROp::BothAppend => {
                        let o = self.open_out(&target, r.op == ROp::BothAppend).or_else(|e| if e.is_empty() { Ok(io.stdout.clone()) } else { Err(e) })?;
                        io.stdout = o.clone();
                        io.stderr = o;
                    }
                    ROp::Dup => match (r.fd, target.as_str()) {
                        (2, "1") => io.stderr = io.stdout.clone(),
                        (1, "2") => io.stdout = io.stderr.clone(),
                        (_, "-") => {
                            if r.fd == 2 {
                                io.stderr = Out::Null;
                            } else if r.fd == 1 {
                                io.stdout = Out::Null;
                            }
                        }
                        (0, _) | (1, "1") | (2, "2") => {}
                        (fd, t) if t.chars().all(|c| c.is_ascii_digit()) => return Err(format!("{fd}>&{t}: only 0, 1 and 2 exist here")),
                        // `>&file` is `&>file`.
                        (_, t) => {
                            let o = self.open_out(t, false)?;
                            io.stdout = o.clone();
                            io.stderr = o;
                        }
                    },
                    ROp::Here(body, expand) => {
                        let text = if r.target.is_empty() {
                            body.clone()
                        } else {
                            String::new()
                        };
                        let text = if !r.target.is_empty() {
                            // `<<<word`
                            format!("{target}\n")
                        } else if *expand {
                            self.expand_heredoc(&text, &io).map_err(|_| "here-document expansion failed".to_string())?
                        } else {
                            text
                        };
                        io.stdin = In::bytes(text.into_bytes());
                    }
                }
                Ok(())
            })();
            if let Err(e) = res {
                io.stderr.put(format!("sh: {e}\n").as_bytes());
                self.last = 1;
                return Err(Flow::Return(1));
            }
        }
        Ok(io)
    }

    fn expand_heredoc(&mut self, text: &str, io: &Io) -> Result<String, Flow> {
        // `$` and backquotes expand; quotes are literal.
        let mut lx = Lexer::new(text);
        let mut out = String::new();
        while lx.i < lx.s.len() {
            match lx.s[lx.i] {
                '\\' if matches!(lx.peek_c(1), Some('$' | '`' | '\\')) => {
                    out.push(lx.s[lx.i + 1]);
                    lx.i += 2;
                }
                '$' => match lx.dollar(true) {
                    Ok(p) => out.push_str(&self.expand_one(&vec![p], io)?),
                    Err(_) => {
                        out.push('$');
                    }
                },
                '`' => {
                    lx.i += 1;
                    let src = lx.backtick().unwrap_or_default();
                    out.push_str(&self.substitute(&src, io)?);
                }
                c => {
                    out.push(c);
                    lx.i += 1;
                }
            }
        }
        Ok(out)
    }

    // ── simple commands ──

    fn simple(&mut self, assigns: &[(String, Word)], words: &[Word], redirs: &[Redir], io: &Io) -> X {
        let mut argv = vec![];
        for w in words {
            argv.extend(self.expand(w, io)?);
        }
        let mut vals = vec![];
        for (k, w) in assigns {
            let v = self.expand_one(w, io)?;
            vals.push((k.clone(), v));
        }
        let io = match self.redirect(redirs, io) {
            Ok(io) => io,
            Err(Flow::Return(n)) => return self.status(n),
            Err(f) => return Err(f),
        };
        if argv.is_empty() {
            let had_sub = assigns.iter().any(|(_, w)| w.iter().any(|p| matches!(p, Part::Sub(..))));
            for (k, v) in vals {
                self.set(&k, v);
            }
            let n = if had_sub { self.last } else { 0 };
            return self.status(n);
        }
        // Prefix assignments: exported to that command only.
        let saved: Vec<(String, Option<String>, bool)> = vals.iter().map(|(k, _)| (k.clone(), self.vars.get(k).cloned(), self.exported.contains(k))).collect();
        for (k, v) in &vals {
            self.vars.insert(k.clone(), v.clone());
            self.exported.insert(k.clone());
        }
        let r = self.exec(&argv, &io);
        for (k, old, exp) in saved {
            match old {
                Some(v) => {
                    self.vars.insert(k.clone(), v);
                }
                None => {
                    self.vars.remove(&k);
                }
            }
            if !exp {
                self.exported.remove(&k);
            }
        }
        let n = r?;
        self.status(n)
    }

    fn exec(&mut self, argv: &[String], io: &Io) -> X {
        let name = argv[0].as_str();
        if let Some(body) = self.funcs.get(name).cloned() {
            let saved = std::mem::replace(&mut self.params, argv[1..].to_vec());
            let r = self.run(&body, io);
            self.params = saved;
            return match r {
                Ok(n) | Err(Flow::Return(n)) => Ok(n),
                Err(f) => Err(f),
            };
        }
        if BUILTINS.contains(&name) {
            if let Some(n) = self.builtin(argv, io)? {
                return Ok(n);
            }
        }
        self.external(argv, io)
    }

    fn external(&mut self, argv: &[String], io: &Io) -> X {
        let env = self.env();
        match self.tools.run(argv, &env, &self.cwd, io) {
            Some(n) => {
                if self.killed() {
                    return Err(Flow::Exit(137));
                }
                Ok(n)
            }
            None => {
                io.stderr.put(format!("sh: {}: command not found\n", argv[0]).as_bytes());
                Ok(127)
            }
        }
    }

    /// `None` = not handled here after all (`mv` / `rm` outside the shell's own files).
    fn builtin(&mut self, argv: &[String], io: &Io) -> Result<Option<i32>, Flow> {
        let args = &argv[1..];
        let say = |s: &str| io.stdout.put(s.as_bytes());
        let err = |s: &str| io.stderr.put(format!("sh: {}: {s}\n", argv[0]).as_bytes());
        Ok(Some(match argv[0].as_str() {
            ":" | "true" | "hash" | "trap" | "wait" | "ulimit" | "alias" | "unalias" => 0,
            "false" => 1,
            "builtin" => {
                if args.is_empty() {
                    return Ok(Some(0));
                }
                return self.builtin(args, io).map(|r| r.or(Some(1)));
            }
            "command" => match args.first().map(String::as_str) {
                Some("-v") | Some("-V") => {
                    let mut n = 0;
                    for a in &args[1..] {
                        match self.locate(a) {
                            Some(p) => say(&format!("{p}\n")),
                            None => n = 1,
                        }
                    }
                    n
                }
                Some(_) => {
                    let rest = args.to_vec();
                    if BUILTINS.contains(&rest[0].as_str()) {
                        return self.builtin(&rest, io);
                    }
                    return self.external(&rest, io).map(Some);
                }
                None => 0,
            },
            "type" => {
                let mut n = 0;
                for a in args {
                    match self.locate(a) {
                        Some(p) if p == *a => say(&format!("{a} is a shell builtin\n")),
                        Some(p) => say(&format!("{a} is {p}\n")),
                        None => {
                            err(&format!("{a}: not found"));
                            n = 1;
                        }
                    }
                }
                n
            }
            "echo" => {
                let (mut nl, mut esc, mut i) = (true, false, 0);
                while let Some(a) = args.get(i) {
                    if a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| "neE".contains(c)) {
                        for c in a[1..].chars() {
                            match c {
                                'n' => nl = false,
                                'e' => esc = true,
                                _ => esc = false,
                            }
                        }
                        i += 1;
                    } else {
                        break;
                    }
                }
                let mut s = args[i.min(args.len())..].join(" ");
                if esc {
                    let (t, stop) = escapes(&s);
                    s = t;
                    if stop {
                        nl = false;
                    }
                }
                if nl {
                    s.push('\n');
                }
                say(&s);
                0
            }
            "printf" => match args.first() {
                None => {
                    err("usage: printf format [arguments]");
                    2
                }
                Some(f) => {
                    let (s, bad) = printf(f, &args[1..]);
                    say(&s);
                    bad as i32
                }
            },
            "pwd" => {
                say(&format!("{}\n", self.cwd));
                0
            }
            "cd" => {
                let mut a: Vec<&String> = args.iter().filter(|a| !matches!(a.as_str(), "-L" | "-P")).collect();
                if a.first().is_some_and(|x| *x == "--") {
                    a.remove(0);
                }
                let target = match a.first() {
                    None => self.get("HOME").unwrap_or_else(|| "/tmp".into()),
                    Some(t) if *t == "-" => self.get("OLDPWD").unwrap_or_else(|| self.cwd.clone()),
                    Some(t) => (*t).clone(),
                };
                let g = join(&self.cwd, &target);
                match self.policy.host(&g, false, true) {
                    Ok((h, _)) if h.is_dir() => {
                        let old = std::mem::replace(&mut self.cwd, g.clone());
                        self.vars.insert("OLDPWD".into(), old);
                        self.vars.insert("PWD".into(), g);
                        0
                    }
                    Ok(_) => {
                        err(&format!("{target}: No such file or directory"));
                        1
                    }
                    Err(e) => {
                        err(&format!("{target}: {}", errno_text(e)));
                        1
                    }
                }
            }
            "export" | "readonly" | "local" => {
                let print = args.is_empty() || args.iter().any(|a| a == "-p");
                if print && argv[0] == "export" {
                    let mut s = String::new();
                    for k in &self.exported {
                        if let Some(v) = self.vars.get(k) {
                            s.push_str(&format!("declare -x {k}=\"{}\"\n", v.replace('\\', "\\\\").replace('"', "\\\"").replace('$', "\\$").replace('`', "\\`")));
                        }
                    }
                    say(&s);
                    return Ok(Some(0));
                }
                for a in args.iter().filter(|a| !a.starts_with('-')) {
                    let (k, v) = match a.split_once('=') {
                        Some((k, v)) => (k.to_string(), Some(v.to_string())),
                        None => (a.clone(), None),
                    };
                    if !is_name(&k) {
                        err(&format!("`{a}': not a valid identifier"));
                        return Ok(Some(1));
                    }
                    if let Some(v) = v {
                        self.set(&k, v);
                    }
                    if argv[0] == "export" {
                        self.exported.insert(k);
                    }
                }
                0
            }
            "unset" => {
                for a in args.iter().filter(|a| !a.starts_with('-')) {
                    self.vars.remove(a);
                    self.exported.remove(a);
                    self.funcs.remove(a);
                }
                0
            }
            "exit" => {
                let n = args.first().and_then(|a| a.parse::<i32>().ok()).unwrap_or(self.last);
                return Err(Flow::Exit(n & 0xff));
            }
            "return" => {
                let n = args.first().and_then(|a| a.parse::<i32>().ok()).unwrap_or(self.last);
                return Err(Flow::Return(n));
            }
            "break" | "continue" => {
                let k = args.first().and_then(|a| a.parse::<u32>().ok()).unwrap_or(1).max(1);
                return Err(if argv[0] == "break" { Flow::Break(k) } else { Flow::Continue(k) });
            }
            "shift" => {
                let k = args.first().and_then(|a| a.parse::<usize>().ok()).unwrap_or(1);
                if k > self.params.len() {
                    1
                } else {
                    self.params.drain(..k);
                    0
                }
            }
            "set" => {
                let mut i = 0;
                while let Some(a) = args.get(i) {
                    match a.as_str() {
                        "--" => {
                            self.params = args[i + 1..].to_vec();
                            break;
                        }
                        "-o" | "+o" => i += 1,
                        a if a.starts_with('-') || a.starts_with('+') => {
                            let on = a.starts_with('-');
                            for c in a[1..].chars() {
                                match c {
                                    'e' => self.errexit = on,
                                    'u' => self.nounset = on,
                                    _ => {}
                                }
                            }
                        }
                        _ => {
                            self.params = args[i..].to_vec();
                            break;
                        }
                    }
                    i += 1;
                }
                0
            }
            "umask" => {
                if args.is_empty() {
                    say("0022\n");
                }
                0
            }
            "eval" => {
                let src = args.join(" ");
                match Parser::parse(&src) {
                    Ok(c) => return self.run(&c, io).map(Some),
                    Err(e) => {
                        err(&e);
                        2
                    }
                }
            }
            "." | "source" => {
                let Some(f) = args.first() else {
                    err("filename argument required");
                    return Ok(Some(2));
                };
                let g = join(&self.cwd, f);
                match self.policy.host(&g, false, true).ok().and_then(|(h, _)| std::fs::read_to_string(h).ok()) {
                    Some(src) => match Parser::parse(&src) {
                        Ok(c) => {
                            let saved = std::mem::replace(&mut self.params, args[1..].to_vec());
                            let r = self.run(&c, io);
                            self.params = saved;
                            return match r {
                                Ok(n) | Err(Flow::Return(n)) => Ok(Some(n)),
                                Err(f) => Err(f),
                            };
                        }
                        Err(e) => {
                            err(&e);
                            2
                        }
                    },
                    None => {
                        err(&format!("{f}: No such file or directory"));
                        1
                    }
                }
            }
            "exec" => {
                if args.is_empty() {
                    return Ok(Some(0));
                }
                let n = self.exec(args, io)?;
                return Err(Flow::Exit(n));
            }
            "read" => self.read(args, io),
            "xargs" => self.xargs(args, io)?,
            "sleep" => {
                let secs: f64 = args.iter().map(|a| parse_duration(a)).sum();
                let until = std::time::Instant::now() + Duration::from_secs_f64(secs.clamp(0.0, 86_400.0));
                while std::time::Instant::now() < until {
                    if self.killed() {
                        return Err(Flow::Exit(137));
                    }
                    std::thread::sleep((until - std::time::Instant::now()).min(Duration::from_millis(20)));
                }
                0
            }
            "test" | "[" => {
                let mut v: Vec<String> = args.to_vec();
                if argv[0] == "[" {
                    if v.last().map(String::as_str) != Some("]") {
                        err("missing `]'");
                        return Ok(Some(2));
                    }
                    v.pop();
                }
                match self.test(&v, false) {
                    Ok(b) => (!b) as i32,
                    Err(e) => {
                        err(&e);
                        2
                    }
                }
            }
            // The shell's own snapshot files (the persistent-shell epilogue) live in a root WASI
            // tools cannot see; anything else goes to the `mv` / `rm` tool.
            "mv" | "rm" => {
                let ops: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
                let private = !ops.is_empty() && ops.iter().all(|a| self.policy.host(&join(&self.cwd, a), true, false).map(|(_, i)| !self.policy.roots[i].tools).unwrap_or(false));
                if !private {
                    return Ok(None);
                }
                let force = args.iter().any(|a| a.starts_with('-') && a.contains('f'));
                let hosts: Vec<std::path::PathBuf> = ops.iter().filter_map(|a| self.policy.host(&join(&self.cwd, a), true, false).ok().map(|(h, _)| h)).collect();
                let r = if argv[0] == "mv" {
                    if hosts.len() != 2 {
                        Err("usage: mv SOURCE DEST".to_string())
                    } else {
                        std::fs::rename(&hosts[0], &hosts[1]).map_err(|e| e.to_string())
                    }
                } else {
                    hosts.iter().try_for_each(|h| match std::fs::remove_file(h) {
                        Err(e) if !(force && e.kind() == std::io::ErrorKind::NotFound) => Err(e.to_string()),
                        _ => Ok(()),
                    })
                };
                match r {
                    Ok(()) => 0,
                    Err(e) => {
                        err(&e);
                        1
                    }
                }
            }
            _ => return Ok(None),
        }))
    }

    /// `command -v` / `type`: the builtin name, the function name, or the tool path.
    fn locate(&self, name: &str) -> Option<String> {
        if BUILTINS.contains(&name) && name != "mv" && name != "rm" || self.funcs.contains_key(name) {
            return Some(name.to_string());
        }
        self.tools.find(name, &self.cwd)
    }

    /// `xargs [-0] [-r] [-n N] [-I REPL] [-d DELIM] [cmd args…]`: a builtin, because the WASI
    /// findutils `xargs` would have to start processes. Runs each batch like any command here.
    fn xargs(&mut self, args: &[String], io: &Io) -> Result<i32, Flow> {
        let (mut nul, mut max, mut repl, mut delim, mut no_empty) = (false, usize::MAX, None::<String>, None::<char>, false);
        let mut i = 0;
        while let Some(a) = args.get(i) {
            match a.as_str() {
                "-0" | "--null" => nul = true,
                "-r" | "--no-run-if-empty" => no_empty = true,
                "-t" | "-p" => {}
                "-n" | "-L" => {
                    i += 1;
                    max = args.get(i).and_then(|n| n.parse().ok()).unwrap_or(1).max(1);
                }
                "-I" | "-i" => {
                    i += 1;
                    repl = Some(args.get(i).cloned().unwrap_or_else(|| "{}".into()));
                }
                "-d" => {
                    i += 1;
                    delim = args.get(i).and_then(|d| escapes(d).0.chars().next());
                }
                a if a.starts_with("-n") && a.len() > 2 => max = a[2..].parse().unwrap_or(1).max(1),
                a if a.starts_with("-I") && a.len() > 2 => repl = Some(a[2..].to_string()),
                "--" => {
                    i += 1;
                    break;
                }
                _ => break,
            }
            i += 1;
        }
        let mut cmd: Vec<String> = args[i.min(args.len())..].to_vec();
        if cmd.is_empty() {
            cmd.push("echo".into());
        }
        let mut input = Vec::new();
        let _ = io.stdin.reader().read_to_end(&mut input);
        let text = String::from_utf8_lossy(&input).into_owned();
        let items: Vec<String> = if nul {
            text.split('\0').filter(|s| !s.is_empty()).map(String::from).collect()
        } else if let Some(d) = delim {
            text.split(d).filter(|s| !s.is_empty()).map(String::from).collect()
        } else if repl.is_some() {
            text.lines().filter(|l| !l.trim().is_empty()).map(|l| l.trim().to_string()).collect()
        } else {
            split_xargs(&text)
        };
        let sub = Io { stdin: In::Null, stdout: io.stdout.clone(), stderr: io.stderr.clone() };
        let mut batches: Vec<Vec<String>> = vec![];
        if let Some(r) = &repl {
            for it in &items {
                batches.push(cmd.iter().map(|a| a.replace(r.as_str(), it)).collect());
            }
        } else if items.is_empty() {
            if !no_empty {
                batches.push(cmd.clone());
            }
        } else {
            for chunk in items.chunks(max.min(items.len())) {
                let mut b = cmd.clone();
                b.extend(chunk.iter().cloned());
                batches.push(b);
            }
        }
        let mut worst = 0;
        for b in batches {
            if self.killed() {
                return Err(Flow::Exit(137));
            }
            let n = match self.exec(&b, &sub) {
                Ok(n) => n,
                Err(Flow::Exit(137)) => return Err(Flow::Exit(137)),
                Err(Flow::Exit(n) | Flow::Return(n)) => n,
                Err(_) => 1,
            };
            if n == 127 || n == 126 {
                return Ok(n);
            }
            if n != 0 {
                worst = 123;
            }
        }
        Ok(worst)
    }

    fn read(&mut self, args: &[String], io: &Io) -> i32 {
        let mut raw = false;
        let mut names = vec![];
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-r" => raw = true,
                "-p" => {
                    i += 1;
                    if let Some(p) = args.get(i) {
                        io.stderr.put(p.as_bytes());
                    }
                }
                a => names.push(a.to_string()),
            }
            i += 1;
        }
        if names.is_empty() {
            names.push("REPLY".into());
        }
        let mut r = io.stdin.reader();
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        let mut got_any = false;
        loop {
            match r.read(&mut b) {
                Ok(1) => {
                    got_any = true;
                    if b[0] == b'\n' {
                        if !raw && line.last() == Some(&b'\\') {
                            line.pop();
                            continue;
                        }
                        break;
                    }
                    line.push(b[0]);
                }
                _ => {
                    if !got_any {
                        for n in &names {
                            self.set(n, String::new());
                        }
                        return 1;
                    }
                    break;
                }
            }
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        let text = if raw { text } else { unescape(&text) };
        let mut parts: Vec<&str> = text.split_whitespace().collect();
        for (k, n) in names.iter().enumerate() {
            if k == names.len() - 1 {
                let rest = parts.join(" ");
                self.set(n, rest);
                break;
            }
            let v = if parts.is_empty() { String::new() } else { parts.remove(0).to_string() };
            self.set(n, v);
        }
        0
    }

    // ── test ──

    fn test(&self, args: &[String], dbl: bool) -> Result<bool, String> {
        let mut i = 0;
        let r = self.t_or(args, &mut i, dbl)?;
        if i != args.len() {
            return Err(format!("unexpected `{}`", args[i]));
        }
        Ok(r)
    }
    fn t_or(&self, a: &[String], i: &mut usize, dbl: bool) -> Result<bool, String> {
        let mut v = self.t_and(a, i, dbl)?;
        while a.get(*i).map(String::as_str) == Some("-o") {
            *i += 1;
            let r = self.t_and(a, i, dbl)?;
            v = v || r;
        }
        Ok(v)
    }
    fn t_and(&self, a: &[String], i: &mut usize, dbl: bool) -> Result<bool, String> {
        let mut v = self.t_not(a, i, dbl)?;
        while a.get(*i).map(String::as_str) == Some("-a") {
            *i += 1;
            let r = self.t_not(a, i, dbl)?;
            v = v && r;
        }
        Ok(v)
    }
    fn t_not(&self, a: &[String], i: &mut usize, dbl: bool) -> Result<bool, String> {
        if a.get(*i).map(String::as_str) == Some("!") && a.len() > *i + 1 {
            *i += 1;
            return Ok(!self.t_not(a, i, dbl)?);
        }
        self.t_prim(a, i, dbl)
    }
    fn t_prim(&self, a: &[String], i: &mut usize, dbl: bool) -> Result<bool, String> {
        let Some(x) = a.get(*i) else { return Ok(false) };
        if x == "(" {
            *i += 1;
            let v = self.t_or(a, i, dbl)?;
            if a.get(*i).map(String::as_str) != Some(")") {
                return Err("missing `)'".into());
            }
            *i += 1;
            return Ok(v);
        }
        // Binary?
        if let (Some(op), Some(rhs)) = (a.get(*i + 1), a.get(*i + 2)) {
            let rhs_pat = rhs.strip_prefix('\u{1}');
            let rhs_s = rhs_pat.map(unescape).unwrap_or_else(|| rhs.clone());
            let r = match op.as_str() {
                "=" | "==" => Some(match rhs_pat {
                    Some(p) if dbl => fnmatch(p, x),
                    _ => *x == rhs_s,
                }),
                "!=" => Some(match rhs_pat {
                    Some(p) if dbl => !fnmatch(p, x),
                    _ => *x != rhs_s,
                }),
                "<" => Some(*x < rhs_s),
                ">" => Some(*x > rhs_s),
                "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge" => {
                    let p = |s: &str| s.trim().parse::<i64>().map_err(|_| format!("{s}: integer expression expected"));
                    let (l, r) = (p(x)?, p(&rhs_s)?);
                    Some(match op.as_str() {
                        "-eq" => l == r,
                        "-ne" => l != r,
                        "-lt" => l < r,
                        "-le" => l <= r,
                        "-gt" => l > r,
                        _ => l >= r,
                    })
                }
                "-nt" | "-ot" => {
                    let m = |s: &str| self.policy.host(&join(&self.cwd, s), false, true).ok().and_then(|(h, _)| std::fs::metadata(h).ok()).and_then(|m| m.modified().ok());
                    let (l, r) = (m(x), m(&rhs_s));
                    Some(if op == "-nt" { l > r } else { l < r && l.is_some() })
                }
                "-ef" => Some(self.policy.host(&join(&self.cwd, x), false, true).ok() == self.policy.host(&join(&self.cwd, &rhs_s), false, true).ok()),
                _ => None,
            };
            if let Some(v) = r {
                *i += 3;
                return Ok(v);
            }
        }
        if x.len() == 2 && x.starts_with('-') && a.get(*i + 1).is_some() && x != "-a" && x != "-o" {
            let arg = a[*i + 1].clone();
            *i += 2;
            let f = |follow: bool| self.policy.host(&join(&self.cwd, &arg), false, follow).ok();
            let md = || f(true).and_then(|(h, _)| std::fs::metadata(h).ok());
            return Ok(match x.as_str() {
                "-z" => arg.is_empty(),
                "-n" => !arg.is_empty(),
                "-e" | "-a" => md().is_some(),
                "-f" => md().is_some_and(|m| m.is_file()),
                "-d" => md().is_some_and(|m| m.is_dir()),
                "-s" => md().is_some_and(|m| m.len() > 0),
                "-r" => md().is_some(),
                "-w" => f(true).is_some_and(|(h, i)| self.policy.roots[i].write && std::fs::metadata(h).is_ok()),
                "-x" => md().is_some_and(|m| m.is_dir() || arg.ends_with(".wasm")),
                "-L" | "-h" => f(false).and_then(|(h, _)| std::fs::symlink_metadata(h).ok()).is_some_and(|m| m.file_type().is_symlink()),
                "-p" | "-S" | "-b" | "-c" | "-t" => false,
                other => return Err(format!("{other}: unary operator expected")),
            });
        }
        *i += 1;
        Ok(!x.is_empty())
    }

    // ── arithmetic ──

    fn arith_str(&mut self, src: &str, io: &Io) -> Result<i64, String> {
        // Parameters inside `$(( ))` expand first (`$x`, `${x}`, `$(cmd)`).
        let mut lx = Lexer::new(src);
        let mut text = String::new();
        while lx.i < lx.s.len() {
            if lx.s[lx.i] == '$' {
                let p = lx.dollar(false)?;
                text.push_str(&self.expand_one(&vec![p], io).map_err(|_| "expansion failed".to_string())?);
            } else {
                text.push(lx.s[lx.i]);
                lx.i += 1;
            }
        }
        let toks = arith_tokens(&text)?;
        let mut p = 0;
        let v = self.a_expr(&toks, &mut p, 0)?;
        if p != toks.len() {
            return Err(format!("syntax error near `{}`", toks[p]));
        }
        Ok(v)
    }

    fn a_var(&self, name: &str) -> i64 {
        self.get(name).and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(0)
    }

    fn a_expr(&mut self, t: &[String], p: &mut usize, min: u8) -> Result<i64, String> {
        // Assignment.
        if t.len() > *p + 1 && is_name(&t[*p]) && matches!(t[*p + 1].as_str(), "=" | "+=" | "-=" | "*=" | "/=") {
            let name = t[*p].clone();
            let op = t[*p + 1].clone();
            *p += 2;
            let r = self.a_expr(t, p, 0)?;
            let cur = self.a_var(&name);
            let v = match op.as_str() {
                "=" => r,
                "+=" => cur.wrapping_add(r),
                "-=" => cur.wrapping_sub(r),
                "*=" => cur.wrapping_mul(r),
                _ => {
                    if r == 0 {
                        return Err("division by 0".into());
                    }
                    cur / r
                }
            };
            self.set(&name, v.to_string());
            return Ok(v);
        }
        let mut lhs = self.a_unary(t, p)?;
        while let Some(op) = t.get(*p).cloned() {
            let prec = match op.as_str() {
                "?" => 1,
                "||" => 2,
                "&&" => 3,
                "|" => 4,
                "^" => 5,
                "&" => 6,
                "==" | "!=" => 7,
                "<" | "<=" | ">" | ">=" => 8,
                "<<" | ">>" => 9,
                "+" | "-" => 10,
                "*" | "/" | "%" => 11,
                "**" => 12,
                _ => break,
            };
            if prec < min.max(1) {
                break;
            }
            *p += 1;
            if op == "?" {
                let a = self.a_expr(t, p, 0)?;
                if t.get(*p).map(String::as_str) != Some(":") {
                    return Err("expected `:`".into());
                }
                *p += 1;
                let b = self.a_expr(t, p, 1)?;
                lhs = if lhs != 0 { a } else { b };
                continue;
            }
            let rhs = self.a_expr(t, p, if op == "**" { prec } else { prec + 1 })?;
            lhs = match op.as_str() {
                "||" => (lhs != 0 || rhs != 0) as i64,
                "&&" => (lhs != 0 && rhs != 0) as i64,
                "|" => lhs | rhs,
                "^" => lhs ^ rhs,
                "&" => lhs & rhs,
                "==" => (lhs == rhs) as i64,
                "!=" => (lhs != rhs) as i64,
                "<" => (lhs < rhs) as i64,
                "<=" => (lhs <= rhs) as i64,
                ">" => (lhs > rhs) as i64,
                ">=" => (lhs >= rhs) as i64,
                "<<" => lhs.wrapping_shl(rhs as u32),
                ">>" => lhs.wrapping_shr(rhs as u32),
                "+" => lhs.wrapping_add(rhs),
                "-" => lhs.wrapping_sub(rhs),
                "*" => lhs.wrapping_mul(rhs),
                "/" | "%" => {
                    if rhs == 0 {
                        return Err("division by 0".into());
                    }
                    if op == "/" {
                        lhs.wrapping_div(rhs)
                    } else {
                        lhs.wrapping_rem(rhs)
                    }
                }
                _ => lhs.wrapping_pow(rhs.clamp(0, 63) as u32),
            };
        }
        Ok(lhs)
    }

    fn a_unary(&mut self, t: &[String], p: &mut usize) -> Result<i64, String> {
        let tok = t.get(*p).cloned().ok_or("unexpected end of expression")?;
        *p += 1;
        match tok.as_str() {
            "-" => Ok(self.a_unary(t, p)?.wrapping_neg()),
            "+" => self.a_unary(t, p),
            "!" => Ok((self.a_unary(t, p)? == 0) as i64),
            "~" => Ok(!self.a_unary(t, p)?),
            "(" => {
                let v = self.a_expr(t, p, 0)?;
                if t.get(*p).map(String::as_str) != Some(")") {
                    return Err("missing `)`".into());
                }
                *p += 1;
                Ok(v)
            }
            "++" | "--" => {
                let name = t.get(*p).cloned().filter(|n| is_name(n)).ok_or("++/-- needs a variable")?;
                *p += 1;
                let v = self.a_var(&name) + if tok == "++" { 1 } else { -1 };
                self.set(&name, v.to_string());
                Ok(v)
            }
            n if n.starts_with(|c: char| c.is_ascii_digit()) => parse_int(n).ok_or_else(|| format!("{n}: bad number")),
            n if is_name(n) => {
                let v = self.a_var(n);
                if let Some(op @ ("++" | "--")) = t.get(*p).map(String::as_str) {
                    let nv = v + if op == "++" { 1 } else { -1 };
                    *p += 1;
                    self.set(n, nv.to_string());
                }
                Ok(v)
            }
            other => Err(format!("syntax error near `{other}`")),
        }
    }
}

fn parse_int(s: &str) -> Option<i64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        i64::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse().ok()
    }
}

fn arith_tokens(s: &str) -> Result<Vec<String>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = vec![];
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' {
            let st = i;
            while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                i += 1;
            }
            out.push(c[st..i].iter().collect());
            continue;
        }
        let two: String = c[i..(i + 2).min(c.len())].iter().collect();
        if ["**", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "++", "--", "+=", "-=", "*=", "/="].contains(&two.as_str()) {
            out.push(two);
            i += 2;
            continue;
        }
        if "+-*/%()<>!~&|^?:=".contains(ch) {
            out.push(ch.to_string());
            i += 1;
            continue;
        }
        return Err(format!("unexpected `{ch}`"));
    }
    Ok(out)
}

/// xargs' default input splitting: blanks and newlines separate, `'…'` `"…"` and `\` quote.
fn split_xargs(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut any = false;
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match c {
            ' ' | '\t' | '\n' => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            '\'' | '"' => {
                any = true;
                for q in it.by_ref() {
                    if q == c {
                        break;
                    }
                    cur.push(q);
                }
            }
            '\\' => {
                any = true;
                if let Some(n) = it.next() {
                    cur.push(n);
                }
            }
            c => {
                any = true;
                cur.push(c);
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

fn parse_duration(a: &str) -> f64 {
    let (n, mul) = match a.chars().last() {
        Some('s') => (&a[..a.len() - 1], 1.0),
        Some('m') => (&a[..a.len() - 1], 60.0),
        Some('h') => (&a[..a.len() - 1], 3600.0),
        _ => (a, 1.0),
    };
    n.parse::<f64>().unwrap_or(0.0) * mul
}

pub fn errno_text(e: u16) -> &'static str {
    use super::wasi::errno::*;
    match e {
        NOTCAPABLE => "outside the sandbox (only the workspace, /tmp and configured paths are visible)",
        ROFS => "read-only in this sandbox",
        NOENT => "No such file or directory",
        ACCES | PERM => "Permission denied",
        _ => "not accessible",
    }
}

/// `echo -e` / `printf %b` escapes; the flag says `\c` stopped the output.
fn escapes(s: &str) -> (String, bool) {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] != '\\' || i + 1 >= c.len() {
            out.push(c[i]);
            i += 1;
            continue;
        }
        i += 1;
        match c[i] {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0c'),
            'v' => out.push('\x0b'),
            'e' | 'E' => out.push('\x1b'),
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            '\'' => out.push('\''),
            'c' => return (out, true),
            '0'..='7' => {
                let st = i;
                let max = if c[i] == '0' { 4 } else { 3 };
                while i < c.len() && i - st < max && ('0'..='7').contains(&c[i]) {
                    i += 1;
                }
                let v = u32::from_str_radix(&c[st..i].iter().collect::<String>(), 8).unwrap_or(0);
                out.push(char::from_u32(v).unwrap_or('?'));
                continue;
            }
            'x' => {
                let st = i + 1;
                let mut e = st;
                while e < c.len() && e - st < 2 && c[e].is_ascii_hexdigit() {
                    e += 1;
                }
                let v = u32::from_str_radix(&c[st..e].iter().collect::<String>(), 16).unwrap_or(0);
                out.push(char::from_u32(v).unwrap_or('?'));
                i = e;
                continue;
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
        i += 1;
    }
    (out, false)
}

/// `printf FORMAT ARGS…`: the format is reused until every argument is consumed. The flag
/// reports an argument that was not a number where one was needed.
fn printf(fmt: &str, args: &[String]) -> (String, bool) {
    let f: Vec<char> = fmt.chars().collect();
    let mut out = String::new();
    let mut ai = 0;
    let mut bad = false;
    loop {
        let mut i = 0;
        let mut used = false;
        while i < f.len() {
            match f[i] {
                '\\' => {
                    let st = i;
                    i += 1;
                    if i < f.len() {
                        i += 1;
                    }
                    while i < f.len() && st + 1 < f.len() && matches!(f[st + 1], '0'..='7' | 'x') && i - st < 5 && f[i].is_ascii_hexdigit() {
                        i += 1;
                    }
                    let (e, _) = escapes(&f[st..i].iter().collect::<String>());
                    out.push_str(&e);
                }
                '%' if f.get(i + 1) == Some(&'%') => {
                    out.push('%');
                    i += 2;
                }
                '%' => {
                    let st = i;
                    i += 1;
                    while i < f.len() && "-+ #0".contains(f[i]) {
                        i += 1;
                    }
                    while i < f.len() && (f[i].is_ascii_digit() || f[i] == '.') {
                        i += 1;
                    }
                    let Some(&conv) = f.get(i) else {
                        out.extend(&f[st..]);
                        break;
                    };
                    i += 1;
                    let spec: String = f[st + 1..i - 1].iter().collect();
                    let arg = args.get(ai).cloned().unwrap_or_default();
                    if ai < args.len() {
                        ai += 1;
                    }
                    used = true;
                    let (left, zero) = (spec.contains('-'), spec.starts_with('0') || spec.contains("0") && !spec.contains('.') && spec.trim_start_matches(['-', '+', ' ', '#']).starts_with('0'));
                    let digits = spec.trim_start_matches(['-', '+', ' ', '#', '0']);
                    let (w, prec) = match digits.split_once('.') {
                        Some((w, p)) => (w.parse::<usize>().unwrap_or(0), Some(p.parse::<usize>().unwrap_or(0))),
                        None => (digits.parse::<usize>().unwrap_or(0), None),
                    };
                    let num = |s: &str, bad: &mut bool| -> i64 {
                        let s = s.trim();
                        if s.is_empty() {
                            return 0;
                        }
                        if let Some(ch) = s.strip_prefix('\'').or_else(|| s.strip_prefix('"')) {
                            return ch.chars().next().map(|c| c as i64).unwrap_or(0);
                        }
                        parse_int(s.trim_start_matches('+')).or_else(|| s.parse::<f64>().ok().map(|f| f as i64)).unwrap_or_else(|| {
                            *bad = true;
                            0
                        })
                    };
                    let body = match conv {
                        's' => match prec {
                            Some(p) => arg.chars().take(p).collect(),
                            None => arg,
                        },
                        'b' => escapes(&arg).0,
                        'c' => arg.chars().next().map(String::from).unwrap_or_default(),
                        'd' | 'i' => num(&arg, &mut bad).to_string(),
                        'u' => (num(&arg, &mut bad) as u64).to_string(),
                        'x' => format!("{:x}", num(&arg, &mut bad)),
                        'X' => format!("{:X}", num(&arg, &mut bad)),
                        'o' => format!("{:o}", num(&arg, &mut bad)),
                        'f' | 'F' | 'e' | 'E' | 'g' | 'G' => {
                            let v = arg.trim().parse::<f64>().unwrap_or_else(|_| {
                                if !arg.trim().is_empty() {
                                    bad = true;
                                }
                                0.0
                            });
                            let p = prec.unwrap_or(6);
                            match conv {
                                'e' | 'E' => format!("{v:.p$e}"),
                                'g' | 'G' => format!("{v}"),
                                _ => format!("{v:.p$}"),
                            }
                        }
                        other => format!("%{spec}{other}"),
                    };
                    let pad = w.saturating_sub(body.chars().count());
                    if left {
                        out.push_str(&body);
                        out.push_str(&" ".repeat(pad));
                    } else if zero && "diuxXofFeE".contains(conv) {
                        let (sign, digits) = if let Some(d) = body.strip_prefix('-') { ("-", d.to_string()) } else { ("", body.clone()) };
                        out.push_str(sign);
                        out.push_str(&"0".repeat(pad));
                        out.push_str(&digits);
                    } else {
                        out.push_str(&" ".repeat(pad));
                        out.push_str(&body);
                    }
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        if !used || ai >= args.len() {
            break;
        }
    }
    (out, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoTools;
    impl Tools for NoTools {
        fn find(&self, _n: &str, _c: &str) -> Option<String> {
            None
        }
        fn run(&self, _a: &[String], _e: &[(String, String)], _c: &str, _io: &Io) -> Option<i32> {
            None
        }
    }

    fn sh(src: &str) -> (i32, String) {
        let t = seagent_core::tmp::TempDir::new("seagent-wasm-sh");
        let mut p = Policy::default();
        p.add("/ws", t.path(), true, true).unwrap();
        let buf = Arc::new(Mutex::new(Vec::new()));
        let io = Io { stdin: In::Null, stdout: Out::Buf(buf.clone()), stderr: Out::Buf(buf.clone()) };
        let mut s = Shell::new(&p, &NoTools, &[("HOME".into(), "/ws".into())], "/ws", Arc::new(AtomicBool::new(false)), 7);
        let n = s.run_script(src, &io);
        let out = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
        (n, out)
    }

    #[test]
    fn the_language_core_works() {
        assert_eq!(sh("echo hello world"), (0, "hello world\n".into()));
        assert_eq!(sh("x=3; y=$((x * 4 + 1)); echo \"$y\" ${z:-dflt} ${#y}"), (0, "13 dflt 2\n".into()));
        assert_eq!(sh("false || echo a && echo b; true && false; echo $?"), (0, "a\nb\n1\n".into()));
        assert_eq!(sh("if [ 2 -gt 1 ]; then echo yes; elif true; then echo no; else echo never; fi"), (0, "yes\n".into()));
        assert_eq!(sh("for i in a b c; do printf '%s-' \"$i\"; done; echo"), (0, "a-b-c-\n".into()));
        assert_eq!(sh("n=0; while [ $n -lt 3 ]; do n=$((n+1)); done; echo $n"), (0, "3\n".into()));
        assert_eq!(sh("case foo.txt in *.rs) echo rust;; *.txt|*.md) echo text;; esac"), (0, "text\n".into()));
        assert_eq!(sh("f() { echo \"[$1:$#]\"; return 3; }; f one two; echo $?"), (0, "[one:2]\n3\n".into()));
        assert_eq!(sh("echo $(echo inner) `echo tick`"), (0, "inner tick\n".into()));
        assert_eq!(sh("v='a b'; for w in $v; do echo \"<$w>\"; done; for w in \"$v\"; do echo \"<$w>\"; done"), (0, "<a>\n<b>\n<a b>\n".into()));
        assert_eq!(sh("( exit 4 ); echo $?; { echo grouped; }"), (0, "4\ngrouped\n".into()));
        assert_eq!(sh("p=/a/b/c.tar.gz; echo ${p##*/} ${p%.*} ${p%%.*} ${p#/a}"), (0, "c.tar.gz /a/b/c.tar /a/b/c /b/c.tar.gz\n".into()));
        assert_eq!(sh("[[ abc == a* && 1 -lt 2 ]] && echo match"), (0, "match\n".into()));
        assert_eq!(sh("printf '%05d|%-4s|%x\\n' 42 ab 255"), (0, "00042|ab  |ff\n".into()));
        assert_eq!(sh("exit 5; echo no"), (5, String::new()));
        assert_eq!(sh("nosuchcmd").0, 127);
        assert_eq!(sh("set -e; false; echo not-reached").0, 1);
        assert_eq!(sh("eval 'a=1; echo $a'"), (0, "1\n".into()));
        assert_eq!(sh("echo -n x; echo -e 'y\\tz'"), (0, "xy\tz\n".into()));
    }

    #[test]
    fn redirections_heredocs_and_globs_stay_in_the_roots() {
        let (n, out) = sh("echo one > a.txt; echo two >> a.txt; read first < a.txt; echo \"$first\"; cat_ok=0\nwhile read l; do echo \"<$l>\"; done < a.txt\nprintf 'x' > b.log; echo *.txt *.log nomatch*");
        assert_eq!((n, out.as_str()), (0, "one\n<one>\n<two>\na.txt b.log nomatch*\n"));
        let (_, out) = sh("read raw <<'EOF'\nraw $HOME\nEOF\necho \"$raw\"; x=1\nread y <<EOF\nv=$x\nEOF\necho \"$y\"; read z <<< 'here'; echo $z");
        assert_eq!(out, "raw $HOME\nv=1\nhere\n");
        let (n, out) = sh("echo secret > /etc/x; echo $?; cd /etc; echo $?; pwd");
        assert_eq!(n, 0);
        assert!(out.contains("outside the sandbox"), "{out}");
        assert_eq!(out.lines().filter(|l| !l.starts_with("sh:")).collect::<Vec<_>>(), ["1", "1", "/ws"], "{out}");
        let (_, out) = sh("mkdirless=1; cd /ws && pwd -P; export FOO='a \"b\"'; export -p | while read -r l; do case \"$l\" in *FOO*) echo \"$l\";; esac; done");
        assert_eq!(out, "/ws\ndeclare -x FOO=\"a \\\"b\\\"\"\n");
    }
}
