//! Connections, one per dialect. Layer 1 of the read-only guarantee lives here: whatever the
//! statement says, the connection itself cannot write.
//!
//! | kind | layer 1 |
//! |---|---|
//! | `sqlite` | file opened `SQLITE_OPEN_READ_ONLY`, `PRAGMA query_only`, and the prepared statement must report `readonly()` |
//! | `postgres` | `psql` with `default_transaction_read_only=on` in `PGOPTIONS` and the statement inside `BEGIN READ ONLY … ROLLBACK` |
//! | `mysql` | `mysql` with `--init-command="SET SESSION TRANSACTION READ ONLY"` and `START TRANSACTION READ ONLY … ROLLBACK` |
//! | `clickhouse` | HTTP with `readonly=1` (the server refuses writes and setting changes) |
//! | `bigquery` | HTTP `jobs.query` (no read-only mode exists: grant the token `bigquery.dataViewer` + `jobUser` only) |
//!
//! PostgreSQL and MySQL go through the stock command-line clients (`psql`, `mysql`), found on
//! `PATH` or named by the source's `client = ["podman", "exec", "-i", "pg", "psql"]`. That keeps
//! ark free of database drivers; the client's output is parsed as a stream so a result of ten
//! million rows is cut at `max_rows` (the client is killed) instead of buffered.

use super::dsn::Dsn;
use super::guard::Dialect;
use ark_core::Cancel;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Largest rendered result handed back to the model; the rest is "truncated".
pub const MAX_OUT_BYTES: usize = 256 * 1024;
/// One cell is cut here.
pub const MAX_CELL_CHARS: usize = 2000;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// More rows existed than `max_rows` (or the output cap) allowed.
    pub truncated: bool,
}

pub struct Limits {
    pub max_rows: usize,
    pub timeout: Duration,
    pub cancel: Cancel,
}

pub fn clip_cell(s: &str) -> String {
    if s.chars().count() <= MAX_CELL_CHARS {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(MAX_CELL_CHARS).collect();
        t.push_str("…[cut]");
        t
    }
}

/// Collects rows while enforcing the row and byte caps.
struct Sink {
    rows: Rows,
    max_rows: usize,
    bytes: usize,
}

impl Sink {
    fn new(max_rows: usize) -> Sink {
        Sink { rows: Rows::default(), max_rows, bytes: 0 }
    }
    /// False once the caps are reached (the row was not stored).
    fn push(&mut self, row: Vec<Value>) -> bool {
        let size: usize = row.iter().map(|v| v.to_string().len() + 1).sum();
        if self.rows.rows.len() >= self.max_rows || self.bytes + size > MAX_OUT_BYTES {
            self.rows.truncated = true;
            return false;
        }
        self.bytes += size;
        self.rows.rows.push(row);
        true
    }
}

// ───────────────────────────── SQLite ─────────────────────────────

pub fn sqlite(path: &std::path::Path, sql: &str, lim: &Limits) -> Result<Rows, String> {
    use rusqlite::{types::ValueRef, Connection, OpenFlags};
    if !path.is_file() {
        return Err(format!("SQLite file {} does not exist", path.display()));
    }
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).map_err(|e| format!("cannot open the database read-only: {e}"))?;
    conn.execute_batch("PRAGMA query_only = ON;").map_err(|e| e.to_string())?;
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    // Third check, from SQLite itself: a statement that could write says so here.
    if !stmt.readonly() {
        return Err("SQLite reports this statement is not read-only".into());
    }
    let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    // Time limit: interrupt the connection from a watchdog thread.
    let handle = conn.get_interrupt_handle();
    let done = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    {
        let (done, timed_out, cancel, timeout) = (done.clone(), timed_out.clone(), lim.cancel.clone(), lim.timeout);
        std::thread::spawn(move || {
            let t0 = Instant::now();
            while !done.load(Ordering::SeqCst) {
                if cancel.is_cancelled() || t0.elapsed() >= timeout {
                    timed_out.store(!cancel.is_cancelled(), Ordering::SeqCst);
                    handle.interrupt();
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
    }
    let mut sink = Sink::new(lim.max_rows);
    sink.rows.columns = columns;
    let n = sink.rows.columns.len();
    let result = (|| -> Result<(), String> {
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                out.push(match r.get_ref(i).map_err(|e| e.to_string())? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(v) => json!(v),
                    ValueRef::Real(v) => json!(v),
                    ValueRef::Text(t) => Value::String(clip_cell(&String::from_utf8_lossy(t))),
                    ValueRef::Blob(b) => Value::String(format!("<blob {} bytes>", b.len())),
                });
            }
            if !sink.push(out) {
                break;
            }
        }
        Ok(())
    })();
    done.store(true, Ordering::SeqCst);
    match result {
        Err(_) if timed_out.load(Ordering::SeqCst) => Err(format!("query exceeded {} seconds and was cancelled", lim.timeout.as_secs())),
        Err(e) if lim.cancel.is_cancelled() => Err(format!("Interrupted ({e})")),
        Err(e) => Err(e),
        Ok(()) => Ok(sink.rows),
    }
}

// ───────────────────────────── command-line clients ─────────────────────────────

struct Kill(Option<Child>);
impl Drop for Kill {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Run `argv` with `env`, feed `script` on stdin, hand stdout to `parse`. The child is killed
/// when `parse` is done early, on timeout, on cancel and on any error path (drop guard).
fn run_client(argv: &[String], env: &[(String, String)], script: &str, lim: &Limits, secret: &str, parse: impl FnOnce(&mut dyn BufRead, usize) -> Result<Rows, String>) -> Result<Rows, String> {
    let (prog, args) = argv.split_first().ok_or("empty client command")?;
    let mut cmd = Command::new(prog);
    cmd.args(args).envs(env.iter().map(|(k, v)| (k, v))).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("cannot start `{prog}`: {e} (install the client or set `client = [...]` on the source)"))?;
    let pid = child.id() as i32;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut stderr = child.stderr.take().ok_or("no stderr")?;
    let mut guard = Kill(Some(child));
    let script = script.to_string();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(script.as_bytes());
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stderr).take(8192).read_to_end(&mut buf);
        let mut sink = [0u8; 4096];
        while stderr.read(&mut sink).map(|n| n > 0).unwrap_or(false) {}
        String::from_utf8_lossy(&buf).into_owned()
    });
    let done = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    {
        let (done, timed_out, cancel, timeout) = (done.clone(), timed_out.clone(), lim.cancel.clone(), lim.timeout);
        std::thread::spawn(move || {
            let t0 = Instant::now();
            while !done.load(Ordering::SeqCst) {
                if cancel.is_cancelled() || t0.elapsed() >= timeout {
                    timed_out.store(!cancel.is_cancelled(), Ordering::SeqCst);
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
    }
    let mut reader = BufReader::new(stdout);
    let parsed = parse(&mut reader, lim.max_rows);
    done.store(true, Ordering::SeqCst);
    let truncated = parsed.as_ref().is_ok_and(|r| r.truncated);
    // Stop the client (it may be mid-stream on a huge result) and collect what it said.
    if let Some(mut c) = guard.0.take() {
        if truncated {
            let _ = c.kill();
        }
        let status = c.wait();
        drop(reader);
        let _ = writer.join();
        let err = err_thread.join().unwrap_or_default();
        let err = redact(err.trim(), secret);
        if timed_out.load(Ordering::SeqCst) {
            return Err(format!("query exceeded {} seconds and was cancelled", lim.timeout.as_secs()));
        }
        if lim.cancel.is_cancelled() {
            return Err("Interrupted".into());
        }
        let failed = status.map(|s| !s.success()).unwrap_or(true);
        match parsed {
            Ok(r) if !failed || truncated => Ok(r),
            Ok(_) => Err(if err.is_empty() { "the client exited with an error".to_string() } else { err }),
            Err(e) => Err(if err.is_empty() { e } else { err }),
        }
    } else {
        Err("client was already gone".into())
    }
}

fn redact(s: &str, secret: &str) -> String {
    let s = if secret.len() >= 4 { s.replace(secret, "***") } else { s.to_string() };
    crate::util::truncate_str(&s, 1500).to_string()
}

/// RFC 4180 record: `(text, was_quoted)` per field. `None` at end of input.
fn csv_record(r: &mut dyn BufRead) -> std::io::Result<Option<Vec<(String, bool)>>> {
    let mut fields: Vec<(String, bool)> = vec![];
    let mut cur: Vec<u8> = vec![];
    let mut quoted = false;
    let mut in_q = false;
    let mut any = false;
    loop {
        let mut b = [0u8; 1];
        if r.read(&mut b)? == 0 {
            if !any {
                return Ok(None);
            }
            break;
        }
        any = true;
        let c = b[0];
        if in_q {
            if c == b'"' {
                let nxt = r.fill_buf()?.first().copied();
                if nxt == Some(b'"') {
                    r.consume(1);
                    cur.push(b'"');
                } else {
                    in_q = false;
                }
            } else {
                cur.push(c);
            }
        } else {
            match c {
                b'"' if cur.is_empty() => {
                    in_q = true;
                    quoted = true;
                }
                b',' => {
                    fields.push((String::from_utf8_lossy(&cur).into_owned(), quoted));
                    cur.clear();
                    quoted = false;
                }
                b'\n' => break,
                b'\r' => {}
                _ => cur.push(c),
            }
        }
    }
    fields.push((String::from_utf8_lossy(&cur).into_owned(), quoted));
    Ok(Some(fields))
}

pub fn parse_psql_csv(r: &mut dyn BufRead, max_rows: usize) -> Result<Rows, String> {
    let mut sink = Sink::new(max_rows);
    let Some(head) = csv_record(r).map_err(|e| e.to_string())? else { return Ok(Rows::default()) };
    sink.rows.columns = head.into_iter().map(|(h, _)| h).collect();
    while let Some(rec) = csv_record(r).map_err(|e| e.to_string())? {
        let row = rec.into_iter().map(|(v, q)| if v.is_empty() && !q { Value::Null } else { Value::String(clip_cell(&v)) }).collect();
        if !sink.push(row) {
            break;
        }
    }
    Ok(sink.rows)
}

fn mysql_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('0') => out.push('\0'),
                Some('\\') => out.push('\\'),
                Some(o) => {
                    out.push('\\');
                    out.push(o)
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn parse_mysql_batch(r: &mut dyn BufRead, max_rows: usize) -> Result<Rows, String> {
    let mut sink = Sink::new(max_rows);
    let mut line = String::new();
    let mut first = true;
    loop {
        line.clear();
        if r.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let l = line.trim_end_matches(['\n', '\r']);
        let cells: Vec<&str> = l.split('\t').collect();
        if first {
            sink.rows.columns = cells.iter().map(|c| mysql_unescape(c)).collect();
            first = false;
            continue;
        }
        let row = cells.iter().map(|c| if *c == "NULL" { Value::Null } else { Value::String(clip_cell(&mysql_unescape(c))) }).collect();
        if !sink.push(row) {
            break;
        }
    }
    Ok(sink.rows)
}

fn client_argv(client: &[String], default: &str) -> Vec<String> {
    if client.is_empty() {
        vec![default.to_string()]
    } else {
        client.to_vec()
    }
}

/// PostgreSQL through `psql`.
pub fn postgres(dsn: &Dsn, client: &[String], sql: &str, lim: &Limits) -> Result<Rows, String> {
    let mut argv = client_argv(client, "psql");
    argv.extend(["-X", "-q", "--csv", "-v", "ON_ERROR_STOP=1"].map(String::from));
    let mut env: Vec<(String, String)> = vec![("PGHOST".into(), dsn.host.clone()), ("PGCONNECT_TIMEOUT".into(), "10".into())];
    if let Some(p) = dsn.port {
        env.push(("PGPORT".into(), p.to_string()));
    }
    if !dsn.user.is_empty() {
        env.push(("PGUSER".into(), dsn.user.clone()));
    }
    if !dsn.password.is_empty() {
        env.push(("PGPASSWORD".into(), dsn.password.clone()));
    }
    if !dsn.database.is_empty() {
        env.push(("PGDATABASE".into(), dsn.database.clone()));
    }
    if let Some(m) = dsn.param("sslmode") {
        env.push(("PGSSLMODE".into(), m.to_string()));
    }
    env.push(("PGOPTIONS".into(), format!("-c default_transaction_read_only=on -c statement_timeout={}", lim.timeout.as_millis())));
    // `podman exec -e NAME` style clients inherit these by name.
    if client.first().is_some_and(|c| c.ends_with("podman") || c.ends_with("docker")) {
        let pos = argv.iter().position(|a| a == "exec").map(|p| p + 1).unwrap_or(1);
        let names: Vec<String> = env.iter().filter(|(k, _)| k.starts_with("PG")).flat_map(|(k, _)| ["-e".to_string(), k.clone()]).collect();
        for (i, n) in names.into_iter().enumerate() {
            argv.insert(pos + i, n);
        }
    }
    let script = format!("BEGIN READ ONLY;\n{sql};\nROLLBACK;\n");
    run_client(&argv, &env, &script, lim, &dsn.password, parse_psql_csv)
}

/// MySQL / MariaDB through `mysql`.
pub fn mysql(dsn: &Dsn, client: &[String], sql: &str, lim: &Limits) -> Result<Rows, String> {
    let mut argv = client_argv(client, "mysql");
    let port = dsn.port.unwrap_or(3306);
    argv.extend(["--batch", "--quick", "--connect-timeout=10", "--init-command=SET SESSION TRANSACTION READ ONLY"].map(String::from));
    argv.push(format!("--host={}", dsn.host));
    argv.push(format!("--port={port}"));
    if !dsn.user.is_empty() {
        argv.push(format!("--user={}", dsn.user));
    }
    if let Some(m) = dsn.param("ssl-mode").or(dsn.param("sslmode")) {
        argv.push(format!("--ssl-mode={m}"));
    }
    if !dsn.database.is_empty() {
        argv.push(format!("--database={}", dsn.database));
    }
    let mut env: Vec<(String, String)> = vec![];
    if !dsn.password.is_empty() {
        env.push(("MYSQL_PWD".into(), dsn.password.clone()));
    }
    let script = format!("SET SESSION max_execution_time={};\nSTART TRANSACTION READ ONLY;\n{sql};\nROLLBACK;\n", lim.timeout.as_millis());
    run_client(&argv, &env, &script, lim, &dsn.password, parse_mysql_batch)
}

// ───────────────────────────── HTTP: ClickHouse, BigQuery ─────────────────────────────

fn http_agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(timeout)).http_status_as_error(false).max_redirects(0).build().into()
}

fn read_capped(resp: &mut ureq::http::Response<ureq::Body>, cap: u64) -> Result<String, String> {
    let mut raw = Vec::new();
    resp.body_mut().with_config().limit(u64::MAX).reader().take(cap).read_to_end(&mut raw).map_err(|e| format!("reading the response failed: {e}"))?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

/// ClickHouse over its HTTP interface with `readonly=1`.
pub fn clickhouse(dsn: &Dsn, sql: &str, lim: &Limits) -> Result<Rows, String> {
    let https = dsn.scheme == "https" || dsn.scheme == "clickhouses";
    let base = format!("{}://{}", if https { "https" } else { "http" }, dsn.dest());
    let mut url = format!("{base}/?readonly=1&default_format=JSONCompact&max_result_rows={}&result_overflow_mode=break&max_execution_time={}&wait_end_of_query=0", lim.max_rows + 1, lim.timeout.as_secs().max(1));
    if !dsn.database.is_empty() {
        url.push_str(&format!("&database={}", crate::web::http::enc(&dsn.database)));
    }
    let mut req = http_agent(lim.timeout + Duration::from_secs(5)).post(&url).header("Content-Type", "text/plain; charset=utf-8");
    if !dsn.user.is_empty() {
        req = req.header("X-ClickHouse-User", &dsn.user);
    }
    if !dsn.password.is_empty() {
        req = req.header("X-ClickHouse-Key", &dsn.password);
    }
    let mut resp = req.send(sql.as_bytes()).map_err(|e| redact(&e.to_string(), &dsn.password))?;
    let status = resp.status().as_u16();
    let body = read_capped(&mut resp, 64 * 1024 * 1024)?;
    if status != 200 {
        return Err(format!("ClickHouse error (HTTP {status}): {}", redact(body.trim(), &dsn.password)));
    }
    let v: Value = serde_json::from_str(&body).map_err(|e| format!("ClickHouse answered something that is not JSON ({e}): {}", crate::util::truncate_str(body.trim(), 200)))?;
    let columns: Vec<String> = v["meta"].as_array().map(|m| m.iter().map(|c| c["name"].as_str().unwrap_or("").to_string()).collect()).unwrap_or_default();
    let mut sink = Sink::new(lim.max_rows);
    sink.rows.columns = columns;
    for row in v["data"].as_array().cloned().unwrap_or_default() {
        let cells = row.as_array().cloned().unwrap_or_default().into_iter().map(cell).collect();
        if !sink.push(cells) {
            break;
        }
    }
    Ok(sink.rows)
}

fn cell(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(clip_cell(&s)),
        Value::Array(_) | Value::Object(_) => Value::String(clip_cell(&v.to_string())),
        o => o,
    }
}

/// BigQuery `jobs.query` (standard SQL). The token is a bearer token from the source's secret.
pub fn bigquery(api_base: &str, project: &str, token: &str, sql: &str, lim: &Limits) -> Result<Rows, String> {
    let url = format!("{}/bigquery/v2/projects/{}/queries", api_base.trim_end_matches('/'), crate::web::http::enc(project));
    let body = json!({"query": sql, "useLegacySql": false, "maxResults": lim.max_rows + 1, "timeoutMs": lim.timeout.as_millis() as u64, "dryRun": false});
    let mut resp = http_agent(lim.timeout + Duration::from_secs(5))
        .post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(&body).unwrap_or_default().as_slice())
        .map_err(|e| redact(&e.to_string(), token))?;
    let status = resp.status().as_u16();
    let text = read_capped(&mut resp, 64 * 1024 * 1024)?;
    let v: Value = serde_json::from_str(&text).map_err(|_| format!("BigQuery answered something that is not JSON (HTTP {status})"))?;
    if status != 200 {
        return Err(format!("BigQuery error (HTTP {status}): {}", redact(v["error"]["message"].as_str().unwrap_or(text.trim()), token)));
    }
    if v["jobComplete"] == json!(false) {
        return Err("BigQuery did not finish within the time limit (jobComplete=false)".into());
    }
    let mut sink = Sink::new(lim.max_rows);
    sink.rows.columns = v["schema"]["fields"].as_array().map(|f| f.iter().map(|c| c["name"].as_str().unwrap_or("").to_string()).collect()).unwrap_or_default();
    for row in v["rows"].as_array().cloned().unwrap_or_default() {
        let cells = row["f"].as_array().cloned().unwrap_or_default().into_iter().map(|c| cell(c["v"].clone())).collect();
        if !sink.push(cells) {
            break;
        }
    }
    if v.get("pageToken").is_some() {
        sink.rows.truncated = true;
    }
    Ok(sink.rows)
}

pub fn dialect_of(kind: &str) -> Option<Dialect> {
    Some(match kind {
        "postgres" | "postgresql" => Dialect::Postgres,
        "mysql" | "mariadb" => Dialect::Mysql,
        "sqlite" => Dialect::Sqlite,
        "clickhouse" => Dialect::ClickHouse,
        "bigquery" => Dialect::BigQuery,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn psql_csv_distinguishes_null_empty_and_quoted_newlines() {
        let csv = "id,note,x\n1,,\"\"\n2,\"line1\nline2, \"\"q\"\"\",z\n";
        let r = parse_psql_csv(&mut Cursor::new(csv), 10).unwrap();
        assert_eq!(r.columns, ["id", "note", "x"]);
        assert_eq!(r.rows[0], vec![json!("1"), Value::Null, json!("")]);
        assert_eq!(r.rows[1][1], json!("line1\nline2, \"q\""));
        assert!(!r.truncated);
    }

    #[test]
    fn row_cap_marks_truncated_and_stops_reading() {
        let mut csv = String::from("n\n");
        for i in 0..50 {
            csv.push_str(&format!("{i}\n"));
        }
        let r = parse_psql_csv(&mut Cursor::new(csv), 5).unwrap();
        assert_eq!((r.rows.len(), r.truncated), (5, true));
        let r = parse_mysql_batch(&mut Cursor::new("a\tb\n1\tNULL\n2\tx\\ty\n"), 1).unwrap();
        assert_eq!((r.rows.len(), r.truncated), (1, true));
        let r = parse_mysql_batch(&mut Cursor::new("a\tb\n1\tNULL\n2\tx\\ty\n"), 9).unwrap();
        assert_eq!(r.rows[0][1], Value::Null);
        assert_eq!(r.rows[1][1], json!("x\ty"));
    }

    #[test]
    fn long_cells_are_cut() {
        let big = "x".repeat(5000);
        let r = parse_psql_csv(&mut Cursor::new(format!("a\n{big}\n")), 9).unwrap();
        assert!(r.rows[0][0].as_str().unwrap().chars().count() < 2100);
    }
}
