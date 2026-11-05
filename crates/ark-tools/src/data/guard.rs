//! Layer 2 of the read-only guarantee for `sql_query`: the statement allowlist.
//!
//! Layer 1 is the connection itself (SQLite opened `SQLITE_OPEN_READ_ONLY`, PostgreSQL and
//! MySQL sessions in a read-only transaction, ClickHouse `readonly=1`); this layer refuses a
//! statement before it is ever sent. Both must agree, so a bug or a clever dialect trick in one
//! does not become a write.
//!
//! The rules, deliberately blunt (a false refusal costs the model one rewrite, a false accept
//! costs data):
//!
//! * exactly one statement (a trailing `;` is fine), no NUL / control characters;
//! * it starts with `SELECT`, `WITH`, `EXPLAIN` or `SHOW` (leading `(` allowed for `(SELECT …) UNION …`);
//! * no SQL comments at all (`--`, `/* */`, and `#` for MySQL / ClickHouse): dialects disagree
//!   about what a comment is, and every disagreement is a way to hide a second statement;
//! * no backslash outside literals (psql meta-commands such as `\!` start with one);
//! * outside of literals and quoted identifiers, none of the write / DDL / session /
//!   file-access words below appears (`WITH x AS (DELETE …)`, `SELECT … INTO …`,
//!   `FOR UPDATE`, `EXPLAIN ANALYZE DELETE …` are all caught by that single scan), and none of
//!   the side-effecting functions (`pg_sleep`, `lo_import`, `nextval`, `load_file`, …) or
//!   file/network table functions (`file(`, `url(`, `s3(`, `remote(`, …);
//! * literals are scanned twice, once with backslash escapes and once without; a statement is
//!   accepted only if it passes both readings, because PostgreSQL and MySQL disagree on
//!   `'a\'` and the disagreement is a classic injection.

/// Which SQL dialect the statement goes to (changes quoting rules only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    Mysql,
    Sqlite,
    ClickHouse,
    BigQuery,
}

const ALLOWED_FIRST: &[&str] = &["SELECT", "WITH", "EXPLAIN", "SHOW"];

const FORBIDDEN_WORDS: &[&str] = &[
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "GRANT", "REVOKE", "MERGE", "UPSERT", "INTO", "COPY", "CALL", "EXEC", "EXECUTE", "DO", "LOAD", "ATTACH", "DETACH", "PRAGMA", "VACUUM", "REINDEX", "SET",
    "RESET", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "LOCK", "UNLOCK", "KILL", "OPTIMIZE", "RENAME", "DISCARD", "LISTEN", "NOTIFY", "PREPARE", "DEALLOCATE",
    "HANDLER", "USE", "UNDROP", "CHECKPOINT", "OUTFILE", "DUMPFILE", "DECLARE", "ASSERT", "RAISE",
];

/// Functions that mutate state, read files, sleep or reach other servers, wherever they appear.
const FORBIDDEN_FUNCTIONS: &[&str] = &[
    "PG_SLEEP", "PG_SLEEP_FOR", "PG_SLEEP_UNTIL", "PG_READ_FILE", "PG_READ_BINARY_FILE", "PG_LS_DIR", "PG_STAT_FILE", "LO_IMPORT", "LO_EXPORT", "LO_UNLINK", "LO_CREAT", "LO_CREATE", "LO_FROM_BYTEA", "LO_PUT", "LO_OPEN",
    "PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND", "PG_RELOAD_CONF", "PG_ROTATE_LOGFILE", "PG_LOGICAL_EMIT_MESSAGE", "PG_CREATE_RESTORE_POINT", "SET_CONFIG", "NEXTVAL", "SETVAL", "DBLINK", "DBLINK_EXEC", "DBLINK_CONNECT",
    "PG_ADVISORY_LOCK", "PG_ADVISORY_XACT_LOCK", "PG_TRY_ADVISORY_LOCK", "PG_TRY_ADVISORY_XACT_LOCK", "LOAD_FILE", "SLEEP", "BENCHMARK", "GET_LOCK", "RELEASE_LOCK", "SYS_EXEC", "SYS_EVAL", "XP_CMDSHELL", "LOAD_EXTENSION",
    "READFILE", "WRITEFILE", "EDIT", "SQLITE_SOURCE_ID_X",
];

/// File / network / remote-database table functions: refused when followed by `(`.
const FORBIDDEN_CALLS: &[&str] = &["FILE", "URL", "S3", "S3CLUSTER", "HDFS", "REMOTE", "REMOTESECURE", "JDBC", "ODBC", "EXECUTABLE", "MYSQL", "POSTGRESQL", "MONGODB", "REDIS", "SQLITE", "OPENROWSET", "OPENQUERY", "OPENDATASOURCE", "INPUT", "CLUSTER", "CLUSTERALLREPLICAS"];

struct Scan {
    /// Upper-cased words outside literals, in order, with whether `(` follows.
    words: Vec<(String, bool)>,
    /// The statement without a trailing `;`.
    stmt: String,
}

fn scan(sql: &str, d: Dialect, backslash: bool) -> Result<Scan, String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    let mut words: Vec<(String, bool)> = vec![];
    let mut end_stmt: Option<usize> = None; // index of the first `;`
    let hash_comment = matches!(d, Dialect::Mysql | Dialect::ClickHouse);
    let dollar = d == Dialect::Postgres;
    let mut first_sig: Option<char> = None;
    while i < chars.len() {
        let c = chars[i];
        if c == '\0' || (c.is_control() && !matches!(c, '\n' | '\r' | '\t')) {
            return Err("control characters are not allowed in a statement".into());
        }
        if let Some(e) = end_stmt {
            if !c.is_whitespace() {
                return Err(format!("only one statement per call (found more after the `;` at position {e})"));
            }
            i += 1;
            continue;
        }
        if first_sig.is_none() && !c.is_whitespace() {
            first_sig = Some(c);
        }
        match c {
            '\\' => return Err("a backslash outside a string literal is not allowed (client meta-commands start with one)".into()),
            '-' if chars.get(i + 1) == Some(&'-') => return Err("SQL comments (`--`) are not allowed; remove them".into()),
            '/' if chars.get(i + 1) == Some(&'*') => return Err("SQL comments (`/* */`) are not allowed; remove them".into()),
            '#' if hash_comment => return Err("SQL comments (`#`) are not allowed; remove them".into()),
            ';' => {
                end_stmt = Some(i);
                i += 1;
            }
            '\'' | '"' | '`' => {
                // Quoted literal or identifier; doubled quote escapes, optional backslash escapes.
                let q = c;
                i += 1;
                let mut closed = false;
                while i < chars.len() {
                    let ch = chars[i];
                    if backslash && ch == '\\' && q != '`' {
                        i += 2;
                        continue;
                    }
                    if ch == q {
                        if chars.get(i + 1) == Some(&q) {
                            i += 2;
                            continue;
                        }
                        closed = true;
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if !closed {
                    return Err("unterminated quote".into());
                }
            }
            '$' if dollar => {
                // $tag$ … $tag$ (tag may be empty). `$1` placeholders are not a quote.
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                if chars.get(j) == Some(&'$') && !(j > i + 1 && chars[i + 1].is_ascii_digit()) {
                    let tag: String = chars[i..=j].iter().collect();
                    let rest: String = chars[j + 1..].iter().collect();
                    match rest.find(&tag) {
                        Some(p) => i = j + 1 + rest[..p].chars().count() + tag.chars().count(),
                        None => return Err("unterminated dollar-quoted string".into()),
                    }
                } else {
                    i += 1;
                }
            }
            c if c.is_alphabetic() || c == '_' => {
                let s = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '$') {
                    i += 1;
                }
                let w: String = chars[s..i].iter().collect::<String>().to_uppercase();
                let mut k = i;
                while k < chars.len() && chars[k].is_whitespace() {
                    k += 1;
                }
                words.push((w, chars.get(k) == Some(&'(')));
            }
            _ => i += 1,
        }
    }
    let stmt_end = end_stmt.unwrap_or(chars.len());
    let stmt: String = chars[..stmt_end].iter().collect::<String>().trim().to_string();
    if stmt.is_empty() {
        return Err("empty statement".into());
    }
    let _ = first_sig;
    Ok(Scan { words, stmt })
}

fn judge(s: &Scan) -> Result<(), String> {
    // Leading parentheses are skipped for the first-keyword test.
    let lead = s.stmt.trim_start_matches(|c: char| c == '(' || c.is_whitespace());
    let first = lead.split(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap_or("").to_uppercase();
    if !ALLOWED_FIRST.contains(&first.as_str()) {
        return Err(format!("only SELECT, WITH, EXPLAIN and SHOW statements are allowed (this one starts with `{}`)", if first.is_empty() { "?" } else { &first }));
    }
    for (i, (w, call)) in s.words.iter().enumerate() {
        if FORBIDDEN_WORDS.contains(&w.as_str()) {
            return Err(format!("`{w}` is not allowed: this connection is read-only (quote the identifier if it is a column name)"));
        }
        if FORBIDDEN_FUNCTIONS.contains(&w.as_str()) || w.starts_with("DBLINK") {
            return Err(format!("function `{}` is not allowed on a read-only connection", w.to_lowercase()));
        }
        if *call && FORBIDDEN_CALLS.contains(&w.as_str()) {
            return Err(format!("table function `{}(` is not allowed (it reaches files or other servers)", w.to_lowercase()));
        }
        if w == "FOR" {
            if let Some((n, _)) = s.words.get(i + 1) {
                if matches!(n.as_str(), "SHARE" | "KEY" | "NO" | "UPDATE") {
                    return Err("`FOR UPDATE/SHARE` takes locks and is not allowed".into());
                }
            }
        }
    }
    Ok(())
}

/// Accept `sql` for the read-only connection of `dialect` or say why not. Returns the single
/// statement without its trailing `;`.
pub fn check_read_only(sql: &str, dialect: Dialect) -> Result<String, String> {
    if sql.trim().is_empty() {
        return Err("empty statement".into());
    }
    if sql.len() > 100_000 {
        return Err("statement is longer than 100000 bytes".into());
    }
    let a = scan(sql, dialect, false)?;
    judge(&a)?;
    let b = scan(sql, dialect, true)?;
    judge(&b)?;
    if a.stmt != b.stmt {
        return Err("the statement reads differently with and without backslash escapes in string literals; write the string with doubled quotes ('') instead".into());
    }
    Ok(a.stmt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use Dialect::*;

    fn ok(s: &str, d: Dialect) {
        assert!(check_read_only(s, d).is_ok(), "should pass: {s}: {:?}", check_read_only(s, d));
    }
    fn no(s: &str, d: Dialect) {
        assert!(check_read_only(s, d).is_err(), "should be refused: {s}");
    }

    #[test]
    fn the_four_read_statements_pass() {
        for d in [Postgres, Mysql, Sqlite, ClickHouse, BigQuery] {
            ok("SELECT 1", d);
            ok("  select id, name from users where name = 'Bob; DROP TABLE users' ;  ", d);
            ok("WITH t AS (SELECT 1 AS a) SELECT a FROM t", d);
            ok("EXPLAIN SELECT * FROM t", d);
            ok("SHOW TABLES", d);
            ok("(SELECT 1) UNION (SELECT 2)", d);
            ok("SELECT replace(name, 'a', 'b'), \"update\" FROM t", d);
        }
        ok("SELECT $$; DROP TABLE x;$$", Postgres);
        ok("SELECT * FROM t WHERE id = $1", Postgres);
        ok("EXPLAIN ANALYZE SELECT 1", Postgres);
    }

    #[test]
    fn writes_ddl_and_session_changes_are_refused() {
        for s in [
            "INSERT INTO t VALUES (1)",
            "update t set a = 1",
            "DELETE FROM t",
            "DROP TABLE t",
            "TRUNCATE t",
            "ALTER TABLE t ADD c int",
            "CREATE TABLE x AS SELECT 1",
            "GRANT ALL ON t TO u",
            "SET default_transaction_read_only = off",
            "BEGIN",
            "COMMIT",
            "COPY t FROM '/etc/passwd'",
            "CALL f()",
            "PRAGMA writable_schema = 1",
            "ATTACH DATABASE 'x' AS y",
            "VACUUM",
            "USE other_db",
            "KILL 1",
            "OPTIMIZE TABLE t",
        ] {
            no(s, Postgres);
        }
    }

    #[test]
    fn a_read_statement_cannot_smuggle_a_write() {
        // Second statement, in every spelling.
        no("SELECT 1; DROP TABLE t", Postgres);
        no("SELECT 1;\nDELETE FROM t", Mysql);
        no("SELECT 1 ; ; SELECT 2", Sqlite);
        // Writable CTE, SELECT INTO, locks, EXPLAIN of a write.
        no("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", Postgres);
        no("SELECT * INTO newt FROM t", Postgres);
        no("SELECT * FROM t INTO OUTFILE '/tmp/x'", Mysql);
        no("SELECT * FROM t FOR UPDATE", Postgres);
        no("SELECT * FROM t FOR SHARE", Postgres);
        no("SELECT * FROM t LOCK IN SHARE MODE", Mysql);
        no("EXPLAIN ANALYZE DELETE FROM t", Postgres);
        // Side-effecting and file-reaching functions.
        no("SELECT pg_sleep(100)", Postgres);
        no("SELECT nextval('s')", Postgres);
        no("SELECT lo_import('/etc/passwd')", Postgres);
        no("SELECT pg_read_file('/etc/passwd')", Postgres);
        no("SELECT LOAD_FILE('/etc/passwd')", Mysql);
        no("SELECT sleep(10)", Mysql);
        no("SELECT * FROM file('/etc/passwd', 'CSV')", ClickHouse);
        no("SELECT * FROM url('http://x', CSV)", ClickHouse);
        no("SELECT * FROM dblink('host=x', 'select 1') AS t(a int)", Postgres);
        no("SELECT load_extension('x')", Sqlite);
        // `url` as a column name is fine; as a table function it is not.
        ok("SELECT url FROM pages", ClickHouse);
        // psql meta-commands never reach the client.
        no("SELECT 1\n\\! id", Postgres);
    }

    #[test]
    fn comments_are_refused_because_dialects_disagree_about_them() {
        no("SELECT 1 -- ; DROP TABLE t", Postgres);
        no("SELECT 1 /* x */", Postgres);
        no("SELECT /*! DROP TABLE t */ 1", Mysql);
        no("SELECT 1 # x", Mysql);
        no("SELECT 1 # x", ClickHouse);
        // `#` is an operator in PostgreSQL, not a comment.
        ok("SELECT '{\"a\":1}'::jsonb #> '{a}'", Postgres);
        // Comment markers inside literals are just text.
        ok("SELECT '-- not a comment', '/* nor this */'", Postgres);
    }

    #[test]
    fn backslash_dialect_differences_cannot_hide_a_statement() {
        // MySQL reads `\'` as an escaped quote, PostgreSQL (standard strings) as backslash + end.
        no("SELECT 'a\\'; DROP TABLE t; --'", Postgres);
        no("SELECT 'a\\'; DROP TABLE t; SELECT '", Mysql);
        no("SELECT 'a\\' ; DELETE FROM t WHERE 'b' = '", Postgres);
        // A plain backslash that does not touch a quote reads the same both ways.
        ok("SELECT 'C:\\temp' AS p", Postgres);
        // Doubled quotes are unambiguous.
        ok("SELECT 'it''s'", Postgres);
        no("SELECT 'it''s'; DROP TABLE t", Postgres);
    }

    #[test]
    fn odd_input_is_refused() {
        no("", Postgres);
        no("   ;", Postgres);
        no("SELECT 'unterminated", Postgres);
        no("SELECT $x$ unterminated", Postgres);
        no("SELECT 1\0; DROP TABLE t", Postgres);
        no("DROP TABLE t; SELECT 1", Postgres);
        no(&format!("SELECT '{}'", "a".repeat(100_001)), Postgres);
        let e = check_read_only("UPDATE t SET a=1", Postgres).unwrap_err();
        assert!(e.contains("only SELECT"), "{e}");
    }

    #[test]
    fn returns_the_statement_without_the_trailing_semicolon() {
        assert_eq!(check_read_only(" SELECT 1 ; ", Sqlite).unwrap(), "SELECT 1");
    }
}
