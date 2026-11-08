use super::*;
use crate::testutil::ctx;
use crate::web::testutil::FakeServer;
use serde_json::json;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn make_db(dir: &Path) -> PathBuf {
    let p = dir.join("sales.db");
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE orders(id INTEGER PRIMARY KEY, customer TEXT NOT NULL, total REAL); CREATE VIEW big AS SELECT * FROM orders WHERE total > 100;").unwrap();
    for i in 1..=50 {
        c.execute("INSERT INTO orders(customer, total) VALUES (?1, ?2)", rusqlite::params![format!("c{}", i % 5), i as f64 * 10.0]).unwrap();
    }
    p
}

fn tool_set(cfg: Value) -> (Arc<dyn Tool>, Arc<dyn Tool>) {
    let mut t = tools(cfg).unwrap();
    assert_eq!(t.len(), 2);
    let schema = t.pop().unwrap();
    (t.pop().unwrap(), schema)
}

fn sqlite_cfg(db: &Path) -> Value {
    json!({"max_rows": 20, "sources": {"local": {"kind": "sqlite", "path": db.to_string_lossy(), "description": "test sales"}}})
}

fn rows_of(o: &ToolOutput) -> Value {
    assert!(!o.is_error, "{}", o.content);
    let start = o.content.find('{').unwrap();
    let end = o.content.rfind('}').unwrap();
    serde_json::from_str(&o.content[start..=end]).unwrap()
}

#[test]
fn sqlite_query_returns_rows_wrapped_as_untrusted_data() {
    let c = ctx("sql-basic");
    let db = make_db(&c.workspace);
    let (q, _) = tool_set(sqlite_cfg(&db));
    let o = q.call(&c, json!({"sql": "SELECT customer, COUNT(*) AS n, SUM(total) AS t FROM orders GROUP BY customer ORDER BY customer;"}));
    assert!(o.content.contains("EXTERNAL_UNTRUSTED_CONTENT"), "{}", o.content);
    let v = rows_of(&o);
    assert_eq!(v["columns"], json!(["customer", "n", "t"]));
    assert_eq!(v["row_count"], 5);
    assert_eq!(v["rows"][0][1], 10);
    assert_eq!(v["read_only"], true);
    assert_eq!(v["truncated"], false);
    // WITH and EXPLAIN are on the allowlist too.
    assert!(!q.call(&c, json!({"sql": "WITH x AS (SELECT 1 AS a) SELECT a FROM x"})).is_error);
    assert!(!q.call(&c, json!({"sql": "EXPLAIN QUERY PLAN SELECT * FROM orders"})).is_error);
}

#[test]
fn the_row_cap_applies_and_the_model_can_only_lower_it() {
    let c = ctx("sql-cap");
    let db = make_db(&c.workspace);
    let (q, _) = tool_set(sqlite_cfg(&db));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT * FROM orders"})));
    assert_eq!((v["row_count"].as_u64(), v["truncated"].as_bool()), (Some(20), Some(true)), "configured cap 20 of 50 rows");
    assert!(v["note"].as_str().unwrap().contains("Aggregate"));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT * FROM orders", "max_rows": 3})));
    assert_eq!(v["row_count"], 3);
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT * FROM orders", "max_rows": 100000})));
    assert_eq!((v["row_count"].as_u64(), v["max_rows"].as_u64()), (Some(20), Some(20)), "asking for more does not raise the cap");
    // The hard ceiling holds even for a generous config.
    let mut cfg = sqlite_cfg(&db);
    cfg["max_rows"] = json!(5_000_000);
    let parsed = DataConfig::from_value(cfg).unwrap();
    assert_eq!(parsed.max_rows(&parsed.sources["local"], None), HARD_MAX_ROWS);
}

#[test]
fn layer_two_refuses_writes_before_they_are_sent() {
    let c = ctx("sql-l2");
    let db = make_db(&c.workspace);
    let (q, _) = tool_set(sqlite_cfg(&db));
    for sql in ["DELETE FROM orders", "INSERT INTO orders(customer) VALUES ('x')", "DROP TABLE orders", "SELECT 1; DROP TABLE orders", "PRAGMA writable_schema=1", "WITH d AS (SELECT 1) DELETE FROM orders", "ATTACH 'x.db' AS x"] {
        let o = q.call(&c, json!({"sql": sql}));
        assert!(o.is_error && o.content.contains("refused"), "{sql}: {}", o.content);
    }
    let n = rusqlite::Connection::open(&db).unwrap().query_row("SELECT COUNT(*) FROM orders", [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(n, 50);
}

#[test]
fn layer_one_refuses_writes_even_if_the_statement_check_were_bypassed() {
    let c = ctx("sql-l1");
    let db = make_db(&c.workspace);
    let lim = Limits { max_rows: 10, timeout: Duration::from_secs(5), cancel: c.cancel.clone() };
    // Straight to the backend, skipping check_read_only: the read-only file still says no.
    for sql in ["DELETE FROM orders", "INSERT INTO orders(customer) VALUES ('x')", "DROP TABLE orders", "CREATE TABLE t(a)"] {
        let e = backends::sqlite(&db, sql, &lim).unwrap_err();
        assert!(e.to_lowercase().contains("read") , "{sql}: {e}");
    }
    let n = rusqlite::Connection::open(&db).unwrap().query_row("SELECT COUNT(*) FROM orders", [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(n, 50, "nothing was written");
    assert!(backends::sqlite(&c.workspace.join("missing.db"), "SELECT 1", &lim).is_err(), "a missing file is not created");
    assert!(!c.workspace.join("missing.db").exists());
}

#[test]
fn schema_tool_lists_sources_tables_and_columns() {
    let c = ctx("sql-schema");
    let db = make_db(&c.workspace);
    let (_, s) = tool_set(sqlite_cfg(&db));
    // One source: defaults to it.
    let v = rows_of(&s.call(&c, json!({})));
    let names: Vec<&str> = v["rows"].as_array().unwrap().iter().map(|r| r[0].as_str().unwrap()).collect();
    assert_eq!(names, ["big", "orders"]);
    let v = rows_of(&s.call(&c, json!({"source": "local", "table": "orders"})));
    assert_eq!(v["rows"].as_array().unwrap().len(), 3);
    assert_eq!(v["rows"][1][0], "customer");
    // A table name cannot carry SQL.
    let o = s.call(&c, json!({"source": "local", "table": "orders'); DROP TABLE orders; --"}));
    assert!(o.is_error, "{}", o.content);
    // Several sources: with none named, the tool lists them (no secrets, no paths).
    let mut cfg = sqlite_cfg(&db);
    cfg["sources"]["wh"] = json!({"kind": "postgres", "dsn": "{{secret:WH_DSN}}", "description": "warehouse"});
    let (_, s2) = tool_set(cfg);
    let o = s2.call(&c, json!({}));
    assert!(o.content.contains("warehouse") && o.content.contains("test sales") && !o.content.contains("WH_DSN") && !o.content.contains(&*db.to_string_lossy()), "{}", o.content);
}

#[test]
fn every_dialect_has_catalog_queries_that_pass_the_guard() {
    let s = SourceCfg { dataset: Some("analytics".into()), ..Default::default() };
    for d in [Dialect::Postgres, Dialect::Mysql, Dialect::Sqlite, Dialect::ClickHouse, Dialect::BigQuery, Dialect::SqlServer, Dialect::Oracle, Dialect::Odbc] {
        for t in [None, Some("orders"), Some("public.orders")] {
            let sql = schema_sql(d, &s, t).unwrap();
            check_read_only(&sql, d).unwrap_or_else(|e| panic!("{d:?} {t:?}: {e}\n{sql}"));
        }
    }
    assert!(schema_sql(Dialect::BigQuery, &SourceCfg::default(), None).is_err());
}

#[test]
fn config_is_validated_and_secrets_stay_secret() {
    assert!(tools(json!({})).unwrap().is_empty(), "no sources, no tools");
    assert!(tools(json!({"enabled": false, "sources": {"a": {"kind": "sqlite", "path": "/x"}}})).unwrap().is_empty());
    assert!(DataConfig::from_value(json!({"sources": {"a": {"kind": "informix", "dsn": "x://y"}}})).unwrap_err().contains("informix"));
    assert!(DataConfig::from_value(json!({"sources": {"a": {"kind": "postgres"}}})).unwrap_err().contains("dsn"));
    assert!(DataConfig::from_value(json!({"sources": {"a": {"kind": "bigquery", "project": "p"}}})).unwrap_err().contains("token"));
    assert!(DataConfig::from_value(json!({"bogus": 1})).is_err());
    // A connection string that points at a secret nobody stored fails with the name, not a leak.
    let c = ctx("sql-secret");
    let (q, _) = tool_set(json!({"sources": {"wh": {"kind": "postgres", "dsn": "{{secret:WH_DSN}}"}}}));
    let o = q.call(&c, json!({"sql": "SELECT 1"}));
    assert!(o.is_error && o.content.contains("WH_DSN") && o.content.contains("not set"), "{}", o.content);
    // Unknown source and the model cannot invent a connection.
    let o = q.call(&c, json!({"source": "postgres://evil@attacker.example/db", "sql": "SELECT 1"}));
    assert!(o.is_error && o.content.contains("unknown source"), "{}", o.content);
}

#[test]
fn effects_name_the_file_or_host_but_never_the_statement() {
    let mut c = ctx("sql-effects");
    c.secrets = Arc::new(|s: &str| s.replace("{{secret:WH_DSN}}", "postgres://u:hunter2@db.internal:5432/sales"));
    let db = make_db(&c.workspace);
    let mut cfg = sqlite_cfg(&db);
    cfg["sources"]["wh"] = json!({"kind": "postgres", "dsn": "{{secret:WH_DSN}}"});
    let (q, _) = tool_set(cfg);
    assert_eq!(q.effects(&c, &json!({"source": "local", "sql": "SELECT 1"})), vec![Effect::Read { path: db.clone() }]);
    assert_eq!(q.effects(&c, &json!({"source": "wh", "sql": "SELECT secret_col FROM t"})), vec![Effect::Net { dest: "db.internal:5432".into(), payload: String::new() }]);
}

#[cfg(unix)]
/// Write an executable fake client that records stdin / argv / env and prints `body`.
fn fake_client(dir: &Path, name: &str, body: &str) -> (String, PathBuf) {
    let out = dir.join(format!("{name}-out"));
    std::fs::create_dir_all(&out).unwrap();
    let script = dir.join(name);
    std::fs::write(&script, format!("#!/bin/sh\ncat > '{o}/stdin.txt'\nprintf '%s\\n' \"$@\" > '{o}/argv.txt'\nenv > '{o}/env.txt'\n{body}\n", o = out.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (script.to_string_lossy().into_owned(), out)
}

#[cfg(unix)]
#[test]
fn postgres_goes_through_a_read_only_transaction_with_the_password_in_the_environment() {
    let c = ctx("sql-pg");
    let (client, out) = fake_client(&c.workspace, "psql", "printf 'id,name\\n1,Ann\\n2,\\n'");
    let (q, _) = tool_set(json!({"sources": {"wh": {"kind": "postgres", "dsn": "postgres://ana:s3cr3tpw@db.internal:6432/sales?sslmode=require", "client": [client]}}}));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT id, name FROM people"})));
    assert_eq!(v["columns"], json!(["id", "name"]));
    assert_eq!(v["rows"], json!([["1", "Ann"], ["2", null]]));
    let stdin = std::fs::read_to_string(out.join("stdin.txt")).unwrap();
    assert!(stdin.starts_with("BEGIN READ ONLY;") && stdin.contains("SELECT id, name FROM people;") && stdin.trim_end().ends_with("ROLLBACK;"), "{stdin}");
    let env = std::fs::read_to_string(out.join("env.txt")).unwrap();
    assert!(env.contains("PGPASSWORD=s3cr3tpw") && env.contains("PGUSER=ana") && env.contains("PGHOST=db.internal") && env.contains("PGPORT=6432") && env.contains("PGSSLMODE=require"), "{env}");
    assert!(env.contains("PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=30000"), "{env}");
    let argv = std::fs::read_to_string(out.join("argv.txt")).unwrap();
    assert!(!argv.contains("s3cr3tpw") && !argv.contains("db.internal"), "credentials never on the command line: {argv}");
    // A refused statement never reaches the client.
    std::fs::remove_file(out.join("stdin.txt")).unwrap();
    assert!(q.call(&c, json!({"sql": "DELETE FROM people"})).is_error);
    assert!(!out.join("stdin.txt").exists(), "the client was not even started");
}

#[cfg(unix)]
/// SQL Server through `sqlcmd`: password in `SQLCMDPASSWORD`, `-K ReadOnly`, the statement in a
/// rolled-back transaction, unit-separator output with NULLs; integrated auth without a user.
#[test]
fn sqlserver_uses_sqlcmd_with_read_only_intent_and_a_rolled_back_transaction() {
    let c = ctx("sql-mssql");
    let (client, out) = fake_client(&c.workspace, "sqlcmd", "printf 'id\\037name\\n--\\037----\\n1\\037Ann\\n2\\037NULL\\n'");
    let (q, s) = tool_set(json!({"sources": {"erp": {"kind": "sqlserver", "dsn": "sqlserver://rpt:Pw0rd%21x@sql01.corp:1433/ERP?trust_server_certificate=true", "client": [client]}}}));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT TOP 10 id, name FROM dbo.customers"})));
    assert_eq!(v["columns"], json!(["id", "name"]));
    assert_eq!(v["rows"], json!([["1", "Ann"], ["2", null]]));
    let argv = std::fs::read_to_string(out.join("argv.txt")).unwrap();
    assert!(argv.contains("tcp:sql01.corp,1433") && argv.contains("ReadOnly") && argv.contains("\n-d\nERP\n") && argv.contains("\n-U\nrpt\n") && argv.contains("\n-C\n"), "{argv}");
    assert!(!argv.contains("Pw0rd"), "the password is never an argument: {argv}");
    assert!(std::fs::read_to_string(out.join("env.txt")).unwrap().contains("SQLCMDPASSWORD=Pw0rd!x"));
    let stdin = std::fs::read_to_string(out.join("stdin.txt")).unwrap();
    assert!(stdin.contains("BEGIN TRANSACTION;\nSELECT TOP 10 id, name FROM dbo.customers;\nROLLBACK TRANSACTION;\nGO"), "{stdin}");
    // T-SQL specific refusals: delays, SELECT … INTO, EXEC, xp_cmdshell, OPENROWSET.
    for bad in ["WAITFOR DELAY '00:00:05'", "SELECT * INTO #t FROM x", "EXEC sp_who", "SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT 1')", "SELECT 1; SHUTDOWN"] {
        assert!(q.call(&c, json!({"sql": bad})).is_error, "{bad}");
    }
    // A server-side error printed on stdout surfaces as an error.
    let (client, _) = fake_client(&c.workspace, "sqlcmd-err", "printf \"Msg 208, Level 16, State 1, Server sql01, Line 4\\nInvalid object name 'nope'.\\n\"");
    let (q2, _) = tool_set(json!({"sources": {"erp": {"kind": "mssql", "dsn": "sqlserver://sql01.corp/ERP", "client": [client]}}}));
    let o = q2.call(&c, json!({"sql": "SELECT * FROM nope"}));
    assert!(o.is_error && o.content.contains("Msg 208"), "{}", o.content);
    // No user: integrated (Kerberos) authentication.
    let (client, out) = fake_client(&c.workspace, "sqlcmd-krb", "printf 'n\\n-\\n1\\n'");
    let (q3, _) = tool_set(json!({"sources": {"erp": {"kind": "sqlserver", "dsn": "sqlserver://sql01.corp/ERP", "client": [client]}}}));
    assert!(!q3.call(&c, json!({"sql": "SELECT 1 AS n"})).is_error);
    assert!(std::fs::read_to_string(out.join("argv.txt")).unwrap().contains("\n-E\n"));
    let _ = s;
}

#[cfg(unix)]
/// Oracle through SQL*Plus: credentials in the CONNECT line on stdin, a READ ONLY transaction,
/// CSV markup; PL/SQL network packages are refused before anything runs.
#[test]
fn oracle_uses_sqlplus_with_a_read_only_transaction() {
    let c = ctx("sql-oracle");
    let (client, out) = fake_client(&c.workspace, "sqlplus", "printf '\"ID\",\"NAME\"\\n1,\"Ann\"\\n2,\\n'");
    let (q, _) = tool_set(json!({"sources": {"fin": {"kind": "oracle", "dsn": "oracle://gl_ro:Secr3tPw@ora01.corp:1521/FINPDB", "client": [client]}}}));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT id, name FROM gl.accounts WHERE ROWNUM <= 5"})));
    assert_eq!(v["columns"], json!(["ID", "NAME"]));
    assert_eq!(v["rows"], json!([["1", "Ann"], ["2", null]]));
    let argv = std::fs::read_to_string(out.join("argv.txt")).unwrap();
    assert_eq!(argv, "-S\n-L\n/nolog\n", "nothing secret on the command line");
    let stdin = std::fs::read_to_string(out.join("stdin.txt")).unwrap();
    assert!(stdin.contains("CONNECT \"gl_ro\"/\"Secr3tPw\"@//ora01.corp:1521/FINPDB") && stdin.contains("SET MARKUP CSV ON QUOTE ON"), "{stdin}");
    assert!(stdin.contains("SET TRANSACTION READ ONLY;\nSELECT id, name FROM gl.accounts WHERE ROWNUM <= 5;\nROLLBACK;"), "{stdin}");
    for bad in ["SELECT UTL_HTTP.REQUEST('http://x') FROM dual", "SELECT DBMS_PIPE.RECEIVE_MESSAGE('a', 10) FROM dual", "SELECT * FROM t FOR UPDATE"] {
        assert!(q.call(&c, json!({"sql": bad})).is_error, "{bad}");
    }
}

#[cfg(unix)]
/// Any ODBC DSN through unixODBC `isql`: batch mode, unit-separator output, the DSN name from
/// the connection string; isql's own error lines become errors.
#[test]
fn odbc_uses_isql_in_batch_mode() {
    let c = ctx("sql-odbc");
    let (client, out) = fake_client(&c.workspace, "isql", "printf 'PARTNO\\037QTY\\nA-1\\0373\\nB-2\\037\\n'");
    let (q, _) = tool_set(json!({"sources": {"as400": {"kind": "odbc", "dsn": "odbc://DB2PROD", "client": [client], "description": "IBM i inventory"}}}));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT partno, qty FROM inv.parts"})));
    assert_eq!(v["rows"], json!([["A-1", "3"], ["B-2", null]]));
    let argv = std::fs::read_to_string(out.join("argv.txt")).unwrap();
    assert_eq!(argv, "-b\n-c\n-x0x1f\nDB2PROD\n");
    assert_eq!(std::fs::read_to_string(out.join("stdin.txt")).unwrap(), "SELECT partno, qty FROM inv.parts\n");
    let (client, _) = fake_client(&c.workspace, "isql-bad", "echo '[ISQL]ERROR: Could not SQLConnect'; exit 1");
    let (q, _) = tool_set(json!({"sources": {"as400": {"kind": "odbc", "dsn": "odbc://DB2PROD", "client": [client]}}}));
    let o = q.call(&c, json!({"sql": "SELECT 1 FROM sysibm.sysdummy1"}));
    assert!(o.is_error && o.content.contains("SQLConnect"), "{}", o.content);
    assert_eq!(q.effects(&c, &json!({"sql": "SELECT 1"})), vec![Effect::Net { dest: "DB2PROD".into(), payload: String::new() }]);
}

#[cfg(unix)]
#[test]
fn mysql_sets_a_read_only_session_and_transaction() {
    let c = ctx("sql-mysql");
    let (client, out) = fake_client(&c.workspace, "mysql", "printf 'n\\tv\\n1\\tNULL\\n'");
    let (q, _) = tool_set(json!({"sources": {"m": {"kind": "mysql", "dsn": "mysql://root:pw123456@10.0.0.5/shop", "client": [client]}}}));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT 1 AS n"})));
    assert_eq!(v["rows"], json!([["1", null]]));
    let argv = std::fs::read_to_string(out.join("argv.txt")).unwrap();
    assert!(argv.contains("--init-command=SET SESSION TRANSACTION READ ONLY") && argv.contains("--host=10.0.0.5") && argv.contains("--database=shop") && !argv.contains("pw123456"), "{argv}");
    assert!(std::fs::read_to_string(out.join("env.txt")).unwrap().contains("MYSQL_PWD=pw123456"));
    let stdin = std::fs::read_to_string(out.join("stdin.txt")).unwrap();
    assert!(stdin.contains("START TRANSACTION READ ONLY;") && stdin.contains("SET SESSION max_execution_time=30000;"), "{stdin}");
    // MariaDB spells the server-side time limit differently (seconds, max_statement_time).
    let (client, out) = fake_client(&c.workspace, "mariadb", "printf 'n\\n1\\n'");
    let (q, _) = tool_set(json!({"sources": {"m": {"kind": "mariadb", "dsn": "mysql://root@10.0.0.5/shop", "client": [client]}}}));
    assert!(!q.call(&c, json!({"sql": "SELECT 1 AS n"})).is_error);
    assert!(std::fs::read_to_string(out.join("stdin.txt")).unwrap().contains("SET SESSION max_statement_time=30;"));
}

#[cfg(unix)]
#[test]
fn a_client_error_is_reported_without_the_password_and_a_huge_result_stops_the_client() {
    let c = ctx("sql-clienterr");
    let (client, _) = fake_client(&c.workspace, "bad", "echo 'psql: error: password authentication failed for user ana (s3cr3tpw)' >&2; exit 2");
    let (q, _) = tool_set(json!({"sources": {"wh": {"kind": "postgres", "dsn": "postgres://ana:s3cr3tpw@h/db", "client": [client]}}}));
    let o = q.call(&c, json!({"sql": "SELECT 1"}));
    assert!(o.is_error && o.content.contains("authentication failed") && !o.content.contains("s3cr3tpw"), "{}", o.content);
    // An endless result is cut at max_rows and the client is killed (no hang, no orphan).
    let (client, _) = fake_client(&c.workspace, "endless", "printf 'n\\n'; exec yes 1");
    let (q, _) = tool_set(json!({"max_rows": 7, "timeout_seconds": 20, "sources": {"wh": {"kind": "postgres", "dsn": "postgres://u@h/db", "client": [client]}}}));
    let t0 = std::time::Instant::now();
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT n FROM t"})));
    assert_eq!((v["row_count"].as_u64(), v["truncated"].as_bool()), (Some(7), Some(true)));
    assert!(t0.elapsed() < Duration::from_secs(10));
}

#[cfg(unix)]
#[test]
fn a_slow_client_is_killed_at_the_timeout() {
    let c = ctx("sql-timeout");
    let (client, _) = fake_client(&c.workspace, "slow", "exec sleep 30");
    let (q, _) = tool_set(json!({"timeout_seconds": 1, "sources": {"wh": {"kind": "postgres", "dsn": "postgres://u@h/db", "client": [client]}}}));
    let t0 = std::time::Instant::now();
    let o = q.call(&c, json!({"sql": "SELECT pg_catalog.now()"}));
    assert!(o.is_error && o.content.contains("exceeded 1 seconds"), "{}", o.content);
    assert!(t0.elapsed() < Duration::from_secs(10));
    let o = q.call(&c, json!({"sql": "SELECT 1"}));
    assert!(o.is_error);
}

#[test]
fn a_missing_client_says_how_to_fix_it() {
    let c = ctx("sql-noclient");
    let (q, _) = tool_set(json!({"sources": {"wh": {"kind": "postgres", "dsn": "postgres://u@h/db", "client": ["/nonexistent/psql-seagent-test"]}}}));
    let o = q.call(&c, json!({"sql": "SELECT 1"}));
    assert!(o.is_error && o.content.contains("cannot start") && o.content.contains("client"), "{}", o.content);
}

#[test]
fn clickhouse_uses_readonly_one_and_headers_for_credentials() {
    let c = ctx("sql-ch");
    let srv = FakeServer::start(vec![("POST /", 200, "application/json", json!({"meta": [{"name": "d", "type": "Date"}, {"name": "n", "type": "UInt64"}], "data": [["2024-01-01", 5], ["2024-01-02", 7], ["2024-01-03", 9]], "rows": 3}).to_string())]);
    let dsn = srv.url.replace("http://", "http://ch:chpw1234@") + "/events";
    let (q, _) = tool_set(json!({"max_rows": 2, "sources": {"ev": {"kind": "clickhouse", "dsn": dsn}}}));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT d, n FROM hits ORDER BY d"})));
    assert_eq!(v["row_count"], 2);
    assert_eq!(v["truncated"], true, "the third row exceeds max_rows");
    let r = srv.last();
    assert!(r.path.contains("readonly=1") && r.path.contains("database=events") && r.path.contains("max_result_rows=3"), "{}", r.path);
    assert_eq!(r.body, "SELECT d, n FROM hits ORDER BY d");
    assert_eq!(r.header("X-ClickHouse-User").as_deref(), Some("ch"));
    assert_eq!(r.header("X-ClickHouse-Key").as_deref(), Some("chpw1234"));
    assert!(!r.path.contains("chpw1234"), "the password is a header, not part of the URL");
}

#[test]
fn clickhouse_errors_surface_without_the_password() {
    let c = ctx("sql-ch-err");
    let srv = FakeServer::start(vec![("POST /", 500, "text/plain", "Code: 497. DB::Exception: user ch: Not enough privileges (chpw1234)".into())]);
    let (q, _) = tool_set(json!({"sources": {"ev": {"kind": "clickhouse", "dsn": srv.url.replace("http://", "http://ch:chpw1234@")}}}));
    let o = q.call(&c, json!({"sql": "SELECT 1"}));
    assert!(o.is_error && o.content.contains("Not enough privileges") && !o.content.contains("chpw1234"), "{}", o.content);
}

#[test]
fn bigquery_sends_a_bearer_token_and_a_standard_sql_job() {
    let mut c = ctx("sql-bq");
    c.secrets = Arc::new(|s: &str| s.replace("{{secret:BQ_TOKEN}}", "ya29.fake-token"));
    let srv = FakeServer::start(vec![(
        "POST /bigquery/v2/projects/my-proj/queries",
        200,
        "application/json",
        json!({"jobComplete": true, "schema": {"fields": [{"name": "country"}, {"name": "n"}]}, "rows": [{"f": [{"v": "TW"}, {"v": "12"}]}, {"f": [{"v": "JP"}, {"v": "9"}]}]}).to_string(),
    )]);
    let (q, s) = tool_set(json!({"sources": {"bq": {"kind": "bigquery", "project": "my-proj", "dataset": "analytics", "token": "{{secret:BQ_TOKEN}}", "api_base": srv.url}}}));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT country, COUNT(*) n FROM `analytics.users` GROUP BY 1"})));
    assert_eq!(v["rows"], json!([["TW", "12"], ["JP", "9"]]));
    let r = srv.last();
    assert_eq!(r.header("Authorization").as_deref(), Some("Bearer ya29.fake-token"));
    assert_eq!((r.json()["useLegacySql"].clone(), r.json()["dryRun"].clone()), (json!(false), json!(false)));
    // Schema goes through INFORMATION_SCHEMA of the configured dataset.
    let _ = s.call(&c, json!({"source": "bq", "table": "users"}));
    assert!(srv.last().json()["query"].as_str().unwrap().contains("`analytics`.INFORMATION_SCHEMA.COLUMNS"));
    // A secret that is not set never produces a request.
    let n = srv.requests().len();
    let c2 = ctx("sql-bq2");
    let o = q.call(&c2, json!({"sql": "SELECT 1"}));
    assert!(o.is_error && o.content.contains("BQ_TOKEN"), "{}", o.content);
    assert_eq!(srv.requests().len(), n);
}

// ───────────── real servers in podman (seagent-test-prodev-*), run with `--ignored` ─────────────

/// Removes the container when the test ends, pass or fail.
struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = std::process::Command::new("podman").args(["rm", "-f", &self.0]).output();
    }
}

fn podman_run(name: &str, args: &[&str]) -> Container {
    let _ = std::process::Command::new("podman").args(["rm", "-f", name]).output();
    let g = Container(name.to_string());
    let mut a = vec!["run", "-d", "--name", name];
    a.extend_from_slice(args);
    let o = std::process::Command::new("podman").args(&a).output().expect("podman");
    assert!(o.status.success(), "podman run: {}", String::from_utf8_lossy(&o.stderr));
    g
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..90 {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("{what} did not become ready");
}

fn pod_ok(args: &[&str]) -> bool {
    std::process::Command::new("podman").args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

/// `cargo test -p seagent-tools data::tests::real_postgres -- --ignored` (needs podman and the postgres:16-alpine image).
#[test]
#[ignore = "needs podman and docker.io/library/postgres:16-alpine"]
fn real_postgres_enforces_read_only_in_both_layers() {
    let name = "seagent-test-prodev-pg";
    let _g = podman_run(name, &["-e", "POSTGRES_PASSWORD=seagent_test_pw", "docker.io/library/postgres:16-alpine"]);
    wait_for("postgres", || pod_ok(&["exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]) && pod_ok(&["exec", "-e", "PGPASSWORD=seagent_test_pw", name, "psql", "-h", "127.0.0.1", "-U", "postgres", "-c", "select 1"]));
    let setup = std::process::Command::new("podman")
        .args(["exec", "-i", "-e", "PGPASSWORD=seagent_test_pw", name, "psql", "-h", "127.0.0.1", "-U", "postgres", "-v", "ON_ERROR_STOP=1"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    setup.stdin.as_ref().unwrap();
    let mut setup = setup;
    setup.stdin.take().unwrap().write_all(b"CREATE TABLE t(id int primary key, v text); INSERT INTO t SELECT g, 'row' || g FROM generate_series(1, 50) g;").unwrap();
    assert!(setup.wait().unwrap().success());

    let c = ctx("sql-realpg");
    let cfg = json!({"max_rows": 10, "sources": {"pg": {"kind": "postgres", "dsn": "postgres://postgres:seagent_test_pw@127.0.0.1:5432/postgres", "client": ["podman", "exec", "-i", name, "psql"]}}});
    let (q, s) = tool_set(cfg);
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT id, v FROM t ORDER BY id"})));
    assert_eq!((v["row_count"].as_u64(), v["truncated"].as_bool()), (Some(10), Some(true)));
    assert_eq!(v["rows"][0], json!(["1", "row1"]));
    let v = rows_of(&s.call(&c, json!({"source": "pg", "table": "t"})));
    assert_eq!(v["rows"][0][0], "id");
    // Layer 2.
    assert!(q.call(&c, json!({"sql": "DELETE FROM t"})).is_error);
    // Layer 1 alone: skip the statement check and hand a write straight to the connection.
    let dsn = Dsn::parse("postgres://postgres:seagent_test_pw@127.0.0.1:5432/postgres").unwrap();
    let client: Vec<String> = ["podman", "exec", "-i", name, "psql"].map(String::from).to_vec();
    let lim = Limits { max_rows: 10, timeout: Duration::from_secs(20), cancel: c.cancel.clone() };
    for w in ["DELETE FROM t", "CREATE TABLE evil(a int)", "UPDATE t SET v = 'x'", "TRUNCATE t"] {
        let e = backends::postgres(&dsn, &client, w, &lim).unwrap_err();
        assert!(e.contains("read-only"), "{w}: {e}");
    }
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT count(*) AS n FROM t"})));
    assert_eq!(v["rows"][0][0], "50", "nothing was deleted");
}

/// `cargo test -p seagent-tools data::tests::real_mariadb -- --ignored` (needs podman and docker.io/library/mariadb:11).
#[test]
#[ignore = "needs podman and docker.io/library/mariadb:11"]
fn real_mariadb_enforces_read_only_in_both_layers() {
    let name = "seagent-test-prodev-mysql";
    let _g = podman_run(name, &["-e", "MARIADB_ROOT_PASSWORD=seagent_test_pw", "-e", "MARIADB_DATABASE=shop", "docker.io/library/mariadb:11"]);
    let mysql = |sql: &str| -> bool {
        let mut ch = std::process::Command::new("podman").args(["exec", "-i", "-e", "MYSQL_PWD=seagent_test_pw", name, "mariadb", "-h", "127.0.0.1", "-uroot", "shop"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        use std::io::Write;
        ch.stdin.take().unwrap().write_all(sql.as_bytes()).unwrap();
        ch.wait().map(|s| s.success()).unwrap_or(false)
    };
    wait_for("mariadb", || mysql("SELECT 1;"));
    assert!(mysql("CREATE TABLE t(id int primary key, v varchar(20)); INSERT INTO t VALUES (1,'a'),(2,'b'),(3,NULL);"));
    let c = ctx("sql-realmy");
    let cfg = json!({"max_rows": 2, "sources": {"my": {"kind": "mariadb", "dsn": "mysql://root:seagent_test_pw@127.0.0.1:3306/shop", "client": ["podman", "exec", "-i", "-e", "MYSQL_PWD", name, "mariadb"]}}});
    let (q, _) = tool_set(cfg);
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT id, v FROM t ORDER BY id"})));
    assert_eq!((v["row_count"].as_u64(), v["truncated"].as_bool()), (Some(2), Some(true)));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT id, v FROM t WHERE id = 3"})));
    assert_eq!(v["rows"][0], json!(["3", null]));
    assert!(q.call(&c, json!({"sql": "DELETE FROM t"})).is_error);
    let dsn = Dsn::parse("mysql://root:seagent_test_pw@127.0.0.1:3306/shop").unwrap();
    let client: Vec<String> = ["podman", "exec", "-i", "-e", "MYSQL_PWD", name, "mariadb"].map(String::from).to_vec();
    let lim = Limits { max_rows: 10, timeout: Duration::from_secs(20), cancel: c.cancel.clone() };
    for w in ["DELETE FROM t", "INSERT INTO t VALUES (9,'z')", "DROP TABLE t"] {
        let e = backends::mysql(&dsn, &client, w, &lim, true).unwrap_err();
        assert!(e.to_lowercase().contains("read") , "{w}: {e}");
    }
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT count(*) FROM t"})));
    assert_eq!(v["rows"][0][0], "3");
}

/// `cargo test -p seagent-tools data::tests::real_clickhouse -- --ignored` (needs podman and the clickhouse-server image).
#[test]
#[ignore = "needs podman and docker.io/clickhouse/clickhouse-server:24.8-alpine"]
fn real_clickhouse_readonly_setting_blocks_writes() {
    let name = "seagent-test-prodev-ch";
    let _g = podman_run(name, &["-p", "127.0.0.1:18123:8123", "-e", "CLICKHOUSE_PASSWORD=seagent_test_pw", "docker.io/clickhouse/clickhouse-server:24.8-alpine"]);
    let ch = |sql: &str| -> bool { pod_ok(&["exec", name, "clickhouse-client", "--password", "seagent_test_pw", "-q", sql]) };
    wait_for("clickhouse", || ch("SELECT 1"));
    assert!(ch("CREATE TABLE t(id UInt32, v String) ENGINE = MergeTree ORDER BY id"));
    assert!(ch("INSERT INTO t SELECT number, toString(number) FROM numbers(30)"));
    let c = ctx("sql-realch");
    let (q, _) = tool_set(json!({"max_rows": 5, "sources": {"ch": {"kind": "clickhouse", "dsn": "http://default:seagent_test_pw@127.0.0.1:18123/default"}}}));
    let v = rows_of(&q.call(&c, json!({"sql": "SELECT id, v FROM t ORDER BY id"})));
    assert_eq!((v["row_count"].as_u64(), v["truncated"].as_bool()), (Some(5), Some(true)));
    // Layer 1 alone.
    let dsn = Dsn::parse("http://default:seagent_test_pw@127.0.0.1:18123/default").unwrap();
    let lim = Limits { max_rows: 5, timeout: Duration::from_secs(20), cancel: c.cancel.clone() };
    for w in ["INSERT INTO t VALUES (99, 'x')", "DROP TABLE t", "TRUNCATE TABLE t"] {
        let e = backends::clickhouse(&dsn, w, &lim).unwrap_err();
        assert!(e.to_lowercase().contains("readonly") || e.to_lowercase().contains("read-only") || e.contains("164"), "{w}: {e}");
    }
    assert_eq!(rows_of(&q.call(&c, json!({"sql": "SELECT count() FROM t"})))["rows"][0][0], "30");
}
