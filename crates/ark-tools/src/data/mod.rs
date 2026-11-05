//! Data-analysis tools (BATCH-next §3, pro-033/034/037): `sql_query` and `sql_schema` over
//! PostgreSQL, MySQL/MariaDB, SQLite, ClickHouse (self-hosted first) and BigQuery.
//!
//! ```toml
//! [integrations.data]
//! max_rows = 1000            # default rows per call (hard cap 10000)
//! timeout_seconds = 30
//! [integrations.data.sources.warehouse]
//! kind = "postgres"          # postgres | mysql | sqlite | clickhouse | bigquery
//! dsn = "{{secret:WAREHOUSE_DSN}}"          # postgres://user:password@host:5432/db?sslmode=require
//! description = "orders and customers (read replica)"
//! [integrations.data.sources.local]
//! kind = "sqlite"
//! path = "~/data/sales.db"
//! [integrations.data.sources.events]
//! kind = "clickhouse"
//! dsn = "{{secret:CLICKHOUSE_DSN}}"         # http://user:password@ch.internal:8123/default
//! [integrations.data.sources.bq]
//! kind = "bigquery"
//! project = "my-project"
//! dataset = "analytics"                     # for sql_schema
//! token = "{{secret:BQ_TOKEN}}"             # OAuth bearer token (e.g. from `gcloud auth print-access-token`)
//! # Legacy enterprise databases through their stock clients (on PATH or `client = [...]`):
//! [integrations.data.sources.erp]
//! kind = "sqlserver"                        # sqlcmd; no user in the DSN = Kerberos (-E)
//! dsn = "{{secret:ERP_DSN}}"                # sqlserver://user:password@sql01:1433/ERP?trust_server_certificate=true
//! [integrations.data.sources.gl]
//! kind = "oracle"                           # sqlplus 12.2+
//! dsn = "{{secret:GL_DSN}}"                 # oracle://user:password@ora01:1521/SERVICE_NAME
//! [integrations.data.sources.as400]
//! kind = "odbc"                             # unixODBC isql; the DSN lives in odbc.ini
//! dsn = "odbc://DB2PROD"
//! ```
//!
//! The model names a **source**, never a connection string: credentials stay in the vault and
//! a prompt-injected "connect to attacker.example" has nothing to attach to.
//!
//! Read-only is enforced twice (see [`guard`] and [`backends`]): the statement must be a single
//! `SELECT` / `WITH` / `EXPLAIN` / `SHOW` free of write words, comments and side-effecting
//! functions, **and** the connection itself is read-only (read-only transaction, read-only
//! file, `readonly=1`). A result is cut at `max_rows` rows and 256 KiB, and arrives wrapped as
//! untrusted external content: cell values are data, not instructions.
//!
//! CSV / xlsx files and charts need no tool of their own: the code-execution tool and the
//! `xlsx` skill already do them, and `sql-data-analysis` (share/skills) wires the workflow.

pub mod backends;
pub mod dsn;
pub mod guard;

use ark_core::tool::{arg_opt_str, arg_opt_u64, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use backends::{Limits, Rows};
use dsn::Dsn;
use guard::{check_read_only, Dialect};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// Hard ceiling for `max_rows`, whatever the config or the model asks.
pub const HARD_MAX_ROWS: usize = 10_000;
pub const DEFAULT_MAX_ROWS: usize = 1000;
pub const DEFAULT_TIMEOUT: u64 = 30;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SourceCfg {
    pub kind: String,
    pub dsn: Option<String>,
    /// Environment variable (or vault secret) holding the connection string.
    pub dsn_env: Option<String>,
    /// SQLite file.
    pub path: Option<String>,
    /// Command prefix replacing `psql` / `mysql` (e.g. `["podman", "exec", "-i", "pg", "psql"]`).
    pub client: Vec<String>,
    pub description: String,
    /// BigQuery.
    pub project: Option<String>,
    pub dataset: Option<String>,
    pub token: Option<String>,
    pub token_env: Option<String>,
    pub api_base: Option<String>,
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DataConfig {
    pub enabled: Option<bool>,
    pub max_rows: Option<usize>,
    pub timeout_seconds: Option<u64>,
    pub sources: BTreeMap<String, SourceCfg>,
}

impl DataConfig {
    pub fn from_value(v: Value) -> Result<DataConfig, String> {
        let cfg: DataConfig = if v.is_null() { DataConfig::default() } else { serde_json::from_value(v).map_err(|e| format!("[integrations.data]: {e}"))? };
        for (name, s) in &cfg.sources {
            let d = backends::dialect_of(&s.kind).ok_or_else(|| format!("[integrations.data.sources.{name}]: kind `{}` is not one of postgres, mysql, sqlite, clickhouse, bigquery, sqlserver, oracle, odbc", s.kind))?;
            let has = |a: &Option<String>| a.as_deref().is_some_and(|x| !x.trim().is_empty());
            let ok = match d {
                Dialect::Sqlite => has(&s.path),
                Dialect::BigQuery => has(&s.project) && (has(&s.token) || has(&s.token_env)),
                _ => has(&s.dsn) || has(&s.dsn_env),
            };
            if !ok {
                return Err(format!("[integrations.data.sources.{name}]: {} needs {}", s.kind, match d { Dialect::Sqlite => "`path`", Dialect::BigQuery => "`project` and `token`", _ => "`dsn` (or `dsn_env`)" }));
            }
        }
        Ok(cfg)
    }
    fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true) && !self.sources.is_empty()
    }
    fn max_rows(&self, s: &SourceCfg, asked: Option<u64>) -> usize {
        let cfg = s.max_rows.or(self.max_rows).unwrap_or(DEFAULT_MAX_ROWS).clamp(1, HARD_MAX_ROWS);
        asked.map(|a| (a as usize).clamp(1, cfg)).unwrap_or(cfg)
    }
    fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT).clamp(1, 600))
    }
}

/// `sql_query` and `sql_schema` when at least one source is configured.
pub fn tools(cfg: Value) -> Result<Vec<Arc<dyn Tool>>, String> {
    let cfg = Arc::new(DataConfig::from_value(cfg)?);
    if !cfg.enabled() {
        return Ok(vec![]);
    }
    Ok(vec![Arc::new(SqlQuery { cfg: cfg.clone() }), Arc::new(SqlSchema { cfg })])
}

fn secret(ctx: &ToolCtx, raw: &str) -> Result<String, String> {
    let v = (ctx.secrets)(raw.trim());
    if let Some(i) = v.find("{{secret:") {
        let name: String = v[i + 9..].chars().take_while(|c| *c != '}').collect();
        return Err(format!("secret `{name}` is not set; store it in the vault ({{{{secret:{name}}}}}) or the environment"));
    }
    Ok(v)
}

fn env_or_secret(ctx: &ToolCtx, name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty()).or_else(|| {
        let ph = format!("{{{{secret:{name}}}}}");
        let v = (ctx.secrets)(&ph);
        (v != ph && !v.trim().is_empty()).then_some(v)
    })
}

fn dsn_of(ctx: &ToolCtx, s: &SourceCfg) -> Result<Dsn, String> {
    let raw = match (&s.dsn, &s.dsn_env) {
        (Some(d), _) if !d.trim().is_empty() => secret(ctx, d)?,
        (_, Some(e)) => env_or_secret(ctx, e).ok_or_else(|| format!("neither the environment nor the vault has `{e}`"))?,
        _ => return Err("no connection string configured".into()),
    };
    Dsn::parse(&raw).map_err(|e| format!("connection string: {e}"))
}

fn sqlite_path(ctx: &ToolCtx, s: &SourceCfg) -> std::path::PathBuf {
    ctx.resolve(s.path.as_deref().unwrap_or(""))
}

fn pick<'a>(cfg: &'a DataConfig, input: &Value) -> Result<(&'a str, &'a SourceCfg), String> {
    match arg_opt_str(input, "source") {
        Some(n) => cfg.sources.get_key_value(n).map(|(k, v)| (k.as_str(), v)).ok_or_else(|| format!("unknown source `{n}`; configured sources: {}", cfg.sources.keys().cloned().collect::<Vec<_>>().join(", "))),
        None if cfg.sources.len() == 1 => cfg.sources.iter().next().map(|(k, v)| (k.as_str(), v)).ok_or_else(|| "no sources".into()),
        None => Err(format!("name a `source`: {}", cfg.sources.keys().cloned().collect::<Vec<_>>().join(", "))),
    }
}

/// Run one already-checked statement on `s`. Layer 1 is inside `backends`.
fn execute(ctx: &ToolCtx, cfg: &DataConfig, s: &SourceCfg, sql: &str, max_rows: usize) -> Result<Rows, String> {
    let lim = Limits { max_rows, timeout: cfg.timeout(), cancel: ctx.cancel.clone() };
    match backends::dialect_of(&s.kind).ok_or("unknown kind")? {
        Dialect::Sqlite => backends::sqlite(&sqlite_path(ctx, s), sql, &lim),
        Dialect::Postgres => backends::postgres(&dsn_of(ctx, s)?, &s.client, sql, &lim),
        Dialect::Mysql => backends::mysql(&dsn_of(ctx, s)?, &s.client, sql, &lim, s.kind == "mariadb"),
        Dialect::ClickHouse => backends::clickhouse(&dsn_of(ctx, s)?, sql, &lim),
        Dialect::SqlServer => backends::sqlserver(&dsn_of(ctx, s)?, &s.client, sql, &lim),
        Dialect::Oracle => backends::oracle(&dsn_of(ctx, s)?, &s.client, sql, &lim),
        Dialect::Odbc => backends::odbc(&dsn_of(ctx, s)?, &s.client, sql, &lim),
        Dialect::BigQuery => {
            let token = match (&s.token, &s.token_env) {
                (Some(t), _) if !t.trim().is_empty() => secret(ctx, t)?,
                (_, Some(e)) => env_or_secret(ctx, e).ok_or_else(|| format!("neither the environment nor the vault has `{e}`"))?,
                _ => return Err("no token configured".into()),
            };
            backends::bigquery(s.api_base.as_deref().unwrap_or("https://bigquery.googleapis.com"), s.project.as_deref().unwrap_or(""), &token, sql, &lim)
        }
    }
}

fn render(name: &str, s: &SourceCfg, r: &Rows, max_rows: usize) -> String {
    let mut v = json!({"source": name, "kind": s.kind, "read_only": true, "columns": r.columns, "rows": r.rows, "row_count": r.rows.len(), "max_rows": max_rows, "truncated": r.truncated});
    if r.truncated {
        v["note"] = json!("The result was cut at the row/size limit. Aggregate (GROUP BY, COUNT) or add WHERE / LIMIT instead of reading everything.");
    }
    crate::web::content::wrap(&serde_json::to_string_pretty(&v).unwrap_or_default(), "sql_query", true)
}

fn effects_for(ctx: &ToolCtx, cfg: &DataConfig, input: &Value) -> Vec<Effect> {
    let Ok((_, s)) = pick(cfg, input) else { return vec![] };
    match backends::dialect_of(&s.kind) {
        Some(Dialect::Sqlite) => vec![Effect::Read { path: sqlite_path(ctx, s) }],
        Some(Dialect::BigQuery) => vec![Effect::Net { dest: s.api_base.clone().unwrap_or_else(|| "https://bigquery.googleapis.com".into()), payload: String::new() }],
        Some(_) => vec![Effect::Net { dest: dsn_of(ctx, s).map(|d| d.dest()).unwrap_or_else(|_| "database".into()), payload: String::new() }],
        None => vec![],
    }
}

pub struct SqlQuery {
    cfg: Arc<DataConfig>,
}

impl Tool for SqlQuery {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "sql_query".into(),
            description: format!(
                "Run ONE read-only SQL statement (SELECT / WITH / EXPLAIN / SHOW) on a configured database and return rows as JSON. Writes, DDL, comments, multiple statements and file/sleep functions are refused, and the connection is read-only as well. Results are cut at max_rows (default {DEFAULT_MAX_ROWS}) — aggregate instead of dumping tables. Look at the structure with sql_schema first. Sources: {}.",
                self.cfg.sources.iter().map(|(n, s)| if s.description.is_empty() { format!("{n} ({})", s.kind) } else { format!("{n} ({}: {})", s.kind, s.description) }).collect::<Vec<_>>().join("; ")
            ),
            input_schema: json!({"type":"object","properties":{
                "source":{"type":"string","description":"Configured source name (optional when only one exists)"},
                "sql":{"type":"string","description":"One SELECT/WITH/EXPLAIN/SHOW statement, no comments"},
                "max_rows":{"type":"integer","minimum":1,"description":"Lower the row cap for this call"}},"required":["sql"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        effects_for(ctx, &self.cfg, input)
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let run = || -> Result<String, String> {
            let (name, s) = pick(&self.cfg, &input)?;
            let sql = arg_str(&input, "sql")?;
            let d = backends::dialect_of(&s.kind).ok_or("unknown kind")?;
            let stmt = check_read_only(sql, d).map_err(|e| format!("refused (read-only source `{name}`): {e}"))?;
            let max = self.cfg.max_rows(s, arg_opt_u64(&input, "max_rows"));
            let rows = execute(ctx, &self.cfg, s, &stmt, max)?;
            Ok(render(name, s, &rows, max))
        };
        match run() {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

pub struct SqlSchema {
    cfg: Arc<DataConfig>,
}

/// Table names are interpolated into a catalog query: letters, digits and a few separators only.
fn ident_ok(t: &str) -> bool {
    !t.is_empty() && t.len() <= 200 && t.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '$' | '-' | ' '))
}

fn lit(t: &str) -> String {
    t.replace('\'', "''")
}

/// The catalog query for `table` (None = list tables) in `d`.
pub fn schema_sql(d: Dialect, s: &SourceCfg, table: Option<&str>) -> Result<String, String> {
    if let Some(t) = table {
        if !ident_ok(t) {
            return Err("table names may only contain letters, digits and _ . $ - space".into());
        }
    }
    let (schema, tbl) = match table.map(|t| t.rsplit_once('.')) {
        Some(Some((a, b))) => (Some(a), Some(b)),
        Some(None) => (None, table),
        None => (None, None),
    };
    Ok(match (d, tbl) {
        (Dialect::Postgres, None) => "SELECT table_schema, table_name, table_type FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1, 2".into(),
        (Dialect::Postgres, Some(t)) => format!("SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_name = '{}'{} ORDER BY table_schema, ordinal_position", lit(t), schema.map(|s| format!(" AND table_schema = '{}'", lit(s))).unwrap_or_default()),
        (Dialect::Mysql, None) => "SELECT table_schema, table_name, table_type FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY 1, 2".into(),
        (Dialect::Mysql, Some(t)) => format!("SELECT column_name, column_type, is_nullable, column_key, column_default FROM information_schema.columns WHERE table_name = '{}' AND table_schema = {} ORDER BY ordinal_position", lit(t), schema.map(|s| format!("'{}'", lit(s))).unwrap_or_else(|| "DATABASE()".into())),
        (Dialect::Sqlite, None) => "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name".into(),
        (Dialect::Sqlite, Some(t)) => format!("SELECT name, type, \"notnull\", pk FROM pragma_table_info('{}')", lit(t)),
        (Dialect::ClickHouse, None) => "SELECT database, name, engine FROM system.tables WHERE database NOT IN ('system','INFORMATION_SCHEMA','information_schema') ORDER BY 1, 2".into(),
        (Dialect::ClickHouse, Some(t)) => format!("SELECT name, type, default_kind FROM system.columns WHERE table = '{}'{} ORDER BY position", lit(t), schema.map(|s| format!(" AND database = '{}'", lit(s))).unwrap_or_default()),
        (Dialect::SqlServer | Dialect::Odbc, None) => "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES ORDER BY 1, 2".into(),
        (Dialect::SqlServer | Dialect::Odbc, Some(t)) => format!("SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{}'{} ORDER BY TABLE_SCHEMA, ORDINAL_POSITION", lit(t), schema.map(|s| format!(" AND TABLE_SCHEMA = '{}'", lit(s))).unwrap_or_default()),
        (Dialect::Oracle, None) => "SELECT owner, table_name FROM all_tables WHERE owner NOT IN ('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','WMSYS','OUTLN','DBSNMP','APPQOSSYS','GSMADMIN_INTERNAL','LBACSYS','OJVMSYS','DVSYS','AUDSYS') ORDER BY 1, 2".into(),
        (Dialect::Oracle, Some(t)) => format!("SELECT column_name, data_type, nullable, data_default FROM all_tab_columns WHERE table_name = UPPER('{}'){} ORDER BY owner, column_id", lit(t), schema.map(|s| format!(" AND owner = UPPER('{}')", lit(s))).unwrap_or_default()),
        (Dialect::BigQuery, t) => {
            let ds = schema.map(str::to_string).or_else(|| s.dataset.clone()).ok_or("BigQuery needs `dataset` on the source (or write dataset.table)")?;
            if !ident_ok(&ds) || ds.contains(' ') {
                return Err("bad dataset name".into());
            }
            match t {
                None => format!("SELECT table_name, table_type FROM `{ds}`.INFORMATION_SCHEMA.TABLES ORDER BY 1"),
                Some(t) => format!("SELECT column_name, data_type, is_nullable FROM `{ds}`.INFORMATION_SCHEMA.COLUMNS WHERE table_name = '{}' ORDER BY ordinal_position", lit(t)),
            }
        }
    })
}

impl Tool for SqlSchema {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "sql_schema".into(),
            description: "Explore a database before querying it: with no `source`, list the configured sources; with a source, list its tables; with `table` (optionally schema.table), list that table's columns and types. Read-only.".into(),
            input_schema: json!({"type":"object","properties":{
                "source":{"type":"string","description":"Configured source name; omit to list sources"},
                "table":{"type":"string","description":"Table (or schema.table) whose columns to list"}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        if input.get("source").is_none() {
            return vec![];
        }
        effects_for(ctx, &self.cfg, input)
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if arg_opt_str(&input, "source").is_none() && self.cfg.sources.len() != 1 {
            let list: Vec<Value> = self.cfg.sources.iter().map(|(n, s)| json!({"source": n, "kind": s.kind, "description": s.description})).collect();
            return ToolOutput::ok(serde_json::to_string_pretty(&json!({"sources": list})).unwrap_or_default());
        }
        let run = || -> Result<String, String> {
            let (name, s) = pick(&self.cfg, &input)?;
            let d = backends::dialect_of(&s.kind).ok_or("unknown kind")?;
            let sql = schema_sql(d, s, arg_opt_str(&input, "table"))?;
            let stmt = check_read_only(&sql, d)?;
            let max = self.cfg.max_rows(s, None);
            let rows = execute(ctx, &self.cfg, s, &stmt, max)?;
            Ok(render(name, s, &rows, max))
        };
        match run() {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests;
