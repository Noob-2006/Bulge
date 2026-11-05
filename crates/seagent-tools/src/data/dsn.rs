//! Connection strings: `scheme://user:password@host:port/database?key=value`.
//!
//! The model never supplies one. They come from `[integrations.data.sources.<name>]`, usually as
//! `dsn = "{{secret:NAME}}"`, and are split here so the password travels in an environment
//! variable (`PGPASSWORD`, `MYSQL_PWD`) or an HTTP header, never on a command line.

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Dsn {
    pub scheme: String,
    pub user: String,
    pub password: String,
    pub host: String,
    pub port: Option<u16>,
    pub database: String,
    pub query: Vec<(String, String)>,
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Dsn {
    pub fn parse(raw: &str) -> Result<Dsn, String> {
        let raw = raw.trim();
        let (scheme, rest) = raw.split_once("://").ok_or("connection string must look like scheme://user:password@host:port/database")?;
        let (rest, query) = match rest.split_once('?') {
            Some((a, q)) => (a, q),
            None => (rest, ""),
        };
        let (auth, hostpart) = match rest.rsplit_once('@') {
            Some((a, h)) => (Some(a), h),
            None => (None, rest),
        };
        let (hostport, db) = match hostpart.split_once('/') {
            Some((h, d)) => (h, d),
            None => (hostpart, ""),
        };
        let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
            let (h, p) = r.split_once(']').ok_or("unterminated [ipv6] host")?;
            (h.to_string(), p.strip_prefix(':').filter(|p| !p.is_empty()).map(str::to_string))
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p.to_string())),
                None => (hostport.to_string(), None),
            }
        };
        let port = match port {
            Some(p) => Some(p.parse::<u16>().map_err(|_| format!("bad port `{p}`"))?),
            None => None,
        };
        if host.is_empty() && !scheme.eq_ignore_ascii_case("unix") {
            return Err("connection string has no host".into());
        }
        let (user, password) = match auth {
            Some(a) => match a.split_once(':') {
                Some((u, p)) => (percent_decode(u), percent_decode(p)),
                None => (percent_decode(a), String::new()),
            },
            None => (String::new(), String::new()),
        };
        let query = query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (percent_decode(k), percent_decode(v))
            })
            .collect();
        Ok(Dsn { scheme: scheme.to_ascii_lowercase(), user, password, host, port, database: percent_decode(db), query })
    }

    pub fn param(&self, k: &str) -> Option<&str> {
        self.query.iter().find(|(a, _)| a.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }

    /// `host` or `host:port`, for the gate effect.
    pub fn dest(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.host),
            None => self.host.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_every_part_and_decodes() {
        let d = Dsn::parse("postgres://app%40corp:p%2Fw%3Ad@db.internal:6432/sales?sslmode=require&application_name=seagent").unwrap();
        assert_eq!((d.scheme.as_str(), d.user.as_str(), d.password.as_str(), d.host.as_str(), d.port, d.database.as_str()), ("postgres", "app@corp", "p/w:d", "db.internal", Some(6432), "sales"));
        assert_eq!(d.param("sslmode"), Some("require"));
        assert_eq!(d.dest(), "db.internal:6432");
        let d = Dsn::parse("mysql://root@[::1]/").unwrap();
        assert_eq!((d.host.as_str(), d.port, d.password.as_str(), d.database.as_str()), ("::1", None, "", ""));
        let d = Dsn::parse("http://u:p@ch:8123").unwrap();
        assert_eq!((d.host.as_str(), d.port, d.database.as_str()), ("ch", Some(8123), ""));
        assert!(Dsn::parse("not a url").is_err());
        assert!(Dsn::parse("postgres://:5432/x").is_err());
        assert!(Dsn::parse("postgres://h:99999/x").is_err());
    }
}
