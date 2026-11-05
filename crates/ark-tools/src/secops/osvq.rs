//! `osv_query` (pro-026): general vulnerability lookups against OSV.dev (or a mirror) — not
//! only the MAL-* malware check the launcher does. Packages by name/version/ecosystem, every
//! pin of a lockfile (Cargo.lock, requirements.txt, package.json, package-lock.json), or
//! advisory ids (CVE / GHSA / RUSTSEC / PYSEC) with their aliases and fixed versions.

use crate::ops::{arg, arg_list, cap_output, Integrations};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_security::osv::{self, Component};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct OsvQuery {
    pub cfg: Arc<Integrations>,
}

impl OsvQuery {
    fn base(&self) -> String {
        self.cfg.str("osv", "url").unwrap_or_else(osv::endpoint).trim_end_matches('/').to_string()
    }
}

/// Components from a lockfile, by file name.
pub fn lockfile_components(name: &str, text: &str) -> Result<Vec<Component>, String> {
    let n = name.rsplit('/').next().unwrap_or(name);
    Ok(match n {
        "Cargo.lock" => osv::components_from_cargo_lock(text, n),
        "package-lock.json" | "npm-shrinkwrap.json" => osv::pins_from_package_lock(text, n),
        "package.json" => osv::pins_from_package_json(text, n),
        x if x.ends_with(".txt") || x.starts_with("requirements") => osv::pins_from_requirements(text, n),
        _ => return Err(format!("{n}: supported lockfiles are Cargo.lock, package-lock.json, package.json and requirements*.txt")),
    })
}

impl Tool for OsvQuery {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "osv_query".into(),
            description: "Look up known vulnerabilities (all CVEs/GHSAs, not only malware) in OSV.dev: `packages` [{name, version, ecosystem: npm|PyPI|crates.io|Go|Maven|…}], a `lockfile` (Cargo.lock, package-lock.json, package.json, requirements.txt), or advisory `ids` (CVE-…, GHSA-…). Returns severity, aliases and fixed versions, most severe first. Sends package names and versions to the OSV endpoint.".into(),
            input_schema: json!({"type":"object","properties":{
                "packages":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"version":{"type":"string"},"ecosystem":{"type":"string"}},"required":["name","version","ecosystem"]}},
                "lockfile":{"type":"string"},"ids":{"type":"array","items":{"type":"string"}}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut fx = vec![];
        let mut sent: Vec<String> = input["packages"].as_array().into_iter().flatten().map(|p| format!("{}@{}", p["name"].as_str().unwrap_or(""), p["version"].as_str().unwrap_or(""))).collect();
        sent.extend(arg_list(input, "ids"));
        if let Some(l) = arg(input, "lockfile") {
            fx.push(Effect::Read { path: ctx.resolve(l) });
            sent.push(format!("(pins of {l})"));
        }
        fx.push(Effect::Net { dest: self.base(), payload: sent.join(" ") });
        fx
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let base = self.base();
        let mut comps: Vec<Component> = vec![];
        for p in input["packages"].as_array().into_iter().flatten() {
            let (Some(n), Some(v), Some(e)) = (p["name"].as_str(), p["version"].as_str(), p["ecosystem"].as_str()) else { return ToolOutput::err("each package needs name, version and ecosystem") };
            comps.push(Component { name: n.trim().into(), version: v.trim().into(), ecosystem: e.trim().into(), source: "query".into() });
        }
        if let Some(l) = arg(&input, "lockfile") {
            let path = ctx.resolve(l);
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => return ToolOutput::err(format!("cannot read {}: {e}", path.display())),
            };
            match lockfile_components(&path.to_string_lossy(), &text) {
                Ok(c) => comps.extend(c),
                Err(e) => return ToolOutput::err(e),
            }
        }
        let ids = arg_list(&input, "ids");
        if comps.is_empty() && ids.is_empty() {
            return ToolOutput::err("give `packages`, a `lockfile` or advisory `ids`");
        }
        let mut out = json!({"endpoint": base});
        if !comps.is_empty() {
            match osv::audit_at(&base, &comps) {
                Ok(f) => {
                    out["packages_checked"] = json!(comps.len());
                    out["findings"] = json!(f.iter().map(|f| json!({"package": f.component.name, "version": f.component.version, "ecosystem": f.component.ecosystem, "source": f.component.source, "id": f.vuln.id, "aliases": f.vuln.aliases, "severity": f.vuln.severity, "summary": f.vuln.summary, "fixed": f.vuln.fixed})).collect::<Vec<_>>());
                }
                Err(e) => return ToolOutput::err(e),
            }
        }
        if !ids.is_empty() {
            let adv: Vec<Value> = ids.iter().take(50).map(|id| match osv::vuln_at(&base, id) {
                Ok(v) => json!({"id": v.id, "aliases": v.aliases, "severity": v.severity, "summary": v.summary, "fixed": v.fixed}),
                Err(e) => json!({"id": id, "error": e}),
            }).collect();
            out["advisories"] = json!(adv);
        }
        ToolOutput::ok(cap_output(ctx, "osv_query", serde_json::to_string_pretty(&out).unwrap_or_default(), 30_000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::FakeServer;

    #[test]
    fn lockfile_packages_and_ids_query_the_configured_endpoint() {
        let ctx = crate::testutil::ctx("secops-osv");
        let rec = json!({"id":"GHSA-35jh","aliases":["CVE-2021-23337"],"summary":"Command injection in lodash","database_specific":{"severity":"HIGH"},"affected":[{"ranges":[{"events":[{"fixed":"4.17.21"}]}]}]}).to_string();
        let srv = FakeServer::start(vec![
            ("POST /v1/querybatch", 200, "application/json", json!({"results":[{"vulns":[{"id":"GHSA-35jh"}]}]}).to_string()),
            ("GET /v1/vulns/GHSA-35jh", 200, "application/json", rec.clone()),
            ("GET /v1/vulns/CVE-2021-23337", 200, "application/json", rec),
        ]);
        std::fs::write(ctx.workspace.join("package-lock.json"), r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#).unwrap();
        let t = OsvQuery { cfg: Arc::new(Integrations::new(json!({"osv": {"url": srv.url}}))) };
        let input = json!({"lockfile": "package-lock.json", "ids": ["CVE-2021-23337"]});
        let fx = t.effects(&ctx, &input);
        assert!(matches!(&fx[1], Effect::Net { dest, .. } if dest == &srv.url));
        let o = t.call(&ctx, input);
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["findings"][0]["aliases"][0], "CVE-2021-23337");
        assert_eq!(v["findings"][0]["fixed"][0], "4.17.21");
        assert_eq!(v["advisories"][0]["severity"], "HIGH");
        assert_eq!(srv.requests()[0].json()["queries"][0]["package"]["name"], "lodash");
        assert!(lockfile_components("go.sum", "").is_err());
        assert!(t.call(&ctx, json!({})).is_error);
    }
}
