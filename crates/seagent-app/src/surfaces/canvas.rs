//! Canvas: hosted documents, A2UI surfaces and the `canvas` tool (OpenClaw
//! extensions/canvas + src/canvas, MIT).
//!
//! - Hosted documents live in `<surfaces>/canvas/documents/<id>/` and are served at
//!   `/surfaces/canvas/documents/<id>/<file>` (unguessable `cv_…` ids are the capability),
//!   with a `sandbox allow-scripts` CSP so they never run as the UI's origin.
//! - A2UI JSONL (v0.8 or v0.9 messages) is validated, stored per document and rendered by a
//!   small built-in renderer at `/surfaces/a2ui/<id>`; nodes render it locally.
//! - The `canvas` tool drives a paired node's canvas: present / hide / navigate / eval /
//!   snapshot / a2ui_push / a2ui_reset. Linux nodes implement those through a browser's
//!   DevTools endpoint (`cdp_url` in node.toml); without one, present / navigate fall back
//!   to `xdg-open` and the rest are unavailable.

use super::{esc_html, now_ms, read_json, write_atomic, write_json, Env};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use seagent_net::httpd::Response;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `[surfaces.canvas]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CanvasConfig {
    /// Serve hosted documents and A2UI surfaces, and offer node-panel presentation.
    /// Default true; `SEAGENT_SKIP_CANVAS_HOST=1` also turns it off.
    pub host_enabled: bool,
}

impl Default for CanvasConfig {
    fn default() -> Self {
        CanvasConfig { host_enabled: true }
    }
}

impl CanvasConfig {
    pub fn enabled(&self) -> bool {
        self.host_enabled && !std::env::var("SEAGENT_SKIP_CANVAS_HOST").is_ok_and(|v| v == "1" || v == "true")
    }
}

pub const DOCUMENTS_PATH: &str = "/surfaces/canvas/documents";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub id: String,
    /// html_bundle | a2ui
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub created_at: String,
    pub created_ms: u64,
    pub entry_url: String,
    pub local_entrypoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_scope: Option<String>,
}

fn docs_dir(dir: &Path) -> PathBuf {
    dir.join("canvas/documents")
}

fn valid_doc_id(id: &str) -> bool {
    !id.is_empty() && id != "." && id != ".." && id.len() <= 80 && id.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// Store an HTML document; keeps at most `max_per_scope` per retention scope (oldest go).
pub fn create_document(dir: &Path, title: &str, html: &str, scope: Option<&str>, max_per_scope: usize) -> Result<Manifest, String> {
    create(dir, "html_bundle", title, "index.html", html.as_bytes(), scope, max_per_scope)
}

fn create(dir: &Path, kind: &str, title: &str, entry: &str, body: &[u8], scope: Option<&str>, max_per_scope: usize) -> Result<Manifest, String> {
    let id = format!("cv_{}", seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(16)));
    let root = docs_dir(dir).join(&id);
    write_atomic(&root.join(entry), body)?;
    let scope = scope.map(|s| seagent_net::crypto::hex(&seagent_net::crypto::sha256(s.as_bytes())));
    let now = now_ms();
    let m = Manifest { id: id.clone(), kind: kind.into(), title: Some(title.trim().to_string()).filter(|t| !t.is_empty()), created_at: super::iso(now), created_ms: now, entry_url: format!("{DOCUMENTS_PATH}/{id}/{entry}"), local_entrypoint: entry.into(), retention_scope: scope.clone() };
    write_json(&root.join("manifest.json"), &m)?;
    if let Some(s) = scope.filter(|_| max_per_scope > 0) {
        prune(dir, &s, max_per_scope);
    }
    Ok(m)
}

fn prune(dir: &Path, scope: &str, keep: usize) {
    let mut docs: Vec<(u64, String)> = std::fs::read_dir(docs_dir(dir))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| read_json::<Manifest>(&e.path().join("manifest.json")))
        .filter(|m| m.retention_scope.as_deref() == Some(scope))
        .map(|m| (m.created_ms, m.id))
        .collect();
    docs.sort();
    let n = docs.len().saturating_sub(keep);
    for (_, id) in docs.into_iter().take(n) {
        let _ = std::fs::remove_dir_all(docs_dir(dir).join(id));
    }
}

fn mime_of(p: &str) -> &'static str {
    match p.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// `GET /surfaces/canvas/documents/<id>/<path>`
pub fn serve_document(dir: &Path, rest: &str) -> Response {
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    let parts: Vec<String> = rest.split('/').filter(|s| !s.is_empty()).map(seagent_net::urldecode).collect();
    let nf = || Response::text(404, "not found");
    let Some((id, file)) = parts.split_first() else { return nf() };
    if !valid_doc_id(id) || file.is_empty() || file.iter().any(|p| p == "." || p == ".." || p.contains([':', '\\', '\0']) || p.chars().any(char::is_control)) {
        return nf();
    }
    let root = docs_dir(dir).join(id);
    let p = root.join(file.join("/"));
    let (Ok(real), Ok(base)) = (p.canonicalize(), root.canonicalize()) else { return nf() };
    if !real.starts_with(&base) || !real.is_file() || real.file_name().is_some_and(|f| f == "manifest.json") {
        return nf();
    }
    let Ok(body) = std::fs::read(&real) else { return nf() };
    let ct = mime_of(&file.join("/"));
    let r = Response::new(200, ct, body);
    if ct.starts_with("text/html") {
        // Direct opens get an opaque origin: widget script never runs as the UI's origin.
        return r.with_header("content-security-policy", "sandbox allow-scripts allow-popups; frame-ancestors *");
    }
    r
}

// ───────────────────────── A2UI ─────────────────────────

const V08_KEYS: &[&str] = &["beginRendering", "surfaceUpdate", "dataModelUpdate", "deleteSurface"];
const V09_KEYS: &[&str] = &["createSurface", "updateComponents", "updateDataModel", "deleteSurface"];

/// Validate A2UI JSONL (OpenClaw validateSupportedA2UIJsonl): one action key per line,
/// v0.8 unversioned or v0.9 with `version`, never mixed. Returns (version, messages).
pub fn validate_jsonl(jsonl: &str) -> Result<(String, Vec<Value>), String> {
    let mut errors = Vec::new();
    let (mut v08, mut v09, mut count) = (false, false, 0);
    let mut msgs = Vec::new();
    for (i, line) in jsonl.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        count += 1;
        let n = i + 1;
        let obj: Value = match serde_json::from_str(t) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("line {n}: {e}"));
                continue;
            }
        };
        let Some(rec) = obj.as_object() else {
            errors.push(format!("line {n}: expected JSON object"));
            continue;
        };
        let ver = rec.get("version");
        if ver == Some(&json!("v0.8")) {
            errors.push(format!("line {n}: A2UI v0.8 messages must not include a version field"));
            continue;
        }
        if ver.is_some_and(|v| v != "v0.9") {
            errors.push(format!("line {n}: unsupported A2UI version: {}", ver.unwrap()));
            continue;
        }
        let is9 = ver.is_some();
        let keys: Vec<&&str> = (if is9 { V09_KEYS } else { V08_KEYS }).iter().filter(|k| rec.contains_key(**k)).collect();
        if keys.len() != 1 {
            errors.push(format!("line {n}: expected exactly one {} action key", if is9 { "v0.9" } else { "v0.8" }));
            continue;
        }
        let key = *keys[0];
        if rec.keys().any(|k| k != key && !(is9 && k == "version")) {
            errors.push(format!("line {n}: unexpected top-level A2UI field"));
            continue;
        }
        let payload = &rec[key];
        if !payload.is_object() {
            errors.push(format!("line {n}: action payload must be an object"));
            continue;
        }
        if payload["surfaceId"].as_str().is_none_or(|s| s.is_empty()) {
            errors.push(format!("line {n}: {key}.surfaceId must be a non-empty string"));
            continue;
        }
        if matches!(key, "surfaceUpdate" | "updateComponents") && !payload["components"].is_array() {
            errors.push(format!("line {n}: {key}.components must be an array"));
            continue;
        }
        if is9 { v09 = true } else { v08 = true }
        msgs.push(obj);
    }
    if count == 0 {
        errors.push("no JSONL messages found".into());
    }
    if v08 && v09 {
        errors.push("mixed A2UI v0.8 and v0.9 messages in one file".into());
    }
    if !errors.is_empty() {
        return Err(format!("Invalid A2UI JSONL:\n- {}", errors.join("\n- ")));
    }
    Ok((if v09 { "v0.9" } else { "v0.8" }.into(), msgs))
}

/// A self-contained A2UI renderer page (Text, Heading, Column, Row, List, Card, Button,
/// Image, Divider, TextField, CheckBox; literal and data-model bound values).
/// `window.seagentA2ui.apply(messages)` / `.reset()` drive it; `initial` is applied on load.
pub fn renderer_html(title: &str, initial: &[Value]) -> String {
    let init = serde_json::to_string(initial).unwrap_or("[]".into()).replace("</", "<\\/");
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{}</title><style>body{{font:14px/1.5 system-ui,sans-serif;margin:12px;color:#222;background:#fafafa}}@media (prefers-color-scheme:dark){{body{{color:#ddd;background:#111}}}}.a2-col{{display:flex;flex-direction:column;gap:8px}}.a2-row{{display:flex;gap:8px;flex-wrap:wrap;align-items:center}}.a2-card{{border:1px solid #8884;border-radius:10px;padding:12px}}.a2-surface{{margin-bottom:16px}}img{{max-width:100%}}button{{padding:6px 14px;border-radius:8px;border:1px solid #8886;cursor:pointer}}</style></head><body><div id="root"></div><script>
(()=>{{const S=new Map();const root=document.getElementById('root');
const get=(m,p)=>{{if(!p)return undefined;let c=m;for(const k of String(p).replace(/^\//,'').split('/').filter(Boolean)){{if(c==null)return undefined;c=c[k];}}return c;}};
const set=(m,p,v)=>{{const ks=String(p||'').replace(/^\//,'').split('/').filter(Boolean);if(!ks.length){{Object.assign(m,v);return;}}let c=m;ks.slice(0,-1).forEach(k=>{{c[k]=c[k]&&typeof c[k]==='object'?c[k]:{{}};c=c[k];}});c[ks[ks.length-1]]=v;}};
const val=(s,v)=>{{if(v==null)return '';if(typeof v!=='object')return String(v);if('literalString'in v)return v.literalString;if('literalNumber'in v)return String(v.literalNumber);if('literalBoolean'in v)return String(v.literalBoolean);if('path'in v){{const x=get(s.data,v.path);return x==null?'':typeof x==='object'?JSON.stringify(x):String(x);}}return '';}};
const kids=(c)=>{{const k=c.children||c.child;if(!k)return [];if(Array.isArray(k))return k;if(k.explicitList)return k.explicitList;if(typeof k==='string')return [k];return [];}};
const surf=(id)=>{{if(!S.has(id))S.set(id,{{comps:new Map(),data:{{}},root:null}});return S.get(id);}};
const toData=(contents)=>{{const o={{}};for(const e of contents||[]){{const v=e.valueString??e.valueNumber??e.valueBoolean??(e.valueMap?toData(e.valueMap):undefined);o[e.key]=v;}}return o;}};
function node(s,id,depth){{const c=s.comps.get(id);const el=document.createElement('div');if(!c||depth>40)return el;
const [type,p]=c.type?[c.type,c]:Object.entries(c.component||{{}})[0]||['',{{}}];
switch(type){{case 'Text':case 'Heading':{{const h=document.createElement(type==='Heading'||/^h[1-5]$/.test(p.usageHint||'')?'h3':'p');h.textContent=val(s,p.text);return h;}}
case 'Column':case 'List':el.className='a2-col';break;case 'Row':el.className='a2-row';break;case 'Card':el.className='a2-card';break;
case 'Divider':return document.createElement('hr');
case 'Image':{{const i=document.createElement('img');const u=val(s,p.url);if(/^(https:|data:image\/)/.test(u))i.src=u;i.alt=val(s,p.altText||p.alt);return i;}}
case 'Button':{{const b=document.createElement('button');const ch=kids(p)[0]||p.child;b.append(ch?node(s,ch,depth+1):document.createTextNode(val(s,p.label)));b.onclick=()=>parent!==window&&parent.postMessage({{type:'a2ui:action',surfaceId:s.id,component:id,action:p.action||null}},'*');return b;}}
case 'TextField':{{const l=document.createElement('label');l.textContent=val(s,p.label)+' ';const i=document.createElement('input');i.value=val(s,p.text);i.oninput=()=>{{if(p.text&&p.text.path)set(s.data,p.text.path,i.value);}};l.append(i);return l;}}
case 'CheckBox':{{const l=document.createElement('label');const i=document.createElement('input');i.type='checkbox';i.checked=val(s,p.value)==='true';l.append(i,' '+val(s,p.label));return l;}}
default:el.textContent='['+type+']';}}
for(const k of kids(p))el.append(node(s,k,depth+1));return el;}}
function render(){{root.innerHTML='';for(const [id,s] of S){{if(!s.root)continue;s.id=id;const w=document.createElement('section');w.className='a2-surface';w.append(node(s,s.root,0));root.append(w);}}}}
function apply(msgs){{for(const m of msgs||[]){{const k=Object.keys(m).find(x=>x!=='version');const p=m[k]||{{}};const s=surf(p.surfaceId);
if(k==='surfaceUpdate'||k==='updateComponents'){{for(const c of p.components||[])s.comps.set(c.id,c.component?c:{{type:c.component||c.type,...c}});if(k==='updateComponents'&&!s.root&&s.comps.has('root'))s.root='root';}}
else if(k==='beginRendering'){{s.root=p.root;}}else if(k==='createSurface'){{s.root=p.root||'root';}}
else if(k==='dataModelUpdate'){{set(s.data,p.path,Array.isArray(p.contents)?toData(p.contents):p.contents);}}else if(k==='updateDataModel'){{set(s.data,p.path,p.value);}}
else if(k==='deleteSurface')S.delete(p.surfaceId);}}render();return S.size;}}
window.seagentA2ui=Object.freeze({{apply,reset(){{S.clear();render();return 0;}}}});apply({init});}})();
</script></body></html>"#,
        esc_html(title)
    )
}

/// Store an A2UI surface document (served by the renderer at `/surfaces/a2ui/<id>`).
pub fn create_a2ui(dir: &Path, title: &str, msgs: &[Value], scope: Option<&str>) -> Result<Manifest, String> {
    let body = serde_json::to_vec(msgs).map_err(|e| e.to_string())?;
    let mut m = create(dir, "a2ui", title, "messages.json", &body, scope, 32)?;
    m.entry_url = format!("/surfaces/a2ui/{}", m.id);
    write_json(&docs_dir(dir).join(&m.id).join("manifest.json"), &m)?;
    Ok(m)
}

/// `GET /surfaces/a2ui/<id>`
pub fn serve_a2ui(dir: &Path, rest: &str) -> Response {
    let id = rest.split(['/', '?', '#']).next().unwrap_or("");
    if !valid_doc_id(id) {
        return Response::text(404, "not found");
    }
    let root = docs_dir(dir).join(id);
    let (Some(m), Some(msgs)) = (read_json::<Manifest>(&root.join("manifest.json")), read_json::<Vec<Value>>(&root.join("messages.json"))) else { return Response::text(404, "not found") };
    if m.kind != "a2ui" {
        return Response::text(404, "not found");
    }
    Response::new(200, "text/html; charset=utf-8", renderer_html(m.title.as_deref().unwrap_or("A2UI"), &msgs).into_bytes()).with_header("content-security-policy", "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src https: data:")
}

// ───────────────────────── nodes ─────────────────────────

/// How the tool reaches nodes (swapped in tests).
pub type Invoker = Arc<dyn Fn(&str, &str, Value, Duration) -> Result<Value, String> + Send + Sync>;
pub type Lister = Arc<dyn Fn() -> Vec<Value> + Send + Sync>;

pub fn default_invoker() -> Invoker {
    Arc::new(|node: &str, cmd: &str, params: Value, t: Duration| crate::node::invoke(node, cmd, params, t, None))
}

pub fn default_lister() -> Lister {
    Arc::new(|| (crate::node::methods())("node.list", &json!({})).and_then(|r| r.ok()).and_then(|v| v["connected"].as_array().cloned()).unwrap_or_default())
}

/// Pick a connected node offering `command` (by id or name when `query` is given).
pub fn resolve_node(nodes: &[Value], query: Option<&str>, command: &str) -> Result<(String, String), String> {
    let eligible: Vec<&Value> = nodes.iter().filter(|n| n["commands"].as_array().is_some_and(|c| c.iter().any(|x| x == command))).collect();
    let ids = || eligible.iter().filter_map(|n| n["id"].as_str()).collect::<Vec<_>>().join(", ");
    let pair = |n: &Value| (n["id"].as_str().unwrap_or("").to_string(), n["name"].as_str().unwrap_or("").to_string());
    match query.map(str::trim).filter(|q| !q.is_empty()) {
        Some(q) => match eligible.iter().find(|n| n["id"] == q || n["name"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(q))) {
            Some(n) => Ok(pair(n)),
            None if nodes.iter().any(|n| n["id"] == q || n["name"] == q) => Err(format!("node \"{q}\" is not an eligible canvas (requires a connected node advertising {command}; eligible node ids: {})", ids())),
            None => Err(format!("unknown node \"{q}\" (eligible canvas node ids: {})", ids())),
        },
        None => match eligible.len() {
            0 => Err(format!("no eligible canvas (requires a connected node advertising {command})")),
            1 => Ok(pair(eligible[0])),
            _ => Err(format!("multiple eligible canvases connected; pass node explicitly: {}", ids())),
        },
    }
}

/// Present `url` on the default canvas node: Ok((node id, name)).
pub fn present_on_node(env: &Env, node: Option<&str>, url: &str) -> Result<(String, String), String> {
    if !env.cfg.canvas.enabled() {
        return Err("canvas hosting is disabled ([surfaces.canvas] host_enabled = false)".into());
    }
    let (id, name) = resolve_node(&(default_lister())(), node, "canvas.present")?;
    (default_invoker())(&id, "canvas.present", json!({"url": url}), Duration::from_secs(30))?;
    Ok((id.clone(), if name.is_empty() { id } else { name }))
}

pub struct CanvasTool {
    env: Arc<Env>,
    invoke: Invoker,
    list: Lister,
}

impl CanvasTool {
    pub fn new(env: Arc<Env>) -> CanvasTool {
        CanvasTool { env, invoke: default_invoker(), list: default_lister() }
    }

    fn url_arg(&self, p: &Value) -> Option<String> {
        let u = p["url"].as_str().or(p["target"].as_str()).map(str::trim).filter(|u| !u.is_empty())?;
        Some(if u.starts_with('/') { format!("{}{u}", self.env.base_url) } else { u.to_string() })
    }

    fn run(&self, ctx: &ToolCtx, p: &Value) -> Result<Value, String> {
        let action = p["action"].as_str().ok_or("action required")?;
        let t = Duration::from_millis(p["timeoutMs"].as_u64().unwrap_or(30_000).clamp(1000, 300_000));
        let node = p["node"].as_str();
        let invoke = |cmd: &str, params: Value| -> Result<(String, Value), String> {
            let (id, _) = resolve_node(&(self.list)(), node, cmd)?;
            let r = (self.invoke)(&id, cmd, params, t)?;
            Ok((id, r))
        };
        match action {
            "present" => {
                let mut params = json!({});
                let url = self.url_arg(p);
                if let Some(u) = &url {
                    check_url(u)?;
                    params["url"] = u.clone().into();
                }
                let place: serde_json::Map<String, Value> = ["x", "y", "width", "height"].iter().filter_map(|k| p[*k].as_f64().filter(|f| f.is_finite()).map(|f| (k.to_string(), json!(f)))).collect();
                if !place.is_empty() {
                    params["placement"] = Value::Object(place);
                }
                let (id, _) = invoke("canvas.present", params)?;
                Ok(json!({"ok": true, "node": id, "url": url}))
            }
            "hide" => invoke("canvas.hide", json!({})).map(|(id, _)| json!({"ok": true, "node": id})),
            "navigate" => {
                let url = self.url_arg(p).ok_or("url required")?;
                check_url(&url)?;
                invoke("canvas.navigate", json!({"url": url})).map(|(id, _)| json!({"ok": true, "node": id, "url": url}))
            }
            "eval" => {
                let js = p["javaScript"].as_str().filter(|s| !s.trim().is_empty()).ok_or("javaScript required")?;
                invoke("canvas.eval", json!({"javaScript": js})).map(|(id, r)| json!({"ok": true, "node": id, "result": r.get("result").cloned().unwrap_or(r)}))
            }
            "snapshot" => {
                let fmt = match p["outputFormat"].as_str().unwrap_or("png") {
                    "png" => "png",
                    "jpg" | "jpeg" => "jpeg",
                    f => return Err(format!("outputFormat must be png or jpg, got {f}")),
                };
                let mut params = json!({"format": fmt});
                if let Some(w) = p["maxWidth"].as_u64() {
                    params["maxWidth"] = w.into();
                }
                if let Some(q) = p["quality"].as_f64() {
                    params["quality"] = q.into();
                }
                let (id, r) = invoke("canvas.snapshot", params)?;
                let b64 = r["base64"].as_str().ok_or("unexpected canvas.snapshot response from node")?;
                let bytes = seagent_net::crypto::b64_decode(b64).ok_or("canvas.snapshot returned invalid base64")?;
                let file = ctx.artifacts.join(format!("canvas-{}.{}", now_ms(), if fmt == "png" { "png" } else { "jpg" }));
                write_atomic(&file, &bytes)?;
                Ok(json!({"ok": true, "node": id, "path": file, "bytes": bytes.len(), "mime": if fmt == "png" { "image/png" } else { "image/jpeg" }}))
            }
            "a2ui_push" => {
                let jsonl = match (p["jsonl"].as_str(), p["jsonlPath"].as_str()) {
                    (Some(j), _) => j.to_string(),
                    (None, Some(path)) => std::fs::read_to_string(ctx.resolve(path)).map_err(|e| format!("jsonlPath: {e}"))?,
                    _ => return Err("jsonl or jsonlPath required".into()),
                };
                let (version, msgs) = validate_jsonl(&jsonl)?;
                if !self.env.cfg.canvas.enabled() {
                    return Err("canvas hosting is disabled ([surfaces.canvas] host_enabled = false)".into());
                }
                let doc = create_a2ui(&self.env.dir, p["title"].as_str().unwrap_or("A2UI"), &msgs, Some(&format!("session:{}", ctx.session_id)))?;
                let url = format!("{}{}", self.env.base_url, doc.entry_url);
                let pushed = if node.is_some() || resolve_node(&(self.list)(), None, "canvas.a2ui.pushJSONL").is_ok() {
                    Some(invoke("canvas.a2ui.pushJSONL", json!({"jsonl": jsonl}))?.0)
                } else {
                    None
                };
                Ok(json!({"ok": true, "version": version, "messageCount": msgs.len(), "node": pushed, "url": url}))
            }
            "a2ui_reset" => invoke("canvas.a2ui.reset", json!({})).map(|(id, _)| json!({"ok": true, "node": id})),
            other => Err(format!("Unknown action: {other}")),
        }
    }
}

fn check_url(u: &str) -> Result<(), String> {
    if u.starts_with("https://") || u.starts_with("http://") {
        Ok(())
    } else {
        Err("url must be http(s) or a hosted /surfaces/… path".into())
    }
}

impl Tool for CanvasTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "canvas".into(),
            description: "Drive the canvas (widget panel) of a paired device node. present: show the panel, optionally with a URL (http(s) or a hosted /surfaces/… document from show_widget) and x/y/width/height placement; hide; navigate {url}; eval {javaScript} runs script in the panel and returns its value; snapshot {outputFormat png|jpg, maxWidth, quality} saves a screenshot; a2ui_push {jsonl | jsonlPath} renders A2UI v0.8/v0.9 JSONL (also hosted for the web UI); a2ui_reset clears it. Pass `node` (id or name) when several canvases are connected. To show a widget on a device prefer show_widget with presentation.target=node_panel. Do not invent local file paths or arbitrary external URLs.".into(),
            input_schema: json!({"type": "object", "properties": {
                "action": {"type": "string", "enum": ["present", "hide", "navigate", "eval", "snapshot", "a2ui_push", "a2ui_reset"]},
                "node": {"type": "string"},
                "target": {"type": "string"}, "url": {"type": "string"},
                "x": {"type": "number"}, "y": {"type": "number"}, "width": {"type": "number"}, "height": {"type": "number"},
                "javaScript": {"type": "string"},
                "outputFormat": {"type": "string", "enum": ["png", "jpg", "jpeg"]}, "maxWidth": {"type": "integer"}, "quality": {"type": "number"},
                "jsonl": {"type": "string"}, "jsonlPath": {"type": "string"}, "title": {"type": "string"},
                "timeoutMs": {"type": "integer", "minimum": 1}
            }, "required": ["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let node = format!("node:{}", input["node"].as_str().unwrap_or("canvas"));
        let mut e = match input["action"].as_str() {
            // Script in a device's browser acts on whatever page it shows.
            Some("eval") => vec![Effect::Remote { dest: node, reason: "canvas eval runs JavaScript on a paired device".into() }],
            Some("snapshot") => vec![Effect::Net { dest: node, payload: String::new() }, Effect::Write { path: ctx.artifacts.clone() }],
            Some(_) => vec![Effect::Net { dest: node, payload: input.to_string().chars().take(2000).collect() }],
            None => vec![],
        };
        if let Some(p) = input["jsonlPath"].as_str() {
            e.push(Effect::Read { path: ctx.resolve(p) });
        }
        e
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ───────────────────────── node side (`seagent node`) ─────────────────────────

/// Canvas commands a node offers: CDP control when `cdp_url` is set, else the xdg-open subset.
pub fn node_commands(canvas: bool, cdp: bool) -> Vec<&'static str> {
    if !canvas {
        return vec![];
    }
    if cdp {
        vec!["canvas.hide", "canvas.navigate", "canvas.eval", "canvas.snapshot", "canvas.a2ui.push", "canvas.a2ui.pushJSONL", "canvas.a2ui.reset"]
    } else {
        vec!["canvas.navigate", "canvas.a2ui.push", "canvas.a2ui.pushJSONL"]
    }
}

/// Does this node handle `command` here (instead of the plain `xdg-open` canvas.present)?
pub fn node_handles(canvas: bool, cdp: bool, command: &str) -> bool {
    canvas && ((command == "canvas.present" && cdp) || node_commands(canvas, cdp).contains(&command))
}

/// The CDP page the panel lives in.
static PANEL: Mutex<Option<String>> = Mutex::new(None);

pub fn node_run(cdp_url: &str, command: &str, p: &Value, t: Duration) -> Result<Value, String> {
    if cdp_url.trim().is_empty() {
        return node_run_plain(command, p);
    }
    let base = endpoint(cdp_url)?;
    match command {
        "canvas.present" => {
            let url = match (p["url"].as_str(), p["html"].as_str()) {
                (Some(u), _) => {
                    check_url(u)?;
                    u.to_string()
                }
                (None, Some(h)) => file_url(h)?,
                (None, None) => "about:blank".into(),
            };
            let page = panel(&base, Some(&url), t)?;
            if let Some(pl) = p.get("placement").filter(|v| v.is_object()) {
                let mut s = Cdp::open(&base, &page, t)?;
                if let Ok(w) = s.send("Browser.getWindowForTarget", json!({"targetId": page})) {
                    let mut b = json!({"windowState": "normal"});
                    for (k, n) in [("x", "left"), ("y", "top"), ("width", "width"), ("height", "height")] {
                        if let Some(v) = pl[k].as_f64() {
                            b[n] = json!(v.round() as i64);
                        }
                    }
                    let _ = s.send("Browser.setWindowBounds", json!({"windowId": w["windowId"], "bounds": b}));
                }
            }
            Ok(json!({"presented": url, "pageRef": page}))
        }
        "canvas.hide" => {
            let page = PANEL.lock().unwrap().take();
            if let Some(id) = page {
                let _ = http_get(&format!("{base}/json/close/{id}"), t);
            }
            Ok(json!({"hidden": true}))
        }
        "canvas.navigate" => {
            let url = p["url"].as_str().ok_or("url required")?;
            check_url(url)?;
            let page = panel(&base, None, t)?;
            Cdp::open(&base, &page, t)?.send("Page.navigate", json!({"url": url}))?;
            Ok(json!({"url": url}))
        }
        "canvas.eval" => {
            let js = p["javaScript"].as_str().ok_or("javaScript required")?;
            let page = panel(&base, None, t)?;
            Ok(json!({"result": Cdp::open(&base, &page, t)?.eval(js)?}))
        }
        "canvas.snapshot" => {
            let page = panel(&base, None, t)?;
            let mut s = Cdp::open(&base, &page, t)?;
            let fmt = if p["format"] == "jpeg" { "jpeg" } else { "png" };
            let mut params = json!({"format": fmt});
            if fmt == "jpeg" {
                params["quality"] = json!((p["quality"].as_f64().unwrap_or(0.85) * 100.0).clamp(1.0, 100.0) as i64);
            }
            if let Some(w) = p["maxWidth"].as_u64() {
                if let Ok(m) = s.send("Page.getLayoutMetrics", json!({})) {
                    let (cw, ch) = (m["cssVisualViewport"]["clientWidth"].as_f64().unwrap_or(0.0), m["cssVisualViewport"]["clientHeight"].as_f64().unwrap_or(0.0));
                    if cw > w as f64 && cw > 0.0 {
                        params["clip"] = json!({"x": 0, "y": 0, "width": cw, "height": ch, "scale": w as f64 / cw});
                    }
                }
            }
            let r = s.send("Page.captureScreenshot", params)?;
            Ok(json!({"format": fmt, "base64": r["data"]}))
        }
        "canvas.a2ui.push" | "canvas.a2ui.pushJSONL" => {
            let msgs = a2ui_messages(p)?;
            let page = a2ui_page(&base, t)?;
            let n = Cdp::open(&base, &page, t)?.eval(&format!("window.seagentA2ui.apply({})", serde_json::to_string(&msgs).unwrap_or("[]".into())))?;
            Ok(json!({"ok": true, "surfaces": n, "messageCount": msgs.len()}))
        }
        "canvas.a2ui.reset" => {
            let page = a2ui_page(&base, t)?;
            Cdp::open(&base, &page, t)?.eval("window.seagentA2ui.reset()")?;
            Ok(json!({"ok": true}))
        }
        other => Err(format!("unknown canvas command `{other}`")),
    }
}

/// Without DevTools: open URLs / a rendered A2UI file in the default browser.
fn node_run_plain(command: &str, p: &Value) -> Result<Value, String> {
    let target = match command {
        "canvas.navigate" => {
            let u = p["url"].as_str().ok_or("url required")?;
            check_url(u)?;
            u.to_string()
        }
        "canvas.a2ui.push" | "canvas.a2ui.pushJSONL" => file_url(&renderer_html("A2UI", &a2ui_messages(p)?))?,
        c => return Err(format!("`{c}` needs `cdp_url` in node.toml (a browser started with --remote-debugging-port)")),
    };
    std::process::Command::new("xdg-open").arg(&target).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().map_err(|e| format!("xdg-open: {e}"))?;
    Ok(json!({"presented": target}))
}

fn a2ui_messages(p: &Value) -> Result<Vec<Value>, String> {
    match (p["jsonl"].as_str(), p["messages"].as_array()) {
        (Some(j), _) => validate_jsonl(j).map(|(_, m)| m),
        (None, Some(m)) => validate_jsonl(&m.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("\n")).map(|(_, m)| m),
        _ => Err("jsonl or messages required".into()),
    }
}

fn file_url(html: &str) -> Result<String, String> {
    if html.len() > 4 << 20 {
        return Err("html larger than 4 MB".into());
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|d| d.is_dir()).unwrap_or_else(std::env::temp_dir);
    let f = dir.join(format!("seagent-canvas-{}-{}.html", std::process::id(), seagent_net::crypto::random_token(6)));
    write_atomic(&f, html.as_bytes())?;
    Ok(format!("file://{}", f.display()))
}

/// The panel page: reuse it while it exists, else open a new one (at `url`).
fn panel(base: &str, url: Option<&str>, t: Duration) -> Result<String, String> {
    let mut cur = PANEL.lock().unwrap();
    let alive = cur.as_ref().is_some_and(|id| targets(base, t).is_ok_and(|ts| ts.iter().any(|x| x["id"] == id.as_str())));
    if alive {
        let id = cur.clone().unwrap();
        if let Some(u) = url {
            Cdp::open(base, &id, t)?.send("Page.navigate", json!({"url": u}))?;
        }
        let _ = http_get(&format!("{base}/json/activate/{id}"), t);
        return Ok(id);
    }
    if url.is_none() {
        return Err("the canvas is not presented; call present first".into());
    }
    let created = http_req("PUT", &format!("{base}/json/new?{}", url.unwrap()), t)?;
    let v: Value = serde_json::from_str(&created).map_err(|e| format!("CDP /json/new: {e}"))?;
    let id = v["id"].as_str().ok_or("CDP /json/new returned no target id")?.to_string();
    *cur = Some(id.clone());
    Ok(id)
}

/// Make sure the panel shows the A2UI renderer.
fn a2ui_page(base: &str, t: Duration) -> Result<String, String> {
    let existing = PANEL.lock().unwrap().clone();
    if let Some(id) = existing {
        if let Ok(mut s) = Cdp::open(base, &id, t) {
            if s.eval("typeof window.seagentA2ui === 'object'").ok() == Some(json!(true)) {
                return Ok(id);
            }
        }
    }
    let url = file_url(&renderer_html("A2UI", &[]))?;
    let id = panel(base, Some(&url), t)?;
    // Wait for the renderer to load.
    let until = Instant::now() + t;
    while Instant::now() < until {
        if Cdp::open(base, &id, t)?.eval("typeof window.seagentA2ui === 'object'").ok() == Some(json!(true)) {
            return Ok(id);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("A2UI renderer did not load in the canvas".into())
}

/// Only a browser on this machine: the endpoint hands out full control of it.
fn endpoint(cdp_url: &str) -> Result<String, String> {
    let u = cdp_url.trim().trim_end_matches('/');
    let rest = u.strip_prefix("http://").ok_or("cdp_url must be http://127.0.0.1:<port>")?;
    let host = rest.rsplit_once(':').map(|(h, _)| h).unwrap_or(rest);
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        return Err("cdp_url must point at this machine (127.0.0.1, localhost or [::1])".into());
    }
    Ok(u.to_string())
}

fn http_req(method: &str, url: &str, t: Duration) -> Result<String, String> {
    let agent: ureq::Agent = seagent_net::http::builder().timeout_global(Some(t)).build().into();
    let r = if method == "PUT" { agent.put(url).send_empty() } else { agent.get(url).call() };
    let mut r = r.map_err(|e| format!("CDP {url}: {e}"))?;
    r.body_mut().read_to_string().map_err(|e| e.to_string())
}

fn http_get(url: &str, t: Duration) -> Result<String, String> {
    http_req("GET", url, t)
}

fn targets(base: &str, t: Duration) -> Result<Vec<Value>, String> {
    let v: Value = serde_json::from_str(&http_get(&format!("{base}/json/list"), t)?).map_err(|e| format!("CDP /json/list: {e}"))?;
    Ok(v.as_array().cloned().unwrap_or_default().into_iter().filter(|x| x["type"] == "page").collect())
}

/// Minimal DevTools session on one page target.
struct Cdp {
    ws: seagent_net::ws::WebSocket<seagent_net::Stream>,
    next: u64,
    t: Duration,
}

impl Cdp {
    fn open(base: &str, page: &str, t: Duration) -> Result<Cdp, String> {
        let target = targets(base, t)?.into_iter().find(|x| x["id"] == page).ok_or("the canvas page was closed; call present again")?;
        let url = target["webSocketDebuggerUrl"].as_str().ok_or("canvas page has no webSocketDebuggerUrl (another DevTools client attached?)")?;
        let (mut ws, _) = seagent_net::ws::WebSocket::connect(url, &[], t).map_err(|e| format!("CDP connect: {e}"))?;
        ws.set_max_message(32 << 20);
        ws.set_read_timeout(Some(Duration::from_millis(200))).ok();
        Ok(Cdp { ws, next: 1, t })
    }
    fn send(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next;
        self.next += 1;
        self.ws.send_text(&json!({"id": id, "method": method, "params": params}).to_string()).map_err(|e| e.to_string())?;
        let until = Instant::now() + self.t;
        while Instant::now() < until {
            let Some(seagent_net::ws::Message::Text(m)) = self.ws.recv().map_err(|e| format!("CDP: {e}"))? else { continue };
            let v: Value = serde_json::from_str(&m).unwrap_or_default();
            if v["id"] != id {
                continue;
            }
            if let Some(e) = v.get("error") {
                return Err(format!("CDP {method}: {}", e["message"].as_str().unwrap_or("error")));
            }
            return Ok(v["result"].clone());
        }
        Err(format!("CDP {method}: timed out"))
    }
    fn eval(&mut self, expr: &str) -> Result<Value, String> {
        let r = self.send("Runtime.evaluate", json!({"expression": expr, "returnByValue": true, "awaitPromise": true}))?;
        if let Some(e) = r.get("exceptionDetails") {
            return Err(format!("canvas script failed: {}", e["exception"]["description"].as_str().or(e["text"].as_str()).unwrap_or("exception")));
        }
        Ok(r["result"]["value"].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;
    use std::io::Write;

    #[test]
    fn a2ui_jsonl_rules() {
        let ok = "{\"surfaceUpdate\":{\"surfaceId\":\"main\",\"components\":[{\"id\":\"root\",\"component\":{\"Text\":{\"text\":{\"literalString\":\"Hi\"}}}}]}}\n\n{\"beginRendering\":{\"surfaceId\":\"main\",\"root\":\"root\"}}";
        let (v, m) = validate_jsonl(ok).unwrap();
        assert_eq!((v.as_str(), m.len()), ("v0.8", 2));
        let (v, _) = validate_jsonl("{\"version\":\"v0.9\",\"createSurface\":{\"surfaceId\":\"s\",\"catalogId\":\"c\"}}").unwrap();
        assert_eq!(v, "v0.9");
        let e = validate_jsonl("{\"version\":\"v0.8\",\"beginRendering\":{\"surfaceId\":\"m\"}}\nnot json\n{\"surfaceUpdate\":{\"surfaceId\":\"m\",\"components\":[]},\"x\":1}\n[1]").unwrap_err();
        assert!(e.contains("line 1: A2UI v0.8 messages must not include a version field") && e.contains("line 2:") && e.contains("line 3: unexpected top-level A2UI field") && e.contains("line 4: expected JSON object"), "{e}");
        assert!(validate_jsonl("{\"beginRendering\":{\"surfaceId\":\"a\"}}\n{\"version\":\"v0.9\",\"deleteSurface\":{\"surfaceId\":\"a\"}}").unwrap_err().contains("mixed"));
        assert!(validate_jsonl("  \n").unwrap_err().contains("no JSONL messages"));
        assert!(renderer_html("t", &m).contains("window.seagentA2ui"));
    }

    #[test]
    fn documents_are_served_safely_and_pruned() {
        let d = testkit::temp("docs");
        let m = create_document(&d, "T", "<p>x</p>", Some("session:a"), 2).unwrap();
        assert!(m.id.starts_with("cv_") && m.entry_url.ends_with("/index.html"));
        let rest = format!("{}/index.html", m.id);
        assert_eq!(serve_document(&d, &rest).status, 200);
        for bad in [format!("{}/manifest.json", m.id), format!("{}/..%2fx", m.id), "../etc/passwd".into(), format!("{}/%2e%2e/%2e%2e/x", m.id)] {
            assert_eq!(serve_document(&d, &bad).status, 404, "{bad}");
        }
        std::thread::sleep(Duration::from_millis(3));
        create_document(&d, "T2", "<p>y</p>", Some("session:a"), 2).unwrap();
        std::thread::sleep(Duration::from_millis(3));
        create_document(&d, "T3", "<p>z</p>", Some("session:a"), 2).unwrap();
        assert_eq!(serve_document(&d, &rest).status, 404, "oldest pruned");
        let a = create_a2ui(&d, "Board", &[json!({"deleteSurface": {"surfaceId": "x"}})], None).unwrap();
        let r = serve_a2ui(&d, &a.id);
        assert_eq!(r.status, 200);
    }

    #[test]
    fn tool_resolves_nodes_and_invokes_canvas_commands() {
        let (env, _) = testkit::env("canvas", &[], "");
        let calls: Arc<Mutex<Vec<(String, String, Value)>>> = Arc::default();
        let c2 = calls.clone();
        let tool = CanvasTool {
            env: env.clone(),
            invoke: Arc::new(move |n: &str, c: &str, p: Value, _| {
                c2.lock().unwrap().push((n.into(), c.into(), p));
                Ok(match c {
                    "canvas.eval" => json!({"result": 42}),
                    "canvas.snapshot" => json!({"base64": seagent_net::crypto::b64(b"PNG"), "format": "png"}),
                    _ => json!({}),
                })
            }),
            list: Arc::new(|| vec![json!({"id": "n1", "name": "Desk", "commands": ["canvas.present", "canvas.eval", "canvas.snapshot", "canvas.navigate", "canvas.a2ui.pushJSONL"]}), json!({"id": "n2", "name": "Phone", "commands": ["camera.snap"]})]),
        };
        let ws = testkit::temp("cv-ws");
        let ctx = testkit::ctx(&env, &ws);
        let o = tool.call(&ctx, json!({"action": "present", "target": "/surfaces/canvas/documents/cv_x/index.html", "width": 800}));
        assert!(!o.is_error, "{}", o.content);
        let c = calls.lock().unwrap()[0].clone();
        assert_eq!((c.0.as_str(), c.1.as_str()), ("n1", "canvas.present"));
        assert_eq!(c.2["url"], "http://127.0.0.1:8640/surfaces/canvas/documents/cv_x/index.html");
        assert_eq!(c.2["placement"]["width"], 800.0);
        assert!(tool.call(&ctx, json!({"action": "eval", "javaScript": "6*7"})).content.contains("\"result\":42"));
        let snap: Value = serde_json::from_str(&tool.call(&ctx, json!({"action": "snapshot"})).content).unwrap();
        assert_eq!(std::fs::read(snap["path"].as_str().unwrap()).unwrap(), b"PNG");
        assert!(tool.call(&ctx, json!({"action": "navigate", "url": "file:///etc/passwd"})).content.contains("http(s)"));
        assert!(tool.call(&ctx, json!({"action": "present", "node": "Phone"})).content.contains("not an eligible canvas"));
        assert!(tool.call(&ctx, json!({"action": "hide"})).content.contains("no eligible canvas"));
        let o = tool.call(&ctx, json!({"action": "a2ui_push", "jsonl": "{\"beginRendering\":{\"surfaceId\":\"m\",\"root\":\"r\"}}"}));
        assert!(o.content.contains("\"node\":\"n1\"") && o.content.contains("/surfaces/a2ui/cv_"), "{}", o.content);
        assert!(matches!(tool.effects(&ctx, &json!({"action": "eval"}))[0], Effect::Remote { .. }));
    }

    /// A fake DevTools endpoint: /json/* over HTTP, then page WebSockets answering by method.
    fn fake_browser() -> (String, Arc<Mutex<Vec<Value>>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let s2 = seen.clone();
        std::thread::spawn(move || {
            let mut open = false;
            for s in l.incoming() {
                let mut s = s.unwrap();
                let (head, rest) = seagent_net::ws::read_head(&mut s, 1 << 16).unwrap();
                let line = head.lines().next().unwrap_or("").to_string();
                let reply = |s: &mut std::net::TcpStream, body: String| {
                    let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                };
                if line.starts_with("PUT /json/new") {
                    open = true;
                    reply(&mut s, json!({"id": "P9", "type": "page"}).to_string());
                    continue;
                }
                if line.starts_with("GET /json/list") {
                    let list = if open { json!([{"id": "P9", "type": "page", "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/P9")}]) } else { json!([]) };
                    reply(&mut s, list.to_string());
                    continue;
                }
                if line.starts_with("GET /json/") {
                    if line.contains("/json/close/") {
                        open = false;
                    }
                    reply(&mut s, "{}".into());
                    continue;
                }
                let mut ws = seagent_net::ws::WebSocket::accept(s, &head, rest).unwrap();
                let s3 = s2.clone();
                std::thread::spawn(move || {
                    while let Ok(seagent_net::ws::Message::Text(t)) = ws.recv_blocking() {
                        let v: Value = serde_json::from_str(&t).unwrap();
                        let result = match v["method"].as_str().unwrap_or("") {
                            "Runtime.evaluate" if v["params"]["expression"].as_str().unwrap_or("").contains("typeof window.seagentA2ui") => json!({"result": {"value": true}}),
                            "Runtime.evaluate" => json!({"result": {"value": 7}}),
                            "Page.captureScreenshot" => json!({"data": "aGk="}),
                            _ => json!({}),
                        };
                        s3.lock().unwrap().push(v.clone());
                        if ws.send_text(&json!({"id": v["id"], "result": result}).to_string()).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (format!("http://127.0.0.1:{port}"), seen)
    }

    #[test]
    fn linux_node_canvas_over_devtools() {
        let (url, seen) = fake_browser();
        let t = Duration::from_secs(5);
        assert!(node_run(&url, "canvas.eval", &json!({"javaScript": "1"}), t).unwrap_err().contains("present first"));
        let r = node_run(&url, "canvas.present", &json!({"url": "https://example.com/"}), t).unwrap();
        assert_eq!(r["pageRef"], "P9");
        node_run(&url, "canvas.navigate", &json!({"url": "https://example.org/"}), t).unwrap();
        assert_eq!(node_run(&url, "canvas.eval", &json!({"javaScript": "3+4"}), t).unwrap()["result"], 7);
        assert_eq!(node_run(&url, "canvas.snapshot", &json!({}), t).unwrap()["base64"], "aGk=");
        let r = node_run(&url, "canvas.a2ui.pushJSONL", &json!({"jsonl": "{\"beginRendering\":{\"surfaceId\":\"m\",\"root\":\"r\"}}"}), t).unwrap();
        assert_eq!(r["messageCount"], 1);
        node_run(&url, "canvas.hide", &json!({}), t).unwrap();
        let methods: Vec<String> = seen.lock().unwrap().iter().map(|v| v["method"].as_str().unwrap_or("").to_string()).collect();
        assert!(methods.contains(&"Page.navigate".to_string()) && methods.contains(&"Page.captureScreenshot".to_string()), "{methods:?}");
        assert!(seen.lock().unwrap().iter().any(|v| v["params"]["expression"].as_str().is_some_and(|e| e.starts_with("window.seagentA2ui.apply("))));
        assert!(node_run("http://10.0.0.1:9222", "canvas.hide", &json!({}), t).unwrap_err().contains("this machine"));
        assert!(node_run("", "canvas.eval", &json!({}), t).unwrap_err().contains("cdp_url"));
        assert!(node_handles(true, false, "canvas.navigate") && !node_handles(true, false, "canvas.present") && node_handles(true, true, "canvas.present") && !node_handles(false, true, "canvas.eval"));
    }
}
