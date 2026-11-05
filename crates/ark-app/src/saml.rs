//! SAML 2.0 service provider (ent-048): SP metadata, AuthnRequest (HTTP-Redirect binding),
//! and the Response check at the Assertion Consumer Service (HTTP-POST binding). A verified
//! assertion becomes the same login an OIDC callback produces (subject, email, name, groups),
//! so role mapping (`[app.rbac]`), the user registry (`ark users`), the signed session cookie,
//! personal tokens and the audit stream are shared with OIDC.
//!
//! ```toml
//! [app.auth]
//! enabled = true
//! provider = "saml"
//! secret = "{{secret:APP_AUTH_SECRET}}"
//! [app.auth.saml]
//! idp_entity_id = "https://idp.example.com/saml"
//! idp_sso_url = "https://idp.example.com/saml/sso"
//! idp_cert = "/etc/ark/idp.pem"          # PEM, bare base64 DER, or a path to a PEM file
//! sp_entity_id = "https://ark.example.com/auth/saml/metadata"   # required: never taken from Host
//! acs_url = "https://ark.example.com/auth/saml/acs"            # required (the IdP posts here)
//! groups_attribute = "groups"            # also tried: memberOf, the Entra/ADFS group claim
//! allow_idp_initiated = false            # unsolicited responses are refused by default
//! ```
//!
//! What a Response must satisfy (anything else is refused, and the browser only learns
//! `login failed`):
//!
//! * well-formed, no DTD, every `ID` in the document unique;
//! * the root is `samlp:Response` with status `Success`, `Destination` (when present) = our ACS;
//! * **exactly one** `saml:Assertion`, a direct child of the Response (no `EncryptedAssertion`);
//! * every `ds:Signature` sits directly in the Response or the Assertion, and covers exactly its
//!   parent (see [`crate::xmldsig::verify_enveloped`]); at least one of them verifies with the
//!   configured IdP certificate, and the assertion that is then read is *that node* (the
//!   assertion itself, or the only assertion inside the signed Response) — the XML signature
//!   wrapping family (XSW1–8) all depend on reading a different node than the one verified;
//! * assertion `Issuer` = `idp_entity_id`; `Conditions` time window (with `clock_skew_secs`) and
//!   `AudienceRestriction` containing our entity id; a bearer `SubjectConfirmationData` whose
//!   `Recipient` is our ACS, `NotOnOrAfter` in the future and `InResponseTo` one of our own
//!   outstanding requests (single use) — or nothing at all when `allow_idp_initiated`;
//! * an assertion ID is accepted once (replay cache until its `NotOnOrAfter`).

use crate::xmldsig::{self, Doc, Key, NS_DSIG};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

pub const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const DEFAULT_NAMEID: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

const EMAIL_ATTRS: &[&str] = &["email", "mail", "emailaddress", "urn:oid:0.9.2342.19200300.100.1.3", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"];
const NAME_ATTRS: &[&str] = &["name", "displayname", "cn", "urn:oid:2.16.840.1.113730.3.1.241", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"];
const GROUP_ATTRS: &[&str] = &["groups", "memberof", "group", "role", "urn:oid:1.3.6.1.4.1.5923.1.5.1.1", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"];

/// `[app.auth.saml]`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SamlConfig {
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    /// The IdP signing certificate(s): PEM (several blocks for a rollover), bare base64 DER, or
    /// the path of a PEM file.
    pub idp_cert: String,
    pub sp_entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// Attribute names (empty = the usual suspects, see the constants above).
    pub email_attribute: String,
    pub name_attribute: String,
    pub groups_attribute: String,
    /// Accept unsolicited (IdP-initiated) responses. Off: every response must answer one of
    /// our own AuthnRequests.
    pub allow_idp_initiated: bool,
    pub clock_skew_secs: i64,
}

impl Default for SamlConfig {
    fn default() -> Self {
        SamlConfig {
            idp_entity_id: String::new(),
            idp_sso_url: String::new(),
            idp_cert: String::new(),
            sp_entity_id: String::new(),
            acs_url: String::new(),
            name_id_format: String::new(),
            email_attribute: String::new(),
            name_attribute: String::new(),
            groups_attribute: String::new(),
            allow_idp_initiated: false,
            clock_skew_secs: 120,
        }
    }
}

impl SamlConfig {
    /// The verification keys, or the operator-facing reason the provider cannot run.
    pub fn keys(&self) -> Result<Vec<Key>, String> {
        let mut missing = vec![];
        // Our own entity id and ACS are configured, never derived from the request's Host: an
        // assertion minted for another SP of the same IdP must not pass the audience check just
        // because the attacker sent `Host: other-sp`.
        for (k, v) in [("idp_entity_id", &self.idp_entity_id), ("idp_sso_url", &self.idp_sso_url), ("idp_cert", &self.idp_cert), ("sp_entity_id", &self.sp_entity_id), ("acs_url", &self.acs_url)] {
            if v.trim().is_empty() {
                missing.push(k);
            }
        }
        if !missing.is_empty() {
            return Err(format!("[app.auth.saml] is incomplete: set {}", missing.join(", ")));
        }
        if self.idp_cert.contains("{{secret:") {
            return Err("[app.auth.saml] idp_cert is an unresolved secret reference".into());
        }
        let t = self.idp_cert.trim();
        let text = if t.starts_with('/') || t.starts_with("~/") {
            std::fs::read_to_string(ark_core::tool::expand_home(t)).map_err(|e| format!("[app.auth.saml] idp_cert {t}: {e}"))?
        } else {
            t.to_string()
        };
        let certs = xmldsig::parse_certs(&text).map_err(|e| format!("[app.auth.saml] idp_cert: {e}"))?;
        certs.iter().map(|c| xmldsig::cert_key(c)).collect()
    }

    pub fn sp_entity_id(&self) -> &str {
        self.sp_entity_id.trim()
    }

    pub fn acs_url(&self) -> &str {
        self.acs_url.trim()
    }

    fn name_id_format(&self) -> &str {
        Some(self.name_id_format.trim()).filter(|s| !s.is_empty()).unwrap_or(DEFAULT_NAMEID)
    }
}

/// What a verified assertion says about the user.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Assertion {
    pub id: String,
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
    /// The AuthnRequest this answers (empty for IdP-initiated).
    pub in_response_to: String,
    /// Unix seconds after which the assertion is void (replay cache horizon).
    pub not_on_or_after: i64,
    /// `AuthnStatement SessionNotOnOrAfter`, when the IdP limits the session.
    pub session_not_on_or_after: Option<i64>,
}

/// The fixed facts a response is checked against.
pub struct Expect<'a> {
    pub sp_entity_id: &'a str,
    pub acs_url: &'a str,
    pub now: i64,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// `xs:dateTime` → Unix seconds (`Z`, an offset, or none = UTC; fractions dropped).
pub fn parse_instant(s: &str) -> Result<i64, String> {
    let bad = || format!("bad xs:dateTime `{s}`");
    let s = s.trim();
    let (date, rest) = s.split_once('T').ok_or_else(bad)?;
    let d: Vec<i64> = date.split('-').map(|x| x.parse::<i64>().map_err(|_| bad())).collect::<Result<_, _>>()?;
    if d.len() != 3 {
        return Err(bad());
    }
    let (time, offset) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 0)
    } else if let Some(i) = rest.rfind(['+', '-']).filter(|&i| i >= 8) {
        let (t, o) = rest.split_at(i);
        let sign = if o.starts_with('-') { -1 } else { 1 };
        let (h, m) = o[1..].split_once(':').ok_or_else(bad)?;
        (t, sign * (h.parse::<i64>().map_err(|_| bad())? * 3600 + m.parse::<i64>().map_err(|_| bad())? * 60))
    } else {
        (rest, 0)
    };
    let hms: Vec<&str> = time.split(':').collect();
    if hms.len() != 3 {
        return Err(bad());
    }
    let h: i64 = hms[0].parse().map_err(|_| bad())?;
    let mi: i64 = hms[1].parse().map_err(|_| bad())?;
    let sec: i64 = hms[2].split('.').next().unwrap_or("").parse().map_err(|_| bad())?;
    if !(1..=12).contains(&d[1]) || !(1..=31).contains(&d[2]) || h > 23 || mi > 59 || sec > 60 {
        return Err(bad());
    }
    let days = ark_kernel::util::days_from_civil(d[0], d[1] as u32, d[2] as u32);
    Ok(days * 86_400 + h * 3600 + mi * 60 + sec - offset)
}

pub fn instant(unix: i64) -> String {
    let (y, m, d) = ark_kernel::util::civil_from_days(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
}

fn time_attr(doc: &Doc, i: usize, name: &str) -> Result<Option<i64>, String> {
    doc.el(i).attr(name).map(parse_instant).transpose()
}

/// Check a base64-decoded `SAMLResponse` and return the assertion that the signature covered.
pub fn verify_response(xml: &str, keys: &[Key], cfg: &SamlConfig, exp: &Expect) -> Result<Assertion, String> {
    let doc = Doc::parse(xml)?;
    let root = Doc::ROOT;
    if !doc.el(root).is(NS_SAMLP, "Response") {
        return Err("not a samlp:Response".into());
    }
    // Every ID-like attribute is unique: a duplicate is how a wrapped copy gets referenced.
    let mut ids = std::collections::BTreeSet::new();
    for e in &doc.nodes {
        for a in e.attrs.iter().filter(|a| a.ns.is_empty() && matches!(a.local.as_str(), "ID" | "Id" | "id" | "AssertionID")) {
            if !ids.insert(a.value.clone()) {
                return Err(format!("duplicate ID `{}`", a.value));
            }
        }
    }
    if doc.all_named(NS_SAML, "EncryptedAssertion").next().is_some() {
        return Err("encrypted assertions are not supported (turn assertion encryption off at the IdP; TLS protects the POST)".into());
    }
    let assertions: Vec<usize> = doc.all_named(NS_SAML, "Assertion").collect();
    let [assertion] = assertions.as_slice() else {
        return Err(format!("expected exactly one Assertion, found {}", assertions.len()));
    };
    let assertion = *assertion;
    if doc.el(assertion).parent != Some(root) {
        return Err("the Assertion is not a direct child of the Response".into());
    }
    // Signatures: only directly inside the Response or the Assertion, each covering its parent.
    let sigs: Vec<usize> = doc.all_named(NS_DSIG, "Signature").collect();
    if sigs.iter().any(|&s| doc.el(s).parent != Some(root) && doc.el(s).parent != Some(assertion)) {
        return Err("a signature outside the Response / Assertion".into());
    }
    let mut covered = Vec::new();
    for sig in sigs {
        covered.push(xmldsig::verify_enveloped(&doc, sig, keys)?);
    }
    if !covered.contains(&assertion) && !covered.contains(&root) {
        return Err("neither the Response nor the Assertion is signed".into());
    }
    // From here on, only nodes inside the verified element are read.
    let signed = if covered.contains(&assertion) { assertion } else { root };
    debug_assert!(doc.contains(signed, assertion));

    let r = doc.el(root);
    if r.attr("Version") != Some("2.0") {
        return Err("not a SAML 2.0 response".into());
    }
    if let Some(dest) = r.attr("Destination") {
        if dest != exp.acs_url {
            return Err(format!("Destination `{dest}` is not our ACS"));
        }
    }
    let status = doc.only_kid(root, NS_SAMLP, "Status")?;
    let code = doc.only_kid(status, NS_SAMLP, "StatusCode")?;
    if doc.el(code).attr("Value") != Some(STATUS_SUCCESS) {
        return Err(format!("IdP status `{}`", doc.el(code).attr("Value").unwrap_or("")));
    }
    let issuer = doc.only_kid(assertion, NS_SAML, "Issuer")?;
    if doc.text(issuer).trim() != cfg.idp_entity_id.trim() {
        return Err(format!("assertion issuer `{}` is not the configured IdP", doc.text(issuer).trim()));
    }
    let skew = cfg.clock_skew_secs.clamp(0, 600);
    let now = exp.now;
    // Conditions: time window and audience.
    let cond = doc.only_kid(assertion, NS_SAML, "Conditions")?;
    if time_attr(&doc, cond, "NotBefore")?.is_some_and(|t| now + skew < t) {
        return Err("assertion not yet valid".into());
    }
    let cond_end = time_attr(&doc, cond, "NotOnOrAfter")?;
    if cond_end.is_some_and(|t| now - skew >= t) {
        return Err("assertion expired".into());
    }
    let restrictions: Vec<usize> = doc.kids_named(cond, NS_SAML, "AudienceRestriction").collect();
    if restrictions.is_empty() {
        return Err("no AudienceRestriction".into());
    }
    for ar in restrictions {
        if !doc.kids_named(ar, NS_SAML, "Audience").any(|a| doc.text(a).trim() == exp.sp_entity_id) {
            return Err("this assertion is for another audience".into());
        }
    }
    // Subject: a bearer confirmation for us.
    let subj = doc.only_kid(assertion, NS_SAML, "Subject")?;
    let name_id = doc.only_kid(subj, NS_SAML, "NameID")?;
    let subject = doc.text(name_id).trim().to_string();
    if subject.is_empty() {
        return Err("empty NameID".into());
    }
    let mut in_response_to = None;
    let mut sc_end = None;
    for sc in doc.kids_named(subj, NS_SAML, "SubjectConfirmation") {
        if doc.el(sc).attr("Method") != Some(CM_BEARER) {
            continue;
        }
        let Some(d) = doc.kid(sc, NS_SAML, "SubjectConfirmationData") else { continue };
        if doc.el(d).attr("Recipient") != Some(exp.acs_url) {
            continue;
        }
        let Some(end) = time_attr(&doc, d, "NotOnOrAfter")? else { continue };
        if now - skew >= end || time_attr(&doc, d, "NotBefore")?.is_some_and(|t| now + skew < t) {
            continue;
        }
        in_response_to = Some(doc.el(d).attr("InResponseTo").unwrap_or("").to_string());
        sc_end = Some(end);
        break;
    }
    let (Some(irt), Some(sc_end)) = (in_response_to, sc_end) else {
        return Err("no valid bearer SubjectConfirmation for our ACS".into());
    };
    let resp_irt = r.attr("InResponseTo").unwrap_or("");
    if !resp_irt.is_empty() && resp_irt != irt {
        return Err("InResponseTo differs between the Response and the assertion".into());
    }
    if irt.is_empty() && !cfg.allow_idp_initiated {
        return Err("unsolicited (IdP-initiated) response refused (`allow_idp_initiated = false`)".into());
    }
    if doc.kid(assertion, NS_SAML, "AuthnStatement").is_none() {
        return Err("no AuthnStatement".into());
    }
    let session_end = doc.kid(assertion, NS_SAML, "AuthnStatement").map(|a| time_attr(&doc, a, "SessionNotOnOrAfter")).transpose()?.flatten();
    // Attributes.
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for st in doc.kids_named(assertion, NS_SAML, "AttributeStatement") {
        for a in doc.kids_named(st, NS_SAML, "Attribute") {
            let vals: Vec<String> = doc.kids_named(a, NS_SAML, "AttributeValue").map(|v| doc.text(v).trim().to_string()).filter(|v| !v.is_empty()).collect();
            for key in [doc.el(a).attr("Name"), doc.el(a).attr("FriendlyName")].into_iter().flatten() {
                attributes.entry(key.to_string()).or_default().extend(vals.iter().cloned());
            }
        }
    }
    let pick = |configured: &str, defaults: &[&str]| -> Vec<String> {
        let names: Vec<String> = if configured.trim().is_empty() { defaults.iter().map(|s| s.to_string()).collect() } else { vec![configured.trim().to_string()] };
        for n in names {
            if let Some(v) = attributes.iter().find(|(k, _)| k.eq_ignore_ascii_case(&n)).map(|(_, v)| v.clone()) {
                return v;
            }
        }
        vec![]
    };
    let email = pick(&cfg.email_attribute, EMAIL_ATTRS).into_iter().next().or_else(|| subject.contains('@').then(|| subject.clone()));
    let name = pick(&cfg.name_attribute, NAME_ATTRS).into_iter().next();
    let mut groups = pick(&cfg.groups_attribute, GROUP_ATTRS);
    groups.sort();
    groups.dedup();
    Ok(Assertion {
        id: doc.el(assertion).attr("ID").unwrap_or("").to_string(),
        subject,
        email,
        name,
        groups,
        attributes,
        in_response_to: irt,
        not_on_or_after: cond_end.map(|c| c.min(sc_end)).unwrap_or(sc_end),
        session_not_on_or_after: session_end,
    })
}

// ───────────────────────── requests, metadata, state ─────────────────────────

/// Our AuthnRequest (unsigned; HTTP-Redirect binding, response by HTTP-POST).
pub fn authn_request(cfg: &SamlConfig, sp_entity_id: &str, acs: &str, id: &str, now: i64) -> String {
    format!(
        "<samlp:AuthnRequest xmlns:samlp=\"{NS_SAMLP}\" xmlns:saml=\"{NS_SAML}\" ID=\"{}\" Version=\"2.0\" IssueInstant=\"{}\" Destination=\"{}\" ProtocolBinding=\"{BINDING_POST}\" AssertionConsumerServiceURL=\"{}\"><saml:Issuer>{}</saml:Issuer><samlp:NameIDPolicy Format=\"{}\" AllowCreate=\"true\"/></samlp:AuthnRequest>",
        esc(id),
        instant(now),
        esc(cfg.idp_sso_url.trim()),
        esc(acs),
        esc(sp_entity_id),
        esc(cfg.name_id_format())
    )
}

/// Raw DEFLATE (RFC 1951) with stored blocks: valid input for every inflater, no codec needed.
pub fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / 65_535 + 1));
    let chunks: Vec<&[u8]> = if data.is_empty() { vec![&[][..]] } else { data.chunks(65_535).collect() };
    for (i, c) in chunks.iter().enumerate() {
        out.push(if i + 1 == chunks.len() { 1 } else { 0 });
        let len = c.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(c);
    }
    out
}

/// The IdP URL a browser is sent to.
pub fn redirect_url(cfg: &SamlConfig, request_xml: &str, relay: &str) -> String {
    let req = ark_net::crypto::b64(&deflate_stored(request_xml.as_bytes()));
    let sep = if cfg.idp_sso_url.contains('?') { '&' } else { '?' };
    format!("{}{sep}{}", cfg.idp_sso_url.trim(), ark_net::form_encode(&[("SAMLRequest", &req), ("RelayState", relay)]))
}

/// SP metadata for the IdP administrator.
pub fn metadata(cfg: &SamlConfig, sp_entity_id: &str, acs: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor xmlns:md=\"{NS_MD}\" entityID=\"{}\">\n  <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"{NS_SAMLP}\">\n    <md:NameIDFormat>{}</md:NameIDFormat>\n    <md:AssertionConsumerService Binding=\"{BINDING_POST}\" Location=\"{}\" index=\"0\" isDefault=\"true\"/>\n  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n",
        esc(sp_entity_id),
        esc(cfg.name_id_format()),
        esc(acs)
    )
}

/// Binding names, for diagnostics.
pub const BINDINGS: (&str, &str) = (BINDING_REDIRECT, BINDING_POST);

const PENDING_TTL: i64 = 600;
const PENDING_MAX: usize = 512;

struct State {
    /// Outstanding AuthnRequest IDs and when they were issued.
    pending: Vec<(String, i64)>,
    /// Accepted assertion IDs and when they stop mattering.
    seen: Vec<(String, i64)>,
}

fn state() -> &'static Mutex<State> {
    static S: Mutex<State> = Mutex::new(State { pending: Vec::new(), seen: Vec::new() });
    &S
}

/// A fresh request ID, remembered for the callback.
pub fn new_request(now: i64) -> String {
    let id = format!("_ark{}", ark_net::crypto::random_token(24));
    let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
    s.pending.retain(|(_, t)| now - t < PENDING_TTL);
    s.pending.push((id.clone(), now));
    while s.pending.len() > PENDING_MAX {
        s.pending.remove(0);
    }
    id
}

/// Accept a verified assertion once: its `InResponseTo` must be outstanding (consumed here) and
/// its ID never seen before.
pub fn accept(a: &Assertion, now: i64) -> Result<(), String> {
    let mut s = state().lock().unwrap_or_else(|e| e.into_inner());
    s.seen.retain(|(_, until)| *until > now);
    if a.id.is_empty() || s.seen.iter().any(|(id, _)| *id == a.id) {
        return Err("assertion replayed".into());
    }
    if !a.in_response_to.is_empty() {
        s.pending.retain(|(_, t)| now - t < PENDING_TTL);
        let Some(i) = s.pending.iter().position(|(id, _)| *id == a.in_response_to) else {
            return Err("InResponseTo is not one of our outstanding requests".into());
        };
        s.pending.remove(i);
    }
    s.seen.push((a.id.clone(), a.not_on_or_after.max(now + 60)));
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const IDP: &str = "https://idp.test.example/saml";
    pub const SP: &str = "https://ark.test.example/auth/saml/metadata";
    pub const ACS: &str = "https://ark.test.example/auth/saml/acs";
    /// 2026-11-05T12:00:00Z, the instant the recorded response was issued.
    pub const T0: i64 = 1_793_880_000;

    pub fn cfg() -> SamlConfig {
        SamlConfig { idp_entity_id: IDP.into(), idp_sso_url: "https://idp.test.example/saml/sso".into(), idp_cert: include_str!("../tests/fixtures/saml/idp-cert.pem").into(), sp_entity_id: SP.into(), acs_url: ACS.into(), ..Default::default() }
    }

    /// Sign the element with `ID=id` in `xml` (enveloped, exc-c14n, RSA-SHA256), inserting the
    /// signature after its Issuer — what an IdP does. Test helper only: the recorded fixture is
    /// what proves interoperability, this lets the tests build attack variants.
    pub fn sign(xml: &str, id: &str, key_pk8: &[u8]) -> String {
        let doc = Doc::parse(xml).unwrap();
        let target = (0..doc.nodes.len()).find(|&i| doc.el(i).attr("ID") == Some(id)).unwrap();
        let digest = ark_net::crypto::b64(ring::digest::digest(&ring::digest::SHA256, doc.exc_c14n(target, None, &[]).as_bytes()).as_ref());
        let si = format!(
            "<ds:SignedInfo xmlns:ds=\"{NS_DSIG}\"><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        );
        let kp = ring::signature::RsaKeyPair::from_pkcs8(key_pk8).unwrap();
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), si.as_bytes(), &mut sig).unwrap();
        let block = format!("<ds:Signature xmlns:ds=\"{NS_DSIG}\">{si}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>", ark_net::crypto::b64(&sig));
        // After the target's Issuer (first `</saml:Issuer>` following the target's start tag).
        let start = xml.find(&format!("ID=\"{id}\"")).unwrap();
        let at = start + xml[start..].find("</saml:Issuer>").unwrap() + "</saml:Issuer>".len();
        format!("{}{block}{}", &xml[..at], &xml[at..])
    }

    pub fn idp_key() -> Vec<u8> {
        include_bytes!("../tests/fixtures/saml/idp-key.pk8").to_vec()
    }

    pub fn attacker_key() -> Vec<u8> {
        include_bytes!("../tests/fixtures/saml/other-key.pk8").to_vec()
    }

    /// An unsigned response in the shape real IdPs send (prefixes, xs/xsi, indentation).
    pub fn response(name_id: &str, assertion_id: &str, irt: &str) -> String {
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-11-05T12:00:00Z" Destination="{ACS}" InResponseTo="{irt}">
  <saml:Issuer>{IDP}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="{assertion_id}" Version="2.0" IssueInstant="2026-11-05T12:00:00Z">
    <saml:Issuer>{IDP}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="{irt}" NotOnOrAfter="2026-11-05T12:05:00Z" Recipient="{ACS}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-11-05T11:59:00Z" NotOnOrAfter="2026-11-05T12:05:00Z">
      <saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-11-05T12:00:00Z" SessionIndex="_s1" SessionNotOnOrAfter="2026-11-05T20:00:00Z">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue xsi:type="xs:string">{name_id}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue xsi:type="xs:string">Test User</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue xsi:type="xs:string">ark-ops</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">eng</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#
        )
    }

    fn keys() -> Vec<Key> {
        cfg().keys().unwrap()
    }

    fn check(xml: &str) -> Result<Assertion, String> {
        verify_response(xml, &keys(), &cfg(), &Expect { sp_entity_id: SP, acs_url: ACS, now: T0 + 30 })
    }

    #[test]
    fn recorded_response_verifies_and_maps_attributes() {
        // Recorded once from `sign(response(..))` with the test IdP key and kept verbatim, so a
        // change in canonicalization shows up here even if signer and verifier drift together.
        let recorded = include_str!("../tests/fixtures/saml/response-signed.xml");
        let a = check(recorded).unwrap();
        assert_eq!(a.subject, "alice@corp.test.example");
        assert_eq!(a.email.as_deref(), Some("alice@corp.test.example"));
        assert_eq!(a.name.as_deref(), Some("Test User"));
        assert_eq!(a.groups, vec!["ark-ops", "eng"]);
        assert_eq!(a.in_response_to, "_req1");
        assert_eq!(a.session_not_on_or_after, Some(parse_instant("2026-11-05T20:00:00Z").unwrap()));
        // Freshly signed variants verify too (assertion-signed and response-signed).
        let x = sign(&response("bob@corp.test.example", "_a2", "_req2"), "_a2", &idp_key());
        assert_eq!(check(&x).unwrap().subject, "bob@corp.test.example");
        let y = sign(&response("bob@corp.test.example", "_a3", "_req3"), "_resp1", &idp_key());
        assert_eq!(check(&y).unwrap().subject, "bob@corp.test.example");
        assert!(check(&response("bob@corp.test.example", "_a4", "_req4")).unwrap_err().contains("neither"), "unsigned");
    }

    #[test]
    fn tampering_wrong_key_and_policy_violations_are_refused() {
        let good = sign(&response("alice@corp.test.example", "_a1", "_req1"), "_a1", &idp_key());
        // Value changed after signing.
        assert!(check(&good.replace("alice@corp", "admin@corp")).unwrap_err().contains("digest"));
        // Signed by someone else's key.
        let forged = sign(&response("alice@corp.test.example", "_a1", "_req1"), "_a1", &attacker_key());
        assert!(check(&forged).unwrap_err().contains("does not verify"));
        // Time window, audience, recipient, issuer.
        let at = |now| verify_response(&good, &keys(), &cfg(), &Expect { sp_entity_id: SP, acs_url: ACS, now });
        assert!(at(T0 + 3600).unwrap_err().contains("expired"));
        assert!(at(T0 - 3600).unwrap_err().contains("not yet"));
        assert!(verify_response(&good, &keys(), &cfg(), &Expect { sp_entity_id: "https://other.example/sp", acs_url: ACS, now: T0 + 30 }).unwrap_err().contains("audience"));
        assert!(verify_response(&good, &keys(), &cfg(), &Expect { sp_entity_id: SP, acs_url: "https://other.example/acs", now: T0 + 30 }).is_err());
        let mut other_idp = cfg();
        other_idp.idp_entity_id = "https://evil.example".into();
        assert!(verify_response(&good, &keys(), &other_idp, &Expect { sp_entity_id: SP, acs_url: ACS, now: T0 + 30 }).unwrap_err().contains("issuer"));
        // IdP-initiated is off by default.
        let unsolicited = sign(&response("alice@corp.test.example", "_a5", "").replace(" InResponseTo=\"\"", ""), "_a5", &idp_key());
        assert!(check(&unsolicited).unwrap_err().contains("unsolicited"));
        let mut open = cfg();
        open.allow_idp_initiated = true;
        assert!(verify_response(&unsolicited, &keys(), &open, &Expect { sp_entity_id: SP, acs_url: ACS, now: T0 + 30 }).is_ok());
        // A DTD (XXE / billion laughs) never reaches the signature code.
        assert!(check(&format!("<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>{good}")).unwrap_err().contains("DTD"));
        // Comment inserted into the NameID after signing: canonical form is unchanged, so the
        // signature still verifies — and the value read is the whole text, not a truncation.
        let commented = good.replacen("alice@corp.test.example</saml:NameID>", "alice@corp.test.example<!--x--></saml:NameID>", 1);
        assert_eq!(check(&commented).unwrap().subject, "alice@corp.test.example");
    }

    /// The XML Signature Wrapping family (Somorovsky et al., 2012): a valid signed assertion is
    /// kept somewhere in the document while a forged one is placed where a naive SP reads.
    #[test]
    fn xml_signature_wrapping_attacks_are_refused() {
        let legit = response("alice@corp.test.example", "_good", "_req1");
        let signed = sign(&legit, "_good", &idp_key());
        let signed_assertion = {
            let s = signed.find("<saml:Assertion").unwrap();
            let e = signed.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
            signed[s..e].to_string()
        };
        let evil_assertion = signed_assertion.replace("alice@corp.test.example", "admin@corp.test.example").replace(r#"<saml:AttributeValue xsi:type="xs:string">ark-ops</saml:AttributeValue>"#, r#"<saml:AttributeValue xsi:type="xs:string">ark-admins</saml:AttributeValue>"#);
        let evil_unsigned = {
            let s = evil_assertion.find("<ds:Signature").unwrap();
            let e = evil_assertion.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
            format!("{}{}", &evil_assertion[..s], &evil_assertion[e..])
        };
        let head_end = signed.find("<saml:Assertion").unwrap();
        let head = &signed[..head_end];
        let tail = "\n</samlp:Response>";
        // XSW: forged assertion first, the signed original kept after it.
        let xsw_sibling = format!("{head}{}{signed_assertion}{tail}", evil_unsigned.replace("ID=\"_good\"", "ID=\"_evil\""));
        assert!(check(&xsw_sibling).unwrap_err().contains("exactly one Assertion"));
        // XSW: same ID reused for the forged copy (a naive getElementById finds either).
        let xsw_dup = format!("{head}{evil_unsigned}{signed_assertion}{tail}");
        assert!(check(&xsw_dup).unwrap_err().contains("duplicate ID"));
        // XSW: the signed original hidden inside Extensions / Object, forged one in its place.
        let hidden = format!("{}<samlp:Extensions>{signed_assertion}</samlp:Extensions>{}{tail}", &head, evil_unsigned.replace("ID=\"_good\"", "ID=\"_evil\""));
        assert!(check(&hidden).is_err());
        let in_object = evil_assertion.replace("</ds:Signature>", &format!("<ds:Object>{signed_assertion}</ds:Object></ds:Signature>"));
        assert!(check(&format!("{head}{in_object}{tail}")).is_err());
        // XSW: forged assertion carries the legit signature, which references the legit ID.
        let moved_sig = format!("{head}{}{tail}", evil_assertion.replace("ID=\"_good\"", "ID=\"_evil\""));
        assert!(check(&moved_sig).unwrap_err().contains("references"));
        // XSW on a signed Response: the signed Response wrapped in a forged one.
        let resp_signed = sign(&legit, "_resp1", &idp_key());
        let wrapped = format!(
            "<samlp:Response xmlns:samlp=\"{NS_SAMLP}\" xmlns:saml=\"{NS_SAML}\" ID=\"_outer\" Version=\"2.0\" Destination=\"{ACS}\"><samlp:Status><samlp:StatusCode Value=\"{STATUS_SUCCESS}\"/></samlp:Status>{}<samlp:Extensions>{resp_signed}</samlp:Extensions></samlp:Response>",
            &evil_unsigned.replace("ID=\"_good\"", "ID=\"_evil\"")
        );
        assert!(check(&wrapped).is_err());
        // A signature anywhere but directly in the Response / Assertion is refused, even a valid one.
        let sig_block = &signed[signed.find("<ds:Signature").unwrap()..signed.find("</ds:Signature>").unwrap() + "</ds:Signature>".len()];
        let stray = signed.replacen("<saml:Attribute Name=\"email\">", &format!("<saml:Attribute Name=\"email\">{}", sig_block.replace("#_good", "#_x")), 1);
        assert!(check(&stray).unwrap_err().contains("outside"));
        // The untouched signed response is still fine.
        assert!(check(&signed).is_ok());
    }

    /// [`response`] with its instants moved to `now` (for the live HTTP flow).
    pub fn response_at(name_id: &str, assertion_id: &str, irt: &str, now: i64) -> String {
        response(name_id, assertion_id, irt)
            .replace("2026-11-05T11:59:00Z", &instant(now - 60))
            .replace("2026-11-05T12:05:00Z", &instant(now + 300))
            .replace("2026-11-05T20:00:00Z", &instant(now + 8 * 3600))
            .replace("2026-11-05T12:00:00Z", &instant(now))
    }

    /// ent-048 end to end over HTTP: SP-initiated login → signed response posted cross-origin by
    /// the IdP page → session cookie with the mapped role and team → ARP; replay, forgery and
    /// an unsolicited response are refused and audited; SP metadata is served.
    #[test]
    fn saml_login_flows_into_the_shared_session_pipeline() {
        use crate::tenant::harness::{app, arp, req, text};
        let mut rbac = crate::identity::RbacConfig::default();
        rbac.groups.insert("ark-ops".into(), "operator".into());
        rbac.teams.insert("eng".into(), "eng".into());
        let a = app(crate::AppConfig {
            enabled: true,
            listen: "127.0.0.1:0".into(),
            rbac: Some(rbac),
            auth: crate::dashboard_auth::AuthConfig { enabled: true, provider: "saml".into(), secret: "0123456789abcdef0123".into(), saml: cfg(), ..Default::default() },
            ..Default::default()
        });
        let data = a.d.k.paths.data.clone();
        ark_kernel::tenancy::org_add(&data, "acme", "").unwrap();
        ark_kernel::tenancy::team_add(&data, "eng", "acme", "").unwrap();
        // Metadata.
        let md = a.clone().handle(req("GET", "/auth/saml/metadata", &[], ""));
        assert_eq!(md.status, 200);
        assert!(text(&md).contains(ACS) && text(&md).contains(SP));
        // SP-initiated: the redirect carries a deflated AuthnRequest whose ID we answer.
        let login = a.clone().handle(req("GET", "/auth/login", &[], ""));
        assert_eq!(login.status, 302);
        let loc = crate::tenant::harness::header(&login, "location").unwrap();
        let q = ark_net::parse_query(loc.split_once('?').unwrap().1);
        let saml_req = &q.iter().find(|(k, _)| k == "SAMLRequest").unwrap().1;
        let raw = ark_net::crypto::b64_decode(saml_req).unwrap();
        let req_xml = String::from_utf8(raw[5..].to_vec()).unwrap();
        let rd = Doc::parse(&req_xml).unwrap();
        let req_id = rd.el(0).attr("ID").unwrap().to_string();
        assert_eq!(rd.el(0).attr("AssertionConsumerServiceURL"), Some(ACS));
        let now = ark_kernel::util::unix_now();
        let post = |xml: &str| {
            let body = ark_net::form_encode(&[("SAMLResponse", &ark_net::crypto::b64(xml.as_bytes())), ("RelayState", "x")]);
            a.clone().handle(req("POST", "/auth/saml/acs", &[("origin", "https://idp.test.example"), ("host", "ark.test.example"), ("content-type", "application/x-www-form-urlencoded")], &body))
        };
        let signed = sign(&response_at("carol@corp.test.example", "_live1", &req_id, now), "_live1", &idp_key());
        let ok = post(&signed);
        assert_eq!(ok.status, 302, "{}", text(&ok));
        let set = crate::tenant::harness::header(&ok, "set-cookie").unwrap();
        let cookie = set.split(';').next().unwrap().to_string();
        let me = arp(&a, &format!("cookie:{cookie}"), "whoami", serde_json::json!({}));
        assert_eq!(me["result"]["kind"], "saml");
        assert_eq!(me["result"]["access"], "operator", "group ark-ops → operator, as with OIDC");
        let show = arp(&a, &format!("cookie:{cookie}"), "tenancy.show", serde_json::json!({}));
        assert_eq!(show["result"]["viewer"]["org"], "acme");
        assert_eq!(show["result"]["viewer"]["team"], "eng", "group eng → team eng");
        // Replay of the same response, a forged one, and an unsolicited one.
        assert_eq!(post(&signed).status, 400);
        let forged = sign(&response_at("carol@corp.test.example", "_live2", &crate::saml::new_request(now), now), "_live2", &attacker_key());
        assert_eq!(post(&forged).status, 400);
        let unsolicited = sign(&response_at("carol@corp.test.example", "_live3", "", now).replace(" InResponseTo=\"\"", ""), "_live3", &idp_key());
        assert_eq!(post(&unsolicited).status, 400);
        let logins = ark_security::audit::query(&data, &ark_security::audit::Query { kind: Some("auth.login".into()), limit: 100, ..Default::default() });
        assert!(logins.iter().any(|r| r["actor"]["kind"] == "saml" && r["outcome"] == "ok" && r["detail"]["roles"][0] == "operator"));
        assert_eq!(logins.iter().filter(|r| r["outcome"] == "fail").count(), 3, "each refusal is recorded with its reason");
        assert!(logins.iter().any(|r| r["detail"]["reason"].as_str().is_some_and(|s| s.contains("replayed"))));
        // A disabled registry profile is refused at login and its cookie stops working.
        let u = ark_kernel::agents::user_add(&a.d.k.paths, "Carol").unwrap();
        ark_kernel::agents::user_link_email(&a.d.k.paths, &u.id, "carol@corp.test.example").unwrap();
        ark_kernel::agents::user_update(&a.d.k.paths, &u.id, |u| {
            u.disabled = true;
            Ok(())
        })
        .unwrap();
        let gone = arp(&a, &format!("cookie:{cookie}"), "whoami", serde_json::json!({}));
        assert!(gone["error"].as_str().is_some_and(|e| e.starts_with("unauthorized")), "{gone}");
        let again = sign(&response_at("carol@corp.test.example", "_live4", &crate::saml::new_request(now), now), "_live4", &idp_key());
        assert_eq!(post(&again).status, 403);
    }

    /// Regenerates `tests/fixtures/saml/response-signed.xml` (run by hand with `--ignored`).
    #[test]
    #[ignore]
    fn record_fixture() {
        let x = sign(&response("alice@corp.test.example", "_a1", "_req1"), "_a1", &idp_key());
        std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/saml/response-signed.xml"), x).unwrap();
    }

    #[test]
    fn request_metadata_deflate_and_replay() {
        let c = cfg();
        let id = new_request(T0);
        let xml = authn_request(&c, SP, ACS, &id, T0);
        assert!(Doc::parse(&xml).is_ok() && xml.contains(&id) && xml.contains(ACS));
        let url = redirect_url(&c, &xml, "r1");
        assert!(url.starts_with("https://idp.test.example/saml/sso?SAMLRequest="));
        // Stored-block deflate round trip.
        let d = deflate_stored(xml.as_bytes());
        assert_eq!(d[0], 1);
        assert_eq!(&d[5..], xml.as_bytes());
        let md = metadata(&c, SP, ACS);
        let doc = Doc::parse(&md).unwrap();
        assert!(doc.el(0).is(NS_MD, "EntityDescriptor") && md.contains("WantAssertionsSigned=\"true\""));
        // InResponseTo must be ours, once; an assertion ID only once.
        let a = Assertion { id: "_x1".into(), in_response_to: id.clone(), not_on_or_after: T0 + 300, ..Default::default() };
        accept(&a, T0).unwrap();
        assert!(accept(&a, T0).unwrap_err().contains("replayed"));
        let b = Assertion { id: "_x2".into(), in_response_to: id, not_on_or_after: T0 + 300, ..Default::default() };
        assert!(accept(&b, T0).unwrap_err().contains("outstanding"));
        assert_eq!(parse_instant("2026-11-05T13:00:00+01:00").unwrap(), T0);
        assert_eq!(parse_instant("2026-11-05T12:00:00.123Z").unwrap(), T0);
        assert_eq!(instant(T0), "2026-11-05T12:00:00Z");
    }
}
