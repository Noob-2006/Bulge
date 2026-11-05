//! A strict XML tree, Exclusive XML Canonicalization 1.0 and enveloped XML-Signature
//! verification — just enough for SAML 2.0 (ent-048), and nothing a SAML response does not need.
//!
//! Why our own tree: the classic SAML breaks are *parser differentials* — the signature is
//! checked over one view of the document and the identity is read from another (XML signature
//! wrapping, the 2018 comment-truncation bugs). Here one tree serves both: the tokenizer is
//! `quick-xml`, namespaces are resolved by us, canonicalization walks the same nodes the SAML
//! layer later reads, and the caller gets back the *node index* that the signature covered.
//!
//! Refused outright: a DTD (no entity expansion, no XXE), entity references other than the five
//! predefined ones and character references, unbound prefixes, more than [`MAX_DEPTH`] levels or
//! [`MAX_NODES`] elements, and input over [`MAX_BYTES`].
//!
//! Signatures: exactly one `SignedInfo` with exactly one `Reference` whose `URI="#id"` names the
//! element that **contains** the signature (enveloped); transforms limited to
//! `enveloped-signature` + `xml-exc-c14n#`; canonicalization `xml-exc-c14n#` (comments are never
//! signed, so a comment can never split a value); digests SHA-256/384/512; signatures RSA PKCS#1
//! v1.5 with SHA-256/384/512 or ECDSA P-256/P-384. SHA-1 is refused. The verification key comes
//! from the caller (the configured IdP certificate), never from `KeyInfo` in the message.

use quick_xml::events::Event;
use std::collections::BTreeMap;

pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";
pub const ALG_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const ALG_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const MAX_BYTES: usize = 1 << 20;
pub const MAX_DEPTH: usize = 64;
pub const MAX_NODES: usize = 20_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    pub prefix: String,
    pub local: String,
    pub ns: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Child {
    Elem(usize),
    Text(String),
    Comment,
    Pi(String, String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Elem {
    pub prefix: String,
    pub local: String,
    pub ns: String,
    /// Namespace declarations written on this element: `(prefix, uri)`, `""` = default.
    pub decls: Vec<(String, String)>,
    pub attrs: Vec<Attr>,
    pub children: Vec<Child>,
    pub parent: Option<usize>,
}

impl Elem {
    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.ns == ns && self.local == local
    }
    /// An unqualified attribute.
    pub fn attr(&self, local: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.ns.is_empty() && a.local == local).map(|a| a.value.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Doc {
    pub nodes: Vec<Elem>,
}

fn predefined(name: &str) -> Option<char> {
    Some(match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "apos" => '\'',
        "quot" => '"',
        _ => return None,
    })
}

fn split_qname(q: &str) -> (&str, &str) {
    match q.split_once(':') {
        Some((p, l)) => (p, l),
        None => ("", q),
    }
}

impl Doc {
    pub const ROOT: usize = 0;

    pub fn parse(text: &str) -> Result<Doc, String> {
        if text.len() > MAX_BYTES {
            return Err(format!("XML document over {MAX_BYTES} bytes"));
        }
        let mut r = quick_xml::Reader::from_str(text);
        {
            let c = r.config_mut();
            c.trim_text(false);
            c.expand_empty_elements = false;
            c.check_end_names = true;
            c.check_comments = true;
        }
        let mut nodes: Vec<Elem> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        // In-scope namespaces per open element (cloned on push: documents are small).
        let mut scopes: Vec<BTreeMap<String, String>> = vec![BTreeMap::from([("xml".to_string(), NS_XML.to_string())])];
        let mut done = false;
        loop {
            let ev = r.read_event().map_err(|e| format!("XML: {e} at byte {}", r.buffer_position()))?;
            match ev {
                Event::Eof => break,
                Event::DocType(_) => return Err("XML: a DTD is not allowed".into()),
                Event::Decl(_) => {}
                Event::Start(ref s) | Event::Empty(ref s) => {
                    if done {
                        return Err("XML: content after the root element".into());
                    }
                    if stack.len() >= MAX_DEPTH {
                        return Err("XML: nesting too deep".into());
                    }
                    if nodes.len() >= MAX_NODES {
                        return Err("XML: too many elements".into());
                    }
                    let mut scope = scopes.last().cloned().unwrap_or_default();
                    let mut decls = Vec::new();
                    let mut raw_attrs = Vec::new();
                    for a in s.attributes() {
                        let a = a.map_err(|e| format!("XML attribute: {e}"))?;
                        let key = a.key.0.to_string();
                        let value = a.normalized_value(quick_xml::XmlVersion::Implicit1_0).map_err(|e| format!("XML attribute `{key}`: {e}"))?.into_owned();
                        if key == "xmlns" {
                            decls.push((String::new(), value.clone()));
                            scope.insert(String::new(), value);
                        } else if let Some(p) = key.strip_prefix("xmlns:") {
                            if value.is_empty() {
                                return Err(format!("XML: prefix `{p}` undeclared (namespaces 1.0)"));
                            }
                            if p == "xml" || p == "xmlns" {
                                return Err(format!("XML: `{key}` may not be declared"));
                            }
                            decls.push((p.to_string(), value.clone()));
                            scope.insert(p.to_string(), value);
                        } else {
                            raw_attrs.push((key, value));
                        }
                    }
                    let qn = s.name().0.to_string();
                    let (prefix, local) = split_qname(&qn);
                    let ns = if prefix.is_empty() { scope.get("").cloned().unwrap_or_default() } else { scope.get(prefix).cloned().ok_or_else(|| format!("XML: unbound prefix `{prefix}`"))? };
                    let mut attrs = Vec::new();
                    for (k, v) in raw_attrs {
                        let (p, l) = split_qname(&k);
                        let ans = if p.is_empty() { String::new() } else { scope.get(p).cloned().ok_or_else(|| format!("XML: unbound prefix `{p}`"))? };
                        if attrs.iter().any(|a: &Attr| a.ns == ans && a.local == l) {
                            return Err(format!("XML: duplicate attribute `{k}`"));
                        }
                        attrs.push(Attr { prefix: p.into(), local: l.into(), ns: ans, value: v });
                    }
                    let idx = nodes.len();
                    let parent = stack.last().copied();
                    if parent.is_none() && idx != 0 {
                        return Err("XML: more than one root element".into());
                    }
                    nodes.push(Elem { prefix: prefix.into(), local: local.into(), ns, decls, attrs, children: vec![], parent });
                    if let Some(p) = parent {
                        nodes[p].children.push(Child::Elem(idx));
                    }
                    if matches!(ev, Event::Start(_)) {
                        stack.push(idx);
                        scopes.push(scope);
                    } else if parent.is_none() {
                        done = true;
                    }
                }
                Event::End(_) => {
                    stack.pop();
                    scopes.pop();
                    if stack.is_empty() {
                        done = true;
                    }
                }
                Event::Text(t) => {
                    let s = t.xml10_content().into_owned();
                    match stack.last() {
                        Some(&p) => push_text(&mut nodes[p], &s),
                        None if s.trim().is_empty() => {}
                        None => return Err("XML: text outside the root element".into()),
                    }
                }
                Event::CData(t) => {
                    let s = t.into_inner().into_owned();
                    match stack.last() {
                        Some(&p) => push_text(&mut nodes[p], &s),
                        None => return Err("XML: CDATA outside the root element".into()),
                    }
                }
                Event::GeneralRef(g) => {
                    let name = g.xml10_content().into_owned();
                    let c = if g.is_char_ref() { g.resolve_char_ref().map_err(|e| format!("XML: {e}"))?.ok_or("XML: bad character reference")? } else { predefined(&name).ok_or_else(|| format!("XML: undefined entity `&{name};`"))? };
                    match stack.last() {
                        Some(&p) => push_text(&mut nodes[p], &c.to_string()),
                        None => return Err("XML: reference outside the root element".into()),
                    }
                }
                Event::Comment(_) => {
                    if let Some(&p) = stack.last() {
                        nodes[p].children.push(Child::Comment);
                    }
                }
                Event::PI(p) => {
                    if let Some(&e) = stack.last() {
                        let target = p.target().to_string();
                        let data = p.content().trim_start().to_string();
                        nodes[e].children.push(Child::Pi(target, data));
                    }
                }
            }
        }
        if nodes.is_empty() || !stack.is_empty() {
            return Err("XML: no complete root element".into());
        }
        Ok(Doc { nodes })
    }

    pub fn el(&self, i: usize) -> &Elem {
        &self.nodes[i]
    }

    /// Child elements of `i`.
    pub fn kids(&self, i: usize) -> impl Iterator<Item = usize> + '_ {
        self.nodes[i].children.iter().filter_map(|c| if let Child::Elem(e) = c { Some(*e) } else { None })
    }

    pub fn kids_named<'a>(&'a self, i: usize, ns: &'a str, local: &'a str) -> impl Iterator<Item = usize> + 'a {
        self.kids(i).filter(move |&k| self.nodes[k].is(ns, local))
    }

    pub fn kid(&self, i: usize, ns: &str, local: &str) -> Option<usize> {
        self.kids_named(i, ns, local).next()
    }

    /// The one child of that name, or an error naming what is missing / repeated.
    pub fn only_kid(&self, i: usize, ns: &str, local: &str) -> Result<usize, String> {
        let v: Vec<usize> = self.kids_named(i, ns, local).collect();
        match v.as_slice() {
            [k] => Ok(*k),
            [] => Err(format!("missing <{local}> in <{}>", self.nodes[i].local)),
            _ => Err(format!("more than one <{local}> in <{}>", self.nodes[i].local)),
        }
    }

    /// Every element in document order (index order is document order).
    pub fn all_named<'a>(&'a self, ns: &'a str, local: &'a str) -> impl Iterator<Item = usize> + 'a {
        (0..self.nodes.len()).filter(move |&i| self.nodes[i].is(ns, local))
    }

    /// Is `a` an ancestor of (or equal to) `b`?
    pub fn contains(&self, a: usize, b: usize) -> bool {
        let mut cur = Some(b);
        while let Some(c) = cur {
            if c == a {
                return true;
            }
            cur = self.nodes[c].parent;
        }
        false
    }

    /// All text below `i`, comments skipped (never "the first text node": a comment must not be
    /// able to cut a value short).
    pub fn text(&self, i: usize) -> String {
        let mut out = String::new();
        for c in &self.nodes[i].children {
            match c {
                Child::Text(t) => out.push_str(t),
                Child::Elem(e) => out.push_str(&self.text(*e)),
                _ => {}
            }
        }
        out
    }

    /// Namespaces in scope at `i` (declarations on `i` and its ancestors).
    fn in_scope(&self, i: usize) -> BTreeMap<String, String> {
        let mut chain = vec![i];
        while let Some(p) = self.nodes[*chain.last().unwrap()].parent {
            chain.push(p);
        }
        let mut m = BTreeMap::new();
        for e in chain.iter().rev() {
            for (p, u) in &self.nodes[*e].decls {
                m.insert(p.clone(), u.clone());
            }
        }
        m
    }

    /// Exclusive XML Canonicalization 1.0, without comments, of the subtree at `apex`, leaving
    /// out the subtree at `exclude` (the enveloped signature). `inclusive` is the
    /// `InclusiveNamespaces PrefixList` (`#default` = the default namespace).
    pub fn exc_c14n(&self, apex: usize, exclude: Option<usize>, inclusive: &[String]) -> String {
        let mut out = String::new();
        let rendered: BTreeMap<String, String> = BTreeMap::new();
        let incl: Vec<String> = inclusive.iter().map(|p| if p == "#default" { String::new() } else { p.clone() }).collect();
        self.c14n_elem(apex, exclude, &incl, &rendered, &mut out);
        out
    }

    fn c14n_elem(&self, i: usize, exclude: Option<usize>, incl: &[String], rendered: &BTreeMap<String, String>, out: &mut String) {
        if Some(i) == exclude {
            return;
        }
        let e = &self.nodes[i];
        let scope = self.in_scope(i);
        // Visibly utilized prefixes: the element's own and those of its prefixed attributes.
        let mut used: Vec<String> = vec![e.prefix.clone()];
        for a in &e.attrs {
            if !a.prefix.is_empty() && !used.contains(&a.prefix) {
                used.push(a.prefix.clone());
            }
        }
        for p in incl {
            if !used.contains(p) && (scope.contains_key(p) || p.is_empty()) {
                used.push(p.clone());
            }
        }
        let mut next = rendered.clone();
        let mut decls: Vec<(String, String)> = Vec::new();
        for p in used {
            if p == "xml" {
                continue;
            }
            let uri = scope.get(&p).cloned().unwrap_or_default();
            let prev = rendered.get(&p).cloned().unwrap_or_default();
            if p.is_empty() {
                // xmlns="" only to undo a non-empty default the output already carries.
                if uri != prev {
                    decls.push((p.clone(), uri.clone()));
                    next.insert(p, uri);
                }
            } else if rendered.get(&p) != Some(&uri) {
                decls.push((p.clone(), uri.clone()));
                next.insert(p, uri);
            }
        }
        decls.sort();
        let qn = |p: &str, l: &str| if p.is_empty() { l.to_string() } else { format!("{p}:{l}") };
        out.push('<');
        out.push_str(&qn(&e.prefix, &e.local));
        for (p, u) in &decls {
            if p.is_empty() {
                out.push_str(" xmlns=\"");
            } else {
                out.push_str(&format!(" xmlns:{p}=\""));
            }
            esc_attr(u, out);
            out.push('"');
        }
        let mut attrs: Vec<&Attr> = e.attrs.iter().collect();
        attrs.sort_by(|a, b| (a.ns.as_str(), a.local.as_str()).cmp(&(b.ns.as_str(), b.local.as_str())));
        for a in attrs {
            out.push(' ');
            out.push_str(&qn(&a.prefix, &a.local));
            out.push_str("=\"");
            esc_attr(&a.value, out);
            out.push('"');
        }
        out.push('>');
        for c in &e.children {
            match c {
                Child::Elem(k) => self.c14n_elem(*k, exclude, incl, &next, out),
                Child::Text(t) => esc_text(t, out),
                Child::Comment => {}
                Child::Pi(t, d) => {
                    out.push_str("<?");
                    out.push_str(t);
                    if !d.is_empty() {
                        out.push(' ');
                        out.push_str(d);
                    }
                    out.push_str("?>");
                }
            }
        }
        out.push_str("</");
        out.push_str(&qn(&e.prefix, &e.local));
        out.push('>');
    }
}

fn push_text(e: &mut Elem, s: &str) {
    if let Some(Child::Text(t)) = e.children.last_mut() {
        t.push_str(s);
    } else {
        e.children.push(Child::Text(s.to_string()));
    }
}

fn esc_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn esc_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

// ───────────────────────── keys ─────────────────────────

/// A verification key taken from an X.509 certificate.
#[derive(Debug, Clone, PartialEq)]
pub enum Key {
    /// `RSAPublicKey` DER.
    Rsa(Vec<u8>),
    /// Uncompressed EC point and the curve (`256` / `384`).
    Ec(Vec<u8>, u16),
}

/// One DER TLV: `(tag, content, rest)`.
fn der(b: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let bad = || "certificate: malformed DER".to_string();
    let tag = *b.first().ok_or_else(bad)?;
    let l0 = *b.get(1).ok_or_else(bad)?;
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < 2 + n {
            return Err(bad());
        }
        (b[2..2 + n].iter().fold(0usize, |a, x| (a << 8) | *x as usize), 2 + n)
    };
    let end = hdr.checked_add(len).ok_or_else(bad)?;
    if b.len() < end {
        return Err(bad());
    }
    Ok((tag, &b[hdr..end], &b[end..]))
}

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// The public key of a DER certificate (`Certificate → tbsCertificate → subjectPublicKeyInfo`).
pub fn cert_key(cert_der: &[u8]) -> Result<Key, String> {
    let (t, cert, _) = der(cert_der)?;
    let (t2, tbs, _) = der(cert)?;
    if t != 0x30 || t2 != 0x30 {
        return Err("certificate: not a SEQUENCE".into());
    }
    let mut rest = tbs;
    // [0] version (optional), serial, signature alg, issuer, validity, subject, then SPKI.
    let (tag, _, r) = der(rest)?;
    if tag == 0xa0 {
        rest = r;
    }
    for _ in 0..5 {
        rest = der(rest)?.2;
    }
    let (tag, spki, _) = der(rest)?;
    if tag != 0x30 {
        return Err("certificate: no subjectPublicKeyInfo".into());
    }
    let (_, alg, after) = der(spki)?;
    let (_, oid, params) = der(alg)?;
    let (btag, bits, _) = der(after)?;
    if btag != 0x03 || bits.first() != Some(&0) {
        return Err("certificate: bad subjectPublicKey".into());
    }
    let key = bits[1..].to_vec();
    if oid == OID_RSA {
        return Ok(Key::Rsa(key));
    }
    if oid == OID_EC {
        let (_, curve, _) = der(params)?;
        return match curve {
            c if c == OID_P256 => Ok(Key::Ec(key, 256)),
            c if c == OID_P384 => Ok(Key::Ec(key, 384)),
            _ => Err("certificate: unsupported EC curve (P-256 / P-384 only)".into()),
        };
    }
    Err("certificate: unsupported key type (RSA or EC only)".into())
}

/// PEM (one or more `CERTIFICATE` blocks) or bare base64 DER → DER certificates.
pub fn parse_certs(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let t = text.trim();
    let mut out = Vec::new();
    if t.contains("-----BEGIN") {
        for block in t.split("-----BEGIN CERTIFICATE-----").skip(1) {
            let body = block.split("-----END CERTIFICATE-----").next().unwrap_or("");
            let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            out.push(seagent_net::crypto::b64_decode(&b64).ok_or("certificate: bad base64 in PEM")?);
        }
    } else if !t.is_empty() {
        let b64: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        out.push(seagent_net::crypto::b64_decode(&b64).ok_or("certificate: not PEM or base64 DER")?);
    }
    if out.is_empty() {
        return Err("no certificate".into());
    }
    for c in &out {
        cert_key(c)?;
    }
    Ok(out)
}

// ───────────────────────── signature verification ─────────────────────────

fn digest(alg: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    use ring::digest as d;
    let a = match alg {
        "http://www.w3.org/2001/04/xmlenc#sha256" => &d::SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => &d::SHA384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => &d::SHA512,
        "http://www.w3.org/2000/09/xmldsig#sha1" => return Err("SHA-1 digests are refused".into()),
        other => return Err(format!("unsupported digest `{other}`")),
    };
    Ok(d::digest(a, data).as_ref().to_vec())
}

fn verify_sig(alg: &str, keys: &[Key], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    use ring::signature as s;
    for k in keys {
        let algo: &dyn s::VerificationAlgorithm = match (alg, k) {
            ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", Key::Rsa(_)) => &s::RSA_PKCS1_2048_8192_SHA256,
            ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", Key::Rsa(_)) => &s::RSA_PKCS1_2048_8192_SHA384,
            ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", Key::Rsa(_)) => &s::RSA_PKCS1_2048_8192_SHA512,
            ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", Key::Ec(_, 256)) => &s::ECDSA_P256_SHA256_FIXED,
            ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", Key::Ec(_, 384)) => &s::ECDSA_P384_SHA384_FIXED,
            ("http://www.w3.org/2000/09/xmldsig#rsa-sha1", _) => return Err("RSA-SHA1 signatures are refused".into()),
            _ => continue,
        };
        let raw = match k {
            Key::Rsa(d) | Key::Ec(d, _) => d,
        };
        if s::UnparsedPublicKey::new(algo, raw).verify(msg, sig).is_ok() {
            return Ok(());
        }
    }
    Err("signature does not verify with the configured IdP certificate".into())
}

fn prefix_list(doc: &Doc, transform: usize) -> Vec<String> {
    doc.kids(transform)
        .filter(|&k| doc.el(k).ns == ALG_EXC_C14N && doc.el(k).local == "InclusiveNamespaces")
        .flat_map(|k| doc.el(k).attr("PrefixList").unwrap_or("").split_whitespace().map(String::from).collect::<Vec<_>>())
        .collect()
}

/// Verify the enveloped signature element `sig` and return the element it covers — always its
/// parent, whose `ID` must be what the single `Reference` names. Any other shape is an error.
pub fn verify_enveloped(doc: &Doc, sig: usize, keys: &[Key]) -> Result<usize, String> {
    let s = doc.el(sig);
    if !s.is(NS_DSIG, "Signature") {
        return Err("not a ds:Signature".into());
    }
    let parent = s.parent.ok_or("a signature cannot be the root")?;
    let id = doc.el(parent).attr("ID").ok_or("the signed element has no ID")?;
    let si = doc.only_kid(sig, NS_DSIG, "SignedInfo")?;
    let cm = doc.only_kid(si, NS_DSIG, "CanonicalizationMethod")?;
    if doc.el(cm).attr("Algorithm") != Some(ALG_EXC_C14N) {
        return Err(format!("unsupported canonicalization `{}` (exclusive C14N without comments only)", doc.el(cm).attr("Algorithm").unwrap_or("")));
    }
    let sm = doc.only_kid(si, NS_DSIG, "SignatureMethod")?;
    let sig_alg = doc.el(sm).attr("Algorithm").unwrap_or("").to_string();
    let reference = doc.only_kid(si, NS_DSIG, "Reference")?;
    let uri = doc.el(reference).attr("URI").unwrap_or("");
    if uri != format!("#{id}") {
        return Err(format!("the signature references `{uri}`, not its own element `#{id}`"));
    }
    let mut incl = Vec::new();
    let mut enveloped = false;
    if let Some(ts) = doc.kid(reference, NS_DSIG, "Transforms") {
        for t in doc.kids(ts) {
            if !doc.el(t).is(NS_DSIG, "Transform") {
                return Err("unexpected element in Transforms".into());
            }
            match doc.el(t).attr("Algorithm").unwrap_or("") {
                ALG_ENVELOPED if !enveloped => enveloped = true,
                ALG_EXC_C14N if incl.is_empty() => incl = prefix_list(doc, t),
                ALG_EXC_C14N => {}
                other => return Err(format!("unsupported transform `{other}`")),
            }
        }
    }
    if !enveloped {
        return Err("the signature must be enveloped (enveloped-signature transform)".into());
    }
    let dm = doc.only_kid(reference, NS_DSIG, "DigestMethod")?;
    let dv = doc.only_kid(reference, NS_DSIG, "DigestValue")?;
    let want = seagent_net::crypto::b64_decode(&doc.text(dv).chars().filter(|c| !c.is_whitespace()).collect::<String>()).ok_or("bad DigestValue")?;
    let got = digest(doc.el(dm).attr("Algorithm").unwrap_or(""), doc.exc_c14n(parent, Some(sig), &incl).as_bytes())?;
    if !seagent_net::crypto::ct_eq(&want, &got) {
        return Err("digest mismatch: the signed element was changed".into());
    }
    let sv = doc.only_kid(sig, NS_DSIG, "SignatureValue")?;
    let sig_bytes = seagent_net::crypto::b64_decode(&doc.text(sv).chars().filter(|c| !c.is_whitespace()).collect::<String>()).ok_or("bad SignatureValue")?;
    let si_incl = prefix_list(doc, cm);
    verify_sig(&sig_alg, keys, doc.exc_c14n(si, None, &si_incl).as_bytes(), &sig_bytes)?;
    Ok(parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(xml: &str, path_local: &str) -> String {
        let d = Doc::parse(xml).unwrap();
        let i = (0..d.nodes.len()).find(|&i| d.el(i).local == path_local).unwrap();
        d.exc_c14n(i, None, &[])
    }

    #[test]
    fn exclusive_c14n_matches_the_specification_examples() {
        // W3C exc-c14n §2.2: only visibly utilized namespaces travel with the apex.
        let xml = r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n0:local>"#;
        assert_eq!(c14n(xml, "elem2"), r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2>"#);
        // Attribute order (namespace URI, local name), declaration order, empty elements,
        // whitespace inside tags, entity and character references, CDATA.
        let xml = "<r xmlns=\"urn:d\" xmlns:b=\"urn:b\" xmlns:a=\"urn:a\" z=\"1\"   b:y=\"2\" a:x='3&amp;\t'><e   /><![CDATA[a<b]]>&#65;&gt;\r\n</r>";
        assert_eq!(c14n(xml, "r"), "<r xmlns=\"urn:d\" xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" z=\"1\" a:x=\"3&amp; \" b:y=\"2\"><e></e>a&lt;bA&gt;\n</r>");
        // A default namespace undone below the apex; comments dropped; PIs kept.
        let xml = r#"<a xmlns="urn:x"><b xmlns=""><!-- c --><?pi data?></b></a>"#;
        assert_eq!(c14n(xml, "a"), r#"<a xmlns="urn:x"><b xmlns=""><?pi data?></b></a>"#);
        assert_eq!(c14n(xml, "b"), r#"<b><?pi data?></b>"#);
        // InclusiveNamespaces: `xs` is rendered although only an attribute *value* uses it.
        let d = Doc::parse(r#"<p xmlns:xs="urn:xs" xmlns:xsi="urn:xsi"><v xsi:type="xs:string">x</v></p>"#).unwrap();
        assert_eq!(d.exc_c14n(1, None, &[]), r#"<v xmlns:xsi="urn:xsi" xsi:type="xs:string">x</v>"#);
        assert_eq!(d.exc_c14n(1, None, &["xs".into()]), r#"<v xmlns:xs="urn:xs" xmlns:xsi="urn:xsi" xsi:type="xs:string">x</v>"#);
    }

    #[test]
    fn hostile_documents_are_refused() {
        assert!(Doc::parse(r#"<!DOCTYPE r [<!ENTITY x "boom">]><r>&x;</r>"#).unwrap_err().contains("DTD"));
        assert!(Doc::parse("<r>&nbsp;</r>").unwrap_err().contains("undefined entity"));
        assert!(Doc::parse("<p:r/>").unwrap_err().contains("unbound prefix"));
        assert!(Doc::parse("<r a='1' a='2'/>").is_err());
        assert!(Doc::parse("<r/><r/>").is_err());
        assert!(Doc::parse(&format!("{}{}", "<a>".repeat(MAX_DEPTH + 1), "</a>".repeat(MAX_DEPTH + 1))).unwrap_err().contains("deep"));
        // A comment never truncates a value.
        let d = Doc::parse("<n>alice@corp.example<!---->.evil.example</n>").unwrap();
        assert_eq!(d.text(0), "alice@corp.example.evil.example");
    }

    #[test]
    fn certificate_keys_parse() {
        let pem = include_str!("../tests/fixtures/saml/idp-cert.pem");
        let der = parse_certs(pem).unwrap();
        assert!(matches!(cert_key(&der[0]).unwrap(), Key::Rsa(_)));
        assert!(parse_certs("not a cert").is_err());
    }
}
