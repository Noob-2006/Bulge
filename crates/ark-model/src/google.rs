//! Google Cloud credentials for Vertex AI (Hermes `agent/vertex_adapter.py`, OpenClaw
//! `extensions/google/vertex-adc.ts`): Application Default Credentials without the SDK.
//! Order: `$GOOGLE_OAUTH_ACCESS_TOKEN` → service-account key (`$GOOGLE_APPLICATION_CREDENTIALS`,
//! RS256 JWT bearer grant) → user ADC (`gcloud auth application-default login`, refresh
//! grant) → GCE metadata server → `gcloud auth print-access-token`.

use crate::auth::{Cred, CredSource};
use crate::ProviderConfig;
use ark_core::{ProviderError, ProviderErrorKind as K};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

pub const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Static(String),
    ServiceAccount {
        email: String,
        key_pem: String,
        token_uri: String,
    },
    User {
        client_id: String,
        client_secret: String,
        refresh: String,
        token_uri: String,
    },
    Metadata(String),
    Gcloud,
}

pub struct TokenSource {
    pub mode: Mode,
    cache: Mutex<Option<(String, u64)>>,
}

fn adc_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let cfg = std::env::var_os("CLOUDSDK_CONFIG")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/gcloud")))?;
    let p = cfg.join("application_default_credentials.json");
    p.exists().then_some(p)
}

/// The Google Cloud project the credentials belong to (fills `{project}`).
pub fn adc_project() -> Option<String> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(adc_path()?).ok()?).ok()?;
    v["project_id"]
        .as_str()
        .or(v["quota_project_id"].as_str())
        .map(String::from)
}

impl TokenSource {
    pub fn new(mode: Mode) -> TokenSource {
        TokenSource {
            mode,
            cache: Mutex::new(None),
        }
    }

    pub fn from_env(_cfg: &ProviderConfig) -> Result<TokenSource, String> {
        if let Some(t) = std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty())
        {
            return Ok(Self::new(Mode::Static(t.trim().into())));
        }
        if let Some(p) = adc_path() {
            let s = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            return Self::from_json(&s).map_err(|e| format!("{}: {e}", p.display()));
        }
        if let Some(h) = std::env::var("GCE_METADATA_HOST")
            .ok()
            .filter(|h| !h.is_empty())
        {
            return Ok(Self::new(Mode::Metadata(format!("http://{h}"))));
        }
        if std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .is_ok_and(|s| s.contains("Google"))
        {
            return Ok(Self::new(Mode::Metadata(
                "http://metadata.google.internal".into(),
            )));
        }
        Ok(Self::new(Mode::Gcloud))
    }

    pub fn from_json(s: &str) -> Result<TokenSource, String> {
        let v: Value = serde_json::from_str(s).map_err(|e| format!("not JSON: {e}"))?;
        let get = |k: &str| v[k].as_str().map(String::from);
        match v["type"].as_str() {
            Some("service_account") => Ok(Self::new(Mode::ServiceAccount {
                email: get("client_email").ok_or("service account key has no client_email")?,
                key_pem: get("private_key").ok_or("service account key has no private_key")?,
                token_uri: get("token_uri").unwrap_or_else(|| TOKEN_URL.into()),
            })),
            Some("authorized_user") => Ok(Self::new(Mode::User {
                client_id: get("client_id").ok_or("ADC has no client_id")?,
                client_secret: get("client_secret").unwrap_or_default(),
                refresh: get("refresh_token").ok_or("ADC has no refresh_token")?,
                token_uri: get("token_uri").unwrap_or_else(|| TOKEN_URL.into()),
            })),
            other => Err(format!("unsupported credential type {other:?} (use a service account key or `gcloud auth application-default login`)")),
        }
    }

    fn mint(&self) -> Result<(String, u64), String> {
        let now = crate::ratelimit::now_ms();
        match &self.mode {
            Mode::Static(t) => Ok((t.clone(), now + 3_000_000)),
            Mode::ServiceAccount {
                email,
                key_pem,
                token_uri,
            } => {
                let jwt = sign_jwt(email, key_pem, token_uri, now / 1000)?;
                let v = crate::login::post_form(
                    token_uri,
                    &[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                        ("assertion", &jwt),
                    ],
                )?;
                token_of(&v, now)
            }
            Mode::User {
                client_id,
                client_secret,
                refresh,
                token_uri,
            } => {
                let v = crate::login::post_form(
                    token_uri,
                    &[
                        ("grant_type", "refresh_token"),
                        ("client_id", client_id),
                        ("client_secret", client_secret),
                        ("refresh_token", refresh),
                    ],
                )?;
                token_of(&v, now)
            }
            Mode::Metadata(host) => {
                // The metadata server is reached directly: it is a credential source here, never a model endpoint.
                let url =
                    format!("{host}/computeMetadata/v1/instance/service-accounts/default/token");
                let agent: ureq::Agent = ureq::Agent::config_builder()
                    .http_status_as_error(false)
                    .timeout_global(Some(Duration::from_secs(5)))
                    .proxy(None)
                    .build()
                    .into();
                let mut r = agent
                    .get(&url)
                    .header("Metadata-Flavor", "Google")
                    .call()
                    .map_err(|e| format!("GCE metadata: {e}"))?;
                let s = r
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| format!("GCE metadata: {e}"))?;
                let v: Value =
                    serde_json::from_str(&s).map_err(|e| format!("GCE metadata: {e}"))?;
                token_of(&v, now)
            }
            Mode::Gcloud => {
                let out = crate::auth::run_capture("gcloud auth print-access-token", Duration::from_secs(30)).map_err(|e| format!("{e}; set GOOGLE_APPLICATION_CREDENTIALS or run `gcloud auth application-default login`"))?;
                Ok((out.trim().to_string(), now + 3_000_000))
            }
        }
    }
}

fn token_of(v: &Value, now: u64) -> Result<(String, u64), String> {
    let t = v["access_token"]
        .as_str()
        .ok_or("token response has no access_token")?;
    Ok((
        t.to_string(),
        now + v["expires_in"].as_u64().unwrap_or(3600) * 1000,
    ))
}

/// PKCS#8 DER from a PEM block.
pub fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    ark_net::crypto::b64_decode(&body)
}

/// RS256 JWT for the OAuth 2.0 JWT bearer grant.
pub fn sign_jwt(email: &str, key_pem: &str, aud: &str, iat: u64) -> Result<String, String> {
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    let der = pem_der(key_pem).ok_or("service account private_key is not PEM")?;
    let key =
        RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("service account private_key: {e}"))?;
    let b = ark_net::crypto::b64url;
    let header = b(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = b(serde_json::json!({"iss": email, "scope": SCOPE, "aud": aud, "iat": iat, "exp": iat + 3600}).to_string().as_bytes());
    let msg = format!("{header}.{claims}");
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        msg.as_bytes(),
        &mut sig,
    )
    .map_err(|_| "RS256 signing failed")?;
    Ok(format!("{msg}.{}", b(&sig)))
}

impl CredSource for TokenSource {
    fn get(&self) -> Result<Cred, ProviderError> {
        let now = crate::ratelimit::now_ms();
        if let Some((t, _)) = self
            .cache
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(_, e)| now + 60_000 < *e)
        {
            return Ok(Cred::token(t.clone()));
        }
        let (t, exp) = self
            .mint()
            .map_err(|e| ProviderError::new(K::Auth, format!("Google Cloud credentials: {e}")))?;
        *self.cache.lock().unwrap() = Some((t.clone(), exp));
        Ok(Cred::token(t))
    }
    fn invalidate(&self) -> bool {
        !matches!(self.mode, Mode::Static(_)) && self.cache.lock().unwrap().take().is_some()
    }
    fn describe(&self) -> String {
        match &self.mode {
            Mode::Static(_) => "$GOOGLE_OAUTH_ACCESS_TOKEN".into(),
            Mode::ServiceAccount { email, .. } => format!("service account {email}"),
            Mode::User { .. } => "application default credentials (user)".into(),
            Mode::Metadata(_) => "GCE metadata server".into(),
            Mode::Gcloud => "gcloud auth print-access-token".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway 2048-bit test key generated for these tests only (not a real credential).
    pub(crate) const TEST_KEY: &str = include_str!("testdata/rsa_test_key.pem");

    #[test]
    fn service_account_jwt_grant() {
        let srv = crate::login::tests::fake_server(vec![(
            200,
            r#"{"access_token":"ya29.test","expires_in":3599}"#.into(),
        )]);
        let sa = serde_json::json!({"type":"service_account","client_email":"bot@p.iam.gserviceaccount.com","private_key": TEST_KEY,"token_uri": format!("{}/token", srv.base)}).to_string();
        let t = TokenSource::from_json(&sa).unwrap();
        assert_eq!(t.get().unwrap().token.as_deref(), Some("ya29.test"));
        t.get().unwrap();
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 1, "cached");
        assert!(reqs[0]
            .1
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"));
        let assertion = ark_net::parse_query(&reqs[0].1)
            .into_iter()
            .find(|(k, _)| k == "assertion")
            .unwrap()
            .1;
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: Value =
            serde_json::from_slice(&ark_net::crypto::b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "bot@p.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], SCOPE);
        // Signature verifies against the key's public half.
        let der = pem_der(TEST_KEY).unwrap();
        let kp = ring::signature::RsaKeyPair::from_pkcs8(&der).unwrap();
        use ring::signature::KeyPair;
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            kp.public_key().as_ref(),
        );
        pk.verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &ark_net::crypto::b64url_decode(parts[2]).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn user_adc_refresh_grant() {
        let srv = crate::login::tests::fake_server(vec![(
            200,
            r#"{"access_token":"ya29.user","expires_in":3600}"#.into(),
        )]);
        let j = serde_json::json!({"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r","token_uri": format!("{}/token", srv.base)}).to_string();
        let t = TokenSource::from_json(&j).unwrap();
        assert_eq!(t.get().unwrap().token.as_deref(), Some("ya29.user"));
        assert!(srv.requests()[0].1.contains("grant_type=refresh_token"));
        assert!(t.invalidate());
        assert!(TokenSource::from_json(r#"{"type":"external_account"}"#).is_err());
    }
}
