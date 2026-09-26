//! Authenticated JSON client for the admin onboarding endpoints.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::pyvalue::Json;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Failure talking to the admin API. `Display` is the user-facing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The server could not be reached at all (DNS, refused, timeout...).
    /// The CLI keeps polling through these while the user switches Wi-Fi.
    Unreachable(String),
    /// The server answered, but not with what we needed.
    Failed(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Unreachable(msg) | ApiError::Failed(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ApiError {}

/// The admin endpoints the onboarding flows use.
pub trait OnboardingApi: Send + Sync {
    fn login(&self) -> Result<(), ApiError>;
    fn list_devices(&self) -> Result<Vec<Value>, ApiError>;
    fn start_session(&self, duid: &str) -> Result<Json, ApiError>;
    fn get_session(&self, session_id: &str) -> Result<Json, ApiError>;
    fn delete_session(&self, session_id: &str) -> Result<Json, ApiError>;
    fn get_status(&self) -> Result<Json, ApiError>;
}

/// Build the message for a non-2xx response like the Python client did.
pub fn format_http_error(status: u16, body: &str) -> String {
    if let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(body) {
        let message = crate::pyvalue::first_str(&[parsed.get("error"), parsed.get("detail")], "");
        let message = message.trim();
        if !message.is_empty() {
            return format!("HTTP {status}: {message}");
        }
    }
    let body = body.trim();
    if body.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {}", truncate_chars(body, 200))
    }
}

fn truncate_chars(text: &str, max: usize) -> &str {
    text.char_indices()
        .nth(max)
        .map_or(text, |(idx, _)| &text[..idx])
}

/// `urllib.parse.quote(value, safe="")`.
pub fn quote_path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The process-wide rustls crypto backend (ring; no C toolchain or OpenSSL).
pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// HTTPS client with a cookie jar, like the Python `urllib` opener.
pub struct RemoteOnboardingApi {
    base_url: String,
    admin_password: String,
    agent: ureq::Agent,
    logged_in: AtomicBool,
    cookies: Mutex<CookieJar>,
}

/// Name/value cookies for the single admin origin. Path, domain and expiry
/// attributes are ignored except `Max-Age<=0`, which deletes the cookie.
#[derive(Debug, Default)]
struct CookieJar(Vec<(String, String)>);

impl CookieJar {
    fn store(&mut self, set_cookie: &str) {
        let mut parts = set_cookie.split(';');
        let Some((name, value)) = parts.next().and_then(|pair| pair.split_once('=')) else {
            return;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() {
            return;
        }
        let expired = parts.any(|attr| {
            attr.split_once('=').is_some_and(|(key, val)| {
                key.trim().eq_ignore_ascii_case("max-age")
                    && val.trim().parse::<i64>().is_ok_and(|age| age <= 0)
            })
        });
        self.0.retain(|(existing, _)| existing != name);
        if !expired {
            self.0.push((name.to_owned(), value.to_owned()));
        }
    }

    fn header(&self) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        let mut sorted: Vec<_> = self.0.iter().collect();
        sorted.sort();
        Some(
            sorted
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

impl RemoteOnboardingApi {
    /// `allow_insecure_tls` disables certificate verification; otherwise the
    /// OS trust store is used (like Python's default SSL context).
    pub fn new(base_url: &str, admin_password: &str, allow_insecure_tls: bool) -> Self {
        use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(crypto_provider())
            .root_certs(RootCerts::PlatformVerifier)
            .disable_verification(allow_insecure_tls)
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(DEFAULT_TIMEOUT))
            .http_status_as_error(false)
            .user_agent(concat!("roborock-onboard/", env!("CARGO_PKG_VERSION")))
            .tls_config(tls)
            .build()
            .into();
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            admin_password: admin_password.to_owned(),
            agent,
            logged_in: AtomicBool::new(false),
            cookies: Mutex::new(CookieJar::default()),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn request_json(
        &self,
        method: &str,
        path: &str,
        payload: Option<&Value>,
        allow_401: bool,
    ) -> Result<Json, ApiError> {
        let url = format!("{}{path}", self.base_url);
        let cookie = self.jar().header();
        let result = match (method, payload) {
            ("POST", Some(payload)) => {
                let mut request = self
                    .agent
                    .post(&url)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json");
                if let Some(cookie) = &cookie {
                    request = request.header("Cookie", cookie);
                }
                request.send(crate::pyjson::dumps(payload))
            }
            _ => {
                let mut request = if method == "DELETE" {
                    self.agent.delete(&url)
                } else {
                    self.agent.get(&url)
                }
                .header("Accept", "application/json");
                if let Some(cookie) = &cookie {
                    request = request.header("Cookie", cookie);
                }
                request.call()
            }
        };
        let mut response = result.map_err(|err| {
            ApiError::Unreachable(format!("Unable to reach {}: {err}", self.base_url))
        })?;
        {
            let mut jar = self.jar();
            for value in response.headers().get_all("set-cookie") {
                if let Ok(value) = value.to_str() {
                    jar.store(value);
                }
            }
        }
        let status = response.status().as_u16();
        let raw = response.body_mut().read_to_vec().map_err(|err| {
            ApiError::Unreachable(format!("Unable to reach {}: {err}", self.base_url))
        })?;
        let raw = String::from_utf8_lossy(&raw);
        if !(200..300).contains(&status) {
            if status == 401 && allow_401 {
                return Err(ApiError::Failed("Invalid admin password.".into()));
            }
            return Err(ApiError::Failed(format_http_error(status, &raw)));
        }
        if raw.is_empty() {
            return Ok(Json::new());
        }
        match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Object(map)) => Ok(map),
            Ok(other) => Err(ApiError::Failed(format!(
                "Unexpected response from {path}: {other}"
            ))),
            Err(_) => Err(ApiError::Failed(format!(
                "Invalid JSON response from {path}: {}",
                truncate_chars(&raw, 200)
            ))),
        }
    }

    fn jar(&self) -> std::sync::MutexGuard<'_, CookieJar> {
        self.cookies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn session_path(session_id: &str) -> String {
        format!(
            "/admin/api/onboarding/sessions/{}",
            quote_path_segment(session_id)
        )
    }
}

impl OnboardingApi for RemoteOnboardingApi {
    fn login(&self) -> Result<(), ApiError> {
        if self.logged_in.load(Ordering::SeqCst) {
            return Ok(());
        }
        let payload = serde_json::json!({"password": self.admin_password});
        self.request_json("POST", "/admin/api/login", Some(&payload), true)?;
        self.logged_in.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn list_devices(&self) -> Result<Vec<Value>, ApiError> {
        let payload = self.request_json("GET", "/admin/api/onboarding/devices", None, false)?;
        Ok(match payload.get("devices") {
            Some(Value::Array(devices)) => devices.clone(),
            _ => Vec::new(),
        })
    }

    fn start_session(&self, duid: &str) -> Result<Json, ApiError> {
        let payload = serde_json::json!({"duid": duid});
        self.request_json(
            "POST",
            "/admin/api/onboarding/sessions",
            Some(&payload),
            false,
        )
    }

    fn get_session(&self, session_id: &str) -> Result<Json, ApiError> {
        self.request_json("GET", &Self::session_path(session_id), None, false)
    }

    fn delete_session(&self, session_id: &str) -> Result<Json, ApiError> {
        self.request_json("DELETE", &Self::session_path(session_id), None, false)
    }

    fn get_status(&self) -> Result<Json, ApiError> {
        self.request_json("GET", "/admin/api/status", None, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_prefers_error_then_detail_field() {
        assert_eq!(
            format_http_error(500, r#"{"error":"boom"}"#),
            "HTTP 500: boom"
        );
        assert_eq!(
            format_http_error(404, r#"{"detail":" gone "}"#),
            "HTTP 404: gone"
        );
        assert_eq!(
            format_http_error(400, r#"{"error":"","detail":"d"}"#),
            "HTTP 400: d"
        );
    }

    #[test]
    fn http_error_falls_back_to_trimmed_body_then_status() {
        assert_eq!(
            format_http_error(502, "  bad gateway \n"),
            "HTTP 502: bad gateway"
        );
        assert_eq!(format_http_error(503, ""), "HTTP 503");
        assert_eq!(format_http_error(500, "{}"), "HTTP 500: {}");
        let long = "x".repeat(300);
        assert_eq!(
            format_http_error(500, &long),
            format!("HTTP 500: {}", "x".repeat(200))
        );
    }

    #[test]
    fn quote_escapes_everything_but_unreserved() {
        assert_eq!(quote_path_segment("sess-1_a.b~c"), "sess-1_a.b~c");
        assert_eq!(quote_path_segment("a/b c?"), "a%2Fb%20c%3F");
        assert_eq!(quote_path_segment("\u{e9}"), "%C3%A9");
    }
}
