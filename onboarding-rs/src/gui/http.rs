//! The localhost HTTP server: serves the embedded `ui.html` and the JSON
//! routes it calls, with the same paths, token check and responses as the
//! FastAPI app in start_onboarding_gui.py.

use std::io;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rsa::rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

use super::state::{Shared, UiCommand};
use super::worker::{self, Deps};
use crate::pyvalue::Json;

/// The repo-root ui.html, embedded at build time (single source of truth).
pub const INDEX_HTML: &str = include_str!("../../../ui.html");

/// How long `/api/quit` waits before stopping, so its response gets out.
const QUIT_GRACE: Duration = Duration::from_millis(300);
/// How long [`GuiServer::wait`] gives the worker to delete its session.
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Fields of the Python `ConfigPayload` model: (name, default if optional).
const CONFIG_FIELDS: &[(&str, Option<&str>)] = &[
    ("server", None),
    ("admin_password", None),
    ("ssid", None),
    ("wifi_password", None),
    ("timezone", Some("")),
    ("country_domain", Some("")),
    ("cst", Some("")),
];
const SELECT_FIELDS: &[(&str, Option<&str>)] = &[("duid", None)];

/// A running GUI: HTTP thread + worker thread.
pub struct GuiServer {
    url: String,
    token: String,
    shared: Arc<Shared>,
    server: Arc<tiny_http::Server>,
    http_thread: Option<JoinHandle<()>>,
    worker_thread: Option<JoinHandle<()>>,
}

impl GuiServer {
    /// Bind `127.0.0.1` on a random free port and start both threads.
    pub fn start(deps: Deps) -> io::Result<Self> {
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(io::Error::other)?;
        let server = Arc::new(server);
        let port = server
            .server_addr()
            .to_ip()
            .map(|addr| addr.port())
            .ok_or_else(|| io::Error::other("server is not bound to an IP address"))?;
        let token = token_urlsafe24();
        let shared = Shared::new();

        let worker_thread = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("onboarding-worker".into())
                .spawn(move || worker::worker_loop(&shared, &deps))?
        };
        let http_thread = {
            let shared = Arc::clone(&shared);
            let server = Arc::clone(&server);
            let token = token.clone();
            thread::Builder::new()
                .name("onboarding-http".into())
                .spawn(move || serve(&server, &shared, &token))?
        };
        Ok(GuiServer {
            url: format!("http://127.0.0.1:{port}/?token={token}"),
            token,
            shared,
            server,
            http_thread: Some(http_thread),
            worker_thread: Some(worker_thread),
        })
    }

    /// `http://127.0.0.1:<port>/?token=<token>`
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Stop serving (Ctrl-C). The worker is told to shut down too.
    pub fn stop(&self) {
        self.shared.request_shutdown();
        self.server.unblock();
    }

    /// A handle that can stop the server from another thread.
    pub fn stopper(&self) -> impl Fn() + Send + Sync + 'static {
        let shared = Arc::clone(&self.shared);
        let server = Arc::clone(&self.server);
        move || {
            shared.request_shutdown();
            server.unblock();
        }
    }

    /// Block until the server stops (via `/api/quit` or [`GuiServer::stop`]),
    /// then give the worker up to two seconds to clean up its session.
    pub fn wait(mut self) {
        if let Some(http) = self.http_thread.take() {
            let _ = http.join();
        }
        self.shared.request_shutdown();
        if let Some(worker) = self.worker_thread.take() {
            let deadline = Instant::now() + WORKER_JOIN_TIMEOUT;
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

/// `secrets.token_urlsafe(24)`: 32 URL-safe base64 characters.
pub fn token_urlsafe24() -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(32);
    for chunk in bytes.chunks_exact(3) {
        let n = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
        for shift in [18, 12, 6, 0] {
            out.push(char::from(ALPHABET[(n >> shift & 0x3f) as usize]));
        }
    }
    out
}

fn serve(server: &tiny_http::Server, shared: &Shared, token: &str) {
    for mut request in server.incoming_requests() {
        let mut body = Vec::new();
        let _ = request.as_reader().read_to_end(&mut body);
        let header_token = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Token"))
            .map(|h| h.value.as_str().to_owned());
        let method = request.method().as_str().to_ascii_uppercase();
        let (reply, quit) = route(
            &method,
            request.url(),
            header_token.as_deref(),
            &body,
            shared,
            token,
        );
        let content_type =
            tiny_http::Header::from_bytes("Content-Type", reply.content_type).expect("valid");
        let response = tiny_http::Response::from_string(reply.body)
            .with_status_code(reply.status)
            .with_header(content_type);
        let _ = request.respond(response);
        if quit {
            thread::sleep(QUIT_GRACE);
            break;
        }
    }
}

struct Reply {
    status: u16,
    content_type: &'static str,
    body: String,
}

impl Reply {
    fn json(status: u16, body: &Value) -> Self {
        Reply {
            status,
            content_type: "application/json",
            body: body.to_string(),
        }
    }

    fn ok() -> Self {
        Reply::json(200, &json!({"ok": true}))
    }

    fn detail(status: u16, detail: &str) -> Self {
        Reply::json(status, &json!({"detail": detail}))
    }
}

/// Dispatch one request. The bool is true when the server should stop.
fn route(
    method: &str,
    url: &str,
    header_token: Option<&str>,
    body: &[u8],
    shared: &Shared,
    token: &str,
) -> (Reply, bool) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let allowed = match path {
        "/" | "/api/state" => "GET",
        "/api/config"
        | "/api/select-device"
        | "/api/refresh-devices"
        | "/api/send-onboarding"
        | "/api/ready"
        | "/api/retry"
        | "/api/reselect"
        | "/api/quit" => "POST",
        _ => return (Reply::detail(404, "Not Found"), false),
    };
    if method != allowed {
        return (Reply::detail(405, "Method Not Allowed"), false);
    }
    let provided = header_token
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .or_else(|| query_param(query, "token"))
        .unwrap_or_default();
    if !constant_time_eq(provided.as_bytes(), token.as_bytes()) {
        return (Reply::detail(403, "Invalid or missing token."), false);
    }

    let simple = |command: UiCommand| {
        shared.set_command(command, Json::new());
        (Reply::ok(), false)
    };
    match path {
        "/" => (
            Reply {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: INDEX_HTML.to_owned(),
            },
            false,
        ),
        "/api/state" => (Reply::json(200, &shared.state_json()), false),
        "/api/config" => match validate_model(body, CONFIG_FIELDS) {
            Ok(payload) => {
                shared.set_command(UiCommand::SubmitConfig, payload);
                (Reply::ok(), false)
            }
            Err(detail) => (Reply::json(422, &json!({"detail": detail})), false),
        },
        "/api/select-device" => match validate_model(body, SELECT_FIELDS) {
            Ok(payload) => {
                shared.set_command(UiCommand::SelectDevice, payload);
                (Reply::ok(), false)
            }
            Err(detail) => (Reply::json(422, &json!({"detail": detail})), false),
        },
        "/api/refresh-devices" => simple(UiCommand::RefreshDevices),
        "/api/send-onboarding" => simple(UiCommand::SendOnboarding),
        "/api/ready" => simple(UiCommand::Ready),
        "/api/retry" => simple(UiCommand::Retry),
        "/api/reselect" => simple(UiCommand::Reselect),
        "/api/quit" => {
            shared.set_command(UiCommand::Quit, Json::new());
            shared.request_shutdown();
            (Reply::ok(), true)
        }
        _ => unreachable!("path matched above"),
    }
}

/// Validate a JSON body against string fields like the pydantic models do,
/// returning the full field set (defaults filled in) or the 422 `detail`.
fn validate_model(body: &[u8], fields: &[(&str, Option<&str>)]) -> Result<Json, Value> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Err(json!([
            {"type": "missing", "loc": ["body"], "msg": "Field required", "input": null}
        ]));
    }
    let value: Value = serde_json::from_slice(body).map_err(|err| {
        json!([{
            "type": "json_invalid",
            "loc": ["body", err.column()],
            "msg": "JSON decode error",
            "input": {},
            "ctx": {"error": err.to_string()},
        }])
    })?;
    let Value::Object(input) = &value else {
        return Err(json!([{
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": value,
        }]));
    };
    let mut out = Json::new();
    let mut problems = Vec::new();
    for (name, default) in fields {
        match (input.get(*name), default) {
            (Some(Value::String(s)), _) => {
                out.insert((*name).to_owned(), Value::String(s.clone()));
            }
            (Some(other), _) => problems.push(json!({
                "type": "string_type",
                "loc": ["body", name],
                "msg": "Input should be a valid string",
                "input": other,
            })),
            (None, Some(default)) => {
                out.insert((*name).to_owned(), Value::String((*default).to_owned()));
            }
            (None, None) => problems.push(json!({
                "type": "missing",
                "loc": ["body", name],
                "msg": "Field required",
                "input": value,
            })),
        }
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(Value::Array(problems))
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (percent_decode(key) == name).then(|| percent_decode(value))
    })
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `secrets.compare_digest`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_param_decodes_percent_escapes() {
        assert_eq!(
            query_param("a=1&token=ab%2Dc", "token").as_deref(),
            Some("ab-c")
        );
        assert_eq!(query_param("token", "token").as_deref(), Some(""));
        assert_eq!(query_param("", "token"), None);
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
    }

    #[test]
    fn constant_time_eq_compares_whole_value() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn validate_model_fills_defaults_and_rejects_non_objects() {
        let ok = validate_model(br#"{"duid":"d","extra":1}"#, SELECT_FIELDS).unwrap();
        assert_eq!(Value::Object(ok), json!({"duid": "d"}));
        let ok = validate_model(
            br#"{"server":"s","admin_password":"a","ssid":"x","wifi_password":"w"}"#,
            CONFIG_FIELDS,
        )
        .unwrap();
        assert_eq!(ok["cst"], json!(""));
        assert_eq!(ok.len(), 7);
        let err = validate_model(b"[1]", SELECT_FIELDS).unwrap_err();
        assert_eq!(err[0]["type"], json!("model_attributes_type"));
        let err = validate_model(b"{nope", SELECT_FIELDS).unwrap_err();
        assert_eq!(err[0]["type"], json!("json_invalid"));
    }
}
