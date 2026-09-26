//! The GUI HTTP server end to end: token checks, routes, validation, and a
//! full onboarding flow driven over HTTP with a mock vacuum on UDP.

mod support;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use roborock_onboard::api::{ApiError, OnboardingApi};
use roborock_onboard::cfgwifi::{self, BodyLog, Exchange};
use roborock_onboard::cli::SystemClock;
use roborock_onboard::gui::http::{token_urlsafe24, GuiServer, INDEX_HTML};
use roborock_onboard::gui::worker::{Deps, Timings};
use roborock_onboard::pyvalue::Json;
use serde_json::{json, Value};
use support::vacuum::{Behavior, MockVacuum};

#[derive(Default)]
struct FakeApi {
    sessions: Mutex<VecDeque<Value>>,
    last: Mutex<Json>,
    deleted: Mutex<Vec<String>>,
}

impl OnboardingApi for FakeApi {
    fn login(&self) -> Result<(), ApiError> {
        Ok(())
    }
    fn list_devices(&self) -> Result<Vec<Value>, ApiError> {
        Ok(vec![json!({
            "duid": "duid-1",
            "name": "Qrevo",
            "connected": false,
            "onboarding": {"has_public_key": false, "key_state": {"query_samples": 0}},
        })])
    }
    fn start_session(&self, _duid: &str) -> Result<Json, ApiError> {
        Ok(json!({"session_id": "sess-1"}).as_object().unwrap().clone())
    }
    fn get_session(&self, _id: &str) -> Result<Json, ApiError> {
        if let Some(next) = self.sessions.lock().unwrap().pop_front() {
            *self.last.lock().unwrap() = next.as_object().unwrap().clone();
        }
        Ok(self.last.lock().unwrap().clone())
    }
    fn delete_session(&self, id: &str) -> Result<Json, ApiError> {
        self.deleted.lock().unwrap().push(id.to_owned());
        Ok(Json::new())
    }
    fn get_status(&self) -> Result<Json, ApiError> {
        Ok(Json::new())
    }
}

fn deps(api: Arc<FakeApi>, exchange: Option<Exchange>) -> Deps {
    Deps {
        make_api: Box::new(move |_| Arc::clone(&api) as Arc<dyn OnboardingApi>),
        preflight: Box::new(|_, _, _| Ok(())),
        send: Box::new(move |config, out| match &exchange {
            Some(exchange) => cfgwifi::onboard_once(config, exchange, out),
            None => Ok(true),
        }),
        timings: Timings {
            poll_interval: Duration::from_millis(10),
            poll_timeout: Duration::from_secs(2),
            reachability_timeout: Duration::from_secs(2),
            reachability_retry: Duration::from_millis(10),
        },
        clock: Box::new(SystemClock::new()),
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

struct Client {
    agent: ureq::Agent,
    base: String,
    token: String,
}

impl Client {
    fn new(gui: &GuiServer) -> Self {
        let base = gui.url().split("/?").next().unwrap().to_owned();
        Client {
            agent: agent(),
            base,
            token: gui.token().to_owned(),
        }
    }

    fn get(&self, path: &str, token: Option<&str>) -> (u16, String, String) {
        let mut req = self.agent.get(format!("{}{path}", self.base));
        if let Some(token) = token {
            req = req.header("X-Token", token);
        }
        let mut resp = req.call().unwrap();
        let ctype = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        (
            resp.status().as_u16(),
            ctype,
            resp.body_mut().read_to_string().unwrap(),
        )
    }

    fn post(&self, path: &str, body: Option<Value>) -> (u16, Value) {
        let req = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("X-Token", &self.token)
            .header("Content-Type", "application/json");
        let mut resp = match body {
            Some(body) => req.send(body.to_string()),
            None => req.send_empty(),
        }
        .unwrap();
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap();
        (status, serde_json::from_str(&text).unwrap())
    }

    fn state(&self) -> Value {
        let (status, _, body) = self.get("/api/state", Some(&self.token.clone()));
        assert_eq!(status, 200);
        serde_json::from_str(&body).unwrap()
    }

    fn wait_phase(&self, phase: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let state = self.state();
            if state["phase"] == json!(phase) {
                return state;
            }
            assert!(Instant::now() < deadline, "waiting for {phase}: {state:#}");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn token_is_32_url_safe_chars() {
    let token = token_urlsafe24();
    assert_eq!(token.len(), 32);
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    assert_ne!(token, token_urlsafe24());
}

#[test]
fn serves_ui_html_only_with_the_token() {
    let gui = GuiServer::start(deps(Arc::default(), None)).unwrap();
    assert!(gui.url().starts_with("http://127.0.0.1:"));
    assert!(gui.url().ends_with(&format!("/?token={}", gui.token())));
    let client = Client::new(&gui);

    let (status, ctype, body) = client.get("/", None);
    assert_eq!(status, 403);
    assert!(ctype.starts_with("application/json"));
    assert_eq!(body, r#"{"detail":"Invalid or missing token."}"#);
    assert_eq!(client.get("/?token=wrong", None).0, 403);

    let (status, ctype, body) = client.get(&format!("/?token={}", gui.token()), None);
    assert_eq!(status, 200);
    assert_eq!(ctype, "text/html; charset=utf-8");
    assert_eq!(body, INDEX_HTML);
    assert_eq!(INDEX_HTML, include_str!("../../ui.html"));
    gui.stop();
    gui.wait();
}

#[test]
fn state_route_accepts_header_or_query_token() {
    let gui = GuiServer::start(deps(Arc::default(), None)).unwrap();
    let client = Client::new(&gui);
    assert_eq!(client.get("/api/state", None).0, 403);
    let (status, ctype, body) = client.get(&format!("/api/state?token={}", gui.token()), None);
    assert_eq!(status, 200);
    assert_eq!(ctype, "application/json");
    let state: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(state["phase"], json!("needs_config"));
    assert_eq!(state["default_timezone"], json!("America/New_York"));
    assert_eq!(client.state()["timezones"][0], json!("America/Anchorage"));
    gui.stop();
    gui.wait();
}

#[test]
fn unknown_routes_and_methods_match_fastapi() {
    let gui = GuiServer::start(deps(Arc::default(), None)).unwrap();
    let client = Client::new(&gui);
    let (status, _, body) = client.get("/nope", Some(gui.token()));
    assert_eq!((status, body.as_str()), (404, r#"{"detail":"Not Found"}"#));
    let (status, _, body) = client.get("/api/quit", Some(gui.token()));
    assert_eq!(
        (status, body.as_str()),
        (405, r#"{"detail":"Method Not Allowed"}"#)
    );
    gui.stop();
    gui.wait();
}

#[test]
fn config_body_is_validated_like_pydantic() {
    let gui = GuiServer::start(deps(Arc::default(), None)).unwrap();
    let client = Client::new(&gui);

    let (status, body) = client.post("/api/config", Some(json!({"server": "x", "ssid": 5})));
    assert_eq!(status, 422);
    let problems: Vec<(String, String)> = body["detail"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["loc"][1].as_str().unwrap().to_owned(),
                d["type"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        problems,
        vec![
            ("admin_password".to_owned(), "missing".to_owned()),
            ("ssid".to_owned(), "string_type".to_owned()),
            ("wifi_password".to_owned(), "missing".to_owned()),
        ]
    );

    let (status, body) = client.post("/api/config", None);
    assert_eq!(status, 422);
    assert_eq!(body["detail"][0]["loc"], json!(["body"]));

    let (status, body) = client.post("/api/select-device", Some(json!({})));
    assert_eq!(status, 422);
    assert_eq!(body["detail"][0]["loc"], json!(["body", "duid"]));

    // Validation errors never reach the worker.
    assert_eq!(client.state()["phase"], json!("needs_config"));
    gui.stop();
    gui.wait();
}

#[test]
fn full_gui_flow_over_http_with_mock_vacuum() {
    let api = Arc::new(FakeApi {
        sessions: Mutex::new(
            vec![
                json!({"session_id": "sess-1", "query_samples": 0, "has_public_key": false, "connected": false}),
                json!({"session_id": "sess-1", "query_samples": 0, "has_public_key": false, "connected": false}),
                json!({"session_id": "sess-1", "query_samples": 2, "has_public_key": true, "public_key_state": "ready", "connected": true}),
            ]
            .into(),
        ),
        ..FakeApi::default()
    });
    let vacuum = MockVacuum::start(Behavior::Normal);
    let exchange = Exchange {
        target: vacuum.addr,
        reply_timeout: Duration::from_secs(2),
        body_log: BodyLog::Redacted,
    };
    let gui = GuiServer::start(deps(Arc::clone(&api), Some(exchange))).unwrap();
    let client = Client::new(&gui);

    let (status, body) = client.post(
        "/api/config",
        Some(json!({
            "server": "api-roborock.example.com",
            "admin_password": "pw",
            "ssid": "Home Wifi",
            "wifi_password": "Secret123",
        })),
    );
    assert_eq!((status, body), (200, json!({"ok": true})));
    let state = client.wait_phase("choosing_device");
    assert_eq!(state["devices"][0]["duid"], json!("duid-1"));

    assert_eq!(
        client.post("/api/select-device", Some(json!({"duid": "duid-1"}))),
        (200, json!({"ok": true}))
    );
    let state = client.wait_phase("awaiting_vacuum_wifi");
    assert_eq!(state["target_name"], json!("Qrevo"));

    assert_eq!(
        client.post("/api/send-onboarding", None),
        (200, json!({"ok": true}))
    );
    let state = client.wait_phase("done");
    assert_eq!(
        state["result_message"],
        json!("The vacuum is connected to the local server.")
    );
    let log: Vec<String> = state["log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["msg"].as_str().unwrap().to_owned())
        .collect();
    assert!(log.iter().any(|m| m == "HELLO_RESP_CMD=16"), "{log:#?}");
    assert!(log.iter().any(|m| m == "TOKEN_T=<redacted>"), "{log:#?}");
    assert!(!log.iter().any(|m| m.contains("Secret123")), "{log:#?}");

    let seen = vacuum.observed();
    let wifi = seen.wifi.expect("vacuum received the Wi-Fi packet");
    assert_eq!(wifi["ssid"], json!("Home Wifi"));
    assert_eq!(wifi["passwd"], json!("Secret123"));
    assert_eq!(wifi["token"]["r"], json!("roborock.example.com:555/"));

    assert_eq!(client.post("/api/quit", None), (200, json!({"ok": true})));
    gui.wait();
    assert_eq!(*api.deleted.lock().unwrap(), vec!["sess-1"]);
    assert!(agent()
        .get(format!("{}/api/state", client.base))
        .call()
        .is_err());
}
