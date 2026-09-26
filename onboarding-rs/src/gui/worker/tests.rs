//! Ports of tests/test_onboarding_gui.py plus worker state-machine flows
//! driven through the shared state (no HTTP).

use super::*;
use crate::api::ApiError;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::Instant;

fn obj(value: Value) -> Json {
    value.as_object().unwrap().clone()
}

#[derive(Default)]
struct FakeApi {
    devices: Mutex<Vec<Value>>,
    sessions: Mutex<VecDeque<Result<Json, ApiError>>>,
    last: Mutex<Json>,
    start_error: Option<ApiError>,
    list_calls: Mutex<u32>,
    started: Mutex<Vec<String>>,
    deleted: Mutex<Vec<String>>,
}

impl FakeApi {
    fn new(devices: Vec<Value>, sessions: Vec<Value>) -> Self {
        Self::scripted(devices, sessions.into_iter().map(|s| Ok(obj(s))).collect())
    }

    fn scripted(devices: Vec<Value>, sessions: Vec<Result<Json, ApiError>>) -> Self {
        FakeApi {
            devices: Mutex::new(devices),
            sessions: Mutex::new(sessions.into()),
            ..FakeApi::default()
        }
    }
}

impl OnboardingApi for FakeApi {
    fn login(&self) -> Result<(), ApiError> {
        Ok(())
    }
    fn list_devices(&self) -> Result<Vec<Value>, ApiError> {
        *self.list_calls.lock().unwrap() += 1;
        Ok(self.devices.lock().unwrap().clone())
    }
    fn start_session(&self, duid: &str) -> Result<Json, ApiError> {
        if let Some(err) = &self.start_error {
            return Err(err.clone());
        }
        self.started.lock().unwrap().push(duid.to_owned());
        Ok(obj(json!({"session_id": "sess-1"})))
    }
    fn get_session(&self, session_id: &str) -> Result<Json, ApiError> {
        assert_eq!(session_id, "sess-1");
        match self.sessions.lock().unwrap().pop_front() {
            Some(Ok(status)) => {
                *self.last.lock().unwrap() = status.clone();
                Ok(status)
            }
            Some(Err(err)) => Err(err),
            None => Ok(self.last.lock().unwrap().clone()),
        }
    }
    fn delete_session(&self, session_id: &str) -> Result<Json, ApiError> {
        self.deleted.lock().unwrap().push(session_id.to_owned());
        Ok(Json::new())
    }
    fn get_status(&self) -> Result<Json, ApiError> {
        Ok(Json::new())
    }
}

fn q7() -> Value {
    json!({
        "duid": "cloud-q7-a",
        "name": "Q7 Upstairs",
        "connected": false,
        "onboarding": {"has_public_key": false, "key_state": {"query_samples": 1}},
    })
}

fn status(samples: i64, has_key: bool, connected: bool) -> Value {
    json!({
        "session_id": "sess-1",
        "query_samples": samples,
        "has_public_key": has_key,
        "public_key_state": if has_key { "ready" } else { "missing" },
        "connected": connected,
        "guidance": "Follow the steps.",
    })
}

fn fast_timings() -> Timings {
    Timings {
        poll_interval: Duration::from_millis(10),
        poll_timeout: Duration::from_millis(300),
        reachability_timeout: Duration::from_millis(300),
        reachability_retry: Duration::from_millis(10),
    }
}

struct Harness {
    shared: Arc<Shared>,
    api: Arc<FakeApi>,
    worker: Option<JoinHandle<()>>,
}

impl Harness {
    fn start(api: FakeApi, preflight: Result<(), String>, sends: Vec<bool>) -> Self {
        let api = Arc::new(api);
        let shared = Shared::new();
        let sends = Mutex::new(VecDeque::from(sends));
        let deps = Deps {
            make_api: Box::new({
                let api = Arc::clone(&api);
                move |_| Arc::clone(&api) as Arc<dyn OnboardingApi>
            }),
            preflight: Box::new(move |_, _, out| {
                let _ = writeln!(out, "Admin API login succeeded.");
                preflight.clone()
            }),
            send: Box::new(move |_, out| {
                let _ = writeln!(out, "HELLO_RESP_CMD=16");
                Ok(sends.lock().unwrap().pop_front().unwrap_or(true))
            }),
            timings: fast_timings(),
            clock: Box::new(SystemClock::new()),
        };
        let worker = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || worker_loop(&shared, &deps))
        };
        Harness {
            shared,
            api,
            worker: Some(worker),
        }
    }

    fn command(&self, command: UiCommand, payload: Value) {
        self.shared.set_command(command, obj(payload));
    }

    fn submit_valid_config(&self) {
        self.command(
            UiCommand::SubmitConfig,
            json!({
                "server": "api-roborock.example.com",
                "admin_password": "pw",
                "ssid": "Home",
                "wifi_password": "wifipw",
                "timezone": "",
                "country_domain": "",
                "cst": "",
            }),
        );
    }

    fn wait_phase(&self, phase: Phase) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = self.shared.state_json();
            if state["phase"] == json!(phase.as_str()) {
                return state;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {phase:?}; state: {state:#}"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn log_text(&self) -> String {
        self.shared
            .log
            .snapshot()
            .into_iter()
            .map(|e| format!("[{}] {}\n", e.level, e.msg))
            .collect()
    }

    fn quit(mut self) -> Arc<FakeApi> {
        self.shared.set_command(UiCommand::Quit, Json::new());
        self.shared.request_shutdown();
        self.worker.take().unwrap().join().unwrap();
        self.api
    }
}

// ---- config / serialization --------------------------------------------

fn payload(overrides: Value) -> Json {
    let mut base = json!({
        "server": "api-roborock.example.com:8443",
        "admin_password": " pw ",
        "ssid": " Home ",
        "wifi_password": " wifi ",
        "timezone": "",
        "country_domain": "",
        "cst": "",
    });
    for (k, v) in overrides.as_object().unwrap() {
        base[k] = v.clone();
    }
    obj(base)
}

#[test]
fn build_config_applies_defaults_and_keeps_passwords_verbatim() {
    let config = build_config_from_payload(&payload(json!({}))).unwrap();
    assert_eq!(config.api_base_url, "https://api-roborock.example.com:8443");
    assert_eq!(config.stack_server, "roborock.example.com:8443/");
    assert_eq!(config.admin_password, " pw ");
    assert_eq!(config.password, " wifi ");
    assert_eq!(config.ssid, "Home");
    assert_eq!(config.timezone, "America/New_York");
    assert_eq!(config.cst, "EST5EDT,M3.2.0,M11.1.0");
    assert_eq!(config.country_domain, "us");
    assert!(!config.allow_insecure_tls);
}

#[test]
fn build_config_derives_from_timezone_and_falls_back_for_unknown() {
    let config = build_config_from_payload(&payload(json!({"timezone": "Asia/Tokyo"}))).unwrap();
    assert_eq!(
        (config.cst.as_str(), config.country_domain.as_str()),
        ("JST-9", "jp")
    );
    let config = build_config_from_payload(&payload(json!({"timezone": "Mars/Olympus"}))).unwrap();
    assert_eq!(config.cst, "EST5EDT,M3.2.0,M11.1.0");
    assert_eq!(config.country_domain, "us");
    let config = build_config_from_payload(&payload(
        json!({"timezone": "Asia/Tokyo", "cst": " X ", "country_domain": " yy "}),
    ))
    .unwrap();
    assert_eq!(
        (config.cst.as_str(), config.country_domain.as_str()),
        ("X", "yy")
    );
}

#[test]
fn build_config_reports_first_missing_field() {
    let cases = [
        (json!({"server": "  "}), "Server is required."),
        (json!({"server": "a.b:x"}), "Server port must be numeric."),
        (json!({"admin_password": ""}), "Admin password is required."),
        (json!({"ssid": "  "}), "Home Wi-Fi SSID is required."),
        (
            json!({"wifi_password": ""}),
            "Home Wi-Fi password is required.",
        ),
    ];
    for (overrides, expected) in cases {
        assert_eq!(
            build_config_from_payload(&payload(overrides.clone())).unwrap_err(),
            expected,
            "{overrides}"
        );
    }
}

#[test]
fn gui_server_normalization_supports_default_and_custom_ports() {
    for (server, api, stack) in [
        (
            "api-roborock.example.com",
            "https://api-roborock.example.com:555",
            "roborock.example.com:555/",
        ),
        (
            "api-roborock.example.com:8443",
            "https://api-roborock.example.com:8443",
            "roborock.example.com:8443/",
        ),
        (
            "https://roborock.example.com:8443/",
            "https://api-roborock.example.com:8443",
            "roborock.example.com:8443/",
        ),
    ] {
        let config = build_config_from_payload(&payload(json!({"server": server}))).unwrap();
        assert_eq!(config.api_base_url, api);
        assert_eq!(config.stack_server, stack);
    }
}

#[test]
fn serializes_devices_and_status_for_the_browser() {
    let devices = serialize_devices(&[q7(), json!({"duid": "d2", "connected": 1})]);
    assert_eq!(
        devices,
        vec![
            json!({"duid": "cloud-q7-a", "name": "Q7 Upstairs", "has_public_key": false, "connected": false, "query_samples": 1}),
            json!({"duid": "d2", "name": "d2", "has_public_key": false, "connected": true, "query_samples": 0}),
        ]
    );
    assert_eq!(
        Value::Object(serialize_status(&obj(
            json!({"query_samples": "2", "has_public_key": 1})
        ))),
        json!({"query_samples": 2, "has_public_key": true, "connected": false, "public_key_state": "missing"})
    );
}

// ---- poll (ported) -----------------------------------------------------

fn poll_with(
    api: &FakeApi,
    baseline: i64,
    has_key: bool,
) -> (PollOutcome, Json, Vec<Duration>, Arc<Shared>) {
    let shared = Shared::new();
    let waits = Mutex::new(Vec::new());
    let timings = Timings {
        poll_interval: Duration::from_secs(5),
        poll_timeout: Duration::from_secs(20),
        ..Timings::default()
    };
    let (outcome, latest) = poll_until_progress(
        api,
        "sess-1",
        baseline,
        has_key,
        &shared,
        &timings,
        &SystemClock::new(),
        &|d| waits.lock().unwrap().push(d),
    );
    let waits = waits.into_inner().unwrap();
    (outcome, latest, waits, shared)
}

#[test]
fn gui_poll_final_cycle_waits_for_connection_when_public_key_already_ready() {
    let api = FakeApi::new(vec![], vec![status(2, true, false), status(2, true, true)]);
    let (outcome, latest, waits, _) = poll_with(&api, 2, true);
    assert_eq!(outcome, PollOutcome::Connected);
    assert_eq!(latest["connected"], json!(true));
    assert_eq!(waits, vec![Duration::from_secs(5)]);
}

#[test]
fn gui_poll_returns_unsupported_without_waiting() {
    let api = FakeApi::new(
        vec![],
        vec![json!({"session_id": "sess-1", "query_samples": 0, "unsupported": true})],
    );
    let (outcome, latest, waits, _) = poll_with(&api, 0, false);
    assert_eq!(outcome, PollOutcome::Unsupported);
    assert_eq!(latest["unsupported"], json!(true));
    assert!(waits.is_empty());
}

#[test]
fn gui_poll_logs_errors_and_keeps_polling() {
    let api = FakeApi::scripted(
        vec![],
        vec![
            Err(ApiError::Failed("HTTP 502: bad gateway".into())),
            Ok(obj(status(1, false, false))),
        ],
    );
    let (outcome, _, waits, shared) = poll_with(&api, 0, false);
    assert_eq!(outcome, PollOutcome::SampleIncreased);
    assert_eq!(waits.len(), 1);
    let log = shared.log.snapshot();
    assert_eq!(log[0].level, "warn");
    assert_eq!(log[0].msg, "poll: get_session error: HTTP 502: bad gateway");
}

#[test]
fn gui_poll_stops_on_shutdown() {
    let api = FakeApi::new(vec![], vec![status(0, false, false)]);
    let shared = Shared::new();
    shared.request_shutdown();
    let (outcome, latest) = poll_until_progress(
        &api,
        "sess-1",
        0,
        false,
        &shared,
        &Timings::default(),
        &SystemClock::new(),
        &|_| panic!("should not wait"),
    );
    assert_eq!(outcome, PollOutcome::Timeout);
    assert!(latest.is_empty());
}

// ---- worker flows ------------------------------------------------------

#[test]
fn invalid_config_is_reported_and_form_stays_open() {
    let h = Harness::start(FakeApi::default(), Ok(()), vec![]);
    h.command(UiCommand::SubmitConfig, json!({"server": ""}));
    let deadline = Instant::now() + Duration::from_secs(5);
    while h.shared.state_json()["config_error"].is_null() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let state = h.wait_phase(Phase::NeedsConfig);
    assert_eq!(state["config_error"], json!("Server is required."));
    assert!(h
        .log_text()
        .contains("[err] Config error: Server is required."));
    h.quit();
}

#[test]
fn preflight_failure_returns_to_config_with_error() {
    let h = Harness::start(
        FakeApi::default(),
        Err("Stack preflight failed: x".into()),
        vec![],
    );
    h.submit_valid_config();
    let deadline = Instant::now() + Duration::from_secs(5);
    while h.shared.state_json()["config_error"].is_null() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let state = h.shared.state_json();
    assert_eq!(state["phase"], json!("needs_config"));
    assert_eq!(state["config_error"], json!("Stack preflight failed: x"));
    assert!(h.shared.lock().config.is_none());
    let log = h.log_text();
    assert!(log.contains("Validating https://api-roborock.example.com:555..."));
    assert!(log.contains("[err] Validation failed: Stack preflight failed: x"));
    h.quit();
}

#[test]
fn happy_path_reaches_done_connected_and_cleans_up() {
    let api = FakeApi::new(
        vec![q7()],
        vec![
            status(0, false, false), // baseline
            status(0, false, false), // reachability probe
            status(2, true, true),   // poll
        ],
    );
    let h = Harness::start(api, Ok(()), vec![true]);
    h.submit_valid_config();
    let state = h.wait_phase(Phase::ChoosingDevice);
    assert_eq!(
        state["devices"],
        json!([{"duid": "cloud-q7-a", "name": "Q7 Upstairs", "has_public_key": false, "connected": false, "query_samples": 1}])
    );
    assert!(h.log_text().contains("[ok] Validation succeeded."));
    assert!(h.log_text().contains("1 device(s) available."));

    h.command(UiCommand::SelectDevice, json!({"duid": "cloud-q7-a"}));
    let state = h.wait_phase(Phase::AwaitingVacuumWifi);
    assert_eq!(state["target_name"], json!("Q7 Upstairs"));
    assert_eq!(state["target_duid"], json!("cloud-q7-a"));
    assert_eq!(state["baseline_samples"], json!(0));
    assert_eq!(
        state["status"],
        json!({"query_samples": 0, "has_public_key": false, "connected": false, "public_key_state": "missing"})
    );

    h.command(UiCommand::SendOnboarding, json!({}));
    let state = h.wait_phase(Phase::Done);
    assert_eq!(
        state["result_message"],
        json!("The vacuum is connected to the local server.")
    );
    assert_eq!(state["result_detail"], json!("Onboarding complete."));
    assert_eq!(state["can_continue"], json!(false));
    assert_eq!(state["status"]["connected"], json!(true));
    let log = h.log_text();
    assert!(log.contains("Sending cfgwifi onboarding packet to 192.168.8.1..."));
    assert!(log.contains("HELLO_RESP_CMD=16"));
    assert!(log.contains("[ok] Onboarding packet sent."));
    assert!(log.contains("[ok] Server reachable. Polling for progress..."));
    assert!(log.contains("[ok] Vacuum connected."));

    let api = h.quit();
    assert_eq!(*api.started.lock().unwrap(), vec!["cloud-q7-a"]);
    assert_eq!(*api.deleted.lock().unwrap(), vec!["sess-1"]);
}

#[test]
fn public_key_ready_allows_another_cycle() {
    let api = FakeApi::new(
        vec![q7()],
        vec![
            status(1, false, false),
            status(1, false, false),
            status(2, true, false),
            status(2, true, false), // next baseline after retry
        ],
    );
    let h = Harness::start(api, Ok(()), vec![true]);
    h.submit_valid_config();
    h.wait_phase(Phase::ChoosingDevice);
    h.command(UiCommand::SelectDevice, json!({"duid": "cloud-q7-a"}));
    h.wait_phase(Phase::AwaitingVacuumWifi);
    h.command(UiCommand::SendOnboarding, json!({}));
    let state = h.wait_phase(Phase::Done);
    assert_eq!(state["result_message"], json!("Public key is ready."));
    assert_eq!(state["can_continue"], json!(true));

    h.command(UiCommand::Retry, json!({}));
    let state = h.wait_phase(Phase::AwaitingVacuumWifi);
    assert_eq!(state["baseline_samples"], json!(2));
    assert_eq!(state["result_message"], json!(null));
    assert!(h
        .log_text()
        .contains("Public key is already ready. This should be the final pairing cycle"));
    h.quit();
}

#[test]
fn timeout_after_key_ready_explains_slow_final_cycle() {
    let api = FakeApi::new(vec![q7()], vec![status(2, true, false)]);
    let h = Harness::start(api, Ok(()), vec![true]);
    h.submit_valid_config();
    h.wait_phase(Phase::ChoosingDevice);
    h.command(UiCommand::SelectDevice, json!({"duid": "cloud-q7-a"}));
    h.wait_phase(Phase::AwaitingVacuumWifi);
    h.command(UiCommand::SendOnboarding, json!({}));
    let state = h.wait_phase(Phase::Done);
    assert_eq!(
        state["result_message"],
        json!("Timed out waiting for progress.")
    );
    assert!(state["result_detail"]
        .as_str()
        .unwrap()
        .starts_with("The public key was already ready"));
    assert_eq!(state["can_continue"], json!(true));
    h.quit();
}

#[test]
fn send_failure_shows_error_and_retry_returns_to_send_step() {
    let api = FakeApi::new(vec![q7()], vec![status(0, false, false)]);
    let h = Harness::start(api, Ok(()), vec![false]);
    h.submit_valid_config();
    h.wait_phase(Phase::ChoosingDevice);
    h.command(UiCommand::SelectDevice, json!({"duid": "cloud-q7-a"}));
    h.wait_phase(Phase::AwaitingVacuumWifi);
    h.command(UiCommand::SendOnboarding, json!({}));
    let state = h.wait_phase(Phase::Error);
    assert_eq!(
        state["error_message"],
        json!("Onboarding send failed. Ensure your machine is joined to the vacuum's Wi-Fi hotspot, then retry.")
    );
    assert_eq!(state["target_name"], json!("Q7 Upstairs"));
    h.command(UiCommand::Retry, json!({}));
    let state = h.wait_phase(Phase::AwaitingVacuumWifi);
    assert_eq!(state["error_message"], json!(null));
    h.quit();
}

#[test]
fn reselect_deletes_session_and_lists_devices_again() {
    let api = FakeApi::new(vec![q7()], vec![status(0, false, false)]);
    let h = Harness::start(api, Ok(()), vec![]);
    h.submit_valid_config();
    h.wait_phase(Phase::ChoosingDevice);
    h.command(UiCommand::SelectDevice, json!({"duid": "cloud-q7-a"}));
    h.wait_phase(Phase::AwaitingVacuumWifi);
    h.command(UiCommand::Reselect, json!({}));
    let state = h.wait_phase(Phase::ChoosingDevice);
    assert_eq!(state["target_name"], json!(null));
    assert_eq!(*h.api.deleted.lock().unwrap(), vec!["sess-1"]);
    assert_eq!(*h.api.list_calls.lock().unwrap(), 2);
    h.quit();
}

#[test]
fn unknown_duid_and_refresh_keep_choosing() {
    let h = Harness::start(FakeApi::new(vec![], vec![]), Ok(()), vec![]);
    h.submit_valid_config();
    h.wait_phase(Phase::ChoosingDevice);
    assert!(h
        .log_text()
        .contains("[warn] 0 device(s) available. Finish the cloud import/fetch-data step first, then refresh."));
    h.command(UiCommand::SelectDevice, json!({"duid": "nope"}));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !h.log_text().contains("[err] Unknown duid nope") {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    h.api.devices.lock().unwrap().push(q7());
    h.command(UiCommand::RefreshDevices, json!({}));
    let deadline = Instant::now() + Duration::from_secs(5);
    while h.shared.state_json()["devices"]
        .as_array()
        .unwrap()
        .is_empty()
    {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(*h.api.list_calls.lock().unwrap() >= 3);
    h.quit();
}

#[test]
fn unreachable_server_after_hotspot_is_an_error() {
    let mut sessions = vec![Ok(obj(status(0, false, false)))];
    sessions.extend((0..200).map(|_| Err(ApiError::Unreachable("down".into()))));
    let h = Harness::start(FakeApi::scripted(vec![q7()], sessions), Ok(()), vec![true]);
    h.submit_valid_config();
    h.wait_phase(Phase::ChoosingDevice);
    h.command(UiCommand::SelectDevice, json!({"duid": "cloud-q7-a"}));
    h.wait_phase(Phase::AwaitingVacuumWifi);
    h.command(UiCommand::SendOnboarding, json!({}));
    let state = h.wait_phase(Phase::Error);
    assert_eq!(
        state["error_message"],
        json!("Could not reach the server after leaving the vacuum hotspot. Check your Wi-Fi and try again.")
    );
    h.quit();
}

#[test]
fn start_session_failure_is_an_error_with_target() {
    let api = FakeApi {
        start_error: Some(ApiError::Failed("HTTP 409: busy".into())),
        ..FakeApi::new(vec![q7()], vec![])
    };
    let h = Harness::start(api, Ok(()), vec![]);
    h.submit_valid_config();
    h.wait_phase(Phase::ChoosingDevice);
    h.command(UiCommand::SelectDevice, json!({"duid": "cloud-q7-a"}));
    let state = h.wait_phase(Phase::Error);
    assert_eq!(state["error_message"], json!("HTTP 409: busy"));
    assert_eq!(state["target_name"], json!("Q7 Upstairs"));
    assert!(h
        .log_text()
        .contains("[err] Failed to start session: HTTP 409: busy"));
    h.command(UiCommand::Reselect, json!({}));
    h.wait_phase(Phase::ChoosingDevice);
    h.quit();
}

#[test]
fn quit_while_awaiting_ends_worker_and_deletes_session() {
    let api = FakeApi::new(vec![q7()], vec![status(0, false, false)]);
    let h = Harness::start(api, Ok(()), vec![]);
    h.submit_valid_config();
    h.wait_phase(Phase::ChoosingDevice);
    h.command(UiCommand::SelectDevice, json!({"duid": "cloud-q7-a"}));
    h.wait_phase(Phase::AwaitingVacuumWifi);
    let api = h.quit();
    assert_eq!(*api.deleted.lock().unwrap(), vec!["sess-1"]);
}
