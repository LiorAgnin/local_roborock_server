//! Ports of tests/test_onboarding_cli.py plus extra coverage of prompts,
//! labels and error paths.

use super::*;
use serde_json::json;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Mutex;

// ---- fakes -------------------------------------------------------------

struct Answers(VecDeque<&'static str>);

impl Answers {
    fn new(answers: &[&'static str]) -> Self {
        Answers(answers.iter().copied().collect())
    }
}

impl Prompter for Answers {
    fn input(&mut self, _prompt: &str) -> Result<String, InputError> {
        self.0.pop_front().map(str::to_owned).ok_or(InputError::Eof)
    }
    fn secret(&mut self, prompt: &str) -> Result<String, InputError> {
        self.input(prompt)
    }
}

/// Records prompts too, for prompt_for_config tests.
struct RecordingPrompter {
    answers: VecDeque<&'static str>,
    prompts: Vec<(String, bool)>,
}

impl RecordingPrompter {
    fn new(answers: &[&'static str]) -> Self {
        RecordingPrompter {
            answers: answers.iter().copied().collect(),
            prompts: Vec::new(),
        }
    }

    fn next(&mut self, prompt: &str, secret: bool) -> Result<String, InputError> {
        self.prompts.push((prompt.to_owned(), secret));
        self.answers
            .pop_front()
            .map(str::to_owned)
            .ok_or(InputError::Eof)
    }
}

impl Prompter for RecordingPrompter {
    fn input(&mut self, prompt: &str) -> Result<String, InputError> {
        self.next(prompt, false)
    }
    fn secret(&mut self, prompt: &str) -> Result<String, InputError> {
        self.next(prompt, true)
    }
}

#[derive(Default)]
struct FakeClock {
    now: RefCell<Duration>,
    sleeps: RefCell<Vec<Duration>>,
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        *self.now.borrow()
    }
    fn sleep(&self, duration: Duration) {
        self.sleeps.borrow_mut().push(duration);
        *self.now.borrow_mut() += duration;
    }
}

impl FakeClock {
    fn sleeps(&self) -> Vec<u64> {
        self.sleeps.borrow().iter().map(Duration::as_secs).collect()
    }
}

fn obj(value: Value) -> Json {
    value.as_object().unwrap().clone()
}

/// get_session pops scripted responses and then repeats the last one.
struct FakeApi {
    devices: Vec<Value>,
    statuses: Mutex<VecDeque<Result<Json, ApiError>>>,
    last: Mutex<Json>,
    login_calls: Mutex<u32>,
    started: Mutex<Vec<String>>,
    deleted: Mutex<Vec<String>>,
}

impl FakeApi {
    fn new(devices: Vec<Value>, statuses: Vec<Value>) -> Self {
        Self::scripted(devices, statuses.into_iter().map(|s| Ok(obj(s))).collect())
    }

    fn scripted(devices: Vec<Value>, statuses: Vec<Result<Json, ApiError>>) -> Self {
        FakeApi {
            devices,
            statuses: Mutex::new(statuses.into()),
            last: Mutex::new(obj(json!({"session_id": "sess-1"}))),
            login_calls: Mutex::new(0),
            started: Mutex::new(Vec::new()),
            deleted: Mutex::new(Vec::new()),
        }
    }

    fn started(&self) -> Vec<String> {
        self.started.lock().unwrap().clone()
    }

    fn deleted(&self) -> Vec<String> {
        self.deleted.lock().unwrap().clone()
    }
}

impl OnboardingApi for FakeApi {
    fn login(&self) -> Result<(), ApiError> {
        *self.login_calls.lock().unwrap() += 1;
        Ok(())
    }
    fn list_devices(&self) -> Result<Vec<Value>, ApiError> {
        Ok(self.devices.clone())
    }
    fn start_session(&self, duid: &str) -> Result<Json, ApiError> {
        self.started.lock().unwrap().push(duid.to_owned());
        Ok(obj(
            json!({"session_id": "sess-1", "target": {"duid": duid}}),
        ))
    }
    fn get_session(&self, session_id: &str) -> Result<Json, ApiError> {
        assert_eq!(session_id, "sess-1");
        match self.statuses.lock().unwrap().pop_front() {
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
        Ok(obj(json!({"ok": true})))
    }
    fn get_status(&self) -> Result<Json, ApiError> {
        unreachable!()
    }
}

fn config() -> OnboardingConfig {
    OnboardingConfig {
        api_base_url: "https://api-roborock.example.com".into(),
        stack_server: "roborock.example.com/".into(),
        admin_password: "secret".into(),
        ssid: "Home Wifi".into(),
        password: "Password123".into(),
        timezone: "America/New_York".into(),
        cst: "EST5EDT,M3.2.0,M11.1.0".into(),
        country_domain: "us".into(),
        allow_insecure_tls: false,
    }
}

fn q7() -> Value {
    json!({
        "duid": "cloud-q7-a",
        "name": "Q7 Upstairs",
        "connected": false,
        "onboarding": {"has_public_key": false, "key_state": {"query_samples": 0}},
    })
}

fn status(samples: i64, has_key: bool, connected: bool) -> Value {
    json!({
        "session_id": "sess-1",
        "query_samples": samples,
        "has_public_key": has_key,
        "public_key_state": if has_key { "ready" } else { "missing" },
        "connected": connected,
        "guidance": "Some guidance.",
        "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
    })
}

fn settings() -> PollSettings {
    PollSettings {
        interval: Duration::from_secs(5),
        timeout: Duration::from_secs(20),
    }
}

struct Run {
    code: Result<i32, CliError>,
    output: String,
    sends: Vec<String>,
}

fn run_flow(api: &FakeApi, answers: &[&'static str], send_ok: bool) -> Run {
    let mut output = Vec::new();
    let mut sends = Vec::new();
    let clock = FakeClock::default();
    let code = run_guided_onboarding(
        &config(),
        api,
        &mut |cfg, _out| {
            sends.push(cfg.ssid.clone());
            Ok(send_ok)
        },
        &mut output,
        &mut Answers::new(answers),
        settings(),
        &clock,
    );
    Run {
        code,
        output: String::from_utf8(output).unwrap(),
        sends,
    }
}

fn text(out: Vec<u8>) -> String {
    String::from_utf8(out).unwrap()
}

// ---- classify / poll ---------------------------------------------------

#[test]
fn classify_checks_conditions_in_python_order() {
    let s = obj;
    assert_eq!(
        classify_progress(
            &s(json!({"identity_conflict": "x", "connected": true})),
            0,
            false
        ),
        Some(PollOutcome::Conflict)
    );
    assert_eq!(
        classify_progress(
            &s(json!({"identity_conflict": "  ", "unsupported": true})),
            0,
            false
        ),
        Some(PollOutcome::Unsupported)
    );
    assert_eq!(
        classify_progress(
            &s(json!({"connected": true, "has_public_key": true})),
            0,
            false
        ),
        Some(PollOutcome::Connected)
    );
    assert_eq!(
        classify_progress(
            &s(json!({"has_public_key": true, "query_samples": 5})),
            0,
            false
        ),
        Some(PollOutcome::PublicKeyReady)
    );
    assert_eq!(
        classify_progress(&s(json!({"query_samples": 1})), 0, false),
        Some(PollOutcome::SampleIncreased)
    );
    // With the key already known only a connection counts as progress.
    assert_eq!(
        classify_progress(
            &s(json!({"has_public_key": true, "query_samples": 9})),
            0,
            true
        ),
        None
    );
    assert_eq!(
        classify_progress(&s(json!({"query_samples": 1})), 1, false),
        None
    );
}

#[test]
fn poll_final_cycle_waits_for_connection_when_public_key_already_ready() {
    let api = FakeApi::new(vec![], vec![status(2, true, false), status(2, true, true)]);
    let baseline = obj(status(2, true, false));
    let clock = FakeClock::default();
    let mut output = Vec::new();

    let (outcome, latest) = poll_session_until_progress(
        &api,
        "sess-1",
        2,
        Some(&baseline),
        &mut output,
        settings(),
        &clock,
    )
    .unwrap();

    assert_eq!(outcome, PollOutcome::Connected);
    assert_eq!(latest["connected"], json!(true));
    assert_eq!(clock.sleeps(), vec![5]);
    assert!(text(output).contains("Waiting for the server to observe new onboarding traffic..."));
}

#[test]
fn poll_returns_unsupported_without_waiting() {
    let api = FakeApi::new(
        vec![],
        vec![json!({"session_id": "sess-1", "query_samples": 0, "unsupported": true})],
    );
    let baseline = obj(json!({"session_id": "sess-1", "query_samples": 0}));
    let clock = FakeClock::default();
    let (outcome, latest) = poll_session_until_progress(
        &api,
        "sess-1",
        0,
        Some(&baseline),
        &mut Vec::new(),
        settings(),
        &clock,
    )
    .unwrap();
    assert_eq!(outcome, PollOutcome::Unsupported);
    assert_eq!(latest["unsupported"], json!(true));
    assert!(clock.sleeps().is_empty());
}

#[test]
fn poll_retries_while_machine_reconnects_to_normal_wifi() {
    let unreachable = || {
        Err(ApiError::Unreachable(
            "Unable to reach https://api-roborock.example.com: Name or service not known".into(),
        ))
    };
    let api = FakeApi::scripted(
        vec![],
        vec![unreachable(), unreachable(), Ok(obj(status(2, true, true)))],
    );
    let clock = FakeClock::default();
    let mut output = Vec::new();
    let (outcome, _) = poll_session_until_progress(
        &api,
        "sess-1",
        0,
        Some(&obj(status(0, false, false))),
        &mut output,
        settings(),
        &clock,
    )
    .unwrap();
    let out = text(output);
    assert_eq!(outcome, PollOutcome::Connected);
    assert_eq!(clock.sleeps(), vec![5, 5]);
    assert!(out.contains("The main server is not reachable yet from this machine."));
    assert!(out.contains("Unable to reach https://api-roborock.example.com"));
    assert!(out.contains("Still waiting for this machine to reach the main server again..."));
}

#[test]
fn poll_times_out_with_latest_status() {
    let api = FakeApi::new(vec![], vec![status(0, false, false)]);
    let clock = FakeClock::default();
    let (outcome, latest) =
        poll_session_until_progress(&api, "sess-1", 0, None, &mut Vec::new(), settings(), &clock)
            .unwrap();
    assert_eq!(outcome, PollOutcome::Timeout);
    assert_eq!(latest["session_id"], json!("sess-1"));
    assert_eq!(clock.sleeps(), vec![5, 5, 5, 5]);
}

#[test]
fn poll_times_out_while_unreachable_keeping_baseline() {
    let api = FakeApi::scripted(
        vec![],
        (0..10)
            .map(|_| Err(ApiError::Unreachable("down".into())))
            .collect(),
    );
    let clock = FakeClock::default();
    let baseline = obj(status(3, false, false));
    let (outcome, latest) = poll_session_until_progress(
        &api,
        "sess-1",
        3,
        Some(&baseline),
        &mut Vec::new(),
        settings(),
        &clock,
    )
    .unwrap();
    assert_eq!(outcome, PollOutcome::Timeout);
    assert_eq!(latest, baseline);
}

#[test]
fn poll_aborts_on_non_reachability_errors() {
    let api = FakeApi::scripted(vec![], vec![Err(ApiError::Failed("HTTP 500: boom".into()))]);
    let err = poll_session_until_progress(
        &api,
        "sess-1",
        0,
        None,
        &mut Vec::new(),
        settings(),
        &FakeClock::default(),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "HTTP 500: boom");
}

// ---- labels / prompts --------------------------------------------------

#[test]
fn device_label_matches_python_format() {
    assert_eq!(
        format_device_label(&q7(), ""),
        "Q7 Upstairs [No Public Key ] [Disconnected ] [0 Query Samples]"
    );
    let device = json!({
        "duid": "d2",
        "name": "",
        "connected": true,
        "onboarding": {"has_public_key": true, "unsupported": true, "key_state": {"query_samples": "3"}},
    });
    assert_eq!(
        format_device_label(&device, "d2"),
        "d2 [d2] [Unsupported ] [Public Key Determined ] [Connected ] [3 Query Samples]"
    );
    assert_eq!(
        format_device_label(&json!({}), ""),
        "Unknown vacuum [No Public Key ] [Disconnected ] [0 Query Samples]"
    );
}

#[test]
fn status_summary_matches_python_format() {
    let mut out = Vec::new();
    print_status_summary(&obj(status(2, true, false)), &mut out);
    assert_eq!(
        text(out),
        "Status for Q7 Upstairs: samples=2, public_key=True, connected=False, state=ready\n\
         Some guidance.\n"
    );
    let mut out = Vec::new();
    print_status_summary(
        &obj(json!({"target": {"did": "123"}, "guidance": "  "})),
        &mut out,
    );
    assert_eq!(
        text(out),
        "Status for 123: samples=0, public_key=False, connected=False, state=missing\n"
    );
}

#[test]
fn choose_device_empty_list_points_to_cloud_import() {
    let mut out = Vec::new();
    let selected = choose_device(&[], &mut out, &mut Answers::new(&[])).unwrap();
    assert!(selected.is_none());
    assert!(text(out).contains("Finish the cloud import/fetch-data step first"));
}

#[test]
fn choose_device_reprompts_on_invalid_input_and_accepts_quit() {
    let mut out = Vec::new();
    let selected = choose_device(
        &[q7()],
        &mut out,
        &mut Answers::new(&["0", "x", "99999999999999999999", " QUIT "]),
    )
    .unwrap();
    assert!(selected.is_none());
    let out = text(out);
    assert_eq!(out.matches("Please enter a valid number.").count(), 3);
    assert_eq!(out.matches("Available vacuums:").count(), 4);
    assert!(out.contains("  1. Q7 Upstairs [No Public Key ] [Disconnected ] [0 Query Samples]\n"));
}

#[test]
fn post_attempt_action_reprompts_until_valid() {
    let mut out = Vec::new();
    let action = prompt_post_attempt_action(
        &obj(status(0, false, false)),
        &mut out,
        &mut Answers::new(&["nope", " Refresh "]),
    )
    .unwrap();
    assert_eq!(action, PostAttemptAction::Refresh);
    let out = text(out);
    assert_eq!(out.matches("Status for Q7 Upstairs").count(), 2);
    assert!(out.contains("Please type retry, refresh, reselect, or quit."));
}

#[test]
fn prompt_for_config_prompts_for_missing_values_with_secrets_hidden() {
    let args = ConfigArgs {
        server: "api-roborock.example.com".into(),
        ..ConfigArgs::default()
    };
    let mut prompter = RecordingPrompter::new(&["pw", "", " My Wifi ", "wifipw", ""]);
    let mut out = Vec::new();
    let config = prompt_for_config(&args, &mut prompter, &mut out).unwrap();
    assert_eq!(
        prompter.prompts,
        vec![
            ("Admin password: ".to_owned(), true),
            ("Home Wi-Fi SSID: ".to_owned(), false),
            ("Home Wi-Fi SSID: ".to_owned(), false),
            ("Home Wi-Fi password: ".to_owned(), true),
            ("Timezone [America/New_York]: ".to_owned(), false),
        ]
    );
    assert_eq!(text(out), "A value is required.\n");
    assert_eq!(
        config,
        OnboardingConfig {
            api_base_url: "https://api-roborock.example.com:555".into(),
            stack_server: "roborock.example.com:555/".into(),
            admin_password: "pw".into(),
            ssid: "My Wifi".into(),
            password: "wifipw".into(),
            timezone: "America/New_York".into(),
            cst: "EST5EDT,M3.2.0,M11.1.0".into(),
            country_domain: "us".into(),
            allow_insecure_tls: false,
        }
    );
}

#[test]
fn prompt_for_config_uses_flags_and_derives_cst_and_country() {
    let args = ConfigArgs {
        server: "roborock.example.com:8443".into(),
        admin_password: " pw ".into(),
        ssid: "s".into(),
        password: "p".into(),
        timezone: "Europe/Berlin".into(),
        allow_insecure_tls: true,
        ..ConfigArgs::default()
    };
    let mut prompter = RecordingPrompter::new(&[]);
    let config = prompt_for_config(&args, &mut prompter, &mut Vec::new()).unwrap();
    assert!(prompter.prompts.is_empty());
    assert_eq!(config.admin_password, "pw");
    assert_eq!(config.cst, "CET-1CEST,M3.5.0,M10.5.0/3");
    assert_eq!(config.country_domain, "de");
    assert!(config.allow_insecure_tls);
}

#[test]
fn prompt_for_config_asks_for_cst_and_country_for_unknown_timezone() {
    let args = ConfigArgs {
        server: "a.example.com".into(),
        admin_password: "pw".into(),
        ssid: "s".into(),
        password: "p".into(),
        timezone: "Mars/Olympus".into(),
        ..ConfigArgs::default()
    };
    let mut prompter = RecordingPrompter::new(&["", "xx"]);
    let config = prompt_for_config(&args, &mut prompter, &mut Vec::new()).unwrap();
    assert_eq!(
        prompter.prompts,
        vec![
            (
                "POSIX TZ string (could not auto-detect from timezone) [EST5EDT,M3.2.0,M11.1.0]: "
                    .to_owned(),
                false
            ),
            (
                "Country domain (could not auto-detect from timezone) [us]: ".to_owned(),
                false
            ),
        ]
    );
    assert_eq!(config.cst, "EST5EDT,M3.2.0,M11.1.0");
    assert_eq!(config.country_domain, "xx");
}

#[test]
fn prompt_for_config_rejects_bad_server_before_prompting() {
    let args = ConfigArgs {
        server: "abcdefghijklmnop.example.com:555".into(),
        ..ConfigArgs::default()
    };
    let err = prompt_for_config(&args, &mut Answers::new(&[]), &mut Vec::new()).unwrap_err();
    assert!(err
        .to_string()
        .contains("token.r must be at most 32 characters, got 33"));
}

// ---- full flow ---------------------------------------------------------

#[test]
fn guided_onboarding_happy_path() {
    let api = FakeApi::new(
        vec![q7()],
        vec![status(0, false, false), status(2, true, true)],
    );
    let run = run_flow(&api, &["1", ""], true);
    assert_eq!(run.code.unwrap(), 0);
    assert_eq!(*api.login_calls.lock().unwrap(), 1);
    assert_eq!(api.started(), vec!["cloud-q7-a"]);
    assert_eq!(api.deleted(), vec!["sess-1"]);
    assert_eq!(run.sends, vec!["Home Wifi"]);
    assert!(run
        .output
        .contains("The vacuum is connected to the local server."));
    assert!(run
        .output
        .contains("Sending cfgwifi onboarding packet...\n"));
}

#[test]
fn guided_onboarding_handles_extra_cycles() {
    let api = FakeApi::new(
        vec![q7()],
        vec![
            status(0, false, false),
            status(1, false, false),
            status(1, false, false),
            status(2, true, false),
            status(2, true, false),
            status(2, true, true),
        ],
    );
    let run = run_flow(&api, &["1", "", "", ""], true);
    assert_eq!(run.code.unwrap(), 0);
    assert_eq!(run.sends.len(), 3);
    assert!(run.output.contains("The sample count increased."));
    assert!(run.output.contains("The public key is ready."));
    assert!(run
        .output
        .contains("The public key is already ready. This should be the final pairing cycle"));
}

#[test]
fn guided_onboarding_timeout_can_retry_without_restart() {
    let mut statuses = vec![status(0, false, false)];
    statuses.extend((0..5).map(|_| status(0, false, false)));
    statuses.push(status(0, false, false));
    statuses.push(status(2, true, true));
    let api = FakeApi::new(vec![q7()], statuses);
    let run = run_flow(&api, &["1", "", "retry", ""], true);
    assert_eq!(run.code.unwrap(), 0);
    assert_eq!(run.sends.len(), 2);
    assert!(!run
        .output
        .contains("Choose: [retry] [refresh] [reselect] [quit]:"));
    assert_eq!(api.deleted(), vec!["sess-1"]);
}

#[test]
fn timeout_after_public_key_ready_explains_slow_final_cycle() {
    let api = FakeApi::new(vec![q7()], vec![status(2, true, false)]);
    let run = run_flow(&api, &["1", "", "quit"], true);
    assert_eq!(run.code.unwrap(), 0);
    assert!(run.output.contains(
        "The public key was already ready, but the vacuum did not finish connecting within the timeout."
    ));
}

#[test]
fn guided_onboarding_duplicate_names_still_selects_requested_device() {
    let mut first = q7();
    first["name"] = json!("Qrevo MaxV");
    let mut second = q7();
    second["name"] = json!("Qrevo MaxV");
    second["duid"] = json!("cloud-q7-b");
    second["onboarding"] = json!({"has_public_key": true, "key_state": {"query_samples": 2}});
    let api = FakeApi::new(
        vec![first, second],
        vec![status(2, true, false), status(2, true, true)],
    );
    let run = run_flow(&api, &["2", ""], true);
    assert_eq!(run.code.unwrap(), 0);
    assert_eq!(api.started(), vec!["cloud-q7-b"]);
    assert!(run
        .output
        .contains("Qrevo MaxV [cloud-q7-a] [No Public Key ]"));
    assert!(run
        .output
        .contains("Qrevo MaxV [cloud-q7-b] [Public Key Determined ]"));
}

#[test]
fn unsupported_vacuum_is_explained_then_quit() {
    let api = FakeApi::new(
        vec![q7()],
        vec![
            status(0, false, false),
            json!({"session_id": "sess-1", "unsupported": true}),
        ],
    );
    let run = run_flow(&api, &["1", "", "quit"], true);
    assert_eq!(run.code.unwrap(), 0);
    assert!(run
        .output
        .contains("This vacuum is not supported by the current onboarding flow."));
    assert_eq!(api.deleted(), vec!["sess-1"]);
}

#[test]
fn failed_send_offers_actions_and_refresh_reprints_status() {
    let api = FakeApi::new(vec![q7()], vec![status(0, false, false)]);
    let run = run_flow(&api, &["1", "", "refresh", "quit"], false);
    assert_eq!(run.code.unwrap(), 0);
    assert!(run.output.contains("Onboarding send failed.\n"));
    assert!(run.output.matches("Status for Q7 Upstairs").count() >= 2);
    assert_eq!(run.sends.len(), 1);
}

#[test]
fn reselect_starts_over_and_deletes_the_old_session() {
    let api = FakeApi::new(vec![q7()], vec![status(0, false, false)]);
    let run = run_flow(&api, &["1", "reselect", "quit"], true);
    assert_eq!(run.code.unwrap(), 0);
    assert_eq!(api.started(), vec!["cloud-q7-a"]);
    assert_eq!(api.deleted(), vec!["sess-1"]);
    assert!(run.sends.is_empty());
    assert_eq!(run.output.matches("Available vacuums:").count(), 2);
}

#[test]
fn quit_at_send_prompt_exits_zero_and_cleans_up() {
    let api = FakeApi::new(vec![q7()], vec![status(0, false, false)]);
    let run = run_flow(&api, &["1", "QUIT"], true);
    assert_eq!(run.code.unwrap(), 0);
    assert_eq!(api.deleted(), vec!["sess-1"]);
}

#[test]
fn send_error_aborts_but_still_deletes_session() {
    let api = FakeApi::new(vec![q7()], vec![status(0, false, false)]);
    let err = run_guided_onboarding(
        &config(),
        &api,
        &mut |_, _| Err(OnboardError::Io(io::Error::other("Network is unreachable"))),
        &mut Vec::new(),
        &mut Answers::new(&["1", ""]),
        settings(),
        &FakeClock::default(),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "Network is unreachable");
    assert_eq!(api.deleted(), vec!["sess-1"]);
}

#[test]
fn eof_on_input_is_an_error_and_still_deletes_session() {
    let api = FakeApi::new(vec![q7()], vec![status(0, false, false)]);
    let run = run_flow(&api, &["1"], true);
    assert!(matches!(run.code, Err(CliError::Input(InputError::Eof))));
    assert_eq!(api.deleted(), vec!["sess-1"]);
}

#[test]
fn missing_session_id_is_an_error() {
    struct NoSessionApi;
    impl OnboardingApi for NoSessionApi {
        fn login(&self) -> Result<(), ApiError> {
            Ok(())
        }
        fn list_devices(&self) -> Result<Vec<Value>, ApiError> {
            Ok(vec![q7()])
        }
        fn start_session(&self, _: &str) -> Result<Json, ApiError> {
            Ok(obj(json!({"session_id": "  "})))
        }
        fn get_session(&self, _: &str) -> Result<Json, ApiError> {
            unreachable!()
        }
        fn delete_session(&self, _: &str) -> Result<Json, ApiError> {
            unreachable!()
        }
        fn get_status(&self) -> Result<Json, ApiError> {
            unreachable!()
        }
    }
    let err = run_guided_onboarding(
        &config(),
        &NoSessionApi,
        &mut |_, _| Ok(true),
        &mut Vec::new(),
        &mut Answers::new(&["1"]),
        settings(),
        &FakeClock::default(),
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "Server did not return an onboarding session id."
    );
}

#[test]
fn no_devices_exits_zero() {
    let api = FakeApi::new(vec![], vec![]);
    let run = run_flow(&api, &[], true);
    assert_eq!(run.code.unwrap(), 0);
    assert!(run
        .output
        .contains("No known vacuums are available for onboarding."));
}

// ---- session tracking (Ctrl-C cleanup) ----------------------------------

#[test]
fn session_tracker_remembers_the_live_session_until_deleted() {
    let tracker = SessionTracker::new(FakeApi::new(vec![q7()], vec![]));
    assert_eq!(tracker.active_session(), None);
    tracker.start_session("cloud-q7-a").unwrap();
    assert_eq!(tracker.active_session().as_deref(), Some("sess-1"));
    tracker.delete_session("sess-1").unwrap();
    assert_eq!(tracker.active_session(), None);
}

#[test]
fn session_tracker_cleanup_deletes_and_forgets() {
    let tracker = SessionTracker::new(FakeApi::new(vec![q7()], vec![]));
    tracker.start_session("cloud-q7-a").unwrap();
    tracker.cleanup();
    assert_eq!(tracker.inner().deleted(), vec!["sess-1"]);
    tracker.cleanup();
    assert_eq!(tracker.inner().deleted(), vec!["sess-1"]);
}
