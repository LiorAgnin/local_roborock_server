//! End to end: the guided CLI flow with the real HTTP client talking to a
//! mock admin server and the real cfgwifi exchange talking to a mock vacuum.

mod support;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use roborock_onboard::api::RemoteOnboardingApi;
use roborock_onboard::cfgwifi::{self, BodyLog, Exchange};
use roborock_onboard::cli::{self, InputError, PollSettings, Prompter, SystemClock};
use roborock_onboard::server::OnboardingConfig;
use serde_json::json;
use support::vacuum::{Behavior, MockVacuum};
use support::{MockAdmin, Reply};

struct Script(VecDeque<&'static str>);

impl Prompter for Script {
    fn input(&mut self, _prompt: &str) -> Result<String, InputError> {
        self.0.pop_front().map(str::to_owned).ok_or(InputError::Eof)
    }
    fn secret(&mut self, prompt: &str) -> Result<String, InputError> {
        self.input(prompt)
    }
}

#[test]
fn cli_flow_pairs_a_vacuum_end_to_end() {
    let session_reads = Arc::new(AtomicUsize::new(0));
    let admin = {
        let session_reads = Arc::clone(&session_reads);
        MockAdmin::start(move |req| match (req.method.as_str(), req.path.as_str()) {
            ("POST", "/admin/api/login") => Reply {
                set_cookie: Some("admin_session=tok; Path=/".into()),
                ..Reply::json(200, json!({"ok": true}))
            },
            (_, _) if req.cookie.as_deref() != Some("admin_session=tok") => {
                Reply::json(401, json!({"error": "Unauthorized"}))
            }
            ("GET", "/admin/api/onboarding/devices") => Reply::json(
                200,
                json!({"devices": [{
                    "duid": "duid-1",
                    "name": "Qrevo",
                    "connected": false,
                    "onboarding": {"has_public_key": false, "key_state": {"query_samples": 0}},
                }]}),
            ),
            ("POST", "/admin/api/onboarding/sessions") => {
                Reply::json(200, json!({"session_id": "sess-9"}))
            }
            ("GET", "/admin/api/onboarding/sessions/sess-9") => {
                let connected = session_reads.fetch_add(1, Ordering::SeqCst) > 0;
                Reply::json(
                    200,
                    json!({
                        "session_id": "sess-9",
                        "query_samples": if connected { 2 } else { 0 },
                        "has_public_key": connected,
                        "public_key_state": if connected { "ready" } else { "missing" },
                        "connected": connected,
                        "target": {"name": "Qrevo", "duid": "duid-1"},
                    }),
                )
            }
            ("DELETE", "/admin/api/onboarding/sessions/sess-9") => {
                Reply::json(200, json!({"ok": true}))
            }
            _ => Reply::json(404, json!({"detail": "Not Found"})),
        })
    };
    let vacuum = MockVacuum::start(Behavior::Normal);
    let exchange = Exchange {
        target: vacuum.addr,
        reply_timeout: Duration::from_secs(2),
        body_log: BodyLog::Full,
    };
    let config = OnboardingConfig {
        api_base_url: admin.base_url.clone(),
        stack_server: "roborock.example.com:555/".into(),
        admin_password: "secret".into(),
        ssid: "Home \u{1f3e0} Wifi".into(),
        password: "Password123".into(),
        timezone: "America/Chicago".into(),
        cst: "CST6CDT,M3.2.0,M11.1.0".into(),
        country_domain: "us".into(),
        allow_insecure_tls: false,
    };
    let api = RemoteOnboardingApi::new(&admin.base_url, &config.admin_password, false);
    let mut output = Vec::new();

    let code = cli::run_guided_onboarding(
        &config,
        &api,
        &mut |cfg, out| cfgwifi::onboard_once(cfg, &exchange, out),
        &mut output,
        &mut Script(["1", ""].into_iter().collect()),
        PollSettings {
            interval: Duration::from_millis(10),
            timeout: Duration::from_secs(5),
        },
        &SystemClock::new(),
    )
    .unwrap();

    let text = String::from_utf8(output).unwrap();
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("HELLO_RESP_CMD=16"), "{text}");
    assert!(text.contains("WIFI_RESP_CMD=1"), "{text}");
    assert!(text.contains("The vacuum is connected to the local server."));

    let seen = vacuum.observed();
    assert!(seen.hello_crc_ok && seen.wifi_crc_ok);
    let wifi = seen.wifi.expect("vacuum received the Wi-Fi packet");
    assert_eq!(wifi["ssid"], json!("Home \u{1f3e0} Wifi"));
    assert_eq!(wifi["passwd"], json!("Password123"));
    assert_eq!(wifi["token"]["r"], json!("roborock.example.com:555/"));
    assert_eq!(wifi["token"]["cst"], json!("CST6CDT,M3.2.0,M11.1.0"));
    assert_eq!(wifi["country_domain"], json!("us"));

    assert_eq!(
        admin.paths(),
        vec![
            "POST /admin/api/login",
            "GET /admin/api/onboarding/devices",
            "POST /admin/api/onboarding/sessions",
            "GET /admin/api/onboarding/sessions/sess-9",
            "GET /admin/api/onboarding/sessions/sess-9",
            "DELETE /admin/api/onboarding/sessions/sess-9",
        ]
    );
}
