//! onboard_once against a mock vacuum on localhost UDP.

mod support;

use std::time::Duration;

use roborock_onboard::cfgwifi::{self, BodyLog, Exchange, OnboardError};
use roborock_onboard::protocol::ProtocolError;
use roborock_onboard::server::OnboardingConfig;
use serde_json::json;
use support::vacuum::{Behavior, MockVacuum};

fn config() -> OnboardingConfig {
    OnboardingConfig {
        api_base_url: "https://api-roborock.example.com:555".into(),
        stack_server: "roborock.example.com:555/".into(),
        admin_password: "secret".into(),
        ssid: "Home Wifi \u{e9}".into(),
        password: "Password123".into(),
        timezone: "Europe/Berlin".into(),
        cst: "CET-1CEST,M3.5.0,M10.5.0/3".into(),
        country_domain: "de".into(),
        allow_insecure_tls: false,
    }
}

fn run(behavior: Behavior, body_log: BodyLog) -> (Result<bool, OnboardError>, String, MockVacuum) {
    let vacuum = MockVacuum::start(behavior);
    let exchange = Exchange {
        target: vacuum.addr,
        reply_timeout: Duration::from_millis(1500),
        body_log,
    };
    let mut out = Vec::new();
    let result = cfgwifi::onboard_once(&config(), &exchange, &mut out);
    (result, String::from_utf8(out).unwrap(), vacuum)
}

fn line<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no {prefix} line in:\n{text}"))
}

#[test]
fn full_exchange_delivers_wifi_config_to_the_vacuum() {
    let (result, text, vacuum) = run(Behavior::Normal, BodyLog::Full);
    assert!(result.unwrap(), "{text}");
    let seen = vacuum.observed();

    let hello = seen.hello.unwrap();
    assert!(seen.hello_crc_ok);
    assert_eq!(hello["id"], json!(1));
    assert_eq!(hello["method"], json!("hello"));
    assert_eq!(hello["params"]["app_ver"], json!(1));
    let pem = hello["params"]["key"].as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));

    let wifi = seen.wifi.unwrap();
    assert!(seen.wifi_crc_ok);
    let token_s = line(&text, "TOKEN_S=");
    let token_t = line(&text, "TOKEN_T=");
    assert_eq!(
        wifi,
        json!({
            "u": "1234567890",
            "ssid": "Home Wifi \u{e9}",
            "token": {
                "r": "roborock.example.com:555/",
                "tz": "Europe/Berlin",
                "s": token_s,
                "cst": "CET-1CEST,M3.5.0,M10.5.0/3",
                "t": token_t,
            },
            "passwd": "Password123",
            "country_domain": "de",
        })
    );
    assert!(token_s.starts_with("S_TOKEN_") && token_s.len() == 40);
    assert!(token_t.starts_with("T_TOKEN_") && token_t.len() == 40);
    assert_ne!(token_s[8..], token_t[8..]);

    assert_eq!(line(&text, "HELLO_RESP_CMD="), "16");
    assert!(line(&text, "HELLO_RESP_JSON=").contains(r#""key":"sEsSiOnKeY012345""#));
    assert_eq!(
        line(&text, "WIFI_BODY_SENT="),
        roborock_onboard::pyjson::dumps(&wifi)
    );
    assert_eq!(line(&text, "WIFI_RESP_CMD="), "1");
    assert!(line(&text, "WIFI_RESP_HEX=").starts_with("312e30"));
}

#[test]
fn output_lines_come_in_python_order() {
    let (_, text, _) = run(Behavior::Normal, BodyLog::Full);
    let keys: Vec<&str> = text.lines().map(|l| l.split('=').next().unwrap()).collect();
    assert_eq!(
        keys,
        vec![
            "HELLO_RESP_CMD",
            "HELLO_RESP_JSON",
            "TOKEN_S",
            "TOKEN_T",
            "WIFI_BODY_SENT",
            "WIFI_RESP_CMD",
            "WIFI_RESP_HEX",
        ]
    );
}

#[test]
fn redacted_log_hides_password_and_token_t() {
    let (result, text, vacuum) = run(Behavior::Normal, BodyLog::Redacted);
    assert!(result.unwrap());
    let seen = vacuum.observed();
    assert_eq!(line(&text, "TOKEN_T="), "<redacted>");
    let sent: serde_json::Value = serde_json::from_str(line(&text, "WIFI_BODY_SENT=")).unwrap();
    assert_eq!(sent["passwd"], json!("<redacted>"));
    assert_eq!(sent["token"]["t"], json!("<redacted>"));
    assert!(!text.contains("Password123"));
    // The vacuum still gets the real secrets.
    assert_eq!(seen.wifi.unwrap()["passwd"], json!("Password123"));
}

#[test]
fn silent_vacuum_means_no_hello_response() {
    let (result, text, _) = run(Behavior::Silent, BodyLog::Full);
    assert!(!result.unwrap());
    assert_eq!(text, "HELLO: no response\n");
}

#[test]
fn bad_session_key_is_reported_and_nothing_else_sent() {
    let (result, text, vacuum) = run(Behavior::BadSessionKey, BodyLog::Full);
    assert!(!result.unwrap());
    assert!(text.ends_with("HELLO: session key invalid\n"), "{text}");
    assert!(vacuum.observed().wifi.is_none());
}

#[test]
fn short_hello_reply_is_a_protocol_error_not_a_panic() {
    let (result, _, _) = run(Behavior::ShortHelloReply, BodyLog::Full);
    assert!(matches!(
        result,
        Err(OnboardError::Protocol(ProtocolError::TooShort { len: 5 }))
    ));
}

#[test]
fn missing_wifi_ack_still_counts_as_sent() {
    let (result, text, vacuum) = run(Behavior::NoWifiAck, BodyLog::Full);
    assert!(result.unwrap());
    assert!(text.ends_with("WIFI_RESP: none\n"), "{text}");
    assert!(vacuum.observed().wifi.is_some());
}

#[test]
fn malformed_wifi_ack_is_logged_not_fatal() {
    let (result, text, _) = run(Behavior::ShortWifiAck, BodyLog::Full);
    assert!(result.unwrap());
    assert!(
        line(&text, "WIFI_RESP_CMD=").contains("too short"),
        "{text}"
    );
    assert_eq!(line(&text, "WIFI_RESP_HEX="), "312e30");
}

#[test]
fn token_hex_is_32_lowercase_hex_chars() {
    let token = cfgwifi::token_hex16();
    assert_eq!(token.len(), 32);
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert_ne!(token, cfgwifi::token_hex16());
}
