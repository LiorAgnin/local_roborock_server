//! Pins the Rust port against output captured from the Python implementation.
//! Regenerate with `tests/fixtures/gen_fixtures.py` (see its docstring).

use roborock_onboard::protocol::{
    self, AesKey, Command, HelloReply, RsaKeyPair, WifiConfigBody, WifiToken,
};
use roborock_onboard::pyjson;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/python_parity.json")).unwrap()
}

fn text(fx: &Value, key: &str) -> String {
    fx[key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture key {key}"))
        .to_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The same body gen_fixtures.py serializes (non-ASCII SSID and password).
fn wifi_body() -> WifiConfigBody {
    WifiConfigBody {
        u: protocol::CFGWIFI_UID.into(),
        ssid: "Caf\u{e9} \u{2615} Stra\u{df}e \u{1f600} \"q\" / \\ \t\u{7f}\u{1}".into(),
        token: WifiToken {
            r: "roborock.example.com:555/".into(),
            tz: "Europe/Berlin".into(),
            s: "S_TOKEN_00112233445566778899aabbccddeeff".into(),
            cst: "CET-1CEST,M3.5.0,M10.5.0/3".into(),
            t: "T_TOKEN_ffeeddccbbaa99887766554433221100".into(),
        },
        passwd: "p\u{e4}ssw\u{f6}rd\n\u{20ac}".into(),
        country_domain: "de".into(),
    }
}

#[test]
fn wifi_body_json_is_byte_identical_to_python() {
    let fx = fixture();
    assert_eq!(pyjson::dumps(&wifi_body()), text(&fx, "wifi_body_json"));
}

#[test]
fn wifi_packet_is_byte_identical_to_python() {
    let fx = fixture();
    let key = AesKey::new(&text(&fx, "session_key")).unwrap();
    let packet = protocol::build_wifi_packet(&key, &wifi_body());
    assert_eq!(hex(&packet), text(&fx, "wifi_packet_hex"));
}

#[test]
fn public_pem_is_identical_to_pycryptodome_export() {
    let fx = fixture();
    let pair = RsaKeyPair::from_pkcs1_pem(&text(&fx, "rsa_private_pem")).unwrap();
    assert_eq!(pair.public_pem().unwrap(), text(&fx, "rsa_public_pem"));
}

#[test]
fn hello_packet_is_byte_identical_to_python() {
    let fx = fixture();
    let pre_key = AesKey::new(&text(&fx, "pre_key")).unwrap();
    let packet = protocol::build_hello_packet(&pre_key, &text(&fx, "rsa_public_pem"));
    assert_eq!(hex(&packet), text(&fx, "hello_packet_hex"));
}

#[test]
fn decrypts_multi_block_ciphertext_from_pycryptodome() {
    let fx = fixture();
    let pair = RsaKeyPair::from_pkcs1_pem(&text(&fx, "rsa_private_pem")).unwrap();
    let plain = pair
        .decrypt_blocks(&unhex(&text(&fx, "session_ciphertext_hex")))
        .unwrap();
    let plain = String::from_utf8(plain).unwrap();
    assert_eq!(plain, text(&fx, "session_plaintext"));
    assert_eq!(
        protocol::parse_hello_reply(&plain).unwrap(),
        HelloReply::SessionKey(AesKey::new(&text(&fx, "session_key")).unwrap())
    );
}

#[test]
fn frames_are_byte_identical_to_python() {
    let fx = fixture();
    assert_eq!(
        hex(&protocol::build_frame(b"hello", Command::Hello).unwrap()),
        text(&fx, "frame_hello_cmd16_hex")
    );
    assert_eq!(
        hex(&protocol::build_frame(b"", Command::WifiConfig).unwrap()),
        text(&fx, "frame_empty_cmd1_hex")
    );
}

#[test]
fn server_normalization_matches_python() {
    use roborock_onboard::server::{normalize_api_base_url, sanitize_stack_server};
    let fx = fixture();
    for case in fx["server_normalization"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let api = normalize_api_base_url(input).map_err(|e| e.to_string());
        match (&case["api_base_url"], &case["api_base_url_error"]) {
            (Value::String(ok), _) => assert_eq!(api.as_deref(), Ok(ok.as_str()), "{input:?}"),
            (_, Value::String(msg)) => assert_eq!(api, Err(msg.clone()), "{input:?}"),
            _ => panic!("bad fixture case {case}"),
        }
        let stack = sanitize_stack_server(input).map_err(|e| e.to_string());
        match (&case["stack_server"], &case["stack_server_error"]) {
            (Value::String(ok), _) => assert_eq!(stack.as_deref(), Ok(ok.as_str()), "{input:?}"),
            (_, Value::String(msg)) => assert_eq!(stack, Err(msg.clone()), "{input:?}"),
            _ => panic!("bad fixture case {case}"),
        }
    }
}
