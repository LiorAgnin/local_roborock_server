//! Stack preflight: admin login, required services, and TLS probes of the
//! HTTPS and MQTT listeners the vacuum will connect to.

use std::fmt;
use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;

use crate::api::{ApiError, OnboardingApi};
use crate::pyvalue::{self, Json};

pub const DEFAULT_MQTT_TLS_PORT: u16 = 8881;
pub const TLS_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const REQUIRED_SERVICE_NAMES: [&str; 3] = ["https_server", "mqtt_tls_proxy", "mqtt_backend_broker"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightError {
    Api(ApiError),
    Failed(String),
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PreflightError::Api(err) => err.fmt(f),
            PreflightError::Failed(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for PreflightError {}

impl From<ApiError> for PreflightError {
    fn from(err: ApiError) -> Self {
        PreflightError::Api(err)
    }
}

/// One TLS listener to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsTarget {
    pub host: String,
    pub port: u16,
    pub allow_insecure_tls: bool,
    pub label: String,
}

/// Run the preflight, writing progress to `output`. `probe` performs the TLS
/// handshake check (see [`probe_tls_endpoint`]); tests pass a fake.
pub fn perform_onboarding_preflight(
    api: &dyn OnboardingApi,
    api_base_url: &str,
    allow_insecure_tls: bool,
    output: &mut dyn Write,
    probe: &mut dyn FnMut(&TlsTarget) -> Result<(), String>,
) -> Result<Json, PreflightError> {
    let (api_host, api_port) = parse_https_endpoint(api_base_url)?;
    let _ = writeln!(
        output,
        "Checking admin API reachability at {api_base_url}/admin/api/status..."
    );
    api.login()?;
    let status = api.get_status()?;
    let _ = writeln!(output, "Admin API login succeeded.");

    let _ = writeln!(output, "Checking required stack services...");
    let services = service_map_from_status(&status)?;
    let mut problems = Vec::new();
    for name in REQUIRED_SERVICE_NAMES {
        let Some(service) = services.iter().find(|(n, _)| n == name).map(|(_, s)| s) else {
            problems.push(format!("{name} is missing from /admin/api/status"));
            continue;
        };
        let enabled = service
            .get("enabled")
            .is_none_or(|v| pyvalue::truthy(Some(v)));
        if !enabled {
            problems.push(format!("{name} is disabled"));
            continue;
        }
        if !pyvalue::truthy(service.get("running")) {
            let detail = pyvalue::first_str(&[service.get("detail")], "");
            let detail = detail.trim();
            let suffix = if detail.is_empty() {
                String::new()
            } else {
                format!(" ({detail})")
            };
            problems.push(format!("{name} is not running{suffix}"));
        }
    }
    if !problems.is_empty() {
        return Err(PreflightError::Failed(format!(
            "Stack preflight failed: {}",
            problems.join("; ")
        )));
    }
    let _ = writeln!(
        output,
        "Required services are running: https_server, mqtt_tls_proxy, mqtt_backend_broker."
    );

    let mqtt_port = services
        .iter()
        .find(|(n, _)| n == "mqtt_tls_proxy")
        .map_or(DEFAULT_MQTT_TLS_PORT, |(_, service)| service_port(service));

    let api_label = format!("https://{api_host}:{api_port}");
    let _ = writeln!(output, "Checking API TLS listener at {api_label}...");
    probe(&TlsTarget {
        host: api_host.clone(),
        port: api_port,
        allow_insecure_tls,
        label: api_label.clone(),
    })
    .map_err(PreflightError::Failed)?;
    let _ = output.write_all(tls_success_message(&api_label, allow_insecure_tls).as_bytes());

    // Prefer the advertised port (external_tls mode) over the internal listener port.
    let advertised = pyvalue::int_or_zero(status.get("advertised_mqtt_tls_port"));
    let mqtt_preflight_port = u16::try_from(advertised)
        .ok()
        .filter(|port| *port != 0)
        .unwrap_or(mqtt_port);
    let mqtt_label = format!("ssl://{api_host}:{mqtt_preflight_port}");
    let _ = writeln!(output, "Checking MQTT TLS listener at {mqtt_label}...");
    probe(&TlsTarget {
        host: api_host,
        port: mqtt_preflight_port,
        allow_insecure_tls,
        label: mqtt_label.clone(),
    })
    .map_err(PreflightError::Failed)?;
    let _ = output.write_all(tls_success_message(&mqtt_label, allow_insecure_tls).as_bytes());
    Ok(status)
}

fn tls_success_message(label: &str, allow_insecure_tls: bool) -> String {
    if allow_insecure_tls {
        format!("TLS listener reachable at {label} (certificate verification skipped).\n")
    } else {
        format!("TLS certificate is valid and listener is reachable at {label}.\n")
    }
}

/// Host and port (default 443) of an `https://host[:port]` URL.
fn parse_https_endpoint(url: &str) -> Result<(String, u16), PreflightError> {
    let invalid = || PreflightError::Failed("A valid HTTPS server URL is required.".into());
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let (host, port) = match hostinfo.strip_prefix('[') {
        Some(bracketed) => {
            let (host, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (host, rest.strip_prefix(':').unwrap_or(""))
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    let host = host.trim().to_lowercase();
    if host.is_empty() {
        return Err(invalid());
    }
    let port = match port {
        "" => 443,
        port => port.parse::<u16>().ok().filter(|p| *p != 0).unwrap_or(443),
    };
    Ok((host, port))
}

fn service_map_from_status(status: &Json) -> Result<Vec<(String, Json)>, PreflightError> {
    let Some(Value::Object(health)) = status.get("health") else {
        return Err(PreflightError::Failed(
            "Stack preflight failed: /admin/api/status did not return a health payload.".into(),
        ));
    };
    let Some(Value::Array(services)) = health.get("services") else {
        return Err(PreflightError::Failed(
            "Stack preflight failed: /admin/api/status did not return health.services.".into(),
        ));
    };
    let mut out: Vec<(String, Json)> = Vec::new();
    for item in services {
        let Value::Object(item) = item else { continue };
        let name = pyvalue::first_str(&[item.get("name")], "");
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        // Later entries win, like assigning into a Python dict.
        out.retain(|(existing, _)| existing != name);
        out.push((name.to_owned(), item.clone()));
    }
    Ok(out)
}

/// Port from a service detail ending in `:<digits>`, e.g. `tls:0.0.0.0:8881`.
fn service_port(service: &Json) -> u16 {
    let detail = pyvalue::first_str(&[service.get("detail")], "");
    let detail = detail.trim_end();
    let digits_start = detail
        .rfind(|c: char| !c.is_ascii_digit())
        .map_or(0, |idx| idx + 1);
    let digits = &detail[digits_start..];
    if digits.is_empty() || !detail[..digits_start].ends_with(':') {
        return DEFAULT_MQTT_TLS_PORT;
    }
    digits.parse().unwrap_or(DEFAULT_MQTT_TLS_PORT)
}

/// Connect to `host:port` and complete a TLS handshake, verifying the
/// certificate against the OS trust store unless `allow_insecure_tls`.
pub fn probe_tls_endpoint(target: &TlsTarget) -> Result<(), String> {
    let label = &target.label;
    let connect_err = |err: &dyn fmt::Display| format!("Could not connect to {label}: {err}");
    let tls_err = |err: &rustls::Error| match err {
        rustls::Error::InvalidCertificate(_) => {
            format!("TLS certificate verification failed for {label}: {err}")
        }
        _ => format!("TLS handshake failed for {label}: {err}"),
    };

    let config = tls_client_config(target.allow_insecure_tls).map_err(|err| tls_err(&err))?;
    let server_name = ServerName::try_from(target.host.clone()).map_err(|err| connect_err(&err))?;
    let mut sock = connect(&target.host, target.port).map_err(|err| connect_err(&err))?;
    sock.set_read_timeout(Some(TLS_CONNECT_TIMEOUT))
        .and_then(|()| sock.set_write_timeout(Some(TLS_CONNECT_TIMEOUT)))
        .map_err(|err| connect_err(&err))?;

    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|e| tls_err(&e))?;
    while conn.is_handshaking() {
        if let Err(err) = conn.complete_io(&mut sock) {
            let tls = err
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>());
            return Err(match tls {
                Some(tls) => tls_err(tls),
                None if err.kind() == io::ErrorKind::UnexpectedEof => {
                    format!("TLS handshake failed for {label}: {err}")
                }
                None => connect_err(&err),
            });
        }
    }
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    Ok(())
}

/// `socket.create_connection`: try each resolved address in turn.
fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, TLS_CONNECT_TIMEOUT) {
            Ok(sock) => return Ok(sock),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses resolved")))
}

fn tls_client_config(allow_insecure_tls: bool) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = crate::api::crypto_provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?
        .dangerous();
    let config = if allow_insecure_tls {
        builder.with_custom_certificate_verifier(Arc::new(NoVerification(provider)))
    } else {
        // Not actually dangerous: the platform verifier checks the OS trust store.
        builder.with_custom_certificate_verifier(Arc::new(rustls_platform_verifier::Verifier::new(
            provider,
        )?))
    };
    Ok(config.with_no_client_auth())
}

/// Accept any certificate (`--allow-insecure-tls`), like Python's
/// `ssl._create_unverified_context()`.
#[derive(Debug)]
struct NoVerification(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiError;
    use serde_json::json;
    use std::sync::Mutex;

    struct FakeApi {
        status: Json,
        calls: Mutex<Vec<&'static str>>,
    }

    impl FakeApi {
        fn new(status: Value) -> Self {
            FakeApi {
                status: status.as_object().unwrap().clone(),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl OnboardingApi for FakeApi {
        fn login(&self) -> Result<(), ApiError> {
            self.calls.lock().unwrap().push("login");
            Ok(())
        }
        fn list_devices(&self) -> Result<Vec<Value>, ApiError> {
            unreachable!()
        }
        fn start_session(&self, _: &str) -> Result<Json, ApiError> {
            unreachable!()
        }
        fn get_session(&self, _: &str) -> Result<Json, ApiError> {
            unreachable!()
        }
        fn delete_session(&self, _: &str) -> Result<Json, ApiError> {
            unreachable!()
        }
        fn get_status(&self) -> Result<Json, ApiError> {
            self.calls.lock().unwrap().push("status");
            Ok(self.status.clone())
        }
    }

    fn healthy(mqtt_detail: &str) -> Value {
        json!({"health": {"services": [
            {"name": "https_server", "running": true, "enabled": true, "detail": "tls:0.0.0.0:555"},
            {"name": "mqtt_tls_proxy", "running": true, "enabled": true, "detail": mqtt_detail},
            {"name": "mqtt_backend_broker", "running": true, "enabled": true, "detail": "embedded:127.0.0.1:18830"},
        ]}})
    }

    fn run(
        status: Value,
        insecure: bool,
    ) -> (
        Result<Json, PreflightError>,
        Vec<TlsTarget>,
        String,
        Vec<&'static str>,
    ) {
        let api = FakeApi::new(status);
        let mut probes = Vec::new();
        let mut out = Vec::new();
        let result = perform_onboarding_preflight(
            &api,
            "https://api-roborock.example.com:555",
            insecure,
            &mut out,
            &mut |target| {
                probes.push(target.clone());
                Ok(())
            },
        );
        let calls = api.calls.lock().unwrap().clone();
        (result, probes, String::from_utf8(out).unwrap(), calls)
    }

    fn target(port: u16, label: &str, insecure: bool) -> TlsTarget {
        TlsTarget {
            host: "api-roborock.example.com".into(),
            port,
            allow_insecure_tls: insecure,
            label: label.into(),
        }
    }

    #[test]
    fn validates_api_services_and_mqtt_tls() {
        let (result, probes, text, calls) = run(healthy("tls:0.0.0.0:1881"), false);
        assert!(result.is_ok());
        assert_eq!(calls, vec!["login", "status"]);
        assert_eq!(
            probes,
            vec![
                target(555, "https://api-roborock.example.com:555", false),
                target(1881, "ssl://api-roborock.example.com:1881", false),
            ]
        );
        assert!(text.contains("Admin API login succeeded."));
        assert!(text.contains("Required services are running"));
        assert!(text.contains("TLS certificate is valid and listener is reachable"));
    }

    #[test]
    fn prints_the_python_progress_lines() {
        let (_, _, text, _) = run(healthy("tls:0.0.0.0:8881"), false);
        assert_eq!(
            text,
            "Checking admin API reachability at https://api-roborock.example.com:555/admin/api/status...\n\
             Admin API login succeeded.\n\
             Checking required stack services...\n\
             Required services are running: https_server, mqtt_tls_proxy, mqtt_backend_broker.\n\
             Checking API TLS listener at https://api-roborock.example.com:555...\n\
             TLS certificate is valid and listener is reachable at https://api-roborock.example.com:555.\n\
             Checking MQTT TLS listener at ssl://api-roborock.example.com:8881...\n\
             TLS certificate is valid and listener is reachable at ssl://api-roborock.example.com:8881.\n"
        );
    }

    #[test]
    fn prefers_advertised_mqtt_port() {
        let mut status = healthy("tls:0.0.0.0:8881");
        status["advertised_mqtt_tls_port"] = json!(8883);
        let (_, probes, _, _) = run(status, false);
        assert_eq!(probes[1].port, 8883);
        assert_eq!(probes[1].label, "ssl://api-roborock.example.com:8883");
    }

    #[test]
    fn falls_back_to_default_mqtt_port_without_detail_port() {
        let (_, probes, _, _) = run(healthy("embedded"), false);
        assert_eq!(probes[1].port, DEFAULT_MQTT_TLS_PORT);
    }

    #[test]
    fn rejects_stopped_required_service_with_detail() {
        let mut status = healthy("tls:0.0.0.0:8881");
        status["health"]["services"][1]["running"] = json!(false);
        let (result, probes, _, _) = run(status, false);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Stack preflight failed: mqtt_tls_proxy is not running (tls:0.0.0.0:8881)"
        );
        assert!(probes.is_empty());
    }

    #[test]
    fn reports_every_problem_at_once() {
        let status = json!({"health": {"services": [
            {"name": "https_server", "running": true, "enabled": false},
            {"name": "mqtt_tls_proxy", "running": false, "detail": ""},
            "not-a-dict",
        ]}});
        let (result, _, _, _) = run(status, false);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Stack preflight failed: https_server is disabled; mqtt_tls_proxy is not running; \
             mqtt_backend_broker is missing from /admin/api/status"
        );
    }

    #[test]
    fn enabled_null_counts_as_disabled_but_missing_counts_as_enabled() {
        let mut status = healthy("x");
        status["health"]["services"][0]
            .as_object_mut()
            .unwrap()
            .remove("enabled");
        status["health"]["services"][2]["enabled"] = json!(null);
        let (result, _, _, _) = run(status, false);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Stack preflight failed: mqtt_backend_broker is disabled"
        );
    }

    #[test]
    fn requires_health_payload_and_services_list() {
        let (result, _, _, _) = run(json!({}), false);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Stack preflight failed: /admin/api/status did not return a health payload."
        );
        let (result, _, _, _) = run(json!({"health": {"services": {}}}), false);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Stack preflight failed: /admin/api/status did not return health.services."
        );
    }

    #[test]
    fn reports_when_tls_verification_is_skipped() {
        let (_, probes, text, _) = run(healthy("tls:0.0.0.0:8881"), true);
        assert!(probes.iter().all(|p| p.allow_insecure_tls));
        assert!(text.contains(
            "TLS listener reachable at https://api-roborock.example.com:555 (certificate verification skipped)."
        ));
    }

    #[test]
    fn probe_failure_stops_preflight() {
        let api = FakeApi::new(healthy("tls:0.0.0.0:8881"));
        let mut out = Vec::new();
        let err = perform_onboarding_preflight(
            &api,
            "https://api-roborock.example.com",
            false,
            &mut out,
            &mut |t| Err(format!("Could not connect to {}: refused", t.label)),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Could not connect to https://api-roborock.example.com:443: refused"
        );
    }
}
