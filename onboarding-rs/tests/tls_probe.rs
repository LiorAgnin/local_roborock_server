//! probe_tls_endpoint against real local listeners.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use roborock_onboard::api::crypto_provider;
use roborock_onboard::preflight::{probe_tls_endpoint, TlsTarget};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A TLS server with a self-signed `localhost` cert that accepts one handshake.
fn self_signed_tls_server() -> u16 {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut conn = rustls::ServerConnection::new(config).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    break;
                }
            }
            let _ = conn.complete_io(&mut sock);
        }
    });
    port
}

fn target(port: u16, insecure: bool) -> TlsTarget {
    TlsTarget {
        host: "localhost".into(),
        port,
        allow_insecure_tls: insecure,
        label: format!("ssl://localhost:{port}"),
    }
}

#[test]
fn insecure_probe_accepts_self_signed_certificate() {
    let port = self_signed_tls_server();
    assert_eq!(probe_tls_endpoint(&target(port, true)), Ok(()));
}

#[test]
fn verified_probe_rejects_self_signed_certificate() {
    let port = self_signed_tls_server();
    let err = probe_tls_endpoint(&target(port, false)).unwrap_err();
    assert!(
        err.starts_with(&format!(
            "TLS certificate verification failed for ssl://localhost:{port}: "
        )),
        "{err}"
    );
}

#[test]
fn non_tls_listener_is_a_handshake_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            // Consume the ClientHello and close gracefully: closing with unread
            // data makes Windows send RST, which surfaces as a connect error
            // (os error 10053) instead of a handshake error.
            let mut hello = [0u8; 4096];
            let _ = sock.read(&mut hello);
            let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nnot tls at all\r\n");
            let _ = sock.shutdown(std::net::Shutdown::Write);
            let _ = sock.read_to_end(&mut Vec::new());
        }
    });
    let err = probe_tls_endpoint(&target(port, true)).unwrap_err();
    assert!(
        err.starts_with(&format!(
            "TLS handshake failed for ssl://localhost:{port}: "
        )),
        "{err}"
    );
}

#[test]
fn closed_port_is_a_connect_failure() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let t = TlsTarget {
        host: "127.0.0.1".into(),
        port,
        allow_insecure_tls: true,
        label: format!("ssl://127.0.0.1:{port}"),
    };
    let err = probe_tls_endpoint(&t).unwrap_err();
    assert!(
        err.starts_with(&format!("Could not connect to ssl://127.0.0.1:{port}: ")),
        "{err}"
    );
}

#[test]
fn unresolvable_host_is_a_connect_failure() {
    let t = TlsTarget {
        host: "does-not-exist.invalid".into(),
        port: 443,
        allow_insecure_tls: true,
        label: "ssl://does-not-exist.invalid:443".into(),
    };
    let err = probe_tls_endpoint(&t).unwrap_err();
    assert!(
        err.starts_with("Could not connect to ssl://does-not-exist.invalid:443: "),
        "{err}"
    );
}
