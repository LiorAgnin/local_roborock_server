//! One onboarding attempt over UDP: hello key exchange, then the encrypted
//! Wi-Fi configuration (Python `onboard_once`).

use std::fmt;
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use rsa::rand_core::{OsRng, RngCore};

use crate::protocol::{
    self, AesKey, HelloReply, ProtocolError, RsaKeyPair, WifiConfigBody, WifiToken,
};
use crate::pyjson;
use crate::server::OnboardingConfig;

/// The vacuum's address on its own setup hotspot.
pub const DEFAULT_TARGET: &str = "192.168.8.1:55559";
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// How much of the sent Wi-Fi body to echo to the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLog {
    /// Full body and `TOKEN_T` (the CLI).
    Full,
    /// Password and `token.t` replaced by `<redacted>` (the GUI log pane).
    Redacted,
}

/// Where and how to send.
#[derive(Debug, Clone, Copy)]
pub struct Exchange {
    pub target: SocketAddr,
    pub reply_timeout: Duration,
    pub body_log: BodyLog,
}

#[derive(Debug)]
pub enum OnboardError {
    Io(io::Error),
    Protocol(ProtocolError),
}

impl fmt::Display for OnboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OnboardError::Io(err) => err.fmt(f),
            OnboardError::Protocol(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for OnboardError {}

impl From<io::Error> for OnboardError {
    fn from(err: io::Error) -> Self {
        OnboardError::Io(err)
    }
}

impl From<ProtocolError> for OnboardError {
    fn from(err: ProtocolError) -> Self {
        OnboardError::Protocol(err)
    }
}

/// Run one hello + Wi-Fi exchange. `Ok(false)` means the vacuum did not
/// answer hello or sent an unusable session key; `Err` is a socket or
/// protocol failure.
pub fn onboard_once(
    config: &OnboardingConfig,
    exchange: &Exchange,
    output: &mut dyn Write,
) -> Result<bool, OnboardError> {
    let token_s = format!("S_TOKEN_{}", token_hex16());
    let token_t = format!("T_TOKEN_{}", token_hex16());
    let keys = RsaKeyPair::generate()?;
    let public_pem = keys.public_pem()?;

    let sock = UdpSocket::bind(("0.0.0.0", 0))?;
    sock.set_read_timeout(Some(exchange.reply_timeout))?;
    let pre_key = AesKey::new(protocol::PRE_KEY)?;
    sock.send_to(
        &protocol::build_hello_packet(&pre_key, &public_pem),
        exchange.target,
    )?;
    let Some(hello_reply) = recv(&sock)?.filter(|packet| !packet.is_empty()) else {
        let _ = writeln!(output, "HELLO: no response");
        return Ok(false);
    };

    let frame = protocol::parse_frame(&hello_reply)?;
    let decrypted = keys.decrypt_blocks(frame.payload)?;
    let decrypted = String::from_utf8_lossy(&decrypted);
    let _ = writeln!(output, "HELLO_RESP_CMD={}", frame.command);
    let _ = writeln!(output, "HELLO_RESP_JSON={decrypted}");
    let session_key = match protocol::parse_hello_reply(&decrypted)? {
        HelloReply::SessionKey(key) => key,
        HelloReply::InvalidKey => {
            let _ = writeln!(output, "HELLO: session key invalid");
            return Ok(false);
        }
    };

    let body = WifiConfigBody {
        u: protocol::CFGWIFI_UID.into(),
        ssid: config.ssid.clone(),
        token: WifiToken {
            r: config.stack_server.clone(),
            tz: config.timezone.clone(),
            s: token_s.clone(),
            cst: config.cst.clone(),
            t: token_t.clone(),
        },
        passwd: config.password.clone(),
        country_domain: config.country_domain.clone(),
    };
    sock.send_to(
        &protocol::build_wifi_packet(&session_key, &body),
        exchange.target,
    )?;
    let _ = writeln!(output, "TOKEN_S={token_s}");
    match exchange.body_log {
        BodyLog::Full => {
            let _ = writeln!(output, "TOKEN_T={token_t}");
            let _ = writeln!(output, "WIFI_BODY_SENT={}", pyjson::dumps(&body));
        }
        BodyLog::Redacted => {
            let _ = writeln!(output, "TOKEN_T=<redacted>");
            let _ = writeln!(output, "WIFI_BODY_SENT={}", pyjson::dumps(&body.redacted()));
        }
    }

    match recv(&sock)? {
        None => {
            let _ = writeln!(output, "WIFI_RESP: none");
        }
        Some(reply) => {
            // The packet was already delivered; a garbled ack is logged, not fatal.
            match protocol::parse_command(&reply) {
                Ok(command) => {
                    let _ = writeln!(output, "WIFI_RESP_CMD={command}");
                }
                Err(err) => {
                    let _ = writeln!(output, "WIFI_RESP_CMD=<malformed: {err}>");
                }
            }
            let hex: String = reply.iter().take(400).map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(output, "WIFI_RESP_HEX={hex}");
        }
    }
    Ok(true)
}

/// Receive one datagram, `None` on timeout.
fn recv(sock: &UdpSocket) -> io::Result<Option<Vec<u8>>> {
    let mut buf = [0u8; 4096];
    match sock.recv_from(&mut buf) {
        Ok((len, _)) => Ok(Some(buf[..len].to_vec())),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// `secrets.token_hex(16)`: 32 lowercase hex characters.
pub fn token_hex16() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
