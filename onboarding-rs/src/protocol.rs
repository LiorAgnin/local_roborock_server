//! The vacuum's cfgwifi UDP protocol.
//!
//! A frame is `"1.0"` + `00 00 00 01` + command (u16 BE) + payload length
//! (u16 BE) + payload + CRC32 (BE) of everything before it. The app sends an
//! AES-128-ECB encrypted `hello` carrying a fresh RSA-1024 public key under a
//! fixed pre-shared key; the vacuum answers with an RSA PKCS#1 v1.5 encrypted
//! session key, which then encrypts the Wi-Fi configuration.
//!
//! Everything that reads bytes off the network returns a [`ProtocolError`]
//! instead of panicking on short or malformed packets.

use std::fmt;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use serde::Serialize;

use crate::pyjson;

const MAGIC: &[u8; 3] = b"1.0";
const SEQUENCE: [u8; 4] = [0, 0, 0, 1];
/// Bytes before the payload: magic, sequence, command, payload length.
pub const HEADER_LEN: usize = 11;
const CRC_LEN: usize = 4;
const RSA_BITS: usize = 1024;

/// Pre-shared AES key the vacuum uses to decrypt `hello`.
pub const PRE_KEY: &str = "6433df70f5a3a42e";
/// Fixed user id the official app sends in the Wi-Fi config.
pub const CFGWIFI_UID: &str = "1234567890";

/// cfgwifi command ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Wi-Fi configuration (`1`).
    WifiConfig,
    /// Key exchange (`16`).
    Hello,
    /// Any id this tool does not send itself.
    Other(u16),
}

impl Command {
    pub fn id(self) -> u16 {
        match self {
            Command::WifiConfig => 1,
            Command::Hello => 16,
            Command::Other(id) => id,
        }
    }
}

impl From<u16> for Command {
    fn from(id: u16) -> Self {
        match id {
            1 => Command::WifiConfig,
            16 => Command::Hello,
            other => Command::Other(other),
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Packet shorter than the fixed header.
    TooShort { len: usize },
    /// Header declares more payload bytes than the packet holds.
    Truncated { declared: usize, available: usize },
    /// Payload does not fit the u16 length field.
    PayloadTooLarge { len: usize },
    /// AES keys must be exactly 16 bytes.
    InvalidKeyLength { len: usize },
    /// RSA ciphertext is not a whole number of key-sized blocks.
    CiphertextLength { len: usize, block: usize },
    /// RSA PKCS#1 v1.5 decryption failed (bad padding or wrong key).
    Decrypt,
    /// RSA key generation or encoding failed.
    Key(String),
    /// The hello reply is not the expected JSON shape.
    HelloReply(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::TooShort { len } => {
                write!(f, "packet too short: {len} bytes, need at least {HEADER_LEN}")
            }
            ProtocolError::Truncated { declared, available } => write!(
                f,
                "packet truncated: header declares {declared} payload bytes, only {available} present"
            ),
            ProtocolError::PayloadTooLarge { len } => {
                write!(f, "payload too large for a frame: {len} bytes")
            }
            ProtocolError::InvalidKeyLength { len } => {
                write!(f, "AES key must be 16 bytes, got {len}")
            }
            ProtocolError::CiphertextLength { len, block } => write!(
                f,
                "Ciphertext with incorrect length: {len} bytes is not a multiple of {block}"
            ),
            ProtocolError::Decrypt => write!(f, "RSA decryption failed"),
            ProtocolError::Key(msg) => write!(f, "RSA key error: {msg}"),
            ProtocolError::HelloReply(msg) => write!(f, "invalid hello reply: {msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// A parsed frame borrowing its payload from the received packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub command: Command,
    pub payload: &'a [u8],
}

/// Build a frame around `payload`.
pub fn build_frame(payload: &[u8], command: Command) -> Result<Vec<u8>, ProtocolError> {
    let len = u16::try_from(payload.len())
        .map_err(|_| ProtocolError::PayloadTooLarge { len: payload.len() })?;
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len() + CRC_LEN);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&SEQUENCE);
    frame.extend_from_slice(&command.id().to_be_bytes());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    let crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&crc.to_be_bytes());
    Ok(frame)
}

/// Read the command id from a packet.
pub fn parse_command(packet: &[u8]) -> Result<Command, ProtocolError> {
    match packet.get(7..9) {
        Some(&[hi, lo]) => Ok(Command::from(u16::from_be_bytes([hi, lo]))),
        _ => Err(ProtocolError::TooShort { len: packet.len() }),
    }
}

/// Parse a frame header and borrow its payload. The CRC is not verified,
/// matching the Python tool, which never checked it either.
pub fn parse_frame(packet: &[u8]) -> Result<Frame<'_>, ProtocolError> {
    let Some((header, rest)) = packet.split_at_checked(HEADER_LEN) else {
        return Err(ProtocolError::TooShort { len: packet.len() });
    };
    let command = Command::from(u16::from_be_bytes([header[7], header[8]]));
    let declared = usize::from(u16::from_be_bytes([header[9], header[10]]));
    let payload = rest.get(..declared).ok_or(ProtocolError::Truncated {
        declared,
        available: rest.len(),
    })?;
    Ok(Frame { command, payload })
}

/// A 16-byte AES-128 key (the pre-shared key or the negotiated session key).
#[derive(Clone, PartialEq, Eq)]
pub struct AesKey([u8; 16]);

impl AesKey {
    pub fn new(key: &str) -> Result<Self, ProtocolError> {
        let bytes: [u8; 16] = key
            .as_bytes()
            .try_into()
            .map_err(|_| ProtocolError::InvalidKeyLength { len: key.len() })?;
        Ok(AesKey(bytes))
    }
}

impl fmt::Debug for AesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AesKey(<redacted>)")
    }
}

/// `json.dumps(body, separators=(",", ":"))`, PKCS#7 padded, AES-128-ECB.
pub fn aes_encrypt_json<T: Serialize + ?Sized>(body: &T, key: &AesKey) -> Vec<u8> {
    let mut data = pyjson::dumps(body).into_bytes();
    let pad = 16 - data.len() % 16;
    data.resize(data.len() + pad, pad as u8);
    let cipher = Aes128::new(&key.0.into());
    for block in data.chunks_exact_mut(16) {
        cipher.encrypt_block(block.into());
    }
    data
}

#[derive(Debug, Serialize)]
struct HelloRequest<'a> {
    id: u32,
    method: &'static str,
    params: HelloParams<'a>,
}

#[derive(Debug, Serialize)]
struct HelloParams<'a> {
    app_ver: u32,
    key: &'a str,
}

/// Wi-Fi configuration body, serialized in the exact key order the vacuum
/// firmware and the Python tool use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WifiConfigBody {
    pub u: String,
    pub ssid: String,
    pub token: WifiToken,
    pub passwd: String,
    pub country_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WifiToken {
    pub r: String,
    pub tz: String,
    pub s: String,
    pub cst: String,
    pub t: String,
}

impl WifiConfigBody {
    /// Copy with the Wi-Fi password and `token.t` replaced by `<redacted>`.
    pub fn redacted(&self) -> Self {
        let mut copy = self.clone();
        copy.passwd = "<redacted>".into();
        copy.token.t = "<redacted>".into();
        copy
    }
}

pub fn build_hello_packet(pre_key: &AesKey, public_key_pem: &str) -> Vec<u8> {
    let body = HelloRequest {
        id: 1,
        method: "hello",
        params: HelloParams {
            app_ver: 1,
            key: public_key_pem,
        },
    };
    encrypted_frame(&body, pre_key, Command::Hello)
}

pub fn build_wifi_packet(session_key: &AesKey, body: &WifiConfigBody) -> Vec<u8> {
    encrypted_frame(body, session_key, Command::WifiConfig)
}

fn encrypted_frame<T: Serialize>(body: &T, key: &AesKey, command: Command) -> Vec<u8> {
    // A hello with a 1024-bit PEM or a Wi-Fi body is a few hundred bytes;
    // exceeding the u16 length field would need a ~64 KiB SSID.
    build_frame(&aes_encrypt_json(body, key), command).expect("cfgwifi payload fits in a frame")
}

/// Outcome of reading the session key out of a decrypted hello reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloReply {
    SessionKey(AesKey),
    /// `params.key` exists but is not a 16-character string.
    InvalidKey,
}

/// Extract `params.key` from the decrypted hello reply JSON.
pub fn parse_hello_reply(json: &str) -> Result<HelloReply, ProtocolError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|err| ProtocolError::HelloReply(err.to_string()))?;
    let key = value
        .get("params")
        .and_then(serde_json::Value::as_object)
        .and_then(|params| params.get("key"))
        .ok_or_else(|| ProtocolError::HelloReply("missing params.key".into()))?;
    Ok(match key.as_str() {
        Some(key) if key.chars().count() == 16 => {
            AesKey::new(key).map_or(HelloReply::InvalidKey, HelloReply::SessionKey)
        }
        _ => HelloReply::InvalidKey,
    })
}

/// Ephemeral RSA-1024 key pair for one onboarding attempt.
pub struct RsaKeyPair {
    private: RsaPrivateKey,
}

impl RsaKeyPair {
    pub fn generate() -> Result<Self, ProtocolError> {
        let private = RsaPrivateKey::new(&mut OsRng, RSA_BITS)
            .map_err(|err| ProtocolError::Key(err.to_string()))?;
        Ok(Self { private })
    }

    /// Load a PKCS#1 PEM private key (`-----BEGIN RSA PRIVATE KEY-----`).
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, ProtocolError> {
        let private = RsaPrivateKey::from_pkcs1_pem(pem)
            .map_err(|err| ProtocolError::Key(err.to_string()))?;
        Ok(Self { private })
    }

    /// SubjectPublicKeyInfo PEM, formatted like pycryptodome's
    /// `publickey().export_key()`: 64-column LF lines, no trailing newline.
    pub fn public_pem(&self) -> Result<String, ProtocolError> {
        let pem = self
            .private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|err| ProtocolError::Key(err.to_string()))?;
        Ok(pem.trim_end_matches('\n').to_owned())
    }

    /// Decrypt PKCS#1 v1.5 ciphertext made of back-to-back key-sized blocks.
    pub fn decrypt_blocks(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let block = self.private.size();
        if ciphertext.len() % block != 0 {
            return Err(ProtocolError::CiphertextLength {
                len: ciphertext.len(),
                block,
            });
        }
        let mut out = Vec::with_capacity(ciphertext.len());
        for chunk in ciphertext.chunks_exact(block) {
            let plain = self
                .private
                .decrypt(Pkcs1v15Encrypt, chunk)
                .map_err(|_| ProtocolError::Decrypt)?;
            out.extend_from_slice(&plain);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_ids_round_trip() {
        assert_eq!(Command::from(1), Command::WifiConfig);
        assert_eq!(Command::from(16), Command::Hello);
        assert_eq!(Command::from(7), Command::Other(7));
        assert_eq!(Command::Hello.id(), 16);
        assert_eq!(Command::WifiConfig.id(), 1);
    }

    #[test]
    fn frame_layout_is_magic_seq_cmd_len_payload_crc() {
        let frame = build_frame(b"hi", Command::Hello).unwrap();
        assert_eq!(&frame[..11], b"1.0\x00\x00\x00\x01\x00\x10\x00\x02");
        assert_eq!(&frame[11..13], b"hi");
        let crc = crc32fast::hash(&frame[..13]).to_be_bytes();
        assert_eq!(&frame[13..], &crc);
    }

    #[test]
    fn build_frame_rejects_oversized_payload() {
        let big = vec![0u8; 0x1_0000];
        assert_eq!(
            build_frame(&big, Command::WifiConfig),
            Err(ProtocolError::PayloadTooLarge { len: 0x1_0000 })
        );
    }

    #[test]
    fn parse_frame_round_trips() {
        let packet = build_frame(b"payload", Command::Other(0x0203)).unwrap();
        let frame = parse_frame(&packet).unwrap();
        assert_eq!(frame.command, Command::Other(0x0203));
        assert_eq!(frame.payload, b"payload");
    }

    #[test]
    fn parse_rejects_every_short_prefix_without_panicking() {
        let packet = build_frame(b"abc", Command::Hello).unwrap();
        for len in 0..HEADER_LEN {
            assert_eq!(
                parse_frame(&packet[..len]),
                Err(ProtocolError::TooShort { len })
            );
        }
        assert_eq!(
            parse_command(&packet[..8]),
            Err(ProtocolError::TooShort { len: 8 })
        );
        assert_eq!(parse_command(&packet[..9]), Ok(Command::Hello));
    }

    #[test]
    fn parse_rejects_truncated_payload() {
        let mut packet = b"1.0\x00\x00\x00\x01\x00\x10\x00\x09abc".to_vec();
        assert_eq!(
            parse_frame(&packet),
            Err(ProtocolError::Truncated {
                declared: 9,
                available: 3
            })
        );
        packet.extend_from_slice(&[0; 6]);
        assert_eq!(parse_frame(&packet).unwrap().payload.len(), 9);
    }

    #[test]
    fn parse_accepts_frame_without_crc() {
        let packet = b"1.0\x00\x00\x00\x01\x00\x01\x00\x02ok";
        let frame = parse_frame(packet).unwrap();
        assert_eq!(frame.command, Command::WifiConfig);
        assert_eq!(frame.payload, b"ok");
    }

    #[test]
    fn parse_survives_arbitrary_garbage() {
        let mut seed = 0x1234_5678u32;
        for len in 0..64 {
            let packet: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (seed >> 16) as u8
                })
                .collect();
            let _ = parse_frame(&packet);
            let _ = parse_command(&packet);
        }
    }

    #[test]
    fn aes_key_must_be_16_bytes() {
        assert!(AesKey::new("0123456789abcdef").is_ok());
        assert_eq!(
            AesKey::new("short").unwrap_err(),
            ProtocolError::InvalidKeyLength { len: 5 }
        );
    }

    #[test]
    fn aes_output_is_pkcs7_padded_blocks() {
        let key = AesKey::new(PRE_KEY).unwrap();
        // `{}` is 2 bytes -> one block; 16 bytes of JSON -> two blocks.
        assert_eq!(aes_encrypt_json(&serde_json::json!({}), &key).len(), 16);
        let sixteen = serde_json::json!({"k": "0123456789"}); // {"k":"0123456789"} = 18
        assert_eq!(aes_encrypt_json(&sixteen, &key).len(), 32);
        let exact = serde_json::json!({"k": "01234567"}); // 16 bytes -> full pad block
        assert_eq!(aes_encrypt_json(&exact, &key).len(), 32);
    }

    #[test]
    fn hello_reply_extracts_session_key() {
        let reply = parse_hello_reply(r#"{"id":1,"params":{"key":"abcdefghijklmnop"}}"#).unwrap();
        assert_eq!(
            reply,
            HelloReply::SessionKey(AesKey::new("abcdefghijklmnop").unwrap())
        );
    }

    #[test]
    fn hello_reply_with_wrong_key_shape_is_invalid_not_error() {
        for body in [
            r#"{"params":{"key":"short"}}"#,
            r#"{"params":{"key":12345}}"#,
            r#"{"params":{"key":null}}"#,
        ] {
            assert_eq!(
                parse_hello_reply(body).unwrap(),
                HelloReply::InvalidKey,
                "{body}"
            );
        }
    }

    #[test]
    fn hello_reply_malformed_is_error() {
        for body in [
            "",
            "not json",
            "[]",
            r#"{"id":1}"#,
            r#"{"params":[]}"#,
            r#"{"params":{}}"#,
        ] {
            assert!(
                matches!(parse_hello_reply(body), Err(ProtocolError::HelloReply(_))),
                "{body}"
            );
        }
    }

    #[test]
    fn redacted_body_hides_password_and_token_t() {
        let body = WifiConfigBody {
            u: CFGWIFI_UID.into(),
            ssid: "Home".into(),
            token: WifiToken {
                r: "r/".into(),
                tz: "tz".into(),
                s: "S".into(),
                cst: "cst".into(),
                t: "T".into(),
            },
            passwd: "secret".into(),
            country_domain: "us".into(),
        };
        let redacted = body.redacted();
        assert_eq!(redacted.passwd, "<redacted>");
        assert_eq!(redacted.token.t, "<redacted>");
        assert_eq!(redacted.token.s, "S");
        assert_eq!(redacted.ssid, "Home");
    }

    #[test]
    fn generated_key_round_trips_through_decrypt_blocks() {
        use rsa::RsaPublicKey;
        let pair = RsaKeyPair::generate().unwrap();
        let public = RsaPublicKey::from(&pair.private);
        let plain = vec![b'x'; 200];
        let mut ciphertext = Vec::new();
        for chunk in plain.chunks(117) {
            ciphertext.extend(public.encrypt(&mut OsRng, Pkcs1v15Encrypt, chunk).unwrap());
        }
        assert_eq!(ciphertext.len(), 256);
        assert_eq!(pair.decrypt_blocks(&ciphertext).unwrap(), plain);
    }

    #[test]
    fn decrypt_rejects_partial_block_and_garbage() {
        let pair = RsaKeyPair::generate().unwrap();
        assert_eq!(
            pair.decrypt_blocks(&[0u8; 100]),
            Err(ProtocolError::CiphertextLength {
                len: 100,
                block: 128
            })
        );
        assert_eq!(
            pair.decrypt_blocks(&[0u8; 128]),
            Err(ProtocolError::Decrypt)
        );
    }

    #[test]
    fn public_pem_matches_pycryptodome_layout() {
        let pem = RsaKeyPair::generate().unwrap().public_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("\n-----END PUBLIC KEY-----"));
        assert!(!pem.contains('\r'));
        let body: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(body[..body.len() - 1].iter().all(|l| l.len() == 64));
    }
}
