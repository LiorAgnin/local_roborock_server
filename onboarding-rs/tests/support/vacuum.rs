//! A mock vacuum hotspot: answers the cfgwifi hello with an RSA-encrypted
//! session key and decrypts the AES Wi-Fi packet it receives.

use std::net::{SocketAddr, UdpSocket};
use std::thread::JoinHandle;
use std::time::Duration;

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use roborock_onboard::protocol::{self, Command, PRE_KEY};
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use serde_json::Value;

pub const SESSION_KEY: &str = "sEsSiOnKeY012345";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    /// Full handshake, acks the Wi-Fi packet.
    Normal,
    /// Never answers.
    Silent,
    /// Answers hello with a session key that is not 16 characters.
    BadSessionKey,
    /// Answers hello with a 5-byte datagram.
    ShortHelloReply,
    /// Full handshake but never acks the Wi-Fi packet.
    NoWifiAck,
    /// Acks the Wi-Fi packet with a 3-byte datagram.
    ShortWifiAck,
}

/// What the vacuum saw, returned when its thread finishes.
#[derive(Debug, Default)]
pub struct Observed {
    pub hello: Option<Value>,
    pub hello_crc_ok: bool,
    pub wifi: Option<Value>,
    pub wifi_crc_ok: bool,
}

pub struct MockVacuum {
    pub addr: SocketAddr,
    thread: Option<JoinHandle<Observed>>,
}

impl MockVacuum {
    pub fn start(behavior: Behavior) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let addr = sock.local_addr().unwrap();
        let thread = std::thread::spawn(move || serve(&sock, behavior));
        MockVacuum {
            addr,
            thread: Some(thread),
        }
    }

    /// Wait for the exchange to finish and return what the vacuum saw.
    pub fn observed(mut self) -> Observed {
        self.thread.take().unwrap().join().unwrap()
    }
}

fn serve(sock: &UdpSocket, behavior: Behavior) -> Observed {
    let mut observed = Observed::default();
    let mut buf = [0u8; 4096];
    let Ok((len, peer)) = sock.recv_from(&mut buf) else {
        return observed;
    };
    let hello_packet = &buf[..len];
    observed.hello_crc_ok = crc_ok(hello_packet);
    let frame = protocol::parse_frame(hello_packet).unwrap();
    assert_eq!(frame.command, Command::Hello);
    let hello: Value = serde_json::from_slice(&aes_decrypt(frame.payload, PRE_KEY)).unwrap();
    let pem = hello["params"]["key"].as_str().unwrap().to_owned();
    observed.hello = Some(hello);

    let session_key = match behavior {
        Behavior::Silent => return observed,
        Behavior::ShortHelloReply => {
            sock.send_to(b"1.0\x00\x00", peer).unwrap();
            return observed;
        }
        Behavior::BadSessionKey => "too-short",
        _ => SESSION_KEY,
    };
    let reply = format!(
        r#"{{"id":1,"method":"hello","params":{{"key":"{session_key}","pad":"{}"}}}}"#,
        "p".repeat(120)
    );
    let public = RsaPublicKey::from_public_key_pem(&pem).unwrap();
    let mut ciphertext = Vec::new();
    for chunk in reply.as_bytes().chunks(117) {
        ciphertext.extend(public.encrypt(&mut OsRng, Pkcs1v15Encrypt, chunk).unwrap());
    }
    let frame = protocol::build_frame(&ciphertext, Command::Hello).unwrap();
    sock.send_to(&frame, peer).unwrap();
    if behavior == Behavior::BadSessionKey {
        return observed;
    }

    let Ok((len, peer)) = sock.recv_from(&mut buf) else {
        return observed;
    };
    let wifi_packet = &buf[..len];
    observed.wifi_crc_ok = crc_ok(wifi_packet);
    let frame = protocol::parse_frame(wifi_packet).unwrap();
    assert_eq!(frame.command, Command::WifiConfig);
    observed.wifi = Some(serde_json::from_slice(&aes_decrypt(frame.payload, SESSION_KEY)).unwrap());
    match behavior {
        Behavior::NoWifiAck => {}
        Behavior::ShortWifiAck => {
            sock.send_to(b"1.0", peer).unwrap();
        }
        _ => {
            let ack = protocol::build_frame(b"ok", Command::WifiConfig).unwrap();
            sock.send_to(&ack, peer).unwrap();
        }
    }
    observed
}

fn crc_ok(packet: &[u8]) -> bool {
    let (body, crc) = packet.split_at(packet.len() - 4);
    crc32fast::hash(body).to_be_bytes() == crc
}

fn aes_decrypt(data: &[u8], key: &str) -> Vec<u8> {
    let key: [u8; 16] = key.as_bytes().try_into().unwrap();
    let cipher = Aes128::new(&key.into());
    let mut data = data.to_vec();
    for block in data.as_chunks_mut::<16>().0 {
        cipher.decrypt_block(block.as_mut_slice().into());
    }
    let pad = usize::from(*data.last().unwrap());
    assert!((1..=16).contains(&pad), "bad PKCS7 padding");
    data.truncate(data.len() - pad);
    data
}
