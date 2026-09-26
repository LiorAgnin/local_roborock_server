"""Regenerate python_parity.json from the Python onboarding implementation.

Run from the repository root:

    uv run --no-project --with 'pycryptodome>=3.20,<4' \
        python onboarding-rs/tests/fixtures/gen_fixtures.py

The Rust tests in tests/python_parity.rs pin the Rust port against this file.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from Crypto.Cipher import PKCS1_v1_5  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402

import start_onboarding as so  # noqa: E402

SESSION_KEY = "0123456789abcdef"

WIFI_BODY = {
    "u": so.CFGWIFI_UID,
    "ssid": 'Café ☕ Straße 😀 "q" / \\ \t\x7f\x01',
    "token": {
        "r": "roborock.example.com:555/",
        "tz": "Europe/Berlin",
        "s": "S_TOKEN_00112233445566778899aabbccddeeff",
        "cst": "CET-1CEST,M3.5.0,M10.5.0/3",
        "t": "T_TOKEN_ffeeddccbbaa99887766554433221100",
    },
    "passwd": "pässwörd\n€",
    "country_domain": "de",
}

SERVER_INPUTS = [
    "api-roborock.example.com",
    "api-roborock.example.com:8443",
    "https://roborock.example.com:8443/",
    "https://api-roborock.example.com",
    "roborock.example.com:443",
    "API-Roborock.Example.COM",
    "  api-roborock.example.com  ",
    "user@api-roborock.example.com:555",
    "abcdefghijklmno.example.com:555",
    "abcdefghijklmnop.example.com:555",
    "api-roborock.example.com:not-a-port",
    "api-roborock.example.com:70000",
    "api-roborock.example.com:",
    "",
    "https://",
]


def _normalize(server: str) -> dict:
    out: dict = {"input": server}
    try:
        out["api_base_url"] = so.normalize_api_base_url(server)
    except ValueError as exc:
        out["api_base_url_error"] = str(exc)
    try:
        out["stack_server"] = so.sanitize_stack_server(server)
    except ValueError as exc:
        out["stack_server_error"] = str(exc)
    return out


def main() -> None:
    key = RSA.generate(1024)
    private_pem = key.export_key().decode()
    public_pem = key.publickey().export_key().decode()

    hello_body = {"id": 1, "method": "hello", "params": {"app_ver": 1, "key": public_pem}}

    # The vacuum answers hello with RSA PKCS#1 v1.5 blocks of at most k-11 bytes.
    session_plain = json.dumps(
        {"id": 1, "method": "hello", "params": {"key": SESSION_KEY, "pad": "x" * 150}},
        separators=(",", ":"),
    ).encode()
    cipher = PKCS1_v1_5.new(key.publickey())
    chunk = key.size_in_bytes() - 11
    session_cipher = b"".join(
        cipher.encrypt(session_plain[i : i + chunk]) for i in range(0, len(session_plain), chunk)
    )

    fixture = {
        "session_key": SESSION_KEY,
        "pre_key": so.CFGWIFI_PRE_KEY,
        "wifi_body_json": json.dumps(WIFI_BODY, separators=(",", ":")),
        "wifi_packet_hex": so.build_wifi_packet(SESSION_KEY, WIFI_BODY).hex(),
        "rsa_private_pem": private_pem,
        "rsa_public_pem": public_pem,
        "hello_body_json": json.dumps(hello_body, separators=(",", ":")),
        "hello_packet_hex": so.build_hello_packet(so.CFGWIFI_PRE_KEY, public_pem.encode()).hex(),
        "session_plaintext": session_plain.decode(),
        "session_ciphertext_hex": session_cipher.hex(),
        "frame_hello_cmd16_hex": so.build_frame(b"hello", 16).hex(),
        "frame_empty_cmd1_hex": so.build_frame(b"", 1).hex(),
        "server_normalization": [_normalize(s) for s in SERVER_INPUTS],
    }
    out = Path(__file__).with_name("python_parity.json")
    out.write_text(json.dumps(fixture, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
