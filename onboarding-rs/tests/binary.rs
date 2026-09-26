//! The compiled `roborock-onboard` binary: argument handling, exit codes,
//! prompts on piped stdin, Ctrl-C, and the `gui` subcommand lifecycle.
//!
//! Secrets are always passed as flags here: hidden-input prompts read the
//! controlling terminal, which a test must never block on.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_roborock-onboard");

fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn help_lists_cli_flags_but_not_hidden_test_hooks() {
    let (code, stdout, _) = run(&["--help"], "");
    assert_eq!(code, 0);
    for flag in [
        "--server",
        "--admin-password",
        "--ssid",
        "--password",
        "--timezone",
        "--cst",
        "--country-domain",
        "--allow-insecure-tls",
        "gui",
    ] {
        assert!(stdout.contains(flag), "missing {flag} in:\n{stdout}");
    }
    assert!(!stdout.contains("cfgwifi"), "{stdout}");
}

#[test]
fn gui_help_works() {
    let (code, stdout, _) = run(&["gui", "--help"], "");
    assert_eq!(code, 0);
    assert!(stdout.contains("127.0.0.1"), "{stdout}");
    assert!(stdout.contains("--no-browser"), "{stdout}");
}

#[test]
fn server_is_required_for_the_cli_flow() {
    let (code, _, stderr) = run(&[], "");
    assert_eq!(code, 2);
    assert!(stderr.contains("--server"), "{stderr}");
}

#[test]
fn invalid_server_exits_1_with_error() {
    let (code, _, stderr) = run(&["--server", "abcdefghijklmnop.example.com:555"], "");
    assert_eq!(code, 1);
    assert!(
        stderr.starts_with("Error: Server host is too long for onboarding: token.r must be at most 32 characters, got 33"),
        "{stderr}"
    );
}

#[test]
fn prompts_on_stdin_then_reports_unreachable_server() {
    let (code, stdout, stderr) = run(
        &[
            "--server",
            "roborock.invalid",
            "--admin-password",
            "pw",
            "--password",
            "wifi",
            "--country-domain",
            "us",
        ],
        "My Wifi\n\n",
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Home Wi-Fi SSID: "), "{stdout}");
    assert!(stdout.contains("Timezone [America/New_York]: "), "{stdout}");
    assert!(
        stdout.contains(
            "Checking admin API reachability at https://api-roborock.invalid:555/admin/api/status..."
        ),
        "{stdout}"
    );
    assert!(
        stderr.starts_with("Error: Unable to reach https://api-roborock.invalid:555: "),
        "{stderr}"
    );
}

#[test]
fn insecure_flag_announces_disabled_verification() {
    let (code, stdout, _) = run(
        &[
            "--server",
            "roborock.invalid",
            "--admin-password",
            "pw",
            "--ssid",
            "s",
            "--password",
            "p",
            "--timezone",
            "Europe/Paris",
            "--allow-insecure-tls",
        ],
        "",
    );
    assert_eq!(code, 1);
    assert!(stdout.starts_with(
        "TLS certificate verification is DISABLED. Preflight will only test reachability.\n"
    ));
}

#[test]
fn closed_stdin_at_a_prompt_is_an_error() {
    let (code, _, stderr) = run(
        &["--server", "roborock.invalid", "--admin-password", "pw"],
        "",
    );
    assert_eq!(code, 1);
    assert!(stderr.starts_with("Error: "), "{stderr}");
}

#[cfg(unix)]
#[test]
fn ctrl_c_at_a_prompt_exits_130() {
    let mut child = Command::new(BIN)
        .args(["--server", "roborock.invalid", "--admin-password", "pw"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    // Wait until the SSID prompt is up (no trailing newline, so read bytes).
    let mut seen = Vec::new();
    while !String::from_utf8_lossy(&seen).contains("Home Wi-Fi SSID: ") {
        let buf = stdout.fill_buf().unwrap();
        assert!(!buf.is_empty(), "process exited early");
        let n = buf.len();
        seen.extend_from_slice(buf);
        stdout.consume(n);
    }
    // Keep stdin open: `Child::wait` would close it, and the resulting EOF
    // would race the Ctrl-C handler (a real terminal never sends EOF here).
    let stdin = child.stdin.take();
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }
    let status = child.wait().unwrap();
    drop(stdin);
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut rest).unwrap();
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert_eq!(
        status.code(),
        Some(130),
        "stdout: {rest:?}\nstderr: {stderr:?}"
    );
    assert!(rest.contains("Interrupted."), "{rest}");
}

#[test]
fn gui_serves_until_quit() {
    let mut child = Command::new(BIN)
        .args(["gui", "--no-browser"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let url = line
        .trim()
        .strip_prefix("Vacuum Onboarding UI: ")
        .unwrap_or_else(|| panic!("unexpected first line {line:?}"))
        .to_owned();
    let (base, token) = url.split_once("/?token=").unwrap();
    assert!(base.starts_with("http://127.0.0.1:"));

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .into();
    let state: serde_json::Value = serde_json::from_str(
        &agent
            .get(format!("{base}/api/state"))
            .header("X-Token", token)
            .call()
            .unwrap()
            .body_mut()
            .read_to_string()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(state["phase"], "needs_config");

    agent
        .post(format!("{base}/api/quit"))
        .header("X-Token", token)
        .send_empty()
        .unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
}
