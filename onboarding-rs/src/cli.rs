//! The interactive guided onboarding CLI (Python `start_onboarding.py`).

use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::api::{ApiError, OnboardingApi};
use crate::cfgwifi::OnboardError;
use crate::pyvalue::{self, Json};
use crate::server::{self, OnboardingConfig};

pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
pub const POLL_TIMEOUT: Duration = Duration::from_secs(300);

/// Reads answers from the user. Prompts are shown by the implementation
/// (stdout for text, the terminal for secrets), not written to `output`.
pub trait Prompter {
    fn input(&mut self, prompt: &str) -> Result<String, InputError>;
    fn secret(&mut self, prompt: &str) -> Result<String, InputError>;
}

#[derive(Debug)]
pub enum InputError {
    /// stdin closed.
    Eof,
    Io(io::Error),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::Eof => f.write_str("end of input"),
            InputError::Io(err) => err.fmt(f),
        }
    }
}

/// Monotonic time source, injectable so polling tests run instantly.
pub trait Clock {
    fn now(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}

pub struct SystemClock(Instant);

impl SystemClock {
    pub fn new() -> Self {
        SystemClock(Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollSettings {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for PollSettings {
    fn default() -> Self {
        PollSettings {
            interval: POLL_INTERVAL,
            timeout: POLL_TIMEOUT,
        }
    }
}

/// Why polling stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    Connected,
    PublicKeyReady,
    SampleIncreased,
    Unsupported,
    Conflict,
    Timeout,
}

/// The progress rules shared by the CLI and the GUI: the first matching
/// condition wins, `None` means keep polling.
pub fn classify_progress(
    latest: &Json,
    baseline_samples: i64,
    baseline_has_public_key: bool,
) -> Option<PollOutcome> {
    let conflict = pyvalue::first_str(&[latest.get("identity_conflict")], "");
    if !conflict.trim().is_empty() {
        Some(PollOutcome::Conflict)
    } else if pyvalue::truthy(latest.get("unsupported")) {
        Some(PollOutcome::Unsupported)
    } else if pyvalue::truthy(latest.get("connected")) {
        Some(PollOutcome::Connected)
    } else if baseline_has_public_key {
        None
    } else if pyvalue::truthy(latest.get("has_public_key")) {
        Some(PollOutcome::PublicKeyReady)
    } else if pyvalue::int_or_zero(latest.get("query_samples")) > baseline_samples {
        Some(PollOutcome::SampleIncreased)
    } else {
        None
    }
}

fn py_bool(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}

/// Anything that ends the CLI with exit code 1.
#[derive(Debug)]
pub enum CliError {
    Api(ApiError),
    Onboard(OnboardError),
    Input(InputError),
    Message(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Api(err) => err.fmt(f),
            CliError::Onboard(err) => err.fmt(f),
            CliError::Input(err) => err.fmt(f),
            CliError::Message(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ApiError> for CliError {
    fn from(err: ApiError) -> Self {
        CliError::Api(err)
    }
}

impl From<OnboardError> for CliError {
    fn from(err: OnboardError) -> Self {
        CliError::Onboard(err)
    }
}

impl From<InputError> for CliError {
    fn from(err: InputError) -> Self {
        CliError::Input(err)
    }
}

/// Values given on the command line; empty means "prompt for it".
#[derive(Debug, Clone, Default)]
pub struct ConfigArgs {
    pub server: String,
    pub admin_password: String,
    pub ssid: String,
    pub password: String,
    pub timezone: String,
    pub cst: String,
    pub country_domain: String,
    pub allow_insecure_tls: bool,
}

/// Normalize the server and prompt for everything not given.
pub fn prompt_for_config(
    args: &ConfigArgs,
    prompter: &mut dyn Prompter,
    output: &mut dyn Write,
) -> Result<OnboardingConfig, CliError> {
    let invalid = |err: server::InvalidServer| CliError::Message(err.to_string());
    let api_base_url = server::normalize_api_base_url(&args.server).map_err(invalid)?;
    let stack_server = server::sanitize_stack_server(&args.server).map_err(invalid)?;
    let mut ask = |value: &str, prompt: &str, default: &str, secret: bool| {
        prompt_text(value, prompt, default, secret, prompter, output)
    };
    let admin_password = ask(&args.admin_password, "Admin password", "", true)?;
    let ssid = ask(&args.ssid, "Home Wi-Fi SSID", "", false)?;
    let password = ask(&args.password, "Home Wi-Fi password", "", true)?;
    let timezone = ask(&args.timezone, "Timezone", server::DEFAULT_TIMEZONE, false)?;
    let mut cst = args.cst.trim().to_owned();
    if cst.is_empty() {
        cst = server::posix_tz_from_iana(&timezone).to_owned();
    }
    if cst.is_empty() {
        cst = ask(
            "",
            "POSIX TZ string (could not auto-detect from timezone)",
            server::DEFAULT_CST,
            false,
        )?;
    }
    let mut country_domain = args.country_domain.trim().to_owned();
    if country_domain.is_empty() {
        country_domain = server::country_from_iana(&timezone).to_owned();
    }
    if country_domain.is_empty() {
        country_domain = ask(
            "",
            "Country domain (could not auto-detect from timezone)",
            server::DEFAULT_COUNTRY_DOMAIN,
            false,
        )?;
    }
    Ok(OnboardingConfig {
        api_base_url,
        stack_server,
        admin_password,
        ssid,
        password,
        timezone,
        cst,
        country_domain,
        allow_insecure_tls: args.allow_insecure_tls,
    })
}

/// Use `value` if given, otherwise prompt until non-empty (or `default`).
fn prompt_text(
    value: &str,
    prompt: &str,
    default: &str,
    secret: bool,
    prompter: &mut dyn Prompter,
    output: &mut dyn Write,
) -> Result<String, CliError> {
    if !value.trim().is_empty() {
        return Ok(value.trim().to_owned());
    }
    let display = if default.is_empty() {
        format!("{prompt}: ")
    } else {
        format!("{prompt} [{default}]: ")
    };
    loop {
        let entered = if secret {
            prompter.secret(&display)?
        } else {
            prompter.input(&display)?
        };
        let candidate = match entered.trim() {
            "" => default,
            trimmed => trimmed,
        };
        if !candidate.is_empty() {
            return Ok(candidate.to_owned());
        }
        let _ = writeln!(output, "A value is required.");
    }
}

/// `Name [Unsupported ] [Public Key Determined ] [Connected ] [N Query Samples]`
/// (the inner `" ] ["` separator is what the Python tool prints).
pub fn format_device_label(device: &Value, disambiguator: &str) -> String {
    let onboarding = pyvalue::object(device.get("onboarding"));
    let key_state = pyvalue::object(onboarding.get("key_state"));
    let mut name = pyvalue::first_str(&[device.get("name"), device.get("duid")], "Unknown vacuum");
    if !disambiguator.is_empty() {
        name = format!("{name} [{disambiguator}]");
    }
    let samples = pyvalue::int_or_zero(key_state.get("query_samples"));
    let mut labels = vec![
        if pyvalue::truthy(onboarding.get("has_public_key")) {
            "Public Key Determined".to_owned()
        } else {
            "No Public Key".to_owned()
        },
        if pyvalue::truthy(device.get("connected")) {
            "Connected".to_owned()
        } else {
            "Disconnected".to_owned()
        },
        format!("{samples} Query Samples"),
    ];
    if pyvalue::truthy(onboarding.get("unsupported")) {
        labels.insert(0, "Unsupported".to_owned());
    }
    format!("{name} [{}]", labels.join(" ] ["))
}

pub fn print_status_summary(status: &Json, output: &mut dyn Write) {
    let target = pyvalue::object(status.get("target"));
    let name = pyvalue::first_str(
        &[target.get("name"), target.get("duid"), target.get("did")],
        "Unknown vacuum",
    );
    let _ = writeln!(
        output,
        "Status for {name}: samples={}, public_key={}, connected={}, state={}",
        pyvalue::int_or_zero(status.get("query_samples")),
        py_bool(pyvalue::truthy(status.get("has_public_key"))),
        py_bool(pyvalue::truthy(status.get("connected"))),
        pyvalue::first_str(&[status.get("public_key_state")], "missing"),
    );
    let guidance = pyvalue::first_str(&[status.get("guidance")], "");
    let guidance = guidance.trim();
    if !guidance.is_empty() {
        let _ = writeln!(output, "{guidance}");
    }
}

fn device_key(device: &Value) -> String {
    pyvalue::first_str(&[device.get("name"), device.get("duid")], "")
        .trim()
        .to_lowercase()
}

/// List the vacuums and let the user pick one (`None` = quit or no devices).
pub fn choose_device(
    devices: &[Value],
    output: &mut dyn Write,
    prompter: &mut dyn Prompter,
) -> Result<Option<Value>, CliError> {
    if devices.is_empty() {
        let _ = writeln!(
            output,
            "No known vacuums are available for onboarding. \
             Finish the cloud import/fetch-data step first, then retry."
        );
        return Ok(None);
    }
    let keys: Vec<String> = devices.iter().map(device_key).collect();
    loop {
        let _ = writeln!(output, "Available vacuums:");
        for (index, (device, key)) in devices.iter().zip(&keys).enumerate() {
            let duplicate = keys.iter().filter(|other| *other == key).count() > 1;
            let disambiguator = if duplicate {
                pyvalue::first_str(&[device.get("duid")], "")
            } else {
                String::new()
            };
            let _ = writeln!(
                output,
                "  {}. {}",
                index + 1,
                format_device_label(device, &disambiguator)
            );
        }
        let raw = prompter
            .input("Select a vacuum by number, or type 'quit': ")?
            .trim()
            .to_lowercase();
        if raw == "quit" {
            return Ok(None);
        }
        if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(index) = raw.parse::<usize>() {
                if (1..=devices.len()).contains(&index) {
                    return Ok(Some(devices[index - 1].clone()));
                }
            }
        }
        let _ = writeln!(output, "Please enter a valid number.");
    }
}

/// Poll the session until the server reports progress or the timeout hits.
/// Unreachable-server errors are retried (the user is switching Wi-Fi);
/// other API errors abort.
#[allow(clippy::too_many_arguments)]
pub fn poll_session_until_progress(
    api: &dyn OnboardingApi,
    session_id: &str,
    baseline_samples: i64,
    baseline_status: Option<&Json>,
    output: &mut dyn Write,
    settings: PollSettings,
    clock: &dyn Clock,
) -> Result<(PollOutcome, Json), CliError> {
    let deadline = clock.now() + settings.timeout;
    let mut latest = baseline_status.cloned().unwrap_or_else(|| {
        let mut status = Json::new();
        status.insert("session_id".into(), session_id.into());
        status.insert("query_samples".into(), baseline_samples.into());
        status
    });
    let baseline_has_public_key =
        baseline_status.is_some_and(|status| pyvalue::truthy(status.get("has_public_key")));
    let mut waiting_for_reconnect = false;
    loop {
        match api.get_session(session_id) {
            Ok(status) => {
                latest = status;
                waiting_for_reconnect = false;
            }
            Err(ApiError::Unreachable(msg)) => {
                if clock.now() >= deadline {
                    return Ok((PollOutcome::Timeout, latest));
                }
                if waiting_for_reconnect {
                    let _ = writeln!(
                        output,
                        "Still waiting for this machine to reach the main server again..."
                    );
                } else {
                    let _ = writeln!(
                        output,
                        "The main server is not reachable yet from this machine. \
                         Finish reconnecting to your normal Wi-Fi and the script will keep retrying."
                    );
                    let _ = writeln!(output, "{msg}");
                    waiting_for_reconnect = true;
                }
                clock.sleep(settings.interval);
                continue;
            }
            Err(err) => return Err(err.into()),
        }
        if let Some(outcome) = classify_progress(&latest, baseline_samples, baseline_has_public_key)
        {
            return Ok((outcome, latest));
        }
        if clock.now() >= deadline {
            return Ok((PollOutcome::Timeout, latest));
        }
        let _ = writeln!(
            output,
            "Waiting for the server to observe new onboarding traffic..."
        );
        clock.sleep(settings.interval);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostAttemptAction {
    Retry,
    Refresh,
    Reselect,
    Quit,
}

pub fn prompt_post_attempt_action(
    status: &Json,
    output: &mut dyn Write,
    prompter: &mut dyn Prompter,
) -> Result<PostAttemptAction, CliError> {
    loop {
        print_status_summary(status, output);
        let raw = prompter
            .input("Choose: [retry] [refresh] [reselect] [quit]: ")?
            .trim()
            .to_lowercase();
        match raw.as_str() {
            "retry" => return Ok(PostAttemptAction::Retry),
            "refresh" => return Ok(PostAttemptAction::Refresh),
            "reselect" => return Ok(PostAttemptAction::Reselect),
            "quit" => return Ok(PostAttemptAction::Quit),
            _ => {
                let _ = writeln!(output, "Please type retry, refresh, reselect, or quit.");
            }
        }
    }
}

/// Sends one onboarding attempt (normally [`crate::cfgwifi::onboard_once`]).
pub type SendOnboarding<'a> =
    dyn FnMut(&OnboardingConfig, &mut dyn Write) -> Result<bool, OnboardError> + 'a;

/// The device/session loop. Returns the process exit code (0) or an error.
#[allow(clippy::too_many_arguments)]
pub fn run_guided_onboarding(
    config: &OnboardingConfig,
    api: &dyn OnboardingApi,
    send_onboarding: &mut SendOnboarding<'_>,
    output: &mut dyn Write,
    prompter: &mut dyn Prompter,
    settings: PollSettings,
    clock: &dyn Clock,
) -> Result<i32, CliError> {
    api.login()?;
    loop {
        let devices = api.list_devices()?;
        let Some(selected) = choose_device(&devices, output, prompter)? else {
            return Ok(0);
        };
        let duid = pyvalue::first_str(&[selected.get("duid")], "");
        let session = api.start_session(&duid)?;
        let session_id = pyvalue::first_str(&[session.get("session_id")], "")
            .trim()
            .to_owned();
        if session_id.is_empty() {
            return Err(CliError::Message(
                "Server did not return an onboarding session id.".into(),
            ));
        }
        let result = run_session(
            config,
            api,
            &session_id,
            send_onboarding,
            output,
            prompter,
            settings,
            clock,
        );
        // Always release the server-side session, like Python's `finally`.
        let _ = api.delete_session(&session_id);
        match result? {
            SessionEnd::Exit => return Ok(0),
            SessionEnd::Reselect => {}
        }
    }
}

enum SessionEnd {
    Exit,
    Reselect,
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    config: &OnboardingConfig,
    api: &dyn OnboardingApi,
    session_id: &str,
    send_onboarding: &mut SendOnboarding<'_>,
    output: &mut dyn Write,
    prompter: &mut dyn Prompter,
    settings: PollSettings,
    clock: &dyn Clock,
) -> Result<SessionEnd, CliError> {
    loop {
        let status = api.get_session(session_id)?;
        let baseline_samples = pyvalue::int_or_zero(status.get("query_samples"));
        let baseline_has_public_key = pyvalue::truthy(status.get("has_public_key"));
        let _ = write!(
            output,
            "\nReset the vacuum Wi-Fi, connect this machine to the vacuum Wi-Fi, \
             then press Enter to send onboarding.\n\
             Type 'reselect' to choose another vacuum or 'quit' to exit.\n"
        );
        if baseline_has_public_key {
            let _ = writeln!(
                output,
                "The public key is already ready. This should be the final pairing cycle, \
                 but some vacuums still take a few minutes to finish reconnecting."
            );
        }
        match prompter.input("> ")?.trim().to_lowercase().as_str() {
            "quit" => return Ok(SessionEnd::Exit),
            "reselect" => return Ok(SessionEnd::Reselect),
            _ => {}
        }

        let _ = writeln!(output, "Sending cfgwifi onboarding packet...");
        if !send_onboarding(config, output)? {
            let _ = writeln!(output, "Onboarding send failed.");
            match prompt_post_attempt_action(&status, output, prompter)? {
                PostAttemptAction::Reselect => return Ok(SessionEnd::Reselect),
                PostAttemptAction::Quit => return Ok(SessionEnd::Exit),
                PostAttemptAction::Refresh => {
                    print_status_summary(&api.get_session(session_id)?, output);
                }
                PostAttemptAction::Retry => {}
            }
            continue;
        }

        let _ = writeln!(
            output,
            "Reconnect this machine to your normal Wi-Fi. \
             Once the main server is reachable again, the script will poll every 5 seconds \
             for up to 5 minutes. Some vacuums take most of that window, especially on the \
             final cycle."
        );
        let (outcome, status) = poll_session_until_progress(
            api,
            session_id,
            baseline_samples,
            Some(&status),
            output,
            settings,
            clock,
        )?;
        print_status_summary(&status, output);
        match outcome {
            PollOutcome::Connected => {
                let _ = writeln!(output, "The vacuum is connected to the local server.");
                return Ok(SessionEnd::Exit);
            }
            PollOutcome::PublicKeyReady => {
                let _ = writeln!(
                    output,
                    "The public key is ready. Do one final pairing cycle to finish the connection."
                );
                continue;
            }
            PollOutcome::SampleIncreased => {
                let _ = writeln!(
                    output,
                    "The sample count increased. Repeat the pairing cycle to collect more onboarding data."
                );
                continue;
            }
            PollOutcome::Unsupported => {
                let _ = writeln!(
                    output,
                    "This vacuum is not supported by the current onboarding flow."
                );
            }
            PollOutcome::Timeout
                if baseline_has_public_key && pyvalue::truthy(status.get("has_public_key")) =>
            {
                let _ = writeln!(
                    output,
                    "The public key was already ready, but the vacuum did not finish connecting \
                     within the timeout. Some models are slow on the final cycle; wait a bit longer \
                     if the vacuum is still working, or retry if it never announces Wi-Fi connected."
                );
            }
            PollOutcome::Timeout | PollOutcome::Conflict => {}
        }

        match prompt_post_attempt_action(&status, output, prompter)? {
            PostAttemptAction::Retry => {}
            PostAttemptAction::Refresh => {
                print_status_summary(&api.get_session(session_id)?, output);
            }
            PostAttemptAction::Quit => return Ok(SessionEnd::Exit),
            PostAttemptAction::Reselect => return Ok(SessionEnd::Reselect),
        }
    }
}

#[cfg(test)]
mod tests;
