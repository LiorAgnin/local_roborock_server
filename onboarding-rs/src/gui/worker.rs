//! The GUI onboarding state machine, run on its own thread. It mirrors the
//! Python worker: wait for a browser command, do the (blocking) network work,
//! publish the next phase.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::state::{Phase, Shared, Target, UiCommand};
use crate::api::{OnboardingApi, RemoteOnboardingApi};
use crate::cfgwifi::{self, BodyLog, Exchange, OnboardError};
use crate::cli::{self, Clock, PollOutcome, SystemClock};
use crate::preflight::{self, TlsTarget};
use crate::pyvalue::{self, Json};
use crate::server::{self, OnboardingConfig};

pub type ApiFactory = dyn Fn(&OnboardingConfig) -> Arc<dyn OnboardingApi> + Send + Sync;
pub type PreflightFn = dyn Fn(&dyn OnboardingApi, &OnboardingConfig, &mut dyn Write) -> Result<(), String>
    + Send
    + Sync;
pub type SendFn =
    dyn Fn(&OnboardingConfig, &mut dyn Write) -> Result<bool, OnboardError> + Send + Sync;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timings {
    pub poll_interval: Duration,
    pub poll_timeout: Duration,
    /// How long to wait for the server after leaving the vacuum hotspot.
    pub reachability_timeout: Duration,
    pub reachability_retry: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Timings {
            poll_interval: cli::POLL_INTERVAL,
            poll_timeout: cli::POLL_TIMEOUT,
            reachability_timeout: Duration::from_secs(120),
            reachability_retry: Duration::from_secs(2),
        }
    }
}

/// Everything the worker talks to, injectable for tests.
pub struct Deps {
    pub make_api: Box<ApiFactory>,
    pub preflight: Box<PreflightFn>,
    pub send: Box<SendFn>,
    pub timings: Timings,
    pub clock: Box<dyn Clock + Send + Sync>,
}

impl Deps {
    /// Real admin API, real preflight (TLS verified), real cfgwifi exchange.
    pub fn production(cfgwifi_target: SocketAddr) -> Self {
        let exchange = Exchange {
            target: cfgwifi_target,
            reply_timeout: cfgwifi::REPLY_TIMEOUT,
            body_log: BodyLog::Redacted,
        };
        Deps {
            make_api: Box::new(|config| {
                Arc::new(RemoteOnboardingApi::new(
                    &config.api_base_url,
                    &config.admin_password,
                    false,
                ))
            }),
            preflight: Box::new(|api, config, out| {
                preflight::perform_onboarding_preflight(
                    api,
                    &config.api_base_url,
                    false,
                    out,
                    &mut |target: &TlsTarget| preflight::probe_tls_endpoint(target),
                )
                .map(|_| ())
                .map_err(|err| err.to_string())
            }),
            send: Box::new(move |config, out| cfgwifi::onboard_once(config, &exchange, out)),
            timings: Timings::default(),
            clock: Box::new(SystemClock::new()),
        }
    }
}

/// Validate the `/api/config` payload (`_build_config_from_payload`).
/// Passwords are used verbatim; the other fields are trimmed.
pub fn build_config_from_payload(payload: &Json) -> Result<OnboardingConfig, String> {
    let field = |name: &str| pyvalue::first_str(&[payload.get(name)], "");
    let server_value = field("server").trim().to_owned();
    if server_value.is_empty() {
        return Err("Server is required.".into());
    }
    let api_base_url =
        server::normalize_api_base_url(&server_value).map_err(|err| err.to_string())?;
    let stack_server =
        server::sanitize_stack_server(&server_value).map_err(|err| err.to_string())?;
    let admin_password = field("admin_password");
    if admin_password.is_empty() {
        return Err("Admin password is required.".into());
    }
    let ssid = field("ssid").trim().to_owned();
    if ssid.is_empty() {
        return Err("Home Wi-Fi SSID is required.".into());
    }
    let password = field("wifi_password");
    if password.is_empty() {
        return Err("Home Wi-Fi password is required.".into());
    }
    let timezone = match field("timezone").trim() {
        "" => server::DEFAULT_TIMEZONE.to_owned(),
        tz => tz.to_owned(),
    };
    let first_non_empty = |candidates: [&str; 3]| {
        candidates
            .into_iter()
            .find(|c| !c.is_empty())
            .unwrap_or_default()
            .to_owned()
    };
    let cst = first_non_empty([
        field("cst").trim(),
        server::posix_tz_from_iana(&timezone),
        server::DEFAULT_CST,
    ]);
    let country_domain = first_non_empty([
        field("country_domain").trim(),
        server::country_from_iana(&timezone),
        server::DEFAULT_COUNTRY_DOMAIN,
    ]);
    Ok(OnboardingConfig {
        api_base_url,
        stack_server,
        admin_password,
        ssid,
        password,
        timezone,
        cst,
        country_domain,
        allow_insecure_tls: false,
    })
}

/// Device list as the browser sees it.
pub fn serialize_devices(devices: &[Value]) -> Vec<Value> {
    devices
        .iter()
        .map(|device| {
            let onboarding = pyvalue::object(device.get("onboarding"));
            let key_state = pyvalue::object(onboarding.get("key_state"));
            json!({
                "duid": pyvalue::first_str(&[device.get("duid")], ""),
                "name": pyvalue::first_str(&[device.get("name"), device.get("duid")], "Unknown"),
                "has_public_key": pyvalue::truthy(onboarding.get("has_public_key")),
                "connected": pyvalue::truthy(device.get("connected")),
                "query_samples": pyvalue::int_or_zero(key_state.get("query_samples")),
            })
        })
        .collect()
}

/// Session status as the browser sees it.
pub fn serialize_status(status: &Json) -> Json {
    let value = json!({
        "query_samples": pyvalue::int_or_zero(status.get("query_samples")),
        "has_public_key": pyvalue::truthy(status.get("has_public_key")),
        "connected": pyvalue::truthy(status.get("connected")),
        "public_key_state": pyvalue::first_str(&[status.get("public_key_state")], "missing"),
    });
    match value {
        Value::Object(map) => map,
        _ => unreachable!("json! object literal"),
    }
}

/// Poll until progress (`_poll_until_progress`). API errors are logged and
/// polling continues; shutdown ends it as a timeout. `wait` sleeps between
/// polls (the shared condvar in production).
#[allow(clippy::too_many_arguments)]
pub fn poll_until_progress(
    api: &dyn OnboardingApi,
    session_id: &str,
    baseline_samples: i64,
    baseline_has_public_key: bool,
    shared: &Shared,
    timings: &Timings,
    clock: &dyn Clock,
    wait: &dyn Fn(Duration),
) -> (PollOutcome, Json) {
    let deadline = clock.now() + timings.poll_timeout;
    let mut latest = Json::new();
    loop {
        if shared.is_shutdown() {
            return (PollOutcome::Timeout, latest);
        }
        match api.get_session(session_id) {
            Ok(status) => latest = status,
            Err(err) => shared.log.warn(&format!("poll: get_session error: {err}")),
        }
        if let Some(outcome) =
            cli::classify_progress(&latest, baseline_samples, baseline_has_public_key)
        {
            return (outcome, latest);
        }
        if clock.now() >= deadline {
            return (PollOutcome::Timeout, latest);
        }
        shared
            .log
            .info("Waiting for the server to observe new onboarding traffic...");
        wait(timings.poll_interval);
    }
}

/// The user asked to quit (Python `_QuitSignal`).
struct Quit;

struct Worker<'a> {
    shared: &'a Shared,
    deps: &'a Deps,
}

impl Worker<'_> {
    fn log(&self) -> &super::log::UiLog {
        &self.shared.log
    }

    /// Wait for one of `expected`; quit (or shutdown) becomes `Err(Quit)`.
    fn wait_or_quit(&self, expected: &[UiCommand]) -> Result<(UiCommand, Json), Quit> {
        match self.shared.wait_for_command(expected, None) {
            None | Some((UiCommand::Quit, _)) => Err(Quit),
            Some(command) => Ok(command),
        }
    }

    fn error_then_wait(&self, message: &str, target: Option<&Target>) -> Result<UiCommand, Quit> {
        self.shared.set_phase(Phase::Error, |s| {
            s.error_message = Some(message.to_owned());
            if let Some(target) = target {
                s.target = Some(target.clone());
            }
        });
        self.wait_or_quit(&[UiCommand::Retry, UiCommand::Reselect, UiCommand::Quit])
            .map(|(command, _)| command)
    }

    fn wait_for_reachability(&self, api: &dyn OnboardingApi, session_id: &str) -> bool {
        let timings = &self.deps.timings;
        let clock = &*self.deps.clock;
        let deadline = clock.now() + timings.reachability_timeout;
        while clock.now() < deadline {
            if self.shared.is_shutdown() {
                return false;
            }
            self.shared.clear_ready();
            if api.get_session(session_id).is_ok() {
                return true;
            }
            self.shared.wait(timings.reachability_retry);
        }
        false
    }

    fn run(&self) {
        self.log()
            .info("Worker started. Waiting for configuration...");
        while !self.shared.is_shutdown() {
            let Some((command, payload)) = self
                .shared
                .wait_for_command(&[UiCommand::SubmitConfig, UiCommand::Quit], None)
            else {
                return;
            };
            if command == UiCommand::Quit {
                return;
            }
            let config = match build_config_from_payload(&payload) {
                Ok(config) => config,
                Err(err) => {
                    self.shared
                        .set_phase(Phase::NeedsConfig, |s| s.config_error = Some(err.clone()));
                    self.log().err(&format!("Config error: {err}"));
                    continue;
                }
            };
            self.shared.set_phase(Phase::LoggingIn, |s| {
                s.config = Some(config.clone());
                s.config_error = None;
            });
            self.log()
                .info(&format!("Validating {}...", config.api_base_url));
            let api = (self.deps.make_api)(&config);
            let mut log = self.log();
            if let Err(err) = (self.deps.preflight)(&*api, &config, &mut log) {
                self.shared.set_phase(Phase::NeedsConfig, |s| {
                    s.config_error = Some(err.clone());
                    s.config = None;
                });
                self.log().err(&format!("Validation failed: {err}"));
                continue;
            }
            self.log().ok("Validation succeeded.");
            if let Err(Quit) = self.run_device_loop(&*api, &config) {
                self.log().info("Quit requested.");
                return;
            }
        }
    }

    fn run_device_loop(
        &self,
        api: &dyn OnboardingApi,
        config: &OnboardingConfig,
    ) -> Result<(), Quit> {
        loop {
            let devices = match api.list_devices() {
                Ok(devices) => devices,
                Err(err) => {
                    self.log().err(&format!("Could not list devices: {err}"));
                    self.error_then_wait(&err.to_string(), None)?;
                    continue;
                }
            };
            self.shared.set_phase(Phase::ChoosingDevice, |s| {
                s.devices = serialize_devices(&devices);
                s.target = None;
                s.session_id = None;
                s.status = Json::new();
                s.result_message = None;
                s.result_detail = None;
                s.error_message = None;
                s.can_continue = false;
            });
            if devices.is_empty() {
                self.log().warn(
                    "0 device(s) available. Finish the cloud import/fetch-data step first, then refresh.",
                );
            } else {
                self.log()
                    .info(&format!("{} device(s) available.", devices.len()));
            }

            let (command, payload) = self.wait_or_quit(&[
                UiCommand::SelectDevice,
                UiCommand::RefreshDevices,
                UiCommand::Quit,
            ])?;
            if command == UiCommand::RefreshDevices {
                continue;
            }
            let duid = pyvalue::first_str(&[payload.get("duid")], "");
            let selected = devices
                .iter()
                .find(|device| pyvalue::first_str(&[device.get("duid")], "") == duid);
            let Some(selected) = selected else {
                self.log().err(&format!("Unknown duid {duid}"));
                continue;
            };
            self.run_onboarding_for_device(api, config, selected)?;
        }
    }

    fn run_onboarding_for_device(
        &self,
        api: &dyn OnboardingApi,
        config: &OnboardingConfig,
        device: &Value,
    ) -> Result<(), Quit> {
        let duid = pyvalue::first_str(&[device.get("duid")], "");
        let name = pyvalue::first_str(&[device.get("name")], "");
        let name = if !name.is_empty() {
            name
        } else if !duid.is_empty() {
            duid.clone()
        } else {
            "vacuum".to_owned()
        };
        let target = Target {
            name: name.clone(),
            duid: duid.clone(),
        };
        self.log()
            .info(&format!("Starting session for {name} ({duid})"));

        let session = match api.start_session(&duid) {
            Ok(session) => session,
            Err(err) => {
                self.log().err(&format!("Failed to start session: {err}"));
                self.error_then_wait(&err.to_string(), Some(&target))?;
                return Ok(());
            }
        };
        let session_id = pyvalue::first_str(&[session.get("session_id")], "")
            .trim()
            .to_owned();
        if session_id.is_empty() {
            self.log().err("Server did not return a session id.");
            self.error_then_wait("Server did not return a session id.", Some(&target))?;
            return Ok(());
        }

        let result = self.run_session(api, config, &session_id, &target);
        // Always release the server-side session, like Python's `finally`.
        let _ = api.delete_session(&session_id);
        result
    }

    fn run_session(
        &self,
        api: &dyn OnboardingApi,
        config: &OnboardingConfig,
        session_id: &str,
        target: &Target,
    ) -> Result<(), Quit> {
        let retry_or_leave = |command: UiCommand| match command {
            UiCommand::Reselect => Some(()),
            _ => None,
        };
        loop {
            let status = match api.get_session(session_id) {
                Ok(status) => status,
                Err(err) => {
                    self.log().err(&format!("get_session failed: {err}"));
                    let command = self.error_then_wait(&err.to_string(), Some(target))?;
                    if let Some(done) = retry_or_leave(command) {
                        return Ok(done);
                    }
                    continue;
                }
            };
            let baseline = pyvalue::int_or_zero(status.get("query_samples"));
            let baseline_has_public_key = pyvalue::truthy(status.get("has_public_key"));
            let mut log = self.log();
            cli::print_status_summary(&status, &mut log);
            self.shared.set_phase(Phase::AwaitingVacuumWifi, |s| {
                s.target = Some(target.clone());
                s.session_id = Some(session_id.to_owned());
                s.baseline_samples = baseline;
                s.status = serialize_status(&status);
                s.result_message = None;
                s.result_detail = None;
                s.error_message = None;
                s.can_continue = false;
            });
            if baseline_has_public_key {
                self.log().info(
                    "Public key is already ready. This should be the final pairing cycle, \
                     but some vacuums still take a few minutes to finish reconnecting.",
                );
            }

            let (command, _) = self.wait_or_quit(&[
                UiCommand::SendOnboarding,
                UiCommand::Reselect,
                UiCommand::Quit,
            ])?;
            if command == UiCommand::Reselect {
                return Ok(());
            }

            self.shared.set_phase(Phase::SendingOnboarding, |_| {});
            self.log()
                .info("Sending cfgwifi onboarding packet to 192.168.8.1...");
            let sent_ok = match (self.deps.send)(config, &mut log) {
                Ok(sent) => sent,
                Err(err) => {
                    self.log().err(&format!("onboard_once raised: {err}"));
                    false
                }
            };
            if !sent_ok {
                self.log()
                    .err("Onboarding send failed. Are you joined to the vacuum's Wi-Fi?");
                let command = self.error_then_wait(
                    "Onboarding send failed. Ensure your machine is joined to the vacuum's \
                     Wi-Fi hotspot, then retry.",
                    Some(target),
                )?;
                if let Some(done) = retry_or_leave(command) {
                    return Ok(done);
                }
                continue;
            }
            self.log().ok("Onboarding packet sent.");

            self.shared.set_phase(Phase::AwaitingNormalWifi, |_| {});
            self.log().info(
                "Waiting for normal Wi-Fi / server reachability. \
                 After the server is reachable again, polling can still take up to 5 minutes, \
                 especially on the final cycle.",
            );
            if !self.wait_for_reachability(api, session_id) {
                self.log()
                    .err("Could not reach the server after leaving the vacuum hotspot.");
                let command = self.error_then_wait(
                    "Could not reach the server after leaving the vacuum hotspot. \
                     Check your Wi-Fi and try again.",
                    Some(target),
                )?;
                if let Some(done) = retry_or_leave(command) {
                    return Ok(done);
                }
                continue;
            }
            self.log().ok("Server reachable. Polling for progress...");

            self.shared.set_phase(Phase::Polling, |_| {});
            let (outcome, latest) = poll_until_progress(
                api,
                session_id,
                baseline,
                baseline_has_public_key,
                self.shared,
                &self.deps.timings,
                &*self.deps.clock,
                &|timeout| self.shared.wait(timeout),
            );
            cli::print_status_summary(&latest, &mut log);
            self.publish_outcome(outcome, &latest, baseline_has_public_key);

            let (command, _) =
                self.wait_or_quit(&[UiCommand::Retry, UiCommand::Reselect, UiCommand::Quit])?;
            if command == UiCommand::Reselect {
                return Ok(());
            }
        }
    }

    fn publish_outcome(&self, outcome: PollOutcome, latest: &Json, baseline_has_public_key: bool) {
        let (message, detail, can_continue) = match outcome {
            PollOutcome::Connected => (
                "The vacuum is connected to the local server.",
                "Onboarding complete.".to_owned(),
                false,
            ),
            PollOutcome::PublicKeyReady => (
                "Public key is ready.",
                "Run one more pairing cycle to finish the connection.".to_owned(),
                true,
            ),
            PollOutcome::SampleIncreased => (
                "Sample count increased.",
                "Repeat the pairing cycle to collect more onboarding data.".to_owned(),
                true,
            ),
            PollOutcome::Conflict => (
                "Identity conflict detected.",
                pyvalue::first_str(&[latest.get("identity_conflict")], ""),
                false,
            ),
            PollOutcome::Unsupported => (
                "Vacuum unsupported.",
                pyvalue::first_str(
                    &[latest.get("guidance")],
                    "This vacuum is not supported by the current onboarding flow.",
                ),
                false,
            ),
            PollOutcome::Timeout => {
                let slow_final_cycle = baseline_has_public_key
                    && pyvalue::truthy(latest.get("has_public_key"))
                    && !pyvalue::truthy(latest.get("connected"));
                let detail = if slow_final_cycle {
                    "The public key was already ready, but the vacuum did not finish connecting \
                     within the timeout. Some models are slow on the final cycle; wait a bit \
                     longer or retry."
                } else {
                    "The server did not observe new onboarding traffic within the timeout."
                };
                ("Timed out waiting for progress.", detail.to_owned(), true)
            }
        };
        self.shared.set_phase(Phase::Done, |s| {
            s.status = serialize_status(latest);
            s.result_message = Some(message.to_owned());
            s.result_detail = Some(detail);
            s.can_continue = can_continue;
        });
        if outcome == PollOutcome::Connected {
            self.log().ok("Vacuum connected.");
        }
    }
}

/// The worker thread body (`_worker_loop`). Returns when the user quits.
pub fn worker_loop(shared: &Shared, deps: &Deps) {
    Worker { shared, deps }.run();
}

#[cfg(test)]
mod tests;
