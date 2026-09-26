//! State shared between the HTTP handlers and the onboarding worker thread.
//!
//! Handlers only post commands; the worker owns the flow and publishes the
//! phase the browser renders. One pending command slot, last write wins,
//! exactly like the Python `_state.pending_command`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::log::UiLog;
use crate::pyvalue::Json;
use crate::server::{self, OnboardingConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    NeedsConfig,
    LoggingIn,
    ChoosingDevice,
    AwaitingVacuumWifi,
    SendingOnboarding,
    AwaitingNormalWifi,
    Polling,
    Done,
    Error,
}

impl Phase {
    /// The phase name ui.html switches on.
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::NeedsConfig => "needs_config",
            Phase::LoggingIn => "logging_in",
            Phase::ChoosingDevice => "choosing_device",
            Phase::AwaitingVacuumWifi => "awaiting_vacuum_wifi",
            Phase::SendingOnboarding => "sending_onboarding",
            Phase::AwaitingNormalWifi => "awaiting_normal_wifi",
            Phase::Polling => "polling",
            Phase::Done => "done",
            Phase::Error => "error",
        }
    }
}

/// Commands the browser can post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiCommand {
    SubmitConfig,
    SelectDevice,
    RefreshDevices,
    SendOnboarding,
    Ready,
    Retry,
    Reselect,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub duid: String,
}

#[derive(Debug, Clone)]
pub struct SharedState {
    pub phase: Phase,
    pub config: Option<OnboardingConfig>,
    pub config_error: Option<String>,
    pub devices: Vec<Value>,
    pub target: Option<Target>,
    pub session_id: Option<String>,
    pub baseline_samples: i64,
    pub status: Json,
    pub result_message: Option<String>,
    pub result_detail: Option<String>,
    pub can_continue: bool,
    pub error_message: Option<String>,
    pending: Option<(UiCommand, Json)>,
}

impl Default for SharedState {
    fn default() -> Self {
        SharedState {
            phase: Phase::NeedsConfig,
            config: None,
            config_error: None,
            devices: Vec::new(),
            target: None,
            session_id: None,
            baseline_samples: 0,
            status: Json::new(),
            result_message: None,
            result_detail: None,
            can_continue: false,
            error_message: None,
            pending: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Shared {
    state: Mutex<SharedState>,
    cond: Condvar,
    shutdown: AtomicBool,
    pub log: UiLog,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn lock(&self) -> MutexGuard<'_, SharedState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Switch phase, apply field updates, wake waiters (`_set_phase`).
    pub fn set_phase(&self, phase: Phase, update: impl FnOnce(&mut SharedState)) {
        let mut state = self.lock();
        state.phase = phase;
        update(&mut state);
        self.cond.notify_all();
    }

    /// Post a command from the browser (`_set_command`).
    pub fn set_command(&self, command: UiCommand, payload: Json) {
        self.lock().pending = Some((command, payload));
        self.cond.notify_all();
    }

    /// Take the pending command if it is one of `expected`, waiting up to
    /// `timeout` (forever when `None`). `None` on timeout or shutdown.
    pub fn wait_for_command(
        &self,
        expected: &[UiCommand],
        timeout: Option<Duration>,
    ) -> Option<(UiCommand, Json)> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut state = self.lock();
        loop {
            if self.is_shutdown() {
                return None;
            }
            if state
                .pending
                .as_ref()
                .is_some_and(|(cmd, _)| expected.contains(cmd))
            {
                return state.pending.take();
            }
            let wait = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return None;
                    }
                    remaining
                }
                // Re-check the shutdown flag at least once a second.
                None => Duration::from_secs(1),
            };
            state = self
                .cond
                .wait_timeout(state, wait)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }

    /// Sleep up to `timeout`, waking early on any state change or command.
    pub fn wait(&self, timeout: Duration) {
        let state = self.lock();
        if self.is_shutdown() {
            return;
        }
        let _ = self.cond.wait_timeout(state, timeout);
    }

    /// Drop a pending "I'm back online" click.
    pub fn clear_ready(&self) {
        let mut state = self.lock();
        if matches!(state.pending, Some((UiCommand::Ready, _))) {
            state.pending = None;
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _guard = self.lock();
        self.cond.notify_all();
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// The `/api/state` payload.
    pub fn state_json(&self) -> Value {
        let state = self.lock();
        let target = state.target.as_ref();
        json!({
            "phase": state.phase.as_str(),
            "config_error": state.config_error,
            "devices": state.devices,
            "target_name": target.map(|t| t.name.as_str()),
            "target_duid": target.map(|t| t.duid.as_str()),
            "status": state.status,
            "baseline_samples": state.baseline_samples,
            "result_message": state.result_message,
            "result_detail": state.result_detail,
            "can_continue": state.can_continue,
            "error_message": state.error_message,
            "timezones": server::known_timezones(),
            "default_timezone": server::DEFAULT_TIMEZONE,
            "log": self.log.snapshot(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn wait_returns_expected_command_and_clears_it() {
        let shared = Shared::new();
        shared.set_command(
            UiCommand::Retry,
            json!({"a": 1}).as_object().unwrap().clone(),
        );
        let (cmd, payload) = shared
            .wait_for_command(&[UiCommand::Retry, UiCommand::Quit], Some(Duration::ZERO))
            .unwrap();
        assert_eq!(cmd, UiCommand::Retry);
        assert_eq!(payload["a"], json!(1));
        assert!(shared
            .wait_for_command(&[UiCommand::Retry], Some(Duration::from_millis(10)))
            .is_none());
    }

    #[test]
    fn unexpected_command_stays_pending_and_last_write_wins() {
        let shared = Shared::new();
        shared.set_command(UiCommand::Ready, Json::new());
        assert!(shared
            .wait_for_command(&[UiCommand::Retry], Some(Duration::from_millis(10)))
            .is_none());
        shared.set_command(UiCommand::Reselect, Json::new());
        assert_eq!(
            shared
                .wait_for_command(&[UiCommand::Reselect], Some(Duration::ZERO))
                .map(|(c, _)| c),
            Some(UiCommand::Reselect)
        );
    }

    #[test]
    fn waiting_thread_wakes_on_command() {
        let shared = Shared::new();
        let waiter = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.wait_for_command(&[UiCommand::SendOnboarding], None))
        };
        thread::sleep(Duration::from_millis(50));
        shared.set_command(UiCommand::SendOnboarding, Json::new());
        assert_eq!(
            waiter.join().unwrap().map(|(c, _)| c),
            Some(UiCommand::SendOnboarding)
        );
    }

    #[test]
    fn shutdown_releases_waiters() {
        let shared = Shared::new();
        let waiter = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.wait_for_command(&[UiCommand::Retry], None))
        };
        thread::sleep(Duration::from_millis(50));
        shared.request_shutdown();
        assert!(waiter.join().unwrap().is_none());
        assert!(shared.is_shutdown());
    }

    #[test]
    fn clear_ready_only_drops_ready() {
        let shared = Shared::new();
        shared.set_command(UiCommand::Ready, Json::new());
        shared.clear_ready();
        assert!(shared
            .wait_for_command(&[UiCommand::Ready], Some(Duration::ZERO))
            .is_none());
        shared.set_command(UiCommand::Quit, Json::new());
        shared.clear_ready();
        assert!(shared
            .wait_for_command(&[UiCommand::Quit], Some(Duration::ZERO))
            .is_some());
    }

    #[test]
    fn state_json_has_the_fields_ui_html_reads() {
        let shared = Shared::new();
        shared.set_phase(Phase::Done, |s| {
            s.target = Some(Target {
                name: "Q7".into(),
                duid: "d1".into(),
            });
            s.result_message = Some("msg".into());
            s.can_continue = true;
            s.baseline_samples = 3;
        });
        shared.log.info("hello");
        let state = shared.state_json();
        assert_eq!(state["phase"], json!("done"));
        assert_eq!(state["target_name"], json!("Q7"));
        assert_eq!(state["target_duid"], json!("d1"));
        assert_eq!(state["result_message"], json!("msg"));
        assert_eq!(state["result_detail"], json!(null));
        assert_eq!(state["config_error"], json!(null));
        assert_eq!(state["error_message"], json!(null));
        assert_eq!(state["can_continue"], json!(true));
        assert_eq!(state["baseline_samples"], json!(3));
        assert_eq!(state["status"], json!({}));
        assert_eq!(state["devices"], json!([]));
        assert_eq!(state["default_timezone"], json!("America/New_York"));
        assert_eq!(state["timezones"].as_array().unwrap().len(), 21);
        assert_eq!(state["log"][0]["msg"], json!("hello"));
        let keys: Vec<&str> = state
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "phase",
                "config_error",
                "devices",
                "target_name",
                "target_duid",
                "status",
                "baseline_samples",
                "result_message",
                "result_detail",
                "can_continue",
                "error_message",
                "timezones",
                "default_timezone",
                "log",
            ]
        );
    }
}
