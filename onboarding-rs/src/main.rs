//! `roborock-onboard`: guided vacuum onboarding for the Roborock Local Server.
//!
//! `roborock-onboard --server <host>` runs the interactive CLI;
//! `roborock-onboard gui` starts the localhost web UI.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use roborock_onboard::api::RemoteOnboardingApi;
use roborock_onboard::cfgwifi::{self, BodyLog, Exchange};
use roborock_onboard::cli::{self, ConfigArgs, PollSettings, SessionTracker, SystemClock};
use roborock_onboard::gui::http::GuiServer;
use roborock_onboard::gui::worker::Deps;
use roborock_onboard::preflight::{self, TlsTarget};
use roborock_onboard::terminal::{self, TerminalPrompter};

/// How long Ctrl-C waits for the open session to be deleted before exiting.
const INTERRUPT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Parser)]
#[command(
    name = "roborock-onboard",
    version,
    about = "Guided Roborock remote onboarding",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Main server hostname or HTTPS URL, usually starting with api-
    #[arg(long, required = true)]
    server: Option<String>,

    /// Admin password (prompted with hidden input if omitted)
    #[arg(long, default_value = "", hide_default_value = true)]
    admin_password: String,

    /// Home Wi-Fi SSID (prompted if omitted)
    #[arg(long, default_value = "", hide_default_value = true)]
    ssid: String,

    /// Home Wi-Fi password (prompted with hidden input if omitted)
    #[arg(long, default_value = "", hide_default_value = true)]
    password: String,

    /// IANA timezone, e.g. America/New_York (prompted if omitted)
    #[arg(long, default_value = "", hide_default_value = true)]
    timezone: String,

    /// POSIX TZ string (derived from --timezone if omitted)
    #[arg(long, default_value = "", hide_default_value = true)]
    cst: String,

    /// Country domain, e.g. us (derived from --timezone if omitted)
    #[arg(long, default_value = "", hide_default_value = true)]
    country_domain: String,

    /// Skip TLS certificate verification for the admin API and MQTT preflight checks.
    #[arg(long)]
    allow_insecure_tls: bool,

    /// Where the vacuum's cfgwifi service listens (testing hook).
    #[arg(
        long,
        global = true,
        hide = true,
        env = "ROBOROCK_ONBOARD_CFGWIFI_TARGET",
        default_value = cfgwifi::DEFAULT_TARGET
    )]
    cfgwifi_target: SocketAddr,
}

#[derive(Subcommand)]
enum Command {
    /// Start the browser-based onboarding UI on 127.0.0.1.
    Gui(GuiArgs),
}

#[derive(Args)]
struct GuiArgs {
    /// Print the URL but do not open a browser.
    #[arg(long)]
    no_browser: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match &cli.command {
        Some(Command::Gui(args)) => run_gui(cli.cfgwifi_target, args.no_browser),
        None => run_cli(&cli),
    };
    let _ = io::stdout().flush();
    ExitCode::from(code)
}

fn run_cli(cli: &Cli) -> u8 {
    type Api = SessionTracker<RemoteOnboardingApi>;
    let api_slot: Arc<OnceLock<Arc<Api>>> = Arc::new(OnceLock::new());
    {
        let saved_terminal = terminal::save();
        let api_slot = Arc::clone(&api_slot);
        let installed = ctrlc::set_handler(move || {
            if let Some(saved) = &saved_terminal {
                terminal::restore(saved);
            }
            if let Some(api) = api_slot.get() {
                // Release the server-side session, but never hang on exit
                // (the machine may still be on the vacuum hotspot).
                let api = Arc::clone(api);
                let (done_tx, done_rx) = mpsc::channel();
                std::thread::spawn(move || {
                    api.cleanup();
                    let _ = done_tx.send(());
                });
                let _ = done_rx.recv_timeout(INTERRUPT_CLEANUP_TIMEOUT);
            }
            println!("\nInterrupted.");
            let _ = io::stdout().flush();
            std::process::exit(130);
        });
        if let Err(err) = installed {
            eprintln!("Warning: could not install Ctrl-C handler: {err}");
        }
    }

    let args = ConfigArgs {
        server: cli.server.clone().unwrap_or_default(),
        admin_password: cli.admin_password.clone(),
        ssid: cli.ssid.clone(),
        password: cli.password.clone(),
        timezone: cli.timezone.clone(),
        cst: cli.cst.clone(),
        country_domain: cli.country_domain.clone(),
        allow_insecure_tls: cli.allow_insecure_tls,
    };
    let mut stdout = io::stdout();
    let config = match cli::prompt_for_config(&args, &mut TerminalPrompter, &mut stdout) {
        Ok(config) => config,
        Err(err) => return fail(&err),
    };

    let api = Arc::new(SessionTracker::new(RemoteOnboardingApi::new(
        &config.api_base_url,
        &config.admin_password,
        config.allow_insecure_tls,
    )));
    let _ = api_slot.set(Arc::clone(&api));

    if config.allow_insecure_tls {
        println!(
            "TLS certificate verification is DISABLED. Preflight will only test reachability."
        );
    }
    if let Err(err) = preflight::perform_onboarding_preflight(
        &*api,
        &config.api_base_url,
        config.allow_insecure_tls,
        &mut stdout,
        &mut |target: &TlsTarget| preflight::probe_tls_endpoint(target),
    ) {
        return fail(&err);
    }

    let exchange = Exchange {
        target: cli.cfgwifi_target,
        reply_timeout: cfgwifi::REPLY_TIMEOUT,
        body_log: BodyLog::Full,
    };
    match cli::run_guided_onboarding(
        &config,
        &*api,
        &mut |config, out| cfgwifi::onboard_once(config, &exchange, out),
        &mut stdout,
        &mut TerminalPrompter,
        PollSettings::default(),
        &SystemClock::new(),
    ) {
        Ok(code) => u8::try_from(code).unwrap_or(1),
        Err(err) => fail(&err),
    }
}

fn fail(err: &dyn std::fmt::Display) -> u8 {
    let _ = io::stdout().flush();
    eprintln!("Error: {err}");
    1
}

fn run_gui(cfgwifi_target: SocketAddr, no_browser: bool) -> u8 {
    let gui = match GuiServer::start(Deps::production(cfgwifi_target)) {
        Ok(gui) => gui,
        Err(err) => return fail(&err),
    };
    let url = gui.url().to_owned();
    println!("Vacuum Onboarding UI: {url}");
    if !no_browser {
        println!("Opening browser...");
        if open::that_detached(&url).is_err() {
            println!("Could not open browser automatically. Copy the URL above.");
        }
    }
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let interrupted = Arc::clone(&interrupted);
        let stop = gui.stopper();
        let _ = ctrlc::set_handler(move || {
            interrupted.store(true, Ordering::SeqCst);
            stop();
        });
    }
    gui.wait();
    if interrupted.load(Ordering::SeqCst) {
        println!("\nInterrupted.");
    }
    0
}
