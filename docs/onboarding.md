# Onboarding

Before you start, finish [Installation](installation.md) and make sure the server is reachable on your `api-...` hostname. If you want a compatibility snapshot, also check [Tested vacuums](tested_vacuums.md).

Make sure you have already completed the cloud import/fetch-data step from Installation before starting onboarding. If you skip that step, the onboarding tools will not know which vacuum to target and you can end up with `No known vacuums are available for onboarding.`

If this is a brand new vacuum, it is still a good idea to set it up once in the official Roborock app first so the app can fetch the vacuum's current metadata. I would skip doing any firmware updates unless you know the latest firmware version is supported.

## Onboarding Methods

You can onboard your vacuum using either of the following approaches:

1. **[Via Computer (CLI or Web UI)](#guided-flow-cli)** — Run the guided onboarding tool (`roborock-onboard`, or the Python scripts `start_onboarding.py` / `start_onboarding_gui.py`) from a second machine on your network.
2. **[Via Mobile App (LocalRock)](#alternative-onboarding-via-localrock)** — Provision directly from your phone over Wi-Fi using the third-party LocalRock app.

---

## Get The Onboarding Tool

`roborock-onboard` is a single self-contained binary with both the CLI and the web UI. It needs no Python, `uv` or other dependencies. Download the file for your machine from the [latest release](https://github.com/python-roborock/local_roborock_server/releases/latest).

> The binaries are attached starting with the first release published after the Rust onboarding tool was added. If the latest release has no `roborock-onboard-*` files yet, build it from source (see the end of this section) or use the [Python scripts](#python-scripts-fallback) for now.

| Machine | File |
| --- | --- |
| macOS, Apple Silicon | `roborock-onboard-aarch64-apple-darwin` |
| macOS, Intel | `roborock-onboard-x86_64-apple-darwin` |
| Linux, x86_64 | `roborock-onboard-x86_64-unknown-linux-musl` |
| Linux, ARM64 (e.g. Raspberry Pi 4/5 with a 64-bit OS) | `roborock-onboard-aarch64-unknown-linux-musl` |
| Windows, x86_64 | `roborock-onboard-x86_64-pc-windows-msvc.exe` |

On macOS or Linux, download it and make it executable (swap in the file name from the table):

```bash
curl -L -o roborock-onboard \
  https://github.com/python-roborock/local_roborock_server/releases/latest/download/roborock-onboard-aarch64-apple-darwin
chmod +x roborock-onboard
```

Each file has a matching `.sha256` checksum next to it on the release page. If macOS blocks a copy you downloaded through a browser, clear the quarantine flag with `xattr -d com.apple.quarantine roborock-onboard`. On Windows, run the `.exe` from PowerShell or Command Prompt, for example `.\roborock-onboard-x86_64-pc-windows-msvc.exe --server api-roborock.example.com`.

To build it yourself from a checkout instead, install Rust and run `cargo build --release --manifest-path onboarding-rs/Cargo.toml`. The binary ends up in `onboarding-rs/target/release/`.

The [Python scripts](#python-scripts-fallback) still work and follow the same flow if you would rather run those.

## Guided Flow (CLI)

Run onboarding from a second machine, not from the machine hosting the local server:

- It must be able to switch from your normal Wi-Fi to the vacuum's temporary Wi-Fi hotspot and back.
- It must resolve your `api-...` stack hostname to the server's LAN IP when it is back on your normal Wi-Fi.

```bash
./roborock-onboard --server api-roborock.example.com
```

If you omit the port, the CLI assumes the default local stack HTTPS port `555`. If your stack uses a custom HTTPS port, include it in `--server`, for example `api-roborock.example.com:8443`.

Onboarding has a hard `token.r` limit of 32 characters after normalization to the final `host[:port]/` value sent to the vacuum. 

The guided CLI will:

1. Log into the main server with your admin password.
2. Show the known vacuums that can be onboarded, with status lines such as `Qrevo MaxV [Public Key Determined] [Disconnected]`.
3. Prompt for any missing local Wi-Fi details on the second machine.
4. Ask you to reset the vacuum Wi-Fi, join the vacuum's Wi-Fi network, and press Enter when ready.
5. Send the cfgwifi onboarding packet.
6. Ask you to reconnect the second machine to your normal Wi-Fi.
7. Wait for the main server to become reachable again, then poll it every 5 seconds for up to 5 minutes to see whether query samples increased, the public key was recovered, or the vacuum connected.
8. Tell you whether to retry, wait, choose a different vacuum, or finish.

You do not need to watch the admin dashboard manually during the loop anymore.

## Prompts And Defaults

The only required CLI flag is `--server`. The tool will prompt for anything missing (passwords are read with hidden input):

- `admin password`
- `ssid`
- `password`
- `timezone`
- `cst`
- `country-domain`

You can still pass them explicitly if you prefer:

```bash
./roborock-onboard --server api-roborock.example.com --ssid "My Wifi" --password "Password123" --timezone "America/New_York" --cst EST5EDT,M3.2.0,M11.1.0 --country-domain us
```

`server` should be your real stack hostname, usually the same `api-...` hostname you use for `/admin`. If you omit the port, the CLI assumes `:555`. Explicit ports are supported, so if your admin page is at `https://api-roborock.example.com:8443/admin`, use `--server api-roborock.example.com:8443`.

If your stack uses a self-signed certificate, `--allow-insecure-tls` skips certificate verification for the admin API and the preflight TLS checks. The vacuum still has to trust your certificate, so treat this as a diagnostic option. Run `./roborock-onboard --help` for the full flag list.

## CST Examples

Eastern Time (US): `EST5EDT,M3.2.0,M11.1.0`

Central Time (US): `CST6CDT,M3.2.0,M11.1.0`

Mountain Time (US - with DST): `MST7MDT,M3.2.0,M11.1.0`

Mountain Time (Arizona - no DST): `MST7`

Pacific Time (US): `PST8PDT,M3.2.0,M11.1.0`

London (UK): `GMT0BST,M3.5.0,M10.5.0`

Central Europe (Paris/Berlin): `CET-1CEST,M3.5.0,M10.5.0`

India (No DST): `IST-5:30`

Japan (No DST): `JST-9`

## What To Expect

- The first successful attempt usually increases the query sample count.
- If the sample count increases but the public key is still missing, run another cycle.
- Public-key recovery can take several minutes. On some newer models, the query sample count stays at zero during recovery; watch for **Public Key determined** instead.
- Once the public key is ready, the script will tell you to do one final pairing cycle so the vacuum connects fully.
- Some vacuums are slow on that final cycle and may take a few minutes before they say Wi-Fi connected or show up as connected in the server.
- Some vacuums need 2-4 cycles total.
- If something goes wrong, the CLI lets you `retry`, `refresh`, `reselect`, or `quit`.

You still need to reset the vacuum's Wi-Fi manually. On many Roborock models that means holding the two buttons on the dock or the left and right buttons on the vacuum for 3-5 seconds until you hear the Wi-Fi reset prompt. Do a Wi-Fi reset, not a full factory reset. If you are unsure, search for your exact model's Wi-Fi reset steps.

Congrats! Once the script reports that the vacuum is connected to the local server, the onboarding flow is complete.

## Web UI (roborock-onboard gui)

If you would rather not use the terminal, there is a web UI version of the same flow. It runs a small local server on your machine and opens your browser automatically:

```bash
./roborock-onboard gui
```

All configuration happens in the browser form on first load. The only option is `--no-browser`, which prints the URL without opening a browser (handy over SSH with a port forward).

Enter the same server host you use for `/admin`. If your stack runs on a custom HTTPS port, include it in the form, for example `api-roborock.example.com:8443`.

The same onboarding `token.r` limit applies in the GUI: the final `host[:port]/` value must be 32 characters or less.

The main reason to use the GUI version is that this flow makes you switch your machine between your normal Wi-Fi and the vacuum's Wi-Fi hotspot several times. A browser talking to `127.0.0.1` keeps working through those switches. The CLI version can get into a bad state if a blocking network call hits while you are still on the vacuum hotspot.

### What it does on startup

1. Picks a random free port on `127.0.0.1`.
2. Generates a random per-run access token.
3. Starts a local server bound to localhost only.
4. Opens your default browser to `http://127.0.0.1:<port>/?token=<token>`.

The server is not reachable from your LAN. The token is included in the launch URL and is required for the protected UI/API requests, so other processes or browser tabs on the same machine cannot drive the onboarding flow unless they have that URL. If the browser does not open on its own, copy the URL printed in the terminal (including the `?token=...` part) and open it manually.

### The five phases

The UI shows a stepper across the top and walks you through five phases:

1. **Configure.** Fill in the server host, admin password, your home Wi-Fi SSID and password, timezone, and country domain. The POSIX TZ string and country domain are auto-derived from the timezone if you leave them blank. Same fields as the CLI, just in a form.
2. **Select vacuum.** The script logs into the main server and lists the known vacuums with pills showing whether each has a public key, is connected, and how many query samples it has. Click one to start a session.
3. **Send onboarding.** Reset the vacuum's Wi-Fi, join its hotspot on this machine, then click "Send onboarding packet". The script sends the cfgwifi packet to `192.168.8.1` over the hotspot.
4. **Reconnect and poll.** Switch back to your normal Wi-Fi. The UI waits for the main server to become reachable again (up to two minutes), then polls every few seconds for up to five minutes. That five-minute window is for the vacuum to make progress, not a deadline for you to reconnect instantly. If you know you are already back online, click "I'm back online, skip the wait".
5. **Done.** The UI tells you whether to run another cycle, pick a different vacuum, or finish.

A live log pane below the stepper shows every packet, status check, and state transition. This is the same information the CLI prints to the terminal.

Your inputs live only in memory for the duration of the run and are discarded when you click Quit or shut down the server.

The `roborock-onboard` binary has the page built in, so there is nothing else to copy.

### Same caveats as the CLI

Everything in "What To Expect" above still applies. Some vacuums need 2-4 cycles, the Wi-Fi reset on the vacuum is still manual, and the POSIX TZ examples are the same. Only the interface changed, the underlying packet flow is identical.

### Troubleshooting

- **The browser didn't open.** Copy the URL printed in the terminal (including the `?token=...` query string) and open it manually.
- **"Onboarding send failed" right after clicking send.** You are probably not joined to the vacuum's hotspot yet, or the vacuum is not in pairing mode. Reset its Wi-Fi and try again.
- **"No known vacuums are available for onboarding."** Go back and finish the cloud import/fetch-data step first so the server has the vacuum inventory.
- **"Could not reach the server after leaving the vacuum hotspot."** Your machine did not rejoin your normal Wi-Fi within two minutes. Check your network and click Retry.
- **The UI is stuck on "Polling...".** Give it the full five-minute timeout. Some vacuums are especially slow on the final cycle after the public key is already ready. If nothing changes, check the log pane for errors, then click Retry or Pick another vacuum.

## Python Scripts (Fallback)

The original Python versions of both tools are still in this repository and run the same flow. They need Python 3.11+ and `uv`:

```bash
uv run start_onboarding.py --server api-roborock.example.com
uv run start_onboarding_gui.py
```

`start_onboarding.py` takes the same flags as `roborock-onboard`. `start_onboarding_gui.py` takes no flags. Run them from a checkout of this repository. If you copy them to another machine instead, keep `start_onboarding.py` and `onboarding_shared.py` together in the same directory for the CLI, and `start_onboarding_gui.py`, `ui.html` and `onboarding_shared.py` together for the web UI.

---
 
## Alternative: Onboarding Via LocalRock

> **Notice:** I did not make this app, nor do I maintain it. LocalRock was created by Sidon ([@DonSidro](https://github.com/DonSidro)).

If you have a smartphone, you can use [LocalRock](roborock_app.md#localrock-third-party-app) (available for Android and iOS) to onboard your vacuum directly from your phone without needing a second computer:
 
1. Connect LocalRock to your local server by providing your server URL and login credentials.
2. Select the **Add vacuum** option in the app.
3. Reset your vacuum's Wi-Fi (press and hold the two dock buttons or the left/right buttons on the vacuum for 3–5 seconds until you hear the Wi-Fi reset alert).
4. Follow the in-app prompts to connect your phone to the vacuum's temporary Wi-Fi hotspot and send your home Wi-Fi credentials.
5. The app will complete the handshake, recover the key, and verify that the vacuum connects to your local server.
 
---
 
## Related Docs

- [Installation](installation.md)
- [Tested vacuums](tested_vacuums.md)
- [Home Assistant](home_assistant.md)
- [Mobile App Options](roborock_app.md)
