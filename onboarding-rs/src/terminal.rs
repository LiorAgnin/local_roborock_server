//! Real terminal I/O for the CLI: line prompts on stdin, hidden input for
//! secrets, and restoring terminal echo if Ctrl-C lands mid-password.

use std::io::{self, BufRead, Write};

use crate::cli::{InputError, Prompter};

/// Python `input()` / `getpass()` equivalents.
pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn input(&mut self, prompt: &str) -> Result<String, InputError> {
        let mut stdout = io::stdout();
        let _ = stdout.write_all(prompt.as_bytes());
        let _ = stdout.flush();
        let mut line = String::new();
        match io::stdin().lock().read_line(&mut line) {
            Ok(0) => Err(InputError::Eof),
            Ok(_) => Ok(line.trim_end_matches(['\n', '\r']).to_owned()),
            Err(err) => Err(InputError::Io(err)),
        }
    }

    fn secret(&mut self, prompt: &str) -> Result<String, InputError> {
        match rpassword::prompt_password(prompt) {
            Ok(value) => Ok(value),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(InputError::Eof),
            // No terminal to hide input on (like getpass's fallback): read stdin.
            Err(_) => {
                eprintln!("Warning: Password input may be echoed.");
                self.input(prompt)
            }
        }
    }
}

/// Terminal settings captured at startup.
pub struct SavedTerminal {
    #[cfg(unix)]
    tty: std::fs::File,
    #[cfg(unix)]
    termios: libc::termios,
}

/// Capture the controlling terminal's settings, if there is one.
#[cfg(unix)]
pub fn save() -> Option<SavedTerminal> {
    use std::os::fd::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    // SAFETY: tcgetattr only writes into the termios struct we pass; an
    // all-zero termios is a valid initial value for this plain C struct.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(tty.as_raw_fd(), &mut termios) } != 0 {
        return None;
    }
    Some(SavedTerminal { tty, termios })
}

#[cfg(not(unix))]
pub fn save() -> Option<SavedTerminal> {
    None
}

/// Put the terminal back (echo on) after an interrupted hidden prompt.
#[cfg(unix)]
pub fn restore(saved: &SavedTerminal) {
    use std::os::fd::AsRawFd;
    // SAFETY: restores settings previously read from the same descriptor.
    unsafe {
        libc::tcsetattr(saved.tty.as_raw_fd(), libc::TCSANOW, &saved.termios);
    }
}

#[cfg(not(unix))]
pub fn restore(_saved: &SavedTerminal) {}
