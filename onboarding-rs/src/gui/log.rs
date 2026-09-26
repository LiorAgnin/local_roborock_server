//! The GUI log pane buffer (Python `_UILogBuffer`).

use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

const MAX_ENTRIES: usize = 500;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LogEntry {
    /// Seconds since the Unix epoch.
    pub ts: f64,
    /// `""`, `"ok"`, `"warn"` or `"err"`.
    pub level: &'static str,
    pub msg: String,
}

#[derive(Debug, Default)]
struct Inner {
    entries: Vec<LogEntry>,
    pending: Vec<u8>,
}

/// Thread-safe log shown in the browser. `&UiLog` implements `Write`, so
/// flow code can print to it line by line like the CLI prints to stdout.
#[derive(Debug, Default)]
pub struct UiLog {
    inner: Mutex<Inner>,
}

impl UiLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Level inferred from the message text.
    pub fn info(&self, msg: &str) {
        self.append(&mut self.lock(), msg, infer_level(msg));
    }

    pub fn ok(&self, msg: &str) {
        self.append(&mut self.lock(), msg, "ok");
    }

    pub fn warn(&self, msg: &str) {
        self.append(&mut self.lock(), msg, "warn");
    }

    pub fn err(&self, msg: &str) {
        self.append(&mut self.lock(), msg, "err");
    }

    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.lock().entries.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn append(&self, inner: &mut Inner, msg: &str, level: &'static str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        inner.entries.push(LogEntry {
            ts,
            level,
            msg: msg.to_owned(),
        });
        if inner.entries.len() > MAX_ENTRIES {
            let excess = inner.entries.len() - MAX_ENTRIES;
            inner.entries.drain(..excess);
        }
    }
}

fn infer_level(msg: &str) -> &'static str {
    let low = msg.to_lowercase();
    if ["fail", "error", "invalid", "unable"]
        .iter()
        .any(|word| low.contains(word))
    {
        "err"
    } else if low.split_whitespace().any(|word| word == "ok")
        || ["success", "reachable", "connected"]
            .iter()
            .any(|word| low.contains(word))
    {
        "ok"
    } else {
        ""
    }
}

impl Write for &UiLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.lock();
        inner.pending.extend_from_slice(buf);
        while let Some(newline) = inner.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = inner.pending.drain(..=newline).collect();
            let line = String::from_utf8_lossy(&line[..newline]).into_owned();
            if !line.trim().is_empty() {
                self.append(&mut inner, &line, infer_level(&line));
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn levels(log: &UiLog) -> Vec<(&'static str, String)> {
        log.snapshot()
            .into_iter()
            .map(|e| (e.level, e.msg))
            .collect()
    }

    #[test]
    fn write_splits_lines_and_skips_blank_ones() {
        let log = UiLog::new();
        let mut w = &log;
        write!(w, "first\n\n   \nsec").unwrap();
        assert_eq!(levels(&log), vec![("", "first".to_owned())]);
        writeln!(w, "ond").unwrap();
        assert_eq!(
            levels(&log),
            vec![("", "first".to_owned()), ("", "second".to_owned())]
        );
    }

    #[test]
    fn write_keeps_multibyte_chars_split_across_writes() {
        let log = UiLog::new();
        let mut w = &log;
        let bytes = "caf\u{e9}\n".as_bytes();
        w.write_all(&bytes[..4]).unwrap();
        w.write_all(&bytes[4..]).unwrap();
        assert_eq!(log.snapshot()[0].msg, "caf\u{e9}");
    }

    #[test]
    fn info_infers_level_like_python() {
        let log = UiLog::new();
        for msg in [
            "Validation failed: x",
            "HTTP error",
            "Invalid admin password.",
            "Unable to reach",
            "all ok here",
            "Login success",
            "Server reachable. Polling",
            "Vacuum connected.",
            "looks okay",
            "plain",
        ] {
            log.info(msg);
        }
        let got: Vec<&str> = log.snapshot().iter().map(|e| e.level).collect();
        assert_eq!(
            got,
            vec!["err", "err", "err", "err", "ok", "ok", "ok", "ok", "", ""]
        );
    }

    #[test]
    fn explicit_levels_are_kept() {
        let log = UiLog::new();
        log.ok("a failure word but ok level");
        log.warn("w");
        log.err("e");
        let got: Vec<&str> = log.snapshot().iter().map(|e| e.level).collect();
        assert_eq!(got, vec!["ok", "warn", "err"]);
    }

    #[test]
    fn keeps_only_the_latest_500_entries() {
        let log = UiLog::new();
        for i in 0..510 {
            log.info(&format!("line {i}"));
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), 500);
        assert_eq!(snap[0].msg, "line 10");
        assert!(snap[0].ts > 1_600_000_000.0);
    }
}
