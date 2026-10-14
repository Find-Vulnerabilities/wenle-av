//! The progress line.
//!
//! # Why a thread and not a print at the end of each file
//!
//! Because the scan runs on every core and the only shared state the workers
//! have is a counter. A worker that drew the line itself would have to
//! synchronise with the other workers to do it, which turns a counter into a
//! lock on the scanning path — and the line would be drawn wherever a worker
//! happened to finish rather than at a readable rate. A thread that reads the
//! counter ten times a second and redraws costs one atomic load per redraw and
//! nothing at all per file.
//!
//! # It draws nothing when nobody is watching
//!
//! Redirected output, a `--quiet` run and a `--no-progress` run all disable it,
//! and a disabled progress line is not a suppressed one: a carriage return in a
//! log file is a corrupted log file.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use console::style;

/// How often the line is redrawn. Fast enough to look alive, slow enough that
/// the drawing never shows up in a profile of a scan of a million files.
const INTERVAL: Duration = Duration::from_millis(100);

/// A counter the scan workers bump and a thread draws.
#[derive(Debug)]
pub struct Progress {
    files: AtomicU64,
    bytes: AtomicU64,
    findings: AtomicU64,
    current: parking_lot::Mutex<String>,
    stop: AtomicBool,
    enabled: bool,
    started: Instant,
}

impl Progress {
    /// A progress line on standard error, unless the stream is not a terminal.
    pub fn new(enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            files: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            findings: AtomicU64::new(0),
            current: parking_lot::Mutex::new(String::new()),
            stop: AtomicBool::new(false),
            enabled: enabled && io::stderr().is_terminal(),
            started: Instant::now(),
        })
    }

    /// Record one file, whether or not it produced anything.
    pub fn file(&self, path: &str, bytes: u64) {
        self.files.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        if self.enabled {
            // The path is written under the same lock the drawing thread takes,
            // and only while the line is enabled: an unconditional write here
            // would be a lock on the scanning path of every file.
            let mut current = self.current.lock();
            current.clear();
            current.push_str(path);
        }
    }

    /// Record one finding.
    pub fn finding(&self) {
        self.findings.fetch_add(1, Ordering::Relaxed);
    }

    /// How many files have been recorded.
    pub fn files(&self) -> u64 {
        self.files.load(Ordering::Relaxed)
    }

    /// Ask the drawing thread to stop and clear the line.
    pub fn finish(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Run the drawing loop until [`Progress::finish`] is called.
    ///
    /// Meant to be the body of the thread that owns this value; it returns when
    /// the scan is over, so a caller that spawns it joins it and knows the line
    /// has been cleared before the report is printed.
    pub fn draw(&self) {
        if !self.enabled {
            return;
        }
        let mut last = 0u64;
        while !self.stop.load(Ordering::Relaxed) {
            let files = self.files();
            if files != last {
                last = files;
                let line = self.render();
                let mut stderr = io::stderr();
                // `clear_line` before the text rather than after: a line that is
                // shorter than the one before it would otherwise leave the tail
                // of the old one on the screen.
                let _ = write!(stderr, "\r\x1b[2K{line}");
                let _ = stderr.flush();
            }
            std::thread::sleep(INTERVAL);
        }
        if last > 0 {
            let _ = write!(io::stderr(), "\r\x1b[2K");
            let _ = io::stderr().flush();
        }
    }

    /// The text of the line as it stands.
    fn render(&self) -> String {
        let files = self.files();
        let bytes = self.bytes.load(Ordering::Relaxed);
        let findings = self.findings.load(Ordering::Relaxed);
        let elapsed = self.started.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            files as f64 / elapsed
        } else {
            0.0
        };
        let name = {
            let current = self.current.lock();
            shorten(&current, 48)
        };
        let found = if findings == 0 {
            style("no findings".to_owned()).dim().to_string()
        } else {
            style(format!("{findings} found")).red().bold().to_string()
        };
        format!(
            "  {} files ({}/s)  {}  {found}  {name}",
            style(human_count(files)).bold(),
            human_count(rate as u64),
            style(human_bytes(bytes)).dim(),
        )
    }
}

/// Shorten a path from the front, which is where the redundant part is.
fn shorten(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let tail: String = text
        .chars()
        .skip(text.chars().count() - limit + 1)
        .collect();
    format!("…{tail}")
}

/// A count with thousands separators.
pub fn human_count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// A byte count in the largest unit that leaves it above one.
///
/// Decimal units, matching `--max-size` and every disk tool the user has met.
pub fn human_bytes(value: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TB", 1_000_000_000_000),
        ("GB", 1_000_000_000),
        ("MB", 1_000_000),
        ("KB", 1_000),
    ];
    for (unit, scale) in UNITS {
        if value >= scale {
            // One decimal place: enough to tell 1.4 MB from 1.9 MB, which is
            // the resolution a person reading a size actually uses.
            let whole = value / scale;
            let tenths = (value % scale) * 10 / scale;
            return format!("{whole}.{tenths} {unit}");
        }
    }
    format!("{value} B")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_is_grouped_in_threes() {
        assert_eq!(human_count(0), "0");
        assert_eq!(human_count(999), "999");
        assert_eq!(human_count(1000), "1,000");
        assert_eq!(human_count(1234567), "1,234,567");
    }

    #[test]
    fn a_size_is_in_the_largest_unit_that_leaves_one() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1000), "1.0 KB");
        assert_eq!(human_bytes(1500), "1.5 KB");
        assert_eq!(human_bytes(1_000_000), "1.0 MB");
        assert_eq!(human_bytes(2_500_000_000), "2.5 GB");
        // The boundary is at the unit, not at some rounding of it: 999 bytes is
        // not 1.0 KB, and a file of exactly 1 MB is not 1000 KB.
        assert_eq!(human_bytes(999_999), "999.9 KB");
    }

    #[test]
    fn a_long_path_is_shortened_from_the_front() {
        assert_eq!(shorten("short", 48), "short");
        let long = "C:/Users/someone/Downloads/a/very/deep/path/that/goes/on/file.exe";
        let cut = shorten(long, 20);
        assert!(cut.starts_with('…'), "{cut}");
        assert!(cut.ends_with("file.exe"), "{cut}");
        assert_eq!(cut.chars().count(), 20);
    }

    #[test]
    fn a_disabled_line_draws_nothing_and_does_not_block() {
        // The point of the flag: the scanning path must not take the render
        // lock when nobody is watching.
        let progress = Progress::new(false);
        progress.file("a", 1);
        progress.finding();
        progress.finish();
        progress.draw();
        assert_eq!(progress.files(), 1);
    }
}
