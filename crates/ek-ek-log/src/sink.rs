// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where a finished line goes.
//!
//! Named as its own trait so a test can read exactly what would have reached
//! standard output. Measuring a log against the bytes it writes is the only
//! way to prove the format; measuring it against the value a function returned
//! proves that two pieces of our own code agree and nothing else.

use std::io::Write;
use std::sync::{Arc, Mutex};

/// Something a finished line can be written to.
pub trait Sink: Send + Sync {
    /// Writes one line. The newline is the sink's to add.
    fn write(&self, line: &str);
}

/// Standard output, which journald collects (ADR-0037).
#[derive(Debug, Default)]
pub struct Stdout;

impl Sink for Stdout {
    fn write(&self, line: &str) {
        let out = std::io::stdout();
        let mut held = out.lock();
        // A log line that cannot be written is not worth stopping a request
        // for, and there is nowhere left to report the failure to.
        let _ = held.write_all(line.as_bytes());
        let _ = held.write_all(b"\n");
        let _ = held.flush();
    }
}

/// Keeps every line, so a test can read what was written.
#[derive(Clone, Debug, Default)]
pub struct Captured {
    lines: Arc<Mutex<Vec<String>>>,
}

impl Captured {
    /// A sink holding nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every line written so far, in order.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default()
    }

    /// Everything written so far as one block of text.
    ///
    /// Used by the leak scan, which asks whether a secret appears anywhere at
    /// all rather than in a particular record.
    #[must_use]
    pub fn text(&self) -> String {
        self.lines().join("\n")
    }

    /// Forgets everything written so far.
    pub fn clear(&self) {
        if let Ok(mut held) = self.lines.lock() {
            held.clear();
        }
    }
}

impl Sink for Captured {
    fn write(&self, line: &str) {
        if let Ok(mut held) = self.lines.lock() {
            held.push(line.to_owned());
        }
    }
}

/// Takes as long as it is told to before accepting a line.
///
/// Stands in for a blocked consumer of standard output, which is the one
/// condition the queue exists for.
#[derive(Debug)]
pub struct Slow {
    delay: std::time::Duration,
    written: std::sync::atomic::AtomicU64,
}

impl Slow {
    /// A sink that waits this long per line.
    #[must_use]
    pub const fn new(delay: std::time::Duration) -> Self {
        Self {
            delay,
            written: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// How many lines it has accepted.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Sink for Slow {
    fn write(&self, _line: &str) {
        std::thread::sleep(self.delay);
        self.written
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
