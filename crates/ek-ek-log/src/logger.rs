// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The installed logger.
//!
//! One per process, installed once. It answers the `log` facade, so records a
//! library underneath us writes are formatted the same way ours are and land
//! in the same place (ADR-0037).
//!
//! # Why a queue
//!
//! Standard output is shared and can block: a pipe nobody drains fills, and a
//! terminal can stop. Writing a record inline would then hold whichever task
//! is serving a request. Records therefore go to a bounded queue that a writer
//! thread drains, and a full queue costs a dropped record rather than a
//! waiting request. Drops are counted, because a gap nobody can measure is
//! worse than a number saying how large it is.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};

use serde::Serialize;

use crate::access::Access;
use crate::level::Level;
use crate::mask;
use crate::sink::{Sink, Stdout};
use crate::time;

/// How many records may wait to be written.
///
/// Large enough that an ordinary burst is never dropped, small enough that a
/// consumer that has stopped costs bounded memory rather than the process.
const QUEUE: usize = 8192;

/// The one logger this process installed.
static INSTALLED: OnceLock<&'static Logger> = OnceLock::new();

/// Formats records and hands them to a writer thread.
#[derive(Debug)]
pub struct Logger {
    /// The application log level, as a number so it can change without a lock.
    level: AtomicU8,
    queue: SyncSender<String>,
    dropped: AtomicU64,
}

/// One application record, as it is written.
#[derive(Serialize)]
struct AppRecord<'a> {
    ts: String,
    kind: &'static str,
    level: &'static str,
    target: &'a str,
    message: String,
}

/// One access record, as it is written.
///
/// The shared fields are spelled out here rather than flattened from
/// [`Access`], so `ts` and `kind` open every line whatever the transport.
#[derive(Serialize)]
struct AccessRecord<'a> {
    ts: String,
    kind: &'static str,
    #[serde(flatten)]
    access: &'a Access,
}

impl Logger {
    /// Builds a logger writing to a sink, and starts its writer thread.
    #[must_use]
    pub fn new(level: Level, sink: Box<dyn Sink>) -> Self {
        let (queue, waiting) = sync_channel::<String>(QUEUE);
        std::thread::Builder::new()
            .name("ek-ek-log".to_owned())
            .spawn(move || {
                for line in waiting {
                    sink.write(&line);
                }
            })
            // A logger that could not start its thread still has to exist, or
            // there is nowhere to report the failure to. The queue then fills
            // once and every record after that is counted as dropped.
            .ok();

        Self {
            level: AtomicU8::new(level.code()),
            queue,
            dropped: AtomicU64::new(0),
        }
    }

    /// The level the application log is written at right now.
    #[must_use]
    pub fn level(&self) -> Level {
        Level::from_code(self.level.load(Ordering::Relaxed))
    }

    /// Changes the level, without a restart and without a lock.
    pub fn set_level(&self, level: Level) {
        self.level.store(level.code(), Ordering::Relaxed);
    }

    /// How many records were dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Queues one line, or counts a drop.
    ///
    /// Never waits. That is the whole point: a blocked consumer of standard
    /// output must not reach the request path.
    fn queue(&self, line: String) {
        match self.queue.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Writes one access record.
    ///
    /// Not filtered by the application log level: an operator quieting the
    /// application log still wants to know which requests arrived (ADR-0037).
    pub fn access(&self, access: &Access) {
        let record = AccessRecord {
            ts: time::now(),
            kind: "access",
            access,
        };
        if let Ok(line) = serde_json::to_string(&record) {
            self.queue(line);
        }
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        Level::of(metadata.level()) <= self.level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = AppRecord {
            ts: time::now(),
            kind: "app",
            level: Level::of(record.level()).name(),
            target: record.target(),
            // Masked whatever wrote it. Our own records carry no secret,
            // but the libraries underneath us write whole headers and whole
            // bodies at debug and trace (ADR-0037).
            message: mask::message(&record.args().to_string()),
        };
        if let Ok(line) = serde_json::to_string(&line) {
            self.queue(line);
        }
    }

    fn flush(&self) {}
}

/// Installs a logger for this process, writing to standard output.
///
/// # Errors
///
/// Fails when a logger is already installed. A process installs one.
pub fn install(level: Level) -> Result<(), log::SetLoggerError> {
    install_to(level, Box::new(Stdout))
}

/// Installs a logger writing somewhere else, which is how a test reads what
/// would have reached standard output.
///
/// # Errors
///
/// Fails when a logger is already installed.
pub fn install_to(level: Level, sink: Box<dyn Sink>) -> Result<(), log::SetLoggerError> {
    // Leaked on purpose: the `log` facade holds a `&'static dyn Log` for the
    // life of the process, and this is installed exactly once.
    let logger: &'static Logger = Box::leak(Box::new(Logger::new(level, sink)));
    log::set_logger(logger)?;
    log::set_max_level(log::LevelFilter::Trace);
    // Ignored if something raced us here; `set_logger` already decided which
    // logger won and this only records the same one.
    let _ = INSTALLED.set(logger);
    Ok(())
}

/// The installed logger, if there is one.
#[must_use]
pub fn installed() -> Option<&'static Logger> {
    INSTALLED.get().copied()
}

/// Changes the application log level of the installed logger.
///
/// The maximum the facade lets through stays at `Trace` and the logger does
/// its own filtering, so a level raised at run time takes effect without the
/// facade having to be told again.
pub fn set_level(level: Level) {
    if let Some(logger) = installed() {
        logger.set_level(level);
    }
}

/// Writes one access record through the installed logger.
///
/// Does nothing when no logger is installed, because a process with no log is
/// still a process that has to serve traffic.
pub fn access(record: &Access) {
    if let Some(logger) = installed() {
        logger.access(record);
    }
}

/// How many records the installed logger dropped.
#[must_use]
pub fn dropped() -> u64 {
    installed().map_or(0, Logger::dropped)
}
