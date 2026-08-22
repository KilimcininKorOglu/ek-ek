// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How much detail the application log carries.
//!
//! Held as its own type rather than taken from the `log` crate, so the
//! configuration model can name a level without depending on whichever
//! logging facade is installed underneath.

use serde::{Deserialize, Serialize};

/// How much detail the application log carries.
///
/// The access log has its own setting and is not affected by this: an
/// operator quieting the application log still wants to know which requests
/// arrived (ADR-0037).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Only what stopped working.
    Error,
    /// Also what is about to stop working.
    Warn,
    /// Also what the process decided. The default.
    #[default]
    Info,
    /// Also enough detail to follow one request through the code.
    Debug,
    /// Everything, including what a library underneath us records.
    Trace,
}

impl Level {
    /// The name written into the `level` field.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Every level, so a test can walk them all.
    pub const ALL: [Self; 5] = [
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];

    /// The same level as the `log` crate names it.
    #[must_use]
    pub const fn filter(self) -> log::LevelFilter {
        match self {
            Self::Error => log::LevelFilter::Error,
            Self::Warn => log::LevelFilter::Warn,
            Self::Info => log::LevelFilter::Info,
            Self::Debug => log::LevelFilter::Debug,
            Self::Trace => log::LevelFilter::Trace,
        }
    }

    /// Reads a level back out of a `log` record.
    #[must_use]
    pub const fn of(record: log::Level) -> Self {
        match record {
            log::Level::Error => Self::Error,
            log::Level::Warn => Self::Warn,
            log::Level::Info => Self::Info,
            log::Level::Debug => Self::Debug,
            log::Level::Trace => Self::Trace,
        }
    }

    /// Stored as a number so the installed logger can change level without a
    /// lock and without a restart.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }

    /// The level a stored number stands for.
    ///
    /// A number nobody assigned reads back as the default rather than as a
    /// panic, because this runs on the logging path.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Error,
            1 => Self::Warn,
            3 => Self::Debug,
            4 => Self::Trace,
            _ => Self::Info,
        }
    }
}
