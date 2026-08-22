// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the configuration says about logging.
//!
//! The level is named here rather than taken from the logging crate, because
//! the configuration model depends on no other crate in the workspace
//! (ADR-0014). The traffic path maps one to the other, and a test walks every
//! variant so a level added on one side cannot be forgotten on the other.

use serde::{Deserialize, Serialize};

/// How much detail the application log carries (ADR-0037).
///
/// Carried in the configuration rather than in an environment variable, so it
/// changes without restarting the process and so the change is versioned,
/// reversible and visible like every other setting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
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

impl LogLevel {
    /// Every level, so a test can walk them all.
    pub const ALL: [Self; 5] = [
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];
}

/// Whether and how often one frontend writes an access record.
///
/// Set per frontend rather than once for the process, because a high volume
/// published service is exactly the one an operator wants to quiet while the
/// rest keep their records (ADR-0037).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLog {
    /// Whether a record is written at all. On by default, because a fault
    /// with no log means waiting for it to happen again (ADR-0037).
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// One record is written per this many requests. One means every request.
    #[serde(default = "every_request")]
    pub sample_one_in: u32,
}

impl Default for AccessLog {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_one_in: 1,
        }
    }
}

impl AccessLog {
    /// Whether the request numbered this way gets a record.
    ///
    /// Counting rather than drawing at random, so a test measures a rate
    /// exactly and an operator reading a sampled log knows what it means.
    #[must_use]
    pub const fn writes(&self, request_number: u64) -> bool {
        if !self.enabled {
            return false;
        }
        if self.sample_one_in <= 1 {
            return true;
        }
        request_number.is_multiple_of(self.sample_one_in as u64)
    }
}

const fn enabled_by_default() -> bool {
    true
}

const fn every_request() -> u32 {
    1
}
