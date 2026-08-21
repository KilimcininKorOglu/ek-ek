// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The configuration the traffic path is serving right now.
//!
//! Swapping it is one atomic pointer store. A request in flight holds the
//! snapshot it started with and finishes on it, so a change never rewrites
//! what a half-finished request is doing and never closes a connection
//! (ADR-0009).
//!
//! There is no half-applied state to observe, because there is no partial
//! update: a delivery replaces the whole thing or nothing at all.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use arc_swap::ArcSwap;
use ek_ek_config::{Config, ValidationErrors, validate};
use ek_ek_ipc::{ConfigUpdate, Counters, DataPlaneState, StatusReport};

/// A configuration together with the delivery it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Live {
    /// Which delivery this is.
    pub generation: u64,
    /// What to serve.
    pub config: Config,
}

/// Holds the live configuration and swaps it atomically.
#[derive(Debug)]
pub struct LiveConfig(ArcSwap<Live>);

impl LiveConfig {
    /// Starts from a delivery that has already been checked.
    #[must_use]
    pub fn new(update: ConfigUpdate) -> Self {
        Self(ArcSwap::from_pointee(Live {
            generation: update.generation,
            config: update.config,
        }))
    }

    /// Takes the snapshot to serve one request from.
    ///
    /// Read this once per request. Reading it twice within one request would
    /// let a swap land in between and serve the first half of the request on
    /// one configuration and the second half on another.
    #[must_use]
    pub fn load(&self) -> Arc<Live> {
        self.0.load_full()
    }

    /// Returns the generation being served.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.0.load().generation
    }

    /// Checks a delivery and swaps it in.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the delivery. The live configuration is
    /// untouched in that case, so a bad delivery costs nothing.
    pub fn apply(&self, update: ConfigUpdate) -> Result<(), ValidationErrors> {
        validate(&update.config)?;
        self.0.store(Arc::new(Live {
            generation: update.generation,
            config: update.config,
        }));
        Ok(())
    }
}

/// What this process reports about itself.
#[derive(Debug, Default)]
pub struct Status {
    state: AtomicU8,
    requests_handled: AtomicU64,
    configs_applied: AtomicU64,
    configs_rejected: AtomicU64,
}

impl Status {
    /// Starts a status that reports [`DataPlaneState::Starting`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what this process is doing.
    pub fn set_state(&self, state: DataPlaneState) {
        let code = match state {
            DataPlaneState::Starting => 0,
            DataPlaneState::Serving => 1,
            DataPlaneState::Degraded => 2,
        };
        self.state.store(code, Ordering::Relaxed);
    }

    /// Returns what this process is doing.
    #[must_use]
    pub fn state(&self) -> DataPlaneState {
        match self.state.load(Ordering::Relaxed) {
            1 => DataPlaneState::Serving,
            2 => DataPlaneState::Degraded,
            _ => DataPlaneState::Starting,
        }
    }

    /// Counts one answered request.
    pub fn request_handled(&self) {
        self.requests_handled.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one applied configuration.
    pub fn config_applied(&self) {
        self.configs_applied.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one refused configuration.
    pub fn config_rejected(&self) {
        self.configs_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Reads the counters.
    #[must_use]
    pub fn counters(&self) -> Counters {
        Counters {
            requests_handled: self.requests_handled.load(Ordering::Relaxed),
            configs_applied: self.configs_applied.load(Ordering::Relaxed),
            configs_rejected: self.configs_rejected.load(Ordering::Relaxed),
        }
    }

    /// Builds the report sent to the agent.
    #[must_use]
    pub fn report(&self, generation: u64) -> StatusReport {
        StatusReport {
            generation,
            state: self.state(),
            counters: self.counters(),
        }
    }
}
