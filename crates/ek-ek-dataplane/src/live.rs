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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use std::sync::Mutex;

use arc_swap::{ArcSwap, ArcSwapOption};
use ek_ek_config::{Config, ValidationErrors, validate};
use ek_ek_ipc::{ConfigUpdate, Counters, DataPlaneState, StatusReport, UdpSessions};

use crate::balance::{Balancer, ring_for};
use crate::certs::Certificates;
use crate::hashring::HashRing;

/// A configuration together with the delivery it came from.
#[derive(Debug)]
pub struct Live {
    /// Which delivery this is.
    pub generation: u64,
    /// What to serve.
    pub config: Config,
    /// One consistent hashing ring per pool, keyed by pool identity.
    ///
    /// Built here rather than per request, because building a ring walks
    /// every member 160 times. It swaps together with the configuration it
    /// belongs to, so a request never reads a ring built from a different
    /// member list than the one it is choosing from.
    pub rings: BTreeMap<String, HashRing>,
    /// The certificates every TLS frontend can serve, already parsed.
    ///
    /// Parsed here rather than per handshake, and swapped together with the
    /// configuration that references them, so a handshake never reads a new
    /// configuration against an old certificate set (ADR-0068).
    pub certificates: Arc<Certificates>,
}

impl Live {
    /// Builds the rings and certificates that go with a configuration.
    fn build(update: ConfigUpdate) -> Self {
        let rings = update
            .config
            .backends
            .iter()
            .map(|pool| (pool.id.as_str().to_owned(), ring_for(pool)))
            .collect();
        let certificates = Arc::new(Certificates::build(&update.config, &update.certificates));
        Self {
            generation: update.generation,
            config: update.config,
            rings,
            certificates,
        }
    }

    /// Returns the ring of a pool, or an empty one when the pool is unknown.
    #[must_use]
    pub fn ring(&self, pool: &str) -> HashRing {
        self.rings.get(pool).cloned().unwrap_or_default()
    }
}

/// Holds the live configuration and swaps it atomically.
#[derive(Debug)]
pub struct LiveConfig(ArcSwap<Live>);

impl LiveConfig {
    /// Starts from a delivery that has already been checked.
    #[must_use]
    pub fn new(update: ConfigUpdate) -> Self {
        Self(ArcSwap::from_pointee(Live::build(update)))
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
        self.0.store(Arc::new(Live::build(update)));
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
    backend_connect_failures: AtomicU64,
    tls_handshakes_refused: AtomicU64,
    proxy_headers_without_an_address: AtomicU64,
    /// Where the open connection counts are read from (ADR-0061).
    ///
    /// Attached after the balancer exists rather than owned, because the
    /// counts belong to the traffic path and the status only reports them.
    balancer: ArcSwapOption<Balancer>,
    /// One entry per UDP frontend, holding how full its session table is
    /// (ADR-0066).
    ///
    /// The frontend registers its own entry when it starts, so the status
    /// never has to know which frontends exist.
    udp: Mutex<BTreeMap<String, Arc<UdpStats>>>,
}

/// How full one UDP frontend's session table is.
///
/// The live count is written by the frontend's own loop and read by the
/// status, so it is atomic rather than locked: a report must never make a
/// datagram wait.
#[derive(Debug)]
pub struct UdpStats {
    sessions: AtomicU64,
    evicted: AtomicU64,
    limit: AtomicU64,
}

impl UdpStats {
    /// Records what the table looks like right now.
    pub fn set(&self, sessions: u64, evicted: u64) {
        self.sessions.store(sessions, Ordering::Relaxed);
        self.evicted.store(evicted, Ordering::Relaxed);
    }

    /// How many sessions the table holds.
    #[must_use]
    pub fn sessions(&self) -> u64 {
        self.sessions.load(Ordering::Relaxed)
    }

    /// How many sessions have been evicted for want of room.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    /// Records the limit the table is running with.
    ///
    /// A configuration change can move it, so it is written rather than
    /// fixed when the frontend registers.
    pub fn set_limit(&self, limit: u64) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    /// The most sessions the table will hold.
    #[must_use]
    pub fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }
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

    /// Counts one backend connection that could not be opened.
    pub fn backend_connect_failed(&self) {
        self.backend_connect_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a handshake refused for want of a certificate (ADR-0070).
    pub fn tls_handshake_refused(&self) {
        self.tls_handshakes_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns how many handshakes have been refused.
    #[must_use]
    pub fn tls_handshakes_refused(&self) -> u64 {
        self.tls_handshakes_refused.load(Ordering::Relaxed)
    }

    /// Counts one PROXY header that had to be sent without an address in it
    /// (ADR-0043).
    pub fn proxy_header_without_an_address(&self) {
        self.proxy_headers_without_an_address
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Returns how many PROXY headers went out stating no address.
    #[must_use]
    pub fn proxy_headers_without_an_address(&self) -> u64 {
        self.proxy_headers_without_an_address
            .load(Ordering::Relaxed)
    }

    /// Reads the counters.
    #[must_use]
    pub fn counters(&self) -> Counters {
        Counters {
            requests_handled: self.requests_handled.load(Ordering::Relaxed),
            configs_applied: self.configs_applied.load(Ordering::Relaxed),
            configs_rejected: self.configs_rejected.load(Ordering::Relaxed),
            backend_connect_failures: self.backend_connect_failures.load(Ordering::Relaxed),
            udp_sessions_evicted: self.udp_evicted(),
            tls_handshakes_refused: self.tls_handshakes_refused.load(Ordering::Relaxed),
            proxy_headers_without_an_address: self
                .proxy_headers_without_an_address
                .load(Ordering::Relaxed),
        }
    }

    /// Points the status at the balancer whose counts it reports.
    pub fn watch(&self, balancer: Arc<Balancer>) {
        self.balancer.store(Some(balancer));
    }

    /// Registers a UDP frontend and returns where it writes its counts.
    ///
    /// Registering replaces any earlier entry for the same frontend, so a
    /// restarted listener reports its own table rather than adding a second
    /// row for the same name.
    pub fn udp_frontend(&self, frontend: &str, limit: usize) -> Arc<UdpStats> {
        let stats = Arc::new(UdpStats {
            sessions: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            limit: AtomicU64::new(limit as u64),
        });
        if let Ok(mut table) = self.udp.lock() {
            table.insert(frontend.to_owned(), Arc::clone(&stats));
        }
        stats
    }

    /// What every UDP frontend's session table looks like right now.
    #[must_use]
    pub fn udp_sessions(&self) -> Vec<UdpSessions> {
        self.udp.lock().map_or_else(
            |_| Vec::new(),
            |table| {
                table
                    .iter()
                    .map(|(frontend, stats)| UdpSessions {
                        frontend: frontend.clone(),
                        count: stats.sessions(),
                        limit: stats.limit(),
                    })
                    .collect()
            },
        )
    }

    /// How many UDP sessions have been evicted across every frontend.
    fn udp_evicted(&self) -> u64 {
        self.udp
            .lock()
            .map_or(0, |table| table.values().map(|stats| stats.evicted()).sum())
    }

    /// Builds the report sent to the agent.
    #[must_use]
    pub fn report(&self, generation: u64) -> StatusReport {
        StatusReport {
            generation,
            state: self.state(),
            counters: self.counters(),
            open_connections: self
                .balancer
                .load()
                .as_ref()
                .map(|balancer| balancer.report())
                .unwrap_or_default(),
            member_health: self
                .balancer
                .load()
                .as_ref()
                .map(|balancer| balancer.health().report())
                .unwrap_or_default(),
            udp_sessions: self.udp_sessions(),
        }
    }
}
