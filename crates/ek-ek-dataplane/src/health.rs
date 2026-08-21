// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deciding which members are healthy, and keeping that decision current.
//!
//! A probe answers one question: did this member give a good answer just now.
//! This turns a run of such answers into a state, using the thresholds the
//! operator set. That separation is why a single lost packet does not take a
//! member out of service.
//!
//! # Thresholds count consecutively
//!
//! A member goes unhealthy after `unhealthy_threshold` failures in a row and
//! comes back after `healthy_threshold` successes in a row. One good answer
//! resets the failure run and one bad answer resets the success run, so a
//! member that alternates never crosses either threshold.
//!
//! # Everybody starts healthy
//!
//! A member is in rotation until it has actually failed enough times. Starting
//! unhealthy would take a whole pool out of service on every restart and hold
//! it there for at least one interval, which is an outage the product itself
//! caused.
//!
//! # Checks never overlap
//!
//! One task per member runs probe, then wait, then probe again. The wait is
//! the configured interval and the probe is bounded by the configured timeout,
//! which validation keeps at or below the interval. Two probes to the same
//! member can therefore never be in flight together.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use ek_ek_config::{AdminState, Config, HealthCheck};
use ek_ek_ipc::MemberHealth;

use crate::probe;

/// Identifies one member of one pool.
type MemberKey = (String, String);

/// What is known about one member's health.
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    /// Whether it is currently taking traffic.
    healthy: bool,
    /// Consecutive failures since the last success.
    failures: u32,
    /// Consecutive successes since the last failure.
    successes: u32,
    /// How many times it has changed state.
    transitions: u64,
}

impl Default for State {
    fn default() -> Self {
        // Healthy until proven otherwise. Starting unhealthy would empty
        // every pool on restart for at least one interval.
        Self {
            healthy: true,
            failures: 0,
            successes: 0,
            transitions: 0,
        }
    }
}

/// What health checking knows, shared with the traffic path.
///
/// The traffic path reads it on every request and the checker writes it once
/// per probe, so reads are what this is built for.
#[derive(Debug, Default)]
pub struct Health {
    states: Mutex<BTreeMap<MemberKey, State>>,
}

/// What one recorded answer did to a member's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// The state did not change.
    None,
    /// The member left rotation.
    WentUnhealthy,
    /// The member came back into rotation.
    WentHealthy,
}

impl Health {
    /// Starts with nothing known, which means everybody is in rotation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether a member is taking traffic.
    ///
    /// A member nothing is known about is healthy: either its pool has no
    /// health check, or checking has not produced a verdict yet.
    #[must_use]
    pub fn is_healthy(&self, pool: &str, member: &str) -> bool {
        self.states
            .lock()
            .ok()
            .and_then(|states| {
                states
                    .get(&(pool.to_owned(), member.to_owned()))
                    .map(|state| state.healthy)
            })
            .unwrap_or(true)
    }

    /// Records one probe answer and returns what it changed.
    pub fn record(&self, pool: &str, member: &str, check: &HealthCheck, good: bool) -> Change {
        let Ok(mut states) = self.states.lock() else {
            return Change::None;
        };
        let state = states
            .entry((pool.to_owned(), member.to_owned()))
            .or_default();

        if good {
            state.successes = state.successes.saturating_add(1);
            state.failures = 0;
            // Only a member that is out of rotation can come back, and only
            // after enough successes in a row.
            if !state.healthy && state.successes >= u32::from(check.healthy_threshold.max(1)) {
                state.healthy = true;
                state.transitions = state.transitions.saturating_add(1);
                return Change::WentHealthy;
            }
        } else {
            state.failures = state.failures.saturating_add(1);
            state.successes = 0;
            if state.healthy && state.failures >= u32::from(check.unhealthy_threshold.max(1)) {
                state.healthy = false;
                state.transitions = state.transitions.saturating_add(1);
                return Change::WentUnhealthy;
            }
        }

        Change::None
    }

    /// Returns how many consecutive failures a member has recorded.
    #[must_use]
    pub fn failures(&self, pool: &str, member: &str) -> u32 {
        self.states
            .lock()
            .ok()
            .and_then(|states| {
                states
                    .get(&(pool.to_owned(), member.to_owned()))
                    .map(|state| state.failures)
            })
            .unwrap_or(0)
    }

    /// Forgets every member that a configuration no longer has.
    ///
    /// Without this, a member removed and later added back would return with
    /// its old state, which is not what an operator who just re-added it
    /// expects.
    pub fn retain(&self, config: &Config) {
        let mut alive: Vec<MemberKey> = Vec::new();
        for pool in &config.backends {
            if pool.health_check.is_none() {
                continue;
            }
            for member in &pool.members {
                alive.push((pool.id.as_str().to_owned(), member.id.as_str().to_owned()));
            }
        }
        if let Ok(mut states) = self.states.lock() {
            states.retain(|key, _| alive.contains(key));
        }
    }

    /// Builds what the agent is told (ADR-0063).
    ///
    /// Members of a pool with no health check are left out, because health
    /// does not exist there and reporting them as healthy would say something
    /// that was never measured.
    #[must_use]
    pub fn report(&self) -> Vec<MemberHealth> {
        self.states
            .lock()
            .map(|states| {
                states
                    .iter()
                    .map(|((pool, member), state)| MemberHealth {
                        pool: pool.clone(),
                        member: member.clone(),
                        healthy: state.healthy,
                        transitions: state.transitions,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// One member that is being checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    /// The pool it belongs to.
    pub pool: String,
    /// The member itself.
    pub member: String,
    /// Where the probe is sent.
    pub address: std::net::IpAddr,
    /// Which port the probe reaches.
    pub port: u16,
    /// The check to run.
    pub check: HealthCheck,
}

/// Works out what a configuration says to check.
///
/// A pool without a health check produces nothing, and so does a member an
/// operator has disabled: probing a member that is out of service by decision
/// tells nobody anything and still costs a connection on the backend.
#[must_use]
pub fn checked(config: &Config) -> Vec<Checked> {
    let mut all = Vec::new();
    for pool in &config.backends {
        let Some(check) = &pool.health_check else {
            continue;
        };
        for member in &pool.members {
            if member.admin_state == AdminState::Disabled {
                continue;
            }
            all.push(Checked {
                pool: pool.id.as_str().to_owned(),
                member: member.id.as_str().to_owned(),
                address: member.address,
                port: member.port,
                check: check.clone(),
            });
        }
    }
    all
}

/// Runs one member's check until it is told to stop.
///
/// Probe, then wait, then probe again. The probe is bounded by the timeout and
/// the wait is the interval, so two probes to the same member never overlap.
pub async fn watch(
    health: Arc<Health>,
    target: Checked,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let interval = Duration::from_millis(u64::from(target.check.interval_ms.max(1)));
    let timeout = Duration::from_millis(u64::from(target.check.timeout_ms.max(1)));

    loop {
        if *stop.borrow() {
            return;
        }

        let outcome = probe::run(&target.check.probe, target.address, target.port, timeout).await;
        health.record(
            &target.pool,
            &target.member,
            &target.check,
            outcome.is_good(),
        );

        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            _ = stop.changed() => return,
        }
    }
}
