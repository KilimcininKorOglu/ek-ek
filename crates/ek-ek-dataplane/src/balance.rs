// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Choosing which member of a pool answers a request.
//!
//! Every algorithm here is a pure decision over a pool, a client address and a
//! count of open connections. Nothing reaches the network, so the shares an
//! algorithm produces are measured directly rather than inferred from traffic.
//!
//! # Who is eligible
//!
//! Only a member an operator has enabled and health checking has not taken out
//! takes a new request. A draining member keeps the connections it has and
//! receives no more, and a disabled member receives nothing at all. When that
//! leaves nobody, the pool sends nothing and the caller answers rather than
//! forwarding to a member known to be down (ADR-0062).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ek_ek_config::{AdminState, Backend, BackendMember, LoadBalancingAlgorithm};
use ek_ek_ipc::OpenConnections;

use crate::hashring::{HashRing, hash};
use crate::health::Health;

/// Identifies where a connection came from and where it went, for counting
/// open connections (ADR-0061).
///
/// The frontend is in the key because the same pool can be published from two
/// of them, and an operator looking at a busy member needs to know which
/// published service is filling it.
type MemberKey = (String, String, String);

/// Picks members and remembers how many connections each one is carrying.
///
/// The counts live here rather than in the configuration, because they are
/// what this process is doing right now and a configuration change must not
/// reset them.
#[derive(Debug, Default)]
pub struct Balancer {
    /// Where round robin left off. One counter for the whole process is
    /// enough: it only has to advance, not to be fair between pools.
    cursor: AtomicU64,
    /// Open connections per member.
    open: Mutex<BTreeMap<MemberKey, u64>>,
    /// What health checking has decided (T-021).
    health: Arc<Health>,
}

/// The members a pool can currently send to.
///
/// Two things take a member out: an operator disabling it, and health checking
/// deciding it is not answering. They are the same to the caller, so they are
/// filtered in one place. A pool where that leaves nobody sends nothing, and
/// the caller answers rather than forwarding to a member known to be down
/// (ADR-0062).
fn eligible<'a>(pool: &'a Backend, health: &Health) -> Vec<&'a BackendMember> {
    enabled(pool)
        .into_iter()
        .filter(|member| health.is_healthy(pool.id.as_str(), member.id.as_str()))
        .collect()
}

/// The members an operator has left in service, in configuration order.
///
/// This is the list the consistent hashing ring is built from, so an index
/// the ring returns addresses this list and no other.
fn enabled(pool: &Backend) -> Vec<&BackendMember> {
    pool.members
        .iter()
        .filter(|member| member.admin_state == AdminState::Enabled)
        .collect()
}

/// Expands a member list by weight, so a heavier member appears more often.
fn by_weight<'a>(members: &[&'a BackendMember]) -> Vec<&'a BackendMember> {
    let mut spread = Vec::new();
    for member in members {
        // A weight of zero would make a member unreachable while still
        // looking configured. One share is the floor.
        let share = member.weight.max(1);
        for _ in 0..share {
            spread.push(*member);
        }
    }
    spread
}

impl Balancer {
    /// Starts with nothing open and the walk at the beginning.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts with an existing health table, shared with the checker.
    #[must_use]
    pub fn with_health(health: Arc<Health>) -> Self {
        Self {
            health,
            ..Self::default()
        }
    }

    /// Returns the health table this balancer consults.
    #[must_use]
    pub fn health(&self) -> Arc<Health> {
        Arc::clone(&self.health)
    }

    /// The members of a pool that can take a request right now.
    ///
    /// Session stickiness needs this list rather than one choice: a cookie
    /// naming a member that cannot take traffic has to be redistributed, and
    /// offering that member for matching would only send the request
    /// somewhere it cannot go.
    #[must_use]
    pub fn eligible<'a>(&self, pool: &'a Backend) -> Vec<&'a BackendMember> {
        eligible(pool, &self.health)
    }

    /// Chooses the member that answers this request.
    ///
    /// Returns `None` when the pool has nobody able to take it, which the
    /// caller turns into an answer rather than a closed connection.
    #[must_use]
    pub fn choose<'a>(
        &self,
        pool: &'a Backend,
        ring: &HashRing,
        client: IpAddr,
    ) -> Option<&'a BackendMember> {
        let members = eligible(pool, &self.health);
        if members.is_empty() {
            return None;
        }

        match pool.algorithm {
            LoadBalancingAlgorithm::RoundRobin => {
                let spread = by_weight(&members);
                let at = self.cursor.fetch_add(1, Ordering::Relaxed);
                spread
                    .get(usize::try_from(at % spread.len() as u64).unwrap_or(0))
                    .copied()
            }
            LoadBalancingAlgorithm::LeastConnections => {
                let open = self.open.lock().ok()?;
                members
                    .iter()
                    .min_by_key(|member| {
                        // Every frontend counts. A member published from two
                        // of them carries both loads, and counting only one
                        // would make it look half as busy as it is.
                        let carried = total_for(&open, pool.id.as_str(), member.id.as_str());
                        // Ties break on identity rather than on list order, so
                        // the answer does not depend on how the pool was typed
                        // in.
                        (carried, member.id.as_str())
                    })
                    .copied()
            }
            LoadBalancingAlgorithm::SourceIpHash => {
                let spread = by_weight(&members);
                let at = hash(client.to_string().as_bytes()) % spread.len() as u64;
                spread.get(usize::try_from(at).unwrap_or(0)).copied()
            }
            LoadBalancingAlgorithm::ConsistentHash => {
                // The ring indexes the administratively enabled members, not
                // the eligible ones: health is left out of it on purpose, so
                // a probe result does not move clients that had no reason to
                // move. That means the index has to be resolved against the
                // same list the ring was built from, and a member that is
                // not eligible is walked past rather than looked up.
                let enabled = enabled(pool);
                let at = ring.pick_where(hash(client.to_string().as_bytes()), |at| {
                    enabled.get(at).is_some_and(|member| {
                        self.health.is_healthy(pool.id.as_str(), member.id.as_str())
                    })
                })?;
                enabled.get(at).copied()
            }
        }
    }

    /// Records that a connection to a member has opened.
    pub fn opened(&self, frontend: &str, pool: &str, member: &str) {
        if let Ok(mut open) = self.open.lock() {
            *open
                .entry((frontend.to_owned(), pool.to_owned(), member.to_owned()))
                .or_insert(0) += 1;
        }
    }

    /// Records that a connection to a member has finished.
    ///
    /// This must run however the connection ended. A count that only comes
    /// down on a clean close leaves a member looking permanently busy, and
    /// least connections then sends it nothing ever again.
    pub fn closed(&self, frontend: &str, pool: &str, member: &str) {
        if let Ok(mut open) = self.open.lock()
            && let Some(count) =
                open.get_mut(&(frontend.to_owned(), pool.to_owned(), member.to_owned()))
        {
            *count = count.saturating_sub(1);
        }
    }

    /// Returns how many connections a member is carrying, across every
    /// frontend it is published from.
    #[must_use]
    pub fn open_connections(&self, pool: &str, member: &str) -> u64 {
        self.open
            .lock()
            .ok()
            .map(|open| total_for(&open, pool, member))
            .unwrap_or(0)
    }

    /// Returns how many connections one frontend has open to one member.
    #[must_use]
    pub fn open_on(&self, frontend: &str, pool: &str, member: &str) -> u64 {
        self.open
            .lock()
            .ok()
            .and_then(|open| {
                open.get(&(frontend.to_owned(), pool.to_owned(), member.to_owned()))
                    .copied()
            })
            .unwrap_or(0)
    }

    /// Reports every member that is carrying something, for the agent
    /// (ADR-0061).
    ///
    /// A member with nothing open is left out rather than reported as zero,
    /// so the report does not grow with every pool that has ever existed.
    #[must_use]
    pub fn report(&self) -> Vec<OpenConnections> {
        self.open
            .lock()
            .map(|open| {
                open.iter()
                    .filter(|(_, count)| **count > 0)
                    .map(|((frontend, pool, member), count)| OpenConnections {
                        frontend: frontend.clone(),
                        pool: pool.clone(),
                        member: member.clone(),
                        count: *count,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Adds up what one member carries across every frontend.
fn total_for(open: &BTreeMap<MemberKey, u64>, pool: &str, member: &str) -> u64 {
    open.iter()
        .filter(|((_, at_pool, at_member), _)| at_pool == pool && at_member == member)
        .map(|(_, count)| *count)
        .sum()
}

/// Builds the ring a pool's consistent hashing walks.
///
/// Only the eligible members go on it, so disabling a member redistributes its
/// share and leaves everybody else where they were.
#[must_use]
pub fn ring_for(pool: &Backend) -> HashRing {
    // Built from the administrative state only. Health changes far more often
    // than configuration, and rebuilding the ring on every probe would move
    // clients that had no reason to move.
    let members = enabled(pool);
    let identities: Vec<&str> = members.iter().map(|member| member.id.as_str()).collect();
    HashRing::build(&identities)
}
