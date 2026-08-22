// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How many requests one backend pool carries at once.
//!
//! pingora keeps its own pool of idle connections, but that pool is one per
//! process and it evicts rather than waits. A limit an operator sets on a
//! backend pool has to mean something else: this many requests in flight to
//! this pool, and the next one waits for a slot (ADR-0045).
//!
//! # Why waiting and not refusing
//!
//! A burst that outruns the limit is a queue, not a failure. Answering it
//! with an error would turn a busy second into an outage the client sees,
//! and the request would have been servable a moment later.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ek_ek_config::{Backend, ConnectionPooling};
use tokio::sync::Semaphore;

/// A slot held for as long as a request is in flight.
pub type Slot = tokio::sync::OwnedSemaphorePermit;

/// One gate per backend pool, kept across configuration swaps.
///
/// The gates outlive a swap because the requests they hold do. Rebuilding
/// them per delivery would hand out a fresh set of slots to a pool that was
/// already full and let the limit be exceeded exactly when it matters.
#[derive(Debug, Default)]
pub struct Gates {
    /// Pool identity to the size it was built for and its gate.
    ///
    /// The size is kept so a delivery that changes it is noticed. Reading it
    /// back from the semaphore would not work: permits in use are gone from
    /// the count.
    gates: Mutex<HashMap<String, (u32, Arc<Semaphore>)>>,
}

impl Gates {
    /// An empty set of gates.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The gate for a pool, built on first use.
    ///
    /// Returns nothing when the pool names no limit, so an unlimited pool
    /// costs no lock and no permit.
    ///
    /// A size a delivery changed replaces the gate. Requests already holding
    /// a slot keep it and finish under the old limit, which is why the old
    /// gate is dropped rather than resized: a slot outliving its gate is
    /// still a slot, and the count it belonged to is gone with it.
    #[must_use]
    pub fn gate(&self, pool: &str, size: u32) -> Option<Arc<Semaphore>> {
        if size == 0 {
            return None;
        }
        let mut gates = self.gates.lock().ok()?;
        if let Some((built_for, gate)) = gates.get(pool)
            && *built_for == size
        {
            return Some(Arc::clone(gate));
        }
        let gate = Arc::new(Semaphore::new(size as usize));
        gates.insert(pool.to_owned(), (size, Arc::clone(&gate)));
        Some(gate)
    }

    /// How many slots a pool has free right now.
    ///
    /// Reported for tests rather than for the product: a gate nobody has
    /// taken a slot from cannot be told from one that does not exist.
    #[must_use]
    pub fn free(&self, pool: &str) -> Option<usize> {
        let gates = self.gates.lock().ok()?;
        gates.get(pool).map(|(_, gate)| gate.available_permits())
    }
}

/// Waits for a slot in a pool's gate.
///
/// Returns nothing when the pool is unlimited, and nothing when the gate was
/// closed. A closed gate means the process is shutting down; the request goes
/// on rather than being refused, because a limit is not worth failing a
/// request that is already being served.
pub async fn slot(gate: Option<Arc<Semaphore>>) -> Option<Slot> {
    gate?.acquire_owned().await.ok()
}

/// The reuse group a request to this pool belongs to.
///
/// A pool that does not reuse connections gets a group of its own for every
/// request, so pingora never finds one to share. Setting the idle timeout to
/// zero is not enough on its own: the connection still enters the pool and
/// the next request can take it before the timeout removes it, which is a
/// race a busy path wins every time.
#[must_use]
pub fn reuse_group(pool: &Backend) -> u64 {
    /// Marks a group that belongs to one request and nothing else. Elapsed
    /// seconds divided by a lifetime never reach this, so a group counted
    /// from the clock and one counted per request cannot collide.
    const NEVER_SHARED: u64 = 1 << 63;
    /// Numbers the groups handed to requests that must not share.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    if pool.connection_pooling == ConnectionPooling::Disabled {
        return NEVER_SHARED | NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    pool.reuse_group(now_seconds())
}

/// Seconds since the epoch, which is what a reuse group is counted in.
///
/// Reads the wall clock rather than a monotonic one on purpose: the group
/// only has to change as time passes, and every request reads it the same
/// way, so a clock that steps costs at most one early retirement.
#[must_use]
pub fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
