// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The UDP session table.
//!
//! UDP has no connection and no close, so a datagram arriving from a client
//! carries nothing that says which member answered the last one. The table
//! remembers, and each session holds its own socket to that member, because
//! a datagram coming back names only the member it came from (ADR-0066).
//!
//! # Why losing an entry is safe
//!
//! The table is an accelerator, never the source of truth. A member is
//! chosen by consistent hashing over the client's address and port, so a
//! client whose entry was evicted, expired, or lost to a restart lands on
//! the same member as long as the pool has not changed (ADR-0025). That is
//! what makes eviction safe, and it is why reaching the limit drops the
//! least recently used session rather than refusing the new client.
//!
//! # What the limit bounds
//!
//! Sessions, and through them file descriptors: one socket each. The limit
//! is per frontend, because a DNS service and a syslog service see very
//! different numbers of clients.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Sessions a frontend keeps when its configuration names no limit.
///
/// Measured rather than guessed. `crates/ek-ek-dataplane/tests/udp_memory.rs`
/// counts every allocation a full table makes and reports 254 bytes an entry,
/// so 16384 sessions cost about 4.2 MB per frontend. Each session also holds
/// one socket, and 16384 descriptors sits under the 65536 a service unit can
/// raise `LimitNOFILE` to without special privileges.
pub const DEFAULT_SESSION_LIMIT: u32 = 16_384;

/// How long a session may sit idle when its frontend names no timeout.
///
/// Long enough for a client that queries once a minute to keep its entry,
/// short enough that a table of one-shot clients empties on its own instead
/// of waiting for eviction.
pub const DEFAULT_IDLE_SECONDS: u32 = 120;

/// What one client is pinned to.
#[derive(Debug)]
pub struct Session<S> {
    /// The pool the client was sent to.
    pub pool: String,
    /// The member inside that pool.
    pub member: String,
    /// Where that member listens.
    pub address: SocketAddr,
    /// The socket connected to it, which is what tells one client's answers
    /// from another's.
    pub socket: S,
    /// When this session last carried a datagram, in either direction.
    used: Instant,
    /// Where this session sits in the use order.
    ///
    /// A counter rather than a timestamp: two datagrams in the same
    /// microsecond would otherwise be indistinguishable, and eviction would
    /// then depend on map order.
    rank: u64,
}

impl<S> Session<S> {
    /// How long this session has been idle, as of `now`.
    #[must_use]
    pub fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.used)
    }
}

/// One frontend's sessions, bounded and ordered by use.
#[derive(Debug)]
pub struct Sessions<S> {
    entries: HashMap<SocketAddr, Session<S>>,
    limit: usize,
    idle: Duration,
    /// Next rank to hand out. Monotonic, so the smallest rank in the table is
    /// always the least recently used session.
    next: u64,
    /// How many sessions have been evicted for want of room.
    evicted: u64,
    /// How many sessions have been dropped for sitting idle.
    expired: u64,
}

impl<S> Sessions<S> {
    /// Builds a table from a frontend's settings.
    ///
    /// Zero means the default for both, which is what an operator who set
    /// neither gets (ADR-0066).
    #[must_use]
    pub fn new(limit: u32, idle_seconds: u32) -> Self {
        let (limit, idle) = Self::settings(limit, idle_seconds);
        Self {
            entries: HashMap::new(),
            limit,
            idle,
            next: 0,
            evicted: 0,
            expired: 0,
        }
    }

    /// Turns a frontend's two numbers into the settings a table runs with.
    fn settings(limit: u32, idle_seconds: u32) -> (usize, Duration) {
        let limit = if limit == 0 {
            DEFAULT_SESSION_LIMIT
        } else {
            limit
        };
        let idle_seconds = if idle_seconds == 0 {
            DEFAULT_IDLE_SECONDS
        } else {
            idle_seconds
        };
        (limit as usize, Duration::from_secs(u64::from(idle_seconds)))
    }

    /// How many sessions the table holds right now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The most sessions this table will hold.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// How long a session may sit idle here.
    #[must_use]
    pub fn idle_limit(&self) -> Duration {
        self.idle
    }

    /// Applies settings from a configuration that has changed.
    ///
    /// A lowered limit is honoured by evicting down to it rather than by
    /// waiting for the next insert, so an operator who lowers it sees the
    /// table shrink. Returns what was evicted, because each entry owns a
    /// socket the caller has to close.
    pub fn retune(&mut self, limit: u32, idle_seconds: u32) -> Vec<Session<S>> {
        let settings = Self::settings(limit, idle_seconds);
        self.limit = settings.0;
        self.idle = settings.1;

        let mut evicted = Vec::new();
        while self.entries.len() > self.limit {
            match self.evict_least_used() {
                Some(session) => evicted.push(session),
                None => break,
            }
        }
        evicted
    }

    /// How many sessions have been evicted for want of room.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// How many sessions have been dropped for sitting idle.
    #[must_use]
    pub fn expired(&self) -> u64 {
        self.expired
    }

    /// Returns the session a client already has, refreshing its place in the
    /// use order.
    pub fn refresh(&mut self, client: SocketAddr, now: Instant) -> Option<&mut Session<S>> {
        let rank = self.next;
        let entry = self.entries.get_mut(&client)?;
        entry.used = now;
        entry.rank = rank;
        self.next += 1;
        Some(entry)
    }

    /// Puts a session in, making room first when the table is full.
    ///
    /// Returns whatever was evicted, so the caller can close its socket
    /// rather than leaving the descriptor to a drop it cannot see.
    pub fn insert(
        &mut self,
        client: SocketAddr,
        pool: String,
        member: String,
        address: SocketAddr,
        socket: S,
        now: Instant,
    ) -> Option<Session<S>> {
        // Room is made before the insert, not after, so the table never
        // holds more than its limit even for an instant.
        let evicted = if self.entries.len() >= self.limit && !self.entries.contains_key(&client) {
            self.evict_least_used()
        } else {
            None
        };

        let rank = self.next;
        self.next += 1;
        self.entries.insert(
            client,
            Session {
                pool,
                member,
                address,
                socket,
                used: now,
                rank,
            },
        );
        evicted
    }

    /// Drops the session a client holds, if any.
    pub fn remove(&mut self, client: SocketAddr) -> Option<Session<S>> {
        self.entries.remove(&client)
    }

    /// Drops every session that has been idle too long.
    ///
    /// Returns them, because each one owns a socket the caller has to close.
    pub fn expire(&mut self, now: Instant) -> Vec<Session<S>> {
        let idle = self.idle;
        let stale: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|(_, session)| session.idle_for(now) >= idle)
            .map(|(client, _)| *client)
            .collect();

        let mut dropped = Vec::with_capacity(stale.len());
        for client in stale {
            if let Some(session) = self.entries.remove(&client) {
                self.expired += 1;
                dropped.push(session);
            }
        }
        dropped
    }

    /// Empties the table, returning everything that was in it.
    ///
    /// Used when a frontend drains, and by the tests that prove the table is
    /// only an accelerator: emptying it must not change where a client goes.
    pub fn clear(&mut self) -> Vec<Session<S>> {
        self.entries.drain().map(|(_, session)| session).collect()
    }

    /// Drops every session pinned to a member that is no longer there.
    ///
    /// Returns them so their sockets close. A session whose member left has
    /// to be recomputed; leaving it would keep sending to an address the
    /// configuration no longer names.
    pub fn retain_members(&mut self, exists: impl Fn(&str, &str) -> bool) -> Vec<Session<S>> {
        let gone: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|(_, session)| !exists(&session.pool, &session.member))
            .map(|(client, _)| *client)
            .collect();

        let mut dropped = Vec::with_capacity(gone.len());
        for client in gone {
            if let Some(session) = self.entries.remove(&client) {
                dropped.push(session);
            }
        }
        dropped
    }

    /// Removes the session used longest ago.
    fn evict_least_used(&mut self) -> Option<Session<S>> {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(client, session)| (session.rank, **client))
            .map(|(client, _)| *client)?;
        let session = self.entries.remove(&oldest)?;
        self.evicted += 1;
        Some(session)
    }
}

/// What one session's own structure costs, in bytes.
///
/// This counts the entry and its key, not the strings they point at. The
/// figure the default limit is derived from comes from
/// `crates/ek-ek-dataplane/tests/udp_memory.rs`, which counts every
/// allocation a full table makes; this function is the floor under it.
#[must_use]
pub fn session_memory<S>() -> usize {
    size_of::<Session<S>>() + size_of::<SocketAddr>()
}
