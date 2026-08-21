// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Consistent hashing, shared by the HTTP path and the UDP path.
//!
//! The UDP path needs two processes to reach the same member during a graceful
//! upgrade, because a datagram has no connection to pin it (ADR-0025). That is
//! only true if both run the same arithmetic, so the ring lives here rather
//! than inside either path.
//!
//! # Why not the standard hasher
//!
//! `DefaultHasher` is explicitly not stable across releases of the standard
//! library. A client landing on one member before an upgrade and another after
//! it would break exactly the property this exists to provide, so the hash is
//! written out here.

use std::collections::BTreeMap;

/// Virtual points each member takes on the ring.
///
/// Too few and the shares come out uneven; too many and building the ring
/// costs more than it saves. 160 is what leaves a two member ring within a few
/// percent of an even split.
const REPLICAS: u32 = 160;

/// FNV-1a offset basis.
const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a prime.
const PRIME: u64 = 0x0000_0100_0000_01b3;

/// Hashes bytes the same way on every release and every machine.
#[must_use]
pub fn hash(bytes: &[u8]) -> u64 {
    let mut value = OFFSET_BASIS;
    for byte in bytes {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(PRIME);
    }
    value
}

/// A ring of members, where removing one only redistributes its own share.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HashRing {
    /// Ring position to the position of the member in the list it was built
    /// from.
    points: BTreeMap<u64, usize>,
}

impl HashRing {
    /// Builds a ring from member identities, in the order they were given.
    ///
    /// The identity is what places a member on the ring, never its address or
    /// its position in the list. A member that changes address keeps its
    /// clients, and a member added to the front of the list does not move
    /// everybody else.
    #[must_use]
    pub fn build(members: &[&str]) -> Self {
        let mut points = BTreeMap::new();
        for (at, member) in members.iter().enumerate() {
            for replica in 0..REPLICAS {
                let point = hash(format!("{member}#{replica}").as_bytes());
                points.insert(point, at);
            }
        }
        Self { points }
    }

    /// Returns whether the ring has nobody on it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// Picks the member a key belongs to.
    ///
    /// Walks clockwise from the key's position and wraps around at the end,
    /// which is what makes a removal cost only the removed member's share.
    #[must_use]
    pub fn pick(&self, key: u64) -> Option<usize> {
        self.points
            .range(key..)
            .next()
            .or_else(|| self.points.iter().next())
            .map(|(_, at)| *at)
    }
}
