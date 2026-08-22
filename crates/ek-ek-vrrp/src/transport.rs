// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How advertisements leave and arrive.
//!
//! Kept behind a trait so the state machine can be measured without a raw
//! socket and without privilege. The socket needs `CAP_NET_RAW` and IP
//! protocol 112, neither of which exists on a developer's machine, and a
//! state machine that could only be measured on the target would not be
//! measured often enough (ADR-0007).

use std::net::Ipv4Addr;

/// Carries advertisements between nodes.
pub trait Transport {
    /// What went wrong.
    ///
    /// Printable, because the only thing a caller can do about a socket that
    /// failed is say so. An error nobody can write down leaves an operator
    /// with a virtual router that stopped and no reason.
    type Error: std::fmt::Display;

    /// Sends bytes to one peer.
    ///
    /// One call per peer, because a VRRPv3 checksum covers the destination
    /// and the same bytes are refused by a second peer.
    ///
    /// # Errors
    ///
    /// Returns whatever the underlying socket reports.
    fn send(&self, to: Ipv4Addr, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Takes the next packet that arrived, if one has.
    ///
    /// Returns nothing when there is nothing waiting, so the caller's loop
    /// can go on to its timers rather than block on a quiet segment.
    ///
    /// # Errors
    ///
    /// Returns whatever the underlying socket reports.
    fn receive(&self) -> Result<Option<(Ipv4Addr, Vec<u8>)>, Self::Error>;
}
