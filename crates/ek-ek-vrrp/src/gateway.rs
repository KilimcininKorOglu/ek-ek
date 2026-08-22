// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Whether this node can still reach the way out, and what to do when it
//! cannot.
//!
//! A node cut off from its gateway carries the virtual address to nowhere:
//! clients reach it and their traffic stops there. Unicast VRRP cannot see
//! this, because the peers are on the same segment and still answer (R-02).
//! So the node asks the gateway directly, and gives the address up when the
//! answer stops coming (ADR-0030).
//!
//! # Why nothing here opens a socket
//!
//! The same reason the state machine does not. This reads no clock and sends
//! nothing: it is told the moment, it says what to send and what to do about
//! the answer. That is what lets a measurement stand either side of a
//! threshold without waiting out three intervals of real time.
//!
//! # Why a node that never heard an answer never gives up the address
//!
//! ICMP is blocked outright in some networks. A node that lowered its
//! priority there would do so on the first check, and so would every other
//! node, and the address would move for a fault that does not exist. So the
//! check counts nothing until the gateway has answered at least once. Until
//! then the state is [`Health::Unconfirmed`], which is reported rather than
//! passed over in silence.

use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How often the gateway is asked, by default.
///
/// Longer than the advertisement interval on purpose (ADR-0029, ADR-0030):
/// the check is about an uplink that is either there or not, and asking more
/// often than the protocol advertises would add traffic that answers nothing.
pub const INTERVAL: Duration = Duration::from_secs(2);

/// How many answers have to go missing in a row before the node stands down.
///
/// One lost packet is not a lost uplink. Three at two second intervals is
/// about six seconds, after which the takeover costs one more second.
pub const THRESHOLD: u32 = 3;

/// Where the gateway check stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// The machine has no default route, so there is nothing to ask.
    NoGateway,
    /// The gateway has never answered, so nothing is counted against it yet.
    Unconfirmed,
    /// The gateway answered the last question.
    Reachable,
    /// The gateway answered before and has now missed the threshold.
    Lost,
}

impl Health {
    /// The name this state is written under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoGateway => "no_gateway",
            Self::Unconfirmed => "unconfirmed",
            Self::Reachable => "reachable",
            Self::Lost => "lost",
        }
    }
}

/// What the caller has to do about the virtual router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Lower this node's claim, so a node that still has a way out takes over.
    Demote,
    /// Put the claim back where the configuration had it.
    Restore,
}

/// The gateway check on one node.
pub struct Watch {
    gateway: Option<IpAddr>,
    interval: Duration,
    threshold: u32,
    /// Whether the gateway has ever answered.
    answered_once: bool,
    /// How many answers have gone missing since the last one that arrived.
    missing: u32,
    /// Whether the claim is currently lowered.
    lowered: bool,
    /// When the next question is due.
    due_at: Option<Instant>,
}

impl Watch {
    /// A check on one gateway, or on nothing when the machine has no default
    /// route.
    #[must_use]
    pub const fn new(gateway: Option<IpAddr>, interval: Duration, threshold: u32) -> Self {
        Self {
            gateway,
            interval,
            threshold,
            answered_once: false,
            missing: 0,
            lowered: false,
            due_at: None,
        }
    }

    /// Where the check stands.
    #[must_use]
    pub const fn health(&self) -> Health {
        if self.gateway.is_none() {
            return Health::NoGateway;
        }
        if !self.answered_once {
            return Health::Unconfirmed;
        }
        if self.lowered {
            return Health::Lost;
        }
        Health::Reachable
    }

    /// The gateway being watched, when there is one.
    #[must_use]
    pub const fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }

    /// How many answers have gone missing since the last one that arrived.
    #[must_use]
    pub const fn missing(&self) -> u32 {
        self.missing
    }

    /// The address to ask, when a question is due.
    ///
    /// Returns nothing when the interval has not elapsed and when there is no
    /// gateway to ask. Asking schedules the next question, so a caller that
    /// calls this every millisecond still sends one packet per interval.
    pub fn due(&mut self, now: Instant) -> Option<IpAddr> {
        let gateway = self.gateway?;
        match self.due_at {
            // The first question goes out at once. Waiting an interval would
            // leave a node that started without an uplink holding the address
            // for that long with nothing measured.
            None => {
                self.due_at = Some(now + self.interval);
                Some(gateway)
            }
            Some(due) if now >= due => {
                self.due_at = Some(now + self.interval);
                Some(gateway)
            }
            Some(_) => None,
        }
    }

    /// Takes an answer that arrived.
    ///
    /// Returns [`Effect::Restore`] when this ends a spell of silence that had
    /// already lowered the claim.
    pub fn answered(&mut self) -> Option<Effect> {
        self.answered_once = true;
        self.missing = 0;
        if self.lowered {
            self.lowered = false;
            return Some(Effect::Restore);
        }
        None
    }

    /// Takes a question that went unanswered.
    ///
    /// Returns [`Effect::Demote`] on the one that reaches the threshold, and
    /// nothing on the ones before it and after it. A caller that acted on
    /// every missed answer would lower the claim it has already lowered.
    pub fn missed(&mut self) -> Option<Effect> {
        // Nothing is counted until the gateway has answered once, so a
        // network that blocks ICMP outright never moves the address.
        if self.gateway.is_none() || !self.answered_once {
            return None;
        }
        self.missing = self.missing.saturating_add(1);
        if self.lowered || self.missing < self.threshold {
            return None;
        }
        self.lowered = true;
        Some(Effect::Demote)
    }
}
