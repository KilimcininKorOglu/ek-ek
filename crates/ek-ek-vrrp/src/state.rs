// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Who holds the virtual router, and when that changes.
//!
//! The machine reads no clock and owns no socket. Every method takes the
//! moment it is called at and returns what to do about it. That is what lets
//! a measurement stand either side of a deadline without waiting for it: the
//! master down interval at the default advertisement interval is over a
//! second, and a test that waited it out would measure the machine it runs on
//! (ADR-0029).
//!
//! # What the machine refuses
//!
//! VRRPv3 carries no authentication, so an advertisement from outside the
//! peer list is the only thing standing between a virtual router and anyone
//! on the segment. Such a packet is counted and dropped (R-02).

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::packet::{Advertisement, GIVING_UP, Malformed};

/// Where the virtual router stands on this node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    /// Nothing has started yet.
    #[default]
    Initialize,
    /// Somebody else holds the role, or nobody has claimed it yet.
    Backup,
    /// This node holds the role and says so.
    Master,
}

impl State {
    /// The name this state is written under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Backup => "backup",
            Self::Master => "master",
        }
    }
}

/// Why a state changed.
///
/// Carried with the transition rather than worked out by whatever writes the
/// record, so two readers cannot disagree about what happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The machine was started.
    Started,
    /// Nobody was heard from within the master down interval.
    NobodyElseAnswered,
    /// A stronger claim arrived.
    StrongerPeer,
    /// The machine was stopped on purpose.
    Stopped,
}

impl Reason {
    /// The name this reason is written under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::NobodyElseAnswered => "nobody_else_answered",
            Self::StrongerPeer => "stronger_peer",
            Self::Stopped => "stopped",
        }
    }
}

/// One state change, ready to be written to the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    /// Where the machine was.
    pub from: State,
    /// Where it is now.
    pub to: State,
    /// What moved it.
    pub reason: Reason,
}

/// Something the caller has to do.
///
/// The machine never sends and never logs. It says what should happen and
/// the caller, which owns the socket and the logger, does it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send this advertisement to every peer.
    Advertise(Advertisement),
    /// Write this state change down.
    Record(Transition),
}

/// Why an advertisement was not acted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    /// The source is not in the peer list.
    UnknownPeer,
    /// The bytes are not an advertisement this product can read.
    Broken(Malformed),
    /// The packet belongs to a different virtual router.
    OtherRouter(u8),
}

/// What a virtual router is set up with.
///
/// Held apart from the machine because these values come from a delivery and
/// the machine's own position does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Which virtual router this is.
    pub vrid: u8,
    /// How strongly this node claims the role.
    pub priority: u8,
    /// How often a master advertises.
    pub interval: Duration,
    /// Whether a stronger node takes the role back when it returns.
    pub preempt: bool,
    /// This node's own address, which decides a tie.
    pub address: Ipv4Addr,
    /// The addresses this virtual router answers for.
    pub virtual_addresses: Vec<Ipv4Addr>,
    /// The only sources an advertisement is accepted from.
    ///
    /// Unicast is not an option here. Multicast leaves the virtual router
    /// open to anyone on the segment, and VRRPv3 has no authentication to
    /// close it (R-02).
    pub peers: Vec<Ipv4Addr>,
}

impl Settings {
    /// The interval in the unit the packet carries it in.
    #[must_use]
    pub const fn interval_centiseconds(&self) -> u16 {
        // Saturating rather than wrapping: an interval nobody can express in
        // twelve bits is clamped to the largest that fits, and the value is
        // refused by validation long before it reaches here.
        let hundredths = self.interval.as_millis() / 10;
        if hundredths > 0x0FFF {
            0x0FFF
        } else {
            hundredths as u16
        }
    }

    /// How long this node waits before it starts its own claim.
    ///
    /// A weaker node waits longer, which is what makes the order of takeover
    /// deterministic without anybody agreeing on it.
    #[must_use]
    pub const fn skew_time(&self) -> Duration {
        let interval = self.interval.as_nanos();
        let share = (256 - self.priority as u128) * interval / 256;
        Duration::from_nanos(share as u64)
    }

    /// How long silence has to last before this node claims the role.
    #[must_use]
    pub const fn master_down_interval(&self) -> Duration {
        Duration::from_nanos(
            (self.interval.as_nanos() * 3) as u64 + self.skew_time().as_nanos() as u64,
        )
    }
}

/// One virtual router on this node.
pub struct Machine {
    settings: Settings,
    state: State,
    /// When the next advertisement is due, while this node is master.
    advertise_at: Option<Instant>,
    /// When silence has lasted long enough to claim the role.
    claim_at: Option<Instant>,
    accepted: u64,
    ignored: u64,
}

impl Machine {
    /// A machine that has not started yet.
    #[must_use]
    pub const fn new(settings: Settings) -> Self {
        Self {
            settings,
            state: State::Initialize,
            advertise_at: None,
            claim_at: None,
            accepted: 0,
            ignored: 0,
        }
    }

    /// Where this node stands.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// What this node was set up with.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// How many advertisements were acted on.
    #[must_use]
    pub const fn accepted(&self) -> u64 {
        self.accepted
    }

    /// How many were dropped.
    #[must_use]
    pub const fn ignored(&self) -> u64 {
        self.ignored
    }

    /// Starts the machine.
    ///
    /// A node whose priority says it owns the addresses claims the role at
    /// once. Every other node waits, because nobody is advertising yet and
    /// there is nothing to hear (T-010).
    pub fn start(&mut self, now: Instant) -> Vec<Action> {
        // 255 is the priority RFC 5798 reserves for the node that owns the
        // addresses. Nothing outranks it, so waiting would only delay it.
        if self.settings.priority == u8::MAX {
            return self.become_master(now, Reason::Started);
        }
        let actions = vec![Action::Record(Transition {
            from: self.state,
            to: State::Backup,
            reason: Reason::Started,
        })];
        self.state = State::Backup;
        self.advertise_at = None;
        // Counted from this moment rather than from a packet, because on a
        // cold start there is no packet. Nodes are separated only by their
        // skew, which is the same order as the spread in process start-up,
        // so a short double master is possible and closes on the first
        // advertisement (T-010).
        self.claim_at = Some(now + self.settings.master_down_interval());
        actions
    }

    /// Moves the machine on to this moment.
    ///
    /// Returns what is due: an advertisement while this node is master, or
    /// the claim once silence has lasted long enough.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        match self.state {
            State::Master => {
                if self.advertise_at.is_some_and(|due| now >= due) {
                    self.advertise_at = Some(now + self.settings.interval);
                    return vec![Action::Advertise(
                        self.advertisement(self.settings.priority),
                    )];
                }
                Vec::new()
            }
            State::Backup => {
                if self.claim_at.is_some_and(|due| now >= due) {
                    return self.become_master(now, Reason::NobodyElseAnswered);
                }
                Vec::new()
            }
            State::Initialize => Vec::new(),
        }
    }

    /// Takes an advertisement that arrived.
    ///
    /// Returns what to do about it, and nothing at all when it is dropped.
    /// Use [`Machine::judge`] when a measurement needs to know why.
    pub fn receive(&mut self, from: Ipv4Addr, bytes: &[u8], now: Instant) -> Vec<Action> {
        self.judge(from, bytes, now).unwrap_or_default()
    }

    /// Takes an advertisement and says why it was dropped, when it was.
    ///
    /// Written apart from [`Machine::receive`] so a measurement can tell a
    /// packet that was refused from one that was acted on with nothing to
    /// do, which look the same from outside.
    ///
    /// # Errors
    ///
    /// Returns [`Ignored`] naming what the packet failed on.
    pub fn judge(
        &mut self,
        from: Ipv4Addr,
        bytes: &[u8],
        now: Instant,
    ) -> Result<Vec<Action>, Ignored> {
        // First, before anything reads the bytes. An address outside the
        // list is the only thing this product checks, so it has to be
        // checked before the packet is trusted enough to parse.
        if !self.settings.peers.contains(&from) {
            self.ignored += 1;
            return Err(Ignored::UnknownPeer);
        }
        // Every address of this router is a possible destination, and the
        // checksum covers the one the sender used. The first that adds up is
        // the one it was sent to.
        let advertisement = self
            .settings
            .virtual_addresses
            .iter()
            .chain(std::iter::once(&self.settings.address))
            .find_map(|to| Advertisement::decode(bytes, from, *to).ok());

        let Some(advertisement) = advertisement else {
            self.ignored += 1;
            // Reported against this node's own address, so the reason names
            // the first thing that failed rather than the last address tried.
            let why = Advertisement::decode(bytes, from, self.settings.address)
                .err()
                .unwrap_or(Malformed::Checksum);
            return Err(Ignored::Broken(why));
        };

        if advertisement.vrid != self.settings.vrid {
            self.ignored += 1;
            return Err(Ignored::OtherRouter(advertisement.vrid));
        }

        self.accepted += 1;
        match self.state {
            State::Master => Ok(self.master_heard(from, &advertisement, now)),
            State::Backup => Ok(self.backup_heard(from, &advertisement, now)),
            State::Initialize => Ok(Vec::new()),
        }
    }

    /// Gives the role up on purpose.
    ///
    /// A master says so with a priority of zero, which lets the next node
    /// wait only its skew time instead of the whole master down interval. A
    /// planned handover then costs a fraction of a failure (T-010).
    pub fn stop(&mut self, _now: Instant) -> Vec<Action> {
        let was = self.state;
        self.state = State::Initialize;
        self.advertise_at = None;
        self.claim_at = None;

        let mut actions = Vec::new();
        if was == State::Master {
            actions.push(Action::Advertise(self.advertisement(GIVING_UP)));
        }
        actions.push(Action::Record(Transition {
            from: was,
            to: State::Initialize,
            reason: Reason::Stopped,
        }));
        actions
    }

    /// What a master does with an advertisement it hears.
    fn master_heard(&mut self, from: Ipv4Addr, heard: &Advertisement, now: Instant) -> Vec<Action> {
        if heard.priority == GIVING_UP {
            // The sender is standing down. Saying so at once shortens the
            // gap for everybody still listening.
            self.advertise_at = Some(now + self.settings.interval);
            return vec![Action::Advertise(
                self.advertisement(self.settings.priority),
            )];
        }
        if self.outranked_by(from, heard.priority) {
            return self.become_backup(now, Reason::StrongerPeer);
        }
        Vec::new()
    }

    /// What a backup does with an advertisement it hears.
    fn backup_heard(&mut self, from: Ipv4Addr, heard: &Advertisement, now: Instant) -> Vec<Action> {
        if heard.priority == GIVING_UP {
            // Only the skew, because the master is leaving rather than gone.
            self.claim_at = Some(now + self.settings.skew_time());
            return Vec::new();
        }
        // With preempt off this node never takes the role from a weaker
        // master, so every advertisement counts as the master being alive.
        // With preempt on, a weaker claim is not a master worth waiting for.
        if !self.settings.preempt || !self.outranks(from, heard.priority) {
            self.claim_at = Some(now + self.settings.master_down_interval());
        }
        Vec::new()
    }

    /// Whether a sender's claim beats this node's.
    ///
    /// The address settles a tie, and the higher one wins. Comparing numbers
    /// rather than drawing lots is what makes two nodes reach the same answer
    /// without talking about it.
    fn outranked_by(&self, from: Ipv4Addr, priority: u8) -> bool {
        priority > self.settings.priority
            || (priority == self.settings.priority && from > self.settings.address)
    }

    /// Whether this node's claim beats a sender's.
    fn outranks(&self, from: Ipv4Addr, priority: u8) -> bool {
        self.settings.priority > priority
            || (priority == self.settings.priority && self.settings.address > from)
    }

    /// Takes the role.
    fn become_master(&mut self, now: Instant, reason: Reason) -> Vec<Action> {
        let from = self.state;
        self.state = State::Master;
        self.claim_at = None;
        self.advertise_at = Some(now + self.settings.interval);
        vec![
            Action::Record(Transition {
                from,
                to: State::Master,
                reason,
            }),
            // Sent before the first interval elapses, so the peers learn who
            // holds the role now rather than one interval from now.
            Action::Advertise(self.advertisement(self.settings.priority)),
        ]
    }

    /// Gives the role up because somebody stronger holds it.
    fn become_backup(&mut self, now: Instant, reason: Reason) -> Vec<Action> {
        let from = self.state;
        self.state = State::Backup;
        self.advertise_at = None;
        self.claim_at = Some(now + self.settings.master_down_interval());
        vec![Action::Record(Transition {
            from,
            to: State::Backup,
            reason,
        })]
    }

    /// The advertisement this node sends, at the priority given.
    fn advertisement(&self, priority: u8) -> Advertisement {
        Advertisement {
            vrid: self.settings.vrid,
            priority,
            interval_centiseconds: self.settings.interval_centiseconds(),
            addresses: self.settings.virtual_addresses.clone(),
        }
    }
}
