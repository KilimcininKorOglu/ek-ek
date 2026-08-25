// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What supervising `data-plane` decides, with no process anywhere near it.
//!
//! Everything here is told what happened and says what to do about it. It
//! spawns nothing, reads no clock and kills nothing, for the same reason the
//! VRRP state machine does not: a measurement can then stand either side of a
//! threshold without waiting out the real intervals, and the decision is
//! measured apart from the system calls that carry it out.
//!
//! # Why a process that is up is not a process that is serving
//!
//! A crashed thread, a deadlock or a runtime that has stopped polling all
//! leave the process in the table while nothing it does reaches anybody. So
//! the claim is lowered on the answer stopping, not on the process ending,
//! and a process that stops answering is ended and restarted like one that
//! crashed (ADR-0033, ADR-0087).

use std::time::{Duration, Instant};

/// How long to wait before the first restart.
///
/// Short, because the common case is a one-off crash and the node is carrying
/// no traffic until the traffic path is back. A wait long enough to notice
/// would add to an outage that this is trying to end.
pub const FIRST_WAIT: Duration = Duration::from_millis(100);

/// The longest wait between two restarts.
///
/// Thirty seconds. A process that has crashed this many times in a row is not
/// coming back on its own, and restarting it faster only spends the machine
/// on a loop nobody is reading. The node holds no address while this runs, so
/// waiting costs this node's traffic and nothing else (ADR-0033).
pub const LONGEST_WAIT: Duration = Duration::from_secs(30);

/// How many crashes in a row before the alarm state is produced.
///
/// Five. A single crash is an incident; five in a row is a fault an operator
/// has to look at, and the restarts carry on regardless.
pub const ALARM_AFTER: u32 = 5;

/// Whether a report from the traffic path says this node can carry traffic.
///
/// A process that is still starting has a configuration and no listeners yet,
/// so it cannot serve and its report does not count as an answer. The claim
/// stays down until it says otherwise (ADR-0087).
///
/// `Degraded` does count. It means serving with something wrong, and dropping
/// the claim for it would move the address for a backend fault every node can
/// see just as well (ADR-0034).
#[must_use]
pub fn serving(state: ek_ek_ipc::DataPlaneState) -> bool {
    match state {
        ek_ek_ipc::DataPlaneState::Starting => false,
        ek_ek_ipc::DataPlaneState::Serving | ek_ek_ipc::DataPlaneState::Degraded => true,
    }
}

/// How long to wait before restarting after this many crashes in a row.
///
/// The first wait is [`FIRST_WAIT`] and each one after it is twice the one
/// before, up to [`LONGEST_WAIT`]. Crash zero is not a crash, so it waits
/// nothing: that is the start, not a restart.
#[must_use]
pub fn wait_after(crashes: u32) -> Duration {
    if crashes == 0 {
        return Duration::ZERO;
    }
    // Shifting by 32 or more is undefined, and the cap is reached long before
    // then anyway, so the exponent is held where the arithmetic still means
    // something.
    let doublings = (crashes - 1).min(31);
    FIRST_WAIT
        .saturating_mul(2_u32.saturating_pow(doublings))
        .min(LONGEST_WAIT)
}

/// What the caller has to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Lower this node's VRRP claim, so a node that can serve takes over.
    Demote,
    /// Put the claim back where the configuration had it.
    Restore,
    /// End the process. It is up and no longer answering, which is a crash
    /// that has not happened yet.
    Terminate,
    /// Start the process again.
    Start,
    /// Say that the process keeps crashing.
    Alarm,
    /// Say that it has stopped crashing.
    Clear,
}

/// Where the traffic path stands, as this node reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Standing {
    /// Not started yet, or started and not answering yet.
    #[default]
    Starting,
    /// Answering, so this node can carry traffic.
    Serving,
    /// Crashed, and waiting to be started again.
    Down,
}

impl Standing {
    /// The name this state is written under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Serving => "serving",
            Self::Down => "down",
        }
    }
}

/// The supervision of one `data-plane` process.
#[derive(Debug)]
pub struct Supervision {
    standing: Standing,
    /// How many times it has crashed without answering in between.
    crashes: u32,
    /// Whether the claim is currently lowered.
    lowered: bool,
    /// Whether the alarm state is on.
    alarm: bool,
    /// When the next start is due, when one is waiting.
    start_at: Option<Instant>,
    /// How many liveness questions have gone unanswered in a row.
    silent: u32,
    /// How many go unanswered before the process counts as crashed.
    patience: u32,
}

impl Supervision {
    /// A supervision that has not started the process yet.
    #[must_use]
    pub const fn new(patience: u32) -> Self {
        Self {
            standing: Standing::Starting,
            crashes: 0,
            lowered: false,
            alarm: false,
            start_at: None,
            silent: 0,
            patience,
        }
    }

    /// Where the traffic path stands.
    #[must_use]
    pub const fn standing(&self) -> Standing {
        self.standing
    }

    /// How many times it has crashed without answering in between.
    #[must_use]
    pub const fn crashes(&self) -> u32 {
        self.crashes
    }

    /// Whether the process keeps crashing.
    ///
    /// Held rather than only written to the log, because a record passes once
    /// and a reader that connects afterwards has no way to learn the alarm is
    /// still on (ADR-0087).
    #[must_use]
    pub const fn alarming(&self) -> bool {
        self.alarm
    }

    /// The first thing to do: start the process.
    pub fn begin(&mut self) -> Vec<Effect> {
        self.start_at = None;
        vec![Effect::Start]
    }

    /// Takes a liveness answer that arrived.
    ///
    /// It says the process still reads what is sent to it, and nothing more.
    /// The claim does not come back here: a process that answers while its
    /// listeners accept nothing answers exactly like one that serves, and
    /// giving the address back to it would be the outage ADR-0033 exists to
    /// end. [`Supervision::serves`] is where the claim returns.
    pub fn answered(&mut self) -> Vec<Effect> {
        self.silent = 0;
        Vec::new()
    }

    /// Takes a report that says the process is carrying traffic.
    ///
    /// This is what says the process is serving, not the fact that it is
    /// running and not the fact that it answers. The claim goes back up here
    /// and nowhere else (ADR-0033, ADR-0087).
    pub fn serves(&mut self) -> Vec<Effect> {
        self.silent = 0;
        if self.standing == Standing::Serving {
            return Vec::new();
        }
        self.standing = Standing::Serving;
        self.crashes = 0;

        let mut effects = Vec::new();
        if self.lowered {
            self.lowered = false;
            effects.push(Effect::Restore);
        }
        if self.alarm {
            self.alarm = false;
            effects.push(Effect::Clear);
        }
        effects
    }

    /// Takes one liveness question that went unanswered.
    ///
    /// Returns [`Effect::Terminate`] on the one that runs out of patience.
    /// The process is not counted as crashed here: it is ended, and the crash
    /// is counted when it actually goes, so both ways in follow one path.
    pub fn unanswered(&mut self) -> Vec<Effect> {
        if self.standing == Standing::Down {
            return Vec::new();
        }
        self.silent = self.silent.saturating_add(1);
        if self.silent < self.patience {
            return Vec::new();
        }
        self.silent = 0;
        vec![Effect::Terminate]
    }

    /// Takes the process ending, however it ended.
    ///
    /// The claim comes down here rather than after the restart is scheduled,
    /// because a node holding an address it cannot serve is the outage this
    /// exists to end (ADR-0033).
    pub fn ended(&mut self, now: Instant) -> Vec<Effect> {
        self.silent = 0;
        self.crashes = self.crashes.saturating_add(1);
        self.standing = Standing::Down;
        self.start_at = Some(now + wait_after(self.crashes));

        let mut effects = Vec::new();
        if !self.lowered {
            self.lowered = true;
            effects.push(Effect::Demote);
        }
        if self.crashes >= ALARM_AFTER && !self.alarm {
            self.alarm = true;
            effects.push(Effect::Alarm);
        }
        effects
    }

    /// Takes the moment, and starts the process again when its wait is over.
    ///
    /// Returns nothing while the wait runs and nothing at all when the
    /// process is up, so a caller may call this as often as it likes.
    pub fn due(&mut self, now: Instant) -> Vec<Effect> {
        match self.start_at {
            Some(at) if now >= at => {
                self.start_at = None;
                self.standing = Standing::Starting;
                vec![Effect::Start]
            }
            _ => Vec::new(),
        }
    }

    /// When the next start is due, when one is waiting.
    #[must_use]
    pub const fn start_at(&self) -> Option<Instant> {
        self.start_at
    }
}
