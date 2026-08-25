// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One virtual router, driven a tick at a time.
//!
//! Everything the state machine needs to actually run: the socket the
//! advertisements travel on, the addresses the kernel is asked to move, the
//! gateway check and the records written for whoever is reading.
//!
//! Here rather than in a binary because two callers drive the same router.
//! `node-agent` runs it beside the supervision of `data-plane` (ADR-0002,
//! ADR-0087), and `ek-ek-vrrp-node` runs it on its own so a measurement can
//! drive one router without the rest of a node. A second copy of this loop
//! would let the two drift, and the one a measurement watches would stop
//! being the one that ships.
//!
//! # Why the caller owns the loop
//!
//! [`Router::tick`] does one round and returns. The agent's loop also reads a
//! channel carrying what the supervision decided, and a router that owned the
//! loop would leave nowhere for that to be read. It also means a caller
//! decides how often a round happens, which is what keeps the advertisement
//! deadline inside a fraction of its interval (ADR-0029).

use std::collections::VecDeque;
use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

use crate::gateway::{Effect, Health, Watch};
use crate::{Action, Carried, Carrier, Machine, Pinger, Settings, Transport};

/// Everything one virtual router was asked to be.
#[derive(Clone, Debug)]
pub struct Plan {
    /// What the state machine needs.
    pub settings: Settings,
    /// Interface the addresses are put on.
    pub interface: String,
    /// Addresses this node carries while it holds the role.
    pub carried: Vec<Carried>,
    /// Whether announcing is switched off.
    ///
    /// The negative control. Without it there is no way to tell an
    /// announcement that moved a cache from a cache that was going to name
    /// this node anyway (T-010).
    pub silent: bool,
    /// Whether the gateway is watched at all.
    pub watch_gateway: bool,
    /// How often the gateway is asked.
    pub check_interval: Duration,
    /// How many answers have to go missing before the claim is lowered.
    pub threshold: u32,
    /// What the claim is lowered to.
    ///
    /// One value for every reason a claim comes down, because the claim is
    /// one number: a node that cannot reach its gateway and a node whose
    /// traffic path is gone are equally unable to carry traffic.
    pub demoted_priority: u8,
}

/// The gateway check on this node, and the question it is waiting on.
struct Check {
    watch: Watch,
    pinger: Pinger,
    /// The sequence number of the question no answer has arrived for.
    ///
    /// One at a time: the next question is only sent when the interval
    /// elapses, and the one before it counts as lost at that moment.
    waiting: Option<u16>,
}

/// One running virtual router.
pub struct Router<'a, T: Transport> {
    machine: Machine,
    carrier: Carrier,
    checker: Option<Check>,
    transport: &'a T,
    peers: Vec<Ipv4Addr>,
    demoted_priority: u8,
    /// When an advertisement was last acted on.
    ///
    /// A takeover is timed from the last one the dying master sent, and
    /// reading both moments off the same clock in the same process is what
    /// makes the difference a failover time rather than the spread between
    /// two machines (T-010).
    heard_at: u128,
}

impl<'a, T: Transport> Router<'a, T> {
    /// Opens the addresses and the gateway check, and starts the machine.
    ///
    /// # Errors
    ///
    /// Returns whatever the operating system said. Moving an address needs
    /// `CAP_NET_ADMIN` and sending a frame needs `CAP_NET_RAW`, so a refusal
    /// here is usually a distribution installed without them.
    pub fn start(plan: Plan, transport: &'a T, now: Instant) -> io::Result<Self> {
        let carrier = Carrier::open(&plan.interface, plan.carried, plan.silent)?;
        let checker = if plan.watch_gateway {
            Some(open_check(
                &plan.interface,
                plan.check_interval,
                plan.threshold,
            )?)
        } else {
            None
        };
        if let Some(Check { watch, .. }) = checker.as_ref() {
            // Said once at startup, so a node with no default route is a line
            // in the log rather than a check nobody notices is not running.
            say(&format!(
                r#"{{"kind":"gateway","ts":{},"event":"watching","health":"{}","gateway":"{}"}}"#,
                milliseconds(),
                watch.health().name(),
                watch
                    .gateway()
                    .map_or_else(|| "none".to_owned(), |address| address.to_string())
            ));
        }

        let peers = plan.settings.peers.clone();
        let mut router = Self {
            machine: Machine::new(plan.settings),
            carrier,
            checker,
            transport,
            peers,
            demoted_priority: plan.demoted_priority,
            heard_at: 0,
        };
        let starting = router.machine.start(now);
        router.carry_out(starting, now);
        Ok(router)
    }

    /// Does one round: reads what arrived, runs the timers, announces.
    pub fn tick(&mut self, now: Instant) {
        // Everything waiting is taken before the timers, so a takeover is
        // decided on what has already arrived.
        loop {
            match self.transport.receive() {
                Ok(Some((from, bytes))) => {
                    let before = self.machine.accepted();
                    let actions = self.machine.receive(from, &bytes, now);
                    if self.machine.accepted() > before {
                        self.heard_at = milliseconds();
                    }
                    self.carry_out(actions, now);
                }
                Ok(None) => break,
                Err(error) => {
                    say(&format!(
                        r#"{{"kind":"app","level":"error","target":"ek_ek_vrrp","message":"the socket could not be read: {}"}}"#,
                        escaped(&error.to_string())
                    ));
                    break;
                }
            }
        }

        let actions = self.machine.tick(now);
        self.carry_out(actions, now);

        if self.checker.is_some() {
            let actions = self.check_gateway(now);
            self.carry_out(actions, now);
        }

        // The announcement is spread over the loop rather than sent in one
        // block, so the advertisement and the socket read are not held for
        // the length of it (ADR-0029).
        if let Err(error) = self.carrier.tick(now) {
            say(&format!(
                r#"{{"kind":"vip","ts":{},"event":"announcement_failed","error":"{}"}}"#,
                milliseconds(),
                escaped(&error.to_string())
            ));
        }
    }

    /// Lowers this node's claim for a reason from outside the router.
    ///
    /// Used when the traffic path is gone: the node is still on the network
    /// and still answering its peers, and nothing the protocol can see says
    /// it cannot serve. Lowering the claim is what hands the address to a
    /// node that can (ADR-0033).
    pub fn demote(&mut self, why: &str, now: Instant) {
        if self.machine.settings().priority == self.demoted_priority {
            return;
        }
        say(&format!(
            r#"{{"kind":"vrrp","ts":{},"event":"demoted","reason":"{}","priority":{}}}"#,
            milliseconds(),
            escaped(why),
            self.demoted_priority
        ));
        let actions = self.machine.demote(self.demoted_priority, now);
        self.carry_out(actions, now);
    }

    /// Puts the claim back where the configuration had it.
    pub fn restore(&mut self, why: &str, now: Instant) {
        if self.machine.settings().priority == self.machine.configured() {
            return;
        }
        say(&format!(
            r#"{{"kind":"vrrp","ts":{},"event":"restored","reason":"{}","priority":{}}}"#,
            milliseconds(),
            escaped(why),
            self.machine.configured()
        ));
        let actions = self.machine.restore(now);
        self.carry_out(actions, now);
    }

    /// The claim this node is currently making.
    #[must_use]
    pub const fn priority(&self) -> u8 {
        self.machine.settings().priority
    }

    /// Gives the addresses up, for a node that is stopping on purpose.
    pub fn stop(&mut self, now: Instant) {
        let actions = self.machine.stop(now);
        self.carry_out(actions, now);
    }

    /// Does what the machine asked for.
    ///
    /// The actions are a queue rather than a list, because failing to take
    /// the addresses makes the machine stand the node down and that produces
    /// more to do. Standing down cannot ask to take them again, so the queue
    /// empties.
    fn carry_out(&mut self, actions: Vec<Action>, now: Instant) {
        let mut queue: VecDeque<Action> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                Action::Advertise(advertisement) => {
                    for peer in &self.peers {
                        // Encoded once per peer: the checksum covers the
                        // destination, so one peer's bytes are refused by
                        // another.
                        let bytes = advertisement.encode(self.machine.settings().address, *peer);
                        if let Err(error) = self.transport.send(*peer, &bytes) {
                            say(&format!(
                                r#"{{"kind":"app","level":"warn","target":"ek_ek_vrrp","message":"advertisement to {peer} did not go: {}"}}"#,
                                escaped(&error.to_string())
                            ));
                        }
                    }
                }
                Action::Record(transition) => say(&format!(
                    r#"{{"kind":"vrrp","ts":{},"heard":{},"vrid":{},"from":"{}","to":"{}","reason":"{}","address":"{}"}}"#,
                    milliseconds(),
                    self.heard_at,
                    self.machine.settings().vrid,
                    transition.from.name(),
                    transition.to.name(),
                    transition.reason.name(),
                    self.machine.settings().address,
                )),
                Action::TakeAddresses => match self.carrier.take(now) {
                    Ok(()) => say(&format!(
                        r#"{{"kind":"vip","ts":{},"event":"taken","addresses":{}}}"#,
                        milliseconds(),
                        listed(&self.carrier)
                    )),
                    Err(error) => {
                        // A master without its addresses answers nothing and
                        // its advertisements stop every other node from
                        // answering either. Standing down turns a silent
                        // outage into a takeover.
                        say(&format!(
                            r#"{{"kind":"vip","ts":{},"event":"take_failed","error":"{}","addresses":{}}}"#,
                            milliseconds(),
                            escaped(&error.to_string()),
                            listed(&self.carrier)
                        ));
                        queue.extend(self.machine.renounce(now));
                    }
                },
                Action::DropAddresses => match self.carrier.drop_all() {
                    Ok(()) => say(&format!(
                        r#"{{"kind":"vip","ts":{},"event":"dropped","addresses":{}}}"#,
                        milliseconds(),
                        listed(&self.carrier)
                    )),
                    Err(error) => say(&format!(
                        r#"{{"kind":"vip","ts":{},"event":"drop_failed","error":"{}","addresses":{}}}"#,
                        milliseconds(),
                        escaped(&error.to_string()),
                        listed(&self.carrier)
                    )),
                },
            }
        }
    }

    /// Asks the gateway, reads what came back, and acts on the count.
    ///
    /// Returns what the state machine asked for, which is nothing at all
    /// until the threshold is reached on a node that holds the role.
    fn check_gateway(&mut self, now: Instant) -> Vec<Action> {
        let Some(check) = self.checker.as_mut() else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        let mut restore = false;

        // Answers first, so a reply that arrived just before the deadline is
        // not counted as lost by the question that follows it.
        loop {
            match check.pinger.collect() {
                Ok(Some((from, echo))) => {
                    if check.watch.gateway() != Some(IpAddr::V4(from)) {
                        continue;
                    }
                    if check.waiting != Some(echo.sequence) {
                        continue;
                    }
                    check.waiting = None;
                    let before = check.watch.health();
                    let effect = check.watch.answered();
                    // The first answer is the moment the check starts
                    // counting. Without a line for it there is no way to tell
                    // a gateway that answers from one that never did, and the
                    // difference decides whether this node ever gives an
                    // address up.
                    if before == Health::Unconfirmed {
                        say(&format!(
                            r#"{{"kind":"gateway","ts":{},"event":"confirmed","health":"{}","gateway":"{from}"}}"#,
                            milliseconds(),
                            check.watch.health().name()
                        ));
                    }
                    if effect == Some(Effect::Restore) {
                        restore = true;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    say(&format!(
                        r#"{{"kind":"app","level":"error","target":"ek_ek_vrrp","message":"the ICMP socket could not be read: {}"}}"#,
                        escaped(&error.to_string())
                    ));
                    break;
                }
            }
        }

        if restore {
            say(&format!(
                r#"{{"kind":"gateway","ts":{},"event":"back","health":"{}","priority":{}}}"#,
                milliseconds(),
                Health::Reachable.name(),
                self.machine.configured()
            ));
            actions.extend(self.machine.restore(now));
        }

        let Some(check) = self.checker.as_mut() else {
            return actions;
        };
        let Some(gateway) = check.watch.due(now) else {
            return actions;
        };

        // The question before this one was never answered.
        if check.waiting.take().is_some() {
            actions.extend(self.note_missed(now));
        }

        let IpAddr::V4(gateway) = gateway else {
            // RFC 5798 keeps one virtual router to one address family, and
            // this one is IPv4. An IPv6 default route is somebody else's
            // question.
            return actions;
        };
        let Some(check) = self.checker.as_mut() else {
            return actions;
        };
        match check.pinger.ask(gateway) {
            Ok(sequence) => check.waiting = Some(sequence),
            Err(error) => {
                // A question that could not even be sent is a question with
                // no answer. The kernel refuses the send outright when the
                // route to the gateway is gone, which is one of the shapes a
                // lost uplink takes; the other is a send that leaves and is
                // never answered. Counting only the second would leave the
                // first unmeasured, and the node would hold the address
                // through it.
                say(&format!(
                    r#"{{"kind":"app","level":"warn","target":"ek_ek_vrrp","message":"the gateway could not be asked: {}"}}"#,
                    escaped(&error.to_string())
                ));
                actions.extend(self.note_missed(now));
            }
        }
        actions
    }

    /// Counts one question nobody answered, and acts when that is enough.
    fn note_missed(&mut self, now: Instant) -> Vec<Action> {
        let Some(check) = self.checker.as_mut() else {
            return Vec::new();
        };
        let effect = check.watch.missed();
        say(&format!(
            r#"{{"kind":"gateway","ts":{},"event":"missed","health":"{}","missing":{}}}"#,
            milliseconds(),
            check.watch.health().name(),
            check.watch.missing()
        ));
        if effect != Some(Effect::Demote) {
            return Vec::new();
        }
        say(&format!(
            r#"{{"kind":"gateway","ts":{},"event":"lost","health":"{}","priority":{}}}"#,
            milliseconds(),
            Health::Lost.name(),
            self.demoted_priority
        ));
        self.machine.demote(self.demoted_priority, now)
    }
}

/// Reads the default gateway and opens the socket the question travels on.
///
/// The gateway is read once at startup. A route that changes while the node
/// runs is a case for a later task; reading it on every check would ask the
/// kernel a question every two seconds to learn something that changes once
/// in a machine's life.
fn open_check(interface: &str, interval: Duration, threshold: u32) -> io::Result<Check> {
    let index = crate::Interface::read(interface)
        .ok()
        .map(|found| found.index);
    let netlink = crate::netlink::Netlink::open()?;
    let gateway = netlink.gateway(crate::route::Family::V4, index)?;
    Ok(Check {
        watch: Watch::new(gateway, interval, threshold),
        pinger: Pinger::open()?,
        waiting: None,
    })
}

/// The carried addresses as a JSON array.
fn listed(carrier: &Carrier) -> String {
    let inside: Vec<String> = carrier
        .addresses()
        .iter()
        .map(|carried| format!(r#""{}/{}""#, carried.address, carried.prefix_length))
        .collect();
    format!("[{}]", inside.join(","))
}

/// A string with the two characters JSON refuses inside one escaped.
///
/// An operating system message is written by somebody else and can hold
/// anything. A quote in it would end the field and leave a line nothing can
/// parse, which is exactly the line a failure has to be read from.
fn escaped(text: &str) -> String {
    text.replace('\\', r"\\").replace('"', "\\\"")
}

/// Writes one line and makes sure it left.
///
/// Flushed on purpose: a reader watching the stream for a transition would
/// otherwise see it whenever the buffer happened to fill, which is exactly
/// the moment a failover measurement is trying to time.
fn say(line: &str) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Milliseconds since the epoch, which is what a failover is timed in.
fn milliseconds() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}
