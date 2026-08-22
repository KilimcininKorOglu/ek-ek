// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Who takes the virtual router, and when.
//!
//! Time is handed to the machine, so every deadline is measured from both
//! sides without waiting for it: a moment before, nothing happens; a moment
//! after, the takeover does. Waiting out a master down interval at the
//! default settings costs over a second per measurement and would measure
//! the machine the test runs on rather than the rule.
//!
//! The same rules are measured again over real packets between two nodes in
//! `ek-ek-itest`. This file cannot see a checksum, a TTL or a protocol
//! number; that one cannot stand either side of a deadline.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use ek_ek_vrrp::{Action, Advertisement, Ignored, Machine, Reason, Settings, State};

/// The interval ADR-0029 makes the default.
const INTERVAL: Duration = Duration::from_millis(300);

/// The addresses in these measurements.
const NODE1: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 11);
const NODE2: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 12);
const NODE3: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 13);
const VIRTUAL: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 100);

/// Settings for one node, at the priority given.
fn settings(address: Ipv4Addr, priority: u8, preempt: bool) -> Settings {
    Settings {
        vrid: 51,
        priority,
        interval: INTERVAL,
        preempt,
        address,
        virtual_addresses: vec![VIRTUAL],
        peers: vec![NODE1, NODE2, NODE3],
    }
}

/// A machine that has started and is waiting.
fn started(address: Ipv4Addr, priority: u8, preempt: bool, now: Instant) -> Machine {
    let mut machine = Machine::new(settings(address, priority, preempt));
    machine.start(now);
    machine
}

/// The advertisement one node would send, encoded towards the virtual
/// address, which is where a real one goes.
fn advertisement_from(from: Ipv4Addr, priority: u8) -> Vec<u8> {
    Advertisement {
        vrid: 51,
        priority,
        interval_centiseconds: 30,
        addresses: vec![VIRTUAL],
    }
    .encode(from, VIRTUAL)
}

/// The transitions among a set of actions.
fn transitions(actions: &[Action]) -> Vec<(State, State, Reason)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Record(transition) => Some((transition.from, transition.to, transition.reason)),
            Action::Advertise(_) => None,
        })
        .collect()
}

/// The advertisements among a set of actions.
fn advertisements(actions: &[Action]) -> Vec<&Advertisement> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Advertise(advertisement) => Some(advertisement),
            Action::Record(_) => None,
        })
        .collect()
}

#[test]
fn the_master_down_interval_is_the_one_rfc_5798_computes() {
    // The numbers the spike measured against, so a change here shows up as a
    // change in failover time rather than as a silent drift.
    let backup = settings(NODE2, 150, true);

    assert_eq!(backup.skew_time(), Duration::from_nanos(124_218_750));
    assert_eq!(
        backup.master_down_interval(),
        Duration::from_nanos(1_024_218_750),
        "three intervals plus the skew, which is 1024 ms at 300 ms and priority 150"
    );

    // A weaker node waits longer. That is the whole mechanism behind a
    // deterministic order of takeover.
    assert!(settings(NODE3, 100, true).master_down_interval() > backup.master_down_interval());
    assert!(settings(NODE1, 200, true).master_down_interval() < backup.master_down_interval());
}

#[test]
fn a_node_that_hears_nothing_takes_the_role_when_the_interval_is_over() {
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);
    assert_eq!(node.state(), State::Backup);

    let due = node.settings().master_down_interval();

    // A moment before the deadline, nothing happens.
    let early = node.tick(start + due - Duration::from_millis(1));
    assert!(early.is_empty(), "the interval is not over yet");
    assert_eq!(node.state(), State::Backup);

    // A moment after, the role is taken.
    let taken = node.tick(start + due);
    assert_eq!(node.state(), State::Master);
    assert_eq!(
        transitions(&taken),
        vec![(State::Backup, State::Master, Reason::NobodyElseAnswered)]
    );
    assert_eq!(
        advertisements(&taken).len(),
        1,
        "the new master says so at once rather than an interval later"
    );
}

#[test]
fn a_node_that_keeps_hearing_the_master_never_takes_the_role() {
    // The other side. A machine that took the role whatever it heard would
    // pass the measurement above.
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);
    let due = node.settings().master_down_interval();

    // The stronger node advertises on time, right up to the deadline.
    //
    // Every transition is collected rather than only the state at the end. A
    // machine that took the role and gave it straight back on the next
    // advertisement would end in backup and say nothing about the rule.
    let mut moved = Vec::new();
    let mut now = start;
    while now < start + due * 3 {
        now += INTERVAL;
        moved.extend(transitions(&node.receive(
            NODE1,
            &advertisement_from(NODE1, 200),
            now,
        )));
        moved.extend(transitions(&node.tick(now)));
    }

    assert_eq!(
        moved,
        Vec::new(),
        "the role must not move at all while the master is heard"
    );
    assert_eq!(node.state(), State::Backup, "the master is still alive");
    assert!(node.accepted() > 0, "the advertisements really arrived");
}

#[test]
fn the_stronger_node_takes_the_role_from_the_weaker_one() {
    let start = Instant::now();
    let mut weaker = started(NODE2, 150, true, start);
    weaker.tick(start + weaker.settings().master_down_interval());
    assert_eq!(weaker.state(), State::Master);

    let heard = weaker.receive(NODE1, &advertisement_from(NODE1, 200), start);

    assert_eq!(weaker.state(), State::Backup);
    assert_eq!(
        transitions(&heard),
        vec![(State::Master, State::Backup, Reason::StrongerPeer)]
    );
}

#[test]
fn a_master_keeps_the_role_against_a_weaker_claim() {
    // The other side. A master that stood down for anything would pass the
    // measurement above and hand the role to the weakest node on the segment.
    let start = Instant::now();
    let mut stronger = started(NODE1, 200, true, start);
    stronger.tick(start + stronger.settings().master_down_interval());
    assert_eq!(stronger.state(), State::Master);

    let heard = stronger.receive(NODE2, &advertisement_from(NODE2, 150), start);

    assert_eq!(stronger.state(), State::Master);
    assert!(transitions(&heard).is_empty());
}

#[test]
fn an_equal_claim_is_settled_by_address_and_settled_the_same_way_twice() {
    // Two nodes at the same priority have to reach the same answer without
    // agreeing on one. The higher address wins, and both sides of the
    // comparison are measured: the lower node stands down, the higher does
    // not.
    let start = Instant::now();

    let outcome = |mine: Ipv4Addr, theirs: Ipv4Addr| {
        let mut node = started(mine, 150, true, start);
        node.tick(start + node.settings().master_down_interval());
        assert_eq!(node.state(), State::Master);
        node.receive(theirs, &advertisement_from(theirs, 150), start);
        node.state()
    };

    assert_eq!(
        outcome(NODE2, NODE3),
        State::Backup,
        "the lower address gives way"
    );
    assert_eq!(
        outcome(NODE3, NODE2),
        State::Master,
        "the higher address keeps the role"
    );

    // Run again from a different starting moment: the answer comes from the
    // addresses and from nothing else.
    let again = Instant::now();
    let mut node = started(NODE2, 150, true, again);
    node.tick(again + node.settings().master_down_interval());
    node.receive(NODE3, &advertisement_from(NODE3, 150), again);
    assert_eq!(node.state(), State::Backup, "and the same answer twice");
}

#[test]
fn preempt_on_gives_the_role_back_to_the_stronger_node() {
    let start = Instant::now();
    let mut weaker = started(NODE2, 150, true, start);
    weaker.tick(start + weaker.settings().master_down_interval());
    assert_eq!(weaker.state(), State::Master);

    // The stronger node comes back and says so.
    weaker.receive(NODE1, &advertisement_from(NODE1, 200), start);

    assert_eq!(weaker.state(), State::Backup, "the role goes back");
}

#[test]
fn preempt_off_leaves_the_role_where_it_is() {
    // The other side of the same setting, and the reason it exists: a node
    // that flaps should not drag the virtual router back and forth with it.
    let start = Instant::now();
    let mut weaker = started(NODE2, 150, false, start);
    weaker.tick(start + weaker.settings().master_down_interval());
    assert_eq!(weaker.state(), State::Master);

    weaker.receive(NODE1, &advertisement_from(NODE1, 200), start);

    // RFC 5798 keeps the master rule the same whatever preempt says: a
    // stronger advertisement still takes the role. What preempt changes is
    // the backup, which is measured below.
    assert_eq!(weaker.state(), State::Backup);

    // And the backup with preempt off treats a weaker master as alive.
    let mut backup = started(NODE1, 200, false, start);
    let due = backup.settings().master_down_interval();
    let mut moved = Vec::new();
    let mut now = start;
    while now < start + due * 3 {
        now += INTERVAL;
        moved.extend(transitions(&backup.receive(
            NODE2,
            &advertisement_from(NODE2, 150),
            now,
        )));
        moved.extend(transitions(&backup.tick(now)));
    }
    assert_eq!(
        moved,
        Vec::new(),
        "with preempt off the role must not move at all"
    );
    assert_eq!(
        backup.state(),
        State::Backup,
        "with preempt off a weaker master is left alone"
    );
}

#[test]
fn preempt_on_does_not_wait_for_a_weaker_master() {
    // The other side of the measurement above. With preempt on, a weaker
    // master is not a reason to keep waiting.
    let start = Instant::now();
    let mut backup = started(NODE1, 200, true, start);
    let due = backup.settings().master_down_interval();

    let mut now = start;
    while now < start + due + INTERVAL {
        now += INTERVAL;
        backup.receive(NODE2, &advertisement_from(NODE2, 150), now);
        backup.tick(now);
    }

    assert_eq!(
        backup.state(),
        State::Master,
        "with preempt on the stronger node takes the role back"
    );
}

#[test]
fn an_advertisement_from_outside_the_peer_list_is_dropped() {
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);
    let stranger = Ipv4Addr::new(172, 28, 0, 99);

    let judged = node.judge(stranger, &advertisement_from(stranger, 255), start);

    assert_eq!(judged, Err(Ignored::UnknownPeer));
    assert_eq!(node.ignored(), 1);
    assert_eq!(node.accepted(), 0);
    // And the timer it would have reset is untouched: the node still takes
    // the role on time.
    node.tick(start + node.settings().master_down_interval());
    assert_eq!(
        node.state(),
        State::Master,
        "a packet from outside must not hold the virtual router open"
    );
}

#[test]
fn an_advertisement_from_inside_the_peer_list_is_acted_on() {
    // The other side. A machine that dropped everything would pass the
    // measurement above and never hear a master at all.
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);

    // Heard one interval in, so the deadline it pushes out lands past the
    // one the machine started with. Receiving at the very start would move
    // the deadline onto itself and prove nothing.
    let judged = node.judge(NODE1, &advertisement_from(NODE1, 200), start + INTERVAL);

    assert_eq!(judged, Ok(Vec::new()), "heard, with nothing to do about it");
    assert_eq!(node.accepted(), 1);
    assert_eq!(node.ignored(), 0);
    // The deadline really moved: the moment the machine would have claimed
    // the role passes with nothing happening.
    node.tick(start + node.settings().master_down_interval());
    assert_eq!(node.state(), State::Backup);
    // And it still claims once the pushed-out deadline arrives.
    node.tick(start + INTERVAL + node.settings().master_down_interval());
    assert_eq!(node.state(), State::Master);
}

#[test]
fn an_advertisement_for_another_virtual_router_is_dropped() {
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);

    let other = Advertisement {
        vrid: 52,
        priority: 255,
        interval_centiseconds: 30,
        addresses: vec![VIRTUAL],
    }
    .encode(NODE1, VIRTUAL);

    assert_eq!(
        node.judge(NODE1, &other, start),
        Err(Ignored::OtherRouter(52))
    );
    assert_eq!(node.ignored(), 1);
}

#[test]
fn a_master_standing_down_lets_the_next_node_wait_only_its_skew() {
    // A planned handover must not cost a full master down interval, or every
    // configuration change would look like a failure to a client (T-010).
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);

    node.receive(NODE1, &advertisement_from(NODE1, 0), start);

    let skew = node.settings().skew_time();
    assert!(
        node.tick(start + skew - Duration::from_millis(1))
            .is_empty(),
        "the skew is not over yet"
    );
    node.tick(start + skew);
    assert_eq!(node.state(), State::Master);
    assert!(
        skew * 4 < node.settings().master_down_interval(),
        "the skew has to be the shorter wait, or standing down buys nothing"
    );
}

#[test]
fn a_master_that_is_stopped_says_so_before_it_goes() {
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);
    node.tick(start + node.settings().master_down_interval());
    assert_eq!(node.state(), State::Master);

    let stopping = node.stop(start);

    assert_eq!(node.state(), State::Initialize);
    let sent = advertisements(&stopping);
    assert_eq!(sent.len(), 1, "the peers are told rather than left waiting");
    assert_eq!(sent[0].priority, 0, "a priority of zero means giving up");
    assert_eq!(
        transitions(&stopping),
        vec![(State::Master, State::Initialize, Reason::Stopped)]
    );
}

#[test]
fn a_backup_that_is_stopped_sends_nothing() {
    // The other side. A backup has no role to give up, and a priority-zero
    // advertisement from one would tell the peers a master left when none
    // did.
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);

    let stopping = node.stop(start);

    assert!(advertisements(&stopping).is_empty());
    assert_eq!(
        transitions(&stopping),
        vec![(State::Backup, State::Initialize, Reason::Stopped)]
    );
}

#[test]
fn a_master_advertises_once_an_interval_and_no_more_often() {
    let start = Instant::now();
    let mut node = started(NODE2, 150, true, start);
    let taken = node.tick(start + node.settings().master_down_interval());
    assert_eq!(advertisements(&taken).len(), 1);

    let mut now = start + node.settings().master_down_interval();
    let mut sent = 0;
    // Ticked far more often than the interval, which is what a real loop
    // does. The count has to follow the interval rather than the loop.
    for _ in 0..100 {
        now += INTERVAL / 10;
        sent += advertisements(&node.tick(now)).len();
    }

    assert_eq!(
        sent, 10,
        "one hundred ticks over ten intervals is ten sends"
    );
}

#[test]
fn every_transition_carries_where_it_came_from_and_why() {
    // The record is what an operator reads after a failover. A transition
    // with no reason would say the role moved and not why.
    let start = Instant::now();
    let mut node = Machine::new(settings(NODE2, 150, true));

    let starting = node.start(start);
    assert_eq!(
        transitions(&starting),
        vec![(State::Initialize, State::Backup, Reason::Started)]
    );

    let taking = node.tick(start + node.settings().master_down_interval());
    assert_eq!(
        transitions(&taking),
        vec![(State::Backup, State::Master, Reason::NobodyElseAnswered)]
    );

    let giving = node.receive(NODE1, &advertisement_from(NODE1, 200), start);
    assert_eq!(
        transitions(&giving),
        vec![(State::Master, State::Backup, Reason::StrongerPeer)]
    );

    let stopping = node.stop(start);
    assert_eq!(
        transitions(&stopping),
        vec![(State::Backup, State::Initialize, Reason::Stopped)]
    );

    // Every state and every reason has a name to be written under.
    for state in [State::Initialize, State::Backup, State::Master] {
        assert!(!state.name().is_empty());
    }
    for reason in [
        Reason::Started,
        Reason::NobodyElseAnswered,
        Reason::StrongerPeer,
        Reason::Stopped,
    ] {
        assert!(!reason.name().is_empty());
    }
}

#[test]
fn the_node_that_owns_the_addresses_takes_the_role_at_once() {
    // Priority 255 is reserved for the node the addresses belong to. Nothing
    // outranks it, so waiting an interval would only delay the inevitable.
    let start = Instant::now();
    let mut owner = Machine::new(settings(NODE1, 255, true));

    let starting = owner.start(start);

    assert_eq!(owner.state(), State::Master);
    assert_eq!(
        transitions(&starting),
        vec![(State::Initialize, State::Master, Reason::Started)]
    );
}

#[test]
fn a_cold_start_leaves_the_cluster_on_the_strongest_node() {
    // Nobody advertises until somebody is master, so on a cold start each
    // node counts from its own beginning. What separates them is the skew,
    // and a short double master is possible; it closes on the first
    // advertisement (T-010).
    let start = Instant::now();
    let mut strong = started(NODE1, 200, true, start);
    let mut weak = started(NODE2, 150, true, start);

    // Both claim, the weaker one later.
    let strong_due = strong.settings().master_down_interval();
    let weak_due = weak.settings().master_down_interval();
    assert!(strong_due < weak_due, "the stronger node claims first");

    strong.tick(start + strong_due);
    assert_eq!(strong.state(), State::Master);
    weak.tick(start + weak_due);
    assert_eq!(weak.state(), State::Master, "both hold it for a moment");

    // The first advertisement closes it.
    weak.receive(NODE1, &advertisement_from(NODE1, 200), start + weak_due);
    assert_eq!(weak.state(), State::Backup);

    // And the window is shorter than one advertisement interval, which is
    // what bounds how long two nodes can both answer.
    assert!(
        weak_due - strong_due < INTERVAL,
        "the gap between the two claims was {:?}",
        weak_due - strong_due
    );
}
