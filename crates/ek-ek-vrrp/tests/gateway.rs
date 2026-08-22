// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Whether the node still has a way out, and what it does when it does not.
//!
//! The route messages, the ICMP bytes and the counting are all measured here,
//! away from any socket. What the numbers do to a running cluster is measured
//! in `ek-ek-itest`, where a node's uplink is really cut.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use ek_ek_vrrp::echo::{HEADER, REPLY, REQUEST, answers, reply, request};
use ek_ek_vrrp::gateway::{Effect, Health, INTERVAL, THRESHOLD, Watch};
use ek_ek_vrrp::route::{Family, defaults, gateway, list};
use ek_ek_vrrp::state::{Action, Machine, Reason, Settings, State, Transition};

/// The gateway of the lab network.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 1);

/// Bytes before a netlink message's payload.
const NLMSG: usize = 16;
/// Bytes of the route message that follows it.
const RTMSG: usize = 12;
/// A route the kernel is telling us about.
const NEW_ROUTE: u16 = 24;
/// The address family of an IPv4 address.
const INET: u8 = 2;

/// Builds one `RTM_NEWROUTE` message the way the kernel writes them.
///
/// Written here by hand rather than taken from a capture, so a measurement
/// can put a value in a field this product's own writer never produces: the
/// reader has to be measured against the kernel's messages, not against ours.
fn route(destination_bits: u8, attributes: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(INET);
    body.push(destination_bits);
    body.extend_from_slice(&[0; RTMSG - 2]);
    for (kind, value) in attributes {
        let length = u16::try_from(4 + value.len()).expect("an attribute fits");
        body.extend_from_slice(&length.to_ne_bytes());
        body.extend_from_slice(&kind.to_ne_bytes());
        body.extend_from_slice(value);
        while body.len() % 4 != 0 {
            body.push(0);
        }
    }

    let mut bytes = Vec::with_capacity(NLMSG + body.len());
    let length = u32::try_from(NLMSG + body.len()).expect("a message fits");
    bytes.extend_from_slice(&length.to_ne_bytes());
    bytes.extend_from_slice(&NEW_ROUTE.to_ne_bytes());
    bytes.extend_from_slice(&0_u16.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

/// The attribute that names a next hop.
fn next_hop(address: Ipv4Addr) -> (u16, Vec<u8>) {
    (5, address.octets().to_vec())
}

/// The attribute that names the interface a route leaves from.
fn out_of(index: u32) -> (u16, Vec<u8>) {
    (4, index.to_ne_bytes().to_vec())
}

/// The attribute that says what a route costs.
fn costing(metric: u32) -> (u16, Vec<u8>) {
    (6, metric.to_ne_bytes().to_vec())
}

#[test]
fn the_request_asks_for_every_route_of_one_family() {
    let bytes = list(Family::V4, 7);

    assert_eq!(
        bytes.len(),
        NLMSG + RTMSG,
        "a route request is fixed length"
    );
    assert_eq!(
        u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
        bytes.len(),
        "the length field has to name the whole message"
    );
    // RTM_GETROUTE, and the flags that ask for a dump rather than one answer.
    assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), 26);
    assert_eq!(u16::from_ne_bytes([bytes[6], bytes[7]]), 0x0301);
    assert_eq!(
        u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        7
    );
    assert_eq!(bytes[NLMSG], INET);

    // The other side: asking for the other family says so in the one byte
    // that carries it.
    let six = list(Family::V6, 7);
    assert_eq!(six[NLMSG], 10);
    assert_ne!(six[NLMSG], bytes[NLMSG]);
}

#[test]
fn the_default_route_is_read_and_a_route_to_one_network_is_not() {
    let mut answer = route(0, &[next_hop(GATEWAY), out_of(2)]);
    // A route to the lab network itself, which has no gateway and a prefix.
    answer.extend(route(24, &[out_of(2)]));
    // And one that does have a gateway but is not the default route.
    answer.extend(route(
        16,
        &[next_hop(Ipv4Addr::new(10, 0, 0, 1)), out_of(2)],
    ));

    let found = defaults(&answer);

    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].gateway, IpAddr::V4(GATEWAY));
    assert_eq!(found[0].interface, 2);
    assert_eq!(gateway(&answer, None), Some(IpAddr::V4(GATEWAY)));
}

#[test]
fn a_default_route_with_no_next_hop_names_no_gateway() {
    // A route out of an interface with nothing to ask. It is a legal route
    // and there is nothing here to send a question to.
    let answer = route(0, &[out_of(2)]);

    assert!(defaults(&answer).is_empty());
    assert_eq!(gateway(&answer, None), None);
}

#[test]
fn the_cheapest_default_route_wins() {
    let mut answer = route(
        0,
        &[
            next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            out_of(3),
            costing(200),
        ],
    );
    answer.extend(route(0, &[next_hop(GATEWAY), out_of(2), costing(100)]));

    // The kernel picks the lowest metric, so this has to pick the same one.
    // Reading the first in the list would answer with the other gateway.
    assert_eq!(gateway(&answer, None), Some(IpAddr::V4(GATEWAY)));

    // And the other side: naming an interface takes the route that leaves
    // from it even when it costs more.
    assert_eq!(
        gateway(&answer, Some(3)),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(
        gateway(&answer, Some(9)),
        None,
        "no route leaves from there"
    );
}

#[test]
fn an_answer_that_holds_no_route_names_no_gateway() {
    assert_eq!(gateway(&[], None), None);
    // A message claiming more bytes than arrived is refused rather than read
    // past the end.
    let mut cut = route(0, &[next_hop(GATEWAY)]);
    cut.truncate(NLMSG + 4);
    assert_eq!(gateway(&cut, None), None);
}

#[test]
fn the_question_is_an_echo_request_that_adds_up() {
    let bytes = request(0x1234, 7, b"ek-ek");

    assert_eq!(bytes[0], REQUEST);
    assert_eq!(bytes[1], 0, "an echo request has no code");
    assert_eq!(bytes.len(), HEADER + 5);
    assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 0x1234);
    assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 7);
    assert_ne!(
        u16::from_be_bytes([bytes[2], bytes[3]]),
        0,
        "a request with no checksum is dropped by the far end"
    );

    // What the gateway sends back is the same message with the type changed,
    // and that is what this reads.
    let mut answered = bytes.clone();
    answered[0] = REPLY;
    // The type is the first byte of a 16 bit word, so the sum moves by 8 << 8.
    let was = u16::from_be_bytes([answered[2], answered[3]]);
    answered[2..4].copy_from_slice(&(was.wrapping_add(8 << 8)).to_be_bytes());

    let read = reply(&answered).expect("the reply reads");
    assert_eq!(read.identifier, 0x1234);
    assert_eq!(read.sequence, 7);
    assert!(answers(&answered, 0x1234, 7));
}

#[test]
fn a_reply_to_somebody_elses_question_is_not_an_answer() {
    // Every reader of a raw ICMP socket sees every reply on the machine.
    let mut theirs = request(0x9999, 4, b"ek-ek");
    theirs[0] = REPLY;
    let was = u16::from_be_bytes([theirs[2], theirs[3]]);
    theirs[2..4].copy_from_slice(&(was.wrapping_add(8 << 8)).to_be_bytes());

    assert!(reply(&theirs).is_some(), "it is a well formed reply");
    assert!(!answers(&theirs, 0x1234, 4), "but not to our question");
    assert!(!answers(&theirs, 0x9999, 5), "and not to that sequence");
    assert!(answers(&theirs, 0x9999, 4), "it does answer its own");
}

#[test]
fn a_request_is_not_a_reply_and_broken_bytes_are_neither() {
    // Our own question comes back to us on the raw socket. Reading it as an
    // answer would make a node believe a gateway that never spoke.
    let ours = request(0x1234, 1, b"ek-ek");
    assert_eq!(reply(&ours), None);

    assert_eq!(reply(&[]), None);
    assert_eq!(reply(&[REPLY, 0, 0, 0]), None, "too short to hold an echo");

    // A reply whose checksum does not add up is not evidence of anything.
    let mut wrong = ours.clone();
    wrong[0] = REPLY;
    assert_eq!(
        reply(&wrong),
        None,
        "the type changed and the checksum did not"
    );
}

/// A watch on the lab gateway with the shipped defaults.
fn watching() -> Watch {
    Watch::new(Some(IpAddr::V4(GATEWAY)), INTERVAL, THRESHOLD)
}

#[test]
fn the_check_runs_no_more_often_than_its_interval() {
    // ADR-0030 asks for a check less frequent than the advertisement
    // interval, which ADR-0029 puts at 300 milliseconds.
    assert!(
        INTERVAL > Duration::from_millis(300),
        "the check would add traffic that answers nothing"
    );

    let mut watch = watching();
    let start = Instant::now();

    assert_eq!(
        watch.due(start),
        Some(IpAddr::V4(GATEWAY)),
        "the first is now"
    );
    // The other side: the loop asks a thousand times inside one interval and
    // one question goes out.
    for step in 0..1_000_u64 {
        assert_eq!(watch.due(start + Duration::from_millis(step)), None);
    }
    assert_eq!(watch.due(start + INTERVAL), Some(IpAddr::V4(GATEWAY)));
}

#[test]
fn one_lost_answer_does_not_lower_the_claim() {
    let mut watch = watching();
    watch.answered();

    assert_eq!(watch.missed(), None, "one");
    assert_eq!(watch.missing(), 1);
    assert_eq!(watch.health(), Health::Reachable);
    assert_eq!(watch.missed(), None, "two");

    // And the other side: the one that reaches the threshold does lower it.
    assert_eq!(watch.missed(), Some(Effect::Demote), "three");
    assert_eq!(watch.health(), Health::Lost);
}

#[test]
fn an_answer_between_two_losses_starts_the_count_again() {
    let mut watch = watching();
    watch.answered();

    assert_eq!(watch.missed(), None);
    assert_eq!(watch.missed(), None);
    assert_eq!(
        watch.answered(),
        None,
        "nothing was lowered, so nothing goes back"
    );
    assert_eq!(watch.missing(), 0);

    // Two more losses are still not three in a row.
    assert_eq!(watch.missed(), None);
    assert_eq!(watch.missed(), None);
    assert_eq!(watch.health(), Health::Reachable);
}

#[test]
fn the_claim_goes_back_up_when_the_gateway_answers_again() {
    let mut watch = watching();
    watch.answered();
    for _ in 0..THRESHOLD {
        watch.missed();
    }
    assert_eq!(watch.health(), Health::Lost);

    assert_eq!(watch.answered(), Some(Effect::Restore));
    assert_eq!(watch.health(), Health::Reachable);

    // Once only. A second answer has nothing left to put back.
    assert_eq!(watch.answered(), None);
}

#[test]
fn the_claim_is_lowered_once_and_not_on_every_loss_after_it() {
    let mut watch = watching();
    watch.answered();

    let mut lowered = 0;
    for _ in 0..20 {
        if watch.missed() == Some(Effect::Demote) {
            lowered += 1;
        }
    }

    assert_eq!(lowered, 1, "the claim was lowered {lowered} times");
}

#[test]
fn a_gateway_that_never_answered_never_moves_the_address() {
    // ICMP is blocked outright in some networks. A node that lowered its
    // claim there would do so on the first check, and so would every other
    // node, and the address would move for a fault that does not exist.
    let mut watch = watching();

    assert_eq!(watch.health(), Health::Unconfirmed);
    for _ in 0..100 {
        assert_eq!(watch.missed(), None);
    }
    assert_eq!(watch.missing(), 0, "nothing is counted yet");
    assert_eq!(watch.health(), Health::Unconfirmed);

    // The other side: one answer, and the count begins.
    watch.answered();
    assert_eq!(watch.health(), Health::Reachable);
    for _ in 0..THRESHOLD - 1 {
        assert_eq!(watch.missed(), None);
    }
    assert_eq!(watch.missed(), Some(Effect::Demote));
}

#[test]
fn a_node_with_no_default_route_asks_nothing_and_says_so() {
    // Reported rather than passed over in silence (ADR-0030).
    let mut watch = Watch::new(None, INTERVAL, THRESHOLD);

    assert_eq!(watch.health(), Health::NoGateway);
    assert_eq!(watch.gateway(), None);
    assert_eq!(watch.due(Instant::now()), None, "there is nothing to ask");
    assert_eq!(watch.missed(), None);
    assert_eq!(watch.health(), Health::NoGateway, "and it stays that way");
}

/// Settings for a node that claims the address at one priority.
fn settings(priority: u8, address: Ipv4Addr, peer: Ipv4Addr) -> Settings {
    Settings {
        vrid: 51,
        priority,
        interval: Duration::from_millis(300),
        preempt: true,
        address,
        virtual_addresses: vec![Ipv4Addr::new(172, 28, 0, 100)],
        peers: vec![peer],
    }
}

/// A machine that already holds the role.
fn mastering(priority: u8) -> (Machine, Instant) {
    let now = Instant::now();
    let mut machine = Machine::new(settings(
        priority,
        Ipv4Addr::new(172, 28, 0, 11),
        Ipv4Addr::new(172, 28, 0, 12),
    ));
    machine.start(now);
    // Nobody answered inside the master down interval, so it takes the role.
    machine.tick(now + machine.settings().master_down_interval());
    assert_eq!(machine.state(), State::Master);
    (machine, now)
}

#[test]
fn a_master_that_lost_its_gateway_gives_the_address_up() {
    let (mut machine, now) = mastering(200);

    let actions = machine.demote(1, now);

    assert_eq!(machine.settings().priority, 1);
    assert_eq!(machine.state(), State::Backup);
    assert_eq!(
        actions,
        vec![
            Action::Record(Transition {
                from: State::Master,
                to: State::Backup,
                reason: Reason::GatewayLost,
            }),
            Action::DropAddresses,
        ]
    );
}

#[test]
fn standing_down_does_not_wait_to_be_outranked() {
    // With preempt switched off no peer ever takes the role from a weaker
    // master. A node that only lowered its number would keep an address it
    // cannot serve, and no measurement of the number alone would show it.
    let now = Instant::now();
    let mut settings = settings(
        200,
        Ipv4Addr::new(172, 28, 0, 11),
        Ipv4Addr::new(172, 28, 0, 12),
    );
    settings.preempt = false;
    let mut machine = Machine::new(settings);
    machine.start(now);
    machine.tick(now + machine.settings().master_down_interval());
    assert_eq!(machine.state(), State::Master);

    machine.demote(1, now);

    assert_eq!(machine.state(), State::Backup, "it has to give the role up");
}

#[test]
fn a_backup_that_lost_its_gateway_only_lowers_its_claim() {
    let now = Instant::now();
    let mut machine = Machine::new(settings(
        150,
        Ipv4Addr::new(172, 28, 0, 12),
        Ipv4Addr::new(172, 28, 0, 11),
    ));
    machine.start(now);
    assert_eq!(machine.state(), State::Backup);

    let actions = machine.demote(1, now);

    assert_eq!(machine.settings().priority, 1);
    assert_eq!(machine.state(), State::Backup);
    assert!(
        actions.is_empty(),
        "there is no address to give up: {actions:?}"
    );
}

#[test]
fn the_claim_the_configuration_asked_for_comes_back() {
    let (mut machine, now) = mastering(200);
    assert_eq!(machine.configured(), 200);

    machine.demote(1, now);
    assert_eq!(machine.settings().priority, 1);

    machine.restore(now);

    assert_eq!(machine.settings().priority, 200);
    assert_eq!(machine.configured(), 200);
    // Restoring takes the role back by the ordinary rule rather than at once,
    // so nothing here claims it.
    assert_eq!(machine.state(), State::Backup);
}

#[test]
fn lowering_a_claim_that_is_already_there_does_nothing() {
    let (mut machine, now) = mastering(200);
    machine.demote(1, now);
    assert_eq!(machine.state(), State::Backup);

    // A caller that lowered the claim on every missed answer would drive the
    // machine through the same transition again and again, and the log would
    // read as a node that keeps losing an address it does not hold.
    let again = machine.demote(1, now);

    assert!(again.is_empty(), "{again:?}");
}

#[test]
fn a_demoted_node_waits_longer_than_anybody_else() {
    // What makes the takeover stick: the lowered claim lengthens this node's
    // own skew, so a healthy node reaches its deadline first.
    let (mut machine, now) = mastering(200);
    let before = machine.settings().master_down_interval();

    machine.demote(1, now);

    let after = machine.settings().master_down_interval();
    assert!(after > before, "{after:?} is not longer than {before:?}");
}
