// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What bounds a backend pool, measured without a network.
//!
//! The traffic path measures the same rules over real sockets. These
//! measurements are here for the parts a socket cannot show: that a gate
//! really blocks when it is full, and that a reuse group changes with time
//! and never repeats for a pool that must not share.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ek_ek_config::{
    AdminState, Backend, BackendId, BackendMember, ConnectionPooling, LoadBalancingAlgorithm,
    MemberId,
};
use ek_ek_dataplane::pool::{Gates, reuse_group, slot};

/// A pool with the settings a measurement names.
fn pool(pooling: ConnectionPooling, size: u32, lifetime_seconds: u32) -> Backend {
    Backend {
        id: BackendId::new("web"),
        members: vec![BackendMember {
            id: MemberId::new("web-1"),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            weight: 1,
            admin_state: AdminState::Enabled,
        }],
        algorithm: LoadBalancingAlgorithm::RoundRobin,
        health_check: None,
        stickiness: ek_ek_config::SessionStickiness::Disabled,
        connection_pooling: pooling,
        connection_pool_size: size,
        connection_lifetime_seconds: lifetime_seconds,
    }
}

#[tokio::test]
async fn a_full_gate_holds_the_next_request_until_a_slot_is_free() {
    let gates = Gates::new();
    let gate = gates.gate("web", 1);

    let held = slot(gate.clone()).await.expect("the first slot is free");
    assert_eq!(gates.free("web"), Some(0), "the only slot is taken");

    // Nothing may come through while the slot is held. Measured by asking
    // for one and finding that the wait does not finish.
    let waiting = tokio::time::timeout(Duration::from_millis(200), slot(gate.clone())).await;
    assert!(
        waiting.is_err(),
        "a full gate must hold the next request rather than let it past"
    );

    drop(held);
    let next = tokio::time::timeout(Duration::from_millis(200), slot(gate))
        .await
        .expect("the slot came free, so the wait must finish");
    assert!(next.is_some(), "the freed slot is handed to the waiter");
}

#[tokio::test]
async fn a_pool_that_names_no_size_has_no_gate_at_all() {
    // The other side. A gate that existed for every pool would make the
    // measurement above pass while costing a lock on every request.
    let gates = Gates::new();

    assert!(gates.gate("web", 0).is_none(), "zero means no limit");
    assert!(slot(None).await.is_none());
    assert_eq!(gates.free("web"), None, "nothing was built for that pool");
}

#[tokio::test]
async fn a_gate_is_kept_between_requests_and_replaced_when_its_size_changes() {
    // A gate rebuilt per request would hand out a fresh set of slots every
    // time and bound nothing.
    let gates = Gates::new();

    let held = slot(gates.gate("web", 2)).await.expect("a slot is free");
    assert_eq!(gates.free("web"), Some(1));

    let _second = gates.gate("web", 2);
    assert_eq!(
        gates.free("web"),
        Some(1),
        "asking again must return the gate that is already holding a slot"
    );

    // A delivery that changes the size replaces the gate. The slot already
    // held stays held; it belongs to the request, not to the gate.
    let _resized = gates.gate("web", 5);
    assert_eq!(gates.free("web"), Some(5));
    drop(held);
}

#[tokio::test]
async fn two_pools_do_not_share_a_gate() {
    let gates = Gates::new();

    let _held = slot(gates.gate("web", 1)).await.expect("a slot is free");

    assert_eq!(gates.free("web"), Some(0));
    let other = tokio::time::timeout(Duration::from_millis(200), slot(gates.gate("mapi", 1))).await;
    assert!(
        other.is_ok(),
        "a pool at its limit must not hold up a different pool"
    );
}

#[test]
fn a_pool_that_reuses_connections_keeps_one_group_while_the_lifetime_lasts() {
    let web = pool(ConnectionPooling::Enabled, 128, 300);

    // Two moments inside one span share a group, so the connection opened
    // at the first is still offered at the second.
    assert_eq!(web.reuse_group(900), web.reuse_group(1_199));
    // And a moment past the span does not.
    assert_ne!(web.reuse_group(900), web.reuse_group(1_500));

    // The lifetime is an upper bound rather than a fixed span: the group is
    // a division of elapsed seconds, so a connection opened a second before
    // a boundary is retired a second later. Stated here because an operator
    // reading "300 seconds" would otherwise expect every connection to last
    // that long.
    assert_ne!(
        web.reuse_group(1_199),
        web.reuse_group(1_201),
        "two seconds apart, and already in different groups"
    );
}

#[test]
fn a_pool_that_names_no_lifetime_never_changes_its_group() {
    // The other side. A group that moved anyway would retire connections a
    // configuration asked to keep.
    let web = pool(ConnectionPooling::Enabled, 128, 0);

    assert_eq!(web.reuse_group(0), web.reuse_group(10_000_000));
}

#[test]
fn a_pool_with_reuse_off_gets_a_group_of_its_own_every_time() {
    // Setting the idle timeout to zero is not enough on its own: the
    // connection still enters pingora's pool and the next request can take
    // it before the timeout removes it. A group nothing else holds is what
    // makes reuse impossible rather than unlikely.
    let web = pool(ConnectionPooling::Disabled, 128, 300);

    let groups: BTreeSet<u64> = (0..50).map(|_| reuse_group(&web)).collect();

    assert_eq!(groups.len(), 50, "no two requests may share a group");
}

#[test]
fn a_pool_with_reuse_on_shares_its_group_between_requests() {
    // The other side of the measurement above.
    let web = pool(ConnectionPooling::Enabled, 128, 3_600);

    let groups: BTreeSet<u64> = (0..50).map(|_| reuse_group(&web)).collect();

    assert_eq!(
        groups.len(),
        1,
        "every request must be offered the same one"
    );
}

#[test]
fn a_group_counted_from_the_clock_never_meets_one_handed_to_a_request() {
    // The two kinds of group are numbers in one space. A collision would
    // hand a request that must not share a connection that was kept.
    let never_shared = pool(ConnectionPooling::Disabled, 128, 300);
    let shared = pool(ConnectionPooling::Enabled, 128, 1);

    let handed: BTreeSet<u64> = (0..100).map(|_| reuse_group(&never_shared)).collect();
    // A second counted from the clock, at the smallest lifetime a document
    // can name, which is the largest group the clock ever produces.
    let from_the_clock = shared.reuse_group(u64::from(u32::MAX));

    assert!(!handed.contains(&from_the_clock));
    assert!(
        handed.iter().all(|group| *group > from_the_clock),
        "the two spaces must not overlap"
    );
}

#[test]
fn the_defaults_are_the_ones_the_decision_names() {
    // ADR-0045 says the defaults must be usable unchanged. Read off the
    // model rather than assumed.
    assert_eq!(Backend::default_pool_size(), 128);
    assert_eq!(Backend::default_connection_lifetime_seconds(), 300);

    let web = pool(
        ConnectionPooling::Enabled,
        Backend::default_pool_size(),
        Backend::default_connection_lifetime_seconds(),
    );
    assert!(web.limits_requests_in_flight());
    assert!(!pool(ConnectionPooling::Enabled, 0, 300).limits_requests_in_flight());
}
