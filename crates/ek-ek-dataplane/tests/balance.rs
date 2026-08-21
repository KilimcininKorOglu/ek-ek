// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What each load balancing algorithm decides.
//!
//! These reach no network. An algorithm is a decision over a pool, a client
//! address and a count of open connections, so the shares it produces are
//! measured directly instead of being inferred from traffic. What that misses,
//! whether the proxy actually forwards to the member it chose, is measured in
//! `ek-ek`'s own proxy tests.
//!
//! Consistent hashing in particular cannot be measured over a socket: it is
//! about what happens to many different client addresses when one member
//! leaves, and every connection from a test machine carries the same address.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{
    AdminState, Backend, BackendId, BackendMember, ConnectionPooling, LoadBalancingAlgorithm,
    MemberId, SessionStickiness,
};
use ek_ek_dataplane::{Balancer, ring_for};

/// Builds a pool from `(identity, weight, state)` triples.
fn pool(algorithm: LoadBalancingAlgorithm, members: &[(&str, u16, AdminState)]) -> Backend {
    Backend {
        id: BackendId::new("web"),
        members: members
            .iter()
            .enumerate()
            .map(|(at, (name, weight, state))| BackendMember {
                id: MemberId::new(*name),
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, u8::try_from(at + 1).unwrap_or(1))),
                port: 8080,
                weight: *weight,
                admin_state: *state,
            })
            .collect(),
        algorithm,
        health_check: None,
        stickiness: SessionStickiness::Disabled,
        connection_pooling: ConnectionPooling::Enabled,
    }
}

/// A client address built from a number, so many distinct clients are cheap.
fn client(number: u32) -> IpAddr {
    let octets = number.to_be_bytes();
    IpAddr::V4(Ipv4Addr::new(192, 168, octets[2].max(1), octets[3].max(1)))
}

/// Runs a pool `count` times from one client address and counts the answers.
fn shares(pool: &Backend, count: usize) -> BTreeMap<String, usize> {
    let balancer = Balancer::new();
    let ring = ring_for(pool);
    let mut counted = BTreeMap::new();

    for _ in 0..count {
        let member = balancer
            .choose(pool, &ring, client(1))
            .expect("a pool with an enabled member must choose one");
        *counted
            .entry(member.id.as_str().to_owned())
            .or_insert(0_usize) += 1;
    }
    counted
}

#[test]
fn round_robin_splits_one_hundred_requests_evenly_between_two_equal_members() {
    let pool = pool(
        LoadBalancingAlgorithm::RoundRobin,
        &[
            ("one", 1, AdminState::Enabled),
            ("two", 1, AdminState::Enabled),
        ],
    );

    let counted = shares(&pool, 100);

    assert_eq!(counted.get("one"), Some(&50), "counted {counted:?}");
    assert_eq!(counted.get("two"), Some(&50), "counted {counted:?}");
}

#[test]
fn a_member_weighted_two_takes_twice_the_share_of_one_weighted_one() {
    let pool = pool(
        LoadBalancingAlgorithm::RoundRobin,
        &[
            ("heavy", 2, AdminState::Enabled),
            ("light", 1, AdminState::Enabled),
        ],
    );

    let counted = shares(&pool, 90);
    let heavy = *counted.get("heavy").unwrap_or(&0);
    let light = *counted.get("light").unwrap_or(&0);

    assert_eq!(heavy, 60, "counted {counted:?}");
    assert_eq!(light, 30, "counted {counted:?}");
    assert_eq!(heavy, light * 2, "weight 2 did not take twice the share");
}

#[test]
fn a_weight_of_zero_still_takes_traffic_rather_than_disappearing() {
    // Zero is not how a member is taken out of service; admin state is.
    // Treating it as no share would make a member look configured while
    // being unreachable.
    let pool = pool(
        LoadBalancingAlgorithm::RoundRobin,
        &[
            ("zero", 0, AdminState::Enabled),
            ("one", 1, AdminState::Enabled),
        ],
    );

    let counted = shares(&pool, 40);

    assert_eq!(counted.get("zero"), Some(&20), "counted {counted:?}");
}

#[test]
fn least_connections_picks_the_member_carrying_fewer_open_connections() {
    let pool = pool(
        LoadBalancingAlgorithm::LeastConnections,
        &[
            ("busy", 1, AdminState::Enabled),
            ("idle", 1, AdminState::Enabled),
        ],
    );
    let balancer = Balancer::new();
    let ring = ring_for(&pool);

    for _ in 0..3 {
        balancer.opened("front", "web", "busy");
    }
    assert_eq!(balancer.open_connections("web", "busy"), 3);

    let chosen = balancer
        .choose(&pool, &ring, client(1))
        .expect("a member must be chosen");
    assert_eq!(chosen.id.as_str(), "idle");

    // Once the busy member finishes, it is eligible again.
    for _ in 0..3 {
        balancer.closed("front", "web", "busy");
    }
    balancer.opened("front", "web", "idle");
    let chosen = balancer
        .choose(&pool, &ring, client(1))
        .expect("a member must be chosen");
    assert_eq!(chosen.id.as_str(), "busy");
}

#[test]
fn source_ip_hash_sends_one_address_to_one_member_every_time() {
    let pool = pool(
        LoadBalancingAlgorithm::SourceIpHash,
        &[
            ("one", 1, AdminState::Enabled),
            ("two", 1, AdminState::Enabled),
            ("three", 1, AdminState::Enabled),
        ],
    );
    let balancer = Balancer::new();
    let ring = ring_for(&pool);

    for number in 1..200_u32 {
        let first = balancer
            .choose(&pool, &ring, client(number))
            .expect("a member must be chosen")
            .id
            .as_str()
            .to_owned();
        for _ in 0..5 {
            let again = balancer
                .choose(&pool, &ring, client(number))
                .expect("a member must be chosen");
            assert_eq!(
                again.id.as_str(),
                first,
                "client {number} moved between members"
            );
        }
    }
}

#[test]
fn source_ip_hash_still_uses_every_member() {
    // A hash that sent everybody to one member would pass the test above and
    // be useless.
    let pool = pool(
        LoadBalancingAlgorithm::SourceIpHash,
        &[
            ("one", 1, AdminState::Enabled),
            ("two", 1, AdminState::Enabled),
            ("three", 1, AdminState::Enabled),
        ],
    );
    let balancer = Balancer::new();
    let ring = ring_for(&pool);

    let reached: BTreeSet<String> = (1..500_u32)
        .filter_map(|number| balancer.choose(&pool, &ring, client(number)))
        .map(|member| member.id.as_str().to_owned())
        .collect();

    assert_eq!(reached.len(), 3, "the hash reached only {reached:?}");
}

#[test]
fn consistent_hash_moves_only_the_removed_members_share() {
    let before = pool(
        LoadBalancingAlgorithm::ConsistentHash,
        &[
            ("one", 1, AdminState::Enabled),
            ("two", 1, AdminState::Enabled),
            ("three", 1, AdminState::Enabled),
            ("four", 1, AdminState::Enabled),
        ],
    );
    // The same pool with one member taken out of service.
    let after = pool(
        LoadBalancingAlgorithm::ConsistentHash,
        &[
            ("one", 1, AdminState::Enabled),
            ("two", 1, AdminState::Enabled),
            ("three", 1, AdminState::Disabled),
            ("four", 1, AdminState::Enabled),
        ],
    );

    let balancer = Balancer::new();
    let ring_before = ring_for(&before);
    let ring_after = ring_for(&after);

    let clients = 2_000_u32;
    let mut was_on_three = 0_usize;
    let mut moved_but_was_not_on_three = 0_usize;

    for number in 1..=clients {
        let first = balancer
            .choose(&before, &ring_before, client(number))
            .expect("a member must be chosen")
            .id
            .as_str()
            .to_owned();
        let second = balancer
            .choose(&after, &ring_after, client(number))
            .expect("a member must be chosen")
            .id
            .as_str()
            .to_owned();

        if first == "three" {
            was_on_three += 1;
            assert_ne!(second, "three", "a removed member still took traffic");
        } else if first != second {
            moved_but_was_not_on_three += 1;
        }
    }

    assert!(
        was_on_three > 0,
        "no client was on the removed member, so the test measures nothing"
    );
    assert_eq!(
        moved_but_was_not_on_three, 0,
        "{moved_but_was_not_on_three} clients moved although their member stayed"
    );
}

#[test]
fn consistent_hash_sends_one_address_to_one_member_every_time() {
    let pool = pool(
        LoadBalancingAlgorithm::ConsistentHash,
        &[
            ("one", 1, AdminState::Enabled),
            ("two", 1, AdminState::Enabled),
            ("three", 1, AdminState::Enabled),
        ],
    );
    let balancer = Balancer::new();
    let ring = ring_for(&pool);

    for number in 1..200_u32 {
        let first = balancer
            .choose(&pool, &ring, client(number))
            .expect("a member must be chosen")
            .id
            .as_str()
            .to_owned();
        let again = balancer
            .choose(&pool, &ring, client(number))
            .expect("a member must be chosen");
        assert_eq!(again.id.as_str(), first);
    }
}

#[test]
fn the_ring_is_built_from_identity_rather_than_address() {
    // A member that is renumbered keeps its clients. Building the ring from
    // the address would move every one of them.
    let mut renumbered = pool(
        LoadBalancingAlgorithm::ConsistentHash,
        &[
            ("one", 1, AdminState::Enabled),
            ("two", 1, AdminState::Enabled),
            ("three", 1, AdminState::Enabled),
        ],
    );
    let original = renumbered.clone();
    for member in &mut renumbered.members {
        member.address = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 9));
        member.port = 9999;
    }

    assert_eq!(
        ring_for(&original),
        ring_for(&renumbered),
        "changing every address moved the ring"
    );
}

#[test]
fn a_member_taken_out_of_service_receives_nothing() {
    for state in [AdminState::Disabled, AdminState::Draining] {
        for algorithm in [
            LoadBalancingAlgorithm::RoundRobin,
            LoadBalancingAlgorithm::LeastConnections,
            LoadBalancingAlgorithm::SourceIpHash,
            LoadBalancingAlgorithm::ConsistentHash,
        ] {
            let pool = pool(
                algorithm,
                &[("taking", 1, AdminState::Enabled), ("out", 1, state)],
            );
            let balancer = Balancer::new();
            let ring = ring_for(&pool);

            for number in 1..100_u32 {
                let chosen = balancer
                    .choose(&pool, &ring, client(number))
                    .expect("the enabled member must be chosen");
                assert_eq!(
                    chosen.id.as_str(),
                    "taking",
                    "a member in state {state:?} took traffic under {algorithm:?}"
                );
            }
        }
    }
}

#[test]
fn a_pool_with_nobody_left_chooses_nothing() {
    // The caller turns this into an answer. Choosing a member that cannot
    // take the request would produce a closed connection instead.
    for algorithm in [
        LoadBalancingAlgorithm::RoundRobin,
        LoadBalancingAlgorithm::LeastConnections,
        LoadBalancingAlgorithm::SourceIpHash,
        LoadBalancingAlgorithm::ConsistentHash,
    ] {
        let pool = pool(algorithm, &[("out", 1, AdminState::Disabled)]);
        let balancer = Balancer::new();
        let ring = ring_for(&pool);

        assert!(
            balancer.choose(&pool, &ring, client(1)).is_none(),
            "a pool with nobody enabled chose a member under {algorithm:?}"
        );
    }
}

#[test]
fn the_hash_does_not_change_between_runs() {
    // Two processes must reach the same member during a graceful upgrade
    // (ADR-0025), so the arithmetic is pinned rather than left to whatever
    // the standard library hashes with today.
    assert_eq!(ek_ek_dataplane::hash(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(ek_ek_dataplane::hash(b"a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(ek_ek_dataplane::hash(b"foobar"), 0x85944171f73967e8);
}
