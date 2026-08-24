// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the number consensus calls a node must hold true.
//!
//! The derivation is not an implementation detail that can be changed later:
//! a node whose number moved would be a new node to the cluster, and the old
//! one would still hold a vote nobody can cast.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_config::NodeId;
use ek_ek_raft::identity;

#[test]
fn one_name_always_derives_to_one_number() {
    // The rule a restart depends on. A node that came back under a different
    // number would be a stranger to the cluster it just left.
    let node = NodeId::new("node-a");
    assert_eq!(identity::of(&node), identity::of(&node));
    assert_eq!(identity::of(&node), identity::of(&NodeId::new("node-a")));
}

#[test]
fn the_number_is_written_down_so_a_release_cannot_move_it() {
    // Compared against a value written here rather than against the function
    // that produced it. A comparison with itself would pass whatever the
    // derivation did, and an upgrade that moved every node's number would
    // split the cluster in half with nothing to show why.
    assert_eq!(
        identity::of(&NodeId::new("node-a")),
        11_840_437_437_241_850_716
    );
    assert_eq!(
        identity::of(&NodeId::new("node-b")),
        9_849_101_705_626_650_435
    );
    assert_eq!(identity::of(&NodeId::new("")), 17_525_818_358_410_699_292);
}

#[test]
fn two_names_derive_to_two_numbers() {
    let names = ["node-a", "node-b", "node-c", "node-1", "a", ""];
    for (left, right) in names.iter().zip(names.iter().skip(1)) {
        assert_ne!(
            identity::of(&NodeId::new(*left)),
            identity::of(&NodeId::new(*right)),
            "{left} and {right} are one node to consensus"
        );
    }
}

#[test]
fn the_number_is_not_the_one_the_same_name_derives_to_elsewhere() {
    // The domain separator. Without it a node's number would equal the number
    // the config derives from the same name for something else, and two rules
    // that must not interact would start agreeing by accident.
    let name = "node-a";
    let mut plain = sha2_of(name.as_bytes());
    plain.truncate(8);
    let mut first = [0_u8; 8];
    first.copy_from_slice(&plain);
    assert_ne!(
        identity::of(&NodeId::new(name)),
        u64::from_be_bytes(first),
        "the name is hashed with nothing to say what it is"
    );
}

#[test]
fn the_length_goes_in_before_the_name() {
    // Without it a longer domain and a shorter name would hash to the same
    // input as a shorter domain and a longer name.
    let joined = format!(
        "{}{}",
        String::from_utf8_lossy(identity::DOMAIN),
        "extra-node-a"
    );
    assert_ne!(
        identity::of(&NodeId::new("node-a")),
        identity::of(&NodeId::new(&joined))
    );
}

#[test]
fn a_membership_of_different_names_is_accepted() {
    let names = [
        NodeId::new("node-a"),
        NodeId::new("node-b"),
        NodeId::new("node-c"),
    ];
    identity::unique(names.iter()).expect("three different names are three nodes");
}

#[test]
fn a_name_repeated_in_a_membership_is_still_one_node() {
    // A membership listing one node twice is a membership, not a collision.
    let names = [NodeId::new("node-a"), NodeId::new("node-a")];
    identity::unique(names.iter()).expect("one name twice is one node");
}

#[test]
fn two_names_that_derive_to_one_number_are_refused_by_name() {
    // The case that must never pass quietly: consensus would count one vote
    // twice. No two short names really collide, so the comparison is fed the
    // collision directly. That is what `distinct` exists for.
    let left = NodeId::new("node-a");
    let right = NodeId::new("node-b");

    let failure = identity::distinct([(7_u64, &left), (7_u64, &right)])
        .expect_err("two names under one number are refused");
    assert_eq!(failure.reason(), ek_ek_raft::Reason::Configuration);
    assert!(
        failure.detail().contains("node-a") && failure.detail().contains("node-b"),
        "the refusal does not name both nodes: {failure}"
    );

    // And two names under two numbers are accepted, so the refusal above is
    // the collision and not the rule refusing everything.
    identity::distinct([(7_u64, &left), (8_u64, &right)]).expect("two numbers are two nodes");
}

fn sha2_of(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finalize().to_vec()
}
