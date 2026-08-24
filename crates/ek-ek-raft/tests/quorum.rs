// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What losing a quorum must and must not do, from this crate's side.
//!
//! ADR-0004's invariant has two halves. This file measures the consensus half:
//! a node with no quorum still answers what it holds, refuses a write by name
//! rather than waiting, and works again the moment a quorum returns. The other
//! half, that traffic and virtual addresses do not notice any of it, is
//! measured in the lab where the traffic path actually runs
//! (`ek-ek-itest/tests/quorum.rs`).
//!
//! # Why the whole state is read back every time
//!
//! A cluster that lost its quorum and a cluster that quietly emptied itself
//! both refuse a write. Only the second one is a fault, and reading the state
//! back is what tells them apart.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use ek_ek_raft::Reason;
use ek_ek_store::Journal;

mod common;

use common::{Fleet, change, snapshot, steady};

/// A state that carries an authority as well as a config.
///
/// State is written whole, so a write that dropped the authority would leave
/// the cluster unable to admit anybody. Every write here carries it forward,
/// which is what every caller in the product does (ADR-0082).
fn holding(nodes: u32) -> ek_ek_store::Snapshot {
    snapshot(nodes).with_cluster(ek_ek_store::ClusterIdentity::new("the authority"))
}

/// The three nodes every measurement here runs.
const NAMES: [&str; 3] = ["node-a", "node-b", "node-c"];

/// How long a stopped node is given to be noticed.
const SETTLING: Duration = Duration::from_millis(800);

/// Stops every node but the one named, so no quorum is left anywhere.
async fn isolate(fleet: &mut Fleet, keep: &str) {
    let quiet: Vec<String> = NAMES
        .iter()
        .filter(|name| **name != keep)
        .map(|name| (*name).to_owned())
        .collect();
    for name in &quiet {
        fleet.named_mut(name).stop().await;
    }
    tokio::time::sleep(SETTLING).await;
}

#[tokio::test]
async fn a_quorum_that_comes_back_makes_writing_work_again() {
    // The half T-037 did not measure. A cluster that refused a write and never
    // recovered would satisfy every rule about refusing and none about being a
    // cluster.
    let mut fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    let leader = fleet.leader().id.clone();
    fleet
        .named(leader.as_str())
        .cluster()
        .write(&holding(4), &change("before the quiet"), 1_700_000_000)
        .await
        .expect("the leader writes while there is a quorum");
    fleet.await_agreement().await;

    isolate(&mut fleet, leader.as_str()).await;

    let refused = fleet
        .named(leader.as_str())
        .cluster()
        .write(&holding(5), &change("during the quiet"), 1_700_000_100)
        .await
        .expect_err("no quorum means no write");
    assert_eq!(refused.reason(), Reason::NoQuorum, "{refused}");

    // Both nodes come back on the stores they left behind, which is what a
    // restart is. A cluster that only recovered from a fresh store would not
    // be recovering.
    let settings = fleet.settings.clone();
    for name in NAMES.iter().filter(|name| **name != leader.as_str()) {
        fleet.named_mut(name).start(settings.clone()).await;
    }
    fleet.await_leader().await;

    let now_leading = fleet.leader().id.clone();
    let version = fleet
        .named(now_leading.as_str())
        .cluster()
        .write(&holding(6), &change("after the quiet"), 1_700_000_200)
        .await
        .expect("a quorum that came back writes again");
    fleet.await_agreement().await;

    // Every node holds it, so what came back is a cluster and not one node
    // writing to itself.
    for node in fleet.running() {
        let held = node
            .cluster()
            .read()
            .expect("readable")
            .expect("a state")
            .config
            .nodes
            .len();
        assert_eq!(held, 6, "{} did not receive the write", node.id.as_str());
    }
    assert!(version.get() > 0);

    // And the refused write is nowhere in the history. A record that was
    // refused and then applied when the quorum returned would be a change the
    // caller was told did not happen.
    let described: Vec<String> = fleet
        .named(now_leading.as_str())
        .store
        .export()
        .expect("readable")
        .versions
        .into_iter()
        .map(|version| version.description)
        .collect();
    assert!(
        !described.iter().any(|note| note == "during the quiet"),
        "a refused write reached the history: {described:?}"
    );
}

#[tokio::test]
async fn a_node_with_no_quorum_answers_what_it_holds_and_says_it_cannot_write() {
    // What a screen would show, measured where the answer comes from. The
    // screen itself is M9; this is the fact behind it, and a node that could
    // not answer this would leave an operator with nothing to look at exactly
    // when something is wrong (ADR-0085).
    let mut fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    let leader = fleet.leader().id.clone();
    fleet
        .named(leader.as_str())
        .cluster()
        .write(&holding(4), &change("before the quiet"), 1_700_000_000)
        .await
        .expect("the leader writes");
    fleet.await_agreement().await;

    let before = fleet
        .named(leader.as_str())
        .store
        .export()
        .expect("readable");
    isolate(&mut fleet, leader.as_str()).await;

    // Reading answers, and answers with everything. A node that could report
    // only half its state would show a screen that is wrong rather than a
    // screen that is late.
    let held = fleet
        .named(leader.as_str())
        .cluster()
        .read()
        .expect("a read does not need a quorum")
        .expect("the state is still held");
    assert_eq!(held.config.nodes.len(), 4);
    assert!(
        held.cluster.is_some(),
        "the authority went missing when the quorum did"
    );

    // The version history is readable too, which is what a rollback screen
    // reads. It is local, so no quorum is asked for it either.
    let after = fleet
        .named(leader.as_str())
        .store
        .export()
        .expect("readable");
    assert_eq!(
        after.versions.len(),
        before.versions.len(),
        "the history changed while nothing was written"
    );
    assert!(!after.versions.is_empty(), "there is no history to show");

    // And the node says why it cannot write, with a reason a caller can act
    // on rather than a message it would have to read.
    let refused = fleet
        .named(leader.as_str())
        .cluster()
        .write(&holding(9), &change("during the quiet"), 1_700_000_100)
        .await
        .expect_err("no quorum means no write");
    assert_eq!(refused.reason(), Reason::NoQuorum, "{refused}");
    assert_eq!(refused.reason().key(), "raft.no_quorum");
    assert!(
        refused.reason().worth_retrying(),
        "a lost quorum has to read as worth retrying, or a screen tells an \
         operator to give up: {refused}"
    );

    // Told apart from every other refusal. A screen that showed "no quorum"
    // for a schema mismatch would send an operator to the wrong problem.
    for other in Reason::ALL.iter().filter(|held| **held != Reason::NoQuorum) {
        assert_ne!(other.key(), refused.reason().key());
    }
}

#[tokio::test]
async fn asking_whether_the_cluster_is_there_is_what_answers_and_not_who_leads() {
    // The trap a status screen falls into. A leader that lost contact with its
    // quorum keeps naming itself in its own metrics, so `leader()` answers and
    // answers wrongly. `reachable()` is the question that costs a heartbeat
    // round and therefore knows (ADR-0085).
    let mut fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    let leader = fleet.leader().id.clone();
    fleet
        .named(leader.as_str())
        .cluster()
        .write(&holding(2), &change("before the quiet"), 1_700_000_000)
        .await
        .expect("the leader writes");
    fleet.await_agreement().await;

    fleet
        .named(leader.as_str())
        .cluster()
        .reachable()
        .await
        .expect("a leader with a quorum can reach it");

    isolate(&mut fleet, leader.as_str()).await;

    let refused = fleet
        .named(leader.as_str())
        .cluster()
        .reachable()
        .await
        .expect_err("a node with no quorum cannot reach one");
    assert_eq!(refused.reason(), Reason::NoQuorum, "{refused}");

    // The belief it kept, recorded rather than asserted away. This is exactly
    // why the question above has to exist: what the node believes and what is
    // true have come apart.
    let believed = fleet.named(leader.as_str()).cluster().leader();
    assert_eq!(
        believed,
        Some(leader.clone()),
        "the measurement below is about a stale belief and there is none"
    );

    // Reading still works while the cluster is unreachable, which is the
    // point of asking the two questions separately.
    assert!(
        fleet
            .named(leader.as_str())
            .cluster()
            .read()
            .expect("readable")
            .is_some(),
        "a node that cannot reach a quorum stopped answering as well"
    );

    // And a follower that cannot reach the leader says so by name, so a screen
    // on that node sends an operator to the right node.
    let settings = fleet.settings.clone();
    let follower = NAMES
        .iter()
        .find(|name| **name != leader.as_str())
        .expect("a second node");
    fleet.named_mut(follower).start(settings).await;
    fleet.await_leader().await;

    let elsewhere = fleet
        .named(follower)
        .cluster()
        .reachable()
        .await
        .expect_err("a follower does not lead");
    assert_eq!(elsewhere.reason(), Reason::NotLeader, "{elsewhere}");
    assert!(
        elsewhere.detail().contains(leader.as_str()),
        "the refusal does not name the leader: {elsewhere}"
    );
}

#[tokio::test]
async fn losing_a_quorum_writes_nothing_to_the_log() {
    // The half that says "no silent local write". A refusal that appended a
    // record would be a change the caller has been told did not happen,
    // waiting for a quorum to apply it.
    let mut fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    let leader = fleet.leader().id.clone();
    fleet
        .named(leader.as_str())
        .cluster()
        .write(&holding(3), &change("before the quiet"), 1_700_000_000)
        .await
        .expect("the leader writes");
    fleet.await_agreement().await;

    isolate(&mut fleet, leader.as_str()).await;

    let span = fleet.named(leader.as_str()).store.span().expect("readable");
    let versions = fleet
        .named(leader.as_str())
        .store
        .export()
        .expect("readable")
        .versions
        .len();

    // Three attempts rather than one. A first refusal that wrote nothing and a
    // second that wrote something would look the same from one call.
    for attempt in 0..3 {
        let refused = fleet
            .named(leader.as_str())
            .cluster()
            .write(
                &holding(20 + attempt),
                &change("during the quiet"),
                1_700_000_100 + i64::from(attempt),
            )
            .await
            .expect_err("no quorum means no write");
        assert_eq!(refused.reason(), Reason::NoQuorum, "{refused}");
    }

    assert_eq!(
        fleet.named(leader.as_str()).store.span().expect("readable"),
        span,
        "a refused write reached the replication log"
    );
    assert_eq!(
        fleet
            .named(leader.as_str())
            .store
            .export()
            .expect("readable")
            .versions
            .len(),
        versions,
        "a refused write reached the version history"
    );
    assert_eq!(
        fleet
            .named(leader.as_str())
            .cluster()
            .read()
            .expect("readable")
            .expect("a state")
            .config
            .nodes
            .len(),
        3,
        "a refused write reached the state"
    );
}
