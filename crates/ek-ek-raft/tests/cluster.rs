// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a three node cluster must hold true.
//!
//! Every measurement here runs three real Raft members over three real stores
//! on disk, talking over the real peer channel. A state machine that only ever
//! ran in memory would prove nothing about a node that restarts, and a
//! transport of its own would prove nothing about the one Raft actually rides
//! (ADR-0083).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;

use ek_ek_store::{History, Journal, Store, journal::marker};

mod common;

use common::{Fleet, PATIENCE, Tap, brisk, change, snapshot, steady, wait_until};

/// The three nodes every measurement here runs.
const NAMES: [&str; 3] = ["node-a", "node-b", "node-c"];

#[tokio::test]
async fn three_nodes_form_a_cluster_and_elect_one_leader() {
    let fleet = Fleet::start(&NAMES, steady()).await;

    // Before the cluster is brought into being nobody leads it, so the leader
    // below is the election and not a value that was there all along.
    assert!(
        fleet
            .nodes
            .iter()
            .all(|node| node.cluster().leader().is_none()),
        "a node named a leader before the cluster existed"
    );

    fleet.initialise().await;

    let leader = fleet.await_leader().await;
    assert!(
        NAMES.contains(&leader.as_str()),
        "the leader is not one of these nodes: {}",
        leader.as_str()
    );
    // One leader, and every node names the same one.
    assert_eq!(
        fleet
            .nodes
            .iter()
            .filter(|node| node.cluster().is_leader())
            .count(),
        1,
        "more than one node believes it leads"
    );
}

#[tokio::test]
async fn a_config_written_on_one_node_is_read_on_the_other_two() {
    let fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    // Nobody holds it before the write, so what is read afterwards arrived.
    assert!(
        fleet
            .nodes
            .iter()
            .all(|node| node.cluster().read().expect("readable").is_none()),
        "a node held a config before one was written"
    );

    fleet
        .leader()
        .cluster()
        .write(&snapshot(3), &change("the first config"), 1_700_000_000)
        .await
        .expect("the leader writes");

    let arrived = wait_until(PATIENCE, || {
        fleet
            .nodes
            .iter()
            .all(|node| {
                node.cluster()
                    .read()
                    .expect("readable")
                    .is_some_and(|held| held.config.nodes.len() == 3)
            })
            .then_some(())
    })
    .await;
    assert!(arrived.is_some(), "the config did not reach every node");

    // The key material arrived too. A node holding the config without the keys
    // could not terminate a single connection (ADR-0018).
    for node in &fleet.nodes {
        let held = node.cluster().read().expect("readable").expect("a config");
        assert_eq!(
            held.secrets[&ek_ek_config::SecretId::new("key-cert-web")].expose(),
            b"the key material for 3",
            "{} holds the config without the key material",
            node.id.as_str()
        );
    }
}

#[tokio::test]
async fn a_write_to_a_node_that_does_not_lead_is_refused_and_names_the_leader() {
    let fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    let leader = fleet.leader().id.clone();
    let follower = fleet.follower();

    let failure = follower
        .cluster()
        .write(&snapshot(2), &change("from a follower"), 1_700_000_000)
        .await
        .expect_err("a follower refuses to write");

    assert_eq!(failure.reason(), ek_ek_raft::Reason::NotLeader);
    assert!(
        failure.detail().contains(leader.as_str()),
        "the refusal does not say where to write instead: {failure}"
    );
    assert!(
        !failure.reason().worth_retrying(),
        "a caller told to write elsewhere would keep asking the same node"
    );

    // Nothing landed anywhere. A refusal that wrote would be worse than one
    // that forwarded.
    assert!(
        fleet
            .nodes
            .iter()
            .all(|node| node.cluster().read().expect("readable").is_none()),
        "the refused write reached a node"
    );

    // And the leader takes the same write, so the refusal is the role and not
    // the write itself.
    fleet
        .leader()
        .cluster()
        .write(&snapshot(2), &change("from the leader"), 1_700_000_000)
        .await
        .expect("the leader writes");
}

#[tokio::test]
async fn stopping_the_leader_elects_another_and_writing_carries_on() {
    let mut fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    fleet
        .leader()
        .cluster()
        .write(&snapshot(1), &change("before the change"), 1_700_000_000)
        .await
        .expect("the leader writes");
    fleet.await_agreement().await;

    let was = fleet.leader().id.clone();
    fleet.named_mut(was.as_str()).stop().await;

    let now = wait_until(PATIENCE, || {
        let named = fleet.running().find_map(|node| node.cluster().leader());
        named.filter(|leader| *leader != was)
    })
    .await
    .expect("a new leader is elected");
    assert_ne!(now, was, "the stopped node is still named as leader");

    // The point of the election: writing carries on.
    let version = fleet
        .named(now.as_str())
        .cluster()
        .write(&snapshot(4), &change("after the change"), 1_700_000_100)
        .await
        .expect("the new leader writes");
    assert!(version.get() > 0);

    let arrived = wait_until(PATIENCE, || {
        fleet
            .running()
            .all(|node| {
                node.cluster()
                    .read()
                    .expect("readable")
                    .is_some_and(|held| held.config.nodes.len() == 4)
            })
            .then_some(())
    })
    .await;
    assert!(
        arrived.is_some(),
        "the write after the election did not reach the nodes still running"
    );
}

#[tokio::test]
async fn a_node_that_was_stopped_catches_up_on_what_it_missed() {
    let mut fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    // Stopped before anything was written, so what it holds afterwards is what
    // it caught up on.
    let away = fleet
        .running()
        .find(|node| !node.cluster().is_leader())
        .expect("a follower runs")
        .id
        .clone();
    fleet.named_mut(away.as_str()).stop().await;
    assert!(
        fleet
            .named(away.as_str())
            .store
            .read()
            .expect("readable")
            .is_none(),
        "the stopped node already held a config"
    );

    for number in 1..=3_u32 {
        fleet
            .leader()
            .cluster()
            .write(
                &snapshot(number),
                &change("while it was away"),
                1_700_000_000 + i64::from(number),
            )
            .await
            .expect("the leader writes");
    }

    let settings = fleet.settings.clone();
    fleet.named_mut(away.as_str()).start(settings).await;

    let caught = wait_until(PATIENCE, || {
        fleet
            .named(away.as_str())
            .cluster()
            .read()
            .expect("readable")
            .filter(|held| held.config.nodes.len() == 3)
    })
    .await;
    assert!(
        caught.is_some(),
        "the node that came back did not catch up on what it missed"
    );

    // It caught up by replaying records, not by taking a snapshot: nothing
    // ever asked for one at these settings.
    assert!(
        fleet
            .named(away.as_str())
            .store
            .snapshot()
            .expect("readable")
            .is_none(),
        "a snapshot was installed where replay was enough"
    );
}

#[tokio::test]
async fn a_node_that_was_away_a_long_time_catches_up_by_snapshot() {
    // The records it missed are gone by the time it comes back, so replay is
    // not open to it. A cluster that could not do this would need an operator
    // to rebuild the node by hand.
    let mut fleet = Fleet::start(&NAMES, brisk(4)).await;
    fleet.initialise().await;

    let away = fleet
        .running()
        .find(|node| !node.cluster().is_leader())
        .expect("a follower runs")
        .id
        .clone();
    fleet.named_mut(away.as_str()).stop().await;

    for number in 1..=12_u32 {
        fleet
            .leader()
            .cluster()
            .write(
                &snapshot(number),
                &change("while it was away"),
                1_700_000_000 + i64::from(number),
            )
            .await
            .expect("the leader writes");
    }

    // The leader took snapshots and dropped the records they cover, so there
    // is nothing left to replay.
    let compacted = wait_until(PATIENCE, || {
        fleet
            .leader()
            .store
            .marker(marker::PURGED)
            .expect("readable")
    })
    .await;
    assert!(
        compacted.is_some(),
        "the leader never compacted, so this measures replay and not snapshot"
    );

    let settings = fleet.settings.clone();
    fleet.named_mut(away.as_str()).start(settings).await;

    let caught = wait_until(PATIENCE, || {
        fleet
            .named(away.as_str())
            .cluster()
            .read()
            .expect("readable")
            .filter(|held| held.config.nodes.len() == 12)
    })
    .await;
    assert!(
        caught.is_some(),
        "the node that was away did not catch up by snapshot"
    );
    assert!(
        fleet
            .named(away.as_str())
            .store
            .snapshot()
            .expect("readable")
            .is_some(),
        "the node caught up without ever installing a snapshot"
    );
}

#[tokio::test]
async fn the_version_history_is_the_same_on_every_node() {
    // T-015's history is what an operator rolls back through. Three nodes with
    // three histories would send an operator to a different config depending
    // on which node they opened.
    let fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    for number in 1..=4_u32 {
        fleet
            .leader()
            .cluster()
            .write(
                &snapshot(number),
                &change(&format!("change {number}")),
                1_700_000_000 + i64::from(number),
            )
            .await
            .expect("the leader writes");
    }
    fleet.await_agreement().await;

    let expected = fleet.leader().store.versions().expect("readable");
    assert_eq!(expected.len(), 4, "the leader did not record four versions");

    for node in &fleet.nodes {
        let held = node.store.versions().expect("readable");
        assert_eq!(
            held.len(),
            expected.len(),
            "{} holds a different number of versions",
            node.id.as_str()
        );
        for (mine, theirs) in held.iter().zip(expected.iter()) {
            assert_eq!(
                mine.id,
                theirs.id,
                "{} renumbered a version",
                node.id.as_str()
            );
            assert_eq!(
                mine.recorded_at_unix,
                theirs.recorded_at_unix,
                "{} stamped a version with its own clock",
                node.id.as_str()
            );
            assert_eq!(mine.description, theirs.description);
            // The config each version holds, not only its label. Two nodes
            // could agree on every heading and still hold different documents.
            assert_eq!(
                node.store.version_config(mine.id).expect("readable"),
                fleet
                    .leader()
                    .store
                    .version_config(theirs.id)
                    .expect("readable"),
                "{} holds a different config under version {}",
                node.id.as_str(),
                mine.id.get()
            );
        }
    }
}

#[tokio::test]
async fn raft_traffic_goes_over_the_peer_channel_and_cannot_be_read_off_the_wire() {
    // A configuration and its key material cross the network on every
    // replicated write. Neither may be readable by anybody watching
    // (ADR-0008, ADR-0082), and the only way to know is to watch.
    let fleet = Fleet::start(&NAMES, steady()).await;

    // A relay in front of one node, so what the leader sends it is kept.
    let watched = fleet.nodes[2].id.clone();
    let tap = Tap::open(fleet.nodes[2].address).await;
    let mut peers: BTreeMap<_, _> = fleet
        .nodes
        .iter()
        .map(|node| (node.id.clone(), node.address.to_string()))
        .collect();
    peers.insert(watched.clone(), tap.address.to_string());
    fleet.initialise_at(peers).await;

    let material = b"the key material for 5".to_vec();
    fleet
        .leader()
        .cluster()
        .write(&snapshot(5), &change("a config with a key"), 1_700_000_000)
        .await
        .expect("the leader writes");

    // The watched node holds it, so the traffic that carried it really crossed
    // the relay.
    let arrived = wait_until(PATIENCE, || {
        fleet
            .named(watched.as_str())
            .cluster()
            .read()
            .expect("readable")
            .filter(|held| held.config.nodes.len() == 5)
    })
    .await;
    assert!(
        arrived.is_some(),
        "the write never reached the watched node"
    );

    let seen = tap.seen();
    assert!(!seen.is_empty(), "nothing crossed the relay");

    // Not the key material, and not the names of the calls that carried it. A
    // channel in the clear would show every one of these.
    for marker in [
        material.as_slice(),
        ek_ek_raft::APPEND_ENTRIES.as_bytes(),
        ek_ek_raft::VOTE.as_bytes(),
        b"vip-web".as_slice(),
        b"schema_version".as_slice(),
    ] {
        assert!(
            !seen.windows(marker.len()).any(|window| window == marker),
            "{} crossed the network in the clear",
            String::from_utf8_lossy(marker)
        );
    }

    // And a TLS record header is there, so what crossed was an encrypted
    // channel and not a socket nobody wrote to.
    assert_eq!(
        seen.first(),
        Some(&0x16),
        "what crossed the relay did not begin with a TLS handshake"
    );
}

#[tokio::test]
async fn a_node_that_drops_the_agreed_history_and_audit_log_takes_them_back() {
    // The history is agreed, not local. A node that removed a row of its own
    // gets it back the moment it takes the cluster's state again, which is
    // what keeps one node from quietly losing an audit trail.
    let mut fleet = Fleet::start(&NAMES, brisk(2)).await;
    fleet.initialise().await;

    for number in 1..=3_u32 {
        fleet
            .leader()
            .cluster()
            .write(
                &snapshot(number),
                &change(&format!("change {number}")),
                1_700_000_000 + i64::from(number),
            )
            .await
            .expect("the leader writes");
    }
    fleet.await_agreement().await;

    // An audit row on the leader, so what the snapshot carries includes the
    // audit log and not only the version history. M8 writes these rows through
    // the state machine; here one is placed on the leader directly so the
    // replication of the table itself is what gets measured.
    let seeded = {
        let mut state = fleet.leader().store.export().expect("exportable");
        state.audit.push(ek_ek_store::AuditRecord {
            recorded_at_unix: 1_700_000_500,
            actor: "admin".to_owned(),
            action: "config.write".to_owned(),
            subject: Some("vip-web".to_owned()),
            detail: Some("an operator changed it".to_owned()),
        });
        fleet
            .leader()
            .store
            .import(&state, &[])
            .expect("the row is placed");
        state.audit.len()
    };
    assert_eq!(seeded, 1, "the leader does not hold the audit row");

    let away = fleet
        .running()
        .find(|node| !node.cluster().is_leader())
        .expect("a follower runs")
        .id
        .clone();
    fleet.named_mut(away.as_str()).stop().await;

    // The node, on its own, throws its history and its audit log away.
    let store = std::sync::Arc::clone(&fleet.named(away.as_str()).store);
    store
        .import(
            &ek_ek_store::FullState {
                snapshot: None,
                versions: Vec::new(),
                audit: Vec::new(),
            },
            &[],
        )
        .expect("the node drops what it held");
    assert!(
        store.versions().expect("readable").is_empty(),
        "the history did not go away"
    );
    assert!(
        store.export().expect("exportable").audit.is_empty(),
        "the audit log did not go away"
    );

    // More changes while it is away, so it has to take a snapshot to come
    // back, and the snapshot carries the whole agreed history.
    for number in 4..=9_u32 {
        fleet
            .leader()
            .cluster()
            .write(
                &snapshot(number),
                &change(&format!("change {number}")),
                1_700_000_000 + i64::from(number),
            )
            .await
            .expect("the leader writes");
    }

    let settings = fleet.settings.clone();
    fleet.named_mut(away.as_str()).start(settings).await;

    let expected = fleet.leader().store.versions().expect("readable").len();
    let restored = wait_until(PATIENCE, || {
        let held = fleet
            .named(away.as_str())
            .store
            .versions()
            .expect("readable");
        (held.len() == expected).then_some(held)
    })
    .await;
    assert!(
        restored.is_some(),
        "the history the node dropped did not come back"
    );

    let audit = wait_until(PATIENCE, || {
        let held = fleet
            .named(away.as_str())
            .store
            .export()
            .expect("exportable")
            .audit;
        (!held.is_empty()).then_some(held)
    })
    .await
    .expect("the audit log the node dropped did not come back");
    assert_eq!(audit[0].action, "config.write");
    assert_eq!(
        audit[0].detail.as_deref(),
        Some("an operator changed it"),
        "the audit row came back without what it said"
    );
}

#[tokio::test]
async fn a_read_is_answered_without_asking_a_quorum() {
    // ADR-0004's invariant, from this crate's side. Reading touches the local
    // store and nothing else, so a node reads what it holds whether or not it
    // can reach anybody. T-039 measures the invariant across a real partition.
    let mut fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    fleet
        .leader()
        .cluster()
        .write(&snapshot(6), &change("before the quiet"), 1_700_000_000)
        .await
        .expect("the leader writes");
    fleet.await_agreement().await;

    // Two of three gone, so no quorum is left anywhere.
    let leader = fleet.leader().id.clone();
    let quiet: Vec<String> = NAMES
        .iter()
        .filter(|name| **name != leader.as_str())
        .map(|name| (*name).to_owned())
        .collect();
    for name in &quiet {
        fleet.named_mut(name).stop().await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    let held = fleet
        .named(leader.as_str())
        .cluster()
        .read()
        .expect("a read does not need a quorum")
        .expect("the config is still held");
    assert_eq!(held.config.nodes.len(), 6);

    // And writing is refused, so the read above is the invariant and not a
    // cluster that is quietly still working.
    let before = fleet.named(leader.as_str()).store.span().expect("readable");
    let refused = tokio::time::timeout(
        Duration::from_secs(30),
        fleet.named(leader.as_str()).cluster().write(
            &snapshot(7),
            &change("during the quiet"),
            1_700_000_200,
        ),
    )
    .await
    .expect("a write with no quorum answers rather than waiting for ever");
    let failure = refused.expect_err("no quorum means no write");
    assert_eq!(failure.reason(), ek_ek_raft::Reason::NoQuorum);
    assert!(
        failure.reason().worth_retrying(),
        "a caller told there is no quorum would give up instead of waiting"
    );

    // Nothing was proposed. A refusal that appended a record would be a change
    // the caller has been told did not happen, waiting for a quorum to apply
    // it.
    assert_eq!(
        fleet.named(leader.as_str()).store.span().expect("readable"),
        before,
        "the refused write reached the log"
    );

    // The config is still the one from before, on the node that refused.
    assert_eq!(
        fleet
            .named(leader.as_str())
            .cluster()
            .read()
            .expect("readable")
            .expect("a config")
            .config
            .nodes
            .len(),
        6
    );
}

#[tokio::test]
async fn a_write_nobody_acknowledges_answers_rather_than_waiting_for_ever() {
    // The guarantee a person at a screen depends on: a configuration write
    // always answers. Here both followers answer heartbeats and acknowledge
    // nothing, so the leader keeps believing it leads and its record is never
    // agreed. That state hangs the library's own call unless something bounds
    // it.
    let fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    for node in &fleet.nodes {
        if !node.cluster().is_leader() {
            node.relay.go_deaf();
        }
    }

    let started = std::time::Instant::now();
    let refused = tokio::time::timeout(
        ek_ek_raft::WRITE_PATIENCE + Duration::from_secs(30),
        fleet
            .leader()
            .cluster()
            .write(&snapshot(8), &change("nobody answers"), 1_700_000_300),
    )
    .await
    .expect("the write answers rather than waiting for ever")
    .expect_err("a record nobody acknowledges is not agreed");

    // Whatever the reason, it has to be one the caller can act on, and it has
    // to arrive. Which of the two arrives depends on whether the leader steps
    // down before the bound runs out, and both are honest answers.
    assert!(
        matches!(
            refused.reason(),
            ek_ek_raft::Reason::NoQuorum | ek_ek_raft::Reason::NotLeader
        ),
        "the refusal is not one a caller can act on: {refused}"
    );
    assert!(
        started.elapsed() < ek_ek_raft::WRITE_PATIENCE + Duration::from_secs(30),
        "the write took {:?}",
        started.elapsed()
    );

    // Nothing was applied on any node, so the refusal is not a write that
    // landed under another name.
    for node in &fleet.nodes {
        assert!(
            node.cluster()
                .read()
                .expect("readable")
                .is_none_or(|held| held.config.nodes.len() != 8),
            "{} applied a record the caller was told was not agreed",
            node.id.as_str()
        );
    }
}

#[tokio::test]
async fn a_raft_call_this_node_does_not_answer_is_refused_by_name() {
    // The transport carries a service name. A node that answered an unknown
    // one would let a newer release believe a call landed.
    let fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    let service = ek_ek_raft::service(fleet.leader().cluster().raft().clone());
    let caller = fleet.follower().id.clone();

    let refused = service
        .call(&caller, "raft.something_else", serde_json::json!({}))
        .await
        .expect_err("a service this node does not run is refused");
    assert!(
        refused.detail().contains("raft.something_else"),
        "the refusal does not name the service: {refused}"
    );

    // And a call it does run is answered, so the refusal is the name and not
    // the service refusing everything.
    let answered = service
        .call(
            &caller,
            ek_ek_raft::VOTE,
            serde_json::to_value(openraft::raft::VoteRequest::new(
                openraft::Vote::new(99, ek_ek_raft::identity::of(&caller)),
                Some(openraft::LogId::new(
                    openraft::CommittedLeaderId::new(1, ek_ek_raft::identity::of(&caller)),
                    1,
                )),
            ))
            .expect("the request writes out"),
        )
        .await
        .expect("a vote is answered");
    assert!(
        answered.get("vote").is_some(),
        "the answer is not a vote answer: {answered}"
    );
}
