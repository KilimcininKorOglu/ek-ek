// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the log store and the state machine must hold true on their own.
//!
//! A running cluster reaches most of this, but not all of it. Throwing away a
//! record a new leader disagrees with needs two logs that diverged, and a
//! cluster that behaves correctly never produces one. The traits are driven
//! directly here so those rules are measured rather than assumed.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Cursor;
use std::sync::Arc;

use ek_ek_raft::{
    LogStore, NodeNumber, PeerNode, StateMachine, TypeConfig, WireSnapshot, WireState, WriteRequest,
};
use ek_ek_store::journal::marker;
use ek_ek_store::{Journal, SqliteStore, Store};
use openraft::storage::{RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine};
use openraft::{
    CommittedLeaderId, Entry, EntryPayload, LogId, RaftLogReader, SnapshotMeta, StoredMembership,
    Vote,
};
use tempfile::TempDir;

mod common;

use common::{change, config, snapshot};

/// The term every record in these measurements carries.
const TERM: u64 = 1;

/// The node every record in these measurements was written by.
const WRITER: NodeNumber = 7;

fn opened() -> (TempDir, Arc<SqliteStore>) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let store = Arc::new(SqliteStore::open(directory.path()).expect("the store opens"));
    (directory, store)
}

fn log_id(index: u64) -> LogId<NodeNumber> {
    LogId::new(CommittedLeaderId::new(TERM, WRITER), index)
}

/// A record that changes nothing, so a log can be built at any length.
fn blank(index: u64) -> Entry<TypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Blank,
    }
}

/// A record that replaces the state.
fn write(index: u64, nodes: u32, now_unix: i64) -> Entry<TypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(WriteRequest {
            state: WireSnapshot::from(&snapshot(nodes)),
            change: (&change("replicated")).into(),
            now_unix,
            audit: Vec::new(),
        }),
    }
}

fn append(log: &LogStore, entries: Vec<Entry<TypeConfig>>) {
    log.keep(entries).expect("the records are written");
}

#[tokio::test]
async fn a_record_a_new_leader_disagrees_with_is_thrown_away() {
    // The record at the index named goes too. A truncate that kept it would
    // leave the node holding a record the cluster has already replaced, and
    // the next append would land on top of a different term.
    let (_directory, store) = opened();
    let mut log = LogStore::new(Arc::clone(&store));

    append(&log, (1..=5).map(blank).collect());
    assert_eq!(
        log.get_log_state().await.expect("readable").last_log_id,
        Some(log_id(5))
    );

    log.truncate(log_id(3))
        .await
        .expect("the tail is thrown away");

    assert_eq!(
        log.get_log_state().await.expect("readable").last_log_id,
        Some(log_id(2)),
        "the record at the index named survived the truncate"
    );
    assert!(
        log.try_get_log_entries(3..4)
            .await
            .expect("readable")
            .is_empty(),
        "the record at the index named is still readable"
    );
}

#[tokio::test]
async fn a_compacted_log_still_reports_where_it_ends() {
    // A follower asks for what comes after the last id it was told about. A
    // node that reported nothing after compaction would be asked for records
    // it deliberately removed, over and over.
    let (_directory, store) = opened();
    let mut log = LogStore::new(Arc::clone(&store));

    append(&log, (1..=4).map(blank).collect());
    log.purge(log_id(4)).await.expect("the log is compacted");

    let state = log.get_log_state().await.expect("readable");
    assert_eq!(
        state.last_purged_log_id,
        Some(log_id(4)),
        "the compaction was not recorded"
    );
    assert_eq!(
        state.last_log_id,
        Some(log_id(4)),
        "an empty log after compaction reports no end at all"
    );
    assert!(
        store.records(1, 5).expect("readable").is_empty(),
        "the records were not removed"
    );
}

#[tokio::test]
async fn the_end_of_the_log_carries_the_term_the_record_was_written_under() {
    // The id is a term and an index. A node that reported the index alone and
    // filled in a term of its own would tell a leader its log matches when it
    // does not.
    let (_directory, store) = opened();
    let mut log = LogStore::new(Arc::clone(&store));

    let later = LogId::new(CommittedLeaderId::new(9, WRITER), 1);
    append(
        &log,
        vec![Entry {
            log_id: later,
            payload: EntryPayload::Blank,
        }],
    );

    assert_eq!(
        log.get_log_state().await.expect("readable").last_log_id,
        Some(later),
        "the term the record was written under was not read back"
    );
}

#[tokio::test]
async fn a_vote_written_is_the_vote_read_back() {
    let (_directory, store) = opened();
    let mut log = LogStore::new(Arc::clone(&store));

    assert_eq!(log.read_vote().await.expect("readable"), None);
    let vote = Vote::new(4, WRITER);
    log.save_vote(&vote).await.expect("written");
    assert_eq!(log.read_vote().await.expect("readable"), Some(vote));

    // And it survives a fresh adapter over the same store, because a vote held
    // only in memory is a vote a restarted node can cast twice.
    let mut reopened = LogStore::new(Arc::clone(&store));
    assert_eq!(reopened.read_vote().await.expect("readable"), Some(vote));
}

#[tokio::test]
async fn an_applied_record_moves_the_state_and_the_position_together() {
    let (_directory, store) = opened();
    let mut machine = StateMachine::new(Arc::clone(&store));

    assert_eq!(machine.applied_state().await.expect("readable").0, None);

    let answers = machine
        .apply(vec![write(1, 3, 1_700_000_000)])
        .await
        .expect("the record applies");
    assert_eq!(answers.len(), 1);
    assert!(answers[0].version > 0, "no version was appended");

    assert_eq!(
        machine.applied_state().await.expect("readable").0,
        Some(log_id(1)),
        "the state moved without the position that says it did"
    );
    assert_eq!(
        store
            .read()
            .expect("readable")
            .expect("a state")
            .config
            .nodes
            .len(),
        3
    );
}

#[tokio::test]
async fn the_moment_an_applied_record_carries_is_the_one_it_is_written_under() {
    // Every node applies the same record. A node reading its own clock would
    // give three nodes three histories of one change (ADR-0083).
    let (_directory, store) = opened();
    let mut machine = StateMachine::new(Arc::clone(&store));

    let at = 1_600_000_000;
    machine.apply(vec![write(1, 2, at)]).await.expect("applies");

    let versions = ek_ek_store::History::versions(store.as_ref()).expect("readable");
    assert_eq!(
        versions[0].recorded_at_unix, at,
        "the version was stamped with something other than the moment in the record"
    );
}

#[tokio::test]
async fn a_membership_record_is_remembered_with_the_position_it_arrived_at() {
    let (_directory, store) = opened();
    let mut machine = StateMachine::new(Arc::clone(&store));

    let membership = openraft::Membership::new(
        vec![[WRITER].into_iter().collect()],
        std::collections::BTreeMap::from([(WRITER, PeerNode::new("node-a", "127.0.0.1:1"))]),
    );
    machine
        .apply(vec![Entry {
            log_id: log_id(2),
            payload: EntryPayload::Membership(membership.clone()),
        }])
        .await
        .expect("applies");

    let (applied, held) = machine.applied_state().await.expect("readable");
    assert_eq!(applied, Some(log_id(2)));
    assert_eq!(
        held.membership(),
        &membership,
        "the membership was forgotten"
    );
    assert_eq!(
        held.voter_ids().collect::<Vec<_>>(),
        vec![WRITER],
        "the voters were forgotten"
    );
}

#[tokio::test]
async fn two_snapshots_at_two_positions_are_two_snapshots() {
    // A follower asks whether it already holds a snapshot by its name. A name
    // that never changed would let a node skip one it has not installed.
    let (_directory, store) = opened();
    let mut machine = StateMachine::new(Arc::clone(&store));

    let empty = machine.build_snapshot().await.expect("a snapshot is built");

    machine
        .apply(vec![write(1, 3, 1_000)])
        .await
        .expect("applies");
    let first = machine.build_snapshot().await.expect("a snapshot is built");

    machine
        .apply(vec![write(2, 4, 2_000)])
        .await
        .expect("applies");
    let second = machine.build_snapshot().await.expect("a snapshot is built");

    assert_ne!(
        empty.meta.snapshot_id, first.meta.snapshot_id,
        "a snapshot of an empty node is named the same as one holding a config"
    );
    assert_ne!(
        first.meta.snapshot_id, second.meta.snapshot_id,
        "two snapshots at two positions carry one name"
    );
    assert_eq!(first.meta.last_log_id, Some(log_id(1)));
    assert_eq!(second.meta.last_log_id, Some(log_id(2)));
}

#[tokio::test]
async fn a_snapshot_carries_the_state_the_history_and_the_authority() {
    let (_directory, store) = opened();
    let mut machine = StateMachine::new(Arc::clone(&store));

    // A cluster identity on the node, and a replicated write that carries it
    // forward. The state is written whole, so a caller that dropped the field
    // would remove the authority; that rule belongs to the caller and is
    // measured in the store (ADR-0082).
    let held = snapshot(3).with_cluster(ek_ek_store::ClusterIdentity::new("the authority"));
    store
        .write_at(&held, &change("with an authority"), 1_000)
        .expect("written");
    machine
        .apply(vec![Entry {
            log_id: log_id(1),
            payload: EntryPayload::Normal(WriteRequest {
                state: WireSnapshot::from(
                    &snapshot(5).with_cluster(ek_ek_store::ClusterIdentity::new("the authority")),
                ),
                change: (&change("replicated")).into(),
                now_unix: 2_000,
                audit: Vec::new(),
            }),
        }])
        .await
        .expect("applies");

    let taken = machine.build_snapshot().await.expect("a snapshot is built");
    let carried: WireState =
        serde_json::from_slice(&taken.snapshot.into_inner()).expect("the snapshot reads back");

    let state = carried.snapshot.as_ref().expect("a state travels");
    assert_eq!(state.config.nodes.len(), 5);
    assert_eq!(
        state.secrets["key-cert-web"],
        b"the key material for 5".to_vec(),
        "the key material did not travel"
    );
    assert_eq!(
        state.cluster.as_deref(),
        Some("the authority"),
        "the cluster authority did not travel"
    );
    assert_eq!(
        carried.versions.len(),
        2,
        "the history did not travel whole"
    );
}

#[tokio::test]
async fn an_installed_snapshot_arrives_with_the_position_it_was_taken_at() {
    // A node that took the state without the position would install the same
    // snapshot again on the way back up, and would ask for records it holds.
    let (_directory, ours) = opened();
    let (_theirs, theirs) = opened();

    let mut leader = StateMachine::new(Arc::clone(&theirs));
    leader
        .apply(vec![write(1, 4, 1_000)])
        .await
        .expect("applies");
    let taken = leader.build_snapshot().await.expect("a snapshot is built");
    let payload = taken.snapshot.into_inner();

    let mut follower = StateMachine::new(Arc::clone(&ours));
    follower
        .install_snapshot(&taken.meta, Box::new(Cursor::new(payload.clone())))
        .await
        .expect("the snapshot installs");

    assert_eq!(
        follower.applied_state().await.expect("readable").0,
        Some(log_id(1)),
        "the state arrived without the position it was taken at"
    );
    assert_eq!(
        ours.read()
            .expect("readable")
            .expect("a state")
            .config
            .nodes
            .len(),
        4
    );
    assert!(
        ours.snapshot().expect("readable").is_some(),
        "the node did not keep the snapshot it installed"
    );
}

#[tokio::test]
async fn an_installed_snapshot_keeps_the_version_numbers_it_arrived_with() {
    // Version numbers are how an operator names a rollback. A node that
    // renumbered them would send an operator to a different config than the
    // one they read on another node (ADR-0083).
    let (_directory, ours) = opened();
    let (_theirs, theirs) = opened();

    let mut leader = StateMachine::new(Arc::clone(&theirs));
    for index in 1..=4 {
        leader
            .apply(vec![write(index, 1 + u32::try_from(index).unwrap(), 1_000)])
            .await
            .expect("applies");
    }
    let taken = leader.build_snapshot().await.expect("a snapshot is built");
    let payload = taken.snapshot.into_inner();

    // Our node has a shorter history, so a renumbering install would land the
    // same configs on different numbers.
    ours.write_at(&snapshot(9), &change("ours"), 1_000)
        .expect("written");

    let mut follower = StateMachine::new(Arc::clone(&ours));
    follower
        .install_snapshot(&taken.meta, Box::new(Cursor::new(payload)))
        .await
        .expect("the snapshot installs");

    let expected: Vec<_> = ek_ek_store::History::versions(theirs.as_ref())
        .expect("readable")
        .into_iter()
        .map(|held| held.id)
        .collect();
    let landed: Vec<_> = ek_ek_store::History::versions(ours.as_ref())
        .expect("readable")
        .into_iter()
        .map(|held| held.id)
        .collect();
    assert_eq!(landed, expected, "the version numbers were not preserved");
}

#[tokio::test]
async fn a_snapshot_this_release_cannot_read_is_refused_rather_than_half_applied() {
    let (_directory, store) = opened();
    store
        .write_at(&snapshot(2), &change("ours"), 1_000)
        .expect("written");

    let mut machine = StateMachine::new(Arc::clone(&store));
    let meta = SnapshotMeta::<NodeNumber, PeerNode> {
        last_log_id: Some(log_id(1)),
        last_membership: StoredMembership::default(),
        snapshot_id: "unreadable".to_owned(),
    };

    machine
        .install_snapshot(&meta, Box::new(Cursor::new(b"not a snapshot".to_vec())))
        .await
        .expect_err("an unreadable snapshot is refused");

    // What the node held is still there, and the position did not move.
    assert_eq!(
        store
            .read()
            .expect("readable")
            .expect("a state")
            .config
            .nodes
            .len(),
        2,
        "the refused snapshot replaced what the node held"
    );
    assert_eq!(
        store.marker(marker::APPLIED).expect("readable"),
        None,
        "the refused snapshot moved the position"
    );
}

#[tokio::test]
async fn a_state_travels_and_comes_back_as_what_it_was() {
    // The conversion between what the store holds and what crosses the wire.
    // A field dropped here is a field three nodes disagree about.
    let held = snapshot(3).with_cluster(ek_ek_store::ClusterIdentity::new("the authority"));
    let travelled = WireSnapshot::from(&held);
    let back = ek_ek_store::Snapshot::from(&travelled);
    assert_eq!(back, held, "the state did not survive the round trip");

    let plain = ek_ek_store::Snapshot::new(config(1));
    assert_eq!(
        ek_ek_store::Snapshot::from(&WireSnapshot::from(&plain)),
        plain,
        "a state with no key material and no authority did not survive"
    );
}

#[tokio::test]
async fn a_token_and_a_refusal_travel_with_the_state_they_belong_to() {
    // Both are outside the config document, so nothing that checks the
    // document would notice either of them going missing on the way.
    let held = snapshot(3)
        .with_join(
            ek_ek_store::TokenId::new("0123456789abcdef"),
            ek_ek_store::JoinRecord {
                secret_digest: "a digest".to_owned(),
                expires_at_unix: 2_000,
                used_by: Some(ek_ek_config::NodeId::new("node2")),
                issued_by: "admin".to_owned(),
                issued_at_unix: 1_000,
            },
        )
        .with_removed(ek_ek_config::NodeId::new("node9"));

    let back = ek_ek_store::Snapshot::from(&WireSnapshot::from(&held));
    assert_eq!(back, held, "the state did not survive the round trip");
}

#[tokio::test]
async fn an_audit_row_is_written_in_the_same_transaction_as_the_state() {
    // A change that landed without its audit row would be a change nobody can
    // account for, which is what the audit log exists to make impossible
    // (ADR-0008, ADR-0084).
    let (_directory, store) = opened();

    let version = store
        .apply_write(
            &snapshot(2),
            &change("replicated"),
            1_700_000_000,
            &[(marker::APPLIED, "{\"index\":1}")],
            &[ek_ek_store::AuditRecord {
                recorded_at_unix: 1_700_000_000,
                actor: "node2".to_owned(),
                action: "node.joined".to_owned(),
                subject: Some("node2".to_owned()),
                detail: Some("with a join token".to_owned()),
            }],
        )
        .expect("the write succeeds");

    let whole = store.export().expect("exported");
    let written = whole
        .audit
        .iter()
        .find(|record| record.action == "node.joined")
        .expect("the audit row is beside the state");
    assert_eq!(written.actor, "node2");
    assert_eq!(written.subject.as_deref(), Some("node2"));
    assert_eq!(written.recorded_at_unix, 1_700_000_000);

    // And the state the row belongs to is there, so the two really did land
    // together rather than the row landing alone.
    assert_eq!(
        store
            .read()
            .expect("readable")
            .expect("a state")
            .config
            .nodes
            .len(),
        2
    );
    assert_eq!(version.get(), 1);

    // A write carrying no rows adds none, so the loop above is not one that
    // writes something whatever it is given.
    store
        .apply_write(
            &snapshot(3),
            &change("replicated again"),
            1_700_000_001,
            &[(marker::APPLIED, "{\"index\":2}")],
            &[],
        )
        .expect("the write succeeds");
    assert_eq!(
        store
            .export()
            .expect("exported")
            .audit
            .iter()
            .filter(|record| record.action == "node.joined")
            .count(),
        1,
        "a write with no audit rows wrote one"
    );
}
