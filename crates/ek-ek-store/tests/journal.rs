// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the replication journal must hold true.
//!
//! The journal knows nothing about consensus. That is the point of measuring
//! it here rather than only through a running cluster: a record, a marker and
//! a snapshot are rows, and rows can be opened and read without three nodes
//! and an election.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{Config, NodeId, NodeRole, SchemaVersion, SecretId, Vip, VipId};
use ek_ek_store::journal::marker;
use ek_ek_store::{
    AuditRecord, Change, FullState, History, Journal, Record, Secret, Snapshot, SqliteStore, Store,
    StoredVersion, VersionId,
};
use tempfile::TempDir;

fn data_directory() -> TempDir {
    tempfile::tempdir().expect("a temporary directory must be available")
}

fn store(directory: &TempDir) -> SqliteStore {
    SqliteStore::open(directory.path()).expect("the store must open")
}

fn address(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

fn config(nodes: u32) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: (1..=nodes)
            .map(|number| ek_ek_config::Node {
                id: NodeId::new(format!("node{number}")),
                address: address(10 + u8::try_from(number).unwrap_or(u8::MAX)),
                roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
            })
            .collect(),
        vips: vec![Vip {
            id: VipId::new("vip-web"),
            address: address(100),
            prefix_length: 24,
            interface: "eth0".to_owned(),
            preferred_node: Some(NodeId::new("node1")),
        }],
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        acme: None,
        stickiness_key: String::new(),
        log_level: Default::default(),
        certificate_expiry_warning_days: 30,
    }
}

fn snapshot(nodes: u32) -> Snapshot {
    Snapshot::new(config(nodes)).with_secret(
        SecretId::new("key-cert-web"),
        Secret::new(b"the key material".to_vec()),
    )
}

fn change(description: &str) -> Change {
    Change::new("admin", description)
}

fn record(index: u64) -> Record {
    Record {
        index,
        payload: format!("{{\"index\":{index}}}"),
    }
}

#[test]
fn a_record_written_is_the_record_read_back() {
    let directory = data_directory();
    let store = store(&directory);

    assert!(
        store.span().expect("the span must be readable").is_none(),
        "a fresh journal holds nothing"
    );

    store
        .append(&[record(1), record(2), record(3)])
        .expect("the records are written");

    let held = store.records(1, 4).expect("the records must be readable");
    assert_eq!(held.len(), 3);
    assert_eq!(held[0].index, 1);
    assert_eq!(held[2].payload, record(3).payload);
    assert_eq!(store.span().expect("readable"), Some((1, 3)));
}

#[test]
fn a_range_returns_what_it_names_and_nothing_beside_it() {
    // The range openraft asks for is half open. A journal returning one record
    // too many would replay an entry a follower already applied.
    let directory = data_directory();
    let store = store(&directory);
    store
        .append(&[record(1), record(2), record(3), record(4)])
        .expect("the records are written");

    let held = store.records(2, 4).expect("readable");
    assert_eq!(
        held.iter().map(|held| held.index).collect::<Vec<_>>(),
        vec![2, 3],
        "the upper bound is not part of the range"
    );
    assert!(
        store.records(9, 12).expect("readable").is_empty(),
        "a range past the end returns nothing rather than failing"
    );
}

#[test]
fn a_record_written_twice_at_one_index_is_the_later_one() {
    // A leader that lost an election has its records overwritten by the new
    // leader's. A journal that refused the second write would leave the node
    // holding a record the cluster does not agree on.
    let directory = data_directory();
    let store = store(&directory);

    store.append(&[record(1)]).expect("written");
    store
        .append(&[Record {
            index: 1,
            payload: "{\"index\":1,\"term\":2}".to_owned(),
        }])
        .expect("the later record replaces the earlier one");

    let held = store.records(1, 2).expect("readable");
    assert_eq!(held.len(), 1, "one index holds one record");
    assert!(held[0].payload.contains("\"term\":2"));
}

#[test]
fn truncating_removes_from_the_index_named_and_purging_removes_up_to_it() {
    // The two directions consensus needs: throwing away records a new leader
    // disagrees with, and dropping records everybody has applied.
    let directory = data_directory();
    let store = store(&directory);
    store
        .append(&[record(1), record(2), record(3), record(4), record(5)])
        .expect("written");

    store.truncate_from(4).expect("the tail is thrown away");
    assert_eq!(
        store.span().expect("readable"),
        Some((1, 3)),
        "the record at the index named goes too"
    );

    store.purge_upto(2).expect("the head is dropped");
    assert_eq!(
        store.span().expect("readable"),
        Some((3, 3)),
        "the record at the index named goes too"
    );
}

#[test]
fn a_marker_set_is_read_back_and_clearing_it_removes_it() {
    let directory = data_directory();
    let store = store(&directory);

    assert_eq!(store.marker(marker::VOTE).expect("readable"), None);

    store
        .set_marker(marker::VOTE, Some("{\"term\":4}"))
        .expect("written");
    assert_eq!(
        store.marker(marker::VOTE).expect("readable").as_deref(),
        Some("{\"term\":4}")
    );

    store
        .set_marker(marker::VOTE, Some("{\"term\":5}"))
        .expect("written");
    assert_eq!(
        store.marker(marker::VOTE).expect("readable").as_deref(),
        Some("{\"term\":5}"),
        "a marker holds the latest value, not both"
    );

    store.set_marker(marker::VOTE, None).expect("cleared");
    assert_eq!(store.marker(marker::VOTE).expect("readable"), None);
}

#[test]
fn a_marker_survives_the_process_that_wrote_it() {
    // A vote held only in memory is a vote a restarted node can cast twice.
    let directory = data_directory();
    {
        let store = store(&directory);
        store
            .set_marker(marker::VOTE, Some("{\"term\":9}"))
            .expect("written");
        store.append(&[record(1), record(2)]).expect("written");
    }

    let reopened = store(&directory);
    assert_eq!(
        reopened.marker(marker::VOTE).expect("readable").as_deref(),
        Some("{\"term\":9}")
    );
    assert_eq!(reopened.span().expect("readable"), Some((1, 2)));
}

#[test]
fn a_snapshot_written_is_the_snapshot_read_back() {
    let directory = data_directory();
    let store = store(&directory);

    assert!(store.snapshot().expect("readable").is_none());

    store
        .set_snapshot("{\"at\":7}", b"the payload")
        .expect("written");
    let (meta, data) = store.snapshot().expect("readable").expect("one is held");
    assert_eq!(meta, "{\"at\":7}");
    assert_eq!(data, b"the payload");

    store
        .set_snapshot("{\"at\":9}", b"a later payload")
        .expect("written");
    let (meta, data) = store.snapshot().expect("readable").expect("one is held");
    assert_eq!(meta, "{\"at\":9}", "a node holds one snapshot, the latest");
    assert_eq!(data, b"a later payload");
}

#[test]
fn an_applied_write_moves_the_config_and_the_marker_together() {
    // The rule that keeps a restarted node from applying a record twice. A
    // node that wrote the config and then stopped before the marker would
    // replay the same change on the way back up.
    let directory = data_directory();
    let store = store(&directory);

    let version = store
        .apply_write(
            &snapshot(2),
            &change("replicated"),
            1_700_000_000,
            &[(marker::APPLIED, "{\"index\":4}")],
        )
        .expect("the record applies");

    assert_eq!(
        store
            .read()
            .expect("readable")
            .expect("something was written")
            .config
            .nodes
            .len(),
        2
    );
    assert_eq!(
        store.marker(marker::APPLIED).expect("readable").as_deref(),
        Some("{\"index\":4}"),
        "the config landed without the marker that says it did"
    );
    assert_eq!(
        store.versions().expect("readable")[0].id,
        version,
        "an applied record appends one version"
    );
}

#[test]
fn the_moment_a_version_records_is_the_one_it_was_given() {
    // Every node applies the same record. A node stamping its own clock would
    // give three nodes three histories of one change (ADR-0083).
    let directory = data_directory();
    let store = store(&directory);

    let at = 1_600_000_000;
    store
        .write_at(&snapshot(1), &change("replicated"), at)
        .expect("written");

    assert_eq!(
        store.versions().expect("readable")[0].recorded_at_unix,
        at,
        "the version carries the node's own clock instead of the leader's"
    );
}

#[test]
fn an_exported_state_carries_the_config_the_keys_the_history_and_the_audit() {
    let directory = data_directory();
    let store = store(&directory);

    store
        .write_at(&snapshot(1), &change("first"), 1_000)
        .expect("written");
    store
        .write_at(&snapshot(3), &change("second"), 2_000)
        .expect("written");

    let exported = store.export().expect("the state must be exportable");
    let held = exported.snapshot.as_ref().expect("a state was written");
    assert_eq!(held.config.nodes.len(), 3, "the latest config travels");
    assert_eq!(
        held.secrets[&SecretId::new("key-cert-web")].expose(),
        b"the key material",
        "the key material travels in the clear inside the state"
    );
    assert_eq!(exported.versions.len(), 2, "the whole history travels");
    assert_eq!(
        exported.versions[0].recorded_at_unix, 1_000,
        "the history travels oldest first"
    );
    assert_eq!(exported.versions[1].description, "second");
}

#[test]
fn an_imported_state_replaces_what_the_node_held_rather_than_joining_it() {
    // A node catching up takes the cluster's state whole. Merging would leave
    // it holding an object no quorum agreed to.
    let ours = data_directory();
    let theirs = data_directory();
    let ours = store(&ours);
    let theirs = store(&theirs);

    ours.write_at(&snapshot(5), &change("ours"), 1_000)
        .expect("written");
    theirs
        .write_at(&snapshot(2), &change("theirs"), 2_000)
        .expect("written");

    let exported = theirs.export().expect("exportable");
    ours.import(&exported, &[(marker::APPLIED, "{\"index\":9}")])
        .expect("the state is taken whole");

    let held = ours.read().expect("readable").expect("a state is held");
    assert_eq!(
        held.config.nodes.len(),
        2,
        "the peer's config replaced ours"
    );
    let versions = ours.versions().expect("readable");
    assert_eq!(versions.len(), 1, "our own history did not survive");
    assert_eq!(versions[0].description, "theirs");
    assert_eq!(
        ours.marker(marker::APPLIED).expect("readable").as_deref(),
        Some("{\"index\":9}"),
        "the state landed without the position that says where it came from"
    );
}

#[test]
fn an_imported_state_keeps_the_version_numbers_it_arrived_with() {
    // Version numbers are how an operator names a rollback. A node that
    // renumbered them would send an operator rolling back to a different
    // config than the one they read on another node (ADR-0083).
    let ours = data_directory();
    let theirs = data_directory();
    let ours = store(&ours);
    let theirs = store(&theirs);

    for number in 1..=4 {
        theirs
            .write_at(&snapshot(number), &change("theirs"), 1_000)
            .expect("written");
    }
    // Ours has a shorter history, so a renumbering import would land the same
    // configs on different numbers.
    ours.write_at(&snapshot(9), &change("ours"), 1_000)
        .expect("written");

    let exported = theirs.export().expect("exportable");
    let expected: Vec<VersionId> = exported.versions.iter().map(|held| held.id).collect();
    ours.import(&exported, &[]).expect("imported");

    let mut landed: Vec<VersionId> = ours
        .versions()
        .expect("readable")
        .into_iter()
        .map(|held| held.id)
        .collect();
    landed.reverse();
    assert_eq!(landed, expected, "the version numbers were not preserved");
}

#[test]
fn an_audit_record_that_arrives_in_a_state_cannot_be_dropped_by_the_node_that_took_it() {
    // The audit log is agreed, not local. A node that removed a row of its own
    // gets it back the moment it takes the cluster's state again.
    let ours = data_directory();
    let theirs = data_directory();
    let ours = store(&ours);
    let theirs = store(&theirs);

    let mut state = theirs.export().expect("exportable");
    state.snapshot = Some(snapshot(1));
    state.versions = vec![StoredVersion {
        id: VersionId::new(1),
        recorded_at_unix: 1_000,
        author: "admin".to_owned(),
        description: "first".to_owned(),
        schema_version: SchemaVersion::CURRENT.get(),
        restored_from: None,
        document: serde_json::to_string(&config(1)).expect("the config writes out"),
    }];
    state.audit = vec![
        AuditRecord {
            recorded_at_unix: 1_000,
            actor: "admin".to_owned(),
            action: "config.write".to_owned(),
            subject: Some("vip-web".to_owned()),
            detail: None,
        },
        AuditRecord {
            recorded_at_unix: 1_100,
            actor: "admin".to_owned(),
            action: "config.rollback".to_owned(),
            subject: Some("1".to_owned()),
            detail: Some("an operator undid it".to_owned()),
        },
    ];

    ours.import(&state, &[]).expect("imported");
    let landed = ours.export().expect("exportable");
    assert_eq!(landed.audit.len(), 2, "the audit rows did not arrive");
    assert_eq!(landed.audit[0].action, "config.write");
    assert_eq!(
        landed.audit[1].detail.as_deref(),
        Some("an operator undid it")
    );

    // A node that drops its own rows takes them back with the next state.
    let mut without = state.clone();
    without.audit.clear();
    ours.import(&without, &[]).expect("imported");
    assert!(
        ours.export().expect("exportable").audit.is_empty(),
        "the rows were not local to begin with"
    );
    ours.import(&state, &[]).expect("imported");
    assert_eq!(
        ours.export().expect("exportable").audit.len(),
        2,
        "the agreed rows did not come back"
    );
}

#[test]
fn key_material_that_arrives_in_a_state_is_sealed_before_it_reaches_the_disk() {
    // ADR-0018. The material travels in the clear inside an authenticated
    // channel and every node seals what it receives with its own master key,
    // which is the one thing nodes never share.
    let directory = data_directory();
    let store = store(&directory);

    let mut state = FullState {
        snapshot: Some(snapshot(1)),
        versions: Vec::new(),
        audit: Vec::new(),
    };
    let material = b"a key nobody may read off the disk".to_vec();
    let mut secrets = BTreeMap::new();
    secrets.insert(SecretId::new("key-cert-web"), Secret::new(material.clone()));
    if let Some(held) = state.snapshot.as_mut() {
        held.secrets = secrets;
    }

    store.import(&state, &[]).expect("imported");

    let read_back = store
        .read()
        .expect("readable")
        .expect("a state is held")
        .secrets[&SecretId::new("key-cert-web")]
        .expose()
        .to_vec();
    assert_eq!(read_back, material, "the material does not read back");

    let raw = std::fs::read(directory.path().join(ek_ek_store::DATABASE_FILE))
        .expect("the database file is readable");
    assert!(
        !raw.windows(material.len())
            .any(|window| window == material.as_slice()),
        "the key material reached the disk in the clear"
    );
}
