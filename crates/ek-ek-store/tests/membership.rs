// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the store must hold true about who may join and who may not speak.
//!
//! Neither of these is configuration. Nobody writes a join token by hand, and
//! a rollback to last week must not resurrect a token that was used or a node
//! that was removed. Every rule here is about that difference (ADR-0084).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{Config, NodeId, SchemaVersion};
use ek_ek_store::{Change, History, JoinRecord, Snapshot, SqliteStore, Store, TokenId};
use tempfile::TempDir;

fn data_directory() -> TempDir {
    tempfile::tempdir().expect("a temporary directory must be available")
}

fn store(directory: &TempDir) -> SqliteStore {
    SqliteStore::open(directory.path()).expect("the store opens")
}

fn config(nodes: u32) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: (1..=nodes)
            .map(|number| ek_ek_config::Node {
                id: NodeId::new(format!("node{number}")),
                address: IpAddr::V4(Ipv4Addr::new(
                    10,
                    0,
                    0,
                    10 + u8::try_from(number).unwrap_or(u8::MAX),
                )),
                roles: vec![ek_ek_config::NodeRole::ControlPlane],
            })
            .collect(),
        vips: Vec::new(),
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        acme: None,
        stickiness_key: String::new(),
        log_level: ek_ek_config::LogLevel::default(),
        certificate_expiry_warning_days: 30,
    }
}

fn record(digest: &str, expires_at_unix: i64) -> JoinRecord {
    JoinRecord {
        secret_digest: digest.to_owned(),
        expires_at_unix,
        used_by: None,
        issued_by: "admin".to_owned(),
        issued_at_unix: 1_000,
    }
}

fn change(description: &str) -> Change {
    Change::new("admin", description)
}

#[test]
fn a_join_token_survives_a_close_and_reopen() {
    let directory = data_directory();
    let id = TokenId::new("0123456789abcdef");

    {
        let store = store(&directory);
        store
            .write(
                &Snapshot::new(config(1)).with_join(id.clone(), record("a digest", 2_000)),
                &change("a token was minted"),
            )
            .expect("the write succeeds");
    }

    let store = store(&directory);
    let held = store.read().expect("readable").expect("a state");
    let back = held.joins.get(&id).expect("the token is still there");
    assert_eq!(back.secret_digest, "a digest");
    assert_eq!(back.expires_at_unix, 2_000);
    assert_eq!(back.used_by, None);
    assert_eq!(back.issued_by, "admin");
    assert_eq!(back.issued_at_unix, 1_000);
}

#[test]
fn marking_a_token_used_replaces_the_record_rather_than_adding_one() {
    // Written whole, like everything else in a state. Two records under one
    // identity would be a token that is used and unused at the same time.
    let directory = data_directory();
    let store = store(&directory);
    let id = TokenId::new("0123456789abcdef");

    store
        .write(
            &Snapshot::new(config(1)).with_join(id.clone(), record("a digest", 2_000)),
            &change("a token was minted"),
        )
        .expect("written");

    let mut used = record("a digest", 2_000);
    used.used_by = Some(NodeId::new("node2"));
    store
        .write(
            &Snapshot::new(config(1)).with_join(id.clone(), used),
            &change("the token was used"),
        )
        .expect("written");

    let held = store.read().expect("readable").expect("a state");
    assert_eq!(held.joins.len(), 1, "the token was recorded twice");
    assert_eq!(
        held.joins.get(&id).expect("the token").used_by,
        Some(NodeId::new("node2"))
    );
}

#[test]
fn a_token_the_state_no_longer_carries_is_gone() {
    // The other side of "written whole". A token that survived a write which
    // dropped it would be a token the cluster believes it withdrew.
    let directory = data_directory();
    let store = store(&directory);
    let id = TokenId::new("0123456789abcdef");

    store
        .write(
            &Snapshot::new(config(1)).with_join(id.clone(), record("a digest", 2_000)),
            &change("a token was minted"),
        )
        .expect("written");
    store
        .write(
            &Snapshot::new(config(1)),
            &change("the token was withdrawn"),
        )
        .expect("written");

    let held = store.read().expect("readable").expect("a state");
    assert!(held.joins.is_empty(), "a withdrawn token is still there");
}

#[test]
fn a_removed_node_survives_a_close_and_reopen() {
    let directory = data_directory();

    {
        let store = store(&directory);
        store
            .write(
                &Snapshot::new(config(1)).with_removed(NodeId::new("node9")),
                &change("a node was removed"),
            )
            .expect("written");
    }

    let store = store(&directory);
    let held = store.read().expect("readable").expect("a state");
    assert!(
        held.removed.contains(&NodeId::new("node9")),
        "the refusal list did not survive a reopen"
    );
    assert!(
        !held.removed.contains(&NodeId::new("node1")),
        "a node that was never removed is on the list"
    );
}

#[test]
fn neither_is_in_the_config_document_and_neither_comes_back_on_a_rollback() {
    // The rule that decides where these live. A rollback restores a document,
    // and a document carrying a used token would hand it back (ADR-0084).
    let directory = data_directory();
    let store = store(&directory);
    let id = TokenId::new("0123456789abcdef");

    let first = store
        .write(&Snapshot::new(config(1)), &change("before anything"))
        .expect("written");

    let mut used = record("a digest", 2_000);
    used.used_by = Some(NodeId::new("node2"));
    store
        .write(
            &Snapshot::new(config(2))
                .with_join(id.clone(), used)
                .with_removed(NodeId::new("node9")),
            &change("a node joined and another was removed"),
        )
        .expect("written");

    // Neither is in the stored document, which is what a rollback restores.
    let whole = store.export().expect("exported");
    let document = &whole
        .versions
        .iter()
        .find(|version| version.id != first)
        .expect("the second version")
        .document;
    assert!(
        !document.contains("0123456789abcdef"),
        "the token is in the config document: {document}"
    );
    assert!(
        !document.contains("node9"),
        "the refusal list is in the config document: {document}"
    );

    store
        .roll_back_to(first, &change("undo the join"))
        .expect("the rollback succeeds");

    let held = store.read().expect("readable").expect("a state");
    assert_eq!(
        held.config.nodes.len(),
        1,
        "the rollback did not restore the config"
    );
    assert_eq!(
        held.joins
            .get(&id)
            .expect("the token is still there")
            .used_by,
        Some(NodeId::new("node2")),
        "a rollback handed back a token that was already used"
    );
    assert!(
        held.removed.contains(&NodeId::new("node9")),
        "a rollback readmitted a node that was removed"
    );
}

#[test]
fn both_travel_when_a_whole_state_is_moved() {
    // What a node catching up receives. A node that took the config without
    // the refusal list would answer a caller its peers refuse.
    let here = data_directory();
    let there = data_directory();
    let from = store(&here);
    let to = store(&there);

    let id = TokenId::new("0123456789abcdef");
    from.write(
        &Snapshot::new(config(2))
            .with_join(id.clone(), record("a digest", 2_000))
            .with_removed(NodeId::new("node9")),
        &change("a token and a removal"),
    )
    .expect("written");

    let whole = from.export().expect("exported");
    to.import(&whole, &[]).expect("imported");

    let held = to.read().expect("readable").expect("a state");
    assert!(held.joins.contains_key(&id), "the token did not travel");
    assert!(
        held.removed.contains(&NodeId::new("node9")),
        "the refusal list did not travel"
    );
}

#[test]
fn moving_an_empty_state_clears_both_lists() {
    // A cluster that holds nothing has to leave this node holding nothing. The
    // writers below only run when there is a state to write, so an empty one
    // has to be cleared on its own or a token nobody holds survives here.
    let here = data_directory();
    let there = data_directory();
    let from = store(&here);
    let to = store(&there);

    to.write(
        &Snapshot::new(config(1))
            .with_join(TokenId::new("aaaaaaaaaaaaaaaa"), record("mine", 2_000))
            .with_removed(NodeId::new("node8")),
        &change("what this node held"),
    )
    .expect("written");

    let empty = from.export().expect("exported");
    assert!(empty.snapshot.is_none(), "the sending node holds a state");
    to.import(&empty, &[]).expect("imported");

    // Read back through a fresh write, because an empty import leaves no state
    // to read at all. What matters is that neither list came back with it.
    to.write(&Snapshot::new(config(1)), &change("after the import"))
        .expect("written");
    let held = to.read().expect("readable").expect("a state");
    assert!(held.joins.is_empty(), "a token survived an empty import");
    assert!(
        held.removed.is_empty(),
        "a refusal survived an empty import"
    );
}

#[test]
fn moving_a_state_replaces_what_was_there_rather_than_adding_to_it() {
    // An import is a whole state. A token the receiving node had and the
    // sending node did not would be a token only one node believes in.
    let here = data_directory();
    let there = data_directory();
    let from = store(&here);
    let to = store(&there);

    to.write(
        &Snapshot::new(config(1))
            .with_join(TokenId::new("aaaaaaaaaaaaaaaa"), record("mine", 2_000))
            .with_removed(NodeId::new("node8")),
        &change("what this node held"),
    )
    .expect("written");

    from.write(
        &Snapshot::new(config(2))
            .with_join(TokenId::new("bbbbbbbbbbbbbbbb"), record("theirs", 3_000)),
        &change("what the cluster holds"),
    )
    .expect("written");

    to.import(&from.export().expect("exported"), &[])
        .expect("imported");

    let held = to.read().expect("readable").expect("a state");
    assert_eq!(
        held.joins.keys().map(TokenId::as_str).collect::<Vec<_>>(),
        ["bbbbbbbbbbbbbbbb"],
        "the node kept a token the cluster does not hold"
    );
    assert!(
        held.removed.is_empty(),
        "the node kept a refusal the cluster does not hold"
    );
}
