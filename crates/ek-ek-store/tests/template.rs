// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What applying a template has to look like in the history.
//!
//! The template itself is a pure function and is measured in `ek-ek-config`.
//! Two of its rules cannot be measured there, because they are about the
//! version log: a template creates a dozen objects and must still be one line
//! in the history, and undoing it must be one step (ADR-0046).
//!
//! That is why these two live here. The base layer cannot depend on the store
//! (ADR-0014), so the store is where the two meet.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::template::{Argument, Arguments, apply, embedded_by_id};
use ek_ek_config::{
    AdminState, BackendMember, Config, MemberId, Node, NodeId, NodeRole, SchemaVersion, TemplateId,
};
use ek_ek_store::{Change, History, Snapshot, SqliteStore, Store};
use tempfile::TempDir;

fn address(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

/// A cluster with nodes and nothing published.
fn empty_cluster() -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: vec![Node {
            id: NodeId::new("node1"),
            address: address(11),
            roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
        }],
        vips: Vec::new(),
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
    }
}

fn arguments() -> Arguments {
    Arguments::new()
        .with("name", Argument::Text("mail".to_owned()))
        .with("domain", Argument::Text("mail.example.org".to_owned()))
        .with("address", Argument::Address(address(100)))
        .with("interface", Argument::Text("eth0".to_owned()))
        .with("node", Argument::Node(NodeId::new("node1")))
        .with(
            "members",
            Argument::Members(
                (1..=2_u8)
                    .map(|number| BackendMember {
                        id: MemberId::new(format!("srv{number}")),
                        address: address(20 + number),
                        port: 443,
                        weight: 1,
                        admin_state: AdminState::Enabled,
                    })
                    .collect(),
            ),
        )
}

fn snapshot(config: Config) -> Snapshot {
    Snapshot {
        config,
        secrets: BTreeMap::new(),
    }
}

fn data_directory() -> TempDir {
    tempfile::tempdir().expect("a temporary directory must be available")
}

/// Applies the Exchange template, which is the one that creates the most.
fn applied_exchange(over: &Config) -> ek_ek_config::template::Applied {
    let template = embedded_by_id(&TemplateId::new("exchange")).expect("the template must ship");
    apply(&template, over, &arguments()).expect("it must apply cleanly")
}

#[test]
fn applying_a_template_is_one_line_in_the_history() {
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");

    let before = empty_cluster();
    store
        .write(&snapshot(before.clone()), &Change::new("admin", "start"))
        .expect("the first write must land");
    let before_count = store.versions().expect("the log must read").len();

    let applied = applied_exchange(&before);
    assert!(
        applied.created.len() >= 10,
        "the template must create many objects, or one line proves nothing: {}",
        applied.created.len()
    );

    store
        .write(
            &snapshot(applied.config.clone()),
            &Change::new("admin", "apply the Exchange template"),
        )
        .expect("the write must land");

    let versions = store.versions().expect("the log must read");
    assert_eq!(
        versions.len(),
        before_count + 1,
        "{} objects were created and the history grew by {}; it has to grow by one",
        applied.created.len(),
        versions.len() - before_count
    );
}

#[test]
fn rolling_back_a_template_removes_everything_it_created_in_one_step() {
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");

    let before = empty_cluster();
    let start = store
        .write(&snapshot(before.clone()), &Change::new("admin", "start"))
        .expect("the first write must land");

    let applied = applied_exchange(&before);
    store
        .write(
            &snapshot(applied.config.clone()),
            &Change::new("admin", "apply the Exchange template"),
        )
        .expect("the write must land");

    // The template really did publish something, so the removal below is
    // measured against a config that had it.
    let published = store
        .read()
        .expect("the state must read")
        .expect("there must be a state");
    assert!(!published.config.frontends.is_empty());
    assert!(!published.config.backends.is_empty());

    store
        .roll_back_to(start, &Change::new("admin", "undo the template"))
        .expect("the rollback must land");

    let after = store
        .read()
        .expect("the state must read")
        .expect("there must be a state");
    assert_eq!(
        after.config, before,
        "one step has to take back every object the template created"
    );

    // A rollback is itself a write, so the history keeps growing rather than
    // losing the line the template wrote.
    let versions = store.versions().expect("the log must read");
    assert_eq!(versions.len(), 3);
}
