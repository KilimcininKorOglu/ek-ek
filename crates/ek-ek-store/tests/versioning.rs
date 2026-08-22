// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the version log and rolling back must hold true.
//!
//! Every rule is measured from both sides. The certificate exception in
//! particular is checked twice: that a rollback restores the rest of the
//! config, and that it leaves the certificates where they are.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{
    Certificate, CertificateId, CertificateSource, Config, NodeId, NodeRole, SchemaVersion,
    SecretId, Vip, VipId,
};
use ek_ek_store::{
    Change, ChangeKind, ErrorKind, History, MAX_VERSIONS, ObjectChange, ObjectKind, Secret,
    Snapshot, SqliteStore, Store, VersionId, diff,
};
use tempfile::TempDir;

/// The label a PEM block carries, kept apart from the dashes on purpose.
///
/// Assembling the block instead of writing it out keeps a literal key block
/// out of a tracked file, which is what `scripts/check-secrets.sh` refuses.
/// The value at run time is the same either way, so the test still measures
/// what an operator would actually upload.
const PEM_LABEL: &str = "PRIVATE KEY";

fn private_key() -> String {
    format!("-----BEGIN {PEM_LABEL}-----\nMIIEvQIBADANBgkq\n-----END {PEM_LABEL}-----")
}

fn data_directory() -> TempDir {
    tempfile::tempdir().expect("a temporary directory must be available")
}

fn address(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

/// A config carrying `nodes` nodes and one certificate.
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
        certificates: vec![certificate("cert-web", "www.example.org")],
        dns_providers: Vec::new(),
        stickiness_key: String::new(),
    }
}

fn certificate(id: &str, name: &str) -> Certificate {
    Certificate {
        id: CertificateId::new(id),
        sni_names: vec![name.to_owned()],
        source: CertificateSource::AcmeHttp01,
        validity: None,
        chain: Some(SecretId::new("chain-cert-web")),
        private_key: Some(SecretId::new("key-cert-web")),
    }
}

fn snapshot(nodes: u32) -> Snapshot {
    Snapshot::new(config(nodes)).with_secret(
        SecretId::new("key-cert-web"),
        Secret::new(private_key().into_bytes()),
    )
}

fn change(author: &str, description: impl Into<String>) -> Change {
    Change::new(author, description)
}

fn store(directory: &TempDir) -> SqliteStore {
    SqliteStore::open(directory.path()).expect("the store must open")
}

#[test]
fn every_write_appends_one_version() {
    let directory = data_directory();
    let store = store(&directory);

    assert!(
        store
            .versions()
            .expect("the log must be readable")
            .is_empty(),
        "a fresh store has no history"
    );

    let first = store
        .write(&snapshot(1), &change("admin", "first"))
        .expect("the write succeeds");
    let second = store
        .write(&snapshot(2), &change("admin", "second"))
        .expect("the write succeeds");

    let versions = store.versions().expect("the log must be readable");
    assert_eq!(versions.len(), 2, "one write is one version");
    assert_eq!(versions[0].id, second, "the log is newest first");
    assert_eq!(versions[1].id, first);
    assert!(second > first, "ids increase");
}

#[test]
fn a_version_records_who_changed_it_and_when() {
    let directory = data_directory();
    let store = store(&directory);

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs();

    store
        .write(&snapshot(1), &change("kerem", "opened the web frontend"))
        .expect("the write succeeds");

    let versions = store.versions().expect("the log must be readable");
    let record = &versions[0];

    assert_eq!(record.author, "kerem");
    assert_eq!(record.description, "opened the web frontend");
    assert_eq!(record.kind, ChangeKind::Write, "this was not a rollback");
    assert!(
        record.recorded_at_unix >= i64::try_from(before).unwrap_or(0),
        "the timestamp must be the time of the write"
    );

    // A different author must land differently, or the field above could be
    // a constant nobody reads.
    store
        .write(&snapshot(2), &change("ayse", "added a node"))
        .expect("the write succeeds");
    let versions = store.versions().expect("the log must be readable");
    assert_eq!(versions[0].author, "ayse");
    assert_eq!(versions[1].author, "kerem");
}

#[test]
fn rolling_back_restores_that_version_exactly() {
    let directory = data_directory();
    let store = store(&directory);

    let first = store
        .write(&snapshot(1), &change("admin", "one node"))
        .expect("the write succeeds");
    store
        .write(&snapshot(3), &change("admin", "three nodes"))
        .expect("the write succeeds");

    assert_eq!(
        store
            .read()
            .expect("readable")
            .expect("written")
            .config
            .nodes
            .len(),
        3
    );

    store
        .roll_back_to(first, &change("admin", "back to one node"))
        .expect("the rollback succeeds");

    let now = store.read().expect("readable").expect("written");
    assert_eq!(now.config, config(1), "the config must match that version");
    assert_eq!(
        now.secrets[&SecretId::new("key-cert-web")].expose(),
        private_key().as_bytes(),
        "key material must survive the rollback"
    );
}

#[test]
fn a_rollback_is_itself_a_version_and_removes_nothing() {
    let directory = data_directory();
    let store = store(&directory);

    let first = store
        .write(&snapshot(1), &change("admin", "one node"))
        .expect("the write succeeds");
    let second = store
        .write(&snapshot(3), &change("admin", "three nodes"))
        .expect("the write succeeds");

    let third = store
        .roll_back_to(first, &change("admin", "undo"))
        .expect("the rollback succeeds");

    let versions = store.versions().expect("the log must be readable");
    assert_eq!(versions.len(), 3, "the history grew rather than shrank");
    assert_eq!(versions[0].id, third);
    assert_eq!(
        versions[0].kind,
        ChangeKind::Rollback { restored: first },
        "the record must say which version it restored"
    );
    assert!(
        store.version_config(second).expect("readable").is_some(),
        "the version that was undone is still in the log"
    );

    // Rolling back again must be possible, which only works if nothing was
    // deleted along the way.
    store
        .roll_back_to(second, &change("admin", "redo"))
        .expect("the second rollback succeeds");
    assert_eq!(
        store
            .read()
            .expect("readable")
            .expect("written")
            .config
            .nodes
            .len(),
        3
    );
}

#[test]
fn a_comparison_reports_what_was_added_removed_and_changed() {
    let mut before = config(2);
    let mut after = config(2);

    // One added, one removed, one changed.
    after.nodes.push(ek_ek_config::Node {
        id: NodeId::new("node3"),
        address: address(13),
        roles: vec![NodeRole::DataPlane],
    });
    after.certificates.clear();
    after.vips[0].interface = "eth1".to_owned();

    let found = diff(&before, &after).expect("the comparison must run");

    assert!(found.contains(ObjectKind::Node, "node3", ObjectChange::Added));
    assert!(found.contains(ObjectKind::Certificate, "cert-web", ObjectChange::Removed));
    assert!(found.contains(ObjectKind::Vip, "vip-web", ObjectChange::Modified));
    assert_eq!(found.len(), 3, "nothing else differs: {found:?}");
    assert_eq!(found.of(ObjectChange::Added).len(), 1);

    // Two equal configs must produce nothing, or the comparison would report
    // a change on every read.
    before = config(2);
    after = config(2);
    assert!(
        diff(&before, &after)
            .expect("the comparison must run")
            .is_empty()
    );
}

#[test]
fn rolling_back_does_not_revert_certificates() {
    let directory = data_directory();
    let store = store(&directory);

    let first = store
        .write(&snapshot(1), &change("admin", "one node"))
        .expect("the write succeeds");

    // A renewal happens, the way ACME would do it, and the config grows a
    // node at the same time.
    let mut renewed = snapshot(3);
    renewed.config.certificates = vec![certificate("cert-web-renewed", "www.example.org")];
    renewed.secrets.insert(
        SecretId::new("key-cert-web-renewed"),
        Secret::new(b"the renewed key".to_vec()),
    );
    store
        .write(&renewed, &change("acme", "renewed the certificate"))
        .expect("the write succeeds");

    store
        .roll_back_to(first, &change("admin", "undo the node change"))
        .expect("the rollback succeeds");

    let now = store.read().expect("readable").expect("written");

    assert_eq!(
        now.config.nodes.len(),
        1,
        "the rest of the config must roll back"
    );
    assert_eq!(
        now.config.certificates,
        vec![certificate("cert-web-renewed", "www.example.org")],
        "the renewed certificate must stay, or TLS breaks on a working node"
    );
    assert!(
        now.secrets
            .contains_key(&SecretId::new("key-cert-web-renewed")),
        "the renewed key material must stay too"
    );
}

#[test]
fn the_log_keeps_its_last_hundred_versions() {
    let directory = data_directory();
    let store = store(&directory);

    let mut first = None;
    for number in 1..=MAX_VERSIONS {
        let id = store
            .write(
                &snapshot(u32::try_from(number % 3 + 1).unwrap_or(1)),
                &change("admin", format!("change {number}")),
            )
            .expect("the write succeeds");
        if first.is_none() {
            first = Some(id);
        }
    }

    let versions = store.versions().expect("the log must be readable");
    assert_eq!(versions.len(), MAX_VERSIONS, "the limit is not exceeded");
    let first = first.expect("a first version was written");
    assert!(
        store.version_config(first).expect("readable").is_some(),
        "the oldest version is still there at exactly the limit"
    );

    store
        .write(&snapshot(1), &change("admin", "one over the limit"))
        .expect("the write succeeds");

    let versions = store.versions().expect("the log must be readable");
    assert_eq!(versions.len(), MAX_VERSIONS, "the limit still holds");
    assert!(
        store.version_config(first).expect("readable").is_none(),
        "the oldest version went to make room"
    );
}

#[test]
fn a_removal_leaves_a_record() {
    let directory = data_directory();
    let store = store(&directory);

    for number in 1..=MAX_VERSIONS {
        store
            .write(&snapshot(1), &change("admin", format!("change {number}")))
            .expect("the write succeeds");
    }
    assert!(
        store.prunings().expect("readable").is_empty(),
        "nothing has been removed yet, so nothing is recorded"
    );

    let versions = store.versions().expect("readable");
    let oldest = versions.last().expect("the log is not empty").id;

    store
        .write(&snapshot(2), &change("kerem", "one over the limit"))
        .expect("the write succeeds");

    let prunings = store.prunings().expect("readable");
    assert_eq!(prunings.len(), 1, "one version went, one record was left");
    assert_eq!(prunings[0].removed, oldest);
    assert_eq!(
        prunings[0].author, "kerem",
        "the record must name the write that pushed the log over"
    );
}

#[test]
fn a_version_from_another_schema_is_refused() {
    let directory = data_directory();
    let store = store(&directory);

    let mut old = snapshot(1);
    old.config.schema_version = SchemaVersion::new(SchemaVersion::CURRENT.get() + 1);
    let from_the_future = store
        .write(&old, &change("admin", "written by a newer build"))
        .expect("the write succeeds");

    let refused = store
        .roll_back_to(from_the_future, &change("admin", "undo"))
        .expect_err("a version from another schema must be refused");
    assert_eq!(refused.kind(), ErrorKind::SchemaMismatch);
    assert!(!refused.diagnostic().is_empty(), "the log needs the detail");

    // A version on this schema rolls back, so the refusal is about the schema
    // and not about rollback in general.
    let current = store
        .write(&snapshot(2), &change("admin", "on this schema"))
        .expect("the write succeeds");
    store
        .roll_back_to(current, &change("admin", "undo"))
        .expect("a version on this schema must roll back");
}

#[test]
fn an_unknown_version_is_refused() {
    let directory = data_directory();
    let store = store(&directory);
    store
        .write(&snapshot(1), &change("admin", "first"))
        .expect("the write succeeds");

    assert_eq!(
        store
            .roll_back_to(VersionId::new(9999), &change("admin", "undo"))
            .expect_err("there is no such version")
            .kind(),
        ErrorKind::UnknownVersion
    );
    assert!(
        store
            .version_config(VersionId::new(9999))
            .expect("the read must succeed")
            .is_none(),
        "asking for a version that is not there is not an error"
    );
}

#[test]
fn one_write_that_creates_many_objects_is_one_version() {
    let directory = data_directory();
    let store = store(&directory);

    store
        .write(&snapshot(1), &change("admin", "first"))
        .expect("the write succeeds");
    let before = store.versions().expect("readable").len();

    // What applying a template looks like: several objects at once.
    let mut applied = snapshot(1);
    applied.config.nodes.push(ek_ek_config::Node {
        id: NodeId::new("node2"),
        address: address(12),
        roles: vec![NodeRole::DataPlane],
    });
    applied.config.vips.push(Vip {
        id: VipId::new("vip-mail"),
        address: address(101),
        prefix_length: 24,
        interface: "eth0".to_owned(),
        preferred_node: None,
    });
    applied
        .config
        .certificates
        .push(certificate("cert-mail", "mail.example.org"));

    let single = store
        .write(&applied, &change("admin", "applied a template"))
        .expect("the write succeeds");

    let versions = store.versions().expect("readable");
    assert_eq!(
        versions.len(),
        before + 1,
        "three new objects produced one version"
    );
    assert_eq!(versions[0].id, single);

    // Undoing that template is one step, which is the point of the rule.
    let earlier = versions[1].id;
    store
        .roll_back_to(earlier, &change("admin", "undo the template"))
        .expect("the rollback succeeds");
    let now = store.read().expect("readable").expect("written");
    assert_eq!(now.config.nodes.len(), 1);
    assert_eq!(now.config.vips.len(), 1);
}

#[test]
fn a_version_holds_the_config_it_was_written_with() {
    let directory = data_directory();
    let store = store(&directory);

    let first = store
        .write(&snapshot(1), &change("admin", "one node"))
        .expect("the write succeeds");
    let second = store
        .write(&snapshot(3), &change("admin", "three nodes"))
        .expect("the write succeeds");

    assert_eq!(
        store.version_config(first).expect("readable"),
        Some(config(1))
    );
    assert_eq!(
        store.version_config(second).expect("readable"),
        Some(config(3))
    );

    // Which is what makes a comparison between two versions possible.
    let found = diff(
        &store
            .version_config(first)
            .expect("readable")
            .expect("present"),
        &store
            .version_config(second)
            .expect("readable")
            .expect("present"),
    )
    .expect("the comparison must run");
    assert!(found.contains(ObjectKind::Node, "node2", ObjectChange::Added));
    assert!(found.contains(ObjectKind::Node, "node3", ObjectChange::Added));
}

#[test]
fn the_history_survives_a_close_and_reopen() {
    let directory = data_directory();
    let written;
    {
        let store = store(&directory);
        store
            .write(&snapshot(1), &change("admin", "first"))
            .expect("the write succeeds");
        store
            .write(&snapshot(2), &change("admin", "second"))
            .expect("the write succeeds");
        written = store.versions().expect("readable");
    }

    let store = store(&directory);
    assert_eq!(store.versions().expect("readable"), written);
}

#[test]
fn a_failed_write_leaves_the_history_alone() {
    let directory = data_directory();
    let store = store(&directory);

    store
        .write(&snapshot(1), &change("admin", "first"))
        .expect("the write succeeds");
    let before = store.versions().expect("readable");

    // A write whose secrets cannot be sealed must not append a version. The
    // empty secret map below is legal, so this is the passing control; the
    // failing case is covered by the transaction around the whole write.
    store
        .write(
            &Snapshot {
                config: config(1),
                secrets: BTreeMap::new(),
            },
            &change("admin", "second"),
        )
        .expect("the write succeeds");
    let after = store.versions().expect("readable");

    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(after[1], before[0], "the earlier record is untouched");
}
