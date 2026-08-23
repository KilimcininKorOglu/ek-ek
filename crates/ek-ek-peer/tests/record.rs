// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where the authority lives once it exists.
//!
//! The readings come off the disk. A state that round-trips through the store
//! object proves the object; only the bytes in the file prove that the key was
//! sealed before it got there.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_config::{Config, SchemaVersion};
use ek_ek_peer::{AUTHORITY_KEY_SECRET, Reason};
use ek_ek_store::{Change, History, Snapshot, SqliteStore, Store};

mod common;

use common::authority;

/// The smallest configuration a store will hold.
///
/// Nothing here measures the configuration. It is there because a state has to
/// carry one, and the authority is what is being read back.
fn config() -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: Vec::new(),
        vips: Vec::new(),
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

fn store(directory: &std::path::Path) -> SqliteStore {
    SqliteStore::open(directory).expect("the store opens")
}

#[test]
fn an_authority_written_is_an_authority_read_back() {
    let home = tempfile::tempdir().expect("a directory");
    let store = store(home.path());
    let authority = authority();

    let state = ek_ek_peer::install(&Snapshot::new(config()), &authority);
    store
        .write(&state, &Change::new("cluster", "authority created"))
        .expect("the write succeeds");

    let held = store.read().expect("readable").expect("a state");
    let read = ek_ek_peer::read(&held).expect("an authority");
    assert_eq!(read.certificate_pem, authority.certificate_pem);
    assert_eq!(read.key_pem.expose(), authority.key_pem.expose());
}

#[test]
fn the_authority_key_is_sealed_before_it_reaches_the_disk() {
    // The point of ADR-0018. A disk image or a backup that carries this file
    // must not carry the key that signs every node identity.
    let home = tempfile::tempdir().expect("a directory");
    let authority = authority();
    {
        let store = store(home.path());
        let state = ek_ek_peer::install(&Snapshot::new(config()), &authority);
        store
            .write(&state, &Change::new("cluster", "authority created"))
            .expect("the write succeeds");
    }

    let mut raw = Vec::new();
    for entry in std::fs::read_dir(home.path()).expect("the directory reads") {
        let path = entry.expect("an entry").path();
        if path.is_file() {
            raw.extend(std::fs::read(&path).expect("the file reads"));
        }
    }

    let key = authority.key_pem.expose();
    assert!(!raw.is_empty(), "nothing was written to the data directory");
    assert!(
        !raw.windows(key.len()).any(|window| window == key),
        "the authority key is on the disk in the clear"
    );
    // The certificate is public and is expected to be there in the clear, so
    // the check above is measuring the sealing and not an empty search.
    let certificate = authority.certificate_pem.as_bytes();
    assert!(
        raw.windows(certificate.len())
            .any(|window| window == certificate),
        "the authority certificate never reached the disk, so the search proves nothing"
    );
}

#[test]
fn the_key_is_stored_under_the_reserved_name() {
    // The name is written out here rather than taken from the product. A
    // stored name is part of what is on the disk: a release that changed it
    // would open a store written by the previous one and find no authority in
    // it, and comparing the product against its own constant would agree
    // whatever the constant became.
    assert_eq!(AUTHORITY_KEY_SECRET, "cluster-ca.key");

    let state = ek_ek_peer::install(&Snapshot::new(config()), &authority());
    assert!(
        state
            .secrets
            .keys()
            .any(|id| id.as_str() == "cluster-ca.key"),
        "the key is not under cluster-ca.key: {:?}",
        state.secrets.keys().collect::<Vec<_>>()
    );
}

#[test]
fn half_an_authority_is_not_present() {
    // What `cluster init` asks before it refuses to run twice. A state with
    // only the certificate would answer "there is already an authority" while
    // holding nothing that can sign, and the node would be stuck: it can
    // neither enrol anybody nor bootstrap again.
    let whole = ek_ek_peer::install(&Snapshot::new(config()), &authority());
    assert!(ek_ek_peer::present(&whole));

    let mut certificate_only = whole.clone();
    certificate_only.secrets.clear();
    assert!(
        !ek_ek_peer::present(&certificate_only),
        "a certificate with no key was reported as an authority"
    );

    let mut key_only = whole;
    key_only.cluster = None;
    assert!(
        !ek_ek_peer::present(&key_only),
        "a key with no certificate was reported as an authority"
    );
}

#[test]
fn half_an_authority_is_refused() {
    // A certificate with no key signs nothing and a key with no certificate is
    // trusted by nobody. Either one alone is a fault to report, never a state
    // to repair by guessing.
    let whole = ek_ek_peer::install(&Snapshot::new(config()), &authority());

    let mut without_key = whole.clone();
    without_key.secrets.clear();
    assert_eq!(
        ek_ek_peer::read(&without_key)
            .expect_err("half an authority is refused")
            .reason(),
        Reason::Storage
    );

    let mut without_certificate = whole;
    without_certificate.cluster = None;
    assert_eq!(
        ek_ek_peer::read(&without_certificate)
            .expect_err("half an authority is refused")
            .reason(),
        Reason::Storage
    );
}

#[test]
fn a_node_with_no_authority_says_so() {
    let failure =
        ek_ek_peer::read(&Snapshot::new(config())).expect_err("a bare state holds no authority");
    assert_eq!(failure.reason(), Reason::Storage);
    assert!(
        failure.detail().contains("cluster init"),
        "the failure does not say what to do: {failure}"
    );
}

#[test]
fn a_configuration_write_built_from_the_stored_state_keeps_the_authority() {
    // The rule every caller in this product follows: read the state, change
    // the part you own, write it back.
    let home = tempfile::tempdir().expect("a directory");
    let store = store(home.path());
    let authority = authority();

    store
        .write(
            &ek_ek_peer::install(&Snapshot::new(config()), &authority),
            &Change::new("cluster", "authority created"),
        )
        .expect("the write succeeds");

    let mut next = store.read().expect("readable").expect("a state");
    next.config.certificate_expiry_warning_days = 45;
    store
        .write(&next, &Change::new("admin", "a setting changed"))
        .expect("the write succeeds");

    let held = store.read().expect("readable").expect("a state");
    assert_eq!(
        ek_ek_peer::read(&held)
            .expect("an authority")
            .certificate_pem,
        authority.certificate_pem,
        "a configuration write took the cluster authority with it"
    );
}

#[test]
fn the_authority_and_its_key_leave_together() {
    // A state is written whole. What must never happen is one half surviving a
    // write the other did not: a certificate with no key signs nothing, and
    // there would be no fault anywhere to say why enrolment stopped working.
    let home = tempfile::tempdir().expect("a directory");
    let store = store(home.path());

    store
        .write(
            &ek_ek_peer::install(&Snapshot::new(config()), &authority()),
            &Change::new("cluster", "authority created"),
        )
        .expect("the write succeeds");
    store
        .write(&Snapshot::new(config()), &Change::new("admin", "bare"))
        .expect("the write succeeds");

    let held = store.read().expect("readable").expect("a state");
    assert!(held.cluster.is_none(), "the certificate outlived its key");
    assert!(
        !held.secrets.contains_key(&ek_ek_peer::authority_key_id()),
        "the key outlived its certificate"
    );
}

#[test]
fn a_rollback_keeps_the_authority() {
    // The reason the identity is not inside the config (ADR-0082). Reverting a
    // configuration to last week must not revert the trust every node depends
    // on to reach every other one.
    let home = tempfile::tempdir().expect("a directory");
    let store = store(home.path());
    let authority = authority();

    let first = store
        .write(&Snapshot::new(config()), &Change::new("admin", "first"))
        .expect("the write succeeds");
    store
        .write(
            &ek_ek_peer::install(&Snapshot::new(config()), &authority),
            &Change::new("cluster", "authority created"),
        )
        .expect("the write succeeds");

    store
        .roll_back_to(first, &Change::new("admin", "back to first"))
        .expect("the rollback succeeds");

    let held = store.read().expect("readable").expect("a state");
    assert_eq!(
        ek_ek_peer::read(&held)
            .expect("an authority")
            .certificate_pem,
        authority.certificate_pem,
        "a rollback took the cluster authority with it"
    );
}

#[test]
fn a_store_that_holds_nothing_holds_no_authority() {
    let home = tempfile::tempdir().expect("a directory");
    let store = store(home.path());
    assert!(store.read().expect("readable").is_none());

    store
        .write(&Snapshot::new(config()), &Change::new("admin", "first"))
        .expect("the write succeeds");
    let held = store.read().expect("readable").expect("a state");
    assert!(
        !ek_ek_peer::present(&held),
        "a store nobody bootstrapped reports an authority"
    );
}
