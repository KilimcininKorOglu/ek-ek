// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the store must hold true about a certificate order that is running.
//!
//! An order is not configuration. Nobody writes one by hand, and a rollback to
//! last week must not restart one that finished days ago. It also has to
//! survive the process that opened it, because the whole point of writing it
//! down is that another node can finish what this one started (ADR-0086).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{CertificateId, Config, NodeId, SchemaVersion, SecretId};
use ek_ek_store::{
    Change, History, OrderChallenge, OrderRecord, Secret, Snapshot, SqliteStore, Store,
};
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

fn running(url: Option<&str>) -> OrderRecord {
    OrderRecord {
        names: vec!["www.example.org".to_owned(), "example.org".to_owned()],
        challenge: OrderChallenge::Http01,
        order_url: url.map(str::to_owned),
        key: SecretId::new("cert-web.order-key"),
        answers: BTreeMap::from([("tokenTOKEN".to_owned(), "tokenTOKEN.thumb".to_owned())]),
        driven_by: Some(NodeId::new("node2")),
        started_at_unix: 1_700_000_000,
    }
}

#[test]
fn an_order_comes_back_out_of_the_store_exactly_as_it_went_in() {
    let directory = data_directory();
    let held = running(Some("https://acme.example.org/order/7"));

    {
        let store = store(&directory);
        store
            .write(
                &Snapshot::new(config(3)).with_order(CertificateId::new("cert-web"), held.clone()),
                &Change::new("acme", "an order was opened"),
            )
            .expect("the order is written");
    }

    // A second open, so what is read comes off the disk rather than out of the
    // process that wrote it. An order that only ever lived in memory would
    // pass every other rule here and still be lost the moment a node stopped,
    // which is the case the record exists for.
    let store = store(&directory);
    let read = store
        .read()
        .expect("the store reads")
        .expect("something was written");

    assert_eq!(
        read.orders.get(&CertificateId::new("cert-web")),
        Some(&held),
        "the order did not survive the process that opened it"
    );
}

#[test]
fn an_order_nothing_was_placed_for_yet_says_so() {
    let directory = data_directory();
    let store = store(&directory);
    store
        .write(
            &Snapshot::new(config(1)).with_order(CertificateId::new("cert-web"), running(None)),
            &Change::new("acme", "an order was opened"),
        )
        .expect("the order is written");

    let read = store
        .read()
        .expect("the store reads")
        .expect("something was written")
        .orders
        .remove(&CertificateId::new("cert-web"))
        .expect("the order is there");

    assert_eq!(read.order_url, None);
    assert!(
        !read.placed(),
        "a record with no URL claimed the server had named the order, \
         so a node taking it over would read an order that does not exist"
    );
}

#[test]
fn the_orders_are_replaced_whole_and_never_merged() {
    let directory = data_directory();
    let store = store(&directory);

    let both = Snapshot::new(config(1))
        .with_order(CertificateId::new("cert-web"), running(Some("one")))
        .with_order(CertificateId::new("cert-mail"), running(Some("two")));
    store
        .write(&both, &Change::new("acme", "two orders"))
        .expect("both are written");

    let one = Snapshot::new(config(1)).with_order(CertificateId::new("cert-web"), running(None));
    store
        .write(&one, &Change::new("acme", "one finished"))
        .expect("the state is written");

    let read = store
        .read()
        .expect("the store reads")
        .expect("something was written");
    assert_eq!(
        read.orders.keys().collect::<Vec<&CertificateId>>(),
        vec![&CertificateId::new("cert-web")],
        "an order that a later state removed came back, \
         so the challenge path would stay open for a name nobody is ordering"
    );
}

#[test]
fn a_rollback_does_not_restart_an_order_that_finished() {
    let directory = data_directory();
    let store = store(&directory);

    let opened = store
        .write(
            &Snapshot::new(config(1))
                .with_order(CertificateId::new("cert-web"), running(Some("u"))),
            &Change::new("acme", "an order was opened"),
        )
        .expect("the order is written");

    store
        .write(
            &Snapshot::new(config(2)),
            &Change::new("acme", "the order finished"),
        )
        .expect("the state is written");

    History::roll_back_to(
        &store,
        opened,
        &Change::new("operator", "back to yesterday"),
    )
    .expect("the rollback goes through");

    let read = store
        .read()
        .expect("the store reads")
        .expect("something was written");
    assert_eq!(
        read.config.nodes.len(),
        1,
        "the rollback did not restore the configuration it was asked for, \
         so the rule below measured nothing"
    );
    assert!(
        read.orders.is_empty(),
        "rolling the configuration back restarted an order that had finished: {:?}",
        read.orders.keys().collect::<Vec<&CertificateId>>()
    );
}

#[test]
fn a_rollback_does_not_take_a_running_order_with_it() {
    let directory = data_directory();
    let store = store(&directory);

    let quiet = store
        .write(
            &Snapshot::new(config(1)),
            &Change::new("operator", "yesterday"),
        )
        .expect("the state is written");
    store
        .write(
            &Snapshot::new(config(2))
                .with_order(CertificateId::new("cert-web"), running(Some("u"))),
            &Change::new("acme", "an order was opened"),
        )
        .expect("the order is written");

    History::roll_back_to(&store, quiet, &Change::new("operator", "back to yesterday"))
        .expect("the rollback goes through");

    let read = store
        .read()
        .expect("the store reads")
        .expect("something was written");
    assert_eq!(
        read.config.nodes.len(),
        1,
        "the rollback did not restore the configuration it was asked for, \
         so the rule below measured nothing"
    );
    assert_eq!(
        read.orders.get(&CertificateId::new("cert-web")).cloned(),
        Some(running(Some("u"))),
        "rolling the configuration back lost an order that was still running, \
         so nobody would finish it and nobody would know it had been placed"
    );
}

#[test]
fn the_signing_key_of_an_order_is_sealed_like_every_other_secret() {
    let directory = data_directory();
    let key = SecretId::new("cert-web.order-key");
    // Built rather than written out. A literal PEM block in a tracked file is
    // what `check-secrets.sh` looks for, and a checker that has to be told
    // which blocks are pretend is one that misses a real one.
    let mark = "KEY";
    let material = format!("-----BEGIN PRIVATE {mark}-----\norder\n-----END PRIVATE {mark}-----\n")
        .into_bytes();

    {
        let store = store(&directory);
        store
            .write(
                &Snapshot::new(config(1))
                    .with_order(CertificateId::new("cert-web"), running(Some("u")))
                    .with_secret(key.clone(), Secret::new(material.clone())),
                &Change::new("acme", "an order was opened"),
            )
            .expect("the order is written");
    }

    let raw = std::fs::read(directory.path().join(ek_ek_store::DATABASE_FILE))
        .expect("the database is readable");
    assert!(
        !raw.windows(material.len()).any(|window| window == material),
        "the signing key of a running order is readable in the database file"
    );

    // The record is there in the clear, which is what says the check above
    // looked at a file that actually holds the order.
    assert!(
        raw.windows(b"cert-web".len())
            .any(|window| window == b"cert-web"),
        "the order never reached the database, so nothing was checked"
    );

    let store = store(&directory);
    let read = store
        .read()
        .expect("the store reads")
        .expect("something was written");
    assert_eq!(
        read.secrets.get(&key).map(Secret::expose),
        Some(material.as_slice()),
        "the signing key did not come back out intact, \
         so a node taking the order over could not finish it"
    );
}

#[test]
fn a_dns01_order_carries_no_answer_for_a_traffic_path() {
    let directory = data_directory();
    let store = store(&directory);

    let mut record = running(Some("https://acme.example.org/order/9"));
    record.challenge = OrderChallenge::Dns01;
    record.answers = BTreeMap::new();
    store
        .write(
            &Snapshot::new(config(1)).with_order(CertificateId::new("cert-wild"), record),
            &Change::new("acme", "a wildcard order"),
        )
        .expect("the order is written");

    let read = store
        .read()
        .expect("the store reads")
        .expect("something was written")
        .orders
        .remove(&CertificateId::new("cert-wild"))
        .expect("the order is there");

    assert_eq!(read.challenge, OrderChallenge::Dns01);
    assert!(
        read.answers.is_empty(),
        "a DNS-01 order left an answer for a traffic path to serve, \
         and the traffic path is not where a name server looks"
    );
}
