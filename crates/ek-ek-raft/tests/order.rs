// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a running certificate order must do once it is replicated.
//!
//! The order is placed on one node and answered on whichever node the
//! certificate authority reaches. That only works if the answer, the order URL
//! and the signing key all arrive on every node, so those three are what is
//! measured here (ADR-0032, ADR-0086).
//!
//! Real consensus over the real peer channel, like everything else in this
//! crate. A record that only ever lived in one process would satisfy a
//! measurement written against a double and lose the order the first time a
//! node stopped.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;

use ek_ek_config::{CertificateId, NodeId, SecretId};
use ek_ek_raft::Reason;
use ek_ek_store::{OrderChallenge, OrderRecord, Secret, Snapshot};

mod common;

use common::{Fleet, PATIENCE, change, snapshot, steady, wait_until};

/// The three nodes every measurement here runs.
const NAMES: [&str; 3] = ["node-a", "node-b", "node-c"];

/// The certificate being ordered.
const CERTIFICATE: &str = "cert-web";

/// The token the certificate authority will ask for.
const TOKEN: &str = "tokenTOKENtoken";

/// What the token has to be answered with.
const ANSWER: &str = "tokenTOKENtoken.thumbprint";

/// Where the certificate authority named the order.
const PLACED: &str = "https://acme.example.org/order/9";

/// The identity the signing key sits under.
const KEY: &str = "cert-web.order-key";

/// The signing key itself, which the taking over node has to hold.
const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nthe order key\n-----END PRIVATE KEY-----\n";

/// How long a stopped node is given to be noticed.
const SETTLING: Duration = Duration::from_millis(800);

/// A state carrying one running order and the key it will be finalised with.
fn ordering(url: Option<&str>) -> Snapshot {
    snapshot(3)
        .with_order(
            CertificateId::new(CERTIFICATE),
            OrderRecord {
                names: vec!["www.example.org".to_owned()],
                challenge: OrderChallenge::Http01,
                order_url: url.map(str::to_owned),
                key: SecretId::new(KEY),
                answers: BTreeMap::from([(TOKEN.to_owned(), ANSWER.to_owned())]),
                driven_by: Some(NodeId::new("node-a")),
                started_at_unix: 1_700_000_000,
            },
        )
        .with_secret(SecretId::new(KEY), Secret::new(KEY_PEM.to_vec()))
}

/// What one node would answer the certificate authority with.
fn answers(node: &common::Node) -> BTreeMap<String, String> {
    let mut held = BTreeMap::new();
    if let Some(state) = node.cluster().read().expect("readable") {
        for record in state.orders.values() {
            for (token, value) in &record.answers {
                held.insert(token.clone(), value.clone());
            }
        }
    }
    held
}

#[tokio::test]
async fn the_answer_one_node_placed_is_held_by_all_three() {
    let fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    // Nobody answers before the order, which is what says the reading below
    // came from the order rather than from something already there.
    for node in &fleet.nodes {
        assert!(
            answers(node).is_empty(),
            "{} answered a challenge before any order was placed",
            node.id.as_str()
        );
    }

    fleet
        .leader()
        .cluster()
        .write(&ordering(Some(PLACED)), &change("an order"), 1_700_000_000)
        .await
        .expect("the leader writes");

    let arrived = wait_until(PATIENCE, || {
        fleet
            .nodes
            .iter()
            .all(|node| answers(node).get(TOKEN).map(String::as_str) == Some(ANSWER))
            .then_some(())
    })
    .await;
    assert!(
        arrived.is_some(),
        "the challenge answer never reached every node, so the certificate \
         authority would get a 404 from any node but the one that ordered: {:?}",
        fleet
            .nodes
            .iter()
            .map(|node| (node.id.as_str().to_owned(), answers(node)))
            .collect::<Vec<(String, BTreeMap<String, String>)>>()
    );
}

#[tokio::test]
async fn every_node_holds_what_it_would_need_to_take_the_order_over() {
    let fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    fleet
        .leader()
        .cluster()
        .write(&ordering(Some(PLACED)), &change("an order"), 1_700_000_000)
        .await
        .expect("the leader writes");
    fleet.await_agreement().await;

    for node in &fleet.nodes {
        let state = node
            .cluster()
            .read()
            .expect("readable")
            .expect("something was written");
        let held = state
            .orders
            .get(&CertificateId::new(CERTIFICATE))
            .unwrap_or_else(|| panic!("{} holds no order", node.id.as_str()));

        assert_eq!(
            held.order_url.as_deref(),
            Some(PLACED),
            "{} does not know where the order is, so it could only start a \
             second one and spend the server's allowance twice",
            node.id.as_str()
        );
        assert_eq!(
            state.secrets.get(&held.key).map(Secret::expose),
            Some(KEY_PEM),
            "{} does not hold the key the certificate will be issued against, \
             so taking the order over would download something it cannot serve",
            node.id.as_str()
        );
    }
}

#[tokio::test]
async fn an_order_that_finished_leaves_no_node_answering() {
    let fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    fleet
        .leader()
        .cluster()
        .write(&ordering(Some(PLACED)), &change("an order"), 1_700_000_000)
        .await
        .expect("the leader writes");
    fleet.await_agreement().await;

    fleet
        .leader()
        .cluster()
        .write(&snapshot(3), &change("the order finished"), 1_700_000_001)
        .await
        .expect("the leader writes");

    let closed = wait_until(PATIENCE, || {
        fleet
            .nodes
            .iter()
            .all(|node| answers(node).is_empty())
            .then_some(())
    })
    .await;
    assert!(
        closed.is_some(),
        "a node kept answering a challenge after the order finished, \
         which is an open path on a name nobody is watching"
    );
}

#[tokio::test]
async fn no_order_is_opened_without_a_quorum() {
    let mut fleet = Fleet::start(&NAMES, steady()).await;
    fleet.initialise().await;

    let leader = fleet.leader().id.clone();
    for name in NAMES.iter().filter(|name| **name != leader.as_str()) {
        fleet.named_mut(name).stop().await;
    }
    tokio::time::sleep(SETTLING).await;

    let refused = fleet
        .named(leader.as_str())
        .cluster()
        .write(&ordering(None), &change("an order"), 1_700_000_002)
        .await
        .expect_err("a cluster with no quorum cannot open an order");
    assert_eq!(
        refused.reason(),
        Reason::NoQuorum,
        "the refusal did not say the cluster was the problem: {refused}"
    );

    // Nothing was written anywhere, so nothing is half opened. An order the
    // caller was told did not happen must not be one a returning quorum then
    // applies (ADR-0086).
    let held = fleet
        .named(leader.as_str())
        .cluster()
        .read()
        .expect("a node with no quorum still answers what it holds");
    assert!(
        held.is_none_or(|state| state.orders.is_empty()),
        "an order was opened on a cluster that could not agree to it"
    );
}
