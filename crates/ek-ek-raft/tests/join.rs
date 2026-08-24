// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What getting into a cluster, and being put out of one, must hold true.
//!
//! Every measurement here runs the real join over the real peer channel: a
//! node with no certificate dials a running cluster, sends a signing request,
//! and comes back holding a certificate that cluster signed. A join that only
//! ever ran against a double would prove nothing about the handshake, which is
//! the half that decides who gets in (ADR-0031, ADR-0084).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::IpAddr;
use std::sync::Arc;

use ek_ek_config::{NodeId, matrix};
use ek_ek_peer::{Credentials, Listener, Listening, Service};
use ek_ek_raft::join::{self, Ask};
use ek_ek_raft::{Reason, Token};

mod common;

use common::{Cohort, PATIENCE, now, steady, wait_until};

#[tokio::test]
async fn the_first_node_becomes_a_cluster_of_one() {
    let cohort = Cohort::found("node-a", steady()).await;

    assert_eq!(
        cohort.leader().id,
        NodeId::new("node-a"),
        "the founder did not become the leader"
    );
    assert_eq!(
        cohort.members[0].cluster.voters(),
        [NodeId::new("node-a")].into_iter().collect(),
        "a cluster of one has one voter"
    );

    // And the state it wrote is readable without asking anybody, which is what
    // makes the next join possible at all.
    let held = cohort.members[0]
        .cluster
        .read()
        .expect("readable")
        .expect("a state was written");
    assert_eq!(held.config.nodes.len(), 1);
    assert!(
        held.cluster.is_some(),
        "the founding state carries no authority"
    );
}

#[tokio::test]
async fn a_minted_token_carries_the_authority_fingerprint() {
    let cohort = Cohort::found("node-a", steady()).await;
    let token = cohort.mint().await;

    let print = ek_ek_peer::fingerprint(&cohort.authority.certificate_pem).expect("a fingerprint");
    assert_eq!(
        token.fingerprint, print,
        "the token does not carry this cluster's authority"
    );

    // And it survives being carried as one word, which is the only form an
    // operator ever handles.
    let word = token.word();
    assert!(
        !word.contains(char::is_whitespace),
        "a token with a space in it does not survive being copied: {word}"
    );
    let read = Token::read(&word).expect("the word reads back");
    assert_eq!(read.id, token.id);
    assert_eq!(read.secret, token.secret);
    assert_eq!(read.fingerprint, token.fingerprint);

    // What the cluster keeps is the digest. A backup that leaks hands over
    // nothing that can be presented.
    let held = cohort.members[0]
        .cluster
        .read()
        .expect("readable")
        .expect("a state");
    let record = held.joins.get(&token.id).expect("the token was recorded");
    assert_ne!(
        record.secret_digest, token.secret,
        "the secret itself was stored"
    );
    assert!(
        ek_ek_raft::presented(&token.secret, &record.secret_digest),
        "the stored digest does not answer to the secret it was taken from"
    );
}

#[tokio::test]
async fn a_second_node_joins_with_a_token_and_an_address() {
    let mut cohort = Cohort::found("node-a", steady()).await;
    let word = cohort.mint().await.word();

    cohort
        .admit("node-b", &word)
        .await
        .expect("the second node joins");
    cohort.await_leader().await;
    cohort.await_agreement().await;

    assert_eq!(
        cohort.members[0].cluster.voters(),
        ["node-a", "node-b"].into_iter().map(NodeId::new).collect(),
        "the cluster did not become two nodes"
    );

    let held = cohort.members[0]
        .cluster
        .read()
        .expect("readable")
        .expect("a state");
    assert_eq!(
        held.config
            .nodes
            .iter()
            .map(|node| node.id.as_str())
            .collect::<Vec<_>>(),
        ["node-a", "node-b"],
        "the config row was not written beside the vote"
    );

    // The certificate the joining node came back with is one this cluster
    // signed, and it names the node the cluster admitted rather than any name
    // the caller asked for.
    let certificate =
        ek_ek_peer::window_of_pem(cohort.members[1].credentials.certificate_pem.as_bytes());
    assert!(
        certificate.is_ok(),
        "the certificate the join handed back does not read as one"
    );
    // It names the node the cluster admitted, and it was signed by this
    // cluster. Measured through the channel: the joined node speaks to the
    // founder with it, which no other authority's certificate could do.
    ek_ek_peer::ask_health(
        cohort.members[0].address,
        &cohort.members[0].id,
        common::SCHEMA,
        &cohort.members[1].credentials,
    )
    .await
    .expect("the certificate the join handed back opens a peer connection");
}

#[tokio::test]
async fn a_third_node_makes_the_quorum_three() {
    let mut cohort = Cohort::found("node-a", steady()).await;

    for name in ["node-b", "node-c"] {
        let word = cohort.mint().await.word();
        cohort.admit(name, &word).await.expect("the node joins");
        cohort.await_leader().await;
        cohort.await_agreement().await;
    }

    assert_eq!(
        cohort.members[0].cluster.voters().len(),
        3,
        "the third node did not become a voter"
    );

    // Three voters means one may be lost. Measured by losing one and writing.
    let leader = cohort.leader().id.clone();
    let spare = cohort
        .members
        .iter()
        .find(|member| member.id != leader)
        .expect("a follower")
        .id
        .clone();
    let held = cohort
        .named(spare.as_str())
        .cluster
        .read()
        .expect("readable")
        .expect("a state");
    stop(&mut cohort, spare.as_str()).await;

    cohort
        .named(leader.as_str())
        .cluster
        .write(
            &held,
            &common::change("with two of three"),
            cohort.moment.at(),
        )
        .await
        .expect("two of three nodes are a quorum");

    // And losing a second one stops it, which is what "three" means.
    let second = cohort
        .members
        .iter()
        .find(|member| member.id != leader && member.id != spare)
        .expect("the third node")
        .id
        .clone();
    stop(&mut cohort, second.as_str()).await;

    let refused = cohort
        .named(leader.as_str())
        .cluster
        .write(
            &held,
            &common::change("with one of three"),
            cohort.moment.at(),
        )
        .await
        .expect_err("one of three nodes is not a quorum");
    assert_eq!(refused.reason(), Reason::NoQuorum, "{refused}");
}

#[tokio::test]
async fn a_used_token_is_refused_the_second_time() {
    let mut cohort = Cohort::found("node-a", steady()).await;
    let word = cohort.mint().await.word();

    cohort.admit("node-b", &word).await.expect("the node joins");
    cohort.await_leader().await;

    let refused = cohort
        .admit("node-c", &word)
        .await
        .expect_err("a token lets one node in and no more");
    assert_eq!(refused.reason(), Reason::Rejected, "{refused}");
    assert!(
        refused.detail().contains("node-b"),
        "the refusal does not say which node used the token: {refused}"
    );

    // The refused node is in neither the config nor the membership. A refusal
    // that left a row behind would be a node half admitted.
    let held = cohort.members[0]
        .cluster
        .read()
        .expect("readable")
        .expect("a state");
    assert!(
        !held
            .config
            .nodes
            .iter()
            .any(|node| node.id.as_str() == "node-c"),
        "a refused join wrote a config row"
    );
    assert!(
        !cohort.members[0]
            .cluster
            .voters()
            .contains(&NodeId::new("node-c")),
        "a refused join became a voter"
    );
}

#[tokio::test]
async fn a_token_is_refused_the_second_it_runs_out_and_not_before() {
    // Both sides of one boundary. A check that refused every token would pass
    // half of this, and a check that refused none would pass the other half.
    //
    // The moment is a parameter here rather than a live clock, so the hour a
    // token lives costs nothing to measure. The join is asked for directly
    // rather than over the channel for the same reason: a certificate signed
    // an hour into the future is one the TLS library refuses today, and this
    // measurement is about the token rather than about the handshake.
    let cohort = Cohort::found("node-a", steady()).await;
    let minted = cohort.moment.at();
    let word = cohort.mint().await.word();
    let leader = cohort.leader();

    let last = join::admit(
        leader.cluster.as_ref(),
        &asking("node-b", &word),
        minted + ek_ek_raft::LIFETIME_SECONDS - 1,
    )
    .await;
    assert!(
        last.is_ok(),
        "a token one second before it runs out let nobody in: {last:?}"
    );

    let cohort = Cohort::found("node-a", steady()).await;
    let minted = cohort.moment.at();
    let word = cohort.mint().await.word();
    let refused = join::admit(
        cohort.leader().cluster.as_ref(),
        &asking("node-b", &word),
        minted + ek_ek_raft::LIFETIME_SECONDS,
    )
    .await
    .expect_err("a token that has run out lets nobody in");
    assert_eq!(refused.reason(), Reason::Rejected, "{refused}");
    assert!(
        refused.detail().contains("run out"),
        "the refusal does not say the token ran out: {refused}"
    );
}

#[tokio::test]
async fn a_token_whose_secret_does_not_check_out_is_refused() {
    // The identity is public and names the record; the secret is what lets a
    // node in. Somebody who read an identity out of a log line still has
    // nothing, and this is what makes that true (ADR-0084).
    let cohort = Cohort::found("node-a", steady()).await;
    let minted = cohort.mint().await;

    let wrong = Token {
        secret: "f".repeat(minted.secret.len()),
        ..minted.clone()
    };
    assert_ne!(wrong.secret, minted.secret, "the secret was not changed");

    let refused = join::admit(
        cohort.leader().cluster.as_ref(),
        &asking("node-b", &wrong.word()),
        cohort.moment.at(),
    )
    .await
    .expect_err("a secret that does not check out lets nobody in");
    assert_eq!(refused.reason(), Reason::Rejected, "{refused}");
    assert!(
        refused.detail().contains("does not check out"),
        "the refusal does not say what was wrong: {refused}"
    );

    // And the right secret does let a node in, so the check is about the
    // secret and not about refusing every token.
    join::admit(
        cohort.leader().cluster.as_ref(),
        &asking("node-b", &minted.word()),
        cohort.moment.at(),
    )
    .await
    .expect("the secret the token was minted with lets a node in");
}

#[tokio::test]
async fn a_token_from_another_cluster_is_refused() {
    let mut ours = Cohort::found("node-a", steady()).await;
    let theirs = Cohort::found("other-a", steady()).await;

    let word = theirs.mint().await.word();
    let refused = ours
        .admit("node-b", &word)
        .await
        .expect_err("a token another cluster minted is not this cluster's");
    assert_eq!(refused.reason(), Reason::Rejected, "{refused}");
    assert!(
        refused.detail().contains("different cluster"),
        "the refusal does not name the reason: {refused}"
    );
}

#[tokio::test]
async fn an_impostor_holding_a_borrowed_authority_is_refused() {
    // The attack the fingerprint exists to stop, run for real. The impostor
    // holds the cluster's authority certificate, which is a public value
    // anybody can copy, and answers the join with it. What it does not hold is
    // the key, so the certificate it serves on the connection was signed by
    // somebody else, and that is what the joining node catches.
    let cohort = Cohort::found("node-a", steady()).await;
    let token = cohort.mint().await;

    let elsewhere = ek_ek_peer::create(now()).expect("another authority");
    let issued = ek_ek_peer::issue(
        &elsewhere,
        &NodeId::new("node-a"),
        &["127.0.0.1".parse::<IpAddr>().expect("an address")],
        now(),
    )
    .expect("a certificate");

    let listener = Listener::bind(
        "127.0.0.1:0",
        &Credentials {
            authority_pem: elsewhere.certificate_pem.clone(),
            certificate_pem: issued.certificate_pem,
            key_pem: issued.key_pem,
        },
        Listening::new(
            &NodeId::new("node-a"),
            common::SCHEMA,
            Arc::new(Borrowed {
                authority_pem: cohort.authority.certificate_pem.clone(),
            }),
        )
        .opening(join::SERVICE),
    )
    .await
    .expect("the impostor listens");
    let address = listener.address().expect("the port is readable");
    let serving = tokio::spawn(Arc::new(listener).serve_forever());

    let refused = join::join(
        &address.to_string(),
        &token.word(),
        join::Joining {
            node: &NodeId::new("node-b"),
            address: "127.0.0.1".parse::<IpAddr>().expect("an address"),
            peer_address: "127.0.0.1:1",
            schema_version: common::SCHEMA,
        },
    )
    .await
    .expect_err("an impostor that cannot sign is not this cluster");

    assert_eq!(refused.reason(), Reason::Rejected, "{refused}");
    assert!(
        refused.detail().contains("does not hold a certificate"),
        "the refusal does not name what was wrong: {refused}"
    );
    serving.abort();
}

#[tokio::test]
async fn a_joined_node_holds_the_whole_config() {
    let mut cohort = Cohort::found("node-a", steady()).await;

    // Something to catch up on that was written before the join, so the
    // measurement is about what the node receives rather than what it saw
    // happen.
    let founding = cohort.members[0]
        .cluster
        .read()
        .expect("readable")
        .expect("a state");
    let mut earlier = founding.clone();
    earlier.config.stickiness_key = "written before anybody joined".to_owned();
    cohort.members[0]
        .cluster
        .write(
            &earlier,
            &common::change("before the join"),
            cohort.moment.at(),
        )
        .await
        .expect("written");

    let word = cohort.mint().await.word();
    cohort.admit("node-b", &word).await.expect("the node joins");
    cohort.await_leader().await;
    cohort.await_agreement().await;

    let held = wait_until(PATIENCE, || {
        cohort.members[1]
            .cluster
            .read()
            .ok()
            .flatten()
            .filter(|state| !state.config.stickiness_key.is_empty())
    })
    .await
    .expect("the joined node catches up");

    assert_eq!(
        held.config.stickiness_key, "written before anybody joined",
        "the joined node did not receive what was written before it arrived"
    );
    assert_eq!(
        held.config,
        cohort.members[0]
            .cluster
            .read()
            .expect("readable")
            .expect("a state")
            .config,
        "the joined node and the founder disagree about the config"
    );
    assert!(
        held.cluster.is_some(),
        "the joined node did not receive the cluster authority"
    );
}

#[tokio::test]
async fn a_join_with_no_quorum_is_refused_with_a_reason() {
    let mut cohort = Cohort::found("node-a", steady()).await;
    let word = cohort.mint().await.word();
    cohort.admit("node-b", &word).await.expect("the node joins");
    cohort.await_leader().await;
    cohort.await_agreement().await;

    // Minted while there is still a quorum, so what the measurement below
    // catches is the lost quorum rather than a token that was already used.
    let spare = cohort.mint().await.word();

    // Two of two is the quorum, so losing one loses it. That is the state the
    // installation documentation warns about, and a join in it has to say so
    // rather than wait.
    let leader = cohort.leader().id.clone();
    let other = cohort
        .members
        .iter()
        .find(|member| member.id != leader)
        .expect("a second node")
        .id
        .clone();
    stop(&mut cohort, other.as_str()).await;

    let minted = join::mint(
        cohort.named(leader.as_str()).cluster.as_ref(),
        "admin",
        cohort.moment.at(),
    )
    .await
    .expect_err("a token cannot be minted without a quorum");
    assert_eq!(minted.reason(), Reason::NoQuorum, "{minted}");

    let refused = join::admit(
        cohort.named(leader.as_str()).cluster.as_ref(),
        &asking("node-c", &spare),
        cohort.moment.at(),
    )
    .await
    .expect_err("a node cannot be admitted without a quorum");
    assert_eq!(refused.reason(), Reason::NoQuorum, "{refused}");
    assert!(
        refused.reason().worth_retrying(),
        "a lost quorum has to read as worth retrying: {refused}"
    );
}

#[tokio::test]
async fn a_removed_node_stops_voting_and_stops_being_answered() {
    let mut cohort = Cohort::found("node-a", steady()).await;
    for name in ["node-b", "node-c"] {
        let word = cohort.mint().await.word();
        cohort.admit(name, &word).await.expect("the node joins");
        cohort.await_leader().await;
        cohort.await_agreement().await;
    }

    let leader = cohort.leader().id.clone();
    let cast_out = cohort
        .members
        .iter()
        .find(|member| member.id != leader)
        .expect("a follower")
        .id
        .clone();
    let credentials = cohort.named(cast_out.as_str()).credentials.clone();

    // Before: it is a voter and its peer connection is answered.
    assert!(
        cohort
            .named(leader.as_str())
            .cluster
            .voters()
            .contains(&cast_out)
    );
    ek_ek_peer::ask_health(
        cohort.named(leader.as_str()).at(),
        &leader,
        common::SCHEMA,
        &credentials,
    )
    .await
    .expect("a node in the cluster is answered");

    join::remove(
        cohort.named(leader.as_str()).cluster.as_ref(),
        &cast_out,
        "admin",
        cohort.moment.at(),
    )
    .await
    .expect("the node is removed");

    assert!(
        !cohort
            .named(leader.as_str())
            .cluster
            .voters()
            .contains(&cast_out),
        "the removed node still votes"
    );

    // After: the same certificate, which nothing revoked and which is still
    // valid for months, is refused by name (R-32). The removal wrote the list
    // through consensus and the write returned only once this node applied it,
    // so there is nothing left to wait for.
    let refused = ek_ek_peer::ask_health(
        cohort.named(leader.as_str()).at(),
        &leader,
        common::SCHEMA,
        &credentials,
    )
    .await
    .expect_err("a removed node is not answered");
    assert!(
        refused.detail().contains(ek_ek_peer::REMOVED) || refused.detail().contains("was removed"),
        "the refusal does not say the node was removed: {refused}"
    );

    // And a node that was not removed is still answered, so the refusal is
    // about the name and not about the listener refusing everybody.
    let still_in = cohort
        .members
        .iter()
        .find(|member| member.id != leader && member.id != cast_out)
        .expect("a third node")
        .credentials
        .clone();
    ek_ek_peer::ask_health(
        cohort.named(leader.as_str()).at(),
        &leader,
        common::SCHEMA,
        &still_in,
    )
    .await
    .expect("a node still in the cluster is answered");
}

#[tokio::test]
async fn a_removed_node_is_not_readmitted_under_the_same_name() {
    // Its certificate is still valid and nothing revoked it. Letting the name
    // back in with a fresh token would make the refusal list mean nothing,
    // because the node would simply rejoin and be answered again (R-32).
    let mut cohort = Cohort::found("node-a", steady()).await;
    let word = cohort.mint().await.word();
    cohort.admit("node-b", &word).await.expect("the node joins");
    cohort.await_leader().await;
    cohort.await_agreement().await;

    let leader = cohort.leader().id.clone();
    let cast_out = cohort
        .members
        .iter()
        .find(|member| member.id != leader)
        .expect("a follower")
        .id
        .clone();

    // Minted before the removal, because a two node cluster loses its quorum
    // the moment one of them stops being a voter.
    let again = cohort.mint().await.word();
    join::remove(
        cohort.named(leader.as_str()).cluster.as_ref(),
        &cast_out,
        "admin",
        cohort.moment.at(),
    )
    .await
    .expect("the node is removed");

    let refused = join::admit(
        cohort.named(leader.as_str()).cluster.as_ref(),
        &asking(cast_out.as_str(), &again),
        cohort.moment.at(),
    )
    .await
    .expect_err("a removed name does not come back");
    assert_eq!(refused.reason(), Reason::Rejected, "{refused}");
    assert!(
        refused.detail().contains(cast_out.as_str()) && refused.detail().contains("removed"),
        "the refusal does not say the name was removed: {refused}"
    );

    // And a name that was never removed is admitted with the same token, so
    // the refusal is about the name and not about the token or the quorum.
    join::admit(
        cohort.named(leader.as_str()).cluster.as_ref(),
        &asking("node-c", &again),
        cohort.moment.at(),
    )
    .await
    .expect("a name that was never removed is admitted");
}

#[tokio::test]
async fn a_join_and_a_removal_are_both_in_the_audit_log() {
    let mut cohort = Cohort::found("node-a", steady()).await;
    let word = cohort.mint().await.word();
    cohort.admit("node-b", &word).await.expect("the node joins");
    cohort.await_leader().await;
    cohort.await_agreement().await;

    let leader = cohort.leader().id.clone();
    let cast_out = cohort
        .members
        .iter()
        .find(|member| member.id != leader)
        .expect("a follower")
        .id
        .clone();
    join::remove(
        cohort.named(leader.as_str()).cluster.as_ref(),
        &cast_out,
        "admin",
        cohort.moment.at(),
    )
    .await
    .expect("the node is removed");

    let actions: Vec<String> = cohort
        .named(leader.as_str())
        .store
        .export()
        .expect("the audit log is readable")
        .audit
        .into_iter()
        .map(|record| record.action)
        .collect();

    for expected in [
        ek_ek_raft::TOKEN_MINTED,
        ek_ek_raft::NODE_JOINED,
        ek_ek_raft::NODE_REMOVED,
    ] {
        assert!(
            actions.iter().any(|action| action == expected),
            "the audit log holds no {expected} row: {actions:?}"
        );
    }
}

#[tokio::test]
async fn a_removed_node_hands_its_addresses_to_the_ones_that_are_left() {
    let mut cohort = Cohort::found("node-a", steady()).await;
    for name in ["node-b", "node-c"] {
        let word = cohort.mint().await.word();
        cohort.admit(name, &word).await.expect("the node joins");
        cohort.await_leader().await;
        cohort.await_agreement().await;
    }

    let leader = cohort.leader().id.clone();
    let holder = cohort
        .members
        .iter()
        .find(|member| member.id != leader)
        .expect("a follower")
        .id
        .clone();

    // The address is pointed at a node that does not lead, because removing
    // the leader is a different question and this one is about the address.
    let mut held = cohort
        .named(leader.as_str())
        .cluster
        .read()
        .expect("readable")
        .expect("a state");
    held.config.vips[0].preferred_node = Some(holder.clone());
    cohort
        .named(leader.as_str())
        .cluster
        .write(
            &held,
            &common::change("the address is pointed"),
            cohort.moment.at(),
        )
        .await
        .expect("written");

    let vip = ek_ek_config::VipId::new("vip-web");
    assert_eq!(
        matrix::matrix(&held.config)
            .router(&vip)
            .expect("the address is in the matrix")
            .holder()
            .cloned()
            .expect("somebody holds it"),
        holder,
        "the address is not where the measurement expects it"
    );

    join::remove(
        cohort.named(leader.as_str()).cluster.as_ref(),
        &holder,
        "admin",
        cohort.moment.at(),
    )
    .await
    .expect("the node is removed");

    let after = cohort
        .named(leader.as_str())
        .cluster
        .read()
        .expect("readable")
        .expect("a state");
    let assigned = matrix::matrix(&after.config);
    let router = assigned
        .router(&vip)
        .expect("the address is still in the matrix");
    let taken = router.holder().cloned().expect("somebody holds it");

    assert_ne!(taken, holder, "the address stayed on the removed node");
    assert!(
        after.config.nodes.iter().any(|node| node.id == taken),
        "the address went to a node that is not in the cluster"
    );
    // Every node left is in the ranking, so losing the one that took the
    // address does not leave it on nobody.
    assert_eq!(
        router.ranking.len(),
        after.config.nodes.len(),
        "not every remaining node can take the address"
    );
}

/// A join request from a node at an address nothing has to reach.
fn asking(name: &str, word: &str) -> Ask {
    Ask {
        token: word.to_owned(),
        node: name.to_owned(),
        address: "127.0.0.1".parse::<IpAddr>().expect("an address"),
        peer_address: "127.0.0.1:1".to_owned(),
        request_pem: ek_ek_peer::request().expect("a request").request_pem,
    }
}

/// An impostor that answers a join with an authority it copied.
struct Borrowed {
    authority_pem: String,
}

impl Service for Borrowed {
    fn call(
        &self,
        _from: Option<&NodeId>,
        _service: &str,
        _body: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<serde_json::Value, ek_ek_peer::Failure>> + Send + '_>,
    > {
        let answer = join::Answer {
            authority_pem: self.authority_pem.clone(),
            certificate_pem: String::new(),
            not_before_unix: 0,
            not_after_unix: 0,
        };
        Box::pin(async move {
            serde_json::to_value(answer).map_err(|error| {
                ek_ek_peer::Failure::new(ek_ek_peer::Reason::Protocol, error.to_string())
            })
        })
    }
}

/// Stops one node, leaving its store where it is.
async fn stop(cohort: &mut Cohort, name: &str) {
    let at = cohort
        .members
        .iter()
        .position(|member| member.id.as_str() == name)
        .expect("the node is in this cluster");
    let member = cohort.members.remove(at);
    member.serving.abort();
    member.cluster.halt().await.expect("the node stops");
}
