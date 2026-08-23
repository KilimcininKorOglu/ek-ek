// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which TLS versions a frontend actually accepts at each policy level.
//!
//! Every measurement runs the real binary and a real TLS client, because what
//! is at stake is what a client on the wire is allowed to do. A level that
//! reads correctly in a table and lets an old client through anyway is worth
//! nothing.
//!
//! Both sides of every level are measured: one version it must accept and one
//! it must refuse. A check that only ever sees a refusal would pass against a
//! frontend that refuses everybody.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use openssl::ssl::SslVersion;

mod common;

use common::tls::{Authority, handshake_at, handshake_with_ciphers};
use common::{Document, Member, Running, free_port};

/// The name every certificate here covers and every client asks for.
const NAME: &str = "web.ornek.test";

/// A document with one TLS frontend at the level named.
///
/// A level of nothing leaves the field out of the document, which is how the
/// default is measured rather than assumed.
fn document(port: u16, member: &Member, authority: &Authority, policy: Option<&str>) -> Document {
    let leaf = authority.issue(&[NAME]);
    Document::new(port, vec![member.entry(1, "enabled")])
        .certificate(
            "cert-web",
            &[NAME],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .terminating_tls_at(&["cert-web"], Some("cert-web"), policy)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_modern_level_takes_tls_1_3_and_refuses_tls_1_2() {
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let port = free_port();
    let running = Running::start(&document(port, &member, &authority, Some("modern"))).await;

    let accepted = handshake_at(running.port, SslVersion::TLS1_3, NAME)
        .expect("a TLS 1.3 client must be served");
    assert_eq!(accepted, "TLSv1.3");

    let refused = handshake_at(running.port, SslVersion::TLS1_2, NAME);
    assert!(
        refused.is_err(),
        "a TLS 1.2 client got through the modern level: {refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_balanced_level_takes_tls_1_2_and_1_3_and_refuses_tls_1_1() {
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let port = free_port();
    let running = Running::start(&document(port, &member, &authority, Some("dengeli"))).await;

    assert_eq!(
        handshake_at(running.port, SslVersion::TLS1_2, NAME)
            .expect("a TLS 1.2 client must be served"),
        "TLSv1.2"
    );
    assert_eq!(
        handshake_at(running.port, SslVersion::TLS1_3, NAME)
            .expect("a TLS 1.3 client must be served"),
        "TLSv1.3"
    );

    for version in [SslVersion::TLS1, SslVersion::TLS1_1] {
        let refused = handshake_at(running.port, version, NAME);
        assert!(
            refused.is_err(),
            "{version:?} got through the balanced level: {refused:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_legacy_level_takes_a_tls_1_0_client() {
    // The deliberate concession (ADR-0028). It exists so an institution with
    // clients it cannot upgrade can still use the product.
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let port = free_port();
    let running = Running::start(&document(port, &member, &authority, Some("eski-uyumlu"))).await;

    for (version, expected) in [
        (SslVersion::TLS1, "TLSv1"),
        (SslVersion::TLS1_1, "TLSv1.1"),
        (SslVersion::TLS1_2, "TLSv1.2"),
        (SslVersion::TLS1_3, "TLSv1.3"),
    ] {
        let spoken = handshake_at(running.port, version, NAME)
            .unwrap_or_else(|error| panic!("{version:?} must be served: {error}"));
        assert_eq!(spoken, expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frontend_that_names_no_level_behaves_like_the_balanced_one() {
    // Measured through the wire rather than through the document, because
    // what matters is what the listener does with a client and not what the
    // deserialiser put in a field.
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let port = free_port();
    let running = Running::start(&document(port, &member, &authority, None)).await;

    assert_eq!(
        handshake_at(running.port, SslVersion::TLS1_2, NAME)
            .expect("a TLS 1.2 client must be served"),
        "TLSv1.2"
    );
    let refused = handshake_at(running.port, SslVersion::TLS1_1, NAME);
    assert!(
        refused.is_err(),
        "a frontend with no level named accepted TLS 1.1: {refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_frontends_at_two_levels_do_not_reach_into_each_other() {
    // One process, two listeners. Two processes would prove nothing about
    // either, because the settings live on the listener (ADR-0081).
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let leaf = authority.issue(&[NAME]);
    let strict_port = free_port();
    let relaxed_port = free_port();
    let paper = Document::new(strict_port, vec![member.entry(1, "enabled")])
        .certificate(
            "cert-web",
            &[NAME],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .terminating_tls_at(&["cert-web"], Some("cert-web"), Some("modern"))
        .second_tls_frontend("web-legacy", relaxed_port, &["cert-web"], "eski-uyumlu");
    let running = Running::start(&paper).await;

    // The relaxed frontend takes an old client.
    assert_eq!(
        handshake_at(relaxed_port, SslVersion::TLS1, NAME)
            .expect("the relaxed frontend must take TLS 1.0"),
        "TLSv1"
    );
    // And the strict one on the same process still refuses TLS 1.2, so the
    // relaxation did not leak across.
    let refused = handshake_at(running.port, SslVersion::TLS1_2, NAME);
    assert!(
        refused.is_err(),
        "the strict frontend was loosened by the relaxed one: {refused:?}"
    );
    assert_eq!(
        handshake_at(running.port, SslVersion::TLS1_3, NAME)
            .expect("the strict frontend must still serve TLS 1.3"),
        "TLSv1.3"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_balanced_level_refuses_a_client_that_offers_only_a_weak_suite() {
    // The cipher list is in the product and not in the document, so this is
    // the only way an operator could reach it: by being a client. A frontend
    // that answered here would be running a list nobody chose.
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let port = free_port();
    let running = Running::start(&document(port, &member, &authority, Some("dengeli"))).await;

    // No forward secrecy and a CBC mode. Both are in the legacy list and in
    // neither of the other two.
    let refused = handshake_with_ciphers(running.port, "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0", NAME);
    assert!(
        refused.is_err(),
        "the balanced level answered a suite it does not offer: {refused:?}"
    );

    // And a suite it does offer still works, so the refusal is the list
    // rather than the frontend refusing everybody.
    let agreed = handshake_with_ciphers(running.port, "ECDHE-ECDSA-AES128-GCM-SHA256", NAME)
        .expect("a suite the level offers must be agreed");
    assert_eq!(agreed, "ECDHE-ECDSA-AES128-GCM-SHA256");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_legacy_level_answers_a_weak_suite_and_still_prefers_a_strong_one() {
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let port = free_port();
    let running = Running::start(&document(port, &member, &authority, Some("eski-uyumlu"))).await;

    // What the concession is for: a client that can offer nothing better.
    let agreed = handshake_with_ciphers(running.port, "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0", NAME)
        .expect("the relaxed level must serve the client it exists for");
    assert_eq!(agreed, "ECDHE-ECDSA-AES128-SHA");

    // A modern client on the same frontend is not dragged down with it.
    let strong = handshake_with_ciphers(
        running.port,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0",
        NAME,
    )
    .expect("a client offering both must be served");
    assert_eq!(strong, "ECDHE-ECDSA-AES128-GCM-SHA256");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relaxed_level_is_announced_by_the_running_process() {
    // The warning in the document says a level was chosen. This says it is in
    // force. M8 moves this line to the audit log (ADR-0081).
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let port = free_port();
    let running = Running::start(&document(port, &member, &authority, Some("eski-uyumlu"))).await;

    let said = running.log_text();
    assert!(
        said.contains("eski-uyumlu"),
        "the process never named the level it is running: {said}"
    );
    assert!(
        said.contains("web"),
        "the line must name the frontend: {said}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frontend_at_a_safe_level_is_not_announced() {
    // The other side. Without it the check above would pass against a process
    // that writes the line for every frontend.
    let member = Member::start("web-1").await;
    let authority = Authority::new();
    let port = free_port();
    let running = Running::start(&document(port, &member, &authority, Some("modern"))).await;

    // The claim rather than the level's name: a line naming the modern level
    // and still saying old versions are accepted would be the same fault, and
    // a check on the name alone would not see it.
    assert!(
        !running.log_text().contains("TLS 1.0 and 1.1 are accepted"),
        "a frontend at the modern level was announced as relaxed: {}",
        running.log_text()
    );
    assert!(!running.log_text().contains("eski-uyumlu"));
}
