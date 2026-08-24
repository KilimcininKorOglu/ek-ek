// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What asking for a certificate must hold true.
//!
//! The point of a signing request is that the key never travels. Every
//! measurement here is about one of the two halves that makes that safe: the
//! request carries no key, and the cluster takes nothing from it but the
//! public one (R-33, ADR-0084).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::IpAddr;

use ek_ek_config::NodeId;
use ek_ek_peer::Reason;

mod common;

use common::{authority, now};

/// The address a certificate carries in these measurements.
fn address() -> IpAddr {
    "127.0.0.1".parse().expect("an address")
}

#[test]
fn a_request_carries_no_key() {
    // The whole reason a request exists. A request that carried the key would
    // be the enrolment file again, moved (R-33).
    let asked = ek_ek_peer::request().expect("a request is made");

    assert!(
        asked.request_pem.contains("CERTIFICATE REQUEST"),
        "what was produced is not a signing request"
    );
    assert!(
        !asked.request_pem.contains("PRIVATE KEY"),
        "the request carries the key it was made with"
    );
    // Read as a request rather than searched for a word. A PEM carrying two
    // blocks would still be readable as a request, and the check above would
    // then rest on the label alone.
    assert_eq!(
        asked.request_pem.matches("-----BEGIN").count(),
        1,
        "the request carries more than one PEM block"
    );

    // And the key it belongs to is a real one, held here.
    assert!(
        ek_ek_peer::key_of(&asked.key_pem).is_ok(),
        "the key beside the request does not read back"
    );
}

#[test]
fn a_request_is_certified_under_the_name_the_cluster_chose() {
    // The rule that stops a node choosing its own identity. The request says
    // one thing about who made it, and the certificate says what the cluster
    // decided (ADR-0084).
    let authority = authority();
    let asked = ek_ek_peer::request().expect("a request is made");

    let signed = ek_ek_peer::certify(
        &authority,
        &asked.request_pem,
        &NodeId::new("node-b"),
        &[address()],
        now(),
    )
    .expect("the request is certified");

    let certificate = openssl::x509::X509::from_pem(signed.certificate_pem.as_bytes())
        .expect("the certificate reads back");
    assert_eq!(
        ek_ek_peer::identity_of(&certificate).expect("a name"),
        NodeId::new("node-b"),
        "the certificate does not name the node the cluster admitted"
    );
    assert_ne!(
        ek_ek_peer::identity_of(&certificate)
            .expect("a name")
            .as_str(),
        ek_ek_peer::REQUEST_COMMON_NAME,
        "the name in the request reached the certificate"
    );
    assert!(
        ek_ek_peer::signed_by(&certificate, &authority.certificate_pem).expect("checkable"),
        "the certificate was not signed by the authority that certified it"
    );
}

#[test]
fn a_certified_request_carries_the_key_that_made_it_and_no_other() {
    // What makes the certificate usable at all. A certificate issued against
    // some other public key would name the node and open nothing.
    let authority = authority();
    let asked = ek_ek_peer::request().expect("a request is made");

    let signed = ek_ek_peer::certify(
        &authority,
        &asked.request_pem,
        &NodeId::new("node-b"),
        &[address()],
        now(),
    )
    .expect("the request is certified");

    let certificate = openssl::x509::X509::from_pem(signed.certificate_pem.as_bytes())
        .expect("the certificate reads back");
    let held = ek_ek_peer::key_of(&asked.key_pem).expect("the key reads back");
    assert!(
        certificate
            .public_key()
            .expect("a public key")
            .public_eq(&held),
        "the certificate was issued against a key this node does not hold"
    );

    // And another key does not answer to it, so the comparison above is not
    // one that passes for anything.
    let other = ek_ek_peer::request().expect("a second request");
    let elsewhere = ek_ek_peer::key_of(&other.key_pem).expect("the key reads back");
    assert!(
        !certificate
            .public_key()
            .expect("a public key")
            .public_eq(&elsewhere),
        "the certificate answers to a key it was not issued against"
    );
}

#[test]
fn a_request_not_signed_with_the_key_it_carries_is_refused() {
    // Proof of possession. Without this check, anybody could have a
    // certificate issued against somebody else's public key, and that
    // somebody would then hold a certificate they never asked for.
    let first = ek_ek_peer::request().expect("a request is made");

    // One request's subject and public key, signed with a key that is not the
    // one it carries. That is what somebody submitting another node's public
    // key would have to produce.
    let forged = signed_with_another_key(&first.request_pem);

    let refused = ek_ek_peer::public_key(&forged)
        .expect_err("a request whose signature does not check out is refused");
    assert!(
        matches!(refused.reason(), Reason::Rejected | Reason::Crypto),
        "the refusal is not about the request: {refused}"
    );

    // The unforged one is accepted, so the check is about the signature and
    // not about refusing every request.
    ek_ek_peer::public_key(&first.request_pem).expect("an honest request is read");
}

#[test]
fn a_request_that_is_not_a_request_is_refused() {
    let refused = ek_ek_peer::public_key("not a signing request at all")
        .expect_err("what is not a request is refused");
    assert_eq!(refused.reason(), Reason::Crypto, "{refused}");
}

/// A request carrying one public key and signed with a different one.
///
/// Built by hand, because no library offers to make an invalid signing
/// request: refusing to is the point of the format.
fn signed_with_another_key(request_pem: &str) -> String {
    use openssl::x509::X509Req;

    let held = X509Req::from_pem(request_pem.as_bytes()).expect("a request");

    let mut builder = X509Req::builder().expect("a builder");
    builder.set_version(0).expect("a version");
    builder
        .set_subject_name(held.subject_name())
        .expect("a subject");
    builder
        .set_pubkey(&held.public_key().expect("a public key"))
        .expect("a public key");

    let elsewhere = ek_ek_peer::request().expect("another request");
    let signing = ek_ek_peer::key_of(&elsewhere.key_pem).expect("the key reads back");
    builder
        .sign(&signing, openssl::hash::MessageDigest::sha256())
        .expect("a signature");

    String::from_utf8(builder.build().to_pem().expect("pem")).expect("text")
}
