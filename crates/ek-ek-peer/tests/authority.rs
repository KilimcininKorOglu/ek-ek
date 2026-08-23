// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the cluster authority is, and what it signs.
//!
//! Everything here is read back out of the encoded certificate with OpenSSL,
//! never out of the value the builder returned. A field that was never encoded
//! and a field this crate simply remembers look identical from the inside, and
//! only one of them reaches a peer.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::IpAddr;

use ek_ek_config::NodeId;
use ek_ek_peer::{
    AUTHORITY_COMMON_NAME, AUTHORITY_LIFETIME_DAYS, CLOCK_SKEW_ALLOWANCE_SECONDS,
    NODE_LIFETIME_DAYS, Reason,
};
use openssl::nid::Nid;
use openssl::x509::X509;

mod common;

use common::{DAY, authority, issue, issue_at, now};

/// A fixed moment, so a window can be read as a number.
const AT: i64 = 1_800_000_000;

fn parsed(pem: &str) -> X509 {
    X509::from_pem(pem.as_bytes()).expect("the certificate reads back")
}

/// The certificate as OpenSSL itself prints it.
///
/// Printed rather than asked field by field, because the printer walks the
/// encoding: an extension that was built and never appended is absent here and
/// would be absent at a peer too.
fn text(certificate: &X509) -> String {
    String::from_utf8(certificate.to_text().expect("the certificate prints"))
        .expect("the print is text")
}

fn common_name(certificate: &X509) -> String {
    certificate
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .expect("a common name")
        .data()
        .as_utf8()
        .expect("readable")
        .to_string()
}

#[test]
fn the_authority_says_it_is_one() {
    // Without the constraint every node certificate would also be able to sign
    // node certificates, and holding one would be holding the cluster.
    let certificate = parsed(&authority().certificate_pem);
    assert!(
        text(&certificate).contains("CA:TRUE"),
        "the authority does not carry the CA constraint:\n{}",
        text(&certificate)
    );
    assert_eq!(common_name(&certificate), AUTHORITY_COMMON_NAME);
}

#[test]
fn a_node_certificate_says_it_is_not_an_authority() {
    // The other side. Without it the check above would pass against a build
    // that marks everything as an authority.
    let certificate = parsed(&issue(&authority(), "node-1").certificate_pem);
    assert!(
        text(&certificate).contains("CA:FALSE"),
        "a node certificate can sign other certificates:\n{}",
        text(&certificate)
    );
}

#[test]
fn every_certificate_is_written_as_x509_v3() {
    // Version 2 in the encoding is v3. A v1 certificate carries no extension
    // field at all, so a verifier is free to ignore the constraints above it,
    // and nothing about the printed text would look different.
    let authority = authority();
    assert_eq!(
        parsed(&authority.certificate_pem).version(),
        2,
        "the authority is not an X.509 v3 certificate"
    );
    assert_eq!(
        parsed(&issue(&authority, "node-1").certificate_pem).version(),
        2,
        "a node certificate is not an X.509 v3 certificate"
    );
}

#[test]
fn the_authority_signs_itself_and_nothing_above_it() {
    let authority = authority();
    let certificate = parsed(&authority.certificate_pem);
    let key = certificate.public_key().expect("a public key");

    assert!(
        certificate.verify(&key).expect("the check runs"),
        "the authority is not signed by its own key"
    );
    assert_eq!(
        format!("{:?}", certificate.issuer_name()),
        format!("{:?}", certificate.subject_name()),
        "the authority names somebody else as its issuer"
    );
}

#[test]
fn a_node_certificate_is_signed_by_the_authority() {
    let authority = authority();
    let issued = issue(&authority, "node-1");

    let signer = parsed(&authority.certificate_pem)
        .public_key()
        .expect("a public key");
    assert!(
        parsed(&issued.certificate_pem)
            .verify(&signer)
            .expect("the check runs"),
        "the node certificate was not signed by this authority"
    );
}

#[test]
fn a_certificate_from_another_authority_does_not_verify() {
    // The other side of the check above. Two authorities are two clusters, and
    // a signature check that passed against either would be no check at all.
    let ours = authority();
    let theirs = authority();
    let issued = issue(&theirs, "node-1");

    let signer = parsed(&ours.certificate_pem)
        .public_key()
        .expect("a public key");
    assert!(
        !parsed(&issued.certificate_pem)
            .verify(&signer)
            .expect("the check runs"),
        "a certificate from another authority verified against ours"
    );
}

#[test]
fn a_node_certificate_carries_the_node_identity() {
    let issued = issue(&authority(), "node-1");
    let certificate = parsed(&issued.certificate_pem);

    assert_eq!(common_name(&certificate), "node-1");

    let names = certificate.subject_alt_names().expect("alternative names");
    let dns: Vec<String> = names
        .iter()
        .filter_map(|name| name.dnsname().map(str::to_owned))
        .collect();
    assert_eq!(
        dns,
        vec!["node-1".to_owned()],
        "the identity is not a subject alternative name"
    );
}

#[test]
fn a_node_certificate_carries_the_addresses_it_was_given() {
    // The address is in there, and the identity is separate from it. A node
    // keeps its identity when its address changes, so the two must not be the
    // same field (ADR-0082).
    let authority = authority();
    let addresses: Vec<IpAddr> = vec![
        "10.0.0.7".parse().expect("an address"),
        "10.0.0.8".parse().expect("an address"),
    ];
    let issued = ek_ek_peer::issue(&authority, &NodeId::new("node-1"), &addresses, now())
        .expect("a certificate is signed");

    let certificate = parsed(&issued.certificate_pem);
    let names = certificate.subject_alt_names().expect("alternative names");
    let found: Vec<String> = names
        .iter()
        .filter_map(|name| name.ipaddress())
        .map(|bytes| {
            let octets: [u8; 4] = bytes.try_into().expect("four octets");
            IpAddr::from(octets).to_string()
        })
        .collect();
    assert_eq!(found, vec!["10.0.0.7".to_owned(), "10.0.0.8".to_owned()]);
}

#[test]
fn a_node_certificate_is_for_both_ends_of_a_connection() {
    // A peer dials and is dialled. One certificate has to carry both, or every
    // node would need two.
    let issued = issue(&authority(), "node-1");
    let printed = text(&parsed(&issued.certificate_pem));

    assert!(
        printed.contains("TLS Web Server Authentication"),
        "the certificate cannot answer a peer:\n{printed}"
    );
    assert!(
        printed.contains("TLS Web Client Authentication"),
        "the certificate cannot dial a peer:\n{printed}"
    );
}

#[test]
fn the_windows_are_the_ones_the_table_names() {
    // Read back as numbers rather than compared to the values the builder
    // returned, because a window that was computed and never encoded would
    // match itself and reach a peer as something else.
    let authority = ek_ek_peer::create(AT).expect("an authority");
    let (started, ends) =
        ek_ek_peer::window_of_pem(authority.certificate_pem.as_bytes()).expect("a window");
    assert_eq!(started, AT - CLOCK_SKEW_ALLOWANCE_SECONDS);
    // Ten years, written out. Comparing the encoding to the constant that
    // produced it would agree with itself whatever the constant became.
    assert_eq!(
        ends,
        AT + 3650 * DAY,
        "the authority no longer lasts ten years"
    );
    assert_eq!(AUTHORITY_LIFETIME_DAYS * DAY, 3650 * DAY);

    let issued = issue_at(&authority, "node-1", AT);
    let (started, ends) =
        ek_ek_peer::window_of_pem(issued.certificate_pem.as_bytes()).expect("a window");
    assert_eq!(started, AT - CLOCK_SKEW_ALLOWANCE_SECONDS);
    assert_eq!(
        ends,
        AT + 90 * DAY,
        "a node certificate no longer lasts ninety days"
    );
    assert_eq!(NODE_LIFETIME_DAYS * DAY, 90 * DAY);
    assert_eq!(
        (issued.not_before_unix, issued.not_after_unix),
        (started, ends)
    );
}

#[test]
fn a_certificate_starts_before_the_moment_it_was_signed() {
    // Two nodes never have the same clock. Without the allowance a certificate
    // signed on one and presented to the other a second later is refused as
    // not yet valid, and nothing in the configuration looks wrong.
    let issued = issue_at(&authority(), "node-1", AT);
    assert!(
        issued.not_before_unix < AT,
        "a certificate signed on one node would be too new for another"
    );
}

#[test]
fn every_certificate_gets_its_own_serial_number() {
    // Two certificates with the same serial from the same authority are two
    // certificates a verifier cannot tell apart.
    let authority = authority();
    let first = parsed(&issue(&authority, "node-1").certificate_pem);
    let second = parsed(&issue(&authority, "node-2").certificate_pem);

    let serial = |certificate: &X509| {
        certificate
            .serial_number()
            .to_bn()
            .expect("a number")
            .to_hex_str()
            .expect("readable")
            .to_string()
    };
    assert_ne!(serial(&first), serial(&second));
}

#[test]
fn every_certificate_gets_its_own_key() {
    // Two nodes sharing a key is one node: either can present the other's
    // identity by swapping the certificate.
    let authority = authority();
    let first = issue(&authority, "node-1");
    let second = issue(&authority, "node-2");

    assert_ne!(first.key_pem.expose(), second.key_pem.expose());
    assert_ne!(first.key_pem.expose(), authority.key_pem.expose());
}

#[test]
fn a_node_with_no_identity_gets_no_certificate() {
    let failure = ek_ek_peer::issue(&authority(), &NodeId::new(""), &[], now())
        .expect_err("a nameless node is refused");
    assert_eq!(failure.reason(), Reason::Configuration);
}

#[test]
fn the_identity_is_read_back_out_of_the_certificate() {
    // This is what a peer answers "who called?" with. It has to come from the
    // signed material and from nowhere else.
    let issued = issue(&authority(), "node-7");
    let read = ek_ek_peer::identity_of(&parsed(&issued.certificate_pem)).expect("an identity");
    assert_eq!(read, NodeId::new("node-7"));
}

#[test]
fn neither_the_authority_nor_a_node_key_is_printed() {
    // Every failure and every trace line eventually reaches a log. A key that
    // prints itself is a key in a log file (T-036).
    let authority = authority();
    let issued = issue(&authority, "node-1");

    let said = format!("{authority:?} {issued:?}");
    assert!(!said.contains("PRIVATE KEY"), "a key was printed: {said}");
    assert!(
        !said.contains("BEGIN"),
        "something PEM shaped was printed: {said}"
    );
}
