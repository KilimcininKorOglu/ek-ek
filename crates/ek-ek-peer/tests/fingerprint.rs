// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The short form of the authority, as a join token carries it.
//!
//! The shape is measured against what `openssl x509 -fingerprint -sha256`
//! produces, because that is the tool an operator holding a copy of the
//! authority would reach for. A value only this crate can compute is a value
//! nobody can check.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_peer::{FINGERPRINT_CHARACTERS, Reason};
use openssl::hash::MessageDigest;
use openssl::x509::X509;

mod common;

use common::{authority, issue};

#[test]
fn a_fingerprint_is_sixty_four_lowercase_hex_characters() {
    let mark = ek_ek_peer::fingerprint(&authority().certificate_pem).expect("a fingerprint");

    assert_eq!(mark.len(), FINGERPRINT_CHARACTERS);
    assert!(
        mark.chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)),
        "the fingerprint is not lowercase hex: {mark}"
    );
    assert!(
        !mark.contains(':'),
        "the fingerprint carries separators and will not survive being copied as one word: {mark}"
    );
}

#[test]
fn the_fingerprint_is_the_digest_openssl_prints() {
    // Computed a second time, independently, straight off the DER. If this
    // crate hashed the PEM text or a different encoding, the two would differ
    // and an operator comparing them would be told the authority is wrong.
    let authority = authority();
    let certificate =
        X509::from_pem(authority.certificate_pem.as_bytes()).expect("the certificate reads back");
    let digest = certificate
        .digest(MessageDigest::sha256())
        .expect("a digest");

    let expected: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        ek_ek_peer::fingerprint(&authority.certificate_pem).expect("a fingerprint"),
        expected
    );
}

#[test]
fn two_authorities_have_two_fingerprints() {
    // What the value is for. A fingerprint that did not change with the
    // authority would let a joining node accept the wrong cluster.
    let first = ek_ek_peer::fingerprint(&authority().certificate_pem).expect("a fingerprint");
    let second = ek_ek_peer::fingerprint(&authority().certificate_pem).expect("a fingerprint");
    assert_ne!(first, second);
}

#[test]
fn the_same_authority_has_the_same_fingerprint_every_time() {
    // The other side. A value that changed between two readings of the same
    // certificate would fail every comparison an operator makes.
    let authority = authority();
    assert_eq!(
        ek_ek_peer::fingerprint(&authority.certificate_pem).expect("a fingerprint"),
        ek_ek_peer::fingerprint(&authority.certificate_pem).expect("a fingerprint")
    );
}

#[test]
fn a_certificate_matches_its_own_fingerprint_and_no_other() {
    let ours = authority();
    let theirs = authority();
    let mark = ek_ek_peer::fingerprint(&ours.certificate_pem).expect("a fingerprint");

    assert!(ek_ek_peer::matches(&ours.certificate_pem, &mark).expect("the check runs"));
    assert!(!ek_ek_peer::matches(&theirs.certificate_pem, &mark).expect("the check runs"));
}

#[test]
fn a_value_that_is_not_a_fingerprint_is_refused_as_one() {
    // A token is typed or pasted by a person. Comparing a mistyped one byte
    // for byte would report the authority as wrong, when what is wrong is the
    // token.
    let authority = authority();
    let mark = ek_ek_peer::fingerprint(&authority.certificate_pem).expect("a fingerprint");

    for wrong in [
        String::new(),
        mark[..FINGERPRINT_CHARACTERS - 1].to_owned(),
        format!("{mark}0"),
        mark.to_uppercase(),
        format!("{}zz", &mark[..FINGERPRINT_CHARACTERS - 2]),
    ] {
        assert!(
            !ek_ek_peer::well_formed(&wrong),
            "{wrong} passed the shape check"
        );
        assert_eq!(
            ek_ek_peer::matches(&authority.certificate_pem, &wrong)
                .expect_err("a malformed token is refused")
                .reason(),
            Reason::Configuration
        );
    }

    // And the real one passes, so the checks above are measuring the shape and
    // not a function that refuses everything.
    assert!(ek_ek_peer::well_formed(&mark));
}

#[test]
fn a_node_certificate_has_a_fingerprint_of_its_own() {
    // The value is computed over whatever certificate it is given, so a caller
    // cannot end up comparing an authority against a node by accident.
    let authority = authority();
    let issued = issue(&authority, "node-1");

    assert_ne!(
        ek_ek_peer::fingerprint(&issued.certificate_pem).expect("a fingerprint"),
        ek_ek_peer::fingerprint(&authority.certificate_pem).expect("a fingerprint")
    );
}

#[test]
fn something_that_is_not_a_certificate_has_no_fingerprint() {
    assert_eq!(
        ek_ek_peer::fingerprint("not a certificate")
            .expect_err("refused")
            .reason(),
        Reason::Crypto
    );
}
