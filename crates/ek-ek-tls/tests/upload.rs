// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What an operator may upload, and what has to be refused.
//!
//! Every certificate here is built when the measurement runs, with the same
//! library the product serves handshakes with. A fixture file would be a key
//! in the repository, and a key in the repository is a leaked key.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{authority, intermediate, joined, leaf, now, text_of};
use ek_ek_config::{CertificateId, ErrorCode, WarningCode};
use ek_ek_tls::inspect;

/// The measurements that only need one working certificate.
fn signed() -> (common::Pair, common::Pair) {
    let ca = authority("ek-ek test CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);
    (ca, server)
}

#[test]
fn a_certificate_and_its_key_are_read() {
    let (ca, server) = signed();
    let chain = joined(&[&server.certificate, &ca.certificate]);

    let upload = inspect(&chain, &server.key_pem(), None, now()).expect("this pair is good");

    assert_eq!(upload.sni_names, vec!["www.example.org".to_owned()]);
    assert!(upload.warnings.is_empty(), "{:?}", upload.warnings);
    assert!(upload.validity.not_before_unix <= now());
    assert!(upload.validity.not_after_unix > now());
    // What is stored is what was parsed, so a file with anything around the
    // PEM blocks is stored in one shape.
    let stored = String::from_utf8(upload.chain.expose().to_vec()).expect("PEM is text");
    assert_eq!(stored.matches("BEGIN CERTIFICATE").count(), 2);
    assert!(
        String::from_utf8_lossy(upload.key.expose()).contains("BEGIN PRIVATE KEY"),
        "the key is stored unencrypted, because the store seals it"
    );
}

#[test]
fn a_key_that_belongs_to_another_certificate_is_refused() {
    let (ca, server) = signed();
    let other = leaf("other.example.org", &["other.example.org"], &ca, 0, 90);

    let refused = inspect(&server.chain_pem(), &other.key_pem(), None, now())
        .expect_err("the pair does not match");

    assert_eq!(refused.codes(), vec![ErrorCode::CertificateKeyMismatch]);
    assert_eq!(refused.as_slice()[0].path.as_text(), "private_key");

    // The other side: its own key is accepted, so the rule is about the pair
    // and not about the key being unreadable.
    assert!(inspect(&server.chain_pem(), &server.key_pem(), None, now()).is_ok());
}

#[test]
fn a_broken_certificate_is_refused() {
    let (_, server) = signed();

    // A file with no PEM block in it, which is what uploading the wrong file
    // looks like.
    let refused = inspect(b"this is not a certificate", &server.key_pem(), None, now())
        .expect_err("it holds no certificate");
    assert_eq!(refused.codes(), vec![ErrorCode::CertificateChainEmpty]);

    // An empty file lands in the same place.
    let refused = inspect(b"", &server.key_pem(), None, now()).expect_err("it is empty");
    assert_eq!(refused.codes(), vec![ErrorCode::CertificateChainEmpty]);

    // A file whose PEM body has been cut in half. It opens as PEM and does
    // not read as a certificate, which is a different fault and a different
    // code, because a truncated upload is not a wrong file.
    let mut damaged = server.chain_pem();
    let middle = damaged.len() / 2;
    damaged.drain(middle..middle + 40);
    let refused = inspect(&damaged, &server.key_pem(), None, now()).expect_err("it is damaged");
    assert_eq!(refused.codes(), vec![ErrorCode::CertificateChainUnreadable]);

    // The other side: the same file undamaged goes in, so the rule is about
    // the damage and not about the shape of the file.
    assert!(inspect(&server.chain_pem(), &server.key_pem(), None, now()).is_ok());
}

#[test]
fn a_broken_key_is_refused() {
    let (_, server) = signed();

    let refused = inspect(&server.chain_pem(), b"not a key", None, now())
        .expect_err("the key is not readable");

    assert_eq!(refused.codes(), vec![ErrorCode::CertificateKeyUnreadable]);
    assert_eq!(refused.as_slice()[0].path.as_text(), "private_key");
}

#[test]
fn a_chain_that_stops_short_of_a_root_is_taken_with_a_warning() {
    let ca = authority("ek-ek test CA");
    let middle = intermediate("ek-ek test issuing CA", &ca);
    let server = leaf("www.example.org", &["www.example.org"], &middle, 0, 90);

    // Leaf and intermediate, with the root left out. This is the shape of the
    // mistake: the file looks complete and every client that does not already
    // hold the root refuses the handshake.
    let short = joined(&[&server.certificate, &middle.certificate]);
    let upload = inspect(&short, &server.key_pem(), None, now()).expect("it is still installable");

    assert_eq!(
        upload
            .warnings
            .iter()
            .map(|warning| warning.code)
            .collect::<Vec<WarningCode>>(),
        vec![WarningCode::CertificateChainIncomplete]
    );
    // The warning names the issuer that is missing, which is what an operator
    // has to go and find.
    assert_eq!(
        upload.warnings[0].parameters.get("issuer"),
        Some(&ek_ek_config::ParameterValue::Identifier(text_of(
            middle.certificate.issuer_name()
        )))
    );

    // The other side: the whole chain produces no warning at all.
    let whole = joined(&[&server.certificate, &middle.certificate, &ca.certificate]);
    let upload = inspect(&whole, &server.key_pem(), None, now()).expect("it is good");
    assert!(upload.warnings.is_empty(), "{:?}", upload.warnings);
}

#[test]
fn a_chain_whose_links_do_not_meet_is_reported_rather_than_taken_quietly() {
    let ca = authority("ek-ek test CA");
    let other = authority("somebody else's CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);

    // The second certificate did not issue the first. A file like this comes
    // from copying the wrong intermediate, and it fails the same way a short
    // chain does.
    let wrong = joined(&[&server.certificate, &other.certificate]);
    let upload = inspect(&wrong, &server.key_pem(), None, now()).expect("it is still installable");

    assert_eq!(
        upload.warnings.first().map(|warning| warning.code),
        Some(WarningCode::CertificateChainIncomplete)
    );
}

#[test]
fn a_self_signed_certificate_alone_is_a_complete_chain() {
    // The other side of the chain rule. A self-signed certificate is the
    // whole chain, so warning about it would train an operator to ignore the
    // warning that matters.
    let ca = authority("ek-ek test CA");

    let upload = inspect(&ca.chain_pem(), &ca.key_pem(), None, now()).expect("it is readable");

    assert!(upload.warnings.is_empty(), "{:?}", upload.warnings);
}

#[test]
fn every_name_the_certificate_carries_is_read() {
    let ca = authority("ek-ek test CA");
    let server = leaf(
        "www.example.org",
        &[
            "www.example.org",
            "api.example.org",
            "*.internal.example.org",
        ],
        &ca,
        0,
        90,
    );

    let upload = inspect(&server.chain_pem(), &server.key_pem(), None, now()).expect("it is good");

    assert_eq!(
        upload.sni_names,
        vec![
            "www.example.org".to_owned(),
            "api.example.org".to_owned(),
            "*.internal.example.org".to_owned(),
        ],
        "the common name comes first and is not repeated"
    );

    // The other side: a certificate with no subject alternative name still
    // gives up its common name, because certificates from a company's own CA
    // often carry nothing else.
    let old = leaf("legacy.example.org", &[], &ca, 0, 90);
    let upload = inspect(&old.chain_pem(), &old.key_pem(), None, now()).expect("it is good");
    assert_eq!(upload.sni_names, vec!["legacy.example.org".to_owned()]);
}

#[test]
fn an_expired_certificate_goes_in_with_a_warning() {
    let ca = authority("ek-ek test CA");
    // Valid from a year ago until last week.
    let old = leaf("old.example.org", &["old.example.org"], &ca, -365, -7);
    // With its issuer, so the only thing wrong with it is the date.
    let chain = joined(&[&old.certificate, &ca.certificate]);

    let upload = inspect(&chain, &old.key_pem(), None, now()).expect("it is installable");

    assert_eq!(
        upload
            .warnings
            .iter()
            .map(|warning| warning.code)
            .collect::<Vec<WarningCode>>(),
        vec![WarningCode::CertificateExpired]
    );
    assert!(upload.validity.not_after_unix < now());

    // The other side: a certificate that is still valid produces no such
    // warning, so the warning means something when it appears.
    let (_, server) = signed();
    let upload = inspect(&server.chain_pem(), &server.key_pem(), None, now()).expect("it is good");
    assert!(
        !upload
            .warnings
            .iter()
            .any(|warning| warning.code == WarningCode::CertificateExpired)
    );
}

#[test]
fn an_encrypted_key_asks_for_its_passphrase() {
    let (_, server) = signed();
    let locked = server.key_pem_encrypted("correct horse");

    // With none given, the answer says which one of the two things to do.
    let refused =
        inspect(&server.chain_pem(), &locked, None, now()).expect_err("it needs a passphrase");
    assert_eq!(
        refused.codes(),
        vec![ErrorCode::CertificateKeyPassphraseRequired]
    );
    assert_eq!(refused.as_slice()[0].path.as_text(), "passphrase");

    // With the wrong one, a different answer, because the operator has to do
    // something different about it.
    let refused = inspect(&server.chain_pem(), &locked, Some("wrong horse"), now())
        .expect_err("the passphrase does not open it");
    assert_eq!(
        refused.codes(),
        vec![ErrorCode::CertificateKeyPassphraseWrong]
    );

    // And with the right one it goes in, stored with no passphrase at all.
    let upload = inspect(&server.chain_pem(), &locked, Some("correct horse"), now())
        .expect("the passphrase opens it");
    let stored = String::from_utf8_lossy(upload.key.expose()).into_owned();
    assert!(stored.contains("BEGIN PRIVATE KEY"), "{stored:?}");
    assert!(!stored.contains("ENCRYPTED"), "the passphrase is not kept");
}

#[test]
fn a_passphrase_for_a_key_that_needs_none_is_not_an_error() {
    // An operator who types their passphrase for the wrong file should get
    // their certificate installed rather than a lecture.
    let (_, server) = signed();

    let upload = inspect(
        &server.chain_pem(),
        &server.key_pem(),
        Some("not needed"),
        now(),
    )
    .expect("the key opens without it");

    assert_eq!(upload.sni_names, vec!["www.example.org".to_owned()]);
}

#[test]
fn an_empty_passphrase_counts_as_none() {
    // An interface that always sends the field would otherwise turn "no
    // passphrase" into "the passphrase is the empty string".
    let (_, server) = signed();
    let locked = server.key_pem_encrypted("correct horse");

    let refused = inspect(&server.chain_pem(), &locked, Some(""), now())
        .expect_err("it still needs a passphrase");

    assert_eq!(
        refused.codes(),
        vec![ErrorCode::CertificateKeyPassphraseRequired]
    );
}

#[test]
fn a_file_holding_more_certificates_than_a_chain_ever_does_is_refused() {
    let ca = authority("ek-ek test CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);

    let mut many: Vec<&openssl::x509::X509> = vec![&server.certificate];
    let filler: Vec<common::Pair> = (0..ek_ek_tls::MOST_CERTIFICATES)
        .map(|at| authority(&format!("filler {at}")))
        .collect();
    many.extend(filler.iter().map(|pair| &pair.certificate));

    let refused =
        inspect(&joined(&many), &server.key_pem(), None, now()).expect_err("that is not a chain");

    assert_eq!(refused.codes(), vec![ErrorCode::CertificateChainTooLong]);

    // The other side: a file at the limit is taken.
    let at_limit: Vec<&openssl::x509::X509> = many
        .into_iter()
        .take(ek_ek_tls::MOST_CERTIFICATES)
        .collect();
    assert!(inspect(&joined(&at_limit), &server.key_pem(), None, now()).is_ok());
}

#[test]
fn no_error_carries_the_material_it_was_given() {
    // Every message ends up in a log eventually (ADR-0018).
    let (_, server) = signed();
    let key = server.key_pem();
    let refused = inspect(b"not a certificate", &key, None, now()).expect_err("it is not readable");

    let written = format!("{refused:?}");
    assert!(!written.contains("PRIVATE KEY"), "{written}");
    assert!(!written.contains("not a certificate"), "{written}");

    // And the upload itself keeps the key behind a redacting `Debug`.
    let upload = inspect(&server.chain_pem(), &key, None, now()).expect("it is good");
    let written = format!("{upload:?}");
    assert!(!written.contains("PRIVATE KEY"), "{written}");
    assert!(written.contains("redacted"), "{written}");
}

#[test]
fn the_certificate_identity_decides_where_the_material_is_filed() {
    let id = CertificateId::new("cert-web");

    assert_eq!(ek_ek_tls::chain_id(&id).as_str(), "cert-web.chain");
    assert_eq!(ek_ek_tls::key_id(&id).as_str(), "cert-web.key");
    assert_ne!(ek_ek_tls::chain_id(&id), ek_ek_tls::key_id(&id));
}
