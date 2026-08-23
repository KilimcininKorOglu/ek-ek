// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! What a monitoring system reads about the certificates.
//!
//! The exposition is text a machine parses, so what is measured is the text:
//! the header lines Prometheus needs, the label set, and what happens to an
//! identity that would otherwise end a line early.

use ek_ek_config::{
    Certificate, CertificateId, CertificateSource, CertificateValidity, DnsProviderId, SecretId,
};
use ek_ek_tls::metrics::{EXPIRY_METRIC, OBTAINED_METRIC, exposition};

/// A day, in seconds.
const DAY: i64 = 86_400;

/// The moment the readings are taken at.
const NOW: i64 = 1_800_000_000;

/// A certificate that ends `days` from `NOW`.
fn certificate(id: &str, source: CertificateSource, days: i64) -> Certificate {
    Certificate {
        id: CertificateId::new(id),
        sni_names: vec!["lab.ek-ek.test".to_owned()],
        source,
        validity: Some(CertificateValidity {
            not_before_unix: NOW - DAY,
            not_after_unix: NOW + days * DAY,
        }),
        chain: Some(SecretId::new(format!("{id}.chain"))),
        private_key: Some(SecretId::new(format!("{id}.key"))),
    }
}

#[test]
fn the_seconds_left_are_published_for_every_certificate() {
    let text = exposition(
        &[
            certificate("web", CertificateSource::AcmeHttp01, 30),
            certificate("mail", CertificateSource::ManualUpload, 7),
        ],
        NOW,
    );

    assert!(
        text.contains(&format!(
            "{EXPIRY_METRIC}{{certificate=\"web\",source=\"acme_http01\"}} {}\n",
            30 * DAY
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "{EXPIRY_METRIC}{{certificate=\"mail\",source=\"manual_upload\"}} {}\n",
            7 * DAY
        )),
        "{text}"
    );
}

#[test]
fn the_reading_follows_the_moment_it_is_taken_at() {
    let held = [certificate("web", CertificateSource::AcmeHttp01, 30)];

    let early = exposition(&held, NOW);
    let late = exposition(&held, NOW + 29 * DAY);

    assert!(early.contains(&format!(" {}\n", 30 * DAY)), "{early}");
    assert!(late.contains(&format!(" {DAY}\n")), "{late}");
}

#[test]
fn an_expired_certificate_reads_as_a_negative_number() {
    // Zero would be indistinguishable from a certificate that ends this
    // second, and a monitoring rule written against it would never fire.
    let text = exposition(
        &[certificate("web", CertificateSource::AcmeHttp01, -3)],
        NOW,
    );

    assert!(text.contains(&format!(" -{}\n", 3 * DAY)), "{text}");
}

#[test]
fn the_dns_challenge_is_named_as_its_own_source() {
    let text = exposition(
        &[certificate(
            "wild",
            CertificateSource::AcmeDns01 {
                provider: DnsProviderId::new("zone"),
            },
            30,
        )],
        NOW,
    );

    assert!(text.contains("source=\"acme_dns01\""), "{text}");
    assert!(
        !text.contains("zone"),
        "the provider is a second identity in the cardinality and the record already carries it: {text}"
    );
}

#[test]
fn a_certificate_that_was_never_obtained_says_so_instead_of_a_number() {
    let mut held = certificate("web", CertificateSource::AcmeHttp01, 30);
    held.validity = None;

    let text = exposition(&[held], NOW);

    assert!(
        !text.contains(&format!("{EXPIRY_METRIC}{{")),
        "there is no number to report, and inventing one is worse than none: {text}"
    );
    assert!(
        text.contains(&format!(
            "{OBTAINED_METRIC}{{certificate=\"web\",source=\"acme_http01\"}} 0\n"
        )),
        "its absence has to be visible rather than silent: {text}"
    );
}

#[test]
fn a_certificate_that_was_obtained_says_so_too() {
    // The other side. A metric that is always zero says nothing about the
    // installation it describes.
    let text = exposition(
        &[certificate("web", CertificateSource::AcmeHttp01, 30)],
        NOW,
    );

    assert!(
        text.contains(&format!(
            "{OBTAINED_METRIC}{{certificate=\"web\",source=\"acme_http01\"}} 1\n"
        )),
        "{text}"
    );
}

#[test]
fn every_metric_carries_the_two_lines_prometheus_reads_first() {
    let text = exposition(
        &[certificate("web", CertificateSource::AcmeHttp01, 30)],
        NOW,
    );

    for metric in [EXPIRY_METRIC, OBTAINED_METRIC] {
        assert!(text.contains(&format!("# HELP {metric} ")), "{text}");
        assert!(text.contains(&format!("# TYPE {metric} gauge\n")), "{text}");
    }
}

#[test]
fn an_identity_that_could_end_a_line_early_is_escaped() {
    // An identity is written by an operator. One holding a quote would close
    // the label set and make every line after it unreadable.
    let text = exposition(
        &[certificate("we\"b\\one", CertificateSource::AcmeHttp01, 30)],
        NOW,
    );

    assert!(text.contains(r#"certificate="we\"b\\one""#), "{text}");
    for line in text.lines() {
        assert!(
            !line.is_empty(),
            "an escaped identity must not break the document into empty lines"
        );
    }
}

#[test]
fn an_installation_with_no_certificates_still_writes_a_valid_document() {
    let text = exposition(&[], NOW);

    assert!(text.contains(&format!("# TYPE {EXPIRY_METRIC} gauge\n")));
    assert!(
        text.ends_with('\n'),
        "several blocks are concatenated into one document: {text:?}"
    );
    assert!(
        !text.contains(&format!("{EXPIRY_METRIC}{{")),
        "no certificate, no reading: {text}"
    );
}
