// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! When a certificate is due, and what a failed order costs the next one.
//!
//! Every reading here is taken against a moment that is passed in. A rule
//! about a window thirty days wide is measured in microseconds, and the same
//! measurement covers a clock that somebody moved forward.

use std::time::Duration;

use ek_ek_config::{
    Certificate, CertificateId, CertificateSource, CertificateValidity, DnsProviderId, SecretId,
};
use ek_ek_tls::renewal::{
    ALARM_AFTER, Attempts, Because, FIRST_BACKOFF, GROWING_WAITS, LONGEST_BACKOFF, backoff, due,
    remaining, renewable, why,
};

/// A day, in seconds.
const DAY: i64 = 86_400;

/// The moment every window below is measured against.
const NOW: i64 = 1_800_000_000;

/// A certificate issued at `NOW` for `days`, from the source given.
fn certificate(id: &str, source: CertificateSource, days: i64) -> Certificate {
    Certificate {
        id: CertificateId::new(id),
        sni_names: vec!["lab.ek-ek.test".to_owned()],
        source,
        validity: Some(CertificateValidity {
            not_before_unix: NOW,
            not_after_unix: NOW + days * DAY,
        }),
        chain: Some(SecretId::new(format!("{id}.chain"))),
        private_key: Some(SecretId::new(format!("{id}.key"))),
    }
}

/// A certificate that has been configured and never obtained.
fn unobtained(id: &str, source: CertificateSource) -> Certificate {
    Certificate {
        id: CertificateId::new(id),
        sni_names: vec!["lab.ek-ek.test".to_owned()],
        source,
        validity: None,
        chain: None,
        private_key: None,
    }
}

#[test]
fn a_certificate_with_more_than_a_third_of_its_life_left_is_not_due() {
    let held = certificate("web", CertificateSource::AcmeHttp01, 90);

    // Sixty days in, thirty days left, which is exactly the third. The day
    // before it is not due.
    assert_eq!(why(&held, NOW + 59 * DAY), None);
}

#[test]
fn a_certificate_with_a_third_of_its_life_left_is_due() {
    let held = certificate("web", CertificateSource::AcmeHttp01, 90);

    assert_eq!(
        why(&held, NOW + 60 * DAY),
        Some(Because::RunningOut),
        "a 90 day certificate is renewed with 30 days left, which leaves room to fix a failure"
    );
}

#[test]
fn moving_the_clock_forward_is_what_makes_a_certificate_due() {
    // The same certificate, the same configuration, one thing different: the
    // moment it is decided against. This is the whole of the time dependent
    // behaviour, and it needs no clock to measure.
    let held = certificate("web", CertificateSource::AcmeHttp01, 90);

    assert_eq!(why(&held, NOW), None, "it was just issued");
    assert_eq!(
        why(&held, NOW + 61 * DAY),
        Some(Because::RunningOut),
        "the clock moved past two thirds of the window and nothing else changed"
    );
}

#[test]
fn a_certificate_that_has_already_expired_is_due() {
    let held = certificate(
        "web",
        CertificateSource::AcmeDns01 {
            provider: DnsProviderId::new("zone"),
        },
        90,
    );

    assert_eq!(why(&held, NOW + 200 * DAY), Some(Because::RunningOut));
    assert!(
        remaining(&held.validity.expect("it has a window"), NOW + 200 * DAY) < 0,
        "what is left has to read as negative, or an expired certificate looks like a fresh one"
    );
}

#[test]
fn a_certificate_that_was_never_obtained_is_due_at_once() {
    let held = unobtained("web", CertificateSource::AcmeHttp01);

    assert_eq!(
        why(&held, NOW),
        Some(Because::NeverObtained),
        "there is no material to serve, so there is nothing to wait for"
    );
}

#[test]
fn an_uploaded_certificate_is_never_renewed_however_little_is_left() {
    // The other side of the rule that matters most: this product cannot ask
    // anybody for this certificate again (ADR-0026).
    let held = certificate("bought", CertificateSource::ManualUpload, 90);

    assert!(!renewable(&held));
    assert_eq!(why(&held, NOW + 89 * DAY), None);
    assert_eq!(
        why(&unobtained("bought", CertificateSource::ManualUpload), NOW),
        None,
        "an uploaded certificate with no material is one nobody has uploaded yet"
    );
}

#[test]
fn both_acme_challenge_kinds_are_renewed() {
    let http = certificate("http", CertificateSource::AcmeHttp01, 90);
    let dns = certificate(
        "dns",
        CertificateSource::AcmeDns01 {
            provider: DnsProviderId::new("zone"),
        },
        90,
    );

    assert!(renewable(&http));
    assert!(renewable(&dns));
}

#[test]
fn a_window_that_is_not_a_window_is_due() {
    // A record whose end is before its start. Treated as due, because the safe
    // direction is to obtain something that can actually be served.
    let mut held = certificate("broken", CertificateSource::AcmeHttp01, 90);
    held.validity = Some(CertificateValidity {
        not_before_unix: NOW + DAY,
        not_after_unix: NOW,
    });

    assert_eq!(why(&held, NOW), Some(Because::RunningOut));
}

#[test]
fn the_sweep_returns_what_is_due_and_leaves_the_rest() {
    let certificates = vec![
        certificate("fresh", CertificateSource::AcmeHttp01, 90),
        certificate("running-out", CertificateSource::AcmeHttp01, 90),
        certificate("bought", CertificateSource::ManualUpload, 1),
        unobtained("new", CertificateSource::AcmeHttp01),
    ];

    // Sixty days on: "fresh" was issued at NOW and so has thirty left, which
    // is the third exactly. Both ACME ones are due; the upload is not.
    let found = due(&certificates, NOW + 60 * DAY);

    let named: Vec<&str> = found
        .iter()
        .map(|one| one.certificate.id.as_str())
        .collect();
    assert_eq!(named, vec!["fresh", "running-out", "new"]);
    assert_eq!(found[2].because, Because::NeverObtained);
}

#[test]
fn the_sweep_returns_nothing_when_nothing_is_due() {
    // The other side. A sweep that always returns something would order every
    // certificate on every run and spend the whole allowance.
    let certificates = vec![
        certificate("one", CertificateSource::AcmeHttp01, 90),
        certificate("two", CertificateSource::ManualUpload, 90),
    ];

    assert!(due(&certificates, NOW).is_empty());
}

#[test]
fn the_wait_after_a_failure_doubles_from_an_hour() {
    assert_eq!(backoff(0), Duration::ZERO, "nothing has failed yet");
    assert_eq!(backoff(1), FIRST_BACKOFF);
    assert_eq!(backoff(2), FIRST_BACKOFF * 2);
    assert_eq!(backoff(3), FIRST_BACKOFF * 4);
    // Written as a number rather than as `GROWING_WAITS`, because a reading
    // taken through the constant follows the constant and says nothing about
    // where the doubling actually stops.
    assert_eq!(backoff(4), FIRST_BACKOFF * 8);
    assert_eq!(
        GROWING_WAITS, 4,
        "four waits double, and the sequence above is what that means"
    );
}

#[test]
fn the_wait_stops_growing_at_a_day() {
    // Without a ceiling the wait would pass the renewal window itself and the
    // certificate would run out while the product was still waiting.
    assert_eq!(backoff(5), LONGEST_BACKOFF);
    assert_eq!(backoff(50), LONGEST_BACKOFF);
    assert_eq!(
        backoff(u32::MAX),
        LONGEST_BACKOFF,
        "a count nobody expects must not overflow the shift"
    );
}

#[test]
fn a_failure_records_when_it_started_and_when_to_try_again() {
    let mut held = Attempts::default();

    held.failed("acme.network", NOW);
    assert_eq!(held.failures, 1);
    assert_eq!(held.first_failed_unix, NOW);
    assert_eq!(held.last_reason, "acme.network");
    assert_eq!(held.next_attempt_unix, NOW + 3_600);

    held.failed("acme.server", NOW + 3_600);
    assert_eq!(held.failures, 2);
    assert_eq!(
        held.first_failed_unix, NOW,
        "when the trouble started does not move with every new failure"
    );
    assert_eq!(held.next_attempt_unix, NOW + 3_600 + 7_200);
}

#[test]
fn another_order_waits_until_the_backoff_is_over() {
    let mut held = Attempts::default();
    held.failed("acme.network", NOW);

    assert!(
        !held.ready(NOW),
        "an order right after a failure spends the server's allowance on the same fault"
    );
    assert!(!held.ready(NOW + 3_599));
    assert!(held.ready(NOW + 3_600));
}

#[test]
fn a_certificate_that_has_never_failed_is_ready_now() {
    // The other side of the wait: a fresh record must not hold an order back.
    let held = Attempts::default();

    assert!(held.ready(NOW));
    assert!(!held.alarming());
}

#[test]
fn the_alarm_starts_at_the_third_failure_in_a_row() {
    let mut held = Attempts::default();
    let mut at = NOW;

    for round in 1..ALARM_AFTER {
        held.failed("acme.configuration", at);
        assert!(
            !held.alarming(),
            "failure {round} of {ALARM_AFTER} is not yet worth waking anybody"
        );
        at = held.next_attempt_unix;
    }

    held.failed("acme.configuration", at);
    assert!(held.alarming());
    assert_eq!(held.failures, ALARM_AFTER);
    assert!(
        at - NOW >= 3 * 3_600,
        "three failures have to span hours, or a passing network fault raises an alarm"
    );
}

#[test]
fn the_state_survives_being_written_and_read_back() {
    // It is kept in a file between runs, so "failing repeatedly" is only
    // countable if it comes back the way it went in.
    let mut held = Attempts::default();
    held.failed("acme.too_many_attempts", NOW);

    let written = serde_json::to_string(&held).expect("it serialises");
    let read: Attempts = serde_json::from_str(&written).expect("it reads back");

    assert_eq!(read, held);
    assert!(
        written.contains("acme.too_many_attempts"),
        "the reason is what an operator reads first: {written}"
    );
}
