// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! What an operator is told about a certificate that is running out.
//!
//! Both warnings come through the one channel the API and the interface read
//! (ADR-0072), so what is measured here is what those two will show.

mod common;

use ek_ek_config::{Config, ParameterValue, ValidationWarning, WarningCode, inspect, validate};

/// A day, in seconds.
const DAY: i64 = 86_400;

/// The moment the sample's certificate stops being usable.
const NOT_AFTER: i64 = 1_775_001_600;

/// Only the warnings of one code.
fn only(config: &Config, now_unix: i64, code: WarningCode) -> Vec<ValidationWarning> {
    inspect(config, now_unix)
        .into_iter()
        .filter(|warning| warning.code == code)
        .collect()
}

#[test]
fn a_document_that_names_no_threshold_gets_thirty_days() {
    // An older document must keep being readable, and the value it then gets
    // is the one the product ships (ADR-0019).
    let document = serde_json::to_value(common::sample()).expect("it serialises");
    let mut object = document.as_object().expect("an object").clone();
    object.remove("certificate_expiry_warning_days");

    let read: Config =
        serde_json::from_value(serde_json::Value::Object(object)).expect("an older document reads");

    assert_eq!(read.certificate_expiry_warning_days, 30);
}

#[test]
fn a_certificate_inside_the_window_is_reported() {
    let config = common::sample();

    // Exactly on the threshold, which is where the rule either holds or is off
    // by a day.
    let found = only(
        &config,
        NOT_AFTER - 30 * DAY,
        WarningCode::CertificateExpiringSoon,
    );

    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].parameters.get("certificate"),
        Some(&ParameterValue::Identifier("cert-web".to_owned()))
    );
    assert_eq!(
        found[0].parameters.get("not_after_unix"),
        Some(&ParameterValue::Number(NOT_AFTER))
    );
    assert_eq!(
        found[0].parameters.get("remaining_seconds"),
        Some(&ParameterValue::Number(30 * DAY))
    );
}

#[test]
fn a_certificate_outside_the_window_is_not_reported() {
    // The other side. A warning on every certificate says nothing about the
    // one that needs attention.
    let config = common::sample();

    assert!(
        only(
            &config,
            NOT_AFTER - 31 * DAY,
            WarningCode::CertificateExpiringSoon
        )
        .is_empty()
    );
}

#[test]
fn the_threshold_is_what_decides_when_the_warning_starts() {
    let mut config = common::sample();
    let at = NOT_AFTER - 45 * DAY;

    assert!(
        only(&config, at, WarningCode::CertificateExpiringSoon).is_empty(),
        "forty five days out is outside the default window"
    );

    config.certificate_expiry_warning_days = 60;
    assert_eq!(
        only(&config, at, WarningCode::CertificateExpiringSoon).len(),
        1,
        "an operator who asked for sixty days has to be told at forty five"
    );
}

#[test]
fn a_threshold_of_zero_warns_only_once_the_certificate_has_gone() {
    let mut config = common::sample();
    config.certificate_expiry_warning_days = 0;

    assert!(
        only(&config, NOT_AFTER - 1, WarningCode::CertificateExpiringSoon).is_empty(),
        "zero means no early warning, which is a choice an operator may make"
    );
    assert_eq!(
        only(&config, NOT_AFTER, WarningCode::CertificateExpiringSoon).len(),
        1,
        "the moment it goes is still worth saying, whatever the threshold is"
    );
}

#[test]
fn a_certificate_that_was_never_obtained_is_not_reported() {
    // It has no window, so it cannot be close to the end of one. An ACME
    // certificate an operator has just written down looks exactly like this.
    let mut config = common::sample();
    config.certificates[0].validity = None;

    assert!(only(&config, NOT_AFTER, WarningCode::CertificateExpiringSoon).is_empty());
}

#[test]
fn a_frontend_offering_an_expired_certificate_is_named() {
    let config = common::sample();

    let found = only(
        &config,
        NOT_AFTER + DAY,
        WarningCode::FrontendCertificateExpired,
    );

    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].parameters.get("frontend"),
        Some(&ParameterValue::Identifier("web-https".to_owned())),
        "the frontend is what stops serving, so it is what the warning names"
    );
    assert_eq!(
        found[0].parameters.get("certificate"),
        Some(&ParameterValue::Identifier("cert-web".to_owned()))
    );
    assert!(
        found[0].path.as_text().starts_with("frontends["),
        "the path has to point at the listener: {}",
        found[0].path.as_text()
    );
}

#[test]
fn a_frontend_offering_a_certificate_that_is_still_good_is_not_named() {
    // The other side, and the one that keeps the warning meaningful.
    let config = common::sample();

    assert!(
        only(
            &config,
            NOT_AFTER - 1,
            WarningCode::FrontendCertificateExpired
        )
        .is_empty()
    );
}

#[test]
fn a_certificate_nobody_offers_does_not_name_a_frontend() {
    // An expired certificate that no listener offers costs an operator
    // nothing. Only the one a handshake can pick is a fault.
    let mut config = common::sample();
    for frontend in &mut config.frontends {
        frontend.tls = None;
    }

    assert!(
        only(
            &config,
            NOT_AFTER + DAY,
            WarningCode::FrontendCertificateExpired
        )
        .is_empty()
    );
    assert_eq!(
        only(
            &config,
            NOT_AFTER + DAY,
            WarningCode::CertificateExpiringSoon
        )
        .len(),
        1,
        "the certificate itself is still worth a word"
    );
}

#[test]
fn neither_warning_refuses_the_document() {
    // A warning never stops a configuration from being stored (ADR-0072). An
    // operator installing the replacement before switching to it has to be
    // able to save the document that says so.
    let config = common::sample();

    assert!(
        !inspect(&config, NOT_AFTER + DAY).is_empty(),
        "the setup produces a warning, or the check below measures nothing"
    );
    assert!(validate(&config).is_ok());
}
