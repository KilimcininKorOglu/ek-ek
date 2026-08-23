// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! What a document says about a frontend's TLS policy, and what an operator
//! is told about it.
//!
//! The relaxed level is a deliberate concession (ADR-0028). What it must never
//! be is quiet, so the warning is measured as carefully as the refusals are.

mod common;

use ek_ek_config::{
    ApplicationProtocol, Config, ParameterValue, TlsPolicyLevel, TlsSettings, ValidationWarning,
    WarningCode, inspect, validate,
};

/// The moment these documents are inspected against.
///
/// The sample's certificate is still valid here, so nothing an expiry warning
/// would add lands in the way of what is measured.
const NOW: i64 = 1_760_000_000;

/// Only the warnings of one code.
fn only(config: &Config, code: WarningCode) -> Vec<ValidationWarning> {
    inspect(config, NOW)
        .into_iter()
        .filter(|warning| warning.code == code)
        .collect()
}

/// The TLS settings of the sample's first frontend.
fn tls_of(config: &mut Config) -> &mut TlsSettings {
    config.frontends[0]
        .tls
        .as_mut()
        .expect("the fixture terminates TLS on its first frontend")
}

#[test]
fn a_document_that_names_no_level_gets_the_balanced_one() {
    // ADR-0028 makes this the default and says nobody is asked at install
    // time, so an older document has to land here rather than fail to read
    // (ADR-0019).
    assert_eq!(TlsPolicyLevel::default(), TlsPolicyLevel::Balanced);

    let document = serde_json::to_value(common::sample()).expect("it serialises");
    let mut object = document.as_object().expect("an object").clone();
    let frontends = object
        .get_mut("frontends")
        .and_then(serde_json::Value::as_array_mut)
        .expect("the fixture has frontends");
    let tls = frontends[0]
        .get_mut("tls")
        .and_then(serde_json::Value::as_object_mut)
        .expect("the first frontend terminates TLS");
    assert!(
        tls.remove("policy").is_some(),
        "the field has to be there before its absence can be measured"
    );

    let read: Config = serde_json::from_value(serde_json::Value::Object(object))
        .expect("a document without the field reads");

    assert_eq!(
        read.frontends[0]
            .tls
            .as_ref()
            .expect("it still terminates TLS")
            .policy,
        TlsPolicyLevel::Balanced
    );
}

#[test]
fn every_level_is_written_under_the_name_adr_0028_gave_it() {
    // The document, the metric label and the log line all use these three
    // words. A rename here is a rename everywhere.
    for (level, name) in [
        (TlsPolicyLevel::Modern, "\"modern\""),
        (TlsPolicyLevel::Balanced, "\"dengeli\""),
        (TlsPolicyLevel::LegacyCompatible, "\"eski-uyumlu\""),
    ] {
        let written = serde_json::to_string(&level).expect("a level serialises");
        assert_eq!(written, name);
        let read: TlsPolicyLevel = serde_json::from_str(name).expect("it reads back");
        assert_eq!(read, level);
    }
}

#[test]
fn the_relaxed_level_is_reported_and_names_the_frontend() {
    let mut config = common::sample();
    tls_of(&mut config).policy = TlsPolicyLevel::LegacyCompatible;

    let found = only(&config, WarningCode::FrontendLegacyTlsPolicy);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path.as_text(), "frontends[0].tls.policy");
    assert_eq!(
        found[0].parameters.get("frontend"),
        Some(&ParameterValue::Identifier("web-https".to_owned())),
        "the warning must name the frontend an operator has to open"
    );
}

#[test]
fn the_other_two_levels_are_not_reported() {
    // The other side of the rule. Without it the check would pass against
    // something that warns about every frontend.
    for level in [TlsPolicyLevel::Modern, TlsPolicyLevel::Balanced] {
        let mut config = common::sample();
        tls_of(&mut config).policy = level;

        assert!(
            only(&config, WarningCode::FrontendLegacyTlsPolicy).is_empty(),
            "{level:?} produced a warning"
        );
    }
}

#[test]
fn the_relaxed_level_is_a_warning_and_never_an_error() {
    // ADR-0028 left the level usable on purpose. An error would make the
    // document unsaveable and take the concession away.
    let mut config = common::sample();
    tls_of(&mut config).policy = TlsPolicyLevel::LegacyCompatible;

    assert!(
        validate(&config).is_ok(),
        "the document must still be saveable: {:?}",
        validate(&config).err().map(|errors| errors.codes())
    );
    assert_eq!(only(&config, WarningCode::FrontendLegacyTlsPolicy).len(), 1);
}

#[test]
fn each_relaxed_frontend_gets_its_own_warning() {
    // Two frontends may be at that level for entirely different reasons, and
    // one warning for the document would leave the second one invisible.
    let mut config = common::sample();
    tls_of(&mut config).policy = TlsPolicyLevel::LegacyCompatible;
    let mut second = config.frontends[0].clone();
    second.id = ek_ek_config::FrontendId::new("web-https-two");
    second.port = 8443;
    config.frontends.push(second);

    let found = only(&config, WarningCode::FrontendLegacyTlsPolicy);

    assert_eq!(found.len(), 2);
    let named: Vec<Option<&ParameterValue>> = found
        .iter()
        .map(|warning| warning.parameters.get("frontend"))
        .collect();
    assert!(named.contains(&Some(&ParameterValue::Identifier("web-https".to_owned()))));
    assert!(named.contains(&Some(&ParameterValue::Identifier(
        "web-https-two".to_owned()
    ))));
}

#[test]
fn a_frontend_that_terminates_no_tls_is_never_reported() {
    // A frontend with no TLS settings carries the default level in the type
    // system and no policy at all in reality. Reporting it would send an
    // operator looking for a setting that is not there.
    let config = common::sample();
    let plain: Vec<&ek_ek_config::Frontend> = config
        .frontends
        .iter()
        .filter(|frontend| frontend.tls.is_none())
        .collect();
    assert!(
        !plain.is_empty(),
        "the fixture must hold a frontend without TLS for this to measure anything"
    );
    assert!(
        plain
            .iter()
            .any(|frontend| frontend.application != ApplicationProtocol::Http),
        "and one of them speaks something other than HTTP"
    );

    assert!(only(&config, WarningCode::FrontendLegacyTlsPolicy).is_empty());
}
