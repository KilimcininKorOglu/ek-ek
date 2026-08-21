// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the validation layer must catch, and what it must let through.
//!
//! Every rule is measured twice. One example violates it and one does not,
//! because a check that only ever sees broken input cannot show that it
//! judges anything.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::sample;
use ek_ek_config::{
    ApplicationProtocol, BackendId, CertificateId, ErrorCode, ParameterValue, SameSitePolicy,
    SessionStickiness, TransportProtocol, ValidationErrors, VipId, validate, validate_vip_removal,
};

/// Runs validation and requires it to fail, returning what it found.
fn faults(config: &ek_ek_config::Config) -> ValidationErrors {
    validate(config).expect_err("this config was broken on purpose")
}

#[test]
fn a_valid_config_produces_no_error() {
    let config = sample();

    let outcome = validate(&config);

    assert!(
        outcome.is_ok(),
        "the fixture must pass, otherwise every other test measures the wrong fault: {:?}",
        outcome.err().map(|errors| errors.codes())
    );
}

#[test]
fn a_second_frontend_on_the_same_vip_port_and_transport_is_refused() {
    let mut config = sample();
    let mut clash = config.frontends[0].clone();
    clash.id = ek_ek_config::FrontendId::new("web-https-copy");
    config.frontends.push(clash);

    let found = faults(&config);

    assert_eq!(found.codes(), vec![ErrorCode::FrontendDuplicateBinding]);
    let error = &found.as_slice()[0];
    assert_eq!(
        error.parameters.get("conflicting_frontend"),
        Some(&ParameterValue::Identifier("web-https".to_owned())),
        "the error must name the frontend that already holds the binding"
    );
    assert_eq!(
        error.parameters.get("port"),
        Some(&ParameterValue::Number(443))
    );
}

#[test]
fn a_tcp_and_a_udp_frontend_may_share_a_vip_and_port() {
    let config = sample();

    let sharing: Vec<&ek_ek_config::Frontend> = config
        .frontends
        .iter()
        .filter(|frontend| frontend.port == 53)
        .collect();
    assert_eq!(sharing.len(), 2, "the DNS pair must be in the fixture");
    assert_eq!(sharing[0].vip, sharing[1].vip);
    assert_ne!(sharing[0].transport, sharing[1].transport);

    assert!(
        validate(&config).is_ok(),
        "the pair is legal, because the transports differ"
    );
}

#[test]
fn a_frontend_pointing_at_an_unknown_vip_is_refused() {
    let mut config = sample();
    config.frontends[0].vip = VipId::new("vip-missing");

    let found = faults(&config);

    assert_eq!(found.codes(), vec![ErrorCode::FrontendUnknownVip]);
    assert_eq!(found.as_slice()[0].path.as_text(), "frontends[0].vip");
    assert_eq!(
        found.as_slice()[0].parameters.get("vip"),
        Some(&ParameterValue::Identifier("vip-missing".to_owned()))
    );
}

#[test]
fn a_frontend_pointing_at_an_unknown_backend_is_refused() {
    let mut config = sample();
    config.frontends[0].default_backend = Some(BackendId::new("backend-missing"));

    let found = faults(&config);

    assert_eq!(found.codes(), vec![ErrorCode::FrontendUnknownBackend]);
    assert_eq!(
        found.as_slice()[0].path.as_text(),
        "frontends[0].default_backend"
    );

    // A rule inside the frontend is checked too, and blamed on its own path.
    let mut config = sample();
    config.frontends[0].routing_rules[1].backend = BackendId::new("backend-missing");
    let found = faults(&config);
    assert_eq!(
        found.as_slice()[0].path.as_text(),
        "frontends[0].routing_rules[1].backend"
    );
}

#[test]
fn removing_a_vip_a_frontend_uses_is_refused() {
    let config = sample();

    let refused = validate_vip_removal(&config, &VipId::new("vip-web"))
        .expect_err("four frontends still sit on this VIP");
    assert_eq!(refused.codes(), vec![ErrorCode::VipInUse]);
    assert_eq!(
        refused.as_slice()[0].parameters.get("frontend_count"),
        Some(&ParameterValue::Number(4))
    );

    // The same call on a VIP nobody uses must succeed, otherwise the check
    // would simply refuse every removal.
    assert!(
        validate_vip_removal(&config, &VipId::new("vip-unused")).is_ok(),
        "an unused VIP must be removable"
    );
}

#[test]
fn a_backend_with_no_members_is_refused() {
    let mut config = sample();
    config.backends[1].members.clear();

    let found = faults(&config);

    assert_eq!(found.codes(), vec![ErrorCode::BackendNoMembers]);
    assert_eq!(found.as_slice()[0].path.as_text(), "backends[1].members");
}

#[test]
fn a_port_outside_the_valid_range_is_refused() {
    let mut config = sample();
    config.frontends[0].port = 0;

    let found = faults(&config);
    assert_eq!(found.codes(), vec![ErrorCode::PortOutOfRange]);
    assert_eq!(found.as_slice()[0].path.as_text(), "frontends[0].port");

    // A member port is checked on the same rule.
    let mut config = sample();
    config.backends[0].members[1].port = 0;
    let found = faults(&config);
    assert_eq!(
        found.as_slice()[0].path.as_text(),
        "backends[0].members[1].port"
    );

    // Both ends of the range stay legal.
    let mut config = sample();
    config.frontends[0].port = 1;
    config.backends[0].members[0].port = 65535;
    assert!(validate(&config).is_ok(), "1 and 65535 are usable ports");
}

#[test]
fn tls_settings_on_a_frontend_that_does_not_speak_http_are_refused() {
    let mut config = sample();
    config.frontends[0].application = ApplicationProtocol::TlsPassthrough;

    let found = faults(&config);

    assert_eq!(found.codes(), vec![ErrorCode::FrontendTlsWithoutHttp]);
    assert_eq!(found.as_slice()[0].path.as_text(), "frontends[0].tls");

    // Dropping the settings rather than the protocol resolves it too.
    let mut config = sample();
    config.frontends[0].application = ApplicationProtocol::TlsPassthrough;
    config.frontends[0].tls = None;
    assert!(validate(&config).is_ok());
}

#[test]
fn cookie_stickiness_behind_a_udp_frontend_is_refused() {
    let mut config = sample();
    // The DNS pool sits behind both a TCP and a UDP frontend.
    config.backends[1].stickiness = SessionStickiness::SignedCookie {
        cookie_name: "ek-ek-affinity".to_owned(),
        same_site: SameSitePolicy::Lax,
    };

    let found = faults(&config);

    assert_eq!(found.codes(), vec![ErrorCode::BackendCookieStickinessOnUdp]);
    assert_eq!(found.as_slice()[0].path.as_text(), "backends[1].stickiness");
    assert_eq!(
        found.as_slice()[0].parameters.get("frontend"),
        Some(&ParameterValue::Identifier("dns-udp".to_owned())),
        "the error must name the UDP frontend that makes it illegal"
    );

    // The very same setting on a pool reached only over TCP is legal, which
    // is what the fixture already proves.
    assert!(matches!(
        sample().backends[0].stickiness,
        SessionStickiness::SignedCookie { .. }
    ));
    assert!(validate(&sample()).is_ok());
}

#[test]
fn a_health_check_timeout_above_its_interval_is_refused() {
    let mut config = sample();
    if let Some(check) = config.backends[0].health_check.as_mut() {
        check.timeout_ms = check.interval_ms + 1;
    }

    let found = faults(&config);
    assert_eq!(
        found.codes(),
        vec![ErrorCode::HealthCheckTimeoutAboveInterval]
    );
    assert_eq!(
        found.as_slice()[0].path.as_text(),
        "backends[0].health_check.timeout_ms"
    );

    // Equal values are still usable, so the rule must not reject them.
    let mut config = sample();
    if let Some(check) = config.backends[0].health_check.as_mut() {
        check.timeout_ms = check.interval_ms;
    }
    assert!(validate(&config).is_ok());
}

/// A value is a stable code when it reads as a dotted identifier.
fn is_code_key(value: &str) -> bool {
    !value.is_empty()
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character == '_')
        })
}

#[test]
fn every_error_carries_a_stable_code_and_no_prose() {
    // The check itself must be able to say no.
    assert!(is_code_key("config.frontend.unknown_vip"));
    assert!(!is_code_key("Frontend zaten tanımlı"), "prose must fail");
    assert!(!is_code_key("unknown_vip"), "a bare word is not a key");

    for code in ErrorCode::ALL {
        assert!(is_code_key(code.key()), "{} is not a key", code.key());

        let encoded = serde_json::to_value(code).expect("a code must serialise");
        assert_eq!(
            encoded.as_str(),
            Some(code.key()),
            "the wire value and the translation key must be the same string"
        );
    }

    // Nothing an error carries may be a sentence: parameter names are stable
    // identifiers and parameter values are ids or numbers.
    let found = faults(&broken_three_ways());
    let encoded = serde_json::to_value(&found).expect("errors must serialise");
    let text = encoded.to_string();
    for banned in ["message", "description", "detail", "title"] {
        assert!(
            !text.contains(banned),
            "an error must not carry a {banned} field"
        );
    }
    for error in found.as_slice() {
        for (name, value) in &error.parameters {
            assert!(
                name.chars().all(|character| character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || character == '_'),
                "{name} is not a stable parameter name"
            );
            match value {
                ParameterValue::Identifier(id) => assert!(
                    !id.contains(' '),
                    "{id} looks like prose rather than an identity"
                ),
                ParameterValue::Number(_) => {}
            }
        }
    }
}

#[test]
fn every_error_carries_the_path_of_the_field_it_blames() {
    let found = faults(&broken_three_ways());

    for error in found.as_slice() {
        assert!(
            !error.path.is_empty(),
            "{} arrived without a path",
            error.code.key()
        );
        assert!(
            !error.path.as_text().is_empty(),
            "{} rendered an empty path",
            error.code.key()
        );
    }

    // The emptiness check must be able to fire, or the loop above proves
    // nothing.
    assert!(ek_ek_config::FieldPath::root().is_empty());
    assert!(ek_ek_config::FieldPath::root().as_text().is_empty());
}

/// A config with three unrelated faults in it.
fn broken_three_ways() -> ek_ek_config::Config {
    let mut config = sample();
    config.frontends[0].vip = VipId::new("vip-missing");
    config.backends[1].members.clear();
    config.frontends[0]
        .tls
        .as_mut()
        .expect("the fixture terminates TLS here")
        .certificates
        .push(CertificateId::new("cert-missing"));
    config
}

#[test]
fn three_faults_produce_three_errors() {
    let found = faults(&broken_three_ways());

    assert_eq!(
        found.len(),
        3,
        "validation must not stop at the first fault: {:?}",
        found.codes()
    );
    assert!(found.contains(ErrorCode::FrontendUnknownVip));
    assert!(found.contains(ErrorCode::BackendNoMembers));
    assert!(found.contains(ErrorCode::FrontendUnknownCertificate));
}

#[test]
fn a_duplicate_identity_is_refused() {
    let mut config = sample();
    let twin = config.backends[0].clone();
    config.backends.push(twin);

    let found = faults(&config);

    assert!(found.contains(ErrorCode::DuplicateId));
    assert_eq!(found.as_slice()[0].path.as_text(), "backends[3].id");
    assert_eq!(
        found.as_slice()[0].parameters.get("kind"),
        Some(&ParameterValue::Identifier("backend".to_owned()))
    );
}

#[test]
fn a_vip_preferring_an_unknown_node_is_refused() {
    let mut config = sample();
    config.vips[0].preferred_node = Some(ek_ek_config::NodeId::new("node-missing"));

    let found = faults(&config);

    assert_eq!(found.codes(), vec![ErrorCode::VipUnknownPreferredNode]);
    assert_eq!(found.as_slice()[0].path.as_text(), "vips[0].preferred_node");

    // Leaving it unset is legal, so the rule must not fire on absence.
    let mut config = sample();
    config.vips[0].preferred_node = None;
    assert!(validate(&config).is_ok());
}

#[test]
fn a_certificate_naming_an_unknown_dns_provider_is_refused() {
    let mut config = sample();
    config.certificates[0].source = ek_ek_config::CertificateSource::AcmeDns01 {
        provider: ek_ek_config::DnsProviderId::new("provider-missing"),
    };

    let found = faults(&config);

    assert_eq!(
        found.codes(),
        vec![ErrorCode::CertificateUnknownDnsProvider]
    );
    assert_eq!(
        found.as_slice()[0].path.as_text(),
        "certificates[0].source.provider"
    );

    // HTTP-01 needs no provider at all.
    let mut config = sample();
    config.certificates[0].source = ek_ek_config::CertificateSource::AcmeHttp01;
    assert!(validate(&config).is_ok());
}

#[test]
fn the_udp_rule_looks_past_the_default_backend() {
    // A pool reached only through a routing rule is still behind the
    // frontend, so the rule must follow that reference too.
    let mut config = sample();
    config.frontends[3].default_backend = None;
    config.frontends[3]
        .routing_rules
        .push(ek_ek_config::RoutingRule {
            host_pattern: None,
            path_prefix: None,
            backend: BackendId::new("dns"),
            request_timeout_seconds: None,
        });
    config.backends[1].stickiness = SessionStickiness::SignedCookie {
        cookie_name: "ek-ek-affinity".to_owned(),
        same_site: SameSitePolicy::Lax,
    };

    let found = faults(&config);

    assert!(found.contains(ErrorCode::BackendCookieStickinessOnUdp));
    assert_eq!(config.frontends[3].transport, TransportProtocol::Udp);
}
