// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the configuration model must hold true.
//!
//! Every check here is paired with the property it guards. The identifier
//! check and the absent-field check both carry a negative control, because a
//! scan that never rejects anything passes silently forever.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::sample;
use ek_ek_config::Config;
use ek_ek_config::{
    AdminState, ApplicationProtocol, ConnectionPooling, DnsRecordType, Frontend,
    LoadBalancingAlgorithm, NodeRole, ProxyProtocol, SameSitePolicy, SecretId, SessionStickiness,
    TlsPolicyLevel, TransportProtocol, TsigAlgorithm, VipId,
};
use serde_json::Value;

#[test]
fn a_config_survives_a_serialisation_round_trip() {
    let original = sample();

    let encoded = serde_json::to_string(&original).expect("the sample config must serialise");
    let decoded: Config = serde_json::from_str(&encoded).expect("the encoded form must decode");

    assert_eq!(decoded, original, "the round trip changed the value");
}

#[test]
fn a_tcp_and_a_udp_frontend_share_one_address_and_port() {
    let config = sample();

    let dns: Vec<&Frontend> = config
        .frontends
        .iter()
        .filter(|frontend| frontend.port == 53)
        .collect();

    assert_eq!(dns.len(), 2, "the DNS scenario needs both frontends");
    assert_eq!(dns[0].vip, dns[1].vip, "both must sit on the same VIP");
    assert_ne!(
        dns[0].transport, dns[1].transport,
        "the pair is only legal because the transports differ"
    );

    // The triple that makes a frontend unique is VIP, port and transport.
    let mut triples: Vec<(&VipId, u16, TransportProtocol)> = config
        .frontends
        .iter()
        .map(|frontend| (&frontend.vip, frontend.port, frontend.transport))
        .collect();
    let total = triples.len();
    triples.sort();
    triples.dedup();
    assert_eq!(triples.len(), total, "no two frontends share the triple");
}

#[test]
fn routing_rule_order_survives_a_round_trip() {
    let original = sample();
    let encoded = serde_json::to_string(&original).expect("the sample config must serialise");
    let decoded: Config = serde_json::from_str(&encoded).expect("the encoded form must decode");

    let before: Vec<&Option<String>> = original.frontends[0]
        .routing_rules
        .iter()
        .map(|rule| &rule.path_prefix)
        .collect();
    let after: Vec<&Option<String>> = decoded.frontends[0]
        .routing_rules
        .iter()
        .map(|rule| &rule.path_prefix)
        .collect();

    assert_eq!(after, before, "first match wins, so order is data");
    assert_eq!(
        before[0].as_deref(),
        Some("/Microsoft-Server-ActiveSync"),
        "the most specific rule must stay first"
    );
}

/// A value is an identifier when it could serve as a translation key segment.
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-')
        })
}

#[test]
fn the_identifier_check_rejects_prose() {
    assert!(is_identifier("eski-uyumlu"));
    assert!(is_identifier("least_connections"));
    assert!(!is_identifier("Balanced TLS policy"), "prose must fail");
    assert!(!is_identifier("Kapalı"), "a translated label must fail");
    assert!(!is_identifier(""), "an empty value must fail");
}

#[test]
fn every_enum_serialises_to_a_stable_identifier() {
    let values = [
        serde_json::to_value(NodeRole::DataPlane),
        serde_json::to_value(TransportProtocol::Udp),
        serde_json::to_value(ApplicationProtocol::TlsPassthrough),
        serde_json::to_value(TlsPolicyLevel::Modern),
        serde_json::to_value(TlsPolicyLevel::Balanced),
        serde_json::to_value(TlsPolicyLevel::LegacyCompatible),
        serde_json::to_value(ProxyProtocol::V2),
        serde_json::to_value(LoadBalancingAlgorithm::LeastConnections),
        serde_json::to_value(SameSitePolicy::Lax),
        serde_json::to_value(ConnectionPooling::Disabled),
        serde_json::to_value(AdminState::Draining),
        serde_json::to_value(DnsRecordType::Aaaa),
        serde_json::to_value(TsigAlgorithm::HmacSha256),
    ];

    for value in values {
        let value = value.expect("every enum must serialise");
        let text = value.as_str().expect("a unit enum must encode as a string");
        assert!(is_identifier(text), "{text} is not a stable identifier");
    }
}

#[test]
fn the_tls_policy_levels_keep_the_names_the_decision_gave_them() {
    let encode = |level: TlsPolicyLevel| {
        serde_json::to_value(level)
            .expect("a policy level must serialise")
            .as_str()
            .expect("a unit enum must encode as a string")
            .to_owned()
    };

    assert_eq!(encode(TlsPolicyLevel::Modern), "modern");
    assert_eq!(encode(TlsPolicyLevel::Balanced), "dengeli");
    assert_eq!(encode(TlsPolicyLevel::LegacyCompatible), "eski-uyumlu");
}

#[test]
fn the_defaults_are_the_ones_the_decisions_state() {
    assert_eq!(TlsPolicyLevel::default(), TlsPolicyLevel::Balanced);
    assert_eq!(ProxyProtocol::default(), ProxyProtocol::Disabled);
    assert_eq!(ConnectionPooling::default(), ConnectionPooling::Enabled);
    assert_eq!(SessionStickiness::default(), SessionStickiness::Disabled);
    assert_eq!(AdminState::default(), AdminState::Enabled);
}

/// Walks every key in a JSON document.
fn keys(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                found.push(key.clone());
                keys(nested, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                keys(item, found);
            }
        }
        _ => {}
    }
}

#[test]
fn the_model_carries_no_vrrp_numbers() {
    let encoded = serde_json::to_value(sample()).expect("the sample config must serialise");
    let mut found = Vec::new();
    keys(&encoded, &mut found);

    assert!(
        found.contains(&"preferred_node".to_owned()),
        "the key walk must actually reach the VIP fields"
    );
    for banned in ["vrid", "priority"] {
        assert!(
            !found.iter().any(|key| key == banned),
            "{banned} is derived from the preferred node, never configured"
        );
    }
}

#[test]
fn a_certificate_carries_a_key_reference_and_never_a_key() {
    let encoded = serde_json::to_value(sample()).expect("the sample config must serialise");
    let mut found = Vec::new();
    keys(&encoded, &mut found);

    assert!(
        found.contains(&"private_key".to_owned()),
        "the reference itself must be present"
    );

    let text = encoded.to_string();
    assert!(
        !text.contains("BEGIN"),
        "no PEM block may reach the config model"
    );
    assert_eq!(
        sample().certificates[0].private_key,
        Some(SecretId::new("key-cert-web")),
        "the model holds an identity, and the store holds the key"
    );
}

#[test]
fn an_unknown_field_is_refused_rather_than_dropped() {
    let mut encoded = serde_json::to_value(sample()).expect("the sample config must serialise");
    encoded
        .as_object_mut()
        .expect("the root must be an object")
        .insert("frontent".to_owned(), Value::Array(Vec::new()));

    let decoded: Result<Config, _> = serde_json::from_value(encoded);
    assert!(
        decoded.is_err(),
        "a misspelled key must fail loudly instead of being ignored"
    );
}

#[test]
fn a_pool_that_names_no_connection_settings_gets_the_defaults() {
    // A document written before these settings existed must still parse, and
    // parse to the behaviour it had (ADR-0045).
    let written = r#"{
        "id": "web",
        "members": [{"id":"web-1","address":"127.0.0.1","port":8080,"weight":1}],
        "algorithm": "round_robin",
        "health_check": null
    }"#;

    let pool: ek_ek_config::Backend =
        serde_json::from_str(written).expect("a document naming none of them must still parse");

    assert_eq!(pool.connection_pooling, ConnectionPooling::Enabled);
    assert_eq!(pool.connection_pool_size, 128);
    assert_eq!(pool.connection_lifetime_seconds, 300);
}

#[test]
fn the_connection_settings_survive_a_serialisation_round_trip() {
    // The other side. A field that serialised but did not read back would
    // lose an operator's setting on the next delivery.
    let written = r#"{
        "id": "mapi",
        "members": [{"id":"mapi-1","address":"127.0.0.1","port":8080,"weight":1}],
        "algorithm": "round_robin",
        "health_check": null,
        "connection_pooling": "disabled",
        "connection_pool_size": 16,
        "connection_lifetime_seconds": 0
    }"#;

    let pool: ek_ek_config::Backend = serde_json::from_str(written).expect("this document parses");
    let again: ek_ek_config::Backend =
        serde_json::from_str(&serde_json::to_string(&pool).expect("it serialises"))
            .expect("and reads back");

    assert_eq!(again, pool);
    assert_eq!(again.connection_pooling, ConnectionPooling::Disabled);
    assert_eq!(again.connection_pool_size, 16);
    assert_eq!(again.connection_lifetime_seconds, 0);
    assert!(
        again.limits_requests_in_flight(),
        "sixteen is a limit; only zero is not"
    );
    assert_eq!(
        again.reuse_group(0),
        again.reuse_group(u64::from(u32::MAX)),
        "a lifetime of zero retires nothing"
    );
}
