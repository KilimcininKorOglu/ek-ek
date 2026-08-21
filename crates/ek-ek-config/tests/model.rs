// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the configuration model must hold true.
//!
//! Every check here is paired with the property it guards. The identifier
//! check and the absent-field check both carry a negative control, because a
//! scan that never rejects anything passes silently forever.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{
    AdminState, ApplicationProtocol, Backend, BackendId, BackendMember, Certificate, CertificateId,
    CertificateSource, CertificateValidity, Config, ConnectionPooling, DnsProvider,
    DnsProviderConnection, DnsProviderId, DnsRecordType, Frontend, FrontendId, HealthCheck,
    HealthProbe, LoadBalancingAlgorithm, MemberId, Node, NodeId, NodeRole, ProbePayload,
    ProxyProtocol, RoutingRule, SameSitePolicy, SchemaVersion, SecretId, SessionStickiness,
    SniRule, TlsPolicyLevel, TlsSettings, TransportProtocol, TsigAlgorithm, Vip, VipId,
};
use serde_json::Value;

fn address(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

/// A configuration that exercises every branch of the model at least once.
fn sample() -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: vec![
            Node {
                id: NodeId::new("node1"),
                address: address(11),
                roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
            },
            Node {
                id: NodeId::new("node2"),
                address: address(12),
                roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
            },
        ],
        vips: vec![Vip {
            id: VipId::new("vip-web"),
            address: address(100),
            prefix_length: 24,
            interface: "eth0".to_owned(),
            preferred_node: Some(NodeId::new("node1")),
        }],
        frontends: vec![
            http_frontend(),
            passthrough_frontend(),
            dns_tcp_frontend(),
            dns_udp_frontend(),
        ],
        backends: vec![web_backend(), dns_backend(), passthrough_backend()],
        certificates: vec![Certificate {
            id: CertificateId::new("cert-web"),
            sni_names: vec!["www.example.org".to_owned(), "*.example.org".to_owned()],
            source: CertificateSource::AcmeDns01 {
                provider: DnsProviderId::new("dns-internal"),
            },
            validity: Some(CertificateValidity {
                not_before_unix: 1_767_225_600,
                not_after_unix: 1_775_001_600,
            }),
            private_key: Some(SecretId::new("key-cert-web")),
        }],
        dns_providers: vec![
            DnsProvider {
                id: DnsProviderId::new("dns-internal"),
                connection: DnsProviderConnection::Rfc2136 {
                    server: address(53),
                    port: 53,
                    zone: "example.org".to_owned(),
                    tsig_key_name: "acme-update".to_owned(),
                    tsig_algorithm: TsigAlgorithm::HmacSha256,
                    tsig_secret: SecretId::new("tsig-acme-update"),
                },
            },
            DnsProvider {
                id: DnsProviderId::new("dns-cloudflare"),
                connection: DnsProviderConnection::Cloudflare {
                    zone_id: "0123456789abcdef".to_owned(),
                    api_token: SecretId::new("cloudflare-token"),
                },
            },
        ],
    }
}

fn http_frontend() -> Frontend {
    Frontend {
        id: FrontendId::new("web-https"),
        vip: VipId::new("vip-web"),
        port: 443,
        transport: TransportProtocol::Tcp,
        application: ApplicationProtocol::Http,
        tls: Some(TlsSettings {
            certificates: vec![CertificateId::new("cert-web")],
            policy: TlsPolicyLevel::Balanced,
        }),
        proxy_protocol: ProxyProtocol::Disabled,
        routing_rules: vec![
            RoutingRule {
                host_pattern: Some("mail.example.org".to_owned()),
                path_prefix: Some("/Microsoft-Server-ActiveSync".to_owned()),
                backend: BackendId::new("web"),
                request_timeout_seconds: Some(3900),
            },
            RoutingRule {
                host_pattern: Some("mail.example.org".to_owned()),
                path_prefix: Some("/owa".to_owned()),
                backend: BackendId::new("web"),
                request_timeout_seconds: None,
            },
            RoutingRule {
                host_pattern: None,
                path_prefix: Some("/api".to_owned()),
                backend: BackendId::new("web"),
                request_timeout_seconds: Some(60),
            },
        ],
        sni_rules: Vec::new(),
        default_backend: Some(BackendId::new("web")),
        drain_timeout_seconds: 30,
    }
}

fn passthrough_frontend() -> Frontend {
    Frontend {
        id: FrontendId::new("imaps"),
        vip: VipId::new("vip-web"),
        port: 993,
        transport: TransportProtocol::Tcp,
        application: ApplicationProtocol::TlsPassthrough,
        tls: None,
        proxy_protocol: ProxyProtocol::V2,
        routing_rules: Vec::new(),
        sni_rules: vec![SniRule {
            sni_pattern: "mail.example.org".to_owned(),
            backend: BackendId::new("passthrough"),
        }],
        default_backend: Some(BackendId::new("passthrough")),
        drain_timeout_seconds: 60,
    }
}

fn dns_tcp_frontend() -> Frontend {
    Frontend {
        id: FrontendId::new("dns-tcp"),
        vip: VipId::new("vip-web"),
        port: 53,
        transport: TransportProtocol::Tcp,
        application: ApplicationProtocol::Raw,
        tls: None,
        proxy_protocol: ProxyProtocol::Disabled,
        routing_rules: Vec::new(),
        sni_rules: Vec::new(),
        default_backend: Some(BackendId::new("dns")),
        drain_timeout_seconds: 10,
    }
}

fn dns_udp_frontend() -> Frontend {
    Frontend {
        id: FrontendId::new("dns-udp"),
        vip: VipId::new("vip-web"),
        port: 53,
        transport: TransportProtocol::Udp,
        application: ApplicationProtocol::Raw,
        tls: None,
        proxy_protocol: ProxyProtocol::Disabled,
        routing_rules: Vec::new(),
        sni_rules: Vec::new(),
        default_backend: Some(BackendId::new("dns")),
        drain_timeout_seconds: 10,
    }
}

fn web_backend() -> Backend {
    Backend {
        id: BackendId::new("web"),
        members: vec![
            BackendMember {
                id: MemberId::new("web-1"),
                address: address(21),
                port: 8080,
                weight: 1,
                admin_state: AdminState::Enabled,
            },
            BackendMember {
                id: MemberId::new("web-2"),
                address: address(22),
                port: 8080,
                weight: 2,
                admin_state: AdminState::Draining,
            },
        ],
        algorithm: LoadBalancingAlgorithm::LeastConnections,
        health_check: Some(HealthCheck {
            probe: HealthProbe::Http {
                path: "/healthz".to_owned(),
                expected_status: vec![200, 204],
                expected_body: Some("ok".to_owned()),
                host_header: Some("mail.example.org".to_owned()),
            },
            interval_ms: 2000,
            timeout_ms: 1000,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        }),
        stickiness: SessionStickiness::SignedCookie {
            cookie_name: "ek-ek-affinity".to_owned(),
            same_site: SameSitePolicy::Lax,
        },
        connection_pooling: ConnectionPooling::Disabled,
    }
}

fn dns_backend() -> Backend {
    Backend {
        id: BackendId::new("dns"),
        members: vec![BackendMember {
            id: MemberId::new("dns-1"),
            address: address(31),
            port: 53,
            weight: 1,
            admin_state: AdminState::Disabled,
        }],
        algorithm: LoadBalancingAlgorithm::ConsistentHash,
        health_check: Some(HealthCheck {
            probe: HealthProbe::DnsQuery {
                name: "example.org".to_owned(),
                record_type: DnsRecordType::Soa,
            },
            interval_ms: 3000,
            timeout_ms: 1500,
            healthy_threshold: 1,
            unhealthy_threshold: 2,
        }),
        stickiness: SessionStickiness::Disabled,
        connection_pooling: ConnectionPooling::Enabled,
    }
}

fn passthrough_backend() -> Backend {
    Backend {
        id: BackendId::new("passthrough"),
        members: vec![BackendMember {
            id: MemberId::new("imap-1"),
            address: address(41),
            port: 993,
            weight: 1,
            admin_state: AdminState::Enabled,
        }],
        algorithm: LoadBalancingAlgorithm::SourceIpHash,
        health_check: Some(HealthCheck {
            probe: HealthProbe::SendExpect {
                send: ProbePayload::Text("a001 CAPABILITY\r\n".to_owned()),
                expect: ProbePayload::Hex("2a204f4b".to_owned()),
            },
            interval_ms: 5000,
            timeout_ms: 2000,
            healthy_threshold: 2,
            unhealthy_threshold: 2,
        }),
        stickiness: SessionStickiness::Disabled,
        connection_pooling: ConnectionPooling::Enabled,
    }
}

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
