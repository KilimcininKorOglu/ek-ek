// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A configuration fixture shared by the test files in this crate.
//!
//! It exercises every branch of the model and passes validation, so a test
//! can break exactly one thing and be sure that is what it measured.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{
    AdminState, ApplicationProtocol, Backend, BackendId, BackendMember, Certificate, CertificateId,
    CertificateSource, CertificateValidity, Config, ConnectionPooling, DnsProvider,
    DnsProviderConnection, DnsProviderId, DnsRecordType, Frontend, FrontendId, HealthCheck,
    HealthProbe, LoadBalancingAlgorithm, MemberId, Node, NodeId, NodeRole, ProbePayload,
    ProxyProtocol, RoutingRule, RuleAction, SameSitePolicy, SchemaVersion, SecretId,
    SessionStickiness, SniRule, TlsPolicyLevel, TlsSettings, TransportProtocol, TsigAlgorithm, Vip,
    VipId,
};

pub fn address(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

/// A configuration that exercises every branch of the model at least once.
pub fn sample() -> Config {
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

pub fn http_frontend() -> Frontend {
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
                action: RuleAction::Proxy {
                    backend: BackendId::new("web"),
                },
                request_timeout_seconds: Some(3900),
            },
            RoutingRule {
                host_pattern: Some("mail.example.org".to_owned()),
                path_prefix: Some("/owa".to_owned()),
                action: RuleAction::Proxy {
                    backend: BackendId::new("web"),
                },
                request_timeout_seconds: None,
            },
            RoutingRule {
                host_pattern: None,
                path_prefix: Some("/api".to_owned()),
                action: RuleAction::Proxy {
                    backend: BackendId::new("web"),
                },
                request_timeout_seconds: Some(60),
            },
        ],
        sni_rules: Vec::new(),
        default_backend: Some(BackendId::new("web")),
        drain_timeout_seconds: 30,
    }
}

pub fn passthrough_frontend() -> Frontend {
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

pub fn dns_tcp_frontend() -> Frontend {
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

pub fn dns_udp_frontend() -> Frontend {
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

pub fn web_backend() -> Backend {
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

pub fn dns_backend() -> Backend {
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

pub fn passthrough_backend() -> Backend {
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
