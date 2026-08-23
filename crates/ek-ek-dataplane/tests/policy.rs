// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! What each TLS policy level means.
//!
//! Read here rather than through a handshake, because a handshake shows the
//! one cipher suite that was chosen and says almost nothing about the list
//! that was offered. The versions a real client is allowed and refused are
//! measured against the running binary in `ek-ek`.

use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{
    ApplicationProtocol, Backend, BackendId, BackendMember, Certificate, CertificateId, Config,
    ConnectionPooling, Frontend, FrontendId, Http2, LoadBalancingAlgorithm, MemberId,
    ProxyProtocol, SchemaVersion, SessionStickiness, TlsPolicyLevel, TlsSettings,
    TransportProtocol, Vip, VipId,
};
use ek_ek_dataplane::policy::{
    POLICY_METRIC, Version, exposition, least_openssl_version, name_of, settings,
};
use pingora::tls::ssl::SslVersion;

/// Every level, so a measurement can walk the whole set rather than the two
/// somebody remembered.
const LEVELS: [TlsPolicyLevel; 3] = [
    TlsPolicyLevel::Modern,
    TlsPolicyLevel::Balanced,
    TlsPolicyLevel::LegacyCompatible,
];

#[test]
fn each_level_accepts_the_versions_adr_0028_names() {
    assert_eq!(
        settings(TlsPolicyLevel::Modern).least_version,
        Version::Tls1_3
    );
    assert_eq!(
        settings(TlsPolicyLevel::Balanced).least_version,
        Version::Tls1_2
    );
    assert_eq!(
        settings(TlsPolicyLevel::LegacyCompatible).least_version,
        Version::Tls1_0
    );
}

#[test]
fn the_version_floor_reaches_the_tls_library_unchanged() {
    // Measured here rather than through a handshake, because two of the three
    // levels cannot be told apart on the wire: the cipher list of the
    // balanced level already excludes everything below TLS 1.2, so a floor
    // set one version too low would change nothing a client could see.
    assert_eq!(
        least_openssl_version(TlsPolicyLevel::Modern),
        SslVersion::TLS1_3
    );
    assert_eq!(
        least_openssl_version(TlsPolicyLevel::Balanced),
        SslVersion::TLS1_2
    );
    assert_eq!(
        least_openssl_version(TlsPolicyLevel::LegacyCompatible),
        SslVersion::TLS1
    );
}

#[test]
fn no_level_pins_an_upper_bound() {
    // Accepting an old client must not pull a modern one down with it. The
    // type carries no maximum at all, which is the strongest form of that:
    // there is nothing to set wrong.
    for level in LEVELS {
        let policy = settings(level);
        assert_eq!(
            policy.ciphersuites,
            settings(TlsPolicyLevel::Modern).ciphersuites,
            "{} offers different TLS 1.3 suites, so a 1.3 client does not get the same treatment everywhere",
            name_of(level)
        );
    }
}

#[test]
fn only_the_legacy_level_relaxes_the_security_level() {
    assert!(!settings(TlsPolicyLevel::Modern).relaxes_security_level);
    assert!(!settings(TlsPolicyLevel::Balanced).relaxes_security_level);
    assert!(settings(TlsPolicyLevel::LegacyCompatible).relaxes_security_level);
    // And the relaxation is written into the list itself, which is the thing
    // OpenSSL actually reads.
    assert!(
        settings(TlsPolicyLevel::LegacyCompatible)
            .cipher_list
            .contains("@SECLEVEL=0")
    );
    assert!(
        !settings(TlsPolicyLevel::Balanced)
            .cipher_list
            .contains("@SECLEVEL")
    );
}

#[test]
fn the_balanced_level_offers_forward_secrecy_and_nothing_else() {
    // Every suite it names starts with an ephemeral key exchange, so a leaked
    // server key never opens a recorded session.
    let list = settings(TlsPolicyLevel::Balanced).cipher_list;
    assert!(!list.is_empty());
    for suite in list.split(':') {
        assert!(
            suite.starts_with("ECDHE-") || suite.starts_with("DHE-"),
            "{suite} has no forward secrecy"
        );
        assert!(
            suite.contains("GCM") || suite.contains("CHACHA20"),
            "{suite} is not an AEAD mode"
        );
    }
}

#[test]
fn the_balanced_level_names_nothing_broken() {
    let list = settings(TlsPolicyLevel::Balanced).cipher_list;
    for banned in ["RC4", "DES", "MD5", "NULL", "EXPORT", "SHA:", "-SHA1"] {
        assert!(
            !list.contains(banned),
            "the balanced level offers {banned}: {list}"
        );
    }
}

#[test]
fn the_legacy_level_still_offers_the_modern_suites_first() {
    // A modern client landing on a relaxed frontend must not be dragged down
    // to what the old client needs. The strong suites come first, so server
    // preference picks one of them.
    let legacy = settings(TlsPolicyLevel::LegacyCompatible).cipher_list;
    let balanced = settings(TlsPolicyLevel::Balanced).cipher_list;
    assert!(
        legacy.starts_with(balanced),
        "the legacy list does not open with the balanced one:\n{legacy}"
    );
}

#[test]
fn the_legacy_level_names_an_ecdsa_suite_beside_every_rsa_one() {
    // A leaf may be either kind. The AEAD suites an ECDSA key can use were
    // defined for TLS 1.2, so a list carrying only the RSA half leaves a
    // frontend with an ECDSA certificate unable to complete a TLS 1.0
    // handshake at all.
    let list = settings(TlsPolicyLevel::LegacyCompatible).cipher_list;
    for shape in ["AES128-SHA", "AES256-SHA"] {
        assert!(
            list.contains(&format!("ECDHE-ECDSA-{shape}")),
            "no ECDSA suite for {shape}: {list}"
        );
        assert!(
            list.contains(&format!("ECDHE-RSA-{shape}")),
            "no RSA suite for {shape}: {list}"
        );
    }
}

#[test]
fn the_legacy_level_refuses_what_is_broken_rather_than_everything_old() {
    // The concession is old protocol versions, not broken cryptography.
    let list = settings(TlsPolicyLevel::LegacyCompatible).cipher_list;
    for banned in [
        "!RC4", "!MD5", "!aNULL", "!eNULL", "!EXPORT", "!DES", "!3DES",
    ] {
        assert!(
            list.contains(banned),
            "the legacy level does not bar {banned}"
        );
    }
}

#[test]
fn every_level_offers_all_three_tls_1_3_suites() {
    // TLS 1.3 defines five suites and two of them are CCM variants nobody
    // uses. These three are what every client speaks, and dropping one would
    // leave a client that only has it unable to connect at all. Pinned by
    // name, because the list is a product decision and not a default.
    for level in LEVELS {
        let suites: Vec<&str> = settings(level).ciphersuites.split(':').collect();
        assert_eq!(
            suites,
            vec![
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
            ],
            "{} offers a different set",
            name_of(level)
        );
    }
}

#[test]
fn the_modern_level_names_no_suites_below_tls_1_3() {
    // Nothing under TLS 1.3 is accepted, so a list of older suites could
    // never be reached. Leaving one there would say the level offers
    // something it does not.
    assert_eq!(settings(TlsPolicyLevel::Modern).cipher_list, "");
    assert!(!settings(TlsPolicyLevel::Modern).ciphersuites.is_empty());
}

#[test]
fn every_level_has_a_name_of_its_own() {
    assert_eq!(name_of(TlsPolicyLevel::Modern), "modern");
    assert_eq!(name_of(TlsPolicyLevel::Balanced), "dengeli");
    assert_eq!(name_of(TlsPolicyLevel::LegacyCompatible), "eski-uyumlu");

    // Three levels, three names. A repeated one would put two levels behind
    // one label and make the metric unreadable.
    let mut named: Vec<&str> = LEVELS.iter().copied().map(name_of).collect();
    named.sort_unstable();
    named.dedup();
    assert_eq!(named.len(), LEVELS.len());
}

#[test]
fn the_exposition_names_every_terminating_frontend_and_its_level() {
    let config = document(&[
        (
            "web-modern",
            ApplicationProtocol::Http,
            Some(TlsPolicyLevel::Modern),
        ),
        (
            "web-legacy",
            ApplicationProtocol::Http,
            Some(TlsPolicyLevel::LegacyCompatible),
        ),
    ]);

    let text = exposition(&config);

    assert!(text.contains(&format!(
        "{POLICY_METRIC}{{frontend=\"web-modern\",level=\"modern\"}} 1"
    )));
    assert!(text.contains(&format!(
        "{POLICY_METRIC}{{frontend=\"web-legacy\",level=\"eski-uyumlu\"}} 1"
    )));
    // The two lines Prometheus reads before any sample.
    assert!(text.contains(&format!("# HELP {POLICY_METRIC} ")));
    assert!(text.contains(&format!("# TYPE {POLICY_METRIC} gauge")));
}

#[test]
fn a_frontend_that_opens_no_handshake_is_left_out() {
    // A zero would read as a policy that is turned off. These frontends have
    // no policy at all: a raw one never speaks TLS and a passthrough one
    // never opens the handshake (ADR-0080).
    let config = document(&[
        (
            "web",
            ApplicationProtocol::Http,
            Some(TlsPolicyLevel::Balanced),
        ),
        ("raw", ApplicationProtocol::Raw, None),
        ("imaps", ApplicationProtocol::TlsPassthrough, None),
    ]);

    let text = exposition(&config);

    assert!(text.contains("frontend=\"web\""));
    assert!(!text.contains("frontend=\"raw\""), "{text}");
    assert!(!text.contains("frontend=\"imaps\""), "{text}");
    assert_eq!(
        text.lines().filter(|line| !line.starts_with('#')).count(),
        1,
        "one sample per terminating frontend:\n{text}"
    );
}

#[test]
fn an_identity_that_could_end_a_line_early_is_escaped() {
    // A frontend identity is written by an operator. A quote in it would
    // close the label set and make every line after it unreadable.
    let config = document(&[(
        "we\"b\\one",
        ApplicationProtocol::Http,
        Some(TlsPolicyLevel::Balanced),
    )]);

    let text = exposition(&config);

    assert!(
        text.contains("frontend=\"we\\\"b\\\\one\""),
        "the identity was not escaped:\n{text}"
    );
}

/// A configuration with the frontends named.
fn document(frontends: &[(&str, ApplicationProtocol, Option<TlsPolicyLevel>)]) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: Vec::new(),
        vips: vec![Vip {
            id: VipId::new("vip"),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix_length: 8,
            interface: "lo".to_owned(),
            preferred_node: None,
        }],
        frontends: frontends
            .iter()
            .enumerate()
            .map(|(at, (id, application, policy))| Frontend {
                id: FrontendId::new(*id),
                vip: VipId::new("vip"),
                port: 443 + u16::try_from(at).unwrap_or(0),
                transport: TransportProtocol::Tcp,
                application: *application,
                tls: policy.map(|policy| TlsSettings {
                    certificates: vec![CertificateId::new("cert")],
                    default_certificate: None,
                    policy,
                }),
                proxy_protocol: ProxyProtocol::Disabled,
                access_log: Default::default(),
                routing_rules: Vec::new(),
                sni_rules: Vec::new(),
                default_backend: Some(BackendId::new("pool")),
                http2: Http2::Enabled,
                connect_timeout_seconds: 2,
                request_timeout_seconds: 5,
                idle_timeout_seconds: 0,
                drain_timeout_seconds: 5,
                udp_session_limit: 0,
            })
            .collect(),
        backends: vec![Backend {
            id: BackendId::new("pool"),
            members: vec![BackendMember {
                id: MemberId::new("one"),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8080,
                weight: 1,
                admin_state: Default::default(),
            }],
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            health_check: None,
            stickiness: SessionStickiness::Disabled,
            connection_pooling: ConnectionPooling::Enabled,
            connection_pool_size: 128,
            connection_lifetime_seconds: 300,
        }],
        certificates: vec![Certificate {
            id: CertificateId::new("cert"),
            sni_names: vec!["ornek.com".to_owned()],
            source: ek_ek_config::CertificateSource::ManualUpload,
            validity: None,
            chain: None,
            private_key: None,
        }],
        dns_providers: Vec::new(),
        acme: None,
        stickiness_key: String::new(),
        log_level: Default::default(),
        certificate_expiry_warning_days: 30,
    }
}
