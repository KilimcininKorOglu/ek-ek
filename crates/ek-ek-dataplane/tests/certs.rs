// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which certificate a handshake is given, and what happens when one cannot
//! be loaded.
//!
//! The handshake itself is measured against the real binary in `ek-ek`. What
//! is measured here is the lookup order and every way loading can fail, which
//! would each need their own broken deployment to reach from outside.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{
    AdminState, ApplicationProtocol, Backend, BackendId, BackendMember, Certificate, CertificateId,
    Config, ConnectionPooling, Frontend, FrontendId, Http2, LoadBalancingAlgorithm, MemberId,
    ProxyProtocol, SchemaVersion, SessionStickiness, TlsPolicyLevel, TlsSettings,
    TransportProtocol, Vip, VipId,
};
use ek_ek_dataplane::certs::{Certificates, LoadFailure, Loaded};
use ek_ek_ipc::CertificateMaterial;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509, X509NameBuilder};

/// A self-signed certificate and its key, both as PEM.
///
/// One level is enough here: the lookup does not care how long a chain is.
fn issue(common: &str) -> (String, String) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("a curve");
    let key = PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key");

    let mut subject = X509NameBuilder::new().expect("a name");
    subject
        .append_entry_by_nid(Nid::COMMONNAME, common)
        .expect("a common name");
    let subject = subject.build();

    let mut serial = BigNum::new().expect("a number");
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .expect("a number");

    let mut builder = X509::builder().expect("a builder");
    builder.set_version(2).expect("x509v3");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("a serial"))
        .expect("a serial");
    builder.set_subject_name(&subject).expect("a subject");
    builder.set_issuer_name(&subject).expect("an issuer");
    builder.set_pubkey(&key).expect("a public key");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("a start"))
        .expect("a start");
    builder
        .set_not_after(&Asn1Time::days_from_now(30).expect("an end"))
        .expect("an end");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("it must sign");

    let certificate = builder.build();
    (
        String::from_utf8(certificate.to_pem().expect("PEM")).expect("text"),
        String::from_utf8(key.private_key_to_pem_pkcs8().expect("PEM")).expect("text"),
    )
}

/// The material of one freshly issued certificate.
fn material(common: &str) -> CertificateMaterial {
    let (chain_pem, key_pem) = issue(common);
    CertificateMaterial { chain_pem, key_pem }
}

/// A PEM block the library refuses to decode.
const CORRUPT_BLOCK: &str =
    "-----BEGIN CERTIFICATE-----\nQUJD!!!not base64\n-----END CERTIFICATE-----\n";

/// A key belonging to some other certificate.
fn stranger_key() -> String {
    issue("somebody else").1
}

/// One certificate entry in a configuration.
fn certificate(id: &str, names: &[&str]) -> Certificate {
    Certificate {
        id: CertificateId::new(id),
        sni_names: names.iter().map(|name| (*name).to_owned()).collect(),
        source: ek_ek_config::CertificateSource::ManualUpload,
        validity: None,
        chain: Some(ek_ek_config::SecretId::new(format!("chain-{id}"))),
        private_key: Some(ek_ek_config::SecretId::new(format!("key-{id}"))),
    }
}

/// A configuration with one TLS frontend offering the certificates named.
fn document(offers: &[&str], default: Option<&str>, certificates: Vec<Certificate>) -> Config {
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
        frontends: vec![Frontend {
            id: FrontendId::new("web"),
            vip: VipId::new("vip"),
            port: 443,
            transport: TransportProtocol::Tcp,
            application: ApplicationProtocol::Http,
            tls: Some(TlsSettings {
                certificates: offers.iter().map(|id| CertificateId::new(*id)).collect(),
                default_certificate: default.map(CertificateId::new),
                policy: TlsPolicyLevel::Balanced,
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
        }],
        backends: vec![Backend {
            id: BackendId::new("pool"),
            members: vec![BackendMember {
                id: MemberId::new("one"),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8080,
                weight: 1,
                admin_state: AdminState::Enabled,
            }],
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            health_check: None,
            stickiness: SessionStickiness::Disabled,
            connection_pooling: ConnectionPooling::Enabled,
            connection_pool_size: Backend::default_pool_size(),
            connection_lifetime_seconds: Backend::default_connection_lifetime_seconds(),
        }],
        certificates,
        dns_providers: Vec::new(),
        stickiness_key: String::new(),
        log_level: Default::default(),
    }
}

/// Which certificate was chosen, by its subject common name.
fn served(set: &Certificates, name: Option<&str>) -> Option<String> {
    set.choose("web", name).map(|chosen| chosen.id.clone())
}

#[test]
fn a_name_a_certificate_covers_exactly_gets_that_certificate() {
    let config = document(
        &["a", "b"],
        None,
        vec![
            certificate("a", &["one.example.test"]),
            certificate("b", &["two.example.test"]),
        ],
    );
    let set = Certificates::build(
        &config,
        &BTreeMap::from([
            (CertificateId::new("a"), material("one")),
            (CertificateId::new("b"), material("two")),
        ]),
    );

    assert_eq!(served(&set, Some("one.example.test")).as_deref(), Some("a"));
    assert_eq!(served(&set, Some("two.example.test")).as_deref(), Some("b"));
}

#[test]
fn an_exact_name_wins_over_a_wildcard_that_would_also_cover_it() {
    // The narrower match has to win, or a certificate bought for one name
    // could never be used while a wildcard is configured beside it.
    let config = document(
        &["wide", "narrow"],
        None,
        vec![
            certificate("wide", &["*.example.test"]),
            certificate("narrow", &["one.example.test"]),
        ],
    );
    let set = Certificates::build(
        &config,
        &BTreeMap::from([
            (CertificateId::new("wide"), material("wide")),
            (CertificateId::new("narrow"), material("narrow")),
        ]),
    );

    assert_eq!(
        served(&set, Some("one.example.test")).as_deref(),
        Some("narrow"),
        "the wildcard was preferred over the exact name"
    );
    // The other side: a name only the wildcard covers still reaches it.
    assert_eq!(
        served(&set, Some("other.example.test")).as_deref(),
        Some("wide")
    );
}

#[test]
fn a_wildcard_covers_one_label_and_no_more() {
    let config = document(
        &["wide"],
        None,
        vec![certificate("wide", &["*.example.test"])],
    );
    let set = Certificates::build(
        &config,
        &BTreeMap::from([(CertificateId::new("wide"), material("wide"))]),
    );

    assert_eq!(
        served(&set, Some("one.example.test")).as_deref(),
        Some("wide"),
        "the wildcard did not cover a single label"
    );
    assert_eq!(
        served(&set, Some("deep.one.example.test")),
        None,
        "the wildcard covered two labels, which no client would accept"
    );
    assert_eq!(
        served(&set, Some("example.test")),
        None,
        "the wildcard covered the bare domain"
    );
}

#[test]
fn a_name_is_matched_whatever_case_it_arrives_in() {
    // DNS names are case insensitive and clients send what the user typed.
    let config = document(&["a"], None, vec![certificate("a", &["One.Example.TEST"])]);
    let set = Certificates::build(
        &config,
        &BTreeMap::from([(CertificateId::new("a"), material("one"))]),
    );

    assert_eq!(served(&set, Some("ONE.example.test")).as_deref(), Some("a"));
    assert_eq!(served(&set, Some("one.example.test")).as_deref(), Some("a"));
}

#[test]
fn a_name_nobody_covers_gets_nothing_when_there_is_no_default() {
    // Nothing is the whole point: the handshake is then refused rather than
    // handed somebody else's certificate (ADR-0070).
    let config = document(&["a"], None, vec![certificate("a", &["one.example.test"])]);
    let set = Certificates::build(
        &config,
        &BTreeMap::from([(CertificateId::new("a"), material("one"))]),
    );

    assert_eq!(served(&set, Some("nobody.example.test")), None);
}

#[test]
fn a_name_nobody_covers_gets_the_default_when_one_is_named() {
    // The other side of the same rule.
    let config = document(
        &["a", "b"],
        Some("b"),
        vec![
            certificate("a", &["one.example.test"]),
            certificate("b", &["fallback.example.test"]),
        ],
    );
    let set = Certificates::build(
        &config,
        &BTreeMap::from([
            (CertificateId::new("a"), material("one")),
            (CertificateId::new("b"), material("fallback")),
        ]),
    );

    assert_eq!(
        served(&set, Some("nobody.example.test")).as_deref(),
        Some("b"),
        "the default was not served to a name nothing covers"
    );
    // And it is the default, not just any certificate: the specific name
    // still reaches its own.
    assert_eq!(served(&set, Some("one.example.test")).as_deref(), Some("a"));
}

#[test]
fn a_client_that_sends_no_name_gets_nothing_when_there_is_no_default() {
    let config = document(&["a"], None, vec![certificate("a", &["one.example.test"])]);
    let set = Certificates::build(
        &config,
        &BTreeMap::from([(CertificateId::new("a"), material("one"))]),
    );

    assert_eq!(
        served(&set, None),
        None,
        "a client that named nothing was served a certificate anyway"
    );
}

#[test]
fn a_client_that_sends_no_name_gets_the_default_when_one_is_named() {
    let config = document(
        &["a", "b"],
        Some("b"),
        vec![
            certificate("a", &["one.example.test"]),
            certificate("b", &["fallback.example.test"]),
        ],
    );
    let set = Certificates::build(
        &config,
        &BTreeMap::from([
            (CertificateId::new("a"), material("one")),
            (CertificateId::new("b"), material("fallback")),
        ]),
    );

    assert_eq!(served(&set, None).as_deref(), Some("b"));
}

#[test]
fn a_frontend_nobody_configured_serves_nothing() {
    let config = document(&["a"], None, vec![certificate("a", &["one.example.test"])]);
    let set = Certificates::build(
        &config,
        &BTreeMap::from([(CertificateId::new("a"), material("one"))]),
    );

    assert!(set.choose("nobody", Some("one.example.test")).is_none());
    assert_eq!(set.count("web"), 1);
    assert_eq!(set.count("nobody"), 0);
}

#[test]
fn a_certificate_whose_material_never_arrived_is_recorded() {
    let config = document(&["a"], None, vec![certificate("a", &["one.example.test"])]);
    let set = Certificates::build(&config, &BTreeMap::new());

    assert_eq!(
        set.failures(),
        &[("a".to_owned(), LoadFailure::Missing)],
        "a certificate with no material was dropped without a word"
    );
    assert_eq!(served(&set, Some("one.example.test")), None);
}

#[test]
fn a_certificate_whose_material_arrived_is_not_recorded_as_a_failure() {
    // The other side. A failure list that always had an entry would say
    // nothing about the deployment it describes.
    let config = document(&["a"], None, vec![certificate("a", &["one.example.test"])]);
    let set = Certificates::build(
        &config,
        &BTreeMap::from([(CertificateId::new("a"), material("one"))]),
    );

    assert!(set.failures().is_empty(), "{:?}", set.failures());
}

#[test]
fn every_way_a_certificate_can_fail_to_load_is_told_apart() {
    let (chain_pem, key_pem) = issue("one");

    let cases = [
        (
            // A PEM block whose body is not base64. Text with no block at all
            // parses as an empty list instead, which is the case below.
            CertificateMaterial {
                chain_pem: CORRUPT_BLOCK.to_owned(),
                key_pem: key_pem.clone(),
            },
            LoadFailure::ChainUnreadable,
        ),
        (
            CertificateMaterial {
                chain_pem: "not a certificate at all".to_owned(),
                key_pem: key_pem.clone(),
            },
            LoadFailure::ChainEmpty,
        ),
        (
            CertificateMaterial {
                chain_pem: chain_pem.clone(),
                key_pem: "not a key".to_owned(),
            },
            LoadFailure::KeyUnreadable,
        ),
        (
            CertificateMaterial {
                chain_pem: chain_pem.clone(),
                key_pem: stranger_key(),
            },
            LoadFailure::KeyDoesNotMatch,
        ),
    ];

    for (material, expected) in cases {
        assert_eq!(
            Loaded::load("a", &material).err(),
            Some(expected),
            "the wrong reason was reported"
        );
    }

    // And the pair that belongs together still loads, so the checks above are
    // not simply refusing everything.
    assert!(Loaded::load("a", &CertificateMaterial { chain_pem, key_pem }).is_ok());
}

#[test]
fn nothing_a_failure_says_carries_key_material() {
    // A failure reaches a log eventually, and a key must never arrive there
    // (ADR-0018).
    let (chain_pem, key_pem) = issue("one");
    let stranger = stranger_key();

    for material in [
        CertificateMaterial {
            chain_pem: chain_pem.clone(),
            key_pem: "not a key".to_owned(),
        },
        CertificateMaterial {
            chain_pem,
            key_pem: stranger.clone(),
        },
    ] {
        let failure = Loaded::load("a", &material).expect_err("it must fail");
        let said = format!("{failure:?} {}", failure.reason());

        for secret in [&key_pem, &stranger, &material.key_pem] {
            for line in secret.lines().filter(|line| !line.starts_with("-----")) {
                assert!(
                    !said.contains(line),
                    "a failure carried key material: {said}"
                );
            }
        }
    }
}

#[test]
fn printing_a_loaded_certificate_prints_no_key() {
    let (chain_pem, key_pem) = issue("one");
    let loaded = Loaded::load(
        "cert-web",
        &CertificateMaterial {
            chain_pem,
            key_pem: key_pem.clone(),
        },
    )
    .expect("it must load");

    let printed = format!("{loaded:?}");

    assert!(
        printed.contains("cert-web"),
        "the identity is what makes a diagnostic useful: {printed}"
    );
    for line in key_pem.lines().filter(|line| !line.starts_with("-----")) {
        assert!(!printed.contains(line), "a key was printed: {printed}");
    }
}

#[test]
fn printing_the_material_a_delivery_carries_prints_neither_half() {
    let (chain_pem, key_pem) = issue("one");
    let material = CertificateMaterial {
        chain_pem: chain_pem.clone(),
        key_pem: key_pem.clone(),
    };

    let printed = format!("{material:?}");

    for secret in [&chain_pem, &key_pem] {
        for line in secret.lines().filter(|line| !line.starts_with("-----")) {
            assert!(
                !printed.contains(line),
                "certificate material was printed: {printed}"
            );
        }
    }
}

#[test]
fn the_chain_is_kept_whole_so_a_client_can_build_a_path() {
    // A leaf on its own verifies only where the intermediate is already
    // installed, which is not something a load balancer may assume.
    let (leaf, key_pem) = issue("one");
    let (intermediate, _) = issue("intermediate");
    let loaded = Loaded::load(
        "a",
        &CertificateMaterial {
            chain_pem: format!("{leaf}{intermediate}"),
            key_pem,
        },
    )
    .expect("it must load");

    assert_eq!(loaded.intermediates().len(), 1, "the chain lost a link");
    assert_eq!(
        loaded
            .leaf()
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|entry| entry.data().as_utf8().ok())
            .map(|name| name.to_string())
            .as_deref(),
        Some("one"),
        "the leaf is not the first certificate in the chain"
    );
}

#[test]
fn a_frontend_that_terminates_no_tls_holds_no_certificates() {
    let mut config = document(&["a"], None, vec![certificate("a", &["one.example.test"])]);
    config.frontends[0].tls = None;

    let set = Certificates::build(
        &config,
        &BTreeMap::from([(CertificateId::new("a"), material("one"))]),
    );

    assert_eq!(set.count("web"), 0);
    assert_eq!(served(&set, Some("one.example.test")), None);
}
