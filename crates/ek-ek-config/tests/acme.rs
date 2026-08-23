// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a configuration has to say before a certificate can be ordered.
//!
//! Every rule is measured from both sides: the document that is missing
//! something is told so, and the document that has it is left alone. A check
//! that only ever fires is a check that would refuse a working installation.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use ek_ek_config::{
    AcmeSettings, ApplicationProtocol, Certificate, CertificateId, CertificateSource, Config,
    Frontend, FrontendId, Http2, ProxyProtocol, TransportProtocol, VipId, WarningCode, acme_faults,
    http01_listener, inspect, validate,
};

/// A configuration with one ACME certificate and a listener that can answer.
fn ordering() -> Config {
    let mut config = common::sample();
    config.certificates = vec![Certificate {
        id: CertificateId::new("cert-site"),
        sni_names: vec!["www.example.org".to_owned()],
        source: CertificateSource::AcmeHttp01,
        validity: None,
        chain: None,
        private_key: None,
    }];
    config.dns_providers.clear();
    // The frontends the fixture carries offer the certificate it used to
    // define, so they are replaced by one plain listener on port 80.
    config.frontends = vec![plain(80)];
    config.backends = vec![common::web_backend()];
    config.acme = Some(AcmeSettings {
        directory_url: "https://acme.example.org/directory".to_owned(),
        contact_email: "yonetici@example.org".to_owned(),
        accepted_terms: true,
        trusted_root_pem: String::new(),
    });
    config
}

/// A plaintext HTTP frontend on a port.
fn plain(port: u16) -> Frontend {
    Frontend {
        id: FrontendId::new(format!("plain-{port}")),
        vip: VipId::new("vip-web"),
        port,
        transport: TransportProtocol::Tcp,
        application: ApplicationProtocol::Http,
        tls: None,
        proxy_protocol: ProxyProtocol::Disabled,
        access_log: Default::default(),
        routing_rules: Vec::new(),
        sni_rules: Vec::new(),
        default_backend: Some(ek_ek_config::BackendId::new("web")),
        http2: Http2::Enabled,
        connect_timeout_seconds: 5,
        request_timeout_seconds: 60,
        idle_timeout_seconds: 0,
        drain_timeout_seconds: 30,
        udp_session_limit: 0,
    }
}

fn codes(config: &Config) -> Vec<WarningCode> {
    acme_faults(config, None)
        .iter()
        .map(|warning| warning.code)
        .collect()
}

#[test]
fn a_configuration_that_can_order_is_told_nothing() {
    let config = ordering();
    assert!(validate(&config).is_ok(), "the document must be storable");
    assert!(
        codes(&config).is_empty(),
        "a working configuration was warned about: {:?}",
        codes(&config)
    );
}

#[test]
fn an_acme_certificate_without_a_server_is_named() {
    let mut config = ordering();
    config.acme = None;

    // The other side first: this is a warning, so the document is still
    // storable. An operator writes the certificate down before they have
    // decided which authority to use, and refusing that would make them do
    // both in one step (ADR-0072).
    assert!(
        validate(&config).is_ok(),
        "a missing ACME block must not refuse the document"
    );
    assert_eq!(codes(&config), vec![WarningCode::AcmeMissing]);
    assert!(
        inspect(&config, 1_800_000_000)
            .iter()
            .any(|warning| warning.code == WarningCode::AcmeMissing),
        "the fault has to reach the operator through the normal inspection"
    );
}

#[test]
fn an_uploaded_certificate_needs_no_acme_server() {
    let mut config = ordering();
    config.certificates[0].source = CertificateSource::ManualUpload;
    config.acme = None;

    assert!(
        codes(&config).is_empty(),
        "an installation that uploads its certificates was asked for an ACME server"
    );
}

#[test]
fn a_directory_that_is_not_https_is_named() {
    let mut config = ordering();
    if let Some(acme) = config.acme.as_mut() {
        acme.directory_url = "http://acme.example.org/directory".to_owned();
    }
    assert_eq!(codes(&config), vec![WarningCode::AcmeDirectoryUrlInvalid]);

    // And the other side: the same address over HTTPS is accepted.
    if let Some(acme) = config.acme.as_mut() {
        acme.directory_url = "https://acme.example.org/directory".to_owned();
    }
    assert!(codes(&config).is_empty());
}

#[test]
fn terms_nobody_accepted_are_named() {
    let mut config = ordering();
    if let Some(acme) = config.acme.as_mut() {
        acme.accepted_terms = false;
    }
    assert_eq!(codes(&config), vec![WarningCode::AcmeTermsNotAccepted]);
}

#[test]
fn http01_without_a_listener_on_port_eighty_is_named() {
    let mut config = ordering();
    config.frontends = vec![plain(8080)];

    let faults = acme_faults(&config, None);
    assert_eq!(
        faults.iter().map(|w| w.code).collect::<Vec<WarningCode>>(),
        vec![WarningCode::AcmeNoHttp01Listener]
    );
    // The certificate is named, because an operator with several has to know
    // which one cannot be obtained.
    assert_eq!(
        faults[0].parameters.get("certificate"),
        Some(&ek_ek_config::ParameterValue::Identifier(
            "cert-site".to_owned()
        ))
    );
    assert_eq!(
        faults[0].parameters.get("port"),
        Some(&ek_ek_config::ParameterValue::Number(80))
    );
}

#[test]
fn a_listener_on_port_eighty_that_terminates_tls_does_not_count() {
    let mut config = ordering();
    let mut listener = plain(80);
    listener.tls = Some(ek_ek_config::TlsSettings {
        certificates: vec![CertificateId::new("cert-site")],
        default_certificate: Some(CertificateId::new("cert-site")),
        policy: ek_ek_config::TlsPolicyLevel::Balanced,
    });
    config.frontends = vec![listener];

    assert!(
        http01_listener(&config).is_none(),
        "a TLS listener cannot answer a request the server sends in the clear"
    );
    assert_eq!(codes(&config), vec![WarningCode::AcmeNoHttp01Listener]);
}

#[test]
fn a_raw_listener_on_port_eighty_does_not_count() {
    let mut config = ordering();
    let mut listener = plain(80);
    listener.application = ApplicationProtocol::Raw;
    config.frontends = vec![listener];

    assert!(
        http01_listener(&config).is_none(),
        "a listener that does not speak HTTP cannot answer an HTTP request"
    );
}

#[test]
fn dns01_needs_no_listener_on_port_eighty() {
    let mut config = ordering();
    config.frontends = vec![plain(8080)];
    config.certificates[0].source = CertificateSource::AcmeDns01 {
        provider: ek_ek_config::DnsProviderId::new("dns-internal"),
    };
    config.dns_providers = common::sample().dns_providers;

    assert!(
        !codes(&config).contains(&WarningCode::AcmeNoHttp01Listener),
        "a DNS-01 certificate was asked for a port 80 listener it never uses"
    );
}

#[test]
fn one_certificates_fault_does_not_stop_another_certificates_order() {
    let mut config = ordering();
    config.certificates.push(Certificate {
        id: CertificateId::new("cert-other"),
        sni_names: vec!["posta.example.org".to_owned()],
        source: CertificateSource::AcmeHttp01,
        validity: None,
        chain: None,
        private_key: None,
    });
    config.frontends = vec![plain(8080)];

    // Both are named when nothing is filtered.
    assert_eq!(acme_faults(&config, None).len(), 2);

    // Asked about one, only that one is named, so an order refuses on its own
    // problem rather than on a neighbour's.
    let only = acme_faults(&config, Some(&CertificateId::new("cert-other")));
    assert_eq!(only.len(), 1);
    assert_eq!(
        only[0].parameters.get("certificate"),
        Some(&ek_ek_config::ParameterValue::Identifier(
            "cert-other".to_owned()
        ))
    );
}

#[test]
fn every_acme_warning_has_a_translation_key() {
    for code in WarningCode::ALL {
        let key = code.key();
        assert!(
            key.contains('.')
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
            "{key} is not a translation key"
        );
    }
    // The four this task added are in the set, so a code added without being
    // listed cannot pass unnoticed.
    for code in [
        WarningCode::AcmeMissing,
        WarningCode::AcmeDirectoryUrlInvalid,
        WarningCode::AcmeTermsNotAccepted,
        WarningCode::AcmeNoHttp01Listener,
    ] {
        assert!(WarningCode::ALL.contains(&code), "{code:?} is not in ALL");
    }
}

#[test]
fn the_acme_block_survives_a_write_and_a_read() {
    let config = ordering();
    let written = serde_json::to_string(&config).expect("a configuration writes out");
    let read: Config = serde_json::from_str(&written).expect("and reads back");
    assert_eq!(read.acme, config.acme);

    // A document written before this field existed still reads, because an
    // upgrade is rolling and a node will meet one (ADR-0019).
    let without = written.replace(
        &format!(r#""acme":{}"#, serde_json::to_string(&config.acme).unwrap()),
        r#""acme":null"#,
    );
    let read: Config = serde_json::from_str(&without).expect("an older document reads");
    assert_eq!(read.acme, None);
}

#[test]
fn a_wildcard_ordered_with_http_validation_is_told_it_needs_dns() {
    let mut config = ordering();
    config.certificates[0].sni_names = vec!["*.example.org".to_owned()];

    assert!(
        codes(&config).contains(&WarningCode::AcmeWildcardNeedsDns01),
        "a wildcard is never issued against an HTTP-01 authorization, so this order can only fail"
    );
}

#[test]
fn a_wildcard_ordered_with_dns_validation_is_left_alone() {
    let mut config = ordering();
    config.certificates[0].sni_names = vec!["*.example.org".to_owned()];
    config.certificates[0].source = CertificateSource::AcmeDns01 {
        provider: ek_ek_config::DnsProviderId::new("dns-internal"),
    };
    config.dns_providers = common::sample().dns_providers;

    assert!(
        !codes(&config).contains(&WarningCode::AcmeWildcardNeedsDns01),
        "this is exactly what DNS-01 is for"
    );
}

#[test]
fn a_name_with_a_star_further_along_is_not_a_wildcard() {
    let mut config = ordering();
    // Not a wildcard and not a name either, but it is not this rule's job to
    // say so: matching it here would report the wrong cause.
    config.certificates[0].sni_names = vec!["www.*.example.org".to_owned()];

    assert!(!codes(&config).contains(&WarningCode::AcmeWildcardNeedsDns01));
}

#[test]
fn an_ordinary_name_is_never_called_a_wildcard() {
    assert!(!codes(&ordering()).contains(&WarningCode::AcmeWildcardNeedsDns01));
}
