// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the templates must produce, and what they must refuse to produce.
//!
//! A template's whole value is that an operator does not have to know what it
//! knows. So every test here checks the property the operator is trusting,
//! not that a function returned something: that ActiveSync gets an hour, that
//! the NTLM pool opens a connection per request, that the relay passes the
//! client address on.
//!
//! Every rule is measured from both sides. Showing a template produces a
//! working config proves nothing on its own if applying it over an address
//! already in use would also succeed.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::template::{
    Applied, Argument, Arguments, CreatedKind, ParameterKind, Verification, apply, embedded,
    embedded_by_id, from_frontend, undo,
};
use ek_ek_config::{
    AdminState, ApplicationProtocol, Backend, BackendId, BackendMember, Config, ConnectionPooling,
    ErrorCode, Frontend, FrontendId, LoadBalancingAlgorithm, MemberId, Node, NodeId, NodeRole,
    ProxyProtocol, SchemaVersion, TemplateId, TransportProtocol, validate,
};

/// A config with two nodes and nothing published yet.
fn empty_cluster() -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: vec![
            Node {
                id: NodeId::new("node1"),
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)),
                roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
            },
            Node {
                id: NodeId::new("node2"),
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12)),
                roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
            },
        ],
        vips: Vec::new(),
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
    }
}

fn members() -> Vec<BackendMember> {
    (1..=2_u8)
        .map(|number| BackendMember {
            id: MemberId::new(format!("srv{number}")),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20 + number)),
            port: 80,
            weight: 1,
            admin_state: AdminState::Enabled,
        })
        .collect()
}

/// The values every template asks for, plus whatever a specific one adds.
fn arguments(name: &str) -> Arguments {
    Arguments::new()
        .with("name", Argument::Text(name.to_owned()))
        .with(
            "address",
            Argument::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100))),
        )
        .with("interface", Argument::Text("eth0".to_owned()))
        .with("node", Argument::Node(NodeId::new("node1")))
        .with("members", Argument::Members(members()))
}

fn run(id: &str, arguments: Arguments) -> Applied {
    let template = embedded_by_id(&TemplateId::new(id)).expect("the template must ship");
    apply(&template, &empty_cluster(), &arguments)
        .unwrap_or_else(|errors| panic!("{id} must apply cleanly: {:?}", errors.codes()))
}

fn frontend<'a>(applied: &'a Applied, id: &str) -> &'a Frontend {
    applied
        .config
        .frontends
        .iter()
        .find(|frontend| frontend.id.as_str() == id)
        .unwrap_or_else(|| {
            panic!(
                "frontend {id} is missing; there are {:?}",
                applied
                    .config
                    .frontends
                    .iter()
                    .map(|frontend| frontend.id.as_str())
                    .collect::<Vec<_>>()
            )
        })
}

fn backend<'a>(applied: &'a Applied, id: &BackendId) -> &'a Backend {
    applied
        .config
        .backends
        .iter()
        .find(|backend| &backend.id == id)
        .unwrap_or_else(|| panic!("backend {} is missing", id.as_str()))
}

// --- Criterion: the website template ---------------------------------------

#[test]
fn the_website_template_publishes_https_with_a_pool_and_a_health_check() {
    let applied = run(
        "website",
        arguments("shop").with("domain", Argument::Text("shop.example.org".to_owned())),
    );

    let listener = frontend(&applied, "shop-https");
    assert_eq!(listener.port, 443);
    assert_eq!(listener.transport, TransportProtocol::Tcp);
    assert_eq!(listener.application, ApplicationProtocol::Http);

    let tls = listener.tls.as_ref().expect("HTTPS needs TLS settings");
    assert_eq!(tls.certificates.len(), 1, "a certificate must be offered");

    let certificate = applied
        .config
        .certificates
        .iter()
        .find(|certificate| certificate.id == tls.certificates[0])
        .expect("the certificate must be in the config");
    assert_eq!(
        certificate.sni_names,
        vec!["shop.example.org".to_owned()],
        "the certificate must cover the domain that was asked for"
    );

    let pool = backend(
        &applied,
        listener
            .default_backend
            .as_ref()
            .expect("traffic must have somewhere to go"),
    );
    assert_eq!(pool.members.len(), 2);
    let check = pool
        .health_check
        .as_ref()
        .expect("a member that stops answering must leave the pool");
    assert!(
        matches!(&check.probe, ek_ek_config::HealthProbe::Http { .. }),
        "a web pool is checked over HTTP, not by opening a socket: {:?}",
        check.probe
    );
}

// --- Criterion: the DNS template -------------------------------------------

#[test]
fn the_dns_template_publishes_udp_and_tcp_on_one_address_and_port() {
    let applied = run("dns", arguments("resolver"));

    let udp = frontend(&applied, "resolver-udp");
    let tcp = frontend(&applied, "resolver-tcp");

    assert_eq!(udp.transport, TransportProtocol::Udp);
    assert_eq!(tcp.transport, TransportProtocol::Tcp);
    assert_eq!(udp.port, 53);
    assert_eq!(tcp.port, 53);
    assert_eq!(
        udp.vip, tcp.vip,
        "both have to be the same address, or a resolver falling back to TCP \
         reaches somewhere else (ADR-0016)"
    );

    // Two listeners on one address and port is exactly what validation
    // rejects when the transport is the same, so the pair only holds because
    // the transports differ.
    assert!(validate(&applied.config).is_ok());
}

#[test]
fn the_dns_pool_hashes_consistently_and_asks_a_real_question() {
    let applied = run("dns", arguments("resolver"));
    let listener = frontend(&applied, "resolver-udp");
    let pool = backend(&applied, listener.default_backend.as_ref().expect("a pool"));

    assert_eq!(
        pool.algorithm,
        LoadBalancingAlgorithm::ConsistentHash,
        "the UDP path needs two processes to pick the same member during an \
         upgrade (ADR-0025)"
    );
    assert!(
        matches!(
            pool.health_check.as_ref().map(|check| &check.probe),
            Some(ek_ek_config::HealthProbe::DnsQuery { .. })
        ),
        "a name server with a broken zone still accepts connections, so a \
         connect probe would call it healthy"
    );
    assert_eq!(
        pool.members[0].port, 53,
        "the members answer on the DNS port, not on the one they were entered with"
    );
}

// --- Criterion: the Exchange template --------------------------------------

#[test]
fn the_exchange_template_produces_four_paths_and_four_pools() {
    let applied = run(
        "exchange",
        arguments("mail").with("domain", Argument::Text("mail.example.org".to_owned())),
    );

    let listener = frontend(&applied, "mail-https");
    assert_eq!(
        listener.routing_rules.len(),
        4,
        "OWA, ActiveSync, EWS and MAPI each need their own rule"
    );

    let paths: Vec<&str> = listener
        .routing_rules
        .iter()
        .filter_map(|rule| rule.path_prefix.as_deref())
        .collect();
    for expected in ["/Microsoft-Server-ActiveSync", "/mapi", "/ews", "/owa"] {
        assert!(
            paths.contains(&expected),
            "{expected} is not routed: {paths:?}"
        );
    }

    let pools: Vec<&BackendId> = listener
        .routing_rules
        .iter()
        .map(|rule| &rule.backend)
        .collect();
    let distinct: std::collections::BTreeSet<&&BackendId> = pools.iter().collect();
    assert_eq!(
        distinct.len(),
        4,
        "the four paths differ in timeout and pooling, so they cannot share a pool"
    );
}

#[test]
fn the_activesync_rule_holds_a_request_open_for_at_least_half_an_hour() {
    let applied = run(
        "exchange",
        arguments("mail").with("domain", Argument::Text("mail.example.org".to_owned())),
    );
    let listener = frontend(&applied, "mail-https");

    let activesync = listener
        .routing_rules
        .iter()
        .find(|rule| rule.path_prefix.as_deref() == Some("/Microsoft-Server-ActiveSync"))
        .expect("ActiveSync must be routed");
    let timeout = activesync
        .request_timeout_seconds
        .expect("push email cannot run on the frontend default");
    assert!(
        timeout >= 1_800,
        "push email holds the request open; {timeout}s turns push into polling"
    );

    // Measured against another rule, so the value above is a decision rather
    // than one number applied everywhere.
    let owa = listener
        .routing_rules
        .iter()
        .find(|rule| rule.path_prefix.as_deref() == Some("/owa"))
        .expect("OWA must be routed");
    assert!(
        owa.request_timeout_seconds.unwrap_or(0) < timeout,
        "OWA runs in minutes and must not wait as long as ActiveSync"
    );
}

#[test]
fn the_mapi_pool_opens_a_connection_per_request() {
    let applied = run(
        "exchange",
        arguments("mail").with("domain", Argument::Text("mail.example.org".to_owned())),
    );
    let listener = frontend(&applied, "mail-https");

    let mapi = listener
        .routing_rules
        .iter()
        .find(|rule| rule.path_prefix.as_deref() == Some("/mapi"))
        .expect("MAPI must be routed");
    assert_eq!(
        backend(&applied, &mapi.backend).connection_pooling,
        ConnectionPooling::Disabled,
        "NTLM binds authentication to the connection; reusing one serves \
         another user's request under the wrong identity (ADR-0045)"
    );

    // And only that pool pays the cost, so the setting is a decision about
    // NTLM rather than a blanket one.
    let owa = listener
        .routing_rules
        .iter()
        .find(|rule| rule.path_prefix.as_deref() == Some("/owa"))
        .expect("OWA must be routed");
    assert_eq!(
        backend(&applied, &owa.backend).connection_pooling,
        ConnectionPooling::Enabled
    );
}

// --- Criterion: the SMTP relay template ------------------------------------

#[test]
fn the_smtp_relay_passes_the_client_address_to_the_backend() {
    let applied = run("smtp_relay", arguments("relay"));
    let listener = frontend(&applied, "relay-smtp");

    assert_ne!(
        listener.proxy_protocol,
        ProxyProtocol::Disabled,
        "a relay decides who may send by client address; without the header \
         it sees only us and relays for everyone or for nobody (ADR-0043)"
    );
    assert_eq!(listener.port, 25);
    assert_eq!(listener.transport, TransportProtocol::Tcp);

    // Measured against a template where it must stay off, because a backend
    // that does not expect the header refuses the connection.
    let plain = run(
        "generic_tcp",
        arguments("db").with("port", Argument::Port(5432)),
    );
    assert_eq!(
        frontend(&plain, "db-tcp").proxy_protocol,
        ProxyProtocol::Disabled
    );
}

// --- Criterion: the plain TCP template -------------------------------------

#[test]
fn the_plain_tcp_template_produces_one_listener_and_one_pool() {
    let applied = run(
        "generic_tcp",
        arguments("db").with("port", Argument::Port(5432)),
    );

    assert_eq!(applied.config.frontends.len(), 1);
    assert_eq!(applied.config.backends.len(), 1);
    assert_eq!(frontend(&applied, "db-tcp").port, 5432);
    assert!(
        applied.config.certificates.is_empty(),
        "a skeleton carries nothing it was not asked for"
    );
}

// --- Criterion: every template carries a verification state ----------------

#[test]
fn every_shipped_template_says_whether_it_was_verified() {
    let shipped = embedded();
    assert_eq!(shipped.len(), 5, "ADR-0046 lists exactly five");

    let catalog = ek_ek_config::Catalog::embedded().expect("the catalogue must be readable");
    for template in &shipped {
        for language in ["en", "tr"] {
            for key in [
                template.name_key.as_str(),
                template.description_key.as_str(),
                template.verification.key(),
            ] {
                assert_ne!(
                    catalog.text(language, key),
                    key,
                    "{language}: '{key}' has no text, so the gallery would show its own key"
                );
            }
        }
        assert!(
            !template.parameters.is_empty(),
            "{} asks for nothing, so it cannot be filled in",
            template.id.as_str()
        );
    }
}

#[test]
fn the_exchange_template_is_marked_unverified() {
    let exchange = embedded_by_id(&TemplateId::new("exchange")).expect("the template must ship");
    assert_eq!(
        exchange.verification,
        Verification::Unverified,
        "its paths and timeouts rest on assumptions until T-069 measures them (R-20)"
    );

    // Measured from the other side: a template that has been tried says so,
    // or the state carries no information at all.
    let website = embedded_by_id(&TemplateId::new("website")).expect("the template must ship");
    assert!(matches!(
        website.verification,
        Verification::Verified { .. }
    ));
}

// --- Criterion: applying goes through validation ---------------------------

#[test]
fn a_vip_and_port_already_in_use_stops_the_template_with_a_field_error() {
    // First application succeeds and takes the address.
    let first = run(
        "website",
        arguments("shop").with("domain", Argument::Text("a.example.org".to_owned())),
    );

    // The second one asks for the same address and the same port.
    let template = embedded_by_id(&TemplateId::new("website")).expect("the template must ship");
    let refused = apply(
        &template,
        &first.config,
        &arguments("shop").with("domain", Argument::Text("b.example.org".to_owned())),
    )
    .expect_err("the address and port are taken");

    assert!(
        refused.contains(ErrorCode::DuplicateId)
            || refused.contains(ErrorCode::FrontendDuplicateBinding),
        "the operator must see the ordinary field error, not a template one: {:?}",
        refused.codes()
    );
    for error in refused.as_slice() {
        assert!(
            !error.path.is_empty(),
            "an error must name the field it blames: {error:?}"
        );
    }

    // The first config is untouched, so a refused application costs nothing.
    assert!(validate(&first.config).is_ok());
}

#[test]
fn a_missing_or_mistyped_parameter_is_reported_before_anything_is_built() {
    let template = embedded_by_id(&TemplateId::new("website")).expect("the template must ship");

    let refused = apply(&template, &empty_cluster(), &Arguments::new())
        .expect_err("a template with no values cannot build anything");
    assert!(refused.contains(ErrorCode::TemplateParameterMissing));
    assert_eq!(
        refused.len(),
        template.parameters.len(),
        "every missing value is reported at once, not one per submission"
    );

    // A value of the wrong kind is a different fault from a missing one.
    let mistyped = arguments("shop")
        .with("domain", Argument::Port(443))
        .with("name", Argument::Text("shop".to_owned()));
    let refused =
        apply(&template, &empty_cluster(), &mistyped).expect_err("a port is not a domain name");
    assert!(refused.contains(ErrorCode::TemplateParameterWrongKind));

    // And a value nothing declares is caught from the other side, so a typed
    // parameter name cannot silently do nothing.
    let extra = arguments("shop")
        .with("domain", Argument::Text("shop.example.org".to_owned()))
        .with("wieght", Argument::Port(1));
    let refused =
        apply(&template, &empty_cluster(), &extra).expect_err("nothing declares 'wieght'");
    assert!(refused.contains(ErrorCode::TemplateParameterUnknown));
}

#[test]
fn every_shipped_template_produces_a_config_that_validates() {
    for template in embedded() {
        let mut values = arguments("svc");
        for parameter in &template.parameters {
            if parameter.kind == ParameterKind::Text && parameter.name == "domain" {
                values = values.with("domain", Argument::Text("svc.example.org".to_owned()));
            }
            if parameter.kind == ParameterKind::Port {
                values = values.with(&parameter.name, Argument::Port(5432));
            }
        }

        let applied = apply(&template, &empty_cluster(), &values).unwrap_or_else(|errors| {
            panic!(
                "{} must produce a valid config: {:?}",
                template.id.as_str(),
                errors.codes()
            )
        });
        assert!(validate(&applied.config).is_ok());
    }
}

// --- Criterion: preview, undo and no tie to the template -------------------

#[test]
fn applying_lists_what_it_creates_before_anything_is_written() {
    let applied = run(
        "exchange",
        arguments("mail").with("domain", Argument::Text("mail.example.org".to_owned())),
    );

    // What the preview claims is exactly what the config gained, so the
    // operator approves the thing that is stored.
    let created_frontends: Vec<&str> = applied
        .created
        .iter()
        .filter(|object| object.kind == CreatedKind::Frontend)
        .map(|object| object.id.as_str())
        .collect();
    let in_config: Vec<&str> = applied
        .config
        .frontends
        .iter()
        .map(|frontend| frontend.id.as_str())
        .collect();
    assert_eq!(created_frontends, in_config);

    assert_eq!(
        applied
            .created
            .iter()
            .filter(|object| object.kind == CreatedKind::Vip)
            .count(),
        1
    );
    assert!(
        applied.created.len() > 5,
        "Exchange creates a VIP, three listeners and six pools: {:?}",
        applied.created
    );
}

#[test]
fn undoing_removes_everything_the_template_created_in_one_step() {
    let before = empty_cluster();
    let template = embedded_by_id(&TemplateId::new("exchange")).expect("the template must ship");
    let applied = apply(
        &template,
        &before,
        &arguments("mail").with("domain", Argument::Text("mail.example.org".to_owned())),
    )
    .expect("it must apply");

    let after = undo(&applied.config, &applied.created);
    assert_eq!(after, before, "undoing must leave exactly what was there");

    // Measured from the other side: undoing with an empty list removes
    // nothing, so the removal above came from the list and not from undo
    // clearing the config.
    assert_eq!(undo(&applied.config, &[]), applied.config);
}

#[test]
fn nothing_produced_refers_back_to_the_template() {
    let applied = run(
        "exchange",
        arguments("mail").with("domain", Argument::Text("mail.example.org".to_owned())),
    );
    let document = serde_json::to_string(&applied.config).expect("the config must serialise");

    for trace in ["template", "exchange"] {
        assert!(
            !document.contains(trace),
            "'{trace}' survives in the config, so it is tied to the template it came from"
        );
    }

    // The result is an ordinary config: it round trips through the same
    // format a hand written one does.
    let reread: Config = serde_json::from_str(&document).expect("it must read back");
    assert_eq!(reread, applied.config);
}

// --- Criterion: a user template carries structure and no key material ------

#[test]
fn a_user_template_is_made_from_a_frontend_and_its_pools() {
    let applied = run(
        "exchange",
        arguments("mail").with("domain", Argument::Text("mail.example.org".to_owned())),
    );

    let saved = from_frontend(
        &applied.config,
        &FrontendId::new("mail-https"),
        "Our Exchange layout",
    )
    .expect("the frontend is there");

    assert_eq!(saved.name, "Our Exchange layout");
    assert_eq!(saved.frontend.routing_rules.len(), 4);
    assert_eq!(
        saved.backends.len(),
        4,
        "every pool the frontend reaches has to travel with it: {:?}",
        saved
            .backends
            .iter()
            .map(|backend| backend.id.as_str())
            .collect::<Vec<_>>()
    );

    // A frontend that is not there is refused rather than saved as an empty
    // template.
    assert!(from_frontend(&applied.config, &FrontendId::new("nothing"), "x").is_err());
}

#[test]
fn a_user_template_carries_no_certificate_and_no_key_material() {
    let applied = run(
        "website",
        arguments("shop").with("domain", Argument::Text("shop.example.org".to_owned())),
    );

    // The config it is made from does reference a certificate, so the
    // stripping below is measured against something that was there.
    let source = applied
        .config
        .frontends
        .iter()
        .find(|frontend| frontend.id.as_str() == "shop-https")
        .expect("the listener is there");
    assert_eq!(
        source
            .tls
            .as_ref()
            .map(|tls| tls.certificates.len())
            .unwrap_or(0),
        1
    );

    let saved = from_frontend(
        &applied.config,
        &FrontendId::new("shop-https"),
        "Web layout",
    )
    .expect("the frontend is there");
    assert!(
        saved
            .frontend
            .tls
            .as_ref()
            .is_some_and(|tls| tls.certificates.is_empty()),
        "a template must not carry a certificate reference"
    );

    let document = serde_json::to_string(&saved).expect("it must serialise");
    for trace in ["cert-", "private_key", "secret"] {
        assert!(
            !document.contains(trace),
            "'{trace}' travels with the template, which moves key material \
             along a path nobody meant to open"
        );
    }
}
