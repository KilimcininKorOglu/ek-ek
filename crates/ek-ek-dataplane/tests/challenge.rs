// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the traffic path answers on the ACME challenge path.
//!
//! Both sides of every rule: what is answered while an order is waiting, and
//! what is answered when none is. A path that is open all the time tells
//! anybody who asks whether a token is live, and a path that is never open
//! means no certificate is ever obtained.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use ek_ek_config::HTTP01_PORT;
use ek_ek_dataplane::challenge::{PREFIX, Reply, reply};

const TOKEN: &str = "tokenTOKENtoken";
const ANSWER: &str = "tokenTOKENtoken.thumbprint";

fn waiting() -> BTreeMap<String, String> {
    let mut challenges = BTreeMap::new();
    challenges.insert(TOKEN.to_owned(), ANSWER.to_owned());
    challenges
}

fn idle() -> BTreeMap<String, String> {
    BTreeMap::new()
}

#[test]
fn the_token_an_order_is_waiting_on_is_answered() {
    assert_eq!(
        reply(&waiting(), HTTP01_PORT, &format!("{PREFIX}{TOKEN}")),
        Reply::Answer(ANSWER)
    );
}

#[test]
fn nothing_is_answered_when_no_order_is_waiting() {
    assert_eq!(
        reply(&idle(), HTTP01_PORT, &format!("{PREFIX}{TOKEN}")),
        Reply::Unknown,
        "the same token was answered outside an order"
    );
}

#[test]
fn a_token_no_order_is_waiting_on_is_not_answered() {
    assert_eq!(
        reply(&waiting(), HTTP01_PORT, &format!("{PREFIX}somethingelse")),
        Reply::Unknown
    );
}

#[test]
fn the_path_is_only_taken_from_routing_on_the_port_the_server_asks_on() {
    // The server connects to port 80 and nowhere else. On any other listener
    // the path routes like any other, so a rule an operator wrote for it still
    // applies.
    for port in [443_u16, 8080, 81] {
        assert_eq!(
            reply(&waiting(), port, &format!("{PREFIX}{TOKEN}")),
            Reply::Elsewhere,
            "port {port} took the path away from routing"
        );
    }
    // And the other side, so this is measuring the port rather than always
    // saying `Elsewhere`.
    assert_eq!(
        reply(&waiting(), HTTP01_PORT, &format!("{PREFIX}{TOKEN}")),
        Reply::Answer(ANSWER)
    );
}

#[test]
fn any_other_path_is_left_to_routing() {
    for path in ["/", "/owa", "/.well-known/", "/.well-known/other/x"] {
        assert_eq!(
            reply(&waiting(), HTTP01_PORT, path),
            Reply::Elsewhere,
            "{path} was taken away from routing"
        );
    }
}

#[test]
fn the_bare_challenge_path_names_no_token() {
    assert_eq!(reply(&waiting(), HTTP01_PORT, PREFIX), Reply::Unknown);
}

#[test]
fn a_deeper_path_under_the_prefix_names_no_token() {
    assert_eq!(
        reply(&waiting(), HTTP01_PORT, &format!("{PREFIX}{TOKEN}/more")),
        Reply::Unknown,
        "a token is one path component"
    );
}

#[test]
fn climbing_out_of_the_challenge_path_reaches_nothing() {
    // Normalisation runs first, so this is `/x` by the time it is matched and
    // it never looks like a token (ADR-0071).
    assert_eq!(
        reply(
            &waiting(),
            HTTP01_PORT,
            "/.well-known/acme-challenge/../../x"
        ),
        Reply::Elsewhere
    );
}

#[test]
fn a_percent_encoded_separator_does_not_hide_a_deeper_path() {
    assert_eq!(
        reply(
            &waiting(),
            HTTP01_PORT,
            &format!("/.well-known/acme-challenge%2f{TOKEN}")
        ),
        Reply::Answer(ANSWER),
        "the encoded separator is decoded once and the path is the same one"
    );
}

#[test]
fn a_query_string_is_not_part_of_the_token() {
    assert_eq!(
        reply(
            &waiting(),
            HTTP01_PORT,
            &format!("{PREFIX}{TOKEN}?anything=here")
        ),
        Reply::Answer(ANSWER)
    );
}

#[test]
fn the_token_is_matched_exactly() {
    // Case matters: a token is drawn at random by the server and compared
    // byte for byte, unlike a host name.
    assert_eq!(
        reply(
            &waiting(),
            HTTP01_PORT,
            &format!("{PREFIX}{}", TOKEN.to_uppercase())
        ),
        Reply::Unknown
    );
    // And a prefix of a live token is not the token.
    assert_eq!(
        reply(&waiting(), HTTP01_PORT, &format!("{PREFIX}token")),
        Reply::Unknown
    );
}

#[test]
fn each_of_several_live_tokens_gets_its_own_answer() {
    let mut challenges = waiting();
    challenges.insert("second".to_owned(), "second.thumbprint".to_owned());

    assert_eq!(
        reply(&challenges, HTTP01_PORT, &format!("{PREFIX}{TOKEN}")),
        Reply::Answer(ANSWER)
    );
    assert_eq!(
        reply(&challenges, HTTP01_PORT, &format!("{PREFIX}second")),
        Reply::Answer("second.thumbprint")
    );
}

#[test]
fn the_delivery_decides_what_is_live() {
    use ek_ek_ipc::ConfigUpdate;

    let mut update = ConfigUpdate {
        generation: 1,
        config: common_config(),
        certificates: BTreeMap::new(),
        challenges: waiting(),
    };
    let live = ek_ek_dataplane::LiveConfig::new(update.clone());
    assert_eq!(live.load().challenges, waiting());

    // The next delivery takes it away, which is how the path closes.
    update.generation = 2;
    update.challenges = idle();
    live.apply(update).expect("the configuration is valid");
    assert!(
        live.load().challenges.is_empty(),
        "the path stayed open after the delivery that closed it"
    );
}

/// A configuration that validates and listens on port 80.
fn common_config() -> ek_ek_config::Config {
    use ek_ek_config::{
        ApplicationProtocol, Backend, BackendId, BackendMember, ConnectionPooling, Frontend,
        FrontendId, Http2, LoadBalancingAlgorithm, MemberId, ProxyProtocol, SchemaVersion,
        TransportProtocol, Vip, VipId,
    };

    ek_ek_config::Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: Vec::new(),
        vips: vec![Vip {
            id: VipId::new("vip-web"),
            address: "127.0.0.1".parse().expect("an address"),
            prefix_length: 32,
            interface: "lo".to_owned(),
            preferred_node: None,
        }],
        frontends: vec![Frontend {
            id: FrontendId::new("plain"),
            vip: VipId::new("vip-web"),
            port: HTTP01_PORT,
            transport: TransportProtocol::Tcp,
            application: ApplicationProtocol::Http,
            tls: None,
            proxy_protocol: ProxyProtocol::Disabled,
            access_log: Default::default(),
            routing_rules: Vec::new(),
            sni_rules: Vec::new(),
            default_backend: Some(BackendId::new("web")),
            http2: Http2::Enabled,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 60,
            idle_timeout_seconds: 0,
            drain_timeout_seconds: 30,
            udp_session_limit: 0,
        }],
        backends: vec![Backend {
            id: BackendId::new("web"),
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            members: vec![BackendMember {
                id: MemberId::new("one"),
                address: "127.0.0.1".parse().expect("an address"),
                port: 8080,
                weight: 1,
                admin_state: ek_ek_config::AdminState::Enabled,
            }],
            health_check: None,
            stickiness: ek_ek_config::SessionStickiness::Disabled,
            connection_pooling: ConnectionPooling::Enabled,
            connection_pool_size: 0,
            connection_lifetime_seconds: 0,
        }],
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        acme: None,
        stickiness_key: String::new(),
        log_level: Default::default(),
        certificate_expiry_warning_days: 30,
    }
}
