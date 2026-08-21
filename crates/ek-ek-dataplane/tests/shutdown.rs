// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How long a process takes to leave once it has been asked to.
//!
//! The two rules here cannot be measured with one frontend and one process:
//! whether the process waits for every UDP frontend rather than the first,
//! and whether pingora's own five minute default was replaced at all. Both
//! are decisions made before anything is bound, so they are measured where
//! they are made (ADR-0067).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{
    ApplicationProtocol, Config, Frontend, FrontendId, Http2, ProxyProtocol, SchemaVersion,
    TransportProtocol, Vip, VipId,
};
use ek_ek_dataplane::{DrainCount, shutdown_conf};

/// One frontend that asks for a drain window of `drain` seconds.
fn frontend(name: &str, port: u16, drain: u32) -> Frontend {
    Frontend {
        id: FrontendId::new(name),
        vip: VipId::new("vip"),
        port,
        transport: TransportProtocol::Udp,
        application: ApplicationProtocol::Raw,
        tls: None,
        proxy_protocol: ProxyProtocol::Disabled,
        routing_rules: Vec::new(),
        sni_rules: Vec::new(),
        default_backend: None,
        http2: Http2::Enabled,
        connect_timeout_seconds: 2,
        request_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        drain_timeout_seconds: drain,
        udp_session_limit: 0,
    }
}

/// A configuration carrying nothing but the frontends given.
fn document(frontends: Vec<Frontend>) -> Config {
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
        frontends,
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        stickiness_key: String::new(),
    }
}

#[test]
fn the_grace_period_is_the_longest_drain_any_frontend_asks_for() {
    // Anything shorter would cut the frontend that asked for the longest
    // window while it was still carrying sessions.
    let conf = shutdown_conf(&document(vec![
        frontend("dns", 5_301, 7),
        frontend("syslog", 5_302, 20),
        frontend("ntp", 5_303, 3),
    ]));

    assert_eq!(
        conf.grace_period_seconds,
        Some(20),
        "the grace period did not cover the longest drain window"
    );
}

#[test]
fn pingora_never_keeps_its_own_grace_period() {
    // Left unset, pingora sleeps five minutes after it has told its services
    // to stop, so a replaced process piles up behind its replacement (R-05).
    // Every configuration must therefore name a period of its own, including
    // one that asks for no drain at all.
    let none = shutdown_conf(&document(Vec::new()));
    let zero = shutdown_conf(&document(vec![frontend("dns", 5_311, 0)]));

    assert!(
        none.grace_period_seconds.is_some(),
        "a configuration with no frontend left pingora's default in place"
    );
    assert!(
        zero.grace_period_seconds.is_some(),
        "a frontend asking for no drain left pingora's default in place"
    );
    assert_eq!(none.grace_period_seconds, Some(1));
    assert_eq!(zero.grace_period_seconds, Some(1));

    // The number pingora would have used on its own, for contrast.
    let default = pingora::server::configuration::ServerConf::default();
    assert_eq!(
        default.grace_period_seconds, None,
        "pingora's default changed, so what this guards against has moved"
    );
}

#[test]
fn the_runtimes_get_a_window_of_their_own_to_unwind() {
    let conf = shutdown_conf(&document(vec![frontend("dns", 5_321, 30)]));

    assert_eq!(
        conf.graceful_shutdown_timeout_seconds,
        Some(5),
        "the runtime shutdown window was left to pingora"
    );
}

#[test]
fn a_process_waits_for_every_udp_frontend_not_just_the_first() {
    // With two frontends, the first to drain must not take the process down
    // while the second is still carrying sessions.
    let count = DrainCount::new(2, true);

    assert!(
        !count.finished(),
        "the process left as soon as the first frontend had drained"
    );
    assert!(
        count.finished(),
        "the process did not leave once the last frontend had drained"
    );
}

#[test]
fn a_lone_udp_frontend_takes_the_process_with_it() {
    // The other side of the same rule.
    let count = DrainCount::new(1, true);

    assert!(
        count.finished(),
        "the process stayed after its only frontend had drained"
    );
}

#[test]
fn a_process_that_also_listens_on_tcp_never_leaves_early() {
    // Open TCP connections are pingora's to close, and cutting them to save
    // a few seconds of grace period would lose requests in flight.
    let count = DrainCount::new(1, false);

    assert!(
        !count.finished(),
        "a process carrying TCP left as soon as its UDP frontend had drained"
    );

    let two = DrainCount::new(2, false);
    assert!(!two.finished());
    assert!(
        !two.finished(),
        "a process carrying TCP left after its last UDP frontend"
    );
}
