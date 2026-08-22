// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which rule a request falls under.
//!
//! The traffic is measured against the real binary in `ek-ek`. What is
//! measured here is the matching itself, one rule at a time, because a path
//! normalisation gap turns into a way around a path-based split and every
//! shape of it has to be tried.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ek_ek_config::{
    ApplicationProtocol, BackendId, Config, ConnectionPooling, Frontend, FrontendId, Http2,
    PathCase, ProxyProtocol, RedirectStatus, RoutingRule, RuleAction, SchemaVersion,
    TransportProtocol, Vip, VipId, WarningCode, inspect,
};
use ek_ek_dataplane::route::{Decision, decide, host_matches, normalise, path_matches};
use ek_ek_dataplane::upstream;

/// A rule sending matching requests to a pool.
fn rule(host: Option<&str>, path: Option<&str>, backend: &str) -> RoutingRule {
    RoutingRule {
        host_pattern: host.map(str::to_owned),
        path_prefix: path.map(str::to_owned),
        path_case: PathCase::Insensitive,
        action: RuleAction::Proxy {
            backend: BackendId::new(backend),
        },
        request_timeout_seconds: None,
    }
}

/// A frontend carrying the rules given, with `web` as its default pool.
fn frontend(rules: Vec<RoutingRule>, default: Option<&str>) -> Frontend {
    Frontend {
        id: FrontendId::new("web"),
        vip: VipId::new("vip"),
        port: 80,
        transport: TransportProtocol::Tcp,
        application: ApplicationProtocol::Http,
        tls: None,
        proxy_protocol: ProxyProtocol::Disabled,
        access_log: Default::default(),
        routing_rules: rules,
        sni_rules: Vec::new(),
        default_backend: default.map(BackendId::new),
        http2: Http2::Enabled,
        connect_timeout_seconds: 2,
        request_timeout_seconds: 5,
        idle_timeout_seconds: 0,
        drain_timeout_seconds: 5,
        udp_session_limit: 0,
    }
}

/// Which pool a request lands in, or nothing.
fn pool<'a>(decision: Decision<'a>) -> Option<&'a str> {
    match decision {
        Decision::Pool { name, .. } => Some(name),
        _ => None,
    }
}

/// How long a request that landed in a pool may take.
fn limit(decision: Decision<'_>) -> Option<u32> {
    match decision {
        Decision::Pool {
            request_timeout_seconds,
            ..
        } => Some(request_timeout_seconds),
        _ => None,
    }
}

// --- Path normalisation ---------------------------------------------------

#[test]
fn a_path_that_climbs_out_of_a_prefix_no_longer_matches_it() {
    // The rule this whole module exists for. Matching the raw path would let
    // `/owa/../admin` reach a pool an `/owa` rule was meant to decide
    // (ADR-0071).
    assert_eq!(normalise("/owa/../admin"), "/admin");

    let rules = vec![rule(None, Some("/owa"), "owa")];
    let web = frontend(rules, Some("web"));

    assert_eq!(pool(decide(&web, None, "/owa/../admin")), Some("web"));
    assert_eq!(pool(decide(&web, None, "/owa/auth")), Some("owa"));
}

#[test]
fn a_percent_encoded_climb_is_decoded_before_it_is_matched() {
    // `%2e%2e` is `..`, and a client sending it means exactly what a client
    // sending `..` means.
    assert_eq!(normalise("/owa/%2e%2e/admin"), "/admin");

    let web = frontend(vec![rule(None, Some("/owa"), "owa")], Some("web"));
    assert_eq!(pool(decide(&web, None, "/owa/%2e%2e/admin")), Some("web"));
}

#[test]
fn a_double_encoded_sequence_is_decoded_only_once() {
    // The other side. `%252e` decodes to `%2e`, which is a literal name and
    // not a climb. Decoding twice would hand back the way around that
    // normalising exists to close (ADR-0071).
    assert_eq!(normalise("/owa/%252e%252e/admin"), "/owa/%2e%2e/admin");

    let web = frontend(vec![rule(None, Some("/owa"), "owa")], Some("web"));
    assert_eq!(
        pool(decide(&web, None, "/owa/%252e%252e/admin")),
        Some("owa"),
        "a double encoded name was read as a climb"
    );
}

#[test]
fn normalising_removes_what_moves_nowhere() {
    assert_eq!(normalise("/owa/./auth"), "/owa/auth");
    assert_eq!(normalise("/owa//auth"), "/owa/auth");
    assert_eq!(normalise("///owa"), "/owa");
    assert_eq!(normalise("/owa/auth/.."), "/owa");
}

#[test]
fn climbing_above_the_root_stops_at_the_root() {
    assert_eq!(normalise("/../../etc/passwd"), "/etc/passwd");
    assert_eq!(normalise("/.."), "/");
    assert_eq!(normalise(".."), "/");
}

#[test]
fn a_trailing_separator_survives_normalisation() {
    // `/owa/` and `/owa` are the same to a rule but not to a backend, and the
    // backend is what receives the path.
    assert_eq!(normalise("/owa/"), "/owa/");
    assert_eq!(normalise("/owa"), "/owa");
    assert_eq!(normalise("/"), "/");
    assert_eq!(normalise(""), "/");
}

#[test]
fn the_query_string_is_not_part_of_the_path() {
    assert_eq!(normalise("/owa?a=/../admin"), "/owa");
    assert_eq!(normalise("/owa#/../admin"), "/owa");

    let web = frontend(vec![rule(None, Some("/owa"), "owa")], Some("web"));
    assert_eq!(
        pool(decide(&web, None, "/owa?redirect=/admin")),
        Some("owa")
    );
}

// --- Path prefix matching -------------------------------------------------

#[test]
fn a_prefix_matches_on_a_component_boundary_and_not_inside_a_name() {
    let web = frontend(vec![rule(None, Some("/owa"), "owa")], Some("web"));

    assert_eq!(pool(decide(&web, None, "/owa")), Some("owa"));
    assert_eq!(pool(decide(&web, None, "/owa/")), Some("owa"));
    assert_eq!(
        pool(decide(&web, None, "/owa/auth/logon.aspx")),
        Some("owa")
    );
    assert_eq!(
        pool(decide(&web, None, "/owanot")),
        Some("web"),
        "a name that only starts with the same letters was captured"
    );
}

#[test]
fn a_prefix_ending_in_a_separator_names_the_boundary_itself() {
    let web = frontend(vec![rule(None, Some("/owa/"), "owa")], Some("web"));

    assert_eq!(pool(decide(&web, None, "/owa/auth")), Some("owa"));
    assert_eq!(
        pool(decide(&web, None, "/owa")),
        Some("web"),
        "a prefix asking for the directory took the bare name too"
    );
}

#[test]
fn a_path_is_matched_case_insensitively_by_default() {
    // IIS serves paths case insensitively, so `/OWA` really does reach OWA
    // and a rule that missed it would drop the request to another pool
    // (ADR-0071).
    let web = frontend(vec![rule(None, Some("/owa"), "owa")], Some("web"));

    assert_eq!(pool(decide(&web, None, "/OWA/auth")), Some("owa"));
    assert_eq!(pool(decide(&web, None, "/Owa")), Some("owa"));
    assert!(path_matches("/owa", "/OWA", PathCase::Insensitive));
}

#[test]
fn a_rule_asking_for_case_sensitivity_gets_it() {
    // The other side. A backend serving paths case sensitively needs the
    // difference kept.
    let mut sensitive = rule(None, Some("/owa"), "owa");
    sensitive.path_case = PathCase::Sensitive;
    let web = frontend(vec![sensitive], Some("web"));

    assert_eq!(pool(decide(&web, None, "/owa/auth")), Some("owa"));
    assert_eq!(
        pool(decide(&web, None, "/OWA/auth")),
        Some("web"),
        "a case sensitive rule matched a path in another case"
    );
    assert!(!path_matches("/owa", "/OWA", PathCase::Sensitive));
}

// --- Host matching --------------------------------------------------------

#[test]
fn a_host_pattern_matches_the_name_it_names() {
    let web = frontend(
        vec![rule(Some("posta.ornek.com.tr"), None, "mail")],
        Some("web"),
    );

    assert_eq!(
        pool(decide(&web, Some("posta.ornek.com.tr"), "/")),
        Some("mail")
    );
    assert_eq!(
        pool(decide(&web, Some("baska.ornek.com.tr"), "/")),
        Some("web")
    );
}

#[test]
fn a_host_is_matched_whatever_case_it_arrives_in() {
    // DNS names are case insensitive and a client sends what the user typed.
    let web = frontend(
        vec![rule(Some("Posta.Ornek.Com.TR"), None, "mail")],
        Some("web"),
    );

    assert_eq!(
        pool(decide(&web, Some("posta.ornek.com.tr"), "/")),
        Some("mail")
    );
    assert!(host_matches("posta.ornek.com.tr", "POSTA.ORNEK.COM.TR"));
}

#[test]
fn a_host_wildcard_covers_one_label() {
    let web = frontend(
        vec![rule(Some("*.ornek.com.tr"), None, "wide")],
        Some("web"),
    );

    assert_eq!(
        pool(decide(&web, Some("posta.ornek.com.tr"), "/")),
        Some("wide")
    );
    assert_eq!(
        pool(decide(&web, Some("www.ornek.com.tr"), "/")),
        Some("wide")
    );
}

#[test]
fn a_host_wildcard_covers_neither_two_labels_nor_the_bare_name() {
    // The other side. Clients apply the same rule to a certificate, so a
    // widening here would send requests somewhere a client would refuse to
    // talk to (ADR-0071).
    let web = frontend(
        vec![rule(Some("*.ornek.com.tr"), None, "wide")],
        Some("web"),
    );

    assert_eq!(
        pool(decide(&web, Some("a.posta.ornek.com.tr"), "/")),
        Some("web"),
        "the wildcard was stretched over two labels"
    );
    assert_eq!(
        pool(decide(&web, Some("ornek.com.tr"), "/")),
        Some("web"),
        "the wildcard covered the bare name"
    );
    assert!(!host_matches("*.ornek.com.tr", ".ornek.com.tr"));
}

#[test]
fn the_port_a_host_header_carries_is_not_part_of_the_name() {
    // A client writing `ornek.com.tr:8080` asked for the same host.
    let web = frontend(
        vec![rule(Some("posta.ornek.com.tr"), None, "mail")],
        Some("web"),
    );

    assert_eq!(
        pool(decide(&web, Some("posta.ornek.com.tr:8080"), "/")),
        Some("mail")
    );
}

#[test]
fn a_rule_naming_a_host_never_takes_a_request_that_named_none() {
    // HTTP/1.0 clients send no `Host` header. A rule about a host cannot
    // decide about a request that named none.
    let web = frontend(
        vec![rule(Some("posta.ornek.com.tr"), None, "mail")],
        Some("web"),
    );

    assert_eq!(pool(decide(&web, None, "/")), Some("web"));
}

// --- Host and path together -----------------------------------------------

#[test]
fn a_rule_naming_both_applies_only_when_both_match() {
    let web = frontend(
        vec![rule(Some("posta.ornek.com.tr"), Some("/owa"), "owa")],
        Some("web"),
    );

    // Both match.
    assert_eq!(
        pool(decide(&web, Some("posta.ornek.com.tr"), "/owa/auth")),
        Some("owa")
    );
    // Host matches, path does not.
    assert_eq!(
        pool(decide(&web, Some("posta.ornek.com.tr"), "/ews")),
        Some("web"),
        "the rule applied although the path did not match"
    );
    // Path matches, host does not.
    assert_eq!(
        pool(decide(&web, Some("baska.ornek.com.tr"), "/owa/auth")),
        Some("web"),
        "the rule applied although the host did not match"
    );
    // Neither matches.
    assert_eq!(
        pool(decide(&web, Some("baska.ornek.com.tr"), "/ews")),
        Some("web")
    );
}

// --- Order ----------------------------------------------------------------

#[test]
fn the_first_matching_rule_wins_and_nothing_after_it_is_tried() {
    let web = frontend(
        vec![
            rule(None, Some("/owa"), "first"),
            rule(None, Some("/owa"), "second"),
            rule(None, Some("/owa/auth"), "more-specific"),
        ],
        Some("web"),
    );

    assert_eq!(pool(decide(&web, None, "/owa/auth")), Some("first"));
}

#[test]
fn reordering_the_list_changes_which_rule_applies() {
    // The other side of the same rule. A list whose order did not matter
    // would give the same answer here.
    let web = frontend(
        vec![
            rule(None, Some("/owa/auth"), "more-specific"),
            rule(None, Some("/owa"), "general"),
        ],
        Some("web"),
    );

    assert_eq!(pool(decide(&web, None, "/owa/auth")), Some("more-specific"));
    assert_eq!(pool(decide(&web, None, "/owa/other")), Some("general"));
}

// --- No match -------------------------------------------------------------

#[test]
fn a_request_no_rule_takes_goes_to_the_default_pool() {
    let web = frontend(vec![rule(None, Some("/owa"), "owa")], Some("web"));

    assert_eq!(pool(decide(&web, None, "/anything")), Some("web"));
}

#[test]
fn a_request_no_rule_takes_goes_nowhere_without_a_default() {
    // The other side. Nowhere is answered with a status, never with a closed
    // connection; that half is measured against the binary.
    let web = frontend(vec![rule(None, Some("/owa"), "owa")], None);

    assert_eq!(decide(&web, None, "/anything"), Decision::Nowhere);
    // And the rule that does match still works, so this is about the default
    // and not about the frontend being broken.
    assert_eq!(pool(decide(&web, None, "/owa")), Some("owa"));
}

#[test]
fn a_rule_naming_neither_a_host_nor_a_path_takes_everything() {
    // What a redirect listener is made of (ADR-0057).
    let mut everything = rule(None, None, "unused");
    everything.action = RuleAction::Redirect {
        status: RedirectStatus::Permanent,
    };
    let web = frontend(vec![everything], Some("web"));

    assert_eq!(decide(&web, None, "/anything"), Decision::Redirect(308));
    assert_eq!(
        decide(&web, Some("posta.ornek.com.tr"), "/owa"),
        Decision::Redirect(308)
    );
}

// --- Timeouts -------------------------------------------------------------

#[test]
fn a_rule_carrying_a_timeout_overrides_the_frontend_value() {
    let mut push = rule(None, Some("/Microsoft-Server-ActiveSync"), "activesync");
    push.request_timeout_seconds = Some(3_600);
    let web = frontend(vec![push], Some("web"));

    assert_eq!(
        limit(decide(&web, None, "/Microsoft-Server-ActiveSync")),
        Some(3_600),
        "the rule's own limit was not applied"
    );
}

#[test]
fn a_rule_carrying_no_timeout_falls_back_to_the_frontend_value() {
    // The other side. A rule list that always overrode would silently drop
    // the frontend setting for every rule that left it unset.
    let web = frontend(vec![rule(None, Some("/owa"), "owa")], Some("web"));

    assert_eq!(limit(decide(&web, None, "/owa")), Some(5));
    assert_eq!(limit(decide(&web, None, "/anything")), Some(5));
}

#[test]
fn a_timeout_of_an_hour_reaches_the_upstream_it_governs() {
    // The ceiling an ActiveSync push needs, followed all the way rather than
    // by holding a request open for an hour: the configured number reaches
    // the decision unchanged, and the decision reaches the option pingora
    // enforces. That a held request really survives its window is measured
    // with real traffic in `ek-ek::routing`, at a length a test can wait out.
    let mut push = rule(None, Some("/Microsoft-Server-ActiveSync"), "activesync");
    push.request_timeout_seconds = Some(3_600);
    let web = frontend(vec![push], Some("web"));

    let decided = limit(decide(&web, None, "/Microsoft-Server-ActiveSync"));
    assert_eq!(
        decided,
        Some(3_600),
        "the hour did not survive the decision"
    );

    let peer = upstream(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        2,
        decided.expect("a pool was chosen"),
        ConnectionPooling::Enabled,
        0,
    )
    .expect("a peer must take its options");

    assert_eq!(
        peer.options.read_timeout,
        Some(Duration::from_secs(3_600)),
        "the hour did not reach the option that enforces it"
    );
}

#[test]
fn a_timeout_of_zero_leaves_the_upstream_with_no_limit_at_all() {
    // The other side. A zero written as `Duration::ZERO` would time every
    // request out immediately instead of never (ADR-0058).
    let peer = upstream(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        2,
        0,
        ConnectionPooling::Enabled,
        0,
    )
    .expect("a peer must take its options");

    assert_eq!(peer.options.read_timeout, None);
    assert_eq!(
        peer.options.connection_timeout,
        Some(Duration::from_secs(2))
    );
}

#[test]
fn a_timeout_of_zero_means_no_limit_rather_than_no_time() {
    let mut forever = rule(None, Some("/imap"), "imap");
    forever.request_timeout_seconds = Some(0);
    let web = frontend(vec![forever], Some("web"));

    assert_eq!(limit(decide(&web, None, "/imap")), Some(0));
}

// --- Unreachable rules ----------------------------------------------------

/// A configuration carrying one frontend with the rules given.
fn document(rules: Vec<RoutingRule>) -> Config {
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
        frontends: vec![frontend(rules, Some("web"))],
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        stickiness_key: String::new(),
        log_level: Default::default(),
    }
}

#[test]
fn a_rule_an_earlier_one_already_shadows_is_reported() {
    let warnings = inspect(&document(vec![
        rule(None, Some("/owa"), "general"),
        rule(None, Some("/owa/auth"), "never-reached"),
    ]));

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_eq!(
        warnings[0].code,
        WarningCode::FrontendUnreachableRoutingRule
    );
}

#[test]
fn a_rule_no_earlier_one_shadows_is_not_reported() {
    // The other side. A warning on every list would say nothing about the
    // list it describes.
    let warnings = inspect(&document(vec![
        rule(None, Some("/owa/auth"), "more-specific"),
        rule(None, Some("/owa"), "general"),
        rule(None, Some("/ews"), "ews"),
    ]));

    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn a_rule_taking_everything_shadows_every_rule_after_it() {
    let warnings = inspect(&document(vec![
        rule(None, None, "maintenance"),
        rule(None, Some("/owa"), "owa"),
        rule(Some("posta.ornek.com.tr"), Some("/ews"), "ews"),
    ]));

    assert_eq!(warnings.len(), 2, "{warnings:?}");
}

#[test]
fn a_host_wildcard_shadows_a_name_it_covers_and_no_other() {
    let warnings = inspect(&document(vec![
        rule(Some("*.ornek.com.tr"), None, "wide"),
        rule(Some("posta.ornek.com.tr"), None, "covered"),
        rule(Some("a.posta.ornek.com.tr"), None, "not-covered"),
        rule(Some("ornek.com.tr"), None, "also-not-covered"),
    ]));

    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

#[test]
fn a_configuration_with_an_unreachable_rule_is_still_valid() {
    // A warning never refuses a configuration, because the operator may have
    // put a general rule first on purpose (ADR-0072).
    let config = document(vec![
        rule(None, Some("/owa"), "general"),
        rule(None, Some("/owa/auth"), "never-reached"),
    ]);

    assert!(!inspect(&config).is_empty(), "the setup produces a warning");
    // Only the routing part is asserted: this document names no backends, so
    // validation refuses it for that instead.
    let refused = ek_ek_config::validate(&config).expect_err("this document is incomplete");
    assert!(
        !refused
            .codes()
            .iter()
            .any(|code| format!("{code:?}").contains("Routing")),
        "an unreachable rule was reported as an error: {:?}",
        refused.codes()
    );
}
