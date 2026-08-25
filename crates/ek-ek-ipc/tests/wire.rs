// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the protocol between the two processes must hold true.
//!
//! Upgrades are rolling, so the two processes briefly run different releases.
//! A message the other side does not know must arrive as an unknown message
//! rather than being read as the wrong one.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use ek_ek_config::{Config, SchemaVersion};
use ek_ek_ipc::{
    AgentMessage, ConfigUpdate, Counters, DataPlaneMessage, DataPlaneState, Hello, MemberHealth,
    OpenConnections, Ping, Pong, StatusReport, UdpSessions, decode, encode,
};

fn empty_config() -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: Vec::new(),
        vips: Vec::new(),
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        acme: None,
        stickiness_key: String::new(),
        log_level: Default::default(),
        certificate_expiry_warning_days: 30,
    }
}

#[test]
fn a_message_survives_a_round_trip() {
    let delivery = AgentMessage::Config(Box::new(ConfigUpdate {
        generation: 12,
        config: empty_config(),
        certificates: BTreeMap::new(),
        challenges: BTreeMap::new(),
    }));
    let line = encode(&delivery).expect("it must encode");
    assert_eq!(
        decode::<AgentMessage>(&line).expect("it must decode"),
        delivery
    );

    let report = DataPlaneMessage::Status(StatusReport {
        generation: 12,
        state: DataPlaneState::Serving,
        counters: Counters {
            requests_handled: 5,
            configs_applied: 2,
            configs_rejected: 1,
            backend_connect_failures: 3,
            tls_handshakes_refused: 4,
            passthrough_connections_refused: 12,
            udp_sessions_evicted: 9,
            proxy_headers_without_an_address: 6,
            log_records_dropped: 8,
            backend_connections_opened: 11,
            backend_connections_reused: 7,
        },
        open_connections: vec![OpenConnections {
            frontend: "web".to_owned(),
            pool: "pool-web".to_owned(),
            member: "web-1".to_owned(),
            count: 7,
        }],
        member_health: vec![MemberHealth {
            pool: "pool-web".to_owned(),
            member: "web-1".to_owned(),
            healthy: false,
            transitions: 4,
        }],
        udp_sessions: vec![UdpSessions {
            frontend: "dns-udp".to_owned(),
            count: 128,
            limit: 4096,
        }],
    });
    let line = encode(&report).expect("it must encode");
    assert_eq!(
        decode::<DataPlaneMessage>(&line).expect("it must decode"),
        report
    );
}

#[test]
fn a_message_is_exactly_one_line() {
    let hello = DataPlaneMessage::Hello(Hello {
        pid: 1234,
        // A value carrying a newline would split the message in two if the
        // format did not escape it.
        version: "0.1.0\nnot-a-second-message".to_owned(),
        generation: Some(3),
    });

    let line = encode(&hello).expect("it must encode");
    assert_eq!(line.matches('\n').count(), 1, "one message, one newline");
    assert!(line.ends_with('\n'));
    assert_eq!(
        decode::<DataPlaneMessage>(&line).expect("it must decode"),
        hello,
        "and the value comes back whole"
    );
}

#[test]
fn a_message_from_a_newer_release_is_refused_by_name() {
    // What a release that knows a message this one does not would send.
    let unknown = r#"{"message":"drain","seconds":30}"#;

    let refused = decode::<AgentMessage>(unknown)
        .expect_err("an unknown message must not be read as a known one");
    assert!(
        refused.diagnostic().contains("drain"),
        "the log must name what arrived: {}",
        refused.diagnostic()
    );

    // A message this release does know still decodes, so the refusal is about
    // the tag and not about every message.
    let known = encode(&AgentMessage::Config(Box::new(ConfigUpdate {
        generation: 1,
        config: empty_config(),
        certificates: BTreeMap::new(),
        challenges: BTreeMap::new(),
    })))
    .expect("it must encode");
    decode::<AgentMessage>(&known).expect("a known message decodes");
}

#[test]
fn the_two_directions_do_not_read_as_each_other() {
    let report = encode(&DataPlaneMessage::Status(StatusReport {
        generation: 1,
        state: DataPlaneState::Starting,
        counters: Counters::default(),
        open_connections: Vec::new(),
        member_health: Vec::new(),
        udp_sessions: Vec::new(),
    }))
    .expect("it must encode");

    assert!(
        decode::<AgentMessage>(&report).is_err(),
        "a report from the traffic path is not something the agent sends"
    );
}

#[test]
fn an_empty_line_is_not_a_message() {
    assert!(decode::<AgentMessage>("").is_err());
    assert!(decode::<AgentMessage>("\n").is_err());
    assert!(decode::<AgentMessage>("   \n").is_err());
}

#[test]
fn a_trailing_newline_is_optional_when_reading() {
    let line = encode(&DataPlaneMessage::Hello(Hello {
        pid: 7,
        version: "0.1.0".to_owned(),
        generation: None,
    }))
    .expect("it must encode");

    let trimmed = line.trim_end();
    assert_eq!(
        decode::<DataPlaneMessage>(trimmed).expect("it must decode"),
        decode::<DataPlaneMessage>(&line).expect("it must decode"),
        "a reader that already stripped the newline gets the same value"
    );
}

#[test]
fn a_liveness_question_carries_the_nonce_its_answer_has_to_repeat() {
    // The nonce is what tells one question from the next. Without it a late
    // answer to an earlier question counts as the answer to the one still
    // outstanding, and a process that stopped answering looks alive for one
    // more round (ADR-0087).
    let asked = AgentMessage::Ping(Ping { nonce: 7 });
    let line = encode(&asked).expect("the question is written out");
    let read: AgentMessage = decode(&line).expect("the question is read back");
    assert_eq!(read, asked);

    let answered = DataPlaneMessage::Pong(Pong { nonce: 7 });
    let line = encode(&answered).expect("the answer is written out");
    let read: DataPlaneMessage = decode(&line).expect("the answer is read back");
    assert_eq!(read, answered);

    // Two questions are told apart, which is the whole point of the field.
    let other = encode(&AgentMessage::Ping(Ping { nonce: 8 })).expect("written out");
    assert_ne!(
        other,
        encode(&asked).expect("written out"),
        "two questions encode the same, so an answer cannot say which it is for"
    );
}

#[test]
fn an_answer_carrying_no_nonce_is_refused_rather_than_read_as_zero() {
    // A release that answered without saying which question it was answering
    // would be read as answering nonce zero, which is a question the agent
    // may well have asked. Refusing by name is what keeps that from counting
    // as a live process.
    let refused: ek_ek_ipc::Result<DataPlaneMessage> = decode(r#"{"message":"pong"}"#);
    assert!(
        refused.is_err(),
        "an answer with no nonce was accepted: {refused:?}"
    );

    let refused: ek_ek_ipc::Result<AgentMessage> = decode(r#"{"message":"ping"}"#);
    assert!(
        refused.is_err(),
        "a question with no nonce was accepted: {refused:?}"
    );
}

#[test]
fn a_question_is_not_read_as_an_answer() {
    // Both directions carry the same field under the same name, so only the
    // tag tells them apart. A question read as an answer would make the agent
    // count its own message as proof the other process is alive.
    let asked = encode(&AgentMessage::Ping(Ping { nonce: 3 })).expect("written out");
    assert!(
        decode::<DataPlaneMessage>(&asked).is_err(),
        "the agent's own question reads as the traffic path's answer"
    );

    let answered = encode(&DataPlaneMessage::Pong(Pong { nonce: 3 })).expect("written out");
    assert!(
        decode::<AgentMessage>(&answered).is_err(),
        "the traffic path's answer reads as a question from the agent"
    );
}
