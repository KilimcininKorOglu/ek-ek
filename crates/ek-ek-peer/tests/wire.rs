// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One JSON object per line, in both directions.
//!
//! The framing is measured against text rather than against a round trip
//! through this crate's own types. A round trip agrees with itself whatever
//! the format became, and the whole reason the peer protocol is a wire format
//! is that the release on the other end may not be this one.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_peer::{Answer, Ask, HealthAnswer, HealthAsk, PROTOCOL, Reason, UNREADABLE};

#[test]
fn a_message_is_one_line_and_ends_with_a_newline() {
    let line = ek_ek_peer::encode(&Ask::Health(HealthAsk {
        protocol: PROTOCOL.to_owned(),
    }))
    .expect("the message writes out");

    assert!(line.ends_with('\n'));
    assert_eq!(line.matches('\n').count(), 1, "the message is not one line");
    assert!(line.contains(r#""message":"health""#), "{line}");
}

#[test]
fn an_answer_carries_the_node_that_sent_it() {
    let line = ek_ek_peer::encode(&Answer::Health(HealthAnswer {
        protocol: PROTOCOL.to_owned(),
        node: "node-1".to_owned(),
    }))
    .expect("the message writes out");
    assert!(line.contains(r#""node":"node-1""#), "{line}");
}

#[test]
fn a_line_written_here_is_read_back_as_what_it_was() {
    let asked = Ask::Health(HealthAsk {
        protocol: PROTOCOL.to_owned(),
    });
    let line = ek_ek_peer::encode(&asked).expect("the message writes out");
    assert_eq!(
        ek_ek_peer::decode::<Ask>(&line).expect("the message reads back"),
        asked
    );
}

#[test]
fn a_message_from_a_newer_release_is_refused_by_name() {
    // An upgrade is rolling, so two releases speak to each other. An unknown
    // tag has to land as an unknown tag rather than as the wrong message.
    let failure = ek_ek_peer::decode::<Ask>(r#"{"message":"raft_append","term":4}"#)
        .expect_err("an unknown message is refused");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn a_message_with_a_field_this_release_does_not_know_is_refused() {
    let failure = ek_ek_peer::decode::<Ask>(r#"{"message":"health","protocol":"x","extra":1}"#)
        .expect_err("an unknown field is refused");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn an_empty_line_is_refused_and_says_it_was_empty() {
    // A peer that closed the connection sends a line of nothing. The
    // diagnostic reaches a log, and "an empty line is not a message" is what
    // tells an operator the peer went away rather than sent something broken.
    for empty in ["", "\n", "\r\n"] {
        let failure = ek_ek_peer::decode::<Ask>(empty).expect_err("an empty line is refused");
        assert_eq!(failure.reason(), Reason::Protocol);
        assert!(
            failure.detail().contains("empty"),
            "the failure does not say the line was empty: {failure}"
        );
    }

    // And a line that is broken rather than empty says something else, so the
    // check above is reading a diagnostic of its own and not the one every
    // unreadable line gets.
    let broken = ek_ek_peer::decode::<Ask>("{").expect_err("a broken line is refused");
    assert!(!broken.detail().contains("empty"), "{broken}");
}

#[test]
fn a_refusal_names_a_stable_reason() {
    // The key is what another release matches on. Text is for the log.
    let line = ek_ek_peer::encode(&Answer::Refused(ek_ek_peer::Refusal {
        reason: UNREADABLE.to_owned(),
        detail: "whatever went wrong".to_owned(),
    }))
    .expect("the message writes out");
    assert!(line.contains("peer.unreadable"), "{line}");
}
