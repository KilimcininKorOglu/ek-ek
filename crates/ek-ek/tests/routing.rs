// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sending a request to a pool chosen from its host and its path.
//!
//! Measured against the real binary over real requests. Which pool took a
//! request is read from the answer the backend wrote, so nothing here rests
//! on what the configuration says should have happened.
//!
//! The matching itself is measured rule by rule in `ek-ek-dataplane`. What is
//! measured here is that a request really lands where the rule says.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{Behaviour, Document, Member, Running, ask_once, free_port, request_to};

/// Which backend answered, read out of what it wrote.
fn answered_by(body: &str) -> Option<&str> {
    body.lines().find_map(|line| line.strip_prefix("member="))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_rule_sends_the_request_to_its_own_pool() {
    let general = Member::start("general").await;
    let owa = Member::start("owa").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("owa", vec![owa.entry(1, "enabled")])
        .rule(None, Some("/owa"), "owa", None);
    let running = Running::start(&document).await;

    let matched = ask_once(
        running.port,
        &request_to("ek-ek.test", "/owa/auth/logon.aspx"),
    )
    .await
    .expect("a request must be answered");
    let other = ask_once(running.port, &request_to("ek-ek.test", "/anything"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&matched.body), Some("owa"));
    assert_eq!(
        answered_by(&other.body),
        Some("general"),
        "a path outside the rule was captured by it"
    );
    assert_eq!(owa.hits(), 1);
    assert_eq!(general.hits(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prefix_does_not_capture_a_name_that_merely_starts_the_same() {
    // The other side of the boundary rule. `/owanot` is a different resource
    // and belongs to whoever the default pool is (ADR-0071).
    let general = Member::start("general").await;
    let owa = Member::start("owa").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("owa", vec![owa.entry(1, "enabled")])
        .rule(None, Some("/owa"), "owa", None);
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &request_to("ek-ek.test", "/owanot"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&answer.body), Some("general"));
    assert_eq!(owa.hits(), 0, "the rule took a request it does not name");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_climb_out_of_a_prefix_does_not_reach_the_pool_the_prefix_names() {
    // The security half. Matching the raw path would let `/owa/../admin`
    // reach the OWA pool although it names another resource entirely.
    let admin = Member::start("admin").await;
    let owa = Member::start("owa").await;
    let port = free_port();
    let document = Document::new(port, vec![admin.entry(1, "enabled")])
        .pool("owa", vec![owa.entry(1, "enabled")])
        .rule(None, Some("/owa"), "owa", None);
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &request_to("ek-ek.test", "/owa/../admin"))
        .await
        .expect("a request must be answered");

    assert_eq!(
        answered_by(&answer.body),
        Some("admin"),
        "a climb out of the prefix still reached its pool"
    );
    assert_eq!(owa.hits(), 0);

    // And the path that really is under the prefix still reaches it, so this
    // is about normalisation and not about the rule being broken.
    let inside = ask_once(running.port, &request_to("ek-ek.test", "/owa/auth"))
        .await
        .expect("a request must be answered");
    assert_eq!(answered_by(&inside.body), Some("owa"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_rule_sends_the_request_to_its_own_pool() {
    let general = Member::start("general").await;
    let mail = Member::start("mail").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("mail", vec![mail.entry(1, "enabled")])
        .rule(Some("posta.ek-ek.test"), None, "mail", None);
    let running = Running::start(&document).await;

    let matched = ask_once(running.port, &request_to("posta.ek-ek.test", "/"))
        .await
        .expect("a request must be answered");
    let other = ask_once(running.port, &request_to("baska.ek-ek.test", "/"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&matched.body), Some("mail"));
    assert_eq!(answered_by(&other.body), Some("general"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_wildcard_covers_one_label_and_not_two() {
    let general = Member::start("general").await;
    let wide = Member::start("wide").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("wide", vec![wide.entry(1, "enabled")])
        .rule(Some("*.ek-ek.test"), None, "wide", None);
    let running = Running::start(&document).await;

    let one_label = ask_once(running.port, &request_to("posta.ek-ek.test", "/"))
        .await
        .expect("a request must be answered");
    let two_labels = ask_once(running.port, &request_to("a.posta.ek-ek.test", "/"))
        .await
        .expect("a request must be answered");
    let bare = ask_once(running.port, &request_to("ek-ek.test", "/"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&one_label.body), Some("wide"));
    assert_eq!(
        answered_by(&two_labels.body),
        Some("general"),
        "the wildcard was stretched over two labels"
    );
    assert_eq!(
        answered_by(&bare.body),
        Some("general"),
        "the wildcard covered the bare name"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_naming_both_a_host_and_a_path_applies_only_when_both_match() {
    let general = Member::start("general").await;
    let owa = Member::start("owa").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("owa", vec![owa.entry(1, "enabled")])
        .rule(Some("posta.ek-ek.test"), Some("/owa"), "owa", None);
    let running = Running::start(&document).await;

    let both = ask_once(running.port, &request_to("posta.ek-ek.test", "/owa/auth"))
        .await
        .expect("a request must be answered");
    let host_only = ask_once(running.port, &request_to("posta.ek-ek.test", "/ews"))
        .await
        .expect("a request must be answered");
    let path_only = ask_once(running.port, &request_to("baska.ek-ek.test", "/owa/auth"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&both.body), Some("owa"));
    assert_eq!(
        answered_by(&host_only.body),
        Some("general"),
        "the rule applied although the path did not match"
    );
    assert_eq!(
        answered_by(&path_only.body),
        Some("general"),
        "the rule applied although the host did not match"
    );
    assert_eq!(owa.hits(), 1, "the pool took more requests than it should");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_matching_rule_applies_and_the_rest_are_not_tried() {
    let general = Member::start("general").await;
    let first = Member::start("first").await;
    let second = Member::start("second").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("first", vec![first.entry(1, "enabled")])
        .pool("second", vec![second.entry(1, "enabled")])
        // Both would take the same request. Only the earlier one may.
        .rule(None, Some("/owa"), "first", None)
        .rule(None, Some("/owa"), "second", None);
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &request_to("ek-ek.test", "/owa/auth"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&answer.body), Some("first"));
    assert_eq!(
        second.hits(),
        0,
        "a rule after the first match was tried anyway"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn putting_the_specific_rule_first_changes_where_the_request_lands() {
    // The other side of the ordering rule. A list whose order did not matter
    // would answer the same as the test above.
    let general = Member::start("general").await;
    let owa = Member::start("owa").await;
    let auth = Member::start("auth").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("owa", vec![owa.entry(1, "enabled")])
        .pool("auth", vec![auth.entry(1, "enabled")])
        .rule(None, Some("/owa/auth"), "auth", None)
        .rule(None, Some("/owa"), "owa", None);
    let running = Running::start(&document).await;

    let specific = ask_once(
        running.port,
        &request_to("ek-ek.test", "/owa/auth/logon.aspx"),
    )
    .await
    .expect("a request must be answered");
    let general_path = ask_once(running.port, &request_to("ek-ek.test", "/owa/other"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&specific.body), Some("auth"));
    assert_eq!(answered_by(&general_path.body), Some("owa"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_rule_matches_case_insensitively_by_default() {
    let general = Member::start("general").await;
    let owa = Member::start("owa").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("owa", vec![owa.entry(1, "enabled")])
        .rule(None, Some("/owa"), "owa", None);
    let running = Running::start(&document).await;

    let upper = ask_once(running.port, &request_to("ek-ek.test", "/OWA/auth"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&upper.body), Some("owa"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_asking_for_case_sensitivity_gets_it() {
    // The other side. A backend serving paths case sensitively needs the
    // difference kept (ADR-0071).
    let general = Member::start("general").await;
    let owa = Member::start("owa").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("owa", vec![owa.entry(1, "enabled")])
        .case_sensitive_rule("/owa", "owa");
    let running = Running::start(&document).await;

    let exact = ask_once(running.port, &request_to("ek-ek.test", "/owa/auth"))
        .await
        .expect("a request must be answered");
    let other_case = ask_once(running.port, &request_to("ek-ek.test", "/OWA/auth"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&exact.body), Some("owa"));
    assert_eq!(
        answered_by(&other_case.body),
        Some("general"),
        "a case sensitive rule matched a path in another case"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_no_rule_takes_goes_to_the_default_pool() {
    let general = Member::start("general").await;
    let owa = Member::start("owa").await;
    let port = free_port();
    let document = Document::new(port, vec![general.entry(1, "enabled")])
        .pool("owa", vec![owa.entry(1, "enabled")])
        .rule(None, Some("/owa"), "owa", None);
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &request_to("ek-ek.test", "/nothing-matches"))
        .await
        .expect("a request must be answered");

    assert_eq!(answered_by(&answer.body), Some("general"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_no_rule_takes_is_refused_in_the_open_without_a_default() {
    // The other side. A closed connection looks like a network fault and
    // sends an operator hunting in the wrong place.
    let owa = Member::start("owa").await;
    let port = free_port();
    let document = Document::new(port, vec![owa.entry(1, "enabled")])
        .without_default_backend()
        .rule(None, Some("/owa"), "web", None);
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &request_to("ek-ek.test", "/nothing-matches"))
        .await
        .expect("the connection must not be closed without an answer");

    assert_eq!(
        answer.status, 503,
        "a request with nowhere to go was not refused with a status"
    );
    // And the rule that does match still works, so the frontend is serving.
    let matched = ask_once(running.port, &request_to("ek-ek.test", "/owa"))
        .await
        .expect("a request must be answered");
    assert_eq!(answered_by(&matched.body), Some("owa"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_timeout_replaces_the_frontend_one_for_the_request_it_takes() {
    // The ActiveSync case, measured in seconds rather than in the half hour a
    // real push request lasts: the frontend allows one second and the rule
    // allows eight, and a backend that holds the answer for four proves which
    // number was used. The mechanism carrying an hour is measured in
    // `ek-ek-dataplane::route`, where no request has to be held open.
    let slow = Member::with_behaviour("slow", Behaviour::Slow(Duration::from_secs(4))).await;
    let port = free_port();
    let document = Document::new(port, vec![slow.entry(1, "enabled")])
        .request_timeout(1)
        .pool("push", vec![slow.entry(1, "enabled")])
        .rule(None, Some("/Microsoft-Server-ActiveSync"), "push", Some(8));
    let running = Running::start(&document).await;

    let held = ask_once(
        running.port,
        &request_to("ek-ek.test", "/Microsoft-Server-ActiveSync/"),
    )
    .await
    .expect("a request must be answered");

    assert_eq!(
        held.status, 200,
        "a request under a rule allowing eight seconds timed out"
    );
    assert_eq!(answered_by(&held.body), Some("slow"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_no_rule_takes_keeps_the_frontend_timeout() {
    // The other side of the same rule, in the same shape: the same slow
    // backend, the same one second frontend limit, and no rule to raise it.
    let slow = Member::with_behaviour("slow", Behaviour::Slow(Duration::from_secs(4))).await;
    let port = free_port();
    let document = Document::new(port, vec![slow.entry(1, "enabled")])
        .request_timeout(1)
        .pool("push", vec![slow.entry(1, "enabled")])
        .rule(None, Some("/Microsoft-Server-ActiveSync"), "push", Some(8));
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &request_to("ek-ek.test", "/owa"))
        .await
        .expect("a request must be answered");

    assert_eq!(
        answer.status, 504,
        "the frontend limit was not applied to a request no rule took"
    );
}
