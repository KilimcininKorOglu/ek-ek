// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What health checking does to real traffic.
//!
//! The probes and the thresholds are measured in `ek-ek-dataplane`. What
//! cannot be measured there is whether a member the checker took out actually
//! stops receiving requests, what a client gets when a whole pool is out, and
//! whether the agent is told. Those need the real binary.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{Document, Member, Running, ask_once, free_port, plain_request};

/// How long a test waits for a probe cycle to land.
const PATIENCE: Duration = Duration::from_secs(20);

/// Sends requests until one is answered by somebody other than `member`, or
/// gives up. Returns how many requests that took.
async fn until_not_from(port: u16, member: &str) -> usize {
    let start = tokio::time::Instant::now();
    let mut asked = 0;
    loop {
        let answer = ask_once(port, &plain_request())
            .await
            .expect("a request must be answered");
        asked += 1;
        if answer.status == 200 && answer.member() != member {
            return asked;
        }
        assert!(
            start.elapsed() < PATIENCE,
            "every request is still going to {member}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_marked_unhealthy_receives_no_request() {
    let staying = Member::start("staying").await;
    let failing = Member::start("failing").await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![staying.entry(1, "enabled"), failing.entry(1, "enabled")],
    )
    .http_health_check("/healthz", 200, 200);
    let running = Running::start(&document).await;

    // Both are answering, so both take traffic.
    let mut seen_failing = false;
    for _ in 0..10 {
        let answer = ask_once(running.port, &plain_request())
            .await
            .expect("a request must be answered");
        if answer.member() == "failing" {
            seen_failing = true;
        }
    }
    assert!(seen_failing, "the member never took traffic to begin with");

    failing.stop_answering();
    running
        .agent
        .wait_for_health("failing", false)
        .await
        .expect("the member must be reported unhealthy");

    // From here nothing may reach it.
    failing.reset();
    for _ in 0..30 {
        let answer = ask_once(running.port, &plain_request())
            .await
            .expect("a request must be answered");
        assert_eq!(answer.status, 200);
        assert_eq!(
            answer.member(),
            "staying",
            "a request went to a member marked unhealthy"
        );
    }
    assert_eq!(
        failing.hits(),
        0,
        "an unhealthy member answered {} requests",
        failing.hits()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_that_recovers_takes_requests_again() {
    let staying = Member::start("staying").await;
    let coming_back = Member::start("coming-back").await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![staying.entry(1, "enabled"), coming_back.entry(1, "enabled")],
    )
    .http_health_check("/healthz", 200, 200);
    let running = Running::start(&document).await;

    coming_back.stop_answering();
    running
        .agent
        .wait_for_health("coming-back", false)
        .await
        .expect("the member must go unhealthy first");

    coming_back.answer_again();
    let transitions = running
        .agent
        .wait_for_health("coming-back", true)
        .await
        .expect("the member must be reported healthy again");
    assert!(
        transitions >= 2,
        "a member that went down and came back reported {transitions} transitions"
    );

    coming_back.reset();
    let asked = until_not_from(running.port, "staying").await;
    assert!(
        asked <= 40,
        "the recovered member did not come back into rotation within {asked} requests"
    );
    assert!(
        coming_back.hits() > 0,
        "the recovered member took no traffic"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_where_every_member_is_unhealthy_refuses_traffic() {
    // Refusing beats forwarding to a member known to be down: the client gets
    // the load balancer's own answer and the operator knows where to look
    // (ADR-0062).
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .http_health_check("/healthz", 200, 200);
    let running = Running::start(&document).await;

    one.stop_answering();
    two.stop_answering();
    running
        .agent
        .wait_for_health("one", false)
        .await
        .expect("the first member must go unhealthy");
    running
        .agent
        .wait_for_health("two", false)
        .await
        .expect("the second member must go unhealthy");

    one.reset();
    two.reset();
    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("a pool with nobody healthy must still answer");

    assert_eq!(
        answer.status, 503,
        "an empty pool answered {} rather than 503",
        answer.status
    );
    assert_eq!(
        one.hits() + two.hits(),
        0,
        "a request reached a dead member"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_state_reaches_the_agent_with_the_pool_and_the_member_named() {
    let member = Member::start("watched").await;
    let port = free_port();
    let document = Document::new(port, vec![member.entry(1, "enabled")])
        .http_health_check("/healthz", 200, 200);
    let running = Running::start(&document).await;

    running
        .agent
        .wait_for_health("watched", true)
        .await
        .expect("a healthy member must be reported");

    let reported = running.agent.health_now().await;
    let entry = reported
        .iter()
        .find(|entry| entry.member == "watched")
        .expect("the member must be in the report");
    assert_eq!(entry.pool, "web", "the pool was not named");
    assert!(entry.healthy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_with_no_health_check_reports_nothing_and_keeps_serving() {
    let member = Member::start("unchecked").await;
    let port = free_port();
    let running = Running::start(&Document::new(port, vec![member.entry(1, "enabled")])).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("a pool with no health check must serve");
    assert_eq!(answer.status, 200);

    // The report says nothing about a member nothing measured. Long enough
    // that a checker probing this pool by mistake would have done so several
    // times over by now.
    running
        .agent
        .wait_for_counter("requests_handled", 1)
        .await
        .expect("a report must have arrived");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let reported = running.agent.health_now().await;
    assert!(
        reported.is_empty(),
        "a member with no health check was reported: {reported:?}"
    );
    assert_eq!(
        member.probes(),
        0,
        "a pool with no health check was probed anyway"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probes_do_not_overlap_and_keep_to_their_interval() {
    // Validation refuses a timeout above the interval, and the checker waits
    // one interval after each probe finishes. Together those mean the number
    // of probes over a stretch of time is bounded by that stretch divided by
    // the interval.
    let member = Member::start("paced").await;
    let port = free_port();
    let document = Document::new(port, vec![member.entry(1, "enabled")])
        .http_health_check("/healthz", 200, 300);
    let running = Running::start(&document).await;

    running
        .agent
        .wait_for_health("paced", true)
        .await
        .expect("the member must be probed at all");

    let before = member.probes();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let probes = member.probes() - before;

    // Three seconds at 300 ms is ten probes. Overlapping probes would produce
    // far more; a stalled checker would produce far fewer.
    assert!(
        (5..=14).contains(&probes),
        "{probes} probes in three seconds at a 300 ms interval"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_disabled_member_is_not_probed() {
    // Probing a member an operator took out of service tells nobody anything
    // and still costs a connection on the backend.
    let taking = Member::start("taking").await;
    let out = Member::start("out").await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![taking.entry(1, "enabled"), out.entry(1, "disabled")],
    )
    .http_health_check("/healthz", 200, 200);
    let running = Running::start(&document).await;

    running
        .agent
        .wait_for_health("taking", true)
        .await
        .expect("the enabled member must be probed");
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(taking.probes() > 0, "the enabled member was never probed");
    assert_eq!(
        out.probes(),
        0,
        "a member an operator disabled was probed {} times",
        out.probes()
    );
}
