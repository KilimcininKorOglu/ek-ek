// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Whether a backend connection is reused, and what bounds it.
//!
//! Every measurement counts connections at the backend, where the operating
//! system accepted them, rather than in the proxy. A proxy counting its own
//! reuse would be reporting what it meant to do; a member counting accepts is
//! reporting what happened.
//!
//! NTLM binds authentication to the connection, so a pool serving an NTLM
//! backend has to be able to turn reuse off. That is what these measurements
//! are for (ADR-0045).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{Behaviour, Document, Member, Running, ask_once, free_port, request_to};

/// Requests one measurement sends.
const REQUESTS: usize = 12;

/// Sends requests one after another and requires every one to be answered.
async fn ask_in_turn(running: &Running, path: &str, times: usize) {
    for _ in 0..times {
        assert_eq!(
            ask_once(running.port, &request_to("mail.example.test", path))
                .await
                .expect("every request must be answered")
                .status,
            200
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_that_reuses_connections_serves_many_requests_over_one() {
    let backend = Member::start("web-1").await;
    let document =
        Document::new(free_port(), vec![backend.entry(1, "enabled")]).connection_pooling("enabled");
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", REQUESTS).await;

    assert_eq!(backend.hits(), REQUESTS as u64, "every request was served");
    // The number the operating system saw, not the number the proxy meant.
    assert_eq!(
        backend.connections(),
        1,
        "{REQUESTS} requests must have crossed one backend connection, the backend accepted {}",
        backend.connections()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_with_reuse_off_opens_a_connection_for_every_request() {
    // The other side of the measurement above. Without it, a proxy that
    // opened one connection and never reused it would pass that one.
    let backend = Member::start("web-1").await;
    let document = Document::new(free_port(), vec![backend.entry(1, "enabled")])
        .connection_pooling("disabled");
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", REQUESTS).await;

    assert_eq!(backend.hits(), REQUESTS as u64, "every request was served");
    assert_eq!(
        backend.connections(),
        REQUESTS as u64,
        "reuse is off, so every request opens its own connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_closes_when_its_request_ends_and_none_is_left_behind() {
    // A pool that opened a connection per request and never closed one would
    // pass the count above and run the process out of file descriptors. What
    // is measured here is the count still open, read from the backend.
    let backend = Member::start("web-1").await;
    let document = Document::new(free_port(), vec![backend.entry(1, "enabled")])
        .connection_pooling("disabled");
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", REQUESTS).await;
    let after_one_round = backend.wait_until_open_is_at_most(1).await;

    // A leak shows itself as growth: twice the requests, twice the sockets
    // left behind. The count after the second round has to be the same.
    ask_in_turn(&running, "/owa", REQUESTS).await;
    let after_two_rounds = backend.wait_until_open_is_at_most(after_one_round).await;

    assert_eq!(
        backend.connections(),
        REQUESTS as u64 * 2,
        "every request opened its own connection"
    );
    assert!(
        after_two_rounds <= after_one_round,
        "twice the requests left {after_two_rounds} connections open against \
         {after_one_round} after the first round, so connections are leaking"
    );
    // And they close rather than merely stop growing: whatever the number of
    // requests, at most one connection is still on its way out.
    //
    // One rather than none on purpose. The connection belonging to the
    // request that just finished may still be closing, and waiting for it to
    // reach zero measures how quickly this machine schedules a task, not
    // whether the proxy holds connections. On an idle machine it reaches zero
    // within half a second; under a full test run it has taken longer than
    // twenty. What separates closing from holding is the bound, and the bound
    // does not move with the number of requests.
    assert!(
        after_two_rounds <= 1,
        "twenty-four requests left {after_two_rounds} connections open, so they are being held"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_that_reuses_connections_keeps_one_open_between_requests() {
    // The other side again. A connection kept for reuse is exactly what must
    // stay open, so the leak measurement above has to read zero for one
    // setting and one for the other.
    let backend = Member::start("web-1").await;
    let document =
        Document::new(free_port(), vec![backend.entry(1, "enabled")]).connection_pooling("enabled");
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", REQUESTS).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        backend.open(),
        1,
        "the pool holds its connection open for the next request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_pools_under_one_frontend_each_follow_their_own_setting() {
    // The setting belongs to the backend pool, not the frontend: whether a
    // backend speaks NTLM is a property of that backend (ADR-0045). One
    // frontend with two pools is what proves it.
    let pooled = Member::start("web-1").await;
    let unpooled = Member::start("mapi-1").await;

    let document = Document::new(free_port(), vec![pooled.entry(1, "enabled")])
        .connection_pooling("enabled")
        .pool_with(
            "mapi",
            vec![unpooled.entry(1, "enabled")],
            "disabled",
            128,
            300,
        )
        .rule(None, Some("/mapi"), "mapi", None)
        .rule(None, None, "web", None);
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", REQUESTS).await;
    ask_in_turn(&running, "/mapi/emsmdb", REQUESTS).await;

    assert_eq!(pooled.hits(), REQUESTS as u64);
    assert_eq!(unpooled.hits(), REQUESTS as u64);
    assert_eq!(
        pooled.connections(),
        1,
        "the pool that reuses must have used one connection"
    );
    assert_eq!(
        unpooled.connections(),
        REQUESTS as u64,
        "the pool beside it must still open one per request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_at_its_limit_makes_the_next_request_wait_rather_than_fail() {
    // One slot and a backend that takes its time, so the second request can
    // only finish after the first has. What is measured is that it finishes
    // at all, and that it waited.
    const DELAY: Duration = Duration::from_millis(700);
    let backend = Member::with_behaviour("web-1", Behaviour::Slow(DELAY)).await;
    let document =
        Document::new(free_port(), vec![backend.entry(1, "enabled")]).connection_pool_size(1);
    let running = Running::start(&document).await;

    let started = tokio::time::Instant::now();
    let port = running.port;
    let request = request_to("mail.example.test", "/owa");
    let both = tokio::join!(ask_once(port, &request), ask_once(port, &request));
    let spent = started.elapsed();

    // Waiting, not failing. A limit that refused would show up here.
    assert_eq!(both.0.expect("the first is answered").status, 200);
    assert_eq!(both.1.expect("the second is answered").status, 200);
    assert!(
        spent >= DELAY * 2,
        "one slot means the two requests run one after the other; they took {spent:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_with_room_for_both_runs_them_at_the_same_time() {
    // The other side. Without it the measurement above would pass against a
    // proxy that serialised every request whatever the limit said.
    const DELAY: Duration = Duration::from_millis(700);
    let backend = Member::with_behaviour("web-1", Behaviour::Slow(DELAY)).await;
    let document =
        Document::new(free_port(), vec![backend.entry(1, "enabled")]).connection_pool_size(2);
    let running = Running::start(&document).await;

    let started = tokio::time::Instant::now();
    let port = running.port;
    let request = request_to("mail.example.test", "/owa");
    let both = tokio::join!(ask_once(port, &request), ask_once(port, &request));
    let spent = started.elapsed();

    assert_eq!(both.0.expect("the first is answered").status, 200);
    assert_eq!(both.1.expect("the second is answered").status, 200);
    assert!(
        spent < DELAY * 2,
        "two slots means the two requests overlap; they took {spent:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_older_than_the_lifetime_is_replaced_by_a_new_one() {
    // A backend that restarted leaves connections behind that still look
    // usable. The lifetime is what takes them out of use.
    let backend = Member::start("web-1").await;
    let document =
        Document::new(free_port(), vec![backend.entry(1, "enabled")]).connection_lifetime(1);
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", 2).await;
    assert_eq!(
        backend.connections(),
        1,
        "two requests inside one lifetime share a connection"
    );

    // Long enough to be certain the reuse group has moved on. The group is a
    // division of elapsed seconds, so the lifetime is an upper bound rather
    // than a fixed span, and waiting past a whole one settles it.
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    ask_in_turn(&running, "/owa", 1).await;

    assert_eq!(
        backend.connections(),
        2,
        "the connection past its lifetime must not have taken the third request"
    );
    assert_eq!(backend.hits(), 3, "every request was still served");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_inside_its_lifetime_is_still_reused() {
    // The other side. A lifetime that retired every connection would pass
    // the measurement above and cost a handshake per request.
    let backend = Member::start("web-1").await;
    let document =
        Document::new(free_port(), vec![backend.entry(1, "enabled")]).connection_lifetime(3_600);
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", 2).await;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    ask_in_turn(&running, "/owa", 1).await;

    assert_eq!(
        backend.connections(),
        1,
        "an hour of lifetime means one connection carries all three requests"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_report_counts_the_connections_opened_and_the_ones_reused() {
    let backend = Member::start("web-1").await;
    let document =
        Document::new(free_port(), vec![backend.entry(1, "enabled")]).connection_pooling("enabled");
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", REQUESTS).await;

    let report = running
        .agent
        .wait_for_backend_connections(REQUESTS as u64)
        .await;
    assert_eq!(
        report.backend_connections_opened, 1,
        "one connection was opened, and the report has to say so"
    );
    assert_eq!(
        report.backend_connections_reused,
        REQUESTS as u64 - 1,
        "every request after the first was served over the connection already held"
    );
    // The two counts are what a reuse rate is worked out from, and they must
    // add up to the requests that reached a backend.
    assert_eq!(
        report.backend_connections_opened + report.backend_connections_reused,
        REQUESTS as u64
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_report_counts_every_request_as_an_open_when_reuse_is_off() {
    // The other side. A report that always said "reused" would pass the one
    // above and tell an operator nothing.
    let backend = Member::start("web-1").await;
    let document = Document::new(free_port(), vec![backend.entry(1, "enabled")])
        .connection_pooling("disabled");
    let running = Running::start(&document).await;

    ask_in_turn(&running, "/owa", REQUESTS).await;

    let report = running
        .agent
        .wait_for_backend_connections(REQUESTS as u64)
        .await;
    assert_eq!(report.backend_connections_opened, REQUESTS as u64);
    assert_eq!(report.backend_connections_reused, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turning_reuse_off_costs_measured_latency() {
    // ADR-0045 says the UI states this cost beside the setting (T-053). The
    // number written there has to come from a measurement, so it is taken
    // here rather than estimated. The same requests are served twice against
    // the same backend, once reusing and once not.
    const ROUNDS: usize = 300;

    async fn spend(document: &Document) -> (Duration, Running) {
        let running = Running::start(document).await;
        // One request first, so the listener's own start-up cost falls
        // outside the measurement.
        let _ = ask_once(running.port, &request_to("mail.example.test", "/owa")).await;

        let started = tokio::time::Instant::now();
        for _ in 0..ROUNDS {
            assert_eq!(
                ask_once(running.port, &request_to("mail.example.test", "/owa"))
                    .await
                    .expect("every request must be answered")
                    .status,
                200
            );
        }
        (started.elapsed(), running)
    }

    let reusing_backend = Member::start("web-1").await;
    let reusing = Document::new(free_port(), vec![reusing_backend.entry(1, "enabled")])
        .connection_pooling("enabled");
    let (with_reuse, _reusing_run) = spend(&reusing).await;

    let opening_backend = Member::start("web-1").await;
    let opening = Document::new(free_port(), vec![opening_backend.entry(1, "enabled")])
        .connection_pooling("disabled");
    let (without_reuse, _opening_run) = spend(&opening).await;

    // Printed so the number in the task file comes from a run rather than
    // from a guess.
    let per_request = |spent: Duration| spent.as_secs_f64() * 1_000.0 / ROUNDS as f64;
    println!(
        "reuse on: {:.3} ms per request; reuse off: {:.3} ms per request; \
         the cost of turning it off is {:.3} ms per request",
        per_request(with_reuse),
        per_request(without_reuse),
        per_request(without_reuse) - per_request(with_reuse)
    );

    // The run really did what it claims to have measured.
    assert_eq!(reusing_backend.connections(), 1);
    assert_eq!(opening_backend.connections(), ROUNDS as u64 + 1);
}
