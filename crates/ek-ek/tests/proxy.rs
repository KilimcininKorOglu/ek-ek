// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the HTTP reverse proxy does with a request.
//!
//! Everything here runs the real binary against real backends over real
//! sockets. An algorithm can be measured in isolation, and it is, in
//! `ek-ek-dataplane`. What cannot be measured there is whether the proxy
//! actually reaches a backend, what it puts on the wire and what it answers
//! when nothing works, so those are measured here.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use tokio::io::BufReader;
use tokio::net::TcpStream;

mod common;

use common::{
    Answer, Behaviour, Document, Member, Running, ask, ask_once, connect, free_port, plain_request,
};

/// Sends a number of requests, each on its own connection, and returns which
/// member answered each one.
///
/// A fresh connection per request is what a load balancer sees from a browser
/// fleet, and it keeps one slow answer from holding up the rest.
async fn spread(port: u16, count: usize) -> Vec<String> {
    let mut answered = Vec::new();
    for _ in 0..count {
        let answer = ask_once(port, &plain_request())
            .await
            .expect("every request must be answered");
        assert_eq!(answer.status, 200, "a request was not proxied: {answer:?}");
        answered.push(answer.member());
    }
    answered
}

/// Counts how many times one member answered.
fn count(answers: &[String], member: &str) -> usize {
    answers.iter().filter(|name| *name == member).count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_http11_request_reaches_the_backend_and_its_answer_comes_back() {
    let only = Member::start("only").await;
    let port = free_port();
    let running = Running::start(&Document::new(port, vec![only.entry(1, "enabled")])).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("the request must be answered");

    assert_eq!(
        answer.status, 200,
        "the backend answered 200, the proxy did not"
    );
    assert_eq!(
        answer.member(),
        "only",
        "the answer did not come from the backend"
    );
    assert_eq!(only.hits(), 1, "the backend was not actually reached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_http2_request_reaches_the_backend_and_its_answer_comes_back() {
    let only = Member::start("only").await;
    let port = free_port();
    let running = Running::start(&Document::new(port, vec![only.entry(1, "enabled")])).await;

    // Cleartext HTTP/2 with prior knowledge: no upgrade dance, the client
    // opens with the connection preface. That is what a frontend with h2c on
    // has to accept.
    let stream = connect(running.port).await;
    let (client, connection) = h2::client::handshake(stream)
        .await
        .expect("the listener must speak HTTP/2");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = client.ready().await.expect("the client must become ready");
    let request = http::Request::builder()
        .method("GET")
        .uri("http://ek-ek.test/")
        .body(())
        .expect("the request must build");
    let (response, _) = client
        .send_request(request, true)
        .expect("the request must be sent");
    let response = response.await.expect("an answer must arrive");

    assert_eq!(response.status(), 200, "the HTTP/2 request was not proxied");
    let mut body = response.into_body();
    let mut text = String::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("the body must read");
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    driver.abort();

    assert!(
        text.contains("member=only"),
        "the HTTP/2 answer did not come from the backend: {text:?}"
    );
    assert_eq!(only.hits(), 1, "the backend was not actually reached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_is_refused_when_the_frontend_turns_it_off() {
    let only = Member::start("only").await;
    let port = free_port();
    let document = Document::new(port, vec![only.entry(1, "enabled")]).without_http2();
    let running = Running::start(&document).await;

    let stream = connect(running.port).await;
    let handshake = h2::client::handshake(stream).await;

    // The listener reads the preface, does not recognise it as one it accepts
    // and falls back to HTTP/1.1, which cannot answer an HTTP/2 request. The
    // failure shows up on the answer rather than on the handshake, because a
    // client writes its preface without waiting for anything back.
    match handshake {
        Err(_) => {}
        Ok((client, connection)) => {
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let answered = tokio::time::timeout(Duration::from_secs(5), async move {
                let mut client = client.ready().await?;
                let request = http::Request::builder()
                    .method("GET")
                    .uri("http://ek-ek.test/")
                    .body(())
                    .expect("the request must build");
                let (response, _) = client.send_request(request, true)?;
                response.await
            })
            .await;
            driver.abort();

            assert!(
                matches!(answered, Ok(Err(_)) | Err(_)),
                "the frontend answered an HTTP/2 request while HTTP/2 was turned off: {answered:?}"
            );
        }
    }

    // HTTP/1.1 on the same listener is untouched.
    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("HTTP/1.1 must still work");
    assert_eq!(answer.status, 200, "turning HTTP/2 off broke HTTP/1.1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_robin_splits_one_hundred_requests_evenly_between_two_equal_members() {
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let port = free_port();
    let running = Running::start(&Document::new(
        port,
        vec![one.entry(1, "enabled"), two.entry(1, "enabled")],
    ))
    .await;

    let answers = spread(running.port, 100).await;

    assert_eq!(
        count(&answers, "one"),
        50,
        "one took {} of 100 requests",
        count(&answers, "one")
    );
    assert_eq!(
        count(&answers, "two"),
        50,
        "two took {} of 100 requests",
        count(&answers, "two")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_weighted_two_takes_twice_the_share_of_one_weighted_one() {
    let heavy = Member::start("heavy").await;
    let light = Member::start("light").await;
    let port = free_port();
    let running = Running::start(&Document::new(
        port,
        vec![heavy.entry(2, "enabled"), light.entry(1, "enabled")],
    ))
    .await;

    let answers = spread(running.port, 90).await;
    let heavy_share = count(&answers, "heavy");
    let light_share = count(&answers, "light");

    assert_eq!(
        heavy_share, 60,
        "the heavier member took {heavy_share} of 90"
    );
    assert_eq!(
        light_share, 30,
        "the lighter member took {light_share} of 90"
    );
    assert_eq!(
        heavy_share,
        light_share * 2,
        "weight 2 did not take twice the share of weight 1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn least_connections_sends_the_next_request_to_the_member_that_is_not_busy() {
    let slow = Member::with_behaviour("slow", Behaviour::Slow(Duration::from_millis(700))).await;
    let quick = Member::start("quick").await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![slow.entry(1, "enabled"), quick.entry(1, "enabled")],
    )
    .algorithm("least_connections");
    let running = Running::start(&document).await;

    // Fill the slow member with requests that are still in flight. Least
    // connections has to count those, not the requests already finished.
    let mut holding = Vec::new();
    for _ in 0..4 {
        let port = running.port;
        holding.push(tokio::spawn(async move {
            ask_once(port, &plain_request()).await
        }));
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    // Now ask, while the slow member is carrying open connections.
    let answers = spread(running.port, 6).await;
    for answer in &answers {
        assert_eq!(
            answer, "quick",
            "a request went to the busy member while an idle one was free"
        );
    }

    for held in holding {
        let answer = held
            .await
            .expect("a held request must finish")
            .expect("a held request must be answered");
        assert_eq!(answer.status, 200, "a held request was not proxied");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_ip_hash_sends_one_client_address_to_one_member_every_time() {
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let three = Member::start("three").await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![
            one.entry(1, "enabled"),
            two.entry(1, "enabled"),
            three.entry(1, "enabled"),
        ],
    )
    .algorithm("source_ip_hash");
    let running = Running::start(&document).await;

    // Thirty separate connections, all from the same address. Round robin
    // would spread these over all three members.
    let answers = spread(running.port, 30).await;
    let distinct: BTreeSet<&String> = answers.iter().collect();

    assert_eq!(
        distinct.len(),
        1,
        "one client address reached {} members: {distinct:?}",
        distinct.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_disabled_member_receives_nothing() {
    let taking = Member::start("taking").await;
    let disabled = Member::start("disabled").await;
    let port = free_port();
    let running = Running::start(&Document::new(
        port,
        vec![taking.entry(1, "enabled"), disabled.entry(1, "disabled")],
    ))
    .await;

    let answers = spread(running.port, 40).await;

    assert_eq!(
        count(&answers, "taking"),
        40,
        "the enabled member did not take every request"
    );
    assert_eq!(
        disabled.hits(),
        0,
        "a member an operator disabled answered {} requests",
        disabled.hits()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_member_unreachable_is_answered_rather_than_the_connection_being_closed() {
    // A port nothing listens on. The pool is configured and its member is
    // enabled, so this is a backend fault rather than a missing pool.
    let dead = free_port();
    let port = free_port();
    let members = vec![format!(
        r#"{{"id":"dead","address":"127.0.0.1","port":{dead},"weight":1,"admin_state":"enabled"}}"#
    )];
    let running = Running::start(&Document::new(port, members)).await;

    let answer: Answer = ask_once(running.port, &plain_request())
        .await
        .expect("an unreachable pool must still produce an answer, not a closed connection");

    assert_eq!(
        answer.status, 503,
        "an unreachable pool was answered {} rather than 503",
        answer.status
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_whose_members_are_all_out_of_service_is_answered_not_hung_up_on() {
    // A different fault from an unreachable member: everybody is reachable
    // and nobody is allowed to take traffic. It must still produce an answer.
    let out = Member::start("out").await;
    let port = free_port();
    let running = Running::start(&Document::new(port, vec![out.entry(1, "disabled")])).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("a pool with nobody enabled must answer, not close the connection");

    assert_eq!(
        answer.status, 503,
        "a pool with nobody enabled answered {}",
        answer.status
    );
    assert_eq!(
        out.hits(),
        0,
        "a member an operator disabled took a request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_that_never_answers_produces_a_timeout_answer() {
    let silent = Member::with_behaviour("silent", Behaviour::Silent).await;
    let port = free_port();
    let document = Document::new(port, vec![silent.entry(1, "enabled")]).request_timeout(1);
    let running = Running::start(&document).await;

    let started = tokio::time::Instant::now();
    let answer = tokio::time::timeout(
        Duration::from_secs(10),
        ask_once(running.port, &plain_request()),
    )
    .await
    .expect("the proxy must give up rather than wait forever")
    .expect("a timed out request must still produce an answer");

    assert_eq!(
        answer.status, 504,
        "a backend that never answered produced {} rather than 504",
        answer.status
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the proxy waited {:?}, which is not the one second it was told",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_timeout_of_one_hour_is_accepted_and_does_not_cut_a_long_request() {
    // ActiveSync push and IMAP IDLE need an hour or more (ADR-0058). What is
    // measured is that the value is accepted and honoured, not that an hour
    // passes.
    let patient =
        Member::with_behaviour("patient", Behaviour::Slow(Duration::from_millis(1200))).await;
    let port = free_port();
    let document = Document::new(port, vec![patient.entry(1, "enabled")]).request_timeout(3_600);
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("a long request must be answered, not cut");

    assert_eq!(
        answer.status, 200,
        "an hour long limit did not let a slow answer through"
    );
    assert_eq!(answer.member(), "patient");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarded_for_carries_the_client_address_and_replaces_what_the_client_claimed() {
    let only = Member::start("only").await;
    let port = free_port();
    let running = Running::start(&Document::new(port, vec![only.entry(1, "enabled")])).await;

    // The client puts its own value in. Anyone can, so it carries no
    // authority and must not survive.
    let forged = "GET / HTTP/1.1\r\nHost: ek-ek.test\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n";
    let stream = TcpStream::connect(("127.0.0.1", running.port))
        .await
        .expect("the frontend must accept a connection");
    let source = stream
        .local_addr()
        .expect("an open connection must have an address")
        .ip()
        .to_string();
    let mut io = BufReader::new(stream);
    let answer = ask(&mut io, forged)
        .await
        .expect("the request must be answered");

    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.field("forwarded_for"),
        source,
        "the header did not carry the address the request actually came from"
    );
    assert!(
        !answer.field("forwarded_for").contains("203.0.113.9"),
        "a forged X-Forwarded-For survived to the backend: {:?}",
        answer.field("forwarded_for")
    );
    assert_eq!(
        answer.field("forwarded_proto"),
        "http",
        "the scheme the client used was not reported"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_redirect_rule_is_answered_without_touching_a_backend() {
    // The point of answering here is that no plaintext request is forwarded
    // anywhere (ADR-0057), so what is measured is both the answer and the
    // backend staying untouched.
    let never = Member::start("never").await;
    let port = free_port();
    let mut document = Document::new(port, vec![never.entry(1, "enabled")]);
    document.routing_rules = vec![
        r#"{"host_pattern":null,"path_prefix":null,"action":{"type":"redirect","status":"permanent"},"request_timeout_seconds":null}"#
            .to_owned(),
    ];
    let running = Running::start(&document).await;

    let request = "GET /owa/auth?a=1 HTTP/1.1\r\nHost: mail.example.test:80\r\n\r\n";
    let stream = TcpStream::connect(("127.0.0.1", running.port))
        .await
        .expect("the frontend must accept a connection");
    let mut io = BufReader::new(stream);
    let answer = ask(&mut io, request)
        .await
        .expect("the request must be answered");

    assert_eq!(
        answer.status, 308,
        "the redirect was answered {}",
        answer.status
    );
    assert_eq!(
        answer.header("location"),
        "https://mail.example.test/owa/auth?a=1",
        "the redirect dropped the path, the query or the host"
    );
    assert_eq!(
        never.hits(),
        0,
        "a redirect reached a backend, so a plaintext request left the proxy"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_request_is_decided_entirely_from_one_snapshot() {
    // A request that read the configuration twice could decide to proxy on
    // the first read and find a redirect listener on the second, which is a
    // request nobody configured (ADR-0009). The two deliveries below differ
    // in exactly that, so a request that mixes them is answered 503 while a
    // request decided from one of them is answered 200 or 308.
    let only = Member::start("only").await;
    let port = free_port();

    let proxying = Document::new(port, vec![only.entry(1, "enabled")]);
    let mut redirecting = Document::new(port, vec![only.entry(1, "enabled")]);
    redirecting.routing_rules = vec![
        r#"{"host_pattern":null,"path_prefix":null,"action":{"type":"redirect","status":"permanent"},"request_timeout_seconds":null}"#
            .to_owned(),
    ];

    let running = Running::start(&proxying).await;
    running.agent.wait_linked().await;

    // The window between the two reads is a few microseconds wide, so it is
    // hit by volume: many askers at once against a configuration changing as
    // fast as it can be delivered.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut askers = Vec::new();
    for _ in 0..16 {
        let stopped = std::sync::Arc::clone(&stop);
        askers.push(tokio::spawn(async move {
            let mut mixed = 0_usize;
            let mut asked = 0_usize;
            while !stopped.load(std::sync::atomic::Ordering::SeqCst) {
                if let Ok(answer) = ask_once(port, &plain_request()).await {
                    asked += 1;
                    if answer.status != 200 && answer.status != 308 {
                        mixed += 1;
                    }
                }
            }
            (asked, mixed)
        }));
    }

    // Alternate the two deliveries underneath the traffic.
    for generation in 2..2_000_u64 {
        let document = if generation % 2 == 0 {
            &redirecting
        } else {
            &proxying
        };
        running.agent.push(&document.delivery(generation));
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    stop.store(true, std::sync::atomic::Ordering::SeqCst);

    let mut asked = 0_usize;
    let mut mixed = 0_usize;
    for asker in askers {
        let (one, two) = asker.await.expect("an asking task must finish");
        asked += one;
        mixed += two;
    }

    assert!(
        asked > 200,
        "only {asked} requests were made, which measures nothing"
    );
    assert_eq!(
        mixed, 0,
        "{mixed} of {asked} requests were decided from two different deliveries"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frontend_with_nowhere_to_send_answers_rather_than_hanging_up() {
    let port = free_port();
    let only = Member::start("only").await;
    let mut document = Document::new(port, vec![only.entry(1, "enabled")]);
    // No rule matches and no default pool: there is nothing to proxy to.
    document.default_backend = "null".to_owned();
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("a frontend with no pool must answer");

    assert_eq!(
        answer.status, 503,
        "a frontend with nowhere to send answered {}",
        answer.status
    );
    assert_eq!(
        only.hits(),
        0,
        "a request reached a pool nothing pointed at"
    );
}
