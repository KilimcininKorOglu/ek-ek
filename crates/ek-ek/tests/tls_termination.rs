// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Terminating TLS and choosing the certificate from the SNI name.
//!
//! Measured against the real binary over real handshakes: the certificate a
//! test reads back is the one the server actually presented, taken off the
//! connection rather than out of a log line.
//!
//! Certificates are issued here, in the test, and never committed. A PEM
//! block in a tracked file is a key in the repository whatever it protects.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{Document, Member, Running, ask_once, free_port, plain_request, tls};

/// How long a certificate change gets to reach the traffic path.
const SWAP_PATIENCE: Duration = Duration::from_secs(10);

/// Waits until a handshake presents the certificate named.
///
/// A delivery is applied between two handshakes rather than during one, so a
/// test that connected once would measure the race and not the rule.
fn wait_until_served(port: u16, name: &str, expected: &str) -> String {
    let deadline = std::time::Instant::now() + SWAP_PATIENCE;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(seen) = tls::handshake(port, Some(name), None, &[]) {
            last = seen.served;
            if last == expected {
                return last;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    last
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_https_request_reaches_the_backend_as_plain_http() {
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let leaf = authority.issue(&["one.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    let running = Running::start(&document).await;

    let answer = tls::request(running.port, "one.example.test", &plain_request())
        .expect("a request over TLS must be answered");

    assert!(
        answer.starts_with("HTTP/1.1 200 OK"),
        "the request was not answered: {answer}"
    );
    assert!(
        answer.contains("member=one"),
        "the request never reached the backend: {answer}"
    );
    // The member is a plaintext HTTP server, so it answering at all is the
    // measurement that TLS was terminated before it. What it saw of the
    // client's own scheme comes from the header the proxy sets.
    assert!(
        answer.contains("forwarded_proto=https"),
        "the backend was not told the client arrived over TLS: {answer}"
    );
    assert_eq!(one.hits(), 1, "the backend answered a different number");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plaintext_request_tells_the_backend_it_was_plaintext() {
    // The other side of the same rule. A header that always said `https`
    // would let a backend build absolute URLs that no plaintext client can
    // follow.
    let one = Member::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]);
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("a request must be answered");

    assert!(
        answer.body.contains("forwarded_proto=http"),
        "a plaintext frontend claimed TLS: {}",
        answer.body
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_names_are_served_two_different_certificates() {
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let first = authority.issue(&["one.example.test"]);
    let second = authority.issue(&["two.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&first),
            &first.key_pem(),
        )
        .certificate(
            "cert-two",
            &["two.example.test"],
            &authority.chain_pem(&second),
            &second.key_pem(),
        )
        .terminating_tls(&["cert-one", "cert-two"], None);
    let running = Running::start(&document).await;

    let root = authority.root_pem();
    let asked_one = tls::handshake(running.port, Some("one.example.test"), Some(&root), &[])
        .expect("the first handshake must complete");
    let asked_two = tls::handshake(running.port, Some("two.example.test"), Some(&root), &[])
        .expect("the second handshake must complete");

    assert_eq!(asked_one.served, "one.example.test");
    assert_eq!(asked_two.served, "two.example.test");
    assert_ne!(
        asked_one.served, asked_two.served,
        "one certificate was served for both names"
    );

    // The chain reached the client, so it could build a path to the root it
    // trusts. A leaf on its own would verify only where the intermediate is
    // already installed.
    assert!(asked_one.verified, "the client could not verify the chain");
    assert!(
        asked_one.chain_length >= 2,
        "the intermediate was not sent: {} certificate(s)",
        asked_one.chain_length
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wildcard_covers_one_label_over_a_real_handshake() {
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let wide = authority.issue(&["*.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-wide",
            &["*.example.test"],
            &authority.chain_pem(&wide),
            &wide.key_pem(),
        )
        .terminating_tls(&["cert-wide"], None);
    let running = Running::start(&document).await;

    let covered = tls::handshake(running.port, Some("one.example.test"), None, &[])
        .expect("a name the wildcard covers must be served");
    assert_eq!(covered.served, "*.example.test");

    // Two labels deep is outside the wildcard, and no client would accept it
    // there either.
    assert!(
        tls::handshake(running.port, Some("deep.one.example.test"), None, &[]).is_err(),
        "the wildcard was stretched over two labels"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_nobody_covers_is_refused_and_counted() {
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let leaf = authority.issue(&["one.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    let running = Running::start(&document).await;

    // The setup works, so a refusal below is about the name and not about
    // the listener.
    assert!(tls::handshake(running.port, Some("one.example.test"), None, &[]).is_ok());

    let refused = tls::handshake(running.port, Some("nobody.example.test"), None, &[])
        .expect_err("a name nobody covers must be refused");
    println!("the handshake was refused: {refused}");

    // And nothing else was handed over in its place.
    assert!(
        !refused.contains("one.example.test"),
        "a certificate was served to a name it does not cover: {refused}"
    );

    let counted = running.agent.wait_for_refused_handshakes(1).await;
    assert!(
        counted >= 1,
        "a refused handshake was not reported, so an operator cannot see it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_nobody_covers_gets_the_default_when_one_is_named() {
    // The other side. The fallback is a certificate the operator named, never
    // one picked at random (ADR-0070).
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let first = authority.issue(&["one.example.test"]);
    let fallback = authority.issue(&["fallback.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&first),
            &first.key_pem(),
        )
        .certificate(
            "cert-fallback",
            &["fallback.example.test"],
            &authority.chain_pem(&fallback),
            &fallback.key_pem(),
        )
        .terminating_tls(&["cert-one", "cert-fallback"], Some("cert-fallback"));
    let running = Running::start(&document).await;

    let seen = tls::handshake(running.port, Some("nobody.example.test"), None, &[])
        .expect("the default must be served");
    assert_eq!(seen.served, "fallback.example.test");

    // The name that has its own certificate still gets its own.
    let own = tls::handshake(running.port, Some("one.example.test"), None, &[])
        .expect("the exact name must be served");
    assert_eq!(own.served, "one.example.test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_sends_no_name_gets_the_default() {
    // What `curl https://IP/` and a monitoring check both look like.
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let leaf = authority.issue(&["one.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .terminating_tls(&["cert-one"], Some("cert-one"));
    let running = Running::start(&document).await;

    let seen = tls::handshake(running.port, None, None, &[])
        .expect("a client with no name must be served the default");

    assert_eq!(seen.served, "one.example.test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_sends_no_name_is_refused_when_no_default_is_named() {
    // The other side. With no default there is nothing to fall back to, and
    // guessing would serve a certificate for a name nobody asked about.
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let leaf = authority.issue(&["one.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    let running = Running::start(&document).await;

    assert!(
        tls::handshake(running.port, Some("one.example.test"), None, &[]).is_ok(),
        "the setup must work, or the refusal below measures nothing"
    );
    assert!(
        tls::handshake(running.port, None, None, &[]).is_err(),
        "a client that named nothing was served a certificate anyway"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_2_is_agreed_with_alpn() {
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let leaf = authority.issue(&["one.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    let running = Running::start(&document).await;

    let seen = tls::handshake(
        running.port,
        Some("one.example.test"),
        None,
        &["h2", "http/1.1"],
    )
    .expect("the handshake must complete");

    assert_eq!(
        seen.alpn.as_deref(),
        Some("h2"),
        "HTTP/2 was offered and not agreed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_offers_only_http_1_1_gets_http_1_1() {
    // The other side. A listener that always answered `h2` would break every
    // client that cannot speak it.
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let leaf = authority.issue(&["one.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    let running = Running::start(&document).await;

    let seen = tls::handshake(running.port, Some("one.example.test"), None, &["http/1.1"])
        .expect("the handshake must complete");

    assert_eq!(seen.alpn.as_deref(), Some("http/1.1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_connection_gets_the_new_certificate_without_a_restart() {
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let before = authority.issue(&["one.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&before),
            &before.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    let running = Running::start(&document).await;
    let pid = running.pid();

    let first = tls::handshake(running.port, Some("one.example.test"), None, &[])
        .expect("the first handshake must complete");
    assert_eq!(first.served, "one.example.test");
    let was = first.served.clone();

    // The same SNI name, different material behind it. Renewal looks exactly
    // like this. The replacement carries a different common name only so a
    // test can tell the two apart on the wire.
    let after = authority.issue(&["renewed.example.test"]);
    let replacement = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&after),
            &after.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    running.agent.push(&replacement.delivery(2));

    let now = wait_until_served(running.port, "one.example.test", "renewed.example.test");
    assert_eq!(
        now, "renewed.example.test",
        "a new connection was still served the old certificate"
    );
    assert_ne!(now, was, "the certificate did not change at all");

    // And it was the same process throughout. A replacement would have made
    // the change true and the rule untested.
    assert_eq!(
        running.pid(),
        pid,
        "the process was replaced instead of swapping its certificates"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_open_across_a_certificate_change_is_not_cut() {
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let before = authority.issue(&["one.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&before),
            &before.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    let running = Running::start(&document).await;

    // A connection that stays open across the change, with a request on it
    // before and a request on it after.
    let mut held = tls::open(running.port, "one.example.test").expect("it must connect");
    let first = tls::exchange(&mut held, &plain_request()).expect("the first request");
    assert!(
        first.contains("member=one"),
        "the first request did not reach the backend: {first}"
    );

    let after = authority.issue(&["renewed.example.test"]);
    let replacement = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-one",
            &["one.example.test"],
            &authority.chain_pem(&after),
            &after.key_pem(),
        )
        .terminating_tls(&["cert-one"], None);
    running.agent.push(&replacement.delivery(2));

    // The change has landed once a fresh connection sees the new certificate.
    let now = wait_until_served(running.port, "one.example.test", "renewed.example.test");
    assert_eq!(now, "renewed.example.test", "the change never landed");

    let second = tls::exchange(&mut held, &plain_request())
        .expect("the connection open across the change must still work");
    assert!(
        second.contains("member=one"),
        "a connection open across a certificate change was cut: {second}"
    );
    assert_eq!(
        one.hits(),
        2,
        "the backend saw a different number of requests"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_whose_material_never_arrived_serves_nothing_and_says_nothing_secret() {
    // The error path, run for real: the configuration names a certificate and
    // the delivery carries no material for it.
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let leaf = authority.issue(&["served.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-served",
            &["served.example.test"],
            &authority.chain_pem(&leaf),
            &leaf.key_pem(),
        )
        .certificate_without_material("cert-missing", &["missing.example.test"])
        .terminating_tls(&["cert-served", "cert-missing"], None);
    let running = Running::start(&document).await;

    assert!(
        tls::handshake(running.port, Some("served.example.test"), None, &[]).is_ok(),
        "the certificate that did arrive must still be served"
    );
    assert!(
        tls::handshake(running.port, Some("missing.example.test"), None, &[]).is_err(),
        "a certificate with no material was served anyway"
    );

    // Whatever the process wrote about it, none of it is key material.
    let said = running.complaints();
    for line in leaf
        .key_pem()
        .lines()
        .filter(|line| !line.starts_with("-----"))
    {
        assert!(
            !said.contains(line),
            "a private key reached the diagnostics: {said}"
        );
    }
    assert!(
        !said.contains("PRIVATE KEY"),
        "a private key block reached the diagnostics: {said}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_that_does_not_belong_to_its_certificate_leaks_nothing() {
    // The other error path: material arrives, and the two halves do not go
    // together. A handshake built on that pair fails on the client and says
    // nothing on the server, so it is refused at load time instead.
    let one = Member::start("one").await;
    let port = free_port();
    let authority = tls::Authority::new();
    let leaf = authority.issue(&["mixed.example.test"]);
    let stranger = authority.issue(&["stranger.example.test"]);
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .certificate(
            "cert-mixed",
            &["mixed.example.test"],
            &authority.chain_pem(&leaf),
            &stranger.key_pem(),
        )
        .terminating_tls(&["cert-mixed"], None);
    let running = Running::start(&document).await;

    assert!(
        tls::handshake(running.port, Some("mixed.example.test"), None, &[]).is_err(),
        "a certificate was served with a key that does not belong to it"
    );

    let said = running.complaints();
    for key in [stranger.key_pem(), leaf.key_pem()] {
        for line in key.lines().filter(|line| !line.starts_with("-----")) {
            assert!(
                !said.contains(line),
                "a private key reached the diagnostics: {said}"
            );
        }
    }
}
