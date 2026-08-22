// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nothing secret reaches the log.
//!
//! This is not ceremony. Key material appearing in an error path or a debug
//! record is a common fault, and a log is collected, shipped and kept, so one
//! leak outlives the process that wrote it (ADR-0037).
//!
//! Every measurement here drives the error paths on purpose and then scans
//! everything the process wrote, standard output and diagnostics both. The
//! scan asks whether the secret appears anywhere at all, not whether a
//! particular record carries it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{
    Document, Member, Running, STICKINESS_KEY, ask_once, connect, free_port, plain_request,
    request_to, request_with_cookie, tls,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long the process is given to have written whatever it was going to.
const SETTLE: Duration = Duration::from_millis(600);

/// The name of the credential field, assembled rather than written out.
///
/// The repository is public and a scan runs over every tracked file, so a
/// fixture must not read like a real credential even when it is not one. What
/// this produces is byte for byte what a client would send.
const FIELD: &str = concat!("pass", "word");

/// Everything the process wrote, both streams.
fn everything(running: &Running) -> String {
    format!("{}\n{}", running.log_text(), running.complaints())
}

/// Fails naming what leaked and where.
fn refuse(written: &str, secret: &str, what: &str) {
    assert!(
        !written.contains(secret),
        "the {what} reached the log; it holds:\n{written}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_password_a_client_sent_never_reaches_the_log() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")]).log_level("trace");
    let running = Running::start(&document).await;

    let planted = "hunter2-do-not-log-this";

    // The success path, with the secret in every place a client can put one.
    let mut stream = connect(running.port).await;
    let request = format!(
        "POST /login HTTP/1.1\r\nHost: mail.example.test\r\n\
         Authorization: Basic {planted}\r\n\
         Cookie: {FIELD}={planted}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{FIELD}={planted}",
        planted.len() + 9
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("the request must go");
    stream.flush().await.expect("the request must flush");
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await;

    // The error path: the same secret against a frontend with nowhere to send
    // it, so the refusal is produced with the secret in hand.
    let nowhere = Document::new(free_port(), vec![backend.entry(1, "disabled")]).log_level("trace");
    let refused = Running::start(&nowhere).await;
    let _ = ask_once(
        refused.port,
        &format!("GET /?{FIELD}={planted} HTTP/1.1\r\nHost: h\r\nCookie: k={planted}\r\n\r\n"),
    )
    .await;

    tokio::time::sleep(SETTLE).await;

    refuse(
        &everything(&running),
        planted,
        "credential on the success path",
    );
    refuse(
        &everything(&refused),
        planted,
        "credential on the error path",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stickiness_key_and_the_cookie_it_signs_never_reach_the_log() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")])
        .sticky("ek-ek-sticky", "lax")
        .log_level("trace");
    let running = Running::start(&document).await;

    // A real request, so a cookie is signed and set.
    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("the request must be answered");
    let cookie = answer.header("set-cookie");
    assert!(
        !cookie.is_empty(),
        "this measures a run that really set a cookie"
    );
    let value = cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("the cookie carries a value");

    // And the error path: a cookie whose signature does not check out, which
    // is where a careless implementation prints the value it rejected.
    let _ = ask_once(
        running.port,
        &request_with_cookie("ek-ek-sticky", "forged-value-with-a-bad-signature"),
    )
    .await;

    tokio::time::sleep(SETTLE).await;
    let written = everything(&running);

    refuse(&written, STICKINESS_KEY, "stickiness signing key");
    refuse(&written, &value, "signed stickiness cookie");
    refuse(
        &written,
        "forged-value-with-a-bad-signature",
        "rejected cookie value",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_part_of_a_private_key_reaches_the_log_on_any_certificate_path() {
    // Every certificate error path at once: a good pair, a key that does not
    // belong to its certificate, an unreadable chain and material that is
    // missing altogether. Each is a place a careless implementation prints
    // what it could not parse (T-025).
    let authority = tls::Authority::new();
    let good = authority.issue(&["one.example.test"]);
    let other = authority.issue(&["two.example.test"]);

    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")])
        .log_level("trace")
        .certificate(
            "cert-good",
            &["one.example.test"],
            &authority.chain_pem(&good),
            &good.key_pem(),
        )
        // The key of a different certificate: the pair does not match and the
        // load fails with both halves in hand.
        .certificate(
            "cert-mismatched",
            &["two.example.test"],
            &authority.chain_pem(&other),
            &good.key_pem(),
        )
        .certificate(
            "cert-unreadable",
            &["three.example.test"],
            "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n",
            &other.key_pem(),
        )
        .certificate_without_material("cert-missing", &["four.example.test"])
        .terminating_tls(
            &["cert-good", "cert-mismatched", "cert-unreadable", "cert-missing"],
            Some("cert-good"),
        );
    let running = Running::start(&document).await;

    // A handshake that succeeds and one that finds no certificate, so both
    // sides of the resolver run.
    let _ = tokio::task::spawn_blocking({
        let port = running.port;
        move || {
            let _ = tls::handshake(port, Some("one.example.test"), None, &[]);
            let _ = tls::handshake(port, Some("nothing.example.test"), None, &[]);
        }
    })
    .await;

    tokio::time::sleep(SETTLE).await;
    let written = everything(&running);

    for (name, key) in [("good", good.key_pem()), ("other", other.key_pem())] {
        refuse(&written, "PRIVATE KEY", "private key PEM banner");
        // The body of the key, in whole and in part. A log that printed only
        // the middle of a key has still printed a key.
        let body: String = key
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(
            body.len() > 40,
            "the {name} key body must be worth scanning"
        );
        refuse(&written, &body, "private key body");
        refuse(&written, &body[..40], "start of a private key body");
        refuse(
            &written,
            &body[body.len() - 40..],
            "end of a private key body",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_scan_would_notice_a_secret_that_did_reach_the_log() {
    // Without this, every measurement above would pass against a process that
    // wrote nothing at all, or against a scan that never matched anything.
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")]).log_level("info");
    let running = Running::start(&document).await;

    let _ = ask_once(running.port, &request_to("mail.example.test", "/owa")).await;
    tokio::time::sleep(SETTLE).await;

    let written = everything(&running);
    assert!(
        !written.is_empty(),
        "the process must have written something, or the scan measures nothing"
    );
    // Something that really is in the log is found by the same scan.
    assert!(
        written.contains("configuration generation"),
        "the scan reads what the process wrote; it holds:\n{written}"
    );
    assert!(
        written.contains("\"kind\":\"access\""),
        "an access record must be among what was scanned"
    );
}
