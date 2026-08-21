// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What each probe type decides, and how a run of answers becomes a state.
//!
//! Every probe here reaches a real socket. A probe that was measured against a
//! stub would prove the parsing and nothing about whether the bytes it sends
//! are the bytes a server understands.
//!
//! The thresholds are measured separately, because they are pure arithmetic
//! over a sequence of answers and need no network at all.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ek_ek_config::{DnsRecordType, HealthCheck, HealthProbe, ProbePayload, TransportProtocol};
use ek_ek_dataplane::probe::{self, PROBE_AGENT};
use ek_ek_dataplane::{Change, Health};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// The loopback address every stand-in listens on.
const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Long enough that a working probe finishes, short enough that a broken one
/// does not hold the test.
const PATIENCE: Duration = Duration::from_secs(5);

/// A port nothing is listening on.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port must be free");
    let port = listener
        .local_addr()
        .expect("the listener must have an address")
        .port();
    drop(listener);
    port
}

/// A check with the given thresholds and generous timing.
fn check(probe: HealthProbe, healthy: u8, unhealthy: u8) -> HealthCheck {
    HealthCheck {
        probe,
        interval_ms: 5_000,
        timeout_ms: 2_000,
        healthy_threshold: healthy,
        unhealthy_threshold: unhealthy,
    }
}

/// A stand-in TCP server, answering with whatever it is told to.
struct Server {
    port: u16,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
    accepted: Arc<AtomicU64>,
    accept: tokio::task::JoinHandle<()>,
}

/// What a stand-in TCP server does with a connection.
#[derive(Clone, Debug)]
enum Answers {
    /// Accepts and closes, which is all a connect probe needs.
    Nothing,
    /// Writes these bytes and closes.
    With(Vec<u8>),
    /// Writes these bytes before reading anything, then holds the connection
    /// open the way a mail server waits for the next command.
    Greeting(Vec<u8>),
    /// Accepts and holds the connection without answering.
    Silence,
}

impl Server {
    async fn start(answers: Answers) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port must be free");
        let port = listener
            .local_addr()
            .expect("the listener must have an address")
            .port();

        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let accepted = Arc::new(AtomicU64::new(0));
        let collected = Arc::clone(&seen);
        let counted = Arc::clone(&accepted);

        let accept = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                let answers = answers.clone();
                let collected = Arc::clone(&collected);

                tokio::spawn(async move {
                    if let Answers::Greeting(greeting) = &answers {
                        let _ = stream.write_all(greeting).await;
                    }
                    if matches!(answers, Answers::Silence) {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    }

                    let mut buffer = vec![0_u8; 8192];
                    if let Ok(read) = stream.read(&mut buffer).await
                        && read > 0
                        && let Ok(mut store) = collected.lock()
                    {
                        store.push(String::from_utf8_lossy(&buffer[..read]).into_owned());
                    }

                    if let Answers::With(bytes) = &answers {
                        let _ = stream.write_all(bytes).await;
                    }

                    if matches!(answers, Answers::Greeting(_)) {
                        // A mail server does not hang up after the greeting.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                });
            }
        });

        Self {
            port,
            seen,
            accepted,
            accept,
        }
    }

    /// A server answering one HTTP response.
    async fn http(status: u16, body: &str) -> Self {
        let answer = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        Self::start(Answers::With(answer.into_bytes())).await
    }

    fn requests(&self) -> Vec<String> {
        self.seen
            .lock()
            .map(|store| store.clone())
            .unwrap_or_default()
    }

    fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// Runs one probe against a port and returns whether it succeeded.
async fn probe_port(probe: &HealthProbe, port: u16) -> probe::Outcome {
    tokio::time::timeout(PATIENCE, probe::run(probe, LOCAL, port, PATIENCE))
        .await
        .expect("a probe must not outlive the test")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_connect_probe_fails_against_a_closed_port() {
    let open = Server::start(Answers::Nothing).await;

    let good = probe_port(&HealthProbe::TcpConnect, open.port).await;
    assert!(
        good.is_good(),
        "an open port was called unhealthy: {good:?}"
    );

    // The probe closes as soon as the connection is up, so the server may
    // still be inside accept when the probe returns.
    let start = tokio::time::Instant::now();
    while open.accepted() == 0 {
        assert!(
            start.elapsed() < PATIENCE,
            "the probe never reached the port"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let bad = probe_port(&HealthProbe::TcpConnect, free_port()).await;
    assert!(!bad.is_good(), "a closed port was called healthy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http_probe_fails_when_the_status_is_not_expected() {
    let probe = HealthProbe::Http {
        path: "/healthz".to_owned(),
        expected_status: vec![200, 204],
        expected_body: None,
        host_header: None,
    };

    let good = Server::http(200, "ok").await;
    assert!(probe_port(&probe, good.port).await.is_good());

    let wrong = Server::http(503, "down").await;
    let outcome = probe_port(&probe, wrong.port).await;
    assert!(!outcome.is_good(), "a 503 was called healthy: {outcome:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http_probe_fails_when_the_body_does_not_match() {
    let probe = HealthProbe::Http {
        path: "/healthz".to_owned(),
        expected_status: vec![200],
        expected_body: Some("READY".to_owned()),
        host_header: None,
    };

    let good = Server::http(200, "status: READY").await;
    assert!(probe_port(&probe, good.port).await.is_good());

    // Right status, wrong body. Checking only the status would miss a
    // service that answers 200 while its dependency is gone.
    let wrong = Server::http(200, "status: STARTING").await;
    let outcome = probe_port(&probe, wrong.port).await;
    assert!(!outcome.is_good(), "a wrong body was accepted: {outcome:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http_probe_does_not_match_the_body_against_a_header() {
    // The expected text appears in a header and nowhere in the body. Searching
    // the whole answer would call this healthy.
    let body = "not ready";
    let answer = format!(
        "HTTP/1.1 200 X\r\nX-State: READY\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let server = Server::start(Answers::With(answer.into_bytes())).await;

    let probe = HealthProbe::Http {
        path: "/healthz".to_owned(),
        expected_status: vec![200],
        expected_body: Some("READY".to_owned()),
        host_header: None,
    };

    let outcome = probe_port(&probe, server.port).await;
    assert!(
        !outcome.is_good(),
        "a header stood in for the body: {outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http_probe_sends_the_host_header_and_names_itself() {
    let server = Server::http(200, "ok").await;
    let probe = HealthProbe::Http {
        path: "/healthz".to_owned(),
        expected_status: vec![200],
        expected_body: None,
        host_header: Some("mail.example.test".to_owned()),
    };

    assert!(probe_port(&probe, server.port).await.is_good());

    let request = server
        .requests()
        .first()
        .cloned()
        .expect("the request must have arrived");
    assert!(
        request.contains("Host: mail.example.test"),
        "the host header was not sent: {request:?}"
    );
    assert!(
        request.contains(PROBE_AGENT),
        "probe traffic is not identifiable in a backend log: {request:?}"
    );
    assert!(
        request.starts_with("GET /healthz "),
        "the configured path was not requested: {request:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_expect_probe_over_tcp_checks_the_answer() {
    let probe = HealthProbe::SendExpect {
        send: ProbePayload::Text("a001 CAPABILITY\r\n".to_owned()),
        expect: ProbePayload::Text("* OK".to_owned()),
        transport: TransportProtocol::Tcp,
    };

    let good = Server::start(Answers::With(b"* OK IMAP4rev1 ready\r\n".to_vec())).await;
    assert!(probe_port(&probe, good.port).await.is_good());

    let wrong = Server::start(Answers::With(b"* BAD server is broken\r\n".to_vec())).await;
    let outcome = probe_port(&probe, wrong.port).await;
    assert!(
        !outcome.is_good(),
        "a wrong banner was accepted: {outcome:?}"
    );

    let sent = good
        .requests()
        .first()
        .cloned()
        .expect("the probe data must have arrived");
    assert_eq!(sent, "a001 CAPABILITY\r\n", "the probe sent something else");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_expect_probe_reads_a_banner_the_server_sends_first() {
    // SMTP and IMAP greet before the client says anything, and then wait. A
    // probe that read until the connection closed would time out against
    // every one of them.
    let server = Server::start(Answers::Greeting(
        b"220 mail.example.test ESMTP\r\n".to_vec(),
    ))
    .await;
    let probe = HealthProbe::SendExpect {
        send: ProbePayload::Text("QUIT\r\n".to_owned()),
        expect: ProbePayload::Text("220 ".to_owned()),
        transport: TransportProtocol::Tcp,
    };

    let started = tokio::time::Instant::now();
    let outcome = probe::run(&probe, LOCAL, server.port, Duration::from_secs(3)).await;

    assert!(outcome.is_good(), "a banner was not read: {outcome:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the probe waited {:?} for a close that never comes",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_expect_probe_can_send_hex() {
    // Binary protocols cannot be written as text. The bytes below are
    // "* OK" and must reach the server exactly.
    let probe = HealthProbe::SendExpect {
        send: ProbePayload::Hex("2a204f4b".to_owned()),
        expect: ProbePayload::Hex("2a204f4b".to_owned()),
        transport: TransportProtocol::Tcp,
    };
    let server = Server::start(Answers::With(b"* OK".to_vec())).await;

    assert!(probe_port(&probe, server.port).await.is_good());
    assert_eq!(
        server.requests().first().map(String::as_str),
        Some("* OK"),
        "the hex payload did not arrive as the bytes it names"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_expect_probe_over_udp_checks_the_answer() {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a port must be free");
    let port = socket
        .local_addr()
        .expect("the socket must have an address")
        .port();

    let answering = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 1024];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            // Answers only what it was asked, so a probe expecting something
            // else fails against the same server.
            let _ = socket.send_to(&buffer[..read], from).await;
        }
    });

    let good = HealthProbe::SendExpect {
        send: ProbePayload::Text("PING".to_owned()),
        expect: ProbePayload::Text("PING".to_owned()),
        transport: TransportProtocol::Udp,
    };
    assert!(probe_port(&good, port).await.is_good());

    let wrong = HealthProbe::SendExpect {
        send: ProbePayload::Text("PING".to_owned()),
        expect: ProbePayload::Text("PONG".to_owned()),
        transport: TransportProtocol::Udp,
    };
    assert!(
        !probe_port(&wrong, port).await.is_good(),
        "a wrong answer was accepted over UDP"
    );

    answering.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_expect_probe_over_udp_fails_when_nothing_answers() {
    let probe = HealthProbe::SendExpect {
        send: ProbePayload::Text("PING".to_owned()),
        expect: ProbePayload::Text("PONG".to_owned()),
        transport: TransportProtocol::Udp,
    };
    // Nothing is bound. On UDP this is silence rather than a refusal, which
    // is why the probe has to give up on its own timeout.
    let outcome = probe::run(&probe, LOCAL, free_port(), Duration::from_millis(300)).await;
    assert!(!outcome.is_good(), "silence over UDP was called healthy");
}

/// A stand-in name server answering with a fixed response code.
async fn name_server(code: u8, answers: u16) -> (u16, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a port must be free");
    let port = socket
        .local_addr()
        .expect("the socket must have an address")
        .port();

    let handle = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 512];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            if read < 12 {
                continue;
            }
            let mut answer = buffer[..read].to_vec();
            // Response flag on, plus the response code being tested.
            answer[2] = 0x81;
            answer[3] = 0x80 | code;
            answer[6..8].copy_from_slice(&answers.to_be_bytes());
            let _ = socket.send_to(&answer, from).await;
        }
    });
    (port, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dns_probe_fails_when_the_name_server_does_not_answer_properly() {
    let probe = HealthProbe::DnsQuery {
        name: "example.test".to_owned(),
        record_type: DnsRecordType::A,
    };

    let (good, serving) = name_server(0, 1).await;
    let outcome = probe_port(&probe, good).await;
    assert!(outcome.is_good(), "a valid answer was refused: {outcome:?}");
    serving.abort();

    // SERVFAIL: the name server is running but broken, which is exactly what
    // a health check exists to catch.
    let (broken, serving) = name_server(2, 0).await;
    let outcome = probe_port(&probe, broken).await;
    assert!(!outcome.is_good(), "a SERVFAIL was accepted: {outcome:?}");
    serving.abort();

    // NOERROR with no record at all is not a working answer either.
    let (empty, serving) = name_server(0, 0).await;
    let outcome = probe_port(&probe, empty).await;
    assert!(
        !outcome.is_good(),
        "an answer with no record was accepted: {outcome:?}"
    );
    serving.abort();

    // Nothing listening at all.
    let outcome = probe::run(&probe, LOCAL, free_port(), Duration::from_millis(300)).await;
    assert!(!outcome.is_good(), "a silent port was called healthy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_probe_that_never_answers_fails_on_its_own_timeout() {
    let silent = Server::start(Answers::Silence).await;
    let probe = HealthProbe::Http {
        path: "/healthz".to_owned(),
        expected_status: vec![200],
        expected_body: None,
        host_header: None,
    };

    let started = tokio::time::Instant::now();
    // Wrapped so a probe with no bound of its own fails this test instead of
    // hanging the whole run.
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        probe::run(&probe, LOCAL, silent.port, Duration::from_millis(400)),
    )
    .await
    .expect("the probe must give up on its own timeout, not run forever");

    assert!(!outcome.is_good(), "a silent server was called healthy");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the probe took {:?} rather than giving up at its timeout",
        started.elapsed()
    );
}

#[test]
fn a_member_is_not_unhealthy_before_its_threshold_is_reached() {
    let health = Health::new();
    let check = check(HealthProbe::TcpConnect, 2, 3);

    // Two failures is not three.
    assert_eq!(
        health.record("web", "one", &check, false),
        Change::None,
        "one failure took a member out"
    );
    assert!(health.is_healthy("web", "one"));
    assert_eq!(health.record("web", "one", &check, false), Change::None);
    assert!(
        health.is_healthy("web", "one"),
        "two failures took a member out of a pool with a threshold of three"
    );

    // The third one does it.
    assert_eq!(
        health.record("web", "one", &check, false),
        Change::WentUnhealthy
    );
    assert!(!health.is_healthy("web", "one"));
}

#[test]
fn a_member_does_not_return_before_its_healthy_threshold_is_reached() {
    let health = Health::new();
    let check = check(HealthProbe::TcpConnect, 2, 1);

    health.record("web", "one", &check, false);
    assert!(
        !health.is_healthy("web", "one"),
        "the setup must take it out"
    );

    assert_eq!(
        health.record("web", "one", &check, true),
        Change::None,
        "one success brought a member back with a threshold of two"
    );
    assert!(!health.is_healthy("web", "one"));

    assert_eq!(
        health.record("web", "one", &check, true),
        Change::WentHealthy
    );
    assert!(health.is_healthy("web", "one"));
}

#[test]
fn a_run_of_failures_is_broken_by_one_success() {
    // Two failures, one success, two failures is not three failures in a row.
    let health = Health::new();
    let check = check(HealthProbe::TcpConnect, 1, 3);

    health.record("web", "one", &check, false);
    health.record("web", "one", &check, false);
    health.record("web", "one", &check, true);
    health.record("web", "one", &check, false);
    health.record("web", "one", &check, false);

    assert!(
        health.is_healthy("web", "one"),
        "failures were counted across a success"
    );
    assert_eq!(health.failures("web", "one"), 2);
}

#[test]
fn a_run_of_successes_is_broken_by_one_failure() {
    let health = Health::new();
    let check = check(HealthProbe::TcpConnect, 3, 1);

    health.record("web", "one", &check, false);
    health.record("web", "one", &check, true);
    health.record("web", "one", &check, true);
    health.record("web", "one", &check, false);
    health.record("web", "one", &check, true);
    health.record("web", "one", &check, true);

    assert!(
        !health.is_healthy("web", "one"),
        "successes were counted across a failure"
    );
}

#[test]
fn a_member_starts_in_rotation() {
    // Starting unhealthy would empty every pool on restart and hold it there
    // for at least one interval.
    let health = Health::new();
    assert!(
        health.is_healthy("web", "never-probed"),
        "a member nothing is known about must take traffic"
    );

    // The first recorded answer is where a wrong starting state shows: one
    // failure against a threshold of three must leave the member in.
    let check = check(HealthProbe::TcpConnect, 1, 3);
    health.record("web", "one", &check, false);
    assert!(
        health.is_healthy("web", "one"),
        "the first failure took a member out, so it did not start in rotation"
    );
}

#[test]
fn every_transition_is_counted_and_reported() {
    let health = Health::new();
    let check = check(HealthProbe::TcpConnect, 1, 1);

    health.record("web", "one", &check, false);
    health.record("web", "one", &check, true);
    health.record("web", "one", &check, false);

    let report = health.report();
    let entry = report
        .iter()
        .find(|entry| entry.member == "one")
        .expect("the member must be reported");

    assert_eq!(entry.pool, "web");
    assert!(!entry.healthy);
    assert_eq!(
        entry.transitions, 3,
        "a member that went down, up and down again reported {} transitions",
        entry.transitions
    );
}

#[test]
fn a_member_with_no_health_check_is_not_reported() {
    // Reporting it as healthy would state something that was never measured.
    let health = Health::new();
    assert!(health.report().is_empty());
    assert!(health.is_healthy("web", "unchecked"));
}
