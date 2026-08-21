// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the L4 TCP proxy does with a connection.
//!
//! Nothing here speaks HTTP. A database client, an SMTP session and an RDP
//! desktop are opaque byte streams, and the point of this path is that it
//! never pretends otherwise. The backends are raw listeners that echo, greet
//! first, stay silent or hang up.
//!
//! Everything runs the real binary over real sockets, because what is being
//! measured is what crosses the wire and when a socket closes.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod common;

use common::{Document, RawBehaviour, RawMember, Running, checksum, connect, free_port, payload};

/// How long a test waits for something that should already have happened.
const PATIENCE: Duration = Duration::from_secs(15);

/// Opens a connection to the frontend, sends bytes and reads what comes back.
async fn exchange(port: u16, sent: &[u8], expected: usize) -> Vec<u8> {
    let mut stream = connect(port).await;
    stream
        .write_all(sent)
        .await
        .expect("the frontend must accept the payload");
    stream.flush().await.expect("the payload must flush");

    let mut received = vec![0_u8; expected];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut received))
        .await
        .expect("the answer must arrive rather than the test hanging")
        .expect("the whole answer must arrive");
    received
}

/// Waits until a condition holds, or gives up.
async fn until(what: &str, mut holds: impl FnMut() -> bool) {
    let start = tokio::time::Instant::now();
    while !holds() {
        assert!(start.elapsed() <= PATIENCE, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_cross_in_both_directions() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&echo]).await;

    let sent = b"SELECT 1;\r\n".to_vec();
    let back = exchange(running.port, &sent, sent.len()).await;

    assert_eq!(back, sent, "the bytes that came back are not the ones sent");
    assert_eq!(echo.accepted(), 1, "the backend was never reached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_that_speaks_first_is_heard() {
    // SMTP and PostgreSQL both greet before the client says anything. A proxy
    // that waits for the client first would hang on either of them.
    let greeting = b"220 mail.example.test ESMTP\r\n".to_vec();
    let greeter = RawMember::start("greeter", RawBehaviour::GreetFirst(greeting.clone())).await;
    let port = free_port();
    let document = Document::new(port, vec![greeter.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&greeter]).await;

    let mut stream = connect(running.port).await;
    let mut received = vec![0_u8; greeting.len()];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut received))
        .await
        .expect("the greeting must arrive without the client speaking first")
        .expect("the whole greeting must arrive");

    assert_eq!(received, greeting);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_closing_closes_the_backend_connection() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&echo]).await;

    let mut stream = connect(running.port).await;
    stream.write_all(b"hello").await.expect("the write must go");
    stream.flush().await.expect("the write must flush");
    until("the backend never saw the connection", || {
        echo.accepted() == 1
    })
    .await;

    drop(stream);

    until(
        "the backend connection stayed open after the client left",
        || echo.closed() == 1,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_closing_closes_the_client_connection() {
    let quitter = RawMember::start(
        "quitter",
        RawBehaviour::CloseAfter(Duration::from_millis(200)),
    )
    .await;
    let port = free_port();
    let document = Document::new(port, vec![quitter.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&quitter]).await;

    let mut stream = connect(running.port).await;
    let mut buffer = [0_u8; 16];
    let read = tokio::time::timeout(PATIENCE, stream.read(&mut buffer))
        .await
        .expect("the client connection must end rather than the test hanging")
        .expect("reading a closed connection must not error");

    assert_eq!(
        read, 0,
        "the client connection stayed open after the backend hung up"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_robin_splits_one_hundred_connections_evenly_between_two_members() {
    let one = RawMember::start("one", RawBehaviour::Echo).await;
    let two = RawMember::start("two", RawBehaviour::Echo).await;
    let port = free_port();
    let document =
        Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&one, &two]).await;

    for number in 0..100_u32 {
        let sent = format!("connection {number}").into_bytes();
        let back = exchange(running.port, &sent, sent.len()).await;
        assert_eq!(back, sent);
    }

    assert_eq!(
        one.accepted(),
        50,
        "one took {} of 100 connections",
        one.accepted()
    );
    assert_eq!(
        two.accepted(),
        50,
        "two took {} of 100 connections",
        two.accepted()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_disabled_member_receives_no_connection() {
    let taking = RawMember::start("taking", RawBehaviour::Echo).await;
    let out = RawMember::start("out", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![taking.entry(1, "enabled"), out.entry(1, "disabled")],
    )
    .raw();
    let running = Running::start_l4(&document, &[&taking, &out]).await;

    for _ in 0..20 {
        let back = exchange(running.port, b"ping", 4).await;
        assert_eq!(&back, b"ping");
    }

    assert_eq!(taking.accepted(), 20);
    assert_eq!(
        out.accepted(),
        0,
        "a member an operator disabled took {} connections",
        out.accepted()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_backend_leaves_the_client_with_no_established_session() {
    // A port nothing listens on. The connection to the frontend is accepted
    // by the kernel, so what is measured is that nothing is forwarded and the
    // client is released rather than left waiting.
    let dead = free_port();
    let port = free_port();
    let members = vec![format!(
        r#"{{"id":"dead","address":"127.0.0.1","port":{dead},"weight":1,"admin_state":"enabled"}}"#
    )];
    let document = Document::new(port, members).raw().connect_timeout(2);
    let running = Running::start(&document).await;

    let mut stream = connect(running.port).await;
    stream
        .write_all(b"anybody there?")
        .await
        .expect("the kernel accepts the write into the socket buffer");

    let mut buffer = [0_u8; 16];
    let ended = tokio::time::timeout(PATIENCE, stream.read(&mut buffer))
        .await
        .expect("the client must be released rather than left waiting");

    // Either end is fine: a clean close reads zero, and a close after the
    // client has already written arrives as a reset. What must not happen is
    // a session that stays up with nothing behind it, or bytes coming back
    // from a backend that was never reached.
    match ended {
        Ok(0) => {}
        Ok(read) => panic!("{read} bytes came back from an unreachable backend"),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => panic!("the connection ended in an unexpected way: {error}"),
    }

    // The failure is on the record rather than only in a dropped connection.
    // It is a count, not a state: one refused connection is not a sick node,
    // and health is the health check's decision (T-021).
    let failures = running
        .agent
        .wait_for_counter("backend_connect_failures", 1)
        .await
        .expect("a backend that could not be reached must be counted");
    assert!(failures >= 1, "the failure was not counted");

    let report = running
        .agent
        .last_report()
        .await
        .expect("the traffic path must report its state");
    assert_eq!(
        report.state, "serving",
        "one unreachable backend took the whole node out of service"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_connection_is_closed_once_its_limit_passes() {
    let silent = RawMember::start("silent", RawBehaviour::Silent).await;
    let port = free_port();
    let document = Document::new(port, vec![silent.entry(1, "enabled")])
        .raw()
        .idle_timeout(1);
    let running = Running::start_l4(&document, &[&silent]).await;

    let mut stream = connect(running.port).await;
    stream.write_all(b"knock").await.expect("the write must go");
    stream.flush().await.expect("the write must flush");

    let started = tokio::time::Instant::now();
    let mut buffer = [0_u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("the idle connection must be cut rather than held")
        .expect("reading a closed connection must not error");

    assert_eq!(read, 0, "the idle connection was not closed");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "the connection was cut after {:?}, before its one second limit",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the connection was held for {:?}, well past its one second limit",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn traffic_keeps_an_idle_limit_from_firing() {
    // The limit is on one quiet stretch, not on the whole connection. A
    // connection that keeps talking must survive past its own limit.
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")])
        .raw()
        .idle_timeout(1);
    let running = Running::start_l4(&document, &[&echo]).await;

    let mut stream = connect(running.port).await;
    for round in 0..6_u32 {
        stream
            .write_all(format!("round {round}\n").as_bytes())
            .await
            .unwrap_or_else(|error| panic!("round {round} could not be sent: {error}"));
        stream.flush().await.expect("the round must flush");

        let mut back = vec![0_u8; format!("round {round}\n").len()];
        tokio::time::timeout(PATIENCE, stream.read_exact(&mut back))
            .await
            .unwrap_or_else(|_| panic!("round {round} was never answered"))
            .unwrap_or_else(|error| panic!("round {round} was cut: {error}"));

        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    // Over two seconds have passed on a one second idle limit, and the
    // connection is still up.
    stream.write_all(b"still here").await.expect("still open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_megabyte_crosses_unchanged_in_both_directions() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&echo]).await;

    let sent = payload(1024 * 1024);
    let sent_sum = checksum(&sent);

    let mut stream = connect(running.port).await;
    let (mut reader, mut writer) = stream.split();

    // Written and read at the same time. Writing a megabyte first would fill
    // the socket buffers and deadlock before the read started.
    let writing = async {
        writer.write_all(&sent).await?;
        writer.flush().await
    };
    let mut back = vec![0_u8; sent.len()];
    let reading = reader.read_exact(&mut back);

    let (written, read) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(writing, reading)
    })
    .await
    .expect("a megabyte must cross rather than the test hanging");
    written.expect("the whole payload must be written");
    let read = read.expect("the whole payload must come back");

    assert_eq!(read, sent.len(), "only {read} bytes came back");
    assert_eq!(
        checksum(&back),
        sent_sum,
        "the payload came back with a different checksum, so it was altered"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_connections_are_reported_per_frontend_and_member() {
    let one = RawMember::start("one", RawBehaviour::Echo).await;
    let two = RawMember::start("two", RawBehaviour::Echo).await;
    let port = free_port();
    let document =
        Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&one, &two]).await;

    // Ten connections held open at once, five to each member.
    let mut held = Vec::new();
    for _ in 0..10 {
        let mut stream = connect(running.port).await;
        stream.write_all(b"hold").await.expect("the write must go");
        stream.flush().await.expect("the write must flush");
        let mut back = [0_u8; 4];
        tokio::time::timeout(PATIENCE, stream.read_exact(&mut back))
            .await
            .expect("the echo must arrive")
            .expect("the echo must be complete");
        held.push(stream);
    }

    let counts = running
        .agent
        .wait_for_open_connections(10)
        .await
        .expect("the report must carry the open connections");
    let by_member: BTreeMap<String, u64> = counts
        .iter()
        .map(|entry| (entry.member.clone(), entry.count))
        .collect();

    assert_eq!(by_member.get("one"), Some(&5), "counted {by_member:?}");
    assert_eq!(by_member.get("two"), Some(&5), "counted {by_member:?}");
    for entry in &counts {
        assert_eq!(entry.frontend, "web", "the frontend was not reported");
        assert_eq!(entry.pool, "web", "the pool was not reported");
    }

    // Closing them brings the count back down. A count that only goes up
    // would make least connections avoid a member forever.
    drop(held);
    let after = running
        .agent
        .wait_for_open_connections(0)
        .await
        .expect("the report must come back down");
    assert!(
        after.is_empty(),
        "connections stayed counted after they closed: {after:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_thousand_connections_are_all_served() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&echo]).await;

    let mut opening = Vec::new();
    for number in 0..1000_u32 {
        let port = running.port;
        opening.push(tokio::spawn(async move {
            let sent = format!("client {number:04}").into_bytes();
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
            stream.write_all(&sent).await?;
            stream.flush().await?;

            let mut back = vec![0_u8; sent.len()];
            match tokio::time::timeout(Duration::from_secs(60), stream.read_exact(&mut back)).await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "no answer arrived",
                    ));
                }
            }
            Ok::<(Vec<u8>, Vec<u8>), std::io::Error>((sent, back))
        }));
    }

    let mut served = 0_usize;
    let mut failures = Vec::new();
    for opened in opening {
        match opened.await.expect("a client task must finish") {
            Ok((sent, back)) => {
                assert_eq!(back, sent, "a connection got another connection's bytes");
                served += 1;
            }
            Err(error) => failures.push(error.to_string()),
        }
    }

    assert_eq!(
        served,
        1000,
        "{} of 1000 connections were not served: {:?}",
        1000 - served,
        failures.first()
    );
    assert_eq!(echo.accepted(), 1000, "the backend saw a different count");
}
