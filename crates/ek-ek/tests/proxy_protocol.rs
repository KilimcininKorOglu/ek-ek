// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a backend behind an L4 frontend actually receives.
//!
//! Every rule here is read off the raw bytes the backend got, never off a
//! parser of our own: the receiver in production is somebody else's SMTP
//! server, and what matters is the bytes, not our reading of them.
//!
//! The client address in each measurement is taken from the client socket
//! itself rather than written into the test, so a header carrying a fixed
//! address that happens to look right would still fail.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

use common::{Document, RawBehaviour, RawMember, Running, connect, connect_to, free_port};

/// How long a test waits for something that should already have happened.
const PATIENCE: Duration = Duration::from_secs(15);

/// The twelve bytes every v2 header opens with.
const SIGNATURE: &[u8] = &[
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Waits until a condition holds, or gives up.
async fn until(what: &str, mut holds: impl FnMut() -> bool) {
    let start = tokio::time::Instant::now();
    while !holds() {
        assert!(start.elapsed() <= PATIENCE, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Opens a connection, sends bytes, reads the echo back, then closes.
///
/// Returns the address the client socket was given, which is the address the
/// backend must be told about.
async fn round_trip(port: u16, sent: &[u8], member: &RawMember) -> std::net::SocketAddr {
    let mut stream = connect(port).await;
    let from = stream
        .local_addr()
        .expect("a connected socket has an address");
    stream.write_all(sent).await.expect("the write must go");
    stream.flush().await.expect("the write must flush");
    // The echo comes back with the header in front of it, so reading a fixed
    // count would block. Closing and reading what the backend recorded is
    // what this measures.
    drop(stream);
    until("the backend never recorded the connection", || {
        !member.received().is_empty()
    })
    .await;
    from
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_header_is_the_first_thing_the_backend_reads() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")])
        .raw()
        .proxy_protocol("v1");
    let running = Running::start_l4(&document, &[&echo]).await;

    let from = round_trip(running.port, b"HELO client.test\r\n", &echo).await;

    let seen = echo.received();
    let text = String::from_utf8_lossy(&seen[0]).into_owned();
    let (line, rest) = text
        .split_once("\r\n")
        .expect("the connection opens with a line");

    assert_eq!(
        line,
        format!(
            "PROXY TCP4 127.0.0.1 127.0.0.1 {} {}",
            from.port(),
            running.port
        ),
        "the backend must read the header before anything the client sent"
    );
    assert_eq!(
        rest, "HELO client.test\r\n",
        "what follows the header is the client's own bytes, unchanged"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_v2_form_reaches_the_backend_as_binary() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")])
        .raw()
        .proxy_protocol("v2");
    let running = Running::start_l4(&document, &[&echo]).await;

    let from = round_trip(running.port, b"HELO client.test\r\n", &echo).await;

    let seen = echo.received();
    let bytes = &seen[0];
    assert_eq!(&bytes[..12], SIGNATURE, "the signature opens the record");
    assert_eq!(bytes[12], 0x21, "version 2, PROXY command");
    assert_eq!(bytes[13], 0x11, "TCP over IPv4");
    assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 12);
    assert_eq!(&bytes[16..20], &[127, 0, 0, 1]);
    assert_eq!(
        u16::from_be_bytes([bytes[24], bytes[25]]),
        from.port(),
        "the source port is the client's own"
    );
    assert_eq!(
        u16::from_be_bytes([bytes[26], bytes[27]]),
        running.port,
        "the destination port is the one the client reached"
    );
    assert_eq!(
        &bytes[28..],
        b"HELO client.test\r\n",
        "the client's bytes follow the record, unchanged"
    );
    assert!(
        !bytes.starts_with(b"PROXY "),
        "the text form must not be sent when v2 is asked for"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_address_and_port_are_the_client_s_own_and_not_a_fixed_value() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")])
        .raw()
        .proxy_protocol("v1");
    let running = Running::start_l4(&document, &[&echo]).await;

    // Two connections from the same host differ only in their source port, so
    // a header built from anything but the socket would announce them alike.
    let first = round_trip(running.port, b"one\r\n", &echo).await;
    until("the first connection was not recorded", || {
        echo.received().len() == 1
    })
    .await;
    let second = round_trip(running.port, b"two\r\n", &echo).await;
    until("the second connection was not recorded", || {
        echo.received().len() == 2
    })
    .await;

    assert_ne!(
        first.port(),
        second.port(),
        "the two clients must differ, or this measures nothing"
    );

    let seen = echo.received();
    let announced: Vec<u16> = seen
        .iter()
        .map(|bytes| {
            let text = String::from_utf8_lossy(bytes).into_owned();
            let line = text.split("\r\n").next().unwrap_or_default().to_owned();
            line.split(' ')
                .nth(4)
                .and_then(|port| port.parse::<u16>().ok())
                .unwrap_or_default()
        })
        .collect();

    assert_eq!(
        announced,
        vec![first.port(), second.port()],
        "each header must carry the port of its own client"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ipv6_client_is_announced_with_its_ipv6_address() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")])
        .raw()
        .proxy_protocol("v2")
        .on_address("::1", 128);
    let running = Running::start_l4(&document, &[&echo]).await;

    // Reached over IPv6 rather than over a loopback that answers both, so the
    // address in the header is one a real IPv6 client produced.
    let mut stream = connect_to("::1", running.port).await;
    let from = stream
        .local_addr()
        .expect("a connected socket has an address");
    assert!(from.is_ipv6(), "the client must really be on IPv6");
    stream
        .write_all(b"EHLO\r\n")
        .await
        .expect("the write must go");
    stream.flush().await.expect("the write must flush");
    drop(stream);
    until("the backend never recorded the connection", || {
        !echo.received().is_empty()
    })
    .await;

    let seen = echo.received();
    let bytes = &seen[0];
    assert_eq!(bytes[13], 0x21, "TCP over IPv6");
    assert_eq!(
        u16::from_be_bytes([bytes[14], bytes[15]]),
        36,
        "an IPv6 record states sixteen bytes each way"
    );
    let source: [u8; 16] = bytes[16..32].try_into().expect("sixteen bytes");
    assert_eq!(
        std::net::IpAddr::from(std::net::Ipv6Addr::from(source)),
        from.ip(),
        "the announced address must be the client's own"
    );
    assert_eq!(
        u16::from_be_bytes([bytes[48], bytes[49]]),
        from.port(),
        "the announced port must be the client's own"
    );
    assert_eq!(&bytes[52..], b"EHLO\r\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_header_goes_once_on_a_connection_carrying_more_than_one_exchange() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")])
        .raw()
        .proxy_protocol("v1");
    let running = Running::start_l4(&document, &[&echo]).await;

    let mut stream = connect(running.port).await;
    let from = stream
        .local_addr()
        .expect("a connected socket has an address");
    let expected = format!(
        "PROXY TCP4 127.0.0.1 127.0.0.1 {} {}\r\n",
        from.port(),
        running.port
    );

    // Three exchanges, each waiting for its own echo, so the connection is
    // genuinely reused rather than three writes racing into one buffer.
    for turn in ["MAIL FROM:<a@test>\r\n", "RCPT TO:<b@test>\r\n", "DATA\r\n"] {
        stream
            .write_all(turn.as_bytes())
            .await
            .expect("the write must go");
        stream.flush().await.expect("the write must flush");
        let mut back = vec![0_u8; turn.len()];
        // The first echo carries the header in front of it, which is read and
        // discarded so the turns after it line up.
        if turn.starts_with("MAIL") {
            let mut head = vec![0_u8; expected.len()];
            tokio::time::timeout(PATIENCE, stream.read_exact(&mut head))
                .await
                .expect("the echoed header must arrive")
                .expect("the whole echoed header must arrive");
            assert_eq!(String::from_utf8_lossy(&head), expected);
        }
        tokio::time::timeout(PATIENCE, stream.read_exact(&mut back))
            .await
            .expect("the echo must arrive")
            .expect("the whole echo must arrive");
        assert_eq!(String::from_utf8_lossy(&back), turn);
    }
    drop(stream);

    until("the backend never recorded the connection", || {
        !echo.received().is_empty()
    })
    .await;

    let seen = echo.received();
    assert_eq!(seen.len(), 1, "all three exchanges were one connection");
    let text = String::from_utf8_lossy(&seen[0]).into_owned();
    assert_eq!(
        text.matches("PROXY TCP4").count(),
        1,
        "the header belongs to the connection, not to the exchange"
    );
    assert_eq!(
        text,
        format!("{expected}MAIL FROM:<a@test>\r\nRCPT TO:<b@test>\r\nDATA\r\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_at_all_is_sent_when_the_protocol_is_off() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")])
        .raw()
        .proxy_protocol("disabled");
    let running = Running::start_l4(&document, &[&echo]).await;

    round_trip(running.port, b"HELO client.test\r\n", &echo).await;

    let seen = echo.received();
    assert_eq!(
        seen[0], b"HELO client.test\r\n",
        "with the protocol off the backend must receive the client's bytes and nothing else"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frontend_that_never_names_the_setting_sends_nothing() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")])
        .raw()
        .without_proxy_protocol_named();
    // The setting really is absent from what the agent delivered.
    assert!(
        !document.render().contains("proxy_protocol"),
        "this measures a document that does not name the setting"
    );
    let running = Running::start_l4(&document, &[&echo]).await;

    round_trip(running.port, b"HELO client.test\r\n", &echo).await;

    let seen = echo.received();
    assert_eq!(
        seen[0], b"HELO client.test\r\n",
        "an operator who never touched the setting must get no header"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_that_does_not_expect_the_header_gives_the_client_nothing() {
    // A backend speaking a protocol of its own reads the header as the first
    // line of that protocol, does not understand it, and hangs up. The client
    // is then left with a connection that carried nothing, which is exactly
    // the failure an operator sees after turning the setting on by mistake.
    let strict = StrictMember::start();

    let plain = Document::new(free_port(), vec![strict.entry()]).raw();
    let running = Running::start_l4(&plain, &[]).await;
    let answer = ask(running.port, "PING\r\n").await;
    assert_eq!(
        answer, "PONG\r\n",
        "with the protocol off the backend answers, so it is a working pair"
    );
    drop(running);

    // A port of its own rather than the one just released: a process being
    // torn down still holds its listener for a moment, and the second run
    // would then fail to bind for a reason that has nothing to do with the
    // header.
    let announced = Document::new(free_port(), vec![strict.entry()])
        .raw()
        .proxy_protocol("v1");
    let running = Running::start_l4(&announced, &[]).await;
    let answer = ask(running.port, "PING\r\n").await;

    assert_eq!(
        answer, "",
        "the same backend must give the client nothing once the header is sent"
    );
    assert!(
        strict.rejected() >= 1,
        "the backend must have refused the greeting it could not read"
    );
}

/// Sends one line and reads whatever comes back before the connection closes.
async fn ask(port: u16, line: &str) -> String {
    let mut stream = connect(port).await;
    stream
        .write_all(line.as_bytes())
        .await
        .expect("the write must go");
    stream.flush().await.expect("the write must flush");

    let mut back = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut back)).await;
    String::from_utf8_lossy(&back).into_owned()
}

/// A backend that speaks one line of its own protocol and nothing else.
///
/// It answers `PING` with `PONG` and hangs up on anything else, which is how
/// a backend not expecting a PROXY header behaves: the header is not a
/// greeting it knows.
struct StrictMember {
    port: u16,
    rejected: Arc<AtomicU64>,
}

impl StrictMember {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a backend port must be free");
        let port = listener
            .local_addr()
            .expect("the backend must have an address")
            .port();
        let rejected = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&rejected);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let counted = Arc::clone(&counted);
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut buffer = [0_u8; 1024];
                    let Ok(read) = stream.read(&mut buffer) else {
                        return;
                    };
                    if &buffer[..read] == b"PING\r\n" {
                        let _ = stream.write_all(b"PONG\r\n");
                        let _ = stream.flush();
                    } else {
                        counted.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });

        Self { port, rejected }
    }

    fn entry(&self) -> String {
        format!(
            r#"{{"id":"strict","address":"127.0.0.1","port":{},"weight":1,"admin_state":"enabled"}}"#,
            self.port
        )
    }

    fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::SeqCst)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_header_precedes_a_tls_handshake_and_does_not_break_it() {
    // What a TLS passthrough frontend does is forward bytes without reading
    // them, which is what this L4 path does. The backend here terminates TLS
    // after reading the header, the way a PROXY-aware TLS server does, so the
    // measurement is that the header arrives before the ClientHello and that
    // the handshake still completes.
    let tls = TlsMember::start();
    let port = free_port();
    let document = Document::new(port, vec![tls.entry()])
        .raw()
        .proxy_protocol("v1");
    let running = Running::start_l4(&document, &[]).await;
    let listening = running.port;

    let (line, body) = tokio::task::spawn_blocking(move || {
        let mut held = common::tls::open(listening, "mail.example.test")
            .expect("the handshake must complete through the proxy");
        let answer = common::tls::exchange(
            &mut held,
            "GET / HTTP/1.1\r\nHost: mail.example.test\r\n\r\n",
        )
        .expect("the request must be answered over the finished handshake");
        (tls.first_line(), answer)
    })
    .await
    .expect("the blocking half must finish");

    assert!(
        line.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "the backend read a header before the handshake, it read: {line}"
    );
    assert!(
        body.contains("200 OK"),
        "the handshake and the request must survive the header, the answer was: {body}"
    );
}

/// A backend that reads a PROXY v1 line, then terminates TLS.
///
/// This is what a TLS server configured for the PROXY protocol does, and it
/// is the only way to measure that the header goes before the ClientHello:
/// the ClientHello is what it reads next.
struct TlsMember {
    port: u16,
    first: Arc<std::sync::Mutex<String>>,
}

impl TlsMember {
    fn start() -> Self {
        let authority = common::tls::Authority::new();
        let leaf = authority.issue(&["mail.example.test"]);
        let chain = authority.chain_pem(&leaf);
        let key = leaf.key_pem();

        let listener = TcpListener::bind("127.0.0.1:0").expect("a backend port must be free");
        let port = listener
            .local_addr()
            .expect("the backend must have an address")
            .port();
        let first = Arc::new(std::sync::Mutex::new(String::new()));
        let recorded = Arc::clone(&first);

        std::thread::spawn(move || {
            let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate(
                openssl::ssl::SslMethod::tls_server(),
            )
            .expect("an acceptor builds");
            let certificates =
                openssl::x509::X509::stack_from_pem(chain.as_bytes()).expect("the chain parses");
            let mut certificates = certificates.into_iter();
            builder
                .set_certificate(&certificates.next().expect("the chain has a leaf"))
                .expect("the leaf is usable");
            for intermediate in certificates {
                builder
                    .add_extra_chain_cert(intermediate)
                    .expect("the intermediate is usable");
            }
            builder
                .set_private_key(
                    &openssl::pkey::PKey::private_key_from_pem(key.as_bytes())
                        .expect("the key parses"),
                )
                .expect("the key matches");
            let acceptor = builder.build();

            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let recorded = Arc::clone(&recorded);
                let acceptor = acceptor.clone();
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    // One byte at a time up to the line ending, so nothing of
                    // the ClientHello is swallowed with the header.
                    let mut line = Vec::new();
                    let mut byte = [0_u8; 1];
                    while stream.read_exact(&mut byte).is_ok() {
                        line.push(byte[0]);
                        if line.ends_with(b"\r\n") {
                            break;
                        }
                    }
                    if let Ok(mut store) = recorded.lock() {
                        *store = String::from_utf8_lossy(&line).into_owned();
                    }

                    let Ok(mut tls) = acceptor.accept(stream) else {
                        return;
                    };
                    let mut buffer = [0_u8; 4096];
                    let Ok(read) = tls.read(&mut buffer) else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    let _ = tls.flush();
                });
            }
        });

        Self { port, first }
    }

    fn entry(&self) -> String {
        format!(
            r#"{{"id":"tls","address":"127.0.0.1","port":{},"weight":1,"admin_state":"enabled"}}"#,
            self.port
        )
    }

    fn first_line(&self) -> String {
        self.first
            .lock()
            .map(|store| store.clone())
            .unwrap_or_default()
    }
}
