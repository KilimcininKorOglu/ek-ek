// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where a TLS connection goes when the load balancer never opens it.
//!
//! The whole point of a passthrough frontend is that the handshake belongs to
//! the backend: the client's certificate has to arrive there untouched, or
//! mTLS cannot work at all (ADR-0027). So nothing here may be measured through
//! a certificate the load balancer holds. Every measurement runs the real
//! binary, a real TLS client and a real TLS server, and reads what the server
//! saw.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openssl::nid::Nid;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;

mod common;

use common::tls::{Authority, Issued};
use common::{Document, Running, free_port};

/// How long a test waits for something that should already have happened.
const PATIENCE: Duration = Duration::from_secs(15);

/// How many connections the readiness check leaves behind.
///
/// Starting the binary means proving it listens, and on a passthrough frontend
/// the only way to prove that is to open a connection and close it. That
/// connection sends no ClientHello, so it is turned away and counted like any
/// other. Named rather than buried in an assertion, because a measurement of
/// the counter has to say which of its increments it means.
const READINESS_PROBE: u64 = 1;

/// A backend that terminates TLS itself.
struct TlsMember {
    /// Which member this is in the document.
    id: String,
    /// Where it listens.
    port: u16,
    /// The name on the certificate it presents.
    served: String,
    /// The server names it was asked for, in order.
    asked_for: Arc<Mutex<Vec<String>>>,
    /// The client certificates it verified, by common name.
    clients: Arc<Mutex<Vec<String>>>,
    /// Handshakes that never completed.
    refused: Arc<AtomicU64>,
}

impl TlsMember {
    /// Starts a TLS server presenting a leaf for the names given.
    ///
    /// With `requiring_clients` set it asks every client for a certificate and
    /// verifies it against the same authority, which is what an mTLS service
    /// does.
    fn start(id: &str, names: &[&str], authority: &Authority, requiring_clients: bool) -> Self {
        let leaf = authority.issue(names);
        let chain = authority.chain_pem(&leaf);
        let key = leaf.key_pem();
        let root = authority.root_pem();

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port must be free");
        let port = listener.local_addr().expect("an address").port();

        let asked_for = Arc::new(Mutex::new(Vec::new()));
        let clients = Arc::new(Mutex::new(Vec::new()));
        let refused = Arc::new(AtomicU64::new(0));

        let served = names[0].to_owned();
        let answer = format!("served-by:{id}\n");
        let seen = Arc::clone(&asked_for);
        let held = Arc::clone(&clients);
        let broken = Arc::clone(&refused);

        std::thread::spawn(move || {
            let mut builder =
                SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("an acceptor");
            let chain = X509::stack_from_pem(chain.as_bytes()).expect("a chain");
            let (leaf, rest) = chain.split_first().expect("a leaf");
            builder.set_certificate(leaf).expect("a certificate");
            for issuer in rest {
                builder
                    .add_extra_chain_cert(issuer.clone())
                    .expect("a chain");
            }
            builder
                .set_private_key(
                    &openssl::pkey::PKey::private_key_from_pem(key.as_bytes()).expect("a key"),
                )
                .expect("a key");
            if requiring_clients {
                builder
                    .cert_store_mut()
                    .add_cert(X509::from_pem(root.as_bytes()).expect("a root"))
                    .expect("a root");
                // Both flags on purpose: asking without failing would let a
                // client with no certificate through, and the measurement is
                // that mTLS actually holds.
                builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            }
            let acceptor = builder.build();

            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let Ok(mut session) = acceptor.accept(stream) else {
                    broken.fetch_add(1, Ordering::SeqCst);
                    continue;
                };
                if let Some(name) = session.ssl().servername(openssl::ssl::NameType::HOST_NAME)
                    && let Ok(mut store) = seen.lock()
                {
                    store.push(name.to_owned());
                }
                if let Some(certificate) = session.ssl().peer_certificate()
                    && let Ok(mut store) = held.lock()
                {
                    store.push(common_name(&certificate));
                }
                let _ = session.write_all(answer.as_bytes());
                let _ = session.flush();
                // Read whatever the client sends, so it is not cut off before
                // it has read the answer.
                let mut sink = [0_u8; 256];
                let _ = session.read(&mut sink);
            }
        });

        Self {
            id: id.to_owned(),
            port,
            served,
            asked_for,
            clients,
            refused,
        }
    }

    /// The member entry this backend goes into a document as.
    fn entry(&self) -> String {
        format!(
            r#"{{"id":"{}","address":"127.0.0.1","port":{},"weight":1,"admin_state":"enabled"}}"#,
            self.id, self.port
        )
    }

    /// The names clients asked it for.
    fn asked_for(&self) -> Vec<String> {
        self.asked_for.lock().expect("no panic held it").clone()
    }

    /// The client certificates it verified.
    fn clients(&self) -> Vec<String> {
        self.clients.lock().expect("no panic held it").clone()
    }

    /// Handshakes it turned away.
    fn refused(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }
}

/// The common name of a certificate.
fn common_name(certificate: &X509) -> String {
    certificate
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().as_utf8().ok())
        .map_or_else(String::new, |name| name.to_string())
}

/// What a client presents when the backend asks it for a certificate.
struct Identity {
    /// The leaf and the issuers above it, as PEM.
    chain_pem: String,
    /// The leaf's private key.
    key: openssl::pkey::PKey<openssl::pkey::Private>,
}

impl Identity {
    /// Issues one, chain and all.
    fn issue(authority: &Authority, name: &str) -> Self {
        let leaf: Issued = authority.issue(&[name]);
        Self {
            chain_pem: authority.chain_pem(&leaf),
            key: leaf.key,
        }
    }
}

/// What one end to end handshake produced.
struct Spoken {
    /// The common name on the certificate the far end presented.
    served: String,
    /// Whether the client could build a path to the root it trusts.
    verified: bool,
    /// What the far end said.
    answer: String,
}

/// Speaks TLS to a port and reads the line the backend answers with.
///
/// # Errors
///
/// Returns why the handshake or the exchange did not complete, which is what a
/// test measuring a refusal reads.
fn speak(
    port: u16,
    server_name: Option<&str>,
    trusted_root: Option<&str>,
    client_certificate: Option<&Identity>,
) -> Result<Spoken, String> {
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|error| error.to_string())?;
    match trusted_root {
        Some(pem) => {
            let root = X509::from_pem(pem.as_bytes()).map_err(|error| error.to_string())?;
            builder
                .cert_store_mut()
                .add_cert(root)
                .map_err(|error| error.to_string())?;
            builder.set_verify(SslVerifyMode::PEER);
        }
        None => builder.set_verify(SslVerifyMode::NONE),
    }
    if let Some(held) = client_certificate {
        // The whole chain, not just the leaf. The backend trusts the root and
        // has never seen the intermediate, so a client sending only its leaf
        // is refused for a reason that has nothing to do with passthrough.
        let chain =
            X509::stack_from_pem(held.chain_pem.as_bytes()).map_err(|error| error.to_string())?;
        let (leaf, issuers) = chain
            .split_first()
            .ok_or_else(|| "an empty chain".to_owned())?;
        builder
            .set_certificate(leaf)
            .map_err(|error| error.to_string())?;
        for issuer in issuers {
            builder
                .add_extra_chain_cert(issuer.clone())
                .map_err(|error| error.to_string())?;
        }
        builder
            .set_private_key(&held.key)
            .map_err(|error| error.to_string())?;
    }
    let connector = builder.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;

    let mut configured = connector
        .configure()
        .map_err(|error| error.to_string())?
        .verify_hostname(false);
    // A client with no name to send is a case of its own, so the harness has
    // to be able to produce it.
    configured.set_use_server_name_indication(server_name.is_some());

    let mut session = configured
        .connect(server_name.unwrap_or(""), stream)
        .map_err(|error| error.to_string())?;

    let served = session
        .ssl()
        .peer_certificate()
        .ok_or_else(|| "the far end presented no certificate".to_owned())?;
    let verified = session.ssl().verify_result() == openssl::x509::X509VerifyResult::OK;

    let mut answer = String::new();
    let mut buffer = [0_u8; 256];
    while !answer.contains('\n') {
        match session.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => answer.push_str(&String::from_utf8_lossy(&buffer[..read])),
            Err(error) => return Err(error.to_string()),
        }
    }

    Ok(Spoken {
        served: common_name(&served),
        verified,
        answer: answer.trim_end().to_owned(),
    })
}

/// A document with one passthrough frontend and the pools given.
fn document(port: u16, members: &[&TlsMember]) -> Document {
    let first = members.first().expect("at least one member");
    Document::new(port, vec![first.entry()]).passthrough()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_names_reach_two_pools() {
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let web = TlsMember::start("web-1", &["web.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&web])
        .pool("mail", vec![mail.entry()])
        .sni_rule("posta.ornek.test", "mail")
        .sni_rule("web.ornek.test", "web");
    let running = Running::start(&paper).await;

    let to_mail = speak(running.port, Some("posta.ornek.test"), None, None)
        .expect("the mail name must reach a backend");
    let to_web = speak(running.port, Some("web.ornek.test"), None, None)
        .expect("the web name must reach a backend");

    assert_eq!(to_mail.answer, "served-by:mail-1");
    assert_eq!(to_web.answer, "served-by:web-1");
    // And each backend saw the name it was asked for, so the connection was
    // routed on the name rather than landing there by chance.
    assert_eq!(mail.asked_for(), vec!["posta.ornek.test".to_owned()]);
    assert_eq!(web.asked_for(), vec!["web.ornek.test".to_owned()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handshake_is_the_backend_s_own() {
    // The document holds no certificate at all, so there is nothing the load
    // balancer could have presented. What the client verifies is the
    // backend's leaf, against the backend's own authority.
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&mail]).sni_rule("posta.ornek.test", "web");
    let running = Running::start(&paper).await;

    let spoken = speak(
        running.port,
        Some("posta.ornek.test"),
        Some(&authority.root_pem()),
        None,
    )
    .expect("the handshake must complete end to end");

    assert_eq!(
        spoken.served, mail.served,
        "the certificate came from somewhere other than the backend"
    );
    assert!(
        spoken.verified,
        "the client could not build a path to the backend's own root, so something re-signed the handshake"
    );
    assert!(
        !paper.render().contains("\"certificates\":[{"),
        "the document under measurement must hold no certificate of its own"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_certificate_reaches_the_backend() {
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, true);
    let port = free_port();
    let paper = document(port, &[&mail]).sni_rule("posta.ornek.test", "web");
    let running = Running::start(&paper).await;

    let client = Identity::issue(&authority, "istemci.ornek.test");
    let spoken = speak(
        running.port,
        Some("posta.ornek.test"),
        Some(&authority.root_pem()),
        Some(&client),
    )
    .expect("an mTLS handshake must complete through a passthrough frontend");

    assert_eq!(spoken.answer, "served-by:mail-1");
    assert_eq!(
        mail.clients(),
        vec!["istemci.ornek.test".to_owned()],
        "the backend did not verify the client's own certificate"
    );

    // And the requirement is real: the same connection without a certificate
    // is refused by the backend rather than let through.
    let refused_before = mail.refused();
    let without = speak(
        running.port,
        Some("posta.ornek.test"),
        Some(&authority.root_pem()),
        None,
    );
    assert!(
        without.is_err(),
        "a client with no certificate got through an mTLS backend"
    );
    assert!(
        mail.refused() > refused_before,
        "the backend, not the load balancer, has to be the one refusing it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_no_rule_covers_falls_to_the_default_pool() {
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let web = TlsMember::start("web-1", &["web.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&web])
        .pool("mail", vec![mail.entry()])
        .sni_rule("posta.ornek.test", "mail");
    let running = Running::start(&paper).await;

    let spoken = speak(running.port, Some("baska.ornek.test"), None, None)
        .expect("a name no rule covers must still be served");

    assert_eq!(spoken.answer, "served-by:web-1", "the default pool took it");
    assert!(
        mail.asked_for().is_empty(),
        "the rule took a name it does not cover"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_sends_no_name_falls_to_the_default_pool() {
    // An old client and a monitoring tool connecting by address both do this.
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let web = TlsMember::start("web-1", &["web.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&web])
        .pool("mail", vec![mail.entry()])
        .sni_rule("posta.ornek.test", "mail");
    let running = Running::start(&paper).await;

    let spoken =
        speak(running.port, None, None, None).expect("a client sending no name must be served");

    assert_eq!(spoken.answer, "served-by:web-1");
    assert!(
        web.asked_for().is_empty(),
        "the backend was told a name the client never sent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wildcard_rule_covers_one_label_and_no_more() {
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let web = TlsMember::start("web-1", &["web.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&web])
        .pool("mail", vec![mail.entry()])
        .sni_rule("*.ornek.test", "mail");
    let running = Running::start(&paper).await;

    let covered = speak(running.port, Some("posta.ornek.test"), None, None)
        .expect("one label under the wildcard must match");
    assert_eq!(covered.answer, "served-by:mail-1");

    // Two labels deep is not covered, so the default pool takes it. A pattern
    // matching this as well would let one rule swallow a whole tree of names.
    let deeper = speak(running.port, Some("a.b.ornek.test"), None, None)
        .expect("a deeper name must still be served");
    assert_eq!(deeper.answer, "served-by:web-1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_default_pool_closes_the_connection_and_records_it() {
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&mail])
        .sni_rule("posta.ornek.test", "web")
        .without_default_backend();
    let running = Running::start(&paper).await;
    running
        .agent
        .wait_for_counter("passthrough_connections_refused", READINESS_PROBE)
        .await
        .expect("the readiness check is counted like any other connection");

    let refused = speak(running.port, Some("baska.ornek.test"), None, None);

    assert!(
        refused.is_err(),
        "a name nothing covers, with no default pool, must not be served"
    );
    assert_eq!(
        running
            .agent
            .wait_for_counter("passthrough_connections_refused", READINESS_PROBE + 1)
            .await,
        Some(READINESS_PROBE + 1),
        "closing it quietly would leave an operator with nothing to look at"
    );
    assert!(
        running
            .log_text()
            .contains("no SNI rule matched it and the frontend names no default pool"),
        "the log must say why it was closed; it said: {}",
        running.log_text()
    );
    assert!(
        mail.asked_for().is_empty(),
        "the connection reached a backend it was never routed to"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_hello_split_across_segments_is_read() {
    // A ClientHello crossing several TCP segments is ordinary, and a parser
    // that read only what the first segment held would route it on a name it
    // never saw. The dribbling relay is what makes the split certain rather
    // than hoped for.
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let web = TlsMember::start("web-1", &["web.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&web])
        .pool("mail", vec![mail.entry()])
        .sni_rule("posta.ornek.test", "mail");
    let running = Running::start(&paper).await;

    let relay = dribble_into(running.port);
    let spoken = speak(relay, Some("posta.ornek.test"), None, None)
        .expect("a hello arriving one byte at a time must still be read");

    assert_eq!(
        spoken.answer, "served-by:mail-1",
        "the name in a split hello was not read, so the default pool took it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_never_finishes_its_hello_is_closed() {
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&mail]).sni_rule("posta.ornek.test", "web");
    let running = Running::start(&paper).await;
    running
        .agent
        .wait_for_counter("passthrough_connections_refused", READINESS_PROBE)
        .await
        .expect("the readiness check is counted like any other connection");

    // A record header promising ten more bytes, and then silence. Nothing
    // else about this connection is wrong, so only the limit can end it.
    let mut stream = TcpStream::connect(("127.0.0.1", running.port)).expect("the frontend listens");
    stream
        .write_all(&[22, 3, 1, 0, 10])
        .expect("the frontend must accept the header");
    stream.flush().expect("it must flush");
    stream
        .set_read_timeout(Some(PATIENCE))
        .expect("a read timeout must be set");

    let started = Instant::now();
    let mut sink = [0_u8; 16];
    assert_eq!(
        stream.read(&mut sink).ok(),
        Some(0),
        "the connection was left open instead of being closed"
    );
    assert!(
        started.elapsed() < PATIENCE,
        "the connection was held for {:?}, which is a socket anybody can take for free",
        started.elapsed()
    );
    assert_eq!(
        running
            .agent
            .wait_for_counter("passthrough_connections_refused", READINESS_PROBE + 1)
            .await,
        Some(READINESS_PROBE + 1)
    );
    assert!(
        mail.asked_for().is_empty(),
        "a connection with no name reached a backend"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hello_that_never_ends_is_cut_at_a_limit() {
    // A record header may claim sixty five thousand bytes, and a sender may
    // then send forever. What is measured is that the wait is bounded by the
    // bytes held, not by the sender's patience.
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&mail]).sni_rule("posta.ornek.test", "web");
    let running = Running::start(&paper).await;

    let mut stream = TcpStream::connect(("127.0.0.1", running.port)).expect("the frontend listens");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("a write timeout must be set");
    // A handshake record claiming the largest body a record may have, and
    // then filler that never completes one. Sixty five kilobytes is a legal
    // claim, so nothing but the byte limit can end this.
    stream
        .write_all(&[22, 3, 1, 0xFF, 0xFF])
        .expect("the frontend must accept the header");
    // Above the limit the parser holds and well below the length the record
    // claims, so the wait can only end because of the limit.
    let _ = stream.write_all(&vec![0x41_u8; 32 * 1024]);

    // Read rather than count bytes written: a socket buffer swallows writes
    // whatever the far end does, while a close is the far end itself.
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("a read timeout must be set");
    let started = Instant::now();
    let mut sink = [0_u8; 16];
    assert_eq!(
        stream.read(&mut sink).ok(),
        Some(0),
        "the frontend kept waiting for the sixty five kilobytes the record claimed"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "it took {:?} to cut it, which is the patience running out rather than the byte limit",
        started.elapsed()
    );
    assert!(
        mail.asked_for().is_empty(),
        "an unfinished hello reached a backend"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_that_are_not_a_handshake_are_turned_away() {
    // Somebody typing the address into a browser sends this. It is a
    // configuration mistake rather than an attack, and it has to be visible.
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&mail]).sni_rule("posta.ornek.test", "web");
    let running = Running::start(&paper).await;
    running
        .agent
        .wait_for_counter("passthrough_connections_refused", READINESS_PROBE)
        .await
        .expect("the readiness check is counted like any other connection");

    let mut stream = TcpStream::connect(("127.0.0.1", running.port)).expect("the frontend listens");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: ornek.test\r\n\r\n")
        .expect("the frontend must accept the request");
    stream.flush().expect("it must flush");
    stream
        .set_read_timeout(Some(PATIENCE))
        .expect("a read timeout must be set");

    let mut sink = [0_u8; 16];
    assert_eq!(
        stream.read(&mut sink).ok(),
        Some(0),
        "an HTTP request on a passthrough port must be closed, not answered"
    );
    assert_eq!(
        running
            .agent
            .wait_for_counter("passthrough_connections_refused", READINESS_PROBE + 1)
            .await,
        Some(READINESS_PROBE + 1)
    );
    assert!(
        running
            .log_text()
            .contains("what it sent first was not a TLS handshake"),
        "the log must name the reason; it said: {}",
        running.log_text()
    );
    assert!(
        mail.asked_for().is_empty(),
        "bytes that are not a handshake reached a backend"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_access_record_says_which_name_sent_it_there() {
    // Without the name in the record, a connection in the wrong pool is a
    // fault with nothing to explain it: every passthrough connection looks
    // alike otherwise.
    let authority = Authority::new();
    let mail = TlsMember::start("mail-1", &["posta.ornek.test"], &authority, false);
    let web = TlsMember::start("web-1", &["web.ornek.test"], &authority, false);
    let port = free_port();
    let paper = document(port, &[&web])
        .pool("mail", vec![mail.entry()])
        .sni_rule("posta.ornek.test", "mail");
    let running = Running::start(&paper).await;

    speak(running.port, Some("posta.ornek.test"), None, None).expect("the named connection");
    speak(running.port, None, None, None).expect("the nameless connection");

    let records = running.wait_for_access_records("tcp", 2).await;
    let named = records
        .iter()
        .find(|record| record["backend_pool"] == "mail")
        .expect("the named connection must have a record");
    assert_eq!(named["sni"], "posta.ornek.test");

    let nameless = records
        .iter()
        .find(|record| record["backend_pool"] == "web")
        .expect("the nameless connection must have a record");
    assert!(
        nameless.get("sni").is_none(),
        "a client that sent no name must not be recorded as having sent one: {nameless}"
    );
}

/// A relay that forwards the first bytes of a connection one at a time.
///
/// Returns the port to connect to instead of the frontend. What it buys is
/// certainty: a client and a load balancer on one loopback otherwise put the
/// whole ClientHello in a single segment, and the split the parser has to
/// survive would never happen.
fn dribble_into(port: u16) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port must be free");
    let front = listener.local_addr().expect("an address").port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { continue };
            let Ok(mut backend) = TcpStream::connect(("127.0.0.1", port)) else {
                continue;
            };
            let Ok(mut back) = backend.try_clone() else {
                continue;
            };
            let Ok(mut out) = client.try_clone() else {
                continue;
            };
            // Backend to client, whole chunks: only the first direction has
            // to be split for the measurement.
            std::thread::spawn(move || {
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = back.read(&mut buffer) {
                    if read == 0 || out.write_all(&buffer[..read]).is_err() {
                        return;
                    }
                    let _ = out.flush();
                }
            });

            std::thread::spawn(move || {
                let mut buffer = [0_u8; 4096];
                // Only the opening bytes are dribbled. Everything after the
                // handshake would be needlessly slow one byte at a time.
                let mut dribbled = 0_usize;
                while let Ok(read) = client.read(&mut buffer) {
                    if read == 0 {
                        return;
                    }
                    if dribbled < 512 {
                        for byte in &buffer[..read] {
                            if backend.write_all(&[*byte]).is_err() {
                                return;
                            }
                            let _ = backend.flush();
                            std::thread::sleep(Duration::from_micros(200));
                        }
                        dribbled += read;
                    } else if backend.write_all(&buffer[..read]).is_err() {
                        return;
                    }
                    let _ = backend.flush();
                }
            });
        }
    });

    front
}
