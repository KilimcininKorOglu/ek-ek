// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the peer channel accepts and what it refuses.
//!
//! Every measurement here opens a real socket and completes a real handshake.
//! Nothing about mutual TLS can be measured any other way: a builder can be
//! configured to ask for a certificate and still accept a caller that sends
//! none, and the two configurations look identical from the inside.
//!
//! Both sides of every rule are measured. A listener that refused everybody
//! would pass every refusal check on this page, so each one sits beside a
//! connection that must succeed.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;

use ek_ek_config::NodeId;
use ek_ek_peer::{Credentials, Listener, PROTOCOL, Reason};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

mod common;

use common::{DAY, authority, credentials, issue, issue_at, now};

/// A listener bound to a port the operating system chooses.
fn listening(node: &str, credentials: &Credentials) -> (Listener, SocketAddr) {
    let listener = Listener::bind("127.0.0.1:0", &NodeId::new(node), credentials)
        .expect("the peer port opens");
    let address = listener.address().expect("the port is readable");
    (listener, address)
}

#[test]
fn two_nodes_of_the_same_cluster_reach_each_other() {
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-1", &server);
    let answering = thread::spawn(move || listener.serve_one());

    let answer = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), &client)
        .expect("a peer of the same cluster is served");
    assert_eq!(answer.node, "node-1");
    assert_eq!(answer.protocol, PROTOCOL);

    let served = answering
        .join()
        .expect("the thread finishes")
        .expect("served");
    // The caller is named by the certificate it presented and by nothing it
    // said. Anybody can claim a name in a message; only one of them was
    // signed by the authority.
    assert_eq!(served.caller, NodeId::new("node-2"));
    assert!(served.asked.is_some());
}

#[test]
fn a_caller_from_another_cluster_is_refused() {
    // The check that makes the authority mean anything. Without it any TLS
    // client at all could open a peer connection.
    let ours = authority();
    let theirs = authority();
    let server = credentials(&ours, &issue(&ours, "node-1"));
    let stranger = credentials(&ours, &issue(&theirs, "node-2"));

    let (listener, address) = listening("node-1", &server);
    let answering = thread::spawn(move || listener.serve_one());

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), &stranger)
        .expect_err("a certificate from another authority is refused");
    assert!(
        matches!(failure.reason(), Reason::Rejected | Reason::Network),
        "the caller was let through: {failure}"
    );
    assert_eq!(
        answering
            .join()
            .expect("the thread finishes")
            .expect_err("the listener refused it")
            .reason(),
        Reason::Rejected
    );
}

#[test]
fn a_caller_with_no_certificate_is_refused() {
    // `SSL_VERIFY_PEER` on its own asks for a certificate and accepts the
    // connection when none arrives. That is the setting that makes mutual TLS
    // look configured and be optional, and this is what catches it.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));

    let (listener, address) = listening("node-1", &server);
    let answering = thread::spawn(move || listener.serve_one());

    let dialling = thread::spawn(move || {
        let mut builder =
            SslConnector::builder(SslMethod::tls_client()).expect("a connector builds");
        // Trusting nobody and checking nothing on the client side, so what is
        // measured is the listener's own decision and not this client's.
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();
        let socket = TcpStream::connect(address).expect("the port answers");
        let mut stream = connector
            .configure()
            .expect("configurable")
            .verify_hostname(false)
            .connect("node-1", socket)
            .map_err(|error| error.to_string())?;
        // Written and read back, because in TLS 1.3 a client learns it was
        // refused only when it tries to use the connection.
        let _ = stream.write_all(b"{\"message\":\"health\",\"protocol\":\"x\"}\n");
        let mut back = Vec::new();
        stream
            .read_to_end(&mut back)
            .map_err(|error| error.to_string())?;
        Ok::<Vec<u8>, String>(back)
    });

    let refusal = answering
        .join()
        .expect("the thread finishes")
        .expect_err("a caller with no certificate is refused");
    assert_eq!(refusal.reason(), Reason::Rejected);
    // Refused by the handshake, not by a check afterwards. Asking for a
    // certificate without requiring one lets the handshake complete, and the
    // guarantee then rests on the application remembering to look. The two
    // land on different messages, which is how they are told apart here.
    assert!(
        refusal.detail().contains("was refused"),
        "the handshake completed and the caller was turned away later: {refusal}"
    );

    let seen = dialling.join().expect("the thread finishes");
    assert!(
        seen.as_ref().map_or(true, Vec::is_empty),
        "the listener answered a caller that presented nothing: {seen:?}"
    );
}

#[test]
fn a_caller_with_an_expired_certificate_is_refused() {
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    // Signed long enough ago that its ninety days are gone.
    let stale = credentials(
        &authority,
        &issue_at(&authority, "node-2", now() - 200 * DAY),
    );

    let (listener, address) = listening("node-1", &server);
    let answering = thread::spawn(move || listener.serve_one());

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), &stale)
        .expect_err("an expired certificate is refused");
    assert!(
        matches!(failure.reason(), Reason::Rejected | Reason::Network),
        "an expired caller was let through: {failure}"
    );
    assert_eq!(
        answering
            .join()
            .expect("the thread finishes")
            .expect_err("the listener refused it")
            .reason(),
        Reason::Rejected
    );
}

#[test]
fn a_node_answering_with_an_expired_certificate_is_refused() {
    // The other direction. A caller has to check the peer as hard as the peer
    // checks the caller, or half the channel is authenticated.
    let authority = authority();
    let stale = credentials(
        &authority,
        &issue_at(&authority, "node-1", now() - 200 * DAY),
    );
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-1", &stale);
    let answering = thread::spawn(move || listener.serve_one());

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), &client)
        .expect_err("a peer with an expired certificate is refused");
    assert_eq!(failure.reason(), Reason::Rejected);
    drop(answering.join());
}

#[test]
fn a_node_answering_under_the_wrong_name_is_refused() {
    // What the caller checks: the identity, never the address. The listener
    // below is reachable and its certificate is valid, and it is still the
    // wrong node.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-3"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-3", &server);
    let answering = thread::spawn(move || listener.serve_one());

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), &client)
        .expect_err("a peer under another name is refused");
    assert_eq!(failure.reason(), Reason::Rejected);
    drop(answering.join());

    // And the same listener answers the caller that asked for the right name,
    // so the refusal above is the name and not the listener.
    let (listener, address) = listening("node-3", &server);
    let answering = thread::spawn(move || listener.serve_one());
    let answer = ek_ek_peer::ask_health(address, &NodeId::new("node-3"), &client)
        .expect("the node it really is answers");
    assert_eq!(answer.node, "node-3");
    drop(answering.join());
}

#[test]
fn a_message_this_release_cannot_read_is_refused_by_name() {
    // An upgrade is rolling, so two releases speak to each other. A peer
    // running a newer one has to be able to tell "you do not know this
    // message" from "you are not there".
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-1", &server);
    let answering = thread::spawn(move || listener.serve_one());

    let connector = {
        let mut builder =
            SslConnector::builder(SslMethod::tls_client()).expect("a connector builds");
        let certificate = openssl::x509::X509::from_pem(client.certificate_pem.as_bytes())
            .expect("a certificate");
        let key =
            openssl::pkey::PKey::private_key_from_pem(client.key_pem.expose()).expect("a key");
        let mut store = openssl::x509::store::X509StoreBuilder::new().expect("a store");
        store
            .add_cert(
                openssl::x509::X509::from_pem(client.authority_pem.as_bytes())
                    .expect("an authority"),
            )
            .expect("the authority is trusted");
        builder.set_cert_store(store.build());
        builder.set_certificate(&certificate).expect("accepted");
        builder.set_private_key(&key).expect("accepted");
        builder.build()
    };

    let socket = TcpStream::connect(address).expect("the port answers");
    let mut stream = connector
        .configure()
        .expect("configurable")
        .connect("node-1", socket)
        .expect("the handshake completes");
    stream
        .write_all(b"{\"message\":\"raft_append\"}\n")
        .expect("the line is sent");

    let mut back = String::new();
    let mut reader = std::io::BufReader::new(&mut stream);
    std::io::BufRead::read_line(&mut reader, &mut back).expect("an answer arrives");
    assert!(
        back.contains(ek_ek_peer::UNREADABLE),
        "the peer said nothing about what it could not read: {back}"
    );

    let served = answering
        .join()
        .expect("the thread finishes")
        .expect("served");
    assert_eq!(served.caller, NodeId::new("node-2"));
    assert!(
        served.asked.is_none(),
        "an unreadable line was taken for a message"
    );
}

#[test]
fn the_channel_is_a_line_of_json_and_nothing_is_readable_off_the_wire() {
    // The bytes a listener actually receives, taken before OpenSSL sees them.
    // A channel that carried the message in the clear would show the field
    // names here, and a packet capture in the lab reads the same wire.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let observer = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let address = observer.local_addr().expect("readable");

    let watching = thread::spawn(move || {
        let (mut accepted, _) = observer.accept().expect("a connection arrives");
        let mut seen = Vec::new();
        let mut buffer = [0_u8; 4096];
        accepted
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("a timeout");
        while let Ok(read) = accepted.read(&mut buffer) {
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..read]);
            if seen.len() > 2048 {
                break;
            }
        }
        seen
    });

    // The dial fails, because nothing on the other end speaks TLS. What
    // matters is what reached the wire before it did.
    drop(ek_ek_peer::ask_health(
        address,
        &NodeId::new("node-1"),
        &client,
    ));
    drop(server);

    let seen = watching.join().expect("the thread finishes");
    assert!(!seen.is_empty(), "nothing reached the wire");
    for marker in [
        b"message".as_slice(),
        b"health".as_slice(),
        b"protocol".as_slice(),
    ] {
        assert!(
            !seen.windows(marker.len()).any(|window| window == marker),
            "{} appeared on the wire in the clear",
            String::from_utf8_lossy(marker)
        );
    }
}

#[test]
fn a_peer_that_names_a_different_node_than_it_proved_is_refused() {
    // A message says whatever its sender types. Only the certificate was
    // signed by the authority, so where the two disagree the message is the
    // one to throw away.
    let authority = authority();
    let liar = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let address = socket.local_addr().expect("readable");

    let answering = thread::spawn(move || {
        let acceptor = {
            let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
                .expect("an acceptor");
            let certificate = openssl::x509::X509::from_pem(liar.certificate_pem.as_bytes())
                .expect("a certificate");
            let key =
                openssl::pkey::PKey::private_key_from_pem(liar.key_pem.expose()).expect("a key");
            builder.set_certificate(&certificate).expect("accepted");
            builder.set_private_key(&key).expect("accepted");
            builder.build()
        };
        let (accepted, _) = socket.accept().expect("a connection");
        let mut stream = acceptor.accept(accepted).expect("the handshake completes");
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(&mut stream), &mut line)
            .expect("a question arrives");
        // A valid certificate for node-1, and an answer claiming to be
        // somebody else.
        let _ = stream.write_all(
            format!("{{\"message\":\"health\",\"protocol\":\"{PROTOCOL}\",\"node\":\"node-9\"}}\n")
                .as_bytes(),
        );
        let _ = stream.flush();
    });

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), &client)
        .expect_err("an answer that names another node is refused");
    assert_eq!(failure.reason(), Reason::Protocol);
    assert!(
        failure.detail().contains("node-9"),
        "the refusal does not say what was claimed: {failure}"
    );
    drop(answering.join());
}

#[test]
fn a_peer_that_cannot_speak_the_newest_tls_is_refused() {
    // Every peer is this same product, so there is no old client to keep and
    // no reason to offer anything below the newest version.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let dial = |ceiling: SslVersion| {
        let (listener, address) = listening("node-1", &server);
        let answering = thread::spawn(move || listener.serve_one());

        let mut builder =
            SslConnector::builder(SslMethod::tls_client()).expect("a connector builds");
        builder
            .set_max_proto_version(Some(ceiling))
            .expect("the ceiling is set");
        let certificate = openssl::x509::X509::from_pem(client.certificate_pem.as_bytes())
            .expect("a certificate");
        let key =
            openssl::pkey::PKey::private_key_from_pem(client.key_pem.expose()).expect("a key");
        let mut store = openssl::x509::store::X509StoreBuilder::new().expect("a store");
        store
            .add_cert(
                openssl::x509::X509::from_pem(client.authority_pem.as_bytes())
                    .expect("an authority"),
            )
            .expect("the authority is trusted");
        builder.set_cert_store(store.build());
        builder.set_certificate(&certificate).expect("accepted");
        builder.set_private_key(&key).expect("accepted");
        let connector = builder.build();

        let socket = TcpStream::connect(address).expect("the port answers");
        let outcome = connector
            .configure()
            .expect("configurable")
            .connect("node-1", socket)
            .map(|_| ())
            .map_err(|error| error.to_string());
        drop(answering.join());
        outcome
    };

    assert!(
        dial(SslVersion::TLS1_2).is_err(),
        "a peer that can speak no newer than TLS 1.2 was served"
    );
    // And the newest one is, so the refusal above is the floor and not a
    // listener that turns everybody away.
    assert!(dial(SslVersion::TLS1_3).is_ok());
}
