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
use std::pin::Pin;
use std::sync::Arc;
use std::thread;

use ek_ek_config::NodeId;
use ek_ek_peer::{
    Credentials, Failure, Listener, Listening, NoServices, PROTOCOL, Peer, Reason, Served, Service,
};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

mod common;

use common::{DAY, authority, credentials, issue, issue_at, now};

/// The config schema every node in these measurements reads.
const SCHEMA: u32 = 1;

/// A listener bound to a port the operating system chooses.
async fn listening(node: &str, credentials: &Credentials) -> (Listener, SocketAddr) {
    listening_at(node, SCHEMA, credentials, Arc::new(NoServices)).await
}

/// The same, with the schema and the services named.
async fn listening_at(
    node: &str,
    schema_version: u32,
    credentials: &Credentials,
    service: Arc<dyn Service>,
) -> (Listener, SocketAddr) {
    let listener = Listener::bind(
        "127.0.0.1:0",
        credentials,
        Listening::new(&NodeId::new(node), schema_version, service),
    )
    .await
    .expect("the peer port opens");
    let address = listener.address().expect("the port is readable");
    (listener, address)
}

/// Serves one peer in the background and hands back what it saw.
fn answering(listener: Listener) -> tokio::task::JoinHandle<Result<Served, Failure>> {
    tokio::spawn(async move { listener.serve_one().await })
}

/// A listener that opens one service to a caller with no certificate.
async fn opening(
    node: &str,
    credentials: &Credentials,
    service: Arc<dyn Service>,
    open: &str,
) -> (Listener, SocketAddr) {
    let listener = Listener::bind(
        "127.0.0.1:0",
        credentials,
        Listening::new(&NodeId::new(node), SCHEMA, service).opening(open),
    )
    .await
    .expect("the peer port opens");
    let address = listener.address().expect("the port is readable");
    (listener, address)
}

/// A gate that turns one name away.
struct Barred(NodeId);

impl ek_ek_peer::Gate for Barred {
    fn refuses(&self, caller: &NodeId) -> bool {
        *caller == self.0
    }
}

/// A service that answers one name and refuses everything else.
struct Echo;

impl Service for Echo {
    fn call(
        &self,
        from: Option<&NodeId>,
        service: &str,
        body: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Failure>> + Send + '_>> {
        let named = service.to_owned();
        let caller = from.map(|node| node.as_str().to_owned());
        Box::pin(async move {
            if named == "echo" {
                Ok(serde_json::json!({ "from": caller, "body": body }))
            } else {
                Err(Failure::new(
                    Reason::Protocol,
                    format!("this node runs no {named} service"),
                ))
            }
        })
    }
}

#[tokio::test]
async fn two_nodes_of_the_same_cluster_reach_each_other() {
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-1", &server).await;
    let served = answering(listener);

    let answer = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), SCHEMA, &client)
        .await
        .expect("a peer of the same cluster is served");
    assert_eq!(answer.node, "node-1");
    assert_eq!(answer.protocol, PROTOCOL);

    let served = served
        .await
        .expect("the task finishes")
        .expect("the peer was served");
    // The caller is named by the certificate it presented and by nothing it
    // said. Anybody can claim a name in a message; only one of them was
    // signed by the authority.
    assert_eq!(served.caller, Some(NodeId::new("node-2")));
}

#[tokio::test]
async fn a_caller_from_another_cluster_is_refused() {
    // The check that makes the authority mean anything. Without it any TLS
    // client at all could open a peer connection.
    let ours = authority();
    let theirs = authority();
    let server = credentials(&ours, &issue(&ours, "node-1"));
    let stranger = credentials(&ours, &issue(&theirs, "node-2"));

    let (listener, address) = listening("node-1", &server).await;
    let served = answering(listener);

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), SCHEMA, &stranger)
        .await
        .expect_err("a certificate from another authority is refused");
    assert!(
        matches!(failure.reason(), Reason::Rejected | Reason::Network),
        "the caller was let through: {failure}"
    );
    assert_eq!(
        served
            .await
            .expect("the task finishes")
            .expect_err("the listener refused it")
            .reason(),
        Reason::Rejected
    );
}

#[tokio::test]
async fn a_caller_with_no_certificate_is_refused() {
    // `SSL_VERIFY_PEER` on its own asks for a certificate and accepts the
    // connection when none arrives. That is the setting that makes mutual TLS
    // look configured and be optional, and this is what catches it.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));

    let (listener, address) = listening("node-1", &server).await;
    let served = answering(listener);

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
        let _ = stream.write_all(b"{\"message\":\"hello\",\"protocol\":\"x\"}\n");
        let mut back = Vec::new();
        stream
            .read_to_end(&mut back)
            .map_err(|error| error.to_string())?;
        Ok::<Vec<u8>, String>(back)
    });

    let refusal = served
        .await
        .expect("the task finishes")
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
        seen.as_ref().is_ok_and(Vec::is_empty) || seen.is_err(),
        "the listener answered a caller that presented nothing: {seen:?}"
    );
}

#[tokio::test]
async fn a_caller_with_an_expired_certificate_is_refused() {
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    // Signed long enough ago that its ninety days are gone.
    let stale = credentials(
        &authority,
        &issue_at(&authority, "node-2", now() - 200 * DAY),
    );

    let (listener, address) = listening("node-1", &server).await;
    let served = answering(listener);

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), SCHEMA, &stale)
        .await
        .expect_err("an expired certificate is refused");
    assert!(
        matches!(failure.reason(), Reason::Rejected | Reason::Network),
        "an expired caller was let through: {failure}"
    );
    assert_eq!(
        served
            .await
            .expect("the task finishes")
            .expect_err("the listener refused it")
            .reason(),
        Reason::Rejected
    );
}

#[tokio::test]
async fn a_node_answering_with_an_expired_certificate_is_refused() {
    // The other direction. A caller has to check the peer as hard as the peer
    // checks the caller, or half the channel is authenticated.
    let authority = authority();
    let stale = credentials(
        &authority,
        &issue_at(&authority, "node-1", now() - 200 * DAY),
    );
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-1", &stale).await;
    let served = answering(listener);

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), SCHEMA, &client)
        .await
        .expect_err("a peer with an expired certificate is refused");
    assert_eq!(failure.reason(), Reason::Rejected);
    served.abort();
}

#[tokio::test]
async fn a_node_answering_under_the_wrong_name_is_refused() {
    // What the caller checks: the identity, never the address. The listener
    // below is reachable and its certificate is valid, and it is still the
    // wrong node.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-3"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-3", &server).await;
    let served = answering(listener);

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), SCHEMA, &client)
        .await
        .expect_err("a peer under another name is refused");
    assert_eq!(failure.reason(), Reason::Rejected);
    served.abort();

    // And the same listener answers the caller that asked for the right name,
    // so the refusal above is the name and not the listener.
    let (listener, address) = listening("node-3", &server).await;
    let served = answering(listener);
    let answer = ek_ek_peer::ask_health(address, &NodeId::new("node-3"), SCHEMA, &client)
        .await
        .expect("the node it really is answers");
    assert_eq!(answer.node, "node-3");
    served.abort();
}

#[tokio::test]
async fn a_message_this_release_cannot_read_is_refused_by_name() {
    // An upgrade is rolling, so two releases speak to each other. A peer
    // running a newer one has to be able to tell "you do not know this
    // message" from "you are not there".
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-1", &server).await;
    let served = answering(listener);

    let seen = tokio::task::spawn_blocking(move || {
        let mut stream = raw_client(address, &client, "node-1");
        stream
            .write_all(b"{\"message\":\"raft_append\"}\n")
            .expect("the line is sent");
        let mut back = String::new();
        let mut reader = std::io::BufReader::new(&mut stream);
        std::io::BufRead::read_line(&mut reader, &mut back).expect("an answer arrives");
        back
    })
    .await
    .expect("the client finishes");

    assert!(
        seen.contains(ek_ek_peer::UNREADABLE),
        "the peer said nothing about what it could not read: {seen}"
    );

    let served = served
        .await
        .expect("the task finishes")
        .expect("the peer was served");
    assert_eq!(served.caller, Some(NodeId::new("node-2")));
    assert_eq!(
        served.calls, 0,
        "an unreadable line was taken for a call: {served:?}"
    );
}

#[tokio::test]
async fn a_peer_that_reads_another_config_schema_is_refused_before_it_joins() {
    // ADR-0019. A node that cannot read what the cluster holds has to stop at
    // the door: one refused connection, not a half joined member that takes a
    // log record and then cannot apply it.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening_at("node-1", 7, &server, Arc::new(NoServices)).await;
    let served = answering(listener);

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), 9, &client)
        .await
        .expect_err("a node reading another schema is refused");
    assert_eq!(failure.reason(), Reason::Rejected);
    assert!(
        failure.detail().contains(ek_ek_peer::WRONG_SCHEMA),
        "the refusal does not name the reason: {failure}"
    );
    // Both schema numbers are in the message, so an operator reading it knows
    // which node to upgrade without opening either one.
    assert!(
        failure.detail().contains('7') && failure.detail().contains('9'),
        "the refusal does not say which schemas disagreed: {failure}"
    );
    served.abort();

    // The same listener serves the node that reads what it reads, so the
    // refusal above is the schema and not the listener.
    let (listener, address) = listening_at("node-1", 7, &server, Arc::new(NoServices)).await;
    let served = answering(listener);
    let answer = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), 7, &client)
        .await
        .expect("a node reading the same schema is served");
    assert_eq!(answer.node, "node-1");
    served.abort();
}

#[tokio::test]
async fn a_peer_that_speaks_before_it_says_hello_is_refused() {
    // The greeting is where the protocol and the schema are checked. A peer
    // that could skip it would replicate before either was compared.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening("node-1", &server).await;
    let served = answering(listener);

    let seen = tokio::task::spawn_blocking(move || {
        let mut stream = raw_client(address, &client, "node-1");
        stream
            .write_all(b"{\"message\":\"call\",\"service\":\"echo\",\"body\":{}}\n")
            .expect("the line is sent");
        let mut back = String::new();
        let mut reader = std::io::BufReader::new(&mut stream);
        std::io::BufRead::read_line(&mut reader, &mut back).expect("an answer arrives");
        back
    })
    .await
    .expect("the client finishes");

    assert!(
        seen.contains(ek_ek_peer::NO_HELLO),
        "a call was taken before the greeting: {seen}"
    );
    let served = served
        .await
        .expect("the task finishes")
        .expect("the peer was served");
    assert_eq!(served.calls, 0, "the call was counted: {served:?}");
}

#[tokio::test]
async fn a_call_reaches_the_service_and_an_unknown_name_is_refused() {
    // The transport Raft rides (ADR-0083). Both sides: a call the node runs
    // reaches it and is counted, and one it does not run is refused by name.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = listening_at("node-1", SCHEMA, &server, Arc::new(Echo)).await;
    let served = answering(listener);

    let mut peer = ek_ek_peer::Peer::dial(address, &NodeId::new("node-1"), SCHEMA, &client)
        .await
        .expect("the peer answers");

    let answer = peer
        .call("echo", serde_json::json!({ "n": 1 }))
        .await
        .expect("the service answers");
    // The service is told who called by the certificate, not by the body.
    assert_eq!(answer["from"], "node-2");
    assert_eq!(answer["body"]["n"], 1);

    let refused = peer
        .call("raft.append_entries", serde_json::json!({}))
        .await
        .expect_err("a service this node does not run is refused");
    assert_eq!(refused.reason(), Reason::Protocol);
    assert!(
        refused.detail().contains("raft.append_entries"),
        "the refusal does not name the service: {refused}"
    );

    drop(peer);
    let served = served
        .await
        .expect("the task finishes")
        .expect("the peer was served");
    assert_eq!(served.calls, 2, "the calls were not counted: {served:?}");
}

#[tokio::test]
async fn the_channel_is_a_line_of_json_and_nothing_is_readable_off_the_wire() {
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
    drop(ek_ek_peer::ask_health(address, &NodeId::new("node-1"), SCHEMA, &client).await);
    drop(server);

    let seen = watching.join().expect("the thread finishes");
    assert!(!seen.is_empty(), "nothing reached the wire");
    for marker in [
        b"message".as_slice(),
        b"hello".as_slice(),
        b"protocol".as_slice(),
        b"schema_version".as_slice(),
    ] {
        assert!(
            !seen.windows(marker.len()).any(|window| window == marker),
            "{} appeared on the wire in the clear",
            String::from_utf8_lossy(marker)
        );
    }
}

#[tokio::test]
async fn a_peer_that_names_a_different_node_than_it_proved_is_refused() {
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
            .expect("a greeting arrives");
        // A valid certificate for node-1, and an answer claiming to be
        // somebody else.
        let _ = stream.write_all(
            format!(
                "{{\"message\":\"hello\",\"protocol\":\"{PROTOCOL}\",\"schema_version\":{SCHEMA},\"node\":\"node-9\"}}\n"
            )
            .as_bytes(),
        );
        let _ = stream.flush();
    });

    let failure = ek_ek_peer::ask_health(address, &NodeId::new("node-1"), SCHEMA, &client)
        .await
        .expect_err("an answer that names another node is refused");
    assert_eq!(failure.reason(), Reason::Protocol);
    assert!(
        failure.detail().contains("node-9"),
        "the refusal does not say what was claimed: {failure}"
    );
    drop(answering.join());
}

#[tokio::test]
async fn a_peer_that_cannot_speak_the_newest_tls_is_refused() {
    // Every peer is this same product, so there is no old client to keep and
    // no reason to offer anything below the newest version.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let client = credentials(&authority, &issue(&authority, "node-2"));

    async fn dial(
        server: &Credentials,
        client: &Credentials,
        ceiling: SslVersion,
    ) -> Result<(), String> {
        let (listener, address) = listening("node-1", server).await;
        let served = answering(listener);
        let client = client.clone();

        let outcome = tokio::task::spawn_blocking(move || {
            let mut builder =
                SslConnector::builder(SslMethod::tls_client()).expect("a connector builds");
            builder
                .set_max_proto_version(Some(ceiling))
                .expect("the ceiling is set");
            with_material(&mut builder, &client);
            let connector = builder.build();

            let socket = TcpStream::connect(address).expect("the port answers");
            connector
                .configure()
                .expect("configurable")
                .connect("node-1", socket)
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
        .await
        .expect("the client finishes");

        served.abort();
        outcome
    }

    assert!(
        dial(&server, &client, SslVersion::TLS1_2).await.is_err(),
        "a peer that can speak no newer than TLS 1.2 was served"
    );
    // And the newest one is, so the refusal above is the floor and not a
    // listener that turns everybody away.
    assert!(dial(&server, &client, SslVersion::TLS1_3).await.is_ok());
}

/// A blocking TLS client that presents this cluster's material.
///
/// Used where a measurement has to write a line the product's own client would
/// never write.
fn raw_client(
    address: SocketAddr,
    credentials: &Credentials,
    expect: &str,
) -> openssl::ssl::SslStream<TcpStream> {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("a connector builds");
    with_material(&mut builder, credentials);
    let connector = builder.build();
    let socket = TcpStream::connect(address).expect("the port answers");
    connector
        .configure()
        .expect("configurable")
        .connect(expect, socket)
        .expect("the handshake completes")
}

/// Puts one node's certificate, key and authority on a connector.
fn with_material(builder: &mut openssl::ssl::SslConnectorBuilder, credentials: &Credentials) {
    let certificate = openssl::x509::X509::from_pem(credentials.certificate_pem.as_bytes())
        .expect("a certificate");
    let key =
        openssl::pkey::PKey::private_key_from_pem(credentials.key_pem.expose()).expect("a key");
    let mut store = openssl::x509::store::X509StoreBuilder::new().expect("a store");
    store
        .add_cert(
            openssl::x509::X509::from_pem(credentials.authority_pem.as_bytes())
                .expect("an authority"),
        )
        .expect("the authority is trusted");
    builder.set_cert_store(store.build());
    builder.set_certificate(&certificate).expect("accepted");
    builder.set_private_key(&key).expect("accepted");
}

#[tokio::test]
async fn a_caller_with_no_certificate_reaches_the_open_service_and_nothing_else() {
    // The whole of what an open service means. A node with no certificate yet
    // has to be able to ask for one, and must not be able to ask for anything
    // else on the way (ADR-0084).
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));

    let (listener, address) = opening("node-1", &server, Arc::new(Echo), "echo").await;
    let serving = tokio::spawn(Arc::new(listener).serve_forever());

    let mut peer = Peer::dial_unproven(address, SCHEMA)
        .await
        .expect("a caller with no certificate reaches an open listener");

    let answered = peer
        .call("echo", serde_json::json!({ "said": "hello" }))
        .await
        .expect("the open service answers");
    assert_eq!(answered["body"]["said"], "hello");
    // The service is told the caller has no name, so it can decide what an
    // unnamed caller may do rather than assume one.
    assert_eq!(answered["from"], serde_json::Value::Null);

    // The same connection, a different name. Refused by the listener rather
    // than by the service, so a service added later cannot forget the rule.
    let mut peer = Peer::dial_unproven(address, SCHEMA)
        .await
        .expect("a second connection opens");
    let refused = peer
        .call("something-else", serde_json::json!({}))
        .await
        .expect_err("only the open service is open");
    assert!(
        refused.detail().contains(ek_ek_peer::NOT_OPEN),
        "the refusal does not say the service is closed to this caller: {refused}"
    );

    serving.abort();
}

#[tokio::test]
async fn a_caller_that_holds_a_certificate_reaches_the_service_the_other_could_not() {
    // The other side of the rule above. Without this, a listener that refused
    // every name would pass that measurement.
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let caller = credentials(&authority, &issue(&authority, "node-2"));

    let (listener, address) = opening("node-1", &server, Arc::new(Echo), "join").await;
    let serving = tokio::spawn(Arc::new(listener).serve_forever());

    let mut peer = Peer::dial(address, &NodeId::new("node-1"), SCHEMA, &caller)
        .await
        .expect("a node of this cluster reaches the listener");
    let answered = peer
        .call("echo", serde_json::json!({ "said": "hello" }))
        .await
        .expect("a named caller reaches a service that is not open");
    assert_eq!(answered["from"], "node-2");

    serving.abort();
}

#[test]
fn a_listener_opens_what_it_was_told_to_open_and_no_more() {
    // The set decides who may reach what. One extra name in it is one service
    // a caller with no certificate can reach, so the set is measured rather
    // than only the behaviour it produces.
    let plain = Listening::new(&NodeId::new("node-1"), SCHEMA, Arc::new(NoServices));
    assert!(
        plain.open.is_empty(),
        "a listener opens something by default: {:?}",
        plain.open
    );

    let opened = plain.opening("cluster.join");
    assert_eq!(
        opened.open.iter().map(String::as_str).collect::<Vec<_>>(),
        ["cluster.join"],
        "the listener opened something it was not told to"
    );
}

#[tokio::test]
async fn a_listener_that_opens_nothing_still_demands_a_certificate() {
    // The setting that decides this is one flag. A listener that opened a
    // service would drop it, and every listener that opens none has to keep it
    // (ADR-0084).
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));

    let (listener, address) = listening("node-1", &server).await;
    let serving = tokio::spawn(Arc::new(listener).serve_forever());

    let refused = Peer::dial_unproven(address, SCHEMA)
        .await
        .expect_err("a listener that opens nothing takes no unnamed caller");
    // The alert the listener sent, read back. In TLS 1.3 a client learns it
    // was refused only when it tries to use the connection, so this arrives as
    // a read failure carrying what the far end said.
    assert!(
        refused.detail().contains("certificate required"),
        "the listener let a caller with no certificate through: {refused}"
    );

    serving.abort();
}

#[tokio::test]
async fn a_removed_caller_is_turned_away_by_name() {
    // Its certificate is valid, was signed by this authority, and nothing
    // revoked it. The list is the only thing that stops it (R-32, ADR-0084).
    let authority = authority();
    let server = credentials(&authority, &issue(&authority, "node-1"));
    let cast_out = credentials(&authority, &issue(&authority, "node-2"));
    let still_in = credentials(&authority, &issue(&authority, "node-3"));

    let listener = Listener::bind(
        "127.0.0.1:0",
        &server,
        Listening::new(&NodeId::new("node-1"), SCHEMA, Arc::new(Echo))
            .behind(Arc::new(Barred(NodeId::new("node-2")))),
    )
    .await
    .expect("the peer port opens");
    let address = listener.address().expect("the port is readable");
    let serving = tokio::spawn(Arc::new(listener).serve_forever());

    let refused = Peer::dial(address, &NodeId::new("node-1"), SCHEMA, &cast_out)
        .await
        .expect_err("a removed caller is not answered");
    assert!(
        refused.detail().contains(ek_ek_peer::REMOVED),
        "the refusal does not say the caller was removed: {refused}"
    );
    assert!(
        refused.detail().contains("node-2"),
        "the refusal does not name the caller: {refused}"
    );

    // And a caller that is not on the list is answered, so the gate is about
    // the name and not about refusing everybody.
    Peer::dial(address, &NodeId::new("node-1"), SCHEMA, &still_in)
        .await
        .expect("a caller that was not removed is answered");

    serving.abort();
}
