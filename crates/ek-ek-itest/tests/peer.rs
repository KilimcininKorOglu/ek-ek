// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Peer traffic between two real nodes, read off the wire.
//!
//! Peer traffic carries configuration and private key material (ADR-0008), so
//! the one thing that has to be true of it is that nobody between the two
//! nodes can read it. Nothing inside the product can answer that: a channel
//! that encrypts and a channel that only reports encrypting look the same from
//! the inside. `tcpdump` reads the frames independently, so what it prints is
//! what a switch, a hypervisor or anybody on the segment would see.
//!
//! The measurement has two sides in one capture. The name of the node being
//! dialled travels in the clear, because it is in the handshake before there
//! is anything to encrypt with, and finding it proves the capture really is
//! reading the bytes. The message itself must not be there.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use ek_ek_itest::{Capture, Cluster, Node};

/// Where the store, the authority and the material live during a measurement.
const HOME: &str = "/tmp/ek-ek-peer";
/// The configuration the store is started from. Nothing here reads it.
const CONFIG: &str = "/tmp/ek-ek-peer/config.json";
/// The port the peer channel is opened on for these measurements.
///
/// Container to container on the lab bridge; no host port is published.
const PORT: u16 = 7373;

/// The smallest document a store will start from.
const DOCUMENT: &str = r#"{
  "schema_version": 1,
  "nodes": [],
  "vips": [],
  "frontends": [],
  "backends": [],
  "certificates": [],
  "dns_providers": [],
  "acme": null
}"#;

/// Clears anything an earlier measurement left behind.
fn clean(node: &Node) {
    node.kill_matching("cluster serve").ok();
    node.shell(&format!("rm -rf {HOME}"))
        .expect("the node should be cleanable");
}

/// Puts a store with an authority on `node`, and returns its fingerprint.
fn bootstrap(node: &Node, product: &str) -> String {
    node.shell(&format!("mkdir -p {HOME}"))
        .expect("the directory should be creatable");
    node.shell(&format!(
        "cat > {CONFIG} <<'DOCUMENT'\n{DOCUMENT}\nDOCUMENT"
    ))
    .expect("the document should be writable");

    let said = node
        .run_ok(&[
            product,
            "cluster",
            "init",
            "--data-dir",
            HOME,
            "--config",
            CONFIG,
        ])
        .expect("the authority should be created");
    let record: serde_json::Value =
        serde_json::from_str(said.trim()).expect("the line should be a record");
    record["fingerprint"]
        .as_str()
        .expect("a fingerprint")
        .to_owned()
}

/// Signs a certificate for `name` and returns the directory it landed in.
fn enrol(node: &Node, product: &str, name: &str, address: &str) -> String {
    let out = format!("{HOME}/{name}");
    node.run_ok(&[
        product,
        "cluster",
        "enroll",
        "--data-dir",
        HOME,
        "--node",
        name,
        "--address",
        address,
        "--out-dir",
        &out,
    ])
    .expect("the certificate should be signed");
    out
}

/// Copies one node's material to another node.
///
/// The join flow that would do this over the wire is T-038. Until it exists
/// the material crosses by hand, which is also what an operator would do.
fn hand_over(from: &Node, to: &Node, directory: &str, name: &str) {
    for file in [
        format!("{name}.crt"),
        format!("{name}.key"),
        "cluster-ca.crt".to_owned(),
    ] {
        let content = from
            .run_ok(&["cat", &format!("{directory}/{file}")])
            .expect("the file should be readable");
        to.shell(&format!("mkdir -p {directory}"))
            .expect("the directory should be creatable");
        to.shell(&format!(
            "cat > {directory}/{file} <<'MATERIAL'\n{}\nMATERIAL",
            content.trim_end()
        ))
        .expect("the file should be writable");
    }
    to.shell(&format!("chmod 600 {directory}/{name}.key"))
        .expect("the key should be restrictable");
}

#[test]
fn peer_traffic_cannot_be_read_off_the_wire() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");

    let first = cluster.node("node1").expect("node1 is in the cluster");
    let second = cluster.node("node2").expect("node2 is in the cluster");
    clean(first);
    clean(second);

    let fingerprint = bootstrap(first, &product);
    assert_eq!(
        fingerprint.len(),
        64,
        "the fingerprint is not join token shaped"
    );

    let served = enrol(first, &product, "node1", &first.address().to_string());
    let dialling = enrol(first, &product, "node2", &second.address().to_string());
    hand_over(first, second, &dialling, "node2");

    let listen = format!("0.0.0.0:{PORT}");
    let listener = first
        .spawn(&[
            &product,
            "cluster",
            "serve",
            "--listen",
            &listen,
            "--node",
            "node1",
            "--material",
            &served,
            "--connections",
            "1",
        ])
        .expect("the listener should start");
    listener
        .wait_for_stdout("\"event\":\"listening\"", Duration::from_secs(10))
        .expect("the listener should say it is up");

    // Started after the listener and before the caller, so every frame of the
    // exchange is inside the window.
    let capture = Capture::payload(
        first,
        &format!("tcp port {PORT}"),
        200,
        Duration::from_secs(15),
    )
    .expect("the capture should start");

    let target = format!("{}:{PORT}", first.address());
    let answered = second
        .run_ok(&[
            &product,
            "cluster",
            "ping",
            "--to",
            &target,
            "--expect",
            "node1",
            "--node",
            "node2",
            "--material",
            &dialling,
        ])
        .expect("the peer should answer");
    assert!(
        answered.contains(r#""node":"node1""#),
        "the peer did not answer: {answered}"
    );

    let seen = capture.finish().expect("the capture should finish");
    assert!(seen.packets() > 0, "no peer traffic was captured at all");

    // The control. This name is in the handshake before there is a key, so it
    // is expected in the clear and its presence is what proves the capture is
    // reading payload bytes rather than headers alone.
    seen.expect_contains("node1")
        .expect("the capture is not reading what the packets carry");

    // And the message itself is not there. These are the field names every
    // peer message carries; a channel in the clear would show all three.
    for readable in ["\"message\"", "protocol", "health"] {
        assert!(
            !seen.contains(readable),
            "{readable} is readable on the wire between two nodes:\n{}",
            seen.text()
        );
    }

    let finished = listener.finish().expect("the listener should stop");
    assert!(
        finished.stdout.contains(r#""caller":"node2""#),
        "the listener did not name the caller from its certificate: {}",
        finished.stdout
    );

    clean(first);
    clean(second);
}

#[test]
fn a_node_of_another_cluster_is_refused_on_the_peer_port() {
    // The other side, between two real nodes. Everything is the same except
    // which authority signed the caller's certificate.
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");

    let first = cluster.node("node1").expect("node1 is in the cluster");
    let second = cluster.node("node2").expect("node2 is in the cluster");
    clean(first);
    clean(second);

    let ours = bootstrap(first, &product);
    let theirs = bootstrap(second, &product);
    assert_ne!(ours, theirs, "two clusters produced one fingerprint");

    let served = enrol(first, &product, "node1", &first.address().to_string());
    let stranger = enrol(second, &product, "node2", &second.address().to_string());

    // The stranger is given our authority to trust, so it dials rather than
    // refusing the listener first. What is being measured is the listener's
    // own decision.
    let authority = first
        .run_ok(&["cat", &format!("{served}/cluster-ca.crt")])
        .expect("the authority should be readable");
    second
        .shell(&format!(
            "cat > {stranger}/cluster-ca.crt <<'MATERIAL'\n{}\nMATERIAL",
            authority.trim_end()
        ))
        .expect("the authority should be writable");

    let listen = format!("0.0.0.0:{PORT}");
    let listener = first
        .spawn(&[
            &product,
            "cluster",
            "serve",
            "--listen",
            &listen,
            "--node",
            "node1",
            "--material",
            &served,
            "--connections",
            "1",
        ])
        .expect("the listener should start");
    listener
        .wait_for_stdout("\"event\":\"listening\"", Duration::from_secs(10))
        .expect("the listener should say it is up");

    let target = format!("{}:{PORT}", first.address());
    let refused = second
        .run(&[
            &product,
            "cluster",
            "ping",
            "--to",
            &target,
            "--expect",
            "node1",
            "--node",
            "node2",
            "--material",
            &stranger,
        ])
        .expect("the ping should run");
    assert!(
        !refused.ok(),
        "a node of another cluster was served: {}",
        refused.stdout
    );

    let finished = listener.finish().expect("the listener should stop");
    assert!(
        finished.stdout.contains(r#""event":"refused""#),
        "the listener did not report the refusal: {}",
        finished.stdout
    );

    clean(first);
    clean(second);
}
