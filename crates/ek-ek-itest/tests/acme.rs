// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A certificate obtained from a real ACME server.
//!
//! Nothing here is simulated. Pebble is Let's Encrypt's own test server: it
//! speaks RFC 8555, it rejects a share of the nonces it issued on purpose, and
//! it validates the challenge by connecting to port 80 and reading what the
//! traffic path answers. So a certificate coming back means the order flow,
//! the signed envelopes, the challenge delivery and the listener all worked
//! together, against software nobody here wrote.
//!
//! Every reading comes from outside the product: the server's own log, the
//! bytes on the disk, and what a client reads off the listener.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::thread;
use std::time::{Duration, Instant};

use ek_ek_itest::{Background, Cluster, LAB_NAME, Node, PEBBLE_DIRECTORY};

/// Where the order writes what it is waiting on, and the agent reads it.
const CHALLENGE_FILE: &str = "/tmp/ek-ek-challenges.json";
/// Where the agent listens for the traffic path.
const SOCKET: &str = "/tmp/ek-ek-agent.sock";
/// The configuration document the order and the traffic path both work from.
const CONFIG: &str = "/tmp/ek-ek-acme.json";
/// The certificate this measurement orders.
const CERTIFICATE: &str = "cert-lab";

/// Puts a value into a JSON string.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// The configuration both processes work from.
///
/// The listener binds the node's own address rather than a VIP, because the
/// name the certificate is for resolves to that address and the ACME server
/// connects to whatever the name says.
fn document(node: &Node, backend: std::net::Ipv4Addr, root: &str, listen_port: u16) -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "nodes": [{{"id":"{name}","address":"{address}","roles":["control_plane","data_plane"]}}],
  "vips": [{{"id":"vip-lab","address":"{address}","prefix_length":24,"interface":"eth0","preferred_node":"{name}"}}],
  "frontends": [{{
    "id": "plain",
    "vip": "vip-lab",
    "port": {listen_port},
    "transport": "tcp",
    "application": "http",
    "tls": null,
    "proxy_protocol": "disabled",
    "routing_rules": [],
    "sni_rules": [],
    "default_backend": "web",
    "http2": "enabled",
    "connect_timeout_seconds": 5,
    "request_timeout_seconds": 30,
    "idle_timeout_seconds": 0,
    "drain_timeout_seconds": 5,
    "udp_session_limit": 0
  }}],
  "backends": [{{
    "id": "web",
    "algorithm": "round_robin",
    "members": [{{"id":"one","address":"{backend}","port":80,"weight":1,"admin_state":"enabled"}}],
    "health_check": null,
    "stickiness": {{"mode":"disabled"}},
    "connection_pooling": "enabled",
    "connection_pool_size": 0,
    "connection_lifetime_seconds": 0
  }}],
  "certificates": [{{
    "id": "{CERTIFICATE}",
    "sni_names": ["{LAB_NAME}"],
    "source": {{"type":"acme_http01"}},
    "validity": null,
    "chain": null,
    "private_key": null
  }}],
  "dns_providers": [],
  "acme": {{
    "directory_url": "{PEBBLE_DIRECTORY}",
    "contact_email": "yonetici@ek-ek.test",
    "accepted_terms": true,
    "trusted_root_pem": "{root}"
  }}
}}"#,
        name = node.name(),
        address = node.address(),
        root = quoted(root),
    )
}

/// The same document on one line.
///
/// The agent delivers one JSON object per line (ADR-0010), so a configuration
/// with real newlines in it arrives cut in half. Every break in the document
/// above sits at a comma or a brace, so joining the trimmed lines produces the
/// same object.
fn one_line(document: &str) -> String {
    document.lines().map(str::trim).collect::<String>()
}

/// Writes a file inside a node.
fn write(node: &Node, path: &str, contents: &str) {
    let written = node
        .shell(&format!(
            "cat > {path} <<'ENDOFFILE'\n{contents}\nENDOFFILE"
        ))
        .expect("the file should be writable");
    assert!(written.ok(), "{path} was not written: {}", written.stderr);
}

/// Everything a node has to forget before this measurement starts.
fn clean(node: &Node) {
    let _ = node.kill_matching("ek-ek-standin-agent");
    let _ = node.kill_matching("data-plane");
    let cleared = node
        .shell(&format!(
            "rm -f {CHALLENGE_FILE} {SOCKET} {CONFIG} /var/lib/ek-ek/config.db* /var/lib/ek-ek/master.key"
        ))
        .expect("the node should be reachable");
    assert!(cleared.ok(), "the node was not cleared: {}", cleared.stderr);
}

/// Asks the listener for a challenge path and returns the status and the body.
///
/// A refused connection comes back as `000`, which is what curl writes when it
/// never got a status. Treating that as an error would make the wait below
/// panic instead of trying again.
fn ask(node: &Node, port: u16, token: &str) -> (String, String) {
    let answer = node
        .run(&[
            "curl",
            "-s",
            "-o",
            "/tmp/ek-ek-body",
            "-w",
            "%{http_code}",
            "--max-time",
            "5",
            &format!(
                "http://{}:{port}/.well-known/acme-challenge/{token}",
                node.address()
            ),
        ])
        .expect("curl should run");
    let body = node.run_ok(&["cat", "/tmp/ek-ek-body"]).unwrap_or_default();
    (answer.stdout.trim().to_owned(), body)
}

/// Waits until the listener answers at all.
fn wait_until_listening(node: &Node, port: u16, plane: &Background) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let (status, _) = ask(node, port, "anything");
        if status == "404" {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "the traffic path never started answering on port {port}\nstdout:\n{}\nstderr:\n{}",
        plane.stdout(),
        plane.stderr()
    );
}

/// Starts the stand-in agent and the traffic path, and returns both.
fn start(node: &Node, agent_binary: &str, product: &str, port: u16) -> (Background, Background) {
    let agent = node
        .spawn(&[
            agent_binary,
            "--socket",
            SOCKET,
            "--config",
            CONFIG,
            "--challenges",
            CHALLENGE_FILE,
        ])
        .expect("the stand-in agent should start");
    agent
        .wait_for_stdout("listening on", Duration::from_secs(10))
        .expect("the stand-in agent should bind its socket");

    let plane = node
        .spawn(&[product, "data-plane", "--agent-socket", SOCKET])
        .expect("the traffic path should start");
    wait_until_listening(node, port, &plane);
    (agent, plane)
}

#[test]
fn a_certificate_is_obtained_from_a_real_acme_server_and_stored_sealed() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let agent_binary = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-agent")
        .expect("the stand-in agent should build");

    let node = cluster.node("node1").expect("node1 is in the cluster");
    clean(node);

    let root = cluster
        .pebble_root()
        .expect("the ACME server's own authority should be readable");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 is in the cluster");
    write(node, CONFIG, &one_line(&document(node, backend, &root, 80)));

    let (_agent, _plane) = start(node, &agent_binary, &product, 80);

    // Before the order: the path is closed. A listener that answers a token
    // outside an order tells anybody who asks what it is holding.
    let (status, _) = ask(node, 80, "not-a-live-token");
    assert_eq!(
        status, "404",
        "the challenge path answered before any order"
    );

    let ordered = node
        .run(&[
            &product,
            "acme",
            "--config",
            CONFIG,
            "--data-dir",
            "/var/lib/ek-ek",
            "--certificate",
            CERTIFICATE,
            "--challenges",
            CHALLENGE_FILE,
        ])
        .expect("the order command should run");

    let report = format!(
        "stdout:\n{}\nstderr:\n{}\npebble:\n{}",
        ordered.stdout,
        ordered.stderr,
        cluster.pebble_log(60).unwrap_or_default()
    );
    assert!(ordered.ok(), "the order did not complete\n{report}");

    // What the product said it did, in order.
    for event in [
        r#""event":"account_key_created""#,
        r#""event":"ordering""#,
        r#""event":"published""#,
        r#""event":"withdrawn""#,
        r#""event":"obtained""#,
        r#""event":"stored""#,
        r#""event":"usable""#,
    ] {
        assert!(
            ordered.stdout.contains(event),
            "{event} is missing from the record\n{report}"
        );
    }
    assert!(
        ordered.stdout.contains(LAB_NAME),
        "the certificate does not cover the name it was ordered for\n{report}"
    );

    // What the certificate authority says it did. This is the reading that
    // comes from outside: the server connected to port 80 and was satisfied.
    let served = cluster.pebble_log(200).unwrap_or_default();
    assert!(
        served.contains(LAB_NAME),
        "the ACME server never mentions the name\n{served}"
    );

    // The path is closed again, and it is closed for the token the order
    // actually used rather than for a token that never existed.
    let token = published_token(&ordered.stdout).expect("the order named its token");
    let (status, body) = ask(node, 80, &token);
    assert_eq!(
        status, "404",
        "the challenge path is still open after the order: {body}"
    );

    // And the material on the disk is sealed. A copied disk image and a backup
    // carry no readable key (ADR-0018).
    let readable = node
        .shell("grep -c 'BEGIN PRIVATE KEY' /var/lib/ek-ek/config.db* 2>/dev/null | tr '\\n' ' '")
        .expect("the node should be readable");
    assert!(
        !readable.stdout.contains(":1") && !readable.stdout.trim_end().ends_with('1'),
        "a private key is readable in the store: {}",
        readable.stdout
    );
    let present = node
        .shell(&format!(
            "grep -c '{CERTIFICATE}' /var/lib/ek-ek/config.db | tr -d '\\n'"
        ))
        .expect("the node should be readable");
    assert_ne!(
        present.stdout.trim(),
        "0",
        "the certificate record did not reach the store, so the check above measured nothing"
    );
}

/// The token from the first `published` record.
fn published_token(records: &str) -> Option<String> {
    let line = records
        .lines()
        .find(|line| line.contains(r#""event":"published""#))?;
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    value
        .get("tokens")?
        .as_array()?
        .first()?
        .as_str()
        .map(str::to_owned)
}

#[test]
fn an_answer_is_served_only_while_the_order_is_waiting_on_it() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let agent_binary = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-agent")
        .expect("the stand-in agent should build");

    let node = cluster.node("node2").expect("node2 is in the cluster");
    clean(node);

    let backend = cluster
        .backend_address("backend2")
        .expect("backend2 is in the cluster");
    // No ACME server is needed here: what is measured is the delivery, from
    // the moment an answer is published to the moment it is taken away.
    write(node, CONFIG, &one_line(&document(node, backend, "", 80)));
    let (_agent, _plane) = start(node, &agent_binary, &product, 80);

    let (status, _) = ask(node, 80, "measured-token");
    assert_eq!(status, "404", "the path answered before anything published");

    write(
        node,
        CHALLENGE_FILE,
        r#"{"measured-token":"measured-token.thumbprint"}"#,
    );
    let (status, body) = wait_for_status(node, 80, "measured-token", "200");
    assert_eq!(status, "200", "the published answer never reached the path");
    assert_eq!(
        body, "measured-token.thumbprint",
        "the path answered with something other than what was published"
    );

    write(node, CHALLENGE_FILE, "{}");
    let (status, _) = wait_for_status(node, 80, "measured-token", "404");
    assert_eq!(
        status, "404",
        "the answer stayed reachable after it was withdrawn"
    );

    // A token that was never published is never answered, at any point.
    let (status, _) = ask(node, 80, "never-published");
    assert_eq!(status, "404");
}

/// Waits until the listener answers with a status, and returns what it said.
fn wait_for_status(node: &Node, port: u16, token: &str, wanted: &str) -> (String, String) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = (String::new(), String::new());
    while Instant::now() < deadline {
        last = ask(node, port, token);
        if last.0 == wanted {
            return last;
        }
        thread::sleep(Duration::from_millis(200));
    }
    last
}

#[test]
fn an_order_with_nothing_listening_on_port_eighty_stops_with_a_named_fault() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");

    let node = cluster.node("node3").expect("node3 is in the cluster");
    clean(node);

    let root = cluster
        .pebble_root()
        .expect("the ACME server's own authority should be readable");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 is in the cluster");
    // The same document, with the listener moved off the port the ACME server
    // asks on. Nothing else differs.
    write(
        node,
        CONFIG,
        &one_line(&document(node, backend, &root, 8080)),
    );

    let refused = node
        .run(&[
            &product,
            "acme",
            "--config",
            CONFIG,
            "--data-dir",
            "/var/lib/ek-ek",
            "--certificate",
            CERTIFICATE,
            "--challenges",
            CHALLENGE_FILE,
        ])
        .expect("the order command should run");

    assert!(
        !refused.ok(),
        "an order that cannot be answered reported success: {}",
        refused.stdout
    );
    assert!(
        refused
            .stdout
            .contains(r#""code":"config.acme.no_http01_listener""#),
        "the fault was not named: {}\n{}",
        refused.stdout,
        refused.stderr
    );
    assert!(
        refused.stdout.contains(r#""event":"failed""#),
        "the order did not say it failed: {}",
        refused.stdout
    );
    // And it stopped before touching the server, so a misconfigured
    // installation spends none of the account's allowance (ADR-0026).
    assert!(
        !refused.stdout.contains(r#""event":"ordering""#),
        "the order was placed anyway: {}",
        refused.stdout
    );
    assert!(
        !refused.stdout.contains(r#""event":"published""#),
        "an answer was published for an order that could never be checked"
    );
}
