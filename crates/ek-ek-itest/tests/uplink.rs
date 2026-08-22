// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A node that has lost its way out gives the virtual address up.
//!
//! Unicast VRRP cannot see this on its own: the peers sit on the same segment
//! and keep answering while the uplink is gone, so the node holding the
//! address would keep holding it and every client would reach a dead end
//! (R-02, ADR-0030).
//!
//! # How the uplink is cut
//!
//! The gateway's neighbour entry is replaced with a hardware address nobody
//! has. The question leaves the node and no answer comes back, which is the
//! shape a pulled cable or a dead switch takes. The peers are untouched, so
//! this is an uplink fault rather than a node that died, and that is the
//! difference the check exists to see.
//!
//! Every reading comes from the kernel: `ip addr` for where the address is,
//! and a capture for what the check costs.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use ek_ek_itest::{Background, Capture, Cluster, Node};

/// The advertisement interval ADR-0029 makes the default.
const INTERVAL_MS: u64 = 300;

/// How long a node is given to reach a state.
const PATIENCE: Duration = Duration::from_secs(30);

/// The prefix length the lab network uses.
const PREFIX: u8 = 24;

/// A hardware address nothing on the segment answers to.
///
/// Locally administered and unicast, so the kernel takes it without
/// complaint and the frames leave the node.
const NOWHERE: &str = "02:00:00:00:00:99";

/// Starts one virtual router that watches its gateway.
fn start(
    node: &Node,
    binary: &str,
    address: Ipv4Addr,
    priority: u8,
    peers: &[Ipv4Addr],
    check_ms: Option<u64>,
) -> Background {
    let mut argv: Vec<String> = vec![
        binary.to_owned(),
        "--address".to_owned(),
        node.address().to_string(),
        "--interface".to_owned(),
        "eth0".to_owned(),
        "--virtual-address".to_owned(),
        format!("{address}/{PREFIX}"),
        "--vrid".to_owned(),
        "51".to_owned(),
        "--priority".to_owned(),
        priority.to_string(),
        "--interval-ms".to_owned(),
        INTERVAL_MS.to_string(),
        "--watch-gateway".to_owned(),
    ];
    for peer in peers {
        argv.push("--peer".to_owned());
        argv.push(peer.to_string());
    }
    // Left at the shipped default unless a measurement is about the timing
    // itself, so what runs here is what an operator gets.
    if let Some(milliseconds) = check_ms {
        argv.push("--check-interval-ms".to_owned());
        argv.push(milliseconds.to_string());
    }

    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    node.spawn(&borrowed)
        .expect("the virtual router must start")
}

/// The gateway this node's routing table names.
///
/// Read from the node rather than written here, so the measurement does not
/// carry its own copy of the lab network's layout.
fn gateway_of(node: &Node) -> String {
    let shown = node
        .run_ok(&["ip", "route", "show", "default"])
        .expect("the routing table should be readable");
    let mut words = shown.split_whitespace();
    while let Some(word) = words.next() {
        if word == "via" {
            return words.next().unwrap_or_default().to_owned();
        }
    }
    panic!("this node has no default route: {shown}");
}

/// Cuts the way out of one node.
fn cut_uplink(node: &Node, gateway: &str) {
    node.run_ok(&[
        "ip",
        "neigh",
        "replace",
        gateway,
        "lladdr",
        NOWHERE,
        "nud",
        "permanent",
        "dev",
        "eth0",
    ])
    .expect("the neighbour entry should be writable");
}

/// Puts it back.
fn mend_uplink(node: &Node, gateway: &str) {
    let _ = node.run(&["ip", "neigh", "del", gateway, "dev", "eth0"]);
}

/// Starts the cluster with nothing left over from an earlier run.
fn clean() -> (Cluster, String) {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    (cluster, binary)
}

/// Stops every virtual router on every node.
fn stop_all(cluster: &Cluster) {
    for node in cluster.nodes() {
        let _ = node.kill_matching("ek-ek-vrrp-node");
    }
}

#[test]
fn a_node_that_lost_its_uplink_gives_the_address_to_one_that_has_not() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(3).expect("vip 3 is inside the reserved range");
    let gateway = gateway_of(node1);

    // Half a second rather than the shipped two, so three losses take under
    // two seconds. What is measured is the rule, and the interval it runs at
    // is measured on its own below.
    let stronger = start(node1, &binary, vip, 200, &[node2.address()], Some(500));
    let weaker = start(node2, &binary, vip, 150, &[node1.address()], Some(500));

    stronger
        .wait_for_stdout(r#""event":"taken""#, PATIENCE)
        .expect("the stronger node must take the address");
    stronger
        .wait_for_stdout(r#""event":"confirmed""#, PATIENCE)
        .expect("and its gateway must answer before anything is counted");
    thread::sleep(Duration::from_millis(500));

    let held_before = node1.has_address(vip).expect("node1 should be readable");
    let peer_before = node2.has_address(vip).expect("node2 should be readable");

    cut_uplink(node1, &gateway);

    let stood_down = stronger.wait_for_stdout(r#""reason":"gateway_lost""#, PATIENCE);
    let took_over = weaker.wait_for_stdout(r#""event":"taken""#, PATIENCE);
    thread::sleep(Duration::from_millis(500));

    let held_after = node1.has_address(vip).expect("node1 should be readable");
    let peer_after = node2.has_address(vip).expect("node2 should be readable");

    // And back: the fault passes, the claim goes up again, and the address
    // returns to the node the configuration prefers.
    mend_uplink(node1, &gateway);
    let came_back = stronger.wait_for_stdout(r#""event":"back""#, PATIENCE);
    // Read on the weaker node on purpose. The stronger one wrote
    // `nobody_else_answered` when it first took the role, and that record is
    // still in its output, so waiting for it there would measure the past.
    // Only the takeover puts `stronger_peer` in the weaker node's output.
    let home = weaker.wait_for_stdout(r#""reason":"stronger_peer""#, PATIENCE);
    thread::sleep(Duration::from_millis(500));
    let held_home = node1.has_address(vip).expect("node1 should be readable");
    let peer_home = node2.has_address(vip).expect("node2 should be readable");

    stop_all(&cluster);

    assert!(held_before, "the stronger node has to hold it first");
    assert!(!peer_before, "and the weaker one must not");

    stood_down.expect("the node that lost its gateway must give the role up");
    took_over.expect("the node that still has one must take it");
    assert!(!held_after, "the cut node must let the address go");
    assert!(peer_after, "and the node with a way out must hold it");

    came_back.expect("the gateway answering again must be noticed");
    home.expect("and the stronger node must take the role back");
    assert!(held_home, "the address must come home");
    assert!(!peer_home, "and leave the weaker node");
}

#[test]
fn a_question_the_kernel_refuses_to_send_counts_as_one_nobody_answered() {
    // The other shape of a lost uplink. Above, the question leaves and no
    // answer comes back. Here the route to the gateway is gone and the send
    // itself is refused, so nothing is ever outstanding to time out. A check
    // that only counted silence would hold the address through this.
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(6).expect("vip 6 is inside the reserved range");
    let gateway = gateway_of(node1);

    let stronger = start(node1, &binary, vip, 200, &[node2.address()], Some(500));
    let weaker = start(node2, &binary, vip, 150, &[node1.address()], Some(500));
    stronger
        .wait_for_stdout(r#""event":"confirmed""#, PATIENCE)
        .expect("the gateway must answer first");
    stronger
        .wait_for_stdout(r#""event":"taken""#, PATIENCE)
        .expect("the stronger node must take the address");

    node1
        .run_ok(&["ip", "route", "add", "blackhole", &format!("{gateway}/32")])
        .expect("the route should be addable");

    let stood_down = stronger.wait_for_stdout(r#""reason":"gateway_lost""#, PATIENCE);
    let took_over = weaker.wait_for_stdout(r#""event":"taken""#, PATIENCE);
    thread::sleep(Duration::from_millis(500));
    let held_after = node1.has_address(vip).expect("node1 should be readable");
    let peer_after = node2.has_address(vip).expect("node2 should be readable");

    let _ = node1.run(&["ip", "route", "del", "blackhole", &format!("{gateway}/32")]);
    stop_all(&cluster);

    stood_down.expect("a node that cannot even ask has lost its way out");
    took_over.expect("and the node that can must take the address");
    assert!(!held_after, "the cut node must let the address go");
    assert!(peer_after, "and the node with a way out must hold it");
}

#[test]
fn the_check_costs_about_one_question_an_interval() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(4).expect("vip 4 is inside the reserved range");

    // The shipped interval, because the traffic an operator gets is what this
    // measures.
    let running = start(node1, &binary, vip, 200, &[node2.address()], None);
    running
        .wait_for_stdout(r#""event":"confirmed""#, PATIENCE)
        .expect("the gateway must answer");

    let window = Duration::from_secs(6);
    let capture = Capture::start(node1, "icmp", 200, window).expect("the capture should start");
    thread::sleep(window);
    let seen = capture.finish().expect("the capture should finish");

    stop_all(&cluster);

    let questions = seen.count("ICMP echo request");
    // Six seconds at the two second interval is three questions, and the
    // window's edges can cut one off either end.
    assert!(
        (2..=4).contains(&questions),
        "{questions} questions in {window:?}: {}",
        seen.text()
    );
    // The other side. A check that sent nothing would also pass a ceiling,
    // and a node that never asks never gives an address up.
    assert!(questions > 0, "the check sent nothing at all");
}

#[test]
fn a_node_with_no_default_route_says_so_and_keeps_the_address() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(5).expect("vip 5 is inside the reserved range");
    let gateway = gateway_of(node1);

    // A machine with nothing to ask. The check has to report that and stop,
    // rather than counting a gateway it never had (ADR-0030).
    node1
        .run_ok(&["ip", "route", "del", "default"])
        .expect("the default route should be removable");

    let running = start(node1, &binary, vip, 200, &[node2.address()], Some(200));
    let said = running.wait_for_stdout(r#""health":"no_gateway""#, PATIENCE);
    let took = running.wait_for_stdout(r#""event":"taken""#, PATIENCE);
    // Long enough for many checks at the interval given, so a node that
    // counted a missing gateway would have given the address up by now.
    thread::sleep(Duration::from_secs(3));
    let still_held = node1.has_address(vip).expect("node1 should be readable");
    let log = running.stdout();

    node1
        .run_ok(&[
            "ip", "route", "add", "default", "via", &gateway, "dev", "eth0",
        ])
        .expect("the default route should go back");
    stop_all(&cluster);

    said.expect("a node with no default route has to say so");
    took.expect("and still take the address");
    assert!(still_held, "it must keep the address it can still serve");
    assert!(
        !log.contains(r#""event":"lost""#),
        "nothing may be counted against a gateway that does not exist: {log}"
    );
    assert!(
        !log.contains(r#""event":"missed""#),
        "and no question may be counted as lost: {log}"
    );
}
