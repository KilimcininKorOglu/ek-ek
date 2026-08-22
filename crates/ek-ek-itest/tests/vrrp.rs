// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! VRRP between two real nodes, over real packets.
//!
//! The state machine is measured on its own in `ek-ek-vrrp`, where time is an
//! input and every deadline can be stood either side of. Nothing there can
//! see a checksum, a TTL or an IP protocol number, and a packet our own code
//! is happy with is worth nothing if no other implementation accepts it. That
//! is what these measurements are for.
//!
//! `tcpdump` is the independent reader. It parses the same bytes and prints
//! what it made of them, so a packet that is wrong shows up as a packet
//! `tcpdump` will not call a VRRPv3 advertisement (T-010).

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use ek_ek_itest::{Background, Capture, Cluster, Node};

/// The advertisement interval ADR-0029 makes the default.
const INTERVAL_MS: u64 = 300;

/// How long a node is given to reach a state.
const PATIENCE: Duration = Duration::from_secs(20);

/// The virtual router these measurements use.
const VRID: &str = "51";

/// Starts one virtual router on a node.
fn start(
    node: &Node,
    binary: &str,
    peers: &[Ipv4Addr],
    virtual_address: Ipv4Addr,
    priority: u8,
    preempt: bool,
) -> Background {
    let address = node.address().to_string();
    let priority = priority.to_string();
    let interval = INTERVAL_MS.to_string();

    let mut argv: Vec<String> = vec![
        binary.to_owned(),
        "--address".to_owned(),
        address,
        "--interface".to_owned(),
        "eth0".to_owned(),
        "--virtual-address".to_owned(),
        format!("{virtual_address}/24"),
        "--vrid".to_owned(),
        VRID.to_owned(),
        "--priority".to_owned(),
        priority,
        "--interval-ms".to_owned(),
        interval,
    ];
    for peer in peers {
        argv.push("--peer".to_owned());
        argv.push(peer.to_string());
    }
    if !preempt {
        argv.push("--no-preempt".to_owned());
    }

    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    node.spawn(&borrowed)
        .expect("the virtual router must start")
}

/// Stops a virtual router and collects what it wrote.
///
/// The process runs until something ends it, so it has to be killed before
/// its output is collected. Waiting on it first would wait forever.
fn stop(node: &Node, running: Background) -> String {
    node.kill_matching("ek-ek-vrrp-node")
        .expect("the virtual router should be killable");
    running
        .finish()
        .map(|output| output.stdout)
        .unwrap_or_default()
}

/// The record a node writes when a stronger peer takes the role from it.
///
/// Matched on the reason as well as the state, because every node writes an
/// `initialize` to `backup` line the moment it starts. Matching the state
/// alone would find that one and report a takeover that never happened.
const GAVE_UP: &str = r#""to":"backup","reason":"stronger_peer""#;

/// Waits until a node's output says it reached a state.
fn wait_for_state(running: &Background, state: &str) {
    running
        .wait_for_stdout(&format!(r#""to":"{state}""#), PATIENCE)
        .unwrap_or_else(|error| {
            panic!("the node never reached {state}: {error}");
        });
}

/// A number out of the record a node wrote when it reached a state.
///
/// Read out of the line the process wrote rather than taken from the test's
/// own clock: the test runs outside the container, and its measurement would
/// include however long `docker exec` took.
fn field_at(output: &str, state: &str, name: &str) -> Option<u128> {
    output
        .lines()
        .filter(|line| line.contains(&format!(r#""to":"{state}""#)))
        .filter_map(|line| {
            let at = line.find(&format!(r#""{name}":"#))? + name.len() + 3;
            let rest = line.get(at..)?;
            let end = rest.find(',')?;
            rest.get(..end)?.parse().ok()
        })
        .next_back()
}

/// The moment a node reported reaching a state.
fn reached_at(output: &str, state: &str) -> Option<u128> {
    field_at(output, state, "ts")
}

#[test]
fn the_advertisement_on_the_wire_is_a_vrrpv3_advertisement() {
    let cluster = Cluster::start().expect("cluster should start");
    // The routers move real addresses now, so a run that failed halfway
    // would leave one on an interface and the next test would read it as
    // its own result.
    cluster.reset().expect("the cluster should start clean");
    let binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(1).expect("vip 1 is inside the reserved range");

    // Watched from the node that receives them, so what is captured is what
    // arrived rather than what was handed to the socket.
    // Verbose, because the addresses a packet carries and the TTL of the
    // header that carried it only appear when tcpdump is asked for them.
    let capture = Capture::verbose(node2, "proto 112", 6, Duration::from_secs(15))
        .expect("capture should start");

    let router = start(node1, &binary, &[node2.address()], vip, 200, true);
    wait_for_state(&router, "master");

    let seen = capture.finish().expect("capture should finish");
    stop(node1, router);

    // tcpdump reads the bytes and says what it made of them. It checks the
    // version 3 checksum, which covers a pseudo header our own code never
    // verifies on the way in, so a wrong one would show up here and nowhere
    // else (T-010).
    seen.expect_contains("VRRPv3, Advertisement")
        .expect("tcpdump must read the packet as a VRRPv3 advertisement");
    seen.expect_contains(&format!("vrid {VRID}"))
        .expect("the virtual router id must be readable");
    seen.expect_contains("prio 200")
        .expect("the priority must be readable");
    seen.expect_contains("intvl 30cs")
        .expect("300 ms is 30 centiseconds on the wire");
    seen.expect_contains(&format!("addrs: {vip}"))
        .expect("the virtual address must be in the packet");
    // RFC 5798 requires 255 and requires a receiver to drop anything lower.
    // It is what tells an advertisement from the local segment apart from one
    // that crossed a router.
    seen.expect_contains("ttl 255")
        .expect("an advertisement must be sent with a TTL of 255");
    assert!(
        !seen.text().contains("bad") && !seen.text().contains("invalid"),
        "tcpdump complained about the packet:\n{}",
        seen.text()
    );
}

#[test]
fn no_advertisement_reaches_the_multicast_group() {
    // The other side of the measurement above, and the reason unicast is not
    // optional: VRRPv3 has no authentication, so a group anyone can join is a
    // virtual router anyone can claim (R-02).
    let cluster = Cluster::start().expect("cluster should start");
    // The routers move real addresses now, so a run that failed halfway
    // would leave one on an interface and the next test would read it as
    // its own result.
    cluster.reset().expect("the cluster should start clean");
    let binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(2).expect("vip 2 is inside the reserved range");

    let group = Capture::start(node2, "host 224.0.0.18", 4, Duration::from_secs(8))
        .expect("capture should start");
    let unicast = Capture::start(
        node2,
        &format!("proto 112 and host {}", node1.address()),
        4,
        Duration::from_secs(8),
    )
    .expect("capture should start");

    let router = start(node1, &binary, &[node2.address()], vip, 200, true);
    wait_for_state(&router, "master");
    thread::sleep(Duration::from_secs(2));

    let to_group = group.finish().expect("capture should finish");
    let to_peer = unicast.finish().expect("capture should finish");
    stop(node1, router);

    assert_eq!(
        to_group.packets(),
        0,
        "not one packet may reach the group:\n{}",
        to_group.text()
    );
    assert!(
        to_peer.packets() > 0,
        "and the same run must really have sent advertisements:\n{}",
        to_peer.text()
    );
}

#[test]
fn the_stronger_node_takes_the_role_and_the_weaker_one_gives_it_up() {
    let cluster = Cluster::start().expect("cluster should start");
    // The routers move real addresses now, so a run that failed halfway
    // would leave one on an interface and the next test would read it as
    // its own result.
    cluster.reset().expect("the cluster should start clean");
    let binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(3).expect("vip 3 is inside the reserved range");

    // The weaker node first, so it claims the role and then has to give it up
    // when the stronger one arrives. Starting them together would measure a
    // cold start rather than a takeover.
    let weaker = start(node2, &binary, &[node1.address()], vip, 150, true);
    wait_for_state(&weaker, "master");

    let stronger = start(node1, &binary, &[node2.address()], vip, 200, true);
    wait_for_state(&stronger, "master");
    weaker
        .wait_for_stdout(GAVE_UP, PATIENCE)
        .expect("the weaker node must give the role up when it hears the stronger one");

    stop(node1, stronger);
    stop(node2, weaker);
}

#[test]
fn a_backup_takes_over_within_the_master_down_interval() {
    let cluster = Cluster::start().expect("cluster should start");
    // The routers move real addresses now, so a run that failed halfway
    // would leave one on an interface and the next test would read it as
    // its own result.
    cluster.reset().expect("the cluster should start clean");
    let binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(4).expect("vip 4 is inside the reserved range");

    let master = start(node1, &binary, &[node2.address()], vip, 200, true);
    wait_for_state(&master, "master");
    let backup = start(node2, &binary, &[node1.address()], vip, 150, true);
    wait_for_state(&backup, "backup");

    thread::sleep(Duration::from_secs(1));

    node1
        .kill_matching("ek-ek-vrrp-node")
        .expect("the master should be killable");

    backup
        .wait_for_stdout(r#""to":"master""#, PATIENCE)
        .expect("the backup must take the role");

    // Both moments come out of the same record, written by the same process
    // off the same clock: when it last acted on an advertisement, and when it
    // took the role. Timing the kill instead would fold in however long
    // `docker exec` took, which is not part of a failover (T-010).
    let output = backup.stdout();
    let took_over_at = reached_at(&output, "master").expect("the record carries a moment");
    let last_heard = field_at(&output, "master", "heard").expect("the record carries the last one");
    assert!(
        last_heard > 0,
        "the backup must really have been hearing the master:\n{output}"
    );

    let failover = took_over_at.saturating_sub(last_heard);

    // The theoretical value is RFC 5798's master down interval: three
    // intervals plus the skew. At 300 ms and priority 150 that is 1024 ms.
    // The spike measured 1031 to 1043 ms and set the allowance from there.
    let theoretical = 1_024_u128;
    println!(
        "failover measured at {failover} ms against a theoretical {theoretical} ms, \
         which is {} ms over",
        failover.saturating_sub(theoretical)
    );
    assert!(
        failover >= theoretical.saturating_sub(60),
        "a takeover faster than the interval means the master was not really \
         heard from; measured {failover} ms"
    );
    assert!(
        failover < 1_500,
        "the takeover has to stay under 1.5 seconds; measured {failover} ms"
    );

    stop(node1, master);
    stop(node2, backup);
}

#[test]
fn preempt_on_gives_the_role_back_and_preempt_off_does_not() {
    let cluster = Cluster::start().expect("cluster should start");
    // The routers move real addresses now, so a run that failed halfway
    // would leave one on an interface and the next test would read it as
    // its own result.
    cluster.reset().expect("the cluster should start clean");
    let binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");

    // With preempt on: the weaker node holds the role, the stronger one comes
    // back and takes it.
    let taken_back = {
        let vip = cluster.vip(5).expect("vip 5 is inside the reserved range");
        let weaker = start(node2, &binary, &[node1.address()], vip, 150, true);
        wait_for_state(&weaker, "master");
        let stronger = start(node1, &binary, &[node2.address()], vip, 200, true);
        wait_for_state(&stronger, "master");

        let gave_up = weaker.wait_for_stdout(GAVE_UP, PATIENCE).is_ok();
        stop(node1, stronger);
        stop(node2, weaker);
        gave_up
    };

    // With preempt off: the same arrangement, and the role stays where it is.
    let kept = {
        let vip = cluster.vip(6).expect("vip 6 is inside the reserved range");
        let weaker = start(node2, &binary, &[node1.address()], vip, 150, false);
        wait_for_state(&weaker, "master");
        // The stronger node also runs with preempt off, which is the setting
        // that decides whether it waits for a weaker master.
        let stronger = start(node1, &binary, &[node2.address()], vip, 200, false);
        thread::sleep(Duration::from_secs(4));

        let stayed_backup = !stronger.stdout().contains(r#""to":"master""#);
        let still_master = !weaker.stdout().contains(GAVE_UP);
        stop(node1, stronger);
        stop(node2, weaker);
        stayed_backup && still_master
    };

    assert!(
        taken_back,
        "with preempt on the stronger node takes the role"
    );
    assert!(kept, "with preempt off the role stays where it is");
}

#[test]
fn an_advertisement_from_outside_the_peer_list_moves_nothing() {
    // The only protection VRRPv3 offers, because it has no authentication at
    // all. A node that acted on this would hand its virtual router to anyone
    // on the segment (R-02).
    let cluster = Cluster::start().expect("cluster should start");
    // The routers move real addresses now, so a run that failed halfway
    // would leave one on an interface and the next test would read it as
    // its own result.
    cluster.reset().expect("the cluster should start clean");
    let binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let node3 = cluster.node("node3").expect("node3 exists");
    let vip = cluster.vip(7).expect("vip 7 is inside the reserved range");

    // node1 knows only node2. node3 is a stranger.
    let router = start(node1, &binary, &[node2.address()], vip, 150, true);
    wait_for_state(&router, "master");

    // The stranger claims the same router at the highest priority there is.
    let stranger = start(node3, &binary, &[node1.address()], vip, 255, true);
    wait_for_state(&stranger, "master");
    thread::sleep(Duration::from_secs(3));

    assert!(
        !router.stdout().contains(GAVE_UP),
        "a stranger must not take the role:\n{}",
        router.stdout()
    );

    stop(node3, stranger);

    // And the same node does give the role up to a peer it knows, so the
    // measurement above is not passing because nothing can move it.
    let known = start(node2, &binary, &[node1.address()], vip, 255, true);
    wait_for_state(&known, "master");
    router
        .wait_for_stdout(GAVE_UP, PATIENCE)
        .expect("a peer in the list must be acted on");
    stop(node2, known);
    stop(node1, router);
}

#[test]
fn a_cold_start_settles_on_the_strongest_node() {
    // Nobody advertises until somebody is master, so on a cold start each
    // node counts from its own beginning. A short double master is possible
    // and closes on the first advertisement; what must not happen is the
    // cluster settling anywhere but on the strongest node (T-010).
    let cluster = Cluster::start().expect("cluster should start");
    // The routers move real addresses now, so a run that failed halfway
    // would leave one on an interface and the next test would read it as
    // its own result.
    cluster.reset().expect("the cluster should start clean");
    let binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(8).expect("vip 8 is inside the reserved range");

    let strong = start(node1, &binary, &[node2.address()], vip, 200, true);
    let weak = start(node2, &binary, &[node1.address()], vip, 150, true);

    wait_for_state(&strong, "master");
    thread::sleep(Duration::from_secs(3));

    assert!(
        !strong.stdout().contains(GAVE_UP),
        "the strongest node must keep the role:\n{}",
        strong.stdout()
    );

    // If the weaker node did claim it first, the window it held has to be
    // shorter than one advertisement interval.
    let weak_output = weak.stdout();
    if let (Some(claimed), Some(gave_up)) = (
        reached_at(&weak_output, "master"),
        reached_at(&weak_output, "backup"),
    ) && gave_up > claimed
    {
        let window = gave_up - claimed;
        println!("the weaker node held the role for {window} ms");
        assert!(
            window < u128::from(INTERVAL_MS),
            "a double master must close within one advertisement interval; it lasted {window} ms"
        );
    }

    stop(node1, strong);
    stop(node2, weak);
}
