// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Moving a virtual address between two real nodes.
//!
//! Holding the role and holding the address are two different things, and the
//! second is the one a client can see. Every measurement here reads the
//! kernel's own answer, `ip addr` or `ip neigh` or a capture, rather than
//! anything this product returned about itself.
//!
//! # What this environment cannot measure
//!
//! A docker bridge floods a frame whose destination hardware address it
//! cannot place, so a wrongly addressed frame still reaches the new master
//! and is answered. What can be measured here is where a frame was
//! addressed; where it arrived is measured on a physical switch in T-069
//! (R-25, T-010).

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

/// How long a takeover needs, with room over the measured 1039 ms.
const TAKEOVER: Duration = Duration::from_secs(3);

/// The prefix length the lab network uses.
const PREFIX: u8 = 24;

/// The port the connection measurement uses.
const PORT: u16 = 9100;

/// One virtual router, as it is asked for.
struct Router<'a> {
    node: &'a Node,
    binary: &'a str,
    peers: Vec<Ipv4Addr>,
    addresses: Vec<String>,
    priority: u8,
    interface: String,
    /// Whether announcing is switched off, which is the negative control.
    silent: bool,
    /// Whether `CAP_NET_ADMIN` is taken away before it starts.
    without_net_admin: bool,
}

impl<'a> Router<'a> {
    /// A router on one node, carrying one address of the lab network.
    fn new(node: &'a Node, binary: &'a str, address: Ipv4Addr, priority: u8) -> Self {
        Self {
            node,
            binary,
            peers: Vec::new(),
            addresses: vec![format!("{address}/{PREFIX}")],
            priority,
            interface: "eth0".to_owned(),
            silent: false,
            without_net_admin: false,
        }
    }

    /// Adds a peer this router talks to.
    fn peer(mut self, peer: Ipv4Addr) -> Self {
        self.peers.push(peer);
        self
    }

    /// Adds another address it carries.
    fn also(mut self, address: &str) -> Self {
        self.addresses.push(address.to_owned());
        self
    }

    /// Puts the addresses on another interface.
    fn on(mut self, interface: &str) -> Self {
        self.interface = interface.to_owned();
        self
    }

    /// Switches the announcement off.
    fn silent(mut self) -> Self {
        self.silent = true;
        self
    }

    /// Takes away the capability an address change needs.
    fn without_net_admin(mut self) -> Self {
        self.without_net_admin = true;
        self
    }

    /// Starts it.
    fn start(self) -> Background {
        let mut argv: Vec<String> = Vec::new();
        if self.without_net_admin {
            // A real capability failure rather than a simulated one. The
            // netlink socket still opens, the raw socket still opens, and the
            // address change is the one thing the kernel refuses.
            argv.push("setpriv".to_owned());
            argv.push("--bounding-set=-net_admin".to_owned());
        }
        argv.push(self.binary.to_owned());
        argv.push("--address".to_owned());
        argv.push(self.node.address().to_string());
        argv.push("--interface".to_owned());
        argv.push(self.interface.clone());
        for address in &self.addresses {
            argv.push("--virtual-address".to_owned());
            argv.push(address.clone());
        }
        argv.push("--vrid".to_owned());
        argv.push("51".to_owned());
        argv.push("--priority".to_owned());
        argv.push(self.priority.to_string());
        argv.push("--interval-ms".to_owned());
        argv.push(INTERVAL_MS.to_string());
        for peer in &self.peers {
            argv.push("--peer".to_owned());
            argv.push(peer.to_string());
        }
        if self.silent {
            argv.push("--silent".to_owned());
        }

        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.node
            .spawn(&borrowed)
            .expect("the virtual router must start")
    }
}

/// Stops every router on a node and collects what one of them wrote.
fn stop(node: &Node, running: Background) -> String {
    node.kill_matching("ek-ek-vrrp-node")
        .expect("the virtual router should be killable");
    running
        .finish()
        .map(|output| output.stdout)
        .unwrap_or_default()
}

/// Waits until a node's output says it reached a state.
fn wait_for_state(running: &Background, state: &str) {
    running
        .wait_for_stdout(&format!(r#""to":"{state}""#), PATIENCE)
        .unwrap_or_else(|error| panic!("the node never reached {state}: {error}"));
}

/// Waits until a node says it took the addresses.
fn wait_for_addresses(running: &Background) {
    running
        .wait_for_stdout(r#""event":"taken""#, PATIENCE)
        .unwrap_or_else(|error| panic!("the node never took its addresses: {error}"));
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

/// What a node's neighbour table says holds an address.
///
/// Read without generating any traffic, because a lookup would resolve the
/// address again and report what the segment answers now rather than what the
/// announcement left behind (T-010).
fn cached_mac(node: &Node, address: Ipv4Addr) -> String {
    let shown = node
        .run_ok(&["ip", "neigh", "show", &address.to_string(), "dev", "eth0"])
        .expect("the neighbour table should be readable");
    let mut words = shown.split_whitespace();
    while let Some(word) = words.next() {
        if word == "lladdr" {
            return words.next().unwrap_or_default().to_owned();
        }
    }
    String::new()
}

#[test]
fn the_master_carries_the_address_and_a_backup_does_not() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(0).expect("vip 0 is inside the reserved range");

    let stronger = Router::new(node1, &binary, vip, 200)
        .peer(node2.address())
        .start();
    let weaker = Router::new(node2, &binary, vip, 150)
        .peer(node1.address())
        .start();

    wait_for_state(&stronger, "master");
    wait_for_addresses(&stronger);
    thread::sleep(Duration::from_millis(500));

    // Read out of `ip addr`, which is the kernel's own answer. What this
    // product believes about itself is not evidence that the address moved.
    let on_master = node1.has_address(vip).expect("node1 should be readable");
    let on_backup = node2.has_address(vip).expect("node2 should be readable");

    stop(node1, stronger);
    stop(node2, weaker);

    assert!(on_master, "the master must carry the address");
    // The other side. An implementation that put the address on every node
    // would pass the first half and give the segment two answers.
    assert!(!on_backup, "a backup must carry none");
}

#[test]
fn losing_the_role_takes_the_address_off() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(1).expect("vip 1 is inside the reserved range");

    // The weaker node starts alone, so it takes the role and the address.
    let weaker = Router::new(node2, &binary, vip, 150)
        .peer(node1.address())
        .start();
    wait_for_state(&weaker, "master");
    wait_for_addresses(&weaker);
    let held_before = node2.has_address(vip).expect("node2 should be readable");

    // Then the stronger one arrives and takes both.
    let stronger = Router::new(node1, &binary, vip, 200)
        .peer(node2.address())
        .start();
    weaker
        .wait_for_stdout(r#""to":"backup","reason":"stronger_peer""#, PATIENCE)
        .expect("the weaker node must give the role up");
    weaker
        .wait_for_stdout(r#""event":"dropped""#, PATIENCE)
        .expect("and say it let the address go");
    thread::sleep(Duration::from_millis(500));

    let held_after = node2.has_address(vip).expect("node2 should be readable");
    let taken_over = node1.has_address(vip).expect("node1 should be readable");

    stop(node1, stronger);
    stop(node2, weaker);

    assert!(held_before, "it has to hold the address before it loses it");
    assert!(!held_after, "and let it go when the role went");
    assert!(taken_over, "while the new master picked it up");
}

#[test]
fn the_announcement_moves_the_cache_and_without_it_the_cache_does_not() {
    // The measurement R-03 exists for. The address moving is not the
    // failover: every other machine on the segment keeps the old hardware
    // address in its cache and keeps sending frames there.
    //
    // The negative control is the whole point. Without it there is no way to
    // tell an announcement that moved a cache from a cache that was going to
    // name the new node anyway (T-010).
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let node3 = cluster.node("node3").expect("node3 exists");
    let vip = cluster.vip(2).expect("vip 2 is inside the reserved range");
    let first_mac = node1.mac().expect("node1 has a hardware address");
    let second_mac = node2.mac().expect("node2 has a hardware address");

    let announced = cache_after_failover(&cluster, &binary, vip, false);
    let silent = cache_after_failover(&cluster, &binary, vip, true);

    assert_eq!(
        announced, second_mac,
        "with the announcement the third node has to name the new master"
    );
    assert_eq!(
        silent, first_mac,
        "without it the cache keeps naming the node that died"
    );
    assert_ne!(
        announced, silent,
        "the two runs must differ, or the measurement is reading something else"
    );
    let _ = node3;
}

/// Runs one failover and returns what a third node's cache names afterwards.
fn cache_after_failover(cluster: &Cluster, binary: &str, vip: Ipv4Addr, silent: bool) -> String {
    cluster.reset().expect("each run starts clean");
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let node3 = cluster.node("node3").expect("node3 exists");

    let stronger = Router::new(node1, binary, vip, 200)
        .peer(node2.address())
        .start();
    let mut weaker = Router::new(node2, binary, vip, 150).peer(node1.address());
    if silent {
        weaker = weaker.silent();
    }
    let weaker = weaker.start();

    wait_for_state(&stronger, "master");
    wait_for_addresses(&stronger);
    wait_for_state(&weaker, "backup");

    // The third node learns who holds the address the ordinary way.
    assert!(
        node3.can_reach(vip).expect("node3 should be able to try"),
        "the address must answer before the failover"
    );
    assert_eq!(
        cached_mac(node3, vip),
        node1.mac().expect("node1 has a hardware address"),
        "the cache has to name the first master before anything moves"
    );

    // Killed rather than stopped, which is what a failure looks like. The
    // dead node keeps the address on its interface, so the cache is the only
    // thing steering traffic (T-010).
    node1
        .kill_matching("ek-ek-vrrp-node")
        .expect("node1's router should be killable");
    wait_for_state(&weaker, "master");
    thread::sleep(TAKEOVER);

    let named = cached_mac(node3, vip);
    let _ = stronger.finish();
    stop(node2, weaker);
    named
}

#[test]
fn the_move_is_announced_five_times_in_both_forms() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(3).expect("vip 3 is inside the reserved range");

    // Watched from another node, so what is counted is what reached the
    // segment rather than what was handed to a socket.
    let capture = Capture::start(
        node2,
        &format!("arp host {vip}"),
        40,
        Duration::from_secs(10),
    )
    .expect("capture should start");

    let router = Router::new(node1, &binary, vip, 200)
        .peer(node2.address())
        .start();
    wait_for_state(&router, "master");
    thread::sleep(Duration::from_secs(2));

    let seen = capture.finish().expect("capture should finish");
    stop(node1, router);

    // A gratuitous request asks about the address it is also answering for,
    // which is what tcpdump prints as "who-has X tell X".
    let requests = seen.count(&format!("Request who-has {vip} tell {vip}"));
    let replies = seen.count(&format!("Reply {vip} is-at"));

    assert!(
        requests >= 3,
        "at least three announcements, and {requests} requests were seen:\n{}",
        seen.text()
    );
    assert!(
        replies >= 3,
        "at least three announcements, and {replies} replies were seen:\n{}",
        seen.text()
    );
    // Five rounds of both forms. One lost frame is a failover nobody sees,
    // and nothing retries it.
    assert_eq!(requests, 5, "five rounds:\n{}", seen.text());
    assert_eq!(replies, 5, "five rounds:\n{}", seen.text());
}

#[test]
fn a_ping_after_a_failover_is_addressed_to_the_new_master() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let node3 = cluster.node("node3").expect("node3 exists");
    let vip = cluster.vip(4).expect("vip 4 is inside the reserved range");
    let second_mac = node2.mac().expect("node2 has a hardware address");

    let stronger = Router::new(node1, &binary, vip, 200)
        .peer(node2.address())
        .start();
    let weaker = Router::new(node2, &binary, vip, 150)
        .peer(node1.address())
        .start();
    wait_for_state(&stronger, "master");
    wait_for_addresses(&stronger);
    assert!(
        node3.can_reach(vip).expect("node3 should be able to try"),
        "the address answers before the failover"
    );

    node1
        .kill_matching("ek-ek-vrrp-node")
        .expect("node1's router should be killable");
    wait_for_state(&weaker, "master");
    thread::sleep(TAKEOVER);

    // Captured on the node that sends, so what is read is the address the
    // frame was given rather than what any bridge did with it afterwards.
    let capture = Capture::start(
        node3,
        &format!("icmp and host {vip}"),
        4,
        Duration::from_secs(8),
    )
    .expect("capture should start");
    let answered = node3.can_reach(vip).expect("node3 should be able to try");
    let seen = capture.finish().expect("capture should finish");

    let _ = stronger.finish();
    stop(node2, weaker);

    assert!(answered, "the address must still answer after the failover");
    seen.expect_contains(&format!("{second_mac} >"))
        .or_else(|_| seen.expect_contains(&format!("> {second_mac}")))
        .unwrap_or_else(|error| {
            panic!("the echo request must be addressed to the new master: {error}")
        });
}

#[test]
fn a_new_connection_after_a_failover_reaches_the_new_master() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let node3 = cluster.node("node3").expect("node3 exists");
    let vip = cluster.vip(5).expect("vip 5 is inside the reserved range");

    let stronger = Router::new(node1, &binary, vip, 200)
        .peer(node2.address())
        .start();
    let weaker = Router::new(node2, &binary, vip, 150)
        .peer(node1.address())
        .start();
    wait_for_state(&stronger, "master");
    wait_for_addresses(&stronger);
    assert!(node3.can_reach(vip).expect("node3 should be able to try"));

    node1
        .kill_matching("ek-ek-vrrp-node")
        .expect("node1's router should be killable");
    wait_for_state(&weaker, "master");
    wait_for_addresses(&weaker);
    thread::sleep(TAKEOVER);

    // The listener runs on the node that took over and answers with its own
    // name, so what identifies the answering node is the payload rather than
    // anything about the connection.
    let listener = node2
        .spawn(&[
            "python3",
            "-c",
            &format!(
                "import socket\n\
                 s=socket.socket()\n\
                 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
                 s.bind(('{vip}',{PORT}))\n\
                 s.listen(1)\n\
                 print('listening',flush=True)\n\
                 c,_=s.accept()\n\
                 c.sendall(b'node2')\n\
                 c.close()\n"
            ),
        ])
        .expect("the listener should start");
    listener
        .wait_for_stdout("listening", Duration::from_secs(10))
        .expect("the listener must bind the address");

    let answered = node3
        .run_ok(&[
            "python3",
            "-c",
            &format!(
                "import socket\n\
                 s=socket.create_connection(('{vip}',{PORT}),5)\n\
                 print(s.recv(16).decode())\n"
            ),
        ])
        .expect("the connection should be made");

    let _ = listener.finish();
    let _ = stronger.finish();
    stop(node2, weaker);

    assert_eq!(
        answered.trim(),
        "node2",
        "the connection must reach the node that took over"
    );
}

#[test]
fn a_node_that_starts_up_clears_an_address_left_behind() {
    // A killed process cannot clean up, so the address stays on its
    // interface. Nothing records how far it got, which is why the cleanup
    // asks for an end state rather than undoing what it did (T-010).
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(6).expect("vip 6 is inside the reserved range");

    let first = Router::new(node1, &binary, vip, 200)
        .peer(node2.address())
        .start();
    wait_for_state(&first, "master");
    wait_for_addresses(&first);

    node1
        .kill_matching("ek-ek-vrrp-node")
        .expect("node1's router should be killable");
    let _ = first.finish();
    thread::sleep(Duration::from_millis(500));

    // Without this the rest of the measurement would pass against a node
    // that never had the address in the first place.
    let left_behind = node1.has_address(vip).expect("node1 should be readable");

    // A stronger node takes the role, so the one that comes back stays a
    // backup and has no reason to add the address again.
    let stronger = Router::new(node2, &binary, vip, 250)
        .peer(node1.address())
        .start();
    wait_for_state(&stronger, "master");
    wait_for_addresses(&stronger);

    let restarted = Router::new(node1, &binary, vip, 100)
        .peer(node2.address())
        .start();
    restarted
        .wait_for_stdout(r#""event":"dropped""#, PATIENCE)
        .expect("a node that starts up says what it cleared");
    thread::sleep(Duration::from_millis(500));

    let after_restart = node1.has_address(vip).expect("node1 should be readable");
    let on_master = node2.has_address(vip).expect("node2 should be readable");

    stop(node1, restarted);
    stop(node2, stronger);

    assert!(left_behind, "a killed process leaves its address behind");
    assert!(!after_restart, "and starting up again clears it");
    assert!(on_master, "while the node that holds the role keeps it");
}

#[test]
fn a_node_with_nothing_to_clear_says_so_rather_than_reporting_a_failure() {
    // The other side of the cleanup. Every node clears at startup, and almost
    // every one of them has nothing to clear, so the kernel answers "that
    // address is not on this interface". Reading that as a fault would put a
    // failure in the record of every ordinary start.
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(7).expect("vip 7 is inside the reserved range");

    // Nothing to clear: the reset above took every address in the range off
    // every node.
    assert!(
        !node1.has_address(vip).expect("node1 should be readable"),
        "the measurement needs a node that is carrying nothing"
    );

    let router = Router::new(node1, &binary, vip, 150)
        .peer(node2.address())
        .start();
    router
        .wait_for_stdout(r#""event":"dropped""#, PATIENCE)
        .expect("a node that starts up says what it cleared");
    thread::sleep(Duration::from_millis(500));

    let written = router.stdout();
    stop(node1, router);

    assert!(
        !written.contains(r#""event":"drop_failed""#),
        "an address that was never there is not a failure:\n{written}"
    );
}

#[test]
fn a_node_that_cannot_take_the_address_stands_down_rather_than_holding_the_role() {
    // The worst state this product has. A master without its address answers
    // nothing, and its advertisements stop every other node from answering
    // either, so the whole cluster goes quiet without anything reporting a
    // fault.
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(7).expect("vip 7 is inside the reserved range");

    // Watched from another node. Announcing before the address is on the
    // interface would teach the segment that this node answers for something
    // it never got, and every frame sent there would go nowhere (T-010).
    let capture = Capture::start(
        node2,
        &format!("arp host {vip}"),
        10,
        Duration::from_secs(8),
    )
    .expect("capture should start");

    // A real refusal from the kernel: the capability an address change needs
    // is taken away, and everything else about the process is unchanged.
    let crippled = Router::new(node1, &binary, vip, 255)
        .peer(node2.address())
        .without_net_admin()
        .start();
    crippled
        .wait_for_stdout(r#""event":"take_failed""#, PATIENCE)
        .expect("the refusal must be written down");
    crippled
        .wait_for_stdout(r#""reason":"address_refused""#, PATIENCE)
        .expect("and the node must stand down");
    thread::sleep(Duration::from_secs(2));

    let seen = capture.finish().expect("capture should finish");
    let written = crippled.stdout();
    let held = node1.has_address(vip).expect("node1 should be readable");
    stop(node1, crippled);

    assert_eq!(
        seen.packets(),
        0,
        "a node that could not take the address must not announce it:\n{}",
        seen.text()
    );

    // Read out of the bytes the process wrote, parsed as JSON, rather than
    // out of a formatted string a test could match by accident.
    let failure = json_line(&written, r#""event":"take_failed""#)
        .expect("the failure must be one JSON object on a line of its own");
    assert_eq!(failure["kind"], "vip");
    assert!(
        failure["error"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("permitted"),
        "the record must carry what the kernel said, and it says {:?}",
        failure["error"]
    );

    let standing_down = json_line(&written, r#""reason":"address_refused""#)
        .expect("standing down must be one JSON object too");
    assert_eq!(standing_down["kind"], "vrrp");
    assert_eq!(standing_down["from"], "master");
    assert_eq!(standing_down["to"], "backup");

    assert!(!held, "and it must not be carrying the address");
    // The other side: the last state it reported is not master. A node that
    // wrote the record and stayed master would pass everything above.
    let last_state = written
        .lines()
        .filter(|line| line.contains(r#""kind":"vrrp""#))
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .next_back()
        .expect("it reported at least one state");
    assert_eq!(
        last_state["to"], "backup",
        "the node must not still think it holds the role"
    );
}

#[test]
fn a_node_that_can_take_the_address_stays_master() {
    // The other side of the measurement above. A node that stood down
    // whatever happened would pass it and never serve anything.
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(8).expect("vip 8 is inside the reserved range");

    let router = Router::new(node1, &binary, vip, 255)
        .peer(node2.address())
        .start();
    wait_for_state(&router, "master");
    wait_for_addresses(&router);
    thread::sleep(Duration::from_secs(2));

    let written = router.stdout();
    let held = node1.has_address(vip).expect("node1 should be readable");
    stop(node1, router);

    assert!(held, "the address must be on the interface");
    assert!(
        !written.contains(r#""event":"take_failed""#),
        "nothing was refused:\n{written}"
    );
    assert!(
        !written.contains(r#""reason":"address_refused""#),
        "so the node had no reason to stand down:\n{written}"
    );

    let taken = json_line(&written, r#""event":"taken""#)
        .expect("taking the addresses is written down too");
    assert_eq!(taken["kind"], "vip");
    assert_eq!(
        taken["addresses"][0],
        format!("{vip}/{PREFIX}"),
        "and the record names what it took"
    );
}

#[test]
fn an_ipv6_address_is_announced_with_a_neighbor_advertisement() {
    // The lab network carries no IPv6, so this runs on an interface of its
    // own. What is measured is the frame the product builds, which is the
    // same frame whatever interface it leaves from.
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster.vip(9).expect("vip 9 is inside the reserved range");
    let six = "fd00:ecec::100";

    node1
        .shell("ip link del lab0 2>/dev/null; ip link add lab0 type dummy && ip link set lab0 up")
        .expect("the extra interface should be creatable");

    let capture = Capture::on(node1, "lab0", "icmp6", 6, Duration::from_secs(10))
        .expect("capture should start");

    let router = Router::new(node1, &binary, vip, 255)
        .peer(node2.address())
        .also(&format!("{six}/64"))
        .on("lab0")
        .start();
    wait_for_state(&router, "master");
    wait_for_addresses(&router);
    thread::sleep(Duration::from_secs(2));

    let seen = capture.finish().expect("capture should finish");
    let held = node1
        .run_ok(&["ip", "-6", "addr", "show", "dev", "lab0"])
        .expect("lab0 should be readable");
    stop(node1, router);
    let _ = node1.shell("ip link del lab0");

    assert!(
        held.contains(six),
        "the IPv6 address must be on the interface:\n{held}"
    );
    // tcpdump reads the bytes and says what it made of them, checksum
    // included. A wrong one would show up here and nowhere else.
    seen.expect_contains("ICMP6, neighbor advertisement")
        .expect("an unsolicited neighbor advertisement must go out");
    seen.expect_contains(&format!("tgt is {six}"))
        .expect("naming the address that moved");
    assert!(
        !seen.text().contains("bad") && !seen.text().contains("invalid"),
        "tcpdump complained about the frame:\n{}",
        seen.text()
    );
}

#[test]
fn an_address_goes_only_on_the_interface_it_was_told_to() {
    let (cluster, binary) = clean();
    let node1 = cluster.node("node1").expect("node1 exists");
    let node2 = cluster.node("node2").expect("node2 exists");
    let vip = cluster
        .vip(10)
        .expect("vip 10 is inside the reserved range");

    node1
        .shell("ip link del lab0 2>/dev/null; ip link add lab0 type dummy && ip link set lab0 up")
        .expect("the extra interface should be creatable");
    let before = node1
        .run_ok(&["ip", "-4", "addr", "show", "dev", "eth0"])
        .expect("eth0 should be readable");
    let routes_before = node1
        .run_ok(&["ip", "-4", "route", "show", "dev", "eth0"])
        .expect("the routes should be readable");

    let router = Router::new(node1, &binary, vip, 255)
        .peer(node2.address())
        .on("lab0")
        .start();
    wait_for_state(&router, "master");
    wait_for_addresses(&router);
    thread::sleep(Duration::from_millis(500));

    let on_target = node1
        .run_ok(&["ip", "-4", "addr", "show", "dev", "lab0"])
        .expect("lab0 should be readable");
    let after = node1
        .run_ok(&["ip", "-4", "addr", "show", "dev", "eth0"])
        .expect("eth0 should be readable");
    let routes_after = node1
        .run_ok(&["ip", "-4", "route", "show", "dev", "eth0"])
        .expect("the routes should be readable");

    stop(node1, router);
    let _ = node1.shell("ip link del lab0");

    assert!(
        on_target.contains(&vip.to_string()),
        "the address must be on the interface it was told to use:\n{on_target}"
    );
    // The other side. An implementation that ignored the interface would put
    // the address on whichever one the kernel picked and pass the half above.
    assert!(
        !after.contains(&vip.to_string()),
        "and nowhere else:\n{after}"
    );
    assert_eq!(
        before.trim(),
        after.trim(),
        "the rest of the machine's addressing must be untouched"
    );
    assert_eq!(
        routes_before.trim(),
        routes_after.trim(),
        "and so must its routes"
    );
}

/// The first line holding the text, read as JSON.
///
/// Parsed rather than matched, because a record is a JSON object and a test
/// that matched on text would pass against a line that only looked like one.
fn json_line(output: &str, needle: &str) -> Option<serde_json::Value> {
    output
        .lines()
        .filter(|line| line.contains(needle))
        .find_map(|line| serde_json::from_str(line).ok())
}
