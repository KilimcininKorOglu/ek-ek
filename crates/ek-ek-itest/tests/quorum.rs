// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Losing a quorum, measured where the traffic actually runs.
//!
//! ADR-0004 promises that a Raft quorum loss does not touch the traffic path.
//! Nothing inside one process can measure that promise: consensus and the
//! traffic path are two processes, and a measurement that runs only one of
//! them is measuring half of the claim. Here all of it runs at once. Three
//! nodes carry a real cluster, one of them carries the traffic path, and two
//! of the three containers are stopped in the middle of a load run.
//!
//! Every reading comes from outside the product: `ip addr` for the virtual
//! address, `curl` and `dig` for the traffic, the load generator's own count
//! for what was lost, and the node process's records for what consensus said.
//!
//! # Where the client traffic comes from
//!
//! From node1, at the virtual address node1 holds. The other two containers
//! are gone, which is what "two nodes stopped" has to mean, so there is no
//! third machine left to send from. The listener socket, the routing and the
//! backend connections are all real: the backends are separate containers, so
//! the backend half of every request crosses the lab network.
//!
//! # What the consensus half is measured against
//!
//! `ek-ek-raft/tests/quorum.rs` measures what one node's consensus does with
//! no quorum. This file measures what the rest of the node does while that is
//! true. Neither is enough on its own.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use ek_ek_itest::{Background, Cluster, Node};

/// Where the consensus store lives inside a node.
const STORE: &str = "/var/lib/ek-ek/quorum-store";
/// Where the peer certificates live inside a node.
const MATERIAL: &str = "/var/lib/ek-ek/quorum-material";
/// The configuration the node process watches and puts through consensus.
const APPLY: &str = "/var/lib/ek-ek/quorum-apply.json";
/// The configuration the traffic path is given, through the stand-in agent.
const SERVING: &str = "/var/lib/ek-ek/quorum-serving.json";
/// The socket the traffic path takes its configuration from.
const SOCKET: &str = "/var/lib/ek-ek/quorum-agent.sock";

/// Port the consensus members answer each other on, inside the lab network.
const PEER_PORT: u16 = 7391;
/// Port the HTTP frontend listens on.
const HTTP_PORT: u16 = 8080;
/// Port the raw TCP frontend listens on.
const RAW_PORT: u16 = 9090;
/// Port the UDP frontend listens on.
const DNS_PORT: u16 = 5353;

/// The virtual router number these measurements use.
const VRID: u8 = 61;
/// The advertisement interval ADR-0029 makes the default.
const INTERVAL_MS: u64 = 300;
/// The prefix length the lab network uses.
const PREFIX: u8 = 24;

/// The three nodes, in the order the cluster is built from.
const NAMES: [&str; 3] = ["node1", "node2", "node3"];

/// How long anything in the lab is given to reach a state.
const PATIENCE: Duration = Duration::from_secs(60);

/// How long the load generator runs, covering the whole outage.
const LOAD_WINDOW: Duration = Duration::from_secs(45);
/// Requests per second the load generator sends.
const RATE: u32 = 20;

/// How often the node process offers a refused document again (ADR-0085).
const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// The smallest document a store will start from.
const SEED: &str = r#"{"schema_version":1,"nodes":[],"vips":[],"frontends":[],"backends":[],"certificates":[],"dns_providers":[],"acme":null}"#;

/// Clears everything an earlier measurement left on a node.
fn clean(node: &Node) {
    node.kill_matching("/var/lib/ek-ek/ek-ek").ok();
    node.kill_matching("ek-ek-vrrp-node").ok();
    node.kill_matching("ek-ek-loadgen").ok();
    node.shell(&format!(
        "rm -rf {STORE} {MATERIAL} {APPLY} {SERVING} {SOCKET}"
    ))
    .expect("the node should be cleanable");
}

/// Writes a file inside a node.
fn put(node: &Node, path: &str, content: &str) {
    node.shell(&format!("cat > {path} <<'CONTENT'\n{content}\nCONTENT"))
        .expect("the file should be writable");
}

/// Creates the authority on the first node.
fn found(node: &Node, product: &str) {
    node.shell(&format!("mkdir -p {STORE}"))
        .expect("the directory should be creatable");
    put(node, "/var/lib/ek-ek/quorum-seed.json", SEED);
    node.run_ok(&[
        product,
        "cluster",
        "init",
        "--data-dir",
        STORE,
        "--config",
        "/var/lib/ek-ek/quorum-seed.json",
    ])
    .expect("the authority should be created");
}

/// Signs a certificate for one node and returns the directory it landed in.
fn enrol(node: &Node, product: &str, name: &str, address: Ipv4Addr) -> String {
    let out = format!("{MATERIAL}/{name}");
    node.run_ok(&[
        product,
        "cluster",
        "enroll",
        "--data-dir",
        STORE,
        "--node",
        name,
        "--address",
        &address.to_string(),
        "--out-dir",
        &out,
    ])
    .expect("the certificate should be signed");
    out
}

/// Copies one node's certificate, key and authority to another node.
///
/// The join flow could do this over the wire (T-038). Here it crosses by hand,
/// which is what ADR-0085 says a lab cluster is built with.
fn hand_over(from: &Node, to: &Node, directory: &str, name: &str) {
    to.shell(&format!("mkdir -p {directory}"))
        .expect("the directory should be creatable");
    for file in [
        format!("{name}.crt"),
        format!("{name}.key"),
        "cluster-ca.crt".to_owned(),
    ] {
        let content = from
            .run_ok(&["cat", &format!("{directory}/{file}")])
            .expect("the file should be readable");
        put(to, &format!("{directory}/{file}"), content.trim_end());
    }
    to.shell(&format!("chmod 600 {directory}/{name}.key"))
        .expect("the key should be restrictable");
}

/// Starts one consensus member and waits until it says it is listening.
fn start_member(node: &Node, product: &str, initialise: Option<&str>) -> Background {
    let listen = format!("0.0.0.0:{PEER_PORT}");
    let material = format!("{MATERIAL}/{}", node.name());
    let mut argv: Vec<String> = vec![
        product.to_owned(),
        "cluster".to_owned(),
        "node".to_owned(),
        "--data-dir".to_owned(),
        STORE.to_owned(),
        "--node".to_owned(),
        node.name().to_owned(),
        "--material".to_owned(),
        material,
        "--listen".to_owned(),
        listen,
        "--apply".to_owned(),
        APPLY.to_owned(),
    ];
    if let Some(membership) = initialise {
        argv.push("--initialise".to_owned());
        argv.push(membership.to_owned());
    }

    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let member = node
        .spawn(&borrowed)
        .unwrap_or_else(|error| panic!("{} must start its member: {error}", node.name()));
    member
        .wait_for_stdout(r#""event":"listening""#, PATIENCE)
        .unwrap_or_else(|error| panic!("{} never opened its peer port: {error}", node.name()));
    member
}

/// The `name=address` list one node initialises the cluster with.
fn membership(cluster: &Cluster) -> String {
    NAMES
        .iter()
        .map(|name| {
            let node = cluster.node(name).expect("the node is in the cluster");
            format!("{name}={}:{PEER_PORT}", node.address())
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// How often a record appears in what a process has written so far.
fn counted(background: &Background, needle: &str) -> usize {
    background.stdout().matches(needle).count()
}

/// Waits until a record has appeared at least this many times.
///
/// Counting rather than looking for the text: a node that reports a quorum,
/// loses it and finds it again writes the same line twice, and `contains`
/// cannot tell the second one from the first.
fn wait_until(background: &Background, needle: &str, at_least: usize, what: &str) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if counted(background, needle) >= at_least {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "{what}: {needle} appeared {} time(s), not {at_least}\n{}",
        counted(background, needle),
        background.stdout()
    );
}

/// Starts one virtual router on a node.
fn start_router(
    node: &Node,
    binary: &str,
    address: Ipv4Addr,
    priority: u8,
    peers: &[Ipv4Addr],
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
        VRID.to_string(),
        "--priority".to_owned(),
        priority.to_string(),
        "--interval-ms".to_owned(),
        INTERVAL_MS.to_string(),
    ];
    for peer in peers {
        argv.push("--peer".to_owned());
        argv.push(peer.to_string());
    }
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    node.spawn(&borrowed)
        .unwrap_or_else(|error| panic!("{} must start its router: {error}", node.name()))
}

/// Waits until a node holds an address, read from the kernel.
fn wait_for_address(node: &Node, address: Ipv4Addr) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if node
            .has_address(address)
            .expect("the address list should be readable")
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{} never took {address}", node.name());
}

/// Waits until something accepts a connection on a port.
///
/// The traffic path is handed in so a failure carries what it said. A process
/// that refused its configuration and exited otherwise reads here as a port
/// that never opened, which sends the reader to the wrong place.
fn wait_for_port(node: &Node, address: Ipv4Addr, port: u16, said: &Background) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        let probe = node
            .shell(&format!(
                "python3 -c \"import socket; socket.create_connection(('{address}',{port}),1).close()\""
            ))
            .expect("the probe should run");
        if probe.ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!(
        "nothing ever listened on {address}:{port}\nstdout: {}\nstderr: {}",
        said.stdout(),
        said.stderr()
    );
}

/// The configuration the traffic path serves during these measurements.
///
/// Three frontends on one virtual address, one per transport the product
/// carries, and a pool of two web servers behind a health check. All of it
/// has to keep working while consensus cannot agree on anything.
fn serving(vip: Ipv4Addr, first: Ipv4Addr, second: Ipv4Addr, resolver: Ipv4Addr) -> String {
    format!(
        r#"{{
  "schema_version": 1,
  "nodes": [{{"id":"node1","address":"172.28.0.11","roles":["control_plane","data_plane"]}}],
  "vips": [{{"id":"vip-quorum","address":"{vip}","prefix_length":{PREFIX},"interface":"eth0","preferred_node":"node1"}}],
  "frontends": [
    {{"id":"web","vip":"vip-quorum","port":{HTTP_PORT},"transport":"tcp","application":"http","tls":null,"proxy_protocol":"disabled","routing_rules":[],"sni_rules":[],"default_backend":"pool","http2":"disabled","connect_timeout_seconds":5,"request_timeout_seconds":30,"idle_timeout_seconds":0,"drain_timeout_seconds":5,"udp_session_limit":0}},
    {{"id":"stream","vip":"vip-quorum","port":{RAW_PORT},"transport":"tcp","application":"raw","tls":null,"proxy_protocol":"disabled","routing_rules":[],"sni_rules":[],"default_backend":"first","http2":"disabled","connect_timeout_seconds":5,"request_timeout_seconds":30,"idle_timeout_seconds":0,"drain_timeout_seconds":5,"udp_session_limit":0}},
    {{"id":"names","vip":"vip-quorum","port":{DNS_PORT},"transport":"udp","application":"raw","tls":null,"proxy_protocol":"disabled","routing_rules":[],"sni_rules":[],"default_backend":"resolver","http2":"disabled","connect_timeout_seconds":5,"request_timeout_seconds":30,"idle_timeout_seconds":0,"drain_timeout_seconds":5,"udp_session_limit":0}}
  ],
  "backends": [
    {{"id":"pool","algorithm":"round_robin","members":[
      {{"id":"one","address":"{first}","port":80,"weight":1,"admin_state":"enabled"}},
      {{"id":"two","address":"{second}","port":80,"weight":1,"admin_state":"enabled"}}
    ],"health_check":{{"probe":{{"type":"http","path":"/healthz","expected_status":[200],"expected_body":null,"host_header":null}},"interval_ms":500,"timeout_ms":400,"healthy_threshold":1,"unhealthy_threshold":2}},"stickiness":{{"mode":"disabled"}},"connection_pooling":"disabled","connection_pool_size":0,"connection_lifetime_seconds":0}},
    {{"id":"first","algorithm":"round_robin","members":[
      {{"id":"one","address":"{first}","port":80,"weight":1,"admin_state":"enabled"}}
    ],"health_check":null,"stickiness":{{"mode":"disabled"}},"connection_pooling":"disabled","connection_pool_size":0,"connection_lifetime_seconds":0}},
    {{"id":"resolver","algorithm":"round_robin","members":[
      {{"id":"one","address":"{resolver}","port":53,"weight":1,"admin_state":"enabled"}}
    ],"health_check":null,"stickiness":{{"mode":"disabled"}},"connection_pooling":"disabled","connection_pool_size":0,"connection_lifetime_seconds":0}}
  ],
  "certificates": [],
  "dns_providers": [],
  "acme": null
}}"#
    )
    // One line. The agent hands the document to the traffic path inside a
    // line-delimited message, so a document with newlines in it arrives cut in
    // half.
    .lines()
    .map(str::trim)
    .collect()
}

/// A configuration document for consensus to agree on, with `count` nodes.
///
/// Nothing serves this: it is what a write puts through the log, and the
/// number of nodes in it is what a later read is checked against.
fn agreed(count: usize) -> String {
    let nodes: Vec<String> = (0..count)
        .map(|at| {
            format!(r#"{{"id":"written-{at}","address":"10.0.0.{at}","roles":["control_plane"]}}"#)
        })
        .collect();
    format!(
        r#"{{"schema_version":1,"nodes":[{}],"vips":[],"frontends":[],"backends":[],"certificates":[],"dns_providers":[],"acme":null}}"#,
        nodes.join(",")
    )
}

/// What `cluster status` says on a node, as a parsed record.
fn status(node: &Node, product: &str) -> serde_json::Value {
    let said = node
        .run_ok(&[product, "cluster", "status", "--data-dir", STORE])
        .expect("a node should be able to say what it holds");
    serde_json::from_str(said.trim())
        .unwrap_or_else(|error| panic!("{said} is not a record: {error}"))
}

/// Fetches one URL from inside a node and returns the body.
fn fetch(node: &Node, url: &str) -> String {
    node.run_ok(&["curl", "-fsS", "--max-time", "5", url])
        .unwrap_or_else(|error| panic!("{url} did not answer: {error}"))
}

/// A file on the host that decides whether a backend passes its health check.
///
/// The backends serve a directory the host owns, so a check can be made to
/// fail by removing a file rather than by stopping a container. That keeps the
/// failure inside the pool, which is what the health check is there for.
fn health_file(backend: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the repository root")
        .join("docker-data")
        .join(backend)
        .join("healthz")
}

/// Makes a backend answer its health check, or stop answering it.
fn healthy(backend: &str, well: bool) {
    let path = health_file(backend);
    if well {
        std::fs::write(&path, "ok\n").expect("the health file should be writable");
    } else if path.exists() {
        std::fs::remove_file(&path).expect("the health file should be removable");
    }
}

/// The three consensus members, and the cluster they were built on.
struct Cohort {
    members: Vec<Background>,
}

impl Cohort {
    /// One member by name.
    fn named(&self, name: &str) -> &Background {
        let at = NAMES
            .iter()
            .position(|held| *held == name)
            .unwrap_or_else(|| panic!("no member named {name}"));
        &self.members[at]
    }
}

/// Builds the authority, hands the certificates out and starts three members.
fn found_cluster(cluster: &Cluster, product: &str) -> Cohort {
    let first = cluster.node("node1").expect("node1 is in the cluster");
    found(first, product);
    for name in NAMES {
        let node = cluster.node(name).expect("the node is in the cluster");
        let directory = enrol(first, product, name, node.address());
        if name != "node1" {
            hand_over(first, node, &directory, name);
        }
    }

    let membership = membership(cluster);
    let members: Vec<Background> = NAMES
        .iter()
        .map(|name| {
            let node = cluster.node(name).expect("the node is in the cluster");
            // Only the first node writes the membership. Every other node is
            // told about the cluster by what it records (ADR-0085).
            let initialise = (*name == "node1").then_some(membership.as_str());
            start_member(node, product, initialise)
        })
        .collect();

    let cohort = Cohort { members };
    for name in NAMES {
        wait_until(
            cohort.named(name),
            r#""event":"quorum","reachable":true"#,
            1,
            &format!("{name} never reached a quorum"),
        );
    }
    cohort
}

#[test]
fn the_traffic_path_does_not_notice_a_lost_quorum() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let agent_binary = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-agent")
        .expect("the stand-in agent should build");
    let router_binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");
    let loadgen = cluster
        .install_binary("ek-ek-itest", "ek-ek-loadgen")
        .expect("the load generator should build");

    for name in NAMES {
        clean(cluster.node(name).expect("the node is in the cluster"));
    }
    healthy("backend1", true);
    healthy("backend2", true);

    let first = cluster.node("node1").expect("node1 is in the cluster");
    let vip = cluster.vip(0).expect("inside the reserved range");

    // Three real consensus members, so losing two of them is a real quorum
    // loss rather than a process that was told to report one.
    let cohort = found_cluster(&cluster, &product);

    // The virtual address, held through VRRP on all three nodes. node1 claims
    // it with the highest number, so it is the one holding it.
    let mut routers = Vec::new();
    for (at, name) in NAMES.iter().enumerate() {
        let node = cluster.node(name).expect("the node is in the cluster");
        let peers: Vec<Ipv4Addr> = NAMES
            .iter()
            .filter(|other| *other != name)
            .map(|other| {
                cluster
                    .node(other)
                    .expect("the node is in the cluster")
                    .address()
            })
            .collect();
        let priority = 200 - u8::try_from(at).expect("three nodes") * 50;
        routers.push(start_router(node, &router_binary, vip, priority, &peers));
    }
    wait_for_address(first, vip);

    // The traffic path, on the node that holds the address.
    put(
        first,
        SERVING,
        &serving(
            vip,
            cluster.backend_address("backend1").expect("backend1"),
            cluster.backend_address("backend2").expect("backend2"),
            cluster.bind_address(),
        ),
    );
    let agent = first
        .spawn(&[&agent_binary, "--socket", SOCKET, "--config", SERVING])
        .expect("the stand-in agent should start");
    agent
        .wait_for_stdout("listening on", PATIENCE)
        .expect("the stand-in agent should say it is listening");
    let data_plane = first
        .spawn(&[&product, "data-plane", "--agent-socket", SOCKET])
        .expect("the traffic path should start");
    wait_for_port(first, vip, HTTP_PORT, &data_plane);
    wait_for_port(first, vip, RAW_PORT, &data_plane);

    // Both members answer before anything is broken. Without this the health
    // check measurement below would prove nothing: a pool that only ever used
    // one member looks the same as one that removed the other.
    let mut before = std::collections::BTreeSet::new();
    for _ in 0..12 {
        before.insert(
            fetch(first, &format!("http://{vip}:{HTTP_PORT}/"))
                .trim()
                .to_owned(),
        );
    }
    assert_eq!(
        before.len(),
        2,
        "the pool did not use both members before the outage: {before:?}"
    );

    // The load runs across the whole outage and is read at the end. Started
    // before the nodes are stopped and finishing after they are back, so a
    // request dropped at any point in between is counted.
    let load = first
        .spawn(&[
            &loadgen,
            "--target",
            &format!("{vip}:{HTTP_PORT}"),
            "--rate",
            &RATE.to_string(),
            "--duration-ms",
            &LOAD_WINDOW.as_millis().to_string(),
        ])
        .expect("the load generator should start");

    // Two of three nodes go away. What is left cannot form a quorum.
    cluster.stop_node("node2").expect("node2 should stop");
    cluster.stop_node("node3").expect("node3 should stop");
    wait_until(
        cohort.named("node1"),
        r#""event":"quorum","reachable":false"#,
        1,
        "node1 never noticed the quorum was gone",
    );

    // HTTP still answers.
    let served = fetch(first, &format!("http://{vip}:{HTTP_PORT}/"));
    assert!(
        served.contains("backend"),
        "HTTP stopped with no quorum: {served}"
    );

    // Raw TCP still answers. The frontend forwards bytes it does not read, so
    // what comes back is the backend's own HTTP response.
    let streamed = fetch(first, &format!("http://{vip}:{RAW_PORT}/"));
    assert!(
        streamed.contains("backend1"),
        "TCP stopped with no quorum: {streamed}"
    );

    // UDP still answers. The name server behind the frontend is authoritative
    // for the lab zone, so the answer is one nothing in this product wrote.
    let resolved = first
        .run_ok(&[
            "dig",
            "+short",
            "+time=3",
            "+tries=1",
            &format!("@{vip}"),
            "-p",
            &DNS_PORT.to_string(),
            "node1.ek-ek.test",
            "A",
        ])
        .expect("the name server should answer through the frontend");
    assert_eq!(
        resolved.trim(),
        first.address().to_string(),
        "UDP stopped with no quorum"
    );

    // The virtual address is still on node1, read from the kernel. This is the
    // most direct reading of VRRP running without Raft: the two peers it was
    // advertising to are gone and consensus cannot agree on anything.
    assert!(
        first
            .has_address(vip)
            .expect("the address list should be readable"),
        "node1 gave up {vip} when it lost the quorum"
    );

    // And the health check still takes a member out. One backend stops
    // answering the probe while there is no quorum at all.
    healthy("backend2", false);
    let deadline = Instant::now() + PATIENCE;
    let mut only_first = false;
    while Instant::now() < deadline {
        let seen: std::collections::BTreeSet<String> = (0..12)
            .map(|_| {
                fetch(first, &format!("http://{vip}:{HTTP_PORT}/"))
                    .trim()
                    .to_owned()
            })
            .collect();
        if seen.len() == 1 && seen.contains("backend1") {
            only_first = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        only_first,
        "the unhealthy member stayed in the pool while there was no quorum"
    );

    // The nodes come back and consensus agrees again.
    cluster.start_node("node2").expect("node2 should come back");
    cluster.start_node("node3").expect("node3 should come back");
    let returned: Vec<Background> = ["node2", "node3"]
        .iter()
        .map(|name| {
            start_member(
                cluster.node(name).expect("the node is in the cluster"),
                &product,
                None,
            )
        })
        .collect();
    wait_until(
        cohort.named("node1"),
        r#""event":"quorum","reachable":true"#,
        2,
        "the quorum never came back",
    );

    // Nothing was lost, across the outage and the recovery together.
    let report = load.finish().expect("the load generator should finish");
    assert!(report.ok(), "the load generator failed: {}", report.stderr);
    let counted =
        ek_ek_itest::LoadReport::parse(&report.stdout).expect("the load report should be readable");
    assert!(
        counted.sent >= u64::from(RATE) * 20,
        "only {} request(s) went out across the outage",
        counted.sent
    );
    assert_eq!(
        counted.failed, 0,
        "{} of {} request(s) were lost while the quorum was gone: {:?}",
        counted.failed, counted.sent, counted.first_error
    );

    healthy("backend2", true);
    drop(returned);
    drop(routers);
    drop(data_plane);
    drop(agent);
    drop(cohort);
    for name in NAMES {
        clean(cluster.node(name).expect("the node is in the cluster"));
    }
}

#[test]
fn a_node_with_no_quorum_refuses_a_write_and_still_answers_what_it_holds() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");

    for name in NAMES {
        clean(cluster.node(name).expect("the node is in the cluster"));
    }
    let first = cluster.node("node1").expect("node1 is in the cluster");
    let cohort = found_cluster(&cluster, &product);

    // A configuration goes in while there is a quorum, so what a later read
    // returns is something that was actually agreed.
    put(first, APPLY, &agreed(2));
    wait_until(
        cohort.named("node1"),
        r#""event":"applied""#,
        1,
        "the first configuration never went in",
    );
    let before = status(first, &product);
    assert_eq!(before["nodes"], 2, "the write did not reach the state");

    cluster.stop_node("node2").expect("node2 should stop");
    cluster.stop_node("node3").expect("node3 should stop");
    wait_until(
        cohort.named("node1"),
        r#""event":"quorum","reachable":false"#,
        1,
        "node1 never noticed the quorum was gone",
    );

    // The record a screen would read. It names the reason rather than only
    // saying something is wrong, which is what an operator has to act on.
    let said = cohort.named("node1").stdout();
    assert!(
        said.contains(r#""event":"quorum","reachable":false,"reason":"raft.no_quorum""#),
        "the node did not name why it cannot reach a quorum:\n{said}"
    );

    // Reading still works, and answers with everything it held. A status
    // command that needed a quorum would fall silent at exactly this moment.
    let during = status(first, &product);
    assert_eq!(during["held"], true, "the node stopped answering");
    assert_eq!(during["nodes"], 2, "the node lost what it held");
    assert_eq!(during["authority"], true, "the authority went missing");
    assert_eq!(
        during["versions"], before["versions"],
        "the version history changed while nothing was written"
    );

    // A write is refused by name, and nothing about it is silently local.
    let refusals = counted(cohort.named("node1"), r#""event":"refused""#);
    put(first, APPLY, &agreed(5));
    wait_until(
        cohort.named("node1"),
        r#""event":"refused""#,
        refusals + 1,
        "the write with no quorum was not refused",
    );
    let refused = cohort.named("node1").stdout();
    assert!(
        refused.contains(r#""event":"refused","reason":"raft.no_quorum""#),
        "the refusal does not name the lost quorum:\n{refused}"
    );

    // Said once. The document is offered again every second until it goes in,
    // and a record for every attempt would bury everything that does change
    // (ADR-0085). Read after several intervals, so a second line would be
    // there by now if there was going to be one.
    let counted_once = counted(cohort.named("node1"), r#""event":"refused""#);
    std::thread::sleep(RETRY_INTERVAL * 4);
    assert_eq!(
        counted(cohort.named("node1"), r#""event":"refused""#),
        counted_once,
        "the same refusal was reported again:\n{}",
        cohort.named("node1").stdout()
    );
    let after = status(first, &product);
    assert_eq!(
        after["nodes"], 2,
        "a refused write reached the state anyway"
    );
    assert_eq!(
        after["versions"], before["versions"],
        "a refused write reached the version history"
    );

    // The nodes come back, and the document nobody touched since goes in on
    // its own. A refusal is a state of the cluster, not a verdict on the
    // document (ADR-0085).
    let applied = counted(cohort.named("node1"), r#""event":"applied""#);
    cluster.start_node("node2").expect("node2 should come back");
    cluster.start_node("node3").expect("node3 should come back");
    let returned: Vec<Background> = ["node2", "node3"]
        .iter()
        .map(|name| {
            start_member(
                cluster.node(name).expect("the node is in the cluster"),
                &product,
                None,
            )
        })
        .collect();
    wait_until(
        cohort.named("node1"),
        r#""event":"applied""#,
        applied + 1,
        "the refused configuration was never applied after the quorum returned",
    );

    let finally = status(first, &product);
    assert_eq!(
        finally["nodes"], 5,
        "the configuration written during the outage never reached the state"
    );
    // The authority the state already held travelled with the new document.
    // A write that replaced the whole state with the document alone would
    // leave the cluster unable to admit anybody (ADR-0082).
    assert_eq!(
        finally["authority"], true,
        "the authority went missing when the configuration went in"
    );

    // And every node holds it, so what came back is a cluster rather than one
    // node writing to itself.
    for name in ["node2", "node3"] {
        let node = cluster.node(name).expect("the node is in the cluster");
        let deadline = Instant::now() + PATIENCE;
        let mut agreed_here = false;
        while Instant::now() < deadline {
            if status(node, &product)["nodes"] == 5 {
                agreed_here = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        assert!(agreed_here, "{name} never received the write");
    }

    drop(returned);
    drop(cohort);
    for name in NAMES {
        clean(cluster.node(name).expect("the node is in the cluster"));
    }
}
