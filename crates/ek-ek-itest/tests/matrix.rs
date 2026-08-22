// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Three virtual addresses over three real nodes.
//!
//! The numbers are not written by hand here. The product's own `matrix`
//! command reads the configuration and says which node should hold which
//! address and what every node claims it with, and those numbers are what the
//! virtual routers are started with. So this measures the matrix and the
//! packets together: an assignment that only looked right on paper would put
//! two addresses on one node, and `ip addr` would say so.
//!
//! Every reading comes from the kernel, never from anything this product
//! reported about itself.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use ek_ek_itest::{Background, Cluster, Node};

/// The advertisement interval ADR-0029 makes the default.
const INTERVAL_MS: u64 = 300;

/// How long a node is given to reach a state.
const PATIENCE: Duration = Duration::from_secs(30);

/// The prefix length the lab network uses.
const PREFIX: u8 = 24;

/// One virtual router, as the product's own matrix described it.
struct Router {
    vip: String,
    address: Ipv4Addr,
    vrid: u8,
    /// Every node and what it claims this address with, strongest first.
    ranking: Vec<(String, u8)>,
}

impl Router {
    /// The node that should hold the address.
    fn holder(&self) -> &str {
        &self.ranking[0].0
    }

    /// What one node claims it with.
    fn priority(&self, node: &str) -> u8 {
        self.ranking
            .iter()
            .find(|(name, _)| name == node)
            .map(|(_, priority)| *priority)
            .unwrap_or_else(|| panic!("{node} has no place in {}", self.vip))
    }
}

/// A configuration document with three nodes and three addresses.
///
/// One address prefers each node, which is what an operator writes when they
/// want the cluster to carry its load on every node.
fn document(nodes: &[&Node], vips: &[(String, Ipv4Addr, String)]) -> String {
    let written_nodes: Vec<String> = nodes
        .iter()
        .map(|node| {
            format!(
                r#"{{"id":"{}","address":"{}","roles":["control_plane","data_plane"]}}"#,
                node.name(),
                node.address()
            )
        })
        .collect();
    let written_vips: Vec<String> = vips
        .iter()
        .map(|(id, address, preferred)| {
            format!(
                r#"{{"id":"{id}","address":"{address}","prefix_length":{PREFIX},"interface":"eth0","preferred_node":"{preferred}"}}"#
            )
        })
        .collect();

    format!(
        r#"{{"schema_version":1,"nodes":[{}],"vips":[{}],"frontends":[],"backends":[],"certificates":[],"dns_providers":[]}}"#,
        written_nodes.join(","),
        written_vips.join(",")
    )
}

/// The address one virtual address identity was given.
fn address_of(vip: &str, vips: &[(String, Ipv4Addr, String)]) -> Ipv4Addr {
    vips.iter()
        .find(|(id, _, _)| id == vip)
        .map(|(_, address, _)| *address)
        .unwrap_or_else(|| panic!("{vip} was never asked for"))
}

/// Asks the product what the matrix is.
///
/// Run inside a node rather than on the host, so the answer comes from the
/// binary the cluster actually carries.
fn ask(
    nodes: &[&Node],
    binary: &str,
    path: &str,
    vips: &[(String, Ipv4Addr, String)],
) -> Vec<Router> {
    let node = nodes[0];
    let document = document(nodes, vips);
    let written = node
        .shell(&format!("cat > {path} <<'JSON'\n{document}\nJSON"))
        .expect("the document should be writable");
    assert!(
        written.ok(),
        "the document was not written: {}",
        written.stderr
    );

    let answer = node
        .run_ok(&[binary, "matrix", "--config", path, "--json"])
        .expect("the matrix command should answer");
    let parsed: serde_json::Value = serde_json::from_str(&answer)
        .unwrap_or_else(|error| panic!("{answer} is not JSON: {error}"));

    parsed["routers"]
        .as_array()
        .expect("the answer carries a list of routers")
        .iter()
        .map(|router| Router {
            vip: router["vip"].as_str().expect("a name").to_owned(),
            address: address_of(router["vip"].as_str().expect("a name"), vips),
            vrid: u8::try_from(router["vrid"].as_u64().expect("a number")).expect("one byte"),
            ranking: router["ranking"]
                .as_array()
                .expect("a ranking")
                .iter()
                .map(|placement| {
                    (
                        placement["node"].as_str().expect("a name").to_owned(),
                        u8::try_from(placement["priority"].as_u64().expect("a number"))
                            .expect("one byte"),
                    )
                })
                .collect(),
        })
        .collect()
}

/// Starts one virtual router on one node with the numbers the matrix gave it.
fn start(node: &Node, binary: &str, router: &Router, peers: &[Ipv4Addr]) -> Background {
    let mut argv: Vec<String> = vec![
        binary.to_owned(),
        "--address".to_owned(),
        node.address().to_string(),
        "--interface".to_owned(),
        "eth0".to_owned(),
        "--virtual-address".to_owned(),
        format!("{}/{PREFIX}", router.address),
        "--vrid".to_owned(),
        router.vrid.to_string(),
        "--priority".to_owned(),
        router.priority(node.name()).to_string(),
        "--interval-ms".to_owned(),
        INTERVAL_MS.to_string(),
    ];
    for peer in peers {
        argv.push("--peer".to_owned());
        argv.push(peer.to_string());
    }

    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    node.spawn(&borrowed)
        .unwrap_or_else(|error| panic!("virtual router {} must start: {error}", router.vrid))
}

/// Stops every virtual router on every node.
fn stop_all(cluster: &Cluster) {
    for node in cluster.nodes() {
        let _ = node.kill_matching("ek-ek-vrrp-node");
    }
}

#[test]
fn three_addresses_land_one_on_each_node_and_move_to_the_second_in_the_order() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let agent = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let router_binary = cluster
        .install_binary("ek-ek-vrrp", "ek-ek-vrrp-node")
        .expect("the virtual router binary should build");

    let nodes: Vec<&Node> = cluster.nodes().iter().collect();
    assert_eq!(nodes.len(), 3, "this measurement needs three nodes");

    // One address per node, each preferring a different one.
    let wanted: Vec<(String, Ipv4Addr, String)> = (0..3_u8)
        .map(|at| {
            (
                format!("vip-{at}"),
                cluster.vip(at).expect("inside the reserved range"),
                nodes[usize::from(at)].name().to_owned(),
            )
        })
        .collect();
    let routers = ask(&nodes, &agent, "/tmp/ek-ek-matrix.json", &wanted);

    assert_eq!(routers.len(), 3, "one virtual router per address");
    // The numbers on the wire have to differ, or two of these three would
    // read each other's advertisements and fight.
    let mut numbers: Vec<u8> = routers.iter().map(|router| router.vrid).collect();
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), 3, "two addresses were given the same VRID");

    // And every node was given exactly one address to hold.
    let mut holders: Vec<&str> = routers.iter().map(Router::holder).collect();
    holders.sort_unstable();
    holders.dedup();
    assert_eq!(holders.len(), 3, "the matrix piled addresses onto one node");

    let mut running: Vec<(String, String, Background)> = Vec::new();
    for router in &routers {
        for node in &nodes {
            let peers: Vec<Ipv4Addr> = nodes
                .iter()
                .filter(|other| other.name() != node.name())
                .map(|other| other.address())
                .collect();
            running.push((
                router.vip.clone(),
                node.name().to_owned(),
                start(node, &router_binary, router, &peers),
            ));
        }
    }

    // Wait until the node the matrix chose says it has the address.
    for router in &routers {
        let held = running
            .iter()
            .find(|(vip, node, _)| vip == &router.vip && node == router.holder())
            .map(|(_, _, background)| background)
            .expect("the holder is running");
        held.wait_for_stdout(r#""event":"taken""#, PATIENCE)
            .unwrap_or_else(|error| {
                stop_all(&cluster);
                panic!("{} never took {}: {error}", router.holder(), router.vip)
            });
    }
    thread::sleep(Duration::from_millis(700));

    // What the kernel says, node by node and address by address.
    let mut placed: Vec<(String, String, bool)> = Vec::new();
    for router in &routers {
        for node in &nodes {
            let has = node
                .has_address(router.address)
                .expect("the node should be readable");
            placed.push((router.vip.clone(), node.name().to_owned(), has));
        }
    }

    // Now take the strongest node for the first address away, and nothing
    // else. The other two addresses are untouched, so what moves is only what
    // this measurement is about.
    let first = &routers[0];
    let second = first.ranking[1].0.clone();
    let third = first.ranking[2].0.clone();
    let dying = nodes
        .iter()
        .find(|node| node.name() == first.holder())
        .expect("the holder is one of the nodes");
    dying
        .kill_matching(&format!("--vrid {}", first.vrid))
        .expect("the virtual router should be killable");

    let taking = running
        .iter()
        .find(|(vip, node, _)| vip == &first.vip && node == &second)
        .map(|(_, _, background)| background)
        .expect("the second in the order is running");
    let took = taking.wait_for_stdout(r#""event":"taken""#, PATIENCE);
    thread::sleep(Duration::from_millis(700));

    let on_second = nodes
        .iter()
        .find(|node| node.name() == second)
        .expect("it is a node")
        .has_address(first.address)
        .expect("the node should be readable");
    let on_third = nodes
        .iter()
        .find(|node| node.name() == third)
        .expect("it is a node")
        .has_address(first.address)
        .expect("the node should be readable");
    // The address that had nothing to do with the failure stays where it was.
    let untouched = nodes
        .iter()
        .find(|node| node.name() == routers[1].holder())
        .expect("it is a node")
        .has_address(routers[1].address)
        .expect("the node should be readable");

    stop_all(&cluster);

    for (vip, node, has) in &placed {
        let router = routers
            .iter()
            .find(|router| &router.vip == vip)
            .expect("it is one of them");
        let expected = router.holder() == node;
        assert_eq!(
            *has,
            expected,
            "{vip} on {node}: expected {expected}, and the matrix said {} holds it",
            router.holder()
        );
    }

    took.unwrap_or_else(|error| panic!("{second} never took over {}: {error}", first.vip));
    assert!(
        on_second,
        "{second} is next in the order and must take over"
    );
    // The other side. Without this a machine that put the address everywhere
    // would pass the line above.
    assert!(!on_third, "{third} is third and must not take over");
    assert!(untouched, "an unrelated address moved");
}
