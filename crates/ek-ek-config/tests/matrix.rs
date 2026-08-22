// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Who holds which virtual address, and with what numbers.
//!
//! The matrix is a pure function, so every rule about it is measured here
//! rather than over a network. What the numbers do once they are on the wire
//! is measured in `ek-ek-itest`, where three real nodes run against the
//! matrix this code produced.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::matrix::{FIRST_VRID, LAST_VRID, STEP, TOP, VRIDS, matrix, priority};
use ek_ek_config::node::{Node, NodeRole};
use ek_ek_config::vip::Vip;
use ek_ek_config::{Config, NodeId, SchemaVersion, VipId};

/// A node that can hold an address.
fn node(name: &str, last: u8) -> Node {
    Node {
        id: NodeId::new(name),
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
        roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
    }
}

/// An address, with or without a node it should live on.
fn vip(name: &str, last: u8, preferred: Option<&str>) -> Vip {
    Vip {
        id: VipId::new(name),
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
        prefix_length: 24,
        interface: "eth0".to_owned(),
        preferred_node: preferred.map(NodeId::new),
    }
}

/// A configuration with nothing in it but nodes and addresses.
///
/// Everything else in a document is beside the point here: the matrix reads
/// the two lists and nothing else.
fn cluster(nodes: Vec<Node>, vips: Vec<Vip>) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes,
        vips,
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        stickiness_key: String::new(),
        log_level: ek_ek_config::LogLevel::default(),
    }
}

/// Three nodes, and three addresses each preferring one of them.
fn three_and_three() -> Config {
    cluster(
        vec![node("node1", 11), node("node2", 12), node("node3", 13)],
        vec![
            vip("vip-web", 100, Some("node1")),
            vip("vip-mail", 101, Some("node2")),
            vip("vip-dns", 102, Some("node3")),
        ],
    )
}

/// Which node holds each address.
fn holders(config: &Config) -> BTreeMap<String, String> {
    matrix(config)
        .routers
        .iter()
        .map(|router| {
            (
                router.vip.as_str().to_owned(),
                router
                    .holder()
                    .map(|node| node.as_str().to_owned())
                    .unwrap_or_default(),
            )
        })
        .collect()
}

/// Which number each address carries.
fn numbers(config: &Config) -> BTreeMap<String, u8> {
    matrix(config)
        .routers
        .iter()
        .map(|router| (router.vip.as_str().to_owned(), router.vrid))
        .collect()
}

#[test]
fn three_addresses_and_three_nodes_put_one_on_each() {
    // The whole point of the matrix: an active-active cluster carries its
    // load on every node rather than on one (ADR-0006).
    let held = holders(&three_and_three());

    assert_eq!(held.get("vip-web").map(String::as_str), Some("node1"));
    assert_eq!(held.get("vip-mail").map(String::as_str), Some("node2"));
    assert_eq!(held.get("vip-dns").map(String::as_str), Some("node3"));

    let distinct: BTreeSet<&String> = held.values().collect();
    assert_eq!(distinct.len(), 3, "one address each: {held:?}");
}

#[test]
fn the_same_configuration_gives_the_same_matrix_twice() {
    // Every node works the matrix out for itself. Two nodes that disagreed
    // would both claim the same address.
    let config = three_and_three();

    let first = matrix(&config);
    let second = matrix(&config);

    assert_eq!(first, second);

    // And the order the document lists the addresses in is not part of the
    // answer, so moving a line does not move a number on the wire.
    let mut shuffled = config.clone();
    shuffled.vips.reverse();
    shuffled.nodes.reverse();
    assert_eq!(matrix(&shuffled), first);
}

#[test]
fn the_second_node_in_the_order_takes_over_and_not_the_third() {
    let config = three_and_three();
    let plan = matrix(&config);
    let web = plan.router(&VipId::new("vip-web")).expect("it is there");

    assert_eq!(web.ranking.len(), 3, "every node has a place");
    assert_eq!(web.ranking[0].node.as_str(), "node1");
    assert_eq!(web.ranking[0].priority, TOP);
    assert_eq!(web.ranking[1].priority, TOP - STEP);
    assert_eq!(web.ranking[2].priority, TOP - 2 * STEP);

    // The order is strictly falling, which is what makes the second node the
    // one that takes over. A machine reading equal priorities would settle it
    // by address instead, and the order would stop being the product's.
    assert!(
        web.ranking[0].priority > web.ranking[1].priority
            && web.ranking[1].priority > web.ranking[2].priority,
        "{:?}",
        web.ranking
    );
    assert_ne!(
        web.ranking[1].node, web.ranking[2].node,
        "the second and the third are different nodes"
    );
}

#[test]
fn a_priority_never_reaches_the_two_values_the_protocol_reserves() {
    // 255 says the node owns the address outright and 0 says a master is
    // standing down. Neither is something this product may claim by accident.
    for rank in 0..64 {
        let claimed = priority(rank);
        assert!(claimed >= 1, "rank {rank} claimed {claimed}");
        assert!(claimed < 255, "rank {rank} claimed {claimed}");
    }
    assert_eq!(priority(0), TOP);
    assert_eq!(priority(1), TOP - STEP);
    // Past the point where the steps would reach zero, every node shares the
    // floor and the address settles the tie, which is VRRP's own rule.
    assert_eq!(priority(100), 1);
}

#[test]
fn the_configuration_carries_no_router_id_and_no_priority() {
    // The operator states a preference and nothing else. A document with a
    // number in it would make them own a protocol detail (ADR-0006).
    let config = three_and_three();
    let written = serde_json::to_string(&config).expect("a config serialises");

    assert!(!written.contains("vrid"), "{written}");
    assert!(!written.contains("priority"), "{written}");
    assert!(
        written.contains("preferred_node"),
        "the one thing an operator does state: {written}"
    );

    // And the other side: a document naming one is refused rather than read
    // with the field dropped.
    let with_a_number = written.replace(
        r#""preferred_node":"node1""#,
        r#""preferred_node":"node1","vrid":51"#,
    );
    assert!(
        serde_json::from_str::<Config>(&with_a_number).is_err(),
        "a document carrying a router id must be refused"
    );
}

#[test]
fn adding_an_address_leaves_every_other_number_alone() {
    let before = numbers(&three_and_three());

    let mut grown = three_and_three();
    grown.vips.push(vip("vip-ldap", 103, Some("node1")));
    let after = numbers(&grown);

    for (name, number) in &before {
        assert_eq!(
            after.get(name),
            Some(number),
            "{name} moved from {number:?} to {:?}",
            after.get(name)
        );
    }
    assert!(after.contains_key("vip-ldap"), "and the new one got one");

    // An identity that sorts before every existing one is the case a counted
    // assignment fails: it would take the first number and push the rest.
    let mut early = three_and_three();
    early.vips.push(vip("aaa-first", 104, None));
    let after = numbers(&early);
    for (name, number) in &before {
        assert_eq!(after.get(name), Some(number), "{name} moved");
    }
}

#[test]
fn removing_an_address_frees_its_number_and_leaves_the_rest_alone() {
    let config = three_and_three();
    let before = numbers(&config);
    let freed = *before.get("vip-mail").expect("it has a number");

    let mut smaller = config;
    smaller.vips.retain(|vip| vip.id.as_str() != "vip-mail");
    let after = numbers(&smaller);

    assert!(!after.contains_key("vip-mail"));
    for (name, number) in &before {
        if name == "vip-mail" {
            continue;
        }
        assert_eq!(after.get(name), Some(number), "{name} moved");
    }

    // The number really is free: an address that hashes there could take it,
    // and nothing holds it any more.
    assert!(
        !after.values().any(|number| *number == freed),
        "{freed} is still in use: {after:?}"
    );
}

#[test]
fn no_two_addresses_share_a_number() {
    // Two virtual routers with the same id on one segment read each other's
    // advertisements and fight (ADR-0006 puts every node on one segment).
    let many: Vec<Vip> = (0..60)
        .map(|at| vip(&format!("vip-{at:03}"), 100, None))
        .collect();
    let config = cluster(vec![node("node1", 11), node("node2", 12)], many);

    let plan = matrix(&config);
    let used: BTreeSet<u8> = plan.routers.iter().map(|router| router.vrid).collect();

    assert_eq!(used.len(), plan.routers.len(), "{used:?}");
    assert_eq!(plan.routers.len(), 60);
    for number in &used {
        assert!(
            (FIRST_VRID..=LAST_VRID).contains(number),
            "{number} is not a virtual router id"
        );
    }
}

#[test]
fn an_address_that_had_to_move_aside_says_so() {
    // Two identities landing on the same number is what hashing does. The
    // one that moved is named, because deleting the address in its way moves
    // it back, and that is the one case where removing an address disturbs a
    // second one.
    let many: Vec<Vip> = (0..200)
        .map(|at| vip(&format!("vip-{at:03}"), 100, None))
        .collect();
    let config = cluster(vec![node("node1", 11)], many);

    let plan = matrix(&config);
    let moved = plan.moved_aside();

    assert!(
        !moved.is_empty(),
        "two hundred addresses in 255 slots must collide somewhere"
    );
    for router in &plan.routers {
        assert_eq!(
            router.vrid_is_first_choice,
            !moved.contains(&&router.vip),
            "{} disagrees with itself",
            router.vip.as_str()
        );
    }

    // The other side: a handful of addresses mostly get what they asked for.
    let few = cluster(
        vec![node("node1", 11)],
        vec![
            vip("vip-web", 100, None),
            vip("vip-mail", 101, None),
            vip("vip-dns", 102, None),
        ],
    );
    assert!(
        matrix(&few).moved_aside().is_empty(),
        "three addresses in 255 slots should not be in each other's way"
    );
}

#[test]
fn addresses_with_no_preference_are_spread_over_the_nodes() {
    let vips: Vec<Vip> = (0..30)
        .map(|at| vip(&format!("vip-{at:03}"), 100, None))
        .collect();
    let config = cluster(
        vec![node("node1", 11), node("node2", 12), node("node3", 13)],
        vips,
    );

    let load = matrix(&config).load();

    assert_eq!(load.len(), 3, "every node carries something: {load:?}");
    let counts: Vec<usize> = load.iter().map(|(_, count)| *count).collect();
    let total: usize = counts.iter().sum();
    assert_eq!(total, 30);
    // Even is ten each. Anything inside half to double that is a spread
    // rather than a pile, and a hash cannot promise better.
    for (node, count) in &load {
        assert!(
            (5..=20).contains(count),
            "{} carries {count} of {total}: {load:?}",
            node.as_str()
        );
    }
}

#[test]
fn a_preference_beats_the_spread() {
    // The other side of the measurement above. A matrix that spread every
    // address would ignore what the operator asked for.
    let config = cluster(
        vec![node("node1", 11), node("node2", 12), node("node3", 13)],
        (0..30)
            .map(|at| vip(&format!("vip-{at:03}"), 100, Some("node2")))
            .collect(),
    );

    let load = matrix(&config).load();

    assert_eq!(load.len(), 1, "every address was asked for on one node");
    assert_eq!(load[0].0.as_str(), "node2");
    assert_eq!(load[0].1, 30);
}

#[test]
fn a_fourth_node_moves_as_little_as_it_can() {
    // The criterion the algorithm is chosen for. A new node has to take a
    // share, and every address it does not take must stay where it was.
    let vips: Vec<Vip> = (0..40)
        .map(|at| vip(&format!("vip-{at:03}"), 100, None))
        .collect();
    let three = cluster(
        vec![node("node1", 11), node("node2", 12), node("node3", 13)],
        vips.clone(),
    );
    let four = cluster(
        vec![
            node("node1", 11),
            node("node2", 12),
            node("node3", 13),
            node("node4", 14),
        ],
        vips,
    );

    let before = holders(&three);
    let after = holders(&four);
    let moved = before
        .iter()
        .filter(|(name, held)| after.get(*name) != Some(*held))
        .count();
    let onto_the_new_node = after.values().filter(|held| *held == "node4").count();

    // Every address that moved went to the new node. Nothing shuffled
    // between the three that were already there.
    assert_eq!(
        moved, onto_the_new_node,
        "an address moved somewhere other than the new node: {before:?} then {after:?}"
    );
    assert!(onto_the_new_node > 0, "the new node has to take a share");
    // A quarter of forty is ten. Anything near that is the least a working
    // assignment can move.
    assert!(
        moved <= 20,
        "{moved} of 40 addresses moved, which is more than sharing needs"
    );

    // And the numbers on the wire did not move at all: a node joining is not
    // a reason to renumber a virtual router.
    assert_eq!(numbers(&three), numbers(&four));
}

#[test]
fn counting_the_nodes_instead_of_hashing_them_fails_that_measurement() {
    // The measurement above is only worth something if an obvious algorithm
    // fails it. This is that algorithm: hand each address to the node at its
    // own position in the list.
    let names: Vec<String> = (0..40).map(|at| format!("vip-{at:03}")).collect();
    let round_robin = |nodes: usize| -> Vec<usize> {
        names
            .iter()
            .enumerate()
            .map(|(at, _)| at % nodes)
            .collect::<Vec<usize>>()
    };

    let before = round_robin(3);
    let after = round_robin(4);
    let moved = before
        .iter()
        .zip(after.iter())
        .filter(|(one, other)| one != other)
        .count();

    assert!(
        moved > 20,
        "counting moved only {moved} of 40, so it would have passed"
    );
}

#[test]
fn a_node_that_does_not_run_the_control_plane_holds_nothing() {
    // VRRP runs inside the node agent, which is the control plane. A data
    // plane process is replaced whenever a listener changes, and a virtual
    // router that went with it would flap the address (ADR-0002).
    let mut nodes = vec![node("node1", 11), node("node2", 12)];
    nodes.push(Node {
        id: NodeId::new("node3"),
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 13)),
        roles: vec![NodeRole::DataPlane],
    });
    let config = cluster(nodes, vec![vip("vip-web", 100, None)]);

    let plan = matrix(&config);
    let web = plan.router(&VipId::new("vip-web")).expect("it is there");

    assert_eq!(web.ranking.len(), 2, "{:?}", web.ranking);
    assert!(
        web.ranking
            .iter()
            .all(|placement| placement.node.as_str() != "node3")
    );

    // The other side: naming it as the preferred node does not smuggle it in.
    let asked = cluster(
        config.nodes.clone(),
        vec![vip("vip-web", 100, Some("node3"))],
    );
    let plan = matrix(&asked);
    let web = plan.router(&VipId::new("vip-web")).expect("it is there");
    assert_eq!(web.ranking.len(), 2);
    assert_ne!(web.holder().map(NodeId::as_str), Some("node3"));
}

#[test]
fn the_matrix_reads_back_as_a_document() {
    // What the UI is given (T-051). It has to survive the trip through JSON
    // rather than being a shape only Rust can hold.
    let plan = matrix(&three_and_three());

    let written = serde_json::to_string(&plan).expect("the matrix serialises");
    let read: ek_ek_config::Matrix = serde_json::from_str(&written).expect("and reads back");

    assert_eq!(read, plan);
    assert!(written.contains("vip-web"));
    assert!(written.contains("vrid"));
    assert!(written.contains("priority"));

    // And it answers the question a screen asks: who holds this address, and
    // what does each node claim it with.
    let web = read.router(&VipId::new("vip-web")).expect("it is there");
    assert_eq!(web.holder().map(NodeId::as_str), Some("node1"));
    assert_eq!(web.priority_of(&NodeId::new("node1")), Some(TOP));
    assert_eq!(web.priority_of(&NodeId::new("nobody")), None);
}

#[test]
fn a_cluster_with_no_nodes_produces_no_ranking_rather_than_a_panic() {
    // A document is validated before it is stored, but the matrix is a
    // library function and takes whatever it is given.
    let config = cluster(Vec::new(), vec![vip("vip-web", 100, Some("node1"))]);

    let plan = matrix(&config);

    assert_eq!(plan.routers.len(), 1);
    assert!(plan.routers[0].ranking.is_empty());
    assert_eq!(plan.routers[0].holder(), None);
    assert!(plan.load().is_empty());
}

#[test]
fn more_addresses_than_the_protocol_has_numbers_leaves_the_extra_ones_out() {
    // The validation layer refuses this document, which is measured in
    // `validation.rs`. What the matrix does with it is measured here: it
    // hands out every number it has and stops, rather than repeating one.
    let many: Vec<Vip> = (0..=VRIDS)
        .map(|at| vip(&format!("vip-{at:03}"), 100, None))
        .collect();
    assert_eq!(many.len(), VRIDS + 1);
    let config = cluster(vec![node("node1", 11)], many);

    let plan = matrix(&config);
    let used: BTreeSet<u8> = plan.routers.iter().map(|router| router.vrid).collect();

    assert_eq!(plan.routers.len(), VRIDS);
    assert_eq!(used.len(), VRIDS, "every number is used exactly once");
    assert_eq!(*used.iter().next().expect("the lowest"), FIRST_VRID);
    assert_eq!(*used.iter().next_back().expect("the highest"), LAST_VRID);
}
