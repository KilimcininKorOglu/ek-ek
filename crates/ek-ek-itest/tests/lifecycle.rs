// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The harness owns the cluster: it brings it up, hands it over clean, and can
//! tear it down. Everything else in the suite rests on these three.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_itest::Cluster;

#[test]
fn the_harness_starts_and_stops_the_cluster() {
    let cluster = Cluster::start().expect("cluster should start");
    assert!(
        Cluster::is_up().expect("compose should answer"),
        "cluster is not running after start"
    );

    cluster.stop().expect("cluster should stop");
    assert!(
        !Cluster::is_up().expect("compose should answer"),
        "containers are still running after stop"
    );

    // Brought back up on the way out. The next test must not have to know that
    // this one tore the environment down.
    let restarted = Cluster::start().expect("cluster should start again");
    assert!(
        Cluster::is_up().expect("compose should answer"),
        "cluster did not come back after a teardown"
    );
    drop(restarted);
}

#[test]
fn a_test_takes_over_a_clean_cluster() {
    let vip;
    {
        let cluster = Cluster::start().expect("cluster should start");
        vip = cluster.vip(0).expect("vip 0 is inside the reserved range");
        let node = cluster.node("node1").expect("node1 exists");
        node.add_address(vip, 24).expect("adding a vip should work");
        assert!(
            node.has_address(vip)
                .expect("address list should be readable")
        );
    }

    // This is what makes two consecutive runs of the same test both pass: the
    // next start clears whatever the previous one left behind.
    let cluster = Cluster::start().expect("cluster should start");
    let node = cluster.node("node1").expect("node1 exists");
    assert!(
        !node
            .has_address(vip)
            .expect("address list should be readable"),
        "reset left {vip} on node1"
    );
}

#[test]
fn every_node_is_reachable_from_every_other() {
    let cluster = Cluster::start().expect("cluster should start");
    for from in cluster.nodes() {
        for to in cluster.nodes() {
            if from.name() == to.name() {
                continue;
            }
            assert!(
                from.can_reach(to.address()).expect("ping should run"),
                "{} cannot reach {}",
                from.name(),
                to.name()
            );
        }
    }
}

#[test]
fn the_failure_report_carries_container_state() {
    let cluster = Cluster::start().expect("cluster should start");

    // Produce a log line first. An idle container writes nothing, and a report
    // that is empty because nothing happened proves nothing about the report.
    let node = cluster.node("node1").expect("node1 exists");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 exists");
    node.run_ok(&[
        "curl",
        "-fsS",
        "--max-time",
        "5",
        &format!("http://{backend}/"),
    ])
    .expect("backend1 should answer");

    let report = cluster.failure_report();
    assert!(
        report.contains("backend1"),
        "no backend log line in the report:\n{report}"
    );
    for expected in ["node1", "node2", "node3", "172.28.0.11"] {
        assert!(
            report.contains(expected),
            "report is missing {expected}:\n{report}"
        );
    }
}
