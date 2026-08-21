// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The capture helper, checked both ways.
//!
//! A helper that always reports "seen" is worse than none, so every positive
//! check here has a negative one beside it.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::thread;
use std::time::Duration;

use ek_ek_itest::{Capture, Cluster};

#[test]
fn the_capture_sees_traffic_between_two_nodes() {
    let cluster = Cluster::start().expect("cluster should start");
    let sender = cluster.node("node1").expect("node1 exists");
    let observer = cluster.node("node2").expect("node2 exists");

    let capture = Capture::start(
        observer,
        &format!("icmp and host {}", sender.address()),
        4,
        Duration::from_secs(8),
    )
    .expect("capture should start");

    sender
        .can_reach(observer.address())
        .expect("ping should run");

    let seen = capture.finish().expect("capture should finish");
    seen.expect_contains(&format!("{} > {}", sender.address(), observer.address()))
        .expect("the echo request should be in the capture");
}

#[test]
fn the_capture_reports_nothing_when_nothing_happens() {
    let cluster = Cluster::start().expect("cluster should start");
    let observer = cluster.node("node2").expect("node2 exists");
    let unused = cluster.vip(9).expect("vip 9 is inside the reserved range");

    // Nobody holds this address, so no frame can carry it. If the helper still
    // reports packets, it is not filtering and every other check here is void.
    let capture = Capture::start(
        observer,
        &format!("host {unused}"),
        4,
        Duration::from_secs(3),
    )
    .expect("capture should start");
    thread::sleep(Duration::from_millis(500));

    let seen = capture.finish().expect("capture should finish");
    assert_eq!(
        seen.packets(),
        0,
        "the filter matched traffic for an address nobody holds:\n{}",
        seen.text()
    );
}

#[test]
fn the_capture_sees_ip_protocol_112() {
    let cluster = Cluster::start().expect("cluster should start");
    let sender = cluster.node("node1").expect("node1 exists");
    let observer = cluster.node("node2").expect("node2 exists");

    // VRRP rides on IP protocol 112, not on UDP. A helper proven against UDP
    // multicast would pass in environments where the protocol VRRP actually
    // uses is blocked, so the check is written against 112 from the start.
    let capture = Capture::start(observer, "proto 112", 2, Duration::from_secs(8))
        .expect("capture should start");

    let send = format!(
        "python3 -c \"import socket; \
         s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 112); \
         s.sendto(bytes(12), ('{}', 0))\"",
        observer.address()
    );
    for _ in 0..2 {
        sender.shell(&send).expect("raw socket send should run");
        thread::sleep(Duration::from_millis(100));
    }

    let seen = capture.finish().expect("capture should finish");
    seen.expect_contains(&format!("{} > {}", sender.address(), observer.address()))
        .expect("the protocol 112 packet should be in the capture");
}
