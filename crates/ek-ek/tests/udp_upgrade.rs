// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Replacing the process that carries UDP without cutting the traffic.
//!
//! UDP sockets are outside pingora's handover, so the replacement binds the
//! same port with `SO_REUSEPORT` and the two processes overlap until the old
//! one has drained (ADR-0017).
//!
//! How the kernel shares datagrams between the sockets in a `SO_REUSEPORT`
//! group differs between systems: Linux hashes them across the group, and on
//! macOS every datagram measured went to the socket that bound last. Nothing
//! here depends on the split. What is measured is what holds either way: both
//! processes can bind, no datagram is lost across the change, a client keeps
//! its member, the old process ends by itself, and nothing is left behind.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{Document, Running, UdpClient, UdpMember, free_port, process_state, udp_listeners};

/// How long a process gets to end on its own before a test calls it stuck.
const PATIENCE: Duration = Duration::from_secs(60);

/// The drain timeout the two drain tests use.
///
/// Long enough that ending when the table empties and waiting the timeout out
/// are far apart, so one test cannot pass for the other's reason. pingora
/// adds a fixed five seconds of its own before it even broadcasts the
/// shutdown, because SIGQUIT first tries to hand listening sockets over.
const DRAIN_LIMIT: u32 = 15;

/// Waits until a replacement is taking datagrams as well.
async fn wait_until_two_listeners(port: u16) -> usize {
    for _ in 0..600 {
        let count = udp_listeners(port);
        if count >= 2 {
            return count;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    udp_listeners(port)
}

/// Waits until only one process holds the port.
async fn wait_until_one_listener(port: u16) -> usize {
    for _ in 0..900 {
        let count = udp_listeners(port);
        if count == 1 {
            return count;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    udp_listeners(port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_bind_the_same_udp_port() {
    let one = UdpMember::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).udp();
    let running = Running::start_udp(&document, &[&one]).await;

    // Nothing was special about the first bind: the second one only works
    // because both are opened with SO_REUSEPORT.
    let mut replacement = running.start_replacement();

    let listeners = wait_until_two_listeners(running.port).await;
    assert_eq!(
        listeners,
        2,
        "the replacement never bound the port the first process is serving; it said: {}",
        replacement.complaints()
    );
    assert!(
        replacement.exited().is_none(),
        "the replacement exited instead of binding: {}",
        replacement.complaints()
    );

    // And it serves: a datagram sent now is answered whichever process takes
    // it.
    let client = UdpClient::open(running.port).await;
    let answer = client.ask("hello").await.expect("it must be answered");
    assert_eq!(answer, "one:hello");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_datagram_is_lost_while_the_process_is_replaced() {
    let one = UdpMember::start("one").await;
    let two = UdpMember::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .udp()
        .algorithm("consistent_hash");
    let mut running = Running::start_udp(&document, &[&one, &two]).await;

    let client = UdpClient::open(running.port).await;
    let mut sent = 0_usize;
    let mut answered = 0_usize;
    let mut lost = Vec::new();

    // A run before the change, so a test that lost every datagram would not
    // pass by measuring nothing.
    for number in 0..10 {
        sent += 1;
        match client.ask(&format!("before-{number}")).await {
            Ok(answer) => {
                assert!(answer.ends_with(&format!("before-{number}")));
                answered += 1;
            }
            Err(_) => lost.push(format!("before-{number}")),
        }
    }

    let mut replacement = running.start_replacement();
    let listeners = wait_until_two_listeners(running.port).await;
    assert_eq!(listeners, 2, "the replacement never came up");

    // Traffic continues while both processes hold the port, and keeps going
    // after the old one is asked to drain.
    for number in 0..20 {
        sent += 1;
        match client.ask(&format!("during-{number}")).await {
            Ok(answer) => {
                assert!(answer.ends_with(&format!("during-{number}")));
                answered += 1;
            }
            Err(_) => lost.push(format!("during-{number}")),
        }
        if number == 5 {
            running.ask_to_drain();
        }
    }

    let ended = running.wait_for_exit(PATIENCE).await;
    assert!(ended.is_some(), "the old process never ended");

    for number in 0..20 {
        sent += 1;
        match client.ask(&format!("after-{number}")).await {
            Ok(answer) => {
                assert!(answer.ends_with(&format!("after-{number}")));
                answered += 1;
            }
            Err(_) => lost.push(format!("after-{number}")),
        }
    }

    println!("sent {sent}, answered {answered}, lost {}", lost.len());
    assert_eq!(sent, 50, "the test did not send what it meant to");
    assert!(
        lost.is_empty(),
        "sent {sent}, answered {answered}, lost {}: {lost:?}",
        lost.len()
    );
    assert_eq!(answered, sent, "sent {sent} but only {answered} came back");
    drop(replacement.exited());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_keeps_its_member_when_the_replacement_takes_over() {
    // The session table is not shared between the processes and does not
    // need to be: both hash the same client to the same member (ADR-0025).
    let one = UdpMember::start("one").await;
    let two = UdpMember::start("two").await;
    let three = UdpMember::start("three").await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![
            one.entry(1, "enabled"),
            two.entry(1, "enabled"),
            three.entry(1, "enabled"),
        ],
    )
    .udp()
    .algorithm("consistent_hash");
    let mut running = Running::start_udp(&document, &[&one, &two, &three]).await;

    // Several clients, so the answer does not rest on one hash landing well.
    let mut pinned = Vec::new();
    for number in 0..12 {
        let client = UdpClient::open(running.port).await;
        let answer = client
            .ask(&format!("first-{number}"))
            .await
            .expect("every client must be answered");
        let member = UdpClient::member_of(&answer);
        pinned.push((client, member));
    }
    assert!(
        pinned
            .iter()
            .map(|(_, member)| member)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1,
        "every client landed on one member, so nothing was measured"
    );

    let mut replacement = running.start_replacement();
    assert_eq!(wait_until_two_listeners(running.port).await, 2);
    running.ask_to_drain();
    assert!(
        running.wait_for_exit(PATIENCE).await.is_some(),
        "the old process never ended"
    );

    // Every datagram now reaches the replacement, which has an empty table.
    for (client, was) in &pinned {
        let answer = client.ask("again").await.expect("it must be answered");
        assert_eq!(
            &UdpClient::member_of(&answer),
            was,
            "a client changed member when the process was replaced"
        );
    }
    drop(replacement.exited());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_old_process_ends_as_soon_as_its_table_is_empty() {
    // A long drain timeout and a short idle window, with no traffic after
    // the signal. The table empties in a moment, so a process that ends when
    // it empties is far quicker than one that waits the timeout out.
    let one = UdpMember::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .udp()
        .idle_timeout(1)
        .drain_timeout(DRAIN_LIMIT);
    let mut running = Running::start_udp(&document, &[&one]).await;

    let client = UdpClient::open(running.port).await;
    client.ask("hello").await.expect("it must be answered");

    running.ask_to_drain();
    let took = running
        .wait_for_exit(PATIENCE)
        .await
        .expect("the old process never ended");

    println!("the old process ended after {took:?}");
    assert!(
        took < Duration::from_secs(u64::from(DRAIN_LIMIT)),
        "the process waited out its drain timeout of {DRAIN_LIMIT}s instead of ending when the table emptied: {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_old_process_ends_when_the_drain_timeout_runs_out() {
    // The other side of the rule. Traffic keeps a session alive, so the table
    // never empties and the timeout is what ends the process.
    let one = UdpMember::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .udp()
        // Far longer than the drain timeout, so the session cannot expire on
        // its own and only the timeout can end the process.
        .idle_timeout(600)
        .drain_timeout(DRAIN_LIMIT);
    let mut running = Running::start_udp(&document, &[&one]).await;

    let client = UdpClient::open(running.port).await;
    client.ask("hello").await.expect("it must be answered");

    running.ask_to_drain();
    // Kept in use across the whole drain window.
    let keeping = tokio::spawn(async move {
        for _ in 0..40 {
            let _ = client.ask("keep").await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });

    let took = running
        .wait_for_exit(PATIENCE)
        .await
        .expect("the old process never ended");
    keeping.abort();

    println!("the old process ended after {took:?}");
    assert!(
        took >= Duration::from_secs(u64::from(DRAIN_LIMIT)),
        "the process ended before its drain timeout of {DRAIN_LIMIT}s although a session was in use: {took:?}"
    );
    assert!(
        took < Duration::from_secs(u64::from(DRAIN_LIMIT) + 15),
        "the process outlived its drain timeout by far: {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_process_holds_the_port_once_the_upgrade_is_done() {
    let one = UdpMember::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .udp()
        .idle_timeout(1);
    let mut running = Running::start_udp(&document, &[&one]).await;

    assert_eq!(
        udp_listeners(running.port),
        1,
        "the port was not held by exactly one process to begin with"
    );

    let mut replacement = running.start_replacement();
    assert_eq!(
        wait_until_two_listeners(running.port).await,
        2,
        "the two processes never overlapped"
    );

    let old = running.pid();
    running.ask_to_drain();
    assert!(
        running.wait_for_exit(PATIENCE).await.is_some(),
        "the old process never ended"
    );

    assert_eq!(
        wait_until_one_listener(running.port).await,
        1,
        "more than one process is still taking datagrams"
    );
    assert_eq!(
        process_state(old),
        "",
        "the old process is still known to the system"
    );

    // The one that is left is the replacement, and it serves.
    let client = UdpClient::open(running.port).await;
    let answer = client.ask("after").await.expect("it must be answered");
    assert_eq!(answer, "one:after");
    assert!(
        replacement.exited().is_none(),
        "the replacement is gone too: {}",
        replacement.complaints()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_replaced_process_leaves_nothing_behind() {
    let one = UdpMember::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .udp()
        .idle_timeout(1);
    let mut running = Running::start_udp(&document, &[&one]).await;

    let old = running.pid();
    assert_ne!(
        process_state(old),
        "",
        "the process was not running to begin with, so nothing was measured"
    );

    running.ask_to_drain();
    assert!(
        running.wait_for_exit(PATIENCE).await.is_some(),
        "the old process never ended"
    );

    // Read from the operating system rather than from the child handle: a
    // process that ended without being reaped would still be listed, with a
    // state of `Z`.
    let state = process_state(old);
    assert!(
        !state.contains('Z'),
        "the old process was left as a zombie: {state}"
    );
    assert_eq!(state, "", "the old process is still listed: {state}");
}
