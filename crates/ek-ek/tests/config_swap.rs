// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a configuration change must not do to traffic already in flight.
//!
//! The other data plane rules are measured against the link on its own. This
//! one cannot be: it is about sockets a client is holding open, so it needs
//! the real binary, a real pingora server, real backends and connections that
//! stay up across the change (ADR-0009).
//!
//! Which delivery is being served is read from the traffic itself. Each
//! delivery points the pool at a different member, and each member names
//! itself in its answer, so a change is observed the way a client would see
//! it rather than through a status endpoint that no longer exists.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::BufReader;

mod common;

use common::{Document, Member, Running, ask, connect, free_port, plain_request};

/// How long a worker keeps asking before giving up on seeing the last change.
const PATIENCE: Duration = Duration::from_secs(20);

/// How many connections hold traffic open across the change.
const WORKERS: usize = 4;

/// What one connection saw over its lifetime.
struct Seen {
    address: SocketAddr,
    requests: usize,
    members: BTreeSet<String>,
    failure: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_change_does_not_cut_connections_that_are_already_open() {
    let first = Member::start("first").await;
    let second = Member::start("second").await;
    let third = Member::start("third").await;
    let port = free_port();

    // Three deliveries, each pointing the pool at one member. Which member
    // answers is therefore which delivery is live.
    let one = Document::new(port, vec![first.entry(1, "enabled")]);
    let two = Document::new(port, vec![second.entry(1, "enabled")]);
    let three = Document::new(port, vec![third.entry(1, "enabled")]);

    let running = Running::start(&one).await;

    // Every worker holds one connection open for the whole test and never
    // opens a second one. A cut connection therefore shows up as a failure
    // rather than as a reconnection nobody notices.
    let mut workers = Vec::new();
    for _ in 0..WORKERS {
        let stream = connect(port).await;
        let address = stream
            .local_addr()
            .expect("an open connection must have an address");

        workers.push(tokio::spawn(async move {
            let mut io = BufReader::new(stream);
            let mut seen = Seen {
                address,
                requests: 0,
                members: BTreeSet::new(),
                failure: None,
            };
            let start = tokio::time::Instant::now();

            loop {
                match ask(&mut io, &plain_request()).await {
                    Ok(answer) => {
                        seen.requests += 1;
                        if answer.status != 200 {
                            seen.failure = Some(format!(
                                "request {} was answered {} rather than proxied",
                                seen.requests, answer.status
                            ));
                            break;
                        }
                        seen.members.insert(answer.member());
                        // Stop on the last change, so the test is not paced by
                        // a fixed sleep.
                        if seen.members.contains("third") {
                            break;
                        }
                    }
                    Err(error) => {
                        seen.failure = Some(format!("after {} requests: {error}", seen.requests));
                        break;
                    }
                }
                if start.elapsed() > PATIENCE {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }

            // Reading the address again from the same socket: a closed
            // connection cannot answer this.
            let still_open = io
                .get_ref()
                .local_addr()
                .map(|later| later == seen.address)
                .unwrap_or(false);
            (seen, still_open)
        }));
    }

    // Traffic is flowing. Change the configuration underneath it, twice.
    running.agent.wait_linked().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    running.agent.push(&two.delivery(2));
    tokio::time::sleep(Duration::from_millis(200)).await;
    running.agent.push(&three.delivery(3));

    for (number, worker) in workers.into_iter().enumerate() {
        let (seen, still_open) = worker.await.expect("a worker must finish");

        assert!(
            seen.failure.is_none(),
            "connection {number} was cut during a configuration change: {}",
            seen.failure.unwrap_or_default()
        );
        assert!(
            seen.members.contains("first"),
            "connection {number} must have been open before the first change, saw {:?}",
            seen.members
        );
        assert!(
            seen.members.contains("third"),
            "connection {number} must have been open after the last change, saw {:?}",
            seen.members
        );
        assert!(
            seen.requests > 10,
            "connection {number} answered only {} requests, which measures nothing",
            seen.requests
        );
        assert!(
            still_open,
            "connection {number} is no longer the socket it started as"
        );
    }
}
