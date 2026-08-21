// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The UDP traffic path, over real sockets.
//!
//! The session table's own behaviour is measured in `ek-ek-dataplane`. What
//! needs the real binary is whether a datagram reaches a member at all,
//! whether the answer finds its way back to the client that asked, and
//! whether two clients sharing a member get their own answers rather than
//! each other's.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

mod common;

use common::{Document, Running, UdpClient, UdpMember, free_port};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_datagram_reaches_a_member_and_its_answer_comes_back() {
    let one = UdpMember::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).udp();
    let running = Running::start_udp(&document, &[&one]).await;

    let client = UdpClient::open(running.port).await;
    let answer = client.ask("hello").await.expect("the datagram must answer");

    assert_eq!(answer, "one:hello", "the answer was not the member's");
    assert_eq!(one.seen(), 1, "the member saw {} datagrams", one.seen());
    assert_eq!(one.payloads(), vec!["hello".to_owned()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_datagram_from_one_client_goes_to_the_same_member() {
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
    let running = Running::start_udp(&document, &[&one, &two, &three]).await;

    let client = UdpClient::open(running.port).await;
    let first = client.ask("1").await.expect("the first must answer");
    let pinned = UdpClient::member_of(&first);

    for number in 2..=20 {
        let answer = client
            .ask(&number.to_string())
            .await
            .expect("every datagram must answer");
        assert_eq!(
            UdpClient::member_of(&answer),
            pinned,
            "datagram {number} went to another member"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_clients_on_one_member_get_their_own_answers() {
    // This is what one socket per session buys. With a shared socket the
    // member's answers could not be told apart, and a client would receive
    // the other's.
    let only = UdpMember::start("only").await;
    let port = free_port();
    let document = Document::new(port, vec![only.entry(1, "enabled")])
        .udp()
        .algorithm("consistent_hash");
    let running = Running::start_udp(&document, &[&only]).await;

    let first = UdpClient::open(running.port).await;
    let second = UdpClient::open(running.port).await;

    for round in 0..10 {
        let mine = format!("first-{round}");
        let theirs = format!("second-{round}");
        let one = first.ask(&mine).await.expect("the first must answer");
        let two = second.ask(&theirs).await.expect("the second must answer");

        assert_eq!(one, format!("only:{mine}"), "a client got another's answer");
        assert_eq!(
            two,
            format!("only:{theirs}"),
            "a client got another's answer"
        );
    }

    assert!(
        only.sources() >= 2,
        "two clients reached the member through {} source address(es)",
        only.sources()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_lands_on_the_same_member_after_the_table_is_emptied() {
    // The table is an accelerator, not the source of truth (ADR-0025). It is
    // emptied here by lowering the limit to one and pushing a second client
    // through, which evicts the first outright.
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
    .algorithm("consistent_hash")
    .udp_session_limit(1);
    let running = Running::start_udp(&document, &[&one, &two, &three]).await;

    let watched = UdpClient::open(running.port).await;
    let pinned = UdpClient::member_of(&watched.ask("first").await.expect("it must answer"));

    // Every other client evicts whatever was there, because the table holds
    // one entry.
    for number in 0..20 {
        let other = UdpClient::open(running.port).await;
        let _ = other.ask(&format!("other-{number}")).await;
    }

    let again = UdpClient::member_of(&watched.ask("again").await.expect("it must answer"));

    assert_eq!(
        again, pinned,
        "an evicted client landed on another member, so the table was the source of truth"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_clients_of_the_member_that_left_are_moved() {
    let staying = UdpMember::start("staying").await;
    let leaving = UdpMember::start("leaving").await;
    let third = UdpMember::start("third").await;
    let port = free_port();
    let all = vec![
        staying.entry(1, "enabled"),
        leaving.entry(1, "enabled"),
        third.entry(1, "enabled"),
    ];
    let document = Document::new(port, all).udp().algorithm("consistent_hash");
    let running = Running::start_udp(&document, &[&staying, &leaving, &third]).await;

    // Enough clients that every member is used.
    let mut clients = Vec::new();
    for number in 0..30 {
        let client = UdpClient::open(running.port).await;
        let answer = client
            .ask(&format!("hello-{number}"))
            .await
            .expect("every client must be answered");
        let member = UdpClient::member_of(&answer);
        clients.push((client, member));
    }
    let on_leaving = clients
        .iter()
        .filter(|(_, member)| member == "leaving")
        .count();
    assert!(
        on_leaving > 0,
        "no client was on the member about to leave, so nothing was measured"
    );

    let smaller = Document::new(
        port,
        vec![staying.entry(1, "enabled"), third.entry(1, "enabled")],
    )
    .udp()
    .algorithm("consistent_hash");
    running.agent.push(&smaller.delivery(2));
    running
        .agent
        .wait_for_counter("configs_applied", 2)
        .await
        .expect("the smaller configuration must apply");
    // The sweep that drops sessions of a member that left runs twice a
    // second.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let mut moved = 0;
    let mut kept = 0;
    for (client, was) in &clients {
        let answer = client.ask("again").await.expect("every client must answer");
        let now = UdpClient::member_of(&answer);
        assert_ne!(now, "leaving", "a member that left still answered");
        if was == "leaving" {
            moved += 1;
        } else {
            assert_eq!(&now, was, "a client of a member that stayed was moved");
            kept += 1;
        }
    }

    assert_eq!(moved, on_leaving, "not every client of the member moved");
    assert_eq!(
        kept,
        clients.len() - on_leaving,
        "the other clients did not stay where they were"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_marked_unhealthy_takes_no_new_session() {
    // The healthy member answers the connect probe; the other speaks only
    // UDP, so the probe against it fails and it is marked unhealthy.
    let staying = UdpMember::also_answering_tcp("staying").await;
    let failing = UdpMember::start("failing").await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![staying.entry(1, "enabled"), failing.entry(1, "enabled")],
    )
    .udp()
    .algorithm("consistent_hash")
    // A TCP connect probe against a member that only speaks UDP fails, which
    // is exactly what is wanted: the member is marked unhealthy without the
    // test having to break it.
    .tcp_health_check(200, 100, 1, 1);
    let running = Running::start_udp(&document, &[&staying, &failing]).await;

    running
        .agent
        .wait_for_health("failing", false)
        .await
        .expect("the member must be reported unhealthy");
    staying.reset();
    failing.reset();

    for number in 0..30 {
        let client = UdpClient::open(running.port).await;
        let answer = client
            .ask(&format!("hello-{number}"))
            .await
            .expect("a pool with a healthy member must answer");
        assert_eq!(
            UdpClient::member_of(&answer),
            "staying",
            "a datagram reached a member marked unhealthy"
        );
    }

    assert_eq!(
        failing.seen(),
        0,
        "an unhealthy member took {} datagrams",
        failing.seen()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_count_and_the_eviction_count_reach_the_agent() {
    let one = UdpMember::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .udp()
        .udp_session_limit(2);
    let running = Running::start_udp(&document, &[&one]).await;

    // Three clients against a table of two: one has to be evicted.
    let mut clients = Vec::new();
    for number in 0..3 {
        let client = UdpClient::open(running.port).await;
        client
            .ask(&format!("hello-{number}"))
            .await
            .expect("every client must be answered");
        clients.push(client);
    }

    let sessions = running
        .agent
        .wait_for_udp_sessions("web", 1)
        .await
        .expect("the session count must be reported");
    assert!(
        sessions.count <= 2,
        "the table reported {} sessions against a limit of 2",
        sessions.count
    );
    assert_eq!(sessions.limit, 2, "the limit was not reported");

    let evicted = running
        .agent
        .wait_for_counter("udp_sessions_evicted", 1)
        .await
        .expect("an eviction must be reported");
    assert!(evicted >= 1, "no eviction was counted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_that_goes_quiet_leaves_the_table() {
    let one = UdpMember::start("one").await;
    let port = free_port();
    // The idle window is long enough that the session is still there when
    // the first status report goes out, which is every five seconds.
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .udp()
        .idle_timeout(8);
    let running = Running::start_udp(&document, &[&one]).await;

    let client = UdpClient::open(running.port).await;
    client.ask("hello").await.expect("it must answer");
    running
        .agent
        .wait_for_udp_sessions("web", 1)
        .await
        .expect("the session must be reported");

    // The idle window, plus a sweep, plus a report.
    tokio::time::sleep(Duration::from_secs(15)).await;

    let sessions = running
        .agent
        .udp_sessions_now("web")
        .await
        .expect("the frontend must still be reported");
    assert_eq!(
        sessions.count, 0,
        "a session that went quiet is still in the table"
    );

    // The client is still served: the entry is rebuilt from the hash.
    let answer = client.ask("again").await.expect("it must answer again");
    assert_eq!(UdpClient::member_of(&answer), "one");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_that_keeps_working_is_not_swept_away() {
    // The other side of the idle rule. A sweep that dropped live sessions
    // would rebuild them constantly and lose the point of the table.
    let one = UdpMember::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .udp()
        .idle_timeout(2);
    let running = Running::start_udp(&document, &[&one]).await;

    // Kept alive for longer than three report intervals and far longer than
    // the idle window, so a sweep that dropped live sessions would show.
    let client = UdpClient::open(running.port).await;
    for _ in 0..40 {
        client.ask("keep").await.expect("it must answer");
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    let sessions = running
        .agent
        .udp_sessions_now("web")
        .await
        .expect("the frontend must be reported");
    assert_eq!(
        sessions.count, 1,
        "a session in constant use was swept away"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_clients_at_once_do_not_push_the_table_past_its_limit() {
    let one = UdpMember::start("one").await;
    let two = UdpMember::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .udp()
        .algorithm("consistent_hash")
        .udp_session_limit(64);
    let running = Running::start_udp(&document, &[&one, &two]).await;

    // Four hundred distinct source ports against a table of sixty four.
    let mut clients = Vec::new();
    for _ in 0..400 {
        clients.push(UdpClient::open(running.port).await);
    }
    for (number, client) in clients.iter().enumerate() {
        client.tell(&format!("hello-{number}")).await;
    }

    let sessions = running
        .agent
        .wait_for_udp_sessions("web", 1)
        .await
        .expect("the frontend must report its table");
    assert!(
        sessions.count <= 64,
        "the table held {} sessions against a limit of 64",
        sessions.count
    );
    assert!(
        one.seen() + two.seen() > 0,
        "no datagram reached a member at all"
    );

    // The table survived it: a new client is still served.
    let fresh = UdpClient::open(running.port).await;
    let answer = fresh.ask("after").await.expect("it must answer");
    assert!(
        answer.ends_with(":after"),
        "the answer came back mangled: {answer}"
    );
}
