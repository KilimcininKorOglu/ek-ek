// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the UDP session table does.
//!
//! The traffic is measured over real sockets in `ek-ek`. What cannot be
//! measured there is the table's own behaviour at scale: ten thousand
//! clients, eviction order, and what one entry costs. Those are measured
//! directly here.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use ek_ek_dataplane::udp::{DEFAULT_IDLE_SECONDS, DEFAULT_SESSION_LIMIT, Sessions, session_memory};

/// A client address built from a number, so many distinct clients are cheap.
fn client(number: u32) -> SocketAddr {
    let octets = number.to_be_bytes();
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 1, octets[2], octets[3])),
        // The port varies too, because two clients behind one NAT differ
        // only there.
        30_000 + u16::try_from(number % 5_000).unwrap_or(0),
    )
}

/// A member address, used only so an entry has one.
fn member_address(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), 53)
}

/// Puts one session in, standing in for a socket with a number.
fn put(table: &mut Sessions<u32>, number: u32, member: &str, now: Instant) {
    drop(table.insert(
        client(number),
        "dns".to_owned(),
        member.to_owned(),
        member_address(1),
        number,
        now,
    ));
}

#[test]
fn a_client_keeps_the_session_it_was_given() {
    let mut table: Sessions<u32> = Sessions::new(10, 60);
    let now = Instant::now();
    put(&mut table, 1, "one", now);

    let found = table
        .refresh(client(1), now)
        .expect("the client must have a session");

    assert_eq!(found.member, "one");
    assert_eq!(table.len(), 1);
}

#[test]
fn a_client_that_was_never_seen_has_no_session() {
    let mut table: Sessions<u32> = Sessions::new(10, 60);
    let now = Instant::now();
    put(&mut table, 1, "one", now);

    assert!(table.refresh(client(2), now).is_none());
}

#[test]
fn the_table_never_holds_more_than_its_limit() {
    let mut table: Sessions<u32> = Sessions::new(4, 60);
    let now = Instant::now();

    for number in 1..=20 {
        put(&mut table, number, "one", now);
        assert!(
            table.len() <= 4,
            "the table held {} entries against a limit of 4",
            table.len()
        );
    }

    assert_eq!(table.len(), 4);
    assert_eq!(
        table.evicted(),
        16,
        "every insert past the limit evicts one"
    );
}

#[test]
fn the_session_used_longest_ago_is_the_one_evicted() {
    let mut table: Sessions<u32> = Sessions::new(3, 60);
    let now = Instant::now();
    put(&mut table, 1, "one", now);
    put(&mut table, 2, "two", now);
    put(&mut table, 3, "three", now);

    // Client 1 is used again, so client 2 becomes the oldest.
    table.refresh(client(1), now).expect("client 1 must be in");

    put(&mut table, 4, "four", now);

    assert!(
        table.refresh(client(2), now).is_none(),
        "the least recently used session survived"
    );
    assert!(
        table.refresh(client(1), now).is_some(),
        "a session used a moment ago was evicted"
    );
    assert!(table.refresh(client(3), now).is_some());
    assert!(table.refresh(client(4), now).is_some());
}

#[test]
fn nothing_is_evicted_while_there_is_room() {
    // The other side of the rule. Evicting early would move clients that had
    // no reason to move.
    let mut table: Sessions<u32> = Sessions::new(100, 60);
    let now = Instant::now();

    for number in 1..=100 {
        put(&mut table, number, "one", now);
    }

    assert_eq!(table.len(), 100);
    assert_eq!(table.evicted(), 0, "the table evicted while it had room");
}

#[test]
fn a_client_that_comes_back_does_not_evict_anybody() {
    // Re-inserting an address that is already there replaces its entry, so
    // the table does not grow and nothing has to leave.
    let mut table: Sessions<u32> = Sessions::new(3, 60);
    let now = Instant::now();
    put(&mut table, 1, "one", now);
    put(&mut table, 2, "two", now);
    put(&mut table, 3, "three", now);

    put(&mut table, 2, "two", now);

    assert_eq!(table.len(), 3);
    assert_eq!(table.evicted(), 0, "a returning client evicted somebody");
}

#[test]
fn a_session_that_has_sat_idle_too_long_is_dropped() {
    let mut table: Sessions<u32> = Sessions::new(10, 2);
    let started = Instant::now();
    put(&mut table, 1, "one", started);
    put(&mut table, 2, "two", started);

    // Client 2 keeps using its session; client 1 does not.
    let later = started + Duration::from_secs(3);
    table
        .refresh(client(2), later)
        .expect("client 2 must be in");

    let dropped = table.expire(later);

    assert_eq!(dropped.len(), 1, "the wrong number of sessions expired");
    assert_eq!(table.len(), 1);
    assert!(table.refresh(client(2), later).is_some());
    assert!(table.refresh(client(1), later).is_none());
    assert_eq!(table.expired(), 1);
}

#[test]
fn a_session_still_within_its_idle_window_is_kept() {
    // The other side. An idle sweep that dropped everything would break
    // every client that queries once a minute.
    let mut table: Sessions<u32> = Sessions::new(10, 60);
    let started = Instant::now();
    put(&mut table, 1, "one", started);

    let dropped = table.expire(started + Duration::from_secs(59));

    assert!(dropped.is_empty(), "a live session was dropped");
    assert_eq!(table.len(), 1);
    assert_eq!(table.expired(), 0);
}

#[test]
fn expiry_and_eviction_are_counted_apart() {
    // They mean different things to an operator: one says the traffic went
    // quiet, the other says the limit is too low.
    let mut table: Sessions<u32> = Sessions::new(2, 2);
    let started = Instant::now();
    put(&mut table, 1, "one", started);
    put(&mut table, 2, "two", started);
    put(&mut table, 3, "three", started);

    assert_eq!(table.evicted(), 1);
    assert_eq!(table.expired(), 0);

    drop(table.expire(started + Duration::from_secs(3)));

    assert_eq!(table.evicted(), 1, "expiry was counted as eviction");
    assert_eq!(table.expired(), 2, "eviction was counted as expiry");
}

#[test]
fn clearing_the_table_returns_everything_that_was_in_it() {
    let mut table: Sessions<u32> = Sessions::new(10, 60);
    let now = Instant::now();
    for number in 1..=5 {
        put(&mut table, number, "one", now);
    }

    let emptied = table.clear();

    assert_eq!(emptied.len(), 5, "clearing lost sessions");
    assert!(table.is_empty());
    assert!(table.refresh(client(1), now).is_none());
}

#[test]
fn a_session_whose_member_left_is_dropped_and_the_others_stay() {
    let mut table: Sessions<u32> = Sessions::new(10, 60);
    let now = Instant::now();
    put(&mut table, 1, "staying", now);
    put(&mut table, 2, "leaving", now);
    put(&mut table, 3, "staying", now);

    let dropped = table.retain_members(|pool, member| pool == "dns" && member != "leaving");

    assert_eq!(dropped.len(), 1, "the wrong number of sessions was dropped");
    assert_eq!(dropped[0].member, "leaving");
    assert_eq!(table.len(), 2, "a session of a member that stayed was lost");
    assert!(table.refresh(client(1), now).is_some());
    assert!(table.refresh(client(3), now).is_some());
}

#[test]
fn ten_thousand_clients_fit_and_stay_within_the_memory_the_limit_names() {
    let count = 10_000_u32;
    let mut table: Sessions<u32> = Sessions::new(count, 3_600);
    let now = Instant::now();

    let mut addresses = BTreeSet::new();
    for number in 1..=count {
        addresses.insert(client(number));
        put(&mut table, number, "one", now);
    }

    assert_eq!(
        addresses.len(),
        count as usize,
        "the test did not produce ten thousand distinct clients"
    );
    assert_eq!(table.len(), count as usize, "the table lost clients");
    assert_eq!(table.evicted(), 0, "the table evicted while it had room");

    // Every client is still pinned to what it was given, so the table did
    // not mix entries up under load.
    for number in 1..=count {
        let session = table
            .refresh(client(number), now)
            .unwrap_or_else(|| panic!("client {number} lost its session"));
        assert_eq!(session.socket, number, "client {number} holds another's");
    }

    // The memory this costs is bounded by what one entry costs times the
    // limit. The number the default comes from is measured, not guessed.
    let one = session_memory::<u32>();
    let total = one * count as usize;
    assert!(
        total < 4 * 1024 * 1024,
        "ten thousand sessions cost {total} bytes at {one} each"
    );
}

#[test]
fn the_default_limit_is_the_documented_one() {
    // Zero means the default, which is what an operator who set nothing
    // gets. A test that only ever passed an explicit limit would not show
    // that the default is reachable at all.
    let table: Sessions<u32> = Sessions::new(0, 0);

    assert_eq!(table.limit(), DEFAULT_SESSION_LIMIT as usize);
    assert_eq!(
        table.idle_limit(),
        Duration::from_secs(u64::from(DEFAULT_IDLE_SECONDS))
    );
    assert_eq!(DEFAULT_SESSION_LIMIT, 16_384);
    assert_eq!(DEFAULT_IDLE_SECONDS, 120);
}

#[test]
fn the_default_limit_fits_the_memory_it_claims() {
    // The doc comment on `DEFAULT_SESSION_LIMIT` names a figure. This is
    // where that figure is measured, so it cannot drift from the constant.
    let one = session_memory::<u32>();
    let total = one * DEFAULT_SESSION_LIMIT as usize;

    assert!(
        total < 8 * 1024 * 1024,
        "the default limit costs {total} bytes at {one} each"
    );
}

#[test]
fn a_configuration_change_moves_the_limit_and_evicts_down_to_it() {
    let mut table: Sessions<u32> = Sessions::new(10, 60);
    let now = Instant::now();
    for number in 1..=10 {
        put(&mut table, number, "one", now);
    }

    let evicted = table.retune(4, 30);

    assert_eq!(table.limit(), 4);
    assert_eq!(table.idle_limit(), Duration::from_secs(30));
    assert_eq!(
        evicted.len(),
        6,
        "the table did not shrink to its new limit"
    );
    assert_eq!(table.len(), 4);
    // The ones that survived are the ones used most recently.
    for number in 7..=10 {
        assert!(
            table.refresh(client(number), now).is_some(),
            "client {number} was evicted although it was recent"
        );
    }
}

#[test]
fn raising_the_limit_evicts_nobody() {
    let mut table: Sessions<u32> = Sessions::new(4, 60);
    let now = Instant::now();
    for number in 1..=4 {
        put(&mut table, number, "one", now);
    }

    let evicted = table.retune(100, 60);

    assert!(evicted.is_empty(), "raising the limit evicted sessions");
    assert_eq!(table.len(), 4);
}
