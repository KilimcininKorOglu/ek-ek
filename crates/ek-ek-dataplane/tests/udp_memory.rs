// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a UDP session table actually costs.
//!
//! The default limit is derived from this measurement rather than from a
//! guess. Every allocation this binary makes is counted, so the number
//! includes what the strings and the map cost, not only the size of the
//! structure.
//!
//! It lives in its own test binary because the counter is a global
//! allocator: another test allocating in parallel would be counted too.

// Counting allocations means implementing `GlobalAlloc`, which is an unsafe
// trait. Every call here is forwarded to the system allocator unchanged, and
// this is test-only code: it is the only way to measure what a session
// actually costs rather than guess at it.
#![allow(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ek_ek_dataplane::udp::{DEFAULT_SESSION_LIMIT, Sessions};

/// How many bytes are held right now.
static HELD: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, with a running total.
struct Counting;

// SAFETY: every call is forwarded to the system allocator unchanged; the
// counter only observes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HELD.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        HELD.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn client(number: u32) -> SocketAddr {
    let octets = number.to_be_bytes();
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 1, octets[2], octets[3])),
        30_000 + u16::try_from(number % 5_000).unwrap_or(0),
    )
}

#[test]
fn a_full_table_stays_inside_the_memory_the_default_limit_promises() {
    let count = 10_000_u32;
    let now = Instant::now();
    let before = HELD.load(Ordering::Relaxed);

    let mut table: Sessions<u32> = Sessions::new(count, 3_600);
    for number in 1..=count {
        drop(table.insert(
            client(number),
            "dns".to_owned(),
            format!("member-{}", number % 8),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53),
            number,
            now,
        ));
    }

    let held = HELD.load(Ordering::Relaxed).saturating_sub(before);
    let each = held / count as usize;
    assert_eq!(table.len(), count as usize, "the table lost clients");

    // Printed so the number behind the default is visible rather than
    // asserted blind.
    println!("ten thousand sessions hold {held} bytes, {each} bytes each");

    assert!(
        each < 512,
        "one session costs {each} bytes, far above what the default limit assumes"
    );

    // What the default limit would cost at this rate. The doc comment on
    // `DEFAULT_SESSION_LIMIT` claims a few megabytes; this is where that
    // claim is measured.
    let at_default = each * DEFAULT_SESSION_LIMIT as usize;
    assert!(
        at_default < 16 * 1024 * 1024,
        "the default limit would hold {at_default} bytes"
    );

    // Emptying the table gives the memory back, so a table that filled once
    // does not stay large forever.
    drop(table.clear());
    drop(table);
    let after = HELD.load(Ordering::Relaxed).saturating_sub(before);
    assert!(
        after < held / 4,
        "clearing the table gave back only {} of {held} bytes",
        held - after
    );
}
