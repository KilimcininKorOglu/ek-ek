// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The parser against bytes nobody meant it to read.
//!
//! An advertisement arrives from the network with no authentication of any
//! kind. Anything on the segment can send anything at all, and a panic in the
//! node agent takes the virtual address down with it. So the measurement is
//! not "does it parse", it is "does it survive".
//!
//! The generator is deterministic: the same seed produces the same bytes
//! every run. A fuzz test that found a fault on a Tuesday and could not be
//! made to find it again would be worse than none.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use ek_ek_vrrp::{Advertisement, Machine, Settings};

/// The sender in every measurement here, and a peer of the machine.
const FROM: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 11);
/// Where a packet is addressed.
const TO: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 100);

/// How many packets one round throws at the parser.
const ROUNDS: usize = 20_000;

/// A generator that repeats exactly, run after run.
///
/// Written out rather than taken from a crate, because a fuzz test that
/// depends on a random source it does not control cannot be replayed.
struct Bytes(u64);

impl Bytes {
    /// The next number in the sequence.
    fn next(&mut self) -> u64 {
        // Xorshift64. Small, and its only requirement here is that it does
        // not repeat quickly.
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number below a bound.
    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    /// A packet of arbitrary length and content.
    fn packet(&mut self) -> Vec<u8> {
        // Zero length included on purpose: an empty packet is what a closed
        // socket hands over, and it has to be refused rather than indexed.
        let length = self.below(40);
        (0..length).map(|_| self.below(256) as u8).collect()
    }

    /// A packet that starts as a real advertisement and is then damaged.
    ///
    /// Bytes drawn at random almost never get past the version check, so
    /// most of the parser would never run. These reach further in.
    fn damaged(&mut self) -> Vec<u8> {
        let mut bytes = Advertisement {
            vrid: 51,
            priority: 200,
            interval_centiseconds: 30,
            addresses: vec![TO],
        }
        .encode(FROM, TO);

        let damage = 1 + self.below(4);
        for _ in 0..damage {
            let at = self.below(bytes.len());
            bytes[at] ^= 1 << self.below(8);
        }
        // Sometimes cut it short, which is what a truncated read produces.
        if self.below(4) == 0 {
            let keep = self.below(bytes.len() + 1);
            bytes.truncate(keep);
        }
        bytes
    }
}

#[test]
fn the_parser_survives_bytes_drawn_at_random() {
    let mut source = Bytes(0x5EED_1234_ABCD_9876);
    let mut parsed = 0;
    let mut refused = 0;

    for _ in 0..ROUNDS {
        let bytes = source.packet();
        match Advertisement::decode(&bytes, FROM, TO) {
            Ok(_) => parsed += 1,
            Err(_) => refused += 1,
        }
    }

    assert_eq!(parsed + refused, ROUNDS, "every packet was judged");
    assert!(
        refused > 0,
        "bytes drawn at random must not all be accepted"
    );
}

#[test]
fn the_parser_survives_a_real_packet_that_has_been_damaged() {
    let mut source = Bytes(0xC0FF_EE00_1234_5678);
    let mut parsed = 0;
    let mut refused = 0;

    for _ in 0..ROUNDS {
        let bytes = source.damaged();
        match Advertisement::decode(&bytes, FROM, TO) {
            Ok(_) => parsed += 1,
            Err(_) => refused += 1,
        }
    }

    assert_eq!(parsed + refused, ROUNDS);
    assert!(
        refused > ROUNDS / 2,
        "damaging a packet must usually break it; {refused} of {ROUNDS} were refused"
    );
}

#[test]
fn the_generator_really_produces_packets_the_parser_has_to_work_at() {
    // Without this the two measurements above would pass against a generator
    // that only ever produced an empty packet, refused at the first line.
    //
    // What is counted is how far into the parser each packet reached, by the
    // reason it was refused for. A generator that never got past the version
    // check would be measuring one `if`.
    let mut source = Bytes(0xC0FF_EE00_1234_5678);
    let mut too_short = 0;
    let mut version = 0;
    let mut kind = 0;
    let mut count = 0;
    let mut checksum = 0;
    let mut accepted = 0;

    for _ in 0..ROUNDS {
        let bytes = source.damaged();
        match Advertisement::decode(&bytes, FROM, TO) {
            Err(ek_ek_vrrp::Malformed::TooShort) => too_short += 1,
            Err(ek_ek_vrrp::Malformed::Version(_)) => version += 1,
            Err(ek_ek_vrrp::Malformed::Type(_)) => kind += 1,
            Err(ek_ek_vrrp::Malformed::AddressCount) => count += 1,
            Err(ek_ek_vrrp::Malformed::Checksum) => checksum += 1,
            Ok(_) => accepted += 1,
        }
    }

    // Every refusal the parser can give is reached. The address count is the
    // one that matters most: it is the field a careless parser trusts and
    // then reads past the end of the buffer on.
    assert!(too_short > 0, "no packet was cut short");
    assert!(version > 0, "no packet had its version damaged");
    assert!(kind > 0, "no packet had its type damaged");
    assert!(
        count > 0,
        "no packet claimed more addresses than it carried"
    );
    assert!(checksum > 0, "no packet reached the checksum");
    // And some survive, so the generator is not simply producing rubbish.
    assert!(
        accepted > 0,
        "not one damaged packet stayed readable, so the generator only makes rubbish"
    );
}

#[test]
fn the_generator_repeats_exactly() {
    // A fault found once must be findable again.
    let first: Vec<Vec<u8>> = {
        let mut source = Bytes(0x1111_2222_3333_4444);
        (0..200).map(|_| source.packet()).collect()
    };
    let second: Vec<Vec<u8>> = {
        let mut source = Bytes(0x1111_2222_3333_4444);
        (0..200).map(|_| source.packet()).collect()
    };

    assert_eq!(first, second);
    assert!(
        first.iter().any(|bytes| !bytes.is_empty()),
        "the generator must produce something to parse"
    );
}

#[test]
fn the_state_machine_survives_the_same_bytes() {
    // The parser is not the only thing that reads a packet. The machine acts
    // on what it decoded, and a virtual router id or a priority nobody
    // expected must not move it anywhere strange.
    let start = Instant::now();
    let mut machine = Machine::new(Settings {
        vrid: 51,
        priority: 150,
        interval: Duration::from_millis(300),
        preempt: true,
        address: Ipv4Addr::new(172, 28, 0, 12),
        virtual_addresses: vec![TO],
        peers: vec![FROM],
    });
    machine.start(start);

    let mut source = Bytes(0xDEAD_BEEF_0000_1111);
    for round in 0..ROUNDS {
        let bytes = if round % 2 == 0 {
            source.packet()
        } else {
            source.damaged()
        };
        // Half from a peer, half from a stranger, so both paths run.
        let from = if round % 4 == 0 {
            Ipv4Addr::new(172, 28, 0, 99)
        } else {
            FROM
        };
        let _ = machine.receive(from, &bytes, start + Duration::from_millis(round as u64));
    }

    assert_eq!(
        machine.accepted() + machine.ignored(),
        ROUNDS as u64,
        "every packet was counted one way or the other"
    );
    assert!(machine.ignored() > 0, "most of that was not readable");
}
