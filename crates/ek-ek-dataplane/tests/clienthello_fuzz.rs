// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ClientHello parser against bytes nobody meant it to read.
//!
//! A passthrough listener is open to the internet and this parser is the first
//! code any connection reaches. Nothing has been authenticated at that point,
//! so anybody who can open a socket decides what these bytes are. A panic here
//! takes the traffic path down for every frontend on the node, so the
//! measurement is not "does it parse", it is "does it survive".
//!
//! The generator is deterministic: the same seed produces the same bytes every
//! run. A fuzz test that found a fault once and could not be made to find it
//! again would be worse than none (ADR-0080).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use ek_ek_dataplane::clienthello::{Outcome, read};

#[path = "common/hello.rs"]
mod hello;

use hello::Hello;

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
        // Zero length included on purpose: an accepted connection that has
        // sent nothing yet is exactly this, and it has to be asked for more
        // rather than indexed.
        let length = self.below(300);
        (0..length).map(|_| self.below(256) as u8).collect()
    }

    /// A packet that starts as a handshake record and is then filled with
    /// rubbish.
    ///
    /// Bytes drawn at random almost never get past the first byte, so nearly
    /// all of the parser would never run. These at least reach the record
    /// header.
    fn handshake_shaped(&mut self) -> Vec<u8> {
        let body: Vec<u8> = (0..self.below(300))
            .map(|_| self.below(256) as u8)
            .collect();
        let mut bytes = vec![hello::HANDSHAKE, 3, 1];
        bytes.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    /// A real ClientHello that has then been damaged.
    ///
    /// This is what reaches the length fields deep inside: the extension
    /// block, the name list, the name itself. Those are the fields a careless
    /// parser trusts and then reads past the end of its buffer on.
    fn damaged(&mut self) -> Vec<u8> {
        let mut bytes = Hello::named("posta.ornek.com")
            .after(0x000B, vec![0x01, 0x02, 0x03])
            .after(0x000A, vec![0xAA; 40])
            .bytes();

        let damage = 1 + self.below(6);
        for _ in 0..damage {
            let at = self.below(bytes.len());
            bytes[at] ^= 1 << self.below(8);
        }
        // Sometimes cut it short, which is what a half arrived record is.
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
    let mut judged = 0;

    for _ in 0..ROUNDS {
        // Any outcome at all is a pass here. What is measured is that the
        // call returns rather than panicking.
        let _ = read(&source.packet());
        judged += 1;
    }

    assert_eq!(judged, ROUNDS, "every packet was judged");
}

#[test]
fn the_parser_survives_a_record_full_of_rubbish() {
    let mut source = Bytes(0xC0FF_EE00_1234_5678);

    for _ in 0..ROUNDS {
        let _ = read(&source.handshake_shaped());
    }
}

#[test]
fn the_parser_survives_a_real_hello_that_has_been_damaged() {
    let mut source = Bytes(0xBEEF_0042_1357_9BDF);
    let mut named = 0;

    for _ in 0..ROUNDS {
        if let Outcome::Named(name) = read(&source.damaged()) {
            // A damaged hello may still carry a readable name, and that name
            // is then used as a routing key. It has to be a string, which
            // `Named` already guarantees, and it has to be bounded.
            assert!(
                name.len() <= 255,
                "a name longer than the RFC allows: {name:?}"
            );
            named += 1;
        }
    }

    assert!(
        named > 0,
        "not one damaged hello stayed readable, so the damage is too heavy to measure the deep path"
    );
}

#[test]
fn the_generator_really_reaches_into_the_parser() {
    // Without this the measurements above would pass against a generator that
    // only ever produced an empty packet, refused at the first line.
    //
    // What is counted is how far into the parser each packet reached, by the
    // outcome it produced. Every one of the four has to happen, because each
    // is a different depth: `More` stops at a length, `NotAHandshake` at a
    // shape, `Nameless` walks the whole extension block, and `Named` runs the
    // parser end to end.
    let mut source = Bytes(0xBEEF_0042_1357_9BDF);
    let mut named = 0;
    let mut nameless = 0;
    let mut more = 0;
    let mut not_a_handshake = 0;

    for _ in 0..ROUNDS {
        match read(&source.damaged()) {
            Outcome::Named(_) => named += 1,
            Outcome::Nameless => nameless += 1,
            Outcome::More => more += 1,
            Outcome::NotAHandshake => not_a_handshake += 1,
        }
    }

    assert_eq!(named + nameless + more + not_a_handshake, ROUNDS);
    assert!(named > 0, "no damaged hello ran the parser end to end");
    assert!(
        nameless > 0,
        "no damaged hello lost its name and kept its shape"
    );
    assert!(more > 0, "no damaged hello was cut short");
    assert!(not_a_handshake > 0, "no damaged hello was refused outright");
}

#[test]
fn the_generator_repeats_exactly() {
    // A fault found once must be findable again.
    let run = || {
        let mut source = Bytes(0x1111_2222_3333_4444);
        (0..200)
            .map(|_| (source.packet(), source.handshake_shaped(), source.damaged()))
            .collect::<Vec<_>>()
    };

    assert_eq!(run(), run());
    assert!(
        run().iter().any(|(packet, _, _)| !packet.is_empty()),
        "the generator must produce something to parse"
    );
}
