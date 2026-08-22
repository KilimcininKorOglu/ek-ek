// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stepping over the IPv4 header a raw socket hands back.
//!
//! A raw socket delivers the IP header along with the payload, so a read has
//! to find where the advertisement begins. The header length is in the low
//! nibble of the first byte, counted in four byte words, and it comes from the
//! network like everything else around it: a packet claiming a header longer
//! than the bytes that arrived is refused rather than indexed into.
//!
//! Kept apart from the socket, and off the platform gate, because the rule is
//! about bytes rather than about Linux. Behind the gate it would only be
//! measured where the socket can be opened, which is not where the code is
//! written.

use std::net::Ipv4Addr;

/// The shortest IPv4 header, in bytes.
const SHORTEST: usize = 20;

/// The source address an IPv4 header names.
///
/// Returns nothing for anything too short to hold one, so a truncated read is
/// dropped rather than read past.
///
/// The sender is taken from here rather than from the socket, which keeps the
/// read safe: the alternative fills an address structure of uninitialised
/// bytes and needs `unsafe` to look at it. The kernel fills it from this same
/// header, so nothing is lost.
#[must_use]
pub fn sender(bytes: &[u8]) -> Option<Ipv4Addr> {
    let octets = bytes.get(12..16)?;
    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

/// The bytes after the IPv4 header.
///
/// Returns nothing when the header says it is longer than what arrived, which
/// is what a truncated or forged packet looks like.
#[must_use]
pub fn payload(bytes: &[u8]) -> Option<&[u8]> {
    let first = *bytes.first()?;
    // The low nibble counts 32 bit words, so the shortest header is five
    // words, or twenty bytes.
    let header = (first & 0x0F) as usize * 4;
    if header < SHORTEST {
        return None;
    }
    // No upper check: a range past the end is what `get` returns nothing for,
    // and a second test of the same thing would be a branch no measurement
    // could tell apart from its absence.
    bytes.get(header..)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{payload, sender};

    /// A header of the length given, followed by the payload given.
    fn packet(words: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![(4 << 4) | words];
        bytes.extend(std::iter::repeat_n(0, words as usize * 4 - 1));
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn the_payload_starts_after_the_header_the_packet_names() {
        assert_eq!(payload(&packet(5, &[0xAA, 0xBB])), Some(&[0xAA, 0xBB][..]));
        // And after a longer header, which is what a packet carrying options
        // arrives as.
        assert_eq!(payload(&packet(6, &[0xCC])), Some(&[0xCC][..]));
    }

    #[test]
    fn a_header_longer_than_the_packet_is_refused_rather_than_indexed() {
        // Fifteen words of header claimed, twenty one bytes delivered. A
        // parser that trusted the field would read past the end.
        let mut short = vec![0x4F];
        short.extend(std::iter::repeat_n(0, 20));
        assert_eq!(payload(&short), None);

        // One byte short of what the header claims, which is the boundary.
        let mut boundary = packet(5, &[]);
        boundary.pop();
        assert_eq!(boundary.len(), 19);
        assert_eq!(payload(&boundary), None);
        // And exactly what it claims, which is a header and no payload.
        assert_eq!(payload(&packet(5, &[])), Some(&[][..]));
    }

    #[test]
    fn a_header_shorter_than_ipv4_allows_is_refused() {
        // Four words claimed, which IPv4 does not allow, and enough bytes
        // delivered to cover them. Without the length there is nothing to
        // measure: a short packet is refused either way, by the bounds rather
        // than by the floor.
        let mut four_words = vec![(4 << 4) | 4];
        four_words.extend(std::iter::repeat_n(0, 19));
        assert_eq!(four_words.len(), 20, "long enough to hold what it claims");
        assert_eq!(payload(&four_words), None, "four words is not a header");

        // And one word more is, which is the other side of the floor.
        let mut five_words = four_words.clone();
        five_words[0] = (4 << 4) | 5;
        assert_eq!(payload(&five_words), Some(&[][..]));

        assert_eq!(payload(&[0x44, 0, 0, 0]), None);
        assert_eq!(payload(&[0x40, 0, 0, 0]), None);
        assert_eq!(payload(&[]), None);
    }

    #[test]
    fn the_sender_comes_out_of_the_header() {
        let mut bytes = vec![0x45];
        bytes.extend(std::iter::repeat_n(0, 11));
        bytes.extend_from_slice(&[172, 28, 0, 11]);
        bytes.extend(std::iter::repeat_n(0, 4));
        bytes.push(0xAA);

        assert_eq!(sender(&bytes), Some(Ipv4Addr::new(172, 28, 0, 11)));
        assert_eq!(sender(&[0, 1, 2]), None, "too short to hold one");
        // The boundary: fifteen bytes cannot hold the field, sixteen can.
        assert_eq!(sender(&bytes[..15]), None);
        assert_eq!(sender(&bytes[..16]), Some(Ipv4Addr::new(172, 28, 0, 11)));
    }
}
