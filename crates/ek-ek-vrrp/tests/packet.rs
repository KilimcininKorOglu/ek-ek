// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What an advertisement looks like on the wire.
//!
//! Every field is read out of the bytes by index, against the layout in RFC
//! 5798. Decoding with our own parser and checking what came back would only
//! show that two halves of the same code agree, and a packet no other
//! implementation accepts would pass. `tcpdump` reads the same bytes in the
//! integration measurement, which is the independent reader.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::net::Ipv4Addr;

use ek_ek_vrrp::{ADVERTISEMENT, Advertisement, Malformed, PROTOCOL, VERSION};

/// The sender in every measurement here.
const FROM: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 11);
/// The address the packet is sent to.
const TO: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 12);
/// The address the virtual router answers for.
const VIRTUAL: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 100);

/// The advertisement the spike measured, field for field.
fn advertisement() -> Advertisement {
    Advertisement {
        vrid: 51,
        priority: 200,
        interval_centiseconds: 30,
        addresses: vec![VIRTUAL],
    }
}

#[test]
fn every_field_lands_where_rfc_5798_puts_it() {
    let bytes = advertisement().encode(FROM, TO);

    assert_eq!(bytes.len(), 12, "eight of header and one address of four");
    assert_eq!(bytes[0] >> 4, VERSION, "version three in the high nibble");
    assert_eq!(
        bytes[0] & 0x0F,
        ADVERTISEMENT,
        "type one in the low nibble; RFC 5798 defines no other"
    );
    assert_eq!(bytes[0], 0x31, "the two together are one byte");
    assert_eq!(bytes[1], 51, "virtual router id");
    assert_eq!(bytes[2], 200, "priority");
    assert_eq!(bytes[3], 1, "one address follows");
    assert_eq!(bytes[4] >> 4, 0, "the four reserved bits are sent as zero");
    // Twelve bits of interval, in centiseconds. 300 milliseconds is 30, which
    // is what tcpdump printed as "intvl 30cs" in the spike.
    assert_eq!(
        (u16::from(bytes[4] & 0x0F) << 8) | u16::from(bytes[5]),
        30,
        "interval in centiseconds"
    );
    assert_eq!(
        &bytes[8..12],
        &VIRTUAL.octets(),
        "the address follows the header"
    );
}

#[test]
fn the_checksum_covers_the_pseudo_header_and_sums_to_zero() {
    // RFC 5798 folds the source and destination into the sum, which version
    // two did not. Worked out here rather than taken from the encoder, so
    // the two do not agree by construction.
    let bytes = advertisement().encode(FROM, TO);

    let mut sum: u32 = 0;
    for address in [FROM, TO] {
        let octets = address.octets();
        sum += u32::from(u16::from_be_bytes([octets[0], octets[1]]));
        sum += u32::from(u16::from_be_bytes([octets[2], octets[3]]));
    }
    sum += bytes.len() as u32;
    sum += u32::from(PROTOCOL);
    for pair in bytes.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    assert_eq!(
        sum & 0xFFFF,
        0xFFFF,
        "a packet carrying its own checksum sums to all ones"
    );
    assert_ne!(
        u16::from_be_bytes([bytes[6], bytes[7]]),
        0,
        "the checksum field really was written"
    );
}

#[test]
fn the_same_advertisement_to_two_peers_carries_two_checksums() {
    // The reason unicast encodes once per peer. Sending one peer's bytes to
    // another would be refused by every implementation that checks, and
    // never noticed by ours (T-010).
    let other = Ipv4Addr::new(172, 28, 0, 13);

    let first = advertisement().encode(FROM, TO);
    let second = advertisement().encode(FROM, other);

    assert_ne!(
        &first[6..8],
        &second[6..8],
        "the destination is part of the sum, so the checksum must differ"
    );
    assert_eq!(
        &first[0..6],
        &second[0..6],
        "and nothing else about the packet changes"
    );
}

#[test]
fn a_packet_is_read_back_exactly_as_it_was_written() {
    let sent = advertisement();
    let bytes = sent.encode(FROM, TO);

    let read = Advertisement::decode(&bytes, FROM, TO).expect("our own packet must decode");

    assert_eq!(read, sent);
}

#[test]
fn a_packet_addressed_elsewhere_fails_its_checksum() {
    // The other side of the measurement above, and the reason a checksum is
    // worth taking at all.
    let bytes = advertisement().encode(FROM, TO);

    let read = Advertisement::decode(&bytes, FROM, Ipv4Addr::new(172, 28, 0, 13));

    assert_eq!(read, Err(Malformed::Checksum));
}

#[test]
fn a_priority_of_zero_still_encodes_and_reads_back() {
    // A master standing down sends this. It has to survive the trip, or a
    // planned handover falls back to a timeout (T-010).
    let giving_up = Advertisement {
        priority: ek_ek_vrrp::GIVING_UP,
        ..advertisement()
    };

    let bytes = giving_up.encode(FROM, TO);

    assert_eq!(bytes[2], 0);
    assert_eq!(Advertisement::decode(&bytes, FROM, TO), Ok(giving_up));
}

#[test]
fn several_addresses_are_counted_and_carried() {
    let many = Advertisement {
        addresses: vec![VIRTUAL, Ipv4Addr::new(172, 28, 0, 101)],
        ..advertisement()
    };

    let bytes = many.encode(FROM, TO);

    assert_eq!(bytes[3], 2, "the count field says two");
    assert_eq!(bytes.len(), 16, "eight of header and two addresses of four");
    assert_eq!(Advertisement::decode(&bytes, FROM, TO), Ok(many));
}

#[test]
fn a_packet_that_is_not_an_advertisement_is_refused() {
    let good = advertisement().encode(FROM, TO);

    // Too short to hold a header.
    assert_eq!(
        Advertisement::decode(&good[..4], FROM, TO),
        Err(Malformed::TooShort)
    );

    // A version this product does not speak.
    let mut wrong_version = good.clone();
    wrong_version[0] = (2 << 4) | ADVERTISEMENT;
    assert_eq!(
        Advertisement::decode(&wrong_version, FROM, TO),
        Err(Malformed::Version(2))
    );

    // A type RFC 5798 does not define.
    let mut wrong_type = good.clone();
    wrong_type[0] = (VERSION << 4) | 7;
    assert_eq!(
        Advertisement::decode(&wrong_type, FROM, TO),
        Err(Malformed::Type(7))
    );

    // A count that does not match the bytes that followed. This is the field
    // a careless parser reads and then indexes past the end of the buffer.
    let mut wrong_count = good.clone();
    wrong_count[3] = 40;
    assert_eq!(
        Advertisement::decode(&wrong_count, FROM, TO),
        Err(Malformed::AddressCount)
    );

    // One bit of the body flipped.
    let mut corrupted = good;
    corrupted[9] ^= 0x01;
    assert_eq!(
        Advertisement::decode(&corrupted, FROM, TO),
        Err(Malformed::Checksum)
    );
}

#[test]
fn the_interval_field_holds_twelve_bits_and_no_more() {
    // The high nibble of that byte is reserved. Writing an interval into it
    // would produce a packet another implementation reads as reserved bits
    // that are not zero.
    let widest = Advertisement {
        interval_centiseconds: 0x0FFF,
        ..advertisement()
    };

    let bytes = widest.encode(FROM, TO);

    assert_eq!(bytes[4] >> 4, 0, "the reserved nibble stays zero");
    assert_eq!(bytes[4] & 0x0F, 0x0F);
    assert_eq!(bytes[5], 0xFF);
    assert_eq!(
        Advertisement::decode(&bytes, FROM, TO)
            .expect("it decodes")
            .interval_centiseconds,
        0x0FFF
    );
}

#[test]
fn an_interval_too_wide_to_fit_is_held_at_the_widest_that_does() {
    // The measurement above uses a value that already fits, so it says
    // nothing about what happens to one that does not. This is the value the
    // reserved nibble would be written from.
    let over = Advertisement {
        interval_centiseconds: 0xABCD,
        ..advertisement()
    };

    let bytes = over.encode(FROM, TO);

    assert_eq!(
        bytes[4] >> 4,
        0,
        "the reserved nibble stays zero whatever the interval was"
    );
    let written = (u16::from(bytes[4] & 0x0F) << 8) | u16::from(bytes[5]);
    assert_eq!(
        written,
        0x0FFF,
        "held at the widest that fits, not wrapped down to {:#06X}",
        0xABCD_u16 & 0x0FFF
    );
    // And the boundary from the other side: masking would turn this one into
    // an interval of zero, which reads as a sender that meant zero.
    let just_over = Advertisement {
        interval_centiseconds: 0x1000,
        ..advertisement()
    };
    let bytes = just_over.encode(FROM, TO);
    assert_eq!(bytes[4] & 0x0F, 0x0F);
    assert_eq!(bytes[5], 0xFF);
}

#[test]
fn the_reserved_bits_are_ignored_on_the_way_in() {
    // RFC 5798 says a receiver ignores them. A packet from an implementation
    // that sets them must still be read, or interoperation depends on
    // everybody agreeing about bits nobody uses.
    let mut bytes = advertisement().encode(FROM, TO);
    bytes[4] |= 0xF0;
    // The checksum is taken again, because the packet as a whole changed.
    let repaired = repair(&mut bytes, FROM, TO);

    assert_eq!(
        Advertisement::decode(repaired, FROM, TO)
            .expect("the reserved bits must not stop it")
            .interval_centiseconds,
        30
    );
}

/// Writes a correct checksum over bytes a test has changed.
///
/// Needed because every measurement of a field has to reach the parser, and
/// the checksum would otherwise refuse the packet before the field is read.
fn repair(bytes: &mut [u8], from: Ipv4Addr, to: Ipv4Addr) -> &[u8] {
    bytes[6] = 0;
    bytes[7] = 0;
    let mut sum: u32 = 0;
    for address in [from, to] {
        let octets = address.octets();
        sum += u32::from(u16::from_be_bytes([octets[0], octets[1]]));
        sum += u32::from(u16::from_be_bytes([octets[2], octets[3]]));
    }
    sum += bytes.len() as u32;
    sum += u32::from(PROTOCOL);
    for pair in bytes.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    bytes[6] = (checksum >> 8) as u8;
    bytes[7] = (checksum & 0xFF) as u8;
    bytes
}
