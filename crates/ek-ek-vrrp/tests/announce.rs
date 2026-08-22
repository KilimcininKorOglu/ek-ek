// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What an announcement looks like on the wire.
//!
//! Every field is read out of the frame by index, against RFC 826 for ARP and
//! RFC 4861 for the neighbor advertisement. `tcpdump` reads the same bytes in
//! the integration measurement and prints what it made of them, which is the
//! independent reader; a frame our own code is happy with proves nothing.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::net::{Ipv4Addr, Ipv6Addr};

use ek_ek_vrrp::announce::MAC;
use ek_ek_vrrp::{Arp, arp, neighbor};

/// The address that moves.
const VIRTUAL: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 100);
/// The address of the node that now holds it.
const SENDER: [u8; MAC] = [0x02, 0x42, 0xAC, 0x1C, 0x00, 0x0C];

/// A two byte field, big endian, which is what a wire uses.
fn short(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

#[test]
fn a_gratuitous_arp_says_the_address_is_here_now() {
    let frame = arp(Arp::Request, VIRTUAL, SENDER);

    assert_eq!(frame.len(), 14 + 28, "an ethernet header and an ARP body");
    assert_eq!(&frame[0..6], &[0xFF; MAC], "everybody on the segment");
    assert_eq!(&frame[6..12], &SENDER, "from this node");
    assert_eq!(short(&frame, 12), 0x0806, "the ARP ethertype");

    let body = &frame[14..];
    assert_eq!(short(body, 0), 1, "ethernet");
    assert_eq!(short(body, 2), 0x0800, "IPv4");
    assert_eq!(body[4], 6, "six bytes of hardware address");
    assert_eq!(body[5], 4, "four bytes of protocol address");
    assert_eq!(short(body, 6), 1, "a request");
    assert_eq!(&body[8..14], &SENDER, "sender hardware address");
    assert_eq!(&body[14..18], &VIRTUAL.octets(), "sender protocol address");
    assert_eq!(&body[18..24], &[0; MAC], "a request addresses nobody yet");
    // This is what makes it gratuitous: the sender is asking about an address
    // it is also answering for.
    assert_eq!(
        &body[24..28],
        &VIRTUAL.octets(),
        "target protocol address is the same address"
    );
}

#[test]
fn the_reply_form_differs_only_where_it_has_to() {
    // Both forms are sent. RFC 5227 defines the gratuitous form as a request,
    // the spike measured a reply moving a cache, and stacks exist that act on
    // only one of the two (T-010).
    let request = arp(Arp::Request, VIRTUAL, SENDER);
    let reply = arp(Arp::Reply, VIRTUAL, SENDER);

    assert_eq!(short(&reply[14..], 6), 2, "a reply");
    assert_eq!(
        &reply[14 + 18..14 + 24],
        &SENDER,
        "a reply names the sender, because nobody asked the question"
    );
    // Everything up to the operation is the same frame.
    assert_eq!(&request[..14 + 6], &reply[..14 + 6]);
    assert_eq!(&request[14 + 8..14 + 18], &reply[14 + 8..14 + 18]);
}

#[test]
fn a_neighbor_advertisement_carries_the_override_flag() {
    let virtual_address = Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 100);
    let all_nodes = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 1);

    let frame = neighbor(virtual_address, SENDER);

    assert_eq!(frame.len(), 14 + 40 + 32);
    assert_eq!(
        &frame[0..6],
        &[0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
        "the hardware address of the all-nodes group"
    );
    assert_eq!(&frame[6..12], &SENDER);
    assert_eq!(short(&frame, 12), 0x86DD, "the IPv6 ethertype");

    let header = &frame[14..54];
    assert_eq!(header[0] >> 4, 6, "version six");
    assert_eq!(short(header, 4), 32, "the payload length");
    assert_eq!(header[6], 58, "ICMPv6");
    // RFC 4861 has a receiver drop anything lower, which is what stops an
    // advertisement that crossed a router from being believed.
    assert_eq!(header[7], 255, "the hop limit");
    assert_eq!(
        &header[8..24],
        &virtual_address.octets(),
        "from the address"
    );
    assert_eq!(&header[24..40], &all_nodes.octets(), "to everybody");

    let message = &frame[54..];
    assert_eq!(message[0], 136, "a neighbor advertisement");
    assert_eq!(message[1], 0);
    assert_eq!(message[4] & 0x80, 0, "this node is not a router");
    assert_eq!(
        message[4] & 0x40,
        0,
        "nobody asked, so the solicited flag would be a lie"
    );
    assert_eq!(
        message[4] & 0x20,
        0x20,
        "override, or a neighbour keeps what it already holds"
    );
    assert_eq!(&message[8..24], &virtual_address.octets(), "the target");
    assert_eq!(message[24], 2, "the target link-layer address option");
    assert_eq!(message[25], 1, "one unit of eight bytes");
    assert_eq!(&message[26..32], &SENDER);
}

#[test]
fn the_advertisement_checksum_covers_the_pseudo_header() {
    // Worked out here rather than taken from the encoder, so the two do not
    // agree by construction. A wrong checksum is dropped by every stack and
    // our own code would never notice, because nothing here reads one.
    let virtual_address = Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 100);
    let all_nodes = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 1);
    let frame = neighbor(virtual_address, SENDER);
    let message = &frame[54..];

    let mut sum: u32 = 0;
    for address in [virtual_address, all_nodes] {
        for pair in address.octets().chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
    }
    sum += message.len() as u32;
    sum += 58;
    for pair in message.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    assert_eq!(
        sum & 0xFFFF,
        0xFFFF,
        "a message carrying its own checksum sums to all ones"
    );
    assert_ne!(
        short(message, 2),
        0,
        "the checksum field really was written"
    );
}

#[test]
fn a_different_address_makes_a_different_checksum() {
    // The other side of the measurement above. A checksum that ignored the
    // message would pass it and be wrong for every frame.
    let first = neighbor(Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 100), SENDER);
    let second = neighbor(Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 101), SENDER);

    assert_ne!(&first[54 + 2..54 + 4], &second[54 + 2..54 + 4]);
}

#[test]
fn a_different_sender_makes_a_different_frame() {
    // The hardware address is the whole point of the announcement: it is what
    // every other machine puts in its cache.
    let other = [0x02, 0x42, 0xAC, 0x1C, 0x00, 0x0B];

    let mine = arp(Arp::Request, VIRTUAL, SENDER);
    let theirs = arp(Arp::Request, VIRTUAL, other);

    assert_ne!(mine, theirs);
    assert_eq!(&theirs[6..12], &other);
    assert_eq!(&theirs[14 + 8..14 + 14], &other);
}
