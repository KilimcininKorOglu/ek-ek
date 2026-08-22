// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Telling the segment that an address moved.
//!
//! Adding the address to an interface changes nothing anybody else can see.
//! Every other machine keeps the old node's hardware address in its cache and
//! keeps sending frames there. The announcement is what changes that, and it
//! is the whole of a failover as far as a client is concerned (R-03).
//!
//! A killed master never removes its own address, so after a takeover the
//! address exists on two nodes at once. The cache is then the only thing
//! steering traffic, which is why this is measured apart from the address
//! (T-010).
//!
//! # What is sent
//!
//! For IPv4, both an ARP request and an ARP reply. RFC 5227 defines the
//! gratuitous form as a request, the spike measured a reply changing a cache,
//! and stacks exist that act on only one of the two. One frame more costs
//! nothing next to a failover nobody sees.
//!
//! For IPv6, an unsolicited neighbor advertisement with the override flag
//! set, which is what RFC 4861 section 7.2.6 asks for.
//!
//! Every frame is built whole, ethernet header included, because a packet
//! socket sends what it is given. Nothing here is host byte order: this goes
//! on a wire.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Bytes of an ethernet header.
const ETHERNET: usize = 14;
/// Bytes of a hardware address.
pub const MAC: usize = 6;

/// The ethertype ARP travels under.
const ARP: u16 = 0x0806;
/// The ethertype IPv6 travels under.
const IPV6: u16 = 0x86DD;

/// Ethernet, as a hardware type.
const HARDWARE_ETHERNET: u16 = 1;
/// IPv4, as a protocol type.
const PROTOCOL_IPV4: u16 = 0x0800;

/// The next header value of ICMPv6.
const ICMPV6: u8 = 58;
/// A neighbor advertisement.
const ADVERTISEMENT: u8 = 136;
/// The option carrying the sender's own hardware address.
const TARGET_LINK_ADDRESS: u8 = 2;

/// Everything on the segment.
const BROADCAST: [u8; MAC] = [0xFF; MAC];
/// Nobody, which is what a request puts where the answer would go.
const NOBODY: [u8; MAC] = [0; MAC];

/// The hardware address of the IPv6 all-nodes group.
///
/// Derived from `ff02::1`: the last four bytes of the address after the
/// `33:33` prefix RFC 2464 assigns to IPv6 multicast.
const ALL_NODES_MAC: [u8; MAC] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];

/// Which of the two ARP frames this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arp {
    /// Asks who holds the address, while already answering it.
    Request,
    /// Answers a question nobody asked.
    Reply,
}

impl Arp {
    /// The operation code this frame carries.
    const fn operation(self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
        }
    }

    /// What goes in the target hardware address field.
    ///
    /// A request has nobody to address yet, so the field is zero. A reply
    /// names the sender, because a reply to a question nobody asked has
    /// nowhere else to point.
    const fn target(self, sender: [u8; MAC]) -> [u8; MAC] {
        match self {
            Self::Request => NOBODY,
            Self::Reply => sender,
        }
    }
}

/// One gratuitous ARP frame, ethernet header included.
///
/// Both the sender and the target address are the virtual address. That is
/// what makes it gratuitous: it answers a question about an address the
/// sender is also asking about.
#[must_use]
pub fn arp(kind: Arp, virtual_address: Ipv4Addr, sender: [u8; MAC]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETHERNET + 28);
    frame.extend_from_slice(&BROADCAST);
    frame.extend_from_slice(&sender);
    frame.extend_from_slice(&ARP.to_be_bytes());

    frame.extend_from_slice(&HARDWARE_ETHERNET.to_be_bytes());
    frame.extend_from_slice(&PROTOCOL_IPV4.to_be_bytes());
    frame.push(u8::try_from(MAC).unwrap_or(6));
    frame.push(4);
    frame.extend_from_slice(&kind.operation().to_be_bytes());

    frame.extend_from_slice(&sender);
    frame.extend_from_slice(&virtual_address.octets());
    frame.extend_from_slice(&kind.target(sender));
    frame.extend_from_slice(&virtual_address.octets());
    frame
}

/// One unsolicited neighbor advertisement, ethernet header included.
///
/// The override flag is set, so a neighbour replaces what it already holds
/// rather than keeping it. Without it the advertisement only fills a cache
/// that was empty, which is not what a failover needs.
#[must_use]
pub fn neighbor(virtual_address: Ipv6Addr, sender: [u8; MAC]) -> Vec<u8> {
    let all_nodes = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 1);

    let mut message = Vec::with_capacity(32);
    message.push(ADVERTISEMENT);
    message.push(0);
    // Zero while the sum is taken, then written over.
    message.extend_from_slice(&[0, 0]);
    // Router off, solicited off, override on. An advertisement nobody asked
    // for is not an answer, so the solicited flag would be a lie.
    message.extend_from_slice(&0x2000_0000_u32.to_be_bytes());
    message.extend_from_slice(&virtual_address.octets());
    message.push(TARGET_LINK_ADDRESS);
    // Counted in units of eight bytes, and this option is exactly one.
    message.push(1);
    message.extend_from_slice(&sender);

    let sum = checksum(&message, virtual_address, all_nodes);
    message[2..4].copy_from_slice(&sum.to_be_bytes());

    let mut frame = Vec::with_capacity(ETHERNET + 40 + message.len());
    frame.extend_from_slice(&ALL_NODES_MAC);
    frame.extend_from_slice(&sender);
    frame.extend_from_slice(&IPV6.to_be_bytes());

    // Version six, no traffic class, no flow label.
    frame.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    frame.extend_from_slice(&u16::try_from(message.len()).unwrap_or(0).to_be_bytes());
    frame.push(ICMPV6);
    // 255 exactly. RFC 4861 has a receiver drop anything lower, which is what
    // stops an advertisement that crossed a router from being believed.
    frame.push(255);
    frame.extend_from_slice(&virtual_address.octets());
    frame.extend_from_slice(&all_nodes.octets());
    frame.extend_from_slice(&message);
    frame
}

/// The ICMPv6 checksum, pseudo header and all.
///
/// Returns zero for a message whose checksum already covers it, which is what
/// lets the same function measure one that arrived.
fn checksum(message: &[u8], from: Ipv6Addr, to: Ipv6Addr) -> u16 {
    let mut sum: u32 = 0;

    for address in [from, to] {
        for pair in address.octets().chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
    }
    let length = u32::try_from(message.len()).unwrap_or(u32::MAX);
    sum += length >> 16;
    sum += length & 0xFFFF;
    sum += u32::from(ICMPV6);

    let mut pairs = message.chunks_exact(2);
    for pair in &mut pairs {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    // An odd length is padded on the right, as RFC 1071 says.
    if let [last] = pairs.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum & 0xFFFF).unwrap_or(0)
}
