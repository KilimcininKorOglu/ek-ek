// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The VRRPv3 advertisement, as RFC 5798 lays it out.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |(rsvd) |     Max Adver Int     |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       IPvX Address(es)                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Why the checksum needs both ends
//!
//! Version 3 covers a pseudo header holding the source and destination
//! addresses, which version 2 did not. A packet sent to two peers therefore
//! carries two different checksums and has to be encoded once per peer. Our
//! own code would never notice the difference, because it does not check what
//! it receives against the sender's addresses; every other implementation
//! does, and would drop the packet (T-010).
//!
//! # Reading what arrived
//!
//! Everything here reads raw, unauthenticated network data. A malformed
//! packet is refused, never trusted and never a panic: a panic in the node
//! agent takes the VIP with it.

use std::net::Ipv4Addr;

/// The IP protocol number VRRP travels under.
pub const PROTOCOL: u8 = 112;

/// The version this product speaks.
pub const VERSION: u8 = 3;
/// The only type RFC 5798 defines.
pub const ADVERTISEMENT: u8 = 1;

/// Bytes before the addresses begin.
const HEADER: usize = 8;
/// Bytes one IPv4 address takes.
const ADDRESS: usize = 4;

/// A priority saying the sender is giving up the role on purpose.
///
/// A backup that hears it waits only its skew time rather than the whole
/// master down interval, so a planned handover does not wait out a timeout.
pub const GIVING_UP: u8 = 0;

/// What went wrong with a packet that arrived.
///
/// Named rather than collapsed into one error, because "too short" and
/// "wrong version" send an operator to different places.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// Fewer bytes than a header needs.
    TooShort,
    /// A version this product does not speak.
    Version(u8),
    /// A type RFC 5798 does not define.
    Type(u8),
    /// The address count does not match the bytes that followed.
    AddressCount,
    /// The checksum does not cover these bytes.
    Checksum,
}

/// One advertisement, decoded or waiting to be encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertisement {
    /// Which virtual router this belongs to.
    pub vrid: u8,
    /// How strongly the sender claims the role.
    pub priority: u8,
    /// How often the sender advertises, in centiseconds.
    ///
    /// Centiseconds because the field is twelve bits wide and that is the
    /// unit RFC 5798 gives it. A 300 millisecond interval is 30 here.
    pub interval_centiseconds: u16,
    /// The addresses this virtual router answers for.
    pub addresses: Vec<Ipv4Addr>,
}

impl Advertisement {
    /// The bytes to put on the wire towards one peer.
    ///
    /// The destination is taken because the checksum covers it. Sending the
    /// same bytes to a second peer would carry a checksum that peer refuses.
    #[must_use]
    pub fn encode(&self, from: Ipv4Addr, to: Ipv4Addr) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER + self.addresses.len() * ADDRESS);
        bytes.push((VERSION << 4) | ADVERTISEMENT);
        bytes.push(self.vrid);
        bytes.push(self.priority);
        // Cast rather than checked: a virtual router with more than 255
        // addresses cannot be built, because the field is one byte wide.
        bytes.push(u8::try_from(self.addresses.len()).unwrap_or(u8::MAX));
        // Four reserved bits, then twelve of interval. The reserved bits are
        // sent as zero and ignored on the way in.
        //
        // Held to the largest that fits rather than masked: masking turns an
        // interval of 4096 centiseconds into one of zero, and a receiver has
        // no way to tell that apart from a sender that meant it. The same
        // ceiling is applied where the value is computed, so nothing reaching
        // here is over it.
        let interval = if self.interval_centiseconds > 0x0FFF {
            0x0FFF
        } else {
            self.interval_centiseconds
        };
        bytes.push(u8::try_from(interval >> 8).unwrap_or(0));
        bytes.push(u8::try_from(interval & 0xFF).unwrap_or(0));
        // Zero while the sum is taken, then written over.
        bytes.push(0);
        bytes.push(0);
        for address in &self.addresses {
            bytes.extend_from_slice(&address.octets());
        }

        let sum = checksum(&bytes, from, to);
        bytes[6] = u8::try_from(sum >> 8).unwrap_or(0);
        bytes[7] = u8::try_from(sum & 0xFF).unwrap_or(0);
        bytes
    }

    /// Reads an advertisement out of bytes that arrived.
    ///
    /// The addresses are needed because the checksum covers them, so a packet
    /// cannot be judged without knowing where it was going.
    ///
    /// # Errors
    ///
    /// Returns [`Malformed`] naming what the packet failed on. Nothing here
    /// panics whatever the bytes hold.
    pub fn decode(bytes: &[u8], from: Ipv4Addr, to: Ipv4Addr) -> Result<Self, Malformed> {
        if bytes.len() < HEADER {
            return Err(Malformed::TooShort);
        }
        let version = bytes[0] >> 4;
        if version != VERSION {
            return Err(Malformed::Version(version));
        }
        let kind = bytes[0] & 0x0F;
        if kind != ADVERTISEMENT {
            return Err(Malformed::Type(kind));
        }

        let count = bytes[3] as usize;
        let expected = HEADER + count * ADDRESS;
        if bytes.len() != expected {
            return Err(Malformed::AddressCount);
        }

        // Taken over the packet as it arrived: the field itself is part of
        // the sum, and a correct packet sums to zero.
        if checksum(bytes, from, to) != 0 {
            return Err(Malformed::Checksum);
        }

        let addresses = bytes[HEADER..]
            .chunks_exact(ADDRESS)
            .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
            .collect();

        Ok(Self {
            vrid: bytes[1],
            priority: bytes[2],
            interval_centiseconds: (u16::from(bytes[4] & 0x0F) << 8) | u16::from(bytes[5]),
            addresses,
        })
    }
}

/// The one's complement sum RFC 5798 asks for, pseudo header and all.
///
/// Returns zero for a packet whose checksum already covers it, which is what
/// makes the same function usable on the way in and on the way out.
fn checksum(message: &[u8], from: Ipv4Addr, to: Ipv4Addr) -> u16 {
    let mut sum: u32 = 0;

    // The pseudo header: both addresses, the length, and the protocol. Its
    // bytes are summed and never sent.
    for address in [from, to] {
        let octets = address.octets();
        sum += u32::from(u16::from_be_bytes([octets[0], octets[1]]));
        sum += u32::from(u16::from_be_bytes([octets[2], octets[3]]));
    }
    let length = u32::try_from(message.len()).unwrap_or(u32::MAX);
    sum += length >> 16;
    sum += length & 0xFFFF;
    sum += u32::from(PROTOCOL);

    let mut pairs = message.chunks_exact(2);
    for pair in &mut pairs {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    // An odd length is padded on the right, as RFC 1071 says. A well formed
    // advertisement is never odd; a malformed one that arrives must still be
    // judged rather than crash the sum.
    if let [last] = pairs.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // Cast is exact: the loop above leaves nothing above sixteen bits.
    !u16::try_from(sum & 0xFFFF).unwrap_or(0)
}
