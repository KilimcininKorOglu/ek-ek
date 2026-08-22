// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ICMP echo request that asks the gateway whether it is still there.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     type      |     code      |           checksum            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         identifier            |        sequence number        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           payload                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! RFC 792. The identifier and the sequence number come back unchanged in the
//! reply, which is how an answer is matched to the question that caused it.
//! Every process on the machine reading a raw ICMP socket sees every reply,
//! so a reply to somebody else's question has to be told apart from ours.
//!
//! # Why the checksum is computed over the message alone
//!
//! ICMP for IPv4 carries no pseudo header, unlike ICMPv6 and unlike VRRP. The
//! sum covers the bytes below and nothing else, so one request is encoded once
//! however many gateways it is sent to.

/// An echo request, which asks.
pub const REQUEST: u8 = 8;
/// An echo reply, which answers.
pub const REPLY: u8 = 0;

/// Bytes of an echo message before its payload.
pub const HEADER: usize = 8;

/// What a reply said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    /// Which asker this belongs to.
    pub identifier: u16,
    /// Which question of that asker.
    pub sequence: u16,
}

/// The bytes of one echo request.
///
/// The payload is carried unchanged and comes back in the reply. It is there
/// because a request with none is legal but unusual, and some middleboxes
/// treat a zero length ICMP payload differently from a normal ping.
#[must_use]
pub fn request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.push(REQUEST);
    bytes.push(0);
    // Written as zero and filled in once the rest is there, because the sum
    // covers the field itself.
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&identifier.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(payload);

    let sum = checksum(&bytes);
    bytes[2..4].copy_from_slice(&sum.to_be_bytes());
    bytes
}

/// Reads an echo reply.
///
/// Returns nothing when the bytes are not a reply, when they are too short to
/// hold one, or when the checksum does not add up. A reply nobody can verify
/// is not evidence the gateway answered.
#[must_use]
pub fn reply(bytes: &[u8]) -> Option<Echo> {
    if *bytes.first()? != REPLY {
        return None;
    }
    if bytes.len() < HEADER {
        return None;
    }
    // The sum of a correct message including its own checksum field is zero.
    if checksum(bytes) != 0 {
        return None;
    }
    Some(Echo {
        identifier: u16::from_be_bytes([*bytes.get(4)?, *bytes.get(5)?]),
        sequence: u16::from_be_bytes([*bytes.get(6)?, *bytes.get(7)?]),
    })
}

/// Whether these bytes answer one particular question.
#[must_use]
pub fn answers(bytes: &[u8], identifier: u16, sequence: u16) -> bool {
    reply(bytes).is_some_and(|echo| echo.identifier == identifier && echo.sequence == sequence)
}

/// The ones complement sum RFC 1071 describes.
fn checksum(message: &[u8]) -> u16 {
    let mut sum: u32 = 0;
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
