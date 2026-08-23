// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reading the server name out of a TLS ClientHello, and nothing else.
//!
//! A passthrough frontend never opens the handshake: the client's certificate
//! has to reach the backend for mTLS to work at all (ADR-0027). So the one
//! thing read here is the name the client asked for, which is what says which
//! pool the connection belongs to.
//!
//! # What this never does
//!
//! It opens no socket and it waits for nothing. Everything is decided from the
//! bytes in hand, and [`Outcome::More`] is how it says the caller should read
//! again. That is what lets a fuzz measurement throw twenty thousand packets
//! at it without a single connection (ADR-0080).
//!
//! # Why nothing else is parsed
//!
//! The cipher list, the session id and the compression methods are walked past
//! by their lengths and never read. None of them decides anything here, and
//! every field a parser reads is a field it can be wrong about. This runs on
//! bytes from anybody who can open a connection.
//!
//! # What it never trusts
//!
//! A length. Every one of them arrives from the network, so each read asks
//! whether that many bytes are actually in hand before it takes them. Slicing
//! on a stated length is exactly how a parser reads past its buffer.

/// The TLS record type that carries a handshake.
const HANDSHAKE_RECORD: u8 = 22;

/// The handshake message type of a ClientHello.
const CLIENT_HELLO: u8 = 1;

/// The extension that carries the server name (RFC 6066).
const SERVER_NAME_EXTENSION: u16 = 0;

/// The name type inside that extension: a DNS host name.
const HOST_NAME: u8 = 0;

/// The longest a server name may be (RFC 6066).
///
/// Checked before anything is allocated, so a length that claims more than
/// this costs nothing.
pub const MOST_NAME_BYTES: usize = 255;

/// The most bytes ever read while waiting for a ClientHello.
///
/// One TLS record's body is at most 16384 bytes and the header is five more.
/// A ClientHello larger than one record is legal and vanishingly rare, and
/// letting the wait grow without a bound is what a slow connection attack
/// spends (ADR-0080).
pub const MOST_HELLO_BYTES: usize = 16_384 + 5;

/// What the bytes in hand turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The client asked for this name.
    Named(String),
    /// A ClientHello with no server name in it, which is what an old client
    /// and a monitoring tool connecting by address both send.
    Nameless,
    /// Not enough has arrived yet. Read again.
    More,
    /// Whatever this is, it is not a TLS handshake.
    NotAHandshake,
}

/// Reads the server name out of a ClientHello.
///
/// Every unreadable shape ends as [`Outcome::NotAHandshake`] rather than as a
/// panic, because these bytes come from anybody who can open a connection.
#[must_use]
pub fn read(bytes: &[u8]) -> Outcome {
    let mut at = Cursor::new(bytes);

    // The record header: type, two version bytes, then the body length.
    let Some(kind) = at.byte() else {
        return Outcome::More;
    };
    if kind != HANDSHAKE_RECORD {
        // An HTTP request, a PROXY header or anything else that is not TLS.
        // Refused here rather than later, because a passthrough frontend has
        // nothing to do with a connection that never becomes a handshake.
        return Outcome::NotAHandshake;
    }
    if at.skip(2).is_none() {
        return Outcome::More;
    }
    let Some(record_length) = at.short() else {
        return Outcome::More;
    };
    if record_length == 0 {
        return Outcome::NotAHandshake;
    }
    // The body has to be here before anything inside it is read. A shorter
    // read is a record split across segments, which is normal.
    if at.left() < usize::from(record_length) {
        return Outcome::More;
    }

    // The handshake header: type, then a three byte length.
    let Some(message) = at.byte() else {
        return Outcome::More;
    };
    if message != CLIENT_HELLO {
        // A handshake record that is not a ClientHello. On a fresh connection
        // there is nothing else it could legitimately be.
        return Outcome::NotAHandshake;
    }
    if at.skip(3).is_none() {
        return Outcome::More;
    }

    // The client's version, then thirty two bytes of randomness.
    if at.skip(2 + 32).is_none() {
        return Outcome::More;
    }
    // Session id, cipher suites, compression methods. Walked past by their
    // lengths; not one of them decides anything here.
    if at.skip_byte_vector().is_none() {
        return Outcome::More;
    }
    if at.skip_short_vector().is_none() {
        return Outcome::More;
    }
    if at.skip_byte_vector().is_none() {
        return Outcome::More;
    }

    // Extensions are optional. A ClientHello that stops here carries no
    // server name, which is a case of its own rather than a fault.
    let Some(extensions_length) = at.short() else {
        return Outcome::Nameless;
    };
    let Some(mut extensions) = at.slice(usize::from(extensions_length)) else {
        return Outcome::More;
    };

    while let Some(kind) = extensions.short() {
        let Some(length) = extensions.short() else {
            return Outcome::NotAHandshake;
        };
        let Some(body) = extensions.slice(usize::from(length)) else {
            return Outcome::NotAHandshake;
        };
        if kind == SERVER_NAME_EXTENSION {
            return name_in(body);
        }
    }

    Outcome::Nameless
}

/// Reads the host name out of a server name extension.
fn name_in(mut body: Cursor<'_>) -> Outcome {
    // The extension holds a list, and the list has its own length.
    let Some(list_length) = body.short() else {
        return Outcome::Nameless;
    };
    let Some(mut list) = body.slice(usize::from(list_length)) else {
        return Outcome::NotAHandshake;
    };

    while let Some(kind) = list.byte() {
        let Some(length) = list.short() else {
            return Outcome::NotAHandshake;
        };
        let length = usize::from(length);
        if kind != HOST_NAME {
            // Some other name type. Walked past rather than refused: the list
            // may still hold a host name after it.
            if list.slice(length).is_none() {
                return Outcome::NotAHandshake;
            }
            continue;
        }
        // Checked before the bytes are taken, so a length claiming more than
        // any name may be costs nothing at all.
        if length > MOST_NAME_BYTES {
            return Outcome::Nameless;
        }
        let Some(name) = list.slice(length) else {
            return Outcome::NotAHandshake;
        };
        // A name is host names only, so anything that is not text is not one.
        let Ok(text) = std::str::from_utf8(name.rest()) else {
            return Outcome::Nameless;
        };
        if text.is_empty() {
            return Outcome::Nameless;
        }
        return Outcome::Named(text.to_owned());
    }

    Outcome::Nameless
}

/// A position in a byte slice that never reads past the end.
///
/// Every method returns nothing rather than panicking when what it was asked
/// for is not there. That is the whole point: the lengths driving these reads
/// arrive from the network.
#[derive(Clone, Debug)]
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// How many bytes are left.
    const fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// Everything from here on.
    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }

    /// The next byte.
    fn byte(&mut self) -> Option<u8> {
        let held = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(held)
    }

    /// The next two bytes, as a number.
    fn short(&mut self) -> Option<u16> {
        let high = u16::from(self.byte_at(self.at)?);
        let low = u16::from(self.byte_at(self.at + 1)?);
        self.at += 2;
        Some((high << 8) | low)
    }

    /// One byte, without moving.
    fn byte_at(&self, at: usize) -> Option<u8> {
        self.bytes.get(at).copied()
    }

    /// Moves past `count` bytes, or nothing when they are not all there.
    fn skip(&mut self, count: usize) -> Option<()> {
        if self.left() < count {
            return None;
        }
        self.at += count;
        Some(())
    }

    /// Takes `count` bytes as a cursor of their own.
    fn slice(&mut self, count: usize) -> Option<Self> {
        if self.left() < count {
            return None;
        }
        let taken = &self.bytes[self.at..self.at + count];
        self.at += count;
        Some(Self::new(taken))
    }

    /// Moves past a vector whose length is one byte.
    fn skip_byte_vector(&mut self) -> Option<()> {
        let length = usize::from(self.byte()?);
        self.skip(length)
    }

    /// Moves past a vector whose length is two bytes.
    fn skip_short_vector(&mut self) -> Option<()> {
        let length = usize::from(self.short()?);
        self.skip(length)
    }
}
