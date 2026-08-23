// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DNS messages, written and read by hand.
//!
//! Enough of RFC 1035 to ask for a TXT record and enough of RFC 2136 to write
//! one. Nothing here opens a socket, so every rule that matters is measurable
//! against bytes written in a test: what a name longer than the protocol
//! allows does, what a compression pointer that loops does, what a truncated
//! answer does.
//!
//! Names are held as text and encoded on the way out. Trailing dots are
//! ignored, so `example.org` and `example.org.` are the same name, which is
//! what an operator writing a zone into a configuration expects.

use crate::error::{Failure, Reason};

/// The internet class.
pub const CLASS_IN: u16 = 1;

/// The class that marks one record for deletion (RFC 2136 section 2.5.4).
pub const CLASS_NONE: u16 = 254;

/// The class that marks a whole set for deletion, and the one TSIG uses.
pub const CLASS_ANY: u16 = 255;

/// Start of authority, which is what an update names its zone with.
pub const TYPE_SOA: u16 = 6;

/// Text record.
pub const TYPE_TXT: u16 = 16;

/// Transaction signature (RFC 8945).
pub const TYPE_TSIG: u16 = 250;

/// The opcode of a dynamic update (RFC 2136).
pub const OPCODE_UPDATE: u8 = 5;

/// Longest a single label may be.
const MOST_LABEL: usize = 63;

/// Longest an encoded name may be, including every length byte and the root.
const MOST_NAME: usize = 255;

/// Longest a character string inside RDATA may be.
const MOST_STRING: usize = 255;

/// How many compression pointers one name may follow.
///
/// A pointer that leads to another pointer is legal. A pointer that leads
/// back to itself is a loop, and without this the reader would never return.
const MOST_POINTERS: usize = 16;

/// The header every DNS message starts with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Identity the answer carries back.
    pub id: u16,
    /// The flags word, opcode and rcode included.
    pub flags: u16,
    /// Questions, or the zone section of an update.
    pub counts: [u16; 4],
}

impl Header {
    /// The response code the flags carry.
    #[must_use]
    pub const fn rcode(self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    /// Whether this message is an answer rather than a request.
    #[must_use]
    pub const fn is_response(self) -> bool {
        self.flags & 0x8000 != 0
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        for count in self.counts {
            out.extend_from_slice(&count.to_be_bytes());
        }
    }

    fn read(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() < 12 {
            return Err(short());
        }
        let word = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        Ok(Self {
            id: word(0),
            flags: word(2),
            counts: [word(4), word(6), word(8), word(10)],
        })
    }
}

/// What a name means when it is written on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    /// As the caller wrote it.
    AsGiven,
    /// Lowercased, which is what a signature is computed over (RFC 8945).
    Canonical,
}

/// Appends a name in wire format.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when a label is empty or too long, or when the
/// whole name does not fit.
pub fn write_name(name: &str, case: Case, out: &mut Vec<u8>) -> Result<(), Failure> {
    let trimmed = name.trim_end_matches('.');
    let start = out.len();

    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() {
                return Err(Failure::new(
                    Reason::Protocol,
                    format!("{name} has an empty label"),
                ));
            }
            if label.len() > MOST_LABEL {
                return Err(Failure::new(
                    Reason::Protocol,
                    format!("a label of {name} is longer than {MOST_LABEL} bytes"),
                ));
            }
            // The length fits: it was just compared against 63.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the label is at most 63 bytes"
            )]
            out.push(label.len() as u8);
            match case {
                Case::AsGiven => out.extend_from_slice(label.as_bytes()),
                Case::Canonical => out.extend(label.bytes().map(|byte| byte.to_ascii_lowercase())),
            }
        }
    }
    out.push(0);

    if out.len() - start > MOST_NAME {
        return Err(Failure::new(
            Reason::Protocol,
            format!("{name} is longer than {MOST_NAME} bytes on the wire"),
        ));
    }
    Ok(())
}

/// Reads one name, following compression pointers.
///
/// Returns the name and where reading continues, which is past the pointer
/// rather than past what the pointer led to.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when the message ends inside the name or when
/// the pointers lead in a circle.
pub fn read_name(bytes: &[u8], from: usize) -> Result<(String, usize), Failure> {
    let mut name = String::new();
    let mut at = from;
    let mut after = None;
    let mut jumps = 0;

    loop {
        let length = *bytes.get(at).ok_or_else(short)?;
        if length & 0xC0 == 0xC0 {
            let low = *bytes.get(at + 1).ok_or_else(short)?;
            let target = usize::from(u16::from_be_bytes([length & 0x3F, low]));
            jumps += 1;
            if jumps > MOST_POINTERS {
                return Err(Failure::new(
                    Reason::Protocol,
                    "the name compression in this answer leads in a circle".to_owned(),
                ));
            }
            after.get_or_insert(at + 2);
            at = target;
            continue;
        }
        if length & 0xC0 != 0 {
            return Err(Failure::new(
                Reason::Protocol,
                "a label length in this answer uses a reserved form".to_owned(),
            ));
        }
        at += 1;
        if length == 0 {
            break;
        }
        let end = at + usize::from(length);
        let label = bytes.get(at..end).ok_or_else(short)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        at = end;
    }

    Ok((name, after.unwrap_or(at)))
}

/// One record an update adds or takes away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The name the record sits at.
    pub name: String,
    /// What kind of record it is.
    pub kind: u16,
    /// The class, which is what says whether this is an addition or a
    /// deletion in an update.
    pub class: u16,
    /// How long a resolver may hold it.
    pub ttl: u32,
    /// The record's own data, already encoded.
    pub data: Vec<u8>,
}

impl Record {
    /// A TXT record to add.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Protocol`] when the value does not fit one character
    /// string.
    pub fn add_txt(name: &str, value: &str, ttl: u32) -> Result<Self, Failure> {
        Ok(Self {
            name: name.to_owned(),
            kind: TYPE_TXT,
            class: CLASS_IN,
            ttl,
            data: txt_data(value)?,
        })
    }

    /// Every TXT record at one name, marked for deletion.
    ///
    /// The whole set rather than one value, so a record an earlier run left
    /// behind goes with it. The name exists for challenge answers and holds
    /// nothing else (ADR-0078).
    #[must_use]
    pub fn delete_txt_set(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            kind: TYPE_TXT,
            class: CLASS_ANY,
            ttl: 0,
            data: Vec::new(),
        }
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Failure> {
        write_name(&self.name, Case::AsGiven, out)?;
        out.extend_from_slice(&self.kind.to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let length = u16::try_from(self.data.len()).map_err(|_| {
            Failure::new(
                Reason::Protocol,
                "a record carries more data than one record can".to_owned(),
            )
        })?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

/// Encodes a TXT value as RDATA.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when the value is longer than one character
/// string holds. A challenge answer is 43 bytes, so this is a fault in what
/// was asked for rather than a limit anybody meets.
pub fn txt_data(value: &str) -> Result<Vec<u8>, Failure> {
    if value.len() > MOST_STRING {
        return Err(Failure::new(
            Reason::Protocol,
            format!("a TXT value longer than {MOST_STRING} bytes needs more than one string"),
        ));
    }
    let mut data = Vec::with_capacity(value.len() + 1);
    // The length fits: it was just compared against 255.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the value is at most 255 bytes"
    )]
    data.push(value.len() as u8);
    data.extend_from_slice(value.as_bytes());
    Ok(data)
}

/// Builds a dynamic update message (RFC 2136).
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when a name cannot be encoded.
pub fn update(id: u16, zone: &str, changes: &[Record]) -> Result<Vec<u8>, Failure> {
    let updates = u16::try_from(changes.len()).map_err(|_| {
        Failure::new(
            Reason::Protocol,
            "more changes than one update message holds".to_owned(),
        )
    })?;

    let mut message = Vec::new();
    Header {
        id,
        flags: u16::from(OPCODE_UPDATE) << 11,
        counts: [1, 0, updates, 0],
    }
    .write(&mut message);

    write_name(zone, Case::AsGiven, &mut message)?;
    message.extend_from_slice(&TYPE_SOA.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());

    for change in changes {
        change.write(&mut message)?;
    }
    Ok(message)
}

/// Builds a question for one record type at one name.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when the name cannot be encoded.
pub fn question(id: u16, name: &str, kind: u16) -> Result<Vec<u8>, Failure> {
    let mut message = Vec::new();
    Header {
        // Recursion desired. An authoritative server ignores it and a
        // resolver needs it, so one message serves both.
        id,
        flags: 0x0100,
        counts: [1, 0, 0, 0],
    }
    .write(&mut message);
    write_name(name, Case::AsGiven, &mut message)?;
    message.extend_from_slice(&kind.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(message)
}

/// Reads the header of a message.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when there is not even a header.
pub fn header(bytes: &[u8]) -> Result<Header, Failure> {
    Header::read(bytes)
}

/// Collects every TXT value in the answer section.
///
/// Records of other types are skipped, which is what a CNAME chain or a
/// signature alongside the answer produces.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when the message ends in the middle of a
/// record.
pub fn txt_answers(bytes: &[u8]) -> Result<Vec<String>, Failure> {
    let head = Header::read(bytes)?;
    let mut at = 12;

    for _ in 0..head.counts[0] {
        let (_, next) = read_name(bytes, at)?;
        // Type and class.
        at = next + 4;
    }

    let mut values = Vec::new();
    for _ in 0..head.counts[1] {
        let (_, next) = read_name(bytes, at)?;
        let kind = u16::from_be_bytes([
            *bytes.get(next).ok_or_else(short)?,
            *bytes.get(next + 1).ok_or_else(short)?,
        ]);
        let length = usize::from(u16::from_be_bytes([
            *bytes.get(next + 8).ok_or_else(short)?,
            *bytes.get(next + 9).ok_or_else(short)?,
        ]));
        let start = next + 10;
        let data = bytes.get(start..start + length).ok_or_else(short)?;
        if kind == TYPE_TXT {
            values.push(read_strings(data));
        }
        at = start + length;
    }
    Ok(values)
}

/// Joins the character strings of one TXT record.
///
/// A long value arrives split across strings and means the concatenation, so
/// joining is what turns the record back into what was written.
fn read_strings(data: &[u8]) -> String {
    let mut text = String::new();
    let mut at = 0;
    while at < data.len() {
        let length = usize::from(data[at]);
        at += 1;
        let end = (at + length).min(data.len());
        text.push_str(&String::from_utf8_lossy(&data[at..end]));
        at = end;
    }
    text
}

fn short() -> Failure {
    Failure::new(
        Reason::Protocol,
        "the name server sent a message that ends too early".to_owned(),
    )
}
