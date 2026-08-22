// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The socket address changes travel on.
//!
//! Netlink is a socket to the kernel itself. An unbound one is given a port
//! on its first write and its peer is the kernel, so nothing here binds and
//! nothing connects. That is what keeps this file free of the address
//! structures socket2 does not model (ADR-0073).
//!
//! Adding and removing an address needs `CAP_NET_ADMIN`, which is the reason
//! this is behind a platform gate. Everything about what the messages hold is
//! in [`crate::address`], outside the gate, where it is measured.

use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use socket2::{Domain, Protocol, Socket, Type};

use crate::address::{Address, Answer, Change, Family, answer, change, list};

/// The address family netlink lives in.
const NETLINK: i32 = 16;
/// The netlink family that carries routes and addresses.
const ROUTE: i32 = 0;

/// The most bytes one read takes.
///
/// A dump of every address on a machine with many interfaces arrives in
/// several reads, so this bounds one read rather than the answer.
const MOST: usize = 32 * 1024;

/// A socket to the kernel's routing tables.
pub struct Netlink {
    socket: Socket,
}

impl Netlink {
    /// Opens the socket.
    ///
    /// # Errors
    ///
    /// Returns what the operating system said. The usual failure is a missing
    /// `CAP_NET_ADMIN`, which arrives as a permission error.
    pub fn open() -> io::Result<Self> {
        let socket = Socket::new(
            Domain::from(NETLINK),
            Type::RAW,
            Some(Protocol::from(ROUTE)),
        )?;
        Ok(Self { socket })
    }

    /// Puts an address on an interface, or takes it off.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket fails, and when the kernel refuses
    /// the change. A refusal arrives only in the answer: the write itself
    /// reports success as soon as the message is queued (T-010).
    pub fn change(&self, what: &Address, how: Change) -> io::Result<()> {
        let sequence = next();
        self.say(&change(what, how, sequence))?;

        let mut buffer = [0_u8; MOST];
        let read = (&self.socket).read(&mut buffer)?;
        let said = buffer.get(..read).unwrap_or_default();

        match answer(said) {
            Some(Answer::Accepted) => Ok(()),
            Some(Answer::Refused(code)) => Err(io::Error::from_raw_os_error(code)),
            Some(Answer::Other(kind)) => Err(io::Error::other(format!(
                "the kernel answered with message type {kind} rather than an acknowledgement"
            ))),
            None => Err(io::Error::other(format!(
                "the kernel answered {read} bytes, which is too short to hold an acknowledgement"
            ))),
        }
    }

    /// Every address of one family the kernel holds, with its interface.
    ///
    /// # Errors
    ///
    /// Returns what the socket said. A dump needs no capability, so this
    /// works wherever the socket opens.
    pub fn addresses(&self, family: Family) -> io::Result<Vec<(IpAddr, u32)>> {
        let sequence = next();
        self.say(&list(family, sequence))?;

        let mut found = Vec::new();
        // A dump arrives in as many reads as it needs and ends with a message
        // of its own. Stopping at the first read would report a truncated
        // answer as the whole of it.
        loop {
            let mut buffer = [0_u8; MOST];
            let read = (&self.socket).read(&mut buffer)?;
            let said = buffer.get(..read).unwrap_or_default();
            found.extend(crate::address::addresses(said));
            if finished(said) {
                return Ok(found);
            }
        }
    }

    /// Writes one message to the kernel.
    fn say(&self, bytes: &[u8]) -> io::Result<()> {
        let written = (&self.socket).write(bytes)?;
        if written == bytes.len() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "netlink took {written} of {} bytes, so the message was cut in half",
            bytes.len()
        )))
    }
}

/// Whether a read holds the message that ends a dump.
fn finished(bytes: &[u8]) -> bool {
    crate::address::messages(bytes).iter().any(|message| {
        let kind = u16::from_ne_bytes([message[4], message[5]]);
        kind == crate::address::DONE || kind == crate::address::ERROR
    })
}

/// The next sequence number.
///
/// Counted rather than fixed, so an answer can be told from a leftover one.
/// It starts at one because zero is what the kernel uses for a message nobody
/// asked for.
fn next() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
