// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Carrying the addresses a virtual router answers for.
//!
//! The state machine says when the addresses move. This puts them on the
//! interface, takes them off, and tells the segment about it.
//!
//! # Why the announcement is spread over the loop
//!
//! Five frames a hundred milliseconds apart is four hundred milliseconds of
//! waiting. Doing that inside the takeover would hold the advertisement and
//! the socket read for the whole of it, and ADR-0029 makes timely
//! advertisement a rule rather than a preference. So the first announcement
//! goes at once and the rest are due later, drained by the same loop that
//! runs the timers.
//!
//! # Why removing an address that is not there is not a failure
//!
//! A killed process leaves whatever it had on the interface, and nothing
//! records how far it got. Both the startup cleanup and the drop after losing
//! the role ask for an end state: the address is not on this interface.

use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::address::{Address, Change};
use crate::announce::{Arp, arp, neighbor};
use crate::frame::Frames;
use crate::interface::Interface;
use crate::netlink::Netlink;

/// The errno the kernel answers when an address is not on the interface.
const NOT_THERE: i32 = 99;

/// How many times a move is announced.
///
/// Five, because one lost frame is a failover nobody sees: the address has
/// moved, every other machine still holds the old hardware address, and
/// nothing retries (R-03).
pub const ANNOUNCEMENTS: u32 = 5;

/// How long between them.
///
/// Short against the advertisement interval, so the whole announcement is
/// over well inside one takeover.
pub const GAP: Duration = Duration::from_millis(100);

/// One address this node carries while it holds the role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    /// The address itself.
    pub address: IpAddr,
    /// How much of it is the network.
    pub prefix_length: u8,
}

/// The interface, the addresses and the two sockets that move them.
pub struct Carrier {
    interface: Interface,
    addresses: Vec<Carried>,
    netlink: Netlink,
    frames: Frames,
    /// When the next announcement is due, and how many are left after it.
    due: Option<(Instant, u32)>,
    /// Whether announcing is switched off.
    ///
    /// Only a measurement sets this. It is the negative control that shows
    /// the announcement is what moves traffic rather than the address: with
    /// it on, a third node's cache keeps naming the node that died (T-010).
    silent: bool,
}

impl Carrier {
    /// Opens both sockets and reads what the interface is.
    ///
    /// # Errors
    ///
    /// Returns an error when the interface is not there or either socket
    /// cannot be opened. Both need a capability, so the usual failure is a
    /// permission error.
    pub fn open(interface: &str, addresses: Vec<Carried>, silent: bool) -> io::Result<Self> {
        let interface = Interface::read(interface)?;
        let frames = Frames::open(interface.index)?;
        Ok(Self {
            interface,
            addresses,
            netlink: Netlink::open()?,
            frames,
            due: None,
            silent,
        })
    }

    /// The addresses this node carries while it holds the role.
    #[must_use]
    pub fn addresses(&self) -> &[Carried] {
        &self.addresses
    }

    /// Puts every address on the interface and announces the first time.
    ///
    /// # Errors
    ///
    /// Returns the first refusal the kernel gave. The caller stands the node
    /// down on one, because a master without its addresses answers nothing
    /// and stops anybody else from answering.
    pub fn take(&mut self, now: Instant) -> io::Result<()> {
        for carried in &self.addresses {
            self.netlink.change(&self.address(carried), Change::Add)?;
        }
        // After the addresses, never before. Announcing first teaches the
        // segment a hardware address for something this node cannot yet
        // answer for (T-010).
        self.announce()?;
        self.due = Some((now + GAP, ANNOUNCEMENTS - 1));
        Ok(())
    }

    /// Takes every address off the interface.
    ///
    /// # Errors
    ///
    /// Returns anything the kernel said other than "it was not there".
    pub fn drop_all(&mut self) -> io::Result<()> {
        self.due = None;
        for carried in &self.addresses {
            match self.netlink.change(&self.address(carried), Change::Remove) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(NOT_THERE) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Sends an announcement when one is due.
    ///
    /// # Errors
    ///
    /// Returns what the packet socket said.
    pub fn tick(&mut self, now: Instant) -> io::Result<()> {
        let Some((at, left)) = self.due else {
            return Ok(());
        };
        if now < at {
            return Ok(());
        }
        self.announce()?;
        self.due = if left > 1 {
            Some((now + GAP, left - 1))
        } else {
            None
        };
        Ok(())
    }

    /// Tells the segment about every address, once.
    fn announce(&self) -> io::Result<()> {
        if self.silent {
            return Ok(());
        }
        for carried in &self.addresses {
            match carried.address {
                IpAddr::V4(address) => {
                    // Both forms. RFC 5227 defines the gratuitous form as a
                    // request, the spike measured a reply moving a cache, and
                    // stacks exist that act on only one of them.
                    for kind in [Arp::Request, Arp::Reply] {
                        self.frames.send(&arp(kind, address, self.interface.mac))?;
                    }
                }
                IpAddr::V6(address) => {
                    self.frames.send(&neighbor(address, self.interface.mac))?;
                }
            }
        }
        Ok(())
    }

    /// One address, as netlink addresses it.
    fn address(&self, carried: &Carried) -> Address {
        Address {
            address: carried.address,
            prefix_length: carried.prefix_length,
            interface: self.interface.index,
        }
    }
}
