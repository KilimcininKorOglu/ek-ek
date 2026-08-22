// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the kernel says about an interface.
//!
//! Netlink addresses an interface by index and a frame carries a hardware
//! address, so both have to be read before either can be used. Both sit in
//! `/sys/class/net/`, which is a plain file rather than a system call, so
//! reading them needs no capability and no `unsafe`.
//!
//! The parsing is kept apart from the reading, so the rules about what a
//! valid index and a valid hardware address look like are measured on the
//! machine this is written on rather than only where the files exist.

use std::io;
use std::path::PathBuf;

use crate::announce::MAC;

/// Where the kernel publishes what it knows about an interface.
const NET: &str = "/sys/class/net";

/// One interface, as much of it as this product needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// The name an operator wrote in the configuration.
    pub name: String,
    /// What netlink addresses it by.
    pub index: u32,
    /// What a frame leaving it carries as its source.
    pub mac: [u8; MAC],
}

impl Interface {
    /// Reads an interface by name.
    ///
    /// # Errors
    ///
    /// Returns an error when the interface is not there or when the kernel
    /// wrote something these parsers do not understand. An interface named in
    /// the configuration but missing from the machine is a delivery fault, so
    /// it is reported rather than worked around.
    pub fn read(name: &str) -> io::Result<Self> {
        let index = std::fs::read_to_string(file(name, "ifindex"))?;
        let address = std::fs::read_to_string(file(name, "address"))?;
        let index = index_of(&index).ok_or_else(|| unreadable(name, "ifindex", &index))?;
        let mac = mac_of(&address).ok_or_else(|| unreadable(name, "address", &address))?;
        Ok(Self {
            name: name.to_owned(),
            index,
            mac,
        })
    }
}

/// The path one attribute of an interface sits at.
fn file(name: &str, attribute: &str) -> PathBuf {
    PathBuf::from(NET).join(name).join(attribute)
}

/// The error a file nobody can parse produces.
fn unreadable(name: &str, attribute: &str, held: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{NET}/{name}/{attribute} holds {held:?}, which is not readable"),
    )
}

/// The index out of what the kernel wrote.
///
/// Zero is refused: netlink reads it as "every interface", so an address
/// change carrying it would land somewhere nobody asked for.
#[must_use]
pub fn index_of(text: &str) -> Option<u32> {
    match text.trim().parse::<u32>() {
        Ok(0) | Err(_) => None,
        Ok(index) => Some(index),
    }
}

/// The hardware address out of what the kernel wrote.
///
/// The form is six hexadecimal pairs separated by colons. An interface with
/// no hardware address of its own, such as a tunnel, writes all zeroes, and
/// that is refused: a frame claiming to come from nobody is never answered.
#[must_use]
pub fn mac_of(text: &str) -> Option<[u8; MAC]> {
    let mut octets = [0_u8; MAC];
    let mut seen = 0;
    for (at, part) in text.trim().split(':').enumerate() {
        if at >= MAC {
            return None;
        }
        octets[at] = u8::from_str_radix(part, 16).ok()?;
        seen += 1;
    }
    if seen != MAC || octets == [0; MAC] {
        return None;
    }
    Some(octets)
}

#[cfg(test)]
mod tests {
    use super::{index_of, mac_of};

    #[test]
    fn an_index_is_read_and_a_useless_one_is_refused() {
        assert_eq!(index_of("2\n"), Some(2));
        assert_eq!(index_of("  17  "), Some(17));
        // Zero means every interface to netlink, so it is not an index.
        assert_eq!(index_of("0\n"), None);
        assert_eq!(index_of(""), None);
        assert_eq!(index_of("eth0"), None);
        assert_eq!(index_of("-1"), None);
    }

    #[test]
    fn a_hardware_address_is_read_and_a_useless_one_is_refused() {
        assert_eq!(
            mac_of("02:42:ac:1c:00:0b\n"),
            Some([0x02, 0x42, 0xAC, 0x1C, 0x00, 0x0B])
        );
        // An interface with no hardware address of its own writes this.
        assert_eq!(mac_of("00:00:00:00:00:00"), None);
        // Too few and too many parts, which is the boundary either side.
        assert_eq!(mac_of("02:42:ac:1c:00"), None);
        assert_eq!(mac_of("02:42:ac:1c:00:0b:0c"), None);
        assert_eq!(mac_of("02:42:ac:1c:00:zz"), None);
        assert_eq!(mac_of(""), None);
    }
}
