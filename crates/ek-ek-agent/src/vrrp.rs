// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the agent was told about the virtual router it runs.
//!
//! Plain values, no platform types. VRRP moves addresses over netlink and
//! sends IP protocol 112, so the types that carry it only exist on Linux
//! (ADR-0007). Keeping this side plain means the caller reads its arguments
//! the same way everywhere and finds out on the platform, rather than failing
//! to compile on the machine the product is written on.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// One address and how much of it is the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carrying {
    /// The address itself.
    pub address: IpAddr,
    /// How many leading bits are the network.
    pub prefix_length: u8,
}

/// The virtual router this node runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vrrp {
    /// This node's own address, which advertisements come from.
    pub address: Ipv4Addr,
    /// The other nodes, by address. Unicast only (ADR-0007).
    pub peers: Vec<Ipv4Addr>,
    /// Interface the addresses are put on.
    pub interface: String,
    /// Addresses this node carries while it holds the role.
    pub carried: Vec<Carrying>,
    /// Which virtual router this is.
    pub vrid: u8,
    /// The claim this node makes when everything is well.
    pub priority: u8,
    /// How often an advertisement goes out.
    pub interval: Duration,
    /// Whether a stronger node takes the role back.
    pub preempt: bool,
    /// Whether announcing is switched off.
    pub silent: bool,
    /// Whether the gateway is watched at all.
    pub watch_gateway: bool,
    /// How often the gateway is asked.
    pub check_interval: Duration,
    /// How many answers have to go missing before the claim is lowered.
    pub failures: u32,
    /// What the claim is lowered to.
    pub demoted_priority: u8,
}

impl Vrrp {
    /// Turns this into what the router needs.
    ///
    /// # Errors
    ///
    /// Returns a sentence naming what is missing. A router with no peer would
    /// hold the role for ever because nothing could contradict it, and one
    /// with no address to carry would hold a role that moves nothing.
    #[cfg(target_os = "linux")]
    pub fn plan(&self) -> Result<ek_ek_vrrp::Plan, String> {
        if self.peers.is_empty() {
            return Err("at least one peer is required; multicast is not offered".to_owned());
        }
        if self.carried.is_empty() {
            return Err("at least one virtual address is required".to_owned());
        }

        // RFC 5798 keeps one virtual router to one address family, so only the
        // IPv4 addresses go in the advertisement. Every one of them is carried
        // on the interface, which is where an IPv6 virtual address lives.
        let virtual_addresses = self
            .carried
            .iter()
            .filter_map(|one| match one.address {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            })
            .collect();

        Ok(ek_ek_vrrp::Plan {
            settings: ek_ek_vrrp::Settings {
                vrid: self.vrid,
                priority: self.priority,
                interval: self.interval,
                preempt: self.preempt,
                address: self.address,
                virtual_addresses,
                peers: self.peers.clone(),
            },
            interface: self.interface.clone(),
            carried: self
                .carried
                .iter()
                .map(|one| ek_ek_vrrp::Carried {
                    address: one.address,
                    prefix_length: one.prefix_length,
                })
                .collect(),
            silent: self.silent,
            watch_gateway: self.watch_gateway,
            check_interval: self.check_interval,
            threshold: self.failures,
            demoted_priority: self.demoted_priority,
        })
    }
}

/// Reads an address and prefix length, written `address/prefix`.
///
/// # Errors
///
/// Returns a sentence naming what is wrong with the text.
pub fn carrying(text: &str) -> Result<Carrying, String> {
    let (address, prefix) = text.split_once('/').ok_or_else(|| {
        format!("a virtual address needs a prefix length, as in {text}/24, and {text} has none")
    })?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("{address} is not an IP address"))?;
    let prefix_length: u8 = prefix
        .parse()
        .map_err(|_| format!("{prefix} is not a prefix length"))?;

    let widest = if address.is_ipv4() { 32 } else { 128 };
    if prefix_length > widest {
        return Err(format!(
            "a prefix length of {prefix_length} is wider than the {widest} bits {address} has"
        ));
    }
    Ok(Carrying {
        address,
        prefix_length,
    })
}
