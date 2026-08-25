// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs one virtual router and says what it does.
//!
//! Every setting arrives as an argument rather than from a configuration
//! document, because the numbers a document would hold are computed from the
//! preferred node and do not exist yet (T-034). The loop, the sockets and the
//! records here are the ones the node agent will use.
//!
//! State changes are written to standard output as one JSON object per line,
//! the same shape the rest of the product writes (ADR-0037). Whatever reads
//! them parses the line; nothing here returns a value for a test to inspect.
//!
//! ```text
//! ek-ek-vrrp-node --address 172.28.0.11 --peer 172.28.0.12 \
//!     --interface eth0 --virtual-address 172.28.0.100/24 \
//!     --vrid 51 --priority 200
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use ek_ek_vrrp::Settings;
// Read where the arguments are read, which is everywhere: the defaults are
// part of what a wrong argument is measured against.
use ek_ek_vrrp::gateway::{INTERVAL as GATEWAY_INTERVAL, THRESHOLD as GATEWAY_THRESHOLD};
#[cfg(target_os = "linux")]
use ek_ek_vrrp::{Carried, Plan, Router, Transport};

/// How often the loop looks at its timers.
///
/// Short against the advertisement interval, so a deadline is acted on within
/// a fraction of it rather than at the next multiple of the tick (ADR-0029).
#[cfg(target_os = "linux")]
const TICK: Duration = Duration::from_millis(10);

/// Everything one virtual router was asked to be.
///
/// Read where the sockets are, which is Linux. The arguments are still read
/// everywhere, so a wrong one is refused with the same sentence on any
/// machine rather than only where it could have run.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Options {
    /// What the state machine needs.
    settings: Settings,
    /// Interface the addresses are put on.
    interface: String,
    /// Addresses this node carries while it holds the role.
    carried: Vec<Carrying>,
    /// Whether announcing is switched off.
    silent: bool,
    /// Whether the gateway is watched at all.
    watch_gateway: bool,
    /// How often the gateway is asked.
    check_interval: Duration,
    /// How many answers have to go missing before the claim is lowered.
    threshold: u32,
    /// What the claim is lowered to.
    demoted_priority: u8,
}

/// One address and how much of it is the network.
///
/// Held here rather than taken from the crate, because the type that carries
/// it only exists on Linux and the arguments are read everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Carrying {
    address: IpAddr,
    prefix_length: u8,
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    let options = match read(&arguments) {
        Ok(options) => options,
        Err(complaint) => {
            eprintln!("ek-ek-vrrp-node: {complaint}");
            return ExitCode::FAILURE;
        }
    };

    #[cfg(target_os = "linux")]
    let transport = match ek_ek_vrrp::RawSocket::open() {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("ek-ek-vrrp-node: the raw socket could not be opened: {error}");
            eprintln!("ek-ek-vrrp-node: VRRP is IP protocol 112 and needs CAP_NET_RAW");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "ek-ek-vrrp-node: virtual router {} cannot run here; VRRP is IP protocol 112, \
             its addresses move over netlink, and both need Linux with CAP_NET_RAW and \
             CAP_NET_ADMIN",
            options.settings.vrid
        );
        ExitCode::FAILURE
    }

    #[cfg(target_os = "linux")]
    run(options, &transport)
}

/// Drives one router until the process is stopped.
#[cfg(target_os = "linux")]
fn run(options: Options, transport: &impl Transport) -> ExitCode {
    let Options {
        settings,
        interface,
        carried,
        silent,
        watch_gateway,
        check_interval,
        threshold,
        demoted_priority,
    } = options;

    let plan = Plan {
        settings,
        interface,
        carried: carried
            .into_iter()
            .map(|one| Carried {
                address: one.address,
                prefix_length: one.prefix_length,
            })
            .collect(),
        silent,
        watch_gateway,
        check_interval,
        threshold,
        demoted_priority,
    };

    let mut router = match Router::start(plan, transport, Instant::now()) {
        Ok(router) => router,
        Err(error) => {
            eprintln!("ek-ek-vrrp-node: the router could not start: {error}");
            eprintln!(
                "ek-ek-vrrp-node: moving an address needs CAP_NET_ADMIN, sending a frame \
                 needs CAP_NET_RAW, and so does asking the gateway"
            );
            return ExitCode::FAILURE;
        }
    };

    loop {
        router.tick(Instant::now());
        std::thread::sleep(TICK);
    }
}

/// Reads the settings out of the arguments.
///
/// # Errors
///
/// Returns a sentence naming what is missing or unreadable.
fn read(arguments: &[String]) -> Result<Options, String> {
    let mut address = None;
    let mut peers = Vec::new();
    let mut carried: Vec<Carrying> = Vec::new();
    let mut interface = "eth0".to_owned();
    let mut vrid = 51_u8;
    let mut priority = 100_u8;
    let mut interval = Duration::from_millis(300);
    let mut preempt = true;
    let mut silent = false;
    let mut watch_gateway = false;
    let mut check_interval = GATEWAY_INTERVAL;
    let mut threshold = GATEWAY_THRESHOLD;
    let mut demoted_priority = 1_u8;

    let mut rest = arguments.iter().skip(1);
    while let Some(name) = rest.next() {
        match name.as_str() {
            "--address" => address = Some(number(rest.next(), "--address")?),
            "--peer" => peers.push(number(rest.next(), "--peer")?),
            "--interface" => {
                interface = rest
                    .next()
                    .ok_or_else(|| "--interface needs a value".to_owned())?
                    .clone();
            }
            "--virtual-address" => carried.push(carrying(rest.next())?),
            "--vrid" => vrid = parse(rest.next(), "--vrid")?,
            "--priority" => priority = parse(rest.next(), "--priority")?,
            "--interval-ms" => {
                interval = Duration::from_millis(parse(rest.next(), "--interval-ms")?);
            }
            "--no-preempt" => preempt = false,
            // The negative control. Without it there is no way to tell an
            // announcement that moved a cache from a cache that was going to
            // name this node anyway (T-010).
            "--silent" => silent = true,
            "--watch-gateway" => watch_gateway = true,
            "--check-interval-ms" => {
                check_interval = Duration::from_millis(parse(rest.next(), "--check-interval-ms")?);
            }
            "--failures" => threshold = parse(rest.next(), "--failures")?,
            "--demoted-priority" => {
                demoted_priority = parse(rest.next(), "--demoted-priority")?;
            }
            other => return Err(format!("{other} is not an argument this understands")),
        }
    }

    let address = address.ok_or_else(|| "--address is required".to_owned())?;
    if peers.is_empty() {
        return Err("at least one --peer is required; multicast is not offered".to_owned());
    }
    if carried.is_empty() {
        return Err("at least one --virtual-address is required".to_owned());
    }

    // RFC 5798 keeps one virtual router to one address family, so only the
    // IPv4 addresses go in the advertisement. Every one of them is carried on
    // the interface, which is where an IPv6 virtual address lives.
    let virtual_addresses = carried
        .iter()
        .filter_map(|one| match one.address {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .collect();

    Ok(Options {
        settings: Settings {
            vrid,
            priority,
            interval,
            preempt,
            address,
            virtual_addresses,
            peers,
        },
        interface,
        carried,
        silent,
        watch_gateway,
        check_interval,
        threshold,
        demoted_priority,
    })
}

/// Reads an address and prefix length argument, written `address/prefix`.
fn carrying(value: Option<&String>) -> Result<Carrying, String> {
    let text = value.ok_or_else(|| "--virtual-address needs a value".to_owned())?;
    let (address, prefix) = text.split_once('/').ok_or_else(|| {
        format!("--virtual-address needs a prefix length, as in {text}/24, and {text} has none")
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

/// Reads an address argument.
fn number(value: Option<&String>, name: &str) -> Result<Ipv4Addr, String> {
    value
        .ok_or_else(|| format!("{name} needs a value"))?
        .parse()
        .map_err(|_| format!("{name} needs an IPv4 address"))
}

/// Reads a numeric argument.
fn parse<T: std::str::FromStr>(value: Option<&String>, name: &str) -> Result<T, String> {
    value
        .ok_or_else(|| format!("{name} needs a value"))?
        .parse()
        .map_err(|_| format!("{name} needs a number"))
}
