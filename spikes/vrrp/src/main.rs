// Throwaway spike code for T-010. Not product code.
//
// One VRRP participant. It sends and receives advertisements, elects a master,
// moves the VIP with rtnetlink and broadcasts a gratuitous ARP after taking
// over. Every state change is printed as one JSON line with a wall clock
// timestamp, so the measuring script can compare events across containers
// without needing a clock of its own.
//
// The state machine follows RFC 5798 only as far as T-010 needs: two states,
// priority comparison, skew time and preempt. Authentication, IPv6, multiple
// VRIDs and accept mode are out of scope and deliberately absent.

mod net;
mod packet;

use std::env;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use net::{Interface, VrrpSocket};
use packet::{Advertisement, VRRP_GROUP};

/// Set from the signal handler. The receive timeout is short, so the loop sees
/// this quickly enough for a stop to look immediate.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum State {
    Backup,
    Master,
}

struct Config {
    node: String,
    iface: String,
    self_addr: Ipv4Addr,
    vip: Ipv4Addr,
    prefix_len: u8,
    vrid: u8,
    priority: u8,
    adver_ms: u64,
    preempt: bool,
    multicast: bool,
    peers: Vec<Ipv4Addr>,
    run_ms: u64,
    /// Negative control. With gratuitous ARP suppressed the VIP still moves and
    /// still shows up in `ip addr`, so a measurement that only looks at the
    /// address reports success while the network keeps sending frames to the
    /// old master. The switch is what makes the difference visible.
    skip_garp: bool,
}

fn env_var(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("{key} is required"))
}

fn env_parsed<T: FromStr>(key: &str, default: T) -> Result<T, String> {
    match env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw
            .trim()
            .parse()
            .map_err(|_| format!("{key}: cannot parse {raw:?}")),
    }
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let peers = env::var("VRRP_PEERS").unwrap_or_default();
        let peers = peers
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<Ipv4Addr>().map_err(|_| format!("bad peer {p:?}")))
            .collect::<Result<Vec<_>, _>>()?;

        let multicast = env_parsed("VRRP_MULTICAST", 0u8)? == 1;
        if peers.is_empty() && !multicast {
            return Err("unicast mode needs VRRP_PEERS".to_string());
        }

        Ok(Self {
            node: env_var("VRRP_NODE")?,
            iface: env::var("VRRP_IFACE").unwrap_or_else(|_| "eth0".to_string()),
            self_addr: env_var("VRRP_SELF")?
                .parse()
                .map_err(|_| "VRRP_SELF is not an IPv4 address".to_string())?,
            vip: env_var("VRRP_VIP")?
                .parse()
                .map_err(|_| "VRRP_VIP is not an IPv4 address".to_string())?,
            prefix_len: env_parsed("VRRP_PREFIX_LEN", 24u8)?,
            vrid: env_parsed("VRRP_VRID", 51u8)?,
            priority: env_parsed("VRRP_PRIORITY", 100u8)?,
            adver_ms: env_parsed("VRRP_ADVER_MS", 1000u64)?,
            preempt: env_parsed("VRRP_PREEMPT", 1u8)? == 1,
            multicast,
            peers,
            run_ms: env_parsed("VRRP_RUN_MS", 60_000u64)?,
            skip_garp: env_parsed("VRRP_SKIP_GARP", 0u8)? == 1,
        })
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

struct Log {
    node: String,
}

impl Log {
    /// One JSON object per line, flushed immediately. The script reads these
    /// while the process is still running, so buffering would hide the event
    /// that the measurement is waiting for.
    fn event(&self, kind: &str, fields: &[(&str, String)]) {
        let mut line = format!(
            "{{\"ts\":{},\"node\":\"{}\",\"event\":\"{}\"",
            now_ms(),
            self.node,
            kind
        );
        for (key, value) in fields {
            line.push_str(&format!(",\"{key}\":{value}"));
        }
        line.push('}');
        println!("{line}");
        let _ = io::stdout().flush();
    }

    fn error(&self, kind: &str, err: &io::Error) {
        self.event(kind, &[("error", format!("{:?}", err.to_string()))]);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("spike-vrrp: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let cfg = Config::from_env()?;
    let log = Log { node: cfg.node.clone() };

    // SIGTERM means a planned stop, so the VIP comes off the interface and the
    // peers get a priority zero advertisement. SIGKILL is the unplanned case
    // and is what the failover measurement uses instead.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }

    let iface = Interface::lookup(&cfg.iface).map_err(|e| format!("interface: {e}"))?;
    let socket = VrrpSocket::open(&cfg.iface, cfg.multicast, 20)
        .map_err(|e| format!("raw socket on protocol 112: {e}"))?;

    // A leftover VIP from a killed run would make this node look like the
    // master before it has won anything, so it is cleared first. Not finding
    // one is the normal case and not an error.
    match net::del_vip(&iface, cfg.vip, cfg.prefix_len) {
        Ok(()) => log.event("stale_vip_removed", &[]),
        Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => {}
        Err(e) => log.error("stale_vip_remove_failed", &e),
    }

    let adver = Duration::from_millis(cfg.adver_ms);
    // RFC 5798: a lower priority backup waits longer, so the highest priority
    // survivor always fires first. This is the whole basis of the deterministic
    // ordering that T-010 has to prove.
    let skew = Duration::from_millis((256 - u64::from(cfg.priority)) * cfg.adver_ms / 256);
    let master_down = adver * 3 + skew;

    log.event(
        "started",
        &[
            ("priority", cfg.priority.to_string()),
            ("vrid", cfg.vrid.to_string()),
            ("adver_ms", cfg.adver_ms.to_string()),
            ("skew_ms", skew.as_millis().to_string()),
            ("master_down_ms", master_down.as_millis().to_string()),
            ("preempt", cfg.preempt.to_string()),
            ("mode", format!("{:?}", if cfg.multicast { "multicast" } else { "unicast" })),
            ("mac", format!("{:?}", mac_string(iface.mac))),
        ],
    );

    let advertisement = Advertisement {
        vrid: cfg.vrid,
        priority: cfg.priority,
        max_adver_int: (cfg.adver_ms / 10).max(1) as u16,
        vip: cfg.vip,
    };

    let started = Instant::now();
    let mut state = State::Backup;
    let mut master_down_at = Instant::now() + master_down;
    let mut next_advert = Instant::now();
    // Timestamp of the last advertisement from anyone else. Failover time is
    // measured from here rather than from when the script killed the master,
    // because that is the moment detection could first have started.
    let mut last_peer_adv_ms: Option<u128> = None;
    let mut sent = 0u64;
    let mut received = 0u64;

    let mut buf = [0u8; 256];
    while !STOP.load(Ordering::SeqCst) && started.elapsed() < Duration::from_millis(cfg.run_ms) {
        match socket.recv(&mut buf) {
            Err(e) => log.error("recv_failed", &e),
            Ok(None) => {}
            Ok(Some((src, adv))) => {
                if adv.vrid == cfg.vrid && src != cfg.self_addr {
                    received += 1;
                    last_peer_adv_ms = Some(now_ms());
                    handle_advertisement(
                        &cfg,
                        &log,
                        &iface,
                        src,
                        adv,
                        &mut state,
                        &mut master_down_at,
                        master_down,
                        skew,
                    );
                }
            }
        }

        let now = Instant::now();
        match state {
            State::Master if now >= next_advert => {
                send_payload(&cfg, &log, &socket, &advertisement, &mut sent);
                next_advert = now + adver;
            }
            State::Backup if now >= master_down_at => {
                become_master(&cfg, &log, &iface, &socket, &advertisement, last_peer_adv_ms, &mut sent);
                state = State::Master;
                next_advert = Instant::now() + adver;
            }
            _ => {}
        }
    }

    if state == State::Master {
        // Priority zero tells the peers to take over now instead of waiting out
        // the master down interval. It is the difference between a planned
        // handover and a timeout.
        let goodbye = Advertisement { priority: 0, ..advertisement };
        send_payload(&cfg, &log, &socket, &goodbye, &mut sent);
        match net::del_vip(&iface, cfg.vip, cfg.prefix_len) {
            Ok(()) => log.event("vip_removed", &[("reason", "\"shutdown\"".to_string())]),
            Err(e) => log.error("vip_remove_failed", &e),
        }
    }

    log.event(
        "stopped",
        &[
            ("state", format!("{state:?}").to_lowercase()),
            ("sent", sent.to_string()),
            ("received", received.to_string()),
        ],
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_advertisement(
    cfg: &Config,
    log: &Log,
    iface: &Interface,
    src: Ipv4Addr,
    adv: Advertisement,
    state: &mut State,
    master_down_at: &mut Instant,
    master_down: Duration,
    skew: Duration,
) {
    // Equal priorities are broken by address, which is what keeps two nodes
    // from both claiming the VIP forever.
    let beats_us = adv.priority > cfg.priority
        || (adv.priority == cfg.priority && src > cfg.self_addr);

    match *state {
        State::Master => {
            if beats_us {
                log.event(
                    "yielded",
                    &[
                        ("to", format!("{:?}", src.to_string())),
                        ("their_priority", adv.priority.to_string()),
                    ],
                );
                match net::del_vip(iface, cfg.vip, cfg.prefix_len) {
                    Ok(()) => log.event("vip_removed", &[("reason", "\"preempted\"".to_string())]),
                    Err(e) => log.error("vip_remove_failed", &e),
                }
                *state = State::Backup;
                *master_down_at = Instant::now() + master_down;
            }
        }
        State::Backup => {
            if adv.priority == 0 {
                // The master is leaving on purpose. Waiting the full interval
                // here would turn a planned handover into an outage.
                *master_down_at = Instant::now() + skew;
                log.event("master_stepped_down", &[("from", format!("{:?}", src.to_string()))]);
            } else if !cfg.preempt || beats_us {
                *master_down_at = Instant::now() + master_down;
            }
            // With preempt on and a weaker master talking, the timer is left
            // to expire so this node takes over.
        }
    }
}

fn become_master(
    cfg: &Config,
    log: &Log,
    iface: &Interface,
    socket: &VrrpSocket,
    own: &Advertisement,
    last_peer_adv_ms: Option<u128>,
    sent: &mut u64,
) {
    let vip_ok = match net::add_vip(iface, cfg.vip, cfg.prefix_len) {
        Ok(()) => true,
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => true,
        Err(e) => {
            log.error("vip_add_failed", &e);
            false
        }
    };

    // Order matters. The ARP goes out after the address exists, otherwise the
    // switch learns a MAC for an address this node cannot yet answer for.
    let garp_ok = if cfg.skip_garp {
        false
    } else {
        match net::send_gratuitous_arp(iface, cfg.vip) {
            Ok(()) => true,
            Err(e) => {
                log.error("garp_failed", &e);
                false
            }
        }
    };

    let detection = last_peer_adv_ms.map(|last| now_ms().saturating_sub(last));
    log.event(
        "became_master",
        &[
            ("vip_added", vip_ok.to_string()),
            ("garp_sent", garp_ok.to_string()),
            (
                "last_peer_adv_ts",
                last_peer_adv_ms.map_or("null".to_string(), |v| v.to_string()),
            ),
            (
                "detect_ms",
                detection.map_or("null".to_string(), |v| v.to_string()),
            ),
        ],
    );

    send_payload(cfg, log, socket, own, sent);
}

fn send_payload(
    cfg: &Config,
    log: &Log,
    socket: &VrrpSocket,
    adv: &Advertisement,
    sent: &mut u64,
) {
    // The checksum covers a pseudo header built from source and destination, so
    // a unicast run encodes the packet once per peer rather than once per tick.
    let destinations: Vec<Ipv4Addr> = if cfg.multicast {
        vec![VRRP_GROUP]
    } else {
        cfg.peers.clone()
    };

    for dst in destinations {
        let payload = adv.encode(cfg.self_addr, dst);
        match socket.send_to(&payload, dst) {
            Ok(()) => *sent += 1,
            Err(e) => log.error("send_failed", &e),
        }
    }
}

fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
