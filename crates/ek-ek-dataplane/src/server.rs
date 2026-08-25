// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Assembling the pingora server.
//!
//! Listeners are declared before the server runs and cannot be added later,
//! so the frontends in the first delivery decide what this process listens
//! on. A frontend appearing or disappearing needs a replacement process with
//! socket handover, which the agent drives (ADR-0002).
//!
//! Everything else, backends included, changes inside this process.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ek_ek_config::{ApplicationProtocol, Config, TlsPolicyLevel, TransportProtocol};
use ek_ek_ipc::DataPlaneState;
use pingora::apps::HttpServerOptions;
use pingora::listeners::tls::TlsSettings;
use pingora::server::{Server, ShutdownWatch};
use pingora::services::background::background_service;
use pingora::services::listening::Service;
use pingora::tls::ssl::SslOptions;

use crate::balance::Balancer;
use crate::error::{Error, ErrorKind, Result};
use crate::handshake::SniResolver;
use crate::health::{Checked, Health, checked, watch};
use crate::link::AgentLink;
use crate::live::{LiveConfig, Status};
use crate::policy;

/// How often the listeners are tried while any of them is not up yet.
const LISTENING_CHECK_INTERVAL: Duration = Duration::from_millis(50);
use crate::proxy::Proxy;
use crate::stream::StreamProxy;
use crate::udpproxy::{UdpProxy, udp_bindings};

/// Where a frontend listens.
///
/// Returned so a caller can report exactly what was bound rather than
/// guessing from the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The frontend this belongs to.
    pub frontend: String,
    /// The address in `host:port` form.
    pub address: String,
    /// Whether this listener accepts cleartext HTTP/2 (ADR-0059).
    ///
    /// Only meaningful on an HTTP listener that does not terminate TLS. Over
    /// TLS the version is negotiated with ALPN instead.
    pub http2: bool,
    /// Whether this listener terminates TLS, choosing its certificate per
    /// handshake from the SNI name (ADR-0068).
    pub terminates_tls: bool,
    /// Which protocol versions and cipher suites this listener accepts.
    ///
    /// Carried on the binding rather than looked up again while the listener
    /// is built, so what was decided and what is applied cannot drift apart.
    /// Meaningless where `terminates_tls` is false, and then left at the
    /// default (ADR-0081).
    pub policy: TlsPolicyLevel,
    /// What the listener does with the bytes it accepts.
    pub kind: ListenerKind,
}

/// Which path serves a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerKind {
    /// Parsed as HTTP and routed on host and path.
    Http,
    /// Forwarded byte for byte, without being interpreted.
    Stream,
    /// The ClientHello's server name is read, and the handshake is then
    /// forwarded untouched (ADR-0027).
    TlsPassthrough,
}

/// Works out what a configuration says to listen on.
///
/// # Errors
///
/// Fails when a frontend names a VIP that is not defined. Validation catches
/// that first, so reaching it here means something delivered a configuration
/// without checking it.
pub fn bindings(config: &Config) -> Result<Vec<Binding>> {
    let mut bindings = Vec::new();

    for frontend in &config.frontends {
        // The UDP path is hand written and does not go through pingora, so
        // its frontends are not listeners here (ADR-0017).
        if frontend.transport != TransportProtocol::Tcp {
            continue;
        }
        let kind = match frontend.application {
            ApplicationProtocol::Http => ListenerKind::Http,
            ApplicationProtocol::Raw => ListenerKind::Stream,
            ApplicationProtocol::TlsPassthrough => ListenerKind::TlsPassthrough,
        };

        let vip = config
            .vips
            .iter()
            .find(|vip| vip.id == frontend.vip)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Listener,
                    format!(
                        "frontend {} names vip {}, which is not in the configuration",
                        frontend.id.as_str(),
                        frontend.vip.as_str()
                    ),
                )
            })?;

        bindings.push(Binding {
            frontend: frontend.id.as_str().to_owned(),
            // Built through SocketAddr rather than by joining the two with a
            // colon: an IPv6 address needs brackets around it, and without
            // them the listener address does not parse and the frontend never
            // binds.
            address: SocketAddr::new(vip.address, frontend.port).to_string(),
            http2: frontend.http2.is_enabled(),
            terminates_tls: frontend.tls.is_some(),
            // A frontend that names no TLS settings names no level either, so
            // the default stands. Nothing reads it there.
            policy: frontend
                .tls
                .as_ref()
                .map_or_else(TlsPolicyLevel::default, |tls| tls.policy),
            kind,
        });
    }

    Ok(bindings)
}

/// Builds the server: the listeners, plus the agent link as a background
/// service.
///
/// The link runs inside the server rather than beside it, so its lifetime is
/// the server's and a shutdown stops both.
///
/// # Errors
///
/// Fails when the server cannot be built or a frontend names a missing VIP.
pub fn build(link: AgentLink) -> Result<Server> {
    let live = link.live();
    let status = link.status();

    let mut server = Server::new_with_opt_and_conf(None, shutdown_conf(&live.load().config));
    server.bootstrap();

    // One balancer for the whole process. The open connection counts belong
    // to what this process is doing, not to a configuration, so they survive
    // every swap.
    let balancer = Arc::new(Balancer::new());
    status.watch(Arc::clone(&balancer));
    // One set of pool gates for the whole process, for the same reason: a
    // limit counts what this process is carrying, and a swap must not hand
    // out a second set of slots to a pool that is already full (ADR-0045).
    let gates = Arc::new(crate::pool::Gates::new());

    let bindings = bindings(&live.load().config)?;
    let tcp_listeners = bindings.len();
    // Kept, so the process can check its own listeners once they are up
    // rather than saying it is serving because it was asked to build them.
    let listening_on: Vec<String> = bindings
        .iter()
        .map(|binding| binding.address.clone())
        .collect();
    for binding in bindings {
        let name = format!("frontend {}", binding.frontend);
        match binding.kind {
            ListenerKind::Http => {
                let proxy = Proxy::new(
                    binding.frontend.clone(),
                    Arc::clone(&live),
                    Arc::clone(&status),
                    Arc::clone(&balancer),
                    Arc::clone(&gates),
                );
                let mut service = pingora::proxy::http_proxy_service_with_name(
                    &server.configuration,
                    proxy,
                    &name,
                );

                // Cleartext HTTP/2 is told apart from HTTP/1.1 by the
                // connection preface, so turning it on leaves HTTP/1.1
                // clients untouched (ADR-0059).
                // The struct is non-exhaustive, so it is built by default and
                // then adjusted rather than written out field by field.
                let mut options = HttpServerOptions::default();
                options.h2c = binding.http2 && !binding.terminates_tls;
                if let Some(logic) = service.app_logic_mut() {
                    logic.server_options = Some(options);
                }

                if binding.terminates_tls {
                    let mut settings = TlsSettings::with_callbacks(Box::new(SniResolver::new(
                        binding.frontend.clone(),
                        Arc::clone(&live),
                        Arc::clone(&status),
                    )))
                    .map_err(|error| {
                        Error::new(
                            ErrorKind::Listener,
                            format!(
                                "frontend {} cannot terminate TLS: {error}",
                                binding.frontend
                            ),
                        )
                    })?;
                    // Over TLS the version is agreed with ALPN, so h2 is
                    // offered here rather than through the h2c preface.
                    if binding.http2 {
                        settings.enable_h2();
                    }
                    apply_policy(&binding.frontend, binding.policy, &mut settings).map_err(
                        |error| {
                            Error::new(
                                ErrorKind::Listener,
                                format!(
                                    "frontend {} cannot run the {} TLS policy: {error}",
                                    binding.frontend,
                                    policy::name_of(binding.policy)
                                ),
                            )
                        },
                    )?;
                    service.add_tls_with_settings(&binding.address, None, settings);
                } else {
                    service.add_tcp(&binding.address);
                }
                server.add_service(service);
            }
            ListenerKind::Stream | ListenerKind::TlsPassthrough => {
                // One path for both. The only difference is whether the name
                // is read before a pool is chosen; the copying, the PROXY
                // header, the idle limit and the access record are the same
                // thing and stay in one place (ADR-0080).
                let build = if binding.kind == ListenerKind::TlsPassthrough {
                    StreamProxy::passthrough
                } else {
                    StreamProxy::new
                };
                let proxy = build(
                    binding.frontend.clone(),
                    Arc::clone(&live),
                    Arc::clone(&status),
                    Arc::clone(&balancer),
                );
                let mut service = Service::new(name, proxy);
                service.add_tcp(&binding.address);
                server.add_service(service);
            }
        }
    }

    // UDP is not pingora's, so each UDP frontend runs its own loop as a
    // background service beside the listeners pingora owns (ADR-0017).
    let udp = udp_bindings(&live.load().config);
    // Counted so the last frontend to finish draining knows it is the last.
    let draining = Arc::new(DrainCount::new(udp.len(), tcp_listeners == 0));
    for binding in udp {
        let name = format!("udp frontend {}", binding.frontend);
        server.add_service(background_service(
            &name,
            UdpService {
                proxy: UdpProxy::new(
                    binding.frontend,
                    binding.address,
                    Arc::clone(&live),
                    Arc::clone(&status),
                    Arc::clone(&balancer),
                ),
                draining: Arc::clone(&draining),
            },
        ));
    }

    // Not `Serving` here. Building the listeners is not the same as having
    // them, and a process that said so before they were up would tell the
    // agent this node can carry traffic while nothing answers on its port.
    // The check below says it, once it has connected to every one of them
    // (ADR-0087).
    server.add_service(background_service(
        "listening check",
        ListeningCheck {
            addresses: listening_on,
            status: Arc::clone(&status),
        },
    ));
    // Health checking runs beside the traffic path rather than inside it, so
    // a slow probe never delays a request (T-021).
    server.add_service(background_service(
        "health checks",
        HealthService {
            live: Arc::clone(&live),
            health: balancer.health(),
        },
    ));
    server.add_service(background_service("node-agent link", LinkService { link }));

    Ok(server)
}

/// Puts a policy level onto a listener's TLS settings.
///
/// `TlsSettings` dereferences to OpenSSL's own acceptor builder, so the level
/// is applied to the context the listener is built from. That is what makes
/// the policy a property of the listener: two frontends at two levels never
/// see each other's settings (ADR-0081).
///
/// The `eski-uyumlu` level is announced here as well as in the warning
/// channel, because a level chosen in a document and a level actually running
/// are two different facts, and M8 moves this line to the audit log.
///
/// # Errors
///
/// Fails when the TLS library refuses a version or a cipher list. That is a
/// build this library cannot serve the level on, and starting anyway would
/// leave a frontend running a policy nobody chose.
fn apply_policy(
    frontend: &str,
    level: TlsPolicyLevel,
    settings: &mut TlsSettings,
) -> std::result::Result<(), pingora::tls::error::ErrorStack> {
    let policy = policy::settings(level);

    // The base pingora builds from turns TLS 1.0 and 1.1 off through options
    // rather than through a minimum version, so lowering the minimum alone
    // leaves them off. Cleared first, then the minimum decides.
    settings.clear_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
    settings.set_min_proto_version(Some(policy::least_openssl_version(level)))?;

    if !policy.cipher_list.is_empty() {
        settings.set_cipher_list(policy.cipher_list)?;
    }
    settings.set_ciphersuites(policy.ciphersuites)?;

    if level == TlsPolicyLevel::LegacyCompatible {
        log::warn!(
            "frontend {frontend} runs the {} TLS policy: TLS 1.0 and 1.1 are accepted and the security level is relaxed",
            policy::name_of(level)
        );
    }
    Ok(())
}

/// The shortest a process may take to leave once it has been asked to.
///
/// pingora sleeps for the grace period after it has told every service to
/// stop, so this is a floor under how long a replacement waits for the
/// process it is replacing.
const LEAST_GRACE: u64 = 1;

/// How long the runtimes get to unwind once the grace period has passed.
const RUNTIME_SHUTDOWN: u64 = 5;

/// Ends this process when any thread panics.
///
/// Each listener runs on its own thread. A thread that panics takes its
/// listener with it and leaves the process running, still holding its socket
/// to the agent and still answering the liveness question, while the port it
/// was serving accepts nothing. The node then keeps its virtual address for a
/// service that is gone, which is the total outage ADR-0033 exists to prevent.
/// Measured in the lab: a listener that could not bind panicked its thread and
/// the supervision went on calling the process healthy.
///
/// So a panic anywhere ends the process. The supervision sees a crash, gives
/// the address up and starts it again, which is the behaviour every other way
/// of failing already gets (ADR-0087).
pub fn end_on_a_panic() {
    let inherited = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panicked| {
        inherited(panicked);
        // Flushed by the hook above before this line. `abort` rather than
        // `exit`, because `exit` runs destructors on a process whose state is
        // whatever the panic left behind.
        std::process::abort();
    }));
}

/// Builds the server configuration that decides how long shutdown takes.
///
/// pingora's own defaults are five minutes of grace period, which would keep
/// a replaced process alive long after it has stopped serving and pile
/// processes up (R-05). The grace period here is the longest drain any
/// frontend asks for, because that is how long the UDP path may still be
/// carrying sessions after the signal (ADR-0067).
pub fn shutdown_conf(config: &Config) -> pingora::server::configuration::ServerConf {
    let drain = config
        .frontends
        .iter()
        .map(|frontend| u64::from(frontend.drain_timeout_seconds))
        .max()
        .unwrap_or(0)
        .max(LEAST_GRACE);

    pingora::server::configuration::ServerConf {
        grace_period_seconds: Some(drain),
        graceful_shutdown_timeout_seconds: Some(RUNTIME_SHUTDOWN),
        ..Default::default()
    }
}

/// Counts UDP frontends that are still draining.
///
/// pingora sleeps out its whole grace period rather than waiting for its
/// services, so a process whose sessions are gone would otherwise sit idle
/// for the rest of it. When the last UDP frontend has drained and there is
/// no TCP listener to wait for, the process leaves (ADR-0067).
pub struct DrainCount {
    left: std::sync::atomic::AtomicUsize,
    /// Whether leaving early is safe, which it is only when nothing else in
    /// this process is carrying traffic.
    alone: bool,
}

impl DrainCount {
    /// Starts a count over `frontends` UDP frontends.
    ///
    /// `alone` says whether this process carries nothing but UDP, which is
    /// the only case where leaving early is safe.
    #[must_use]
    pub fn new(frontends: usize, alone: bool) -> Self {
        Self {
            left: std::sync::atomic::AtomicUsize::new(frontends),
            alone,
        }
    }

    /// Records one frontend as drained. Returns whether the process may now
    /// leave, which needs both the last frontend and nothing else to wait for.
    pub fn finished(&self) -> bool {
        let before = self.left.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.alone && before <= 1
    }
}

/// Runs one UDP frontend for as long as the server runs.
struct UdpService {
    proxy: UdpProxy,
    draining: Arc<DrainCount>,
}

#[async_trait]
impl pingora::services::background::BackgroundService for UdpService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let (stop_sender, stop) = tokio::sync::watch::channel(false);
        let mut serving = std::pin::pin!(self.proxy.run(stop));

        let mut drained = false;
        let outcome = tokio::select! {
            outcome = &mut serving => outcome,
            _ = shutdown.changed() => {
                let _ = stop_sender.send(true);
                drained = true;
                // Awaited rather than dropped: the frontend is draining now,
                // and dropping the future here would cut the sessions it is
                // still carrying (ADR-0067).
                serving.await
            }
        };

        // A UDP frontend that cannot bind is a frontend that serves nothing.
        // Saying so beats a process that looks healthy and silently drops a
        // service.
        if let Err(error) = outcome {
            log::error!("udp frontend could not run: {error}");
        }

        if drained && self.draining.finished() {
            // Everything this process was carrying is gone, and pingora would
            // sleep out the rest of its grace period regardless. Leaving now
            // is what lets a replacement stop waiting.
            std::process::exit(0);
        }
    }
}

/// Runs the agent link for as long as the server runs.
/// Reads whether a socket is listening on this address out of a kernel table.
///
/// The table is `/proc/net/tcp` or `/proc/net/tcp6`, whose lines carry the
/// local address, the port and the connection state. `0A` is `TCP_LISTEN`.
///
/// A listener on the unspecified address answers for every address on its
/// port, so it counts for the one asked about. So does an IPv6 listener on
/// `::` for an IPv4 address: a socket without `IPV6_V6ONLY` accepts both.
// Read only on Linux, and measured everywhere. The parsing is what a
// measurement can hold a table against without a kernel; the file read is
// what only Linux has.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn listening_in(table: &str, wanted: SocketAddr) -> bool {
    /// The state a listening socket is in.
    const LISTEN: &str = "0A";

    table.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        let Some(local) = fields.next().and_then(|_slot| fields.next()) else {
            return false;
        };
        if fields.next().and_then(|_remote| fields.next()) != Some(LISTEN) {
            return false;
        }

        let Some((address, port)) = local.rsplit_once(':') else {
            return false;
        };
        if u16::from_str_radix(port, 16) != Ok(wanted.port()) {
            return false;
        }
        match read_address(address) {
            Some(found) => found.is_unspecified() || found == wanted.ip(),
            None => false,
        }
    })
}

/// Reads one address out of a kernel table's hex form.
///
/// Each word is a little endian `u32` printed big endian first, so the bytes
/// come back in the order the address has them by reading each word the other
/// way round.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_address(hex: &str) -> Option<std::net::IpAddr> {
    match hex.len() {
        8 => {
            let word = u32::from_str_radix(hex, 16).ok()?;
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                word.to_le_bytes(),
            )))
        }
        32 => {
            let mut bytes = [0_u8; 16];
            for (index, chunk) in hex.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Whether the kernel holds a listening socket on this address.
///
/// Both tables are read whatever the address is, because an IPv6 socket on
/// `::` carries IPv4 traffic as well and appears only in the second one.
#[cfg(target_os = "linux")]
fn listening(wanted: SocketAddr) -> bool {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .any(|table| listening_in(&table, wanted))
}

/// Says every address is listening, because this system has no such table.
///
/// The product runs on Linux (ADR-0007). Everywhere else this keeps the
/// process from waiting for an answer that will never come; what it does not
/// do is measure anything, and the state it reports says only that the
/// services were started.
#[cfg(not(target_os = "linux"))]
fn listening(_wanted: SocketAddr) -> bool {
    true
}

/// Watches this process's own listeners, and says so once they are up.
///
/// The one thing that turns "the listeners were built" into "the listeners
/// are up". Everything about this process reaching the outside world runs
/// through those sockets, and a supervisor told the process is serving before
/// they accept anything would leave this node holding an address for a
/// service that is not there (ADR-0033, ADR-0087).
///
/// Read out of the kernel rather than by connecting. A connection to a
/// frontend is a request as far as the traffic path is concerned: it is
/// accepted, a backend is chosen and a connection to it is opened. Checking
/// by connecting would cost every backend one connection per start of this
/// process, and a process that keeps crashing would keep making them.
struct ListeningCheck {
    /// The addresses to look for, in `host:port` form.
    addresses: Vec<String>,
    status: Arc<Status>,
}

#[async_trait]
impl pingora::services::background::BackgroundService for ListeningCheck {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // Nothing to check means nothing to wait for. A process with only UDP
        // frontends serves the moment its loops are running.
        if self.addresses.is_empty() {
            self.status.set_state(DataPlaneState::Serving);
            return;
        }

        let mut left: Vec<SocketAddr> = self
            .addresses
            .iter()
            // An address this process cannot parse is one it never asked the
            // kernel for either, so waiting on it would be waiting for ever.
            .filter_map(|address| address.parse().ok())
            .collect();
        loop {
            left.retain(|address| !listening(*address));
            if left.is_empty() {
                log::info!("data-plane: every listener is up, so this process is serving");
                self.status.set_state(DataPlaneState::Serving);
                return;
            }

            tokio::select! {
                () = tokio::time::sleep(LISTENING_CHECK_INTERVAL) => {}
                _ = shutdown.changed() => return,
            }
        }
    }
}

struct LinkService {
    link: AgentLink,
}

#[async_trait]
impl pingora::services::background::BackgroundService for LinkService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let (stop_sender, stop) = tokio::sync::watch::channel(false);
        let link = self.link.run(stop);

        tokio::select! {
            () = link => {}
            _ = shutdown.changed() => {
                let _ = stop_sender.send(true);
            }
        }
    }
}

/// Keeps one probe task per checked member, following the configuration.
///
/// A configuration change stops the tasks that no longer apply and starts the
/// ones that now do. What it never does is reset the health of a member that
/// did not change, because a pool edit elsewhere is not evidence about this
/// member.
struct HealthService {
    live: Arc<LiveConfig>,
    health: Arc<Health>,
}

/// How often the service looks for a configuration change.
///
/// Short enough that a new member starts being probed promptly, long enough
/// that the comparison costs nothing.
const RESCAN: Duration = Duration::from_millis(500);

#[async_trait]
impl pingora::services::background::BackgroundService for HealthService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut running: BTreeMap<(String, String), Running> = BTreeMap::new();

        loop {
            let live = self.live.load();
            let wanted = checked(&live.config);

            // Stop what is gone or has changed, keep what is untouched.
            let keep: BTreeMap<(String, String), Checked> = wanted
                .into_iter()
                .map(|target| ((target.pool.clone(), target.member.clone()), target))
                .collect();
            running.retain(|key, task| {
                let same = keep.get(key).is_some_and(|target| *target == task.target);
                if !same {
                    task.stop();
                }
                same
            });

            // Start what is new.
            for (key, target) in keep {
                if running.contains_key(&key) {
                    continue;
                }
                let (stop, listen) = tokio::sync::watch::channel(false);
                let handle = tokio::spawn(watch(Arc::clone(&self.health), target.clone(), listen));
                running.insert(
                    key,
                    Running {
                        target,
                        stop,
                        handle,
                    },
                );
            }

            // A member that has left the configuration keeps no state.
            self.health.retain(&live.config);

            tokio::select! {
                () = tokio::time::sleep(RESCAN) => {}
                _ = shutdown.changed() => {
                    for (_, task) in running {
                        task.stop();
                    }
                    return;
                }
            }
        }
    }
}

/// One probe task and the handle that stops it.
struct Running {
    target: Checked,
    stop: tokio::sync::watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

impl Running {
    fn stop(&self) {
        let _ = self.stop.send(true);
        self.handle.abort();
    }
}

#[cfg(test)]
// Test code may panic on a broken precondition. Product code may not.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;
    #[cfg(target_os = "linux")]
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use pingora::services::background::BackgroundService as _;

    use super::{DataPlaneState, ListeningCheck, Status, listening_in};

    /// A table with a header line, as the kernel writes it.
    fn table(rows: &[&str]) -> String {
        let mut written = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
        for row in rows {
            written.push_str(row);
            written.push('\n');
        }
        written
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("the address is one this test wrote")
    }

    #[test]
    fn a_listening_socket_is_found_where_the_kernel_wrote_it() {
        // 0100007F is 127.0.0.1 and 1F91 is 8081. The kernel prints each word
        // of the address the other way round, so a reader that took the hex
        // at face value would look for 1.0.0.127.
        let held = table(&[
            "   0: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1",
        ]);
        assert!(listening_in(&held, address("127.0.0.1:8081")));
    }

    #[test]
    fn a_socket_that_is_not_listening_is_not_one_to_serve_on() {
        // 01 is ESTABLISHED. A connection to this address is not a listener
        // on it, and a process that took one for the other would call itself
        // serving because somebody was talking to it.
        let held = table(&[
            "   0: 0100007F:1F91 0100007F:9C40 01 00000000:00000000 00:00000000 00000000 0 0 1 1",
        ]);
        assert!(!listening_in(&held, address("127.0.0.1:8081")));
    }

    #[test]
    fn a_listener_on_another_port_is_not_the_one_asked_about() {
        let held = table(&[
            "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1",
        ]);
        assert!(!listening_in(&held, address("127.0.0.1:8081")));
    }

    #[test]
    fn a_listener_on_another_address_is_not_the_one_asked_about() {
        // Two frontends on one port and two addresses is ordinary: one
        // virtual address per service. A reader that matched on the port
        // alone would call a process serving an address it never bound.
        let held = table(&[
            "   0: 0B001CAC:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1",
        ]);
        assert!(!listening_in(&held, address("172.28.0.12:8081")));
        assert!(listening_in(&held, address("172.28.0.11:8081")));
    }

    #[test]
    fn a_listener_on_every_address_covers_the_one_asked_about() {
        let held = table(&[
            "   0: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1",
        ]);
        assert!(listening_in(&held, address("172.28.0.11:8081")));
    }

    #[test]
    fn an_ipv6_listener_is_read_word_by_word() {
        // ::1, which the kernel writes as four words with each one reversed.
        let held = table(&[
            "   0: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1",
        ]);
        assert!(listening_in(&held, address("[::1]:8081")));
        assert!(!listening_in(&held, address("[::2]:8081")));
    }

    #[test]
    fn an_ipv6_listener_on_every_address_covers_an_ipv4_one() {
        // A socket on `::` without IPV6_V6ONLY accepts IPv4 as well, and it
        // appears in the second table only. A reader that skipped it would
        // wait for ever for a listener that is up.
        let held = table(&[
            "   0: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1",
        ]);
        assert!(listening_in(&held, address("172.28.0.11:8081")));
    }

    #[test]
    fn an_empty_table_holds_no_listener() {
        assert!(!listening_in(&table(&[]), address("127.0.0.1:8081")));
    }

    /// Runs the check against these addresses and hands back what it watches.
    fn checking(addresses: Vec<String>) -> (Arc<Status>, tokio::task::JoinHandle<()>) {
        let status = Arc::new(Status::default());
        let watched = Arc::clone(&status);
        let (_sender, shutdown) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move {
            ListeningCheck {
                addresses,
                status: watched,
            }
            .start(shutdown)
            .await;
        });
        (status, handle)
    }

    /// Waits for a state, and says which one it saw when it gives up.
    async fn reaches(status: &Status, wanted: DataPlaneState, patience: Duration) {
        let deadline = Instant::now() + patience;
        while Instant::now() < deadline {
            if status.state() == wanted {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "the process reported {:?} rather than {wanted:?}",
            status.state()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_process_is_not_serving_until_every_listener_is_up() {
        // The defect this measures was found in the lab: a listener that
        // could not bind panicked its own thread, the process kept answering
        // the agent, and this node held the virtual address for a service
        // that was not there (ADR-0087).
        let up = TcpListener::bind("127.0.0.1:0").expect("a port should be free");
        let answering = up.local_addr().expect("the listener has an address");

        // A port nothing listens on. Bound and dropped, so the number is one
        // the kernel handed out rather than one this test hoped was free.
        let closed = TcpListener::bind("127.0.0.1:0").expect("a port should be free");
        let refusing = closed.local_addr().expect("the listener has an address");
        drop(closed);

        let (status, handle) = checking(vec![answering.to_string(), refusing.to_string()]);

        // One of the two is up, which is not enough.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            status.state(),
            DataPlaneState::Starting,
            "the process called itself serving while one of its listeners was \
             not there"
        );

        handle.abort();
        drop(up);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_process_whose_listeners_are_all_up_is_serving() {
        let first = TcpListener::bind("127.0.0.1:0").expect("a port should be free");
        let second = TcpListener::bind("127.0.0.1:0").expect("a port should be free");
        let addresses = vec![
            first
                .local_addr()
                .expect("the listener has an address")
                .to_string(),
            second
                .local_addr()
                .expect("the listener has an address")
                .to_string(),
        ];

        let (status, handle) = checking(addresses);
        reaches(&status, DataPlaneState::Serving, Duration::from_secs(5)).await;
        handle.abort();
    }

    #[tokio::test]
    async fn a_process_with_nothing_to_bind_serves_at_once() {
        // A configuration with only UDP frontends has no TCP listener to look
        // for. Waiting for one would leave the claim down for ever.
        let (status, handle) = checking(Vec::new());
        reaches(&status, DataPlaneState::Serving, Duration::from_secs(5)).await;
        handle.abort();
    }
}
