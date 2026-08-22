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
use ek_ek_config::{ApplicationProtocol, Config, TransportProtocol};
use ek_ek_ipc::DataPlaneState;
use pingora::apps::HttpServerOptions;
use pingora::listeners::tls::TlsSettings;
use pingora::server::{Server, ShutdownWatch};
use pingora::services::background::background_service;
use pingora::services::listening::Service;

use crate::balance::Balancer;
use crate::error::{Error, ErrorKind, Result};
use crate::handshake::SniResolver;
use crate::health::{Checked, Health, checked, watch};
use crate::link::AgentLink;
use crate::live::LiveConfig;
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
        // TLS passthrough needs the ClientHello read before a member is
        // chosen, which arrives with M4. It has no listener until then.
        let kind = match frontend.application {
            ApplicationProtocol::Http => ListenerKind::Http,
            ApplicationProtocol::Raw => ListenerKind::Stream,
            ApplicationProtocol::TlsPassthrough => continue,
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
                    service.add_tls_with_settings(&binding.address, None, settings);
                } else {
                    service.add_tcp(&binding.address);
                }
                server.add_service(service);
            }
            ListenerKind::Stream => {
                let proxy = StreamProxy::new(
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

    status.set_state(DataPlaneState::Serving);
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

/// The shortest a process may take to leave once it has been asked to.
///
/// pingora sleeps for the grace period after it has told every service to
/// stop, so this is a floor under how long a replacement waits for the
/// process it is replacing.
const LEAST_GRACE: u64 = 1;

/// How long the runtimes get to unwind once the grace period has passed.
const RUNTIME_SHUTDOWN: u64 = 5;

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
