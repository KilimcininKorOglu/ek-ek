// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The UDP traffic path.
//!
//! pingora is TCP only, so this is written by hand and runs beside it in the
//! same process (ADR-0017). One socket takes datagrams from clients; each
//! session holds its own socket to the member it was pinned to, because a
//! datagram coming back names only the member it came from (ADR-0066).
//!
//! A session's return socket is read by its own task, which writes the
//! answer back to the client through the shared listening socket. The task
//! ends when the session leaves the table, whether it expired, was evicted,
//! or lost the member it was pinned to.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ek_ek_config::{Backend, Config, Frontend, TransportProtocol};
use tokio::net::UdpSocket;

use crate::balance::Balancer;
use crate::live::{Live, LiveConfig, Status};
use crate::udp::Sessions;

/// The largest datagram read in one go.
///
/// Above the standard MTU, so a jumbo frame that does arrive is forwarded
/// whole rather than truncated. Fragmentation itself is out of scope.
const MOST: usize = 9_216;

/// How often the table is swept for sessions that have gone idle.
const SWEEP: Duration = Duration::from_millis(500);

/// The return half of a session.
///
/// Holding the task handle here is what ties the reader's lifetime to the
/// session's: dropping the session aborts the task, so a session that leaves
/// the table takes its socket and its reader with it.
#[derive(Debug)]
pub struct Upstream {
    socket: Arc<UdpSocket>,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Serves one UDP frontend.
pub struct UdpProxy {
    /// Which frontend this serves.
    frontend: String,
    /// Where it listens.
    address: SocketAddr,
    /// The live configuration, shared with every other frontend.
    live: Arc<LiveConfig>,
    /// Counters reported to the agent.
    status: Arc<Status>,
    /// Chooses members and knows which are healthy.
    balancer: Arc<Balancer>,
}

impl UdpProxy {
    /// Builds a proxy for one UDP frontend.
    #[must_use]
    pub fn new(
        frontend: String,
        address: SocketAddr,
        live: Arc<LiveConfig>,
        status: Arc<Status>,
        balancer: Arc<Balancer>,
    ) -> Self {
        Self {
            frontend,
            address,
            live,
            status,
            balancer,
        }
    }

    /// Takes datagrams until told to stop.
    ///
    /// # Errors
    ///
    /// Fails when the listening socket cannot be bound.
    pub async fn run(&self, mut stop: tokio::sync::watch::Receiver<bool>) -> std::io::Result<()> {
        let listener = Arc::new(UdpSocket::bind(self.address).await?);
        let settings = self.settings();
        let mut sessions: Sessions<Upstream> = Sessions::new(settings.0, settings.1);
        let stats = self.status.udp_frontend(&self.frontend, sessions.limit());

        let mut buffer = vec![0_u8; MOST];
        let mut sweep = tokio::time::interval(SWEEP);

        loop {
            tokio::select! {
                received = listener.recv_from(&mut buffer) => {
                    let Ok((read, client)) = received else { continue };
                    self.forward(&mut sessions, &listener, client, &buffer[..read]).await;
                    stats.set(sessions.len() as u64, sessions.evicted());
                }
                _ = sweep.tick() => {
                    // A configuration change may have moved the limit or the
                    // idle timeout, so both are re-read here rather than only
                    // at startup.
                    let settings = self.settings();
                    drop(sessions.retune(settings.0, settings.1));
                    stats.set_limit(sessions.limit() as u64);
                    // Sessions that went quiet are dropped here rather than
                    // when the table fills, so a table of one-shot clients
                    // empties on its own instead of evicting live sessions
                    // to make room.
                    drop(sessions.expire(Instant::now()));
                    self.drop_missing_members(&mut sessions);
                    stats.set(sessions.len() as u64, sessions.evicted());
                }
                _ = stop.changed() => {
                    drop(sessions.clear());
                    stats.set(0, sessions.evicted());
                    return Ok(());
                }
            }
        }
    }

    /// Reads this frontend's session settings from the live configuration.
    fn settings(&self) -> (u32, u32) {
        let live = self.live.load();
        frontend(&live, &self.frontend).map_or((0, 0), |frontend| {
            (frontend.udp_session_limit, frontend.idle_timeout_seconds)
        })
    }

    /// Sends one datagram on, opening a session for a client that has none.
    async fn forward(
        &self,
        sessions: &mut Sessions<Upstream>,
        listener: &Arc<UdpSocket>,
        client: SocketAddr,
        datagram: &[u8],
    ) {
        let now = Instant::now();
        if let Some(session) = sessions.refresh(client, now) {
            let _ = session.socket.socket.send(datagram).await;
            return;
        }

        // The only place the live configuration is read for this datagram.
        let live = self.live.load();
        let Some(frontend) = frontend(&live, &self.frontend) else {
            return;
        };
        let Some(name) = frontend.default_backend.as_ref().map(|pool| pool.as_str()) else {
            return;
        };
        let Some(pool) = pool(&live, name) else {
            return;
        };
        // Consistent hashing over the client's address and port, which is
        // what lets an evicted session land on the same member (ADR-0025).
        // The port is part of the key here and not on TCP: a datagram has no
        // connection, so the pair is what identifies a session.
        let Some(member) =
            self.balancer
                .choose_by(pool, &live.ring(name), client.to_string().as_bytes())
        else {
            // Nobody can take it. A datagram has no status code to answer
            // with, so it is dropped rather than sent to a member known to
            // be down (ADR-0062).
            return;
        };

        let target = SocketAddr::new(member.address, member.port);
        let Some(upstream) = open(target, client, Arc::clone(listener)).await else {
            self.status.backend_connect_failed();
            return;
        };
        let _ = upstream.socket.send(datagram).await;

        // The evicted session is dropped here, which aborts its reader and
        // closes its socket. Leaving it to the map would leak a descriptor.
        drop(sessions.insert(
            client,
            name.to_owned(),
            member.id.as_str().to_owned(),
            target,
            upstream,
            now,
        ));
    }

    /// Drops sessions pinned to a member the configuration no longer names.
    fn drop_missing_members(&self, sessions: &mut Sessions<Upstream>) {
        let live = self.live.load();
        drop(sessions.retain_members(|name, member| {
            pool(&live, name).is_some_and(|pool| {
                self.balancer
                    .eligible(pool)
                    .iter()
                    .any(|candidate| candidate.id.as_str() == member)
            })
        }));
    }
}

/// Opens the socket a session sends on, and starts the task that reads its
/// answers back.
async fn open(
    target: SocketAddr,
    client: SocketAddr,
    listener: Arc<UdpSocket>,
) -> Option<Upstream> {
    // Bound to the same family as the member, so an IPv6 member does not get
    // a socket that cannot reach it.
    let local = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = Arc::new(UdpSocket::bind(local).await.ok()?);
    socket.connect(target).await.ok()?;

    let reading = Arc::clone(&socket);
    let reader = tokio::spawn(async move {
        let mut buffer = vec![0_u8; MOST];
        loop {
            match reading.recv(&mut buffer).await {
                Ok(read) => {
                    // Back through the listening socket, so the client sees
                    // the answer coming from the address it wrote to.
                    let _ = listener.send_to(&buffer[..read], client).await;
                }
                Err(_) => return,
            }
        }
    });

    Some(Upstream { socket, reader })
}

/// Finds a frontend by identity.
fn frontend<'a>(live: &'a Live, name: &str) -> Option<&'a Frontend> {
    live.config
        .frontends
        .iter()
        .find(|frontend| frontend.id.as_str() == name)
}

/// Finds a pool by identity.
fn pool<'a>(live: &'a Live, name: &str) -> Option<&'a Backend> {
    live.config
        .backends
        .iter()
        .find(|pool| pool.id.as_str() == name)
}

/// Where a UDP frontend listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpBinding {
    /// The frontend this belongs to.
    pub frontend: String,
    /// The address it listens on.
    pub address: SocketAddr,
}

/// Works out which UDP listeners a configuration asks for.
///
/// Returns nothing for a frontend whose VIP is missing rather than failing:
/// validation catches that first, and a listener that cannot be placed is
/// simply not opened.
#[must_use]
pub fn udp_bindings(config: &Config) -> Vec<UdpBinding> {
    let mut bindings = Vec::new();
    for frontend in &config.frontends {
        if frontend.transport != TransportProtocol::Udp {
            continue;
        }
        let Some(vip) = config.vips.iter().find(|vip| vip.id == frontend.vip) else {
            continue;
        };
        bindings.push(UdpBinding {
            frontend: frontend.id.as_str().to_owned(),
            address: SocketAddr::new(vip.address, frontend.port),
        });
    }
    bindings
}
