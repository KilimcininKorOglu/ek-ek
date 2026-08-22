// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The L4 TCP proxy.
//!
//! A database client, an SMTP session and an RDP desktop are not HTTP and must
//! not be parsed as if they were. This path forwards bytes and nothing else:
//! it never reads a request, never rewrites a header and never assumes a
//! message boundary exists.
//!
//! # Both directions, one connection
//!
//! Client to backend and backend to client are copied at the same time, so
//! neither waits for the other. A protocol where the server speaks first, as
//! SMTP and PostgreSQL both do, works only because of that.
//!
//! # Closing
//!
//! When either side goes away, the other is dropped with it. Half-closing and
//! waiting would leave a socket held open by a peer that has already gone, and
//! a busy frontend would run out of file descriptors long before anyone
//! noticed.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ek_ek_config::{Config, ProxyProtocol};
use pingora::apps::ServerApp;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::balance::Balancer;
use crate::live::{Live, LiveConfig, Status};
use crate::proxy::elapsed_ms;
use crate::proxyproto;
use crate::requestid;

/// How much is moved in one copy step.
///
/// Large enough that a megabyte is a handful of steps rather than a thousand,
/// small enough that a mostly idle connection does not hold it for nothing.
const CHUNK: usize = 16 * 1024;

/// Proxies one L4 frontend.
pub struct StreamProxy {
    /// Which frontend this serves.
    frontend: String,
    /// The live configuration, shared with every other frontend.
    live: Arc<LiveConfig>,
    /// Counters reported to the agent.
    status: Arc<Status>,
    /// Connection counts and the round robin cursor.
    balancer: Arc<Balancer>,
    /// Connections this frontend has taken, which access log sampling counts
    /// against.
    seen: AtomicU64,
}

/// What one connection was routed to.
///
/// Held so the count can come back down when the connection ends, whichever
/// way it ends.
struct Routed {
    pool: String,
    member: String,
    address: SocketAddr,
    connect_timeout: Duration,
    idle_timeout: Option<Duration>,
    /// Which PROXY header, if any, this backend is told the client with.
    proxy_protocol: ProxyProtocol,
    /// Whether this connection gets an access record, decided from the same
    /// snapshot as everything else.
    logged: bool,
}

impl StreamProxy {
    /// Builds a proxy for one L4 frontend.
    #[must_use]
    pub fn new(
        frontend: String,
        live: Arc<LiveConfig>,
        status: Arc<Status>,
        balancer: Arc<Balancer>,
    ) -> Self {
        Self {
            frontend,
            live,
            status,
            balancer,
            seen: AtomicU64::new(0),
        }
    }

    /// Decides where one connection goes.
    ///
    /// Reads the live configuration exactly once. Everything the connection
    /// needs afterwards comes out of the value returned here, so a
    /// configuration change never moves a connection that is already up
    /// (ADR-0009).
    fn route(&self, live: &Live, client: IpAddr) -> Option<Routed> {
        let frontend = live
            .config
            .frontends
            .iter()
            .find(|frontend| frontend.id.as_str() == self.frontend)?;
        // An L4 frontend routes to one pool. Host and path do not exist here,
        // so there is nothing for a routing rule to match on.
        let name = frontend.default_backend.as_ref()?.as_str();
        let pool = live
            .config
            .backends
            .iter()
            .find(|pool| pool.id.as_str() == name)?;
        let member = self.balancer.choose(pool, &live.ring(name), client)?;

        Some(Routed {
            pool: name.to_owned(),
            member: member.id.as_str().to_owned(),
            address: SocketAddr::new(member.address, member.port),
            connect_timeout: Duration::from_secs(u64::from(frontend.connect_timeout_seconds)),
            // Zero means no limit (ADR-0060).
            idle_timeout: match frontend.idle_timeout_seconds {
                0 => None,
                seconds => Some(Duration::from_secs(u64::from(seconds))),
            },
            proxy_protocol: frontend.proxy_protocol,
            logged: frontend
                .access_log
                .writes(self.seen.fetch_add(1, Ordering::Relaxed)),
        })
    }
}

/// Where a frontend's connections come from, for counting.
///
/// Kept as its own type so the count is always decremented against exactly the
/// key it was incremented against.
struct Counted<'a> {
    balancer: &'a Balancer,
    frontend: &'a str,
    pool: String,
    member: String,
}

impl<'a> Counted<'a> {
    fn open(balancer: &'a Balancer, frontend: &'a str, pool: &str, member: &str) -> Self {
        balancer.opened(frontend, pool, member);
        Self {
            balancer,
            frontend,
            pool: pool.to_owned(),
            member: member.to_owned(),
        }
    }
}

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        // On drop rather than at the end of the copy, so a panic, an early
        // return or a shutdown all bring the count down. A member left
        // looking busy would never be chosen by least connections again.
        self.balancer
            .closed(self.frontend, &self.pool, &self.member);
    }
}

/// Copies bytes both ways until one side goes away.
///
/// Returns how many bytes moved in each direction, which is what lets a test
/// assert that a megabyte crossed rather than that the call returned.
async fn couple(
    client: &mut Stream,
    backend: &mut TcpStream,
    idle_timeout: Option<Duration>,
) -> io::Result<(u64, u64)> {
    let mut to_backend = 0_u64;
    let mut from_backend = 0_u64;
    let mut upward = vec![0_u8; CHUNK];
    let mut downward = vec![0_u8; CHUNK];

    loop {
        let step = async {
            tokio::select! {
                read = client.read(&mut upward) => {
                    let read = read?;
                    if read == 0 {
                        // The client is done. The backend has nobody left to
                        // answer, so it goes too.
                        return Ok(Moved::ClientClosed);
                    }
                    backend.write_all(&upward[..read]).await?;
                    backend.flush().await?;
                    Ok(Moved::Up(read as u64))
                }
                read = backend.read(&mut downward) => {
                    let read = read?;
                    if read == 0 {
                        return Ok(Moved::BackendClosed);
                    }
                    client.write_all(&downward[..read]).await?;
                    client.flush().await?;
                    Ok(Moved::Down(read as u64))
                }
            }
        };

        let moved: io::Result<Moved> = match idle_timeout {
            // The limit is on one quiet stretch, not on the whole connection.
            // Any byte in either direction restarts it, because a connection
            // waiting for a slow query is working rather than idle.
            Some(limit) => match tokio::time::timeout(limit, step).await {
                Ok(moved) => moved,
                Err(_) => return Ok((to_backend, from_backend)),
            },
            None => step.await,
        };

        match moved? {
            Moved::Up(count) => to_backend += count,
            Moved::Down(count) => from_backend += count,
            Moved::ClientClosed | Moved::BackendClosed => {
                return Ok((to_backend, from_backend));
            }
        }
    }
}

/// What one copy step did.
enum Moved {
    /// Bytes went to the backend.
    Up(u64),
    /// Bytes came back.
    Down(u64),
    /// The client hung up.
    ClientClosed,
    /// The backend hung up.
    BackendClosed,
}

/// The address a connection came from.
///
/// A socket whose address cannot be read is served from the unspecified
/// address rather than refused: the connection is real, only its origin is
/// unreadable, and source hashing simply lands everybody on one member.
fn client_address(client: &Stream) -> IpAddr {
    ends(client).map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |(peer, _)| peer.ip())
}

/// Both ends of an accepted connection, with their ports.
///
/// A PROXY header states four things, and the port is two of them: an
/// Exchange connector matching on address alone still needs the port to tell
/// two sessions from one host apart in its own log.
fn ends(client: &Stream) -> Option<(SocketAddr, SocketAddr)> {
    let digest = client.get_socket_digest()?;
    let peer = *digest.peer_addr()?.as_inet()?;
    let local = *digest.local_addr()?.as_inet()?;
    Some((peer, local))
}

/// The PROXY header this connection opens with, if any.
///
/// A frontend with the protocol turned off sends nothing at all, which is
/// what keeps a backend that does not expect a header working (ADR-0043).
#[must_use]
pub fn announce(
    format: ProxyProtocol,
    ends: Option<(SocketAddr, SocketAddr)>,
    status: &Status,
) -> Option<Vec<u8>> {
    let header = match ends {
        Some((peer, local)) => proxyproto::header(format, peer, local),
        // The connection is real and the backend is waiting for a header, so
        // one is sent saying no address is being stated. Sending nothing
        // would leave the backend reading the client's first bytes as a
        // header and refusing the connection.
        None => proxyproto::unknown(format),
    }?;

    if !header.states_an_address() {
        // The backend is about to decide on the load balancer's address, and
        // nothing else would say so (ADR-0043).
        status.proxy_header_without_an_address();
    }
    Some(header.bytes().to_vec())
}

/// Whether a configuration says this frontend is an L4 listener.
#[must_use]
pub fn is_stream_frontend(config: &Config, frontend: &str) -> bool {
    config.frontends.iter().any(|candidate| {
        candidate.id.as_str() == frontend
            && candidate.application == ek_ek_config::ApplicationProtocol::Raw
    })
}

#[async_trait]
impl ServerApp for StreamProxy {
    async fn process_new(
        self: &Arc<Self>,
        mut client: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let live = self.live.load();
        self.status.request_handled();
        let started = Instant::now();
        // Generated rather than read from the connection: an L4 stream has no
        // header to carry one in, and the record still needs an identity the
        // application log can be joined on (ADR-0037).
        let request_id = requestid::generate();

        let address = client_address(&client);

        let Some(routed) = self.route(&live, address) else {
            // Nowhere to send it. There is no status line to answer with on a
            // raw connection, so closing is the only thing left; what matters
            // is that it is closed here rather than left hanging.
            return None;
        };

        let backend =
            tokio::time::timeout(routed.connect_timeout, TcpStream::connect(routed.address)).await;
        let Ok(Ok(mut backend)) = backend else {
            // Unreachable member. The client connection is closed without
            // anything having been forwarded, so nothing is half-sent.
            //
            // Counted rather than turned into a degraded state: one refused
            // connection is not a sick node, and a state with no way back
            // would drop this node's VRRP priority over a single blip.
            self.status.backend_connect_failed();
            return None;
        };
        // Small writes go out immediately. A protocol that waits for a short
        // reply, which is most of them, otherwise pays the delay every turn.
        let _ = backend.set_nodelay(true);

        // Written before anything the client sent, and only here, so a
        // backend reading it as the first bytes of the connection is right to
        // and reads it exactly once (ADR-0043). On a TLS passthrough frontend
        // this is also before the ClientHello, which is why the handshake is
        // unaffected.
        if let Some(header) = announce(routed.proxy_protocol, ends(&client), &self.status)
            && (backend.write_all(&header).await.is_err() || backend.flush().await.is_err())
        {
            // The backend went away before the header landed. Nothing of the
            // client's has been forwarded, so closing here leaves no
            // half-written session behind.
            self.status.backend_connect_failed();
            return None;
        }

        let counted = Counted::open(&self.balancer, &self.frontend, &routed.pool, &routed.member);
        let moved = couple(&mut client, &mut backend, routed.idle_timeout).await;
        drop(counted);

        if routed.logged {
            let (to_backend, from_backend) = moved.unwrap_or((0, 0));
            let client =
                ends(&client).map_or_else(|| address.to_string(), |(peer, _)| peer.to_string());
            ek_ek_log::access(
                &ek_ek_log::Access::new(
                    ek_ek_log::Protocol::Tcp,
                    &self.frontend,
                    &client,
                    elapsed_ms(started),
                )
                .with_request_id(&request_id)
                .to_backend(&routed.pool, &routed.member)
                .tcp(to_backend, from_backend),
            );
        }

        // Never reused: this connection carried an opaque protocol and there
        // is no message boundary to hand the next one a clean start from.
        None
    }
}
