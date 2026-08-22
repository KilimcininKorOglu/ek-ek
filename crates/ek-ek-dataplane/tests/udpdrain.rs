// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a UDP frontend does once it has been told to stop.
//!
//! Measured against the frontend directly rather than through two processes.
//! How a `SO_REUSEPORT` group splits datagrams differs between systems, so a
//! test that drove the drain through a replacement process would measure the
//! kernel's split on the machine it happened to run on. Here the frontend is
//! the only one holding the port, so every datagram reaches the code under
//! test.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use ek_ek_config::{
    AdminState, ApplicationProtocol, Backend, BackendId, BackendMember, Config, ConnectionPooling,
    Frontend, FrontendId, Http2, LoadBalancingAlgorithm, MemberId, Node, NodeId, NodeRole,
    ProxyProtocol, SchemaVersion, SessionStickiness, TransportProtocol, Vip, VipId,
};
use ek_ek_dataplane::udpproxy::UdpProxy;
use ek_ek_dataplane::{Balancer, LiveConfig, Status};
use tokio::net::UdpSocket;

#[allow(dead_code)]
mod common;

/// How long a datagram may take to come back.
const ANSWER: Duration = Duration::from_millis(800);

/// A stand-in backend that answers every datagram with its own name.
async fn member(name: &str) -> (u16, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a backend port must be free");
    let port = socket.local_addr().expect("it must have one").port();
    let identity = name.to_owned();

    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 4096];
        loop {
            let Ok((read, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let payload = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let _ = socket
                .send_to(format!("{identity}:{payload}").as_bytes(), from)
                .await;
        }
    });
    (port, task)
}

/// A configuration with one UDP frontend and one member.
fn document(port: u16, member_port: u16, idle: u32, drain: u32) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: vec![Node {
            id: NodeId::new("node1"),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
        }],
        vips: vec![Vip {
            id: VipId::new("vip"),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix_length: 8,
            interface: "lo".to_owned(),
            preferred_node: Some(NodeId::new("node1")),
        }],
        frontends: vec![Frontend {
            id: FrontendId::new("dns"),
            vip: VipId::new("vip"),
            port,
            transport: TransportProtocol::Udp,
            application: ApplicationProtocol::Raw,
            tls: None,
            proxy_protocol: ProxyProtocol::Disabled,
            routing_rules: Vec::new(),
            sni_rules: Vec::new(),
            default_backend: Some(BackendId::new("pool")),
            http2: Http2::Enabled,
            connect_timeout_seconds: 2,
            request_timeout_seconds: 5,
            idle_timeout_seconds: idle,
            drain_timeout_seconds: drain,
            udp_session_limit: 0,
        }],
        backends: vec![Backend {
            id: BackendId::new("pool"),
            members: vec![BackendMember {
                id: MemberId::new("one"),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: member_port,
                weight: 1,
                admin_state: AdminState::Enabled,
            }],
            algorithm: LoadBalancingAlgorithm::ConsistentHash,
            health_check: None,
            stickiness: SessionStickiness::Disabled,
            connection_pooling: ConnectionPooling::Enabled,
        }],
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        stickiness_key: String::new(),
    }
}

/// A frontend running on a port of its own, with the pieces a test pokes at.
struct Running {
    port: u16,
    status: Arc<Status>,
    stop: tokio::sync::watch::Sender<bool>,
    running: tokio::task::JoinHandle<std::io::Result<()>>,
    _member: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn start(idle: u32, drain: u32) -> Self {
        let (member_port, member_task) = member("one").await;
        let port = common::free_port();
        let live = Arc::new(LiveConfig::new(ek_ek_ipc::ConfigUpdate {
            generation: 1,
            config: document(port, member_port, idle, drain),
            certificates: std::collections::BTreeMap::new(),
        }));
        let status = Arc::new(Status::new());
        let balancer = Arc::new(Balancer::new());
        status.watch(Arc::clone(&balancer));

        let proxy = UdpProxy::new(
            "dns".to_owned(),
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Arc::clone(&live),
            Arc::clone(&status),
            balancer,
        );
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let running = tokio::spawn(async move { proxy.run(receiver).await });

        let frontend = Self {
            port,
            status,
            stop,
            running,
            _member: member_task,
        };
        frontend.wait_until_answering().await;
        frontend
    }

    /// Opens a client and asks once, so the frontend is known to be up.
    async fn wait_until_answering(&self) {
        for _ in 0..200 {
            let client = Client::open(self.port).await;
            if client.ask("ready").await.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the frontend never answered on port {}", self.port);
    }

    /// How many sessions its table holds right now.
    fn sessions(&self) -> u64 {
        self.status
            .udp_sessions()
            .into_iter()
            .find(|entry| entry.frontend == "dns")
            .map_or(0, |entry| entry.count)
    }

    /// Tells it to drain.
    fn ask_to_drain(&self) {
        let _ = self.stop.send(true);
    }

    /// Waits for the run loop to end, returning how long it took.
    async fn wait_for_end(&mut self, patience: Duration) -> Option<Duration> {
        let start = tokio::time::Instant::now();
        match tokio::time::timeout(patience, &mut self.running).await {
            Ok(_) => Some(start.elapsed()),
            Err(_) => None,
        }
    }
}

/// One client, holding its own socket so its source port stays the same.
struct Client {
    socket: UdpSocket,
    target: std::net::SocketAddr,
}

impl Client {
    async fn open(port: u16) -> Self {
        Self {
            socket: UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("a client port must be free"),
            target: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// Sends one datagram and waits briefly for the answer.
    async fn ask(&self, payload: &str) -> Option<String> {
        self.socket
            .send_to(payload.as_bytes(), self.target)
            .await
            .ok()?;
        let mut buffer = vec![0_u8; 4096];
        let read = tokio::time::timeout(ANSWER, self.socket.recv(&mut buffer))
            .await
            .ok()?
            .ok()?;
        Some(String::from_utf8_lossy(&buffer[..read]).into_owned())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draining_frontend_still_answers_a_client_it_has_no_session_for() {
    // Dropping the datagram would be a measurable loss, and the replacement
    // may not have taken over yet (ADR-0067).
    let frontend = Running::start(60, 30).await;
    let known = Client::open(frontend.port).await;
    assert!(known.ask("first").await.is_some(), "the setup must work");

    frontend.ask_to_drain();

    let fresh = Client::open(frontend.port).await;
    let answer = fresh.ask("during-drain").await;

    assert_eq!(
        answer,
        Some("one:during-drain".to_owned()),
        "a draining frontend dropped a datagram from a new client"
    );
    frontend.stop.send(true).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draining_frontend_puts_no_new_client_in_its_table() {
    // The other half of the same rule: the datagram goes on, but the table
    // only shrinks from here, otherwise it never empties.
    let frontend = Running::start(60, 30).await;
    let known = Client::open(frontend.port).await;
    assert!(known.ask("first").await.is_some());
    // The readiness client and this one are both in the table by now.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let before = frontend.sessions();
    assert!(before > 0, "the table was empty before the drain started");

    frontend.ask_to_drain();

    for number in 0..5 {
        let fresh = Client::open(frontend.port).await;
        assert!(
            fresh.ask(&format!("new-{number}")).await.is_some(),
            "a datagram was dropped during the drain"
        );
    }
    tokio::time::sleep(Duration::from_millis(700)).await;

    assert!(
        frontend.sessions() <= before,
        "the table grew during the drain: {} was {before}",
        frontend.sessions()
    );
    frontend.stop.send(true).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drain_ends_as_soon_as_the_table_is_empty() {
    // A drain window far longer than the idle window, so ending when the
    // table empties and waiting the window out are far apart.
    let mut frontend = Running::start(1, 30).await;
    let client = Client::open(frontend.port).await;
    assert!(client.ask("hello").await.is_some());

    frontend.ask_to_drain();
    let took = frontend
        .wait_for_end(Duration::from_secs(25))
        .await
        .expect("the drain never ended");

    assert!(
        took < Duration::from_secs(10),
        "the drain waited out its window of 30s instead of ending when the table emptied: {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drain_ends_when_its_window_runs_out() {
    // The other side. Traffic keeps a session alive, so the table never
    // empties and only the window can end the drain.
    let mut frontend = Running::start(600, 3).await;
    let client = Client::open(frontend.port).await;
    assert!(client.ask("hello").await.is_some());

    frontend.ask_to_drain();
    let keeping = tokio::spawn(async move {
        for _ in 0..60 {
            let _ = client.ask("keep").await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    let took = frontend
        .wait_for_end(Duration::from_secs(25))
        .await
        .expect("the drain never ended");
    keeping.abort();

    assert!(
        took >= Duration::from_secs(3),
        "the drain ended before its window although a session was in use: {took:?}"
    );
    assert!(
        took < Duration::from_secs(10),
        "the drain outlived its window of 3s: {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frontend_that_was_never_told_to_stop_keeps_running() {
    // The other side of the shutdown rule: nothing ends a frontend that was
    // not asked to stop.
    let mut frontend = Running::start(1, 1).await;
    let client = Client::open(frontend.port).await;
    assert!(client.ask("hello").await.is_some());

    // Longer than both windows put together.
    assert!(
        frontend
            .wait_for_end(Duration::from_secs(4))
            .await
            .is_none(),
        "the frontend ended although nothing asked it to"
    );
    assert!(
        client.ask("still here").await.is_some(),
        "the frontend stopped answering on its own"
    );
}
