// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Three nodes, three stores on disk, and one channel between them.
//!
//! Every measurement in this crate runs real consensus over the real peer
//! channel. Nothing here is a double: a state machine that only ever ran in
//! memory would prove nothing about a node that restarts, and a transport that
//! only ever ran in a channel of its own would prove nothing about the one
//! Raft actually rides (ADR-0083).

#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ek_ek_config::{Config, NodeId, NodeRole, SchemaVersion, SecretId, Vip, VipId};
use ek_ek_peer::{Authority, Credentials, Failure, Listener, Service};
use ek_ek_raft::{Cluster, Membership, PeerNode, TypeConfig};
use ek_ek_store::{Change, Secret, Snapshot, SqliteStore};
use openraft::Raft;
use tempfile::TempDir;

/// The config schema every node in these measurements reads.
pub const SCHEMA: u32 = 1;

/// How long a measurement waits for consensus to settle.
///
/// An election takes at most the election timeout plus a round trip, and every
/// wait here is bounded so a broken rule fails rather than hangs.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// The moment the system is at.
///
/// A live handshake is checked against the real clock by the TLS library, so
/// the certificates have to be issued around now.
pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_secs(),
    )
    .expect("the clock fits in a timestamp")
}

/// A service whose Raft can be taken away and put back.
///
/// What a node being stopped and started again looks like from the outside.
/// The socket stays where it is, so the peers keep the address they were told,
/// and every call while the Raft is away is refused. Both are what a node that
/// is down looks like to the nodes still running.
#[derive(Clone, Default)]
pub struct Relay {
    raft: Arc<Mutex<Option<Raft<TypeConfig>>>>,
    deaf: Arc<AtomicBool>,
}

impl Relay {
    /// Points this listener at a running Raft.
    pub fn hold(&self, raft: Raft<TypeConfig>) {
        *self.raft.lock().expect("the relay is not poisoned") = Some(raft);
    }

    /// Takes the Raft away, so every call is refused from here on.
    pub fn release(&self) {
        *self.raft.lock().expect("the relay is not poisoned") = None;
    }

    /// Stops answering records while still answering heartbeats.
    ///
    /// What a node looks like when it can be reached but cannot keep up. A
    /// leader's heartbeat round succeeds, so it still believes it leads, and
    /// nothing it proposes is ever acknowledged. No other state produces that,
    /// and it is the one state the bound on a write exists for.
    pub fn go_deaf(&self) {
        self.deaf.store(true, Ordering::SeqCst);
    }
}

/// Whether a call is an append carrying records rather than a heartbeat.
fn carries_records(service: &str, body: &serde_json::Value) -> bool {
    service == ek_ek_raft::APPEND_ENTRIES
        && body
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|entries| !entries.is_empty())
}

impl Service for Relay {
    fn call(
        &self,
        from: &NodeId,
        service: &str,
        body: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Failure>> + Send + '_>> {
        let held = self
            .raft
            .lock()
            .expect("the relay is not poisoned")
            .clone()
            .map(ek_ek_raft::service);
        let deaf = self.deaf.load(Ordering::SeqCst) && carries_records(service, &body);
        let from = from.clone();
        let named = service.to_owned();
        Box::pin(async move {
            if deaf {
                // Never answered, and the connection is not closed either. A
                // refusal would tell the leader something; this tells it
                // nothing, which is the case the bound is for.
                std::future::pending::<()>().await;
            }
            match held {
                Some(service) => service.call(&from, &named, body).await,
                None => Err(Failure::new(
                    ek_ek_peer::Reason::Network,
                    "this node is not running".to_owned(),
                )),
            }
        })
    }
}

/// A relay between two nodes that keeps a copy of what crossed it.
///
/// The only way to measure what Raft actually puts on the network. A rule
/// checked against what the code meant to send would pass whether or not the
/// bytes were encrypted.
#[derive(Clone)]
pub struct Tap {
    /// Where the nodes dial instead of the real listener.
    pub address: SocketAddr,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Tap {
    /// Opens a relay in front of the address given.
    pub async fn open(onward: SocketAddr) -> Self {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = socket.local_addr().expect("the port is readable");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::clone(&seen);

        tokio::spawn(async move {
            loop {
                let Ok((mut from, _)) = socket.accept().await else {
                    return;
                };
                let Ok(mut to) = tokio::net::TcpStream::connect(onward).await else {
                    continue;
                };
                let held = Arc::clone(&held);
                tokio::spawn(async move {
                    let (mut reading, mut writing) = from.split();
                    let (mut back, mut onward) = to.split();
                    let forward = async {
                        let mut buffer = [0_u8; 8192];
                        loop {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let read = match reading.read(&mut buffer).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => read,
                            };
                            held.lock()
                                .expect("the tap is not poisoned")
                                .extend_from_slice(&buffer[..read]);
                            if onward.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    };
                    let backward = async {
                        let _ = tokio::io::copy(&mut back, &mut writing).await;
                    };
                    tokio::join!(forward, backward);
                });
            }
        });

        Self { address, seen }
    }

    /// What crossed the relay towards the node behind it.
    pub fn seen(&self) -> Vec<u8> {
        self.seen.lock().expect("the tap is not poisoned").clone()
    }
}

/// One node of the cluster.
pub struct Node {
    /// What the node is called.
    pub id: NodeId,
    /// Where its peers reach it.
    pub address: SocketAddr,
    /// Its consensus member, while it is running.
    pub cluster: Option<Cluster>,
    /// Its store, which outlives a restart.
    pub store: Arc<SqliteStore>,
    /// What its listener answers with.
    pub relay: Relay,
    /// The directory the store lives in, kept so it is not removed.
    pub directory: TempDir,
    /// This node's own credentials.
    pub credentials: Credentials,
    /// The task answering peers.
    pub serving: tokio::task::JoinHandle<()>,
}

impl Node {
    /// The consensus member, which must be running.
    pub fn cluster(&self) -> &Cluster {
        self.cluster.as_ref().expect("the node is running")
    }

    /// Stops this node's consensus member, leaving its store on disk.
    pub async fn stop(&mut self) {
        self.relay.release();
        if let Some(cluster) = self.cluster.take() {
            cluster.stop().await.expect("the node stops");
        }
    }

    /// Starts a stopped node again, on the store it left behind.
    pub async fn start(&mut self, settings: openraft::Config) {
        let cluster = Cluster::start_with(
            settings,
            Arc::clone(&self.store),
            &self.id,
            SCHEMA,
            self.credentials.clone(),
        )
        .await
        .expect("the node starts");
        self.relay.hold(cluster.raft().clone());
        self.cluster = Some(cluster);
    }
}

/// A cluster of nodes, running.
pub struct Fleet {
    /// The nodes, in the order they were named.
    pub nodes: Vec<Node>,
    /// The settings every node runs.
    pub settings: openraft::Config,
}

impl Fleet {
    /// Starts a cluster of the names given, with the settings given.
    pub async fn start(names: &[&str], settings: openraft::Config) -> Self {
        let authority = ek_ek_peer::create(now()).expect("an authority is created");
        let mut nodes = Vec::new();

        for name in names {
            nodes.push(one(&authority, name, settings.clone()).await);
        }

        Self { nodes, settings }
    }

    /// Brings the cluster into being and waits for a leader.
    pub async fn initialise(&self) {
        let peers: BTreeMap<NodeId, String> = self
            .nodes
            .iter()
            .map(|node| (node.id.clone(), node.address.to_string()))
            .collect();
        self.initialise_at(peers).await;
    }

    /// The same, with the addresses named.
    ///
    /// A measurement that has to watch the traffic puts a relay in front of one
    /// node and names the relay here.
    pub async fn initialise_at(&self, peers: BTreeMap<NodeId, String>) {
        self.nodes[0]
            .cluster()
            .initialise(&Membership {
                node: self.nodes[0].id.clone(),
                peers,
            })
            .await
            .expect("the cluster is initialised");

        self.await_leader().await;
    }

    /// Waits until every running node names the same leader.
    pub async fn await_leader(&self) -> NodeId {
        let settled = wait_until(PATIENCE, || {
            let named: Vec<Option<NodeId>> =
                self.running().map(|node| node.cluster().leader()).collect();
            let first = named.first().cloned().flatten();
            first.filter(|leader| named.iter().all(|held| held.as_ref() == Some(leader)))
        })
        .await;
        settled.expect("a leader is elected")
    }

    /// The nodes that are running.
    pub fn running(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(|node| node.cluster.is_some())
    }

    /// The node that is the leader.
    pub fn leader(&self) -> &Node {
        let named = self
            .running()
            .find_map(|node| node.cluster().leader())
            .expect("a leader is known");
        self.nodes
            .iter()
            .find(|node| node.id == named)
            .expect("the leader is one of these nodes")
    }

    /// A running node that is not the leader.
    pub fn follower(&self) -> &Node {
        let leader = self.leader().id.clone();
        self.running()
            .find(|node| node.id != leader)
            .expect("a follower is running")
    }

    /// The node of the name given.
    pub fn named(&self, name: &str) -> &Node {
        self.nodes
            .iter()
            .find(|node| node.id.as_str() == name)
            .expect("the node was named at start")
    }

    /// The node of the name given, to change.
    pub fn named_mut(&mut self, name: &str) -> &mut Node {
        self.nodes
            .iter_mut()
            .find(|node| node.id.as_str() == name)
            .expect("the node was named at start")
    }

    /// Waits until every running node has applied the same records.
    pub async fn await_agreement(&self) {
        let settled = wait_until(PATIENCE, || {
            let applied: Vec<Option<u64>> = self
                .running()
                .map(|node| node.cluster().applied())
                .collect();
            let first = applied.first().copied().flatten();
            first.filter(|held| applied.iter().all(|seen| *seen == Some(*held)))
        })
        .await;
        assert!(
            settled.is_some(),
            "the running nodes never applied the same records"
        );
    }
}

async fn one(authority: &Authority, name: &str, settings: openraft::Config) -> Node {
    let id = NodeId::new(name);
    let issued = ek_ek_peer::issue(
        authority,
        &id,
        &["127.0.0.1".parse::<IpAddr>().expect("an address")],
        now(),
    )
    .expect("a certificate is signed");
    let credentials = Credentials {
        authority_pem: authority.certificate_pem.clone(),
        certificate_pem: issued.certificate_pem.clone(),
        key_pem: issued.key_pem.clone(),
    };

    let directory = tempfile::tempdir().expect("a temporary directory");
    let store = Arc::new(SqliteStore::open(directory.path()).expect("the store opens"));

    let relay = Relay::default();
    let listener = Listener::bind(
        "127.0.0.1:0",
        &id,
        SCHEMA,
        &credentials,
        Arc::new(relay.clone()),
    )
    .await
    .expect("the peer port opens");
    let address = listener.address().expect("the port is readable");
    let serving = tokio::spawn(Arc::new(listener).serve_forever());

    let cluster = Cluster::start_with(
        settings,
        Arc::clone(&store),
        &id,
        SCHEMA,
        credentials.clone(),
    )
    .await
    .expect("the node starts");
    relay.hold(cluster.raft().clone());

    Node {
        id,
        address,
        cluster: Some(cluster),
        store,
        relay,
        directory,
        credentials,
        serving,
    }
}

/// Settings that reach a snapshot quickly.
///
/// The product's own thresholds are in `Cluster::settings`, and a measurement
/// of snapshot catch-up would otherwise have to write sixty four
/// configurations to reach one.
pub fn brisk(snapshot_every: u64) -> openraft::Config {
    openraft::Config {
        election_timeout_min: 300,
        election_timeout_max: 600,
        heartbeat_interval: 100,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(snapshot_every),
        max_in_snapshot_log_to_keep: 0,
        purge_batch_size: 1,
        ..Default::default()
    }
    .validate()
    .expect("the settings hold together")
}

/// Settings that never take a snapshot on their own.
pub fn steady() -> openraft::Config {
    openraft::Config {
        election_timeout_min: 300,
        election_timeout_max: 600,
        heartbeat_interval: 100,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(10_000),
        ..Default::default()
    }
    .validate()
    .expect("the settings hold together")
}

/// Polls until the answer arrives or the patience runs out.
pub async fn wait_until<T, F>(patience: Duration, mut ready: F) -> Option<T>
where
    F: FnMut() -> Option<T>,
{
    let started = Instant::now();
    loop {
        if let Some(held) = ready() {
            return Some(held);
        }
        if started.elapsed() > patience {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn address(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
}

/// A config carrying the number of nodes given.
pub fn config(nodes: u32) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: (1..=nodes)
            .map(|number| ek_ek_config::Node {
                id: NodeId::new(format!("node{number}")),
                address: address(10 + u8::try_from(number).unwrap_or(u8::MAX)),
                roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
            })
            .collect(),
        vips: vec![Vip {
            id: VipId::new("vip-web"),
            address: address(100),
            prefix_length: 24,
            interface: "eth0".to_owned(),
            preferred_node: Some(NodeId::new("node1")),
        }],
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        acme: None,
        stickiness_key: String::new(),
        log_level: Default::default(),
        certificate_expiry_warning_days: 30,
    }
}

/// A state carrying that config and one piece of key material.
pub fn snapshot(nodes: u32) -> Snapshot {
    Snapshot::new(config(nodes)).with_secret(
        SecretId::new("key-cert-web"),
        Secret::new(format!("the key material for {nodes}").into_bytes()),
    )
}

/// A change note.
pub fn change(description: &str) -> Change {
    Change::new("admin", description)
}

/// Where a node is, as consensus knows it.
pub fn peer_node(node: &Node) -> PeerNode {
    PeerNode::new(node.id.as_str(), node.address.to_string())
}
