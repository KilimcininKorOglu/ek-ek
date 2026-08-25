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
use ek_ek_peer::{Authority, Credentials, Failure, Listener, Listening, Service};
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
        from: Option<&NodeId>,
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
        let from = from.cloned();
        let named = service.to_owned();
        Box::pin(async move {
            if deaf {
                // Never answered, and the connection is not closed either. A
                // refusal would tell the leader something; this tells it
                // nothing, which is the case the bound is for.
                std::future::pending::<()>().await;
            }
            match held {
                Some(service) => service.call(from.as_ref(), &named, body).await,
                None => Err(Failure::new(
                    ek_ek_peer::Reason::Network,
                    "this node is not running".to_owned(),
                )),
            }
        })
    }
}

/// A moment a measurement can move.
///
/// Every rule about a token running out is a rule about hours. Moving this
/// instead of waiting is what keeps those rules measurable in microseconds.
#[derive(Clone)]
pub struct Moment(Arc<std::sync::atomic::AtomicI64>);

impl Moment {
    /// Starts at the real clock, because a live handshake is checked against
    /// it.
    pub fn real() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicI64::new(now())))
    }

    /// What the moment is.
    pub fn at(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    /// Moves it forward.
    pub fn pass(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }

    /// The clock a service reads.
    pub fn clock(&self) -> ek_ek_raft::Clock {
        let held = Arc::clone(&self.0);
        Arc::new(move || held.load(Ordering::SeqCst))
    }
}

/// A service and a gate that are installed after the listener is bound.
///
/// The listener needs an address before the cluster can be told about it, and
/// the service needs the cluster. Something has to come second, and this is it.
#[derive(Clone, Default)]
pub struct Deputy {
    service: Arc<Mutex<Option<Arc<dyn Service>>>>,
    gate: Arc<Mutex<Option<Arc<dyn ek_ek_peer::Gate>>>>,
}

impl Deputy {
    /// Points the listener at a running cluster.
    pub fn hold(&self, cluster: Arc<Cluster>, clock: ek_ek_raft::Clock) {
        *self.service.lock().expect("the deputy is not poisoned") = Some(Arc::new(
            ek_ek_raft::Admission::new(Arc::clone(&cluster), clock),
        ));
        *self.gate.lock().expect("the deputy is not poisoned") =
            Some(Arc::new(ek_ek_raft::Refusals::new(cluster)));
    }
}

impl Service for Deputy {
    fn call(
        &self,
        from: Option<&NodeId>,
        service: &str,
        body: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Failure>> + Send + '_>> {
        let held = self
            .service
            .lock()
            .expect("the deputy is not poisoned")
            .clone();
        let from = from.cloned();
        let named = service.to_owned();
        Box::pin(async move {
            match held {
                Some(service) => service.call(from.as_ref(), &named, body).await,
                None => Err(Failure::new(
                    ek_ek_peer::Reason::Network,
                    "this node is not running".to_owned(),
                )),
            }
        })
    }
}

impl ek_ek_peer::Gate for Deputy {
    fn refuses(&self, caller: &NodeId) -> bool {
        self.gate
            .lock()
            .expect("the deputy is not poisoned")
            .as_ref()
            .is_some_and(|gate| gate.refuses(caller))
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
    /// This cluster's place among the ones running at once.
    _place: tokio::sync::OwnedSemaphorePermit,
}

impl Fleet {
    /// Starts a cluster of the names given, with the settings given.
    pub async fn start(names: &[&str], settings: openraft::Config) -> Self {
        let place = a_place().await;
        let authority = ek_ek_peer::create(now()).expect("an authority is created");
        let mut nodes = Vec::new();

        for name in names {
            nodes.push(one(&authority, name, settings.clone()).await);
        }

        Self {
            nodes,
            settings,
            _place: place,
        }
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

    /// Waits until every running node names the same leader, and that leader
    /// can reach a quorum.
    ///
    /// Both, because they are different questions. `leader()` answers from a
    /// node's own metrics and a leader that has not heartbeated a quorum yet
    /// still names itself, while `reachable()` costs a round to a quorum and
    /// answers whether the cluster is actually there (ADR-0085). A write is
    /// refused rather than made to wait (ADR-0004), so a measurement that
    /// wrote on the strength of the belief alone would be asking at a moment
    /// the product is entitled to refuse.
    pub async fn await_leader(&self) -> NodeId {
        let settled = wait_until(PATIENCE, || {
            let named: Vec<Option<NodeId>> =
                self.running().map(|node| node.cluster().leader()).collect();
            let first = named.first().cloned().flatten();
            first.filter(|leader| named.iter().all(|held| held.as_ref() == Some(leader)))
        })
        .await;
        let named = settled.expect("a leader is elected");
        self.await_quorum().await;
        named
    }

    /// Waits until the node that leads can reach a quorum.
    pub async fn await_quorum(&self) {
        let started = Instant::now();
        loop {
            if let Some(leader) = self.running().find(|node| node.cluster().is_leader())
                && leader.cluster().reachable().await.is_ok()
            {
                return;
            }
            assert!(
                started.elapsed() <= PATIENCE,
                "no leader could reach a quorum within {PATIENCE:?}"
            );
            // Slower than the other waits here, because this question costs a
            // heartbeat round to a quorum while they are local reads. Asking
            // it forty times a second would add the very load it is waiting
            // for the machine to work through.
            tokio::time::sleep(QUORUM_POLL).await;
        }
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
        &credentials,
        Listening::new(&id, SCHEMA, Arc::new(relay.clone())),
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

/// One node of a cluster that admits others.
///
/// Told apart from [`Node`] because a joining node has no certificate until
/// the cluster gives it one, so nothing here can be handed out in advance.
pub struct Member {
    /// What the node is called.
    pub id: NodeId,
    /// Where its peers reach it.
    pub address: SocketAddr,
    /// Its consensus member.
    pub cluster: Arc<Cluster>,
    /// Its store.
    pub store: Arc<SqliteStore>,
    /// What it presents to its peers.
    pub credentials: Credentials,
    /// What its listener answers with.
    pub deputy: Deputy,
    /// The directory the store lives in, kept so it is not removed.
    pub directory: TempDir,
    /// The task answering peers.
    pub serving: tokio::task::JoinHandle<()>,
}

impl Member {
    /// Where consensus reaches this node, as a string.
    pub fn at(&self) -> String {
        self.address.to_string()
    }
}

/// A cluster that starts with one node and admits the rest.
pub struct Cohort {
    /// The nodes, founder first.
    pub members: Vec<Member>,
    /// The authority the founder made.
    pub authority: Authority,
    /// The moment every node reads.
    pub moment: Moment,
    /// The settings every node runs.
    pub settings: openraft::Config,
    /// This cluster's place among the ones running at once.
    _place: tokio::sync::OwnedSemaphorePermit,
}

impl Cohort {
    /// Founds a cluster of one, holding an authority and a config.
    pub async fn found(name: &str, settings: openraft::Config) -> Self {
        let place = a_place().await;
        let authority = ek_ek_peer::create(now()).expect("an authority is created");
        let moment = Moment::real();
        let founder = admitting(&authority, name, settings.clone(), &moment).await;

        founder
            .cluster
            .initialise(&Membership {
                node: founder.id.clone(),
                peers: BTreeMap::from([(founder.id.clone(), founder.at())]),
            })
            .await
            .expect("the cluster is initialised");

        let cohort = Self {
            members: vec![founder],
            authority,
            moment,
            settings,
            _place: place,
        };
        cohort.await_leader().await;

        // The authority and the founder's own row, through consensus. Every
        // node reads them from the replicated state from here on, which is
        // what makes the founder no different from any other node.
        let founder = &cohort.members[0];
        let state = ek_ek_peer::install(
            &Snapshot::new(founding_config(&founder.id)),
            &cohort.authority,
        );
        founder
            .cluster
            .write(
                &state,
                &change("the cluster was founded"),
                cohort.moment.at(),
            )
            .await
            .expect("the founding state is written");

        cohort
    }

    /// The node that is the leader.
    pub fn leader(&self) -> &Member {
        let named = self
            .members
            .iter()
            .find_map(|member| member.cluster.leader())
            .expect("a leader is known");
        self.members
            .iter()
            .find(|member| member.id == named)
            .expect("the leader is one of these nodes")
    }

    /// The node of the name given.
    pub fn named(&self, name: &str) -> &Member {
        self.members
            .iter()
            .find(|member| member.id.as_str() == name)
            .expect("the node is in this cluster")
    }

    /// Mints a token on the leader.
    pub async fn mint(&self) -> ek_ek_raft::Token {
        ek_ek_raft::join::mint(self.leader().cluster.as_ref(), "admin", self.moment.at())
            .await
            .expect("a token is minted")
    }

    /// Runs the whole join for one new name, and starts the node it admits.
    ///
    /// # Errors
    ///
    /// Returns whatever the join was refused with.
    pub async fn admit(&mut self, name: &str, word: &str) -> Result<(), ek_ek_raft::Failure> {
        let id = NodeId::new(name);
        let directory = tempfile::tempdir().expect("a temporary directory");
        let store = Arc::new(SqliteStore::open(directory.path()).expect("the store opens"));

        // Bound first. The join records where this node can be reached, so the
        // port has to exist before the cluster is told about it.
        let deputy = Deputy::default();
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = socket.local_addr().expect("the port is readable");
        drop(socket);

        let at = address.to_string();
        let joining = ek_ek_raft::Joining {
            node: &id,
            address: "127.0.0.1".parse::<IpAddr>().expect("an address"),
            peer_address: &at,
            schema_version: SCHEMA,
        };

        let joined = ek_ek_raft::join::join(&self.leader().at(), word, joining).await?;

        let listener = Listener::bind(
            address,
            &joined.credentials,
            Listening::new(&id, SCHEMA, Arc::new(deputy.clone()))
                .opening(ek_ek_raft::join::SERVICE)
                .behind(Arc::new(deputy.clone())),
        )
        .await
        .expect("the peer port opens");
        let serving = tokio::spawn(Arc::new(listener).serve_forever());

        let cluster = Arc::new(
            Cluster::start_with(
                self.settings.clone(),
                Arc::clone(&store),
                &id,
                SCHEMA,
                joined.credentials.clone(),
            )
            .await
            .expect("the node starts"),
        );
        deputy.hold(Arc::clone(&cluster), self.moment.clock());

        // The second half of the join, from the node that is now running. The
        // first call could not make it a voter, because a membership change
        // waits for the new member and there was nothing to wait for yet.
        let leader = self.leader();
        ek_ek_raft::join::enlist(&leader.at(), word, &leader.id, joining, &joined.credentials)
            .await?;

        self.members.push(Member {
            id,
            address,
            cluster,
            store,
            credentials: joined.credentials,
            deputy,
            directory,
            serving,
        });
        Ok(())
    }

    /// Waits until every node names the same leader.
    pub async fn await_leader(&self) -> NodeId {
        let named = self.await_named().await;
        let started = Instant::now();
        loop {
            if let Some(member) = self
                .members
                .iter()
                .find(|member| member.cluster.is_leader())
                && member.cluster.reachable().await.is_ok()
            {
                return named;
            }
            assert!(
                started.elapsed() <= PATIENCE,
                "no leader could reach a quorum within {PATIENCE:?}"
            );
            // Slower than the other waits here, because this question costs a
            // heartbeat round to a quorum while they are local reads. Asking
            // it forty times a second would add the very load it is waiting
            // for the machine to work through.
            tokio::time::sleep(QUORUM_POLL).await;
        }
    }

    /// Waits until every member names the same leader.
    async fn await_named(&self) -> NodeId {
        let settled = wait_until(PATIENCE, || {
            let named: Vec<Option<NodeId>> = self
                .members
                .iter()
                .map(|member| member.cluster.leader())
                .collect();
            let first = named.first().cloned().flatten();
            first.filter(|leader| named.iter().all(|held| held.as_ref() == Some(leader)))
        })
        .await;
        settled.expect("a leader is elected")
    }

    /// Waits until every node has applied the same records.
    pub async fn await_agreement(&self) {
        let settled = wait_until(PATIENCE, || {
            let applied: Vec<Option<u64>> = self
                .members
                .iter()
                .map(|member| member.cluster.applied())
                .collect();
            let first = applied.first().copied().flatten();
            first.filter(|held| applied.iter().all(|seen| *seen == Some(*held)))
        })
        .await;
        assert!(
            settled.is_some(),
            "the nodes never applied the same records"
        );
    }
}

/// A node that runs the join service.
async fn admitting(
    authority: &Authority,
    name: &str,
    settings: openraft::Config,
    moment: &Moment,
) -> Member {
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

    let deputy = Deputy::default();
    let listener = Listener::bind(
        "127.0.0.1:0",
        &credentials,
        Listening::new(&id, SCHEMA, Arc::new(deputy.clone()))
            .opening(ek_ek_raft::join::SERVICE)
            .behind(Arc::new(deputy.clone())),
    )
    .await
    .expect("the peer port opens");
    let address = listener.address().expect("the port is readable");
    let serving = tokio::spawn(Arc::new(listener).serve_forever());

    let cluster = Arc::new(
        Cluster::start_with(
            settings,
            Arc::clone(&store),
            &id,
            SCHEMA,
            credentials.clone(),
        )
        .await
        .expect("the node starts"),
    );
    deputy.hold(Arc::clone(&cluster), moment.clock());

    Member {
        id,
        address,
        cluster,
        store,
        credentials,
        deputy,
        directory,
        serving,
    }
}

/// A config holding one node and one virtual address it prefers.
pub fn founding_config(founder: &NodeId) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: vec![ek_ek_config::Node {
            id: founder.clone(),
            address: address(11),
            roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
        }],
        vips: vec![Vip {
            id: VipId::new("vip-web"),
            address: address(100),
            prefix_length: 24,
            interface: "eth0".to_owned(),
            preferred_node: Some(founder.clone()),
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

/// How many clusters of real nodes may run at one time.
///
/// A cluster here is three processes' worth of consensus on one runtime
/// thread, and every Raft call opens its own mutually authenticated connection
/// (`crate::network`), so a heartbeat costs a full handshake at both ends.
/// Left to itself the test runner starts one measurement per core, which is
/// forty odd nodes handshaking at each other on one machine; the leaders are
/// then starved of scheduling slots and deposed by their own followers, and
/// what fails is the machine rather than the rule under measurement.
///
/// Four is what one machine carries with room to spare. The measurements still
/// run in parallel; only the heavy part of them queues.
const FLEETS_AT_ONCE: usize = 4;

/// Waits for a place to run a cluster in.
///
/// The permit is held for the cluster's whole life and released when it is
/// dropped, so the next measurement starts as this one finishes.
async fn a_place() -> tokio::sync::OwnedSemaphorePermit {
    static HELD: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    // Never closed, so the only way this fails is a bug in the harness rather
    // than anything a measurement did.
    Arc::clone(HELD.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(FLEETS_AT_ONCE))))
        .acquire_owned()
        .await
        .expect("the semaphore is open")
}

/// How often a measurement asks whether the leader can reach a quorum.
const QUORUM_POLL: Duration = Duration::from_millis(250);

/// The timings a measurement runs, which are the product's own.
///
/// Faster ones were tried and they measured the machine instead of the rule.
/// Every Raft call opens its own mutually authenticated connection
/// (`crate::network`), so a heartbeat costs a full handshake at both ends, and
/// openraft gives one heartbeat interval for the whole round trip. Shorten the
/// interval and a loaded machine fails the round; a leader that fails the
/// round cannot reach a quorum, and the write a measurement makes next is
/// refused (ADR-0004). Only the snapshot policy below differs from what a node
/// actually runs.
const ELECTION_MIN_MS: u64 = ek_ek_raft::ELECTION_TIMEOUT_MIN_MS;

/// The upper end of the range, so nodes do not all stand at the same instant.
const ELECTION_MAX_MS: u64 = ek_ek_raft::ELECTION_TIMEOUT_MAX_MS;

/// How often a leader says it is still there, and how long one round may take.
const HEARTBEAT_MS: u64 = ek_ek_raft::HEARTBEAT_MS;

/// Settings that reach a snapshot quickly.
///
/// The product's own thresholds are in `Cluster::settings`, and a measurement
/// of snapshot catch-up would otherwise have to write sixty four
/// configurations to reach one.
pub fn brisk(snapshot_every: u64) -> openraft::Config {
    openraft::Config {
        election_timeout_min: ELECTION_MIN_MS,
        election_timeout_max: ELECTION_MAX_MS,
        heartbeat_interval: HEARTBEAT_MS,
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
        election_timeout_min: ELECTION_MIN_MS,
        election_timeout_max: ELECTION_MAX_MS,
        heartbeat_interval: HEARTBEAT_MS,
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
