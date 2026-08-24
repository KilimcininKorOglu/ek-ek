// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the rest of the product uses: write through consensus, read locally.
//!
//! # Why reading is local
//!
//! ADR-0004's invariant. Losing quorum must never affect the data plane, and a
//! read that needed a quorum would make every configuration lookup depend on
//! one. A follower's state is behind the leader's by however long replication
//! takes, and for a configuration that is the right trade: the traffic path
//! serves what its node holds, and what it holds was agreed by a quorum
//! before it arrived.
//!
//! # Why a write on a follower is refused rather than forwarded
//!
//! A forwarded write is one the caller believes landed. When the second hop
//! fails, nothing on either node says so and the caller has no way to find
//! out. A refusal that names the leader is one the caller can act on
//! (ADR-0083).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use ek_ek_config::NodeId;
use ek_ek_peer::Credentials;
use ek_ek_store::{AuditRecord, Change, Snapshot as StoredSnapshot, SqliteStore, Store, VersionId};
use openraft::error::{CheckIsLeaderError, ClientWriteError, ForwardToLeader, RaftError};
use openraft::{Config as RaftConfig, Raft};

use crate::error::{Failure, Reason};
use crate::identity;
use crate::log::LogStore;
use crate::machine::StateMachine;
use crate::network::Dialler;
use crate::types::{
    NodeNumber, PeerNode, TypeConfig, WireAudit, WireChange, WireSnapshot, WriteRequest,
};

/// How long a node waits before it decides the leader is gone.
///
/// Raft's own election timeout, not VRRP's. This one may be slow: a
/// configuration that cannot be written for a second costs nothing, and an
/// election that starts too eagerly costs a leader (ADR-0004).
pub const ELECTION_TIMEOUT_MIN_MS: u64 = 1_000;

/// The upper end of the election timeout range.
///
/// A range rather than a value, so three nodes that lost the same leader do
/// not all stand for election at the same instant.
pub const ELECTION_TIMEOUT_MAX_MS: u64 = 2_000;

/// How often a leader tells its followers it is still there.
pub const HEARTBEAT_MS: u64 = 300;

/// How long a write waits to be agreed before it gives up.
///
/// A configuration write comes from a person waiting at a screen. Five seconds
/// is longer than a healthy cluster ever needs and short enough that an
/// operator learns something is wrong instead of watching a spinner.
pub const WRITE_PATIENCE: Duration = Duration::from_secs(5);

/// How many applied records trigger a snapshot.
///
/// Small enough that a node which was away for a while catches up from a
/// snapshot rather than by replaying everything, and large enough that an
/// ordinary run of configuration changes does not take one every time.
pub const SNAPSHOT_EVERY: u64 = 64;

/// One node's view of the cluster.
pub struct Cluster {
    raft: Raft<TypeConfig>,
    store: Arc<SqliteStore>,
    node: NodeId,
}

impl std::fmt::Debug for Cluster {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cluster")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

/// What a node needs to take part.
pub struct Membership {
    /// This node's identity.
    pub node: NodeId,
    /// Where every node in the cluster is, this one included.
    pub peers: BTreeMap<NodeId, String>,
}

impl Cluster {
    /// The Raft settings every node in this cluster runs.
    ///
    /// Written out rather than taken from the library's defaults, because a
    /// dependency bump would otherwise move an election timeout with nothing
    /// in this repository to show it.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Configuration`] when the settings do not hold
    /// together.
    pub fn settings() -> Result<RaftConfig, Failure> {
        RaftConfig {
            election_timeout_min: ELECTION_TIMEOUT_MIN_MS,
            election_timeout_max: ELECTION_TIMEOUT_MAX_MS,
            heartbeat_interval: HEARTBEAT_MS,
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(SNAPSHOT_EVERY),
            // Keep enough behind the snapshot that a follower a few records
            // behind catches up by replay rather than by a whole snapshot.
            max_in_snapshot_log_to_keep: SNAPSHOT_EVERY,
            ..Default::default()
        }
        .validate()
        .map_err(|error| {
            Failure::new(
                Reason::Configuration,
                format!("the raft settings do not hold together: {error}"),
            )
        })
    }

    /// Starts this node's Raft over its own store.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Consensus`] when Raft cannot be started.
    pub async fn start(
        store: Arc<SqliteStore>,
        node: &NodeId,
        schema_version: u32,
        credentials: Credentials,
    ) -> Result<Self, Failure> {
        Self::start_with(Self::settings()?, store, node, schema_version, credentials).await
    }

    /// The same, with the settings named.
    ///
    /// What [`Self::start`] does, with the timings open. A measurement that had
    /// to write sixty four configurations to reach a snapshot would spend a
    /// minute proving something a smaller threshold proves in a second, and
    /// the product's own thresholds stay in [`Self::settings`].
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Consensus`] when Raft cannot be started.
    pub async fn start_with(
        settings: RaftConfig,
        store: Arc<SqliteStore>,
        node: &NodeId,
        schema_version: u32,
        credentials: Credentials,
    ) -> Result<Self, Failure> {
        let raft = Raft::new(
            identity::of(node),
            Arc::new(settings),
            Dialler::new(credentials, schema_version),
            LogStore::new(Arc::clone(&store)),
            StateMachine::new(Arc::clone(&store)),
        )
        .await
        .map_err(|error| {
            Failure::new(
                Reason::Consensus,
                format!("raft could not be started: {error}"),
            )
        })?;

        Ok(Self {
            raft,
            store,
            node: node.clone(),
        })
    }

    /// The Raft behind this node, for the peer listener to answer calls with.
    #[must_use]
    pub fn raft(&self) -> &Raft<TypeConfig> {
        &self.raft
    }

    /// Which node this is.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Brings a cluster into being with the membership given.
    ///
    /// Run once, on one node. Every other node is told about the cluster by
    /// the membership this call records.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Consensus`] when the cluster is already initialised
    /// or cannot be.
    pub async fn initialise(&self, membership: &Membership) -> Result<(), Failure> {
        identity::unique(membership.peers.keys())?;

        let members: BTreeMap<u64, PeerNode> = membership
            .peers
            .iter()
            .map(|(node, address)| (identity::of(node), PeerNode::new(node.as_str(), address)))
            .collect();

        self.raft.initialize(members).await.map_err(|error| {
            Failure::new(
                Reason::Consensus,
                format!("the cluster could not be initialised: {error}"),
            )
        })
    }

    /// Adds a node to the cluster as a voter.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Consensus`] when the change cannot be made, and
    /// [`Reason::NotLeader`] when this node is not the leader.
    pub async fn add_voter(&self, node: &NodeId, address: &str) -> Result<(), Failure> {
        self.raft
            .add_learner(
                identity::of(node),
                PeerNode::new(node.as_str(), address),
                true,
            )
            .await
            .map_err(|error| {
                Failure::new(
                    Reason::Consensus,
                    format!("{} could not be added: {error}", node.as_str()),
                )
            })?;

        let mut members: BTreeSet<u64> = self
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect();
        members.insert(identity::of(node));

        self.raft
            .change_membership(members, false)
            .await
            .map(|_| ())
            .map_err(|error| {
                Failure::new(
                    Reason::Consensus,
                    format!("the membership could not be changed: {error}"),
                )
            })
    }

    /// Drops a node from the cluster.
    ///
    /// The learner is dropped as well as the vote, so the node stops receiving
    /// records at all. It keeps whatever it already had, which is what makes
    /// the refusal list matter: nothing here takes its certificate away
    /// (ADR-0084).
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Consensus`] when the change cannot be made,
    /// [`Reason::NotLeader`] when this node is not the leader, and
    /// [`Reason::Configuration`] when the node is the only voter left.
    pub async fn remove_voter(&self, node: &NodeId) -> Result<(), Failure> {
        let number = identity::of(node);
        let mut members: BTreeSet<u64> = self
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect();

        if !members.remove(&number) {
            // Already gone. Said rather than treated as success, because an
            // operator removing a name that is not there has the wrong name.
            return Err(Failure::new(
                Reason::Configuration,
                format!("{} is not a voter in this cluster", node.as_str()),
            ));
        }
        if members.is_empty() {
            return Err(Failure::new(
                Reason::Configuration,
                format!(
                    "{} is the only voter left, and a cluster with none cannot elect anything",
                    node.as_str()
                ),
            ));
        }

        self.raft
            .change_membership(members, true)
            .await
            .map(|_| ())
            .map_err(|error| {
                Failure::new(
                    Reason::Consensus,
                    format!("{} could not be removed: {error}", node.as_str()),
                )
            })
    }

    /// Which nodes vote, by the name each was added under.
    #[must_use]
    pub fn voters(&self) -> BTreeSet<NodeId> {
        let metrics = self.raft.metrics();
        let borrowed = metrics.borrow();
        let membership = borrowed.membership_config.membership();
        membership
            .voter_ids()
            .filter_map(|number| membership.get_node(&number))
            .map(PeerNode::node)
            .collect()
    }

    /// Replaces the stored state, through consensus.
    ///
    /// Leadership is confirmed with a quorum before anything is proposed, so a
    /// write that cannot be agreed is refused rather than left waiting. That
    /// order matters: proposing first and giving up afterwards would leave a
    /// record in the log that the caller has already been told did not happen,
    /// and a returning quorum would then apply it.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::NotLeader`] when this node is not the leader, naming
    /// the one that is, [`Reason::NoQuorum`] when no quorum can be reached, and
    /// [`Reason::Consensus`] when the write cannot be agreed.
    pub async fn write(
        &self,
        state: &StoredSnapshot,
        change: &Change,
        now_unix: i64,
    ) -> Result<VersionId, Failure> {
        self.write_audited(state, change, now_unix, &[]).await
    }

    /// Replaces the stored state and writes audit rows in the same transaction.
    ///
    /// One entry, one transaction. A change that landed and an audit row that
    /// did not would be a change nobody can account for, which is the one thing
    /// the audit log exists to make impossible (ADR-0008, ADR-0084).
    ///
    /// # Errors
    ///
    /// The same as [`Cluster::write`].
    pub async fn write_audited(
        &self,
        state: &StoredSnapshot,
        change: &Change,
        now_unix: i64,
        audit: &[AuditRecord],
    ) -> Result<VersionId, Failure> {
        // Asked first so that a node with no quorum proposes nothing at all.
        self.reachable().await?;

        let request = WriteRequest {
            state: WireSnapshot::from(state),
            change: WireChange::from(change),
            now_unix,
            audit: audit.iter().map(WireAudit::from).collect(),
        };

        // Bounded even so. The check above can succeed and the quorum can go
        // away before the entry reaches it, and a configuration write that
        // never returns is a web request that never returns.
        match tokio::time::timeout(WRITE_PATIENCE, self.raft.client_write(request)).await {
            Ok(Ok(answered)) => Ok(VersionId::new(answered.data.version)),
            Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(elsewhere)))) => {
                Err(self.elsewhere(&elsewhere))
            }
            Ok(Err(RaftError::APIError(ClientWriteError::ChangeMembershipError(error)))) => {
                Err(Failure::new(
                    Reason::Consensus,
                    format!("the membership change was refused: {error}"),
                ))
            }
            Ok(Err(RaftError::Fatal(fatal))) => Err(Failure::new(
                Reason::Consensus,
                format!("consensus has stopped: {fatal}"),
            )),
            Err(_) => Err(Failure::new(
                Reason::NoQuorum,
                format!(
                    "the write was not agreed within {} seconds; \
                     it may still be agreed if a quorum returns",
                    WRITE_PATIENCE.as_secs()
                ),
            )),
        }
    }

    /// Whether this node can reach a quorum at this moment.
    ///
    /// A question about the cluster, not a read of the configuration. Nothing
    /// on the read path asks it, because a configuration lookup that needed a
    /// quorum would make every one of them depend on one (ADR-0004).
    ///
    /// What asks it is a write, before it proposes anything, and a status
    /// screen. A screen needs it because [`Self::leader`] answers from this
    /// node's own metrics: a leader that lost contact keeps naming itself
    /// until it stands down, so "who leads?" answers even when nobody does
    /// (ADR-0085).
    ///
    /// The question costs a heartbeat round to a quorum, and it fails rather
    /// than waits.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::NotLeader`] when another node leads, naming it,
    /// [`Reason::NoQuorum`] when no quorum can be reached, and
    /// [`Reason::Consensus`] when consensus has stopped.
    pub async fn reachable(&self) -> Result<(), Failure> {
        match self.raft.get_read_log_id().await {
            Ok(_) => Ok(()),
            Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(elsewhere))) => {
                Err(self.elsewhere(&elsewhere))
            }
            Err(RaftError::APIError(CheckIsLeaderError::QuorumNotEnough(short))) => {
                Err(Failure::new(
                    Reason::NoQuorum,
                    format!("no quorum can be reached: {short}"),
                ))
            }
            Err(RaftError::Fatal(fatal)) => Err(Failure::new(
                Reason::Consensus,
                format!("consensus has stopped: {fatal}"),
            )),
        }
    }

    /// Reads what this node holds.
    ///
    /// Local on purpose: this keeps working while quorum is lost (ADR-0004).
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Storage`] when the local state cannot be read.
    pub fn read(&self) -> Result<Option<StoredSnapshot>, Failure> {
        self.store.read().map_err(|error| {
            Failure::new(
                Reason::Storage,
                format!("the local state could not be read: {error}"),
            )
        })
    }

    /// The store this node keeps its state in.
    #[must_use]
    pub fn store(&self) -> &Arc<SqliteStore> {
        &self.store
    }

    /// Which node this one believes is the leader, if any.
    ///
    /// Named, not numbered. The number comes back from consensus and the
    /// membership is what turns it back into the name an operator gave the
    /// node ([`crate::identity`]).
    ///
    /// A belief, and it can be out of date. A leader that lost contact with
    /// its quorum keeps naming itself here until it stands down, so a screen
    /// that showed only this would show a healthy cluster while nothing can be
    /// written. [`Self::reachable`] is what asks whether the cluster is
    /// actually there (ADR-0085).
    #[must_use]
    pub fn leader(&self) -> Option<NodeId> {
        let metrics = self.raft.metrics();
        let held = metrics.borrow();
        let leader = held.current_leader?;
        held.membership_config
            .membership()
            .get_node(&leader)
            .map(PeerNode::node)
    }

    /// Whether this node is the leader.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.raft
            .metrics()
            .borrow()
            .current_leader
            .is_some_and(|leader| leader == identity::of(&self.node))
    }

    /// The highest record this node has applied.
    #[must_use]
    pub fn applied(&self) -> Option<u64> {
        self.raft
            .metrics()
            .borrow()
            .last_applied
            .as_ref()
            .map(|log_id| log_id.index)
    }

    /// Stops this node's Raft.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Consensus`] when the shutdown does not complete.
    pub async fn stop(self) -> Result<(), Failure> {
        self.halt().await
    }

    /// Stops this node's Raft without taking the cluster with it.
    ///
    /// What a node that shares its cluster with a service and a gate has to
    /// call: those hold it too, so nothing can take sole ownership of it to
    /// stop it (ADR-0084). Everything the cluster holds afterwards is a store
    /// that still reads and a Raft that answers nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Consensus`] when the shutdown does not complete.
    pub async fn halt(&self) -> Result<(), Failure> {
        self.raft.shutdown().await.map_err(|error| {
            Failure::new(
                Reason::Consensus,
                format!("raft did not shut down: {error}"),
            )
        })
    }

    /// Says where to write instead, when this node is not the leader.
    ///
    /// The name comes out of the answer consensus gave to this call. The answer
    /// carries the node itself, so the operator's own name for it is there to
    /// be read; the metrics carry only the number, which would then have to be
    /// looked up in the membership to say anything an operator recognises.
    fn elsewhere(&self, elsewhere: &ForwardToLeader<NodeNumber, PeerNode>) -> Failure {
        let named = elsewhere
            .leader_node
            .as_ref()
            .map(|node| node.name.clone())
            .or_else(|| elsewhere.leader_id.map(|id| id.to_string()));

        match named {
            Some(leader) => Failure::new(
                Reason::NotLeader,
                format!(
                    "{} is not the leader; write to {leader} instead",
                    self.node.as_str()
                ),
            ),
            // Consensus knows this node does not lead and does not know who
            // does. Saying so is the whole answer: there is nowhere to send the
            // caller until an election finishes.
            None => Failure::new(
                Reason::NoQuorum,
                format!(
                    "{} is not the leader and no leader is known",
                    self.node.as_str()
                ),
            ),
        }
    }
}
