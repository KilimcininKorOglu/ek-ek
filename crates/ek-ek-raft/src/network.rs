// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Raft over the peer channel.
//!
//! Every RPC is a call on the channel `ek-ek-peer` already opens: the same
//! certificates, the same authority and the same mutual check (ADR-0082,
//! ADR-0083). No second listener exists, because two trust setups would have
//! to be verified separately and one of them would eventually drift.
//!
//! # Why a connection is not held open here
//!
//! A dropped connection is redialled on the next call. openraft retries an
//! RPC that failed, so a redial costs one round trip and the alternative is a
//! reconnect state machine of our own beside the one openraft already runs.

use std::sync::Arc;

use ek_ek_peer::{Credentials, Failure, Peer, Service};
use openraft::error::{RPCError, RaftError, Unreachable};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{Raft, RaftTypeConfig};

use crate::types::{NodeNumber, PeerNode, TypeConfig};

/// The service name an append reaches.
pub const APPEND_ENTRIES: &str = "raft.append_entries";
/// The service name a vote reaches.
pub const VOTE: &str = "raft.vote";
/// The service name a snapshot chunk reaches.
pub const INSTALL_SNAPSHOT: &str = "raft.install_snapshot";

/// What every peer connection this node opens needs.
#[derive(Clone)]
pub struct Dialler {
    credentials: Credentials,
    schema_version: u32,
}

impl std::fmt::Debug for Dialler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Dialler").finish_non_exhaustive()
    }
}

impl Dialler {
    /// Builds a dialler with this node's own credentials.
    #[must_use]
    pub const fn new(credentials: Credentials, schema_version: u32) -> Self {
        Self {
            credentials,
            schema_version,
        }
    }
}

impl RaftNetworkFactory<TypeConfig> for Dialler {
    type Network = Wire;

    async fn new_client(&mut self, _target: u64, node: &PeerNode) -> Self::Network {
        Wire {
            // Dialled by name, because a certificate proves a name and not a
            // number (ADR-0082). The number openraft passes is the same name
            // put through `identity::of`.
            target: node.node(),
            address: node.address.clone(),
            credentials: self.credentials.clone(),
            schema_version: self.schema_version,
        }
    }
}

/// One node's end of a conversation with one peer.
#[derive(Clone)]
pub struct Wire {
    target: ek_ek_config::NodeId,
    address: String,
    credentials: Credentials,
    schema_version: u32,
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Wire")
            .field("target", &self.target.as_str())
            .finish_non_exhaustive()
    }
}

impl Wire {
    async fn call<Q, A>(
        &self,
        service: &str,
        request: &Q,
    ) -> Result<A, RPCError<NodeNumber, PeerNode, RaftError<NodeNumber>>>
    where
        Q: serde::Serialize,
        A: serde::de::DeserializeOwned,
    {
        let body =
            serde_json::to_value(request).map_err(|error| unreachable(&error.to_string()))?;

        let mut peer = Peer::dial(
            &self.address,
            &self.target,
            self.schema_version,
            &self.credentials,
        )
        .await
        .map_err(|failure| unreachable(&failure.to_string()))?;

        let answer = peer
            .call(service, body)
            .await
            .map_err(|failure| unreachable(&failure.to_string()))?;

        serde_json::from_value(answer).map_err(|error| unreachable(&error.to_string()))
    }
}

impl RaftNetwork<TypeConfig> for Wire {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<NodeNumber>,
        RPCError<NodeNumber, PeerNode, RaftError<NodeNumber>>,
    > {
        self.call(APPEND_ENTRIES, &rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeNumber>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeNumber>, RPCError<NodeNumber, PeerNode, RaftError<NodeNumber>>>
    {
        self.call(VOTE, &rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeNumber>,
        RPCError<
            NodeNumber,
            PeerNode,
            RaftError<NodeNumber, openraft::error::InstallSnapshotError>,
        >,
    > {
        let body = serde_json::to_value(&rpc).map_err(|error| unreachable(&error.to_string()))?;

        let mut peer = Peer::dial(
            &self.address,
            &self.target,
            self.schema_version,
            &self.credentials,
        )
        .await
        .map_err(|failure| unreachable(&failure.to_string()))?;

        let answer = peer
            .call(INSTALL_SNAPSHOT, body)
            .await
            .map_err(|failure| unreachable(&failure.to_string()))?;

        serde_json::from_value(answer).map_err(|error| unreachable(&error.to_string()))
    }
}

/// The answering side: what a node does with a Raft call that arrives.
pub struct RaftService {
    raft: Raft<TypeConfig>,
}

impl RaftService {
    /// Answers Raft calls with this node's own Raft.
    #[must_use]
    pub const fn new(raft: Raft<TypeConfig>) -> Self {
        Self { raft }
    }
}

impl Service for RaftService {
    fn call(
        &self,
        _from: &ek_ek_config::NodeId,
        service: &str,
        body: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<serde_json::Value, Failure>> + Send + '_>>
    {
        let named = service.to_owned();
        let raft = self.raft.clone();
        Box::pin(async move {
            match named.as_str() {
                APPEND_ENTRIES => {
                    let rpc: AppendEntriesRequest<TypeConfig> = read(body)?;
                    write(raft.append_entries(rpc).await)
                }
                VOTE => {
                    let rpc: VoteRequest<<TypeConfig as RaftTypeConfig>::NodeId> = read(body)?;
                    write(raft.vote(rpc).await)
                }
                INSTALL_SNAPSHOT => {
                    let rpc: InstallSnapshotRequest<TypeConfig> = read(body)?;
                    write(raft.install_snapshot(rpc).await)
                }
                other => Err(Failure::new(
                    ek_ek_peer::Reason::Protocol,
                    format!("this node runs no {other} service"),
                )),
            }
        })
    }
}

fn read<T: serde::de::DeserializeOwned>(body: serde_json::Value) -> Result<T, Failure> {
    serde_json::from_value(body).map_err(|error| {
        Failure::new(
            ek_ek_peer::Reason::Protocol,
            format!("a raft call could not be read: {error}"),
        )
    })
}

fn write<T: serde::Serialize, E: std::fmt::Display>(
    answered: Result<T, E>,
) -> Result<serde_json::Value, Failure> {
    let answered = answered.map_err(|error| {
        Failure::new(
            ek_ek_peer::Reason::Protocol,
            format!("a raft call failed: {error}"),
        )
    })?;
    serde_json::to_value(answered).map_err(|error| {
        Failure::new(
            ek_ek_peer::Reason::Protocol,
            format!("a raft answer could not be written: {error}"),
        )
    })
}

/// Every network failure is reported as unreachable.
///
/// openraft answers an unreachable peer with a backoff before it tries again
/// (`replication`), which is the right treatment for a peer that is down: a
/// node that cannot be dialled, cannot be authenticated or answers something
/// unreadable is not a node to retry in a tight loop.
fn unreachable<E>(detail: &str) -> RPCError<NodeNumber, PeerNode, E>
where
    E: std::error::Error,
{
    RPCError::Unreachable(Unreachable::new(&PeerFault {
        detail: detail.to_owned(),
    }))
}

/// A peer that could not be reached, in the shape openraft's errors take.
#[derive(Debug)]
struct PeerFault {
    detail: String,
}

impl std::fmt::Display for PeerFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for PeerFault {}

/// The service a node answers Raft calls with, ready for the peer listener.
#[must_use]
pub fn service(raft: Raft<TypeConfig>) -> Arc<dyn Service> {
    Arc::new(RaftService::new(raft))
}
