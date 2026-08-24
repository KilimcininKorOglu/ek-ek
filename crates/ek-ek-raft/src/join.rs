// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How a node gets into a cluster, and how it is put out of one.
//!
//! An operator mints a token on a running node, carries it to the new machine
//! with a peer address, and runs one command. The new node makes its own key,
//! asks to be admitted, and comes back holding a certificate the cluster
//! signed (ADR-0031, ADR-0084).
//!
//! # Why this is one module and not four
//!
//! Admitting a node touches the token store, the authority, the config and
//! Raft membership, and every one of those has to happen or none of them.
//! Splitting it would put the ordering rules in four files and the reason for
//! them in none.
//!
//! # What the cluster decides and what the caller decides
//!
//! The caller says what it wants to be called and where it can be reached. The
//! cluster decides everything else: the certificate, the addresses in it, and
//! whether the name is admitted at all. A caller that could decide any of that
//! would be a caller choosing its own identity.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use ek_ek_config::{Node, NodeId, NodeRole};
use ek_ek_peer::{
    Credentials, Failure as PeerFailure, Gate, Peer, Service, authority, fingerprint, request,
};
use ek_ek_store::{AuditRecord, Change, JoinRecord, Snapshot as StoredSnapshot};
use serde::{Deserialize, Serialize};

use crate::cluster::Cluster;
use crate::error::{Failure, Reason};
use crate::network::RaftService;
use crate::token::{self, Token};

/// The service a joining node calls.
///
/// The only name a caller with no certificate may reach, and the listener
/// refuses every other one by name (ADR-0084).
pub const SERVICE: &str = "cluster.join";

/// The audit action a mint writes.
pub const TOKEN_MINTED: &str = "join_token.minted";

/// The audit action an admission writes.
pub const NODE_JOINED: &str = "node.joined";

/// The audit action a removal writes.
pub const NODE_REMOVED: &str = "node.removed";

/// What a joining node sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ask {
    /// The whole token, as one word.
    pub token: String,
    /// The name this node wants to be known by.
    pub node: String,
    /// The address the cluster records for it, and reaches it on.
    pub address: IpAddr,
    /// Host and port of its peer channel.
    pub peer_address: String,
    /// A signing request made against a key that never leaves the caller.
    pub request_pem: String,
}

/// What the cluster sends back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    /// The cluster authority, which the caller checks against its token.
    pub authority_pem: String,
    /// The certificate the cluster signed for the caller.
    pub certificate_pem: String,
    /// When the certificate starts being valid.
    pub not_before_unix: i64,
    /// When it stops.
    pub not_after_unix: i64,
}

/// What a node joining a cluster knows about itself.
///
/// A structure rather than four parameters, because the same four go to both
/// halves of a join and a positional list of them is a list somebody will get
/// out of order.
#[derive(Clone, Copy, Debug)]
pub struct Joining<'a> {
    /// The name this node wants to be known by.
    pub node: &'a NodeId,
    /// The address the cluster records for it.
    pub address: IpAddr,
    /// Host and port of its peer channel.
    pub peer_address: &'a str,
    /// The config schema it reads.
    pub schema_version: u32,
}

impl Joining<'_> {
    /// The request this node sends, with a fresh signing request in it.
    fn asking(&self, word: &str, request_pem: String) -> Ask {
        Ask {
            token: word.trim().to_owned(),
            node: self.node.as_str().to_owned(),
            address: self.address,
            peer_address: self.peer_address.to_owned(),
            request_pem,
        }
    }
}

/// What a joining node ends up holding.
#[derive(Clone)]
pub struct Joined {
    /// Everything it needs to speak to its peers from now on.
    pub credentials: Credentials,
    /// When the certificate stops being valid.
    pub not_after_unix: i64,
}

impl std::fmt::Debug for Joined {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Joined")
            .field("not_after_unix", &self.not_after_unix)
            .finish_non_exhaustive()
    }
}

/// Mints a token and records its digest through consensus.
///
/// The word comes back once. What the cluster keeps is the digest, so this
/// return value is the only chance anybody has to read the secret (ADR-0084).
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the cluster has no authority yet,
/// [`Reason::Crypto`] when the token cannot be made random, and whatever
/// [`Cluster::write_audited`] returns.
pub async fn mint(cluster: &Cluster, actor: &str, now_unix: i64) -> Result<Token, Failure> {
    let state = held(cluster)?;
    let authority = state.cluster.as_ref().ok_or_else(|| {
        Failure::new(
            Reason::Configuration,
            "this cluster has no authority, so it can admit nobody".to_owned(),
        )
    })?;

    let print = fingerprint::fingerprint(&authority.authority_pem)
        .map_err(|failure| Failure::new(Reason::Crypto, failure.detail().to_owned()))?;
    let token = token::mint(&print)?;

    let next = state.clone().with_join(
        token.id.clone(),
        JoinRecord {
            secret_digest: token::digest(&token.secret),
            expires_at_unix: now_unix + token::LIFETIME_SECONDS,
            used_by: None,
            issued_by: actor.to_owned(),
            issued_at_unix: now_unix,
        },
    );

    cluster
        .write_audited(
            &next,
            &Change::new(actor, "a join token was minted"),
            now_unix,
            &[AuditRecord {
                recorded_at_unix: now_unix,
                actor: actor.to_owned(),
                action: TOKEN_MINTED.to_owned(),
                subject: Some(token.id.as_str().to_owned()),
                // The secret is not here and must never be. An audit log an
                // operator can read is an audit log an attacker can read.
                detail: Some(format!("valid for {} seconds", token::LIFETIME_SECONDS)),
            }],
        )
        .await?;

    Ok(token)
}

/// Admits a node, on the leader.
///
/// Called twice by one join, with the same request both times.
///
/// The first call writes the config row, marks the token used and signs a
/// certificate. It does not make the caller a voter, because a caller with no
/// certificate is a caller with nothing running: a membership change waits for
/// the new member to catch up, and it would wait for a node that cannot be
/// dialled yet.
///
/// The second call arrives once that node is running and holding what the
/// first call gave it. It makes the caller a voter and nothing else. A join
/// that stops between the two leaves a node in the config that cannot vote,
/// which is why the request is decided entirely by the caller's own name and
/// can simply be sent again (ADR-0084, R-36).
///
/// # Errors
///
/// Returns [`Reason::Rejected`] when the token does not check out or the node
/// was removed from this cluster, [`Reason::Configuration`] when the request
/// does not name a node, and whatever [`Cluster::write_audited`] returns.
pub async fn admit(cluster: &Cluster, ask: &Ask, now_unix: i64) -> Result<Answer, Failure> {
    let token = Token::read(&ask.token)?;
    let node = NodeId::new(&ask.node);
    if ask.node.trim().is_empty() {
        return Err(Failure::new(
            Reason::Configuration,
            "a node with no name asked to join".to_owned(),
        ));
    }

    let state = held(cluster)?;
    let authority = state.cluster.as_ref().ok_or_else(|| {
        Failure::new(
            Reason::Configuration,
            "this cluster has no authority, so it can admit nobody".to_owned(),
        )
    })?;

    // The token was minted by this cluster or by another one. Checked here as
    // well as by the caller, because a token from a different cluster names a
    // record this one does not have and "no such token" would be the wrong
    // thing to say.
    let print = fingerprint::fingerprint(&authority.authority_pem)
        .map_err(|failure| Failure::new(Reason::Crypto, failure.detail().to_owned()))?;
    if token.fingerprint != print {
        return Err(refused(
            "the token was minted by a different cluster than this one",
        ));
    }

    // A node this cluster removed does not come back under the same name. It
    // still holds a valid certificate, and readmitting it would make the
    // refusal list mean nothing (R-32).
    if state.removed.contains(&node) {
        return Err(refused(&format!(
            "{} was removed from this cluster and is not readmitted under that name",
            node.as_str()
        )));
    }

    let record = state
        .joins
        .get(&token.id)
        .ok_or_else(|| refused("this cluster holds no such join token"))?;

    if !token::presented(&token.secret, &record.secret_digest) {
        return Err(refused("the join token secret does not check out"));
    }
    // The same node finishing a join it already started. Told apart from a
    // second node presenting the same token, which is what single use means.
    let finishing = record.used_by.as_ref().is_some_and(|used| *used == node);
    if record.used_by.is_some() && !finishing {
        return Err(refused(&format!(
            "this join token was already used by {}",
            record
                .used_by
                .as_ref()
                .map_or("another node", NodeId::as_str)
        )));
    }
    if !finishing && record.expired(now_unix) {
        return Err(refused("this join token has run out"));
    }

    // Read whole rather than assembled here. The certificate and the key that
    // signs with it have to come out together, and that rule already lives in
    // one place (ADR-0082).
    let held = ek_ek_peer::read(&state)
        .map_err(|failure| Failure::new(Reason::Configuration, failure.detail().to_owned()))?;

    let signed = request::certify(&held, &ask.request_pem, &node, &[ask.address], now_unix)
        .map_err(|failure| match failure.reason() {
            ek_ek_peer::Reason::Rejected => refused(failure.detail()),
            _ => Failure::new(Reason::Crypto, failure.detail().to_owned()),
        })?;

    if finishing {
        // The second call. The node is running now, so a membership change can
        // wait for it to catch up without waiting forever.
        if !cluster.voters().contains(&node) {
            cluster.add_voter(&node, &ask.peer_address).await?;
        }
    } else {
        // The config row first. The VIP matrix is computed over `config.nodes`,
        // so a node that is in the config is carrying addresses from the moment
        // the record lands (T-034).
        let mut next = state.clone();
        if !next.config.nodes.iter().any(|held| held.id == node) {
            next.config.nodes.push(Node {
                id: node.clone(),
                address: ask.address,
                roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
            });
        }
        next.joins.insert(
            token.id.clone(),
            JoinRecord {
                used_by: Some(node.clone()),
                ..record.clone()
            },
        );

        cluster
            .write_audited(
                &next,
                &Change::new(node.as_str(), "a node joined the cluster"),
                now_unix,
                &[AuditRecord {
                    recorded_at_unix: now_unix,
                    actor: node.as_str().to_owned(),
                    action: NODE_JOINED.to_owned(),
                    subject: Some(node.as_str().to_owned()),
                    detail: Some(format!(
                        "at {} with join token {}",
                        ask.peer_address, token.id
                    )),
                }],
            )
            .await?;
    }

    Ok(Answer {
        authority_pem: authority.authority_pem.clone(),
        certificate_pem: signed.certificate_pem,
        not_before_unix: signed.not_before_unix,
        not_after_unix: signed.not_after_unix,
    })
}

/// Puts a node out of the cluster, on the leader.
///
/// The vote goes first and the config row after it, so a leader that falls
/// between the two leaves a node that cannot vote rather than one that can
/// still write. Its certificate stays valid either way, and what stops it
/// speaking is the refusal list this call writes (R-32, ADR-0084).
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the node is not in this cluster or
/// is the last voter in it, and whatever [`Cluster::write_audited`] returns.
pub async fn remove(
    cluster: &Cluster,
    node: &NodeId,
    actor: &str,
    now_unix: i64,
) -> Result<(), Failure> {
    let state = held(cluster)?;
    if !state.config.nodes.iter().any(|held| held.id == *node) {
        return Err(Failure::new(
            Reason::Configuration,
            format!("{} is not a node in this cluster", node.as_str()),
        ));
    }

    // The vote first. A leader that falls between the two steps leaves a node
    // that cannot vote rather than one that can still write, and the refusal
    // list below is what stops it speaking either way (ADR-0084).
    cluster.remove_voter(node).await?;

    let mut next = state.clone();
    next.config.nodes.retain(|held| held.id != *node);
    next.removed.insert(node.clone());

    cluster
        .write_audited(
            &next,
            &Change::new(actor, "a node was removed from the cluster"),
            now_unix,
            &[AuditRecord {
                recorded_at_unix: now_unix,
                actor: actor.to_owned(),
                action: NODE_REMOVED.to_owned(),
                subject: Some(node.as_str().to_owned()),
                detail: Some(
                    "the node no longer votes and its peer connections are refused".to_owned(),
                ),
            }],
        )
        .await?;

    Ok(())
}

/// Joins a cluster, on the node doing the joining.
///
/// The key is made here and stays here. What crosses the channel is a signing
/// request and what comes back is a certificate, so nothing that could
/// impersonate this node ever travels (R-33, ADR-0084).
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the token is not one,
/// [`Reason::Rejected`] when the cluster refuses the join or answers with an
/// authority the token does not name, and [`Reason::Consensus`] when the
/// exchange itself fails.
pub async fn join(target: &str, word: &str, joining: Joining<'_>) -> Result<Joined, Failure> {
    let token = Token::read(word)?;
    let asked = request::request().map_err(crypto)?;

    let mut peer = Peer::dial_unproven(target, joining.schema_version)
        .await
        .map_err(|failure| Failure::new(Reason::Consensus, failure.detail().to_owned()))?;

    // Kept before the exchange. The certificate the far end served is what the
    // authority below has to have signed, and reading it afterwards would let
    // a second connection answer for the first.
    let served = peer
        .served()
        .cloned()
        .ok_or_else(|| refused("the cluster presented no certificate at all"))?;

    let answered = peer
        .call(
            SERVICE,
            serde_json::to_value(joining.asking(word, asked.request_pem)).map_err(|error| {
                Failure::new(
                    Reason::Configuration,
                    format!("the join request could not be written out: {error}"),
                )
            })?,
        )
        .await
        .map_err(|failure| Failure::new(Reason::Rejected, failure.detail().to_owned()))?;

    let answer: Answer = serde_json::from_value(answered).map_err(|error| {
        Failure::new(
            Reason::Consensus,
            format!("the join answer could not be read: {error}"),
        )
    })?;

    // Both halves, in this order. The fingerprint says the authority is the
    // one the token named; the signature says the node that answered holds a
    // certificate from it. Either half alone proves nothing: a fingerprint is
    // a public value anybody can repeat, and a signature from an authority
    // nobody named is a signature from an authority nobody trusts.
    if !fingerprint::matches(&answer.authority_pem, &token.fingerprint).map_err(crypto)? {
        return Err(refused(
            "the cluster answered with an authority the token does not name",
        ));
    }
    if !authority::signed_by(&served, &answer.authority_pem).map_err(crypto)? {
        return Err(refused(
            "the node that answered does not hold a certificate from that authority",
        ));
    }

    Ok(Joined {
        credentials: Credentials {
            authority_pem: answer.authority_pem,
            certificate_pem: answer.certificate_pem,
            key_pem: asked.key_pem,
        },
        not_after_unix: answer.not_after_unix,
    })
}

/// What a node in a cluster answers: the Raft calls, and the one call a node
/// with no certificate is allowed to make.
///
/// One service rather than two listeners. A second port would be a second
/// trust setup to get right, which is the reason ADR-0083 refused one for Raft
/// and the reason ADR-0084 refuses one here.
pub struct Admission {
    cluster: Arc<Cluster>,
    raft: RaftService,
    clock: Clock,
}

/// Where this module reads the time.
///
/// A parameter rather than a call to the operating system, so a token that ran
/// out last week is a value away and the rules about hours are measured in
/// microseconds.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

impl Admission {
    /// Answers for one cluster.
    #[must_use]
    pub fn new(cluster: Arc<Cluster>, clock: Clock) -> Self {
        let raft = RaftService::new(cluster.raft().clone());
        Self {
            cluster,
            raft,
            clock,
        }
    }
}

impl Service for Admission {
    fn call(
        &self,
        from: Option<&NodeId>,
        service: &str,
        body: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, PeerFailure>> + Send + '_>> {
        if service != SERVICE {
            return self.raft.call(from, service, body);
        }

        let cluster = Arc::clone(&self.cluster);
        let now = (self.clock)();
        Box::pin(async move {
            let ask: Ask = serde_json::from_value(body).map_err(|error| {
                PeerFailure::new(
                    ek_ek_peer::Reason::Protocol,
                    format!("a join request could not be read: {error}"),
                )
            })?;

            let answer = admit(&cluster, &ask, now)
                .await
                .map_err(|failure| PeerFailure::new(carried(failure.reason()), failure.detail()))?;

            serde_json::to_value(answer).map_err(|error| {
                PeerFailure::new(
                    ek_ek_peer::Reason::Protocol,
                    format!("the join answer could not be written out: {error}"),
                )
            })
        })
    }
}

/// The refusal list, as the peer listener asks about it.
///
/// Read from this node's own state, without a quorum. A node that could not
/// reach a quorum and therefore admitted a removed peer would be a node whose
/// refusal list stops working exactly when the cluster is already in trouble
/// (ADR-0004, ADR-0084).
pub struct Refusals {
    cluster: Arc<Cluster>,
}

impl Refusals {
    /// Reads the list this cluster holds.
    #[must_use]
    pub const fn new(cluster: Arc<Cluster>) -> Self {
        Self { cluster }
    }
}

impl Gate for Refusals {
    fn refuses(&self, caller: &NodeId) -> bool {
        self.cluster
            .read()
            .ok()
            .flatten()
            .is_some_and(|state| state.removed.contains(caller))
    }
}

/// The reason a peer sees for a reason this crate raised.
const fn carried(reason: Reason) -> ek_ek_peer::Reason {
    match reason {
        Reason::Rejected => ek_ek_peer::Reason::Rejected,
        Reason::Crypto => ek_ek_peer::Reason::Crypto,
        Reason::Configuration => ek_ek_peer::Reason::Configuration,
        Reason::NotLeader | Reason::NoQuorum | Reason::Consensus | Reason::Storage => {
            ek_ek_peer::Reason::Network
        }
        Reason::Schema => ek_ek_peer::Reason::Protocol,
    }
}

/// Finishes a join, from the node that is now running.
///
/// The same request as [`join`], sent again with the certificate the first
/// call handed back. This is the call that makes the node a voter, and it has
/// to come from a node that is up: a membership change waits for the new
/// member to catch up (ADR-0084).
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the token is not one,
/// [`Reason::Rejected`] when the cluster refuses, and [`Reason::Consensus`]
/// when the exchange itself fails.
pub async fn enlist(
    target: &str,
    word: &str,
    leader: &NodeId,
    joining: Joining<'_>,
    credentials: &Credentials,
) -> Result<(), Failure> {
    let mut peer = Peer::dial(target, leader, joining.schema_version, credentials)
        .await
        .map_err(|failure| Failure::new(Reason::Consensus, failure.detail().to_owned()))?;

    // A fresh signing request rather than the first one kept. The certificate
    // the answer carries is discarded, so what this one certifies does not
    // matter; keeping the first would mean holding a signing request open
    // across a restart for no reason.
    let asking = joining.asking(word, request::request().map_err(crypto)?.request_pem);

    peer.call(
        SERVICE,
        serde_json::to_value(asking).map_err(|error| {
            Failure::new(
                Reason::Configuration,
                format!("the join request could not be written out: {error}"),
            )
        })?,
    )
    .await
    .map_err(|failure| Failure::new(Reason::Rejected, failure.detail().to_owned()))?;

    Ok(())
}

/// The state this node holds, refusing to act on an empty one.
fn held(cluster: &Cluster) -> Result<StoredSnapshot, Failure> {
    cluster.read()?.ok_or_else(|| {
        Failure::new(
            Reason::Configuration,
            "this node holds no state, so it can admit nobody".to_owned(),
        )
    })
}

fn refused(detail: &str) -> Failure {
    Failure::new(Reason::Rejected, detail.to_owned())
}

fn crypto(failure: ek_ek_peer::Failure) -> Failure {
    Failure::new(Reason::Crypto, failure.detail().to_owned())
}
