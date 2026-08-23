// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Putting the cluster authority into a store state, and reading it back.
//!
//! The authority certificate and the key that signs with it have to arrive
//! together. A certificate nobody can sign with is a cluster that can never
//! enrol another node; a key with no certificate is material kept for no
//! reason.
//!
//! The key goes in as a secret, so the store seals it with the node's own
//! master key before it touches the disk (ADR-0018). The certificate goes in
//! as the cluster identity, which is public and is what a joining node is
//! asked to trust.

use ek_ek_config::SecretId;
use ek_ek_store::{ClusterIdentity, Secret, Snapshot};

use crate::authority::Authority;
use crate::error::{Failure, Reason};

/// The identity the cluster authority's private key is stored under.
///
/// Reserved: no certificate an operator uploads can produce this name,
/// because `ek-ek-tls` derives its own from a certificate identity and
/// appends a suffix to it (`record::key_id`). A configuration that referenced
/// this name would be referring to the cluster's own key, which is why it is
/// named here once and never typed anywhere else.
pub const AUTHORITY_KEY_SECRET: &str = "cluster-ca.key";

/// The identity the cluster authority's private key is stored under.
#[must_use]
pub fn authority_key_id() -> SecretId {
    SecretId::new(AUTHORITY_KEY_SECRET)
}

/// Puts a fresh authority into a state.
///
/// Replaces whatever was there. Whether it may be replaced is a question for
/// the caller: `ek-ek cluster init` refuses to run twice, because a second
/// authority would leave every node certificate signed by the first one
/// unable to connect.
#[must_use]
pub fn install(state: &Snapshot, authority: &Authority) -> Snapshot {
    let mut next = state.clone();
    next.cluster = Some(ClusterIdentity::new(authority.certificate_pem.clone()));
    next.secrets
        .insert(authority_key_id(), authority.key_pem.clone());
    next
}

/// Reads the authority back out of a state.
///
/// # Errors
///
/// Returns [`Reason::Storage`] when either half is missing. Half an authority
/// is refused rather than repaired: a certificate with no key means nothing
/// can be signed, and a key with no certificate means nothing can be trusted,
/// and neither is something this crate may guess its way out of.
pub fn read(state: &Snapshot) -> Result<Authority, Failure> {
    let identity = state.cluster.as_ref().ok_or_else(|| {
        Failure::new(
            Reason::Storage,
            "this node holds no cluster authority; run `ek-ek cluster init` or join a cluster"
                .to_owned(),
        )
    })?;

    let key: &Secret = state.secrets.get(&authority_key_id()).ok_or_else(|| {
        Failure::new(
            Reason::Storage,
            format!(
                "the cluster authority certificate is stored but {AUTHORITY_KEY_SECRET} is not"
            ),
        )
    })?;

    Ok(Authority {
        certificate_pem: identity.authority_pem.clone(),
        key_pem: key.clone(),
    })
}

/// Whether a state already carries an authority.
///
/// Both halves, because either one alone is what [`read`] refuses.
#[must_use]
pub fn present(state: &Snapshot) -> bool {
    state.cluster.is_some() && state.secrets.contains_key(&authority_key_id())
}
