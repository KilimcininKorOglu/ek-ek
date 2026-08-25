// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Putting an inspected upload into a store state.
//!
//! The certificate record and the two pieces of material it references have
//! to arrive together. A record that names material nobody stored is a
//! frontend that answers no handshake, and material nobody references is a
//! private key kept for no reason.

use ek_ek_config::{Certificate, CertificateId, CertificateSource, Config, SecretId};
use ek_ek_store::Snapshot;

use crate::inspect::Upload;

/// The suffix the stored chain is filed under.
pub const CHAIN_SUFFIX: &str = ".chain";

/// The suffix the stored private key is filed under.
pub const KEY_SUFFIX: &str = ".key";

/// The identity the chain of one certificate is stored under.
#[must_use]
pub fn chain_id(certificate: &CertificateId) -> SecretId {
    SecretId::new(format!("{}{CHAIN_SUFFIX}", certificate.as_str()))
}

/// The identity the private key of one certificate is stored under.
#[must_use]
pub fn key_id(certificate: &CertificateId) -> SecretId {
    SecretId::new(format!("{}{KEY_SUFFIX}", certificate.as_str()))
}

/// The suffix the key of a running order is filed under.
pub const ORDER_KEY_SUFFIX: &str = ".order-key";

/// The identity the signing key of a running order is stored under.
///
/// Separate from [`key_id`] on purpose. The order key is written before the
/// certificate authority is asked anything, so filing it under the serving
/// identity would replace the key of the certificate currently being served
/// with one no certificate belongs to yet (ADR-0086).
#[must_use]
pub fn order_key_id(certificate: &CertificateId) -> SecretId {
    SecretId::new(format!("{}{ORDER_KEY_SUFFIX}", certificate.as_str()))
}

/// Puts an upload into a state, replacing any certificate of the same name.
///
/// Derived identities rather than fresh ones: uploading a replacement writes
/// over the two entries the old certificate used, so nothing is left behind
/// for a later sweep to find. It also means a stored key can be traced back
/// to the certificate it belongs to by its name alone.
///
/// The names come from the certificate itself and are never typed by an
/// operator, because a name that does not match the certificate is a
/// handshake that fails for one host and works for the others (T-025).
///
/// The source is passed in rather than assumed. The same material arrives from
/// an operator's upload and from an ACME order, and the record has to say
/// which, because renewal reads it: a certificate filed as an upload is never
/// renewed, and one filed as ACME is (ADR-0026).
#[must_use]
pub fn install(
    state: &Snapshot,
    id: &CertificateId,
    source: CertificateSource,
    upload: Upload,
) -> Snapshot {
    let Upload {
        sni_names,
        validity,
        chain,
        key,
        warnings: _,
    } = upload;

    let record = Certificate {
        id: id.clone(),
        sni_names,
        source,
        validity: Some(validity),
        chain: Some(chain_id(id)),
        private_key: Some(key_id(id)),
    };

    let mut next = state.clone();
    match next
        .config
        .certificates
        .iter_mut()
        .find(|held| &held.id == id)
    {
        Some(held) => *held = record,
        None => next.config.certificates.push(record),
    }
    next.secrets.insert(chain_id(id), chain);
    next.secrets.insert(key_id(id), key);
    next
}

/// A document with what has already been obtained carried into it.
///
/// Two things know about a certificate and neither knows all of it. The
/// document says which certificates exist, which names they cover and how they
/// are obtained; an operator writes it and it is the authority on all three.
/// What an order produced (the validity window and the two references to the
/// material) exists only after an order, so only the store has it.
///
/// Without this, replacing the stored configuration with the document would
/// throw that away, and renewal would then see every certificate as one that
/// has never been obtained and order all of them on every run (ADR-0079).
///
/// The names are not part of the decision: a document that changes which names
/// a certificate covers keeps the material it already has, which is the same
/// thing the traffic path does with it.
#[must_use]
pub fn carry_obtained(document: &Config, stored: &Config) -> Config {
    let mut next = document.clone();
    for certificate in &mut next.certificates {
        let Some(held) = stored
            .certificates
            .iter()
            .find(|held| held.id == certificate.id)
        else {
            continue;
        };
        certificate.validity = held.validity;
        certificate.chain.clone_from(&held.chain);
        certificate.private_key.clone_from(&held.private_key);
    }
    next
}

/// Takes a certificate and its material out of a state.
///
/// Whether it may go is a question for the validation layer, which knows
/// what still references it (`validate_certificate_removal`). This does the
/// removal itself and leaves no material behind.
#[must_use]
pub fn remove(state: &Snapshot, id: &CertificateId) -> Snapshot {
    let mut next = state.clone();
    next.config.certificates.retain(|held| &held.id != id);
    next.secrets.remove(&chain_id(id));
    next.secrets.remove(&key_id(id));
    next
}
