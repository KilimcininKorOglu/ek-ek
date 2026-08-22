// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Putting an inspected upload into a store state.
//!
//! The certificate record and the two pieces of material it references have
//! to arrive together. A record that names material nobody stored is a
//! frontend that answers no handshake, and material nobody references is a
//! private key kept for no reason.

use ek_ek_config::{Certificate, CertificateId, CertificateSource, SecretId};
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
#[must_use]
pub fn install(state: &Snapshot, id: &CertificateId, upload: Upload) -> Snapshot {
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
        source: CertificateSource::ManualUpload,
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
