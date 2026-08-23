// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the product needs to talk to an ACME server.
//!
//! One block at the root of the configuration, not one per certificate. Every
//! certificate an installation orders comes from the same account, because a
//! second account buys nothing and every account counts separately against the
//! server's rate limits (ADR-0026).
//!
//! No key material is here. The account key lives sealed in the store under a
//! fixed identity, so exporting a configuration cannot leak it, and an
//! operator never has to hold it (ADR-0018).

use serde::{Deserialize, Serialize};

/// The identity the ACME account key is stored under.
///
/// Fixed rather than configurable: the server recognises an account by the
/// fingerprint of its key, so which key is in use is not a choice an operator
/// has, and a field for it would only be a way to break the account.
pub const ACCOUNT_KEY: &str = "acme.account.key";

/// How the product reaches an ACME server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSettings {
    /// The server's directory document.
    ///
    /// This one field is what switches between a production server and a
    /// staging one, because that is all the two differ by. Nothing else in
    /// the configuration names an environment, so there is no second place
    /// for the two to disagree.
    pub directory_url: String,
    /// Address the account is registered with.
    ///
    /// Optional, because RFC 8555 does not require one and some servers
    /// refuse the ones they cannot reach.
    #[serde(default)]
    pub contact_email: String,
    /// Whether the operator has accepted the server's terms of service.
    ///
    /// Kept as an explicit field rather than sent unconditionally: agreeing to
    /// a contract on somebody's behalf is not this product's to do.
    #[serde(default)]
    pub accepted_terms: bool,
    /// A certificate authority to trust for the ACME server's own HTTPS
    /// endpoint, as PEM.
    ///
    /// Empty means the system trust store, which is what a public server
    /// needs. A value is what an internal ACME server (step-ca, smallstep) or
    /// a local test server needs, because neither is signed by an authority
    /// the machine already trusts.
    ///
    /// A root certificate is public material, so it sits in the configuration
    /// rather than in the store beside the keys.
    #[serde(default)]
    pub trusted_root_pem: String,
}
