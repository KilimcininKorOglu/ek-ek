// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identifiers used to reference one config object from another.
//!
//! References are made by identity rather than by embedding, so one backend
//! pool can serve several frontends and a member keeps its identity when its
//! address changes.

use serde::{Deserialize, Serialize};

macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps a value that is already a valid identifier.
            ///
            /// Whether the value is well formed and whether it resolves are
            /// both questions for the validation layer.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Borrows the wrapped value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

identifier! {
    /// Identifies a cluster node.
    NodeId
}

identifier! {
    /// Identifies a virtual IP.
    VipId
}

identifier! {
    /// Identifies a frontend.
    FrontendId
}

identifier! {
    /// Identifies a backend pool.
    BackendId
}

identifier! {
    /// Identifies a member inside a backend pool.
    ///
    /// The session stickiness cookie carries this value rather than an
    /// address, so a member that moves keeps its client affinity.
    MemberId
}

identifier! {
    /// Identifies a certificate.
    CertificateId
}

identifier! {
    /// Identifies a DNS provider configuration.
    DnsProviderId
}

identifier! {
    /// References key material held encrypted in the store.
    ///
    /// The config model never carries a private key, an API token or a TSIG
    /// secret. It carries this reference and the store resolves it.
    SecretId
}
