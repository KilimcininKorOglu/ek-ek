// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The root configuration object.

use serde::{Deserialize, Serialize};

use crate::backend::Backend;
use crate::certificate::{Certificate, DnsProvider};
use crate::frontend::Frontend;
use crate::logging::LogLevel;
use crate::node::Node;
use crate::vip::Vip;

/// Everything an operator has configured.
///
/// Objects sit in flat lists and reference each other by identity, so one
/// backend pool can serve several frontends without being duplicated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema this record was written against.
    pub schema_version: SchemaVersion,
    /// Cluster members.
    pub nodes: Vec<Node>,
    /// Addresses that move between nodes.
    pub vips: Vec<Vip>,
    /// Listening endpoints.
    pub frontends: Vec<Frontend>,
    /// Server pools.
    pub backends: Vec<Backend>,
    /// Certificates served or renewed.
    pub certificates: Vec<Certificate>,
    /// Providers used for the ACME DNS-01 challenge.
    pub dns_providers: Vec<DnsProvider>,
    /// Key the stickiness cookie is signed with, as hex.
    ///
    /// It sits at the root rather than inside a pool because it has to be
    /// the same on every node: the VIP moves, and a cookie written on one
    /// node is read on another (ADR-0065). Generating it and replicating it
    /// belong to M6; this release reads it.
    ///
    /// Empty means no key is configured, which validation refuses only when
    /// a pool actually asks for cookie stickiness.
    #[serde(default)]
    pub stickiness_key: String,
    /// How much detail the application log carries (ADR-0037).
    ///
    /// It sits at the root because logging is a property of the process, and
    /// it sits in the configuration rather than in an environment variable so
    /// an operator can change it without restarting anything.
    #[serde(default)]
    pub log_level: LogLevel,
}

/// The schema a configuration record was written against.
///
/// Upgrades are rolling, so a new release reads records written by the
/// previous one and applies the migration steps in between. A record from a
/// newer schema than the running release knows about is refused rather than
/// read with the fields it happens to recognise (ADR-0019).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    /// The schema this build writes.
    pub const CURRENT: Self = Self(1);

    /// Wraps a version read from a record.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the wrapped number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}
