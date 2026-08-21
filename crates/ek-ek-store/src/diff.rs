// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What changed between two configs.
//!
//! The comparison is pure computation over two values, so it needs no store
//! and belongs to nobody's database. Rendering it is the UI's job (M9); this
//! answers only which objects appeared, disappeared or changed.

use std::collections::BTreeMap;

use ek_ek_config::Config;
use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, ErrorKind, Result};

/// A kind of object a config holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    /// A cluster node.
    Node,
    /// A virtual IP.
    Vip,
    /// A listening endpoint.
    Frontend,
    /// A server pool.
    Backend,
    /// A certificate.
    Certificate,
    /// A DNS provider configuration.
    DnsProvider,
}

impl ObjectKind {
    /// Returns the stable identifier this kind is named by.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Vip => "vip",
            Self::Frontend => "frontend",
            Self::Backend => "backend",
            Self::Certificate => "certificate",
            Self::DnsProvider => "dns_provider",
        }
    }
}

/// What happened to one object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectChange {
    /// It is in the later config and not in the earlier one.
    Added,
    /// It is in the earlier config and not in the later one.
    Removed,
    /// It is in both and its contents differ.
    Modified,
}

/// One line of a comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffEntry {
    /// What kind of object this is.
    pub kind: ObjectKind,
    /// The identity of the object.
    pub id: String,
    /// What happened to it.
    pub change: ObjectChange,
}

/// Everything that differs between two configs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigDiff {
    /// The differences, ordered by kind and then by identity.
    pub entries: Vec<DiffEntry>,
}

impl ConfigDiff {
    /// Returns whether the two configs hold the same objects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns how many objects differ.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the entries of one kind of change.
    #[must_use]
    pub fn of(&self, change: ObjectChange) -> Vec<&DiffEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.change == change)
            .collect()
    }

    /// Returns whether this object changed in this way.
    #[must_use]
    pub fn contains(&self, kind: ObjectKind, id: &str, change: ObjectChange) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.kind == kind && entry.id == id && entry.change == change)
    }
}

/// Compares two configs.
///
/// # Errors
///
/// Fails when an object cannot be rendered for comparison, which would mean
/// the model and its serialisation disagree.
pub fn diff(before: &Config, after: &Config) -> Result<ConfigDiff> {
    let mut entries = Vec::new();

    compare(
        ObjectKind::Node,
        &index(&before.nodes, |node| node.id.as_str())?,
        &index(&after.nodes, |node| node.id.as_str())?,
        &mut entries,
    );
    compare(
        ObjectKind::Vip,
        &index(&before.vips, |vip| vip.id.as_str())?,
        &index(&after.vips, |vip| vip.id.as_str())?,
        &mut entries,
    );
    compare(
        ObjectKind::Frontend,
        &index(&before.frontends, |frontend| frontend.id.as_str())?,
        &index(&after.frontends, |frontend| frontend.id.as_str())?,
        &mut entries,
    );
    compare(
        ObjectKind::Backend,
        &index(&before.backends, |backend| backend.id.as_str())?,
        &index(&after.backends, |backend| backend.id.as_str())?,
        &mut entries,
    );
    compare(
        ObjectKind::Certificate,
        &index(&before.certificates, |certificate| certificate.id.as_str())?,
        &index(&after.certificates, |certificate| certificate.id.as_str())?,
        &mut entries,
    );
    compare(
        ObjectKind::DnsProvider,
        &index(&before.dns_providers, |provider| provider.id.as_str())?,
        &index(&after.dns_providers, |provider| provider.id.as_str())?,
        &mut entries,
    );

    Ok(ConfigDiff { entries })
}

fn index<T: Serialize>(
    items: &[T],
    identity: impl Fn(&T) -> &str,
) -> Result<BTreeMap<String, Value>> {
    let mut indexed = BTreeMap::new();
    for item in items {
        let value = serde_json::to_value(item).map_err(|error| {
            Error::new(
                ErrorKind::Serialisation,
                format!("an object could not be rendered for comparison: {error}"),
            )
        })?;
        indexed.insert(identity(item).to_owned(), value);
    }
    Ok(indexed)
}

fn compare(
    kind: ObjectKind,
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    entries: &mut Vec<DiffEntry>,
) {
    for (id, old) in before {
        let change = match after.get(id) {
            None => ObjectChange::Removed,
            Some(new) if new == old => continue,
            Some(_) => ObjectChange::Modified,
        };
        entries.push(DiffEntry {
            kind,
            id: id.clone(),
            change,
        });
    }

    for id in after.keys() {
        if !before.contains_key(id) {
            entries.push(DiffEntry {
                kind,
                id: id.clone(),
                change: ObjectChange::Added,
            });
        }
    }
}
