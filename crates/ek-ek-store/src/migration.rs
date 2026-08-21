// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bringing a stored config forward to the schema this build reads.
//!
//! Steps run on the stored document rather than on [`Config`], because a
//! document written by an older release may not parse into the current model
//! at all. That is the situation migration exists for, so migrating through
//! the model would only work in the cases that need no migration.
//!
//! Steps are one way. There is no downgrade, and none is written, because a
//! step that adds meaning cannot invent it again in reverse (ADR-0019).
//!
//! Upgrades are rolling, so a node may read a record written by a newer
//! release. It refuses to start rather than reading the fields it happens to
//! recognise.

use ek_ek_config::{Config, SchemaVersion};
use serde_json::Value;

use crate::error::{Error, ErrorKind, Result};

/// One step from the schema below it to the schema it names.
///
/// The runner sets `schema_version` after the step returns, so a step only
/// has to describe the shape change.
#[derive(Clone, Copy)]
pub struct Migration {
    /// The schema this step produces.
    pub to: SchemaVersion,
    /// The change it makes to a stored document.
    pub apply: fn(&mut Value) -> Result<()>,
}

impl std::fmt::Debug for Migration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Migration")
            .field("to", &self.to.get())
            .finish_non_exhaustive()
    }
}

/// Every step this build knows, in the order they run.
///
/// Schema 1 is the first schema, so there is nothing to step through yet. A
/// second schema adds one entry here and one example document under
/// `tests/fixtures/config/`.
pub const MIGRATIONS: &[Migration] = &[];

/// The schema a set of steps arrives at.
#[must_use]
pub fn target_version(steps: &[Migration]) -> SchemaVersion {
    steps
        .iter()
        .map(|step| step.to)
        .max()
        .unwrap_or(SchemaVersion::CURRENT)
        .max(SchemaVersion::CURRENT)
}

/// Reads the schema version a stored document carries.
///
/// # Errors
///
/// Fails when the document is not an object or carries no usable version,
/// which means it was not written by this product.
pub fn document_version(document: &Value) -> Result<SchemaVersion> {
    let value = document
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Serialisation,
                "a stored document carries no schema version".to_owned(),
            )
        })?;

    u32::try_from(value).map(SchemaVersion::new).map_err(|_| {
        Error::new(
            ErrorKind::Serialisation,
            format!("a schema version of {value} cannot be read"),
        )
    })
}

/// Runs every step a document still needs.
///
/// Returns the schema the document ends on. A document already at the target
/// is left exactly as it is.
///
/// # Errors
///
/// Returns [`ErrorKind::SchemaMismatch`] when the document was written by a
/// newer release than these steps reach. The caller must stop rather than
/// carry on with a document it does not understand.
pub fn migrate_document(document: &mut Value, steps: &[Migration]) -> Result<SchemaVersion> {
    let from = document_version(document)?;
    let target = target_version(steps);

    if from > target {
        return Err(Error::new(
            ErrorKind::SchemaMismatch,
            format!(
                "a record written against schema {} cannot be read by a build that reaches {}",
                from.get(),
                target.get()
            ),
        ));
    }

    let mut at = from;
    for step in steps {
        if step.to <= at {
            continue;
        }
        (step.apply)(document)?;
        set_version(document, step.to)?;
        at = step.to;
    }

    Ok(at)
}

/// Runs the steps and then reads the result into the current model.
///
/// # Errors
///
/// Fails when a step fails, or when the migrated document still does not fit
/// the model, which means a step is missing or wrong.
pub fn migrate_into_config(document: &mut Value, steps: &[Migration]) -> Result<Config> {
    migrate_document(document, steps)?;
    serde_json::from_value(document.clone()).map_err(|error| {
        Error::new(
            ErrorKind::Serialisation,
            format!("a migrated document does not fit the current model: {error}"),
        )
    })
}

fn set_version(document: &mut Value, version: SchemaVersion) -> Result<()> {
    let object = document.as_object_mut().ok_or_else(|| {
        Error::new(
            ErrorKind::Serialisation,
            "a stored document is not an object".to_owned(),
        )
    })?;
    object.insert(
        "schema_version".to_owned(),
        Value::from(u64::from(version.get())),
    );
    Ok(())
}
