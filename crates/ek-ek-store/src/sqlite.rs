// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SQLite implementation of the store.
//!
//! Every statement in this file binds its values as parameters. No query is
//! ever assembled by joining strings, so no stored value can be read as SQL.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ek_ek_config::{CertificateId, Config, NodeId, SchemaVersion, SecretId};
use rusqlite::{Connection, OptionalExtension, Transaction};

use crate::cluster::ClusterIdentity;
use crate::crypto::{Sealed, open, seal};
use crate::error::{Error, ErrorKind, Result};
use crate::journal::{AuditRecord, FullState, Journal, Record, StoredVersion};
use crate::master_key::{MASTER_KEY_FILE, MasterKey};
use crate::membership::{JoinRecord, Removed, TokenId};
use crate::migration::{MIGRATIONS, Migration, migrate_document, target_version};
use crate::order::{OrderChallenge, OrderRecord, Orders};
use crate::secret::Secret;
use crate::store::{Snapshot, Store};
use crate::version::{
    Change, ChangeKind, History, MAX_VERSIONS, PruningRecord, VersionId, VersionRecord,
};

/// The action a pruning row carries in the audit log.
///
/// M8 owns the audit log. The table is already there and reserved for it, so
/// a retention note goes in as a row rather than into a second table nobody
/// would think to look in.
const PRUNED_ACTION: &str = "version.pruned";

/// Where a node keeps its data in a real installation (ADR-0010).
pub const DEFAULT_DATA_DIRECTORY: &str = "/var/lib/ek-ek";

/// Name of the database inside the data directory.
pub const DATABASE_FILE: &str = "config.db";

/// What a pre-migration backup file is called before its schema and time.
pub const BACKUP_PREFIX: &str = "backup-schema-";

/// Permissions the data directory carries.
const DIRECTORY_MODE: u32 = 0o700;

/// The one row the config state occupies.
const STATE_ROW: i64 = 1;

/// A store backed by a SQLite database in a node's data directory.
#[derive(Debug)]
pub struct SqliteStore {
    connection: Mutex<Connection>,
    key: MasterKey,
    directory: PathBuf,
    /// The schema this store reached when it opened.
    ///
    /// It is the migration steps' target rather than [`SchemaVersion::CURRENT`],
    /// because a build carrying steps reads further than the schema it writes
    /// by default.
    target: SchemaVersion,
}

impl SqliteStore {
    /// Opens the store, creating the directory, the key and the schema when
    /// they are not there yet.
    ///
    /// # Errors
    ///
    /// Refuses to start when a database exists without its master key, rather
    /// than quietly presenting an empty state as if nothing had been stored.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_migrations(directory, MIGRATIONS)
    }

    /// Opens the store, bringing an older record forward through `steps`.
    ///
    /// The step list is a parameter so a test can prove the runner works
    /// without a fake step ever shipping in [`MIGRATIONS`].
    ///
    /// # Errors
    ///
    /// Refuses to start when a database exists without its master key, and
    /// when a record was written against a schema newer than `steps` reach.
    pub fn open_with_migrations(directory: impl AsRef<Path>, steps: &[Migration]) -> Result<Self> {
        let directory = directory.as_ref().to_path_buf();

        fs::create_dir_all(&directory).map_err(|error| {
            Error::new(
                ErrorKind::DataDirectory,
                format!("{} could not be created: {error}", directory.display()),
            )
        })?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(DIRECTORY_MODE)).map_err(
            |error| {
                Error::new(
                    ErrorKind::DataDirectory,
                    format!(
                        "{} could not be restricted to its owner: {error}",
                        directory.display()
                    ),
                )
            },
        )?;

        let database = directory.join(DATABASE_FILE);
        let key_path = directory.join(MASTER_KEY_FILE);

        let key = if key_path.exists() {
            MasterKey::read(&key_path)?
        } else if database.exists() {
            return Err(Error::new(
                ErrorKind::MasterKeyMissing,
                format!(
                    "{} exists but {} does not, so the stored state cannot be opened",
                    database.display(),
                    key_path.display()
                ),
            ));
        } else {
            MasterKey::create(&key_path)?
        };

        let connection = Connection::open(&database).map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("{} could not be opened: {error}", database.display()),
            )
        })?;

        let store = Self {
            connection: Mutex::new(connection),
            key,
            directory,
            target: target_version(steps),
        };
        store.prepare()?;
        store.bring_forward(steps)?;
        Ok(store)
    }

    /// Reads the schema the stored config was written against.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be read.
    pub fn stored_schema_version(&self) -> Result<Option<SchemaVersion>> {
        let connection = self.connection()?;
        let stored: Option<i64> = connection
            .query_row(
                "SELECT schema_version FROM config_state WHERE id = ?1",
                [STATE_ROW],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage("the stored schema version could not be read"))?;
        drop(connection);

        stored
            .map(|value| {
                u32::try_from(value).map(SchemaVersion::new).map_err(|_| {
                    Error::new(
                        ErrorKind::Serialisation,
                        format!("a stored schema version of {value} cannot be read"),
                    )
                })
            })
            .transpose()
    }

    /// Copies the database somewhere safe before a migration touches it.
    ///
    /// The copy goes through SQLite's own backup, so it holds what the
    /// write-ahead log holds as well. Copying the file by hand would leave
    /// out everything committed since the last checkpoint.
    ///
    /// # Errors
    ///
    /// Fails when the copy cannot be made.
    pub fn back_up(&self, from: SchemaVersion) -> Result<PathBuf> {
        let stamp = seconds_since_epoch()?;
        let path = self
            .directory
            .join(format!("{BACKUP_PREFIX}{}-{stamp}.db", from.get()));

        let connection = self.connection()?;
        connection
            .backup(rusqlite::MAIN_DB, &path, None)
            .map_err(storage("the backup could not be written"))?;

        Ok(path)
    }

    /// Runs every step the stored records still need.
    ///
    /// The current state and every version in the log move together, so
    /// rolling back to an earlier version keeps working across an upgrade.
    /// A failure leaves the store exactly as it was.
    fn bring_forward(&self, steps: &[Migration]) -> Result<()> {
        let Some(stored) = self.stored_schema_version()? else {
            return Ok(());
        };
        let target = self.target;

        if stored > target {
            return Err(Error::new(
                ErrorKind::SchemaMismatch,
                format!(
                    "the stored config was written against schema {} and this build reaches {}",
                    stored.get(),
                    target.get()
                ),
            ));
        }
        if stored == target {
            return Ok(());
        }

        // Take the backup before anything is touched, so a failed migration
        // still leaves a copy of what was there.
        self.back_up(stored)?;

        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(storage("a transaction could not be started"))?;

        migrate_row(
            &transaction,
            "SELECT document FROM config_state WHERE id = ?1",
            "UPDATE config_state SET document = ?2, schema_version = ?3 WHERE id = ?1",
            STATE_ROW,
            steps,
        )?;

        let ids = version_ids(&transaction)?;
        for id in ids {
            migrate_row(
                &transaction,
                "SELECT document FROM config_version WHERE id = ?1",
                "UPDATE config_version SET document = ?2, schema_version = ?3 WHERE id = ?1",
                id,
                steps,
            )?;
        }

        transaction
            .commit()
            .map_err(storage("the migration could not be committed"))?;

        Ok(())
    }

    /// Returns the schema this store reads up to.
    #[must_use]
    pub const fn target_schema_version(&self) -> SchemaVersion {
        self.target
    }

    /// Returns the directory this store lives in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Runs SQLite's own consistency check.
    ///
    /// # Errors
    ///
    /// Fails when the check cannot be run.
    pub fn integrity_check(&self) -> Result<String> {
        let connection = self.connection()?;
        connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("the integrity check did not run: {error}"),
                )
            })
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("the store lock was poisoned by an earlier panic: {error}"),
            )
        })
    }

    fn prepare(&self) -> Result<()> {
        let connection = self.connection()?;

        // Write-ahead logging lets a reader work while a writer holds the
        // database, and the busy timeout makes a second writer wait its turn
        // instead of failing outright.
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(storage("write-ahead logging could not be turned on"))?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(storage("durable writes could not be turned on"))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(10))
            .map_err(storage("the busy timeout could not be set"))?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(storage("foreign keys could not be turned on"))?;

        connection
            .execute_batch(SCHEMA)
            .map_err(storage("the schema could not be created"))?;

        Ok(())
    }
}

impl Store for SqliteStore {
    fn read(&self) -> Result<Option<Snapshot>> {
        let connection = self.connection()?;

        let document: Option<String> = connection
            .query_row(
                "SELECT document FROM config_state WHERE id = ?1",
                [STATE_ROW],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage("the stored config could not be read"))?;

        let Some(document) = document else {
            return Ok(None);
        };

        let config: Config = serde_json::from_str(&document).map_err(|error| {
            Error::new(
                ErrorKind::Serialisation,
                format!("the stored config could not be read back: {error}"),
            )
        })?;

        let mut statement = connection
            .prepare("SELECT id, nonce, ciphertext FROM secret ORDER BY id")
            .map_err(storage("the secret query could not be prepared"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(storage("the stored secrets could not be read"))?;

        let mut secrets = BTreeMap::new();
        for row in rows {
            let (id, nonce, ciphertext) =
                row.map_err(storage("a stored secret could not be read"))?;
            let sealed = Sealed { nonce, ciphertext };
            let plaintext = open(&self.key, id.as_bytes(), &sealed)?;
            secrets.insert(SecretId::new(id), Secret::new(plaintext));
        }

        let authority_pem: Option<String> = connection
            .query_row(
                "SELECT authority_pem FROM cluster_identity WHERE id = ?1",
                [STATE_ROW],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage("the cluster identity could not be read"))?;

        Ok(Some(Snapshot {
            config,
            secrets,
            cluster: authority_pem.map(ClusterIdentity::new),
            joins: read_joins(&connection)?,
            removed: read_removed(&connection)?,
            orders: read_orders(&connection)?,
        }))
    }

    fn write(&self, snapshot: &Snapshot, change: &Change) -> Result<VersionId> {
        self.write_at(snapshot, change, seconds_since_epoch()?)
    }

    fn write_at(&self, snapshot: &Snapshot, change: &Change, now_unix: i64) -> Result<VersionId> {
        self.write_version(snapshot, change, None, now_unix, &[], &[])
    }
}

impl SqliteStore {
    /// Applies one replicated write and records where the log has been
    /// applied to, in one transaction.
    ///
    /// The two have to move together. A node that stops between them either
    /// applies the same record twice or never applies it, and nothing on disk
    /// would say which (ADR-0083).
    ///
    /// # Errors
    ///
    /// Fails when the state cannot be written. A failed apply leaves the
    /// previous state and the previous marker intact.
    pub fn apply_write(
        &self,
        snapshot: &Snapshot,
        change: &Change,
        now_unix: i64,
        markers: &[(&str, &str)],
        audit: &[AuditRecord],
    ) -> Result<VersionId> {
        self.write_version(snapshot, change, None, now_unix, markers, audit)
    }

    fn write_version(
        &self,
        snapshot: &Snapshot,
        change: &Change,
        restored: Option<VersionId>,
        now: i64,
        markers: &[(&str, &str)],
        audit: &[AuditRecord],
    ) -> Result<VersionId> {
        let document = serde_json::to_string(&snapshot.config).map_err(|error| {
            Error::new(
                ErrorKind::Serialisation,
                format!("the config could not be written out: {error}"),
            )
        })?;

        // Seal outside the transaction, so the database is held for as short
        // a time as possible and a sealing failure never leaves a half
        // written state behind.
        let mut sealed = Vec::with_capacity(snapshot.secrets.len());
        for (id, secret) in &snapshot.secrets {
            sealed.push((
                id.as_str().to_owned(),
                seal(&self.key, id.as_str().as_bytes(), secret.expose())?,
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(storage("a transaction could not be started"))?;

        transaction
            .execute("DELETE FROM secret", [])
            .map_err(storage("the previous secrets could not be replaced"))?;
        for (id, record) in &sealed {
            transaction
                .execute(
                    "INSERT INTO secret (id, nonce, ciphertext) VALUES (?1, ?2, ?3)",
                    rusqlite::params![id, record.nonce, record.ciphertext],
                )
                .map_err(storage("a secret could not be written"))?;
        }

        transaction
            .execute(
                "INSERT INTO config_state (id, schema_version, document, updated_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(id) DO UPDATE SET \
                 schema_version = excluded.schema_version, \
                 document = excluded.document, \
                 updated_at = excluded.updated_at",
                rusqlite::params![
                    STATE_ROW,
                    i64::from(snapshot.config.schema_version.get()),
                    document,
                    now
                ],
            )
            .map_err(storage("the config could not be written"))?;

        // Replaced whole, exactly as the secrets above are. The authority
        // certificate and the key that signs with it have to move together: a
        // certificate that survived a write its key did not would be half an
        // authority, which nothing can use and nothing would report.
        transaction
            .execute("DELETE FROM cluster_identity", [])
            .map_err(storage(
                "the previous cluster identity could not be replaced",
            ))?;
        if let Some(cluster) = &snapshot.cluster {
            transaction
                .execute(
                    "INSERT INTO cluster_identity (id, authority_pem) VALUES (?1, ?2)",
                    rusqlite::params![STATE_ROW, cluster.authority_pem],
                )
                .map_err(storage("the cluster identity could not be written"))?;
        }

        // Replaced whole, like everything else in a state. A token that
        // survived a write which removed it would be a token the cluster
        // believes it withdrew (ADR-0084).
        write_joins(&transaction, snapshot)?;
        write_removed(&transaction, snapshot)?;
        write_orders(&transaction, snapshot)?;

        let version = append_version(&transaction, &document, snapshot, change, restored, now)?;
        prune(&transaction, change, now)?;

        // In the same transaction as the state above. A change that landed
        // without its audit row would be a change nobody can account for, which
        // is the one thing this log exists to make impossible (ADR-0008).
        for record in audit {
            transaction
                .execute(
                    "INSERT INTO audit_log (recorded_at, actor, action, subject, detail) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        record.recorded_at_unix,
                        record.actor,
                        record.action,
                        record.subject,
                        record.detail
                    ],
                )
                .map_err(storage(
                    "an audit record could not be written beside the state",
                ))?;
        }

        for (name, value) in markers {
            transaction
                .execute(
                    "INSERT INTO raft_marker (name, value) VALUES (?1, ?2) \
                     ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                    rusqlite::params![name, value],
                )
                .map_err(storage("a marker could not be written beside the state"))?;
        }

        transaction
            .commit()
            .map_err(storage("the transaction could not be committed"))?;

        Ok(version)
    }
}

impl History for SqliteStore {
    fn versions(&self) -> Result<Vec<VersionRecord>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, recorded_at, author, description, schema_version, restored_from \
                 FROM config_version ORDER BY id DESC",
            )
            .map_err(storage("the version query could not be prepared"))?;

        let rows = statement
            .query_map([], |row| {
                let schema: i64 = row.get(4)?;
                let schema = u32::try_from(schema)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, schema))?;
                Ok(VersionRecord {
                    id: VersionId::new(row.get(0)?),
                    recorded_at_unix: row.get(1)?,
                    author: row.get(2)?,
                    description: row.get(3)?,
                    schema_version: SchemaVersion::new(schema),
                    kind: match row.get::<_, Option<i64>>(5)? {
                        None => ChangeKind::Write,
                        Some(restored) => ChangeKind::Rollback {
                            restored: VersionId::new(restored),
                        },
                    },
                })
            })
            .map_err(storage("the version log could not be read"))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(storage("a version record could not be read"))?);
        }
        Ok(records)
    }

    fn version_config(&self, id: VersionId) -> Result<Option<Config>> {
        let connection = self.connection()?;
        let document: Option<String> = connection
            .query_row(
                "SELECT document FROM config_version WHERE id = ?1",
                [id.get()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage("a version could not be read"))?;

        let Some(document) = document else {
            return Ok(None);
        };

        serde_json::from_str(&document).map(Some).map_err(|error| {
            Error::new(
                ErrorKind::Serialisation,
                format!("version {} could not be read back: {error}", id.get()),
            )
        })
    }

    fn roll_back_to(&self, id: VersionId, change: &Change) -> Result<VersionId> {
        let stored = self.version_schema(id)?.ok_or_else(|| {
            Error::new(
                ErrorKind::UnknownVersion,
                format!("version {} is not in the log", id.get()),
            )
        })?;

        if stored != self.target {
            return Err(Error::new(
                ErrorKind::SchemaMismatch,
                format!(
                    "version {} was written against schema {} and this store reads {}",
                    id.get(),
                    stored.get(),
                    self.target.get()
                ),
            ));
        }

        let restored = self.version_config(id)?.ok_or_else(|| {
            Error::new(
                ErrorKind::UnknownVersion,
                format!("version {} is not in the log", id.get()),
            )
        })?;

        let current = self.read()?.ok_or_else(|| {
            Error::new(
                ErrorKind::UnknownVersion,
                "there is no current state to roll back from".to_owned(),
            )
        })?;

        // Certificates and key material keep their current values. Reverting
        // a certificate that ACME renewed in the meantime would break TLS on
        // a node that was serving a moment earlier (ADR-0018).
        let mut config = restored;
        config.certificates = current.config.certificates.clone();

        // The join tokens, the removed nodes and the running orders are
        // carried forward for the same reason the authority is: none of them
        // is in the config document at all. A rollback that resurrected a used
        // token, readmitted a removed node or restarted an order that finished
        // days ago would undo a decision by restoring a configuration
        // (ADR-0084, ADR-0086).
        let snapshot = Snapshot {
            config,
            secrets: current.secrets,
            cluster: current.cluster,
            joins: current.joins,
            removed: current.removed,
            orders: current.orders,
        };
        self.write_version(
            &snapshot,
            change,
            Some(id),
            seconds_since_epoch()?,
            &[],
            &[],
        )
    }

    fn prunings(&self) -> Result<Vec<PruningRecord>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT recorded_at, actor, subject FROM audit_log \
                 WHERE action = ?1 ORDER BY id DESC",
            )
            .map_err(storage("the pruning query could not be prepared"))?;

        let rows = statement
            .query_map([PRUNED_ACTION], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(storage("the pruning records could not be read"))?;

        let mut records = Vec::new();
        for row in rows {
            let (recorded_at_unix, author, subject) =
                row.map_err(storage("a pruning record could not be read"))?;
            let removed = subject
                .as_deref()
                .and_then(|value| value.parse::<i64>().ok())
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Serialisation,
                        "a pruning record names no version".to_owned(),
                    )
                })?;
            records.push(PruningRecord {
                recorded_at_unix,
                author,
                removed: VersionId::new(removed),
            });
        }
        Ok(records)
    }
}

impl SqliteStore {
    fn version_schema(&self, id: VersionId) -> Result<Option<SchemaVersion>> {
        let connection = self.connection()?;
        let stored: Option<i64> = connection
            .query_row(
                "SELECT schema_version FROM config_version WHERE id = ?1",
                [id.get()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage("a version could not be read"))?;
        stored
            .map(|value| {
                u32::try_from(value).map(SchemaVersion::new).map_err(|_| {
                    Error::new(
                        ErrorKind::Serialisation,
                        format!("a stored schema version of {value} cannot be read"),
                    )
                })
            })
            .transpose()
    }
}

fn append_version(
    transaction: &Transaction<'_>,
    document: &str,
    snapshot: &Snapshot,
    change: &Change,
    restored: Option<VersionId>,
    now: i64,
) -> Result<VersionId> {
    transaction
        .execute(
            "INSERT INTO config_version \
             (recorded_at, author, description, schema_version, restored_from, document) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                now,
                change.author,
                change.description,
                i64::from(snapshot.config.schema_version.get()),
                restored.map(VersionId::get),
                document
            ],
        )
        .map_err(storage("the version could not be recorded"))?;

    Ok(VersionId::new(transaction.last_insert_rowid()))
}

/// Keeps the log at its limit and notes what went.
///
/// A silent removal would make an operator's history shorter than they
/// remember with nothing to explain it, so every removal leaves a row.
fn prune(transaction: &Transaction<'_>, change: &Change, now: i64) -> Result<()> {
    let mut statement = transaction
        .prepare("SELECT id FROM config_version ORDER BY id DESC LIMIT -1 OFFSET ?1")
        .map_err(storage("the retention query could not be prepared"))?;

    let rows = statement
        .query_map([i64::try_from(MAX_VERSIONS).unwrap_or(i64::MAX)], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(storage("the versions past the limit could not be listed"))?;

    let mut doomed = Vec::new();
    for row in rows {
        doomed.push(row.map_err(storage("a version past the limit could not be read"))?);
    }
    drop(statement);

    for id in doomed {
        transaction
            .execute("DELETE FROM config_version WHERE id = ?1", [id])
            .map_err(storage("an old version could not be removed"))?;
        transaction
            .execute(
                "INSERT INTO audit_log (recorded_at, actor, action, subject, detail) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    now,
                    change.author,
                    PRUNED_ACTION,
                    id.to_string(),
                    format!("retention limit {MAX_VERSIONS}")
                ],
            )
            .map_err(storage("the removal could not be recorded"))?;
    }

    Ok(())
}

/// Reads one stored document, runs the steps over it and writes it back.
fn migrate_row(
    transaction: &Transaction<'_>,
    select: &str,
    update: &str,
    row: i64,
    steps: &[Migration],
) -> Result<()> {
    let document: Option<String> = transaction
        .query_row(select, [row], |value| value.get(0))
        .optional()
        .map_err(storage("a stored document could not be read"))?;

    let Some(document) = document else {
        return Ok(());
    };

    let mut value: serde_json::Value = serde_json::from_str(&document).map_err(|error| {
        Error::new(
            ErrorKind::Serialisation,
            format!("a stored document could not be read for migration: {error}"),
        )
    })?;

    let reached = migrate_document(&mut value, steps)?;
    let migrated = serde_json::to_string(&value).map_err(|error| {
        Error::new(
            ErrorKind::Serialisation,
            format!("a migrated document could not be written out: {error}"),
        )
    })?;

    transaction
        .execute(
            update,
            rusqlite::params![row, migrated, i64::from(reached.get())],
        )
        .map_err(storage("a migrated document could not be stored"))?;

    Ok(())
}

fn version_ids(transaction: &Transaction<'_>) -> Result<Vec<i64>> {
    let mut statement = transaction
        .prepare("SELECT id FROM config_version ORDER BY id")
        .map_err(storage("the version list could not be prepared"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(storage("the version list could not be read"))?;

    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(storage("a version id could not be read"))?);
    }
    Ok(ids)
}

/// Reads the join tokens the cluster holds.
fn read_joins(connection: &Connection) -> Result<BTreeMap<TokenId, JoinRecord>> {
    let mut statement = connection
        .prepare(
            "SELECT id, secret_digest, expires_at, used_by, issued_by, issued_at \
             FROM join_token ORDER BY id",
        )
        .map_err(storage("the join tokens could not be prepared"))?;

    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(storage("the join tokens could not be read"))?;

    let mut held = BTreeMap::new();
    for row in rows {
        let (id, secret_digest, expires_at, used_by, issued_by, issued_at) =
            row.map_err(storage("a join token could not be read"))?;
        held.insert(
            TokenId::new(id),
            JoinRecord {
                secret_digest,
                expires_at_unix: expires_at,
                used_by: used_by.map(NodeId::new),
                issued_by,
                issued_at_unix: issued_at,
            },
        );
    }
    Ok(held)
}

/// Reads the nodes this cluster has removed.
fn read_removed(connection: &Connection) -> Result<Removed> {
    let mut statement = connection
        .prepare("SELECT node FROM removed_node ORDER BY node")
        .map_err(storage("the removed nodes could not be prepared"))?;

    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage("the removed nodes could not be read"))?;

    let mut held = Removed::new();
    for row in rows {
        held.insert(NodeId::new(
            row.map_err(storage("a removed node could not be read"))?,
        ));
    }
    Ok(held)
}

/// Replaces the join tokens with the ones the state carries.
fn write_joins(transaction: &Transaction<'_>, snapshot: &Snapshot) -> Result<()> {
    transaction
        .execute("DELETE FROM join_token", [])
        .map_err(storage("the previous join tokens could not be replaced"))?;

    for (id, record) in &snapshot.joins {
        transaction
            .execute(
                "INSERT INTO join_token \
                 (id, secret_digest, expires_at, used_by, issued_by, issued_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    id.as_str(),
                    record.secret_digest,
                    record.expires_at_unix,
                    record.used_by.as_ref().map(NodeId::as_str),
                    record.issued_by,
                    record.issued_at_unix
                ],
            )
            .map_err(storage("a join token could not be written"))?;
    }
    Ok(())
}

/// Reads the orders the cluster is running.
///
/// The names and the answers are two columns of JSON rather than two tables.
/// They are only ever read and written whole with the record they belong to,
/// and a table nothing joins against buys nothing.
fn read_orders(connection: &Connection) -> Result<Orders> {
    let mut statement = connection
        .prepare(
            "SELECT certificate, names, challenge, order_url, key_id, answers, driven_by, started_at \
             FROM acme_order ORDER BY certificate",
        )
        .map_err(storage("the running orders could not be prepared"))?;

    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(storage("the running orders could not be read"))?;

    let mut held = Orders::new();
    for row in rows {
        let (certificate, names, challenge, order_url, key_id, answers, driven_by, started_at) =
            row.map_err(storage("a running order could not be read"))?;

        // A challenge nothing recognises is a failure rather than a default.
        // Guessing here would drive an order the wrong way and publish the
        // answer somewhere the certificate authority never looks.
        let challenge = OrderChallenge::from_key(&challenge).ok_or_else(|| {
            Error::new(
                ErrorKind::Serialisation,
                format!("{certificate} names a challenge this build does not know: {challenge}"),
            )
        })?;
        let names: Vec<String> = serde_json::from_str(&names).map_err(|error| {
            Error::new(
                ErrorKind::Serialisation,
                format!("the names of {certificate} could not be read: {error}"),
            )
        })?;
        let answers: BTreeMap<String, String> =
            serde_json::from_str(&answers).map_err(|error| {
                Error::new(
                    ErrorKind::Serialisation,
                    format!("the challenge answers of {certificate} could not be read: {error}"),
                )
            })?;

        held.insert(
            CertificateId::new(certificate),
            OrderRecord {
                names,
                challenge,
                order_url,
                key: SecretId::new(key_id),
                answers,
                driven_by: driven_by.map(NodeId::new),
                started_at_unix: started_at,
            },
        );
    }
    Ok(held)
}

/// Replaces the running orders with the ones the state carries.
fn write_orders(transaction: &Transaction<'_>, snapshot: &Snapshot) -> Result<()> {
    transaction
        .execute("DELETE FROM acme_order", [])
        .map_err(storage("the previous running orders could not be replaced"))?;

    for (id, record) in &snapshot.orders {
        let names = serde_json::to_string(&record.names).map_err(|error| {
            Error::new(
                ErrorKind::Serialisation,
                format!("the names of an order could not be written out: {error}"),
            )
        })?;
        let answers = serde_json::to_string(&record.answers).map_err(|error| {
            Error::new(
                ErrorKind::Serialisation,
                format!("the challenge answers could not be written out: {error}"),
            )
        })?;
        transaction
            .execute(
                "INSERT INTO acme_order \
                 (certificate, names, challenge, order_url, key_id, answers, driven_by, started_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    id.as_str(),
                    names,
                    record.challenge.key(),
                    record.order_url,
                    record.key.as_str(),
                    answers,
                    record.driven_by.as_ref().map(NodeId::as_str),
                    record.started_at_unix
                ],
            )
            .map_err(storage("a running order could not be written"))?;
    }
    Ok(())
}

/// Replaces the removed nodes with the ones the state carries.
fn write_removed(transaction: &Transaction<'_>, snapshot: &Snapshot) -> Result<()> {
    transaction
        .execute("DELETE FROM removed_node", [])
        .map_err(storage("the previous removed nodes could not be replaced"))?;

    for node in &snapshot.removed {
        transaction
            .execute(
                "INSERT INTO removed_node (node) VALUES (?1)",
                [node.as_str()],
            )
            .map_err(storage("a removed node could not be written"))?;
    }
    Ok(())
}

fn storage(what: &'static str) -> impl Fn(rusqlite::Error) -> Error {
    move |error| Error::new(ErrorKind::Storage, format!("{what}: {error}"))
}

fn seconds_since_epoch() -> Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::new(
                ErrorKind::Clock,
                format!("the system clock is set before the Unix epoch: {error}"),
            )
        })?;
    i64::try_from(elapsed.as_secs()).map_err(|error| {
        Error::new(
            ErrorKind::Clock,
            format!("the system clock is beyond what a timestamp can hold: {error}"),
        )
    })
}

impl SqliteStore {
    /// Reads everything a peer would need to become identical to this node.
    ///
    /// Key material comes back in the clear. What travels is protected by the
    /// channel it crosses; what rests is sealed by whichever node stores it,
    /// with its own master key (ADR-0018).
    ///
    /// # Errors
    ///
    /// Fails when any part of the state cannot be read.
    pub fn export(&self) -> Result<FullState> {
        let snapshot = self.read()?;

        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, recorded_at, author, description, schema_version, restored_from, document \
                 FROM config_version ORDER BY id",
            )
            .map_err(storage("the version export could not be prepared"))?;
        let rows = statement
            .query_map([], |row| {
                Ok(StoredVersion {
                    id: VersionId::new(row.get(0)?),
                    recorded_at_unix: row.get(1)?,
                    author: row.get(2)?,
                    description: row.get(3)?,
                    schema_version: {
                        let value: i64 = row.get(4)?;
                        u32::try_from(value)
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, value))?
                    },
                    restored_from: row.get::<_, Option<i64>>(5)?.map(VersionId::new),
                    document: row.get(6)?,
                })
            })
            .map_err(storage("the version log could not be exported"))?;
        let mut versions = Vec::new();
        for row in rows {
            versions.push(row.map_err(storage("a version could not be exported"))?);
        }
        drop(statement);

        let mut statement = connection
            .prepare(
                "SELECT recorded_at, actor, action, subject, detail FROM audit_log ORDER BY id",
            )
            .map_err(storage("the audit export could not be prepared"))?;
        let rows = statement
            .query_map([], |row| {
                Ok(AuditRecord {
                    recorded_at_unix: row.get(0)?,
                    actor: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    detail: row.get(4)?,
                })
            })
            .map_err(storage("the audit log could not be exported"))?;
        let mut audit = Vec::new();
        for row in rows {
            audit.push(row.map_err(storage("an audit record could not be exported"))?);
        }

        Ok(FullState {
            snapshot,
            versions,
            audit,
        })
    }

    /// Replaces everything this node holds with the state given.
    ///
    /// One transaction. A node catching up must never be left holding half of
    /// one peer's state and half of its own.
    ///
    /// # Errors
    ///
    /// Fails when the state cannot be written. A failed import leaves the
    /// previous state intact.
    pub fn import(&self, state: &FullState, markers: &[(&str, &str)]) -> Result<()> {
        let now = seconds_since_epoch()?;

        // Sealed outside the transaction, so a sealing failure never leaves a
        // half written state behind.
        let mut sealed = Vec::new();
        if let Some(held) = &state.snapshot {
            for (id, secret) in &held.secrets {
                sealed.push((
                    id.as_str().to_owned(),
                    seal(&self.key, id.as_str().as_bytes(), secret.expose())?,
                ));
            }
        }

        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(storage("a transaction could not be started"))?;

        // Everything the state describes is cleared first, the config row
        // included. A snapshot carrying no state is a cluster that has written
        // nothing, and a node keeping its old config after receiving one would
        // hold a document with no version history behind it.
        //
        // Written out one statement at a time rather than built from a list of
        // table names. A statement this code assembles is a statement nobody
        // can read off the page, and the rule that keeps SQL injection out of
        // this file is that no SQL is ever assembled here.
        for statement in [
            "DELETE FROM secret",
            "DELETE FROM config_state",
            "DELETE FROM config_version",
            "DELETE FROM audit_log",
            "DELETE FROM cluster_identity",
            "DELETE FROM join_token",
            "DELETE FROM removed_node",
            "DELETE FROM acme_order",
        ] {
            transaction
                .execute(statement, [])
                .map_err(storage("the previous state could not be replaced"))?;
        }

        for (id, record) in &sealed {
            transaction
                .execute(
                    "INSERT INTO secret (id, nonce, ciphertext) VALUES (?1, ?2, ?3)",
                    rusqlite::params![id, record.nonce, record.ciphertext],
                )
                .map_err(storage("a secret could not be written"))?;
        }

        if let Some(held) = &state.snapshot {
            if let Some(cluster) = &held.cluster {
                transaction
                    .execute(
                        "INSERT INTO cluster_identity (id, authority_pem) VALUES (?1, ?2)",
                        rusqlite::params![STATE_ROW, cluster.authority_pem],
                    )
                    .map_err(storage("the cluster identity could not be written"))?;
            }

            // The tokens, the removed nodes and the running orders travel with
            // everything else. A node that caught up without them would
            // readmit a caller its peers refuse, honour a token they consider
            // spent, and answer no challenge for an order in flight
            // (ADR-0084, ADR-0086).
            write_joins(&transaction, held)?;
            write_removed(&transaction, held)?;
            write_orders(&transaction, held)?;

            let document = serde_json::to_string(&held.config).map_err(|error| {
                Error::new(
                    ErrorKind::Serialisation,
                    format!("the config could not be written out: {error}"),
                )
            })?;
            transaction
                .execute(
                    "INSERT INTO config_state (id, schema_version, document, updated_at) \
                     VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT(id) DO UPDATE SET \
                     schema_version = excluded.schema_version, \
                     document = excluded.document, \
                     updated_at = excluded.updated_at",
                    rusqlite::params![
                        STATE_ROW,
                        i64::from(held.config.schema_version.get()),
                        document,
                        now
                    ],
                )
                .map_err(storage("the config could not be written"))?;
        }

        // The identities travel with the rows. A node that renumbered them
        // would hold a version history its peers do not recognise, and an
        // operator rolling back on one node would reach a different config
        // than on another (ADR-0083).
        for version in &state.versions {
            transaction
                .execute(
                    "INSERT INTO config_version \
                     (id, recorded_at, author, description, schema_version, restored_from, document) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        version.id.get(),
                        version.recorded_at_unix,
                        version.author,
                        version.description,
                        i64::from(version.schema_version),
                        version.restored_from.map(VersionId::get),
                        version.document
                    ],
                )
                .map_err(storage("a version could not be written"))?;
        }

        for record in &state.audit {
            transaction
                .execute(
                    "INSERT INTO audit_log (recorded_at, actor, action, subject, detail) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        record.recorded_at_unix,
                        record.actor,
                        record.action,
                        record.subject,
                        record.detail
                    ],
                )
                .map_err(storage("an audit record could not be written"))?;
        }

        for (name, value) in markers {
            transaction
                .execute(
                    "INSERT INTO raft_marker (name, value) VALUES (?1, ?2) \
                     ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                    rusqlite::params![name, value],
                )
                .map_err(storage("a marker could not be written beside the state"))?;
        }

        transaction
            .commit()
            .map_err(storage("the imported state could not be committed"))
    }
}

impl Journal for SqliteStore {
    fn append(&self, records: &[Record]) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction()
            .map_err(storage("a transaction could not be started"))?;
        for record in records {
            transaction
                .execute(
                    "INSERT INTO raft_log (idx, payload) VALUES (?1, ?2) \
                     ON CONFLICT(idx) DO UPDATE SET payload = excluded.payload",
                    rusqlite::params![as_i64(record.index)?, record.payload],
                )
                .map_err(storage("a log record could not be written"))?;
        }
        transaction
            .commit()
            .map_err(storage("the log records could not be committed"))
    }

    fn records(&self, from: u64, to: u64) -> Result<Vec<Record>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT idx, payload FROM raft_log WHERE idx >= ?1 AND idx < ?2 ORDER BY idx")
            .map_err(storage("the log query could not be prepared"))?;
        let rows = statement
            .query_map([as_i64(from)?, as_i64(to)?], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage("the log could not be read"))?;

        let mut records = Vec::new();
        for row in rows {
            let (index, payload) = row.map_err(storage("a log record could not be read"))?;
            records.push(Record {
                index: as_u64(index)?,
                payload,
            });
        }
        Ok(records)
    }

    fn span(&self) -> Result<Option<(u64, u64)>> {
        let connection = self.connection()?;
        let bounds: Option<(Option<i64>, Option<i64>)> = connection
            .query_row("SELECT MIN(idx), MAX(idx) FROM raft_log", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(storage("the log bounds could not be read"))?;

        match bounds {
            Some((Some(first), Some(last))) => Ok(Some((as_u64(first)?, as_u64(last)?))),
            _ => Ok(None),
        }
    }

    fn truncate_from(&self, index: u64) -> Result<()> {
        let connection = self.connection()?;
        connection
            .execute("DELETE FROM raft_log WHERE idx >= ?1", [as_i64(index)?])
            .map_err(storage("the log tail could not be removed"))?;
        Ok(())
    }

    fn purge_upto(&self, index: u64) -> Result<()> {
        let connection = self.connection()?;
        connection
            .execute("DELETE FROM raft_log WHERE idx <= ?1", [as_i64(index)?])
            .map_err(storage("the log head could not be removed"))?;
        Ok(())
    }

    fn set_marker(&self, name: &str, value: Option<&str>) -> Result<()> {
        let connection = self.connection()?;
        match value {
            Some(value) => connection
                .execute(
                    "INSERT INTO raft_marker (name, value) VALUES (?1, ?2) \
                     ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                    rusqlite::params![name, value],
                )
                .map_err(storage("a marker could not be written"))?,
            None => connection
                .execute("DELETE FROM raft_marker WHERE name = ?1", [name])
                .map_err(storage("a marker could not be removed"))?,
        };
        Ok(())
    }

    fn marker(&self, name: &str) -> Result<Option<String>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT value FROM raft_marker WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage("a marker could not be read"))
    }

    fn set_snapshot(&self, meta: &str, data: &[u8]) -> Result<()> {
        let connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO raft_snapshot (id, meta, data) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(id) DO UPDATE SET meta = excluded.meta, data = excluded.data",
                rusqlite::params![STATE_ROW, meta, data],
            )
            .map_err(storage("the snapshot could not be written"))?;
        Ok(())
    }

    fn snapshot(&self) -> Result<Option<(String, Vec<u8>)>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT meta, data FROM raft_snapshot WHERE id = ?1",
                [STATE_ROW],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage("the snapshot could not be read"))
    }
}

fn as_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| {
        Error::new(
            ErrorKind::Storage,
            format!("a log position of {value} is beyond what this store holds"),
        )
    })
}

fn as_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| {
        Error::new(
            ErrorKind::Storage,
            format!("a stored log position of {value} cannot be read"),
        )
    })
}

/// The schema.
///
/// `audit_log` is created here and left empty. M8 fills it, and defining it
/// now means that milestone needs no schema migration.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS config_state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    document       TEXT    NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS config_version (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at      INTEGER NOT NULL,
    author           TEXT    NOT NULL,
    description      TEXT    NOT NULL,
    schema_version   INTEGER NOT NULL,
    restored_from    INTEGER,
    document         TEXT    NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS secret (
    id         TEXT PRIMARY KEY,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS join_token (
    id             TEXT    PRIMARY KEY,
    secret_digest  TEXT    NOT NULL,
    expires_at     INTEGER NOT NULL,
    used_by        TEXT,
    issued_by      TEXT    NOT NULL,
    issued_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS removed_node (
    node TEXT PRIMARY KEY
) STRICT;

CREATE TABLE IF NOT EXISTS acme_order (
    certificate TEXT    PRIMARY KEY,
    names       TEXT    NOT NULL,
    challenge   TEXT    NOT NULL,
    order_url   TEXT,
    key_id      TEXT    NOT NULL,
    answers     TEXT    NOT NULL,
    driven_by   TEXT,
    started_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS cluster_identity (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    authority_pem TEXT    NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at INTEGER NOT NULL,
    actor       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    subject     TEXT,
    detail      TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS raft_log (
    idx     INTEGER PRIMARY KEY,
    payload TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS raft_marker (
    name  TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS raft_snapshot (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    meta TEXT NOT NULL,
    data BLOB NOT NULL
) STRICT;
";
