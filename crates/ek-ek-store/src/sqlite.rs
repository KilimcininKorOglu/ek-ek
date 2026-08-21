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

use ek_ek_config::{Config, SchemaVersion, SecretId};
use rusqlite::{Connection, OptionalExtension, Transaction};

use crate::crypto::{Sealed, open, seal};
use crate::error::{Error, ErrorKind, Result};
use crate::master_key::{MASTER_KEY_FILE, MasterKey};
use crate::migration::{MIGRATIONS, Migration, migrate_document, target_version};
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

        Ok(Some(Snapshot { config, secrets }))
    }

    fn write(&self, snapshot: &Snapshot, change: &Change) -> Result<VersionId> {
        self.write_version(snapshot, change, None)
    }
}

impl SqliteStore {
    fn write_version(
        &self,
        snapshot: &Snapshot,
        change: &Change,
        restored: Option<VersionId>,
    ) -> Result<VersionId> {
        let document = serde_json::to_string(&snapshot.config).map_err(|error| {
            Error::new(
                ErrorKind::Serialisation,
                format!("the config could not be written out: {error}"),
            )
        })?;
        let now = seconds_since_epoch()?;

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

        let version = append_version(&transaction, &document, snapshot, change, restored, now)?;
        prune(&transaction, change, now)?;

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

        let snapshot = Snapshot {
            config,
            secrets: current.secrets,
        };
        self.write_version(&snapshot, change, Some(id))
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

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at INTEGER NOT NULL,
    actor       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    subject     TEXT,
    detail      TEXT
) STRICT;
";
