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

use ek_ek_config::{Config, SecretId};
use rusqlite::{Connection, OptionalExtension};

use crate::crypto::{Sealed, open, seal};
use crate::error::{Error, ErrorKind, Result};
use crate::master_key::{MASTER_KEY_FILE, MasterKey};
use crate::secret::Secret;
use crate::store::{Snapshot, Store};

/// Where a node keeps its data in a real installation (ADR-0010).
pub const DEFAULT_DATA_DIRECTORY: &str = "/var/lib/ek-ek";

/// Name of the database inside the data directory.
pub const DATABASE_FILE: &str = "config.db";

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
        };
        store.prepare()?;
        Ok(store)
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

    fn write(&self, snapshot: &Snapshot) -> Result<()> {
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

        transaction
            .commit()
            .map_err(storage("the transaction could not be committed"))?;

        Ok(())
    }
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
