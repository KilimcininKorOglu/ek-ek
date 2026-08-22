// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the schema migration runner must hold true.
//!
//! Infrastructure with no migration to run cannot be shown to work, so these
//! tests define a second schema of their own. It lives here and never in
//! [`MIGRATIONS`], which one of the tests checks, so nothing fake ships.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use ek_ek_config::{Config, NodeId, NodeRole, SchemaVersion, SecretId, Vip, VipId};
use ek_ek_store::{
    Change, ErrorKind, History, MIGRATIONS, Migration, Secret, Snapshot, SqliteStore, Store,
    document_version, migrate_document, migrate_into_config, target_version,
};
use serde_json::Value;
use tempfile::TempDir;

const SCHEMA_TWO: SchemaVersion = SchemaVersion::new(2);
const PEM_LABEL: &str = "PRIVATE KEY";

fn private_key() -> String {
    format!("-----BEGIN {PEM_LABEL}-----\nMIIEvQIBADANBgkq\n-----END {PEM_LABEL}-----")
}

fn data_directory() -> TempDir {
    tempfile::tempdir().expect("a temporary directory must be available")
}

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config/v1")
        .join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    serde_json::from_str(&text).expect("the fixture must be a JSON document")
}

/// A second schema, invented here so the runner has something to run.
///
/// It widens every VIP prefix and drops the field the current model refuses,
/// which is a shape change the model cannot express and so can only be done
/// on the document.
fn to_schema_two() -> Migration {
    Migration {
        to: SCHEMA_TWO,
        apply: to_schema_two_body,
    }
}

fn to_schema_two_body(document: &mut Value) -> ek_ek_store::Result<()> {
    let object = document.as_object_mut().ok_or_else(unreachable_document)?;
    object.remove("legacy_setting");

    if let Some(vips) = object.get_mut("vips").and_then(Value::as_array_mut) {
        for vip in vips {
            if let Some(vip) = vip.as_object_mut() {
                vip.insert("prefix_length".to_owned(), Value::from(25));
            }
        }
    }
    Ok(())
}

/// A second schema whose step always fails.
fn failing_step() -> Migration {
    Migration {
        to: SCHEMA_TWO,
        apply: |_| {
            Err(ek_ek_store::Error::new(
                ErrorKind::Serialisation,
                "this step fails on purpose".to_owned(),
            ))
        },
    }
}

fn unreachable_document() -> ek_ek_store::Error {
    ek_ek_store::Error::new(
        ErrorKind::Serialisation,
        "a stored document is not an object".to_owned(),
    )
}

fn config_at_v1() -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: vec![ek_ek_config::Node {
            id: NodeId::new("node1"),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)),
            roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
        }],
        vips: vec![Vip {
            id: VipId::new("vip-web"),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            prefix_length: 24,
            interface: "eth0".to_owned(),
            preferred_node: Some(NodeId::new("node1")),
        }],
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        stickiness_key: String::new(),
        log_level: Default::default(),
    }
}

fn snapshot() -> Snapshot {
    Snapshot::new(config_at_v1()).with_secret(
        SecretId::new("key-cert-web"),
        Secret::new(private_key().into_bytes()),
    )
}

fn change(description: &str) -> Change {
    Change::new("admin", description)
}

fn backups(directory: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(directory)
        .expect("the directory must be readable")
        .map(|entry| {
            entry
                .expect("each entry must be readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("backup-schema-"))
        .collect();
    found.sort();
    found
}

#[test]
fn the_schema_version_can_be_read_from_a_stored_record() {
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");

    assert_eq!(
        store.stored_schema_version().expect("readable"),
        None,
        "nothing has been written, so there is no version to read"
    );

    store
        .write(&snapshot(), &change("first"))
        .expect("the write succeeds");

    assert_eq!(
        store.stored_schema_version().expect("readable"),
        Some(SchemaVersion::CURRENT)
    );

    // And from a document, which is where migration reads it.
    assert_eq!(
        document_version(&fixture("basic.json")).expect("readable"),
        SchemaVersion::CURRENT
    );
    assert_eq!(
        document_version(&Value::from(1))
            .expect_err("a document that is not an object carries no version")
            .kind(),
        ErrorKind::Serialisation
    );
}

#[test]
fn a_record_from_a_newer_schema_stops_the_store() {
    let directory = data_directory();
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        let mut ahead = snapshot();
        ahead.config.schema_version = SCHEMA_TWO;
        store
            .write(&ahead, &change("written by a newer build"))
            .expect("the write succeeds");
    }

    let refused = SqliteStore::open(directory.path())
        .expect_err("a build that only reaches schema 1 must not open a schema 2 record");
    assert_eq!(refused.kind(), ErrorKind::SchemaMismatch);
    assert!(
        refused.diagnostic().contains('2'),
        "the log must say which schema it met: {}",
        refused.diagnostic()
    );

    // A build that does reach schema 2 opens the same directory, so the
    // refusal is about the build's reach and not about the record.
    SqliteStore::open_with_migrations(directory.path(), &[to_schema_two()])
        .expect("a build that reaches schema 2 must open it");
}

#[test]
fn an_older_record_is_brought_forward_in_order() {
    let directory = data_directory();
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        store
            .write(&snapshot(), &change("first"))
            .expect("the write succeeds");
    }

    let store = SqliteStore::open_with_migrations(directory.path(), &[to_schema_two()])
        .expect("the store must open and migrate");

    assert_eq!(
        store.stored_schema_version().expect("readable"),
        Some(SCHEMA_TWO),
        "the stored record now carries the new schema"
    );
    let now = store.read().expect("readable").expect("written");
    assert_eq!(
        now.config.vips[0].prefix_length, 25,
        "the step's change must be visible in the config"
    );
    assert_eq!(
        now.config.schema_version, SCHEMA_TWO,
        "the document's own version field moved too"
    );
    assert_eq!(
        now.secrets[&SecretId::new("key-cert-web")].expose(),
        private_key().as_bytes(),
        "key material is untouched by a migration"
    );

    // Opening again must change nothing, because the record is already there.
    drop(store);
    let store = SqliteStore::open_with_migrations(directory.path(), &[to_schema_two()])
        .expect("the store must reopen");
    assert_eq!(store.read().expect("readable").expect("written"), now);
}

#[test]
fn the_version_log_moves_forward_with_the_current_state() {
    let directory = data_directory();
    let first;
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        first = store
            .write(&snapshot(), &change("first"))
            .expect("the write succeeds");
        store
            .write(&snapshot(), &change("second"))
            .expect("the write succeeds");
    }

    let store = SqliteStore::open_with_migrations(directory.path(), &[to_schema_two()])
        .expect("the store must open and migrate");

    for record in store.versions().expect("readable") {
        assert_eq!(
            record.schema_version, SCHEMA_TWO,
            "every version in the log moved with the current state"
        );
    }

    // Which is what keeps rolling back usable after an upgrade. Without this
    // the log would be full of records the schema check refuses.
    store
        .roll_back_to(first, &change("undo after the upgrade"))
        .expect("a migrated version must still be reachable");
    assert_eq!(
        store
            .read()
            .expect("readable")
            .expect("written")
            .config
            .vips[0]
            .prefix_length,
        25
    );
}

#[test]
fn a_backup_is_taken_before_a_migration_runs() {
    let directory = data_directory();
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        store
            .write(&snapshot(), &change("first"))
            .expect("the write succeeds");
        assert!(
            backups(directory.path()).is_empty(),
            "an ordinary write takes no backup"
        );
    }

    let store = SqliteStore::open_with_migrations(directory.path(), &[to_schema_two()])
        .expect("the store must open and migrate");
    drop(store);

    let found = backups(directory.path());
    assert_eq!(found.len(), 1, "one migration, one backup: {found:?}");
    assert!(
        found[0].starts_with("backup-schema-1-"),
        "the name must carry the schema it came from: {}",
        found[0]
    );

    let size = fs::metadata(directory.path().join(&found[0]))
        .expect("the backup must exist")
        .len();
    assert!(size > 0, "the backup must hold something");

    // Opening again migrates nothing, so no second backup appears.
    let store = SqliteStore::open_with_migrations(directory.path(), &[to_schema_two()])
        .expect("the store must reopen");
    drop(store);
    assert_eq!(backups(directory.path()).len(), 1);
}

#[test]
fn a_failed_step_leaves_the_store_as_it_was() {
    let directory = data_directory();
    let before;
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        store
            .write(&snapshot(), &change("first"))
            .expect("the write succeeds");
        before = store.read().expect("readable").expect("written");
    }

    let refused = SqliteStore::open_with_migrations(directory.path(), &[failing_step()])
        .expect_err("a failing step must not produce a store");
    assert_eq!(refused.kind(), ErrorKind::Serialisation);

    let store = SqliteStore::open(directory.path()).expect("the store must still open");
    assert_eq!(
        store.stored_schema_version().expect("readable"),
        Some(SchemaVersion::CURRENT),
        "the schema did not move"
    );
    assert_eq!(
        store.read().expect("readable").expect("written"),
        before,
        "nothing was half applied"
    );
    assert_eq!(
        store.integrity_check().expect("the check must run"),
        "ok",
        "the database is intact"
    );

    // The backup taken before the attempt is still there, which is the point
    // of taking it first.
    assert_eq!(backups(directory.path()).len(), 1);
}

#[test]
fn a_real_v1_document_is_brought_forward() {
    let mut document = fixture("basic.json");
    assert_eq!(
        document_version(&document).expect("readable"),
        SchemaVersion::CURRENT
    );

    let reached = migrate_document(&mut document, &[to_schema_two()]).expect("the step must run");

    assert_eq!(reached, SCHEMA_TWO);
    assert_eq!(document["schema_version"], Value::from(2));
    assert_eq!(document["vips"][0]["prefix_length"], Value::from(25));
    assert_eq!(
        document["vips"][0]["id"],
        Value::from("vip-web"),
        "the step must change only what it means to change"
    );

    // With no steps the same document is left exactly as it is, so the
    // assertions above are about the step and not about being rewritten.
    let mut untouched = fixture("basic.json");
    assert_eq!(
        migrate_document(&mut untouched, &[]).expect("nothing to run"),
        SchemaVersion::CURRENT
    );
    assert_eq!(untouched, fixture("basic.json"));
}

#[test]
fn a_step_runs_on_a_document_the_current_model_cannot_parse() {
    let document = fixture("legacy-extra-field.json");

    // This is the case migration exists for: the stored document does not fit
    // the model, so migrating through the model would be impossible.
    let refused: std::result::Result<Config, _> = serde_json::from_value(document.clone());
    assert!(
        refused.is_err(),
        "the fixture must be one the current model refuses"
    );

    let mut document = document;
    let config = migrate_into_config(&mut document, &[to_schema_two()]).expect("the step must run");

    assert_eq!(config.schema_version, SCHEMA_TWO);
    assert_eq!(config.vips[0].prefix_length, 25);
}

#[test]
fn a_document_beyond_the_steps_is_refused() {
    let mut document = fixture("basic.json");
    document["schema_version"] = Value::from(9);

    assert_eq!(
        migrate_document(&mut document, &[to_schema_two()])
            .expect_err("schema 9 is beyond a build that reaches 2")
            .kind(),
        ErrorKind::SchemaMismatch
    );

    // A document at the target is not refused, it is simply left alone.
    let mut document = fixture("basic.json");
    document["schema_version"] = Value::from(2);
    assert_eq!(
        migrate_document(&mut document, &[to_schema_two()]).expect("nothing to run"),
        SCHEMA_TWO
    );
}

#[test]
fn no_invented_step_ships_in_the_product() {
    assert!(
        MIGRATIONS.is_empty(),
        "schema 1 is the first schema, so there is nothing to step through"
    );
    assert_eq!(
        target_version(MIGRATIONS),
        SchemaVersion::CURRENT,
        "the build reaches exactly the schema it writes"
    );
    assert_eq!(
        target_version(&[to_schema_two()]),
        SCHEMA_TWO,
        "the target follows the steps it is given"
    );
}

#[test]
fn the_fixture_directory_holds_a_document_per_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config");
    let version_one = root.join("v1");

    assert!(version_one.is_dir(), "{} must exist", version_one.display());
    let documents: Vec<String> = fs::read_dir(&version_one)
        .expect("the directory must be readable")
        .map(|entry| {
            entry
                .expect("each entry must be readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".json"))
        .collect();

    assert!(
        !documents.is_empty(),
        "a schema directory with no document proves nothing"
    );
    for name in documents {
        let document = fixture(&name);
        assert_eq!(
            document_version(&document).expect("readable"),
            SchemaVersion::new(1),
            "{name} sits in v1 and must say so"
        );
    }
}

/// Counts how many documents the step below has been handed.
static HANDLED: AtomicUsize = AtomicUsize::new(0);

/// A step that works on the first document and fails on the second.
///
/// The current state is migrated before the version log, so this fails after
/// something has already changed. That is the only way to tell a store that
/// rolls the whole migration back from one that commits it piece by piece.
fn failing_after_the_first_document() -> Migration {
    Migration {
        to: SCHEMA_TWO,
        apply: |document| {
            if HANDLED.fetch_add(1, Ordering::SeqCst) == 0 {
                return to_schema_two_body(document);
            }
            Err(ek_ek_store::Error::new(
                ErrorKind::Serialisation,
                "this step fails on the second document".to_owned(),
            ))
        },
    }
}

#[test]
fn a_step_failing_partway_through_leaves_nothing_half_applied() {
    let directory = data_directory();
    let before;
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        store
            .write(&snapshot(), &change("first"))
            .expect("the write succeeds");
        store
            .write(&snapshot(), &change("second"))
            .expect("the write succeeds");
        before = store.read().expect("readable").expect("written");
    }

    HANDLED.store(0, Ordering::SeqCst);
    let refused =
        SqliteStore::open_with_migrations(directory.path(), &[failing_after_the_first_document()])
            .expect_err("a step that fails partway must not produce a store");
    assert_eq!(refused.kind(), ErrorKind::Serialisation);
    assert!(
        HANDLED.load(Ordering::SeqCst) >= 2,
        "the step must have succeeded once before failing, or this measures nothing"
    );

    // A build that only reaches schema 1 must still be able to open this
    // directory. It cannot if the current state was moved to schema 2 and
    // left there.
    let store = SqliteStore::open(directory.path()).expect("the store must still open");
    assert_eq!(
        store.stored_schema_version().expect("readable"),
        Some(SchemaVersion::CURRENT)
    );
    assert_eq!(store.read().expect("readable").expect("written"), before);
    for record in store.versions().expect("readable") {
        assert_eq!(
            record.schema_version,
            SchemaVersion::CURRENT,
            "the version log did not move either"
        );
    }
}
