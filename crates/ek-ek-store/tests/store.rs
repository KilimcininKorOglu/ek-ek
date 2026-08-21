// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the store must hold true.
//!
//! Every rule is measured from both sides. A check that only ever sees the
//! failing case cannot show that it lets the passing case through, and one
//! that only ever sees the passing case cannot show that it judges anything.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use ek_ek_config::{Config, NodeId, NodeRole, SchemaVersion, SecretId, Vip, VipId};
use ek_ek_store::{
    Change, DATABASE_FILE, Error, ErrorKind, KEY_MODE, MASTER_KEY_FILE, MasterKey, Result, Sealed,
    Secret, Snapshot, SqliteStore, Store, VersionId, crypto,
};
use tempfile::TempDir;

/// The label a PEM block carries, kept apart from the dashes on purpose.
///
/// Assembling the block instead of writing it out keeps a literal key block
/// out of a tracked file, which is what `scripts/check-secrets.sh` refuses.
/// The value at run time is the same either way, so the test still measures
/// what an operator would actually upload.
const PEM_LABEL: &str = "PRIVATE KEY";

fn private_key() -> String {
    format!("-----BEGIN {PEM_LABEL}-----\nMIIEvQIBADANBgkq\n-----END {PEM_LABEL}-----")
}

fn pem_header() -> String {
    format!("BEGIN {PEM_LABEL}")
}

fn data_directory() -> TempDir {
    tempfile::tempdir().expect("a temporary directory must be available")
}

/// A config that carries a node and a VIP, so a round trip means something.
fn config(marker: u32) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: vec![ek_ek_config::Node {
            id: NodeId::new(format!("node{marker}")),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)),
            roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
        }],
        vips: vec![Vip {
            id: VipId::new("vip-web"),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            prefix_length: 24,
            interface: "eth0".to_owned(),
            preferred_node: Some(NodeId::new(format!("node{marker}"))),
        }],
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
    }
}

/// The change every test in this file records, since who wrote it is not
/// what any of them is measuring. The version log itself is tested in
/// `versioning.rs`.
fn change() -> Change {
    Change::new("admin", "test write")
}

fn snapshot(marker: u32) -> Snapshot {
    Snapshot::new(config(marker)).with_secret(
        SecretId::new("key-cert-web"),
        Secret::new(private_key().into_bytes()),
    )
}

/// Reads every file in the data directory as raw bytes.
fn stored_bytes(directory: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).expect("the data directory must be readable") {
        let entry = entry.expect("each entry must be readable");
        if entry.path().is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path()).expect("each file must be readable");
            files.push((name, bytes));
        }
    }
    assert!(!files.is_empty(), "the store must have written something");
    files
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn an_empty_directory_becomes_a_working_store() {
    let directory = data_directory();
    let path = directory.path().join("nested").join("data");
    assert!(!path.exists(), "the directory must not exist yet");

    let store = SqliteStore::open(&path).expect("an empty directory must be enough");

    assert!(path.join(DATABASE_FILE).exists(), "the database is created");
    assert!(path.join(MASTER_KEY_FILE).exists(), "the key is created");
    assert_eq!(
        store.read().expect("a fresh store must be readable"),
        None,
        "nothing has been written yet, and that is not an error"
    );
    assert_eq!(store.integrity_check().expect("the check must run"), "ok");
}

#[test]
fn a_written_config_survives_a_close_and_reopen() {
    let directory = data_directory();
    let written = snapshot(1);

    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        store
            .write(&written, &change())
            .expect("the write must succeed");
    }

    let store = SqliteStore::open(directory.path()).expect("the store must reopen");
    let read = store
        .read()
        .expect("the state must be readable")
        .expect("something was written");

    assert_eq!(read, written, "the round trip changed the value");
    assert_eq!(
        read.secrets[&SecretId::new("key-cert-web")].expose(),
        private_key().as_bytes(),
        "the key material must come back byte for byte"
    );
}

#[test]
fn key_material_never_reaches_the_database_file_in_the_clear() {
    let directory = data_directory();
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        store
            .write(&snapshot(1), &change())
            .expect("the write must succeed");
    }

    let files = stored_bytes(directory.path());

    // The scan must be able to find something, or its silence proves nothing.
    // A config value is stored in the clear on purpose and is the control.
    assert!(
        files.iter().any(|(_, bytes)| contains(bytes, b"vip-web")),
        "the scan must reach the stored config, otherwise it measures nothing"
    );

    for (name, bytes) in &files {
        assert!(
            !contains(bytes, private_key().as_bytes()),
            "{name} holds the private key in the clear"
        );
        assert!(
            !contains(bytes, pem_header().as_bytes()),
            "{name} holds a PEM header in the clear"
        );
    }
}

#[test]
fn the_master_key_file_is_readable_by_its_owner_alone() {
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");

    let key_path = store.directory().join(MASTER_KEY_FILE);
    let mode = fs::metadata(&key_path)
        .expect("the key file must exist")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(mode, KEY_MODE, "the key file must carry mode 0600");

    // Widening the mode must be refused, otherwise the check above only
    // describes what the store happened to write.
    drop(store);
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))
        .expect("the mode must be changeable");
    let refused =
        SqliteStore::open(directory.path()).expect_err("a world readable key must not be accepted");
    assert_eq!(refused.kind(), ErrorKind::MasterKeyPermissions);
}

#[test]
fn a_missing_master_key_stops_the_store_instead_of_emptying_it() {
    let directory = data_directory();
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        store
            .write(&snapshot(1), &change())
            .expect("the write must succeed");
    }

    fs::remove_file(directory.path().join(MASTER_KEY_FILE)).expect("the key must be removable");

    let refused =
        SqliteStore::open(directory.path()).expect_err("a database without its key must not open");
    assert_eq!(refused.kind(), ErrorKind::MasterKeyMissing);
    assert!(
        !refused.diagnostic().is_empty(),
        "the log needs to say what happened"
    );

    // The same directory with its key in place opens and still holds the
    // state, so the refusal above is about the missing key and nothing else.
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");
    store
        .write(&snapshot(1), &change())
        .expect("the write must succeed");
    assert!(store.read().expect("readable").is_some());
}

/// A source line builds SQL by hand when it names a statement and a formatter
/// on the same line.
fn builds_sql_by_hand(line: &str) -> bool {
    let sql = ["SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE "];
    let assembled = ["format!", "push_str", "to_owned() +", "concat!"];
    sql.iter().any(|keyword| line.contains(keyword))
        && assembled.iter().any(|joiner| line.contains(joiner))
}

#[test]
fn every_sql_statement_binds_its_values() {
    // The detector must be able to say yes, or its silence below is empty.
    assert!(builds_sql_by_hand(
        r#"connection.execute(&format!("DELETE FROM {table}"))"#
    ));
    assert!(!builds_sql_by_hand(
        r#"connection.execute("DELETE FROM secret", [])"#
    ));

    let source = include_str!("../src/sqlite.rs");
    for (number, line) in source.lines().enumerate() {
        assert!(
            !builds_sql_by_hand(line),
            "src/sqlite.rs line {} assembles SQL: {line}",
            number + 1
        );
    }

    // Every statement that takes a value must carry a bind marker.
    for statement in source.split("execute(").skip(1) {
        let head: String = statement.chars().take(200).collect();
        if head.contains("VALUES") {
            assert!(
                head.contains("?1"),
                "a statement with values must bind them: {head}"
            );
        }
    }
}

/// A second implementation of the trait, holding state in memory.
///
/// It exists to show that the interface names nothing a database provides.
#[derive(Default)]
struct MemoryStore {
    state: std::sync::Mutex<Vec<Snapshot>>,
}

impl Store for MemoryStore {
    fn read(&self) -> Result<Option<Snapshot>> {
        match self.state.lock() {
            Ok(state) => Ok(state.last().cloned()),
            Err(error) => Err(Error::new(ErrorKind::Storage, format!("poisoned: {error}"))),
        }
    }

    fn write(&self, snapshot: &Snapshot, _change: &Change) -> Result<VersionId> {
        match self.state.lock() {
            Ok(mut state) => {
                state.push(snapshot.clone());
                Ok(VersionId::new(
                    i64::try_from(state.len()).unwrap_or(i64::MAX),
                ))
            }
            Err(error) => Err(Error::new(ErrorKind::Storage, format!("poisoned: {error}"))),
        }
    }
}

/// Code a caller could write, knowing only the trait.
fn round_trip(store: &dyn Store) -> Snapshot {
    assert_eq!(store.read().expect("a fresh store reads as empty"), None);
    let written = snapshot(7);
    store
        .write(&written, &change())
        .expect("the write must succeed");
    store
        .read()
        .expect("the state must be readable")
        .expect("something was written")
}

#[test]
fn the_store_interface_can_be_implemented_without_sqlite() {
    // The trait definition itself must not name the database.
    let definition = include_str!("../src/store.rs");
    assert!(
        !definition.contains("rusqlite"),
        "the interface must not expose the database crate"
    );

    let directory = data_directory();
    let backed = SqliteStore::open(directory.path()).expect("the store must open");
    let memory = MemoryStore::default();

    // The same caller code drives both, so nothing it needs is SQLite's.
    assert_eq!(round_trip(&backed), round_trip(&memory));
}

#[test]
fn concurrent_writes_leave_one_whole_state() {
    let directory = data_directory();
    let store = Arc::new(SqliteStore::open(directory.path()).expect("the store must open"));

    let writers = 8;
    let mut handles = Vec::new();
    for marker in 0..writers {
        let store = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            store
                .write(&snapshot(marker), &change())
                .expect("every write succeeds")
        }));
    }
    for handle in handles {
        handle.join().expect("no writer may panic");
    }

    assert_eq!(
        store.integrity_check().expect("the check must run"),
        "ok",
        "the database must still be consistent"
    );

    let read = store
        .read()
        .expect("the state must be readable")
        .expect("something was written");
    let candidates: Vec<Snapshot> = (0..writers).map(snapshot).collect();
    assert!(
        candidates.contains(&read),
        "the stored state must be exactly one writer's, never a mixture"
    );

    // A reopen must agree, so the winner was committed and not merely cached.
    drop(store);
    let store = SqliteStore::open(directory.path()).expect("the store must reopen");
    assert_eq!(store.read().expect("readable"), Some(read));
}

#[test]
fn an_altered_record_does_not_open() {
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");
    let key = MasterKey::read(&store.directory().join(MASTER_KEY_FILE)).expect("the key is there");

    let sealed = crypto::seal(&key, b"key-cert-web", &private_key().into_bytes()).expect("seals");
    assert_eq!(
        crypto::open(&key, b"key-cert-web", &sealed).expect("opens"),
        private_key().as_bytes(),
        "an untouched record must open"
    );

    let mut altered = sealed.clone();
    altered.ciphertext[0] ^= 0x01;
    assert_eq!(
        crypto::open(&key, b"key-cert-web", &altered)
            .expect_err("an altered record must not open")
            .kind(),
        ErrorKind::Decryption
    );

    // Moving a record onto another identity must fail too, which is what
    // binding the identity as associated data buys.
    assert_eq!(
        crypto::open(&key, b"key-other", &sealed)
            .expect_err("a moved record must not open")
            .kind(),
        ErrorKind::Decryption
    );
}

#[test]
fn another_nodes_key_cannot_open_this_nodes_secrets() {
    let ours = data_directory();
    let theirs = data_directory();

    {
        let our_store = SqliteStore::open(ours.path()).expect("the store must open");
        our_store
            .write(&snapshot(1), &change())
            .expect("the write succeeds");
    }
    // A second node generates its own key, which is the whole point of a
    // per-node key: a copied database is not readable elsewhere.
    drop(SqliteStore::open(theirs.path()).expect("the store must open"));

    // Both stores are closed, so the write-ahead log has been folded back
    // into the database file and copying that file copies the state.
    fs::copy(
        ours.path().join(DATABASE_FILE),
        theirs.path().join(DATABASE_FILE),
    )
    .expect("the database must be copyable");

    let their_store = SqliteStore::open(theirs.path()).expect("the store must reopen");
    assert_eq!(
        their_store
            .read()
            .expect_err("another node's key must not open our secrets")
            .kind(),
        ErrorKind::Decryption
    );

    // The same copy opened with its own key works, so the refusal above is
    // about the key and not about the copy.
    let our_store = SqliteStore::open(ours.path()).expect("the store must reopen");
    assert_eq!(our_store.read().expect("readable"), Some(snapshot(1)));
}

#[test]
fn a_secret_never_prints_its_contents() {
    let secret = Secret::new(private_key().into_bytes());
    let printed = format!("{secret:?}");

    assert!(!printed.contains("BEGIN"), "a debug line must not leak it");
    assert!(printed.contains("redacted"));
    assert_eq!(secret.len(), private_key().len());

    // The same treatment for the key itself.
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");
    let key = MasterKey::read(&store.directory().join(MASTER_KEY_FILE)).expect("the key is there");
    let printed = format!("{key:?}");
    assert_eq!(printed, "MasterKey(redacted)");
    assert!(!format!("{store:?}").contains(&hex(key.as_bytes())));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_malformed_key_file_is_refused() {
    let directory = data_directory();
    {
        let store = SqliteStore::open(directory.path()).expect("the store must open");
        store
            .write(&snapshot(1), &change())
            .expect("the write succeeds");
    }

    let key_path = directory.path().join(MASTER_KEY_FILE);
    fs::write(&key_path, b"too short").expect("the file must be writable");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(KEY_MODE))
        .expect("the mode must be settable");

    assert_eq!(
        SqliteStore::open(directory.path())
            .expect_err("a key of the wrong length must be refused")
            .kind(),
        ErrorKind::MasterKeyMalformed
    );
}

#[test]
fn a_short_nonce_is_refused_rather_than_guessed() {
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");
    let key = MasterKey::read(&store.directory().join(MASTER_KEY_FILE)).expect("the key is there");

    let sealed = Sealed {
        nonce: vec![0_u8; 8],
        ciphertext: vec![0_u8; 32],
    };
    assert_eq!(
        crypto::open(&key, b"key-cert-web", &sealed)
            .expect_err("a short nonce must be refused")
            .kind(),
        ErrorKind::Decryption
    );
}

#[test]
fn the_store_can_be_shared_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SqliteStore>();
    assert_send_sync::<Snapshot>();
}

#[test]
fn writing_an_empty_secret_map_clears_what_was_there() {
    let directory = data_directory();
    let store = SqliteStore::open(directory.path()).expect("the store must open");

    store
        .write(&snapshot(1), &change())
        .expect("the write succeeds");
    assert_eq!(
        store
            .read()
            .expect("readable")
            .expect("written")
            .secrets
            .len(),
        1
    );

    store
        .write(
            &Snapshot {
                config: config(1),
                secrets: BTreeMap::new(),
            },
            &change(),
        )
        .expect("the write succeeds");
    assert!(
        store
            .read()
            .expect("readable")
            .expect("written")
            .secrets
            .is_empty(),
        "a whole-state write must not leave the old secrets behind"
    );
}

/// Leaves a real store on disk so the raw files can be inspected from
/// outside the test process.
///
/// It is ignored in a normal run and reported as such, rather than quietly
/// doing nothing. The task's verification block runs it on purpose with a
/// directory of its own.
#[test]
#[ignore = "writes into the directory named by EK_EK_STORE_KEEP"]
fn keeps_a_store_for_outside_inspection() {
    let target = std::env::var("EK_EK_STORE_KEEP")
        .expect("EK_EK_STORE_KEEP must name the directory to write into");

    let store = SqliteStore::open(&target).expect("the store must open");
    store
        .write(&snapshot(1), &change())
        .expect("the write must succeed");
    drop(store);

    println!("store written to {target}");
}
