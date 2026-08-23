// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What an upload leaves on the disk.
//!
//! The rules about reading a certificate are measured in `upload.rs`, away
//! from any file. This is the other half: an upload that was accepted has to
//! reach the store, and the key has to be unreadable in every file the store
//! wrote (ADR-0018).

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::fs;
use std::path::Path;

use common::{authority, joined, leaf, now};
use ek_ek_config::{CertificateId, CertificateSource, Config, LogLevel, SchemaVersion};
use ek_ek_store::{Change, Snapshot, SqliteStore, Store};
use ek_ek_tls::{carry_obtained, chain_id, inspect, install, key_id, remove};

/// A configuration with nothing in it.
fn empty() -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: Vec::new(),
        vips: Vec::new(),
        frontends: Vec::new(),
        backends: Vec::new(),
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        acme: None,
        stickiness_key: String::new(),
        log_level: LogLevel::default(),
        certificate_expiry_warning_days: 30,
    }
}

/// Every byte the store wrote, whatever file it wrote it into.
fn everything_written(directory: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in fs::read_dir(directory).expect("the data directory must be readable") {
        let entry = entry.expect("each entry must be readable");
        if entry.path().is_file() {
            bytes.extend(fs::read(entry.path()).expect("each file must be readable"));
        }
    }
    assert!(!bytes.is_empty(), "the store must have written something");
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn an_uploaded_certificate_is_stored_and_its_key_is_unreadable_on_disk() {
    let ca = authority("ek-ek test CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);
    let chain = joined(&[&server.certificate, &ca.certificate]);
    let key_pem = server.key_pem();

    let upload = inspect(&chain, &key_pem, None, now()).expect("this pair is good");
    let id = CertificateId::new("cert-web");
    let state = install(
        &Snapshot::new(empty()),
        &id,
        CertificateSource::ManualUpload,
        upload,
    );

    let directory = tempfile::tempdir().expect("a temporary directory");
    let store = SqliteStore::open(directory.path()).expect("the store must open");
    store
        .write(&state, &Change::new("admin", "certificate uploaded"))
        .expect("the write must succeed");

    let written = everything_written(directory.path());
    // The whole point of sealing it: a copied disk image and a backup carry
    // no readable key.
    assert!(
        !contains(&written, &key_pem),
        "the private key is on the disk as it was uploaded"
    );
    assert!(
        !contains(&written, b"BEGIN PRIVATE KEY"),
        "even the PEM header is readable"
    );

    // And the other side: what was stored comes back, so sealing it did not
    // lose it.
    let read = store
        .read()
        .expect("the state must read")
        .expect("something was written");
    let held = read
        .secrets
        .get(&key_id(&id))
        .expect("the key is filed under the certificate's name");
    assert!(String::from_utf8_lossy(held.expose()).contains("BEGIN PRIVATE KEY"));
    assert!(read.secrets.contains_key(&chain_id(&id)));

    let record = read
        .config
        .certificates
        .iter()
        .find(|certificate| certificate.id == id)
        .expect("the certificate record is there");
    assert_eq!(record.sni_names, vec!["www.example.org".to_owned()]);
    assert_eq!(record.source, CertificateSource::ManualUpload);
    assert_eq!(record.chain, Some(chain_id(&id)));
    assert_eq!(record.private_key, Some(key_id(&id)));
    assert!(record.validity.is_some());
}

#[test]
fn uploading_a_replacement_leaves_nothing_of_the_one_before_it() {
    let ca = authority("ek-ek test CA");
    let first = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);
    let second = leaf("www.example.org", &["www.example.org"], &ca, 0, 365);
    let id = CertificateId::new("cert-web");

    let one = inspect(&first.chain_pem(), &first.key_pem(), None, now()).expect("it is good");
    let state = install(
        &Snapshot::new(empty()),
        &id,
        CertificateSource::ManualUpload,
        one,
    );
    let held_first = state
        .secrets
        .get(&key_id(&id))
        .expect("the first key")
        .clone();

    let two = inspect(&second.chain_pem(), &second.key_pem(), None, now()).expect("it is good");
    let state = install(&state, &id, CertificateSource::ManualUpload, two);

    assert_eq!(state.config.certificates.len(), 1, "one record, not two");
    assert_eq!(state.secrets.len(), 2, "two pieces of material, not four");
    assert_ne!(
        state.secrets.get(&key_id(&id)),
        Some(&held_first),
        "the old key is still there"
    );
}

#[test]
fn removing_a_certificate_takes_its_material_with_it() {
    let ca = authority("ek-ek test CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);
    let id = CertificateId::new("cert-web");

    let upload = inspect(&server.chain_pem(), &server.key_pem(), None, now()).expect("it is good");
    let state = install(
        &Snapshot::new(empty()),
        &id,
        CertificateSource::ManualUpload,
        upload,
    );
    assert_eq!(state.secrets.len(), 2);

    let after = remove(&state, &id);

    assert!(after.config.certificates.is_empty());
    assert!(
        after.secrets.is_empty(),
        "a private key nothing references is a key kept for no reason: {:?}",
        after.secrets.keys().collect::<Vec<_>>()
    );

    // The other side: removing one certificate leaves another one alone.
    let other = CertificateId::new("cert-mail");
    let upload = inspect(&server.chain_pem(), &server.key_pem(), None, now()).expect("it is good");
    let two = install(&state, &other, CertificateSource::ManualUpload, upload);
    let after = remove(&two, &id);
    assert_eq!(after.config.certificates.len(), 1);
    assert_eq!(after.secrets.len(), 2);
    assert!(after.secrets.contains_key(&key_id(&other)));
}

#[test]
fn the_record_says_where_the_certificate_came_from() {
    let ca = authority("ek-ek test CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);

    // Renewal reads this field: an uploaded certificate is never renewed, and
    // one obtained through ACME is. Filing both the same way would either
    // renew somebody's own certificate over the top or let an ACME one expire.
    for source in [
        CertificateSource::ManualUpload,
        CertificateSource::AcmeHttp01,
    ] {
        let id = CertificateId::new("cert-web");
        let upload =
            inspect(&server.chain_pem(), &server.key_pem(), None, now()).expect("it is good");
        let state = install(&Snapshot::new(empty()), &id, source.clone(), upload);
        assert_eq!(
            state.config.certificates[0].source, source,
            "the record does not say where the certificate came from"
        );
    }
}

#[test]
fn what_an_order_produced_survives_the_document_being_written_over_it() {
    // The document an operator writes cannot carry a validity window: only an
    // order produces one. Replacing the stored configuration with the document
    // without this would leave every certificate looking unobtained, and
    // renewal would order all of them on every run (ADR-0079).
    let ca = authority("ek-ek test CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);
    let id = CertificateId::new("cert-web");
    let upload = inspect(&server.chain_pem(), &server.key_pem(), None, now()).expect("it is good");
    let stored = install(
        &Snapshot::new(empty()),
        &id,
        CertificateSource::AcmeHttp01,
        upload,
    );

    // What an operator has on disk: the same certificate, nothing obtained.
    let mut document = empty();
    document.certificates = vec![ek_ek_config::Certificate {
        id: id.clone(),
        sni_names: vec!["www.example.org".to_owned()],
        source: CertificateSource::AcmeHttp01,
        validity: None,
        chain: None,
        private_key: None,
    }];

    let merged = carry_obtained(&document, &stored.config);

    assert_eq!(
        merged.certificates[0].validity, stored.config.certificates[0].validity,
        "the window the order produced was thrown away"
    );
    assert_eq!(merged.certificates[0].chain, Some(chain_id(&id)));
    assert_eq!(merged.certificates[0].private_key, Some(key_id(&id)));
}

#[test]
fn the_document_still_decides_what_exists_and_how_it_is_obtained() {
    // The other side. Carrying everything forward would make the document
    // unable to change a certificate at all.
    let ca = authority("ek-ek test CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);
    let id = CertificateId::new("cert-web");
    let upload = inspect(&server.chain_pem(), &server.key_pem(), None, now()).expect("it is good");
    let stored = install(
        &Snapshot::new(empty()),
        &id,
        CertificateSource::AcmeHttp01,
        upload,
    );

    let mut document = empty();
    document.certificates = vec![ek_ek_config::Certificate {
        id: id.clone(),
        sni_names: vec!["posta.example.org".to_owned()],
        source: CertificateSource::ManualUpload,
        validity: None,
        chain: None,
        private_key: None,
    }];

    let merged = carry_obtained(&document, &stored.config);

    assert_eq!(
        merged.certificates[0].source,
        CertificateSource::ManualUpload
    );
    assert_eq!(merged.certificates[0].sni_names, vec!["posta.example.org"]);
}

#[test]
fn a_stored_certificate_under_another_name_is_not_carried_across() {
    // The match is by identity. Taking the first stored record whatever it is
    // would file one certificate's window against another one's name.
    let ca = authority("ek-ek test CA");
    let server = leaf("www.example.org", &["www.example.org"], &ca, 0, 90);
    let upload = inspect(&server.chain_pem(), &server.key_pem(), None, now()).expect("it is good");
    let stored = install(
        &Snapshot::new(empty()),
        &CertificateId::new("cert-other"),
        CertificateSource::AcmeHttp01,
        upload,
    );

    let mut document = empty();
    document.certificates = vec![ek_ek_config::Certificate {
        id: CertificateId::new("cert-web"),
        sni_names: vec!["www.example.org".to_owned()],
        source: CertificateSource::AcmeHttp01,
        validity: None,
        chain: None,
        private_key: None,
    }];

    let merged = carry_obtained(&document, &stored.config);

    assert_eq!(merged.certificates[0].validity, None);
    assert_eq!(merged.certificates[0].chain, None);
}

#[test]
fn a_certificate_the_store_never_held_is_left_as_the_document_wrote_it() {
    let mut document = empty();
    document.certificates = vec![ek_ek_config::Certificate {
        id: CertificateId::new("cert-new"),
        sni_names: vec!["yeni.example.org".to_owned()],
        source: CertificateSource::AcmeHttp01,
        validity: None,
        chain: None,
        private_key: None,
    }];

    let merged = carry_obtained(&document, &empty());

    assert_eq!(merged.certificates[0].validity, None);
    assert_eq!(merged.certificates[0].chain, None);
}
