// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the translation catalogue must hold true.
//!
//! Every rule is measured from both sides. A catalogue that always answers
//! with something looks correct until the answer is the key itself, so each
//! test that shows a lookup working also shows the case where it must not.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ek_ek_config::i18n::EMBEDDED;
use ek_ek_config::validation::{
    ErrorCode, FieldPath, ParameterValue, ValidationError, WarningCode,
};
use ek_ek_config::{Catalog, DialogKeys};

/// The languages that ship. A third one is added by adding a file, so this is
/// what that file has to join, not a list it has to be written into.
const SHIPPED: [&str; 2] = ["en", "tr"];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .to_path_buf()
}

fn catalog() -> Catalog {
    Catalog::embedded().expect("the shipped catalogue must be readable")
}

/// Runs the checker against a locales directory and hands back what it said.
fn check(directory: &Path) -> Output {
    Command::new(repository().join("scripts").join("check-locales.sh"))
        .arg(directory)
        .output()
        .expect("the checker must be runnable")
}

/// Copies the shipped catalogue somewhere a test can damage it.
fn copy_catalogue(into: &Path) {
    for language in SHIPPED {
        let name = format!("{language}.json");
        std::fs::copy(repository().join("locales").join(&name), into.join(&name))
            .expect("the shipped catalogue must be readable");
    }
}

fn document(directory: &Path, language: &str) -> BTreeMap<String, String> {
    let raw = std::fs::read_to_string(directory.join(format!("{language}.json")))
        .expect("the document must be readable");
    serde_json::from_str(&raw).expect("the document must be JSON")
}

fn write_document(directory: &Path, language: &str, document: &BTreeMap<String, String>) {
    let raw = serde_json::to_string_pretty(document).expect("the document must serialise");
    std::fs::write(directory.join(format!("{language}.json")), raw)
        .expect("the document must be writable");
}

fn identifier(value: &str) -> ParameterValue {
    ParameterValue::Identifier(value.to_owned())
}

// --- Criterion: both language files are embedded in the binary -------------

#[test]
fn both_languages_are_embedded_in_the_binary() {
    let embedded: BTreeMap<&str, &str> = EMBEDDED.iter().copied().collect();
    assert_eq!(
        embedded.keys().copied().collect::<Vec<_>>(),
        SHIPPED,
        "every file in locales/ must be compiled in"
    );

    for language in SHIPPED {
        let on_disk = std::fs::read_to_string(
            repository()
                .join("locales")
                .join(format!("{language}.json")),
        )
        .expect("the file must exist");
        assert_eq!(
            embedded[language], on_disk,
            "the compiled in {language} document must be the file itself, \
             or the binary ships a catalogue nobody edited"
        );
    }

    // And the compiled in documents are what the catalogue answers from, so
    // nothing reads the directory at run time.
    let catalog = catalog();
    assert_eq!(catalog.languages(), SHIPPED);
    for language in SHIPPED {
        assert!(
            !catalog
                .keys(language)
                .expect("the language is there")
                .is_empty(),
            "{language} must carry keys"
        );
    }
}

// --- Criterion: keys are identifiers, not English sentences ----------------

#[test]
fn every_key_is_an_identifier_and_not_a_sentence() {
    let catalog = catalog();

    for language in SHIPPED {
        for key in catalog.keys(language).expect("the language is there") {
            assert!(
                !key.contains(' '),
                "'{key}' reads as a sentence; a key must be a stable identifier"
            );
            assert!(
                key.contains('.'),
                "'{key}' has no namespace, so it cannot stay stable as the set grows"
            );
            assert!(
                key.chars().all(|character| character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || character == '.'
                    || character == '_'),
                "'{key}' carries something other than a lowercase identifier"
            );
        }
    }
}

#[test]
fn the_checker_catches_a_key_written_as_a_sentence() {
    let directory = tempfile::tempdir().expect("a temporary directory must be available");
    copy_catalogue(directory.path());
    assert!(check(directory.path()).status.success());

    for language in SHIPPED {
        let mut texts = document(directory.path(), language);
        texts.insert("Backend pool is empty".to_owned(), "whatever".to_owned());
        write_document(directory.path(), language, &texts);
    }

    let refused = check(directory.path());
    assert!(
        !refused.status.success(),
        "a sentence used as a key must fail the check"
    );
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("is not an identifier shaped key"),
        "the failure must name the rule: {}",
        String::from_utf8_lossy(&refused.stdout)
    );
}

// --- Criterion: a parameter lands in the text ------------------------------

#[test]
fn a_parameter_lands_in_the_sentence() {
    let catalog = catalog();
    let parameters = BTreeMap::from([
        ("frontend".to_owned(), identifier("web")),
        ("backend".to_owned(), identifier("app-pool")),
    ]);

    for language in SHIPPED {
        let text = catalog.text_with(language, "config.frontend.unknown_backend", &parameters);
        assert!(text.contains("web"), "{language}: {text}");
        assert!(text.contains("app-pool"), "{language}: {text}");
        assert!(
            !text.contains('{'),
            "{language}: a placeholder survived: {text}"
        );
    }

    // A number is placed as it stands, never grouped. A port read as 8.080
    // is a port nobody can type back into a form.
    let port = BTreeMap::from([("port".to_owned(), ParameterValue::Number(8080))]);
    for language in SHIPPED {
        let text = catalog.text_with(language, "config.port.out_of_range", &port);
        assert!(text.contains("8080"), "{language}: {text}");
    }
}

#[test]
fn a_placeholder_with_no_value_stays_visible() {
    let catalog = catalog();
    // Only one of the two values the sentence needs.
    let half = BTreeMap::from([("frontend".to_owned(), identifier("web"))]);

    for language in SHIPPED {
        let text = catalog.text_with(language, "config.frontend.unknown_backend", &half);
        assert!(text.contains("web"), "{language}: {text}");
        assert!(
            text.contains("{backend}"),
            "{language}: the missing value must be visible, not an empty space: {text}"
        );
    }
}

// --- Criterion: a dialog has all four keys (ADR-0048) ----------------------

#[test]
fn a_dialog_carries_a_title_a_body_and_two_buttons() {
    let catalog = catalog();
    let keys = DialogKeys::of("delete");
    assert_eq!(
        keys.all(),
        [
            "dialog.delete.title",
            "dialog.delete.body",
            "dialog.delete.confirm",
            "dialog.delete.cancel"
        ]
    );

    let parameters = BTreeMap::from([
        ("name".to_owned(), identifier("vip-web")),
        ("effect".to_owned(), identifier("Two frontends lose it.")),
    ]);

    for language in SHIPPED {
        for key in keys.all() {
            assert_ne!(
                catalog.text(language, key),
                key,
                "{language}: '{key}' has no text, so the dialog would show its own key"
            );
        }

        let dialog = catalog.dialog(language, "delete", &parameters);
        assert!(!dialog.title.is_empty());
        assert!(!dialog.confirm.is_empty());
        assert!(!dialog.cancel.is_empty());
        assert_ne!(
            dialog.confirm, dialog.cancel,
            "{language}: the two buttons must not read the same"
        );
        assert!(
            dialog.body.contains("vip-web"),
            "{language}: a destructive dialog must name the object: {}",
            dialog.body
        );
    }
}

#[test]
fn the_checker_catches_a_dialog_missing_one_of_its_four_keys() {
    let directory = tempfile::tempdir().expect("a temporary directory must be available");
    copy_catalogue(directory.path());
    assert!(check(directory.path()).status.success());

    // Removed from both, so this is the incomplete dialog rule failing and
    // not the missing key rule.
    for language in SHIPPED {
        let mut texts = document(directory.path(), language);
        texts.remove("dialog.delete.cancel");
        write_document(directory.path(), language, &texts);
    }

    let refused = check(directory.path());
    assert!(!refused.status.success());
    let said = String::from_utf8_lossy(&refused.stdout);
    assert!(
        said.contains("dialog 'delete': 'cancel' is missing"),
        "the failure must name the missing part: {said}"
    );
}

// --- Criterion: a missing key is never hidden ------------------------------

#[test]
fn a_missing_key_shows_itself() {
    let catalog = catalog();

    assert_eq!(
        catalog.text("tr", "config.frontend.nothing_defines_this"),
        "config.frontend.nothing_defines_this",
        "an undefined key must show itself, not an empty string"
    );

    // A language nobody shipped behaves the same way. Falling back to another
    // language would render text the operator never asked for and hide that
    // the language is absent.
    assert_eq!(
        catalog.text("de", "config.backend.no_members"),
        "config.backend.no_members"
    );

    // And a key that is defined comes back as its text, so the rule above is
    // about the gap and not about every lookup.
    assert_ne!(
        catalog.text("tr", "config.backend.no_members"),
        "config.backend.no_members"
    );
}

// --- Criterion: the checker catches a missing and an extra key -------------

#[test]
fn the_checker_catches_a_missing_key() {
    let directory = tempfile::tempdir().expect("a temporary directory must be available");
    copy_catalogue(directory.path());
    assert!(
        check(directory.path()).status.success(),
        "the shipped catalogue must pass, or the failure below measures nothing"
    );

    let mut english = document(directory.path(), "en");
    english
        .remove("config.backend.no_members")
        .expect("the key must have been there");
    write_document(directory.path(), "en", &english);

    let refused = check(directory.path());
    assert!(!refused.status.success());
    let said = String::from_utf8_lossy(&refused.stdout);
    assert!(
        said.contains("en: 'config.backend.no_members' is missing"),
        "the failure must name the language and the key: {said}"
    );
}

#[test]
fn the_checker_catches_an_extra_key() {
    let directory = tempfile::tempdir().expect("a temporary directory must be available");
    copy_catalogue(directory.path());
    assert!(check(directory.path()).status.success());

    let mut english = document(directory.path(), "en");
    english.insert(
        "config.backend.only_here".to_owned(),
        "Only here.".to_owned(),
    );
    write_document(directory.path(), "en", &english);

    let refused = check(directory.path());
    assert!(!refused.status.success());
    let said = String::from_utf8_lossy(&refused.stdout);
    assert!(
        said.contains("en: 'config.backend.only_here' is not in tr"),
        "the failure must say which language has the extra key: {said}"
    );
}

#[test]
fn the_checker_refuses_a_catalogue_it_cannot_compare() {
    let directory = tempfile::tempdir().expect("a temporary directory must be available");
    std::fs::copy(
        repository().join("locales").join("en.json"),
        directory.path().join("en.json"),
    )
    .expect("the shipped catalogue must be readable");

    // One language on its own always agrees with itself, so a checker that
    // accepted it would report a pass while comparing nothing.
    let refused = check(directory.path());
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("at least 2 are needed"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
}

#[test]
fn the_shipped_catalogue_passes_the_checker() {
    let output = check(&repository().join("locales"));
    assert!(
        output.status.success(),
        "the shipped catalogue must pass: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

// --- Criterion: the checker runs inside make ci ----------------------------

#[test]
fn the_checker_runs_in_make_ci() {
    let makefile =
        std::fs::read_to_string(repository().join("Makefile")).expect("the Makefile must exist");
    let ci = makefile
        .lines()
        .find(|line| line.starts_with("ci:"))
        .expect("there must be a ci target");
    assert!(
        ci.contains("check-locales"),
        "a check outside `make ci` never runs in the pipeline: {ci}"
    );
}

// --- Criterion: numbers and dates follow the language ----------------------

#[test]
fn a_number_is_grouped_the_way_the_language_groups_it() {
    let catalog = catalog();

    assert_eq!(catalog.number("en", 1_234_567), "1,234,567");
    assert_eq!(catalog.number("tr", 1_234_567), "1.234.567");
    assert_ne!(
        catalog.number("en", 1_234_567),
        catalog.number("tr", 1_234_567),
        "the two languages must not group the same way, or nothing is measured"
    );

    // Short numbers take no separator at all, in either language.
    for language in SHIPPED {
        assert_eq!(catalog.number(language, 0), "0");
        assert_eq!(catalog.number(language, 999), "999");
    }
    assert_eq!(catalog.number("en", -1_234), "-1,234");

    // A language with no separator defined must not paste the key between
    // the digits.
    assert_eq!(catalog.number("de", 1_234_567), "1234567");
}

#[test]
fn a_date_follows_the_language_order() {
    let catalog = catalog();
    // 2026-08-21T14:30:00Z
    let moment = 1_787_322_600;

    assert_eq!(catalog.date("en", moment), "2026-08-21");
    assert_eq!(catalog.date("tr", moment), "21.08.2026");
    assert_eq!(catalog.datetime("en", moment), "2026-08-21 14:30");
    assert_eq!(catalog.datetime("tr", moment), "21.08.2026 14:30");

    // The epoch and a moment before it, so the arithmetic is not only right
    // for dates that happen to be recent.
    assert_eq!(catalog.date("en", 0), "1970-01-01");
    assert_eq!(catalog.date("tr", -1), "31.12.1969");
    // A leap day, which a naive day count gets wrong.
    assert_eq!(catalog.date("en", 1_709_164_800), "2024-02-29");
}

// --- Criterion: log messages are not translated ---------------------------

#[test]
fn no_key_is_meant_for_a_log_message() {
    let catalog = catalog();
    for language in SHIPPED {
        for key in catalog.keys(language).expect("the language is there") {
            assert!(
                !key.starts_with("log."),
                "'{key}': logs are machine read and stay in English"
            );
        }
    }
}

#[test]
fn the_checker_catches_a_key_added_for_a_log_message() {
    let directory = tempfile::tempdir().expect("a temporary directory must be available");
    copy_catalogue(directory.path());
    assert!(check(directory.path()).status.success());

    for language in SHIPPED {
        let mut texts = document(directory.path(), language);
        texts.insert("log.startup.listening".to_owned(), "Listening.".to_owned());
        write_document(directory.path(), language, &texts);
    }

    let refused = check(directory.path());
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("log messages are not translated"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
}

// --- Criterion: an error code becomes text in a given language ------------

#[test]
fn every_error_code_has_a_text_in_every_language() {
    let catalog = catalog();

    for code in ErrorCode::ALL {
        for language in SHIPPED {
            let text = catalog.text(language, code.key());
            assert_ne!(
                text,
                code.key(),
                "{language}: the validation layer can produce {} and nothing translates it",
                code.key()
            );
        }
    }
}

#[test]
fn every_warning_code_has_a_text_in_every_language() {
    // The same guarantee as for errors. A warning nobody translated renders
    // as its own key, which reads like a deliberate identifier (ADR-0072).
    let catalog = catalog();

    for code in WarningCode::ALL {
        for language in SHIPPED {
            let text = catalog.text(language, code.key());
            assert_ne!(
                text,
                code.key(),
                "{language}: the validation layer can produce {} and nothing translates it",
                code.key()
            );
        }
    }
}

#[test]
fn an_error_becomes_a_sentence_in_each_language() {
    let catalog = catalog();
    let error = ValidationError {
        code: ErrorCode::FrontendUnknownVip,
        path: FieldPath::root().field("frontends").index(0).field("vip"),
        parameters: BTreeMap::from([
            ("frontend".to_owned(), identifier("web")),
            ("vip".to_owned(), identifier("vip-missing")),
        ]),
    };

    let turkish = catalog.error_text("tr", &error);
    let english = catalog.error_text("en", &error);

    for text in [&turkish, &english] {
        assert!(text.contains("web"), "{text}");
        assert!(text.contains("vip-missing"), "{text}");
        assert!(!text.contains('{'), "a placeholder survived: {text}");
    }
    assert_ne!(
        turkish, english,
        "the same error must read differently in the two languages"
    );

    // A code the catalogue does not cover comes back as the code, so the
    // gap is visible rather than rendered as an empty sentence.
    let unknown = ValidationError {
        code: ErrorCode::FrontendUnknownVip,
        path: FieldPath::root(),
        parameters: BTreeMap::new(),
    };
    assert!(
        catalog.error_text("de", &unknown).starts_with("config."),
        "an untranslated language must show the code"
    );
}
