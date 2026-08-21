// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Translation catalogue and the text infrastructure built on it.
//!
//! The product is multilingual from the first release (ADR-0015). Adding the
//! catalogue after the first user-facing string exists would mean rewriting
//! every place that produces text, so it is here before any of them.
//!
//! # What this knows nothing about
//!
//! There is no HTTP context here, no cookie and no `Accept-Language` header.
//! The language arrives as a parameter. That is what lets the catalogue be
//! written before the API exists, and what keeps the choice of language a
//! presentation decision rather than a property of the text.
//!
//! # Keys are identifiers, not sentences
//!
//! A key is a stable identifier such as `config.frontend.unknown_vip`. Using
//! an English sentence as the key would break every translation the moment
//! the sentence is edited. Validation error codes are keys already
//! ([`ErrorCode::key`]), so the two systems share one namespace instead of
//! keeping a mapping table between them.
//!
//! # A missing key is never hidden
//!
//! Looking up a key nothing defines returns the key itself. An empty string
//! or a fallback language would make the gap invisible in the interface,
//! which is exactly when it survives to a release. `scripts/check-locales.sh`
//! catches the same gap in CI.
//!
//! # Log messages are not translated
//!
//! Nothing here is used for logging. Logs are machine read and stay in
//! English, in one language, whatever the operator's interface is set to.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use crate::validation::{ParameterValue, ValidationError};

include!(concat!(env!("OUT_DIR"), "/locales.rs"));

/// Why a catalogue could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    language: String,
    diagnostic: String,
}

impl Error {
    /// Returns the language whose document could not be read.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// Returns what went wrong, for a log line.
    #[must_use]
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

/// The four keys every dialog is built from (ADR-0048).
///
/// A dialog is refused as a design unless it has all four, because a
/// destructive action needs a title, the object it affects, and two clearly
/// named buttons. A confirmation reading "Are you sure?" is not acceptable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialogKeys {
    /// Key of the dialog heading.
    pub title: String,
    /// Key of the explanatory text.
    pub body: String,
    /// Key of the button that performs the action.
    pub confirm: String,
    /// Key of the button that abandons it.
    pub cancel: String,
}

impl DialogKeys {
    /// Builds the four keys of a named dialog.
    #[must_use]
    pub fn of(name: &str) -> Self {
        Self {
            title: format!("dialog.{name}.title"),
            body: format!("dialog.{name}.body"),
            confirm: format!("dialog.{name}.confirm"),
            cancel: format!("dialog.{name}.cancel"),
        }
    }

    /// Returns the four keys in a fixed order, so a check can walk them.
    #[must_use]
    pub fn all(&self) -> [&str; 4] {
        [&self.title, &self.body, &self.confirm, &self.cancel]
    }
}

/// A dialog with its four texts already translated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dialog {
    /// The heading.
    pub title: String,
    /// The explanatory text.
    pub body: String,
    /// The button that performs the action.
    pub confirm: String,
    /// The button that abandons it.
    pub cancel: String,
}

/// Key of the group separator a language puts between thousands.
const GROUP_SEPARATOR_KEY: &str = "format.number.group_separator";
/// Key of the date pattern.
const DATE_PATTERN_KEY: &str = "format.date.pattern";
/// Key of the date and time pattern.
const DATETIME_PATTERN_KEY: &str = "format.datetime.pattern";

/// Every translation, keyed by language code and then by key.
#[derive(Clone, Debug, Default)]
pub struct Catalog {
    languages: BTreeMap<String, BTreeMap<String, String>>,
}

impl Catalog {
    /// Builds the catalogue from the files embedded at compile time.
    ///
    /// # Errors
    ///
    /// Fails when a document is not a flat JSON object of strings. The
    /// documents are compiled in, so this can only happen when one of them is
    /// edited into an invalid shape.
    pub fn embedded() -> Result<Self, Error> {
        Self::from_documents(EMBEDDED)
    }

    /// Builds a catalogue from documents given directly.
    ///
    /// This is what lets a test measure the rules against a catalogue it
    /// controls, rather than only against the one that ships.
    ///
    /// # Errors
    ///
    /// Fails when a document is not a flat JSON object of strings.
    pub fn from_documents(documents: &[(&str, &str)]) -> Result<Self, Error> {
        let mut languages = BTreeMap::new();
        for (code, document) in documents {
            let parsed: BTreeMap<String, String> =
                serde_json::from_str(document).map_err(|error| Error {
                    language: (*code).to_owned(),
                    diagnostic: format!("the translation document is not readable: {error}"),
                })?;
            languages.insert((*code).to_owned(), parsed);
        }
        Ok(Self { languages })
    }

    /// Returns the language codes the catalogue carries, in order.
    #[must_use]
    pub fn languages(&self) -> Vec<&str> {
        self.languages.keys().map(String::as_str).collect()
    }

    /// Returns every key defined for a language, or `None` when the language
    /// is not in the catalogue.
    #[must_use]
    pub fn keys(&self, language: &str) -> Option<BTreeSet<&str>> {
        self.languages
            .get(language)
            .map(|texts| texts.keys().map(String::as_str).collect())
    }

    /// Looks a key up, returning the key itself when nothing defines it.
    ///
    /// An unknown language behaves the same way. Falling back to another
    /// language would show text the operator did not ask for and hide that
    /// the language is missing entirely.
    #[must_use]
    pub fn text<'a>(&'a self, language: &str, key: &'a str) -> Cow<'a, str> {
        self.languages
            .get(language)
            .and_then(|texts| texts.get(key))
            .map_or(Cow::Borrowed(key), |text| Cow::Borrowed(text.as_str()))
    }

    /// Looks a key up and places the parameters into it.
    ///
    /// A placeholder with no parameter is left as it stands, so the gap is
    /// visible rather than silently rendered as an empty space.
    #[must_use]
    pub fn text_with(
        &self,
        language: &str,
        key: &str,
        parameters: &BTreeMap<String, ParameterValue>,
    ) -> String {
        fill(&self.text(language, key), &placeholders(parameters))
    }

    /// Turns a validation error into a sentence in the given language.
    ///
    /// The error carries a code and structured parameters and no text at all,
    /// which is what makes this possible in any language.
    #[must_use]
    pub fn error_text(&self, language: &str, error: &ValidationError) -> String {
        self.text_with(language, error.code.key(), &error.parameters)
    }

    /// Translates a dialog's four texts at once.
    #[must_use]
    pub fn dialog(
        &self,
        language: &str,
        name: &str,
        parameters: &BTreeMap<String, ParameterValue>,
    ) -> Dialog {
        let keys = DialogKeys::of(name);
        Dialog {
            title: self.text_with(language, &keys.title, parameters),
            body: self.text_with(language, &keys.body, parameters),
            confirm: self.text_with(language, &keys.confirm, parameters),
            cancel: self.text_with(language, &keys.cancel, parameters),
        }
    }

    /// Writes a number the way the language groups its digits.
    ///
    /// This is deliberately separate from parameter placement. A port and a
    /// millisecond count are read as whole numbers, so grouping them would
    /// turn `8080` into something nobody types into a form.
    #[must_use]
    pub fn number(&self, language: &str, value: i64) -> String {
        let separator = self.text(language, GROUP_SEPARATOR_KEY);
        // An absent separator key leaves the key itself as the value, which
        // would be pasted between every group of digits. Group only when the
        // language actually defines one.
        let separator = if separator == GROUP_SEPARATOR_KEY {
            ""
        } else {
            separator.as_ref()
        };

        let negative = value < 0;
        let digits = value.unsigned_abs().to_string();
        let mut grouped = String::with_capacity(digits.len() * 2);
        for (at, digit) in digits.chars().enumerate() {
            if at > 0 && (digits.len() - at).is_multiple_of(3) {
                grouped.push_str(separator);
            }
            grouped.push(digit);
        }
        if negative {
            format!("-{grouped}")
        } else {
            grouped
        }
    }

    /// Writes a Unix timestamp as a date in the language's own order.
    #[must_use]
    pub fn date(&self, language: &str, unix_seconds: i64) -> String {
        self.stamp(language, DATE_PATTERN_KEY, unix_seconds)
    }

    /// Writes a Unix timestamp as a date and a time of day.
    #[must_use]
    pub fn datetime(&self, language: &str, unix_seconds: i64) -> String {
        self.stamp(language, DATETIME_PATTERN_KEY, unix_seconds)
    }

    fn stamp(&self, language: &str, key: &str, unix_seconds: i64) -> String {
        let (year, month, day, hour, minute) = civil(unix_seconds);
        let parts = BTreeMap::from([
            ("year".to_owned(), format!("{year:04}")),
            ("month".to_owned(), format!("{month:02}")),
            ("day".to_owned(), format!("{day:02}")),
            ("hour".to_owned(), format!("{hour:02}")),
            ("minute".to_owned(), format!("{minute:02}")),
        ]);
        fill(&self.text(language, key), &parts)
    }
}

/// Renders parameters as the text that replaces a placeholder.
fn placeholders(parameters: &BTreeMap<String, ParameterValue>) -> BTreeMap<String, String> {
    parameters
        .iter()
        .map(|(name, value)| {
            let text = match value {
                ParameterValue::Identifier(identifier) => identifier.clone(),
                ParameterValue::Number(number) => number.to_string(),
            };
            (name.clone(), text)
        })
        .collect()
}

/// Replaces every `{name}` for which a value exists.
fn fill(template: &str, values: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            // An unclosed brace is text, not a placeholder.
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &after[..close];
        match values.get(name) {
            Some(value) => out.push_str(value),
            // Left as it stands: a value nobody supplied has to be visible.
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }

    out.push_str(rest);
    out
}

/// Splits a Unix timestamp into year, month, day, hour and minute in UTC.
///
/// The arithmetic is the civil-from-days algorithm rather than a date crate,
/// because a whole dependency for one conversion is a dependency the traffic
/// path carries for nothing.
fn civil(unix_seconds: i64) -> (i64, i64, i64, i64, i64) {
    let days = unix_seconds.div_euclid(86_400);
    let time_of_day = unix_seconds.rem_euclid(86_400);

    // Shift the epoch to 0000-03-01 so leap days land at the end of a cycle.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = if month <= 2 { year + 1 } else { year };

    (
        year,
        month,
        day,
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
    )
}
