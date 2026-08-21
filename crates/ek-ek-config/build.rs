// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Embeds every translation file found in `locales/`.
//!
//! The list is discovered rather than written down, because adding a language
//! has to be a matter of adding a file and nothing else (ADR-0015). A hand
//! maintained list would mean a new language compiles, ships, and is simply
//! not there.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")?;
    let locales = Path::new(&manifest).join("..").join("..").join("locales");

    // A file added or removed changes the generated list, so the directory
    // itself has to be watched and not only the files in it.
    println!("cargo:rerun-if-changed={}", locales.display());

    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(&locales)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let Some(code) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        println!("cargo:rerun-if-changed={}", path.display());
        found.push((code.to_owned(), path));
    }
    found.sort();

    let mut generated = String::from(
        "/// Every translation file in `locales/`, as (language code, document).\n\
         pub static EMBEDDED: &[(&str, &str)] = &[\n",
    );
    for (code, path) in &found {
        let path = path.to_str().ok_or("a locale path is not valid UTF-8")?;
        generated.push_str(&format!("    ({code:?}, include_str!({path:?})),\n"));
    }
    generated.push_str("];\n");

    let out = PathBuf::from(std::env::var("OUT_DIR")?).join("locales.rs");
    fs::write(&out, generated)?;
    Ok(())
}
