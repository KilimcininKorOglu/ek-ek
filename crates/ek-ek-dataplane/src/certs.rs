// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Choosing a certificate while a handshake is running.
//!
//! The certificate is not fixed to the listener: it is picked per handshake
//! from the SNI name the client sent, so an operator can replace a
//! certificate without replacing the process (ADR-0068).
//!
//! Everything here is built once per configuration delivery and read many
//! times. The read side takes no lock, because a handshake that waited on a
//! lock would make every other handshake wait with it.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use ek_ek_config::{CertificateId, Config, TransportProtocol};
use ek_ek_ipc::CertificateMaterial;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;

/// Why one certificate could not be loaded.
///
/// No variant carries the material it was given. An error is written to a log
/// eventually, and key material must never arrive there (ADR-0018).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadFailure {
    /// The configuration references material that was not delivered.
    Missing,
    /// The chain is not readable as PEM.
    ChainUnreadable,
    /// The chain parsed but holds no certificate.
    ChainEmpty,
    /// The key is not readable as PEM.
    KeyUnreadable,
    /// The key does not belong to the leaf certificate.
    KeyDoesNotMatch,
}

impl LoadFailure {
    /// A short reason, safe to write to a log.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Missing => "no material was delivered for it",
            Self::ChainUnreadable => "its chain is not readable as PEM",
            Self::ChainEmpty => "its chain holds no certificate",
            Self::KeyUnreadable => "its key is not readable as PEM",
            Self::KeyDoesNotMatch => "its key does not belong to its leaf certificate",
        }
    }
}

/// One certificate, parsed and ready to be handed to a handshake.
pub struct Loaded {
    /// Which certificate this is, for a report or a log line.
    pub id: String,
    /// The chain, leaf first.
    chain: Vec<X509>,
    /// The private key of the leaf.
    key: PKey<Private>,
}

impl Loaded {
    /// Parses one certificate's material.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the material, naming no part of it.
    pub fn load(id: &str, material: &CertificateMaterial) -> Result<Self, LoadFailure> {
        let chain = X509::stack_from_pem(material.chain_pem.as_bytes())
            .map_err(|_| LoadFailure::ChainUnreadable)?;
        let leaf = chain.first().ok_or(LoadFailure::ChainEmpty)?;

        let key = PKey::private_key_from_pem(material.key_pem.as_bytes())
            .map_err(|_| LoadFailure::KeyUnreadable)?;

        // A mismatched pair produces a handshake that fails on the client and
        // says nothing on the server, so it is refused at load time instead.
        let public = leaf
            .public_key()
            .map_err(|_| LoadFailure::ChainUnreadable)?;
        if !public.public_eq(&key) {
            return Err(LoadFailure::KeyDoesNotMatch);
        }

        Ok(Self {
            id: id.to_owned(),
            chain,
            key,
        })
    }

    /// The leaf certificate, which is what a handshake presents.
    #[must_use]
    pub fn leaf(&self) -> &X509 {
        // `load` refuses an empty chain, so there is always a first entry.
        &self.chain[0]
    }

    /// Everything above the leaf, sent so a client can build the path.
    #[must_use]
    pub fn intermediates(&self) -> &[X509] {
        &self.chain[1..]
    }

    /// The private key of the leaf.
    #[must_use]
    pub const fn key(&self) -> &PKey<Private> {
        &self.key
    }
}

impl fmt::Debug for Loaded {
    /// Prints the identity and nothing else, because the key is in here.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Loaded")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// What one frontend can serve, indexed the way a handshake looks it up.
#[derive(Debug, Default)]
struct Offered {
    /// Names covered exactly, lowercased.
    exact: BTreeMap<String, Arc<Loaded>>,
    /// Wildcard names, keyed by what follows `*.`, lowercased.
    wildcard: BTreeMap<String, Arc<Loaded>>,
    /// Served when nothing matches and when no name was sent (ADR-0070).
    default: Option<Arc<Loaded>>,
}

/// Every frontend's certificates, built once per configuration delivery.
#[derive(Debug, Default)]
pub struct Certificates {
    by_frontend: BTreeMap<String, Offered>,
    /// Certificates a frontend references but could not load, with why.
    ///
    /// Kept rather than dropped, because a certificate that silently failed
    /// to load looks exactly like one nobody configured.
    failures: Vec<(String, LoadFailure)>,
}

impl Certificates {
    /// Loads what every TLS frontend in a configuration references.
    #[must_use]
    pub fn build(config: &Config, material: &BTreeMap<CertificateId, CertificateMaterial>) -> Self {
        let names: BTreeMap<&CertificateId, &Vec<String>> = config
            .certificates
            .iter()
            .map(|certificate| (&certificate.id, &certificate.sni_names))
            .collect();

        let mut by_frontend = BTreeMap::new();
        let mut failures = Vec::new();
        // One certificate can be offered by several frontends, and parsing it
        // once per frontend would repeat the most expensive step here.
        let mut loaded: BTreeMap<&CertificateId, Option<Arc<Loaded>>> = BTreeMap::new();

        for frontend in &config.frontends {
            // TLS on anything but a TCP frontend is refused by validation, so
            // reaching one here would mean an unchecked configuration.
            let Some(tls) = &frontend.tls else { continue };
            if frontend.transport != TransportProtocol::Tcp {
                continue;
            }

            let mut offered = Offered::default();
            for id in &tls.certificates {
                let entry = loaded.entry(id).or_insert_with(|| match material.get(id) {
                    None => {
                        failures.push((id.as_str().to_owned(), LoadFailure::Missing));
                        None
                    }
                    Some(material) => match Loaded::load(id.as_str(), material) {
                        Ok(certificate) => Some(Arc::new(certificate)),
                        Err(failure) => {
                            failures.push((id.as_str().to_owned(), failure));
                            None
                        }
                    },
                });
                let Some(certificate) = entry.clone() else {
                    continue;
                };

                for name in names.get(id).copied().into_iter().flatten() {
                    let name = name.to_lowercase();
                    if let Some(suffix) = name.strip_prefix("*.") {
                        offered
                            .wildcard
                            .insert(suffix.to_owned(), Arc::clone(&certificate));
                    } else {
                        offered.exact.insert(name, Arc::clone(&certificate));
                    }
                }

                if tls.default_certificate.as_ref() == Some(id) {
                    offered.default = Some(certificate);
                }
            }

            by_frontend.insert(frontend.id.as_str().to_owned(), offered);
        }

        Self {
            by_frontend,
            failures,
        }
    }

    /// Picks the certificate a handshake should present.
    ///
    /// The order is exact match, then wildcard, then the frontend's default
    /// (ADR-0070). Nothing else is ever returned, so a client that asked for
    /// a name nobody covers is refused rather than handed somebody else's
    /// certificate.
    #[must_use]
    pub fn choose(&self, frontend: &str, name: Option<&str>) -> Option<&Arc<Loaded>> {
        let offered = self.by_frontend.get(frontend)?;

        let Some(name) = name else {
            // No name was sent, so there is nothing to match against.
            return offered.default.as_ref();
        };

        let name = name.to_lowercase();
        if let Some(certificate) = offered.exact.get(&name) {
            return Some(certificate);
        }
        if let Some(parent) = parent_of(&name)
            && let Some(certificate) = offered.wildcard.get(parent)
        {
            return Some(certificate);
        }
        offered.default.as_ref()
    }

    /// The certificates that could not be loaded, with why.
    #[must_use]
    pub fn failures(&self) -> &[(String, LoadFailure)] {
        &self.failures
    }

    /// How many certificates a frontend can serve.
    #[must_use]
    pub fn count(&self, frontend: &str) -> usize {
        self.by_frontend
            .get(frontend)
            .map_or(0, |offered| offered.exact.len() + offered.wildcard.len())
    }
}

/// What a wildcard would have to cover to match this name.
///
/// A wildcard stands for exactly one label: `*.ornek.com` covers
/// `a.ornek.com` and neither `a.b.ornek.com` nor `ornek.com`. That is the
/// rule clients apply, so it is the rule applied here.
fn parent_of(name: &str) -> Option<&str> {
    name.split_once('.').map(|(_, rest)| rest)
}
