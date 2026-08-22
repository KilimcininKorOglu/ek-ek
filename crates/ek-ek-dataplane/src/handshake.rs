// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Handing a certificate to a handshake that is already running.
//!
//! pingora calls this back in the middle of the TLS handshake, once the
//! client's SNI name is known and before the server picks what to present.
//! The certificate is chosen there rather than fixed to the listener, which
//! is what lets a certificate change without the process changing (ADR-0068).

use std::sync::Arc;

use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::ext;
use pingora::tls::ssl::NameType;

use crate::certs::Loaded;
use crate::live::{LiveConfig, Status};

/// Chooses one frontend's certificate for each handshake it is asked about.
pub struct SniResolver {
    /// Which frontend this listener serves.
    frontend: String,
    /// Where the certificate set is read from on every handshake.
    live: Arc<LiveConfig>,
    /// Where a refused handshake is counted.
    status: Arc<Status>,
}

impl SniResolver {
    /// Builds a resolver for one frontend.
    #[must_use]
    pub const fn new(frontend: String, live: Arc<LiveConfig>, status: Arc<Status>) -> Self {
        Self {
            frontend,
            live,
            status,
        }
    }
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // A client that sent no SNI extension leaves this unset, which is a
        // case of its own rather than a name that matched nothing (ADR-0070).
        let asked_for = ssl.servername(NameType::HOST_NAME).map(str::to_owned);

        // Read once. Reading twice would let a delivery land in between and
        // present a leaf from one certificate with a chain from another.
        let live = self.live.load();
        let Some(certificate) = live
            .certificates
            .choose(&self.frontend, asked_for.as_deref())
        else {
            // Nothing is set on the handshake, so OpenSSL has no certificate
            // to present and refuses the connection. Counted rather than
            // dropped quietly: a refusal nobody can see is an outage nobody
            // can explain.
            self.status.tls_handshake_refused();
            return;
        };

        if present(certificate, ssl).is_none() {
            self.status.tls_handshake_refused();
        }
    }
}

/// Puts a certificate, its chain and its key onto a running handshake.
///
/// Returns nothing when the TLS library refused any part of it, which leaves
/// the handshake without a certificate and therefore refused.
fn present(certificate: &Loaded, ssl: &mut TlsRef) -> Option<()> {
    ext::ssl_use_certificate(ssl, certificate.leaf()).ok()?;
    ext::ssl_use_private_key(ssl, certificate.key()).ok()?;
    // Sent so a client can build the path to a root it trusts. A leaf on its
    // own verifies only where the intermediate is already installed.
    for intermediate in certificate.intermediates() {
        ext::ssl_add_chain_cert(ssl, intermediate).ok()?;
    }
    Some(())
}
