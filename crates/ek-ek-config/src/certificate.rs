// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certificates and the DNS providers ACME uses to prove ownership.
//!
//! No private key, API token or TSIG secret appears here. Key material lives
//! encrypted in the store (ADR-0018) and this model carries a reference to
//! it, so exporting a configuration cannot leak a key.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::id::{CertificateId, DnsProviderId, SecretId};

/// A certificate the product serves or renews.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    /// Identity TLS settings reference.
    pub id: CertificateId,
    /// Names this certificate covers, matched against the handshake's SNI.
    pub sni_names: Vec<String>,
    /// Where the certificate comes from and how it is renewed.
    pub source: CertificateSource,
    /// Validity window, once a certificate has actually been obtained.
    pub validity: Option<CertificateValidity>,
    /// Reference to the stored certificate chain, leaf first.
    ///
    /// The chain is public, so sealing it costs something and buys nothing on
    /// its own. It is stored beside the key anyway, because one path and one
    /// rule are misused less often than two (ADR-0069).
    pub chain: Option<SecretId>,
    /// Reference to the stored private key.
    ///
    /// Unset until the key exists, which is the case for an ACME order that
    /// has been configured but not yet completed.
    pub private_key: Option<SecretId>,
}

/// How a certificate is obtained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CertificateSource {
    /// ACME with the HTTP-01 challenge, answered by the product itself
    /// because it already terminates port 80. Nothing to configure.
    AcmeHttp01,
    /// ACME with the DNS-01 challenge, which is what wildcard certificates
    /// and services with no inbound path from the internet need.
    AcmeDns01 {
        /// Provider that answers the challenge.
        provider: DnsProviderId,
    },
    /// Uploaded by an operator and never renewed automatically.
    ManualUpload,
}

/// The window a certificate is usable in.
///
/// Both values are Unix timestamps in seconds, which keeps the model free of
/// a calendar library and a time zone question.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateValidity {
    /// Start of the window.
    pub not_before_unix: i64,
    /// End of the window, which is what renewal is scheduled against.
    pub not_after_unix: i64,
}

/// A DNS provider ACME can write challenge records to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsProvider {
    /// Identity a certificate source references.
    pub id: DnsProviderId,
    /// Provider type and its connection parameters.
    pub connection: DnsProviderConnection,
}

/// How the product reaches a DNS provider.
///
/// Only two are supported. Every additional provider is a permanent
/// maintenance and verification cost, so the list stays short (ADR-0026).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum DnsProviderConnection {
    /// Dynamic DNS update, which covers BIND and Windows DNS Server.
    Rfc2136 {
        /// Server that accepts the update.
        server: IpAddr,
        /// Port the update is sent to.
        port: u16,
        /// Zone the challenge record is written into.
        zone: String,
        /// Name of the TSIG key the update is signed with.
        tsig_key_name: String,
        /// Algorithm the TSIG signature uses.
        tsig_algorithm: TsigAlgorithm,
        /// Reference to the stored TSIG secret.
        tsig_secret: SecretId,
    },
    /// Cloudflare's API.
    Cloudflare {
        /// Zone the challenge record is written into.
        zone_id: String,
        /// Reference to the stored API token.
        api_token: SecretId,
    },
}

/// Algorithm a TSIG signature uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TsigAlgorithm {
    /// HMAC-SHA256, which Windows DNS Server and BIND both accept.
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
    /// HMAC-SHA512.
    #[serde(rename = "hmac-sha512")]
    HmacSha512,
}
