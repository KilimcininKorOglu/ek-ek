// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a monitoring system reads about the certificates.
//!
//! A small team that already runs Prometheus should get the expiry warning
//! from there rather than from a second place they have to remember to look at
//! (ADR-0038). This builds the lines; the endpoint that serves them, the
//! management interface it binds to and the cardinality limit are T-058's
//! (ADR-0079).
//!
//! # What is never a label
//!
//! Anything an operator did not name. A label built from something a client
//! sends is how a metrics endpoint becomes an unbounded memory allocation.
//! Here every label is a certificate identity out of the configuration.

use ek_ek_config::{Certificate, CertificateSource};

use crate::renewal::remaining;

/// Seconds left before a certificate stops being usable.
pub const EXPIRY_METRIC: &str = "ek_ek_certificate_expiry_seconds";

/// Whether material has been obtained for a certificate at all.
pub const OBTAINED_METRIC: &str = "ek_ek_certificate_obtained";

/// The Prometheus exposition for every certificate, as text.
///
/// Ends with a newline, so several blocks concatenate into one valid document.
/// A certificate that has never been obtained carries no expiry line, because
/// there is no number to report; it carries an `obtained` of zero instead, so
/// its absence is visible rather than silent.
#[must_use]
pub fn exposition(certificates: &[Certificate], now_unix: i64) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "# HELP {EXPIRY_METRIC} Seconds until the certificate stops being usable.\n"
    ));
    out.push_str(&format!("# TYPE {EXPIRY_METRIC} gauge\n"));
    for certificate in certificates {
        let Some(validity) = certificate.validity else {
            continue;
        };
        out.push_str(&format!(
            "{EXPIRY_METRIC}{} {}\n",
            labels(certificate),
            remaining(&validity, now_unix)
        ));
    }

    out.push_str(&format!(
        "# HELP {OBTAINED_METRIC} 1 when material has been obtained for the certificate, 0 when it has not.\n"
    ));
    out.push_str(&format!("# TYPE {OBTAINED_METRIC} gauge\n"));
    for certificate in certificates {
        out.push_str(&format!(
            "{OBTAINED_METRIC}{} {}\n",
            labels(certificate),
            i32::from(certificate.validity.is_some())
        ));
    }

    out
}

/// The label set both metrics carry.
fn labels(certificate: &Certificate) -> String {
    format!(
        "{{certificate=\"{}\",source=\"{}\"}}",
        escape(certificate.id.as_str()),
        source_of(&certificate.source)
    )
}

/// How a source is named in a label.
///
/// The same words the configuration uses, so somebody reading a graph and
/// somebody reading the document are reading one vocabulary. The DNS provider
/// is not a label: it would put a second identity into the cardinality for a
/// value the certificate record already carries.
const fn source_of(source: &CertificateSource) -> &'static str {
    match source {
        CertificateSource::AcmeHttp01 => "acme_http01",
        CertificateSource::AcmeDns01 { .. } => "acme_dns01",
        CertificateSource::ManualUpload => "manual_upload",
    }
}

/// Makes text safe to sit inside a label value.
///
/// Prometheus reads the exposition line by line, so a backslash, a quote or a
/// newline in an identity would end the label set early and make every line
/// after it unreadable.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}
