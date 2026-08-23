// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Config validation.
//!
//! An invalid config that reaches the data plane cuts traffic, so a config is
//! checked before it is stored rather than when it is applied.
//!
//! Two properties shape everything here.
//!
//! An error carries a code, a field path and structured parameters. It never
//! carries a sentence. The code doubles as the translation key, so the same
//! error renders in Turkish and in English without this layer knowing either
//! (ADR-0015).
//!
//! A validation run collects every error it finds. Stopping at the first one
//! would make an operator fix a form, submit it, and be told about the next
//! problem, once per problem.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::backend::SessionStickiness;
use crate::certificate::CertificateSource;
use crate::config::Config;
use crate::frontend::{ApplicationProtocol, RoutingRule, RuleAction, TransportProtocol};
use crate::id::{BackendId, CertificateId, DnsProviderId, NodeId, VipId};

/// A stable identifier for one kind of validation failure.
///
/// The value is also the translation key the presentation layer looks up, so
/// it never changes once released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Two objects of the same kind share an identity.
    #[serde(rename = "config.duplicate_id")]
    DuplicateId,
    /// Two frontends claim the same VIP, port and transport.
    #[serde(rename = "config.frontend.duplicate_binding")]
    FrontendDuplicateBinding,
    /// A frontend names a VIP that is not defined.
    #[serde(rename = "config.frontend.unknown_vip")]
    FrontendUnknownVip,
    /// A frontend, routing rule or SNI rule names a backend that is not
    /// defined.
    #[serde(rename = "config.frontend.unknown_backend")]
    FrontendUnknownBackend,
    /// A frontend names a certificate that is not defined.
    #[serde(rename = "config.frontend.unknown_certificate")]
    FrontendUnknownCertificate,
    /// A frontend's default certificate is not one it offers.
    #[serde(rename = "config.frontend.unknown_default_certificate")]
    FrontendUnknownDefaultCertificate,
    /// A frontend samples its access log at a rate that writes nothing.
    #[serde(rename = "config.frontend.access_log_sample_zero")]
    FrontendAccessLogSampleZero,
    /// A frontend carries TLS settings without terminating TLS.
    #[serde(rename = "config.frontend.tls_without_http")]
    FrontendTlsWithoutHttp,
    /// A frontend redirects without speaking HTTP, where it cannot answer.
    #[serde(rename = "config.frontend.redirect_without_http")]
    FrontendRedirectWithoutHttp,
    /// A VIP still has frontends bound to it.
    #[serde(rename = "config.vip.in_use")]
    VipInUse,
    /// A VIP prefers a node that is not defined.
    #[serde(rename = "config.vip.unknown_preferred_node")]
    VipUnknownPreferredNode,
    /// More VIPs than the protocol has virtual router ids for.
    #[serde(rename = "config.vip.too_many")]
    VipTooMany,
    /// A certificate names a DNS provider that is not defined.
    #[serde(rename = "config.certificate.unknown_dns_provider")]
    CertificateUnknownDnsProvider,
    /// A certificate is still offered by a frontend.
    #[serde(rename = "config.certificate.in_use")]
    CertificateInUse,
    /// A DNS provider is given no time at all to publish its record.
    #[serde(rename = "config.dns_provider.propagation_timeout_zero")]
    DnsProviderPropagationTimeoutZero,
    /// A DNS provider's API address is not one a token may be sent to.
    #[serde(rename = "config.dns_provider.api_base_invalid")]
    DnsProviderApiBaseInvalid,
    /// The uploaded chain is not readable as PEM.
    #[serde(rename = "certificate.chain.unreadable")]
    CertificateChainUnreadable,
    /// The uploaded chain parsed but holds no certificate.
    #[serde(rename = "certificate.chain.empty")]
    CertificateChainEmpty,
    /// The uploaded chain holds more certificates than anybody serves.
    #[serde(rename = "certificate.chain.too_long")]
    CertificateChainTooLong,
    /// The uploaded key is not readable as PEM.
    #[serde(rename = "certificate.key.unreadable")]
    CertificateKeyUnreadable,
    /// The uploaded key does not belong to the leaf certificate.
    #[serde(rename = "certificate.key.mismatch")]
    CertificateKeyMismatch,
    /// The uploaded key is encrypted and no passphrase was given.
    #[serde(rename = "certificate.key.passphrase_required")]
    CertificateKeyPassphraseRequired,
    /// The passphrase does not open the uploaded key.
    #[serde(rename = "certificate.key.passphrase_wrong")]
    CertificateKeyPassphraseWrong,
    /// A backend pool has nobody to send traffic to.
    #[serde(rename = "config.backend.no_members")]
    BackendNoMembers,
    /// A pool behind a UDP frontend uses cookie stickiness, which needs HTTP.
    #[serde(rename = "config.backend.cookie_stickiness_on_udp")]
    BackendCookieStickinessOnUdp,
    /// Cookie stickiness is on but no key is configured to sign with.
    #[serde(rename = "config.stickiness_key.missing")]
    StickinessKeyMissing,
    /// A stickiness cookie name carries something a header cannot.
    #[serde(rename = "config.backend.stickiness_cookie_name_invalid")]
    BackendStickinessCookieNameInvalid,
    /// A port falls outside the usable range.
    #[serde(rename = "config.port.out_of_range")]
    PortOutOfRange,
    /// A health check would still be waiting when the next probe is due.
    #[serde(rename = "config.health_check.timeout_above_interval")]
    HealthCheckTimeoutAboveInterval,
    /// A template was applied without a value it requires.
    #[serde(rename = "template.parameter.missing")]
    TemplateParameterMissing,
    /// A template parameter was given a value of the wrong kind.
    #[serde(rename = "template.parameter.wrong_kind")]
    TemplateParameterWrongKind,
    /// A template was applied with a value nothing in it declares.
    #[serde(rename = "template.parameter.unknown")]
    TemplateParameterUnknown,
}

impl ErrorCode {
    /// Every code, so a test can check the whole set at once.
    pub const ALL: [Self; 32] = [
        Self::DuplicateId,
        Self::FrontendDuplicateBinding,
        Self::FrontendUnknownVip,
        Self::FrontendUnknownBackend,
        Self::FrontendUnknownCertificate,
        Self::FrontendUnknownDefaultCertificate,
        Self::FrontendAccessLogSampleZero,
        Self::FrontendTlsWithoutHttp,
        Self::FrontendRedirectWithoutHttp,
        Self::VipInUse,
        Self::VipUnknownPreferredNode,
        Self::VipTooMany,
        Self::CertificateUnknownDnsProvider,
        Self::CertificateInUse,
        Self::DnsProviderPropagationTimeoutZero,
        Self::DnsProviderApiBaseInvalid,
        Self::CertificateChainUnreadable,
        Self::CertificateChainEmpty,
        Self::CertificateChainTooLong,
        Self::CertificateKeyUnreadable,
        Self::CertificateKeyMismatch,
        Self::CertificateKeyPassphraseRequired,
        Self::CertificateKeyPassphraseWrong,
        Self::BackendNoMembers,
        Self::BackendCookieStickinessOnUdp,
        Self::StickinessKeyMissing,
        Self::BackendStickinessCookieNameInvalid,
        Self::PortOutOfRange,
        Self::HealthCheckTimeoutAboveInterval,
        Self::TemplateParameterMissing,
        Self::TemplateParameterWrongKind,
        Self::TemplateParameterUnknown,
    ];

    /// Returns the translation key this code is looked up under.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::DuplicateId => "config.duplicate_id",
            Self::FrontendDuplicateBinding => "config.frontend.duplicate_binding",
            Self::FrontendUnknownVip => "config.frontend.unknown_vip",
            Self::FrontendUnknownBackend => "config.frontend.unknown_backend",
            Self::FrontendUnknownCertificate => "config.frontend.unknown_certificate",
            Self::FrontendUnknownDefaultCertificate => {
                "config.frontend.unknown_default_certificate"
            }
            Self::FrontendAccessLogSampleZero => "config.frontend.access_log_sample_zero",
            Self::FrontendTlsWithoutHttp => "config.frontend.tls_without_http",
            Self::FrontendRedirectWithoutHttp => "config.frontend.redirect_without_http",
            Self::VipInUse => "config.vip.in_use",
            Self::VipUnknownPreferredNode => "config.vip.unknown_preferred_node",
            Self::VipTooMany => "config.vip.too_many",
            Self::CertificateUnknownDnsProvider => "config.certificate.unknown_dns_provider",
            Self::CertificateInUse => "config.certificate.in_use",
            Self::DnsProviderPropagationTimeoutZero => {
                "config.dns_provider.propagation_timeout_zero"
            }
            Self::DnsProviderApiBaseInvalid => "config.dns_provider.api_base_invalid",
            Self::CertificateChainUnreadable => "certificate.chain.unreadable",
            Self::CertificateChainEmpty => "certificate.chain.empty",
            Self::CertificateChainTooLong => "certificate.chain.too_long",
            Self::CertificateKeyUnreadable => "certificate.key.unreadable",
            Self::CertificateKeyMismatch => "certificate.key.mismatch",
            Self::CertificateKeyPassphraseRequired => "certificate.key.passphrase_required",
            Self::CertificateKeyPassphraseWrong => "certificate.key.passphrase_wrong",
            Self::BackendNoMembers => "config.backend.no_members",
            Self::BackendCookieStickinessOnUdp => "config.backend.cookie_stickiness_on_udp",
            Self::StickinessKeyMissing => "config.stickiness_key.missing",
            Self::BackendStickinessCookieNameInvalid => {
                "config.backend.stickiness_cookie_name_invalid"
            }
            Self::PortOutOfRange => "config.port.out_of_range",
            Self::HealthCheckTimeoutAboveInterval => "config.health_check.timeout_above_interval",
            Self::TemplateParameterMissing => "template.parameter.missing",
            Self::TemplateParameterWrongKind => "template.parameter.wrong_kind",
            Self::TemplateParameterUnknown => "template.parameter.unknown",
        }
    }
}

/// One step along the path to the field an error blames.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathSegment {
    /// A named field.
    Field(String),
    /// A position in a list.
    Index(usize),
}

/// Where in the config an error sits.
///
/// The path is kept as segments rather than as a formatted string, so the UI
/// can walk it to focus the offending input instead of parsing text.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FieldPath(Vec<PathSegment>);

impl FieldPath {
    /// Starts a path at the root of the config.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    /// Appends a named field.
    #[must_use]
    pub fn field(mut self, name: &str) -> Self {
        self.0.push(PathSegment::Field(name.to_owned()));
        self
    }

    /// Appends a list position.
    #[must_use]
    pub fn index(mut self, at: usize) -> Self {
        self.0.push(PathSegment::Index(at));
        self
    }

    /// Borrows the segments.
    #[must_use]
    pub fn segments(&self) -> &[PathSegment] {
        &self.0
    }

    /// Returns whether the path points at the config as a whole.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Renders the path the way it is written in code, for example
    /// `frontends[1].tls`.
    #[must_use]
    pub fn as_text(&self) -> String {
        let mut text = String::new();
        for segment in &self.0 {
            match segment {
                PathSegment::Field(name) => {
                    if !text.is_empty() {
                        text.push('.');
                    }
                    text.push_str(name);
                }
                PathSegment::Index(at) => {
                    text.push('[');
                    text.push_str(&at.to_string());
                    text.push(']');
                }
            }
        }
        text
    }
}

/// A value the presentation layer places into a translated sentence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum ParameterValue {
    /// The identity of a config object.
    Identifier(String),
    /// A number, such as a port or a duration.
    Number(i64),
}

/// One thing wrong with a config.
///
/// This type carries no sentence and implements no `Display`, because a
/// message produced here would be in one language and could not be translated
/// afterwards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationError {
    /// What went wrong.
    pub code: ErrorCode,
    /// Which field is to blame.
    pub path: FieldPath,
    /// Values the translated sentence needs, keyed by stable names.
    pub parameters: BTreeMap<String, ParameterValue>,
}

impl ValidationError {
    /// Builds an error against one field.
    ///
    /// Public because faults are found outside this crate as well: an
    /// uploaded certificate is refused by `ek-ek-tls`, and an operator has to
    /// read that refusal in the same shape as any other (ADR-0015).
    #[must_use]
    pub fn new(code: ErrorCode, path: FieldPath) -> Self {
        Self {
            code,
            path,
            parameters: BTreeMap::new(),
        }
    }

    /// Adds an identifier the translated sentence needs.
    #[must_use]
    pub fn with_id(mut self, name: &str, value: &str) -> Self {
        self.parameters.insert(
            name.to_owned(),
            ParameterValue::Identifier(value.to_owned()),
        );
        self
    }

    /// Adds a number the translated sentence needs.
    #[must_use]
    pub fn with_number(mut self, name: &str, value: i64) -> Self {
        self.parameters
            .insert(name.to_owned(), ParameterValue::Number(value));
        self
    }
}

/// Everything wrong with a config, gathered in one pass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidationErrors(Vec<ValidationError>);

impl ValidationErrors {
    /// Gathers errors found outside this module, such as by a template or by
    /// the certificate upload path.
    #[must_use]
    pub fn from_errors(errors: Vec<ValidationError>) -> Self {
        Self(errors)
    }

    /// Borrows the collected errors.
    #[must_use]
    pub fn as_slice(&self) -> &[ValidationError] {
        &self.0
    }

    /// Returns how many errors were found.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the run found nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns whether any error carries this code.
    #[must_use]
    pub fn contains(&self, code: ErrorCode) -> bool {
        self.0.iter().any(|error| error.code == code)
    }

    /// Returns the codes in the order they were found.
    #[must_use]
    pub fn codes(&self) -> Vec<ErrorCode> {
        self.0.iter().map(|error| error.code).collect()
    }
}

/// Checks a whole config and reports every problem it finds.
///
/// # Errors
///
/// Returns every violated rule at once. An empty result is impossible: the
/// call succeeds instead.
pub fn validate(config: &Config) -> Result<(), ValidationErrors> {
    let mut errors = Vec::new();

    check_duplicate_ids(config, &mut errors);
    check_frontend_bindings(config, &mut errors);
    check_frontend_references(config, &mut errors);
    check_tls_placement(config, &mut errors);
    check_redirects(config, &mut errors);
    check_vips(config, &mut errors);
    check_certificates(config, &mut errors);
    check_dns_providers(config, &mut errors);
    check_backends(config, &mut errors);
    check_stickiness_against_transport(config, &mut errors);
    check_stickiness_key(config, &mut errors);
    check_stickiness_cookie_name(config, &mut errors);
    check_access_log(config, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ValidationErrors(errors))
    }
}

/// Checks whether a VIP can be removed.
///
/// Removal is checked on its own, because the frontends that would be left
/// dangling are what the operator has to deal with first.
///
/// # Errors
///
/// Returns one error naming every frontend still bound to the VIP.
pub fn validate_vip_removal(config: &Config, vip: &VipId) -> Result<(), ValidationErrors> {
    let users: Vec<&crate::frontend::Frontend> = config
        .frontends
        .iter()
        .filter(|frontend| &frontend.vip == vip)
        .collect();

    if users.is_empty() {
        return Ok(());
    }

    let mut error = ValidationError::new(
        ErrorCode::VipInUse,
        FieldPath::root().field("vips").field(vip.as_str()),
    )
    .with_id("vip", vip.as_str())
    .with_number("frontend_count", users.len() as i64);

    for (position, frontend) in users.iter().enumerate() {
        error = error.with_id(&format!("frontend_{position}"), frontend.id.as_str());
    }

    Err(ValidationErrors(vec![error]))
}

/// Refuses removing a certificate a frontend still offers.
///
/// Checked here rather than in the store, for the same reason a VIP is: the
/// store keeps state and this layer knows what the state means. A frontend
/// left pointing at a certificate that is gone answers no handshake, and the
/// fault shows up as a TLS error nobody can place (T-013).
///
/// # Errors
///
/// Returns one error naming every frontend that still offers it, so an
/// operator sees the whole list rather than one name per attempt.
pub fn validate_certificate_removal(
    config: &Config,
    certificate: &CertificateId,
) -> Result<(), ValidationErrors> {
    let users: Vec<&crate::frontend::Frontend> = config
        .frontends
        .iter()
        .filter(|frontend| offers(frontend, certificate))
        .collect();

    if users.is_empty() {
        return Ok(());
    }

    let mut error = ValidationError::new(
        ErrorCode::CertificateInUse,
        FieldPath::root()
            .field("certificates")
            .field(certificate.as_str()),
    )
    .with_id("certificate", certificate.as_str())
    .with_number("frontend_count", users.len() as i64);

    for (position, frontend) in users.iter().enumerate() {
        error = error.with_id(&format!("frontend_{position}"), frontend.id.as_str());
    }

    Err(ValidationErrors(vec![error]))
}

/// Whether a frontend offers one certificate.
///
/// Both places count: the list it picks from per handshake, and the one it
/// falls back to when the handshake carries no name it knows. A certificate
/// named only as the default is still in use.
fn offers(frontend: &crate::frontend::Frontend, certificate: &CertificateId) -> bool {
    let Some(tls) = &frontend.tls else {
        return false;
    };
    tls.certificates.contains(certificate) || tls.default_certificate.as_ref() == Some(certificate)
}

fn check_duplicate_ids(config: &Config, errors: &mut Vec<ValidationError>) {
    let mut report = |kind: &str, seen: &mut HashSet<String>, id: &str, path: FieldPath| {
        if !seen.insert(id.to_owned()) {
            errors.push(
                ValidationError::new(ErrorCode::DuplicateId, path)
                    .with_id("kind", kind)
                    .with_id("id", id),
            );
        }
    };

    let mut nodes = HashSet::new();
    for (at, node) in config.nodes.iter().enumerate() {
        report(
            "node",
            &mut nodes,
            node.id.as_str(),
            FieldPath::root().field("nodes").index(at).field("id"),
        );
    }

    let mut vips = HashSet::new();
    for (at, vip) in config.vips.iter().enumerate() {
        report(
            "vip",
            &mut vips,
            vip.id.as_str(),
            FieldPath::root().field("vips").index(at).field("id"),
        );
    }

    let mut frontends = HashSet::new();
    for (at, frontend) in config.frontends.iter().enumerate() {
        report(
            "frontend",
            &mut frontends,
            frontend.id.as_str(),
            FieldPath::root().field("frontends").index(at).field("id"),
        );
    }

    let mut backends = HashSet::new();
    for (at, backend) in config.backends.iter().enumerate() {
        report(
            "backend",
            &mut backends,
            backend.id.as_str(),
            FieldPath::root().field("backends").index(at).field("id"),
        );

        let mut members = HashSet::new();
        for (member_at, member) in backend.members.iter().enumerate() {
            report(
                "member",
                &mut members,
                member.id.as_str(),
                FieldPath::root()
                    .field("backends")
                    .index(at)
                    .field("members")
                    .index(member_at)
                    .field("id"),
            );
        }
    }

    let mut certificates = HashSet::new();
    for (at, certificate) in config.certificates.iter().enumerate() {
        report(
            "certificate",
            &mut certificates,
            certificate.id.as_str(),
            FieldPath::root()
                .field("certificates")
                .index(at)
                .field("id"),
        );
    }

    let mut providers = HashSet::new();
    for (at, provider) in config.dns_providers.iter().enumerate() {
        report(
            "dns_provider",
            &mut providers,
            provider.id.as_str(),
            FieldPath::root()
                .field("dns_providers")
                .index(at)
                .field("id"),
        );
    }
}

fn check_frontend_bindings(config: &Config, errors: &mut Vec<ValidationError>) {
    let mut taken: HashMap<(&VipId, u16, TransportProtocol), &str> = HashMap::new();

    for (at, frontend) in config.frontends.iter().enumerate() {
        let binding = (&frontend.vip, frontend.port, frontend.transport);

        if let Some(holder) = taken.get(&binding) {
            errors.push(
                ValidationError::new(
                    ErrorCode::FrontendDuplicateBinding,
                    FieldPath::root().field("frontends").index(at),
                )
                .with_id("vip", frontend.vip.as_str())
                .with_number("port", i64::from(frontend.port))
                .with_id("conflicting_frontend", holder),
            );
        } else {
            taken.insert(binding, frontend.id.as_str());
        }
    }
}

fn check_frontend_references(config: &Config, errors: &mut Vec<ValidationError>) {
    let vips: HashSet<&VipId> = config.vips.iter().map(|vip| &vip.id).collect();
    let backends: HashSet<&BackendId> = config.backends.iter().map(|pool| &pool.id).collect();
    let certificates: HashSet<&CertificateId> = config
        .certificates
        .iter()
        .map(|certificate| &certificate.id)
        .collect();

    for (at, frontend) in config.frontends.iter().enumerate() {
        let here = || FieldPath::root().field("frontends").index(at);

        if !vips.contains(&frontend.vip) {
            errors.push(
                ValidationError::new(ErrorCode::FrontendUnknownVip, here().field("vip"))
                    .with_id("frontend", frontend.id.as_str())
                    .with_id("vip", frontend.vip.as_str()),
            );
        }

        if frontend.port == 0 {
            errors.push(
                ValidationError::new(ErrorCode::PortOutOfRange, here().field("port"))
                    .with_number("port", i64::from(frontend.port)),
            );
        }

        let mut unknown_backend = |backend: &BackendId, path: FieldPath| {
            if !backends.contains(backend) {
                errors.push(
                    ValidationError::new(ErrorCode::FrontendUnknownBackend, path)
                        .with_id("frontend", frontend.id.as_str())
                        .with_id("backend", backend.as_str()),
                );
            }
        };

        if let Some(backend) = &frontend.default_backend {
            unknown_backend(backend, here().field("default_backend"));
        }
        for (rule_at, rule) in frontend.routing_rules.iter().enumerate() {
            // A redirect rule names no pool, so there is nothing to resolve.
            if let RuleAction::Proxy { backend } = &rule.action {
                unknown_backend(
                    backend,
                    here()
                        .field("routing_rules")
                        .index(rule_at)
                        .field("action")
                        .field("backend"),
                );
            }
        }
        for (rule_at, rule) in frontend.sni_rules.iter().enumerate() {
            unknown_backend(
                &rule.backend,
                here().field("sni_rules").index(rule_at).field("backend"),
            );
        }

        if let Some(tls) = &frontend.tls {
            for (certificate_at, certificate) in tls.certificates.iter().enumerate() {
                if !certificates.contains(certificate) {
                    errors.push(
                        ValidationError::new(
                            ErrorCode::FrontendUnknownCertificate,
                            here()
                                .field("tls")
                                .field("certificates")
                                .index(certificate_at),
                        )
                        .with_id("frontend", frontend.id.as_str())
                        .with_id("certificate", certificate.as_str()),
                    );
                }
            }

            // Checked against what this frontend offers rather than against
            // every certificate defined: a default the frontend does not
            // serve could never be selected (ADR-0070).
            if let Some(certificate) = &tls.default_certificate
                && !tls.certificates.contains(certificate)
            {
                errors.push(
                    ValidationError::new(
                        ErrorCode::FrontendUnknownDefaultCertificate,
                        here().field("tls").field("default_certificate"),
                    )
                    .with_id("frontend", frontend.id.as_str())
                    .with_id("certificate", certificate.as_str()),
                );
            }
        }
    }
}

fn check_tls_placement(config: &Config, errors: &mut Vec<ValidationError>) {
    for (at, frontend) in config.frontends.iter().enumerate() {
        if frontend.tls.is_some() && frontend.application != ApplicationProtocol::Http {
            errors.push(
                ValidationError::new(
                    ErrorCode::FrontendTlsWithoutHttp,
                    FieldPath::root().field("frontends").index(at).field("tls"),
                )
                .with_id("frontend", frontend.id.as_str()),
            );
        }
    }
}

/// Checks that a redirecting frontend can answer, and does only that.
///
/// A frontend either proxies or redirects. Letting it carry both would leave
/// one of the two doing nothing, and which one wins is exactly the kind of
/// thing nobody discovers until traffic is on it (ADR-0057).
fn check_redirects(config: &Config, errors: &mut Vec<ValidationError>) {
    for (at, frontend) in config.frontends.iter().enumerate() {
        // Answering with a status line and a `Location` header means speaking
        // HTTP. A raw or a passthrough frontend has no way to say it, so a
        // redirect rule there would never fire and nobody would know why.
        if frontend.application == ApplicationProtocol::Http
            && frontend.transport == TransportProtocol::Tcp
        {
            continue;
        }

        for (rule_at, rule) in frontend.routing_rules.iter().enumerate() {
            if matches!(rule.action, RuleAction::Redirect { .. }) {
                errors.push(
                    ValidationError::new(
                        ErrorCode::FrontendRedirectWithoutHttp,
                        FieldPath::root()
                            .field("frontends")
                            .index(at)
                            .field("routing_rules")
                            .index(rule_at)
                            .field("action"),
                    )
                    .with_id("frontend", frontend.id.as_str()),
                );
            }
        }
    }
}

fn check_vips(config: &Config, errors: &mut Vec<ValidationError>) {
    let nodes: HashSet<&NodeId> = config.nodes.iter().map(|node| &node.id).collect();

    // VRRP carries the virtual router id in one byte and zero is not one, so
    // a segment holds 255 of them. Past that there is no number left to give
    // an address, and the matrix would silently leave it out (T-034).
    if config.vips.len() > crate::matrix::VRIDS {
        errors.push(
            ValidationError::new(ErrorCode::VipTooMany, FieldPath::root().field("vips"))
                .with_number(
                    "vip_count",
                    i64::try_from(config.vips.len()).unwrap_or(i64::MAX),
                )
                .with_number(
                    "limit",
                    i64::try_from(crate::matrix::VRIDS).unwrap_or(i64::MAX),
                ),
        );
    }

    for (at, vip) in config.vips.iter().enumerate() {
        if let Some(preferred) = &vip.preferred_node
            && !nodes.contains(preferred)
        {
            errors.push(
                ValidationError::new(
                    ErrorCode::VipUnknownPreferredNode,
                    FieldPath::root()
                        .field("vips")
                        .index(at)
                        .field("preferred_node"),
                )
                .with_id("vip", vip.id.as_str())
                .with_id("node", preferred.as_str()),
            );
        }
    }
}

fn check_certificates(config: &Config, errors: &mut Vec<ValidationError>) {
    let providers: HashSet<&DnsProviderId> = config
        .dns_providers
        .iter()
        .map(|provider| &provider.id)
        .collect();

    for (at, certificate) in config.certificates.iter().enumerate() {
        if let CertificateSource::AcmeDns01 { provider } = &certificate.source
            && !providers.contains(provider)
        {
            errors.push(
                ValidationError::new(
                    ErrorCode::CertificateUnknownDnsProvider,
                    FieldPath::root()
                        .field("certificates")
                        .index(at)
                        .field("source")
                        .field("provider"),
                )
                .with_id("certificate", certificate.id.as_str())
                .with_id("provider", provider.as_str()),
            );
        }
    }
}

fn check_dns_providers(config: &Config, errors: &mut Vec<ValidationError>) {
    for (at, provider) in config.dns_providers.iter().enumerate() {
        let here = || FieldPath::root().field("dns_providers").index(at);

        // Zero is not "do not wait": the record is written and the server is
        // told to check before anything can have picked it up, which is the
        // one failure no retry undoes (ADR-0026).
        if provider.propagation_timeout_secs == 0 {
            errors.push(
                ValidationError::new(
                    ErrorCode::DnsProviderPropagationTimeoutZero,
                    here().field("propagation_timeout_secs"),
                )
                .with_id("provider", provider.id.as_str()),
            );
        }

        // An API token is a bearer credential. Sending it anywhere but over
        // TLS hands it to whoever is on the path.
        if let crate::certificate::DnsProviderConnection::Cloudflare { api_base, .. } =
            &provider.connection
            && !api_base.is_empty()
            && !api_base.starts_with("https://")
        {
            errors.push(
                ValidationError::new(
                    ErrorCode::DnsProviderApiBaseInvalid,
                    here().field("connection").field("api_base"),
                )
                .with_id("provider", provider.id.as_str()),
            );
        }
    }
}

/// Whether a name covers more than itself.
///
/// Only the leading label counts. RFC 8555 issues nothing else, and a name
/// with a star anywhere further along is not a wildcard at all.
#[must_use]
fn is_wildcard(name: &str) -> bool {
    name.starts_with("*.")
}

/// The port an ACME server asks the HTTP-01 challenge on.
///
/// Fixed by RFC 8555: the server connects to port 80 and follows redirects
/// from there. It is not configurable, because the other side of the
/// conversation does not read this configuration.
pub const HTTP01_PORT: u16 = 80;

/// The frontend that can answer an HTTP-01 challenge, if there is one.
///
/// A plaintext HTTP frontend over TCP on port 80. TLS is excluded because the
/// server connects in the clear, and a listener that only speaks TLS answers
/// nothing it sends.
///
/// Shared rather than written twice: the same rule decides whether a
/// configuration is accepted and whether an order may be started, and two
/// copies of it would eventually disagree (ADR-0026).
#[must_use]
pub fn http01_listener(config: &Config) -> Option<&crate::frontend::Frontend> {
    config.frontends.iter().find(|frontend| {
        frontend.port == HTTP01_PORT
            && frontend.application == ApplicationProtocol::Http
            && frontend.transport == TransportProtocol::Tcp
            && frontend.tls.is_none()
    })
}

/// Everything that stops an ACME order from working.
///
/// These are warnings rather than errors, and the reason is what a
/// configuration means. A certificate an ACME server has not issued yet is a
/// perfectly storable intention: an operator writes the certificate down,
/// then points the name at this cluster, then accepts the terms. Refusing the
/// document would mean the three had to happen in one step, and the shipped
/// `website` template could not produce a document at all (ADR-0072).
///
/// The order itself refuses on exactly this list, so nothing fails silently:
/// what is a warning while the configuration sits still is a hard stop the
/// moment somebody asks for the certificate (ADR-0026).
///
/// With `only` given, faults about other certificates are left out, so one
/// order is not stopped by another certificate's problem.
#[must_use]
pub fn acme_faults(config: &Config, only: Option<&CertificateId>) -> Vec<ValidationWarning> {
    let mut warnings = Vec::new();

    let ordered: Vec<(usize, &crate::certificate::Certificate)> = config
        .certificates
        .iter()
        .enumerate()
        .filter(|(_, certificate)| {
            only.is_none_or(|wanted| &certificate.id == wanted)
                && matches!(
                    certificate.source,
                    CertificateSource::AcmeHttp01 | CertificateSource::AcmeDns01 { .. }
                )
        })
        .collect();

    if ordered.is_empty() {
        return warnings;
    }

    let here = |at: usize| {
        FieldPath::root()
            .field("certificates")
            .index(at)
            .field("source")
    };

    let Some(acme) = &config.acme else {
        for (at, certificate) in &ordered {
            warnings.push(
                ValidationWarning::new(WarningCode::AcmeMissing, here(*at))
                    .with_id("certificate", certificate.id.as_str()),
            );
        }
        return warnings;
    };

    // Every request in the flow is signed, but the directory that says where
    // to send them is not. Over plain HTTP, anybody on the path could point
    // the account at a server of their own.
    if !acme.directory_url.starts_with("https://") {
        warnings.push(ValidationWarning::new(
            WarningCode::AcmeDirectoryUrlInvalid,
            FieldPath::root().field("acme").field("directory_url"),
        ));
    }

    if !acme.accepted_terms {
        warnings.push(ValidationWarning::new(
            WarningCode::AcmeTermsNotAccepted,
            FieldPath::root().field("acme").field("accepted_terms"),
        ));
    }

    // Named per certificate rather than once, because the operator has to know
    // which certificate cannot be obtained, not only that one cannot.
    if http01_listener(config).is_none() {
        for (at, certificate) in &ordered {
            if certificate.source != CertificateSource::AcmeHttp01 {
                continue;
            }
            warnings.push(
                ValidationWarning::new(WarningCode::AcmeNoHttp01Listener, here(*at))
                    .with_id("certificate", certificate.id.as_str())
                    .with_number("port", i64::from(HTTP01_PORT)),
            );
        }
    }

    // A wildcard is only ever issued against a DNS-01 authorization. The
    // server offers no other challenge for it, so the order would fail at the
    // authorization with nothing an operator could read as a cause.
    for (at, certificate) in &ordered {
        if certificate.source == CertificateSource::AcmeHttp01
            && certificate.sni_names.iter().any(|name| is_wildcard(name))
        {
            warnings.push(
                ValidationWarning::new(WarningCode::AcmeWildcardNeedsDns01, here(*at))
                    .with_id("certificate", certificate.id.as_str()),
            );
        }
    }

    warnings
}

fn check_backends(config: &Config, errors: &mut Vec<ValidationError>) {
    for (at, backend) in config.backends.iter().enumerate() {
        let here = || FieldPath::root().field("backends").index(at);

        if backend.members.is_empty() {
            errors.push(
                ValidationError::new(ErrorCode::BackendNoMembers, here().field("members"))
                    .with_id("backend", backend.id.as_str()),
            );
        }

        for (member_at, member) in backend.members.iter().enumerate() {
            if member.port == 0 {
                errors.push(
                    ValidationError::new(
                        ErrorCode::PortOutOfRange,
                        here().field("members").index(member_at).field("port"),
                    )
                    .with_number("port", i64::from(member.port)),
                );
            }
        }

        if let Some(check) = &backend.health_check
            && check.timeout_ms > check.interval_ms
        {
            errors.push(
                ValidationError::new(
                    ErrorCode::HealthCheckTimeoutAboveInterval,
                    here().field("health_check").field("timeout_ms"),
                )
                .with_id("backend", backend.id.as_str())
                .with_number("timeout_ms", i64::from(check.timeout_ms))
                .with_number("interval_ms", i64::from(check.interval_ms)),
            );
        }
    }
}

fn check_stickiness_against_transport(config: &Config, errors: &mut Vec<ValidationError>) {
    for (at, backend) in config.backends.iter().enumerate() {
        if !matches!(backend.stickiness, SessionStickiness::SignedCookie { .. }) {
            continue;
        }

        let Some(frontend) = config.frontends.iter().find(|frontend| {
            frontend.transport == TransportProtocol::Udp && reaches(frontend, &backend.id)
        }) else {
            continue;
        };

        errors.push(
            ValidationError::new(
                ErrorCode::BackendCookieStickinessOnUdp,
                FieldPath::root()
                    .field("backends")
                    .index(at)
                    .field("stickiness"),
            )
            .with_id("backend", backend.id.as_str())
            .with_id("frontend", frontend.id.as_str()),
        );
    }
}

/// The shortest key accepted, in bytes.
///
/// A signature is only worth what the key behind it is worth. Anything under
/// this is short enough to search, and a forged cookie would then pick the
/// backend for the client.
const SHORTEST_KEY: usize = 32;

/// Refuses cookie stickiness that has nothing to sign with.
///
/// Checked only when a pool asks for it: a configuration that uses no
/// stickiness needs no key, and demanding one would refuse a document that
/// works.
fn check_stickiness_key(config: &Config, errors: &mut Vec<ValidationError>) {
    let wanted = config
        .backends
        .iter()
        .any(|backend| matches!(backend.stickiness, SessionStickiness::SignedCookie { .. }));
    if !wanted {
        return;
    }

    let bytes = hex_length(&config.stickiness_key);
    if bytes.is_some_and(|length| length >= SHORTEST_KEY) {
        return;
    }

    errors.push(
        ValidationError::new(
            ErrorCode::StickinessKeyMissing,
            FieldPath::root().field("stickiness_key"),
        )
        .with_number("shortest_bytes", SHORTEST_KEY as i64),
    );
}

/// Returns how many bytes a hex string names, or `None` when it is not hex.
fn hex_length(key: &str) -> Option<usize> {
    if key.is_empty() || !key.len().is_multiple_of(2) {
        return None;
    }
    if !key.bytes().all(|digit| digit.is_ascii_hexdigit()) {
        return None;
    }
    Some(key.len() / 2)
}

/// Refuses a cookie name that would break the header carrying it.
///
/// A name with a space, a semicolon or a newline in it does not produce a
/// cookie the client rejects: it produces a `Set-Cookie` header that means
/// something else, and a newline splits the response outright.
fn check_stickiness_cookie_name(config: &Config, errors: &mut Vec<ValidationError>) {
    for (at, backend) in config.backends.iter().enumerate() {
        let SessionStickiness::SignedCookie { cookie_name, .. } = &backend.stickiness else {
            continue;
        };
        if is_token(cookie_name) {
            continue;
        }

        errors.push(
            ValidationError::new(
                ErrorCode::BackendStickinessCookieNameInvalid,
                FieldPath::root()
                    .field("backends")
                    .index(at)
                    .field("stickiness")
                    .field("cookie_name"),
            )
            .with_id("backend", backend.id.as_str()),
        );
    }
}

/// Refuses an access log sample rate that writes nothing.
///
/// A rate of zero reads as "one record in zero requests", which is not a rate
/// at all. Left alone it would silently behave like a switched off access log
/// while the setting still says the log is on (ADR-0037).
fn check_access_log(config: &Config, errors: &mut Vec<ValidationError>) {
    for (at, frontend) in config.frontends.iter().enumerate() {
        if !frontend.access_log.enabled || frontend.access_log.sample_one_in > 0 {
            continue;
        }

        errors.push(
            ValidationError::new(
                ErrorCode::FrontendAccessLogSampleZero,
                FieldPath::root()
                    .field("frontends")
                    .index(at)
                    .field("access_log")
                    .field("sample_one_in"),
            )
            .with_id("frontend", frontend.id.as_str()),
        );
    }
}

/// Whether a string is an HTTP token, which is what a cookie name must be.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn reaches(frontend: &crate::frontend::Frontend, backend: &BackendId) -> bool {
    frontend.default_backend.as_ref() == Some(backend)
        || frontend.routing_rules.iter().any(
            |rule| matches!(&rule.action, RuleAction::Proxy { backend: named } if named == backend),
        )
        || frontend
            .sni_rules
            .iter()
            .any(|rule| &rule.backend == backend)
}

/// What a configuration warning is about.
///
/// Separate from `ErrorCode` so the two can never be confused: an error stops
/// a configuration from being accepted, a warning never does (ADR-0072).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarningCode {
    /// A routing rule can never match, because an earlier rule already takes
    /// every request it would take.
    #[serde(rename = "config.frontend.unreachable_routing_rule")]
    FrontendUnreachableRoutingRule,
    /// An uploaded certificate is past its validity window.
    ///
    /// Uploading one is allowed on purpose: an operator may install the
    /// replacement before switching to it. The warning cannot be silenced.
    #[serde(rename = "certificate.expired")]
    CertificateExpired,
    /// An uploaded chain stops before a self-signed certificate.
    ///
    /// Clients that do not already hold the missing issuer refuse the
    /// handshake, and the fault looks like a broken certificate rather than a
    /// short chain.
    #[serde(rename = "certificate.chain.incomplete")]
    CertificateChainIncomplete,
    /// A certificate is ordered from an ACME server, but none is configured.
    #[serde(rename = "config.acme.missing")]
    AcmeMissing,
    /// The ACME directory is named by something that is not an HTTPS URL.
    #[serde(rename = "config.acme.directory_url_invalid")]
    AcmeDirectoryUrlInvalid,
    /// A certificate is ordered from an ACME server whose terms nobody has
    /// accepted.
    #[serde(rename = "config.acme.terms_not_accepted")]
    AcmeTermsNotAccepted,
    /// A certificate uses HTTP-01 with nothing listening where the challenge
    /// is asked for.
    #[serde(rename = "config.acme.no_http01_listener")]
    AcmeNoHttp01Listener,
    /// A certificate covers a wildcard name and is ordered with HTTP-01.
    ///
    /// RFC 8555 issues a wildcard only against a DNS-01 authorization, so the
    /// server never offers the challenge this certificate would answer.
    #[serde(rename = "config.acme.wildcard_needs_dns01")]
    AcmeWildcardNeedsDns01,
    /// A certificate is inside its expiry warning window.
    ///
    /// An uploaded certificate is never renewed automatically (ADR-0026), so
    /// this warning is the only thing standing between an operator and a
    /// service that stops answering handshakes. It is raised for an ACME
    /// certificate too: renewal can fail, and then the warning is the one
    /// piece of news that is left.
    #[serde(rename = "certificate.expiring_soon")]
    CertificateExpiringSoon,
    /// A frontend offers a certificate whose validity window has passed.
    ///
    /// Separate from `certificate.expired`, which is about material somebody
    /// uploaded. This one names the frontend, because that is what stops
    /// serving and what an operator is looking at when they ask why.
    #[serde(rename = "config.frontend.certificate_expired")]
    FrontendCertificateExpired,
}

impl WarningCode {
    /// Every code, so a test can check the whole set at once.
    pub const ALL: [Self; 10] = [
        Self::FrontendUnreachableRoutingRule,
        Self::CertificateExpired,
        Self::CertificateChainIncomplete,
        Self::AcmeMissing,
        Self::AcmeDirectoryUrlInvalid,
        Self::AcmeTermsNotAccepted,
        Self::AcmeNoHttp01Listener,
        Self::AcmeWildcardNeedsDns01,
        Self::CertificateExpiringSoon,
        Self::FrontendCertificateExpired,
    ];

    /// Returns the translation key this code is looked up under.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::FrontendUnreachableRoutingRule => "config.frontend.unreachable_routing_rule",
            Self::CertificateExpired => "certificate.expired",
            Self::CertificateChainIncomplete => "certificate.chain.incomplete",
            Self::AcmeMissing => "config.acme.missing",
            Self::AcmeDirectoryUrlInvalid => "config.acme.directory_url_invalid",
            Self::AcmeTermsNotAccepted => "config.acme.terms_not_accepted",
            Self::AcmeNoHttp01Listener => "config.acme.no_http01_listener",
            Self::AcmeWildcardNeedsDns01 => "config.acme.wildcard_needs_dns01",
            Self::CertificateExpiringSoon => "certificate.expiring_soon",
            Self::FrontendCertificateExpired => "config.frontend.certificate_expired",
        }
    }
}

/// Something worth telling an operator that is not an error.
///
/// Carries no sentence, for the same reason `ValidationError` carries none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationWarning {
    /// What is worth mentioning.
    pub code: WarningCode,
    /// Which field it is about.
    pub path: FieldPath,
    /// Values the translated sentence needs, keyed by stable names.
    pub parameters: BTreeMap<String, ParameterValue>,
}

impl ValidationWarning {
    /// Builds a warning against one field.
    ///
    /// Public for the same reason [`ValidationError::new`] is: an uploaded
    /// certificate that works but is worth a word comes from another crate.
    #[must_use]
    pub fn new(code: WarningCode, path: FieldPath) -> Self {
        Self {
            code,
            path,
            parameters: BTreeMap::new(),
        }
    }

    /// Adds an identifier the translated sentence needs.
    #[must_use]
    pub fn with_id(mut self, name: &str, value: &str) -> Self {
        self.parameters.insert(
            name.to_owned(),
            ParameterValue::Identifier(value.to_owned()),
        );
        self
    }

    /// Adds a number the translated sentence needs.
    #[must_use]
    pub fn with_number(mut self, name: &str, value: i64) -> Self {
        self.parameters
            .insert(name.to_owned(), ParameterValue::Number(value));
        self
    }
}

/// Looks for configurations that are valid but probably not what was meant.
///
/// Nothing here refuses a configuration. A caller that accepts configuration
/// shows these to the operator; the traffic path does not call this at all,
/// because a warning never stops a delivery (ADR-0072).
///
/// The clock arrives as a parameter rather than being read here, because two
/// of these warnings are about time and a rule that reads the system clock is
/// one nobody can measure (ADR-0079).
#[must_use]
pub fn inspect(config: &Config, now_unix: i64) -> Vec<ValidationWarning> {
    let mut warnings = Vec::new();
    check_unreachable_rules(config, &mut warnings);
    warnings.extend(acme_faults(config, None));
    check_expiry(config, now_unix, &mut warnings);
    warnings
}

/// Reports certificates that are close to their end, and frontends past it.
///
/// Both readings come from the same window, so a certificate cannot be past
/// its end without also being reported as expiring. That is on purpose: the
/// first warning names the certificate and the second names what stops
/// serving because of it.
fn check_expiry(config: &Config, now_unix: i64, warnings: &mut Vec<ValidationWarning>) {
    // Days rather than seconds, because that is the unit an operator set it
    // in. The product cannot overflow: the threshold is a `u32` and the
    // result is an `i64`.
    let window = i64::from(config.certificate_expiry_warning_days) * 86_400;

    for (at, certificate) in config.certificates.iter().enumerate() {
        // Nothing has been obtained yet, which is the normal state of an ACME
        // certificate somebody has just configured. It cannot expire.
        let Some(validity) = certificate.validity else {
            continue;
        };
        if validity.not_after_unix - now_unix > window {
            continue;
        }
        warnings.push(
            ValidationWarning::new(
                WarningCode::CertificateExpiringSoon,
                FieldPath::root().field("certificates").index(at),
            )
            .with_id("certificate", certificate.id.as_str())
            .with_number("not_after_unix", validity.not_after_unix)
            .with_number("remaining_seconds", validity.not_after_unix - now_unix),
        );
    }

    for (at, frontend) in config.frontends.iter().enumerate() {
        let Some(tls) = &frontend.tls else {
            continue;
        };
        for (offered, id) in tls.certificates.iter().enumerate() {
            let Some(certificate) = config
                .certificates
                .iter()
                .find(|held| &held.id == id)
                .filter(|held| {
                    held.validity
                        .is_some_and(|window| window.not_after_unix <= now_unix)
                })
            else {
                continue;
            };
            // Named against the frontend rather than the certificate: a
            // certificate that has expired and that nothing offers costs an
            // operator nothing, and one that a listener offers is a handshake
            // that has already started failing.
            warnings.push(
                ValidationWarning::new(
                    WarningCode::FrontendCertificateExpired,
                    FieldPath::root()
                        .field("frontends")
                        .index(at)
                        .field("tls")
                        .field("certificates")
                        .index(offered),
                )
                .with_id("frontend", frontend.id.as_str())
                .with_id("certificate", id.as_str())
                .with_number(
                    "not_after_unix",
                    certificate
                        .validity
                        .map_or(0, |window| window.not_after_unix),
                ),
            );
        }
    }
}

/// Reports a routing rule an earlier rule already takes every request from.
fn check_unreachable_rules(config: &Config, warnings: &mut Vec<ValidationWarning>) {
    for (at, frontend) in config.frontends.iter().enumerate() {
        for (later, rule) in frontend.routing_rules.iter().enumerate() {
            let Some(earlier) = frontend.routing_rules[..later]
                .iter()
                .position(|before| covers(before, rule))
            else {
                continue;
            };

            warnings.push(
                ValidationWarning::new(
                    WarningCode::FrontendUnreachableRoutingRule,
                    FieldPath::root()
                        .field("frontends")
                        .index(at)
                        .field("routing_rules")
                        .index(later),
                )
                .with_id("frontend", frontend.id.as_str())
                .with_number("rule", i64::try_from(later).unwrap_or(i64::MAX))
                .with_number("earlier", i64::try_from(earlier).unwrap_or(i64::MAX)),
            );
        }
    }
}

/// Whether every request `later` would take is already taken by `earlier`.
fn covers(earlier: &RoutingRule, later: &RoutingRule) -> bool {
    host_covers(
        earlier.host_pattern.as_deref(),
        later.host_pattern.as_deref(),
    ) && path_covers(earlier.path_prefix.as_deref(), later.path_prefix.as_deref())
}

/// Whether one host pattern takes every host another would take.
fn host_covers(earlier: Option<&str>, later: Option<&str>) -> bool {
    let Some(earlier) = earlier else {
        // No pattern takes every host, so it covers anything.
        return true;
    };
    let Some(later) = later else {
        // A pattern cannot cover "every host".
        return false;
    };

    let earlier = earlier.to_lowercase();
    let later = later.to_lowercase();
    if earlier == later {
        return true;
    }
    // `*.ornek.com` covers `posta.ornek.com` and nothing deeper (ADR-0071).
    earlier.strip_prefix("*.").is_some_and(|suffix| {
        later
            .split_once('.')
            .is_some_and(|(_, rest)| rest == suffix)
    })
}

/// Whether one path prefix takes every path another would take.
fn path_covers(earlier: Option<&str>, later: Option<&str>) -> bool {
    let Some(earlier) = earlier else {
        return true;
    };
    let Some(later) = later else {
        return false;
    };
    // Compared case insensitively, which is the wider of the two matching
    // modes: a rule that would shadow under the wider one is worth naming.
    let earlier = earlier.to_lowercase();
    let later = later.to_lowercase();
    later == earlier
        || later
            .strip_prefix(&earlier)
            .is_some_and(|rest| earlier.ends_with('/') || rest.starts_with('/'))
}
