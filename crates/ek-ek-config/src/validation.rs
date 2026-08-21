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
use crate::frontend::{ApplicationProtocol, RuleAction, TransportProtocol};
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
    /// A certificate names a DNS provider that is not defined.
    #[serde(rename = "config.certificate.unknown_dns_provider")]
    CertificateUnknownDnsProvider,
    /// A backend pool has nobody to send traffic to.
    #[serde(rename = "config.backend.no_members")]
    BackendNoMembers,
    /// A pool behind a UDP frontend uses cookie stickiness, which needs HTTP.
    #[serde(rename = "config.backend.cookie_stickiness_on_udp")]
    BackendCookieStickinessOnUdp,
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
    pub const ALL: [Self; 17] = [
        Self::DuplicateId,
        Self::FrontendDuplicateBinding,
        Self::FrontendUnknownVip,
        Self::FrontendUnknownBackend,
        Self::FrontendUnknownCertificate,
        Self::FrontendTlsWithoutHttp,
        Self::FrontendRedirectWithoutHttp,
        Self::VipInUse,
        Self::VipUnknownPreferredNode,
        Self::CertificateUnknownDnsProvider,
        Self::BackendNoMembers,
        Self::BackendCookieStickinessOnUdp,
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
            Self::FrontendTlsWithoutHttp => "config.frontend.tls_without_http",
            Self::FrontendRedirectWithoutHttp => "config.frontend.redirect_without_http",
            Self::VipInUse => "config.vip.in_use",
            Self::VipUnknownPreferredNode => "config.vip.unknown_preferred_node",
            Self::CertificateUnknownDnsProvider => "config.certificate.unknown_dns_provider",
            Self::BackendNoMembers => "config.backend.no_members",
            Self::BackendCookieStickinessOnUdp => "config.backend.cookie_stickiness_on_udp",
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
    pub(crate) fn new(code: ErrorCode, path: FieldPath) -> Self {
        Self {
            code,
            path,
            parameters: BTreeMap::new(),
        }
    }

    pub(crate) fn with_id(mut self, name: &str, value: &str) -> Self {
        self.parameters.insert(
            name.to_owned(),
            ParameterValue::Identifier(value.to_owned()),
        );
        self
    }

    pub(crate) fn with_number(mut self, name: &str, value: i64) -> Self {
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
    /// Gathers errors found outside this module, such as by a template.
    pub(crate) fn from_errors(errors: Vec<ValidationError>) -> Self {
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
    check_backends(config, &mut errors);
    check_stickiness_against_transport(config, &mut errors);

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
