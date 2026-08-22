// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Templates that produce config objects and then let go of them.
//!
//! A real Exchange publication needs four routing rules, four backend pools,
//! a timeout per path, pooling turned off for NTLM and product-specific
//! health check paths. A one or two person team cannot assemble that
//! correctly from scratch, so the knowledge goes into the product rather than
//! into documentation (ADR-0046).
//!
//! # A producer, not a live abstraction
//!
//! Applying a template yields ordinary config objects. Nothing in them
//! references the template they came from, so editing the product's template
//! later never rewrites a config an operator has since adjusted. That is the
//! decision's core, and it is why [`Applied`] carries a whole [`Config`] and
//! not a link.
//!
//! # No template language
//!
//! Parameters are a flat, typed list. There is no condition, no loop, no
//! expression and no script. A template fills a fixed set of objects with the
//! values it was given, and nothing else.
//!
//! # Applying is a pure function
//!
//! [`apply`] reads a config and returns what the config would become. It
//! writes nothing and reaches no network, so the preview an operator sees
//! before applying is produced by the same code that applies it, rather than
//! by a second implementation that can disagree with it.
//!
//! Storing the result is the store's business: it is one write, so it becomes
//! one version and one step to roll back (ADR-0046, T-015).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::backend::{
    AdminState, Backend, BackendMember, ConnectionPooling, LoadBalancingAlgorithm,
    SessionStickiness,
};
use crate::certificate::{Certificate, CertificateSource};
use crate::config::Config;
use crate::frontend::{
    ApplicationProtocol, Frontend, Http2, ProxyProtocol, RedirectStatus, RoutingRule, RuleAction,
    TlsSettings, TransportProtocol,
};
use crate::health::{DnsRecordType, HealthCheck, HealthProbe, ProbePayload};
use crate::id::{BackendId, CertificateId, FrontendId, MemberId, NodeId, TemplateId, VipId};
use crate::validation::{ErrorCode, FieldPath, ValidationError, ValidationErrors, validate};
use crate::vip::Vip;

/// Whether a template has been tried against the real product.
///
/// The distinction is shown to the operator, because a template built from
/// assumptions and one measured against a live deployment carry very
/// different risk (ADR-0046).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum Verification {
    /// Tested against a real deployment of the named product version.
    Verified {
        /// Which version it was tested against.
        product_version: String,
    },
    /// Built from assumptions. The operator accepts that knowingly.
    Unverified,
}

impl Verification {
    /// Returns the translation key describing this state.
    #[must_use]
    pub const fn key(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "template.verification.verified",
            Self::Unverified => "template.verification.unverified",
        }
    }
}

/// What kind of value a parameter takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterKind {
    /// Free text, such as a domain name.
    Text,
    /// An IP address.
    Address,
    /// A port number.
    Port,
    /// One of the nodes in the config.
    Node,
    /// The members of a backend pool.
    Members,
}

/// One value a template asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    /// Stable identifier the value is given under.
    pub name: String,
    /// Translation key of the label shown beside the input.
    pub label_key: String,
    /// What kind of value it takes.
    pub kind: ParameterKind,
}

/// A value handed to a template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Argument {
    /// Free text.
    Text(String),
    /// An IP address.
    Address(IpAddr),
    /// A port number.
    Port(u16),
    /// A node in the config.
    Node(NodeId),
    /// The members of a backend pool.
    Members(Vec<BackendMember>),
}

impl Argument {
    /// Returns the kind this value satisfies.
    #[must_use]
    pub const fn kind(&self) -> ParameterKind {
        match self {
            Self::Text(_) => ParameterKind::Text,
            Self::Address(_) => ParameterKind::Address,
            Self::Port(_) => ParameterKind::Port,
            Self::Node(_) => ParameterKind::Node,
            Self::Members(_) => ParameterKind::Members,
        }
    }
}

/// The values a template is applied with.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Arguments(BTreeMap<String, Argument>);

impl Arguments {
    /// Starts an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one value.
    #[must_use]
    pub fn with(mut self, name: &str, value: Argument) -> Self {
        self.0.insert(name.to_owned(), value);
        self
    }

    fn text(&self, name: &str) -> Option<&str> {
        match self.0.get(name) {
            Some(Argument::Text(value)) => Some(value),
            _ => None,
        }
    }

    fn address(&self, name: &str) -> Option<IpAddr> {
        match self.0.get(name) {
            Some(Argument::Address(value)) => Some(*value),
            _ => None,
        }
    }

    fn port(&self, name: &str) -> Option<u16> {
        match self.0.get(name) {
            Some(Argument::Port(value)) => Some(*value),
            _ => None,
        }
    }

    fn node(&self, name: &str) -> Option<&NodeId> {
        match self.0.get(name) {
            Some(Argument::Node(value)) => Some(value),
            _ => None,
        }
    }

    fn members(&self, name: &str) -> Option<&[BackendMember]> {
        match self.0.get(name) {
            Some(Argument::Members(value)) => Some(value),
            _ => None,
        }
    }
}

/// What kind of object a template created.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatedKind {
    /// A virtual address.
    Vip,
    /// A listener.
    Frontend,
    /// A pool of members.
    Backend,
    /// A certificate.
    Certificate,
}

/// One object a template creates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Created {
    /// What it is.
    pub kind: CreatedKind,
    /// Its identity in the config.
    pub id: String,
}

/// What applying a template produces.
///
/// Nothing here has been written anywhere. This is both the preview an
/// operator is shown and the value the store writes, which is what keeps the
/// two from disagreeing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The config as it would be afterwards.
    pub config: Config,
    /// What the template adds, in the order it adds them.
    pub created: Vec<Created>,
}

/// A template that ships with the product.
///
/// The name and the description are translation keys rather than sentences,
/// because a domain type never carries user-facing text (ADR-0015).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    /// Its identity.
    pub id: TemplateId,
    /// Translation key of its name.
    pub name_key: String,
    /// Translation key of its description.
    pub description_key: String,
    /// What it asks the operator for.
    pub parameters: Vec<Parameter>,
    /// Whether it has been tried against the real product.
    pub verification: Verification,
}

/// A template an operator saved from a working config.
///
/// It carries structure only. No certificate, no secret reference and no key
/// material of any kind travels with it (ADR-0046), so saving one and sharing
/// the config store between nodes never moves a private key along a path
/// nobody meant to open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserTemplate {
    /// Its identity.
    pub id: TemplateId,
    /// What the operator called it, in their own words.
    pub name: String,
    /// The listener, with any TLS certificate reference stripped.
    pub frontend: Frontend,
    /// The pools it sends to, with their members kept as a starting point.
    pub backends: Vec<Backend>,
}

/// Every template that ships with the product (ADR-0046).
///
/// The list is defined in code rather than read from a file, so a broken
/// template fails to compile instead of failing on the operator's screen.
/// Extending it is a new decision, because each template is a lasting
/// maintenance and verification obligation.
#[must_use]
pub fn embedded() -> Vec<Template> {
    vec![
        website_template(),
        dns_template(),
        exchange_template(),
        smtp_relay_template(),
        generic_tcp_template(),
    ]
}

/// Finds a shipped template by identity.
#[must_use]
pub fn embedded_by_id(id: &TemplateId) -> Option<Template> {
    embedded().into_iter().find(|template| &template.id == id)
}

fn parameter(name: &str, kind: ParameterKind) -> Parameter {
    Parameter {
        name: name.to_owned(),
        label_key: format!("template.parameter.{name}.label"),
        kind,
    }
}

fn template(id: &str, parameters: Vec<Parameter>, verification: Verification) -> Template {
    Template {
        id: TemplateId::new(id),
        name_key: format!("template.{id}.name"),
        description_key: format!("template.{id}.description"),
        parameters,
        verification,
    }
}

fn website_template() -> Template {
    template(
        "website",
        vec![
            parameter("name", ParameterKind::Text),
            parameter("domain", ParameterKind::Text),
            parameter("address", ParameterKind::Address),
            parameter("interface", ParameterKind::Text),
            parameter("node", ParameterKind::Node),
            parameter("members", ParameterKind::Members),
        ],
        Verification::Verified {
            product_version: "nginx 1.24, Apache 2.4".to_owned(),
        },
    )
}

fn dns_template() -> Template {
    template(
        "dns",
        vec![
            parameter("name", ParameterKind::Text),
            parameter("address", ParameterKind::Address),
            parameter("interface", ParameterKind::Text),
            parameter("node", ParameterKind::Node),
            parameter("members", ParameterKind::Members),
        ],
        Verification::Verified {
            product_version: "BIND 9.18".to_owned(),
        },
    )
}

fn exchange_template() -> Template {
    template(
        "exchange",
        vec![
            parameter("name", ParameterKind::Text),
            parameter("domain", ParameterKind::Text),
            parameter("address", ParameterKind::Address),
            parameter("interface", ParameterKind::Text),
            parameter("node", ParameterKind::Node),
            parameter("members", ParameterKind::Members),
        ],
        // The paths and the timeouts rest on assumptions until T-069 measures
        // them against a real deployment (R-20).
        Verification::Unverified,
    )
}

fn smtp_relay_template() -> Template {
    template(
        "smtp_relay",
        vec![
            parameter("name", ParameterKind::Text),
            parameter("address", ParameterKind::Address),
            parameter("interface", ParameterKind::Text),
            parameter("node", ParameterKind::Node),
            parameter("members", ParameterKind::Members),
        ],
        Verification::Verified {
            product_version: "Postfix 3.7".to_owned(),
        },
    )
}

fn generic_tcp_template() -> Template {
    template(
        "generic_tcp",
        vec![
            parameter("name", ParameterKind::Text),
            parameter("address", ParameterKind::Address),
            parameter("interface", ParameterKind::Text),
            parameter("node", ParameterKind::Node),
            parameter("port", ParameterKind::Port),
            parameter("members", ParameterKind::Members),
        ],
        Verification::Verified {
            product_version: "".to_owned(),
        },
    )
}

/// Applies a template to a config and returns what the config would become.
///
/// Nothing is written. The result is the preview and the value to store, so
/// what an operator approves is exactly what is saved.
///
/// # Errors
///
/// Returns every problem at once: a value the template asked for and did not
/// get, a value of the wrong kind, a value nothing declares, and everything
/// the config validation layer finds about the result. A VIP and port already
/// in use therefore comes back as the ordinary field-level error rather than
/// as a template-specific one.
pub fn apply(
    template: &Template,
    config: &Config,
    arguments: &Arguments,
) -> Result<Applied, ValidationErrors> {
    check_arguments(template, arguments)?;

    let mut next = config.clone();
    let mut created = Vec::new();
    build(template, arguments, &mut next, &mut created);

    validate(&next)?;
    Ok(Applied {
        config: next,
        created,
    })
}

/// Removes everything a template created, in one step.
///
/// The store rolls back by restoring an earlier version, which is the path an
/// operator takes. This is the same result computed directly, for a caller
/// that holds the [`Applied`] value and no history.
#[must_use]
pub fn undo(config: &Config, created: &[Created]) -> Config {
    let mut next = config.clone();
    let gone: BTreeSet<(CreatedKind, &str)> = created
        .iter()
        .map(|object| (object.kind, object.id.as_str()))
        .collect();

    next.vips
        .retain(|vip| !gone.contains(&(CreatedKind::Vip, vip.id.as_str())));
    next.frontends
        .retain(|frontend| !gone.contains(&(CreatedKind::Frontend, frontend.id.as_str())));
    next.backends
        .retain(|backend| !gone.contains(&(CreatedKind::Backend, backend.id.as_str())));
    next.certificates
        .retain(|certificate| !gone.contains(&(CreatedKind::Certificate, certificate.id.as_str())));
    next
}

/// Saves the structure of a frontend and the pools it reaches as a template.
///
/// # Errors
///
/// Fails when the frontend is not in the config.
pub fn from_frontend(
    config: &Config,
    frontend: &FrontendId,
    name: &str,
) -> Result<UserTemplate, ValidationErrors> {
    let found = config
        .frontends
        .iter()
        .find(|candidate| &candidate.id == frontend)
        .ok_or_else(|| {
            ValidationErrors::from_errors(vec![
                ValidationError::new(
                    ErrorCode::FrontendUnknownBackend,
                    FieldPath::root().field("frontends"),
                )
                .with_id("frontend", frontend.as_str()),
            ])
        })?;

    let mut stripped = found.clone();
    // Key material never travels with a template. The operator picks a
    // certificate when they apply it.
    if let Some(tls) = &mut stripped.tls {
        tls.certificates.clear();
    }

    let wanted: BTreeSet<&BackendId> = stripped
        .default_backend
        .iter()
        .chain(
            stripped
                .routing_rules
                .iter()
                .filter_map(|rule| match &rule.action {
                    RuleAction::Proxy { backend } => Some(backend),
                    RuleAction::Redirect { .. } => None,
                }),
        )
        .chain(stripped.sni_rules.iter().map(|rule| &rule.backend))
        .collect();

    let backends = config
        .backends
        .iter()
        .filter(|backend| wanted.contains(&backend.id))
        .cloned()
        .collect();

    Ok(UserTemplate {
        id: TemplateId::new(format!("user-{}", frontend.as_str())),
        name: name.to_owned(),
        frontend: stripped,
        backends,
    })
}

/// Reports every parameter problem at once.
fn check_arguments(template: &Template, arguments: &Arguments) -> Result<(), ValidationErrors> {
    let mut errors = Vec::new();
    let declared: BTreeSet<&str> = template
        .parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect();

    for parameter in &template.parameters {
        let path = FieldPath::root().field("parameters").field(&parameter.name);
        match arguments.0.get(&parameter.name) {
            None => errors.push(
                ValidationError::new(ErrorCode::TemplateParameterMissing, path)
                    .with_id("parameter", &parameter.name),
            ),
            Some(argument) if argument.kind() != parameter.kind => errors.push(
                ValidationError::new(ErrorCode::TemplateParameterWrongKind, path)
                    .with_id("parameter", &parameter.name),
            ),
            Some(_) => {}
        }
    }

    // Reported from the other side too: a value nothing declares is a typed
    // parameter name that silently did nothing, which is exactly the mistake
    // that is hardest to see on a form.
    for name in arguments.0.keys() {
        if !declared.contains(name.as_str()) {
            errors.push(
                ValidationError::new(
                    ErrorCode::TemplateParameterUnknown,
                    FieldPath::root().field("parameters").field(name),
                )
                .with_id("parameter", name),
            );
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ValidationErrors::from_errors(errors))
    }
}

/// A gathered view of the values every template shares.
struct Common<'a> {
    name: &'a str,
    address: IpAddr,
    interface: &'a str,
    node: Option<&'a NodeId>,
    members: Vec<BackendMember>,
}

fn common<'a>(arguments: &'a Arguments) -> Common<'a> {
    Common {
        name: arguments.text("name").unwrap_or("service"),
        address: arguments
            .address("address")
            .unwrap_or(IpAddr::from([0, 0, 0, 0])),
        interface: arguments.text("interface").unwrap_or("eth0"),
        node: arguments.node("node"),
        members: arguments.members("members").unwrap_or_default().to_vec(),
    }
}

fn build(
    template: &Template,
    arguments: &Arguments,
    config: &mut Config,
    created: &mut Vec<Created>,
) {
    let values = common(arguments);
    let vip = add_vip(config, created, &values);

    match template.id.as_str() {
        "website" => build_website(arguments, config, created, &values, &vip),
        "dns" => build_dns(config, created, &values, &vip),
        "exchange" => build_exchange(arguments, config, created, &values, &vip),
        "smtp_relay" => build_smtp_relay(config, created, &values, &vip),
        // A template nothing else matches produces the plain skeleton, which
        // is what the generic entry is.
        _ => build_generic_tcp(arguments, config, created, &values, &vip),
    }
}

fn add_vip(config: &mut Config, created: &mut Vec<Created>, values: &Common<'_>) -> VipId {
    let id = VipId::new(format!("vip-{}", values.name));
    config.vips.push(Vip {
        id: id.clone(),
        address: values.address,
        prefix_length: if values.address.is_ipv4() { 24 } else { 64 },
        interface: values.interface.to_owned(),
        preferred_node: values.node.cloned(),
    });
    created.push(Created {
        kind: CreatedKind::Vip,
        id: id.as_str().to_owned(),
    });
    id
}

fn add_backend(
    config: &mut Config,
    created: &mut Vec<Created>,
    id: &str,
    members: Vec<BackendMember>,
    algorithm: LoadBalancingAlgorithm,
    health_check: Option<HealthCheck>,
    pooling: ConnectionPooling,
) -> BackendId {
    let id = BackendId::new(id);
    config.backends.push(Backend {
        id: id.clone(),
        members,
        algorithm,
        health_check,
        stickiness: SessionStickiness::Disabled,
        connection_pooling: pooling,
    });
    created.push(Created {
        kind: CreatedKind::Backend,
        id: id.as_str().to_owned(),
    });
    id
}

fn add_frontend(config: &mut Config, created: &mut Vec<Created>, frontend: Frontend) {
    created.push(Created {
        kind: CreatedKind::Frontend,
        id: frontend.id.as_str().to_owned(),
    });
    config.frontends.push(frontend);
}

/// Moves a pool's members onto another port, so one set of addresses can back
/// several services of one product.
fn members_on(members: &[BackendMember], suffix: &str, port: u16) -> Vec<BackendMember> {
    members
        .iter()
        .map(|member| BackendMember {
            id: MemberId::new(format!("{}-{suffix}", member.id.as_str())),
            address: member.address,
            port,
            weight: member.weight,
            admin_state: AdminState::Enabled,
        })
        .collect()
}

fn http_check(path: &str, host: Option<&str>) -> HealthCheck {
    HealthCheck {
        probe: HealthProbe::Http {
            path: path.to_owned(),
            expected_status: vec![200, 401],
            expected_body: None,
            host_header: host.map(str::to_owned),
        },
        interval_ms: 5_000,
        timeout_ms: 3_000,
        healthy_threshold: 2,
        unhealthy_threshold: 3,
    }
}

fn build_website(
    arguments: &Arguments,
    config: &mut Config,
    created: &mut Vec<Created>,
    values: &Common<'_>,
    vip: &VipId,
) {
    let domain = arguments.text("domain").unwrap_or(values.name);

    let certificate = CertificateId::new(format!("cert-{}", values.name));
    config.certificates.push(Certificate {
        id: certificate.clone(),
        sni_names: vec![domain.to_owned()],
        // HTTP-01 needs nothing configured, because the product already
        // answers on port 80.
        source: CertificateSource::AcmeHttp01,
        validity: None,
        chain: None,
        private_key: None,
    });
    created.push(Created {
        kind: CreatedKind::Certificate,
        id: certificate.as_str().to_owned(),
    });

    let backend = add_backend(
        config,
        created,
        &format!("pool-{}", values.name),
        values.members.clone(),
        LoadBalancingAlgorithm::RoundRobin,
        Some(http_check("/", Some(domain))),
        ConnectionPooling::Enabled,
    );

    add_frontend(
        config,
        created,
        Frontend {
            id: FrontendId::new(format!("{}-https", values.name)),
            vip: vip.clone(),
            port: 443,
            transport: TransportProtocol::Tcp,
            application: ApplicationProtocol::Http,
            tls: Some(TlsSettings {
                certificates: vec![certificate],
                // Left unset on purpose. A template that guessed a default
                // would serve this certificate to names it does not cover,
                // and the operator would only see it client side (ADR-0070).
                default_certificate: None,
                policy: crate::frontend::TlsPolicyLevel::Balanced,
            }),
            proxy_protocol: ProxyProtocol::Disabled,
            routing_rules: Vec::new(),
            sni_rules: Vec::new(),
            default_backend: Some(backend),
            http2: Http2::Enabled,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 60,
            idle_timeout_seconds: 0,
            drain_timeout_seconds: 30,
            udp_session_limit: 0,
        },
    );

    // Port 80 answers as well. Without it the address someone typed into a
    // browser reaches nothing, and the operator is left publishing a site
    // that only works if the visitor types the scheme (ADR-0057).
    //
    // The redirect is answered here, so no plaintext request is ever
    // forwarded to a backend.
    add_frontend(
        config,
        created,
        Frontend {
            id: FrontendId::new(format!("{}-http", values.name)),
            vip: vip.clone(),
            port: 80,
            transport: TransportProtocol::Tcp,
            application: ApplicationProtocol::Http,
            tls: None,
            proxy_protocol: ProxyProtocol::Disabled,
            routing_rules: vec![RoutingRule {
                // Matches everything, which is what a redirect listener is.
                host_pattern: None,
                path_prefix: None,
                action: RuleAction::Redirect {
                    // 308 rather than 301: a browser following a 301 turns a
                    // POST into a GET and drops the body.
                    status: RedirectStatus::Permanent,
                },
                request_timeout_seconds: None,
            }],
            sni_rules: Vec::new(),
            // Nothing to fall through to: every request is answered.
            default_backend: None,
            http2: Http2::Enabled,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 60,
            idle_timeout_seconds: 0,
            drain_timeout_seconds: 10,
            udp_session_limit: 0,
        },
    );
}

fn build_dns(config: &mut Config, created: &mut Vec<Created>, values: &Common<'_>, vip: &VipId) {
    let check = HealthCheck {
        // A real query rather than a connect: a name server with a broken
        // zone still accepts connections.
        probe: HealthProbe::DnsQuery {
            name: ".".to_owned(),
            record_type: DnsRecordType::Soa,
        },
        interval_ms: 5_000,
        timeout_ms: 2_000,
        healthy_threshold: 2,
        unhealthy_threshold: 3,
    };

    // Consistent hashing rather than round robin: the UDP path needs two
    // processes to reach the same member during an upgrade (ADR-0025).
    let backend = add_backend(
        config,
        created,
        &format!("pool-{}", values.name),
        members_on(&values.members, "dns", 53),
        LoadBalancingAlgorithm::ConsistentHash,
        Some(check),
        ConnectionPooling::Enabled,
    );

    // One VIP and port, two transports. DNS falls back to TCP for answers
    // that do not fit in a datagram, so publishing only UDP breaks zone
    // transfers and large responses (ADR-0016).
    for (suffix, transport) in [
        ("udp", TransportProtocol::Udp),
        ("tcp", TransportProtocol::Tcp),
    ] {
        add_frontend(
            config,
            created,
            Frontend {
                id: FrontendId::new(format!("{}-{suffix}", values.name)),
                vip: vip.clone(),
                port: 53,
                transport,
                application: ApplicationProtocol::Raw,
                tls: None,
                proxy_protocol: ProxyProtocol::Disabled,
                routing_rules: Vec::new(),
                sni_rules: Vec::new(),
                default_backend: Some(backend.clone()),
                http2: Http2::Enabled,
                connect_timeout_seconds: 5,
                // Raw traffic carries no request to time out.
                request_timeout_seconds: 0,
                idle_timeout_seconds: 0,
                drain_timeout_seconds: 10,
                udp_session_limit: 0,
            },
        );
    }
}

fn build_exchange(
    arguments: &Arguments,
    config: &mut Config,
    created: &mut Vec<Created>,
    values: &Common<'_>,
    vip: &VipId,
) {
    let domain = arguments.text("domain").unwrap_or(values.name);

    // Four paths, four pools. They differ in timeout and in whether a
    // backend connection may be reused, which is why they cannot share one.
    let owa = add_backend(
        config,
        created,
        &format!("pool-{}-owa", values.name),
        members_on(&values.members, "owa", 443),
        LoadBalancingAlgorithm::RoundRobin,
        Some(http_check("/owa/healthcheck.htm", Some(domain))),
        ConnectionPooling::Enabled,
    );
    let activesync = add_backend(
        config,
        created,
        &format!("pool-{}-activesync", values.name),
        members_on(&values.members, "activesync", 443),
        LoadBalancingAlgorithm::RoundRobin,
        Some(http_check(
            "/Microsoft-Server-ActiveSync/healthcheck.htm",
            Some(domain),
        )),
        ConnectionPooling::Enabled,
    );
    let ews = add_backend(
        config,
        created,
        &format!("pool-{}-ews", values.name),
        members_on(&values.members, "ews", 443),
        LoadBalancingAlgorithm::RoundRobin,
        Some(http_check("/ews/healthcheck.htm", Some(domain))),
        ConnectionPooling::Enabled,
    );
    // MAPI over HTTP authenticates with NTLM, which binds the credentials to
    // the TCP connection. Reusing one for another user's request fails
    // silently and at random, so this pool opens a connection per request
    // (ADR-0045).
    let mapi = add_backend(
        config,
        created,
        &format!("pool-{}-mapi", values.name),
        members_on(&values.members, "mapi", 443),
        LoadBalancingAlgorithm::RoundRobin,
        Some(http_check("/mapi/healthcheck.htm", Some(domain))),
        ConnectionPooling::Disabled,
    );

    let rules = vec![
        RoutingRule {
            host_pattern: None,
            path_prefix: Some("/Microsoft-Server-ActiveSync".to_owned()),
            action: RuleAction::Proxy {
                backend: activesync,
            },
            // Push email holds the request open. Anything shorter turns push
            // into polling and drains phone batteries (ADR-0044).
            request_timeout_seconds: Some(3_600),
        },
        RoutingRule {
            host_pattern: None,
            path_prefix: Some("/mapi".to_owned()),
            action: RuleAction::Proxy { backend: mapi },
            request_timeout_seconds: Some(3_600),
        },
        RoutingRule {
            host_pattern: None,
            path_prefix: Some("/ews".to_owned()),
            action: RuleAction::Proxy { backend: ews },
            request_timeout_seconds: Some(600),
        },
        RoutingRule {
            host_pattern: None,
            path_prefix: Some("/owa".to_owned()),
            action: RuleAction::Proxy {
                backend: owa.clone(),
            },
            request_timeout_seconds: Some(600),
        },
    ];

    add_frontend(
        config,
        created,
        Frontend {
            id: FrontendId::new(format!("{}-https", values.name)),
            vip: vip.clone(),
            port: 443,
            transport: TransportProtocol::Tcp,
            application: ApplicationProtocol::Http,
            tls: Some(TlsSettings {
                certificates: Vec::new(),
                default_certificate: None,
                policy: crate::frontend::TlsPolicyLevel::Balanced,
            }),
            proxy_protocol: ProxyProtocol::Disabled,
            routing_rules: rules,
            sni_rules: Vec::new(),
            default_backend: Some(owa),
            http2: Http2::Enabled,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 60,
            idle_timeout_seconds: 0,
            drain_timeout_seconds: 60,
            udp_session_limit: 0,
        },
    );

    // SMTP and IMAP are separate listeners rather than paths, because they
    // are not HTTP at all.
    let smtp = add_backend(
        config,
        created,
        &format!("pool-{}-smtp", values.name),
        members_on(&values.members, "smtp", 25),
        LoadBalancingAlgorithm::RoundRobin,
        Some(banner_check("220")),
        ConnectionPooling::Enabled,
    );
    add_frontend(
        config,
        created,
        raw_frontend(
            &format!("{}-smtp", values.name),
            vip,
            25,
            smtp,
            // The backend decides relay permission by client address, so it
            // has to see the client rather than us (ADR-0043).
            ProxyProtocol::V2,
        ),
    );

    let imap = add_backend(
        config,
        created,
        &format!("pool-{}-imap", values.name),
        members_on(&values.members, "imap", 143),
        LoadBalancingAlgorithm::RoundRobin,
        Some(banner_check("* OK")),
        ConnectionPooling::Enabled,
    );
    add_frontend(
        config,
        created,
        raw_frontend(
            &format!("{}-imap", values.name),
            vip,
            143,
            imap,
            ProxyProtocol::V2,
        ),
    );
}

fn banner_check(expected: &str) -> HealthCheck {
    HealthCheck {
        probe: HealthProbe::SendExpect {
            send: ProbePayload::Text("\r\n".to_owned()),
            expect: ProbePayload::Text(expected.to_owned()),
            transport: TransportProtocol::Tcp,
        },
        interval_ms: 10_000,
        timeout_ms: 5_000,
        healthy_threshold: 2,
        unhealthy_threshold: 3,
    }
}

fn raw_frontend(
    id: &str,
    vip: &VipId,
    port: u16,
    backend: BackendId,
    proxy_protocol: ProxyProtocol,
) -> Frontend {
    Frontend {
        id: FrontendId::new(id),
        vip: vip.clone(),
        port,
        transport: TransportProtocol::Tcp,
        application: ApplicationProtocol::Raw,
        tls: None,
        proxy_protocol,
        routing_rules: Vec::new(),
        sni_rules: Vec::new(),
        default_backend: Some(backend),
        http2: Http2::Enabled,
        connect_timeout_seconds: 5,
        // Raw traffic carries no request to time out.
        request_timeout_seconds: 0,
        idle_timeout_seconds: 0,
        drain_timeout_seconds: 30,
        udp_session_limit: 0,
    }
}

fn build_smtp_relay(
    config: &mut Config,
    created: &mut Vec<Created>,
    values: &Common<'_>,
    vip: &VipId,
) {
    let backend = add_backend(
        config,
        created,
        &format!("pool-{}", values.name),
        members_on(&values.members, "smtp", 25),
        LoadBalancingAlgorithm::RoundRobin,
        Some(banner_check("220")),
        ConnectionPooling::Enabled,
    );

    add_frontend(
        config,
        created,
        raw_frontend(
            &format!("{}-smtp", values.name),
            vip,
            25,
            backend,
            // A relay decides who may send by client address. Without this it
            // sees only us and either relays for everyone or for nobody
            // (ADR-0043).
            ProxyProtocol::V2,
        ),
    );
}

fn build_generic_tcp(
    arguments: &Arguments,
    config: &mut Config,
    created: &mut Vec<Created>,
    values: &Common<'_>,
    vip: &VipId,
) {
    let port = arguments.port("port").unwrap_or(80);
    let backend = add_backend(
        config,
        created,
        &format!("pool-{}", values.name),
        values.members.clone(),
        LoadBalancingAlgorithm::RoundRobin,
        Some(HealthCheck {
            probe: HealthProbe::TcpConnect,
            interval_ms: 5_000,
            timeout_ms: 2_000,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        }),
        ConnectionPooling::Enabled,
    );

    add_frontend(
        config,
        created,
        raw_frontend(
            &format!("{}-tcp", values.name),
            vip,
            port,
            backend,
            ProxyProtocol::Disabled,
        ),
    );
}
