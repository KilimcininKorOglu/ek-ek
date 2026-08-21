// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration domain model, serialisation and validation.
//!
//! This is the base layer. It depends on no other workspace crate, so every
//! other layer can use its types without creating a dependency cycle.
//!
//! Error values carry a stable code and structured parameters, never a
//! user-facing string, because the UI layer performs the translation.
//!
//! # What the model is built from
//!
//! The types here name what an operator has in mind: a VIP, a frontend, a
//! backend pool, a health check, a certificate. They are not a rendering of
//! another product's configuration file. There is no ACL language, no request
//! rewriting and no stick table, and importing a `haproxy.cfg` is not a goal
//! (ADR-0005).
//!
//! # No display text lives here
//!
//! No field holds a label, a description or a message. Every enum serialises
//! to a stable identifier, and the presentation layer turns that identifier
//! into a translation key such as `config.transport.tcp`. That is what lets
//! the same configuration render in Turkish and in English without the model
//! knowing either language (ADR-0015).
//!
//! # What is deliberately absent
//!
//! A VIP carries no VRID and no VRRP priority. Both are computed from the
//! preferred node and the node list, because a number the product can derive
//! is a number the operator should never have to own.

pub mod backend;
pub mod certificate;
pub mod config;
pub mod frontend;
pub mod health;
pub mod i18n;
pub mod id;
pub mod node;
pub mod template;
pub mod validation;
pub mod vip;

pub use backend::{
    AdminState, Backend, BackendMember, ConnectionPooling, LoadBalancingAlgorithm, SameSitePolicy,
    SessionStickiness,
};
pub use certificate::{
    Certificate, CertificateSource, CertificateValidity, DnsProvider, DnsProviderConnection,
    TsigAlgorithm,
};
pub use config::{Config, SchemaVersion};
pub use frontend::{
    ApplicationProtocol, Frontend, ProxyProtocol, RoutingRule, SniRule, TlsPolicyLevel,
    TlsSettings, TransportProtocol,
};
pub use health::{DnsRecordType, HealthCheck, HealthProbe, ProbePayload};
pub use i18n::{Catalog, Dialog, DialogKeys};
pub use id::{
    BackendId, CertificateId, DnsProviderId, FrontendId, MemberId, NodeId, SecretId, TemplateId,
    VipId,
};
pub use node::{Node, NodeRole};
pub use template::{
    Applied, Argument, Arguments, Created, CreatedKind, Parameter, ParameterKind, Template,
    UserTemplate, Verification, apply, embedded, embedded_by_id, from_frontend, undo,
};
pub use validation::{
    ErrorCode, FieldPath, ParameterValue, PathSegment, ValidationError, ValidationErrors, validate,
    validate_vip_removal,
};
pub use vip::Vip;
