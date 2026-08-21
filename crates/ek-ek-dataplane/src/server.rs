// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Assembling the pingora server.
//!
//! Listeners are declared before the server runs and cannot be added later,
//! so the frontends in the first delivery decide what this process listens
//! on. A frontend appearing or disappearing needs a replacement process with
//! socket handover, which the agent drives (ADR-0002).
//!
//! Everything else, backends included, changes inside this process.

use std::sync::Arc;

use async_trait::async_trait;
use ek_ek_config::{ApplicationProtocol, Config, TransportProtocol};
use ek_ek_ipc::DataPlaneState;
use pingora::apps::HttpServerOptions;
use pingora::server::{Server, ShutdownWatch};
use pingora::services::background::background_service;

use crate::balance::Balancer;
use crate::error::{Error, ErrorKind, Result};
use crate::link::AgentLink;
use crate::proxy::Proxy;

/// Where a frontend listens.
///
/// Returned so a caller can report exactly what was bound rather than
/// guessing from the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The frontend this belongs to.
    pub frontend: String,
    /// The address in `host:port` form.
    pub address: String,
    /// Whether this listener accepts cleartext HTTP/2 (ADR-0059).
    pub http2: bool,
}

/// Works out what a configuration says to listen on.
///
/// # Errors
///
/// Fails when a frontend names a VIP that is not defined. Validation catches
/// that first, so reaching it here means something delivered a configuration
/// without checking it.
pub fn bindings(config: &Config) -> Result<Vec<Binding>> {
    let mut bindings = Vec::new();

    for frontend in &config.frontends {
        // The UDP path is hand written and does not go through pingora, so
        // its frontends are not listeners here (ADR-0017).
        if frontend.transport != TransportProtocol::Tcp {
            continue;
        }
        // Only HTTP frontends have somewhere to go yet. A raw or passthrough
        // frontend is silently skipped nowhere: it simply has no listener
        // until the path that serves it exists.
        if frontend.application != ApplicationProtocol::Http {
            continue;
        }

        let vip = config
            .vips
            .iter()
            .find(|vip| vip.id == frontend.vip)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Listener,
                    format!(
                        "frontend {} names vip {}, which is not in the configuration",
                        frontend.id.as_str(),
                        frontend.vip.as_str()
                    ),
                )
            })?;

        bindings.push(Binding {
            frontend: frontend.id.as_str().to_owned(),
            address: format!("{}:{}", vip.address, frontend.port),
            http2: frontend.http2.is_enabled(),
        });
    }

    Ok(bindings)
}

/// Builds the server: the listeners, plus the agent link as a background
/// service.
///
/// The link runs inside the server rather than beside it, so its lifetime is
/// the server's and a shutdown stops both.
///
/// # Errors
///
/// Fails when the server cannot be built or a frontend names a missing VIP.
pub fn build(link: AgentLink) -> Result<Server> {
    let live = link.live();
    let status = link.status();

    let mut server = Server::new(None).map_err(|error| {
        Error::new(
            ErrorKind::Listener,
            format!("the server could not be created: {error}"),
        )
    })?;
    server.bootstrap();

    // One balancer for the whole process. The open connection counts belong
    // to what this process is doing, not to a configuration, so they survive
    // every swap.
    let balancer = Arc::new(Balancer::new());

    let bindings = bindings(&live.load().config)?;
    for binding in bindings {
        let proxy = Proxy::new(
            binding.frontend.clone(),
            Arc::clone(&live),
            Arc::clone(&status),
            Arc::clone(&balancer),
        );
        let mut service = pingora::proxy::http_proxy_service_with_name(
            &server.configuration,
            proxy,
            &format!("frontend {}", binding.frontend),
        );

        // Cleartext HTTP/2 is told apart from HTTP/1.1 by the connection
        // preface, so turning it on leaves HTTP/1.1 clients untouched
        // (ADR-0059).
        // The struct is non-exhaustive, so it is built by default and then
        // adjusted rather than written out field by field.
        let mut options = HttpServerOptions::default();
        options.h2c = binding.http2;
        if let Some(logic) = service.app_logic_mut() {
            logic.server_options = Some(options);
        }

        service.add_tcp(&binding.address);
        server.add_service(service);
    }

    status.set_state(DataPlaneState::Serving);
    server.add_service(background_service("node-agent link", LinkService { link }));

    Ok(server)
}

/// Runs the agent link for as long as the server runs.
struct LinkService {
    link: AgentLink,
}

#[async_trait]
impl pingora::services::background::BackgroundService for LinkService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let (stop_sender, stop) = tokio::sync::watch::channel(false);
        let link = self.link.run(stop);

        tokio::select! {
            () = link => {}
            _ = shutdown.changed() => {
                let _ = stop_sender.send(true);
            }
        }
    }
}
