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
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;
use pingora::server::{Server, ShutdownWatch};
use pingora::services::background::background_service;
use pingora::services::listening::Service;

use crate::error::{Error, ErrorKind, Result};
use crate::link::AgentLink;
use crate::live::{LiveConfig, Status};

/// Answers a request from the live configuration.
///
/// Real proxying arrives with the HTTP and TCP paths. What this does now is
/// prove the shape: one snapshot is taken per request and the request is
/// finished on it, whatever happens to the configuration meanwhile.
#[derive(Debug)]
pub struct Endpoint {
    live: Arc<LiveConfig>,
    status: Arc<Status>,
}

impl Endpoint {
    /// Builds an endpoint serving from this configuration.
    #[must_use]
    pub fn new(live: Arc<LiveConfig>, status: Arc<Status>) -> Self {
        Self { live, status }
    }
}

#[async_trait]
impl ServeHttp for Endpoint {
    async fn response(&self, _session: &mut ServerSession) -> http::Response<Vec<u8>> {
        // One read, held for the whole request. Reading twice would let a
        // swap land in between and answer half the request from each.
        let live = self.live.load();
        self.status.request_handled();

        let body = format!(
            "generation={}\nbackends={}\n",
            live.generation,
            live.config.backends.len()
        );

        http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(body.into_bytes())
            .unwrap_or_else(|_| {
                // Every part above is a constant, so this cannot fail. An
                // empty 500 is still better than a panic on the traffic path.
                let mut fallback = http::Response::new(Vec::new());
                *fallback.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                fallback
            })
    }
}

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

    let bindings = bindings(&live.load().config)?;
    for binding in bindings {
        let mut service = Service::new(
            format!("frontend {}", binding.frontend),
            pingora::apps::http_app::HttpServer::new_app(Endpoint::new(
                Arc::clone(&live),
                Arc::clone(&status),
            )),
        );
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
