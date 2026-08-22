// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The HTTP reverse proxy.
//!
//! One instance serves one frontend. It reads the live configuration once per
//! request, picks a member, and forwards. A configuration swap landing mid
//! request never touches it: the snapshot is held for the whole request
//! (ADR-0009).
//!
//! # What a client cannot decide
//!
//! An incoming `X-Forwarded-For` is written over, never appended to. A client
//! can put anything in that header, so trusting it would let anyone claim any
//! address, and every decision downstream that reads it (an access log, a
//! backend's own allow list) would be reading the client's own claim.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ek_ek_config::{
    ApplicationProtocol, Backend, ConnectionPooling, Frontend, RoutingRule, RuleAction,
};
use pingora::http::ResponseHeader;
use pingora::prelude::HttpPeer;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::Peer;
use pingora::{Error, ErrorType};

use crate::live::{Live, LiveConfig, Status};
use crate::sticky::{self, Signer};

/// Header carrying the client address to the backend.
const FORWARDED_FOR: &str = "X-Forwarded-For";
/// Header carrying the scheme the client used.
const FORWARDED_PROTO: &str = "X-Forwarded-Proto";
/// Header carrying the host the client asked for.
const FORWARDED_HOST: &str = "X-Forwarded-Host";

/// Answered when the pool has nobody able to take the request.
///
/// A closed connection would look like a network fault and send an operator
/// looking in the wrong place. A status code says which side is at fault.
const NO_MEMBER: u16 = 503;
/// Answered when the backend did not finish in time.
const TIMED_OUT: u16 = 504;

/// What one request carries while it is being proxied.
///
/// Everything here is decided once, from one snapshot. Holding the decision
/// rather than the configuration is what makes a second read impossible: by
/// the time the request reaches the upstream, there is nothing left to look
/// up (ADR-0009).
pub struct RequestContext {
    /// Where the request goes, already built.
    peer: Option<Box<HttpPeer>>,
    /// Pool and member chosen, kept so the open connection count can be
    /// decremented when the request finishes.
    chosen: Option<(String, String)>,
    /// The `Set-Cookie` line to add, when this request needs one.
    ///
    /// Built in the request filter, from the same snapshot everything else
    /// was decided from, and written when the answer comes back.
    set_cookie: Option<String>,
}

/// Proxies one frontend.
pub struct Proxy {
    /// Which frontend this serves.
    frontend: String,
    /// The live configuration, shared with every other frontend.
    live: Arc<LiveConfig>,
    /// Counters reported to the agent.
    status: Arc<Status>,
    /// Connection counts and the round robin cursor.
    balancer: Arc<crate::balance::Balancer>,
}

impl Proxy {
    /// Builds a proxy for one frontend.
    #[must_use]
    pub fn new(
        frontend: String,
        live: Arc<LiveConfig>,
        status: Arc<Status>,
        balancer: Arc<crate::balance::Balancer>,
    ) -> Self {
        Self {
            frontend,
            live,
            status,
            balancer,
        }
    }

    /// Finds this frontend in a snapshot.
    ///
    /// Returns `None` when the frontend has been removed by a configuration
    /// change. The listener is still bound, because pingora cannot unbind
    /// one, so the request has to be answered rather than dropped.
    fn frontend<'a>(&self, live: &'a Live) -> Option<&'a Frontend> {
        live.config
            .frontends
            .iter()
            .find(|frontend| frontend.id.as_str() == self.frontend)
    }
}

/// Which pool a request goes to.
///
/// Host and path matching arrives with T-070. Until then a rule that matches
/// everything is honoured, which is what a redirect listener is made of
/// (ADR-0057), and everything else falls through to the default pool.
fn decide<'a>(frontend: &'a Frontend) -> Decision<'a> {
    for rule in &frontend.routing_rules {
        if !matches_everything(rule) {
            continue;
        }
        return match &rule.action {
            RuleAction::Proxy { backend } => Decision::Pool(backend.as_str()),
            RuleAction::Redirect { status } => Decision::Redirect(status.code()),
        };
    }

    frontend
        .default_backend
        .as_ref()
        .map_or(Decision::Nowhere, |backend| {
            Decision::Pool(backend.as_str())
        })
}

/// Whether a rule takes every request.
fn matches_everything(rule: &RoutingRule) -> bool {
    rule.host_pattern.is_none() && rule.path_prefix.is_none()
}

/// What is done with a request.
enum Decision<'a> {
    /// Forward it to this pool.
    Pool(&'a str),
    /// Answer it with this redirect status.
    Redirect(u16),
    /// Nowhere to send it.
    Nowhere,
}

/// Finds a pool by identity.
fn pool<'a>(live: &'a Live, name: &str) -> Option<&'a Backend> {
    live.config
        .backends
        .iter()
        .find(|pool| pool.id.as_str() == name)
}

/// The address a request came from.
///
/// A session with no peer address is answered as if it came from an unknown
/// address rather than refused: the request is real, only its origin is
/// unreadable.
fn client_address(session: &Session) -> IpAddr {
    session
        .client_addr()
        .and_then(|address| address.as_inet())
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |inet| inet.ip())
}

/// Every `Cookie` header line a request carries.
///
/// A client may send the cookies in one line or in several, so all of them
/// are read rather than only the first.
fn cookie_lines(session: &Session) -> impl Iterator<Item = &str> {
    session
        .req_header()
        .headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
}

/// Builds the redirect answer.
fn redirect_to_https(session: &Session, code: u16) -> Option<ResponseHeader> {
    let host = session
        .req_header()
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())?;
    // The port is dropped: a redirect to HTTPS on the port the plaintext
    // listener happened to use would point back at plaintext.
    let name = host.split(':').next().unwrap_or(host);
    let path = session
        .req_header()
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), std::string::ToString::to_string);

    let mut header = ResponseHeader::build(code, Some(2)).ok()?;
    header
        .insert_header(http::header::LOCATION, format!("https://{name}{path}"))
        .ok()?;
    header
        .insert_header(http::header::CONTENT_LENGTH, "0")
        .ok()?;
    Some(header)
}

/// Answers a request without reaching a backend.
///
/// Every answer produced here has an empty body, so the header is the whole
/// response and the stream ends with it.
async fn answer(session: &mut Session, header: ResponseHeader) {
    let _ = session.write_response_header(Box::new(header), true).await;
}

/// Builds a bare status answer.
fn bare(code: u16) -> Option<ResponseHeader> {
    let mut header = ResponseHeader::build(code, Some(1)).ok()?;
    header
        .insert_header(http::header::CONTENT_LENGTH, "0")
        .ok()?;
    Some(header)
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            peer: None,
            chosen: None,
            set_cookie: None,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        // The only place the live configuration is read. Everything the rest
        // of the request needs is decided here and carried in the context, so
        // there is no second read for a swap to land in between (ADR-0009).
        let live = self.live.load();
        self.status.request_handled();

        let Some(frontend) = self.frontend(&live) else {
            if let Some(header) = bare(NO_MEMBER) {
                answer(session, header).await;
            }
            return Ok(true);
        };

        if frontend.application != ApplicationProtocol::Http {
            if let Some(header) = bare(NO_MEMBER) {
                answer(session, header).await;
            }
            return Ok(true);
        }

        let name = match decide(frontend) {
            Decision::Redirect(code) => {
                // No backend is contacted, so no plaintext request ever
                // leaves this process (ADR-0057).
                let header = redirect_to_https(session, code).or_else(|| bare(400));
                if let Some(header) = header {
                    answer(session, header).await;
                }
                return Ok(true);
            }
            Decision::Nowhere => {
                if let Some(header) = bare(NO_MEMBER) {
                    answer(session, header).await;
                }
                return Ok(true);
            }
            Decision::Pool(name) => name,
        };

        let Some(pool) = pool(&live, name) else {
            if let Some(header) = bare(NO_MEMBER) {
                answer(session, header).await;
            }
            return Ok(true);
        };
        // Stickiness first: a client the pool has already answered goes back
        // to the same member, and only a client with no usable cookie is
        // distributed by the algorithm (ADR-0024).
        let sticky = sticky::settings(pool).and_then(|(cookie, policy)| {
            Signer::from_hex(&live.config.stickiness_key).map(|signer| (cookie, policy, signer))
        });

        let pinned = sticky.as_ref().and_then(|(cookie, _, signer)| {
            let value = sticky::read(cookie_lines(session), cookie)?;
            // Only members that can take traffic are offered, so a cookie
            // naming one that went out, or one that was removed from the
            // pool, matches nothing and falls through to the algorithm.
            signer.member_for(name, &self.balancer.eligible(pool), &value)
        });

        let member = match pinned {
            Some(member) => member,
            None => {
                let Some(member) =
                    self.balancer
                        .choose(pool, &live.ring(name), client_address(session))
                else {
                    // Nobody in the pool can take it. Saying so beats closing
                    // the connection, which would look like a network fault.
                    if let Some(header) = bare(NO_MEMBER) {
                        answer(session, header).await;
                    }
                    return Ok(true);
                };
                // A cookie is written only when the client did not arrive
                // with a usable one. Rewriting an already correct cookie on
                // every answer would put a header on every response for no
                // change.
                if let Some((cookie, policy, signer)) = sticky.as_ref() {
                    ctx.set_cookie = Some(sticky::set_cookie(
                        cookie,
                        &signer.token(name, member.id.as_str()),
                        *policy,
                        frontend.tls.is_some(),
                    ));
                }
                member
            }
        };

        self.balancer
            .opened(&self.frontend, name, member.id.as_str());
        ctx.chosen = Some((name.to_owned(), member.id.as_str().to_owned()));

        let address = SocketAddr::new(member.address, member.port);
        // TLS to the backend arrives with M4. Until then the hop is plain and
        // the SNI is empty rather than guessed.
        let mut peer = HttpPeer::new(address, false, String::new());
        let options = peer.get_mut_peer_options().ok_or_else(|| {
            Error::explain(ErrorType::InternalError, "peer has no options to set")
        })?;
        options.connection_timeout = Some(Duration::from_secs(u64::from(
            frontend.connect_timeout_seconds,
        )));
        // Zero means no limit, which is what an ActiveSync or IMAP IDLE
        // request needs (ADR-0058).
        let request_limit = frontend.request_timeout_seconds;
        if request_limit > 0 {
            options.read_timeout = Some(Duration::from_secs(u64::from(request_limit)));
        }
        if pool.connection_pooling == ConnectionPooling::Disabled {
            // NTLM binds authentication to the connection, so reuse would
            // hand one client's authenticated connection to another
            // (ADR-0045).
            options.idle_timeout = Some(Duration::ZERO);
        }

        ctx.peer = Some(Box::new(peer));
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        // Already decided. Choosing here instead would mean reading the live
        // configuration a second time within one request.
        ctx.peer
            .clone()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no peer was chosen"))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        // Overwritten, never appended to. Whatever the client sent under this
        // name is its own claim and carries no authority.
        upstream_request
            .insert_header(FORWARDED_FOR, client_address(session).to_string())
            .ok();
        // The request is forwarded as plain HTTP whatever the client used, so
        // this header is the only way a backend can tell how the client
        // reached the listener. It is read from the configuration rather than
        // from the connection: a listener terminates TLS or it does not, and
        // the client has no say in it.
        let scheme = if self
            .frontend(&self.live.load())
            .is_some_and(|frontend| frontend.tls.is_some())
        {
            "https"
        } else {
            "http"
        };
        upstream_request.insert_header(FORWARDED_PROTO, scheme).ok();

        if let Some(host) = session
            .req_header()
            .headers
            .get(http::header::HOST)
            .cloned()
        {
            upstream_request.insert_header(FORWARDED_HOST, host).ok();
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        // Appended rather than inserted: the application may set cookies of
        // its own, and replacing the header would drop them.
        if let Some(cookie) = ctx.set_cookie.take() {
            upstream_response
                .append_header(http::header::SET_COOKIE, cookie)
                .ok();
        }
        Ok(())
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&Error>, ctx: &mut Self::CTX) {
        // The count has to come down whether the request succeeded or not,
        // otherwise least connections would send every later request away
        // from a member that once failed.
        if let Some((pool, member)) = ctx.chosen.take() {
            self.balancer.closed(&self.frontend, &pool, &member);
        }
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &Error,
        _ctx: &mut Self::CTX,
    ) -> pingora::proxy::FailToProxy {
        let code = match error.etype() {
            ErrorType::HTTPStatus(code) => *code,
            // Nobody answered in time. That is a different fault from
            // nobody being there, and an operator reading a log needs to
            // tell them apart.
            ErrorType::ReadTimedout | ErrorType::WriteTimedout | ErrorType::ConnectTimedout => {
                TIMED_OUT
            }
            // Reachable but refusing, or not reachable at all.
            ErrorType::ConnectRefused | ErrorType::ConnectNoRoute | ErrorType::ConnectError => {
                NO_MEMBER
            }
            _ => 502,
        };

        if code > 0
            && let Some(header) = bare(code)
        {
            answer(session, header).await;
        }

        pingora::proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}
