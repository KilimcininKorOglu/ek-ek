// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The channel two nodes talk over.
//!
//! Both ends present a certificate and both ends check the other's. That is
//! the whole point: peer traffic carries configuration and private keys, so a
//! connection nobody authenticated is a connection that hands them to whoever
//! dialled (ADR-0008).
//!
//! # What is checked
//!
//! - The certificate was signed by this cluster's authority, and by no other.
//! - It has not run out and has started.
//! - The caller presented one at all.
//! - The answering node is the one the caller meant to reach, by name.
//! - The caller reads the same config schema this node does.
//!
//! The name check is by name and never by address. A node keeps its identity
//! when its address changes (ADR-0082), and an address proves nothing anyway:
//! anybody can dial from anywhere.
//!
//! # Why the sockets are async
//!
//! Raft rides this channel (ADR-0083). A leader replicates to every follower
//! at once and waits on whichever answers first, which is what an async
//! runtime is for. The TLS is the same OpenSSL the rest of the tree speaks,
//! so no second TLS stack enters the tree (ADR-0068).

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ek_ek_config::NodeId;
use ek_ek_store::Secret;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_openssl::SslStream;

use crate::authority::identity_of;
use crate::error::{Failure, Reason, crypto};
use crate::message::{
    Answer, Ask, Call, HealthAnswer, HealthAsk, Hello, HelloAnswer, NO_HELLO, NO_SERVICE, PROTOCOL,
    Refusal, Reply, UNREADABLE, WRONG_PROTOCOL, WRONG_SCHEMA,
};
use crate::wire::{MOST_LINE_BYTES, decode, encode};

/// The port a node listens for its peers on.
///
/// Not a registered number and not one an operator picks per node: every node
/// in a cluster has to agree on it, and a per-node setting would be a way to
/// build a cluster where half the nodes cannot reach the other half.
pub const DEFAULT_PORT: u16 = 7373;

/// How long a peer has to finish what it started.
///
/// Ten seconds covers a handshake and a single exchange on any network this
/// product runs on. Without it a peer that connects and then says nothing
/// holds the socket for as long as it likes.
pub const PATIENCE: Duration = Duration::from_secs(10);

/// What one node needs to speak to its peers.
///
/// Its `Debug` prints none of it. Two of the three fields are public material,
/// but printing them beside a redacted key invites somebody to relax the rule
/// for the other field too.
#[derive(Clone)]
pub struct Credentials {
    /// The cluster authority, and the only one either end trusts.
    pub authority_pem: String,
    /// This node's own certificate.
    pub certificate_pem: String,
    /// The key that certificate was issued against.
    pub key_pem: Secret,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Credentials")
            .finish_non_exhaustive()
    }
}

/// Something a node answers calls with.
///
/// The body is opaque here. A service defines what it takes and what it
/// returns; this crate only carries it and says who called (ADR-0083).
pub trait Service: Send + Sync + 'static {
    /// Answers one call.
    ///
    /// # Errors
    ///
    /// Returns a failure the caller receives as a refusal, naming the reason.
    fn call(
        &self,
        from: &NodeId,
        service: &str,
        body: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Failure>> + Send + '_>>;
}

/// A service that answers nothing.
///
/// What a node runs before it joins a cluster: it still proves who it is and
/// still answers a health question, and every call is refused by name.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoServices;

impl Service for NoServices {
    fn call(
        &self,
        _from: &NodeId,
        service: &str,
        _body: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, Failure>> + Send + '_>> {
        let named = service.to_owned();
        Box::pin(async move {
            Err(Failure::new(
                Reason::Protocol,
                format!("this node runs no {named} service"),
            ))
        })
    }
}

/// A node that answers its peers.
pub struct Listener {
    socket: TcpListener,
    acceptor: SslAcceptor,
    node: NodeId,
    schema_version: u32,
    service: Arc<dyn Service>,
}

/// One connection that was served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    /// Which node called, read out of the certificate it presented.
    pub caller: NodeId,
    /// How many calls it made before it went away.
    pub calls: usize,
}

impl Listener {
    /// Binds and prepares to answer peers.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Network`] when the address cannot be bound and
    /// [`Reason::Crypto`] when the credentials do not build an acceptor.
    pub async fn bind(
        address: impl ToSocketAddrs,
        node: &NodeId,
        schema_version: u32,
        credentials: &Credentials,
        service: Arc<dyn Service>,
    ) -> Result<Self, Failure> {
        let socket = TcpListener::bind(address).await.map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("the peer port could not be bound: {error}"),
            )
        })?;

        Ok(Self {
            socket,
            acceptor: acceptor(credentials)?,
            node: node.clone(),
            schema_version,
            service,
        })
    }

    /// The address this listener actually took.
    ///
    /// Asked for rather than assumed, because a test binds port zero and the
    /// operating system chooses.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Network`] when the socket cannot say.
    pub fn address(&self) -> Result<std::net::SocketAddr, Failure> {
        self.socket.local_addr().map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("the peer port could not be read back: {error}"),
            )
        })
    }

    /// Accepts one peer, answers it until it goes away, and returns who it was.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Rejected`] when the handshake failed, which is what a
    /// certificate from another authority, an expired one, and no certificate
    /// at all all produce.
    pub async fn serve_one(&self) -> Result<Served, Failure> {
        let (stream, from) = self.socket.accept().await.map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("a peer connection could not be accepted: {error}"),
            )
        })?;

        let mut stream = accept(&self.acceptor, stream, from).await?;
        let caller = caller_of(&stream)?;
        let calls = self.converse(&mut stream, &caller).await?;
        Ok(Served { caller, calls })
    }

    /// Answers peers until the future is dropped.
    ///
    /// One task per connection. A peer that stops answering never holds up
    /// another one, which is what a leader replicating to two followers at
    /// once depends on.
    pub async fn serve_forever(self: Arc<Self>) {
        loop {
            let Ok((stream, from)) = self.socket.accept().await else {
                // The listening socket is gone. There is nothing left to
                // serve, and looping on a dead socket would spin.
                return;
            };
            let held = Arc::clone(&self);
            tokio::spawn(async move {
                match accept(&held.acceptor, stream, from).await {
                    Ok(mut stream) => match caller_of(&stream) {
                        Ok(caller) => {
                            if let Err(failure) = held.converse(&mut stream, &caller).await {
                                log::debug!("peer {} left: {failure}", caller.as_str());
                            }
                        }
                        Err(failure) => log::warn!("a peer at {from} was refused: {failure}"),
                    },
                    Err(failure) => log::warn!("a peer at {from} was refused: {failure}"),
                }
            });
        }
    }

    /// Reads the opening line, then answers whatever follows.
    async fn converse(
        &self,
        stream: &mut SslStream<TcpStream>,
        caller: &NodeId,
    ) -> Result<usize, Failure> {
        let mut reader = BufReader::new(stream);
        let mut greeted = false;
        let mut calls = 0;

        loop {
            let Some(line) = read_line(&mut reader).await? else {
                return Ok(calls);
            };

            let answer = match decode::<Ask>(&line) {
                // Said by name rather than by silence. A peer running a newer
                // release has to be able to tell "you do not know this
                // message" from "you are not there".
                Err(failure) => refusal(UNREADABLE, failure.detail()),
                Ok(Ask::Hello(hello)) => match self.greet(&hello) {
                    Ok(answer) => {
                        greeted = true;
                        answer
                    }
                    Err(refused) => {
                        write_line(&mut reader, &refused).await?;
                        return Ok(calls);
                    }
                },
                Ok(_) if !greeted => {
                    let refused = refusal(NO_HELLO, "a peer spoke before it said hello");
                    write_line(&mut reader, &refused).await?;
                    return Ok(calls);
                }
                Ok(Ask::Health(_)) => Answer::Health(HealthAnswer {
                    protocol: PROTOCOL.to_owned(),
                    node: self.node.as_str().to_owned(),
                }),
                Ok(Ask::Call(Call { service, body })) => {
                    calls += 1;
                    match self.service.call(caller, &service, body).await {
                        Ok(body) => Answer::Reply(Reply { body }),
                        Err(failure) => refusal(NO_SERVICE, failure.detail()),
                    }
                }
            };

            write_line(&mut reader, &answer).await?;
        }
    }

    /// Decides whether a caller may speak to this node at all.
    fn greet(&self, hello: &Hello) -> Result<Answer, Answer> {
        if hello.protocol != PROTOCOL {
            return Err(refusal(
                WRONG_PROTOCOL,
                &format!(
                    "this node speaks {PROTOCOL} and the caller speaks {}",
                    hello.protocol
                ),
            ));
        }
        // Refused here rather than when a record arrives. A node that cannot
        // read what the cluster holds must stop before it takes a single log
        // record, so the fault is one connection and not a half joined node
        // (ADR-0019, ADR-0083).
        if hello.schema_version != self.schema_version {
            return Err(refusal(
                WRONG_SCHEMA,
                &format!(
                    "this node reads config schema {} and the caller reads {}",
                    self.schema_version, hello.schema_version
                ),
            ));
        }
        Ok(Answer::Hello(HelloAnswer {
            protocol: PROTOCOL.to_owned(),
            schema_version: self.schema_version,
            node: self.node.as_str().to_owned(),
        }))
    }
}

/// An open connection to one peer.
pub struct Peer {
    stream: BufReader<SslStream<TcpStream>>,
    node: NodeId,
}

impl Peer {
    /// Dials a peer and completes the opening exchange.
    ///
    /// `expect` is the node the caller means to reach. The handshake fails
    /// unless the certificate on the other side carries that name, so a peer
    /// that answers is the peer that was meant.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Network`] when the peer cannot be reached,
    /// [`Reason::Rejected`] when its certificate is refused, and
    /// [`Reason::Protocol`] when it answers something this release cannot read
    /// or names a different node than the one it proved it was.
    pub async fn dial(
        address: impl ToSocketAddrs,
        expect: &NodeId,
        schema_version: u32,
        credentials: &Credentials,
    ) -> Result<Self, Failure> {
        let socket = TcpStream::connect(address).await.map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("the peer could not be reached: {error}"),
            )
        })?;

        let connector = connector(credentials)?;
        let configuration = connector
            .configure()
            .map_err(crypto("the peer connection could not be configured"))?;
        let ssl = configuration
            .into_ssl(expect.as_str())
            .map_err(crypto("the peer name could not be set"))?;
        let mut stream = SslStream::new(ssl, socket)
            .map_err(crypto("the peer connection could not be built"))?;
        Pin::new(&mut stream).connect().await.map_err(|error| {
            Failure::new(
                Reason::Rejected,
                format!(
                    "{} did not prove it is who it claims: {error}",
                    expect.as_str()
                ),
            )
        })?;

        let mut peer = Self {
            stream: BufReader::new(stream),
            node: expect.clone(),
        };

        let greeting = peer
            .exchange(&Ask::Hello(Hello {
                protocol: PROTOCOL.to_owned(),
                schema_version,
            }))
            .await?;
        match greeting {
            Answer::Hello(answer) => {
                // The name in the message and the name in the certificate have
                // to agree. Only the second one was signed by anything, so a
                // disagreement means the message is not to be trusted.
                if answer.node != expect.as_str() {
                    return Err(Failure::new(
                        Reason::Protocol,
                        format!(
                            "the certificate says {} and the answer says {}",
                            expect.as_str(),
                            answer.node
                        ),
                    ));
                }
                Ok(peer)
            }
            Answer::Refused(refused) => Err(Failure::new(
                Reason::Rejected,
                format!("{}: {}", refused.reason, refused.detail),
            )),
            other => Err(Failure::new(
                Reason::Protocol,
                format!("a peer answered hello with {other:?}"),
            )),
        }
    }

    /// Which node is on the other end.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Asks whether the peer is there.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Protocol`] when the answer is not a health answer, or
    /// names a different node than the one the certificate proved.
    pub async fn health(&mut self) -> Result<HealthAnswer, Failure> {
        match self
            .exchange(&Ask::Health(HealthAsk {
                protocol: PROTOCOL.to_owned(),
            }))
            .await?
        {
            Answer::Health(answer) if answer.node == self.node.as_str() => Ok(answer),
            Answer::Health(answer) => Err(Failure::new(
                Reason::Protocol,
                format!(
                    "the certificate says {} and the answer says {}",
                    self.node.as_str(),
                    answer.node
                ),
            )),
            Answer::Refused(refused) => Err(Failure::new(
                Reason::Protocol,
                format!("{}: {}", refused.reason, refused.detail),
            )),
            other => Err(Failure::new(
                Reason::Protocol,
                format!("a peer answered a health question with {other:?}"),
            )),
        }
    }

    /// Calls a named service on the peer.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Protocol`] when the peer refuses the call or answers
    /// something else, and [`Reason::Network`] when it goes away.
    pub async fn call(
        &mut self,
        service: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, Failure> {
        match self
            .exchange(&Ask::Call(Call {
                service: service.to_owned(),
                body,
            }))
            .await?
        {
            Answer::Reply(reply) => Ok(reply.body),
            Answer::Refused(refused) => Err(Failure::new(
                Reason::Protocol,
                format!("{}: {}", refused.reason, refused.detail),
            )),
            other => Err(Failure::new(
                Reason::Protocol,
                format!("a peer answered a call with {other:?}"),
            )),
        }
    }

    async fn exchange(&mut self, ask: &Ask) -> Result<Answer, Failure> {
        write_line(&mut self.stream, ask).await?;
        let line = read_line(&mut self.stream).await?.ok_or_else(|| {
            Failure::new(
                Reason::Network,
                "the peer closed the connection without answering".to_owned(),
            )
        })?;
        decode(&line)
    }
}

/// Asks one peer whether it is there, on a connection of its own.
///
/// # Errors
///
/// Returns whatever [`Peer::dial`] and [`Peer::health`] return.
pub async fn ask_health(
    address: impl ToSocketAddrs,
    expect: &NodeId,
    schema_version: u32,
    credentials: &Credentials,
) -> Result<HealthAnswer, Failure> {
    let mut peer = Peer::dial(address, expect, schema_version, credentials).await?;
    peer.health().await
}

fn refusal(reason: &str, detail: &str) -> Answer {
    Answer::Refused(Refusal {
        reason: reason.to_owned(),
        detail: detail.to_owned(),
    })
}

/// Completes the server side of a handshake, with a bound on how long it takes.
async fn accept(
    acceptor: &SslAcceptor,
    stream: TcpStream,
    from: std::net::SocketAddr,
) -> Result<SslStream<TcpStream>, Failure> {
    let ssl = Ssl::new(acceptor.context()).map_err(crypto("no handshake could be started"))?;
    let mut stream =
        SslStream::new(ssl, stream).map_err(crypto("the connection could not be wrapped"))?;

    // Bounded on purpose. A caller that opens a socket and never finishes the
    // handshake would otherwise hold it for as long as it likes.
    let finished = tokio::time::timeout(PATIENCE, Pin::new(&mut stream).accept())
        .await
        .map_err(|_| {
            Failure::new(
                Reason::Rejected,
                format!("a peer at {from} never finished its handshake"),
            )
        })?;
    finished.map_err(|error| {
        Failure::new(
            Reason::Rejected,
            format!("a peer at {from} was refused: {error}"),
        )
    })?;

    Ok(stream)
}

/// The trust store both ends verify against: this cluster's authority alone.
fn trust(authority_pem: &str) -> Result<X509Store, Failure> {
    let authority = X509::from_pem(authority_pem.as_bytes())
        .map_err(crypto("the cluster authority does not read back"))?;
    let mut builder = X509StoreBuilder::new().map_err(crypto("no trust store"))?;
    builder
        .add_cert(authority)
        .map_err(crypto("the cluster authority could not be trusted"))?;
    Ok(builder.build())
}

fn own_material(credentials: &Credentials) -> Result<(X509, PKey<Private>), Failure> {
    let certificate = X509::from_pem(credentials.certificate_pem.as_bytes())
        .map_err(crypto("this node's certificate does not read back"))?;
    let key = PKey::private_key_from_pem(credentials.key_pem.expose())
        .map_err(crypto("this node's key does not read back"))?;
    Ok((certificate, key))
}

/// The server side.
///
/// `FAIL_IF_NO_PEER_CERT` beside `PEER` is what makes a caller with no
/// certificate a refusal. `PEER` alone asks for one and accepts the connection
/// when none arrives, which is the setting that makes mutual TLS look
/// configured and be optional.
fn acceptor(credentials: &Credentials) -> Result<SslAcceptor, Failure> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(crypto("no acceptor could be built"))?;
    // Every peer is this same product. There is no old client to keep, so
    // there is no reason to offer anything below the newest version.
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(crypto("the version floor could not be set"))?;
    builder.set_cert_store(trust(&credentials.authority_pem)?);
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    let (certificate, key) = own_material(credentials)?;
    builder
        .set_certificate(&certificate)
        .map_err(crypto("this node's certificate was not accepted"))?;
    builder
        .set_private_key(&key)
        .map_err(crypto("this node's key was not accepted"))?;
    builder.check_private_key().map_err(crypto(
        "this node's certificate and key do not belong together",
    ))?;

    Ok(builder.build())
}

/// The client side.
fn connector(credentials: &Credentials) -> Result<SslConnector, Failure> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(crypto("no connector could be built"))?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(crypto("the version floor could not be set"))?;
    builder.set_cert_store(trust(&credentials.authority_pem)?);
    builder.set_verify(SslVerifyMode::PEER);

    let (certificate, key) = own_material(credentials)?;
    builder
        .set_certificate(&certificate)
        .map_err(crypto("this node's certificate was not accepted"))?;
    builder
        .set_private_key(&key)
        .map_err(crypto("this node's key was not accepted"))?;
    builder.check_private_key().map_err(crypto(
        "this node's certificate and key do not belong together",
    ))?;

    Ok(builder.build())
}

/// Who is on the other end, read out of the certificate they presented.
fn caller_of(stream: &SslStream<TcpStream>) -> Result<NodeId, Failure> {
    let certificate = stream.ssl().peer_certificate().ok_or_else(|| {
        Failure::new(
            Reason::Rejected,
            "a peer completed a handshake without presenting a certificate".to_owned(),
        )
    })?;
    identity_of(&certificate)
}

/// Reads one line, or nothing when the peer went away.
///
/// Bounded as it reads rather than after. A peer that never sends a newline
/// would otherwise spend this node's memory for free, and a check applied to
/// the finished line would already have paid for it. The limit is not
/// configurable, because an operator raising it would raise it for an attacker
/// too.
async fn read_line<R>(reader: &mut R) -> Result<Option<String>, Failure>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let bytes = tokio::time::timeout(PATIENCE, take_line(reader))
        .await
        .map_err(|_| {
            Failure::new(
                Reason::Network,
                "a peer said nothing for longer than the channel waits".to_owned(),
            )
        })??;

    let Some(bytes) = bytes else {
        return Ok(None);
    };
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| Failure::new(Reason::Protocol, format!("a peer sent no text: {error}")))
}

async fn take_line<R>(reader: &mut R) -> Result<Option<Vec<u8>>, Failure>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("a peer message could not be read: {error}"),
            )
        })?;

        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(Failure::new(
                    Reason::Network,
                    "a peer went away in the middle of a message".to_owned(),
                ))
            };
        }

        match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => {
                line.extend_from_slice(&available[..=at]);
                reader.consume(at + 1);
                return Ok(Some(line));
            }
            None => {
                let used = available.len();
                line.extend_from_slice(available);
                reader.consume(used);
            }
        }

        if line.len() as u64 > MOST_LINE_BYTES {
            return Err(Failure::new(
                Reason::Protocol,
                format!("a peer sent more than {MOST_LINE_BYTES} bytes without a newline"),
            ));
        }
    }
}

async fn write_line<W, T>(writer: &mut W, message: &T) -> Result<(), Failure>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let line = encode(message)?;
    writer.write_all(line.as_bytes()).await.map_err(|error| {
        Failure::new(
            Reason::Network,
            format!("a peer message could not be sent: {error}"),
        )
    })?;
    writer.flush().await.map_err(|error| {
        Failure::new(
            Reason::Network,
            format!("a peer message could not be flushed: {error}"),
        )
    })
}
