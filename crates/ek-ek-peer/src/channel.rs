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
//!
//! The last one is by name and never by address. A node keeps its identity
//! when its address changes (ADR-0082), and an address proves nothing anyway:
//! anybody can dial from anywhere.
//!
//! # Why the sockets are blocking
//!
//! One health question and one answer, on a channel that is dialled rarely.
//! An async runtime here would buy nothing and would be a decision T-037 has
//! to make anyway, when Raft moves onto this channel.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use ek_ek_config::NodeId;
use ek_ek_store::Secret;
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;

use crate::authority::identity_of;
use crate::error::{Failure, Reason, crypto};
use crate::message::{Answer, Ask, HealthAnswer, HealthAsk, PROTOCOL, Refusal, UNREADABLE};
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
/// Its `Debug` prints none of it. Two of the three fields are public
/// material, but printing them beside a redacted key invites somebody to relax
/// the rule for the other field too.
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

/// A node that answers its peers.
pub struct Listener {
    socket: TcpListener,
    acceptor: SslAcceptor,
    node: NodeId,
}

/// One connection that was served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    /// Which node called, read out of the certificate it presented.
    pub caller: NodeId,
    /// What it asked, or nothing when the line was not a message.
    pub asked: Option<Ask>,
}

impl Listener {
    /// Binds and prepares to answer peers.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Network`] when the address cannot be bound and
    /// [`Reason::Crypto`] when the credentials do not build an acceptor.
    pub fn bind(
        address: impl ToSocketAddrs,
        node: &NodeId,
        credentials: &Credentials,
    ) -> Result<Self, Failure> {
        let socket = TcpListener::bind(address).map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("the peer port could not be bound: {error}"),
            )
        })?;

        Ok(Self {
            socket,
            acceptor: acceptor(credentials)?,
            node: node.clone(),
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
    pub fn address(&self) -> Result<SocketAddr, Failure> {
        self.socket.local_addr().map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("the peer port could not be read back: {error}"),
            )
        })
    }

    /// Accepts one peer, answers it, and returns who it was.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Rejected`] when the handshake failed, which is what a
    /// certificate from another authority, an expired one, and no certificate
    /// at all all produce.
    pub fn serve_one(&self) -> Result<Served, Failure> {
        let (stream, from) = self.socket.accept().map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("a peer connection could not be accepted: {error}"),
            )
        })?;
        set_patience(&stream)?;

        let mut stream = self.acceptor.accept(stream).map_err(|error| {
            Failure::new(
                Reason::Rejected,
                format!("a peer at {from} was refused: {error}"),
            )
        })?;

        let caller = caller_of(&stream)?;
        let line = read_line(&mut stream)?;

        let answer = match decode::<Ask>(&line) {
            Ok(Ask::Health(asked)) => {
                let answer = Answer::Health(HealthAnswer {
                    protocol: PROTOCOL.to_owned(),
                    node: self.node.as_str().to_owned(),
                });
                write_line(&mut stream, &answer)?;
                Served {
                    caller,
                    asked: Some(Ask::Health(asked)),
                }
            }
            Err(failure) => {
                // Said by name rather than by silence. A peer running a newer
                // release has to be able to tell "you do not know this
                // message" from "you are not there".
                let answer = Answer::Refused(Refusal {
                    reason: UNREADABLE.to_owned(),
                    detail: failure.detail().to_owned(),
                });
                write_line(&mut stream, &answer)?;
                Served {
                    caller,
                    asked: None,
                }
            }
        };

        Ok(answer)
    }
}

/// Asks one peer whether it is there.
///
/// `expect` is the node the caller means to reach. The handshake fails unless
/// the certificate on the other side carries that name, so a peer that
/// answers is the peer that was meant.
///
/// # Errors
///
/// Returns [`Reason::Network`] when the peer cannot be reached,
/// [`Reason::Rejected`] when its certificate is refused, and
/// [`Reason::Protocol`] when it answers something this release cannot read or
/// names a different node than the one it proved it was.
pub fn ask_health(
    address: impl ToSocketAddrs,
    expect: &NodeId,
    credentials: &Credentials,
) -> Result<HealthAnswer, Failure> {
    let socket = TcpStream::connect(address).map_err(|error| {
        Failure::new(
            Reason::Network,
            format!("the peer could not be reached: {error}"),
        )
    })?;
    set_patience(&socket)?;

    let configuration = connector(credentials)?
        .configure()
        .map_err(crypto("the peer connection could not be configured"))?;

    let mut stream = configuration
        .connect(expect.as_str(), socket)
        .map_err(|error| {
            Failure::new(
                Reason::Rejected,
                format!(
                    "{} did not prove it is who it claims: {error}",
                    expect.as_str()
                ),
            )
        })?;

    write_line(
        &mut stream,
        &Ask::Health(HealthAsk {
            protocol: PROTOCOL.to_owned(),
        }),
    )?;

    let line = read_line(&mut stream)?;
    match decode::<Answer>(&line)? {
        Answer::Health(answer) => {
            // The name in the message and the name in the certificate have to
            // agree. Only the second one was signed by anything, so a
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
            Ok(answer)
        }
        Answer::Refused(refusal) => Err(Failure::new(
            Reason::Protocol,
            format!("{}: {}", refusal.reason, refusal.detail),
        )),
    }
}

/// The trust store both ends verify against: this cluster's authority alone.
fn trust(authority_pem: &str) -> Result<openssl::x509::store::X509Store, Failure> {
    let authority = X509::from_pem(authority_pem.as_bytes())
        .map_err(crypto("the cluster authority does not read back"))?;
    let mut builder = X509StoreBuilder::new().map_err(crypto("no trust store"))?;
    builder
        .add_cert(authority)
        .map_err(crypto("the cluster authority could not be trusted"))?;
    Ok(builder.build())
}

fn own_material(
    credentials: &Credentials,
) -> Result<(X509, PKey<openssl::pkey::Private>), Failure> {
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

fn set_patience(socket: &TcpStream) -> Result<(), Failure> {
    socket.set_read_timeout(Some(PATIENCE)).map_err(|error| {
        Failure::new(
            Reason::Network,
            format!("the read timeout could not be set: {error}"),
        )
    })?;
    socket.set_write_timeout(Some(PATIENCE)).map_err(|error| {
        Failure::new(
            Reason::Network,
            format!("the write timeout could not be set: {error}"),
        )
    })
}

fn read_line(stream: &mut SslStream<TcpStream>) -> Result<String, Failure> {
    let mut line = String::new();
    let mut limited = stream.take(MOST_LINE_BYTES);
    BufReader::new(&mut limited)
        .read_line(&mut line)
        .map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("a peer message could not be read: {error}"),
            )
        })?;
    Ok(line)
}

fn write_line<T: serde::Serialize>(
    stream: &mut SslStream<TcpStream>,
    message: &T,
) -> Result<(), Failure> {
    let line = encode(message)?;
    stream.write_all(line.as_bytes()).map_err(|error| {
        Failure::new(
            Reason::Network,
            format!("a peer message could not be sent: {error}"),
        )
    })?;
    stream.flush().map_err(|error| {
        Failure::new(
            Reason::Network,
            format!("a peer message could not be flushed: {error}"),
        )
    })
}
