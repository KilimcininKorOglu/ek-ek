// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ACME order flow, with no network in it.
//!
//! This decides what to ask an ACME server next and reads what comes back. It
//! opens no socket, so every rule in RFC 8555 that matters here is measurable
//! against an answer written by hand: what a rejected nonce does, what an
//! invalid order does, when the challenge is published and when it is taken
//! away again.
//!
//! The carrier that actually speaks HTTPS is in [`crate::acme`]. It holds the
//! nonce, the waits and the trust store, and it knows nothing about the order
//! beyond passing answers back here. That split is the same one the VRRP state
//! machine has against its socket.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::{Failure, Reason};
use crate::jws::{Identify, key_authorization};

/// How many times the order is read while waiting for the server.
///
/// The server checks a challenge in its own time and says "pending" until it
/// has. This bounds the wait so a server that never finishes ends the attempt
/// instead of holding it open.
pub const MOST_POLLS: u32 = 60;

/// How many times one request is repeated after a rejected nonce.
///
/// A rejected nonce is normal (RFC 8555 section 6.5) and the fix is to send
/// the same request again with a fresh one. A server rejecting every nonce is
/// not normal, and repeating forever would be a loop nothing breaks.
pub const MOST_NONCE_RETRIES: u32 = 5;

/// The challenge type this flow answers.
const HTTP01: &str = "http-01";

/// The problem type a server uses for a nonce it will not take.
const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";

/// What the flow wants sent next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    /// An unsigned read. Only the directory and the nonce endpoint are
    /// fetched this way, because they carry nothing private.
    Read {
        /// Where to read from.
        url: String,
    },
    /// A signed request.
    Send {
        /// Where to send it.
        url: String,
        /// The body, or `None` for a POST-as-GET that only reads.
        payload: Option<String>,
        /// How the account is named in the envelope.
        identify: Identify,
    },
}

impl Ask {
    /// Where this ask goes.
    #[must_use]
    pub fn url(&self) -> &str {
        match self {
            Self::Read { url } | Self::Send { url, .. } => url,
        }
    }
}

/// What one answer did to the flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// The flow moved on. Ask it what is next.
    Moved,
    /// The server refused the nonce. Send the same ask again with a fresh one.
    Again,
}

/// One answer from the server, as the carrier read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The body, as text.
    pub body: String,
    /// The `Location` header, which is how ACME names what it just created.
    pub location: Option<String>,
}

impl Answer {
    /// Builds an answer.
    #[must_use]
    pub fn new(status: u16, body: impl Into<String>, location: Option<String>) -> Self {
        Self {
            status,
            body: body.into(),
            location,
        }
    }
}

/// Where the flow is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Read the directory to learn the server's endpoints.
    Directory,
    /// Collect the first nonce.
    Nonce,
    /// Create or find the account.
    Account,
    /// Place the order.
    Order,
    /// Read the next authorization to learn its challenge.
    Authorization,
    /// Tell the server the challenge is ready to be checked.
    Accept,
    /// Read the order until the server has made up its mind.
    Poll,
    /// Hand over the signing request.
    Finalize,
    /// Collect the certificate.
    Download,
    /// Nothing left to ask.
    Done,
}

/// The server's endpoints, as the directory names them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

/// One order, from the directory to the certificate.
#[derive(Debug)]
pub struct Flow {
    stage: Stage,
    directory_url: String,
    names: Vec<String>,
    thumbprint: String,
    contact: String,
    csr: String,
    directory: Directory,
    account: Option<String>,
    order: Option<String>,
    finalize: Option<String>,
    certificate: Option<String>,
    waiting: Vec<String>,
    challenge: Option<String>,
    published: BTreeMap<String, String>,
    chain: Option<String>,
    polls: u32,
}

impl Flow {
    /// Starts an order for a set of names.
    ///
    /// `thumbprint` is the account key's, which is what turns a token into an
    /// answer only this account can give. `csr` is the signing request,
    /// already encoded, so this module never touches a key.
    #[must_use]
    pub fn new(
        directory_url: impl Into<String>,
        names: Vec<String>,
        thumbprint: impl Into<String>,
        contact: impl Into<String>,
        csr: impl Into<String>,
    ) -> Self {
        Self {
            stage: Stage::Directory,
            directory_url: directory_url.into(),
            names,
            thumbprint: thumbprint.into(),
            contact: contact.into(),
            csr: csr.into(),
            directory: Directory::default(),
            account: None,
            order: None,
            finalize: None,
            certificate: None,
            waiting: Vec::new(),
            challenge: None,
            published: BTreeMap::new(),
            chain: None,
            polls: 0,
        }
    }

    /// What to send next, or `None` when the order is finished.
    #[must_use]
    pub fn next(&self) -> Option<Ask> {
        match self.stage {
            Stage::Directory => Some(Ask::Read {
                url: self.directory_url.clone(),
            }),
            Stage::Nonce => Some(Ask::Read {
                url: self.directory.new_nonce.clone(),
            }),
            Stage::Account => Some(Ask::Send {
                url: self.directory.new_account.clone(),
                payload: Some(self.account_payload()),
                identify: Identify::Key,
            }),
            Stage::Order => Some(Ask::Send {
                url: self.directory.new_order.clone(),
                payload: Some(self.order_payload()),
                identify: Identify::Account,
            }),
            Stage::Authorization => self.waiting.first().map(|url| Ask::Send {
                url: url.clone(),
                payload: None,
                identify: Identify::Account,
            }),
            Stage::Accept => self.challenge.clone().map(|url| Ask::Send {
                url,
                // An empty object, not an absent payload: this is a write that
                // tells the server to start checking, and POST-as-GET would
                // only read the challenge back.
                payload: Some("{}".to_owned()),
                identify: Identify::Account,
            }),
            Stage::Poll => self.order.clone().map(|url| Ask::Send {
                url,
                payload: None,
                identify: Identify::Account,
            }),
            Stage::Finalize => self.finalize.clone().map(|url| Ask::Send {
                url,
                payload: Some(format!(r#"{{"csr":"{}"}}"#, self.csr)),
                identify: Identify::Account,
            }),
            Stage::Download => self.certificate.clone().map(|url| Ask::Send {
                url,
                payload: None,
                identify: Identify::Account,
            }),
            Stage::Done => None,
        }
    }

    /// The challenge answers that must be reachable right now.
    ///
    /// Empty before the first authorization is read and empty again once the
    /// order finishes, so the path is open only while the server is actually
    /// asking (ADR-0026).
    #[must_use]
    pub fn published(&self) -> &BTreeMap<String, String> {
        &self.published
    }

    /// The account this order signs as, once the server has named one.
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// The certificate chain, once it has been collected.
    #[must_use]
    pub fn chain(&self) -> Option<&str> {
        self.chain.as_deref()
    }

    /// Whether the order is finished.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.stage == Stage::Done
    }

    /// Whether the last answer left the flow waiting on the server.
    ///
    /// The carrier uses this to decide whether to pause before asking again.
    /// Everything else in the flow is asked back to back.
    #[must_use]
    pub fn waiting_on_server(&self) -> bool {
        self.stage == Stage::Poll
    }

    /// Feeds one answer back into the flow.
    ///
    /// # Errors
    ///
    /// Returns why the order cannot go on. A refused challenge is
    /// [`Reason::Challenge`] and is not worth retrying; an answer this client
    /// cannot read is [`Reason::Protocol`].
    pub fn accept(&mut self, answer: &Answer) -> Result<Progress, Failure> {
        if answer.status == 400 && problem_type(&answer.body).as_deref() == Some(BAD_NONCE) {
            return Ok(Progress::Again);
        }
        if answer.status >= 400 {
            return Err(self.server_said(answer));
        }

        match self.stage {
            Stage::Directory => self.read_directory(answer),
            Stage::Nonce => {
                self.stage = Stage::Account;
                Ok(Progress::Moved)
            }
            Stage::Account => self.read_account(answer),
            Stage::Order => self.read_order(answer),
            Stage::Authorization => self.read_authorization(answer),
            Stage::Accept => {
                // The server now has the challenge to check. The next
                // authorization, if there is one, is read the same way.
                self.challenge = None;
                self.stage = if self.waiting.is_empty() {
                    Stage::Poll
                } else {
                    Stage::Authorization
                };
                Ok(Progress::Moved)
            }
            Stage::Poll => self.read_progress(answer),
            Stage::Finalize => {
                // Finalising returns the order again, in whatever state it
                // reached. Reading it as progress covers a server that issued
                // the certificate immediately as well as one that did not.
                self.polls = 0;
                self.stage = Stage::Poll;
                self.read_progress(answer)
            }
            Stage::Download => {
                if answer.body.trim().is_empty() {
                    return Err(Failure::new(
                        Reason::Protocol,
                        "the server sent an empty certificate".to_owned(),
                    ));
                }
                self.chain = Some(answer.body.clone());
                // The order is done, so nothing has to stay reachable.
                self.published.clear();
                self.stage = Stage::Done;
                Ok(Progress::Moved)
            }
            Stage::Done => Ok(Progress::Moved),
        }
    }

    /// Gives up on the order and takes the challenge answers away.
    ///
    /// Called by the carrier on every path out, so a failed attempt never
    /// leaves the path open for the next one to inherit.
    pub fn abandon(&mut self) {
        self.published.clear();
        self.stage = Stage::Done;
    }

    fn account_payload(&self) -> String {
        if self.contact.is_empty() {
            return r#"{"termsOfServiceAgreed":true}"#.to_owned();
        }
        format!(
            r#"{{"termsOfServiceAgreed":true,"contact":["mailto:{}"]}}"#,
            self.contact
        )
    }

    fn order_payload(&self) -> String {
        let identifiers: Vec<String> = self
            .names
            .iter()
            .map(|name| format!(r#"{{"type":"dns","value":"{name}"}}"#))
            .collect();
        format!(r#"{{"identifiers":[{}]}}"#, identifiers.join(","))
    }

    fn read_directory(&mut self, answer: &Answer) -> Result<Progress, Failure> {
        let document = parse(&answer.body)?;
        self.directory = Directory {
            new_nonce: text(&document, "newNonce")?,
            new_account: text(&document, "newAccount")?,
            new_order: text(&document, "newOrder")?,
        };
        self.stage = Stage::Nonce;
        Ok(Progress::Moved)
    }

    fn read_account(&mut self, answer: &Answer) -> Result<Progress, Failure> {
        // The account URL is only ever in the header. A server that created
        // the account and one that recognised an existing key both answer this
        // way, which is why this flow never has to remember an account.
        let account = answer.location.clone().ok_or_else(|| {
            Failure::new(Reason::Protocol, "the server named no account".to_owned())
        })?;
        self.account = Some(account);
        self.stage = Stage::Order;
        Ok(Progress::Moved)
    }

    fn read_order(&mut self, answer: &Answer) -> Result<Progress, Failure> {
        let document = parse(&answer.body)?;
        let order = answer.location.clone().ok_or_else(|| {
            Failure::new(Reason::Protocol, "the server named no order".to_owned())
        })?;
        self.order = Some(order);
        self.finalize = Some(text(&document, "finalize")?);

        let authorizations = document
            .get("authorizations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Failure::new(
                    Reason::Protocol,
                    "the order names no authorizations".to_owned(),
                )
            })?;
        self.waiting = authorizations
            .iter()
            .filter_map(|url| url.as_str().map(str::to_owned))
            .collect();

        if self.waiting.is_empty() {
            // Every name is already authorised, which happens when an earlier
            // order for the same names went through.
            self.stage = Stage::Poll;
        } else {
            self.stage = Stage::Authorization;
        }
        Ok(Progress::Moved)
    }

    fn read_authorization(&mut self, answer: &Answer) -> Result<Progress, Failure> {
        let document = parse(&answer.body)?;

        // Taken off the list before anything can fail, so a fault cannot leave
        // the flow reading the same authorization forever.
        if !self.waiting.is_empty() {
            self.waiting.remove(0);
        }

        if document.get("status").and_then(Value::as_str) == Some("valid") {
            // Already proven, so there is nothing to publish and nothing to
            // ask the server to check.
            self.stage = if self.waiting.is_empty() {
                Stage::Poll
            } else {
                Stage::Authorization
            };
            return Ok(Progress::Moved);
        }

        let challenges = document
            .get("challenges")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Failure::new(
                    Reason::Protocol,
                    "the authorization names no challenges".to_owned(),
                )
            })?;
        let challenge = challenges
            .iter()
            .find(|challenge| challenge.get("type").and_then(Value::as_str) == Some(HTTP01))
            .ok_or_else(|| {
                Failure::new(
                    Reason::Challenge,
                    "the server offers no HTTP-01 challenge for this name".to_owned(),
                )
            })?;

        let token = text(challenge, "token")?;
        if token.is_empty() || token.contains('/') {
            return Err(Failure::new(
                Reason::Protocol,
                "the server sent a token that cannot name a path".to_owned(),
            ));
        }
        self.published
            .insert(token.clone(), key_authorization(&token, &self.thumbprint));
        self.challenge = Some(text(challenge, "url")?);
        self.stage = Stage::Accept;
        Ok(Progress::Moved)
    }

    fn read_progress(&mut self, answer: &Answer) -> Result<Progress, Failure> {
        let document = parse(&answer.body)?;
        match document.get("status").and_then(Value::as_str) {
            Some("valid") => {
                self.certificate = Some(text(&document, "certificate")?);
                self.stage = Stage::Download;
                Ok(Progress::Moved)
            }
            Some("ready") => {
                self.stage = Stage::Finalize;
                Ok(Progress::Moved)
            }
            Some("pending" | "processing") => {
                self.polls += 1;
                if self.polls > MOST_POLLS {
                    return Err(Failure::new(
                        Reason::Network,
                        format!("the server was still deciding after {MOST_POLLS} reads"),
                    ));
                }
                self.stage = Stage::Poll;
                Ok(Progress::Moved)
            }
            Some("invalid") => Err(Failure::new(
                Reason::Challenge,
                // The name is what an operator has to fix, so it is named.
                // Nothing else in the document is worth carrying: the answer
                // itself is the challenge, and it does not belong in a log.
                format!(
                    "the server refused the challenge for {}",
                    self.names.join(", ")
                ),
            )),
            other => Err(Failure::new(
                Reason::Protocol,
                format!("the order is in a state this client does not know: {other:?}"),
            )),
        }
    }

    /// Turns a failed answer into something worth logging.
    fn server_said(&self, answer: &Answer) -> Failure {
        let kind = problem_type(&answer.body).unwrap_or_else(|| "no type".to_owned());
        let detail = parse(&answer.body)
            .ok()
            .and_then(|document| {
                document
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        Failure::new(
            Reason::Server,
            format!(
                "{} while {}: {kind} {detail}",
                answer.status,
                kind_of(self.stage)
            ),
        )
    }
}

/// What the flow was doing, for a message an operator reads.
const fn kind_of(stage: Stage) -> &'static str {
    match stage {
        Stage::Directory => "reading the directory",
        Stage::Nonce => "collecting a nonce",
        Stage::Account => "creating the account",
        Stage::Order => "placing the order",
        Stage::Authorization => "reading an authorization",
        Stage::Accept => "handing over the challenge",
        Stage::Poll => "reading the order",
        Stage::Finalize => "finalising the order",
        Stage::Download => "collecting the certificate",
        Stage::Done => "nothing",
    }
}

/// Reads a JSON document, or says the answer was unreadable.
fn parse(body: &str) -> Result<Value, Failure> {
    serde_json::from_str(body).map_err(|error| {
        Failure::new(
            Reason::Protocol,
            format!("the server sent something that is not JSON: {error}"),
        )
    })
}

/// Reads one string field, or says which one was missing.
fn text(document: &Value, field: &str) -> Result<String, Failure> {
    document
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::new(Reason::Protocol, format!("the answer carries no {field}")))
}

/// The problem type an error document names, if it is one.
fn problem_type(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body)
        .ok()?
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
}
