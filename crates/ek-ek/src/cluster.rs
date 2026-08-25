// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `cluster` commands: the authority every node's peer certificate comes
//! from, and the channel those certificates open.
//!
//! Until the join flow exists (T-038) this is how an authority is created and
//! how a node gets a certificate from it. The web interface will call the same
//! library; nothing here is a second implementation.
//!
//! # Why the node key is written to a file
//!
//! The second node has no way to receive it yet: there is no join flow, and
//! its store is sealed with its own master key (ADR-0018), so the first node
//! cannot write into it. The file is created with owner-only permissions and
//! T-038 removes this step (ADR-0082).

use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ek_ek_config::{Config, NodeId};
use ek_ek_peer::{Authority, Credentials, Issued};
use ek_ek_store::{Change, Secret, Snapshot, SqliteStore, Store};

/// The config schema this release reads.
///
/// Told to every peer in the opening line, so a node running another release
/// is refused at the door rather than after it has taken a log record
/// (ADR-0019, ADR-0083).
const SCHEMA_VERSION: u32 = ek_ek_config::SchemaVersion::CURRENT.get();

/// Permissions a written private key carries.
const KEY_MODE: u32 = 0o600;

/// What the authority certificate is called in an output directory.
const AUTHORITY_FILE: &str = "cluster-ca.crt";

/// How often `cluster node` looks at the file it applies and at who leads.
///
/// Short, because a configuration an operator wrote is one they are waiting
/// on. Nothing here costs a network round trip: both are local reads.
const WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

/// How often `cluster node` asks whether it can still reach a quorum.
///
/// Slower than the watch above, because this one costs a heartbeat round to a
/// quorum while the others are local reads. One second is well inside what an
/// operator watching a screen would call live.
const QUORUM_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long a refused configuration waits before it is offered again.
///
/// A configuration that was refused has to be tried again, or an operator who
/// wrote a file during a quorum loss would find it silently dropped once the
/// cluster came back. One attempt costs one heartbeat round, the same as the
/// quorum question above, and a refusal that has already been reported is not
/// reported again, so retrying this often is neither expensive nor loud.
const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How often a leading node looks for a certificate to order.
///
/// A certificate is renewed with a third of its life left (ADR-0079), so
/// nothing here is urgent. This is short enough that a measurement does not
/// wait on it and long enough that a cluster does not read its own state in a
/// loop.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Creates the cluster authority.
pub struct InitArguments<'a> {
    /// Where the store lives.
    pub data_dir: &'a str,
    /// A configuration to start an empty store from, if it is empty.
    pub config: Option<&'a str>,
}

/// Reads the authority's fingerprint back.
pub struct FingerprintArguments<'a> {
    /// Where the store lives.
    pub data_dir: &'a str,
}

/// Signs a certificate for one node.
pub struct EnrollArguments<'a> {
    /// Where the store lives.
    pub data_dir: &'a str,
    /// The node the certificate is for.
    pub node: &'a str,
    /// Addresses to put in the certificate beside the identity.
    pub addresses: &'a [String],
    /// Where to write the certificate, the key and the authority.
    pub out_dir: &'a str,
    /// Decide against this moment instead of the system clock.
    pub at: Option<i64>,
    /// Sign again even when the certificate on disk is not due yet.
    pub force: bool,
}

/// Opens the peer port and answers.
pub struct ServeArguments<'a> {
    /// Address to listen on.
    pub listen: &'a str,
    /// Which node this is.
    pub node: &'a str,
    /// Directory holding the certificate, the key and the authority.
    pub material: &'a str,
    /// How many peers to answer before stopping.
    pub connections: u32,
}

/// Runs this node's consensus member until it is told to stop.
pub struct NodeArguments<'a> {
    /// Where the store lives.
    pub data_dir: &'a str,
    /// Which node this is.
    pub node: &'a str,
    /// Directory holding the certificate, the key and the authority.
    pub material: &'a str,
    /// Address to listen for peers on.
    pub listen: &'a str,
    /// `name=address` pairs, comma separated, to bring a cluster into being.
    ///
    /// Run on one node, once. Every other node is told about the cluster by
    /// the membership this records (ADR-0085).
    pub initialise: Option<&'a str>,
    /// A configuration file to watch and apply through consensus.
    pub apply: Option<&'a str>,
    /// A file to write this node's share of the live challenge answers to.
    ///
    /// The answers replicate, so every node writes the same ones and the
    /// certificate authority is answered by whichever node the name resolves
    /// to, driver or not (ADR-0032, ADR-0086).
    pub challenges: Option<&'a str>,
    /// Order certificates that are running out, while this node leads.
    pub acme: bool,
}

/// Reads what this node holds, without asking anybody.
pub struct StatusArguments<'a> {
    /// Where the store lives.
    pub data_dir: &'a str,
}

/// Asks one peer whether it is there.
pub struct PingArguments<'a> {
    /// Address to dial.
    pub to: &'a str,
    /// Which node is expected to answer.
    pub expect: &'a str,
    /// Which node this is.
    pub node: &'a str,
    /// Directory holding the certificate, the key and the authority.
    pub material: &'a str,
}

/// Creates the authority this cluster's peer certificates come from.
///
/// Refuses to run twice. A second authority would leave every certificate the
/// first one signed unable to connect, and there would be nothing on either
/// node to say why.
pub fn init(arguments: &InitArguments<'_>) -> ExitCode {
    let store = match SqliteStore::open(Path::new(arguments.data_dir)) {
        Ok(store) => store,
        Err(error) => {
            return refused(&format!(
                "{} could not be opened: {error}",
                arguments.data_dir
            ));
        }
    };

    let state = match store.read() {
        Ok(Some(held)) => held,
        Ok(None) => match empty(arguments.config) {
            Ok(state) => state,
            Err(said) => return refused(&said),
        },
        Err(error) => return refused(&format!("the store could not be read: {error}")),
    };

    if ek_ek_peer::present(&state) {
        return refused(
            "this node already holds a cluster authority; \
             creating a second one would lock out every node the first one signed",
        );
    }

    let authority = match ek_ek_peer::create(now()) {
        Ok(authority) => authority,
        Err(failure) => return refused(&format!("the authority could not be created: {failure}")),
    };

    let next = ek_ek_peer::install(&state, &authority);
    if let Err(error) = store.write(&next, &Change::new("cluster", "authority created")) {
        return refused(&format!("the authority could not be stored: {error}"));
    }

    let mark = match ek_ek_peer::fingerprint(&authority.certificate_pem) {
        Ok(mark) => mark,
        Err(failure) => return refused(&format!("the fingerprint could not be taken: {failure}")),
    };

    // The fingerprint, never the key. This line goes wherever standard output
    // goes, and the key that signs every node identity does not belong there.
    say(&format!(
        r#"{{"kind":"cluster","ts":{},"event":"created","fingerprint":"{mark}"}}"#,
        now()
    ));
    ExitCode::SUCCESS
}

/// Prints the authority's fingerprint, as a join token carries it.
pub fn fingerprint(arguments: &FingerprintArguments<'_>) -> ExitCode {
    let authority = match held(arguments.data_dir) {
        Ok(authority) => authority,
        Err(said) => return refused(&said),
    };

    match ek_ek_peer::fingerprint(&authority.certificate_pem) {
        Ok(mark) => {
            say(&format!(
                r#"{{"kind":"cluster","ts":{},"event":"fingerprint","fingerprint":"{mark}"}}"#,
                now()
            ));
            ExitCode::SUCCESS
        }
        Err(failure) => refused(&format!("the fingerprint could not be taken: {failure}")),
    }
}

/// Signs a certificate for one node and writes it out.
///
/// Runs the renewal rule first: a certificate already on disk with more than a
/// third of its life left is left alone, so the same command can be run on a
/// timer without signing a new certificate every time.
pub fn enroll(arguments: &EnrollArguments<'_>) -> ExitCode {
    let authority = match held(arguments.data_dir) {
        Ok(authority) => authority,
        Err(said) => return refused(&said),
    };

    let mut addresses = Vec::with_capacity(arguments.addresses.len());
    for value in arguments.addresses {
        match value.parse::<IpAddr>() {
            Ok(address) => addresses.push(address),
            Err(error) => return refused(&format!("{value} is not an address: {error}")),
        }
    }

    let at = arguments.at.unwrap_or_else(now);
    let out = PathBuf::from(arguments.out_dir);
    let certificate_path = out.join(format!("{}.crt", arguments.node));
    let key_path = out.join(format!("{}.key", arguments.node));

    if !arguments.force {
        match standing(&certificate_path, at) {
            Ok(Some(remaining)) => {
                say(&format!(
                    r#"{{"kind":"cluster","ts":{},"event":"kept","node":"{}","remaining_seconds":{remaining}}}"#,
                    now(),
                    escape(arguments.node)
                ));
                return ExitCode::SUCCESS;
            }
            Ok(None) => {}
            Err(said) => return refused(&said),
        }
    }

    let node = NodeId::new(arguments.node);
    let issued = match ek_ek_peer::issue(&authority, &node, &addresses, at) {
        Ok(issued) => issued,
        Err(failure) => return refused(&format!("the certificate could not be signed: {failure}")),
    };

    if let Err(said) = write_material(&out, &authority, &issued, &certificate_path, &key_path) {
        return refused(&said);
    }

    say(&format!(
        r#"{{"kind":"cluster","ts":{},"event":"enrolled","node":"{}","not_before":{},"not_after":{}}}"#,
        now(),
        escape(arguments.node),
        issued.not_before_unix,
        issued.not_after_unix
    ));
    ExitCode::SUCCESS
}

/// Answers peers on the peer port.
pub fn serve(arguments: &ServeArguments<'_>) -> ExitCode {
    let credentials = match material(arguments.material, arguments.node) {
        Ok(credentials) => credentials,
        Err(said) => return refused(&said),
    };

    let Some(runtime) = runtime() else {
        return refused("the async runtime could not be started");
    };

    runtime.block_on(async {
        let node = NodeId::new(arguments.node);
        // No services. This command proves who the node is and answers a
        // health question; the Raft services arrive with the node the cluster
        // runs, not with a diagnostic command (ADR-0083).
        let listener = match ek_ek_peer::Listener::bind(
            arguments.listen,
            &credentials,
            ek_ek_peer::Listening::new(&node, SCHEMA_VERSION, Arc::new(ek_ek_peer::NoServices)),
        )
        .await
        {
            Ok(listener) => listener,
            Err(failure) => {
                return refused(&format!("the peer port could not be opened: {failure}"));
            }
        };

        match listener.address() {
            Ok(address) => say(&format!(
                r#"{{"kind":"cluster","ts":{},"event":"listening","address":"{address}"}}"#,
                now()
            )),
            Err(failure) => {
                return refused(&format!("the peer port could not be read back: {failure}"));
            }
        }

        for _ in 0..arguments.connections {
            match listener.serve_one().await {
                Ok(served) => say(&format!(
                    r#"{{"kind":"cluster","ts":{},"event":"served","caller":"{}"}}"#,
                    now(),
                    escape(served.caller.as_ref().map_or("", NodeId::as_str))
                )),
                // Said rather than swallowed. A refused peer is the most
                // interesting thing this command ever sees.
                Err(failure) => say(&format!(
                    r#"{{"kind":"cluster","ts":{},"event":"refused","reason":"{}","detail":"{}"}}"#,
                    now(),
                    failure.reason().key(),
                    escape(failure.detail())
                )),
            }
        }

        ExitCode::SUCCESS
    })
}

/// Runs this node's consensus member until a signal stops it.
///
/// This is the process that carries Raft. The traffic path is a separate
/// process that never speaks to it, which is what makes losing a quorum
/// something the traffic path cannot notice (ADR-0004, ADR-0085).
///
/// Every state change is a record on standard output, because there is no
/// admin API yet and an operator has nowhere else to read it.
pub fn node(arguments: &NodeArguments<'_>) -> ExitCode {
    let store = match SqliteStore::open(Path::new(arguments.data_dir)) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            return refused(&format!(
                "{} could not be opened: {error}",
                arguments.data_dir
            ));
        }
    };

    let credentials = match material(arguments.material, arguments.node) {
        Ok(credentials) => credentials,
        Err(said) => return refused(&said),
    };

    let membership = match arguments.initialise.map(peers).transpose() {
        Ok(membership) => membership,
        Err(said) => return refused(&said),
    };

    let Some(runtime) = runtime() else {
        return refused("the async runtime could not be started");
    };

    runtime.block_on(async {
        let id = NodeId::new(arguments.node);
        let cluster = match ek_ek_raft::Cluster::start(
            Arc::clone(&store),
            &id,
            SCHEMA_VERSION,
            credentials.clone(),
        )
        .await
        {
            Ok(cluster) => Arc::new(cluster),
            Err(failure) => return refused(&format!("consensus could not be started: {failure}")),
        };

        // The clock is the system's here. A moment a caller could choose
        // belongs in a measurement, not in the process an operator runs.
        let clock: ek_ek_raft::Clock = Arc::new(now);
        let listener = match ek_ek_peer::Listener::bind(
            arguments.listen,
            &credentials,
            ek_ek_peer::Listening::new(
                &id,
                SCHEMA_VERSION,
                Arc::new(ek_ek_raft::Admission::new(Arc::clone(&cluster), clock)),
            )
            .opening(ek_ek_raft::join::SERVICE)
            .behind(Arc::new(ek_ek_raft::Refusals::new(Arc::clone(&cluster)))),
        )
        .await
        {
            Ok(listener) => listener,
            Err(failure) => {
                return refused(&format!("the peer port could not be opened: {failure}"));
            }
        };

        match listener.address() {
            Ok(address) => say(&format!(
                r#"{{"kind":"cluster","ts":{},"event":"listening","node":"{}","address":"{address}"}}"#,
                now(),
                escape(id.as_str())
            )),
            Err(failure) => {
                return refused(&format!("the peer port could not be read back: {failure}"));
            }
        }
        let serving = tokio::spawn(Arc::new(listener).serve_forever());

        if let Some(membership) = membership {
            let count = membership.len();
            if let Err(failure) = cluster
                .initialise(&ek_ek_raft::Membership {
                    node: id.clone(),
                    peers: membership,
                })
                .await
            {
                serving.abort();
                let _ = cluster.halt().await;
                return refused(&format!("the cluster could not be initialised: {failure}"));
            }
            say(&format!(
                r#"{{"kind":"cluster","ts":{},"event":"initialised","nodes":{count}}}"#,
                now()
            ));
        }

        watch(
            &cluster,
            &Watching {
                apply: arguments.apply,
                challenges: arguments.challenges,
                acme: arguments.acme,
                data_dir: arguments.data_dir,
                node: id.clone(),
            },
        )
        .await;

        serving.abort();
        if let Err(failure) = cluster.halt().await {
            return refused(&format!("consensus did not stop: {failure}"));
        }
        say(&format!(
            r#"{{"kind":"cluster","ts":{},"event":"stopped","node":"{}"}}"#,
            now(),
            escape(id.as_str())
        ));
        ExitCode::SUCCESS
    })
}

/// Reads what this node holds, without asking anybody.
///
/// Local on purpose. A status command that needed a quorum would fall silent
/// at exactly the moment somebody wants to know what is wrong (ADR-0004).
pub fn status(arguments: &StatusArguments<'_>) -> ExitCode {
    let store = match SqliteStore::open(Path::new(arguments.data_dir)) {
        Ok(store) => store,
        Err(error) => {
            return refused(&format!(
                "{} could not be opened: {error}",
                arguments.data_dir
            ));
        }
    };

    let held = match store.read() {
        Ok(held) => held,
        Err(error) => return refused(&format!("the store could not be read: {error}")),
    };
    let versions = match ek_ek_store::History::versions(&store) {
        Ok(versions) => versions.len(),
        Err(error) => return refused(&format!("the version log could not be read: {error}")),
    };

    let (nodes, authority) = held.as_ref().map_or((0, false), |state| {
        (state.config.nodes.len(), state.cluster.is_some())
    });
    let certificates = held.as_ref().map_or_else(String::new, |state| {
        held_certificates(state)
            .iter()
            .map(|id| format!(r#""{}""#, escape(id)))
            .collect::<Vec<String>>()
            .join(",")
    });
    say(&format!(
        r#"{{"kind":"cluster","ts":{},"event":"status","held":{},"nodes":{nodes},"versions":{versions},"authority":{authority},"certificates":[{certificates}]}}"#,
        now(),
        held.is_some()
    ));
    ExitCode::SUCCESS
}

/// Which certificates this node can actually serve.
///
/// Named rather than counted because the question an operator asks is which
/// one is missing, and because a count cannot tell a certificate that arrived
/// from one that left. A certificate is here only when both halves are: a
/// chain with no key serves nothing, and the document naming a secret is not
/// the same as the state holding it.
fn held_certificates(state: &Snapshot) -> Vec<&str> {
    state
        .config
        .certificates
        .iter()
        .filter(|certificate| {
            [certificate.chain.as_ref(), certificate.private_key.as_ref()]
                .into_iter()
                .all(|half| half.is_some_and(|id| state.secrets.contains_key(id)))
        })
        .map(|certificate| certificate.id.as_str())
        .collect()
}

/// Applies a configuration whenever the file changes, until a signal arrives.
///
/// The write comes from inside this process because consensus is inside this
/// process. A second process could reach it only over the peer channel, and a
/// write service there is the admin API's question rather than this one's
/// (ADR-0085).
/// Everything the loop below does besides carrying consensus.
struct Watching<'a> {
    /// A configuration file to watch and apply through consensus.
    apply: Option<&'a str>,
    /// A file to write this node's share of the live challenge answers to.
    challenges: Option<&'a str>,
    /// Order certificates that are running out, while this node leads.
    acme: bool,
    /// Where the store lives, and where the attempt state sits beside it.
    data_dir: &'a str,
    /// Which node this is.
    node: NodeId,
}

async fn watch(cluster: &Arc<ek_ek_raft::Cluster>, watching: &Watching<'_>) {
    let mut stopping =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(stopping) => stopping,
            Err(error) => {
                say(&format!(
                    r#"{{"kind":"cluster","ts":{},"event":"failed","detail":"{}"}}"#,
                    now(),
                    escape(&format!("the stop signal could not be watched: {error}"))
                ));
                return;
            }
        };

    let mut leader: Option<NodeId> = None;
    // Empty rather than absent, so the first read of a file that is already
    // there counts as a change and the first configuration goes in the same
    // way every later one does.
    let mut applied = String::new();
    let mut attempted = String::new();
    // The refusal already reported for the document being attempted.
    let mut reported: Option<String> = None;
    // Unknown rather than reachable, so the first answer is always reported.
    let mut reachable: Option<bool> = None;
    let mut asked = std::time::Instant::now() - QUORUM_INTERVAL;
    let mut offered = std::time::Instant::now() - RETRY_INTERVAL;
    // The last document written to the challenge file, so an unchanged one is
    // not rewritten two hundred times a second.
    let mut served: Option<String> = None;
    let mut swept = std::time::Instant::now() - SWEEP_INTERVAL;
    // Set while an order is running on a blocking thread. One at a time, so a
    // sweep that takes a minute is not started again every five seconds.
    let ordering = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The refusal already reported for the sweep, said once for the same
    // reason a refused configuration is (ADR-0085).
    let mut refused_sweep: Option<String> = None;
    let writing: Writer = Arc::new(tokio::sync::Mutex::new(()));

    loop {
        if let Some(named) = cluster.leader()
            && leader.as_ref() != Some(&named)
        {
            say(&format!(
                r#"{{"kind":"cluster","ts":{},"event":"leader","node":"{}"}}"#,
                now(),
                escape(named.as_str())
            ));
            leader = Some(named);
        }

        // Asked rather than read off the metrics. A leader that lost contact
        // keeps naming itself, so a screen built on `leader` alone would show
        // a healthy cluster while nothing can be written (ADR-0085).
        if asked.elapsed() >= QUORUM_INTERVAL {
            asked = std::time::Instant::now();
            let answered = cluster.reachable().await;
            // A follower is refused because it does not lead, and that answer
            // means the cluster is there. Only "no leader is known" means it
            // is not.
            let now_reachable = match &answered {
                Ok(()) => true,
                Err(failure) => failure.reason() == ek_ek_raft::Reason::NotLeader,
            };
            if reachable != Some(now_reachable) {
                reachable = Some(now_reachable);
                if now_reachable {
                    say(&format!(
                        r#"{{"kind":"cluster","ts":{},"event":"quorum","reachable":true}}"#,
                        now()
                    ));
                } else if let Err(failure) = &answered {
                    say(&format!(
                        r#"{{"kind":"cluster","ts":{},"event":"quorum","reachable":false,"reason":"{}","detail":"{}"}}"#,
                        now(),
                        failure.reason().key(),
                        escape(failure.detail())
                    ));
                }
            }
        }

        // A document is offered until it goes in, not until it has been tried.
        // Recording an attempt as done would drop a configuration an operator
        // wrote while the quorum was gone, or one written on a node that does
        // not lead yet (ADR-0085). Content that has not been offered yet goes
        // at once; content that was refused waits out the interval.
        if let Some(path) = watching.apply {
            let read = std::fs::read_to_string(path).unwrap_or_default();
            let fresh = read != attempted;
            if !read.trim().is_empty()
                && read != applied
                && (fresh || offered.elapsed() >= RETRY_INTERVAL)
            {
                if fresh {
                    attempted.clone_from(&read);
                    // A new document is a new question, so its first answer is
                    // reported whatever the last one was.
                    reported = None;
                }
                offered = std::time::Instant::now();
                match apply_once(cluster, &writing, &read).await {
                    Applied::Went(version) => {
                        applied.clone_from(&read);
                        reported = None;
                        say(&format!(
                            r#"{{"kind":"cluster","ts":{},"event":"applied","version":{version}}}"#,
                            now()
                        ));
                    }
                    // Said once. The same refusal every second would bury the
                    // records that do change, and nothing new has happened.
                    Applied::Refused { reason, detail } => {
                        if reported.as_ref() != Some(&reason) {
                            say(&format!(
                                r#"{{"kind":"cluster","ts":{},"event":"refused","reason":"{reason}","detail":"{}"}}"#,
                                now(),
                                escape(&detail)
                            ));
                            reported = Some(reason);
                        }
                    }
                }
            }
        }

        // Every node writes its own file, the one driving the order included.
        // A leader that wrote its own answer by a shorter route would be the
        // one node whose challenge path nothing measured (ADR-0086).
        if let Some(path) = watching.challenges {
            publish_answers(cluster, path, &mut served);
        }

        // Only the leader orders. Every other node reads the answer out of the
        // state and serves it, which is what keeps three nodes from spending
        // three times the certificate authority's allowance (ADR-0032).
        if watching.acme
            && swept.elapsed() >= SWEEP_INTERVAL
            && !ordering.load(std::sync::atomic::Ordering::SeqCst)
            && cluster.is_leader()
        {
            swept = std::time::Instant::now();
            // Asked before anything is sent anywhere. An order that cannot be
            // written is one that must not be placed, and asking here keeps a
            // cluster with no quorum from spending the server's allowance on
            // a certificate it could not have stored (ADR-0086).
            match cluster.reachable().await {
                Ok(()) => {
                    refused_sweep = None;
                    start_sweep(cluster, watching, &ordering, &writing);
                }
                Err(failure) => {
                    let reason = failure.reason().key().to_owned();
                    if refused_sweep.as_ref() != Some(&reason) {
                        say(&format!(
                            r#"{{"kind":"cluster","ts":{},"event":"order_refused","reason":"{reason}","detail":"{}"}}"#,
                            now(),
                            escape(failure.detail())
                        ));
                        refused_sweep = Some(reason);
                    }
                }
            }
        }

        tokio::select! {
            () = tokio::time::sleep(WATCH_INTERVAL) => {}
            _ = stopping.recv() => return,
            _ = tokio::signal::ctrl_c() => return,
        }
    }
}

/// Writes the challenge answers this node holds where its agent reads them.
///
/// Written whole every time it changes, the empty map included. A file that
/// was only ever added to would leave every token of every order answerable
/// for as long as the process lives, and the path would stay open on a node
/// with no order at all (ADR-0086).
fn publish_answers(cluster: &Arc<ek_ek_raft::Cluster>, path: &str, last: &mut Option<String>) {
    let held = match cluster.read() {
        Ok(held) => held,
        Err(failure) => {
            say(&format!(
                r#"{{"kind":"cluster","ts":{},"event":"failed","detail":"{}"}}"#,
                now(),
                escape(&format!(
                    "the challenge answers could not be read: {failure}"
                ))
            ));
            return;
        }
    };

    let mut answers: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    if let Some(state) = &held {
        for record in state.orders.values() {
            for (token, value) in &record.answers {
                answers.insert(token.clone(), value.clone());
            }
        }
    }

    let document = match serde_json::to_string(&answers) {
        Ok(document) => document,
        Err(error) => {
            say(&format!(
                r#"{{"kind":"cluster","ts":{},"event":"failed","detail":"{}"}}"#,
                now(),
                escape(&format!(
                    "the challenge answers could not be written out: {error}"
                ))
            ));
            return;
        }
    };
    if last.as_ref() == Some(&document) {
        return;
    }

    if let Err(error) = std::fs::write(path, &document) {
        say(&format!(
            r#"{{"kind":"cluster","ts":{},"event":"failed","detail":"{}"}}"#,
            now(),
            escape(&format!("{path} could not be written: {error}"))
        ));
        return;
    }
    *last = Some(document);

    // The tokens, never the answers. A token is what the server sends in the
    // clear and names nothing by itself; the answer is what proves the account
    // key, and a log is not where it belongs.
    say(&format!(
        r#"{{"kind":"cluster","ts":{},"event":"answering","tokens":[{}]}}"#,
        now(),
        answers
            .keys()
            .map(|token| format!(r#""{}""#, escape(token)))
            .collect::<Vec<String>>()
            .join(",")
    ));
}

/// The one writer this process has.
///
/// The node process writes the replicated state from two places: the loop that
/// applies a configuration file, and the task that drives an order. Both read
/// the whole state, change part of it and write it back, so two overlapping
/// ones lose whichever change landed first. What gets lost is a challenge
/// answer the certificate authority is about to ask for, or a certificate that
/// was just obtained (ADR-0083, ADR-0086).
///
/// An async lock rather than a plain one: the order runs on a blocking thread
/// and holds this across a write that takes a round trip to a quorum, and the
/// loop waiting for it must yield rather than stall the runtime that carries
/// consensus.
type Writer = Arc<tokio::sync::Mutex<()>>;

/// The state one write reads and replaces.
///
/// A trait so the rule below can be measured. Two writers losing each other's
/// work is a race, and a race against consensus cannot be made to happen on
/// purpose: this lets a measurement run the same steps against a state in
/// memory, where two threads can be made to collide every time.
trait State {
    /// Reads what this node holds. Local, so a lost quorum does not stop it
    /// (ADR-0004).
    fn read(&self) -> Result<Option<Snapshot>, ek_ek_raft::Failure>;

    /// Replaces the state whole, and says which version it became.
    fn write(
        &self,
        next: &Snapshot,
        change: &Change,
    ) -> impl Future<Output = Result<i64, ek_ek_raft::Failure>>;
}

impl State for ek_ek_raft::Cluster {
    fn read(&self) -> Result<Option<Snapshot>, ek_ek_raft::Failure> {
        Self::read(self)
    }

    async fn write(&self, next: &Snapshot, change: &Change) -> Result<i64, ek_ek_raft::Failure> {
        Self::write(self, next, change, now())
            .await
            .map(|version| version.get())
    }
}

/// Why one write did not land.
enum Broke {
    /// The state could not be read or could not be written.
    State(ek_ek_raft::Failure),
    /// The caller's own edit refused.
    Edit(ek_ek_tls::Failure),
}

/// Reads, edits and writes the state, with no other writer in between.
///
/// Two writers run in this process: the loop that applies a configuration file
/// and the task that drives an order. Both read the whole state, change one
/// part of it and write the whole thing back. Without this, a document applied
/// between an order's read and its write takes the challenge answer with it,
/// the certificate authority gets a 404 and the order fails (ADR-0086).
///
/// The lock is held across the write, not only across the read. Releasing it
/// after the edit would let the other writer read the state this one is about
/// to replace, which is the same lost write with an extra step.
async fn one_at_a_time<S: State>(
    state: &S,
    writing: &Writer,
    change: &Change,
    edit: &mut dyn FnMut(Option<Snapshot>) -> Result<Snapshot, ek_ek_tls::Failure>,
) -> Result<i64, Broke> {
    let _held = writing.lock().await;
    let held = state.read().map_err(Broke::State)?;
    let next = edit(held).map_err(Broke::Edit)?;
    state.write(&next, change).await.map_err(Broke::State)
}

/// Files a state through consensus.
///
/// Reading is local, like every other read in this product (ADR-0004).
/// Writing goes through the log and is refused when no quorum can be reached,
/// which is what stops an order being started at all.
///
/// The blocking call is deliberate. Everything that uses this runs on a
/// blocking thread, where there is no future being polled to stall, and the
/// ACME driver waits with `std::thread::sleep` anyway.
struct Replicated {
    cluster: Arc<ek_ek_raft::Cluster>,
    handle: tokio::runtime::Handle,
    writing: Writer,
}

impl crate::acme::Filing for Replicated {
    fn read(&self) -> Result<Option<Snapshot>, ek_ek_tls::Failure> {
        self.cluster.read().map_err(consensus_said)
    }

    fn update(
        &self,
        change: &Change,
        edit: &mut dyn FnMut(Option<Snapshot>) -> Result<Snapshot, ek_ek_tls::Failure>,
    ) -> Result<(), ek_ek_tls::Failure> {
        self.handle
            .block_on(one_at_a_time(&*self.cluster, &self.writing, change, edit))
            .map(|_| ())
            .map_err(|broke| match broke {
                Broke::State(failure) => consensus_said(failure),
                Broke::Edit(failure) => failure,
            })
    }
}

/// Turns a consensus failure into one the order reports.
///
/// A lost quorum keeps its own name rather than becoming a configuration
/// fault: nothing was sent to the certificate authority, so no allowance was
/// spent and another attempt is worth making (ADR-0086).
fn consensus_said(failure: ek_ek_raft::Failure) -> ek_ek_tls::Failure {
    let reason = match failure.reason() {
        ek_ek_raft::Reason::NoQuorum | ek_ek_raft::Reason::NotLeader => ek_ek_tls::Reason::NoQuorum,
        _ => ek_ek_tls::Reason::Configuration,
    };
    ek_ek_tls::Failure::new(reason, failure.detail().to_owned())
}

/// Starts one sweep on a blocking thread, if none is running.
///
/// Off the loop because an order takes seconds at best: driving it here would
/// stop this node answering its peers, and a node that stops answering loses
/// the leadership the order depends on.
fn start_sweep(
    cluster: &Arc<ek_ek_raft::Cluster>,
    watching: &Watching<'_>,
    ordering: &Arc<std::sync::atomic::AtomicBool>,
    writing: &Writer,
) {
    ordering.store(true, std::sync::atomic::Ordering::SeqCst);
    let filing = Replicated {
        cluster: Arc::clone(cluster),
        handle: tokio::runtime::Handle::current(),
        writing: Arc::clone(writing),
    };
    let node = watching.node.clone();
    let data_dir = watching.data_dir.to_owned();
    let running = Arc::clone(ordering);

    tokio::task::spawn_blocking(move || {
        sweep_once(&filing, &node, &data_dir);
        running.store(false, std::sync::atomic::Ordering::SeqCst);
    });
}

/// Orders what is running out, and takes over what somebody left behind.
///
/// The decision comes from the same pure function the single node sweep reads
/// (ADR-0079), so there is no second renewal rule to keep in step.
fn sweep_once(filing: &Replicated, node: &NodeId, data_dir: &str) {
    let held = match crate::acme::Filing::read(filing) {
        Ok(Some(held)) => held,
        Ok(None) => return,
        Err(failure) => return said_failed(&failure),
    };
    let at = now();

    // An order somebody left behind comes first, whether the certificate is
    // due or not. A record that is there is an order in flight, and finishing
    // it costs nothing of the server's allowance while a fresh one does
    // (ADR-0086).
    let mut wanted: Vec<ek_ek_config::CertificateId> = held.orders.keys().cloned().collect();
    for due in ek_ek_tls::due(&held.config.certificates, at) {
        if !wanted.contains(&due.certificate.id) {
            wanted.push(due.certificate.id.clone());
        }
    }
    if wanted.is_empty() {
        return;
    }

    let state_path = crate::renew::state_path(data_dir);
    let mut attempts = match crate::renew::read_state(&state_path) {
        Ok(attempts) => attempts,
        Err(failure) => return said_failed(&failure),
    };

    for id in wanted {
        // A certificate that failed recently is left alone until its wait is
        // over. Trying again now would spend the server's allowance on the
        // same fault, and the allowance belongs to the server (ADR-0077).
        let backoff = attempts.get(&id).cloned().unwrap_or_default();
        if !backoff.ready(at) {
            continue;
        }

        say(&format!(
            r#"{{"kind":"cluster","ts":{},"event":"ordering","certificate":"{}","node":"{}"}}"#,
            now(),
            escape(id.as_str()),
            escape(node.as_str())
        ));

        match crate::acme::obtain_order(&crate::acme::Order {
            config: &held.config,
            filing,
            delivery: crate::acme::Delivery::Replicated,
            id: &id,
            driver: Some(node),
            pause: None,
        }) {
            Ok(()) => {
                attempts.remove(&id);
                say(&format!(
                    r#"{{"kind":"cluster","ts":{},"event":"ordered","certificate":"{}"}}"#,
                    now(),
                    escape(id.as_str())
                ));
            }
            Err(failure) => {
                attempts
                    .entry(id.clone())
                    .or_default()
                    .failed(failure.reason().key(), at);
                say(&format!(
                    r#"{{"kind":"cluster","ts":{},"event":"order_failed","certificate":"{}","reason":"{}","detail":"{}"}}"#,
                    now(),
                    escape(id.as_str()),
                    failure.reason().key(),
                    escape(failure.detail())
                ));
            }
        }
    }

    if let Err(failure) = crate::renew::write_state(&state_path, &attempts) {
        said_failed(&failure);
    }
}

/// Says a failure the sweep could do nothing about.
fn said_failed(failure: &ek_ek_tls::Failure) {
    say(&format!(
        r#"{{"kind":"cluster","ts":{},"event":"failed","detail":"{}"}}"#,
        now(),
        escape(&format!("{failure}"))
    ));
}

/// What one attempt at a configuration came to.
enum Applied {
    /// It reached the log, at this version.
    Went(i64),
    /// It did not, for this reason.
    ///
    /// A refusal is a state of the cluster rather than a verdict on the
    /// document, so the caller keeps offering the same document.
    Refused {
        /// The reason key, as a caller would match on it.
        reason: String,
        /// What an operator would read.
        detail: String,
    },
}

/// Puts one configuration through consensus and reports what came of it.
///
/// Says nothing itself. Whether an answer is worth a record depends on what
/// the last answer was, and only the caller knows that.
async fn apply_once(
    cluster: &Arc<ek_ek_raft::Cluster>,
    writing: &Writer,
    document: &str,
) -> Applied {
    let config: Config = match serde_json::from_str(document) {
        Ok(config) => config,
        Err(error) => {
            return Applied::Refused {
                reason: "config.unreadable".to_owned(),
                detail: format!("the configuration could not be read: {error}"),
            };
        }
    };

    // Through the same one-writer-at-a-time step the order uses. An order
    // running on a blocking thread reads and writes this state too, and a
    // document applied between its read and its write would take the challenge
    // answer with it (ADR-0086).
    let outcome = one_at_a_time(
        &**cluster,
        writing,
        &Change::new("operator", "applied from a file"),
        &mut |held| {
            // Read whole and written whole, like every other write in this
            // product. The key material and the cluster authority the state
            // already holds have to travel with the new document (ADR-0082).
            let mut next = held.unwrap_or_else(|| Snapshot::new(config.clone()));
            // What an order produced comes back with the new document. Only
            // the state has ever held it, and replacing the document with the
            // file as written would drop the material of every certificate the
            // cluster obtained, which is a TLS listener that stops answering on
            // a configuration change nobody connected to it (ADR-0079).
            next.config = ek_ek_tls::carry_obtained(&config, &next.config);
            Ok(next)
        },
    )
    .await;

    match outcome {
        Ok(version) => Applied::Went(version),
        Err(Broke::State(failure)) => Applied::Refused {
            reason: failure.reason().key().to_owned(),
            detail: failure.detail().to_owned(),
        },
        Err(Broke::Edit(failure)) => Applied::Refused {
            reason: failure.reason().key().to_owned(),
            detail: failure.detail().to_owned(),
        },
    }
}

/// Reads `name=address` pairs into a membership.
fn peers(given: &str) -> Result<std::collections::BTreeMap<NodeId, String>, String> {
    let mut held = std::collections::BTreeMap::new();
    for pair in given.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (name, address) = pair
            .split_once('=')
            .ok_or_else(|| format!("{pair} is not a name=address pair"))?;
        if name.trim().is_empty() || address.trim().is_empty() {
            return Err(format!("{pair} is not a name=address pair"));
        }
        held.insert(NodeId::new(name.trim()), address.trim().to_owned());
    }
    if held.is_empty() {
        return Err("a cluster cannot be brought into being with no nodes".to_owned());
    }
    Ok(held)
}

/// Asks one peer whether it is there.
pub fn ping(arguments: &PingArguments<'_>) -> ExitCode {
    let credentials = match material(arguments.material, arguments.node) {
        Ok(credentials) => credentials,
        Err(said) => return refused(&said),
    };

    let Some(runtime) = runtime() else {
        return refused("the async runtime could not be started");
    };

    runtime.block_on(async {
        let expect = NodeId::new(arguments.expect);
        match ek_ek_peer::ask_health(arguments.to, &expect, SCHEMA_VERSION, &credentials).await {
            Ok(answer) => {
                say(&format!(
                    r#"{{"kind":"cluster","ts":{},"event":"answered","node":"{}","protocol":"{}"}}"#,
                    now(),
                    escape(&answer.node),
                    escape(&answer.protocol)
                ));
                ExitCode::SUCCESS
            }
            Err(failure) => refused(&format!("{failure}")),
        }
    })
}

/// A runtime for the two commands that open a socket.
///
/// Built here rather than around `main`, so the commands that read a file and
/// write a certificate do not start a runtime they never use.
fn runtime() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
}

/// How long the certificate on disk has left, when it is not due yet.
///
/// `None` when there is none, or when it is due. An unreadable one is a
/// failure rather than a reason to sign a new one: a file that is there and
/// cannot be read is something an operator has to look at.
fn standing(path: &Path, at: i64) -> Result<Option<i64>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let pem = std::fs::read(path)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    let (not_before, not_after) = ek_ek_peer::window_of_pem(&pem)
        .map_err(|failure| format!("{} could not be read: {failure}", path.display()))?;

    if ek_ek_peer::due(not_before, not_after, at) {
        return Ok(None);
    }
    Ok(Some(ek_ek_peer::remaining(not_after, at)))
}

fn write_material(
    out: &Path,
    authority: &Authority,
    issued: &Issued,
    certificate_path: &Path,
    key_path: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(out)
        .map_err(|error| format!("{} could not be created: {error}", out.display()))?;

    std::fs::write(certificate_path, issued.certificate_pem.as_bytes()).map_err(|error| {
        format!(
            "{} could not be written: {error}",
            certificate_path.display()
        )
    })?;
    std::fs::write(
        out.join(AUTHORITY_FILE),
        authority.certificate_pem.as_bytes(),
    )
    .map_err(|error| {
        format!(
            "{} could not be written: {error}",
            out.join(AUTHORITY_FILE).display()
        )
    })?;

    std::fs::write(key_path, issued.key_pem.expose())
        .map_err(|error| format!("{} could not be written: {error}", key_path.display()))?;
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(KEY_MODE)).map_err(|error| {
        format!(
            "{} could not be restricted to its owner: {error}",
            key_path.display()
        )
    })
}

/// The authority this node holds.
fn held(data_dir: &str) -> Result<Authority, String> {
    let store = SqliteStore::open(Path::new(data_dir))
        .map_err(|error| format!("{data_dir} could not be opened: {error}"))?;
    let state = store
        .read()
        .map_err(|error| format!("the store could not be read: {error}"))?
        .ok_or_else(|| "the store holds nothing yet".to_owned())?;
    ek_ek_peer::read(&state).map_err(|failure| format!("{failure}"))
}

/// What one node needs to speak to its peers, read out of a directory.
fn material(directory: &str, node: &str) -> Result<Credentials, String> {
    let out = PathBuf::from(directory);
    let read = |path: PathBuf| {
        std::fs::read(&path)
            .map_err(|error| format!("{} could not be read: {error}", path.display()))
    };

    Ok(Credentials {
        authority_pem: text(read(out.join(AUTHORITY_FILE))?)?,
        certificate_pem: text(read(out.join(format!("{node}.crt")))?)?,
        key_pem: Secret::new(read(out.join(format!("{node}.key")))?),
    })
}

fn text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes).map_err(|error| format!("a certificate is not text: {error}"))
}

/// A state to write into a store that holds nothing yet.
fn empty(config: Option<&str>) -> Result<Snapshot, String> {
    let path = config.ok_or_else(|| {
        "the store is empty, so a configuration is needed to start it: pass --config".to_owned()
    })?;
    let document = std::fs::read_to_string(path)
        .map_err(|error| format!("{path} could not be read: {error}"))?;
    let config: Config = serde_json::from_str(&document)
        .map_err(|error| format!("{path} is not a configuration: {error}"))?;
    Ok(Snapshot::new(config))
}

fn refused(said: &str) -> ExitCode {
    say(&format!(
        r#"{{"kind":"cluster","ts":{},"event":"failed","detail":"{}"}}"#,
        now(),
        escape(said)
    ));
    ExitCode::FAILURE
}

fn say(record: &str) {
    println!("{record}");
    let _ = std::io::stdout().flush();
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(0))
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::Mutex;

    use ek_ek_config::{Config, SecretId};
    use ek_ek_store::{Change, Secret, Snapshot};

    /// The smallest configuration that reads back, so the measurement below is
    /// about the writes rather than about what is in them.
    fn nothing_configured() -> Config {
        serde_json::from_str(
            r#"{"schema_version":1,"nodes":[],"vips":[],"frontends":[],
                "backends":[],"certificates":[],"dns_providers":[]}"#,
        )
        .expect("the document is a configuration")
    }

    use super::{Broke, State, Writer, one_at_a_time};

    /// A state two writers can be made to collide over.
    ///
    /// The write yields before it lands, which is what a write through
    /// consensus does while it waits for a quorum. Without that the two
    /// writers below would run one after the other whatever the lock did, and
    /// the measurement would pass against no lock at all.
    struct InMemory {
        held: Mutex<Option<Snapshot>>,
    }

    impl State for InMemory {
        fn read(&self) -> Result<Option<Snapshot>, ek_ek_raft::Failure> {
            Ok(self.held.lock().expect("nothing else holds it").clone())
        }

        async fn write(
            &self,
            next: &Snapshot,
            _change: &Change,
        ) -> Result<i64, ek_ek_raft::Failure> {
            tokio::task::yield_now().await;
            *self.held.lock().expect("nothing else holds it") = Some(next.clone());
            Ok(1)
        }
    }

    /// One writer that adds one secret and leaves everything else alone.
    async fn adds(state: &InMemory, writing: &Writer, name: &str) -> Result<i64, Broke> {
        one_at_a_time(
            state,
            writing,
            &Change::new("test", "adds one secret"),
            &mut |held| {
                let mut next = held.expect("the state is there");
                next.secrets
                    .insert(SecretId::new(name), Secret::new(name.as_bytes().to_vec()));
                Ok(next)
            },
        )
        .await
    }

    #[tokio::test]
    async fn two_writers_in_this_process_never_lose_each_others_work() {
        // The two writers this process runs: the loop applying a configuration
        // file and the task driving an order. Both read the whole state,
        // change one part and write the whole thing back. If they overlap, the
        // second one's read predates the first one's write and the first one's
        // change is gone. In production that change is the challenge answer,
        // and losing it fails the order (ADR-0086).
        let state = InMemory {
            held: Mutex::new(Some(Snapshot::new(nothing_configured()))),
        };
        let writing: Writer = Writer::default();

        let (first, second) = tokio::join!(
            adds(&state, &writing, "from-the-configuration"),
            adds(&state, &writing, "from-the-order")
        );
        assert!(first.is_ok() && second.is_ok(), "both writes land");

        let held = state
            .held
            .lock()
            .expect("nothing else holds it")
            .clone()
            .expect("the state is there");
        let names: Vec<&str> = held.secrets.keys().map(SecretId::as_str).collect();
        assert_eq!(
            names,
            vec!["from-the-configuration", "from-the-order"],
            "one writer read the state before the other's write landed and \
             then replaced it, so that write is gone"
        );
    }
}
