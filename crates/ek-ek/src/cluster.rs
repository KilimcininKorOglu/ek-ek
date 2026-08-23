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
use std::time::{SystemTime, UNIX_EPOCH};

use ek_ek_config::{Config, NodeId};
use ek_ek_peer::{Authority, Credentials, Issued};
use ek_ek_store::{Change, Secret, Snapshot, SqliteStore, Store};

/// Permissions a written private key carries.
const KEY_MODE: u32 = 0o600;

/// What the authority certificate is called in an output directory.
const AUTHORITY_FILE: &str = "cluster-ca.crt";

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

    let node = NodeId::new(arguments.node);
    let listener = match ek_ek_peer::Listener::bind(arguments.listen, &node, &credentials) {
        Ok(listener) => listener,
        Err(failure) => return refused(&format!("the peer port could not be opened: {failure}")),
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
        match listener.serve_one() {
            Ok(served) => say(&format!(
                r#"{{"kind":"cluster","ts":{},"event":"served","caller":"{}"}}"#,
                now(),
                escape(served.caller.as_str())
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
}

/// Asks one peer whether it is there.
pub fn ping(arguments: &PingArguments<'_>) -> ExitCode {
    let credentials = match material(arguments.material, arguments.node) {
        Ok(credentials) => credentials,
        Err(said) => return refused(&said),
    };

    let expect = NodeId::new(arguments.expect);
    match ek_ek_peer::ask_health(arguments.to, &expect, &credentials) {
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
