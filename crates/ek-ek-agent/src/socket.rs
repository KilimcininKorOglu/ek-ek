// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The agent's side of the socket `data-plane` takes its configuration from.
//!
//! One JSON object per line, both ways (ADR-0002). This side delivers the
//! configuration, asks whether the other side is still answering, and reports
//! everything it hears to whoever is supervising.
//!
//! # Why the questions are asked from here
//!
//! The supervision decides what an unanswered question means; the socket is
//! what can ask one. Keeping the two apart is what lets the decision be
//! measured without a socket and the socket without a decision.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::Duration;

use ek_ek_ipc::{AgentMessage, DataPlaneMessage, Ping, decode, encode};

/// Permissions the socket carries.
///
/// Owner only. The configuration crossing it holds private keys and the
/// challenge answers of a running order, and a socket anybody could connect
/// to would hand both to any user on the machine (ADR-0069).
const SOCKET_MODE: u32 = 0o600;

/// What the socket heard from the traffic path.
#[derive(Clone, Debug)]
pub enum Heard {
    /// A process introduced itself.
    Greeted {
        /// Which process it is, so a connection can be matched to a child.
        pid: u32,
    },
    /// A liveness question was answered.
    Answered,
    /// A periodic report arrived.
    Reported(Box<ek_ek_ipc::StatusReport>),
    /// A delivered configuration was refused.
    Refused(Box<ek_ek_ipc::ConfigRejection>),
}

/// The agent's listening socket.
#[derive(Debug)]
pub struct Listening {
    listener: UnixListener,
    path: PathBuf,
    /// The document delivered to whoever connects, already encoded.
    document: Arc<str>,
    /// Counts up on every delivery, so a report can name which one is live.
    generation: Arc<AtomicU64>,
}

impl Listening {
    /// Binds the socket and prepares the document to deliver.
    ///
    /// # Errors
    ///
    /// Returns whatever the operating system said when the socket could not
    /// be bound, and an error naming the file when the configuration cannot
    /// be read or is not a configuration.
    pub fn open(path: &Path, config: &Path) -> std::io::Result<Self> {
        let document = std::fs::read_to_string(config)?;
        let config: ek_ek_config::Config = serde_json::from_str(&document).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} is not a configuration: {error}", config.display()),
            )
        })?;
        // Refused here rather than at the far end. The traffic path stops on a
        // first delivery that does not validate, and an agent that sent one
        // would be restarting a process for a fault of its own (T-018).
        ek_ek_config::validate(&config).map_err(|faults| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the configuration is not valid: {:?}", faults.codes()),
            )
        })?;

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        // A leftover socket from a previous run makes the bind fail, and the
        // traffic path would then connect to nothing.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;

        Ok(Self {
            listener,
            path: path.to_path_buf(),
            document: Arc::from(document.trim()),
            generation: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Where the socket is, for a record naming it.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Answers connections until the flag is set.
    ///
    /// Every connection gets two threads: one reading what arrives and one
    /// asking whether the far end is still answering. Asking on the reading
    /// thread would mean a question waits behind whatever is being read,
    /// which is exactly the case being asked about.
    pub fn serve(&self, heard: &Sender<Heard>, asking: Duration, stopping: &Arc<AtomicBool>) {
        for stream in self.listener.incoming() {
            if stopping.load(Ordering::SeqCst) {
                return;
            }
            let Ok(stream) = stream else { continue };
            let heard = heard.clone();
            let document = Arc::clone(&self.document);
            let generation = Arc::clone(&self.generation);
            let stopping = Arc::clone(stopping);
            std::thread::spawn(move || {
                answer(stream, &heard, &document, &generation, asking, &stopping);
            });
        }
    }
}

impl Drop for Listening {
    /// Takes the socket file away.
    ///
    /// A file left behind makes the next bind fail, and the agent would then
    /// start with a traffic path that can never reach it.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Answers one traffic path connection.
fn answer(
    stream: UnixStream,
    heard: &Sender<Heard>,
    document: &str,
    generation: &Arc<AtomicU64>,
    asking: Duration,
    stopping: &Arc<AtomicBool>,
) {
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let mut writer = stream;
    let mut lines = BufReader::new(reader).lines();

    // The traffic path greets first and says which generation it already
    // holds. Only a connection holding nothing needs the configuration; the
    // long lived one that follows already has it, and resending would make
    // every reconnection look like a change.
    let Some(Ok(line)) = lines.next() else {
        return;
    };
    let Ok(DataPlaneMessage::Hello(hello)) = decode::<DataPlaneMessage>(&line) else {
        return;
    };
    let _ = heard.send(Heard::Greeted { pid: hello.pid });

    if hello.generation.is_none() {
        let next = generation.fetch_add(1, Ordering::SeqCst) + 1;
        if send(
            &mut writer,
            &format!(
                r#"{{"message":"config","generation":{next},"config":{document},"certificates":{{}},"challenges":{{}}}}"#
            ),
        )
        .is_err()
        {
            return;
        }
    }

    let asker = {
        let Ok(mut writer) = writer.try_clone() else {
            return;
        };
        let stopping = Arc::clone(stopping);
        std::thread::spawn(move || {
            let mut nonce = 0_u64;
            while !stopping.load(Ordering::SeqCst) {
                std::thread::sleep(asking);
                nonce = nonce.wrapping_add(1);
                let Ok(line) = encode(&AgentMessage::Ping(Ping { nonce })) else {
                    return;
                };
                if send(&mut writer, line.trim_end()).is_err() {
                    return;
                }
            }
        })
    };

    for line in lines.map_while(Result::ok) {
        match decode::<DataPlaneMessage>(&line) {
            // The nonce is not checked against the one asked. Any answer is
            // one this process produced after this process asked, which is
            // what the question is for; matching them would only narrow the
            // measurement to the last question in flight.
            Ok(DataPlaneMessage::Pong(_)) => {
                let _ = heard.send(Heard::Answered);
            }
            Ok(DataPlaneMessage::Status(report)) => {
                let _ = heard.send(Heard::Reported(Box::new(report)));
            }
            Ok(DataPlaneMessage::ConfigRejected(rejection)) => {
                let _ = heard.send(Heard::Refused(Box::new(rejection)));
            }
            Ok(DataPlaneMessage::Hello(hello)) => {
                let _ = heard.send(Heard::Greeted { pid: hello.pid });
            }
            Err(_) => return,
        }
    }
    // The far end is gone, so the questions have nowhere to go. Ending the
    // asking thread here keeps one thread per connection rather than one per
    // connection this process has ever had.
    drop(writer);
    let _ = asker.join();
}

fn send(writer: &mut UnixStream, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}
