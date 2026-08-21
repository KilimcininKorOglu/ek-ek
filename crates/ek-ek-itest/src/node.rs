// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Running commands inside a node container and watching long lived ones.

use std::io::{BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::cluster::compose;
use crate::error::{Error, Result};

/// What a finished command left behind.
#[derive(Debug, Clone)]
pub struct Output {
    /// Exit code, or `None` when a signal ended the process.
    pub code: Option<i32>,
    /// Everything the command wrote to stdout.
    pub stdout: String,
    /// Everything the command wrote to stderr.
    pub stderr: String,
}

impl Output {
    /// True when the command exited with code zero.
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

/// One container in the development cluster.
#[derive(Debug, Clone)]
pub struct Node {
    name: String,
    address: Ipv4Addr,
}

impl Node {
    pub(crate) fn new(name: &str, address: Ipv4Addr) -> Self {
        Self {
            name: name.to_string(),
            address,
        }
    }

    /// Compose service name, which is also the container hostname.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Fixed address on the lab network.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Runs a command to completion and returns what it produced.
    ///
    /// A non-zero exit is not an error here: plenty of checks are phrased as
    /// "this command should fail". Use [`Node::run_ok`] when it must succeed.
    pub fn run(&self, argv: &[&str]) -> Result<Output> {
        let mut command = compose();
        command.arg("exec").arg("-T").arg(&self.name).args(argv);
        let output = command
            .output()
            .map_err(|e| Error::new(format!("{}: cannot run {argv:?}: {e}", self.name)))?;
        Ok(Output {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// Runs a command that must succeed and returns its stdout.
    pub fn run_ok(&self, argv: &[&str]) -> Result<String> {
        let output = self.run(argv)?;
        if output.ok() {
            return Ok(output.stdout);
        }
        Err(Error::new(format!(
            "{}: {argv:?} exited with {:?}\nstdout: {}\nstderr: {}",
            self.name, output.code, output.stdout, output.stderr
        )))
    }

    /// Runs a shell snippet inside the container.
    pub fn shell(&self, script: &str) -> Result<Output> {
        self.run(&["bash", "-c", script])
    }

    /// Starts a command and keeps it running, streaming its output.
    pub fn spawn(&self, argv: &[&str]) -> Result<Background> {
        let mut command = compose();
        command
            .arg("exec")
            .arg("-T")
            .arg(&self.name)
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| Error::new(format!("{}: cannot start {argv:?}: {e}", self.name)))?;

        let stdout = collect(child.stdout.take());
        let stderr = collect(child.stderr.take());
        Ok(Background {
            child,
            stdout: stdout.0,
            stderr: stderr.0,
            readers: vec![stdout.1, stderr.1],
        })
    }

    /// Kills every process in the container whose command line matches.
    ///
    /// Killing the local `docker compose exec` client leaves the process inside
    /// the container running, so a spawned process is always stopped from the
    /// inside.
    ///
    /// The first character is wrapped in a character class before the pattern
    /// is used. `pkill -f` matches whole command lines, and the shell running
    /// the `pkill` carries the pattern in its own command line, so a plain
    /// pattern makes the shell kill itself and everything after it in the
    /// script never runs.
    pub fn kill_matching(&self, pattern: &str) -> Result<()> {
        let mut characters = pattern.chars();
        let first = characters
            .next()
            .ok_or_else(|| Error::new("kill_matching needs a non-empty pattern"))?;
        let self_safe = format!("[{first}]{}", characters.as_str());
        self.shell(&format!("pkill -9 -f '{self_safe}' || true"))?;
        Ok(())
    }

    /// MAC address of the lab interface.
    pub fn mac(&self) -> Result<String> {
        Ok(self
            .run_ok(&["cat", "/sys/class/net/eth0/address"])?
            .trim()
            .to_string())
    }

    /// True when the address is configured on the lab interface.
    pub fn has_address(&self, address: Ipv4Addr) -> Result<bool> {
        let shown = self.run_ok(&["ip", "-4", "addr", "show", "dev", "eth0"])?;
        Ok(shown
            .split_whitespace()
            .any(|word| word == address.to_string() || word.starts_with(&format!("{address}/"))))
    }

    /// Adds an address to the lab interface.
    pub fn add_address(&self, address: Ipv4Addr, prefix_len: u8) -> Result<()> {
        self.run_ok(&[
            "ip",
            "addr",
            "add",
            &format!("{address}/{prefix_len}"),
            "dev",
            "eth0",
        ])?;
        Ok(())
    }

    /// Removes an address from the lab interface.
    pub fn remove_address(&self, address: Ipv4Addr, prefix_len: u8) -> Result<()> {
        self.run_ok(&[
            "ip",
            "addr",
            "del",
            &format!("{address}/{prefix_len}"),
            "dev",
            "eth0",
        ])?;
        Ok(())
    }

    /// Sends ICMP echo requests and reports whether any came back.
    pub fn can_reach(&self, address: Ipv4Addr) -> Result<bool> {
        Ok(self
            .run(&["ping", "-c", "2", "-W", "1", &address.to_string()])?
            .ok())
    }
}

/// A command still running inside a container.
pub struct Background {
    child: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    readers: Vec<JoinHandle<()>>,
}

impl Background {
    /// Everything written to stdout so far.
    pub fn stdout(&self) -> String {
        read_shared(&self.stdout)
    }

    /// Everything written to stderr so far.
    pub fn stderr(&self) -> String {
        read_shared(&self.stderr)
    }

    /// Waits until the given text shows up on stderr.
    ///
    /// This is how the harness knows a tool is ready before traffic is
    /// generated. Measuring before the observer is listening turns the startup
    /// window into a fault in the results.
    pub fn wait_for_stderr(&self, needle: &str, timeout: Duration) -> Result<()> {
        self.wait_for(needle, timeout, false)
    }

    /// Waits until the given text shows up on stdout.
    pub fn wait_for_stdout(&self, needle: &str, timeout: Duration) -> Result<()> {
        self.wait_for(needle, timeout, true)
    }

    fn wait_for(&self, needle: &str, timeout: Duration, on_stdout: bool) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let seen = if on_stdout {
                self.stdout()
            } else {
                self.stderr()
            };
            if seen.contains(needle) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        Err(Error::new(format!(
            "waited {timeout:?} for {needle:?}\nstdout: {}\nstderr: {}",
            self.stdout(),
            self.stderr()
        )))
    }

    /// Waits for the command to exit and returns what it produced.
    pub fn finish(mut self) -> Result<Output> {
        let status = self.child.wait()?;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        Ok(Output {
            code: status.code(),
            stdout: self.stdout(),
            stderr: self.stderr(),
        })
    }
}

fn collect<R: Read + Send + 'static>(stream: Option<R>) -> (Arc<Mutex<String>>, JoinHandle<()>) {
    let shared = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&shared);
    let handle = thread::spawn(move || {
        let Some(stream) = stream else { return };
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            // A read failure is written into the buffer rather than ending the
            // loop quietly, so a truncated capture is visible as a truncated
            // capture instead of an empty one.
            let last = match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => false,
                Err(e) => {
                    line = format!("<stream ended early: {e}>\n");
                    true
                }
            };
            // A poisoned lock means a reader thread panicked. The buffer is
            // still readable and losing it would hide the very output that
            // explains the failure.
            let mut guard = sink.lock().unwrap_or_else(|e| e.into_inner());
            guard.push_str(&line);
            drop(guard);
            if last {
                break;
            }
        }
    });
    (shared, handle)
}

fn read_shared(shared: &Arc<Mutex<String>>) -> String {
    shared.lock().unwrap_or_else(|e| e.into_inner()).clone()
}
