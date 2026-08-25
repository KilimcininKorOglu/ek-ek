// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lifecycle of the three node development cluster.

use crate::error::{Error, Result};
use crate::node::Node;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Addresses reserved for VIP tests. Nothing in the compose file may take one.
pub const VIP_RANGE: (u8, u8) = (100, 110);

const NODES: [(&str, u8); 3] = [("node1", 11), ("node2", 12), ("node3", 13)];
const BACKENDS: [(&str, u8); 2] = [("backend1", 21), ("backend2", 22)];
/// The real SMTP server the PROXY protocol measurements run against.
const MAIL: (&str, u8) = ("mail", 23);
/// Port on the mail server that expects a PROXY header.
pub const MAIL_PROXIED_PORT: u16 = 25;
/// Port on the mail server that knows nothing about the header.
pub const MAIL_PLAIN_PORT: u16 = 26;
/// The ACME test server the certificate measurements order from.
const PEBBLE: (&str, u8) = ("pebble", 41);
/// The container running systemd as PID 1, for the one measurement that needs
/// a real init and a real unit file.
const SYSTEMD: (&str, u8) = ("systemd", 51);
/// Where the ACME server publishes its directory document.
pub const PEBBLE_DIRECTORY: &str = "https://pebble:14000/dir";
/// The authority inside the ACME server's image that signs its own HTTPS
/// certificate.
///
/// A client has to be told to trust it, because nothing else does. Read out of
/// the container at run time rather than copied into this repository: a
/// certificate in a tracked file is a certificate that goes stale and a file
/// the secret scan has to be argued with.
const PEBBLE_ROOT: &str = "/test/certs/pebble.minica.pem";
/// The name node1 answers to on the lab network, for an ACME identifier.
///
/// An ACME identifier is a domain name, and a single label is not one. This is
/// a network alias on the node, so the ACME server's own resolver answers it.
pub const LAB_NAME: &str = "node1.ek-ek.test";
/// The lab's name server, which is authoritative for the zone below.
const BIND: (&str, u8) = ("bind", 42);
/// The zone the name server answers for, and the one an update writes into.
pub const LAB_ZONE: &str = "ek-ek.test";
/// The name of the shared key the name server accepts updates signed with.
pub const LAB_TSIG_KEY: &str = "ek-ek-update";
/// A wildcard name inside the lab zone, for measuring what only DNS-01 gets.
pub const LAB_WILDCARD: &str = "*.ek-ek.test";
/// Where the name server leaves the key it generated at start.
///
/// Regenerated on every start and never tracked: a shared key in a repository
/// is a credential published from the first commit.
const TSIG_SECRET_FILE: &str = "docker-data/bind/tsig.secret";
const BUILDER: &str = "builder";
const BUILDERS: usize = 1;
const LAB_PREFIX: [u8; 3] = [172, 28, 0];
/// Where a binary installed by the harness lands inside a node.
const INSTALL_DIR: &str = "/var/lib/ek-ek";
/// Where the systemd container reads its binaries from.
const SYSTEMD_DIR: &str = "/opt/ek-ek";

/// The cluster, brought up and cleaned for one test.
///
/// Dropping it does not tear the containers down. Bringing three containers up
/// costs more than every test in a file put together, so the cluster is shared
/// and each test takes it over clean. [`Cluster::stop`] is there for the test
/// that has to prove teardown works.
pub struct Cluster {
    nodes: Vec<Node>,
    dump_logs_on_panic: bool,
}

impl Cluster {
    /// Brings the cluster up if it is not already, then clears leftover state.
    ///
    /// Calling this at the start of every test is what makes two consecutive
    /// runs of the same test both pass.
    pub fn start() -> Result<Self> {
        require_env_file()?;
        // `--build` on every start. Without it a changed Dockerfile is ignored
        // as long as an image with the same tag exists, and the tests then run
        // against an image nobody can reproduce from the repository.
        compose_ok(&["up", "-d", "--build", "--wait"])?;
        refresh_builder()?;

        let cluster = Self {
            nodes: NODES
                .iter()
                .map(|(name, host)| Node::new(name, lab_address(*host)))
                .collect(),
            dump_logs_on_panic: true,
        };
        cluster.reset()?;
        Ok(cluster)
    }

    /// Tears the containers down and removes the lab network.
    ///
    /// Takes ownership, because a torn down cluster cannot be used again.
    pub fn stop(mut self) -> Result<()> {
        self.dump_logs_on_panic = false;
        compose_ok(&["down", "--remove-orphans"])
    }

    /// Stops one node's container, and with it everything running inside.
    ///
    /// This is what "a node went away" means: not a process that was killed,
    /// but a machine that is no longer there. A measurement of what the rest
    /// of the cluster does without it has to be able to say that much.
    pub fn stop_node(&self, name: &str) -> Result<()> {
        self.node(name)?;
        compose_ok(&["stop", "-t", "3", name])
    }

    /// Starts a node's container again and waits until it answers.
    ///
    /// The store is on a bind mount, so what comes back is the node that left
    /// rather than a new one.
    pub fn start_node(&self, name: &str) -> Result<()> {
        let node = self.node(name)?;
        compose_ok(&["start", name])?;
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while std::time::Instant::now() < deadline {
            if node.run(&["true"]).is_ok_and(|answered| answered.ok()) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err(Error::new(format!("{name} did not come back")))
    }

    /// True when every service in the compose project is running.
    pub fn is_up() -> Result<bool> {
        let listed = compose_output(&["ps", "--status", "running", "--format", "{{.Name}}"])?;
        let running = listed.lines().filter(|l| !l.trim().is_empty()).count();
        // Three nodes, two backends, the mail server and the builder.
        let expected = NODES.len() + BACKENDS.len() + BUILDERS + 1;
        Ok(running >= expected)
    }

    /// The three load balancer nodes.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// One node by compose service name.
    pub fn node(&self, name: &str) -> Result<&Node> {
        self.nodes
            .iter()
            .find(|n| n.name() == name)
            .ok_or_else(|| Error::new(format!("no node named {name}")))
    }

    /// Address of a backend web server on the lab network.
    pub fn backend_address(&self, name: &str) -> Result<Ipv4Addr> {
        BACKENDS
            .iter()
            .find(|(service, _)| *service == name)
            .map(|(_, host)| lab_address(*host))
            .ok_or_else(|| Error::new(format!("no backend named {name}")))
    }

    /// The container running systemd as PID 1.
    ///
    /// One measurement uses it: whether the supervision runs under a real
    /// unit, as a non-root user, with the capabilities granted ambiently
    /// (ADR-0012, ADR-0087). Nothing else in this lab can answer that, because
    /// every other container has no init but Docker's and runs as root.
    pub fn systemd(&self) -> Node {
        Node::new(SYSTEMD.0, lab_address(SYSTEMD.1))
    }

    /// Puts a workspace binary where the systemd container can run it.
    ///
    /// A separate mount from the nodes', because that container is not one of
    /// them: it carries no lab addresses and takes part in no cluster.
    /// Returns the path the unit runs it from.
    pub fn install_binary_for_systemd(&self, package: &str, bin: &str) -> Result<String> {
        build_in_container(package, bin)?;

        let built = repo_root()
            .join("docker-data/builder-target/release")
            .join(bin);
        if !built.is_file() {
            return Err(Error::new(format!(
                "{} was not produced by the builder",
                built.display()
            )));
        }
        ensure_host_owned(&built)?;
        let target = repo_root().join("docker-data/systemd").join(bin);
        std::fs::create_dir_all(repo_root().join("docker-data/systemd"))
            .map_err(|e| Error::new(format!("cannot make the systemd directory: {e}")))?;
        std::fs::copy(&built, &target)
            .map_err(|e| Error::new(format!("cannot place {bin} for systemd: {e}")))?;
        set_executable(&target)?;
        Ok(format!("{SYSTEMD_DIR}/{bin}"))
    }

    /// Address of the real SMTP server on the lab network.
    pub fn mail_address(&self) -> Ipv4Addr {
        lab_address(MAIL.1)
    }

    /// Address of the ACME test server on the lab network.
    pub fn pebble_address(&self) -> Ipv4Addr {
        lab_address(PEBBLE.1)
    }

    /// The certificate authority the ACME test server's own HTTPS endpoint is
    /// signed by, as PEM.
    ///
    /// Read out of the running container, so what a measurement trusts is what
    /// the image actually uses rather than a copy that drifted.
    pub fn pebble_root(&self) -> Result<String> {
        // Copied out rather than read with a shell: the image carries the
        // server and nothing else, so there is no command inside it to run.
        let pem = copy_out("ek-ek-pebble", PEBBLE_ROOT)?;
        if !pem.contains("BEGIN CERTIFICATE") {
            return Err(Error::new(
                "the ACME test server's root certificate did not come back as PEM".to_owned(),
            ));
        }
        Ok(pem)
    }

    /// Address of the lab's name server.
    pub fn bind_address(&self) -> Ipv4Addr {
        lab_address(BIND.1)
    }

    /// The shared key the name server accepts updates signed with.
    ///
    /// Read from what the container wrote at start, so a measurement uses the
    /// key that server actually holds rather than one written down somewhere.
    pub fn tsig_secret(&self) -> Result<String> {
        let path = repo_root().join(TSIG_SECRET_FILE);
        let held = std::fs::read_to_string(&path)
            .map_err(|e| Error::new(format!("cannot read {}: {e}", path.display())))?;
        let held = held.trim().to_owned();
        if held.is_empty() {
            return Err(Error::new(format!(
                "{} holds no key; the name server may not have started",
                path.display()
            )));
        }
        Ok(held)
    }

    /// Everything the name server has logged, newest lines last.
    ///
    /// It records every update it accepted or refused, which is the reading of
    /// a dynamic update that comes from outside this project.
    pub fn bind_log(&self, lines: usize) -> Result<String> {
        compose_output(&["logs", "--tail", &lines.to_string(), BIND.0])
    }

    /// Everything the ACME test server has logged, newest lines last.
    ///
    /// It says what it asked for and what it made of the answer, which is the
    /// only reading of the challenge that comes from outside this project.
    pub fn pebble_log(&self, lines: usize) -> Result<String> {
        compose_output(&["logs", "--tail", &lines.to_string(), PEBBLE.0])
    }

    /// Everything the mail server has logged, newest lines last.
    ///
    /// Postfix names the client of every session on its connect line, which is
    /// the only reading of a PROXY header that comes from outside this project.
    pub fn mail_log(&self, lines: usize) -> Result<String> {
        compose_output(&["logs", "--tail", &lines.to_string(), MAIL.0])
    }

    /// An address from the reserved VIP range.
    ///
    /// Tests take a VIP from here rather than inventing one, so cleanup knows
    /// every address it has to remove.
    pub fn vip(&self, offset: u8) -> Result<Ipv4Addr> {
        let host = VIP_RANGE.0 + offset;
        if host > VIP_RANGE.1 {
            return Err(Error::new(format!(
                "vip offset {offset} falls outside the reserved range {}-{}",
                VIP_RANGE.0, VIP_RANGE.1
            )));
        }
        Ok(lab_address(host))
    }

    /// Clears everything a previous test may have left on the nodes.
    ///
    /// Without this a test that failed halfway leaves a VIP or a process
    /// behind, and the next run reads that leftover as its own result.
    pub fn reset(&self) -> Result<()> {
        let script = format!(
            "for host in $(seq {} {}); do \
                 ip addr del {}.{}.{}.$host/24 dev eth0 >/dev/null 2>&1 || true; \
             done; \
             ip neigh flush dev eth0 >/dev/null 2>&1 || true",
            VIP_RANGE.0, VIP_RANGE.1, LAB_PREFIX[0], LAB_PREFIX[1], LAB_PREFIX[2]
        );
        for node in &self.nodes {
            // Processes first: one still running could put an address back
            // between the delete and the next test.
            node.kill_matching(&format!("{INSTALL_DIR}/"))?;
            node.shell(&script)?;
        }
        Ok(())
    }

    /// Compiles a workspace binary for Linux and puts it on every node.
    ///
    /// The nodes carry the capabilities but no toolchain, and the builder has
    /// the toolchain but no capabilities. The binary crosses on a bind mount.
    /// Returns the path it can be run from inside a node.
    pub fn install_binary(&self, package: &str, bin: &str) -> Result<String> {
        build_in_container(package, bin)?;

        let built = repo_root()
            .join("docker-data/builder-target/release")
            .join(bin);
        if !built.is_file() {
            return Err(Error::new(format!(
                "{} was not produced by the builder",
                built.display()
            )));
        }
        ensure_host_owned(&built)?;
        for (name, _) in NODES {
            let target = repo_root().join("docker-data").join(name).join(bin);
            std::fs::copy(&built, &target)
                .map_err(|e| Error::new(format!("cannot place {bin} on {name}: {e}")))?;
            set_executable(&target)?;
        }
        Ok(format!("{INSTALL_DIR}/{bin}"))
    }

    /// Container logs, newest lines last.
    pub fn logs(&self, lines: usize) -> Result<String> {
        compose_output(&["logs", "--tail", &lines.to_string()])
    }

    /// Everything worth knowing about the cluster when a test has just failed.
    ///
    /// Gathered here rather than inside [`Drop`] so a test can check that the
    /// report actually carries container state. Proving that by letting a test
    /// fail would mean shipping a failing test.
    pub fn failure_report(&self) -> String {
        let mut report = String::from("--- container logs ---\n");
        match self.logs(80) {
            Ok(logs) => report.push_str(&logs),
            Err(e) => report.push_str(&format!("could not read container logs: {e}\n")),
        }
        for node in &self.nodes {
            match node.run_ok(&["ip", "-4", "addr", "show", "dev", "eth0"]) {
                Ok(shown) => {
                    report.push_str(&format!("--- {} addresses ---\n{shown}", node.name()));
                }
                Err(e) => {
                    report.push_str(&format!("--- {} addresses unavailable: {e}\n", node.name()));
                }
            }
        }
        report.push_str("--- end of container state ---\n");
        report
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        // Only on the way out of a failing test. Printing the state of a
        // passing test buries the one run that needs reading.
        if !self.dump_logs_on_panic || !std::thread::panicking() {
            return;
        }
        eprintln!("{}", self.failure_report());
    }
}

/// A `docker compose` invocation rooted at the repository.
///
/// `--env-file` is explicit because compose looks for `.env` next to the
/// compose file, not in the project root.
pub(crate) fn compose() -> Command {
    let mut command = Command::new("docker");
    command.current_dir(repo_root()).args([
        "compose",
        "--env-file",
        ".env",
        "-f",
        "docker/compose.yml",
    ]);
    command
}

pub(crate) fn repo_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        // crates/ek-ek-itest -> crates -> repository root
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest
            .ancestors()
            .nth(2)
            .unwrap_or(manifest)
            .to_path_buf()
    })
}

fn lab_address(host: u8) -> Ipv4Addr {
    Ipv4Addr::new(LAB_PREFIX[0], LAB_PREFIX[1], LAB_PREFIX[2], host)
}

fn require_env_file() -> Result<()> {
    if repo_root().join(".env").is_file() {
        return Ok(());
    }
    Err(Error::new(
        "no .env in the repository root; run `make dev-env` first. \
         Compose reads HOST_UID and HOST_GID from it, and without them the \
         bind mounts fill with files owned by the wrong user.",
    ))
}

fn compose_ok(args: &[&str]) -> Result<()> {
    let output = compose()
        .args(args)
        .output()
        .map_err(|e| Error::new(format!("docker compose {args:?} could not start: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(Error::new(format!(
        "docker compose {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

/// Replaces the builder when the files it compiles from are no longer there.
///
/// The builder mounts single files, and an editor that writes a new file over
/// `Cargo.toml` leaves the container holding the old one, now unlinked. Every
/// build then fails with a missing manifest, which reads like a broken
/// workspace rather than a stale mount. Checking costs one exec; recreating
/// only happens after the manifest was actually edited.
fn refresh_builder() -> Result<()> {
    let present = compose()
        .args(["exec", "-T", BUILDER, "test", "-f", "/src/Cargo.toml"])
        .output()
        .map_err(|e| Error::new(format!("cannot reach the builder: {e}")))?;
    if present.status.success() {
        return Ok(());
    }
    compose_ok(&["up", "-d", "--force-recreate", BUILDER])
}

/// Reads one file out of a container that has no shell in it.
///
/// `docker cp` to standard output writes a tar stream, so the file is copied
/// into a temporary directory and read from there instead of parsed.
fn copy_out(container: &str, path: &str) -> Result<String> {
    let directory = std::env::temp_dir().join(format!("ek-ek-copy-{container}"));
    std::fs::create_dir_all(&directory)
        .map_err(|e| Error::new(format!("cannot make {}: {e}", directory.display())))?;
    let name = Path::new(path)
        .file_name()
        .ok_or_else(|| Error::new(format!("{path} names no file")))?;
    let target = directory.join(name);

    let output = Command::new("docker")
        .args(["cp", &format!("{container}:{path}")])
        .arg(&target)
        .output()
        .map_err(|e| Error::new(format!("docker cp could not start: {e}")))?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "docker cp {container}:{path} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    std::fs::read_to_string(&target)
        .map_err(|e| Error::new(format!("cannot read {}: {e}", target.display())))
}

fn compose_output(args: &[&str]) -> Result<String> {
    let output = compose()
        .args(args)
        .output()
        .map_err(|e| Error::new(format!("docker compose {args:?} could not start: {e}")))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Builds one binary inside the builder container.
///
/// `--locked` keeps the read only source mount workable: without it cargo would
/// want to write `Cargo.lock` back into the mount and fail.
///
/// `setpriv` drops to the host user, so the cargo cache and the target
/// directory do not fill with root owned files that the host cannot remove.
fn build_in_container(package: &str, bin: &str) -> Result<()> {
    static BUILT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let built = BUILT.get_or_init(|| Mutex::new(HashSet::new()));
    {
        let seen = built.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains(&format!("{package}/{bin}")) {
            return Ok(());
        }
    }

    let script = format!(
        "set -e; \
         setpriv --reuid \"$HOST_UID\" --regid \"$HOST_GID\" --clear-groups \
             cargo build --locked --release \
                 --manifest-path /src/Cargo.toml -p {package} --bin {bin}"
    );
    let output = compose()
        .args(["exec", "-T", BUILDER, "bash", "-c", &script])
        .output()
        .map_err(|e| Error::new(format!("builder could not start: {e}")))?;
    if output.status.success() {
        built
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(format!("{package}/{bin}"));
        return Ok(());
    }
    Err(Error::new(format!(
        "building {package}/{bin} in the builder failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

/// Refuses a binary the builder produced as root.
///
/// The build drops to the host user with `setpriv`. If that ever stops
/// working, the cargo cache and the target directory fill with root owned
/// files and `make dev-reset` cannot remove them. Docker on macOS remaps bind
/// mount ownership and would hide it; on Linux this check is what catches it.
#[cfg(unix)]
fn ensure_host_owned(built: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    // The repository is checked out by the host user, so it carries the uid the
    // build output is supposed to have.
    let expected = std::fs::metadata(repo_root())?.uid();
    let actual = std::fs::metadata(built)?.uid();
    if actual == expected {
        return Ok(());
    }
    Err(Error::new(format!(
        "{} belongs to uid {actual} while the repository belongs to uid {expected}. \
         The build did not drop to the host user, so docker-data is filling with \
         files the host cannot remove.",
        built.display()
    )))
}

#[cfg(not(unix))]
fn ensure_host_owned(_built: &Path) -> Result<()> {
    Err(Error::new("the harness only runs on unix hosts"))
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Err(Error::new("the harness only runs on unix hosts"))
}
