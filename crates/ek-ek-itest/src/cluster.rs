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

/// Addresses reserved for VIP tests. Nothing in the compose file may take one.
pub const VIP_RANGE: (u8, u8) = (100, 110);

const NODES: [(&str, u8); 3] = [("node1", 11), ("node2", 12), ("node3", 13)];
const BACKENDS: [(&str, u8); 2] = [("backend1", 21), ("backend2", 22)];
const BUILDER: &str = "builder";
const BUILDERS: usize = 1;
const LAB_PREFIX: [u8; 3] = [172, 28, 0];
/// Where a binary installed by the harness lands inside a node.
const INSTALL_DIR: &str = "/var/lib/ek-ek";

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

    /// True when every service in the compose project is running.
    pub fn is_up() -> Result<bool> {
        let listed = compose_output(&["ps", "--status", "running", "--format", "{{.Name}}"])?;
        let running = listed.lines().filter(|l| !l.trim().is_empty()).count();
        // Three nodes, two backends and the builder.
        let expected = NODES.len() + BACKENDS.len() + BUILDERS;
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
