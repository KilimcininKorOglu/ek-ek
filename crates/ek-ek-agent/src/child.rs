// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Starting and ending the `data-plane` process.
//!
//! # Why the child is told to die with its parent
//!
//! An agent that crashes leaves a traffic path nobody supervises. It keeps
//! its listeners, keeps answering, and no longer has anything lowering this
//! node's VRRP claim when it goes wrong. Two nodes then serve the same
//! address and one of them is unsupervised, which is worse than the crash
//! that started it.
//!
//! Linux answers this with `PR_SET_PDEATHSIG`: the kernel signals the child
//! when the thread that started it goes, whether the parent exited cleanly or
//! was killed outright. Nothing in userspace can be relied on here, because
//! the case being handled is the parent not running any more.
//!
//! The call is made in the child between `fork` and `exec`, which is the only
//! window where it can be made at all.

use std::io;
use std::process::{Child as Spawned, Command, ExitStatus, Stdio};

/// How long a process is given to end on its own before it is killed.
///
/// `data-plane` finishes in-flight requests when it is asked to stop, and the
/// agent is stopping anyway, so this is generous rather than tight. What it
/// prevents is an agent that never exits because its child never did.
pub const TERMINATE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// One `data-plane` process.
#[derive(Debug)]
pub struct Child {
    process: Spawned,
}

impl Child {
    /// Starts one process, told to die with this one.
    ///
    /// # Errors
    ///
    /// Returns whatever the operating system said when the process could not
    /// be started, which is what an operator needs to see: a missing binary
    /// and a refused permission are different faults with different fixes.
    #[allow(unsafe_code)]
    pub fn spawn(program: &str, arguments: &[String]) -> io::Result<Self> {
        let mut command = Command::new(program);
        command
            .args(arguments)
            // Inherited on purpose. Both processes write one JSON object per
            // line to standard output (ADR-0037), and whatever collects the
            // agent's records collects the traffic path's the same way.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt as _;
            // SAFETY: the closure runs in the child between fork and exec,
            // where only async-signal-safe calls are allowed. `prctl` and
            // `getppid` are both on that list, and neither touches memory
            // this process allocated.
            unsafe {
                command.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    // The parent may already have died between the fork and
                    // this line, in which case the signal has been and gone
                    // and nothing will send it again. Asking who the parent
                    // is now is what closes that window.
                    if libc::getppid() == 1 {
                        return Err(io::Error::other(
                            "the agent went away while the traffic path was starting",
                        ));
                    }
                    Ok(())
                });
            }
        }

        Ok(Self {
            process: command.spawn()?,
        })
    }

    /// The process identifier, as the operating system knows it.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.process.id()
    }

    /// Whether the process has ended, without waiting for it.
    ///
    /// # Errors
    ///
    /// Returns whatever the operating system said when the process could not
    /// be asked about.
    pub fn ended(&mut self) -> io::Result<Option<ExitStatus>> {
        self.process.try_wait()
    }

    /// Asks the process to stop, and kills it if it will not.
    ///
    /// Asking first is what lets in-flight requests finish. Killing after is
    /// what keeps the agent from waiting on a process that has stopped
    /// reading its signals, which is the same fault the supervision treats as
    /// a crash.
    ///
    /// # Errors
    ///
    /// Returns whatever the operating system said when the process could
    /// neither be asked nor killed.
    #[allow(unsafe_code)]
    pub fn terminate(&mut self, patience: std::time::Duration) -> io::Result<ExitStatus> {
        if let Some(status) = self.process.try_wait()? {
            return Ok(status);
        }

        // Never signalled as a group. A pid that did not fit would become
        // zero, and zero means every process in this one's group, which is
        // the agent itself and whatever started it.
        let pid = libc::pid_t::try_from(self.process.id()).map_err(|_| {
            io::Error::other(format!(
                "the traffic path's process id {} does not fit the one the kernel signals",
                self.process.id()
            ))
        })?;
        // SAFETY: the pid belongs to a child of this process that has not
        // been reaped, so it names that child and the number cannot have
        // been reused by another process yet.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }

        let deadline = std::time::Instant::now() + patience;
        while std::time::Instant::now() < deadline {
            if let Some(status) = self.process.try_wait()? {
                return Ok(status);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        self.process.kill()?;
        self.process.wait()
    }
}
