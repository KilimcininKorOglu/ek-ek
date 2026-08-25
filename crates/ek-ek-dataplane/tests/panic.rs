// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A panic on any thread ends this process.
//!
//! pingora runs every service on its own thread, so a panic there ends the
//! thread and leaves the process running. Measured in the lab: a listener
//! that could not bind panicked, the process kept answering the agent, and
//! the node held its virtual address for a service that was gone (ADR-0087).
//!
//! The measurement runs in a second process, because the rule it measures is
//! that the process ends. Asserting it in this one would take the test
//! runner with it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;
use std::time::Duration;

/// Set in the process that is measured, not in the one that measures.
const CHILD: &str = "EK_EK_PANIC_IN_A_THREAD";

#[test]
fn a_panic_on_any_thread_ends_the_process() {
    if std::env::var(CHILD).is_ok() {
        ek_ek_dataplane::end_on_a_panic();
        // Joined rather than left running, so without the hook this process
        // reaches the end and exits cleanly. That is what makes the
        // measurement two sided: remove the hook and it passes here.
        std::thread::spawn(|| panic!("a listener could not bind"))
            .join()
            .ok();
        std::thread::sleep(Duration::from_millis(200));
        return;
    }

    let ran = Command::new(std::env::current_exe().expect("the test binary knows its own path"))
        .args(["a_panic_on_any_thread_ends_the_process", "--exact"])
        .env(CHILD, "1")
        .output()
        .expect("the test binary should be runnable");

    // No exit code at all on unix means a signal ended it, which is what
    // `abort` does. A process that survived its thread's panic would have
    // reached the end of the branch above and exited zero.
    assert!(
        ran.status.code().is_none(),
        "the process survived a panic on one of its threads and exited {:?}: \
         a node would keep its virtual address for listeners that are gone\n{}",
        ran.status.code(),
        String::from_utf8_lossy(&ran.stderr)
    );
}
