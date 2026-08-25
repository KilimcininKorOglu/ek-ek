// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What starting and ending a child process must do.
//!
//! Real processes, because everything here is a system call and a double
//! would only measure the double. The children are shell commands rather than
//! the traffic path: what is being measured is the supervision's side of the
//! contract, and a real `data-plane` would drag a socket and a configuration
//! into a measurement about signals.
//!
//! The rule that a child dies with its parent is not here. It needs the agent
//! itself to die, which no test in this process can arrange for itself, so it
//! is measured in the lab against a real killed agent.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use ek_ek_agent::Child;

/// Runs a shell command as the child.
fn shell(script: &str) -> Vec<String> {
    vec!["-c".to_owned(), script.to_owned()]
}

/// Runs `terminate` with a bound of the measurement's own.
///
/// A product that never gave up would leave a plain call waiting for ever,
/// and a measurement that never returns reports nothing. The process is
/// killed before this gives up, so nothing is left running either way.
fn terminate_within(
    child: &mut Child,
    patience: Duration,
    give_up_after: Duration,
) -> (std::io::Result<std::process::ExitStatus>, Duration) {
    let started = Instant::now();
    let pid = child.pid();
    let returned = std::sync::atomic::AtomicBool::new(false);

    let (outcome, took) = std::thread::scope(|scope| {
        let done = &returned;
        scope.spawn(move || {
            while started.elapsed() < give_up_after {
                if done.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            // The measurement is over either way. Killing here is what lets
            // the call under measurement return, so a product that waits for
            // ever produces a failure rather than a test that never ends.
            std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status()
                .ok();
        });
        let outcome = child.terminate(patience);
        let took = started.elapsed();
        returned.store(true, std::sync::atomic::Ordering::SeqCst);
        (outcome, took)
    });

    assert!(
        took < give_up_after,
        "terminate took {took:?} and was still waiting when this measurement \
         gave up at {give_up_after:?}: a process that will not stop was \
         waited on rather than killed"
    );
    (outcome, took)
}

/// Waits for the child to end, and says how long it took.
fn until_ended(child: &mut Child, patience: Duration) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < patience {
        if child
            .ended()
            .expect("the child can be asked about")
            .is_some()
        {
            return Some(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

#[test]
fn a_started_process_runs_and_says_which_one_it_is() {
    let mut child = Child::spawn("/bin/sh", &shell("exit 0")).expect("the child starts");
    assert!(child.pid() > 1, "the child reported no usable process id");
    assert!(
        until_ended(&mut child, Duration::from_secs(5)).is_some(),
        "the child never ended"
    );
}

#[test]
fn a_running_process_is_not_reported_as_ended() {
    // Otherwise the supervision would count a crash on the first tick and
    // restart a process that is serving perfectly well.
    let mut child = Child::spawn("/bin/sh", &shell("sleep 5")).expect("the child starts");
    assert!(
        child
            .ended()
            .expect("the child can be asked about")
            .is_none(),
        "a running process was reported as ended"
    );
    let _ = child.terminate(Duration::from_secs(2));
}

#[test]
fn a_process_that_could_not_be_started_says_why() {
    // A missing binary and a refused permission are different faults with
    // different fixes, and a supervision that reported "it crashed" for both
    // would restart a binary that is not there for ever with nothing said.
    let refused = Child::spawn("/nonexistent/ek-ek-not-a-binary", &[]);
    let error = refused.expect_err("a binary that is not there cannot start");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::NotFound,
        "the reason a process could not start was lost: {error}"
    );
}

#[test]
fn a_process_asked_to_stop_is_asked_before_it_is_killed() {
    // In-flight requests finish because the traffic path is asked rather than
    // killed. A supervision that went straight to a kill would cut them, and
    // nothing else in the product would notice.
    let mut child = Child::spawn(
        "/bin/sh",
        // Exits 7 on its own when asked, which no kill can produce: a killed
        // process carries a signal, not an exit code.
        &shell("trap 'exit 7' TERM; while true; do sleep 0.05; done"),
    )
    .expect("the child starts");

    // Given a moment to install the handler. Without it the signal can arrive
    // before the trap is set and the shell dies on the default action, which
    // would pass this measurement for the wrong reason.
    std::thread::sleep(Duration::from_millis(300));

    let status = child
        .terminate(Duration::from_secs(5))
        .expect("the child can be stopped");
    assert_eq!(
        status.code(),
        Some(7),
        "the process was killed rather than asked: {status:?}"
    );
}

#[test]
fn a_process_that_will_not_stop_is_killed_rather_than_waited_on_for_ever() {
    // The same fault the supervision treats as a crash: the process is there
    // and no longer acting on what reaches it. An agent that waited would
    // never exit, and the node would keep an address it cannot serve.
    let mut child = Child::spawn(
        "/bin/sh",
        &shell("trap '' TERM; while true; do sleep 0.05; done"),
    )
    .expect("the child starts");
    std::thread::sleep(Duration::from_millis(300));

    let patience = Duration::from_millis(400);
    let (outcome, took) = terminate_within(&mut child, patience, Duration::from_secs(10));
    let status = outcome.expect("the child can be killed");

    assert!(
        status.code().is_none(),
        "a process that ignores the request exited on its own: {status:?}"
    );
    assert!(
        took >= patience,
        "the process was killed before it was given its patience: {took:?}"
    );
    assert!(
        took < patience + Duration::from_secs(5),
        "the kill did not follow the patience: {took:?}"
    );
}

#[test]
fn a_process_that_already_ended_is_not_signalled_again() {
    // Its number can have been given to something else by then, and a signal
    // sent to it would end a process this one knows nothing about.
    let mut child = Child::spawn("/bin/sh", &shell("exit 3")).expect("the child starts");
    assert!(until_ended(&mut child, Duration::from_secs(5)).is_some());

    let status = child
        .terminate(Duration::from_secs(5))
        .expect("an ended child reports what it did");
    assert_eq!(
        status.code(),
        Some(3),
        "the status of a process that had already ended was lost"
    );
}
