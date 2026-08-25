// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What supervising `data-plane` must decide.
//!
//! No process is started here. The rules are about which decision follows
//! which event, and measuring them against real processes would mean waiting
//! out the real backoff to find out whether the fifth crash raises the alarm.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use ek_ek_agent::{
    ALARM_AFTER, Effect, FIRST_WAIT, LONGEST_WAIT, Standing, Supervision,
    serving as counts_as_serving, wait_after,
};
use ek_ek_ipc::DataPlaneState;

/// How many unanswered questions these measurements allow before a crash.
const PATIENCE: u32 = 2;

/// A supervision with the process up and carrying traffic.
fn serving(now: Instant) -> Supervision {
    let mut held = Supervision::new(PATIENCE);
    assert_eq!(held.begin(), vec![Effect::Start]);
    let _ = now;
    assert_eq!(held.serves(), Vec::new(), "nothing was lowered yet");
    assert_eq!(held.standing(), Standing::Serving);
    held
}

#[test]
fn the_claim_comes_down_the_moment_the_process_ends() {
    // ADR-0033's whole point. A node holding the address while its traffic
    // path is gone is a total outage for that address, and it lasts until
    // somebody notices rather than until the next election.
    let now = Instant::now();
    let mut held = serving(now);

    let effects = held.ended(now);
    assert!(
        effects.contains(&Effect::Demote),
        "the process ended and the claim stayed where it was: {effects:?}"
    );
    assert_eq!(held.standing(), Standing::Down);
}

#[test]
fn a_second_death_does_not_lower_a_claim_that_is_already_down() {
    // The claim is one value, not a counter. Lowering it twice would be a
    // second advertisement saying what the first one already said, and a
    // caller acting on it would move an address that has already moved.
    let now = Instant::now();
    let mut held = serving(now);

    assert!(held.ended(now).contains(&Effect::Demote));
    let again = held.ended(now + Duration::from_secs(1));
    assert!(
        !again.contains(&Effect::Demote),
        "the claim was lowered twice: {again:?}"
    );
}

#[test]
fn the_claim_goes_back_up_on_a_report_and_not_on_a_start() {
    // The difference this whole design rests on. A process that is running is
    // not a process that is serving, so starting it is not what restores the
    // claim; the first report that says it serves is (ADR-0087).
    let now = Instant::now();
    let mut held = serving(now);
    held.ended(now);

    let started = held.due(now + LONGEST_WAIT);
    assert_eq!(started, vec![Effect::Start]);
    assert!(
        !started.contains(&Effect::Restore),
        "starting the process put the claim back before it answered: {started:?}"
    );
    assert_eq!(held.standing(), Standing::Starting);

    let answered = held.answered();
    assert!(
        !answered.contains(&Effect::Restore),
        "a liveness answer put the claim back: a process whose listeners \
         accept nothing answers exactly like one that serves: {answered:?}"
    );
    assert_eq!(held.standing(), Standing::Starting);

    let reported = held.serves();
    assert!(
        reported.contains(&Effect::Restore),
        "the process reported that it serves and the claim stayed down: {reported:?}"
    );
    assert_eq!(held.standing(), Standing::Serving);
}

#[test]
fn a_report_from_a_process_that_never_stopped_changes_nothing() {
    // The reports arrive every interval. Acting on each of them would put the
    // claim back over and over, which is an advertisement per interval saying
    // what nothing changed.
    let now = Instant::now();
    let mut held = serving(now);

    for _ in 0..5 {
        assert_eq!(
            held.serves(),
            Vec::new(),
            "a report from a process that was already serving produced work"
        );
    }
}

#[test]
fn a_process_that_stops_answering_is_ended_rather_than_left_running() {
    // The case a process table cannot see: the process is there, and nothing
    // it does reaches anybody. Ending it is what makes the two ways in follow
    // one path (ADR-0087).
    let now = Instant::now();
    let mut held = serving(now);

    assert_eq!(
        held.unanswered(),
        Vec::new(),
        "one unanswered question ended the process, so a single lost answer \
         costs this node its address"
    );
    assert_eq!(
        held.unanswered(),
        vec![Effect::Terminate],
        "the patience ran out and the process was left running"
    );
}

#[test]
fn an_answer_between_two_missed_questions_starts_the_patience_over() {
    // Otherwise the misses add up across minutes and a process that answers
    // almost every time is eventually killed for it.
    let now = Instant::now();
    let mut held = serving(now);

    held.unanswered();
    held.answered();
    assert_eq!(
        held.unanswered(),
        Vec::new(),
        "a missed question from before an answer was still being counted"
    );
}

#[test]
fn the_waits_between_restarts_double_and_then_stop_growing() {
    // ADR-0033: exponential backoff with a cap. Without the cap a process
    // that has crashed thirty times waits longer than anybody is willing to
    // watch; without the growth it crashes in a loop as fast as the machine
    // allows.
    assert_eq!(
        wait_after(0),
        Duration::ZERO,
        "the first start is not a restart"
    );
    assert_eq!(wait_after(1), FIRST_WAIT);
    assert_eq!(wait_after(2), FIRST_WAIT * 2);
    assert_eq!(wait_after(3), FIRST_WAIT * 4);

    // Written as a number rather than as the constant, so a change to the
    // constant is a change this measurement sees.
    assert_eq!(wait_after(1), Duration::from_millis(100));
    assert_eq!(LONGEST_WAIT, Duration::from_secs(30));

    let capped = wait_after(20);
    assert_eq!(capped, LONGEST_WAIT, "the wait grew past the cap");
    assert_eq!(
        wait_after(1_000),
        LONGEST_WAIT,
        "a very large count wrapped or overflowed instead of staying capped"
    );

    // And every wait is at least as long as the one before it.
    let mut before = Duration::ZERO;
    for crashes in 1..40 {
        let wait = wait_after(crashes);
        assert!(
            wait >= before,
            "wait {crashes} is shorter than the one before it: {wait:?} after {before:?}"
        );
        before = wait;
    }
}

#[test]
fn restarting_never_stops() {
    // ADR-0033 says so in as many words. A node that gave up would hold no
    // address and never try again, so a fault that clears by itself would
    // still cost the node until somebody logged in.
    let mut now = Instant::now();
    let mut held = serving(now);

    for round in 1..200_u32 {
        held.ended(now);
        let due = held.start_at().expect("a restart is always scheduled");
        now = due;
        assert_eq!(
            held.due(now),
            vec![Effect::Start],
            "the supervision stopped restarting after {round} crashes"
        );
    }
}

#[test]
fn nothing_is_started_before_its_wait_is_over() {
    // Otherwise the backoff is a number nobody reads and the process restarts
    // as fast as it crashes.
    let now = Instant::now();
    let mut held = serving(now);
    held.ended(now);

    let due = held.start_at().expect("a restart is scheduled");
    assert_eq!(
        held.due(due - Duration::from_millis(1)),
        Vec::new(),
        "the process was started before its wait was over"
    );
    assert_eq!(held.due(due), vec![Effect::Start]);
    assert_eq!(
        held.due(due + Duration::from_secs(1)),
        Vec::new(),
        "the same restart was started twice"
    );
}

#[test]
fn the_alarm_comes_on_after_the_threshold_and_the_restarts_carry_on() {
    // M10 turns this into a notification; here it only has to exist, and the
    // restarts have to keep going while it does.
    let mut now = Instant::now();
    let mut held = serving(now);

    for crash in 1..ALARM_AFTER {
        let effects = held.ended(now);
        assert!(
            !effects.contains(&Effect::Alarm),
            "the alarm came on after {crash} crashes, before the threshold"
        );
        assert!(!held.alarming());
        now = held.start_at().expect("a restart is scheduled");
        assert_eq!(held.due(now), vec![Effect::Start]);
    }

    let effects = held.ended(now);
    assert!(
        effects.contains(&Effect::Alarm),
        "the threshold was reached and no alarm was produced: {effects:?}"
    );
    assert!(held.alarming(), "the alarm was said once and not held");
    assert_eq!(held.crashes(), ALARM_AFTER);

    // Still restarting.
    now = held.start_at().expect("a restart is still scheduled");
    assert_eq!(held.due(now), vec![Effect::Start]);

    // And said once, not once per crash after it.
    let again = held.ended(now);
    assert!(
        !again.contains(&Effect::Alarm),
        "the alarm was raised again while it was already on: {again:?}"
    );
}

#[test]
fn the_alarm_goes_off_when_the_process_serves_again() {
    // An alarm that never clears is one an operator learns to ignore.
    let mut now = Instant::now();
    let mut held = serving(now);

    for _ in 0..ALARM_AFTER {
        held.ended(now);
        now = held.start_at().expect("a restart is scheduled");
        held.due(now);
    }
    assert!(held.alarming());

    let effects = held.serves();
    assert!(
        effects.contains(&Effect::Clear),
        "the process serves again and the alarm stayed on: {effects:?}"
    );
    assert!(!held.alarming());
    assert_eq!(
        held.crashes(),
        0,
        "the crashes before a successful start are still counted, so the next \
         single crash would raise the alarm again"
    );
}

#[test]
fn a_process_that_answers_in_between_does_not_reach_the_threshold() {
    // The counter is consecutive crashes, not crashes. A process that crashes
    // once a week for five weeks is not a crash loop, and an alarm that could
    // not tell the difference would be on for ever.
    let mut now = Instant::now();
    let mut held = serving(now);

    for _ in 0..ALARM_AFTER * 3 {
        held.ended(now);
        now = held.start_at().expect("a restart is scheduled");
        held.due(now);
        held.serves();
        assert!(
            !held.alarming(),
            "a process that came back between crashes raised the crash loop alarm"
        );
    }
}

#[test]
fn a_process_that_stops_answering_is_treated_exactly_like_one_that_crashed() {
    // The criterion says the same behaviour, so this measures the two paths
    // against each other rather than restating one of them.
    let now = Instant::now();

    let mut crashed = serving(now);
    let by_crash = crashed.ended(now);

    let mut silent = serving(now);
    silent.unanswered();
    assert_eq!(silent.unanswered(), vec![Effect::Terminate]);
    // The caller ends it, and the end arrives the same way any other does.
    let by_silence = silent.ended(now);

    assert_eq!(
        by_crash, by_silence,
        "a process that stopped answering was treated differently from one \
         that crashed"
    );
    assert_eq!(crashed.standing(), silent.standing());
    assert_eq!(crashed.crashes(), silent.crashes());
    assert_eq!(crashed.start_at().is_some(), silent.start_at().is_some());
}

#[test]
fn a_process_that_is_already_down_is_not_asked_to_stop_again() {
    // The liveness questions go unanswered while the process is not there.
    // Counting those would end a process that has already ended and schedule
    // a restart on top of the one already waiting.
    let now = Instant::now();
    let mut held = serving(now);
    held.ended(now);

    for _ in 0..10 {
        assert_eq!(
            held.unanswered(),
            Vec::new(),
            "a process that had already crashed was asked to stop"
        );
    }
    assert_eq!(held.crashes(), 1, "the crash was counted more than once");
}

#[test]
fn a_process_that_is_still_starting_does_not_count_as_serving() {
    // The lab found this one: the traffic path reports itself the moment it
    // has a configuration, well before its listeners accept anything. An
    // agent that took that report as an answer would put this node's claim
    // back up for a service nobody can reach (ADR-0087).
    assert!(
        !counts_as_serving(DataPlaneState::Starting),
        "a process that is still starting was counted as one carrying traffic"
    );
}

#[test]
fn a_process_that_serves_counts_as_serving() {
    assert!(counts_as_serving(DataPlaneState::Serving));
}

#[test]
fn a_degraded_process_still_counts_as_serving() {
    // Degraded means serving with something wrong, and what is wrong is
    // usually a backend every node sees the same way. Lowering the claim for
    // it would move the address to a node with the same problem (ADR-0034).
    assert!(
        counts_as_serving(DataPlaneState::Degraded),
        "a degraded process lost this node its address, and moving the \
         address does not fix a backend"
    );
}

#[test]
fn a_report_that_says_it_serves_starts_the_patience_over() {
    // A report reaches the agent the same way an answer does. Counting it as
    // silence would end a process that was talking, which is the crash the
    // supervision invents rather than the one it is there to find.
    let now = Instant::now();
    let mut held = serving(now);
    held.ended(now);
    held.due(now + LONGEST_WAIT);

    held.unanswered();
    held.serves();
    assert_eq!(
        held.unanswered(),
        Vec::new(),
        "one missed question before a report and one after it ended the \
         process, so the report did not count as reaching the agent"
    );
}
