// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `node-agent` process itself.
//!
//! Three execution paths, on purpose (ADR-0002, ADR-0087):
//!
//! - the socket, answering the traffic path and asking whether it still
//!   answers back,
//! - the virtual router, advertising on its own interval,
//! - the supervision, starting and ending the traffic path.
//!
//! The router never shares a loop with the supervision. The T-009 spike
//! measured what happens when it does: a wait during a process replacement
//! delayed the advertisement past its interval, which takes the address away
//! for a fault that did not happen.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use crate::child::Child;
use crate::socket::{Heard, Listening};
use crate::supervise::{Effect, Supervision};

/// How often the supervision looks at its timers.
///
/// Short, because ADR-0033 asks for the claim to come down within a second of
/// the traffic path going and the tick is the whole delay between the process
/// ending and that being noticed.
const TICK: Duration = Duration::from_millis(50);

/// How often the standing is written out even when nothing changed.
///
/// A record of an event passes once. A reader that connects afterwards has no
/// way to learn the alarm is still on, so the state is said again on a timer
/// as well as at the moment it changes (ADR-0087).
const SAY_INTERVAL: Duration = Duration::from_secs(5);

/// How long a process that stopped answering is given to stop on its own.
///
/// Shorter than [`crate::TERMINATE_PATIENCE`], which is for an agent shutting
/// down cleanly. Here the process has already stopped answering, this node is
/// about to give its address up, and every second spent asking politely is a
/// second the address has not moved.
const SILENT_PATIENCE: Duration = Duration::from_secs(1);

/// Everything `node-agent` was asked to be.
pub struct Plan<'a> {
    /// Where the traffic path takes its configuration from.
    pub socket: &'a str,
    /// The configuration document to deliver.
    pub config: &'a str,
    /// The program to run as the traffic path.
    pub program: &'a str,
    /// What to pass it.
    pub arguments: Vec<String>,
    /// How often the traffic path is asked whether it is still answering.
    pub asking: Duration,
    /// How many questions may go unanswered before it counts as crashed.
    pub patience: u32,
    /// The virtual router to run, when this node runs one.
    pub router: Option<crate::vrrp::Vrrp>,
}

/// What the supervision decided about this node's claim.
enum Claim {
    /// Lower it: the traffic path is not serving.
    Down,
    /// Put it back: the traffic path answered.
    Up,
}

/// Runs the agent until it is told to stop.
pub fn run(plan: Plan<'_>) -> ExitCode {
    let stopping = Arc::new(AtomicBool::new(false));
    if let Err(error) = catch_signals(&stopping) {
        return failed(&format!("the stop signals could not be caught: {error}"));
    }

    // A virtual address is not on this node's interface until this node holds
    // the role, and the traffic path binds its listeners when it starts. The
    // kernel refuses a bind to an address that is not there, so without this
    // the traffic path can only start on the node that already holds the
    // address. Every other node would crash-loop until it won an election,
    // which is the moment it is least able to take over (ADR-0033).
    if plan.router.is_some() {
        allow_binding_addresses_this_node_does_not_hold();
    }

    let listening = match Listening::open(Path::new(plan.socket), Path::new(plan.config)) {
        Ok(listening) => listening,
        Err(error) => return failed(&format!("{} could not be opened: {error}", plan.socket)),
    };
    say(&format!(
        r#"{{"kind":"agent","ts":{},"event":"listening","socket":"{}"}}"#,
        milliseconds(),
        escaped(plan.socket)
    ));

    let (heard_sender, heard) = mpsc::channel::<Heard>();
    let (claims, claimed) = mpsc::channel::<Claim>();

    #[cfg(target_os = "linux")]
    let router = match plan
        .router
        .as_ref()
        .map(crate::vrrp::Vrrp::plan)
        .transpose()
    {
        Ok(wanted) => start_router(wanted, claimed, &stopping),
        Err(complaint) => {
            return failed(&format!(
                "the virtual router was not asked for correctly: {complaint}"
            ));
        }
    };
    #[cfg(not(target_os = "linux"))]
    let router: Option<std::thread::JoinHandle<()>> = {
        // Nowhere to send a claim, so the channel is dropped rather than left
        // open with nobody reading it. VRRP moves addresses over netlink and
        // sends IP protocol 112, neither of which exists here (ADR-0007).
        drop(claimed);
        if plan.router.is_some() {
            return failed("a virtual router was asked for, and VRRP only runs on Linux");
        }
        None
    };

    let outcome = std::thread::scope(|scope| {
        let listening = &listening;
        let socket_stop = Arc::clone(&stopping);
        scope.spawn(move || {
            listening.serve(&heard_sender, plan.asking, &socket_stop);
        });

        supervise(&plan, &heard, &claims, &stopping)
    });

    if let Some(router) = router {
        let _ = router.join();
    }
    outcome
}

/// Runs the virtual router on its own thread.
///
/// Its own thread rather than the supervision's, because the supervision
/// waits on processes and the router has a deadline measured in fractions of
/// its advertisement interval (ADR-0029, ADR-0087).
#[cfg(target_os = "linux")]
fn start_router(
    plan: Option<ek_ek_vrrp::Plan>,
    claimed: mpsc::Receiver<Claim>,
    stopping: &Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let plan = plan?;
    let stopping = Arc::clone(stopping);
    Some(std::thread::spawn(move || {
        let transport = match ek_ek_vrrp::RawSocket::open() {
            Ok(socket) => socket,
            Err(error) => {
                failed(&format!(
                    "the raw socket could not be opened: {error}; VRRP is IP protocol 112 \
                     and needs CAP_NET_RAW"
                ));
                return;
            }
        };
        let mut router = match ek_ek_vrrp::Router::start(plan, &transport, Instant::now()) {
            Ok(router) => router,
            Err(error) => {
                failed(&format!(
                    "the virtual router could not start: {error}; moving an address \
                     needs CAP_NET_ADMIN"
                ));
                return;
            }
        };

        while !stopping.load(Ordering::SeqCst) {
            let now = Instant::now();
            // Read before the tick, so a claim decided in this round is
            // advertised in this round rather than the next one.
            while let Ok(claim) = claimed.try_recv() {
                match claim {
                    Claim::Down => router.demote("data_plane_down", now),
                    Claim::Up => router.restore("data_plane_serving", now),
                }
            }
            router.tick(now);
            std::thread::sleep(Duration::from_millis(10));
        }
        // Told on purpose rather than left to time out. A node that stops
        // without giving its addresses up leaves every other node waiting out
        // three advertisement intervals for something it already knows.
        router.stop(Instant::now());
    }))
}

/// The supervision loop.
fn supervise(
    plan: &Plan<'_>,
    heard: &mpsc::Receiver<Heard>,
    claims: &mpsc::Sender<Claim>,
    stopping: &Arc<AtomicBool>,
) -> ExitCode {
    let mut supervision = Supervision::new(plan.patience);
    let mut child: Option<Child> = None;
    let mut answered_at = Instant::now();
    let mut question_at = Instant::now() + plan.asking;
    let mut said_at = Instant::now();
    let mut said = None;

    carry(
        supervision.begin(),
        &mut supervision,
        &mut child,
        plan,
        claims,
    );

    while !stopping.load(Ordering::SeqCst) {
        let now = Instant::now();

        while let Ok(what) = heard.try_recv() {
            match what {
                // A Pong says the process still reads what is sent to it.
                // It does not say the listeners accept anything, so it keeps
                // the process from counting as crashed and leaves the claim
                // where it is (ADR-0087).
                Heard::Answered => {
                    answered_at = now;
                    let effects = supervision.answered();
                    carry(effects, &mut supervision, &mut child, plan, claims);
                }
                Heard::Greeted { pid } => say(&format!(
                    r#"{{"kind":"agent","ts":{},"event":"greeted","pid":{pid}}}"#,
                    milliseconds()
                )),
                Heard::Refused(rejection) => say(&format!(
                    r#"{{"kind":"agent","ts":{},"event":"config_refused","generation":{},"errors":{}}}"#,
                    milliseconds(),
                    rejection.generation,
                    rejection.errors.len()
                )),
                // A report is an answer as well, and it carries something a
                // liveness answer does not: what the process says it is
                // doing. What that means for the claim is
                // [`crate::supervise::serving`].
                Heard::Reported(report) => {
                    // A report proves the link is alive either way, so the
                    // silence count starts over. What it says about the
                    // claim is [`crate::supervise::serving`].
                    answered_at = now;
                    let effects = if crate::supervise::serving(report.state) {
                        supervision.serves()
                    } else {
                        say(&format!(
                            r#"{{"kind":"agent","ts":{},"event":"data_plane_not_serving","state":"{}"}}"#,
                            milliseconds(),
                            escaped(&format!("{:?}", report.state).to_lowercase())
                        ));
                        supervision.answered()
                    };
                    carry(effects, &mut supervision, &mut child, plan, claims);
                }
            }
        }

        if let Some(running) = child.as_mut() {
            match running.ended() {
                Ok(Some(status)) => {
                    say(&format!(
                        r#"{{"kind":"agent","ts":{},"event":"data_plane_ended","status":"{}"}}"#,
                        milliseconds(),
                        escaped(&status.to_string())
                    ));
                    child = None;
                    let effects = supervision.ended(now);
                    carry(effects, &mut supervision, &mut child, plan, claims);
                }
                Ok(None) => {}
                Err(error) => {
                    return failed(&format!(
                        "the traffic path could not be asked about: {error}"
                    ));
                }
            }
        }

        // One question's worth of silence per interval, counted only while
        // there is a process to be silent.
        if now >= question_at {
            question_at = now + plan.asking;
            if child.is_some() && now.duration_since(answered_at) >= plan.asking {
                let effects = supervision.unanswered();
                carry(effects, &mut supervision, &mut child, plan, claims);
            }
        }

        let effects = supervision.due(now);
        carry(effects, &mut supervision, &mut child, plan, claims);

        // The standing goes out when it changes and again on a timer, so a
        // reader that connects later still learns where things stand.
        let standing = (supervision.standing(), supervision.alarming());
        if said != Some(standing) || now.duration_since(said_at) >= SAY_INTERVAL {
            said = Some(standing);
            said_at = now;
            say(&format!(
                r#"{{"kind":"agent","ts":{},"event":"standing","standing":"{}","crashes":{},"alarming":{}}}"#,
                milliseconds(),
                supervision.standing().name(),
                supervision.crashes(),
                supervision.alarming()
            ));
        }

        std::thread::sleep(TICK);
    }

    // Nothing is left behind. A traffic path that outlived its agent keeps
    // its listeners with nothing lowering this node's claim when it goes
    // wrong, which is worse than the stop that started it.
    if let Some(mut running) = child.take() {
        let pid = running.pid();
        match running.terminate(crate::TERMINATE_PATIENCE) {
            Ok(status) => say(&format!(
                r#"{{"kind":"agent","ts":{},"event":"data_plane_stopped","pid":{pid},"status":"{}"}}"#,
                milliseconds(),
                escaped(&status.to_string())
            )),
            Err(error) => {
                return failed(&format!("the traffic path could not be stopped: {error}"));
            }
        }
    }
    say(&format!(
        r#"{{"kind":"agent","ts":{},"event":"stopped"}}"#,
        milliseconds()
    ));
    ExitCode::SUCCESS
}

/// Does what the supervision asked for.
fn carry(
    effects: Vec<Effect>,
    supervision: &mut Supervision,
    child: &mut Option<Child>,
    plan: &Plan<'_>,
    claims: &mpsc::Sender<Claim>,
) {
    for effect in effects {
        match effect {
            Effect::Demote => {
                say(&format!(
                    r#"{{"kind":"agent","ts":{},"event":"claim_lowered","reason":"data_plane_down"}}"#,
                    milliseconds()
                ));
                let _ = claims.send(Claim::Down);
            }
            Effect::Restore => {
                say(&format!(
                    r#"{{"kind":"agent","ts":{},"event":"claim_restored","reason":"data_plane_serving"}}"#,
                    milliseconds()
                ));
                let _ = claims.send(Claim::Up);
            }
            Effect::Terminate => {
                let Some(running) = child.as_mut() else {
                    continue;
                };
                let pid = running.pid();
                say(&format!(
                    r#"{{"kind":"agent","ts":{},"event":"data_plane_silent","pid":{pid}}}"#,
                    milliseconds()
                ));
                match running.terminate(SILENT_PATIENCE) {
                    Ok(status) => {
                        *child = None;
                        say(&format!(
                            r#"{{"kind":"agent","ts":{},"event":"data_plane_ended","status":"{}"}}"#,
                            milliseconds(),
                            escaped(&status.to_string())
                        ));
                        // The same path a crash takes, because the criterion
                        // is that the two are treated alike (ADR-0087).
                        let more = supervision.ended(Instant::now());
                        carry(more, supervision, child, plan, claims);
                    }
                    Err(error) => {
                        failed_line(&format!("the traffic path could not be stopped: {error}"))
                    }
                }
            }
            Effect::Start => match Child::spawn(plan.program, &plan.arguments) {
                Ok(started) => {
                    say(&format!(
                        r#"{{"kind":"agent","ts":{},"event":"data_plane_started","pid":{}}}"#,
                        milliseconds(),
                        started.pid()
                    ));
                    *child = Some(started);
                }
                Err(error) => {
                    // Not fatal. A binary that is not there yet, a mount that
                    // has not come up: both clear by themselves, and an agent
                    // that exited here would take VRRP down with it for a
                    // fault the restart would have fixed.
                    failed_line(&format!("the traffic path could not be started: {error}"));
                    let more = supervision.ended(Instant::now());
                    carry(more, supervision, child, plan, claims);
                }
            },
            Effect::Alarm => say(&format!(
                r#"{{"kind":"agent","ts":{},"event":"crash_loop","crashes":{}}}"#,
                milliseconds(),
                supervision.crashes()
            )),
            Effect::Clear => say(&format!(
                r#"{{"kind":"agent","ts":{},"event":"crash_loop_over"}}"#,
                milliseconds()
            )),
        }
    }
}

/// Lets a listener bind an address this node does not currently hold.
///
/// The standard answer for a load balancer that follows a virtual address:
/// the listener is bound once and the address arrives and leaves underneath
/// it. Without it every listener would have to be rebuilt on every failover,
/// and a rebuild drops the connections ADR-0009 promises to keep.
///
/// Said either way rather than refused. An installation may have set it
/// already, and a node with no virtual address of its own never needs it.
fn allow_binding_addresses_this_node_does_not_hold() {
    const KNOB: &str = "/proc/sys/net/ipv4/ip_nonlocal_bind";

    let asked = std::fs::write(KNOB, "1\n");
    // Read back rather than reported from the write. An installation may have
    // set it already through a unit or a sysctl file, in which case this
    // process cannot write it and does not need to; what matters is the value
    // the kernel holds, not who put it there.
    let held = std::fs::read_to_string(KNOB).unwrap_or_default();
    let allowed = held.trim() == "1";
    say(&format!(
        r#"{{"kind":"agent","ts":{},"event":"nonlocal_bind","allowed":{allowed},"set_here":{},"detail":"{}"}}"#,
        milliseconds(),
        asked.is_ok(),
        escaped(
            &asked
                .err()
                .map_or_else(String::new, |error| error.to_string())
        )
    ));
}

/// Catches the signals that mean stop.
///
/// Handled rather than left to the default action, because the default is to
/// die at once and leave the traffic path running with nobody watching it.
#[allow(unsafe_code)]
fn catch_signals(stopping: &Arc<AtomicBool>) -> std::io::Result<()> {
    STOPPING
        .set(Arc::clone(stopping))
        .map_err(|_| std::io::Error::other("the stop flag was installed twice"))?;

    extern "C" fn asked(_signal: libc::c_int) {
        // Async-signal-safe: one atomic store into memory that was allocated
        // before the handler was installed. Nothing here allocates, locks or
        // writes to a stream.
        if let Some(stopping) = STOPPING.get() {
            stopping.store(true, Ordering::SeqCst);
        }
    }

    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: the handler is a plain function that stores into an atomic
        // already allocated above, which is what a signal handler is allowed
        // to do.
        let installed = unsafe { libc::signal(signal, asked as *const () as libc::sighandler_t) };
        if installed == libc::SIG_ERR {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The flag the signal handler sets.
///
/// A static because a signal handler takes no argument and can capture
/// nothing. Written once, before any signal can arrive.
static STOPPING: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

/// Says a failure and stops.
fn failed(said: &str) -> ExitCode {
    failed_line(said);
    ExitCode::FAILURE
}

/// Says a failure and carries on.
fn failed_line(said: &str) {
    say(&format!(
        r#"{{"kind":"agent","ts":{},"event":"failed","detail":"{}"}}"#,
        milliseconds(),
        escaped(said)
    ));
}

/// A string with the two characters JSON refuses inside one escaped.
fn escaped(text: &str) -> String {
    text.replace('\\', r"\\").replace('"', "\\\"")
}

/// Writes one line and makes sure it left.
fn say(line: &str) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Milliseconds since the epoch, which is what a failover is timed in.
fn milliseconds() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}
