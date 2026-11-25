//! Latency-diagnostic helpers shared by the client and the server.
//!
//! The interactive echo path spans several threads and processes:
//!
//! ```text
//! client key event → send_input (client)
//!   → terminal-connection writer → websocket → server connection reader
//!   → forward_input → PTY write → PTY read thread → session output queue
//!   → process_session_output → viewer queue → connection writer → websocket
//!   → client reader (output batching) → AppMessage queue → UI event loop
//!   → parse worker → repaint
//! ```
//!
//! When typing "feels late" (a key echo only appears after the next
//! keypress), the delay can sit at any hop: a session lock on the server, a
//! full output queue, a websocket write stall, or the client event loop not
//! waking. Each hop logs a `[latency]` line when `VTERM_LATENCY_LOG` is set
//! in the environment of the respective process; correlating the timestamps
//! of one keystroke across both log files pinpoints the slow hop.
//!
//! All helpers are cheap no-ops (a single relaxed atomic load) when the env
//! var is unset, so they are safe to leave in release builds.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use crate::SessionId;

/// Environment variable enabling the `[latency]` probes. Set it in the
/// client's and/or the server's environment independently.
pub const LATENCY_LOG_ENV: &str = "VTERM_LATENCY_LOG";

pub static LATENCY_LOG_ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var(LATENCY_LOG_ENV).is_ok_and(|value| !value.is_empty()));

/// Emit a `[latency]` log line at `trace` level, but only when
/// [`LATENCY_LOG_ENV`] opted in. Trace keeps these out of the default
/// `debug` filter — they fire per keystroke; to see them set e.g.
/// `RUST_LOG=trace` (or per-target `RUST_LOG=vterm_common=trace,vterm_server=trace`)
/// in addition to [`LATENCY_LOG_ENV`].
#[macro_export]
macro_rules! latency_log {
    ($($arg:tt)+) => {
        if *$crate::latency::LATENCY_LOG_ENABLED {
            tracing::trace!($($arg)+);
        }
    };
}

/// Per-session timestamps of the most recent input ("the user just typed").
/// Both sides record it: the client when the key event is dispatched to the
/// connection, the server when `forward_input` writes to the PTY. The
/// output-side probes compare against it to measure the interactive echo
/// path end-to-end.
static LAST_INPUT_AT: LazyLock<Mutex<HashMap<SessionId, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Per-session timestamp of the most recent `Message::Output` handed to the
/// client's UI event loop. The app-loop probe compares against it to measure
/// how long the enqueued message waited for the UI thread to wake and drain
/// it (the "did `App::wait` actually wake" check).
static LAST_OUTPUT_ENQUEUED_AT: LazyLock<Mutex<HashMap<SessionId, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn stamp(map: &LazyLock<Mutex<HashMap<SessionId, Instant>>>, session_id: SessionId) {
    if !*LATENCY_LOG_ENABLED {
        return;
    }
    if let Ok(mut map) = map.lock() {
        map.insert(session_id, Instant::now());
    }
}

fn ms_since(
    map: &LazyLock<Mutex<HashMap<SessionId, Instant>>>,
    session_id: SessionId,
) -> Option<u128> {
    let at = map.lock().ok()?.get(&session_id).copied()?;
    Some(at.elapsed().as_millis())
}

/// How long after a keystroke a PTY output batch still counts as the echo
/// of that keystroke. Output arriving later is background stream (a running
/// program, a log tail) and is excluded from the echo-path probes.
pub const ECHO_WINDOW_MS: u128 = 1500;

/// Once the first output bytes after a keystroke have arrived, only this
/// grace of follow-up chunks still counts as the same echo frame. Without
/// it, a TUI that keeps streaming (spinner ticks, an LLM answer) after the
/// user pressed Enter would have every chunk within [`ECHO_WINDOW_MS`]
/// misreported as a late keystroke echo. The grace must cover the slowest
/// legitimate downstream measurement (server dispatch → client batch →
/// parse → repaint), not just the server-side reads.
pub const ECHO_GRACE_MS: u128 = 500;

/// Per-session timestamp of the first output batch observed after the most
/// recent input. Cleared by [`note_input`]; set once by
/// [`note_first_output`]. Entries are per-process (client and server each
/// track their own sighting).
static FIRST_OUTPUT_AT: LazyLock<Mutex<HashMap<SessionId, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Milliseconds since the last input for `session_id`, but only while this
/// output batch plausibly carries the echo of a recent keystroke: the input
/// must be within [`ECHO_WINDOW_MS`], and once the echo's first bytes have
/// been seen, only [`ECHO_GRACE_MS`] of follow-up chunks still count. `None`
/// otherwise (no input yet, input too old, or the echo was already delivered
/// and this is background stream), which is how output-side probes filter
/// background PTY streams from interactive echo streams.
pub fn echo_ms_since_input(session_id: SessionId) -> Option<u128> {
    let elapsed = ms_since_input(session_id)?;
    if elapsed > ECHO_WINDOW_MS {
        return None;
    }
    let first_output = FIRST_OUTPUT_AT.lock().ok()?.get(&session_id).copied();
    match first_output {
        Some(at) if at.elapsed().as_millis() > ECHO_GRACE_MS => None,
        _ => Some(elapsed),
    }
}

/// Record that the first output bytes after the latest input have been
/// observed for `session_id`. Call at the earliest output sighting on each
/// side (server: PTY read thread; client: output batch flush). Subsequent
/// calls before the next [`note_input`] are no-ops.
pub fn note_first_output(session_id: SessionId) {
    if !*LATENCY_LOG_ENABLED {
        return;
    }
    if let Ok(mut map) = FIRST_OUTPUT_AT.lock() {
        map.entry(session_id).or_insert_with(Instant::now);
    }
}

// ---------------------------------------------------------------------------
// Adaptive slow-sample filtering
// ---------------------------------------------------------------------------

/// Samples between per-stage summaries in [`sample`].
const SUMMARY_EVERY: u64 = 500;

#[derive(Default)]
struct StageStats {
    /// Robust baseline (EMA) of *normal* samples; slow outliers do not enter
    /// it so a single stall does not silence the detector for follow-ups.
    ema_ms: Option<f64>,
    samples: u64,
    slow: u64,
    max_ms: f64,
}

/// Adaptive baselines are tracked per `(stage, session)`: echo latency that
/// is normal for a session running a heavy TUI must not raise the bar for
/// an interactive shell session. Entries for closed sessions are tiny and
/// never reused (SessionId is a UUID), so no pruning is needed.
static STAGE_STATS: LazyLock<Mutex<HashMap<(&'static str, SessionId), StageStats>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Record one latency sample for `stage` on `session_id` and decide whether
/// it is worth a log line.
///
/// A sample is "slow" — returns `true` — when it exceeds `floor_ms` *and*
/// `factor` × the stage's baseline **for this session**, so a stage that
/// normally runs at 2 ms logs from ~max(floor, 6 ms) upward while a stage at
/// 40 ms only logs beyond 120 ms. Fast samples never log; they only refine
/// the baseline. Every [`SUMMARY_EVERY`] samples the stage also emits one
/// aggregate line (count / slow / baseline / max) so chronic degradation
/// stays visible without per-event spam.
///
/// No-op (returns `false` without locking) when [`LATENCY_LOG_ENV`] is off.
pub fn sample(
    stage: &'static str,
    session_id: SessionId,
    value_ms: f64,
    floor_ms: f64,
    factor: f64,
) -> bool {
    if !*LATENCY_LOG_ENABLED {
        return false;
    }
    let mut stats = match STAGE_STATS.lock() {
        Ok(stats) => stats,
        Err(_) => return false,
    };
    let entry = stats.entry((stage, session_id)).or_default();
    entry.samples += 1;
    entry.max_ms = entry.max_ms.max(value_ms);

    let baseline = entry.ema_ms.unwrap_or(value_ms);
    let slow = value_ms >= floor_ms && value_ms >= baseline * factor;
    if slow {
        entry.slow += 1;
    } else {
        // Only normal samples feed the baseline; outliers would otherwise
        // raise it and mute the very anomalies we want to see.
        entry.ema_ms = Some(match entry.ema_ms {
            Some(ema) => ema * 0.9 + value_ms * 0.1,
            None => value_ms,
        });
    }

    let emit_summary = entry.samples % SUMMARY_EVERY == 0;
    let summary = if emit_summary {
        Some((
            entry.samples,
            entry.slow,
            entry.ema_ms.unwrap_or(0.0),
            entry.max_ms,
        ))
    } else {
        None
    };
    drop(stats);

    if let Some((samples, slow_count, ema_ms, max_ms)) = summary {
        tracing::trace!(
            stage,
            session = %session_id,
            samples,
            slow = slow_count,
            baseline_ms = ema_ms,
            max_ms,
            "[latency] stage summary (periodic; slow events logged individually)"
        );
        // Reset the window so the next summary describes fresh samples.
        if let Ok(mut stats) = STAGE_STATS.lock() {
            if let Some(entry) = stats.get_mut(&(stage, session_id)) {
                entry.samples = 0;
                entry.slow = 0;
                entry.max_ms = 0.0;
            }
        }
    }

    slow
}

/// Record that input for `session_id` was just sent (client) or received and
/// about to be written to the PTY (server).
pub fn note_input(session_id: SessionId) {
    if *LATENCY_LOG_ENABLED {
        if let Ok(mut map) = FIRST_OUTPUT_AT.lock() {
            map.remove(&session_id);
        }
    }
    stamp(&LAST_INPUT_AT, session_id);
}

/// Milliseconds since [`note_input`] was last called for `session_id`.
pub fn ms_since_input(session_id: SessionId) -> Option<u128> {
    ms_since(&LAST_INPUT_AT, session_id)
}

/// Record that output for `session_id` was just enqueued for the client UI
/// event loop.
pub fn note_output_enqueued(session_id: SessionId) {
    stamp(&LAST_OUTPUT_ENQUEUED_AT, session_id);
}

/// Milliseconds since [`note_output_enqueued`] was last called for
/// `session_id` — measures the wake/drain latency of the UI loop.
pub fn ms_since_output_enqueued(session_id: SessionId) -> Option<u128> {
    ms_since(&LAST_OUTPUT_ENQUEUED_AT, session_id)
}
