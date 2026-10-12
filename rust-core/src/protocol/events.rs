//! Protocol event log entries, exposed to the UI as the "event
//! timeline." Every entry captures message type, sender, receiver,
//! timestamp, session ID, stage, status, and non-sensitive detail —
//! never a private key, PUF secret, shared secret, or AEAD key (that
//! redaction discipline is enforced structurally: `detail` is always a
//! human-readable `String` built explicitly by call sites from
//! already-public fields, never a `Debug`-dump of a whole struct that
//! might contain secret material).

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventStatus {
    Info,
    Ok,
    Fail,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolEvent {
    pub session_id: String,
    pub stage: String, // "M1".."M8", "K1".."K4", "R1".."R3", "APP", "TRACE"
    pub sender: String,
    pub receiver: String,
    pub timestamp_unix_ms: u64,
    pub status: EventStatus,
    pub detail: String,
}

pub struct EventLog {
    pub events: Vec<ProtocolEvent>,
}

impl EventLog {
    pub fn new() -> Self {
        EventLog { events: Vec::new() }
    }

    pub fn push(
        &mut self,
        session_id: &str,
        stage: &str,
        sender: &str,
        receiver: &str,
        status: EventStatus,
        detail: impl Into<String>,
    ) {
        self.events.push(ProtocolEvent {
            session_id: session_id.to_string(),
            stage: stage.to_string(),
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            timestamp_unix_ms: now_unix_ms(),
            status,
            detail: detail.into(),
        });
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

thread_local! {
    static CLOCK_SKEW_MS: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}

/// Simulation/test-only: run `f` with this thread's clock shifted by
/// `skew_ms` (used by negative tests for stale/future timestamps and
/// expiry). Never used by the server path.
pub fn with_clock_skew<T>(skew_ms: i64, f: impl FnOnce() -> T) -> T {
    let prev = CLOCK_SKEW_MS.with(|c| c.replace(skew_ms));
    let out = f();
    CLOCK_SKEW_MS.with(|c| c.set(prev));
    out
}

pub fn now_unix_ms() -> u64 {
    let base = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as i64;
    (base + CLOCK_SKEW_MS.with(|c| c.get())) as u64
}
