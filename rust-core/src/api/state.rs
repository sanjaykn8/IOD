//! `SimulationState`: the single shared, mutex-guarded state object the
//! HTTP server operates on. Each mutating operation also persists to
//! SQLite immediately afterward (simple "write-through" — not the most
//! efficient possible design, but correct and easy to audit, which
//! matters more at this scale).

use crate::identity::metadata::MembershipMetadata;
use crate::protocol::entities::{DroneState, GcsState};
use crate::protocol::events::EventLog;
use crate::protocol::messages::VerificationReport;
use crate::protocol::simulation;
use crate::storage::Database;
use crate::trace::TraceManager;
use std::collections::HashMap;

pub struct SimulationState {
    pub gcs: GcsState,
    pub drones: HashMap<String, DroneState>,
    pub log: EventLog,
    pub trace: TraceManager,
    pub db: Database,
    /// Completed M1-M8 runs (in-memory only: they hold session objects).
    pub runs: HashMap<String, simulation::AuthRunResult>,
    /// Directional channel keys per session (never serialized/exposed).
    pub channels: HashMap<String, simulation::ChannelEstablished>,
    /// Latest session per unordered drone pair.
    pub pair_session: HashMap<(String, String), String>,
    pub admin: crate::trace::AdminAuth,
    pub last_reports: HashMap<String, VerificationReport>,
    pub merkle_depth: usize,
    /// Sequence counters per (session, direction).
    pub message_seq: HashMap<(String, u8), u32>,
}

fn pair_key(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

impl SimulationState {
    pub fn new(db_path: &str) -> anyhow::Result<Self> {
        let db = Database::open(db_path)?;
        let gcs = db.load_gcs()?.unwrap_or_else(GcsState::new);
        let mut drones = HashMap::new();
        for id in db.load_all_drone_ids()? {
            if let Some(snap) = db.load_drone_local(&id)? {
                if let Ok(drone) = DroneState::from_local_snapshot(snap) {
                    drones.insert(id, drone);
                }
            }
        }
        Ok(SimulationState {
            gcs,
            drones,
            log: EventLog::new(),
            trace: TraceManager::new(),
            db,
            runs: HashMap::new(),
            channels: HashMap::new(),
            pair_session: HashMap::new(),
            admin: crate::trace::AdminAuth::from_env(),
            last_reports: HashMap::new(),
            merkle_depth: 8,
            message_seq: HashMap::new(),
        })
    }

    fn persist(&self) -> anyhow::Result<()> {
        self.db.save_gcs(&self.gcs)?;
        for d in self.drones.values() {
            self.db.save_drone_local(&d.to_local_snapshot())?;
        }
        Ok(())
    }

    /// Push an event into the live in-memory log AND persist it to
    /// SQLite immediately, so `GET /api/events/history` reflects
    /// everything even across a process restart (the plain in-memory
    /// `log` resets on restart by design — see `storage` module docs on
    /// why the append-only event table is the durable source of truth).
    fn record(
        &mut self,
        session_id: &str,
        stage: &str,
        sender: &str,
        receiver: &str,
        status: crate::protocol::events::EventStatus,
        detail: impl Into<String>,
    ) {
        self.log.push(session_id, stage, sender, receiver, status, detail);
        if let Some(ev) = self.log.events.last() {
            let _ = self.db.append_event(ev);
        }
    }

    pub fn reset(&mut self) -> anyhow::Result<()> {
        self.db.reset_all()?;
        self.gcs = GcsState::new();
        self.drones.clear();
        self.log = EventLog::new();
        self.trace = TraceManager::new();
        self.runs.clear();
        self.channels.clear();
        self.pair_session.clear();
        self.last_reports.clear();
        self.message_seq.clear();
        self.persist()
    }

    pub fn create_group(&mut self, group_id: &str) -> anyhow::Result<()> {
        self.gcs.create_group(group_id, self.merkle_depth);
        self.record("system", "R2", "GCS", "GCS", crate::protocol::events::EventStatus::Info, format!("Group '{group_id}' created"));
        self.persist()
    }

    pub fn create_drone(&mut self, drone_id: &str) -> anyhow::Result<()> {
        if self.drones.contains_key(drone_id) {
            anyhow::bail!("drone '{drone_id}' already exists");
        }
        let mut entropy = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut entropy);
        let drone = DroneState::new(drone_id, entropy);
        self.record("system", "R1", drone_id, drone_id, crate::protocol::events::EventStatus::Info, "Simulated device created (SRAM PUF initialized)");
        self.drones.insert(drone_id.to_string(), drone);
        self.persist()
    }

    pub fn register_drone(&mut self, drone_id: &str, group_id: &str, role: &str) -> anyhow::Result<usize> {
        let drone = self.drones.get_mut(drone_id).ok_or_else(|| anyhow::anyhow!("unknown drone"))?;
        let md = MembershipMetadata { role: role.to_string(), issued_at_unix: crate::protocol::events::now_unix_ms() / 1000 };
        let idx = crate::protocol::registration::register_drone(&mut self.gcs, drone, group_id, md, self.merkle_depth)?;
        // Refresh every other active member of this group so their
        // cached witnesses stay valid (spec: "regenerate affected
        // witnesses").
        let mut others: Vec<&mut DroneState> = self.drones.values_mut().filter(|d| d.drone_id != drone_id).collect();
        simulation::refresh_all_in_group(&self.gcs, &mut others, group_id);
        self.record("system", "R3", "GCS", drone_id, crate::protocol::events::EventStatus::Ok, format!("Registered into '{group_id}' at leaf index {idx}"));
        self.persist()?;
        Ok(idx)
    }

    pub fn revoke_drone(&mut self, drone_id: &str) -> anyhow::Result<()> {
        simulation::revoke_drone(&mut self.gcs, drone_id)?;
        let group_id = self.drones.get(drone_id).and_then(|d| d.group_id.clone());
        if let Some(g) = group_id {
            let mut others: Vec<&mut DroneState> = self.drones.values_mut().filter(|d| d.drone_id != drone_id).collect();
            simulation::refresh_all_in_group(&self.gcs, &mut others, &g);
        }
        self.record("system", "R2", "GCS", drone_id, crate::protocol::events::EventStatus::Fail, "Revoked (Merkle leaf zeroed, version incremented)");
        self.persist()
    }

    pub fn reactivate_drone(&mut self, drone_id: &str) -> anyhow::Result<usize> {
        let drone = self.drones.get_mut(drone_id).ok_or_else(|| anyhow::anyhow!("unknown drone"))?;
        drone.revoked = false;
        let idx = simulation::reactivate_drone(&mut self.gcs, drone, self.merkle_depth)?;
        self.record("system", "R3", "GCS", drone_id, crate::protocol::events::EventStatus::Ok, "Reactivated");
        self.persist()?;
        Ok(idx)
    }

    pub fn move_drone(&mut self, drone_id: &str, new_group_id: &str) -> anyhow::Result<usize> {
        let drone = self.drones.get_mut(drone_id).ok_or_else(|| anyhow::anyhow!("unknown drone"))?;
        let old_group = drone.group_id.clone();
        let idx = simulation::move_drone(&mut self.gcs, drone, new_group_id, self.merkle_depth)?;
        if let Some(g) = old_group {
            let mut others: Vec<&mut DroneState> = self.drones.values_mut().filter(|d| d.drone_id != drone_id).collect();
            simulation::refresh_all_in_group(&self.gcs, &mut others, &g);
        }
        let mut others: Vec<&mut DroneState> = self.drones.values_mut().filter(|d| d.drone_id != drone_id).collect();
        simulation::refresh_all_in_group(&self.gcs, &mut others, new_group_id);
        self.record("system", "R3", "GCS", drone_id, crate::protocol::events::EventStatus::Ok, format!("Moved to '{new_group_id}'"));
        self.persist()?;
        Ok(idx)
    }

    pub fn authenticate(&mut self, d1_id: &str, d2_id: &str) -> anyhow::Result<(String, VerificationReport)> {
        if !self.drones.contains_key(d1_id) || !self.drones.contains_key(d2_id) {
            anyhow::bail!("unknown drone id");
        }
        let events_before = self.log.events.len();
        let mut d1 = self.drones.remove(d1_id).unwrap();
        let result = {
            let d2 = self.drones.get(d2_id).unwrap();
            simulation::run_authentication(&mut self.gcs, &mut d1, d2, &mut self.log)
        };
        self.drones.insert(d1_id.to_string(), d1);
        let result = result?;
        // `run_authentication` pushes directly into `self.log` (it only
        // has an `&mut EventLog`, not DB access — a deliberate
        // separation of the pure protocol logic from persistence). Persist
        // exactly the NEW events it added, in their original order —
        // NOT the whole log's "last 20", which would re-insert
        // already-persisted earlier events as duplicates (a real bug
        // caught during manual end-to-end testing in this session; see
        // docs/IMPLEMENTATION_STATUS.md).
        for ev in &self.log.events[events_before..] {
            let _ = self.db.append_event(ev);
        }
        self.last_reports.insert(pair_key_string(d1_id, d2_id), result.report.clone());
        let sid = result.session_id.clone();
        let report = result.report.clone();
        self.pair_session.insert(pair_key(d1_id, d2_id), sid.clone());
        self.runs.insert(sid.clone(), result);
        self.persist()?;
        Ok((sid, report))
    }

    /// K1-K3 for a COMPLETED session. The session must exist in this
    /// process (it holds the D1/D2 session objects and D1's confirmation)
    /// and the GCS independently enforces PufVerified + ALLOW + exact
    /// session binding. There are no placeholder nonces or contexts.
    pub fn establish_group_key(&mut self, session_id: &str, mission_id: &str) -> anyhow::Result<()> {
        let run = self.runs.get(session_id).ok_or_else(|| anyhow::anyhow!("NO_AUTH_SESSION: no completed authentication session '{session_id}'"))?;
        let (d1_id, d2_id) = {
            let s = self.gcs.sessions.get(session_id).ok_or_else(|| anyhow::anyhow!("NO_AUTH_SESSION: unknown at GCS"))?;
            (s.d1_id.clone(), s.d2_id.clone())
        };
        let d1 = self.drones.get(&d1_id).ok_or_else(|| anyhow::anyhow!("unknown D1"))?;
        let d2 = self.drones.get(&d2_id).ok_or_else(|| anyhow::anyhow!("unknown D2"))?;
        let events_before = self.log.events.len();
        let res = simulation::run_group_key_establishment(&mut self.gcs, d1, d2, run, mission_id, &mut self.log);
        for ev in &self.log.events[events_before..] {
            let _ = self.db.append_event(ev);
        }
        let ch = res.map_err(|e| anyhow::anyhow!("{e}"))?;
        self.channels.insert(session_id.to_string(), ch);
        self.persist()
    }

    /// Resolve the latest session of an unordered pair (compat helper for
    /// clients that name the drones instead of the session).
    pub fn latest_session(&self, a: &str, b: &str) -> Option<String> {
        self.pair_session.get(&pair_key(a, b)).cloned()
    }

    /// Sends one message over the session's channel and has the receiver
    /// decrypt it. `from_id` must be a participant of `session_id`.
    pub fn send_secure_message(&mut self, session_id: &str, from_id: &str, plaintext: &str) -> anyhow::Result<String> {
        let ch = self.channels.get(session_id).ok_or_else(|| anyhow::anyhow!("no group key established for this session"))?;
        let s = self.gcs.sessions.get(session_id).ok_or_else(|| anyhow::anyhow!("unknown session"))?;
        // direction 1 = D1 -> D2, 2 = D2 -> D1
        let direction: u8 = if from_id == s.d1_id {
            1
        } else if from_id == s.d2_id {
            2
        } else {
            anyhow::bail!("sender is not a participant of this session");
        };
        let (send_key, recv_key, tag) = if direction == 1 {
            (&ch.d1_keys.d1_to_d2, &ch.d2_keys.d1_to_d2, ch.d1_keys.channel_tag)
        } else {
            (&ch.d2_keys.d2_to_d1, &ch.d1_keys.d2_to_d1, ch.d1_keys.channel_tag)
        };
        let seq_entry = self.message_seq.entry((session_id.to_string(), direction)).or_insert(0);
        let last_seen = *seq_entry;
        *seq_entry += 1;
        let seq = *seq_entry;
        let transport = crate::transport::PassthroughTransport;
        let (msg, _wire) = crate::protocol::secure_messaging::send_message(send_key, &transport, tag, direction, seq, plaintext.as_bytes())?;
        let opened = crate::protocol::secure_messaging::receive_message(recv_key, tag, direction, &msg, last_seen)?;
        let ct_len = msg.sealed.ciphertext.len();
        // Event details carry only the pseudonymous channel header facts.
        self.record(session_id, "K4", "channel", "channel", crate::protocol::events::EventStatus::Ok,
            format!("SecureMessage dir={direction} seq={seq} ciphertext_len={ct_len}B delivered+decrypted OK"));
        Ok(String::from_utf8_lossy(&opened).to_string())
    }
}

fn pair_key_string(a: &str, b: &str) -> String {
    let (x, y) = pair_key(a, b);
    format!("{x}|{y}")
}
