//! `SimulationState`: the single shared, mutex-guarded state object the
//! HTTP server operates on. Each mutating operation also persists to
//! SQLite immediately afterward (simple "write-through" — not the most
//! efficient possible design, but correct and easy to audit, which
//! matters more at this scale).

use crate::crypto::aead::AeadKey;
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
    pub session_keys: HashMap<(String, String), AeadKey>,
    pub last_reports: HashMap<String, VerificationReport>,
    pub merkle_depth: usize,
    pub message_seq: HashMap<(String, String), u32>,
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
            session_keys: HashMap::new(),
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
        self.session_keys.clear();
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
        self.persist()?;
        Ok((result.session_id, result.report))
    }

    pub fn establish_group_key(&mut self, d1_id: &str, d2_id: &str, mission_id: &str) -> anyhow::Result<()> {
        use crate::protocol::group_key::*;
        let d1_pid1 = {
            let d1 = self.drones.get(d1_id).ok_or_else(|| anyhow::anyhow!("unknown D1"))?;
            crate::identity::pid::derive_pid(&d1.reconstruct_seed(), d1.pid_counter.saturating_sub(1))
        };
        let group_id = self
            .drones
            .get(d1_id)
            .and_then(|d| d.group_id.clone())
            .ok_or_else(|| anyhow::anyhow!("D1 is not registered to a group"))?;
        // Ensure GCS can resolve this PID even if authenticate() wasn't
        // run first in this exact process lifetime.
        self.gcs.pid_pool.entry(d1_pid1.clone()).or_insert_with(|| d1_id.to_string());

        let (wire1, _plain1) = {
            let d2 = self.drones.get(d2_id).ok_or_else(|| anyhow::anyhow!("unknown D2"))?;
            k1_group_key_req(d2, &group_id, &d1_pid1, mission_id, [0u8; 32], &self.gcs.kem_pk)?
        };
        let wire7 = gcs_handle_k1(&self.gcs, &wire1).map_err(|e| anyhow::anyhow!("{e}"))?;
        let (resp, key_delivery) = {
            let d2 = self.drones.get(d2_id).unwrap();
            d2_handle_k1_response(d2, &wire7)?
        };
        let k_d1 = {
            let d1 = self.drones.get(d1_id).unwrap();
            d1_decapsulate_group_key(d1, &key_delivery)?
        };
        let k_d2 = {
            let d2 = self.drones.get(d2_id).unwrap();
            d2_decapsulate_group_key(d2, &resp)?
        };
        anyhow::ensure!(k_d1 == k_d2, "group key mismatch between D1 and D2");
        let aead = derive_aead_key(&k_d1, b"n1", b"n2", b"n6", b"n7");
        self.session_keys.insert(pair_key(d1_id, d2_id), aead);
        self.record("system", "K4", d1_id, d2_id, crate::protocol::events::EventStatus::Ok, "Group session AEAD key established (GCS-assisted)");
        self.persist()
    }

    pub fn send_secure_message(&mut self, from_id: &str, to_id: &str, plaintext: &str) -> anyhow::Result<String> {
        let key = self
            .session_keys
            .get(&pair_key(from_id, to_id))
            .ok_or_else(|| anyhow::anyhow!("no group key established between these two drones yet"))?
            .clone_for_use();
        let seq_entry = self.message_seq.entry(pair_key(from_id, to_id)).or_insert(0);
        *seq_entry += 1;
        let seq = *seq_entry;
        let transport = crate::transport::PassthroughTransport;
        let (msg, _wire) = crate::protocol::secure_messaging::send_message(
            &key,
            &transport,
            seq,
            from_id.as_bytes(),
            to_id.as_bytes(),
            plaintext.as_bytes(),
        )?;
        let opened = crate::protocol::secure_messaging::receive_message(&key, &msg, seq.saturating_sub(1))?;
        self.record(
            "system",
            "K4",
            from_id,
            to_id,
            crate::protocol::events::EventStatus::Ok,
            format!("SecureMessage seq={seq} ciphertext_len={}B delivered+decrypted OK", msg.sealed.ciphertext.len()),
        );
        Ok(String::from_utf8_lossy(&opened).to_string())
    }
}

fn pair_key_string(a: &str, b: &str) -> String {
    let (x, y) = pair_key(a, b);
    format!("{x}|{y}")
}

impl AeadKey {
    // Not derivable via Clone in the crypto layer on purpose (keys
    // generally shouldn't be casually cloned); the API layer needs one
    // owned copy per call, so we expose a narrowly-scoped helper here
    // rather than adding `Clone` to the crypto-facing type everywhere.
    fn clone_for_use(&self) -> AeadKey {
        AeadKey(self.0)
    }
}
