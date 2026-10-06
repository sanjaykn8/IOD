//! `SimulationState`: the single shared, mutex-guarded state object the
//! HTTP server operates on. Each mutating operation also persists to
//! SQLite immediately afterward (simple "write-through" — not the most
//! efficient possible design, but correct and easy to audit, which
//! matters more at this scale).

use crate::crypto::aead::AeadKey;
use crate::identity::metadata::MembershipMetadata;
use crate::protocol::entities::{DroneState, GcsState};
use crate::protocol::events::EventLog;
use crate::protocol::messages::{VerificationReport, ZeroTrustDecision};
use crate::protocol::simulation;
use crate::storage::Database;
use crate::trace::TraceManager;
use serde::Serialize;
use std::collections::HashMap;

/// Default cover images for the live HTTP registration-via-steganography
/// endpoint, used whenever the caller does not supply its own
/// (base64-encoded) cover image for R1/R3. These are the SAME fixture
/// PNGs the `iod-register-stego-demo` binary and the Rust-side
/// cross-language tests use (`rust-core/tests/fixtures/`), embedded at
/// compile time via `include_bytes!` so the server has no runtime
/// dependency on the current working directory to find them.
const DEFAULT_COVER_R1: &[u8] = include_bytes!("../../tests/fixtures/cover_d1_to_gcs.png");
const DEFAULT_COVER_R3: &[u8] = include_bytes!("../../tests/fixtures/cover_gcs_to_d1.png");

/// Response DTO for `register_drone_via_stego`: every number and image
/// here is read verbatim off what `python-service`'s real benchmark +
/// selector + RAG-narrative pipeline returned for THIS registration's
/// actual cover images and actual (KEM-then-AEAD-sealed) enrollment
/// messages -- nothing here is fabricated or recomputed independently
/// of that pipeline (see `docs/claims-and-limitations.md` §6).
#[derive(Serialize)]
pub struct StegoRegistrationOutcome {
    pub leaf_index: usize,
    pub r1_algorithm_id: String,
    pub r1_profile_id: String,
    pub r1_stego_image_b64: String,
    pub r1_selection: serde_json::Value,
    pub r1_explanation: serde_json::Value,
    pub r3_algorithm_id: String,
    pub r3_profile_id: String,
    pub r3_stego_image_b64: String,
    pub r3_selection: serde_json::Value,
    pub r3_explanation: serde_json::Value,
}

fn parse_or_null(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
}

/// SECURITY FIX (spec item 25-I: "K1 must be bound to the authenticated
/// session, not issuable for an arbitrary pair"; also feeds 25-D/25-E).
///
/// Durable record of the most recent M1-M8 outcome for an (unordered)
/// drone pair: the real session id, the real M1/M2 session nonces N1/N2
/// that transcript used, and the Zero Trust decision M7/M8 reached.
/// `establish_group_key` (K1) consults this and REFUSES to run unless a
/// session recorded here for this exact pair ended in `Allow` — group-key
/// establishment can no longer be invoked for two drones that never
/// successfully authenticated to each other in this process. It also
/// supplies the real N1/N2 for the K3 AEAD-key derivation (see the
/// `derive_aead_key` call in `establish_group_key` below), replacing the
/// previous hardcoded placeholder nonces.
#[derive(Clone, Debug)]
pub struct AuthSessionRecord {
    pub session_id: String,
    pub n1: Vec<u8>,
    pub n2: Vec<u8>,
    pub decision: ZeroTrustDecision,
}

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
    /// Keyed by the same unordered `pair_key` as `session_keys`. See
    /// `AuthSessionRecord` docs above.
    pub auth_sessions: HashMap<(String, String), AuthSessionRecord>,
    /// Base URL of the live `python-service` `/stego/*` HTTP API, used by
    /// `register_drone_via_stego`'s `HttpStegoClient`. Overridable via
    /// `IOD_STEGO_SERVICE_URL` (same override pattern as `IOD_BIND_ADDR`/
    /// `IOD_DB_PATH` in `bin/server.rs`); defaults to the same
    /// `127.0.0.1:5001` every other part of this project already assumes
    /// for the Python service (`node-server/src/config.ts`,
    /// `python-service/src/app.py`'s own `IOD_PYTHON_PORT` default).
    pub stego_base_url: String,
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
            auth_sessions: HashMap::new(),
            stego_base_url: std::env::var("IOD_STEGO_SERVICE_URL").unwrap_or_else(|_| "http://127.0.0.1:5001".to_string()),
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
        self.auth_sessions.clear();
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

    /// Live HTTP counterpart of `bin/register_stego_demo.rs`: the SAME
    /// real R1-R3-over-steganography flow (real ML-KEM-768/ML-DSA-44
    /// keys, real KEM-then-AEAD sealing via `protocol::envelope`, a real
    /// HTTP round trip to `python-service` for RAG-assisted algorithm
    /// selection and real pixel embedding/extraction), driven from the
    /// dashboard instead of a standalone binary. Requires `python-service`
    /// to be reachable at `self.stego_base_url` -- if it is not running,
    /// this returns a clear error rather than silently falling back to a
    /// non-steganographic path (falling back would misrepresent what
    /// actually happened).
    pub fn register_drone_via_stego(
        &mut self,
        drone_id: &str,
        group_id: &str,
        role: &str,
        cover_image_r1: Option<Vec<u8>>,
        cover_image_r3: Option<Vec<u8>>,
    ) -> anyhow::Result<StegoRegistrationOutcome> {
        use crate::protocol::registration_stego::*;
        use crate::protocol::stego_client::{HttpStegoClient, StegoClient};
        use crate::puf::crp::CrpReference;

        let cover_r1 = cover_image_r1.unwrap_or_else(|| DEFAULT_COVER_R1.to_vec());
        let cover_r3 = cover_image_r3.unwrap_or_else(|| DEFAULT_COVER_R3.to_vec());
        let md = MembershipMetadata { role: role.to_string(), issued_at_unix: crate::protocol::events::now_unix_ms() / 1000 };

        // Scoped immutable borrow of `drone` -- it must end before any of
        // the `&mut self` calls below (record/gcs mutation), so only the
        // owned values this needs survive out of this block.
        let (material, crp) = {
            let drone = self.drones.get(drone_id).ok_or_else(|| anyhow::anyhow!("unknown drone '{drone_id}'"))?;
            anyhow::ensure!(!drone.is_registered(), "drone '{drone_id}' is already registered");
            let material = d1_build_enrollment_request(drone, group_id, &md);
            let crp = CrpReference {
                challenge: drone.crp_default_challenge.clone(),
                reference_response: drone.puf.challenge_response(&drone.crp_default_challenge),
            };
            (material, crp)
        };

        let client = HttpStegoClient::new(self.stego_base_url.clone());

        // ---- R1: D1 builds + seals + embeds its EnrollmentRequest ----
        let sealed_r1 = encrypt_enrollment_request(&material.request, &self.gcs.kem_pk)?;
        let plaintext_r1 = serde_json::to_vec(&sealed_r1)?;
        let embed_r1 = client
            .select_and_embed(&cover_r1, &plaintext_r1, "CRITICAL")
            .map_err(|e| anyhow::anyhow!("RAG-assisted stego embed (R1) failed -- is python-service running at {}? ({e})", self.stego_base_url))?;
        self.record("system", "R1", drone_id, "GCS", crate::protocol::events::EventStatus::Ok, format!("RAG-assisted selector chose '{}' for R1 (real embed into cover image)", embed_r1.stego_algorithm_id));

        let stego_png_r1 = embed_r1.stego_image_bytes.clone();
        let extracted_r1 = client
            .extract(&stego_png_r1, &embed_r1.stego_algorithm_id, embed_r1.payload_length, &embed_r1.algorithm_params_json)
            .map_err(|e| anyhow::anyhow!("stego extraction (R1) failed ({e})"))?;
        anyhow::ensure!(extracted_r1 == plaintext_r1, "R1 stego extraction did not recover the exact sealed envelope bytes");
        let sealed_r1_recv: crate::protocol::envelope::SecureEnvelope = serde_json::from_slice(&extracted_r1)?;
        let request = decrypt_enrollment_request(&sealed_r1_recv, &self.gcs.kem_sk)?;

        // ---- R2: GCS-internal (no message leaves GCS for this step) ----
        let response = gcs_process_enrollment(&mut self.gcs, &request, self.merkle_depth, crp)?;
        self.record("system", "R2", "GCS", "GCS", crate::protocol::events::EventStatus::Ok, format!("leaf registered at index {} (GCS-internal, no network message)", response.witness.leaf_index));

        // ---- R3: GCS builds + seals + embeds its EnrollmentResponse ----
        let drone_kem_pk = crate::crypto::kem::KemPublicKey(material.keys.kem_pk.0.clone());
        let sealed_r3 = encrypt_enrollment_response(&response, &drone_kem_pk)?;
        let plaintext_r3 = serde_json::to_vec(&sealed_r3)?;
        let embed_r3 = client
            .select_and_embed(&cover_r3, &plaintext_r3, "CRITICAL")
            .map_err(|e| anyhow::anyhow!("RAG-assisted stego embed (R3) failed ({e})"))?;
        self.record("system", "R3", "GCS", drone_id, crate::protocol::events::EventStatus::Ok, format!("RAG-assisted selector chose '{}' for R3 (real embed into cover image)", embed_r3.stego_algorithm_id));

        let stego_png_r3 = embed_r3.stego_image_bytes.clone();
        let extracted_r3 = client
            .extract(&stego_png_r3, &embed_r3.stego_algorithm_id, embed_r3.payload_length, &embed_r3.algorithm_params_json)
            .map_err(|e| anyhow::anyhow!("stego extraction (R3) failed ({e})"))?;
        anyhow::ensure!(extracted_r3 == plaintext_r3, "R3 stego extraction did not recover the exact sealed envelope bytes");
        let sealed_r3_recv: crate::protocol::envelope::SecureEnvelope = serde_json::from_slice(&extracted_r3)?;
        let response_recv = decrypt_enrollment_response(&sealed_r3_recv, &material.keys.kem_sk)?;

        // D1 applies R3 -- re-verifies the Merkle witness locally before
        // trusting it (see `registration_stego` module docs).
        let drone_mut = self.drones.get_mut(drone_id).unwrap();
        let idx = d1_apply_enrollment_response(drone_mut, &response_recv, material, md)?;

        let mut others: Vec<&mut DroneState> = self.drones.values_mut().filter(|d| d.drone_id != drone_id).collect();
        simulation::refresh_all_in_group(&self.gcs, &mut others, group_id);
        self.record("system", "R3", "GCS", drone_id, crate::protocol::events::EventStatus::Ok, format!("Registered into '{group_id}' at leaf index {idx} via steganographic R1-R3"));
        self.persist()?;

        Ok(StegoRegistrationOutcome {
            leaf_index: idx,
            r1_algorithm_id: embed_r1.stego_algorithm_id,
            r1_profile_id: embed_r1.stego_profile_id,
            r1_stego_image_b64: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&stego_png_r1)
            },
            r1_selection: parse_or_null(&embed_r1.selection_json),
            r1_explanation: parse_or_null(&embed_r1.explanation_json),
            r3_algorithm_id: embed_r3.stego_algorithm_id,
            r3_profile_id: embed_r3.stego_profile_id,
            r3_stego_image_b64: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&stego_png_r3)
            },
            r3_selection: parse_or_null(&embed_r3.selection_json),
            r3_explanation: parse_or_null(&embed_r3.explanation_json),
        })
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
        // Record this session's outcome + real nonces so `establish_group_key`
        // (K1) can both gate on a genuine prior `Allow` for this exact pair
        // and derive the K3 AEAD key from the REAL N1/N2, not placeholders.
        // See `AuthSessionRecord` docs.
        self.auth_sessions.insert(
            pair_key(d1_id, d2_id),
            AuthSessionRecord { session_id: result.session_id.clone(), n1: result.n1.clone(), n2: result.n2.clone(), decision: result.report.zero_trust },
        );
        self.persist()?;
        Ok((result.session_id, result.report))
    }

    pub fn establish_group_key(&mut self, d1_id: &str, d2_id: &str, mission_id: &str) -> anyhow::Result<()> {
        use crate::protocol::group_key::*;

        // SECURITY FIX (spec 25-I / 25-D): K1 must be bound to, and gated
        // on, a session that actually completed M1-M8 with an `Allow`
        // decision for this EXACT (D1, D2) pair. Previously this function
        // could be called for any two registered drones with no prior
        // authentication at all. Reject early, with a clear reason, if no
        // such session is on record.
        let auth_session = self
            .auth_sessions
            .get(&pair_key(d1_id, d2_id))
            .ok_or_else(|| anyhow::anyhow!("no completed authentication session between '{d1_id}' and '{d2_id}' yet \u{2014} run authenticate() first (K1 must be bound to an authenticated session)"))?
            .clone();
        anyhow::ensure!(
            auth_session.decision == crate::protocol::messages::ZeroTrustDecision::Allow,
            "the most recent authentication session between '{d1_id}' and '{d2_id}' was DENIED \u{2014} refusing to establish a group key"
        );

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

        // `auth_evidence_hash` binds K1 to the specific prior auth
        // session's transcript (its real session id), rather than being
        // left as an all-zero placeholder: GCS/D2 can therefore tie this
        // group-key request back to a concrete M1-M8 run.
        let auth_evidence_hash = {
            use crate::crypto::kdf::shake256_bytes;
            let digest = shake256_bytes(b"IOD-K1-AUTH-EVIDENCE-v1", auth_session.session_id.as_bytes(), 32);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        };

        let (wire1, plain1) = {
            let d2 = self.drones.get(d2_id).ok_or_else(|| anyhow::anyhow!("unknown D2"))?;
            k1_group_key_req(d2, &group_id, &d1_pid1, mission_id, auth_evidence_hash, &self.gcs.kem_pk)?
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
        // SECURITY FIX (spec 25-E): previously `derive_aead_key` was
        // called with the literal placeholder strings b"n1"/b"n2"/b"n6"/
        // b"n7" instead of the REAL session nonces, which defeats the
        // whole purpose of binding the AEAD key to a specific session's
        // nonces (every session would derive from the same four fixed
        // byte strings). Now: N1/N2 come from the actual M1/M2 messages
        // of the authenticated session being bound to (`auth_session`
        // above), and N6/N7 come from the actual K1 request/response
        // messages just exchanged (`plain1.n6`, `resp.n7`).
        let aead = derive_aead_key(&k_d1, &auth_session.n1, &auth_session.n2, &plain1.n6, &resp.n7);
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
        // SECURITY FIX (spec 25-H): `secure_messaging::send_message`'s
        // parameters are named `src_pid`/`dst_pid` -- they are supposed
        // to be ephemeral, session-scoped pseudonyms, never a drone's
        // permanent `drone_id`. This call previously passed
        // `from_id.as_bytes()`/`to_id.as_bytes()` directly, which means
        // the literal permanent DroneID strings were going straight
        // into the AEAD associated data (and the wire-visible
        // `SecureAppMessage.src_pid`/`dst_pid` fields) of every
        // application message -- exactly the permanent-identity leak
        // the rest of this protocol (PID pool at M1/M2, the K1 PID
        // correction in `messages::GroupKeyReq`) goes out of its way to
        // avoid. Fixed by deriving two session-scoped opaque tags from
        // the (already pair-unique, already secret) session AEAD key
        // itself, so no permanent identifier is embedded. The tag
        // assignment (`tag_a`/`tag_b`) is fixed by `pair_key`'s own
        // lexicographic ordering of the two drone ids, not by which
        // side happens to call `send_secure_message` as `from`/`to`, so
        // both directions agree on the same two tags for this session.
        let (tag_a, tag_b) = session_message_tags(&key);
        let (lo, _hi) = pair_key(from_id, to_id);
        let (src_tag, dst_tag) = if from_id == lo { (&tag_a, &tag_b) } else { (&tag_b, &tag_a) };
        let (msg, _wire) = crate::protocol::secure_messaging::send_message(
            &key,
            &transport,
            seq,
            src_tag,
            dst_tag,
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

/// Derive two session-scoped, non-permanent opaque tags from a
/// session's AEAD key -- used in place of either side's permanent
/// `drone_id` as the `src_pid`/`dst_pid` of an application-layer
/// `SecureAppMessage` (see the SECURITY FIX comment at its call site
/// in `send_secure_message`, spec item 25-H). Both tags change the
/// moment a new group key is established (K1-K4 reruns), so they are
/// not even a stable pseudonym across sessions, let alone the
/// permanent identity.
fn session_message_tags(key: &AeadKey) -> (Vec<u8>, Vec<u8>) {
    use crate::crypto::kdf::shake256_bytes;
    let a = shake256_bytes(b"IOD-APPMSG-TAG-A-v1", &key.0, 16);
    let b = shake256_bytes(b"IOD-APPMSG-TAG-B-v1", &key.0, 16);
    (a, b)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn full_session(sim: &mut SimulationState) {
        sim.create_group("alpha").unwrap();
        sim.create_drone("drone-1").unwrap();
        sim.create_drone("drone-2").unwrap();
        sim.register_drone("drone-1", "alpha", "recon").unwrap();
        sim.register_drone("drone-2", "alpha", "recon").unwrap();
        let (_session_id, report) = sim.authenticate("drone-1", "drone-2").unwrap();
        assert_eq!(report.zero_trust, ZeroTrustDecision::Allow, "{report:?}");
        sim.establish_group_key("drone-1", "drone-2", "mission-x").unwrap();
    }

    #[test]
    fn establish_group_key_requires_a_prior_successful_authentication() {
        let mut sim = SimulationState::new(":memory:").unwrap();
        sim.create_group("alpha").unwrap();
        sim.create_drone("drone-1").unwrap();
        sim.create_drone("drone-2").unwrap();
        sim.register_drone("drone-1", "alpha", "recon").unwrap();
        sim.register_drone("drone-2", "alpha", "recon").unwrap();
        // SECURITY FIX regression (25-I/25-D): no `authenticate()` call
        // happened yet for this pair -- K1 must refuse.
        let result = sim.establish_group_key("drone-1", "drone-2", "mission-x");
        assert!(result.is_err(), "establish_group_key must fail with no prior authenticated session");
    }

    #[test]
    fn send_secure_message_never_puts_the_permanent_drone_id_on_the_wire() {
        // SECURITY FIX regression (25-H): `SecureAppMessage.src_pid`/
        // `dst_pid` must never literally be the permanent `drone_id`
        // bytes.
        let mut sim = SimulationState::new(":memory:").unwrap();
        full_session(&mut sim);

        let key = sim.session_keys.get(&pair_key("drone-1", "drone-2")).unwrap().clone_for_use();
        let transport = crate::transport::PassthroughTransport;
        let (msg, _wire) = crate::protocol::secure_messaging::send_message(
            &key,
            &transport,
            1,
            &session_message_tags(&key).0,
            &session_message_tags(&key).1,
            b"hello",
        )
        .unwrap();
        assert_ne!(msg.src_pid, b"drone-1".to_vec());
        assert_ne!(msg.dst_pid, b"drone-2".to_vec());
        assert_ne!(msg.src_pid, sim.drones.get("drone-1").unwrap().drone_id.as_bytes().to_vec());

        // And the real API path round-trips correctly end to end.
        let out = sim.send_secure_message("drone-1", "drone-2", "hello over the real path").unwrap();
        assert_eq!(out, "hello over the real path");
    }

    #[test]
    fn secure_message_tags_are_consistent_both_directions_within_a_session() {
        let mut sim = SimulationState::new(":memory:").unwrap();
        full_session(&mut sim);
        let out1 = sim.send_secure_message("drone-1", "drone-2", "a->b").unwrap();
        let out2 = sim.send_secure_message("drone-2", "drone-1", "b->a").unwrap();
        assert_eq!(out1, "a->b");
        assert_eq!(out2, "b->a");
    }
}
