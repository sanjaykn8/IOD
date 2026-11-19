//! SQLite persistence (via `rusqlite`, bundled SQLite — no separate
//! system dependency required, works identically on Windows and Linux).
//! See `storage::snapshots` module docs for the schema design rationale.

use super::snapshots::{DroneLocalSnapshot, GcsSnapshot};
use crate::protocol::entities::GcsState;
use crate::protocol::events::ProtocolEvent;
use crate::trace::{SuspicionFlag, TraceRecord};
use rusqlite::{params, Connection, OptionalExtension};

#[derive(Default, Clone, Debug)]
pub struct StegoEventFilter {
    pub session_id: Option<String>,
    pub direction: Option<i64>,
    pub algorithm: Option<String>,
    pub outcome: Option<String>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub limit: Option<i64>,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let db = Database { conn };
        db.init_schema()?;
        Ok(db)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Database { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS gcs_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS drones_local (
                drone_id TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS protocol_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trace_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS suspicion_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rag_contributions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stego_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                direction INTEGER,
                algorithm TEXT,
                outcome TEXT NOT NULL,
                data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_stego_events_ts ON stego_events(ts_ms);
            -- state written under another cryptographic suite (e.g. Round-3 Kyber/Dilithium);
            -- archived verbatim at start-up, never loaded (see storage::snapshots docs)
            CREATE TABLE IF NOT EXISTS legacy_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                archived_ms INTEGER NOT NULL,
                kind TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                detected_suite TEXT NOT NULL,
                reason TEXT NOT NULL,
                data TEXT NOT NULL
            );
            -- EDUCATIONAL workbench records (never mixed with operational stego_events)
            CREATE TABLE IF NOT EXISTS learn_experiments (
                id TEXT PRIMARY KEY,
                ts_ms INTEGER NOT NULL,
                payload_mode TEXT NOT NULL,
                algorithms TEXT NOT NULL,
                data TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    // ---------------------------------------------------------- GCS ---

    pub fn save_gcs(&self, gcs: &GcsState) -> anyhow::Result<()> {
        let json = serde_json::to_string(&gcs.to_snapshot())?;
        self.conn.execute(
            "INSERT INTO gcs_state (id, data) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET data = excluded.data",
            params![json],
        )?;
        Ok(())
    }

    pub fn load_gcs(&self) -> anyhow::Result<Option<GcsState>> {
        let mut stmt = self.conn.prepare("SELECT data FROM gcs_state WHERE id = 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let data: String = row.get(0)?;
            let snap: GcsSnapshot = serde_json::from_str(&data)?;
            crate::crypto::suite::require(&snap.suite)?;
            Ok(Some(GcsState::from_snapshot(snap)))
        } else {
            Ok(None)
        }
    }

    // ------------------------------------------------- drones (local) --

    pub fn save_drone_local(&self, snapshot: &DroneLocalSnapshot) -> anyhow::Result<()> {
        let json = serde_json::to_string(snapshot)?;
        self.conn.execute(
            "INSERT INTO drones_local (drone_id, data) VALUES (?1, ?2)
             ON CONFLICT(drone_id) DO UPDATE SET data = excluded.data",
            params![snapshot.drone_id, json],
        )?;
        Ok(())
    }

    pub fn load_drone_local(&self, drone_id: &str) -> anyhow::Result<Option<DroneLocalSnapshot>> {
        let mut stmt = self.conn.prepare("SELECT data FROM drones_local WHERE drone_id = ?1")?;
        let mut rows = stmt.query(params![drone_id])?;
        if let Some(row) = rows.next()? {
            let data: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&data)?))
        } else {
            Ok(None)
        }
    }

    pub fn load_all_drone_ids(&self) -> anyhow::Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT drone_id FROM drones_local")?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    // -------------------------------------------------- protocol log --

    pub fn append_event(&self, event: &ProtocolEvent) -> anyhow::Result<()> {
        let json = serde_json::to_string(event)?;
        self.conn.execute(
            "INSERT INTO protocol_events (session_id, data) VALUES (?1, ?2)",
            params![event.session_id, json],
        )?;
        Ok(())
    }

    pub fn recent_events(&self, limit: i64) -> anyhow::Result<Vec<ProtocolEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM protocol_events ORDER BY id DESC LIMIT ?1")?;
        let mut out: Vec<ProtocolEvent> = stmt
            .query_map(params![limit], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();
        out.reverse();
        Ok(out)
    }

    // -------------------------------------------------------- trace ---

    pub fn append_trace_record(&self, record: &TraceRecord) -> anyhow::Result<()> {
        let json = serde_json::to_string(record)?;
        self.conn.execute("INSERT INTO trace_records (data) VALUES (?1)", params![json])?;
        Ok(())
    }

    pub fn append_suspicion_flag(&self, flag: &SuspicionFlag) -> anyhow::Result<()> {
        let json = serde_json::to_string(flag)?;
        self.conn.execute("INSERT INTO suspicion_flags (data) VALUES (?1)", params![json])?;
        Ok(())
    }

    pub fn all_trace_records(&self) -> anyhow::Result<Vec<TraceRecord>> {
        let mut stmt = self.conn.prepare("SELECT data FROM trace_records ORDER BY id ASC")?;
        let out = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();
        Ok(out)
    }

    // ------------------------------------------------- stego events ---

    /// Append one image-transport event (metadata only: never plaintext,
    /// ciphertext or key material). Returns the new event id.
    pub fn append_stego_event(
        &self,
        ts_ms: i64,
        session_id: &str,
        direction: Option<i64>,
        algorithm: Option<&str>,
        outcome: &str,
        data: &serde_json::Value,
    ) -> anyhow::Result<i64> {
        self.conn.execute(
            "INSERT INTO stego_events (ts_ms, session_id, direction, algorithm, outcome, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![ts_ms, session_id, direction, algorithm, outcome, serde_json::to_string(data)?],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Filtered history, newest first. All filters are bound parameters.
    pub fn query_stego_events(&self, f: &StegoEventFilter) -> anyhow::Result<Vec<serde_json::Value>> {
        let limit = f.limit.unwrap_or(200).clamp(1, 100_000);
        let mut stmt = self.conn.prepare(
            "SELECT id, data, outcome FROM stego_events
             WHERE (?1 IS NULL OR session_id = ?1)
               AND (?2 IS NULL OR direction = ?2)
               AND (?3 IS NULL OR algorithm = ?3)
               AND (?4 IS NULL OR outcome = ?4)
               AND (?5 IS NULL OR ts_ms >= ?5)
               AND (?6 IS NULL OR ts_ms <= ?6)
             ORDER BY id DESC LIMIT ?7",
        )?;
        let rows = stmt.query_map(
            params![f.session_id, f.direction, f.algorithm, f.outcome, f.since_ms, f.until_ms, limit],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )?;
        let mut out = Vec::new();
        for r in rows {
            let (id, data, outcome) = r?;
            let mut v: serde_json::Value = serde_json::from_str(&data)?;
            v["event_id"] = serde_json::json!(id);
            v["outcome"] = serde_json::json!(outcome);
            out.push(v);
        }
        Ok(out)
    }

    pub fn insert_learn_experiment(&self, id: &str, ts_ms: i64, payload_mode: &str, algorithms: &str, data: &serde_json::Value) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO learn_experiments (id, ts_ms, payload_mode, algorithms, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, ts_ms, payload_mode, algorithms, serde_json::to_string(data)?],
        )?;
        Ok(())
    }

    /// Newest first; summaries only (id, time, mode, algorithms).
    pub fn list_learn_experiments(&self, limit: i64) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut stmt = self.conn.prepare("SELECT id, ts_ms, payload_mode, algorithms FROM learn_experiments ORDER BY ts_ms DESC, id LIMIT ?1")?;
        let rows = stmt.query_map(params![limit.clamp(1, 1000)], |r| {
            Ok(serde_json::json!({"experiment_id": r.get::<_, String>(0)?, "created_ms": r.get::<_, i64>(1)?,
                                  "payload_mode": r.get::<_, String>(2)?, "algorithms": r.get::<_, String>(3)?}))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_learn_experiment(&self, id: &str) -> anyhow::Result<Option<serde_json::Value>> {
        let mut stmt = self.conn.prepare("SELECT data FROM learn_experiments WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(r) => Ok(Some(serde_json::from_str(&r.get::<_, String>(0)?)?)),
            None => Ok(None),
        }
    }

    pub fn count_stego_events(&self) -> anyhow::Result<(i64, i64)> {
        let ok: i64 = self.conn.query_row("SELECT COUNT(*) FROM stego_events WHERE outcome = 'ok'", [], |r| r.get(0))?;
        let failed: i64 = self.conn.query_row("SELECT COUNT(*) FROM stego_events WHERE outcome <> 'ok'", [], |r| r.get(0))?;
        Ok((ok, failed))
    }

    pub fn get_stego_event(&self, id: i64) -> anyhow::Result<Option<serde_json::Value>> {
        let mut stmt = self.conn.prepare("SELECT data FROM stego_events WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let data: String = row.get(0)?;
            let mut v: serde_json::Value = serde_json::from_str(&data)?;
            v["event_id"] = serde_json::json!(id);
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    /// Start-up migration guard. Moves every persisted identity row that does not
    /// belong to the active suite into `legacy_snapshots` and deletes it from the
    /// live tables, so it can never be loaded as current-suite state. Rows with no
    /// `suite` field were written by releases before the FIPS migration and are
    /// labelled `LEGACY_SUITE_ID`. When the GCS row is archived, every drone row is
    /// archived too (their credentials name a trust anchor that no longer exists).
    /// Idempotent; returns what was archived by THIS call.
    pub fn quarantine_incompatible(&self) -> anyhow::Result<serde_json::Value> {
        use crate::crypto::suite::{LEGACY_SUITE_ID, SUITE_ID};
        let detect = |data: &str| -> String {
            match serde_json::from_str::<serde_json::Value>(data) {
                Ok(v) => v.get("suite").and_then(|s| s.as_str()).map(str::to_string).unwrap_or_else(|| LEGACY_SUITE_ID.to_string()),
                Err(_) => "<unparseable>".to_string(),
            }
        };
        let now = crate::protocol::events::now_unix_ms() as i64;
        let mut archived = Vec::new();
        let tx = self.conn.unchecked_transaction()?;
        let gcs_row: Option<String> = tx.query_row("SELECT data FROM gcs_state WHERE id = 1", [], |r| r.get(0)).optional()?;
        let mut gcs_archived = false;
        if let Some(data) = gcs_row {
            let suite = detect(&data);
            if suite != SUITE_ID {
                tx.execute("INSERT INTO legacy_snapshots (archived_ms, kind, entity_id, detected_suite, reason, data) VALUES (?1, 'gcs', 'gcs', ?2, ?3, ?4)",
                           params![now, suite, "GCS identity from another cryptographic suite", data])?;
                tx.execute("DELETE FROM gcs_state", [])?;
                archived.push(serde_json::json!({"kind": "gcs", "id": "gcs", "detected_suite": suite}));
                gcs_archived = true;
            }
        }
        let drones: Vec<(String, String)> = {
            let mut st = tx.prepare("SELECT drone_id, data FROM drones_local")?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for (id, data) in drones {
            let suite = detect(&data);
            let reason = if suite != SUITE_ID {
                Some("drone identity from another cryptographic suite")
            } else if gcs_archived {
                Some("GCS trust anchor was archived; drone must re-register")
            } else {
                match serde_json::from_str::<DroneLocalSnapshot>(&data).map_err(anyhow::Error::from).and_then(crate::protocol::entities::DroneState::from_local_snapshot) {
                    Ok(_) => None,
                    Err(_) => Some("stored device keys failed validation"),
                }
            };
            if let Some(reason) = reason {
                tx.execute("INSERT INTO legacy_snapshots (archived_ms, kind, entity_id, detected_suite, reason, data) VALUES (?1, 'drone', ?2, ?3, ?4, ?5)",
                           params![now, id, suite, reason, data])?;
                tx.execute("DELETE FROM drones_local WHERE drone_id = ?1", params![id])?;
                archived.push(serde_json::json!({"kind": "drone", "id": id, "detected_suite": suite, "reason": reason}));
            }
        }
        tx.commit()?;
        Ok(serde_json::json!({"archived_now": archived}))
    }

    /// Summary of archived incompatible rows (no key material; ids, suites, reasons).
    pub fn legacy_snapshot_summary(&self) -> anyhow::Result<serde_json::Value> {
        let mut st = self.conn.prepare("SELECT archived_ms, kind, entity_id, detected_suite, reason FROM legacy_snapshots ORDER BY id")?;
        let rows = st
            .query_map([], |r| {
                Ok(serde_json::json!({"archived_ms": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "id": r.get::<_, String>(2)?,
                                      "detected_suite": r.get::<_, String>(3)?, "reason": r.get::<_, String>(4)?}))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({"count": rows.len(), "rows": rows}))
    }

    /// Test/diagnostic helper: write a raw row into a live identity table.
    #[doc(hidden)]
    pub fn put_raw_identity_row(&self, kind: &str, id: &str, data: &str) -> anyhow::Result<()> {
        match kind {
            "gcs" => self.conn.execute("INSERT INTO gcs_state (id, data) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET data = excluded.data", params![data])?,
            _ => self.conn.execute("INSERT INTO drones_local (drone_id, data) VALUES (?1, ?2) ON CONFLICT(drone_id) DO UPDATE SET data = excluded.data", params![id, data])?,
        };
        Ok(())
    }

    pub fn reset_all(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            DELETE FROM legacy_snapshots;
            DELETE FROM gcs_state;
            DELETE FROM drones_local;
            DELETE FROM protocol_events;
            DELETE FROM trace_records;
            DELETE FROM suspicion_flags;
            DELETE FROM rag_contributions;
            DELETE FROM stego_events;
            "#,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::metadata::MembershipMetadata;
    use crate::protocol::entities::DroneState;
    use crate::protocol::events::{EventStatus};
    use crate::protocol::registration::register_drone;

    #[test]
    fn gcs_round_trip_preserves_group_root_and_drone_records() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        register_drone(&mut gcs, &mut d1, "alpha", md, 6).unwrap();
        let root_before = gcs.groups.get("alpha").unwrap().root();

        let db = Database::open_in_memory().unwrap();
        db.save_gcs(&gcs).unwrap();
        let restored = db.load_gcs().unwrap().expect("should have a saved GCS state");

        assert_eq!(restored.groups.get("alpha").unwrap().root(), root_before);
        assert!(restored.drones.contains_key("drone-1"));
        assert_eq!(restored.pid_pool.len(), gcs.pid_pool.len());
    }

    #[test]
    fn drone_local_round_trip_preserves_private_keys_and_cache() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        register_drone(&mut gcs, &mut d1, "alpha", md, 6).unwrap();

        let db = Database::open_in_memory().unwrap();
        db.save_drone_local(&d1.to_local_snapshot()).unwrap();
        let snap = db.load_drone_local("drone-1").unwrap().expect("should exist");
        let restored = DroneState::from_local_snapshot(snap).unwrap();

        assert_eq!(restored.cached_root, d1.cached_root);
        assert_eq!(restored.leaf, d1.leaf);
        // Reconstructing the seed from the restored device must give the
        // exact same seed as before persistence (golden pattern + helper
        // data round-tripped correctly).
        assert_eq!(restored.reconstruct_seed(), d1.reconstruct_seed());
    }

    #[test]
    fn event_log_persists_and_reads_back_in_order() {
        let db = Database::open_in_memory().unwrap();
        for i in 0..5 {
            let ev = ProtocolEvent {
                session_id: "s1".into(),
                stage: format!("M{i}"),
                sender: "D1".into(),
                receiver: "D2".into(),
                timestamp_unix_ms: i,
                status: EventStatus::Info,
                detail: format!("event {i}"),
            };
            db.append_event(&ev).unwrap();
        }
        let events = db.recent_events(3).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].stage, "M2");
        assert_eq!(events[2].stage, "M4");
    }

    #[test]
    fn reset_clears_everything() {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        let md = MembershipMetadata { role: "recon".into(), issued_at_unix: 1 };
        register_drone(&mut gcs, &mut d1, "alpha", md, 6).unwrap();
        let db = Database::open_in_memory().unwrap();
        db.save_gcs(&gcs).unwrap();
        db.save_drone_local(&d1.to_local_snapshot()).unwrap();
        db.reset_all().unwrap();
        assert!(db.load_gcs().unwrap().is_none());
        assert!(db.load_all_drone_ids().unwrap().is_empty());
    }

    fn registered() -> (GcsState, DroneState) {
        let mut gcs = GcsState::new();
        let mut d1 = DroneState::new("drone-1", [1u8; 32]);
        register_drone(&mut gcs, &mut d1, "alpha", MembershipMetadata { role: "recon".into(), issued_at_unix: 1 }, 6).unwrap();
        (gcs, d1)
    }

    #[test]
    fn current_suite_rows_are_kept_by_the_start_up_guard() {
        let (gcs, d1) = registered();
        let db = Database::open_in_memory().unwrap();
        db.save_gcs(&gcs).unwrap();
        db.save_drone_local(&d1.to_local_snapshot()).unwrap();
        assert_eq!(db.quarantine_incompatible().unwrap()["archived_now"].as_array().unwrap().len(), 0);
        assert!(db.load_gcs().unwrap().is_some());
        assert_eq!(db.load_all_drone_ids().unwrap(), vec!["drone-1".to_string()]);
        assert_eq!(db.legacy_snapshot_summary().unwrap()["count"], 0);
    }

    #[test]
    fn pre_migration_rows_are_archived_never_loaded() {
        // Rows as written by the Round-3 release: same structure, no `suite` field,
        // Dilithium2-sized private keys. Built from a current row to keep the shape.
        let (gcs, d1) = registered();
        let mut g = serde_json::to_value(gcs.to_snapshot()).unwrap();
        g.as_object_mut().unwrap().remove("suite");
        g["sign_sk"] = serde_json::json!(vec![0u8; 2528]);
        let mut d = serde_json::to_value(d1.to_local_snapshot()).unwrap();
        d.as_object_mut().unwrap().remove("suite");
        d["keys"].as_object_mut().unwrap().remove("suite");
        let db = Database::open_in_memory().unwrap();
        db.put_raw_identity_row("gcs", "gcs", &g.to_string()).unwrap();
        db.put_raw_identity_row("drone", "drone-1", &d.to_string()).unwrap();
        // loading directly is refused, not reinterpreted
        assert!(db.load_gcs().is_err());
        let out = db.quarantine_incompatible().unwrap();
        let a = out["archived_now"].as_array().unwrap();
        assert_eq!(a.len(), 2);
        assert!(a.iter().all(|r| r["detected_suite"] == crate::crypto::suite::LEGACY_SUITE_ID));
        assert!(db.load_gcs().unwrap().is_none());
        assert!(db.load_all_drone_ids().unwrap().is_empty());
        let sum = db.legacy_snapshot_summary().unwrap();
        assert_eq!(sum["count"], 2);
        assert!(!sum.to_string().contains("sign_sk"), "the summary carries no key material");
        // idempotent
        assert_eq!(db.quarantine_incompatible().unwrap()["archived_now"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn mixed_or_inconsistent_rows_are_archived() {
        let (gcs, d1) = registered();
        let db = Database::open_in_memory().unwrap();
        db.save_gcs(&gcs).unwrap();
        // a drone row labelled with another suite
        let mut other = serde_json::to_value(d1.to_local_snapshot()).unwrap();
        other["suite"] = serde_json::json!("iod-fips203-mlkem768-fips204-mldsa44-v2");
        db.put_raw_identity_row("drone", "drone-x", &other.to_string()).unwrap();
        // a current-suite row whose public key does not match its private seed
        let mut bad = serde_json::to_value(d1.to_local_snapshot()).unwrap();
        bad["keys"]["kem_pk"] = serde_json::to_value(crate::crypto::kem::keypair().0).unwrap();
        db.put_raw_identity_row("drone", "drone-y", &bad.to_string()).unwrap();
        db.save_drone_local(&d1.to_local_snapshot()).unwrap();
        let out = db.quarantine_incompatible().unwrap();
        let ids: Vec<&str> = out["archived_now"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"drone-x") && ids.contains(&"drone-y"));
        assert_eq!(db.load_all_drone_ids().unwrap(), vec!["drone-1".to_string()]);
        assert!(db.load_gcs().unwrap().is_some(), "a current GCS row stays");
    }

    #[test]
    fn archiving_the_gcs_also_archives_its_drones() {
        let (gcs, d1) = registered();
        let mut g = serde_json::to_value(gcs.to_snapshot()).unwrap();
        g["suite"] = serde_json::json!(crate::crypto::suite::LEGACY_SUITE_ID);
        let db = Database::open_in_memory().unwrap();
        db.put_raw_identity_row("gcs", "gcs", &g.to_string()).unwrap();
        db.save_drone_local(&d1.to_local_snapshot()).unwrap();
        let out = db.quarantine_incompatible().unwrap();
        assert_eq!(out["archived_now"].as_array().unwrap().len(), 2);
        assert!(db.load_all_drone_ids().unwrap().is_empty());
    }
}
