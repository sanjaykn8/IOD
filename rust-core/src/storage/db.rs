//! SQLite persistence (via `rusqlite`, bundled SQLite — no separate
//! system dependency required, works identically on Windows and Linux).
//! See `storage::snapshots` module docs for the schema design rationale.

use super::snapshots::{DroneLocalSnapshot, GcsSnapshot};
use crate::protocol::entities::GcsState;
use crate::protocol::events::ProtocolEvent;
use crate::trace::{SuspicionFlag, TraceRecord};
use rusqlite::{params, Connection};

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

    pub fn reset_all(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            DELETE FROM gcs_state;
            DELETE FROM drones_local;
            DELETE FROM protocol_events;
            DELETE FROM trace_records;
            DELETE FROM suspicion_flags;
            DELETE FROM rag_contributions;
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
}
