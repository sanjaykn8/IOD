import { useCallback } from "react";
import { api } from "../services/api";
import { usePolling } from "../hooks/usePolling";

export function DashboardPage() {
  const fetcher = useCallback(() => api.getState(), []);
  const { data, error } = usePolling(fetcher, 3000);

  return (
    <div>
      <h2 className="page-title">System Overview</h2>
      <p className="page-sub">GCS status, drones, groups, and system health at a glance. Refreshes every 3s.</p>

      {error && <div className="error-banner">{error}</div>}

      <div className="grid">
        <div className="card">
          <div className="stat-label">Drones</div>
          <div className="stat-value">{data?.drone_count ?? "–"}</div>
        </div>
        <div className="card">
          <div className="stat-label">Groups</div>
          <div className="stat-value">{data?.group_count ?? "–"}</div>
        </div>
        <div className="card">
          <div className="stat-label">Protocol events (this session)</div>
          <div className="stat-value">{data?.event_count ?? "–"}</div>
        </div>
        <div className="card">
          <div className="stat-label">GCS status</div>
          <div className="stat-value" style={{ color: "var(--ok)" }}>{data ? "ONLINE" : "…"}</div>
        </div>
      </div>

      <div className="panel">
        <h3>Groups</h3>
        <table>
          <thead>
            <tr><th>Group</th><th>Merkle Root</th><th>Version</th><th>Members</th><th>Capacity</th></tr>
          </thead>
          <tbody>
            {(data?.groups ?? []).map((g) => (
              <tr key={g.group_id}>
                <td>{g.group_id}</td>
                <td className="mono">{g.root_hex}</td>
                <td>{g.version}</td>
                <td>{g.active_members.length}</td>
                <td>{g.capacity}</td>
              </tr>
            ))}
            {data && data.groups.length === 0 && (
              <tr><td colSpan={5} style={{ color: "var(--text-dim)" }}>No groups yet — create one on the Groups page.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3>Drones</h3>
        <table>
          <thead>
            <tr><th>Drone</th><th>Group</th><th>Active</th><th>Role</th><th>KEM PK fingerprint</th><th>Dilithium PK fingerprint</th></tr>
          </thead>
          <tbody>
            {(data?.drones ?? []).map((d) => (
              <tr key={d.drone_id}>
                <td>{d.drone_id}</td>
                <td>{d.group_id ?? "—"}</td>
                <td>{d.active ? <span className="pill ok">ACTIVE</span> : <span className="pill fail">INACTIVE</span>}</td>
                <td>{d.role ?? "—"}</td>
                <td className="mono">{d.kem_pk_fingerprint ?? "—"}</td>
                <td className="mono">{d.dil_pk_fingerprint ?? "—"}</td>
              </tr>
            ))}
            {data && data.drones.length === 0 && (
              <tr><td colSpan={6} style={{ color: "var(--text-dim)" }}>No drones yet — create one on the Drones page.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
