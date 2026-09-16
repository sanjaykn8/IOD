import { useCallback, useState } from "react";
import { api } from "../services/api";
import { usePolling } from "../hooks/usePolling";

export function DronesPage() {
  const fetcher = useCallback(() => api.getDrones(), []);
  const { data, error, refresh } = usePolling(fetcher, 3000);
  const groupsFetcher = useCallback(() => api.getGroups(), []);
  const { data: groupsData } = usePolling(groupsFetcher, 3000);

  const [newId, setNewId] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const [regDrone, setRegDrone] = useState("");
  const [regGroup, setRegGroup] = useState("");
  const [regRole, setRegRole] = useState("member");

  const [moveDrone, setMoveDrone] = useState("");
  const [moveGroup, setMoveGroup] = useState("");

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      refresh();
    } catch (e: any) {
      setActionError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2 className="page-title">Drone Management</h2>
      <p className="page-sub">Create simulated devices, register them into groups, and manage their lifecycle. Private keys, PUF seeds, and raw PUF responses are never shown here — only public fingerprints.</p>

      {actionError && <div className="error-banner">{actionError}</div>}

      <div className="panel">
        <h3>Create Drone</h3>
        <div className="row">
          <input placeholder="drone id (e.g. drone-3)" value={newId} onChange={(e) => setNewId(e.target.value)} />
          <button disabled={busy || !newId} onClick={() => run(() => api.createDrone(newId)).then(() => setNewId(""))}>
            Create
          </button>
        </div>
      </div>

      <div className="panel">
        <h3>Register Drone Into Group</h3>
        <div className="row">
          <select value={regDrone} onChange={(e) => setRegDrone(e.target.value)}>
            <option value="">select drone…</option>
            {(data?.drones ?? []).map((d) => <option key={d.drone_id} value={d.drone_id}>{d.drone_id}</option>)}
          </select>
          <select value={regGroup} onChange={(e) => setRegGroup(e.target.value)}>
            <option value="">select group…</option>
            {(groupsData?.groups ?? []).map((g) => <option key={g.group_id} value={g.group_id}>{g.group_id}</option>)}
          </select>
          <input placeholder="role (e.g. recon)" value={regRole} onChange={(e) => setRegRole(e.target.value)} />
          <button disabled={busy || !regDrone || !regGroup} onClick={() => run(() => api.registerDrone(regDrone, regGroup, regRole))}>
            Register
          </button>
        </div>
      </div>

      <div className="panel">
        <h3>Move Drone To Another Group</h3>
        <div className="row">
          <select value={moveDrone} onChange={(e) => setMoveDrone(e.target.value)}>
            <option value="">select drone…</option>
            {(data?.drones ?? []).map((d) => <option key={d.drone_id} value={d.drone_id}>{d.drone_id}</option>)}
          </select>
          <select value={moveGroup} onChange={(e) => setMoveGroup(e.target.value)}>
            <option value="">select destination group…</option>
            {(groupsData?.groups ?? []).map((g) => <option key={g.group_id} value={g.group_id}>{g.group_id}</option>)}
          </select>
          <button disabled={busy || !moveDrone || !moveGroup} onClick={() => run(() => api.moveDrone(moveDrone, moveGroup))}>
            Move
          </button>
        </div>
      </div>

      <div className="panel">
        <h3>Drones</h3>
        <table>
          <thead>
            <tr>
              <th>Drone</th><th>Group</th><th>Status</th><th>Leaf Index</th><th>Root (cached)</th><th>Version (cached)</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {(data?.drones ?? []).map((d) => (
              <tr key={d.drone_id}>
                <td>{d.drone_id}</td>
                <td>{d.group_id ?? "—"}</td>
                <td>
                  {!d.registered && <span className="pill warn">UNREGISTERED</span>}
                  {d.registered && d.active && <span className="pill ok">ACTIVE</span>}
                  {d.registered && !d.active && <span className="pill fail">REVOKED</span>}
                </td>
                <td>{d.leaf_index ?? "—"}</td>
                <td className="mono">{d.cached_root_hex ?? "—"}</td>
                <td>{d.cached_version ?? "—"}</td>
                <td className="row">
                  <button className="secondary" disabled={busy || !d.active} onClick={() => run(() => api.revokeDrone(d.drone_id))}>Revoke</button>
                  <button className="secondary" disabled={busy || d.active || !d.registered} onClick={() => run(() => api.reactivateDrone(d.drone_id))}>Reactivate</button>
                </td>
              </tr>
            ))}
            {data && data.drones.length === 0 && (
              <tr><td colSpan={7} style={{ color: "var(--text-dim)" }}>No drones yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {error && <div className="error-banner">{error}</div>}
    </div>
  );
}
