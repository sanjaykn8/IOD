import { useCallback, useState } from "react";
import { api } from "../services/api";
import { usePolling } from "../hooks/usePolling";

export function GroupsPage() {
  const fetcher = useCallback(() => api.getGroups(), []);
  const { data, error, refresh } = usePolling(fetcher, 3000);
  const [newId, setNewId] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  async function create() {
    setBusy(true);
    setActionError(null);
    try {
      await api.createGroup(newId);
      setNewId("");
      refresh();
    } catch (e: any) {
      setActionError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2 className="page-title">Group Management</h2>
      <p className="page-sub">Each group has its own Poseidon Merkle membership tree, maintained entirely by GCS. Drones only ever hold their own witness, never the full tree.</p>

      {(actionError || error) && <div className="error-banner">{actionError ?? error}</div>}

      <div className="panel">
        <h3>Create Group</h3>
        <div className="row">
          <input placeholder="group id (e.g. bravo)" value={newId} onChange={(e) => setNewId(e.target.value)} />
          <button disabled={busy || !newId} onClick={create}>Create</button>
        </div>
      </div>

      <div className="grid">
        {(data?.groups ?? []).map((g) => (
          <div className="card" key={g.group_id}>
            <div className="stat-label">{g.group_id}</div>
            <div style={{ marginTop: 8, fontSize: 13 }}>
              <div>Root: <span className="mono">{g.root_hex}</span></div>
              <div>Version: {g.version}</div>
              <div>Members: {g.active_members.length} / {g.capacity}</div>
              <div style={{ marginTop: 6, color: "var(--text-dim)" }}>
                {g.active_members.join(", ") || "no active members"}
              </div>
            </div>
          </div>
        ))}
        {data && data.groups.length === 0 && (
          <p style={{ color: "var(--text-dim)" }}>No groups yet.</p>
        )}
      </div>
    </div>
  );
}
