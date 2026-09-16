import { useCallback, useState } from "react";
import { api } from "../services/api";
import { usePolling } from "../hooks/usePolling";

export function TracePage() {
  const fetcher = useCallback(() => api.getTrace(), []);
  const { data, refresh } = usePolling(fetcher, 4000);

  const [sessionId, setSessionId] = useState("");
  const [flagReason, setFlagReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const [pidHex, setPidHex] = useState("");
  const [role, setRole] = useState("administrator");
  const [requester, setRequester] = useState("admin-1");
  const [traceReason, setTraceReason] = useState("");

  async function flag() {
    setError(null);
    try {
      await api.flagSession(sessionId, "operator", flagReason);
      setSessionId(""); setFlagReason("");
      refresh();
    } catch (e: any) { setError(e.message || String(e)); }
  }

  async function requestTrace() {
    setError(null);
    try {
      await api.requestTrace(requester, role, traceReason, pidHex);
      setPidHex(""); setTraceReason("");
      refresh();
    } catch (e: any) { setError(e.message || String(e)); }
  }

  return (
    <div>
      <h2 className="page-title">Trace Manager (Administrator Only)</h2>
      <p className="page-sub">
        Not part of the normal authentication path. Only requests with role <span className="mono">administrator</span> ever resolve a PID
        to a permanent DroneID — every attempt, authorized or not, is recorded in the audit trail below.
      </p>

      {error && <div className="error-banner">{error}</div>}

      <div className="panel">
        <h3>Flag a Session as Suspicious</h3>
        <div className="row">
          <input placeholder="session id" value={sessionId} onChange={(e) => setSessionId(e.target.value)} />
          <input placeholder="reason" value={flagReason} onChange={(e) => setFlagReason(e.target.value)} style={{ flex: 1 }} />
          <button disabled={!sessionId || !flagReason} onClick={flag}>Flag Session</button>
        </div>
      </div>

      <div className="panel">
        <h3>Request a Trace</h3>
        <div className="row">
          <input placeholder="requested by" value={requester} onChange={(e) => setRequester(e.target.value)} style={{ width: 120 }} />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="administrator">administrator</option>
            <option value="drone">drone (unauthorized)</option>
            <option value="operator">operator (unauthorized)</option>
          </select>
          <input placeholder="target PID (hex)" value={pidHex} onChange={(e) => setPidHex(e.target.value)} style={{ width: 220 }} />
          <input placeholder="reason" value={traceReason} onChange={(e) => setTraceReason(e.target.value)} style={{ flex: 1 }} />
          <button disabled={!pidHex || !traceReason} onClick={requestTrace}>Request Trace</button>
        </div>
        <p style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 8 }}>
          Tip: PIDs are not shown elsewhere in this UI by design (D2 never learns D1's permanent identity).
          For a demo trace, use the session id from the Authentication page's event log and inspect the protocol logs for a PID value, or use any hex string to see an "unresolved" trace.
        </p>
      </div>

      <div className="panel">
        <h3>Suspicion Flags</h3>
        <table>
          <thead><tr><th>Session</th><th>Flagged By</th><th>Reason</th></tr></thead>
          <tbody>
            {(data?.flags ?? []).map((f) => (
              <tr key={f.flag_id}><td>{f.session_id}</td><td>{f.flagged_by}</td><td>{f.reason}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3>Trace Audit Trail</h3>
        <table>
          <thead><tr><th>Requested By</th><th>Role</th><th>Authorized</th><th>Resolved Drone</th><th>Reason</th></tr></thead>
          <tbody>
            {(data?.trace_records ?? []).map((t) => (
              <tr key={t.trace_id}>
                <td>{t.requested_by}</td>
                <td>{t.requester_role}</td>
                <td>{t.authorized ? <span className="pill ok">YES</span> : <span className="pill fail">NO</span>}</td>
                <td>{t.resolved_drone_id ?? "—"}</td>
                <td>{t.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
