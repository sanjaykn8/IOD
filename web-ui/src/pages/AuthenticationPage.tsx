import { useCallback, useState } from "react";
import { api } from "../services/api";
import { usePolling } from "../hooks/usePolling";
import { Pill } from "../components/Pill";
import type { AuthResultView, ProtocolEvent } from "../types/api";

export function AuthenticationPage() {
  const dronesFetcher = useCallback(() => api.getDrones(), []);
  const { data } = usePolling(dronesFetcher, 3000);

  const [d1, setD1] = useState("");
  const [d2, setD2] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AuthResultView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sessionEvents, setSessionEvents] = useState<ProtocolEvent[]>([]);

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    setSessionEvents([]);
    try {
      const r = await api.authenticate(d1, d2);
      setResult(r);
      const hist = await api.getEventsHistory(50);
      setSessionEvents(hist.events.filter((e) => e.session_id === r.session_id));
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2 className="page-title">D1 → D2 Authentication</h2>
      <p className="page-sub">Runs the full M1–M8 handshake: PUF proof, ZK membership proof, ML-DSA signature, and the Zero Trust decision.</p>

      {error && <div className="error-banner">{error}</div>}

      <div className="panel">
        <h3>Start Authentication</h3>
        <div className="row">
          <select value={d1} onChange={(e) => setD1(e.target.value)}>
            <option value="">select D1 (initiator)…</option>
            {(data?.drones ?? []).map((d) => <option key={d.drone_id} value={d.drone_id}>{d.drone_id}</option>)}
          </select>
          <select value={d2} onChange={(e) => setD2(e.target.value)}>
            <option value="">select D2 (verifier)…</option>
            {(data?.drones ?? []).map((d) => <option key={d.drone_id} value={d.drone_id}>{d.drone_id}</option>)}
          </select>
          <button disabled={busy || !d1 || !d2 || d1 === d2} onClick={run}>
            {busy ? "Running M1–M8…" : "Authenticate"}
          </button>
        </div>
      </div>

      {result && (
        <div className="panel">
          <h3>Verification Report — session {result.session_id.slice(0, 12)}…</h3>
          <div className="checklist">
            <div className="check-item"><span>Freshness (timestamps / nonces)</span><Pill ok={result.freshness_ok} /></div>
            <div className="check-item"><span>ZK Membership Proof</span><Pill ok={result.zk_membership_ok} /></div>
            <div className="check-item"><span>ML-DSA Signature (sig1)</span><Pill ok={result.signature_ok} /></div>
            <div className="check-item"><span>PUF Verification</span><Pill ok={result.puf_ok} /></div>
            <div className="check-item"><span>Merkle Root / Version consistency</span><Pill ok={result.root_version_ok} /></div>
            <div className="check-item">
              <strong>Zero Trust Decision</strong>
              <span className={`pill ${result.decision === "ALLOW" ? "ok" : "fail"}`}>{result.decision}</span>
            </div>
          </div>
          <p style={{ marginTop: 10, color: "var(--text-dim)", fontSize: 12 }}>Reason code: <span className="mono">{result.reason_code}</span></p>
        </div>
      )}

      {sessionEvents.length > 0 && (
        <div className="panel">
          <h3>Message Sequence (M1–M8)</h3>
          {sessionEvents.map((ev, i) => (
            <div className="event-line" key={i}>
              <span className="stage">{ev.stage}</span>
              <span className={`pill ${ev.status === "Ok" ? "ok" : ev.status === "Fail" ? "fail" : "info"}`}>{ev.status}</span>
              <span>{ev.sender}</span>
              <span>→ {ev.receiver}</span>
              <span style={{ color: "var(--text-dim)" }}>{ev.detail}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
