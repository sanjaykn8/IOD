import { useCallback, useState } from "react";
import { api } from "../services/api";
import { usePolling } from "../hooks/usePolling";

export function SecureCommPage() {
  const dronesFetcher = useCallback(() => api.getDrones(), []);
  const { data } = usePolling(dronesFetcher, 3000);

  const [d1, setD1] = useState("");
  const [d2, setD2] = useState("");
  const [mission, setMission] = useState("mission-alpha");
  const [keyStatus, setKeyStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [message, setMessage] = useState("Perimeter clear, proceeding to waypoint 2.");
  const [sendResult, setSendResult] = useState<{ decrypted_by_receiver: string } | null>(null);

  async function establishKey() {
    setBusy(true); setError(null); setKeyStatus(null);
    try {
      await api.establishGroupKey(d1, d2, mission);
      setKeyStatus("K1–K4 complete: GCS-assisted group key established. AEAD session key derived on both sides (never shown here).");
    } catch (e: any) {
      setError(e.message || String(e));
    } finally { setBusy(false); }
  }

  async function send() {
    setBusy(true); setError(null); setSendResult(null);
    try {
      const r = await api.sendSecureMessage(d1, d2, message);
      setSendResult(r);
    } catch (e: any) {
      setError(e.message || String(e));
    } finally { setBusy(false); }
  }

  return (
    <div>
      <h2 className="page-title">Secure Communication</h2>
      <p className="page-sub">GCS-assisted group-key establishment (K1–K4), followed by AEAD-encrypted application messaging. AEAD keys and KEM shared secrets are never exposed via this UI or any API response.</p>

      {error && <div className="error-banner">{error}</div>}

      <div className="panel">
        <h3>1. Establish Group Session Key</h3>
        <div className="row">
          <select value={d1} onChange={(e) => setD1(e.target.value)}>
            <option value="">D1…</option>
            {(data?.drones ?? []).map((d) => <option key={d.drone_id} value={d.drone_id}>{d.drone_id}</option>)}
          </select>
          <select value={d2} onChange={(e) => setD2(e.target.value)}>
            <option value="">D2…</option>
            {(data?.drones ?? []).map((d) => <option key={d.drone_id} value={d.drone_id}>{d.drone_id}</option>)}
          </select>
          <input placeholder="mission id" value={mission} onChange={(e) => setMission(e.target.value)} />
          <button disabled={busy || !d1 || !d2 || d1 === d2} onClick={establishKey}>Establish Group Key</button>
        </div>
        {keyStatus && <p style={{ color: "var(--ok)", fontSize: 13, marginTop: 10 }}>{keyStatus}</p>}
      </div>

      <div className="panel">
        <h3>2. Send Secure Message (D1 → D2)</h3>
        <textarea value={message} onChange={(e) => setMessage(e.target.value)} />
        <div className="row" style={{ marginTop: 10 }}>
          <button disabled={busy || !d1 || !d2} onClick={send}>Encrypt &amp; Send</button>
        </div>
        {sendResult && (
          <div style={{ marginTop: 14, fontSize: 13 }}>
            <div className="row"><span className="pill info">Plaintext (sender)</span><span>{message}</span></div>
            <div className="row" style={{ marginTop: 6 }}><span className="pill ok">AEAD sealed</span><span style={{ color: "var(--text-dim)" }}>ChaCha20-Poly1305, transported over the passthrough transport abstraction</span></div>
            <div className="row" style={{ marginTop: 6 }}><span className="pill ok">Decrypted (receiver)</span><span>{sendResult.decrypted_by_receiver}</span></div>
          </div>
        )}
      </div>
    </div>
  );
}
