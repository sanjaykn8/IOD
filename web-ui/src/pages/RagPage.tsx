import { useCallback, useState } from "react";
import { api } from "../services/api";
import { usePolling } from "../hooks/usePolling";
import type { RagRunResult } from "../types/api";

export function RagPage() {
  const stateFetcher = useCallback(() => api.ragState(), []);
  const { data, refresh } = usePolling(stateFetcher, 4000);

  const [droneId, setDroneId] = useState("drone-1");
  const [content, setContent] = useState("");
  const [confidence, setConfidence] = useState(0.85);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<RagRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function contribute() {
    setBusy(true); setError(null);
    try {
      await api.ragContribute(droneId, content, confidence);
      setContent("");
      refresh();
    } catch (e: any) { setError(e.message || String(e)); }
    finally { setBusy(false); }
  }

  async function runQuery() {
    setBusy(true); setError(null); setResult(null);
    try {
      const r = await api.ragRun(query);
      setResult(r);
    } catch (e: any) { setError(e.message || String(e)); }
    finally { setBusy(false); }
  }

  async function reset() {
    await api.ragReset();
    setResult(null);
    refresh();
  }

  return (
    <div>
      <h2 className="page-title">Collaborative RAG Simulation</h2>
      <p className="page-sub">
        Deterministic mock-LLM pipeline: drone contribution → retrieval → validation
        (simple outlier-based heuristic — <em>not</em> a real Byzantine-fault-tolerant defense) → fusion → generation.
        Active provider: <span className="mono">{data?.llm_provider ?? "…"}</span>
      </p>

      {error && <div className="error-banner">{error}</div>}

      <div className="panel">
        <h3>Add Drone Contribution</h3>
        <div className="row">
          <input placeholder="drone id" value={droneId} onChange={(e) => setDroneId(e.target.value)} style={{ width: 120 }} />
          <input placeholder="confidence 0-1" type="number" step="0.05" min={0} max={1} value={confidence} onChange={(e) => setConfidence(parseFloat(e.target.value))} style={{ width: 110 }} />
        </div>
        <textarea style={{ marginTop: 8 }} placeholder="contribution content…" value={content} onChange={(e) => setContent(e.target.value)} />
        <div className="row" style={{ marginTop: 8 }}>
          <button disabled={busy || !content} onClick={contribute}>Submit Contribution</button>
          <button className="secondary" onClick={reset}>Reset RAG State</button>
        </div>
      </div>

      <div className="panel">
        <h3>Contributions ({data?.contributions.length ?? 0})</h3>
        <table>
          <thead><tr><th>Drone</th><th>Content</th><th>Confidence</th><th>Trust</th><th>Flag</th></tr></thead>
          <tbody>
            {(data?.contributions ?? []).map((c, i) => (
              <tr key={i}>
                <td>{c.drone_id}</td>
                <td>{c.content}</td>
                <td>{c.confidence.toFixed(2)}</td>
                <td>{c.trust_score.toFixed(2)}</td>
                <td>{c.flagged_suspicious ? <span className="pill warn" title={c.flag_reason}>SUSPICIOUS</span> : <span className="pill ok">OK</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3>Run Query</h3>
        <div className="row">
          <input style={{ flex: 1 }} placeholder="e.g. What is happening on route 7?" value={query} onChange={(e) => setQuery(e.target.value)} />
          <button disabled={busy || !query} onClick={runQuery}>Run RAG Pipeline</button>
        </div>
      </div>

      {result && (
        <div className="panel">
          <h3>Result</h3>
          <p><strong>Included:</strong> {result.included_drone_ids.join(", ") || "none"}</p>
          <p><strong>Excluded:</strong> {result.excluded_drone_ids.join(", ") || "none"}</p>
          <pre style={{ whiteSpace: "pre-wrap", background: "var(--panel-2)", padding: 10, borderRadius: 6, fontSize: 12 }}>{result.generated_output}</pre>
        </div>
      )}
    </div>
  );
}
