import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { ArrowRight, Camera, ImageOff, Play, RefreshCw, Send, Download, FlaskConical, Info } from "lucide-react";
import { api } from "@/lib/api";
import { stegoApi, stegoUrl, downloadStegoReport, type StegoResult } from "@/lib/stego-api";
import { CAMERA_REASONS, describeStegoError } from "@/lib/stego-errors";
import { usePolling } from "@/hooks/use-polling";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { BusyLabel, DataTable, Empty, Field, Metric, PageHeader, Panel, Status, TechnicalId, selectClass, type Tone } from "./core";
import type { ProtocolEvent } from "@/lib/api";
import type {
  StegoCameraProbe, StegoCandidate, StegoCoverRequest, StegoErrorBody, StegoEvent, StegoExplanation, StegoMessageResult,
  StegoNum, StegoPriority, StegoReport, StegoSelection, StegoStage,
} from "@/types/api";

/* ------------------------------------------------------------------ formatting */
const isNil = (v: unknown): v is null | undefined => v === null || v === undefined;
function fmtNum(v: unknown, digits = 3, unit = ""): string {
  if (isNil(v)) return "n/a";
  if (typeof v === "string") return /^[+]?inf(inity)?$/i.test(v) ? "∞ (identical)" : v;
  if (typeof v !== "number") return String(v);
  if (!Number.isFinite(v)) return v > 0 ? "∞ (identical)" : "n/a";
  return `${Number.isInteger(v) ? v : v.toFixed(digits)}${unit}`;
}
/** Quality metrics: a null means "undefined" in the core's sense -- never substitute a number. */
function fmtMetric(v: StegoNum, digits = 3, unit = ""): string {
  return isNil(v) ? "undefined" : fmtNum(v, digits, unit);
}
const fmtPct = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? `${(v * 100).toFixed(1)}%` : "n/a");
const fmtMs = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? `${v < 10 ? v.toFixed(2) : v.toFixed(1)} ms` : "n/a");
const fmtTime = (ms?: number) => (typeof ms === "number" ? new Date(ms).toLocaleString() : "n/a");
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const short = (s?: string | null, n = 8) => (s ? (s.length > n ? `${s.slice(0, n)}…` : s) : "—");
const ALGORITHMS = ["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct"] as const;

function Bar({ value, max, tone = "info" }: { value: number | null; max: number; tone?: Tone }) {
  const pct = value === null || max <= 0 ? 0 : Math.max(0, Math.min(100, (value / max) * 100));
  return <span className={`stego-bar stego-bar-${tone}`} aria-hidden="true"><i style={{ width: `${pct}%` }} /></span>;
}
function KV({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="stego-kv">{rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>;
}
function Notice({ tone, title, children }: { tone: "danger" | "warning" | "info"; title: string; children: ReactNode }) {
  return <div className={`notice notice-${tone === "info" ? "info" : tone}`} role={tone === "danger" ? "alert" : "status"}><Info aria-hidden="true" /><div><strong>{title}</strong><p>{children}</p></div></div>;
}
function Flag({ label, v }: { label: string; v: boolean | null | undefined }) {
  return <Status tone={v === true ? "success" : v === false ? "danger" : "neutral"}>{label}: {v === true ? "OK" : v === false ? "FAILED" : "n/a"}</Status>;
}
function Preview({ id, kind, label }: { id?: string | undefined; kind: "stego" | "cover"; label: string }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [id, kind]);
  return (
    <figure className="stego-preview">
      <figcaption>{label}</figcaption>
      {id && !failed
        ? <img src={stegoUrl.artifact(id, kind)} alt={`${label} image`} onError={() => setFailed(true)} />
        : <div className="stego-preview-missing"><ImageOff aria-hidden="true" /><span>{id ? "preview unavailable (image failed to load)" : "no image yet"}</span></div>}
    </figure>
  );
}

/* ------------------------------------------------------------------ stages */
const CANON: { key: string; label: string; re: RegExp }[] = [
  { key: "seal", label: "AEAD seal", re: /seal|encrypt/i },
  { key: "select", label: "Selector decision", re: /select|policy|decision/i },
  { key: "embed", label: "Embedding", re: /embed|encode/i },
  { key: "save", label: "Save to disk", re: /save|write|persist/i },
  { key: "read", label: "Local read", re: /read|load/i },
  { key: "extract", label: "Extraction", re: /extract/i },
  { key: "verify", label: "Metadata / header verification", re: /verif|header|metadata|mac|bootstrap/i },
  { key: "open", label: "AEAD verification / decryption", re: /aead_open|open|decrypt/i },
  { key: "explain", label: "RAG explanation", re: /explain|rag/i },
];
function canonKey(name: string): string | null {
  // "aead_open" must win over "aead seal"/"verify"; check the more specific patterns first.
  if (/aead.*(open|verif|decrypt)|open|decrypt/i.test(name)) return "open";
  if (/seal|encrypt/i.test(name)) return "seal";
  for (const c of CANON) if (c.re.test(name)) return c.key;
  return null;
}
function normStatus(s: string): "ok" | "failed" | "skipped" | "other" {
  const v = s.toLowerCase();
  if (["ok", "success", "passed", "done"].includes(v)) return "ok";
  if (["failed", "fail", "error"].includes(v)) return "failed";
  if (["skipped", "skip", "not_run"].includes(v)) return "skipped";
  return "other";
}

function Timeline({ stages, error }: { stages: StegoStage[]; error?: StegoErrorBody | undefined }) {
  const rows = useMemo(() => {
    const byKey = new Map<string, StegoStage>();
    const extra: StegoStage[] = [];
    for (const s of stages) {
      const k = canonKey(s.name);
      if (k && !byKey.has(k)) byKey.set(k, s); else extra.push(s);
    }
    const list = CANON.map((c) => ({ label: c.label, stage: byKey.get(c.key) ?? null }));
    for (const s of extra) list.push({ label: s.name, stage: s });
    return list;
  }, [stages]);
  return (
    <ol className="stego-timeline" aria-label="Transaction stages">
      {rows.map(({ label, stage }, i) => {
        const st = stage ? normStatus(stage.status) : "none";
        const isFail = !!stage && (st === "failed" || (!!error?.stage && error.stage === stage.name));
        const cls = isFail ? "failed" : st === "none" ? "none" : st;
        return (
          <li key={`${label}-${i}`} className={`stego-stage stego-stage-${cls}`} data-testid={`stage-${cls}`}>
            <span className="stego-stage-n">{String(i + 1).padStart(2, "0")}</span>
            <div>
              <strong>{label}{stage && stage.name !== label ? <small> ({stage.name})</small> : null}</strong>
              {stage?.detail ? <p>{stage.detail}</p> : null}
              {isFail && error ? <p className="stego-stage-code"><code>{error.code}</code> {error.message}</p> : null}
            </div>
            <span className="stego-stage-ms">{stage ? fmtMs(stage.ms) : ""}</span>
            <Status tone={isFail ? "danger" : st === "ok" ? "success" : st === "skipped" ? "neutral" : st === "none" ? "neutral" : "info"}>
              {isFail ? "FAILED" : st === "none" ? "NOT REACHED" : st === "other" && stage ? stage.status.toUpperCase() : st.toUpperCase()}
            </Status>
          </li>
        );
      })}
    </ol>
  );
}

/* ------------------------------------------------------------------ candidates */
function Candidates({ selection }: { selection: StegoSelection }) {
  const cands = selection.candidates ?? [];
  const maxScore = Math.max(0, ...cands.map((c) => num(c.score) ?? 0));
  const winner = selection.selected ?? null;
  return (
    <>
      <KV rows={[
        ["SELECTED", winner ?? "none"], ["REASON CODE", selection.reason_code ?? "n/a"],
        ["POLICY", selection.policy_version ?? "n/a"], ["MODE", selection.mode ?? (selection.reason_code === "MANUAL_OVERRIDE" ? "manual override" : "n/a")],
      ]} />
      <DataTable label="Candidate algorithms">
        <thead><tr><th>Algorithm</th><th>Eligibility</th><th>Capacity</th><th>Utilisation</th><th>Est. cost</th><th>MSE</th><th>PSNR</th><th>SSIM</th><th>Score (lower = better)</th></tr></thead>
        <tbody>
          {cands.map((c: StegoCandidate) => {
            const isWin = winner === c.algorithm;
            return (
              <tr key={c.algorithm} className={isWin ? "stego-winner" : c.eligible ? "" : "stego-excluded"} data-testid={`cand-${c.algorithm}`}>
                <td><strong>{c.algorithm}{isWin ? <span className="stego-winner-mark"> ★ WINNER</span> : null}</strong>{isWin && selection.reason_code ? <small>{selection.reason_code}</small> : null}</td>
                <td>{c.eligible ? <Status tone="success">ELIGIBLE</Status> : <><Status tone="danger">EXCLUDED</Status><small>{c.exclusion_reason ?? "reason n/a"}</small></>}</td>
                <td>{isNil(c.capacity_bytes) ? "n/a" : `${c.capacity_bytes} B`}</td>
                <td><div className="stego-cellbar">{fmtPct(c.utilization)}<Bar value={num(c.utilization)} max={1} /></div></td>
                <td>{fmtNum(c.est_cost_units, 2)}</td>
                <td>{fmtMetric(c.mse)}</td><td>{fmtMetric(c.psnr, 2, " dB")}</td><td>{fmtMetric(c.ssim, 4)}</td>
                <td><div className="stego-cellbar">{fmtNum(c.score, 4)}<Bar value={c.eligible ? num(c.score) : null} max={maxScore} tone={isWin ? "success" : "info"} /></div></td>
              </tr>
            );
          })}
        </tbody>
      </DataTable>
    </>
  );
}

/* ------------------------------------------------------------------ RAG panel */
function renderEvidence(ev: unknown): ReactNode {
  if (isNil(ev)) return <p className="stego-muted">No evidence returned.</p>;
  if (Array.isArray(ev)) return <ul className="stego-list">{ev.map((e, i) => <li key={i}>{typeof e === "string" ? e : JSON.stringify(e)}</li>)}</ul>;
  if (typeof ev === "object") {
    return <KV rows={Object.entries(ev as Record<string, unknown>).map(([k, v]): [string, ReactNode] => [k, typeof v === "object" && v !== null ? <code>{JSON.stringify(v)}</code> : String(v)])} />;
  }
  return <p>{String(ev)}</p>;
}
function retrievedIds(r: unknown): string[] {
  if (!Array.isArray(r)) return [];
  return r.map((x) => (typeof x === "string" ? x : x && typeof x === "object" && "id" in x ? String((x as { id: unknown }).id) : JSON.stringify(x)));
}
function ExplanationPanel({ ex }: { ex: StegoExplanation }) {
  const ids = retrievedIds(ex.retrieved);
  return (
    <>
      <Notice tone="info" title="Simulated RAG — explanation only, does not choose the algorithm">
        The algorithm was chosen by the deterministic policy before this text was written. The retrieval is word-overlap over a small knowledge base and the narrative is template text (mock LLM).
      </Notice>
      {ex.fallback ? <Notice tone="warning" title="Deterministic fallback explanation">The explanation service did not produce a verified narrative, so a rule-based text generated by the core is shown instead.</Notice> : null}
      <div className="split-grid stego-rag-grid">
        <div className="output-block output-primary" data-testid="rag-evidence"><span>MACHINE-COMPUTED EVIDENCE</span>{renderEvidence(ex.evidence)}</div>
        <div className="output-block" data-testid="rag-narrative"><span>GENERATED NARRATIVE {ex.fallback ? "(DETERMINISTIC FALLBACK)" : "(SIMULATED)"}</span><p className="stego-narrative">{ex.narrative || "No narrative returned."}</p></div>
      </div>
      <div className="stego-chips">
        <Status tone="neutral">status: {ex.status ?? "n/a"}</Status>
        <Status tone="neutral">kb: {ex.kb_version ?? "n/a"}</Status>
        <Flag label="selection unchanged by explanation" v={ex.selected_unchanged} />
        {ids.length ? ids.map((id) => <Status key={id} tone="info">kb:{id}</Status>) : <Status tone="neutral">no KB snippets retrieved</Status>}
      </div>
    </>
  );
}

/* ------------------------------------------------------------------ main page */
type Outcome = { ok: true; data: StegoMessageResult } | { ok: false; error: StegoErrorBody; stages: StegoStage[] };
const DIRS = { D1_D2: "D1 → D2", D2_D1: "D2 → D1" } as const;
const TIME_RANGES: Record<string, number> = { all: 0, "15m": 15 * 60e3, "1h": 3600e3, "24h": 24 * 3600e3 };

export function SteganographyLabPage() {
  const dronesFetcher = useCallback(() => api.getDrones(), []);
  const histFetcher = useCallback(() => api.getEventsHistory(1000), []);
  const statusFetcher = useCallback(async () => stegoApi.status(), []);
  const { data: droneData, error: droneErr } = usePolling(dronesFetcher, 4000);
  const { data: hist, refresh: refreshHist } = usePolling(histFetcher, 4000);
  const { data: statusRes, refresh: refreshStatus } = usePolling(statusFetcher, 5000);

  const [d1, setD1] = useState(""), [d2, setD2] = useState("");
  const [sessionSel, setSessionSel] = useState("auto");
  const [dir, setDir] = useState<keyof typeof DIRS>("D1_D2");
  const [coverSrc, setCoverSrc] = useState<"webcam" | "procedural" | "test_cover">("webcam");
  const [algo, setAlgo] = useState("auto");
  const [priority, setPriority] = useState<StegoPriority>("normal");
  const [message, setMessage] = useState("Perimeter clear, proceeding to waypoint 2.");
  const [busy, setBusy] = useState<"" | "send" | "analyze" | "probe" | "bench">("");
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [selView, setSelView] = useState<{ sel: StegoSelection; origin: string } | null>(null);
  const [probe, setProbe] = useState<StegoResult<StegoCameraProbe> | null>(null);
  const [reuseCoverId, setReuseCoverId] = useState<string | null>(null);

  /* ---- readiness (derived from the existing protocol event history) */
  const sessions = useMemo(() => {
    const m = new Map<string, { id: string; ts: number; stages: Set<string>; fails: Set<string> }>();
    for (const e of (hist?.events ?? []) as ProtocolEvent[]) {
      let s = m.get(e.session_id);
      if (!s) { s = { id: e.session_id, ts: 0, stages: new Set(), fails: new Set() }; m.set(e.session_id, s); }
      s.ts = Math.max(s.ts, e.timestamp_unix_ms);
      if (e.status === "Ok") s.stages.add(e.stage);
      if (e.status === "Fail") s.fails.add(e.stage);
    }
    return [...m.values()].filter((s) => s.stages.size || s.fails.size).sort((a, b) => b.ts - a.ts).map((s) => ({
      id: s.id, ts: s.ts,
      authOk: s.stages.has("M8") && ![...s.fails].some((f) => f.startsWith("M")),
      keyOk: s.stages.has("K3") && ![...s.fails].some((f) => f.startsWith("K")),
    }));
  }, [hist]);
  const authSessions = sessions.filter((s) => s.id && (s.authOk || s.keyOk));
  const effective = sessionSel === "auto" ? (sessions[0] ?? null) : (sessions.find((s) => s.id === sessionSel) ?? null);
  const benchSession = sessionSel === "auto" ? (sessions.find((s) => s.authOk && s.keyOk) ?? null) : effective;

  const drones = droneData?.drones ?? [];
  const dA = drones.find((d) => d.drone_id === d1), dB = drones.find((d) => d.drone_id === d2);
  const dronesOk = !!dA && !!dB && dA.registered && dB.registered && dA.active && dB.active && !!dA.group_id && dA.group_id === dB.group_id;

  const st = statusRes && statusRes.ok ? statusRes.data : null;
  const backendUp = !!st?.backend.reachable;
  const cam = st?.backend.health?.camera;
  const camMode = cam?.mode ?? "unknown";
  const camLikely = !!cam?.opencv_available && !/disabled|absent|none|procedural|unavailable/i.test(camMode);
  const probed = probe && probe.ok ? probe.data : null;
  const webcamAvailable = probed ? probed.available : null; // null = not probed

  const needsPair = !d1 || !d2 || d1 === d2;
  const fromId = dir === "D1_D2" ? d1 : d2;

  function coverReq(): StegoCoverRequest {
    if (coverSrc === "test_cover" && reuseCoverId) return { source: "test_cover", test_cover_id: reuseCoverId };
    return { source: coverSrc === "test_cover" ? "procedural" : coverSrc };
  }

  /* ---- events + report */
  const [filters, setFilters] = useState({ session_id: "", direction: "", algorithm: "", outcome: "", range: "all" });
  const [events, setEvents] = useState<StegoResult<{ events: StegoEvent[] }> | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<StegoEvent | null>(null);
  const [report, setReport] = useState<StegoResult<StegoReport> | null>(null);
  const [dlError, setDlError] = useState<string | null>(null);
  const [timingStage, setTimingStage] = useState("total");

  const loadEvents = useCallback(async (f = filters) => {
    const range = TIME_RANGES[f.range] ?? 0;
    setEvents(await stegoApi.events({ session_id: f.session_id, direction: f.direction, algorithm: f.algorithm, outcome: f.outcome, ...(range ? { since_ms: Date.now() - range } : {}), limit: 200 }));
  }, [filters]);
  const loadReport = useCallback(async () => setReport(await stegoApi.report()), []);
  useEffect(() => { void loadEvents(); void loadReport(); /* initial load only */ // eslint-disable-line react-hooks/exhaustive-deps
  }, []);

  /* ---- actions */
  async function send() {
    setBusy("send"); setOutcome(null); setSelView(null);
    const base = { from_id: fromId, plaintext: message, cover: coverReq(), priority, ...(algo !== "auto" ? { algorithm: algo } : {}) };
    const r = await stegoApi.message(sessionSel === "auto" ? { ...base, d1_id: d1, d2_id: d2 } : { ...base, session_id: sessionSel });
    if (r.ok) {
      setOutcome({ ok: true, data: r.data });
      if (r.data.selection) setSelView({ sel: r.data.selection, origin: "transaction" });
      if (r.data.artifact?.id) setReuseCoverId(r.data.cover?.artifact_id ?? r.data.artifact.id);
    } else {
      setOutcome({ ok: false, error: r.error, stages: r.stages ?? [] });
      const cands = (r.error.details as { candidates?: StegoCandidate[]; selection?: StegoSelection } | null | undefined);
      if (cands?.selection) setSelView({ sel: cands.selection, origin: "failure" });
      else if (cands?.candidates) setSelView({ sel: { candidates: cands.candidates, selected: null, reason_code: r.error.code }, origin: "failure" });
    }
    setBusy("");
    void refreshHist(); void refreshStatus(); void loadEvents(); void loadReport();
  }
  async function analyze() {
    setBusy("analyze");
    const frameBytes = new TextEncoder().encode(message).length + 64; // rough preview size; the real frame size is decided by the core
    const r = await stegoApi.analyze({ frame_bytes: frameBytes, cover: coverReq(), priority });
    if (r.ok && r.data.selection) setSelView({ sel: r.data.selection, origin: "analyze" });
    else if (!r.ok) setOutcome({ ok: false, error: r.error, stages: r.stages ?? [] });
    setBusy("");
  }
  async function runProbe() {
    setBusy("probe"); setProbe(await stegoApi.probeCamera()); setBusy("");
  }

  /* ---- benchmark */
  const [iters, setIters] = useState(5), [sizes, setSizes] = useState("64,256,1024");
  const [bench, setBench] = useState<StegoResult<{ runs?: unknown[]; summary?: unknown }> | null>(null);
  async function runBench() {
    if (!benchSession) return;
    setBusy("bench");
    const frame_sizes = sizes.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => Number.isFinite(n) && n > 0);
    const c = coverReq();
    setBench(await stegoApi.benchmark({ session_id: benchSession.id, iterations: Math.max(1, Math.min(50, iters || 1)), ...(frame_sizes.length ? { frame_sizes } : {}), ...(c.source === "test_cover" ? {} : { cover: c }) }));
    setBusy(""); void loadReport(); void loadEvents(); void refreshStatus();
  }

  const result = outcome?.ok ? outcome.data : null;
  const failure = outcome && !outcome.ok ? outcome : null;
  const stagesShown = result?.stages ?? failure?.stages ?? [];
  const explanation = result?.explanation;
  const fallbackReason = result?.cover?.fallback_reason;
  const rep = report && report.ok ? report.data : null;
  const timingKeys = useMemo(() => [...new Set((rep?.per_algorithm ?? []).flatMap((a) => Object.keys(a.timings_ms ?? {})))], [rep]);
  const maxCap = Math.max(0, ...(rep?.per_algorithm ?? []).map((a) => a.capacity_bytes?.mean ?? 0));
  const maxPsnr = Math.max(0, ...(rep?.per_algorithm ?? []).map((a) => a.psnr?.mean ?? 0));

  const errView = failure ? describeStegoError(failure.error.code, failure.error.message) : null;
  const e = result?.embed;
  const cover = result?.cover;
  const art = result?.artifact;
  const dims = (art?.width ?? cover?.width) ? `${art?.width ?? cover?.width} × ${art?.height ?? cover?.height}` : "n/a";
  const capBytes = e?.capacity_bytes ?? null, frameLen = e?.frame_len ?? null;

  return <>
    <PageHeader eyebrow="STEGANOGRAPHY LAB / K4 TRANSPORT" title="Steganography Lab" description="Application messages travel as lossless PNG images after M1–M8 and K1–K3. The core seals, embeds, saves, re-reads and verifies every message; this page only renders the result." actions={<Button variant="outline" size="sm" onClick={() => { void refreshStatus(); void refreshHist(); }}><RefreshCw />Refresh status</Button>} />

    {/* 1 readiness */}
    <Panel title="1 / Readiness" meta={<Status tone={backendUp && dronesOk && effective?.authOk && effective?.keyOk ? "success" : "warning"}>{backendUp && dronesOk && effective?.authOk && effective?.keyOk ? "READY" : "CHECK PREREQUISITES"}</Status>}>
      {droneErr ? <Notice tone="danger" title="Core state unavailable">{droneErr}</Notice> : null}
      <div className="form-grid stego-grid-4">
        <Field label="Drone D1 (initiator)"><select className={selectClass} value={d1} onChange={(ev) => setD1(ev.target.value)} aria-label="Drone D1"><option value="">Select D1</option>{drones.map((d) => <option key={d.drone_id}>{d.drone_id}</option>)}</select></Field>
        <Field label="Drone D2 (verifier)"><select className={selectClass} value={d2} onChange={(ev) => setD2(ev.target.value)} aria-label="Drone D2"><option value="">Select D2</option>{drones.map((d) => <option key={d.drone_id}>{d.drone_id}</option>)}</select></Field>
        <Field label="Session" hint="Auto lets the core resolve the latest session for the pair."><select className={selectClass} value={sessionSel} onChange={(ev) => setSessionSel(ev.target.value)} aria-label="Session">
          <option value="auto">Auto: latest session of this pair</option>
          {authSessions.map((s) => <option key={s.id} value={s.id}>{short(s.id, 12)} {"·"} M1–M8 {s.authOk ? "✓" : "✗"} K1–K3 {s.keyOk ? "✓" : "✗"}</option>)}
        </select></Field>
        <div className="field"><span>Camera</span><Button variant="outline" onClick={() => void runProbe()} disabled={busy === "probe" || !backendUp}><Camera /><BusyLabel busy={busy === "probe"} idle="Probe webcam" busyText="Probing" /></Button></div>
      </div>
      <div className="stego-ready-grid">
        <ReadyItem label="M1–M8 mutual authentication" ok={effective ? effective.authOk : null} detail={effective ? `session ${short(effective.id, 12)}` : "no session found in event history"} />
        <ReadyItem label="K1–K3 group key" ok={effective ? effective.keyOk : null} detail={effective ? `session ${short(effective.id, 12)}` : "no session found in event history"} />
        <ReadyItem label="Selected drones registered, active, same group" ok={needsPair ? null : dronesOk} detail={needsPair ? "choose two different drones" : dronesOk ? `${d1}, ${d2}` : "not both active members of one group"} />
        <ReadyItem label="Steganography backend (Python)" ok={statusRes ? backendUp : null} detail={!statusRes ? "checking…" : backendUp ? `v${st?.backend.health?.version ?? "?"}, artifacts writable: ${st?.backend.health?.artifact_dir_writable === false ? "NO" : "yes"}` : (statusRes.ok ? (st?.backend.error ?? "unreachable") : `${statusRes.error.code}: ${statusRes.error.message}`)} />
      </div>
      {sessionSel === "auto" ? <p className="stego-muted">Auto mode: protocol events do not name the drone pair, so M/K readiness above reflects the newest session overall. The core is authoritative and will answer NO_AUTH_SESSION / NO_GROUP_KEY if the selected pair is not ready.</p> : null}
      {!statusRes ? null : !backendUp ? <Notice tone="danger" title="STEGO_BACKEND_UNAVAILABLE">{describeStegoError("STEGO_BACKEND_UNAVAILABLE").text}</Notice> : null}
      {backendUp ? (
        webcamAvailable === true
          ? <Notice tone="info" title="Webcam available">{`Probe succeeded${probed?.width ? ` (${probed.width}×${probed.height})` : ""}. "Webcam with fallback" will use it and fall back to a procedural cover if a capture fails.`}</Notice>
          : <Notice tone="info" title={webcamAvailable === false || !camLikely ? "No webcam: procedural fallback will be used" : "Webcam backend present (not probed)"}>
              {webcamAvailable === false
                ? `Probe result: ${probed?.reason ?? "unavailable"}${probed?.reason && CAMERA_REASONS[probed.reason] ? ` (${CAMERA_REASONS[probed.reason]})` : ""}. A procedural cover image will be generated instead; this is a fallback, not an error.`
                : !camLikely ? `Camera mode "${camMode}", OpenCV ${cam?.opencv_available ? "present" : "not available"}. The procedural cover generator will be used. Use "Probe webcam" to confirm.`
                : `Camera mode "${camMode}". Not probed yet; if a capture fails the procedural fallback is used automatically.`}
            </Notice>
      ) : null}
      {st ? <p className="stego-muted">Stored events: {st.counts?.events ?? "n/a"} ({st.counts?.ok ?? "n/a"} ok / {st.counts?.failed ?? "n/a"} failed){st.config?.policy ? ` · policy ${String((st.config.policy as { name?: string }).name ?? "configured")}` : ""}</p> : null}
    </Panel>

    {/* 2 composer */}
    <Panel title="2 / Message composer" meta={<Status tone="info">POST /api/stego/message</Status>}>
      <div className="comm-heading"><div><strong>{(dir === "D1_D2" ? d1 : d2) || (dir === "D1_D2" ? "D1" : "D2")}</strong><span>SENDER</span></div><ArrowRight /><div><strong>{(dir === "D1_D2" ? d2 : d1) || (dir === "D1_D2" ? "D2" : "D1")}</strong><span>RECEIVER</span></div></div>
      <div className="form-grid stego-grid-4">
        <Field label="Direction"><select className={selectClass} value={dir} onChange={(ev) => setDir(ev.target.value as keyof typeof DIRS)} aria-label="Direction"><option value="D1_D2">{DIRS.D1_D2}</option><option value="D2_D1">{DIRS.D2_D1}</option></select></Field>
        <Field label="Cover source"><select className={selectClass} value={coverSrc} onChange={(ev) => setCoverSrc(ev.target.value as typeof coverSrc)} aria-label="Cover source">
          <option value="webcam">Webcam with procedural fallback (default)</option><option value="procedural">Procedural (force generator)</option>
          <option value="test_cover" disabled={!reuseCoverId}>Reuse cover of last result{reuseCoverId ? "" : " (send once first)"}</option>
          <option disabled>Upload test cover — not available</option>
        </select></Field>
        <Field label="Algorithm"><select className={selectClass} value={algo} onChange={(ev) => setAlgo(ev.target.value)} aria-label="Algorithm">
          <option value="auto">Automatic (deterministic policy)</option>
          <optgroup label="Manual override (controlled experiment)">{ALGORITHMS.map((a) => <option key={a} value={a}>{a}</option>)}</optgroup>
        </select></Field>
        <Field label="Priority class"><select className={selectClass} value={priority} onChange={(ev) => setPriority(ev.target.value as StegoPriority)} aria-label="Priority class"><option value="urgent">urgent</option><option value="normal">normal</option><option value="background">background</option></select></Field>
      </div>
      {algo !== "auto" ? <Notice tone="warning" title="Controlled experiment: manual algorithm override"><FlaskConical className="stego-inline-icon" aria-hidden="true" /> The deterministic policy is bypassed for <code>{algo}</code>. Safety limits still apply: an ineligible algorithm is rejected with ALGORITHM_NOT_ELIGIBLE.</Notice> : null}
      <p className="stego-muted">Uploading your own test cover is not available: the core API has no cover-upload endpoint, so this page does not fake it. A cover from a previous result can be reused instead.</p>
      <Field label="Message payload"><Textarea value={message} onChange={(ev) => setMessage(ev.target.value)} rows={3} aria-label="Message payload" /></Field>
      <div className="button-row">
        <Button disabled={!!busy || needsPair || !message || (sessionSel !== "auto" && !effective)} onClick={() => void send()}><Send /><BusyLabel busy={busy === "send"} idle="Send as image" busyText="Embedding, saving, verifying" /></Button>
        <Button variant="outline" disabled={!!busy || !backendUp} onClick={() => void analyze()}><Play /><BusyLabel busy={busy === "analyze"} idle="Preview selection (analyze only)" busyText="Analyzing" /></Button>
        {needsPair ? <span className="stego-muted">Choose two different drones above.</span> : null}
      </div>
    </Panel>

    {/* errors / notices */}
    {failure && errView ? (
      <div data-testid="error-notice"><Notice tone={errView.tone} title={`${errView.title} (${failure.error.code})`}>{errView.text}{failure.error.stage ? ` Failed at stage: ${failure.error.stage}.` : ""}{errView.title === "Operation failed" || !TABLE_HAS(failure.error.code) ? ` Code: ${failure.error.code}. Message: ${failure.error.message}` : ""}</Notice></div>
    ) : null}
    {fallbackReason ? <Notice tone="info" title={`Webcam not used (${fallbackReason})`}>{CAMERA_REASONS[fallbackReason] ? `${CAMERA_REASONS[fallbackReason]}. ` : ""}A procedural cover was used instead.</Notice> : null}

    {/* 3 result */}
    <Panel title="3 / Result" meta={result ? <Status tone="success">DELIVERED · EVENT {String(result.event_id ?? "n/a")}</Status> : failure ? <Status tone="danger">FAILED</Status> : <Status tone="neutral">NO TRANSACTION YET</Status>}>
      {!result && !failure ? <Empty title="No result yet" description="Send a message to see cover, stego image, capacity and quality metrics." /> : null}
      {(result || failure) ? (
        <div className="stego-result-grid">
          <Preview id={result?.cover?.artifact_id ?? art?.id} kind="cover" label="Cover image" />
          <Preview id={art?.id} kind="stego" label="Stego PNG" />
          {result ? (
            <div className="stego-result-data">
              <div className="output-block output-primary" data-testid="delivered"><span>DELIVERED TO RECEIVER ({result.to_role ?? "receiver"}) AFTER EXTRACTION + AEAD OPEN</span><pre>{result.delivered_message ?? "n/a"}</pre></div>
              <KV rows={[
                ["DIRECTION", (result.direction === 1 ? "D1 → D2" : result.direction === 2 ? "D2 → D1" : result.direction) ?? "n/a"], ["SEQ", fmtNum(result.seq)], ["SESSION", <TechnicalId key="s">{result.session_id}</TechnicalId>],
                ["ALGORITHM", e?.algorithm ?? result.selection?.selected ?? "n/a"], ["IMAGE", `${dims} · ${art?.mode ?? cover?.mode ?? "n/a"} · ${art?.format ?? "PNG"}`],
                ["PNG SIZE", isNil(art?.size) ? "n/a" : `${art?.size} B`], ["CAPACITY", isNil(capBytes) ? "n/a" : `${capBytes} B`], ["FRAME SIZE", isNil(frameLen) ? "n/a" : `${frameLen} B`],
                ["MARGIN", capBytes !== null && frameLen !== null ? `${capBytes - frameLen} B` : "n/a"], ["UTILISATION", fmtPct(e?.used_fraction)],
                ["COVER SOURCE", cover?.source ?? "n/a"],
              ]} />
              <div className="stego-chips"><Flag label="frame match" v={result.verification?.frame_match} /><Flag label="header MAC" v={result.verification?.header_mac_ok} /><Flag label="algorithm consistent" v={result.verification?.algorithm_consistent} /><Flag label="AEAD" v={result.verification?.aead_ok} /></div>
            </div>
          ) : null}
        </div>
      ) : null}
      {result ? <div className="split-grid">
        <div className="output-block"><span>DISTORTION METRICS (cover vs stego)</span>
          <KV rows={[["MSE", fmtMetric(e?.metrics?.mse)], ["PSNR", fmtMetric(e?.metrics?.psnr, 2, " dB")], ["SSIM", fmtMetric(e?.metrics?.ssim, 4)], ["CHANGED SAMPLES", fmtNum(e?.metrics?.changed_samples)], ["CHANGED FRACTION", fmtPct(e?.metrics?.changed_fraction)], ["MAX |DIFF|", fmtNum(e?.metrics?.max_abs_diff)]]} />
          <p className="stego-muted">&quot;undefined&quot; means the core could not define the metric (for example PSNR of identical images); nothing is substituted.</p>
        </div>
        <div className="output-block"><span>ALGORITHM PARAMETERS</span>
          <KV rows={[["ALG ID", fmtNum(e?.alg_id)], ["PARAM", isNil(e?.param) ? "n/a" : JSON.stringify(e?.param)], ...Object.entries(e?.params ?? {}).map(([k, v]): [string, ReactNode] => [k.toUpperCase(), JSON.stringify(v)])]} />
        </div>
        <div className="output-block span-full-grid"><span>PER-STAGE TIMINGS</span>
          <div className="stego-timings">{Object.entries(result.timings_ms ?? {}).map(([k, v]) => <div key={k}><b>{k}</b><Bar value={num(v)} max={Math.max(1, ...Object.entries(result.timings_ms ?? {}).filter(([kk]) => kk !== "total").map(([, vv]) => num(vv) ?? 0))} /><i>{fmtMs(v)}</i></div>)}</div>
        </div>
      </div> : null}
    </Panel>

    {/* 4 timeline */}
    <Panel title="4 / Transaction timeline" meta={failure ? <Status tone="danger">FAILED AT {(failure.error.stage ?? "unknown").toUpperCase()} {"·"} {failure.error.code}</Status> : result ? <Status tone="success">ALL STAGES OK</Status> : undefined}>
      {stagesShown.length || failure ? <Timeline stages={stagesShown} error={failure?.error} /> : <Empty title="No timeline" description="Stages appear after the first transaction." />}
    </Panel>

    {/* 5 candidates */}
    <Panel title="5 / Algorithm candidates" meta={selView ? <Status tone="neutral">{selView.origin === "analyze" ? "ANALYZE ONLY (NO IMAGE SAVED)" : selView.origin === "failure" ? "FROM FAILED TRANSACTION" : "SELECTED FOR THIS TRANSACTION"}</Status> : undefined}>
      {selView && (selView.sel.candidates?.length ?? 0) > 0 ? <Candidates selection={selView.sel} /> : <Empty title="No candidate table" description="Send a message or use Preview selection to see how each algorithm scored." />}
    </Panel>

    {/* 6 RAG */}
    <Panel title="6 / Explanation (simulated RAG)">
      {explanation ? <ExplanationPanel ex={explanation} /> : <Empty title="No explanation" description={failure ? "Explanations are produced only for completed selections." : "Appears after a successful transaction."} />}
    </Panel>

    {/* 7 events */}
    <Panel title="7 / Event history" meta={<span className="panel-count">{events && events.ok ? `${events.data.events.length} events` : ""}</span>}>
      <div className="stego-filters">
        <Field label="Session"><Input list="stego-sessions" value={filters.session_id} placeholder="any" onChange={(ev) => setFilters({ ...filters, session_id: ev.target.value })} aria-label="Filter session" /></Field>
        <datalist id="stego-sessions">{sessions.map((s) => <option key={s.id} value={s.id} />)}</datalist>
        <Field label="Direction"><select className={selectClass} value={filters.direction} onChange={(ev) => setFilters({ ...filters, direction: ev.target.value })} aria-label="Filter direction"><option value="">any</option><option value="D1_to_D2">D1 → D2</option><option value="D2_to_D1">D2 → D1</option></select></Field>
        <Field label="Algorithm"><select className={selectClass} value={filters.algorithm} onChange={(ev) => setFilters({ ...filters, algorithm: ev.target.value })} aria-label="Filter algorithm"><option value="">any</option>{ALGORITHMS.map((a) => <option key={a}>{a}</option>)}</select></Field>
        <Field label="Outcome"><select className={selectClass} value={filters.outcome} onChange={(ev) => setFilters({ ...filters, outcome: ev.target.value })} aria-label="Filter outcome"><option value="">any</option><option value="ok">ok</option><option value="failed">failed</option></select></Field>
        <Field label="Time range"><select className={selectClass} value={filters.range} onChange={(ev) => setFilters({ ...filters, range: ev.target.value })} aria-label="Filter time range"><option value="all">all time</option><option value="15m">last 15 min</option><option value="1h">last hour</option><option value="24h">last 24 h</option></select></Field>
        <Button variant="outline" onClick={() => void loadEvents(filters)}>Apply filters</Button>
      </div>
      {events && !events.ok ? <Notice tone="danger" title={`${events.error.code}`}>{describeStegoError(events.error.code, events.error.message).text}</Notice> : null}
      {events && events.ok && events.data.events.length === 0 ? <Empty title="No events match" description="Adjust the filters or send a message." /> : null}
      {events && events.ok && events.data.events.length > 0 ? (
        <DataTable label="Steganography events">
          <thead><tr><th>Time</th><th>Session</th><th>Dir</th><th>Seq</th><th>Algorithm</th><th>Outcome</th><th>Cover</th><th>Image</th><th>PSNR</th><th>Error</th></tr></thead>
          <tbody>{events.data.events.map((ev, i) => {
            const ok = ev.outcome ? ev.outcome === "ok" : ev.success;
            return <tr key={`${ev.event_id ?? i}`} className="stego-row" onClick={() => setSelectedEvent(ev)} data-testid="event-row" tabIndex={0} onKeyDown={(k) => { if (k.key === "Enter") setSelectedEvent(ev); }}>
              <td>{fmtTime(ev.ts_ms)}</td><td><TechnicalId>{ev.session_id}</TechnicalId></td><td>{ev.direction_label ?? ev.direction ?? "n/a"}</td><td>{fmtNum(ev.seq)}</td><td>{ev.algorithm ?? "—"}</td>
              <td><Status tone={ok ? "success" : "danger"}>{ok ? "OK" : "FAILED"}</Status></td><td>{ev.cover_source ?? "n/a"}{ev.cover_fallback_reason ? <small>{ev.cover_fallback_reason}</small> : null}</td>
              <td>{isNil(ev.width) ? "n/a" : `${ev.width}×${ev.height}`}</td><td>{fmtMetric(ev.psnr, 1)}</td><td>{ev.error_code ?? "—"}{ev.error_stage ? <small>{ev.error_stage}</small> : null}</td></tr>;
          })}</tbody>
        </DataTable>
      ) : null}
      {selectedEvent ? <div className="output-block" data-testid="event-detail"><span>EVENT DETAIL {String(selectedEvent.event_id ?? "")} <button className="stego-link" onClick={() => setSelectedEvent(null)}>close</button></span>
        <KV rows={[["KIND", selectedEvent.kind ?? "n/a"], ["SELECTION", `${selectedEvent.selection_mode ?? "n/a"} / ${selectedEvent.selection_reason_code ?? "n/a"} / ${selectedEvent.selection_policy_version ?? "n/a"}`], ["CAPACITY / FRAME / IMAGE", `${fmtNum(selectedEvent.capacity_bytes)} / ${fmtNum(selectedEvent.frame_bytes)} / ${fmtNum(selectedEvent.image_bytes)} B`], ["MSE / PSNR / SSIM", `${fmtMetric(selectedEvent.mse)} / ${fmtMetric(selectedEvent.psnr, 2)} / ${fmtMetric(selectedEvent.ssim, 4)}`], ["EXPLANATION", selectedEvent.explanation_status ?? "n/a"], ["ERROR", selectedEvent.error_code ? `${selectedEvent.error_code} at ${selectedEvent.error_stage ?? "?"}: ${selectedEvent.error_message ?? ""}` : "none"]]} />
        <pre>{JSON.stringify(selectedEvent, null, 2)}</pre></div> : null}
    </Panel>

    {/* 8 report */}
    <Panel title="8 / Report and benchmark" meta={<div className="button-row"><Button size="sm" variant="outline" onClick={() => void loadReport()}><RefreshCw />Reload</Button><Button size="sm" variant="outline" onClick={() => { setDlError(null); downloadStegoReport("json").catch((x: unknown) => setDlError(String(x))); }}><Download />JSON</Button><Button size="sm" variant="outline" onClick={() => { setDlError(null); downloadStegoReport("csv").catch((x: unknown) => setDlError(String(x))); }}><Download />CSV</Button></div>}>
      {dlError ? <Notice tone="danger" title="Download failed">{dlError}</Notice> : null}
      {report && !report.ok ? <Notice tone="danger" title={report.error.code}>{describeStegoError(report.error.code, report.error.message).text}</Notice> : null}
      {rep ? <>
        <div className="metrics-grid">
          <Metric label="TOTAL EVENTS" value={rep.totals?.events ?? "n/a"} detail={rep.schema} />
          <Metric label="SUCCESS" value={rep.totals?.ok ?? "n/a"} detail="completed transactions" tone="success" />
          <Metric label="FAILURE" value={rep.totals?.failed ?? "n/a"} detail="persisted failure events" tone={rep.totals?.failed ? "danger" : "neutral"} />
          <Metric label="FALLBACK COVERS" value={rep.totals?.fallback_cover_count ?? "n/a"} detail="procedural instead of webcam" tone="info" />
        </div>
        {rep.totals?.error_counts && Object.keys(rep.totals.error_counts).length ? <div className="stego-chips">{Object.entries(rep.totals.error_counts).map(([c, n]) => <Status key={c} tone="danger">{c}: {n}</Status>)}</div> : null}
        <div className="button-row"><Field label="Timing stage for p50 / p95"><select className={selectClass} value={timingStage} onChange={(ev) => setTimingStage(ev.target.value)} aria-label="Timing stage">{(timingKeys.length ? timingKeys : ["total"]).map((k) => <option key={k}>{k}</option>)}</select></Field></div>
        {(rep.per_algorithm ?? []).length === 0 ? <Empty title="No per-algorithm data" description="Send messages or run the benchmark first." /> :
          <DataTable label="Per-algorithm report">
            <thead><tr><th>Algorithm</th><th>Trials (ok / failed)</th><th>Capacity (mean)</th><th>Frame (mean)</th><th>MSE (mean, n)</th><th>PSNR (mean, n)</th><th>SSIM (mean, n)</th><th>{timingStage} p50 / p95</th><th>Capacity vs PSNR</th></tr></thead>
            <tbody>{(rep.per_algorithm ?? []).map((a) => {
              const t = a.timings_ms?.[timingStage];
              return <tr key={a.algorithm}><td><strong>{a.algorithm}</strong></td><td>{a.n_ok} / {a.n_failed}</td><td>{fmtNum(a.capacity_bytes?.mean, 0, " B")}</td><td>{fmtNum(a.frame_bytes?.mean, 1, " B")}</td>
                <td>{fmtMetric(a.mse?.mean ?? null)} (n={a.mse?.n ?? 0})</td><td>{fmtMetric(a.psnr?.mean ?? null, 2, " dB")} (n={a.psnr?.n ?? 0})</td><td>{fmtMetric(a.ssim?.mean ?? null, 4)} (n={a.ssim?.n ?? 0})</td>
                <td>{t && t.p50 != null && t.p95 != null ? `${fmtMs(t.p50)} / ${fmtMs(t.p95)}` : <span title="Percentiles need at least 20 samples">n&lt;20: percentiles unavailable</span>}</td>
                <td><div className="stego-dual"><Bar value={a.capacity_bytes?.mean ?? null} max={maxCap} /><Bar value={a.psnr?.mean ?? null} max={maxPsnr} tone="success" /></div></td></tr>;
            })}</tbody>
          </DataTable>}
        <p className="stego-muted">Bars: top = mean capacity, bottom = mean PSNR (higher is better), each scaled to the maximum across algorithms.</p>
        {rep.limitations?.length ? <details className="stego-details"><summary>Report limitations ({rep.limitations.length})</summary><ul className="stego-list">{rep.limitations.map((l) => <li key={l}>{l}</li>)}</ul></details> : null}
      </> : null}
      <h3 className="stego-h3">Run benchmark</h3>
      <p className="stego-muted">Runs real sealed messages through the full pipeline on a ready session. {benchSession ? <>Session <code>{short(benchSession.id, 12)}</code>.</> : <strong>No ready session (M1–M8 and K1–K3 complete) found.</strong>}</p>
      <div className="form-grid stego-grid-4">
        <Field label="Iterations (max 50)"><Input type="number" min={1} max={50} value={iters} onChange={(ev) => setIters(Math.max(1, Math.min(50, parseInt(ev.target.value, 10) || 1)))} aria-label="Iterations" /></Field>
        <Field label="Frame sizes (bytes, comma separated)"><Input value={sizes} onChange={(ev) => setSizes(ev.target.value)} aria-label="Frame sizes" /></Field>
        <div /><Button disabled={!!busy || !benchSession || !backendUp} onClick={() => void runBench()}><Play /><BusyLabel busy={busy === "bench"} idle="Run benchmark" busyText="Running" /></Button>
      </div>
      {bench && !bench.ok ? <Notice tone={describeStegoError(bench.error.code).tone} title={`${describeStegoError(bench.error.code).title} (${bench.error.code})`}>{describeStegoError(bench.error.code, bench.error.message).text}</Notice> : null}
      {bench && bench.ok ? <div className="output-block output-primary" data-testid="bench-summary"><span>BENCHMARK SUMMARY ({bench.data.runs?.length ?? 0} runs)</span>{renderEvidence(bench.data.summary)}</div> : null}
    </Panel>

    {/* what this protects */}
    <Panel title="What this does and does not protect">
      <ul className="stego-list" data-testid="protect-note">
        <li><strong>Confidentiality and authenticity</strong> come from the ML-KEM-derived AEAD keys and the frame MAC, enforced in the Rust core. Keys never reach this page.</li>
        <li><strong>The image is an obscurity layer on top of AEAD</strong>, not extra cryptographic strength: the embedded frame is already high-entropy ciphertext.</li>
        <li>Transport is a <strong>lossless PNG handoff only</strong> (saved file, then read back). JPEG, resizing or filtering destroys the message; none of the five methods is claimed robust.</li>
        <li><strong>LSB-class methods are fragile and statistically detectable</strong>; no anti-steganalysis claim is made.</li>
        <li>The RAG panel is <strong>mock retrieval and template text</strong>; it explains a choice already made by the deterministic policy.</li>
        <li>The decrypted message is shown only as the receiver&apos;s delivered result of this transaction; it is not stored in events or reports.</li>
      </ul>
    </Panel>
  </>;
}

function TABLE_HAS(code: string): boolean {
  return describeStegoError(code).title !== "Operation failed";
}
function ReadyItem({ label, ok, detail }: { label: string; ok: boolean | null; detail: string }) {
  return <div className="stego-ready"><Status tone={ok === null ? "neutral" : ok ? "success" : "danger"}>{ok === null ? "UNKNOWN" : ok ? "READY" : "NOT READY"}</Status><strong>{label}</strong><small>{detail}</small></div>;
}
