// Patch-wise Stego Lab (operational flow). The core seals the message, the image service generates a
// fresh payload-aware cover, segments it and selects one algorithm per patch from the static knowledge base, the core authenticates
// the manifest + payload, and the saved PNG is re-read and verified. This page only renders results.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Play, RefreshCw, Send, Download } from "lucide-react";
import { api } from "@/lib/api";
import {
  stegoApi,
  downloadStegoReport,
  downloadBlob,
  toCsv,
  type StegoResult,
} from "@/lib/stego-api";
import { describeStegoError } from "@/lib/stego-errors";
import { usePolling } from "@/hooks/use-polling";
import {
  CandidateTable,
  EMPTY_COVER_FORM,
  GeneratedCoverConfig,
  GenerationDiagnostics,
  coverFormProblems,
  coverGenerationRequest,
  type CoverGenForm,
} from "./stego-generation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  BusyLabel,
  DataTable,
  Disclosure,
  Empty,
  Field,
  KeyValues,
  Metric,
  Panel,
  Status,
  TechnicalId,
  selectClass,
} from "./core";
import {
  ALGORITHMS,
  Bar,
  Flag,
  KV,
  Notice,
  Preview,
  fmtMetric,
  fmtMs,
  fmtNum,
  fmtPct,
  fmtTime,
  isNil,
  num,
  short,
} from "./stego-shared";
import { PatchInspector, PatchOverlay, PatchTable, type PatchContext } from "./stego-patches";
import type { ProtocolEvent } from "@/lib/api";
import type {
  GenerationInfo,
  PlanAttempt,
  StegoBenchmarkResult,
  StegoErrorBody,
  StegoEvent,
  StegoMessageResult,
  StegoPlanPreview,
  StegoReport,
  StegoStage,
} from "@/types/api";

/* ------------------------------------------------------------------ stages */
const CANON: { key: string; label: string }[] = [
  { key: "aead_seal", label: "Message sealed (core)" },
  {
    key: "plan",
    label:
      "Cover generated, segmented, one permitted algorithm per patch, manifest validated, frame v3 MAC and encrypted carrier built (core)",
  },
  { key: "embed", label: "Patches and carrier embedded, saved PNG re-read and verified" },
  { key: "save", label: "Saved file confirmed by the core" },
  { key: "read", label: "Receiver reads the saved PNG" },
  {
    key: "extract",
    label:
      "Carrier located by sync word, manifest decrypted and validated, patches extracted (no re-segmentation)",
  },
  { key: "verify_frame", label: "Frame MAC over manifest and payload, sequence check (core)" },
  { key: "aead_open", label: "Channel, direction, replay, decryption (core)" },
];
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
      if (CANON.some((c) => c.key === s.name) && !byKey.has(s.name)) byKey.set(s.name, s);
      else extra.push(s);
    }
    const list: { label: string; stage: StegoStage | null }[] = CANON.map((c) => ({
      label: c.label,
      stage: byKey.get(c.key) ?? null,
    }));
    for (const s of extra) list.push({ label: s.name, stage: s });
    return list;
  }, [stages]);
  return (
    <ol className="stego-timeline" aria-label="Transaction stages">
      {rows.map(({ label, stage }, i) => {
        const st = stage ? normStatus(stage.status) : "none";
        const isFail = !!stage && st === "failed";
        const cls = isFail ? "failed" : st === "none" ? "none" : st;
        return (
          <li
            key={`${label}-${i}`}
            className={`stego-stage stego-stage-${cls}`}
            data-testid={`stage-${cls}`}
          >
            <span className="stego-stage-n">{i + 1}</span>
            <div>
              <strong>
                {label}
                {stage ? <small> ({stage.name})</small> : null}
              </strong>
              {stage?.detail && !isFail ? <p>{stage.detail}</p> : null}
              {isFail && error ? (
                <p className="stego-stage-code">
                  <code>{error.code}</code> {error.message}
                </p>
              ) : null}
            </div>
            <span className="stego-stage-ms">{stage ? fmtMs(stage.ms) : ""}</span>
            <Status
              tone={
                isFail
                  ? "danger"
                  : st === "ok"
                    ? "success"
                    : st === "none" || st === "skipped"
                      ? "neutral"
                      : "info"
              }
            >
              {isFail
                ? "Failed"
                : st === "none"
                  ? "Not reached"
                  : st === "other" && stage
                    ? stage.status
                    : st === "ok"
                      ? "Done"
                      : "Skipped"}
            </Status>
          </li>
        );
      })}
    </ol>
  );
}

function Attempts({ attempts }: { attempts: PlanAttempt[] }) {
  return (
    <DataTable label="Segmentation refinement attempts">
      <thead>
        <tr>
          <th>Level</th>
          <th>Patches</th>
          <th>Usable patches</th>
          <th>Capacity</th>
          <th>Manifest</th>
          <th>Carrier pixels</th>
          <th>Outcome</th>
        </tr>
      </thead>
      <tbody>
        {attempts.map((a, i) => (
          <tr key={i}>
            <td>{a.level}</td>
            <td>{fmtNum(a.regions)}</td>
            <td>{fmtNum(a.usable_patches)}</td>
            <td>{isNil(a.capacity_bytes) ? "n/a" : `${a.capacity_bytes} B`}</td>
            <td>{isNil(a.manifest_bytes) ? "n/a" : `${a.manifest_bytes} B`}</td>
            <td>{fmtNum(a.carrier_pixels)}</td>
            <td>
              <Status tone={a.outcome === "OK" ? "success" : "warning"}>
                {a.outcome ?? "n/a"}
              </Status>
              {!isNil(a.failed_patch) ? <small> patch #{a.failed_patch}</small> : null}
            </td>
          </tr>
        ))}
      </tbody>
    </DataTable>
  );
}

/* ------------------------------------------------------------------ main page */
type Outcome =
  | { ok: true; data: StegoMessageResult }
  | { ok: false; error: StegoErrorBody; stages: StegoStage[] };
const DIRS = { D1_D2: "D1 → D2", D2_D1: "D2 → D1" } as const;
const TIME_RANGES: Record<string, number> = {
  all: 0,
  "15m": 15 * 60e3,
  "1h": 3600e3,
  "24h": 24 * 3600e3,
};
const PATCH_COLUMNS = [
  "patch_id",
  "used",
  "pixels",
  "usable_pixels",
  "gradient_mean",
  "variance",
  "entropy",
  "edge_density",
  "selected",
  "alg_id",
  "param",
  "kb_entry",
  "bm25",
  "query_terms",
  "ranking",
  "payload_offset",
  "payload_length",
  "measured_capacity_bytes",
  "embed_status",
  "extract_status",
];

export function SteganographyLabPage() {
  const dronesFetcher = useCallback(() => api.getDrones(), []);
  const histFetcher = useCallback(() => api.getEventsHistory(1000), []);
  const statusFetcher = useCallback(async () => stegoApi.status(), []);
  const { data: droneData, error: droneErr } = usePolling(dronesFetcher, 4000);
  const { data: hist, refresh: refreshHist } = usePolling(histFetcher, 4000);
  const { data: statusRes, refresh: refreshStatus } = usePolling(statusFetcher, 5000);

  const [d1, setD1] = useState(""),
    [d2, setD2] = useState("");
  const [sessionSel, setSessionSel] = useState("auto");
  const [dir, setDir] = useState<keyof typeof DIRS>("D1_D2");
  const [coverForm, setCoverForm] = useState<CoverGenForm>(EMPTY_COVER_FORM);
  const [message, setMessage] = useState("Perimeter clear, proceeding to waypoint 2.");
  const [busy, setBusy] = useState<"" | "send" | "plan" | "bench">("");
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [preview, setPreview] = useState<StegoPlanPreview | null>(null);
  const [selPatch, setSelPatch] = useState<number | null>(null);

  /* ---- readiness (derived from the existing protocol event history) */
  const sessions = useMemo(() => {
    const m = new Map<
      string,
      { id: string; ts: number; stages: Set<string>; fails: Set<string> }
    >();
    for (const e of (hist?.events ?? []) as ProtocolEvent[]) {
      let s = m.get(e.session_id);
      if (!s) {
        s = { id: e.session_id, ts: 0, stages: new Set(), fails: new Set() };
        m.set(e.session_id, s);
      }
      s.ts = Math.max(s.ts, e.timestamp_unix_ms);
      if (e.status === "Ok") s.stages.add(e.stage);
      if (e.status === "Fail") s.fails.add(e.stage);
    }
    return [...m.values()]
      .filter((s) => s.stages.size || s.fails.size)
      .sort((a, b) => b.ts - a.ts)
      .map((s) => ({
        id: s.id,
        ts: s.ts,
        authOk: s.stages.has("M8") && ![...s.fails].some((f) => f.startsWith("M")),
        keyOk: s.stages.has("K3") && ![...s.fails].some((f) => f.startsWith("K")),
      }));
  }, [hist]);
  const authSessions = sessions.filter((s) => s.id && (s.authOk || s.keyOk));
  const effective =
    sessionSel === "auto"
      ? (sessions[0] ?? null)
      : (sessions.find((s) => s.id === sessionSel) ?? null);
  const benchSession =
    sessionSel === "auto" ? (sessions.find((s) => s.authOk && s.keyOk) ?? null) : effective;

  const drones = droneData?.drones ?? [];
  const dA = drones.find((d) => d.drone_id === d1),
    dB = drones.find((d) => d.drone_id === d2);
  const dronesOk =
    !!dA &&
    !!dB &&
    dA.registered &&
    dB.registered &&
    dA.active &&
    dB.active &&
    !!dA.group_id &&
    dA.group_id === dB.group_id;

  const st = statusRes && statusRes.ok ? statusRes.data : null;
  const backendUp = !!st?.backend.reachable;
  const genView = st?.config?.cover_generation;
  const genHealth = st?.backend.health?.cover_generator;
  const coverProblems = coverFormProblems(coverForm, genView?.effective);

  const needsPair = !d1 || !d2 || d1 === d2;
  const fromId = dir === "D1_D2" ? d1 : d2;

  /** Only tightening settings; never a seed, file, source or stored cover. */
  const coverGen = () => coverGenerationRequest(coverForm, genView?.effective);

  /* ---- events + report */
  const [filters, setFilters] = useState({
    session_id: "",
    direction: "",
    algorithm: "",
    outcome: "",
    range: "all",
  });
  const [events, setEvents] = useState<StegoResult<{ events: StegoEvent[] }> | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<StegoEvent | null>(null);
  const [report, setReport] = useState<StegoResult<StegoReport> | null>(null);
  const [dlError, setDlError] = useState<string | null>(null);

  const loadEvents = useCallback(
    async (f = filters) => {
      const range = TIME_RANGES[f.range] ?? 0;
      setEvents(
        await stegoApi.events({
          session_id: f.session_id,
          direction: f.direction,
          algorithm: f.algorithm,
          outcome: f.outcome,
          ...(range ? { since_ms: Date.now() - range } : {}),
          limit: 200,
        }),
      );
    },
    [filters],
  );
  const loadReport = useCallback(async () => setReport(await stegoApi.report()), []);
  useEffect(() => {
    void loadEvents();
    void loadReport(); /* initial load only */ // eslint-disable-line react-hooks/exhaustive-deps
  }, []);

  /* ---- actions */
  async function send() {
    setBusy("send");
    setOutcome(null);
    setPreview(null);
    setSelPatch(null);
    const base = { from_id: fromId, plaintext: message, cover_generation: coverGen() };
    const r = await stegoApi.message(
      sessionSel === "auto"
        ? { ...base, d1_id: d1, d2_id: d2 }
        : { ...base, session_id: sessionSel },
    );
    if (r.ok) {
      setOutcome({ ok: true, data: r.data });
      const first = r.data.plan?.patches?.find((p) => p.used);
      setSelPatch(first ? first.patch_id : null);
    } else {
      setOutcome({ ok: false, error: r.error, stages: r.stages ?? [] });
    }
    setBusy("");
    void refreshHist();
    void refreshStatus();
    void loadEvents();
    void loadReport();
  }
  async function planOnly() {
    setBusy("plan");
    setOutcome(null);
    setPreview(null);
    setSelPatch(null);
    // The core decides the real size when it seals: AppWire = 28-byte header + plaintext + 16-byte AEAD tag, plus the 32-byte frame tag.
    const payload_bytes = new TextEncoder().encode(message).length + 28 + 16 + 32;
    const r = await stegoApi.plan({ payload_bytes, cover_generation: coverGen() });
    if (r.ok) {
      setPreview(r.data);
      const first = r.data.plan?.patches?.find((p) => p.used);
      setSelPatch(first ? first.patch_id : null);
    } else setOutcome({ ok: false, error: r.error, stages: r.stages ?? [] });
    setBusy("");
  }

  /* ---- benchmark */
  const [iters, setIters] = useState(5),
    [sizes, setSizes] = useState("64,256,1024");
  const [bench, setBench] = useState<StegoResult<StegoBenchmarkResult> | null>(null);
  async function runBench() {
    if (!benchSession) return;
    setBusy("bench");
    const frame_sizes = sizes
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isFinite(n) && n > 0);
    setBench(
      await stegoApi.benchmark({
        session_id: benchSession.id,
        iterations: Math.max(1, Math.min(50, iters || 1)),
        ...(frame_sizes.length ? { frame_sizes } : {}),
        cover_generation: coverGen(),
      }),
    );
    setBusy("");
    void loadReport();
    void loadEvents();
    void refreshStatus();
  }

  const result = outcome?.ok ? outcome.data : null;
  const failure = outcome && !outcome.ok ? outcome : null;
  const stagesShown = result?.stages ?? failure?.stages ?? [];
  const plan = result?.plan ?? preview?.plan ?? null;
  const cover = result?.cover ?? preview?.cover;
  const inspection = result?.inspection ?? preview?.inspection;
  const generation = result?.generation ?? preview?.generation ?? null;
  const rep = report && report.ok ? report.data : null;
  const errView = failure ? describeStegoError(failure.error.code, failure.error.message) : null;
  const failAttempts = (failure?.error.details as { attempts?: PlanAttempt[] } | null | undefined)
    ?.attempts;
  // generation failures carry the candidate table (scores, gates, rejection reasons, budget) in `details`
  const failGen =
    failure?.error.details && Array.isArray((failure.error.details as GenerationInfo).candidates)
      ? (failure.error.details as GenerationInfo)
      : null;
  const e = result?.embed;
  const art = result?.artifact;
  const tr = result?.transport;
  const ctx: PatchContext | null = plan
    ? {
        plan,
        coverId: cover?.artifact_id,
        width: cover?.width,
        height: cover?.height,
        palette: inspection?.palette,
        embed: e?.patches,
        extraction: result?.extraction,
      }
    : null;
  const patch = plan?.patches?.find((p) => p.patch_id === selPatch) ?? null;
  const usedAlgs = Object.entries(plan?.algorithms_used ?? {});
  const extractedOk = (result?.extraction ?? []).filter((x) => x.status === "extracted").length;

  function exportRun(kind: "json" | "csv") {
    if (!plan) return;
    const stamp = result?.event_id !== undefined ? `event-${result.event_id}` : "plan-preview";
    if (kind === "json") {
      // exactly what the backend returned for this run (the delivered plaintext is deliberately left out of the export)
      const { delivered_message: _omit, ...rest } = (result ?? {}) as Record<string, unknown>;
      void _omit;
      downloadBlob(
        new Blob([JSON.stringify(result ? rest : preview, null, 2)], { type: "application/json" }),
        `stego-run-${stamp}.json`,
      );
      return;
    }
    const emb = new Map((e?.patches ?? []).map((x) => [x.patch_id, x]));
    const ext = new Map((result?.extraction ?? []).map((x) => [x.patch_id, x]));
    const rows = (plan.patches ?? []).map((p) => {
      const top = p.retrieval?.candidates.find((c) => c.algorithm === p.selected);
      return {
        patch_id: p.patch_id,
        used: p.used,
        pixels: p.features.pixels,
        usable_pixels: p.features.usable_pixels,
        gradient_mean: p.features.gradient_mean,
        variance: p.features.variance,
        entropy: p.features.entropy,
        edge_density: p.features.edge_density,
        selected: p.selected ?? "",
        alg_id: p.alg_id ?? "",
        param: p.param ?? "",
        kb_entry: top?.kb_entry ?? "",
        bm25: top?.bm25 ?? "",
        query_terms: p.retrieval?.query_terms ?? [],
        ranking: p.retrieval?.ranking ?? [],
        payload_offset: p.payload_offset ?? "",
        payload_length: p.payload_length ?? 0,
        measured_capacity_bytes: p.measured_capacity_bytes ?? "",
        embed_status: emb.get(p.patch_id)?.extraction ?? "",
        extract_status: ext.get(p.patch_id)?.status ?? "",
      };
    });
    downloadBlob(
      new Blob([toCsv(PATCH_COLUMNS, rows)], { type: "text/csv" }),
      `stego-patches-${stamp}.csv`,
    );
  }

  return (
    <>
      {/* 1 readiness */}
      <Panel
        title="Session"
        meta={
          <Status
            tone={
              backendUp && dronesOk && effective?.authOk && effective?.keyOk ? "success" : "warning"
            }
          >
            {backendUp && dronesOk && effective?.authOk && effective?.keyOk
              ? "Ready"
              : "Check prerequisites"}
          </Status>
        }
      >
        {droneErr ? (
          <Notice tone="danger" title="Core state unavailable">
            {droneErr}
          </Notice>
        ) : null}
        <div className="form-grid stego-grid-4">
          <Field label="Initiator">
            <select
              className={selectClass}
              value={d1}
              onChange={(ev) => setD1(ev.target.value)}
              aria-label="Initiator"
            >
              <option value="">Select drone</option>
              {drones.map((d) => (
                <option key={d.drone_id}>{d.drone_id}</option>
              ))}
            </select>
          </Field>
          <Field label="Verifier">
            <select
              className={selectClass}
              value={d2}
              onChange={(ev) => setD2(ev.target.value)}
              aria-label="Verifier"
            >
              <option value="">Select drone</option>
              {drones.map((d) => (
                <option key={d.drone_id}>{d.drone_id}</option>
              ))}
            </select>
          </Field>
          <Field label="Session">
            <select
              className={selectClass}
              value={sessionSel}
              onChange={(ev) => setSessionSel(ev.target.value)}
              aria-label="Session"
            >
              <option value="auto">Latest session of this pair</option>
              {authSessions.map((s) => (
                <option key={s.id} value={s.id}>
                  {short(s.id, 12)} {"·"} M1–M8 {s.authOk ? "✓" : "✗"} K1–K3 {s.keyOk ? "✓" : "✗"}
                </option>
              ))}
            </select>
          </Field>
          <div className="field">
            <span>Cover</span>
            <strong>Generated per message</strong>
            <small>
              {genHealth
                ? `${genHealth.generator_version ?? "generator"} · profile ${genHealth.active_profile ?? "n/a"} · seeding ${genHealth.seeding ?? "n/a"}`
                : "generator status unknown"}
            </small>
          </div>
        </div>
        <div className="stego-ready-grid">
          <ReadyItem
            label="Authentication (M1–M8)"
            ok={effective ? effective.authOk : null}
            detail={
              effective ? `session ${short(effective.id, 12)}` : "no session found in event history"
            }
          />
          <ReadyItem
            label="Session key (K1–K3)"
            ok={effective ? effective.keyOk : null}
            detail={
              effective ? `session ${short(effective.id, 12)}` : "no session found in event history"
            }
          />
          <ReadyItem
            label="Drones active in one group"
            ok={needsPair ? null : dronesOk}
            detail={
              needsPair
                ? "choose two different drones"
                : dronesOk
                  ? `${d1}, ${d2}`
                  : "not both active members of one group"
            }
          />
          <ReadyItem
            label="Image service"
            ok={statusRes ? backendUp : null}
            detail={
              !statusRes
                ? "checking…"
                : backendUp
                  ? `v${st?.backend.health?.version ?? "?"}, artifacts writable: ${st?.backend.health?.artifact_dir_writable === false ? "NO" : "yes"}`
                  : statusRes.ok
                    ? typeof st?.backend.error === "string"
                      ? st.backend.error
                      : (st?.backend.error?.code ?? "unreachable")
                    : `${statusRes.error.code}: ${statusRes.error.message}`
            }
          />
        </div>
        {sessionSel === "auto" ? (
          <p className="stego-muted">
            Protocol events do not name the drone pair, so the readiness above reflects the newest
            session. The core answers NO_AUTH_SESSION or NO_GROUP_KEY if this pair is not ready.
          </p>
        ) : null}
        {!statusRes ? null : !backendUp ? (
          <Notice tone="danger" title="STEGO_BACKEND_UNAVAILABLE">
            {describeStegoError("STEGO_BACKEND_UNAVAILABLE").text}
          </Notice>
        ) : null}
        {backendUp && genHealth?.seeding && genHealth.seeding !== "os-random" ? (
          <Notice tone="warning" title="Test seeding is active">
            The image service was started with a fixed test seed sequence ({genHealth.seeding}).
            Covers are reproducible in this mode; do not use it operationally.
          </Notice>
        ) : null}
        <Disclosure summary="Service versions">
          {st ? (
            <p className="stego-muted">
              Stored events: {st.counts?.events ?? "n/a"} ({st.counts?.ok ?? "n/a"} ok /{" "}
              {st.counts?.failed ?? "n/a"} failed)
              {st.backend.health?.kb_version
                ? ` · knowledge base ${st.backend.health.kb_version} · selector ${st.backend.health.selector_version ?? "n/a"} · segmentation ${st.backend.health.segmentation_version ?? "n/a"}`
                : ""}
              {st.transport?.format_version ? ` · ${st.transport.format_version}` : ""}
            </p>
          ) : null}
        </Disclosure>
      </Panel>

      {/* 2 composer */}
      <Panel title="Message">
        <div className="form-grid stego-grid-4">
          <Field label="From → to">
            <select
              className={selectClass}
              value={dir}
              onChange={(ev) => setDir(ev.target.value as keyof typeof DIRS)}
              aria-label="Direction"
            >
              <option value="D1_D2">
                {d1 || "Initiator"} → {d2 || "verifier"}
              </option>
              <option value="D2_D1">
                {d2 || "Verifier"} → {d1 || "initiator"}
              </option>
            </select>
          </Field>
        </div>
        <Field label="Message payload">
          <Textarea
            value={message}
            onChange={(ev) => setMessage(ev.target.value)}
            rows={3}
            aria-label="Message payload"
          />
        </Field>
        <div className="button-row">
          <Button
            disabled={
              !!busy ||
              needsPair ||
              !message ||
              coverProblems.length > 0 ||
              (sessionSel !== "auto" && !effective)
            }
            onClick={() => void send()}
          >
            <Send />
            <BusyLabel
              busy={busy === "send"}
              idle="Send as image"
              busyText="Planning, embedding, verifying"
            />
          </Button>
          <Button
            variant="outline"
            disabled={!!busy || !backendUp || !message || coverProblems.length > 0}
            onClick={() => void planOnly()}
          >
            <Play />
            <BusyLabel
              busy={busy === "plan"}
              idle="Preview plan (nothing is sent)"
              busyText="Segmenting and selecting"
            />
          </Button>
          {needsPair ? (
            <span className="stego-muted">
              Choose two different drones above to send. A plan preview needs no session.
            </span>
          ) : null}
        </div>
        <Disclosure summary="Cover and transport settings" testId="transport-settings">
          <GeneratedCoverConfig
            view={genView}
            form={coverForm}
            onChange={setCoverForm}
            disabled={!!busy}
          />
          <KeyValues
            items={[
              [
                "Algorithm policy",
                st?.config?.algorithm_policy
                  ? `${st.config.algorithm_policy.name ?? "n/a"}: ${(st.config.algorithm_policy.allowed ?? []).join(", ")}`
                  : "n/a",
              ],
              [
                "Excluded",
                (st?.config?.algorithm_policy?.excluded ?? []).map((x) => x.algorithm).join(", ") ||
                  "none",
              ],
              [
                "Selection",
                "per patch: permitted algorithms ranked by measured risk, distortion and cost (risk table), BM25 as tie-break; no manual override",
              ],
              [
                "Bootstrap",
                st?.config?.bootstrap
                  ? `v${st.config.bootstrap.version ?? "?"} keyed carrier, sync window ${st.config.bootstrap.sync_window ?? "?"}`
                  : "n/a",
              ],
              [
                "Segmentation",
                <>
                  {st?.config?.segmentation_overrides &&
                  Object.keys(st.config.segmentation_overrides).length
                    ? Object.entries(st.config.segmentation_overrides)
                        .map(([k, v]) => `${k}=${v}`)
                        .join(", ")
                    : "service defaults"}{" "}
                  · target chunk {st?.config?.target_chunk_bytes ?? "n/a"} B · re-plans ≤{" "}
                  {st?.config?.max_replans ?? "n/a"} (set by environment)
                </>,
              ],
            ]}
          />
        </Disclosure>
      </Panel>

      {/* errors / notices */}
      {failure && errView ? (
        <div data-testid="error-notice">
          <Notice tone={errView.tone} title={`${errView.title} (${failure.error.code})`}>
            {errView.text}
            {failure.error.stage ? ` Failed at stage: ${failure.error.stage}.` : ""}
            {errView.title === "Operation failed" ? ` Message: ${failure.error.message}` : ""}
          </Notice>
          {failGen ? (
            <div data-testid="generation-failure">
              <h3 className="stego-h3">
                Cover candidates of the failed attempt{failGen.reason ? ` (${failGen.reason})` : ""}
              </h3>
              {failGen.candidates?.length ? (
                <CandidateTable candidates={failGen.candidates} />
              ) : (
                <p className="stego-muted">
                  No candidate was generated
                  {failGen.embedding_rate?.limit_bytes_at_requested_size
                    ? `: the payload is above the embedding-rate limit of ${failGen.embedding_rate.limit_bytes_at_requested_size} bytes for the requested cover size`
                    : ""}
                  {failGen.allow_payload_driven_resize === false
                    ? " and payload-driven resize is off"
                    : ""}
                  .
                </p>
              )}
              {failGen.budget ? (
                <p className="stego-muted">
                  Budget: {fmtMs(failGen.budget.used_ms)} used of {fmtNum(failGen.budget.limit_ms)}{" "}
                  ms{failGen.budget.exceeded ? " (exceeded)" : ""}. No other cover source was tried.
                </p>
              ) : null}
            </div>
          ) : null}
          {failAttempts?.length ? <Attempts attempts={failAttempts} /> : null}
        </div>
      ) : null}
      {preview ? (
        <Notice tone="info" title="Plan preview only">
          {preview.note ?? "No message was sealed and no stego image was saved."}
        </Notice>
      ) : null}

      {/* 5 result */}
      <Panel
        title="Result"
        meta={
          result ? (
            <Status tone="success">Delivered · event {String(result.event_id ?? "n/a")}</Status>
          ) : failure ? (
            <Status tone="danger">Failed</Status>
          ) : (
            <Status tone="neutral">No transaction yet</Status>
          )
        }
      >
        {!result ? (
          <Empty
            title={failure ? "Nothing was delivered" : "No result yet"}
            description={
              failure
                ? "The transaction failed closed; no plaintext is returned and no fallback transport is used."
                : "Send a message to see the cover, the stego PNG, their difference and the verification results."
            }
          />
        ) : (
          <>
            <div className="stego-triple">
              <Preview id={cover?.artifact_id} kind="cover" label="Cover image (before)" />
              <Preview id={art?.id} kind="stego" label="Stego PNG (after, as saved)" />
              <Preview
                id={art?.id}
                kind="diff"
                label="Difference |stego − cover| × 64"
                note="Changes are confined to the used patches and the reserved carrier pixels."
              />
            </div>
            <div className="output-block output-primary" data-testid="delivered">
              <span>Delivered to the receiver after extraction, frame MAC and decryption</span>
              <pre>{result.delivered_message ?? "n/a"}</pre>
            </div>
            <div className="stego-chips">
              <Flag label="frame MAC (manifest + payload)" v={result.verification?.header_mac_ok} />
              <Flag
                label="manifest authenticated"
                v={result.verification?.manifest_authenticated}
              />
              <Flag label="recovered frame = sent frame" v={result.verification?.frame_match} />
              <Flag label="AEAD" v={result.verification?.aead_ok} />
              <Flag label="saved PNG re-read" v={e?.exact_frame_recovery_from_saved_png} />
              <Status tone={result.verification?.resegmented === false ? "success" : "danger"}>
                receiver re-segmented: {result.verification?.resegmented === false ? "no" : "n/a"}
              </Status>
              <Status tone={extractedOk === (plan?.used_patches ?? -1) ? "success" : "danger"}>
                patches extracted: {extractedOk} / {plan?.used_patches ?? "n/a"}
              </Status>
            </div>
            <div className="split-grid">
              <div className="output-block">
                <span>Transport</span>
                <KV
                  rows={[
                    [
                      "Direction",
                      result.direction === 1
                        ? "Initiator → verifier"
                        : result.direction === 2
                          ? "Verifier → initiator"
                          : String(result.direction ?? "n/a"),
                    ],
                    ["Sequence number", fmtNum(result.seq)],
                    ["Session", <TechnicalId key="s">{result.session_id}</TechnicalId>],
                    ["Format", tr?.format_version ?? "n/a"],
                    ["Frame", `${fmtNum(tr?.frame_bytes)} B`],
                    ["= Header 16 + manifest", `${fmtNum(tr?.manifest_bytes)} B`],
                    ["+ AppWire", `${fmtNum(tr?.wire_bytes)} B`],
                    ["+ Frame tag", "32 B"],
                    ["In patches (AppWire + tag)", `${fmtNum(tr?.payload_section_bytes)} B`],
                    [
                      "Image",
                      `${art?.width ?? cover?.width ?? "n/a"} × ${art?.height ?? cover?.height ?? "n/a"} · ${art?.mode ?? cover?.mode ?? "n/a"} · ${art?.format ?? "PNG"}`,
                    ],
                    ["PNG size", isNil(art?.size) ? "n/a" : `${art?.size} B`],
                    [
                      "Cover",
                      `${cover?.source ?? "n/a"}${cover?.family ? ` · ${cover.family}` : ""}`,
                    ],
                  ]}
                />
              </div>
              <div className="output-block">
                <span>Distortion (cover vs stego, whole image)</span>
                <KV
                  rows={[
                    ["MSE", fmtMetric(e?.metrics?.mse)],
                    ["PSNR", fmtMetric(e?.metrics?.psnr, 2, " dB")],
                    ["SSIM", fmtMetric(e?.metrics?.ssim, 4)],
                    ["Changed samples", fmtNum(e?.metrics?.changed_samples)],
                    ["Changed fraction", fmtPct(e?.metrics?.changed_fraction)],
                    ["Max |diff|", fmtNum(e?.metrics?.max_abs_diff)],
                  ]}
                />
                <p className="stego-muted">
                  &quot;undefined&quot; means the service could not define the metric (for example
                  PSNR of identical images); nothing is substituted. High PSNR/SSIM is not evidence
                  of undetectability.
                </p>
              </div>
              <div className="output-block span-full-grid">
                <span>Timings</span>
                <div className="stego-timings">
                  {Object.entries(result.timings_ms ?? {}).map(([k, v]) => (
                    <div key={k}>
                      <b>{k}</b>
                      <Bar
                        value={num(v)}
                        max={Math.max(
                          1,
                          ...Object.entries(result.timings_ms ?? {})
                            .filter(([kk]) => kk !== "total")
                            .map(([, vv]) => num(vv) ?? 0),
                        )}
                      />
                      <i>{fmtMs(v)}</i>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </Panel>

      {/* 3 segmentation */}
      <Panel
        title="Patches"
        meta={
          plan ? (
            <Status tone="neutral">
              {plan.patch_count ?? "?"} patches · {plan.used_patches ?? "?"} used · level{" "}
              {plan.refinement_level ?? "?"}
            </Status>
          ) : (
            <Status tone="neutral">No plan yet</Status>
          )
        }
      >
        {!plan || !ctx ? (
          <Empty
            title="No segmentation yet"
            description="Send a message or preview a plan to see the adaptive region-growing segmentation of the cover and the algorithm chosen for each patch."
          />
        ) : (
          <>
            <div className="patch-layout">
              <PatchOverlay ctx={ctx} selected={selPatch} onSelect={setSelPatch} />
              <div>
                <KV
                  rows={[
                    ["Segmentation", plan.segmentation?.version ?? "n/a"],
                    ["Patches", fmtNum(plan.patch_count)],
                    ["Grown before merge", fmtNum(plan.segmentation?.regions_before_merge)],
                    ["Merges (undersized)", fmtNum(plan.segmentation?.merges)],
                    ["Target count", fmtNum(plan.segmentation?.target_regions)],
                    ["Complexity", fmtNum(plan.segmentation?.complexity, 4)],
                    ["Cell size", `${plan.segmentation?.cell_size ?? "n/a"} px`],
                    ["Growth threshold τ", fmtNum(plan.segmentation?.tau, 4)],
                    [
                      "Min / max region",
                      `${fmtNum(plan.segmentation?.min_region_px)} / ${fmtNum(plan.segmentation?.max_region_px)} px`,
                    ],
                    ["Refinement level", fmtNum(plan.refinement_level)],
                    ["Selector", plan.selector_version ?? "n/a"],
                    ["Knowledge base", plan.kb_version ?? "n/a"],
                    ["Payload to distribute", `${fmtNum(plan.payload_bytes)} B`],
                    ["Manifest", `${fmtNum(plan.manifest_bytes)} B`],
                    ["Carrier pixels reserved", fmtNum(plan.carrier_pixels)],
                    ["Carrier bits", fmtNum(plan.bootstrap_carrier_bits)],
                    ["Compressed manifest", `${fmtNum(plan.manifest_deflate_bytes)} B`],
                    ["Target chunk", `${fmtNum(plan.target_chunk_bytes)} B`],
                    ["Plan time", fmtMs(plan.plan_ms)],
                  ]}
                />
                <div className="stego-chips">
                  {usedAlgs.length ? (
                    usedAlgs.map(([a, n]) => (
                      <Status key={a} tone="info">
                        {a}: {n} patch{n === 1 ? "" : "es"}
                      </Status>
                    ))
                  ) : (
                    <Status tone="neutral">no algorithm in use</Status>
                  )}
                </div>
                {plan.segmentation?.settings ? (
                  <details className="stego-details">
                    <summary>Segmentation settings in effect</summary>
                    <KV
                      rows={Object.entries(plan.segmentation.settings).map(
                        ([k, v]): [string, string] => [k, String(v)],
                      )}
                    />
                  </details>
                ) : null}
                {plan.allocation_rule ? (
                  <p className="stego-muted">
                    Allocation: {plan.allocation_rule}. Chunks are contiguous, non-overlapping byte
                    ranges of the payload.
                  </p>
                ) : null}
              </div>
            </div>
            {(plan.attempts?.length ?? 0) > 1 ? (
              <>
                <h3 className="stego-h3">Refinement attempts</h3>
                <Attempts attempts={plan.attempts ?? []} />
              </>
            ) : null}
            <PatchTable ctx={ctx} selected={selPatch} onSelect={setSelPatch} />
            <div className="button-row">
              <Button size="sm" variant="outline" onClick={() => exportRun("json")}>
                <Download />
                Export this run (JSON)
              </Button>
              <Button size="sm" variant="outline" onClick={() => exportRun("csv")}>
                <Download />
                Patch table (CSV)
              </Button>
            </div>
          </>
        )}
      </Panel>

      {/* 4 inspector */}
      <Panel
        title="Patch inspector"
        meta={patch ? <Status tone="info">Patch {patch.patch_id}</Status> : undefined}
      >
        {ctx ? (
          <PatchInspector ctx={ctx} patch={patch} />
        ) : (
          <Empty title="No patch data" description="Appears with the first plan." />
        )}
      </Panel>

      {/* generated cover */}
      <Panel
        title="Cover"
        meta={
          generation ? (
            <Status tone={generation.budget?.exceeded ? "warning" : "success"}>
              {generation.family ?? "cover"} · {cover?.width ?? "?"}×{cover?.height ?? "?"} ·
              quality {fmtNum(generation.quality_score ?? cover?.quality_score, 3)}
            </Status>
          ) : (
            <Status tone="neutral">No cover yet</Status>
          )
        }
      >
        {generation ? (
          <Disclosure
            summary="Generation diagnostics and candidates"
            testId="generation-disclosure"
          >
            <div className="patch-layout">
              <Preview
                id={cover?.artifact_id}
                kind="cover"
                label="Cover generated for this transmission"
              />
              <GenerationDiagnostics g={generation} table={false} />
            </div>
            {generation.candidates?.length ? (
              <CandidateTable candidates={generation.candidates} />
            ) : null}
          </Disclosure>
        ) : (
          <Empty
            title="No cover generated yet"
            description="Send a message or preview a plan. A new cover is generated each time; the candidates, their quality scores and the reasons for any rejection appear here."
          />
        )}
      </Panel>

      {/* 6 timeline */}
      <Panel
        title="Transaction stages"
        meta={
          failure ? (
            <Status tone="danger">
              Failed at {failure.error.stage ?? "unknown"} {"·"} {failure.error.code}
            </Status>
          ) : result ? (
            <Status tone="success">All stages ok</Status>
          ) : undefined
        }
      >
        {stagesShown.length || (failure && !preview) ? (
          <Timeline stages={stagesShown} error={failure?.error} />
        ) : (
          <Empty
            title="No timeline"
            description="Stages appear after the first transaction (a plan preview runs no transaction)."
          />
        )}
      </Panel>

      {/* 7 events */}
      <Panel
        title="History"
        meta={
          <span className="panel-count">
            {events && events.ok ? `${events.data.events.length} events` : ""}
          </span>
        }
      >
        <div className="stego-filters">
          <Field label="Session">
            <Input
              list="stego-sessions"
              value={filters.session_id}
              placeholder="any"
              onChange={(ev) => setFilters({ ...filters, session_id: ev.target.value })}
              aria-label="Filter session"
            />
          </Field>
          <datalist id="stego-sessions">
            {sessions.map((s) => (
              <option key={s.id} value={s.id} />
            ))}
          </datalist>
          <Field label="Direction">
            <select
              className={selectClass}
              value={filters.direction}
              onChange={(ev) => setFilters({ ...filters, direction: ev.target.value })}
              aria-label="Filter direction"
            >
              <option value="">any</option>
              <option value="D1_to_D2">Initiator → verifier</option>
              <option value="D2_to_D1">Verifier → initiator</option>
            </select>
          </Field>
          <Field label="Dominant algorithm">
            <select
              className={selectClass}
              value={filters.algorithm}
              onChange={(ev) => setFilters({ ...filters, algorithm: ev.target.value })}
              aria-label="Filter algorithm"
            >
              <option value="">any</option>
              {ALGORITHMS.map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </Field>
          <Field label="Outcome">
            <select
              className={selectClass}
              value={filters.outcome}
              onChange={(ev) => setFilters({ ...filters, outcome: ev.target.value })}
              aria-label="Filter outcome"
            >
              <option value="">any</option>
              <option value="ok">ok</option>
              <option value="failed">failed</option>
            </select>
          </Field>
          <Field label="Time range">
            <select
              className={selectClass}
              value={filters.range}
              onChange={(ev) => setFilters({ ...filters, range: ev.target.value })}
              aria-label="Filter time range"
            >
              <option value="all">all time</option>
              <option value="15m">last 15 min</option>
              <option value="1h">last hour</option>
              <option value="24h">last 24 h</option>
            </select>
          </Field>
          <Button variant="outline" onClick={() => void loadEvents(filters)}>
            Apply filters
          </Button>
        </div>
        {events && !events.ok ? (
          <Notice tone="danger" title={`${events.error.code}`}>
            {describeStegoError(events.error.code, events.error.message).text}
          </Notice>
        ) : null}
        {events && events.ok && events.data.events.length === 0 ? (
          <Empty title="No events match" description="Adjust the filters or send a message." />
        ) : null}
        {events && events.ok && events.data.events.length > 0 ? (
          <DataTable label="Steganography events">
            <thead>
              <tr>
                <th>Time</th>
                <th>Session</th>
                <th>Dir</th>
                <th>Seq</th>
                <th>Patches (used)</th>
                <th>Algorithms</th>
                <th>Outcome</th>
                <th>Cover (family, quality)</th>
                <th>Image</th>
                <th>PSNR</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {events.data.events.map((ev, i) => {
                const ok = ev.outcome ? ev.outcome === "ok" : ev.success;
                return (
                  <tr
                    key={`${ev.event_id ?? i}`}
                    className="stego-row"
                    onClick={() => setSelectedEvent(ev)}
                    data-testid="event-row"
                    tabIndex={0}
                    onKeyDown={(k) => {
                      if (k.key === "Enter") setSelectedEvent(ev);
                    }}
                  >
                    <td>{fmtTime(ev.ts_ms)}</td>
                    <td>
                      <TechnicalId>{ev.session_id}</TechnicalId>
                    </td>
                    <td>{ev.direction_label ?? ev.direction ?? "n/a"}</td>
                    <td>{fmtNum(ev.seq)}</td>
                    <td>
                      {isNil(ev.patch_count)
                        ? "—"
                        : `${ev.patch_count} (${ev.used_patches ?? "?"})`}
                      {ev.refinement_level ? <small>level {ev.refinement_level}</small> : null}
                    </td>
                    <td>
                      {ev.algorithms_used
                        ? Object.entries(ev.algorithms_used)
                            .map(([a, v]) => `${a}×${v.patches}`)
                            .join(", ")
                        : "—"}
                    </td>
                    <td>
                      <Status tone={ok ? "success" : "danger"}>{ok ? "OK" : "Failed"}</Status>
                    </td>
                    <td>
                      {ev.cover_family ?? ev.cover_source ?? "—"}
                      {!isNil(ev.cover_quality_score) ? (
                        <small>q {fmtNum(ev.cover_quality_score, 3)}</small>
                      ) : null}
                    </td>
                    <td>{isNil(ev.width) ? "n/a" : `${ev.width}×${ev.height}`}</td>
                    <td>{fmtMetric(ev.psnr, 1)}</td>
                    <td>
                      {ev.error_code ?? "—"}
                      {ev.error_stage ? <small>{ev.error_stage}</small> : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </DataTable>
        ) : null}
        {selectedEvent ? (
          <div className="output-block" data-testid="event-detail">
            <span>
              Event {String(selectedEvent.event_id ?? "")}{" "}
              <button className="stego-link" onClick={() => setSelectedEvent(null)}>
                close
              </button>
            </span>
            <KV
              rows={[
                ["Kind", selectedEvent.kind ?? "n/a"],
                [
                  "Versions",
                  `${selectedEvent.segmentation_version ?? "n/a"} / ${selectedEvent.selector_version ?? "n/a"} / ${selectedEvent.kb_version ?? "n/a"}`,
                ],
                [
                  "Wire / manifest / frame / image",
                  `${fmtNum(selectedEvent.wire_bytes)} / ${fmtNum(selectedEvent.manifest_bytes)} / ${fmtNum(selectedEvent.frame_bytes)} / ${fmtNum(selectedEvent.image_bytes)} B`,
                ],
                [
                  "MSE / PSNR / SSIM",
                  `${fmtMetric(selectedEvent.mse)} / ${fmtMetric(selectedEvent.psnr, 2)} / ${fmtMetric(selectedEvent.ssim, 4)}`,
                ],
                ["Re-plans (same cover)", fmtNum(selectedEvent.replans?.length)],
                [
                  "Cover",
                  `${selectedEvent.cover_source ?? "n/a"} · ${selectedEvent.generator_version ?? "n/a"} · ${selectedEvent.generator_profile ?? "n/a"} · ${selectedEvent.cover_family ?? "n/a"}`,
                ],
                [
                  "Cover quality / candidates",
                  `${fmtNum(selectedEvent.cover_quality_score, 4)} / ${fmtNum(selectedEvent.generation_candidates)}`,
                ],
                [
                  "Generation time / budget",
                  `${fmtMs(selectedEvent.generation_used_ms)} / ${fmtNum(selectedEvent.generation_budget_ms)} ms${selectedEvent.generation_budget_exceeded ? " (exceeded)" : ""}`,
                ],
                [
                  "Requested → actual size",
                  `${selectedEvent.requested_width ?? "?"}×${selectedEvent.requested_height ?? "?"} → ${selectedEvent.width ?? "?"}×${selectedEvent.height ?? "?"}${selectedEvent.cover_resized ? " (resized)" : ""}`,
                ],
                ["Seed fingerprint", selectedEvent.seed_fingerprint ?? "n/a"],
                [
                  "Frame MAC / AEAD",
                  `${selectedEvent.header_mac_ok === true ? "ok" : selectedEvent.header_mac_ok === false ? "Failed" : "n/a"} / ${selectedEvent.aead_ok === true ? "ok" : selectedEvent.aead_ok === false ? "Failed" : "n/a"}`,
                ],
                [
                  "Error",
                  selectedEvent.error_code
                    ? `${selectedEvent.error_code} at ${selectedEvent.error_stage ?? "?"}: ${selectedEvent.error_message ?? ""}`
                    : "none",
                ],
              ]}
            />
            {selectedEvent.generation?.candidates?.length ? (
              <CandidateTable candidates={selectedEvent.generation.candidates} />
            ) : null}
            {selectedEvent.patches?.length ? (
              <DataTable label="Patches recorded for this event">
                <thead>
                  <tr>
                    <th>Patch</th>
                    <th>Pixels</th>
                    <th>Algorithm</th>
                    <th>KB entry</th>
                    <th>BM25</th>
                    <th>Query terms</th>
                    <th>Offset</th>
                    <th>Length</th>
                    <th>Capacity</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedEvent.patches.map((p) => (
                    <tr key={p.patch_id} className={p.used ? "" : "stego-excluded"}>
                      <td>#{p.patch_id}</td>
                      <td>{fmtNum(p.pixels)}</td>
                      <td>
                        {p.algorithm ?? "not used"}
                        {p.param ? <small>param {p.param}</small> : null}
                      </td>
                      <td>{p.kb_entry ?? "—"}</td>
                      <td>{isNil(p.bm25) ? "—" : fmtNum(p.bm25, 4)}</td>
                      <td>{p.query_terms?.join(", ") ?? "—"}</td>
                      <td>{p.used ? fmtNum(p.payload_offset) : "—"}</td>
                      <td>{p.used ? `${fmtNum(p.payload_length)} B` : "—"}</td>
                      <td>{isNil(p.capacity_bytes) ? "—" : `${p.capacity_bytes} B`}</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            ) : null}
            <details className="stego-details">
              <summary>Raw event (JSON)</summary>
              <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
            </details>
          </div>
        ) : null}
      </Panel>

      {/* 8 report */}
      <Panel
        title="Report and benchmark"
        meta={
          <div className="button-row">
            <Button size="sm" variant="outline" onClick={() => void loadReport()}>
              <RefreshCw />
              Reload
            </Button>
            {(["json", "csv", "patches_csv"] as const).map((f) => (
              <Button
                key={f}
                size="sm"
                variant="outline"
                onClick={() => {
                  setDlError(null);
                  downloadStegoReport(f).catch((x: unknown) => setDlError(String(x)));
                }}
              >
                <Download />
                {f === "json" ? "Report JSON" : f === "csv" ? "Events CSV" : "Patches CSV"}
              </Button>
            ))}
          </div>
        }
      >
        {dlError ? (
          <Notice tone="danger" title="Download failed">
            {dlError}
          </Notice>
        ) : null}
        {report && !report.ok ? (
          <Notice tone="danger" title={report.error.code}>
            {describeStegoError(report.error.code, report.error.message).text}
          </Notice>
        ) : null}
        {rep ? (
          <>
            <div className="metrics-grid">
              <Metric
                label="Total events"
                value={rep.totals?.events ?? "n/a"}
                detail={rep.schema}
              />
              <Metric
                label="Success"
                value={rep.totals?.ok ?? "n/a"}
                detail="completed transactions"
                tone="success"
              />
              <Metric
                label="Failure"
                value={rep.totals?.failed ?? "n/a"}
                detail="persisted failure events"
                tone={rep.totals?.failed ? "danger" : "neutral"}
              />
              <Metric
                label="Covers generated"
                value={rep.cover_generation?.covers_generated ?? "n/a"}
                detail="one fresh cover per transmission"
                tone="info"
              />
            </div>
            {rep.cover_generation ? (
              <KV
                rows={[
                  [
                    "Cover families",
                    Object.entries(rep.cover_generation.families ?? {})
                      .map(([f, n]) => `${f}: ${n}`)
                      .join(", ") || "n/a",
                  ],
                  [
                    "Cover quality score (mean, N)",
                    `${fmtNum(rep.cover_generation.cover_quality_score?.mean, 4)} (n=${rep.cover_generation.cover_quality_score?.n ?? 0})`,
                  ],
                  [
                    "Candidates / transmission (mean)",
                    fmtNum(rep.cover_generation.candidates_per_transmission?.mean, 2),
                  ],
                  [
                    "Generation + selection (mean)",
                    fmtMs(rep.cover_generation.generation_used_ms?.mean),
                  ],
                  ["Budget exceeded", fmtNum(rep.cover_generation.budget_exceeded_count)],
                  [
                    "Payload-driven resizes",
                    fmtNum(rep.cover_generation.payload_driven_resize_count),
                  ],
                  [
                    "Candidate rejection reasons",
                    Object.entries(rep.cover_generation.candidate_rejection_reasons ?? {})
                      .map(([r, n]) => `${r}: ${n}`)
                      .join(", ") || "none",
                  ],
                  [
                    "Host",
                    `${rep.environment?.host?.device_model ?? rep.environment?.host?.cpu_model ?? "n/a"} · ${rep.environment?.host?.arch ?? "?"} · profile ${rep.environment?.generator_profile ?? "n/a"}`,
                  ],
                ]}
              />
            ) : null}
            <p className="stego-muted">
              Cover quality score (heuristic coherence before embedding), distortion metrics (MSE /
              PSNR / SSIM between cover and stego) and detector AUC (offline evaluation script only)
              are three different things; none of them shows undetectability.
            </p>
            {rep.totals?.error_counts && Object.keys(rep.totals.error_counts).length ? (
              <div className="stego-chips">
                {Object.entries(rep.totals.error_counts).map(([c, n]) => (
                  <Status key={c} tone="danger">
                    {c}: {n}
                  </Status>
                ))}
              </div>
            ) : null}
            <KV
              rows={[
                ["Patches / image (mean)", fmtNum(rep.overall?.patch_count?.mean, 1)],
                ["Used patches (mean)", fmtNum(rep.overall?.used_patches?.mean, 1)],
                ["Manifest (mean)", fmtNum(rep.overall?.manifest_bytes?.mean, 0, " B")],
                ["Frame (mean)", fmtNum(rep.overall?.frame_bytes?.mean, 0, " B")],
                [
                  "PSNR (mean, N)",
                  `${fmtMetric(rep.overall?.psnr?.mean ?? null, 2, " dB")} (n=${rep.overall?.psnr?.n ?? 0})`,
                ],
                [
                  "SSIM (mean, N)",
                  `${fmtMetric(rep.overall?.ssim?.mean ?? null, 4)} (n=${rep.overall?.ssim?.n ?? 0})`,
                ],
                ["MSE (mean)", fmtMetric(rep.overall?.mse?.mean ?? null)],
              ]}
            />
            {(rep.per_algorithm ?? []).length === 0 ? (
              <Empty
                title="No per-algorithm data"
                description="Send messages or run the benchmark first."
              />
            ) : (
              <DataTable label="Per-algorithm usage across successful events">
                <thead>
                  <tr>
                    <th>Algorithm</th>
                    <th>Events using it</th>
                    <th>Patches</th>
                    <th>Payload bytes carried</th>
                    <th>Share of payload</th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const total = (rep.per_algorithm ?? []).reduce(
                      (s, a) => s + a.payload_bytes,
                      0,
                    );
                    return (rep.per_algorithm ?? []).map((a) => (
                      <tr key={a.algorithm}>
                        <td>
                          <strong>{a.algorithm}</strong>
                        </td>
                        <td>{a.events}</td>
                        <td>{a.patches}</td>
                        <td>{a.payload_bytes} B</td>
                        <td>
                          <div className="stego-cellbar">
                            {total ? fmtPct(a.payload_bytes / total) : "n/a"}
                            <Bar value={a.payload_bytes} max={total} />
                          </div>
                        </td>
                      </tr>
                    ));
                  })()}
                </tbody>
              </DataTable>
            )}
            {rep.overall?.timings_ms ? (
              <DataTable label="Stage timings over successful events">
                <thead>
                  <tr>
                    <th>Stage</th>
                    <th>n</th>
                    <th>mean</th>
                    <th>p50</th>
                    <th>p95</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(rep.overall.timings_ms).map(([k, t]) => (
                    <tr key={k}>
                      <td>{k}</td>
                      <td>{t.n ?? 0}</td>
                      <td>{fmtMs(t.mean)}</td>
                      <td>
                        {t.p50 != null ? (
                          fmtMs(t.p50)
                        ) : (
                          <span title="Percentiles need at least 20 samples">n&lt;20</span>
                        )}
                      </td>
                      <td>{t.p95 != null ? fmtMs(t.p95) : "n<20"}</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            ) : null}
            {rep.limitations?.length ? (
              <details className="stego-details">
                <summary>Report limitations ({rep.limitations.length})</summary>
                <ul className="stego-list">
                  {rep.limitations.map((l) => (
                    <li key={l}>{l}</li>
                  ))}
                </ul>
              </details>
            ) : null}
          </>
        ) : null}
        <Disclosure summary="Run benchmark">
          <p className="stego-muted">
            Runs real sealed messages through the full patch-wise pipeline on a ready session,
            generating a fresh cover for every run under the Generated Cover Configuration above.{" "}
            {benchSession ? (
              <>
                Session <code>{short(benchSession.id, 12)}</code>.
              </>
            ) : (
              <strong>No ready session (M1–M8 and K1–K3 complete) found.</strong>
            )}
          </p>
          <div className="form-grid stego-grid-4">
            <Field label="Iterations (max 50)">
              <Input
                type="number"
                min={1}
                max={50}
                value={iters}
                onChange={(ev) =>
                  setIters(Math.max(1, Math.min(50, parseInt(ev.target.value, 10) || 1)))
                }
                aria-label="Iterations"
              />
            </Field>
            <Field label="Message sizes (bytes, comma separated)">
              <Input
                value={sizes}
                onChange={(ev) => setSizes(ev.target.value)}
                aria-label="Message sizes"
              />
            </Field>
            <div />
            <Button
              disabled={!!busy || !benchSession || !backendUp}
              onClick={() => void runBench()}
            >
              <Play />
              <BusyLabel busy={busy === "bench"} idle="Run benchmark" busyText="Running" />
            </Button>
          </div>
          {bench && !bench.ok ? (
            <Notice
              tone={describeStegoError(bench.error.code).tone}
              title={`${describeStegoError(bench.error.code).title} (${bench.error.code})`}
            >
              {describeStegoError(bench.error.code, bench.error.message).text}
            </Notice>
          ) : null}
          {bench && bench.ok ? (
            <div className="output-block output-primary" data-testid="bench-summary">
              <span>Benchmark ({bench.data.runs?.length ?? 0} runs)</span>
              <p className="stego-muted" data-testid="bench-label">
                {bench.data.measurement_label ?? "host measurement"}. Host:{" "}
                {bench.data.host?.device_model ?? bench.data.host?.cpu_model ?? "unknown"} (
                {bench.data.host?.arch ?? "?"}, {bench.data.host?.logical_cpus ?? "?"} logical CPUs)
                {bench.data.host?.is_raspberry_pi_5 ? "" : " — not a Raspberry Pi 5"}.
              </p>
              <DataTable label="Benchmark runs">
                <thead>
                  <tr>
                    <th>Message bytes</th>
                    <th>Iteration</th>
                    <th>Outcome</th>
                    <th>Total</th>
                    <th>Cover (family, quality, generation)</th>
                    <th>Algorithms (patches)</th>
                    <th>Event</th>
                  </tr>
                </thead>
                <tbody>
                  {(bench.data.runs ?? []).map((r, i) => (
                    <tr key={i}>
                      <td>{r.payload_bytes}</td>
                      <td>{r.iteration}</td>
                      <td>
                        <Status tone={r.ok ? "success" : "danger"}>
                          {r.ok ? "OK" : (r.error_code ?? "Failed")}
                        </Status>
                      </td>
                      <td>{fmtMs(r.total_ms)}</td>
                      <td>
                        {r.cover
                          ? `${r.cover.family ?? "?"} · q ${fmtNum(r.cover.quality_score, 3)} · ${fmtMs(r.cover.generation_ms)}`
                          : "—"}
                      </td>
                      <td>
                        {r.algorithms_used
                          ? Object.entries(r.algorithms_used)
                              .map(([a, n]) => `${a}×${n}`)
                              .join(", ")
                          : "—"}
                      </td>
                      <td>{fmtNum(r.event_id)}</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </div>
          ) : null}
        </Disclosure>
      </Panel>

      {/* what this protects */}
      <Panel title="Scope and limits">
        <Disclosure summary="What the image transport protects and what it does not">
          <ul className="stego-list" data-testid="protect-note">
            <li>
              <strong>Confidentiality and authenticity</strong> come from the ML-KEM-derived AEAD
              keys and the frame MAC, enforced in the Rust core. Keys never reach the image service
              or this page.
            </li>
            <li>
              <strong>The patch manifest is authenticated</strong>: image size, segmentation map,
              patch ids, algorithm ids, parameters, offsets and lengths are covered by the same MAC
              as the payload. The in-image CRC only detects accidents; it is not authentication.
            </li>
            <li>
              <strong>The receiver never re-segments</strong>: the core locates and decrypts the
              manifest carried in the image and the image service rebuilds the patch masks from it,
              so it cannot drift from the sender.
            </li>
            <li>
              <strong>The image is an obscurity layer on top of AEAD</strong>, not extra
              cryptographic strength. No algorithm here is claimed undetectable; LSB-class methods
              are statistically detectable.
            </li>
            <li>
              <strong>Covers are generated locally</strong> for each transmission by a procedural
              generator (no pretrained model, no network, no camera, no upload). Candidates are
              screened with documented heuristics and only the payload <em>length</em> influences
              the choice. A generated image is still a synthetic image: it is not claimed to be
              indistinguishable from a photograph or undetectable.
            </li>
            <li>
              Transport is a <strong>lossless PNG handoff only</strong>. JPEG, resizing or filtering
              destroys the message; robustness is not claimed.
            </li>
            <li>
              Algorithm names denote <strong>this repository&apos;s variants</strong> (for example
              an additive approximation of HUGO, and custom STC sub-matrices) — see the Knowledge
              Base page.
            </li>
            <li>
              The decrypted message is shown only as the receiver&apos;s delivered result of this
              transaction; it is not stored in events, reports or exports.
            </li>
            <li>
              <strong>The manifest travels in a keyed carrier</strong>: compressed, encrypted and
              written by ±1 changes at pixel positions derived from a per-message key that never
              leaves the core. This hides where it is, not that pixels changed.
            </li>
          </ul>
        </Disclosure>
      </Panel>
    </>
  );
}

function ReadyItem({ label, ok, detail }: { label: string; ok: boolean | null; detail: string }) {
  return (
    <div className="stego-ready">
      <Status tone={ok === null ? "neutral" : ok ? "success" : "danger"}>
        {ok === null ? "Unknown" : ok ? "Ready" : "Not ready"}
      </Status>
      <strong>{label}</strong>
      <small>{detail}</small>
    </div>
  );
}
