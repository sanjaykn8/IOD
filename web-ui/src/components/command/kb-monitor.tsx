// Knowledge Base / Retrieval Monitor. Read-only inspection of the static, curated algorithm knowledge
// base and of what the deterministic retrieval (structured filters -> BM25 -> top-1) decided per patch.
// This is NOT a chatbot: nothing here calls a language model and nothing here changes a selection.
import { useCallback, useEffect, useMemo, useState } from "react";
import { BookOpen, Play, RefreshCw } from "lucide-react";
import { stegoApi, type StegoResult } from "@/lib/stego-api";
import { describeStegoError } from "@/lib/stego-errors";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { BusyLabel, DataTable, Empty, Field, Metric, PageHeader, Panel, Status, TechnicalId, selectClass } from "./core";
import { KV, Notice, fmtNum, fmtTime, isNil } from "./stego-shared";
import { PatchInspector, PatchOverlay, PatchTable, type PatchContext } from "./stego-patches";
import type { KbEntry, KnowledgeBase, StegoEvent, StegoPlanPreview } from "@/types/api";

const KIND_LABEL: Record<string, string> = { published: "PUBLISHED", implementation: "IMPLEMENTATION-SPECIFIC", local_heuristic: "LOCAL HEURISTIC" };
const KIND_TONE: Record<string, "success" | "info" | "warning"> = { published: "success", implementation: "info", local_heuristic: "warning" };

function List({ items }: { items?: string[] | undefined }) {
  return items?.length ? <ul className="stego-list">{items.map((s) => <li key={s}>{s}</li>)}</ul> : <p className="stego-muted">none recorded</p>;
}

function EntryDetail({ e, kb }: { e: KbEntry; kb: KnowledgeBase }) {
  const reg = kb.registry?.find((r) => r.id === e.id);
  const refs = new Map(kb.references.map((r) => [r.id, r]));
  return (
    <div data-testid="kb-entry-detail">
      <div className="stego-chips">
        <Status tone="info">{kb.kb_version}#{e.id}</Status><Status tone="neutral">{e.domain}{e.sub_domain ? ` · ${e.sub_domain}` : ""}</Status>
        <Status tone="neutral">cost: {e.cost.relative ?? "n/a"}</Status>
        {reg?.block ? <Status tone="warning">needs complete {reg.block}×{reg.block} blocks inside the patch</Status> : <Status tone="success">any irregular mask</Status>}
      </div>
      <KV rows={[["ALGORITHM ID (stable)", String(e.id)], ["NAME", e.name], ["EXACT VARIANT IN THIS REPOSITORY", <code key="v">{e.variant}</code>],
        ["CODING", reg?.coding ?? "n/a"], ["PARAMETER RANGE", reg?.param_range ? (reg.param_range[1] ? `${reg.param_range[0]}–${reg.param_range[1]}` : "none") : "n/a"],
        ["MASK SUPPORT", reg?.mask_support ?? "n/a"]]} />
      <p>{e.summary}</p>
      <div className="kb-cols">
        <div className="output-block"><span>SUITABLE WHEN</span><List items={e.suitable_when} />
          <div className="stego-chips">{e.suitable_terms.map((t) => <Status key={t} tone="info">{t}</Status>)}</div>
          <p className="stego-muted">The chips are the indexed terms (weight {kb.selector.field_weights["suitable_terms"] ?? "?"}); a patch scores when its query terms match them.</p></div>
        <div className="output-block"><span>AVOID WHEN</span><List items={e.avoid_when} />
          {e.hard_avoid.length ? <><span>HARD EXCLUSION RULES (structured filter)</span><ul className="stego-list">{e.hard_avoid.map((r) => <li key={r.feature + r.op}><code>{r.feature} {r.op} {JSON.stringify(r.value)}</code> → {r.reason}</li>)}</ul></> : <p className="stego-muted">No hard exclusion rule.</p>}</div>
        <div className="output-block"><span>MASK / GEOMETRY REQUIREMENTS</span>
          <KV rows={Object.entries(e.requirements).map(([k, v]): [string, string] => [k.toUpperCase(), String(v)])} /></div>
        <div className="output-block"><span>CAPACITY BEHAVIOUR</span><p>{e.capacity.behavior ?? "n/a"}</p>
          <KV rows={[["DEPENDS ON", e.capacity.factors?.join(", ") ?? "n/a"], ["ADVISORY bits / sample", isNil(e.capacity.advisory_bits_per_sample) ? "n/a" : String(e.capacity.advisory_bits_per_sample)]]} />
          <p className="stego-muted">Advisory only. Selection always uses the capacity <em>measured by the implementation</em> on the actual patch.</p></div>
        <div className="output-block"><span>DISTORTION</span><p>{e.distortion.impact ?? "n/a"}</p><p className="stego-muted">Measured with: {e.distortion.metrics?.join(", ") ?? "n/a"}</p></div>
        <div className="output-block"><span>COMPUTATIONAL COST</span><p>{e.cost.relative ?? "n/a"}{e.cost.notes ? ` — ${e.cost.notes}` : ""}</p></div>
        <div className="output-block"><span>COLOUR / FORMAT ASSUMPTIONS</span><p>{e.assumptions}</p></div>
        <div className="output-block"><span>EXTRACTION AND SYNCHRONISATION</span><p>{e.extraction}</p></div>
      </div>
      <div className="output-block"><span>LIMITATIONS</span><List items={e.limitations} /></div>
      <div className="output-block"><span>EVIDENCE NOTES</span>
        {e.evidence.map((ev, i) => <div key={i} className={`kb-ev kb-ev-${ev.kind}`}>
          <Status tone={KIND_TONE[ev.kind] ?? "info"}>{KIND_LABEL[ev.kind] ?? ev.kind}</Status> {ev.claim}
          {ev.refs?.length ? <small> — {ev.refs.map((r) => refs.get(r)?.title ? `${refs.get(r)?.authors} (${refs.get(r)?.year})` : r).join("; ")}</small> : null}
          {ev.validate ? <small> — validated by <code>{ev.validate}</code></small> : null}{ev.note ? <small> — {ev.note}</small> : null}
        </div>)}
      </div>
      <div className="output-block"><span>REFERENCES</span>
        {e.references.length ? <ul className="stego-list">{e.references.map((id) => { const r = refs.get(id); return <li key={id}>{r ? <>{r.authors} ({r.year}). <em>{r.title}</em>{r.venue ? `. ${r.venue}` : ""}{r.doi ? <> · DOI <code>{r.doi}</code></> : null}{r.verified ? <small> [{r.verified}]</small> : null}</> : id}</li>; })}</ul> : <p className="stego-muted">No external reference: this entry is described from the implementation only.</p>}
      </div>
    </div>
  );
}

export function KnowledgeBasePage() {
  const [kbRes, setKbRes] = useState<StegoResult<KnowledgeBase> | null>(null);
  const [sel, setSel] = useState(1);
  const [events, setEvents] = useState<StegoEvent[] | null>(null);
  const [evSel, setEvSel] = useState<StegoEvent | null>(null);
  const [payload, setPayload] = useState(300);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<StegoResult<StegoPlanPreview> | null>(null);
  const [selPatch, setSelPatch] = useState<number | null>(null);

  const load = useCallback(async () => {
    setKbRes(await stegoApi.kb());
    const ev = await stegoApi.events({ limit: 50 });
    setEvents(ev.ok ? ev.data.events.filter((e) => (e.patches?.length ?? 0) > 0) : []);
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function run() {
    setBusy(true); setSelPatch(null);
    const r = await stegoApi.plan({ payload_bytes: Math.max(33, payload) });
    setPreview(r);
    if (r.ok) setSelPatch(r.data.plan?.patches?.find((p) => p.used)?.patch_id ?? null);
    setBusy(false);
  }

  const kb = kbRes && kbRes.ok ? kbRes.data : null;
  const entry = kb?.entries.find((e) => e.id === sel) ?? null;
  const rulesByTerm = useMemo(() => new Map((kb?.query_terms ?? []).map((q) => [q.term, q])), [kb]);
  const pv = preview && preview.ok ? preview.data : null;
  const ctx: PatchContext | null = pv?.plan ? { plan: pv.plan, coverId: pv.cover?.artifact_id, width: pv.cover?.width, height: pv.cover?.height, palette: pv.inspection?.palette } : null;
  const patch = pv?.plan?.patches?.find((p) => p.patch_id === selPatch) ?? null;

  return <>
    <PageHeader eyebrow="KNOWLEDGE BASE / RETRIEVAL MONITOR" title="Algorithm Knowledge Base and Retrieval Monitor"
      description="The static, curated knowledge base that the patch-wise transport consults, and the deterministic retrieval that picks one algorithm per patch. Inspection only."
      actions={<Button variant="outline" size="sm" onClick={() => void load()}><RefreshCw />Reload</Button>} />
    <Notice tone="info" title="Deterministic retrieval — no language model, no embeddings, no network">
      For every patch: (1) structured hard filters (mask geometry, minimum size, complete blocks, hard-avoid rules, measured capacity for the assigned chunk), then (2) BM25 over the entries that passed, then (3) the top-1 entry is used. If nothing is eligible there is no fallback algorithm: the cover is re-segmented more coarsely a bounded number of times, otherwise the message is rejected.
    </Notice>
    {kbRes && !kbRes.ok ? <Notice tone="danger" title={`${describeStegoError(kbRes.error.code).title} (${kbRes.error.code})`}>{describeStegoError(kbRes.error.code, kbRes.error.message).text}</Notice> : null}
    {!kbRes ? <Empty title="Loading knowledge base" description="Requesting /api/stego/kb." /> : null}

    {kb ? <>
      <Panel title="1 / Selector" meta={<Status tone="success">VALIDATED AT SERVICE START</Status>}>
        <div className="metrics-grid">
          <Metric label="KNOWLEDGE BASE" value={kb.kb_version} detail={`schema ${String(kb.schema_version ?? "n/a")}`} />
          <Metric label="SELECTOR" value={kb.selector.version} detail="structured filters → BM25 → top-1" tone="info" />
          <Metric label="ENTRIES" value={kb.entries.length} detail="one per algorithm id (1–10)" />
          <Metric label="REFERENCES" value={kb.references.length} detail="bibliographic entries" />
        </div>
        <KV rows={[["BM25 k1", String(kb.selector.bm25.k1)], ["BM25 b", String(kb.selector.bm25.b)],
          ["FIELD WEIGHTS", Object.entries(kb.selector.field_weights).map(([k, v]) => `${k}×${v}`).join(", ")], ["TIE BREAK", kb.selector.tie_break ?? "n/a"],
          ["CAPACITY SOURCE", kb.selector.capacity_source ?? "n/a"], ["DOCUMENTS", fmtNum(kb.bm25_stats?.documents)], ["AVG DOCUMENT LENGTH", fmtNum(kb.bm25_stats?.avg_doc_len, 2)],
          ["FORMAT", kb.format_version ?? "n/a"], ["SEGMENTATION", kb.segmentation_version ?? "n/a"]]} />
        {kb.citation_note ? <p className="stego-muted">{kb.citation_note}</p> : null}
        <h3 className="stego-h3">Query terms (how patch features become a query)</h3>
        {kb.query_terms_note ? <p className="stego-muted">{kb.query_terms_note}</p> : null}
        <DataTable label="Query term rules and inverse document frequencies">
          <thead><tr><th>Term</th><th>Emitted when</th><th>IDF in this corpus</th><th>Entries that index it</th></tr></thead>
          <tbody>{kb.query_terms.map((q) => <tr key={q.term}><td><strong>{q.term}</strong></td><td><code>{q.feature} {q.op} {JSON.stringify(q.value)}</code></td>
            <td>{isNil(kb.bm25_stats?.idf[q.term]) ? "not indexed" : fmtNum(kb.bm25_stats?.idf[q.term], 4)}</td>
            <td>{kb.entries.filter((e) => e.suitable_terms.includes(q.term)).map((e) => e.name).join(", ") || "—"}</td></tr>)}</tbody>
        </DataTable>
        <p className="stego-muted">The thresholds in “emitted when” are local heuristics of this project, not published constants.</p>
        {kb.segmentation_defaults ? <details className="stego-details"><summary>Segmentation defaults of the image service</summary><KV rows={Object.entries(kb.segmentation_defaults).map(([k, v]): [string, string] => [k, String(v)])} /></details> : null}
      </Panel>

      <Panel title="2 / Knowledge-base entries" meta={<span className="panel-count">{kb.entries.length} entries</span>}>
        <div className="kb-grid" role="tablist" aria-label="Knowledge-base entries">
          {kb.entries.map((e) => <button key={e.id} type="button" role="tab" aria-selected={sel === e.id} className={`kb-card ${sel === e.id ? "kb-card-on" : ""}`} onClick={() => setSel(e.id)} data-testid={`kb-card-${e.name}`}>
            <strong>{e.id}. {e.name}</strong><small>{e.domain}</small><small>{e.suitable_terms.slice(0, 4).join(" · ")}</small></button>)}
        </div>
        {entry ? <EntryDetail e={entry} kb={kb} /> : null}
      </Panel>

      <Panel title="3 / References" meta={<BookOpen aria-hidden="true" />}>
        <DataTable label="References cited by the knowledge base">
          <thead><tr><th>Id</th><th>Authors</th><th>Year</th><th>Title</th><th>Venue</th><th>DOI</th><th>Check status</th><th>Cited by</th></tr></thead>
          <tbody>{kb.references.map((r) => <tr key={r.id}><td><code>{r.id}</code></td><td>{r.authors}</td><td>{r.year}</td><td>{r.title}</td><td>{r.venue ?? "—"}</td><td>{r.doi ? <code>{r.doi}</code> : "—"}</td><td>{r.verified ?? "—"}</td>
            <td>{kb.entries.filter((e) => e.references.includes(r.id)).map((e) => e.name).join(", ") || "—"}</td></tr>)}</tbody>
        </DataTable>
      </Panel>
    </> : null}

    <Panel title="4 / Retrieval monitor — recent transactions" meta={<span className="panel-count">{events ? `${events.length} events with patch records` : ""}</span>}>
      {events && events.length === 0 ? <Empty title="No retrieval recorded yet" description="Send a message in the Steganography Lab; every event stores the per-patch query terms, ranking and BM25 score." /> : null}
      {events && events.length > 0 ? <div className="form-grid stego-grid-4"><Field label="Event">
        <select className={selectClass} value={evSel ? String(evSel.event_id) : ""} onChange={(x) => setEvSel(events.find((e) => String(e.event_id) === x.target.value) ?? null)} aria-label="Event">
          <option value="">Select an event</option>{events.map((e) => <option key={String(e.event_id)} value={String(e.event_id)}>#{String(e.event_id)} · {fmtTime(e.ts_ms)} · {e.direction_label ?? ""} · {e.used_patches ?? "?"}/{e.patch_count ?? "?"} patches</option>)}
        </select></Field></div> : null}
      {evSel ? <>
        <KV rows={[["SESSION", <TechnicalId key="s">{evSel.session_id}</TechnicalId>], ["KNOWLEDGE BASE", evSel.kb_version ?? "n/a"], ["SELECTOR", evSel.selector_version ?? "n/a"], ["SEGMENTATION", evSel.segmentation_version ?? "n/a"],
          ["REFINEMENT LEVEL", fmtNum(evSel.refinement_level)], ["OUTCOME", evSel.success ? "ok" : `failed (${evSel.error_code ?? "?"})`]]} />
        <DataTable label="Per-patch retrieval of the selected event">
          <thead><tr><th>Patch</th><th>Pixels</th><th>Query terms</th><th>Eligible ranking (best first)</th><th>Selected</th><th>KB entry</th><th>BM25</th><th>Chunk</th></tr></thead>
          <tbody>{(evSel.patches ?? []).map((p) => <tr key={p.patch_id} className={p.used ? "" : "stego-excluded"} data-testid="monitor-row"><td>#{p.patch_id}</td><td>{fmtNum(p.pixels)}</td>
            <td>{p.query_terms?.length ? p.query_terms.map((t) => <span key={t} title={rulesByTerm.get(t) ? `${rulesByTerm.get(t)?.feature} ${rulesByTerm.get(t)?.op} ${JSON.stringify(rulesByTerm.get(t)?.value)}` : undefined}>{t} </span>) : "—"}</td>
            <td>{p.ranking?.join(" › ") ?? "—"}</td><td>{p.used ? <strong>{p.algorithm}</strong> : "not used"}</td><td>{p.kb_entry ?? "—"}</td><td>{isNil(p.bm25) ? "—" : fmtNum(p.bm25, 4)}</td>
            <td>{p.used ? `${fmtNum(p.payload_length)} B @ ${fmtNum(p.payload_offset)}` : "—"}</td></tr>)}</tbody>
        </DataTable>
      </> : null}
    </Panel>

    <Panel title="5 / Retrieval monitor — try a cover" meta={<Status tone="info">POST /api/stego/plan</Status>}>
      <p className="stego-muted">Runs the real planner (segmentation, features, filters, BM25, allocation, dry run) on a freshly generated cover for a payload length (a new cover every run, under the active generation profile). No message is sealed and nothing is embedded or sent.</p>
      <div className="form-grid stego-grid-4">
        <Field label="Payload length (bytes)"><Input type="number" min={33} max={60000} value={payload} onChange={(x) => setPayload(parseInt(x.target.value, 10) || 33)} aria-label="Payload length" /></Field>
        <div /><Button onClick={() => void run()} disabled={busy}><Play /><BusyLabel busy={busy} idle="Run retrieval" busyText="Planning" /></Button>
      </div>
      {preview && !preview.ok ? <Notice tone={describeStegoError(preview.error.code).tone} title={`${describeStegoError(preview.error.code).title} (${preview.error.code})`}>{describeStegoError(preview.error.code, preview.error.message).text}</Notice> : null}
      {pv?.generation ? <p className="stego-muted" data-testid="kb-cover-line">Cover generated for this run: {pv.generation.family ?? "n/a"} · {pv.cover?.width}×{pv.cover?.height} · quality score {pv.generation.quality_score ?? "n/a"} · {pv.generation.candidate_count ?? "?"} candidate(s) · fingerprint <code>{pv.generation.seed_fingerprint ?? "n/a"}</code>. Running again generates a different cover.</p> : null}
      {ctx ? <>
        <div className="patch-layout"><PatchOverlay ctx={ctx} selected={selPatch} onSelect={setSelPatch} /><div><PatchInspector ctx={ctx} patch={patch} /></div></div>
        <PatchTable ctx={ctx} selected={selPatch} onSelect={setSelPatch} />
      </> : null}
    </Panel>
  </>;
}
