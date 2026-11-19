// Knowledge base page. Read-only inspection of the static, curated algorithm knowledge base, the versioned
// risk table and of what the deterministic selector (filters -> risk tier, distortion, cost -> BM25 -> top-1)
// decided per patch.
// This is NOT a chatbot: nothing here calls a language model and nothing here changes a selection.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Play, RefreshCw } from "lucide-react";
import { stegoApi, type StegoResult } from "@/lib/stego-api";
import { describeStegoError } from "@/lib/stego-errors";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  BusyLabel,
  DataTable,
  Disclosure,
  Empty,
  Field,
  Metric,
  PageHeader,
  Panel,
  Status,
  TechnicalId,
  selectClass,
} from "./core";
import { KV, Notice, fmtNum, fmtTime, isNil } from "./stego-shared";
import { PatchInspector, PatchOverlay, PatchTable, type PatchContext } from "./stego-patches";
import type {
  KbEntry,
  KnowledgeBase,
  StegoEvent,
  StegoPlanPreview,
  StegoStatus,
} from "@/types/api";

const KIND_LABEL: Record<string, string> = {
  published: "Published",
  implementation: "Implementation-specific",
  local_heuristic: "Local heuristic",
};
const KIND_TONE: Record<string, "success" | "info" | "warning"> = {
  published: "success",
  implementation: "info",
  local_heuristic: "warning",
};

function List({ items }: { items?: string[] | undefined }) {
  return items?.length ? (
    <ul className="stego-list">
      {items.map((s) => (
        <li key={s}>{s}</li>
      ))}
    </ul>
  ) : (
    <p className="stego-muted">none recorded</p>
  );
}

function EntryDetail({ e, kb }: { e: KbEntry; kb: KnowledgeBase }) {
  const reg = kb.registry?.find((r) => r.id === e.id);
  const refs = new Map(kb.references.map((r) => [r.id, r]));
  return (
    <div data-testid="kb-entry-detail">
      <div className="stego-chips">
        <Status tone="info">
          {kb.kb_version}#{e.id}
        </Status>
        <Status tone="neutral">
          {e.domain}
          {e.sub_domain ? ` · ${e.sub_domain}` : ""}
        </Status>
        <Status tone="neutral">cost: {e.cost.relative ?? "n/a"}</Status>
        {reg?.block ? (
          <Status tone="warning">
            needs complete {reg.block}×{reg.block} blocks inside the patch
          </Status>
        ) : (
          <Status tone="success">any irregular mask</Status>
        )}
      </div>
      <KV
        rows={[
          ["Algorithm ID (stable)", String(e.id)],
          ["Name", e.name],
          ["Exact variant in this repository", <code key="v">{e.variant}</code>],
          ["Coding", reg?.coding ?? "n/a"],
          [
            "Parameter range",
            reg?.param_range
              ? reg.param_range[1]
                ? `${reg.param_range[0]}–${reg.param_range[1]}`
                : "none"
              : "n/a",
          ],
          ["Mask support", reg?.mask_support ?? "n/a"],
        ]}
      />
      <p>{e.summary}</p>
      <div className="kb-cols">
        <div className="output-block">
          <span>Suitable when</span>
          <List items={e.suitable_when} />
          <div className="stego-chips">
            {e.suitable_terms.map((t) => (
              <Status key={t} tone="info">
                {t}
              </Status>
            ))}
          </div>
          <p className="stego-muted">
            The chips are the indexed terms (weight{" "}
            {kb.selector.field_weights["suitable_terms"] ?? "?"}); a patch scores when its query
            terms match them.
          </p>
        </div>
        <div className="output-block">
          <span>Avoid when</span>
          <List items={e.avoid_when} />
          {e.hard_avoid.length ? (
            <>
              <span>Hard exclusion rules (structured filter)</span>
              <ul className="stego-list">
                {e.hard_avoid.map((r) => (
                  <li key={r.feature + r.op}>
                    <code>
                      {r.feature} {r.op} {JSON.stringify(r.value)}
                    </code>{" "}
                    → {r.reason}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="stego-muted">No hard exclusion rule.</p>
          )}
        </div>
        <div className="output-block">
          <span>Mask and geometry requirements</span>
          <KV
            rows={Object.entries(e.requirements).map(([k, v]): [string, string] => [
              k.replace(/_/g, " "),
              String(v),
            ])}
          />
        </div>
        <div className="output-block">
          <span>Capacity behaviour</span>
          <p>{e.capacity.behavior ?? "n/a"}</p>
          <KV
            rows={[
              ["Depends on", e.capacity.factors?.join(", ") ?? "n/a"],
              [
                "Advisory bits per sample",
                isNil(e.capacity.advisory_bits_per_sample)
                  ? "n/a"
                  : String(e.capacity.advisory_bits_per_sample),
              ],
            ]}
          />
          <p className="stego-muted">
            Advisory only. Selection always uses the capacity{" "}
            <em>measured by the implementation</em> on the actual patch.
          </p>
        </div>
        <div className="output-block">
          <span>Distortion</span>
          <p>{e.distortion.impact ?? "n/a"}</p>
          <p className="stego-muted">Measured with: {e.distortion.metrics?.join(", ") ?? "n/a"}</p>
        </div>
        <div className="output-block">
          <span>Computational cost</span>
          <p>
            {e.cost.relative ?? "n/a"}
            {e.cost.notes ? ` — ${e.cost.notes}` : ""}
          </p>
        </div>
        <div className="output-block">
          <span>Colour and format assumptions</span>
          <p>{e.assumptions}</p>
        </div>
        <div className="output-block">
          <span>Extraction and synchronisation</span>
          <p>{e.extraction}</p>
        </div>
      </div>
      <div className="output-block">
        <span>Limitations</span>
        <List items={e.limitations} />
      </div>
      <div className="output-block">
        <span>Evidence notes</span>
        {e.evidence.map((ev, i) => (
          <div key={i} className={`kb-ev kb-ev-${ev.kind}`}>
            <Status tone={KIND_TONE[ev.kind] ?? "info"}>{KIND_LABEL[ev.kind] ?? ev.kind}</Status>{" "}
            {ev.claim}
            {ev.refs?.length ? (
              <small>
                {" "}
                —{" "}
                {ev.refs
                  .map((r) =>
                    refs.get(r)?.title ? `${refs.get(r)?.authors} (${refs.get(r)?.year})` : r,
                  )
                  .join("; ")}
              </small>
            ) : null}
            {ev.validate ? (
              <small>
                {" "}
                — validated by <code>{ev.validate}</code>
              </small>
            ) : null}
            {ev.note ? <small> — {ev.note}</small> : null}
          </div>
        ))}
      </div>
      <div className="output-block">
        <span>References</span>
        {e.references.length ? (
          <ul className="stego-list">
            {e.references.map((id) => {
              const r = refs.get(id);
              return (
                <li key={id}>
                  {r ? (
                    <>
                      {r.authors} ({r.year}). <em>{r.title}</em>
                      {r.venue ? `. ${r.venue}` : ""}
                      {r.doi ? (
                        <>
                          {" "}
                          · DOI <code>{r.doi}</code>
                        </>
                      ) : null}
                      {r.verified ? <small> [{r.verified}]</small> : null}
                    </>
                  ) : (
                    id
                  )}
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="stego-muted">
            No external reference: this entry is described from the implementation only.
          </p>
        )}
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
  const [status, setStatus] = useState<StegoStatus | null>(null);

  const load = useCallback(async () => {
    setKbRes(await stegoApi.kb());
    const st = await stegoApi.status();
    setStatus(st.ok ? st.data : null);
    const ev = await stegoApi.events({ limit: 50 });
    setEvents(ev.ok ? ev.data.events.filter((e) => (e.patches?.length ?? 0) > 0) : []);
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  async function run() {
    setBusy(true);
    setSelPatch(null);
    const r = await stegoApi.plan({ payload_bytes: Math.max(33, payload) });
    setPreview(r);
    if (r.ok) setSelPatch(r.data.plan?.patches?.find((p) => p.used)?.patch_id ?? null);
    setBusy(false);
  }

  const kb = kbRes && kbRes.ok ? kbRes.data : null;
  const policyAllowed = status?.config?.algorithm_policy?.allowed ?? null;
  const entry = kb?.entries.find((e) => e.id === sel) ?? null;
  const rulesByTerm = useMemo(() => new Map((kb?.query_terms ?? []).map((q) => [q.term, q])), [kb]);
  const pv = preview && preview.ok ? preview.data : null;
  const ctx: PatchContext | null = pv?.plan
    ? {
        plan: pv.plan,
        coverId: pv.cover?.artifact_id,
        width: pv.cover?.width,
        height: pv.cover?.height,
        palette: pv.inspection?.palette,
      }
    : null;
  const patch = pv?.plan?.patches?.find((p) => p.patch_id === selPatch) ?? null;

  return (
    <>
      <PageHeader
        title="Knowledge base"
        description="The curated algorithm knowledge base, the measured risk table and the operational policy that together pick one algorithm per patch. Read-only."
        actions={
          <Button variant="outline" size="sm" onClick={() => void load()}>
            <RefreshCw />
            Reload
          </Button>
        }
      />
      {kbRes && !kbRes.ok ? (
        <Notice
          tone="danger"
          title={`${describeStegoError(kbRes.error.code).title} (${kbRes.error.code})`}
        >
          {describeStegoError(kbRes.error.code, kbRes.error.message).text}
        </Notice>
      ) : null}
      {!kbRes ? (
        <Empty title="Loading knowledge base" description="Requesting /api/stego/kb." />
      ) : null}

      {kb ? (
        <>
          <Panel title="Selector" meta={<Status tone="success">Validated at service start</Status>}>
            <div className="metrics-grid">
              <Metric
                label="Knowledge base"
                value={kb.kb_version}
                detail={`schema ${String(kb.schema_version ?? "n/a")}`}
              />
              <Metric
                label="Selector"
                value={kb.selector.version}
                detail="filters → risk, distortion, cost → BM25"
              />
              <Metric
                label="Entries"
                value={kb.entries.length}
                detail="one per algorithm id (1–10)"
              />
              <Metric
                label="References"
                value={kb.references.length}
                detail="bibliographic entries"
              />
            </div>
            <KV
              rows={[
                ["BM25 k1", String(kb.selector.bm25.k1)],
                ["BM25 b", String(kb.selector.bm25.b)],
                [
                  "Field weights",
                  Object.entries(kb.selector.field_weights)
                    .map(([k, v]) => `${k}×${v}`)
                    .join(", "),
                ],
                ["Ranking", kb.selector.ranking ?? "n/a"],
                ["Tie break", kb.selector.tie_break ?? "n/a"],
                ["Capacity source", kb.selector.capacity_source ?? "n/a"],
                ["Documents", fmtNum(kb.bm25_stats?.documents)],
                ["Avg document length", fmtNum(kb.bm25_stats?.avg_doc_len, 2)],
                ["Format", kb.format_version ?? "n/a"],
                ["Segmentation", kb.segmentation_version ?? "n/a"],
              ]}
            />
            {kb.citation_note ? <p className="stego-muted">{kb.citation_note}</p> : null}
            <p className="stego-muted">
              For every patch: hard filters (operational policy, mask geometry, minimum size,
              complete blocks, hard-avoid rules, measured capacity for the chunk) → ranking by the
              risk table → BM25 as the suitability tie-break → top-1. If nothing is eligible,
              planning moves to a coarser segmentation or fails; there is no fallback algorithm. No
              language model, embeddings or network are involved.
            </p>
            <Disclosure summary="Query terms and BM25 statistics">
              <h3 className="stego-h3">Query terms (how patch features become a query)</h3>
              {kb.query_terms_note ? <p className="stego-muted">{kb.query_terms_note}</p> : null}
              <DataTable label="Query term rules and inverse document frequencies">
                <thead>
                  <tr>
                    <th>Term</th>
                    <th>Emitted when</th>
                    <th>IDF in this corpus</th>
                    <th>Entries that index it</th>
                  </tr>
                </thead>
                <tbody>
                  {kb.query_terms.map((q) => (
                    <tr key={q.term}>
                      <td>
                        <strong>{q.term}</strong>
                      </td>
                      <td>
                        <code>
                          {q.feature} {q.op} {JSON.stringify(q.value)}
                        </code>
                      </td>
                      <td>
                        {isNil(kb.bm25_stats?.idf[q.term])
                          ? "not indexed"
                          : fmtNum(kb.bm25_stats?.idf[q.term], 4)}
                      </td>
                      <td>
                        {kb.entries
                          .filter((e) => e.suitable_terms.includes(q.term))
                          .map((e) => e.name)
                          .join(", ") || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
              <p className="stego-muted">
                The thresholds in “emitted when” are local heuristics of this project, not published
                constants.
              </p>
              {kb.segmentation_defaults ? (
                <details className="stego-details">
                  <summary>Segmentation defaults of the image service</summary>
                  <KV
                    rows={Object.entries(kb.segmentation_defaults).map(
                      ([k, v]): [string, string] => [k, String(v)],
                    )}
                  />
                </details>
              ) : null}
            </Disclosure>
          </Panel>

          {kb.risk_table ? (
            <Panel
              title="Risk table"
              meta={<Status tone="neutral">{kb.risk_table.version}</Status>}
            >
              <p className="panel-desc">
                {kb.risk_table.label} Each algorithm embeds alone over the whole image at the
                reference rate; the detector AUC sets the tier (
                {Object.entries(kb.risk_table.tiers ?? {})
                  .map(([t, r]) => `${t}: ${r}`)
                  .join("; ")}
                ). A lower AUC means these detectors separated it less well, not that it is
                undetectable.
              </p>
              <DataTable label="Risk table">
                <thead>
                  <tr>
                    <th>Algorithm</th>
                    <th>Tier</th>
                    <th className="num">AUC</th>
                    <th>95 % CI</th>
                    <th className="num">Rate (bits/sample)</th>
                    <th className="num">Changes / bit</th>
                    <th className="num">ms / KiB</th>
                    <th className="num">Pairs</th>
                    <th>Default policy</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(kb.risk_table.algorithms)
                    .sort(
                      (a, b) =>
                        (kb.entries.find((e) => e.name === a[0])?.id ?? 0) -
                        (kb.entries.find((e) => e.name === b[0])?.id ?? 0),
                    )
                    .map(([name, r]) => (
                      <tr key={name} data-testid={`risk-row-${name}`}>
                        <td className="mono">{name}</td>
                        <td>
                          <span className={`tier tier-${r.tier}`}>{r.tier}</span>
                        </td>
                        <td className="num">{fmtNum(r.auc, 3)}</td>
                        <td>
                          {r.auc_ci95
                            ? `${fmtNum(r.auc_ci95[0], 3)}–${fmtNum(r.auc_ci95[1], 3)}`
                            : "—"}
                        </td>
                        <td className="num">
                          {fmtNum(r.achieved_rate_bps, 4)}
                          {r.reached_reference_rate === false ? " *" : ""}
                        </td>
                        <td className="num">{fmtNum(r.changes_per_bit, 3)}</td>
                        <td className="num">{fmtNum(r.ms_per_kib, 1)}</td>
                        <td className="num">{r.n_pairs ?? "—"}</td>
                        <td>
                          {policyAllowed ? (
                            policyAllowed.includes(name) ? (
                              <Status tone="success">Allowed</Status>
                            ) : (
                              <Status tone="neutral">Excluded</Status>
                            )
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </DataTable>
              <p className="stego-muted">
                * could not reach the reference rate on every image; the measured rate is shown.
                Detector: {kb.risk_table.detector}. Rebuild: <code>{kb.risk_table.command}</code>
              </p>
            </Panel>
          ) : null}

          <Panel
            title="Entries"
            meta={<span className="panel-count">{kb.entries.length} entries</span>}
          >
            <div className="kb-grid" role="tablist" aria-label="Knowledge-base entries">
              {kb.entries.map((e) => (
                <button
                  key={e.id}
                  type="button"
                  role="tab"
                  aria-selected={sel === e.id}
                  className={`kb-card ${sel === e.id ? "kb-card-on" : ""}`}
                  onClick={() => setSel(e.id)}
                  data-testid={`kb-card-${e.name}`}
                >
                  <strong>
                    {e.id}. {e.name}
                  </strong>
                  <small>{e.domain}</small>
                  <small>{e.suitable_terms.slice(0, 4).join(" · ")}</small>
                </button>
              ))}
            </div>
            {entry ? <EntryDetail e={entry} kb={kb} /> : null}
          </Panel>

          <Panel title="References">
            <DataTable label="References cited by the knowledge base">
              <thead>
                <tr>
                  <th>Id</th>
                  <th>Authors</th>
                  <th>Year</th>
                  <th>Title</th>
                  <th>Venue</th>
                  <th>DOI</th>
                  <th>Check status</th>
                  <th>Cited by</th>
                </tr>
              </thead>
              <tbody>
                {kb.references.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <code>{r.id}</code>
                    </td>
                    <td>{r.authors}</td>
                    <td>{r.year}</td>
                    <td>{r.title}</td>
                    <td>{r.venue ?? "—"}</td>
                    <td>{r.doi ? <code>{r.doi}</code> : "—"}</td>
                    <td>{r.verified ?? "—"}</td>
                    <td>
                      {kb.entries
                        .filter((e) => e.references.includes(r.id))
                        .map((e) => e.name)
                        .join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </Panel>
        </>
      ) : null}

      <Panel
        title="Recent selections"
        meta={
          <span className="panel-count">
            {events ? `${events.length} events with patch records` : ""}
          </span>
        }
      >
        {events && events.length === 0 ? (
          <Empty
            title="No selection recorded yet"
            description="Send a message in the steganography lab; every event stores the per-patch ranking."
          />
        ) : null}
        {events && events.length > 0 ? (
          <div className="form-grid stego-grid-4">
            <Field label="Event">
              <select
                className={selectClass}
                value={evSel ? String(evSel.event_id) : ""}
                onChange={(x) =>
                  setEvSel(events.find((e) => String(e.event_id) === x.target.value) ?? null)
                }
                aria-label="Event"
              >
                <option value="">Select an event</option>
                {events.map((e) => (
                  <option key={String(e.event_id)} value={String(e.event_id)}>
                    #{String(e.event_id)} · {fmtTime(e.ts_ms)} · {e.direction_label ?? ""} ·{" "}
                    {e.used_patches ?? "?"}/{e.patch_count ?? "?"} patches
                  </option>
                ))}
              </select>
            </Field>
          </div>
        ) : null}
        {evSel ? (
          <>
            <KV
              rows={[
                ["Session", <TechnicalId key="s">{evSel.session_id}</TechnicalId>],
                ["Knowledge base", evSel.kb_version ?? "n/a"],
                ["Selector", evSel.selector_version ?? "n/a"],
                ["Segmentation", evSel.segmentation_version ?? "n/a"],
                ["Refinement level", fmtNum(evSel.refinement_level)],
                ["Outcome", evSel.success ? "ok" : `failed (${evSel.error_code ?? "?"})`],
              ]}
            />
            <DataTable label="Per-patch retrieval of the selected event">
              <thead>
                <tr>
                  <th>Patch</th>
                  <th>Pixels</th>
                  <th>Query terms</th>
                  <th>Eligible ranking (best first)</th>
                  <th>Selected</th>
                  <th>KB entry</th>
                  <th>BM25</th>
                  <th>Chunk</th>
                </tr>
              </thead>
              <tbody>
                {(evSel.patches ?? []).map((p) => (
                  <tr
                    key={p.patch_id}
                    className={p.used ? "" : "stego-excluded"}
                    data-testid="monitor-row"
                  >
                    <td>#{p.patch_id}</td>
                    <td>{fmtNum(p.pixels)}</td>
                    <td>
                      {p.query_terms?.length
                        ? p.query_terms.map((t) => (
                            <span
                              key={t}
                              title={
                                rulesByTerm.get(t)
                                  ? `${rulesByTerm.get(t)?.feature} ${rulesByTerm.get(t)?.op} ${JSON.stringify(rulesByTerm.get(t)?.value)}`
                                  : undefined
                              }
                            >
                              {t}{" "}
                            </span>
                          ))
                        : "—"}
                    </td>
                    <td>{p.ranking?.join(" › ") ?? "—"}</td>
                    <td>{p.used ? <strong>{p.algorithm}</strong> : "not used"}</td>
                    <td>{p.kb_entry ?? "—"}</td>
                    <td>{isNil(p.bm25) ? "—" : fmtNum(p.bm25, 4)}</td>
                    <td>
                      {p.used ? `${fmtNum(p.payload_length)} B @ ${fmtNum(p.payload_offset)}` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </>
        ) : null}
      </Panel>

      <Panel title="Try a cover">
        <p className="stego-muted">
          Runs the real planner (segmentation, features, filters, risk ranking, allocation, dry run)
          on a freshly generated cover for a payload length (a new cover every run, under the active
          generation profile). No message is sealed and nothing is embedded or sent.
        </p>
        <div className="form-grid stego-grid-4">
          <Field label="Payload length (bytes)">
            <Input
              type="number"
              min={33}
              max={60000}
              value={payload}
              onChange={(x) => setPayload(parseInt(x.target.value, 10) || 33)}
              aria-label="Payload length"
            />
          </Field>
          <div />
          <Button onClick={() => void run()} disabled={busy}>
            <Play />
            <BusyLabel busy={busy} idle="Run retrieval" busyText="Planning" />
          </Button>
        </div>
        {preview && !preview.ok ? (
          <Notice
            tone={describeStegoError(preview.error.code).tone}
            title={`${describeStegoError(preview.error.code).title} (${preview.error.code})`}
          >
            {describeStegoError(preview.error.code, preview.error.message).text}
          </Notice>
        ) : null}
        {pv?.generation ? (
          <p className="stego-muted" data-testid="kb-cover-line">
            Cover generated for this run: {pv.generation.family ?? "n/a"} · {pv.cover?.width}×
            {pv.cover?.height} · quality score {pv.generation.quality_score ?? "n/a"} ·{" "}
            {pv.generation.candidate_count ?? "?"} candidate(s) · fingerprint{" "}
            <code>{pv.generation.seed_fingerprint ?? "n/a"}</code>. Running again generates a
            different cover.
          </p>
        ) : null}
        {ctx ? (
          <>
            <div className="patch-layout">
              <PatchOverlay ctx={ctx} selected={selPatch} onSelect={setSelPatch} />
              <div>
                <PatchInspector ctx={ctx} patch={patch} />
              </div>
            </div>
            <PatchTable ctx={ctx} selected={selPatch} onSelect={setSelPatch} />
          </>
        ) : null}
      </Panel>
    </>
  );
}
