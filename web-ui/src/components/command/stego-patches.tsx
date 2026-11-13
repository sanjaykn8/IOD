// Segmentation overlay, patch table and patch inspector of the patch-wise Stego Lab.
// Everything shown is a value returned by the backend for THIS plan / transaction.
import { useEffect, useState } from "react";
import { ImageOff } from "lucide-react";
import { stegoUrl } from "@/lib/stego-api";
import { DataTable, Empty, Status } from "./core";
import { Bar, KV, fmtMs, fmtNum, fmtPct, isNil, num, patchColor } from "./stego-shared";
import type { EmbedPatch, ExtractedPatch, PlanPatch, StegoPlan } from "@/types/api";

export interface PatchContext {
  plan: StegoPlan; coverId?: string | undefined; width?: number | undefined; height?: number | undefined; palette?: number[][] | undefined;
  embed?: EmbedPatch[] | undefined; extraction?: ExtractedPatch[] | undefined;
}

/** Segmentation overlay rendered by the image service, with one selectable marker per patch (at its centroid). */
export function PatchOverlay({ ctx, selected, onSelect }: { ctx: PatchContext; selected: number | null; onSelect: (id: number) => void }) {
  const [failed, setFailed] = useState(false);
  const [showIds, setShowIds] = useState(true);
  useEffect(() => setFailed(false), [ctx.coverId]);
  const patches = ctx.plan.patches ?? [];
  const w = ctx.width ?? 0, h = ctx.height ?? 0;
  const rr = ctx.plan.reserved_rows ?? 0;
  return (
    <figure className="patch-overlay">
      <figcaption>
        SEGMENTATION OVERLAY · {patches.length} patches · {ctx.plan.segmentation?.version ?? "n/a"}
        <label className="patch-toggle"><input type="checkbox" checked={showIds} onChange={(e) => setShowIds(e.target.checked)} /> patch ids</label>
      </figcaption>
      <div className="patch-stage" style={w && h ? { aspectRatio: `${w} / ${h}` } : undefined}>
        {ctx.coverId && !failed
          ? <img src={stegoUrl.artifact(ctx.coverId, "seg")} alt={`Cover with ${patches.length} coloured patches`} onError={() => setFailed(true)} />
          : <div className="stego-preview-missing"><ImageOff aria-hidden="true" /><span>{ctx.coverId ? "overlay unavailable" : "no plan yet"}</span></div>}
        {w && h && rr ? <span className="patch-reserved" style={{ height: `${(rr / h) * 100}%` }} title={`${rr} rows reserved for the bootstrap carrier (never part of a patch)`}>bootstrap rows</span> : null}
        {showIds && w && h ? patches.map((p) => {
          const c = p.features.centroid;
          if (!c || c.length < 2) return null;
          return (
            <button key={p.patch_id} type="button" className={`patch-marker ${selected === p.patch_id ? "patch-marker-on" : ""} ${p.used ? "" : "patch-marker-unused"}`}
              style={{ top: `${((c[0] ?? 0) / h) * 100}%`, left: `${((c[1] ?? 0) / w) * 100}%`, borderColor: patchColor(ctx.palette, p.patch_id) }}
              onClick={() => onSelect(p.patch_id)} aria-pressed={selected === p.patch_id}
              aria-label={`Patch ${p.patch_id}${p.used ? `, ${p.selected}, ${p.payload_length} bytes` : ", not used"}`} data-testid={`patch-marker-${p.patch_id}`}>
              {p.patch_id}
            </button>
          );
        }) : null}
      </div>
      <small className="stego-muted">Colours are the palette returned with the plan; a dimmed marker is a patch that carries no payload. Patches are irregular unions of {ctx.plan.segmentation?.cell_size ?? "?"}×{ctx.plan.segmentation?.cell_size ?? "?"} cells.</small>
    </figure>
  );
}

export function PatchTable({ ctx, selected, onSelect }: { ctx: PatchContext; selected: number | null; onSelect: (id: number) => void }) {
  const patches = ctx.plan.patches ?? [];
  const emb = new Map((ctx.embed ?? []).map((e) => [e.patch_id, e]));
  const ext = new Map((ctx.extraction ?? []).map((e) => [e.patch_id, e]));
  const maxLen = Math.max(1, ...patches.map((p) => p.payload_length ?? 0));
  return (
    <DataTable label="Patches of this plan">
      <thead><tr><th>Patch</th><th>Pixels (usable)</th><th>Gradient</th><th>Selected algorithm</th><th>KB entry / BM25</th><th>Offset</th><th>Length</th><th>Capacity</th><th>Embedded</th><th>Extracted</th></tr></thead>
      <tbody>{patches.map((p) => {
        const top = p.retrieval?.candidates.find((c) => c.algorithm === p.selected);
        const e = emb.get(p.patch_id), x = ext.get(p.patch_id);
        return (
          <tr key={p.patch_id} className={`stego-row ${selected === p.patch_id ? "stego-winner" : p.used ? "" : "stego-excluded"}`} onClick={() => onSelect(p.patch_id)}
            tabIndex={0} onKeyDown={(k) => { if (k.key === "Enter" || k.key === " ") { k.preventDefault(); onSelect(p.patch_id); } }} data-testid={`patch-row-${p.patch_id}`}>
            <td><span className="patch-swatch" style={{ background: patchColor(ctx.palette, p.patch_id) }} aria-hidden="true" /><strong>#{p.patch_id}</strong></td>
            <td>{p.features.pixels}{p.features.usable_pixels !== p.features.pixels ? <small>{p.features.usable_pixels} usable</small> : null}</td>
            <td>{fmtNum(p.features.gradient_mean, 2)}</td>
            <td>{p.used ? <><strong>{p.selected}</strong>{!isNil(p.param) && p.param !== 0 ? <small>param {p.param}</small> : null}</> : <span className="stego-muted">not used</span>}</td>
            <td>{top ? <><code>{top.kb_entry}</code><small>BM25 {fmtNum(top.bm25, 4)}{p.retrieval?.tie ? " (tie → lower id)" : ""}</small></> : "—"}</td>
            <td>{p.used ? p.payload_offset : "—"}</td>
            <td>{p.used ? <div className="stego-cellbar">{p.payload_length} B<Bar value={p.payload_length ?? 0} max={maxLen} /></div> : "—"}</td>
            <td>{p.used ? `${fmtNum(p.measured_capacity_bytes)} B` : `${fmtNum(p.max_capacity_bytes)} B max`}</td>
            <td>{e?.used ? <Status tone={e.extraction === "verified_from_saved_png" ? "success" : "warning"}>{e.extraction === "verified_from_saved_png" ? "VERIFIED" : (e.extraction ?? "EMBEDDED").toUpperCase()}</Status> : p.used && ctx.embed ? <Status tone="danger">MISSING</Status> : "—"}</td>
            <td>{x ? <Status tone={x.status === "extracted" ? "success" : "danger"}>{(x.status ?? "?").toUpperCase()}</Status> : p.used && ctx.extraction ? <Status tone="danger">MISSING</Status> : "—"}</td>
          </tr>
        );
      })}</tbody>
    </DataTable>
  );
}

const FEATURE_ROWS: [string, string, number][] = [
  ["MEAN INTENSITY", "mean", 2], ["VARIANCE", "variance", 2], ["ENTROPY (bits)", "entropy", 3], ["GRADIENT MEAN", "gradient_mean", 3], ["GRADIENT STD", "gradient_std", 3],
  ["EDGE DENSITY", "edge_density", 4], ["TEXTURE", "texture", 3], ["SMOOTHNESS", "smoothness", 4], ["HF ENERGY RATIO", "hf_energy_ratio", 4], ["AC ENERGY", "ac_energy_mean", 2],
  ["SATURATION", "saturation", 4], ["COMPACTNESS", "compactness", 4], ["ASPECT RATIO", "aspect_ratio", 3], ["8×8 BLOCK FILL", "block8_fill", 4],
];

export function PatchInspector({ ctx, patch }: { ctx: PatchContext; patch: PlanPatch | null }) {
  if (!patch) return <Empty title="No patch selected" description="Select a patch on the overlay or in the table to inspect its features and the knowledge-base retrieval that chose its algorithm." />;
  const f = patch.features;
  const r = patch.retrieval;
  const e = (ctx.embed ?? []).find((x) => x.patch_id === patch.patch_id);
  const x = (ctx.extraction ?? []).find((y) => y.patch_id === patch.patch_id);
  const maxScore = Math.max(0, ...(r?.candidates ?? []).map((c) => c.bm25));
  const bbox = f.bbox && f.bbox.length === 4 ? `rows ${f.bbox[0]}–${f.bbox[2]}, cols ${f.bbox[1]}–${f.bbox[3]}` : "n/a";
  return (
    <div className="patch-inspector" data-testid="patch-inspector">
      <div className="stego-chips">
        <Status tone="info"><span className="patch-swatch" style={{ background: patchColor(ctx.palette, patch.patch_id) }} aria-hidden="true" /> PATCH #{patch.patch_id}</Status>
        {patch.used ? <Status tone="success">CARRIES {patch.payload_length} B @ OFFSET {patch.payload_offset}</Status> : <Status tone="neutral">NOT USED FOR THIS PAYLOAD</Status>}
        {patch.used ? <Status tone="neutral">{patch.selected}{!isNil(patch.param) && patch.param !== 0 ? ` · param ${patch.param}` : ""}</Status> : null}
        {patch.dry_run ? <Status tone={patch.dry_run.ok ? "success" : "danger"}>dry run: {patch.dry_run.ok ? "OK" : patch.dry_run.error ?? "FAILED"} ({fmtMs(patch.dry_run.ms)})</Status> : null}
        {e?.used ? <Status tone={e.extraction === "verified_from_saved_png" ? "success" : "warning"}>saved PNG: {e.extraction ?? "n/a"}</Status> : null}
        {x ? <Status tone={x.status === "extracted" ? "success" : "danger"}>receiver: {x.status}</Status> : null}
      </div>
      {patch.variant ? <p className="stego-muted">Implemented variant in this repository: <code>{patch.variant}</code></p> : null}
      <div className="split-grid">
        <div className="output-block"><span>GEOMETRY AND MASK</span>
          <KV rows={[["PIXELS", String(f.pixels)], ["USABLE (minus bootstrap rows)", String(f.usable_pixels)], ["BOUNDING BOX", bbox], ["BBOX W × H", `${f.width ?? "n/a"} × ${f.height ?? "n/a"}`],
            ["PERIMETER", fmtNum(f.perimeter)], ["CENTROID (row, col)", f.centroid ? f.centroid.map((v) => fmtNum(v, 1)).join(", ") : "n/a"],
            ["COMPLETE 8×8 BLOCKS", fmtNum(f.blocks8)], ["COMPLETE 2×2 BLOCKS", fmtNum(f.blocks2)], ["MEAN COLOUR", f.mean_rgb ? f.mean_rgb.map((v) => fmtNum(v, 0)).join(", ") : "grayscale"]]} />
        </div>
        <div className="output-block"><span>FEATURE VECTOR</span>
          <KV rows={FEATURE_ROWS.map(([label, key, d]): [string, string] => [label, fmtNum(f[key], d)])} />
        </div>
      </div>
      {f.capacity_bits ? <div className="output-block"><span>MEASURED CAPACITY PER ALGORITHM (bits, by the implementation on this mask)</span>
        <KV rows={Object.entries(f.capacity_bits).map(([k, v]): [string, string] => [k, `${v} (${Math.floor(v / 8)} B)`])} /></div> : null}
      {r ? <>
        <div className="output-block output-primary"><span>KNOWLEDGE-BASE RETRIEVAL · {r.kb_version} · {r.selector_version} · needs {r.required_bits} bits</span>
          <div className="stego-chips">{r.query_terms.length ? r.query_terms.map((t) => <Status key={t} tone="info">{t}</Status>) : <Status tone="neutral">no descriptive term matched</Status>}</div>
          <p className="stego-muted">Query terms are derived from the feature vector by the knowledge base&apos;s threshold rules. Structured filters run first; only eligible entries are ranked by BM25 and the top-1 is used. No language model is involved.</p>
        </div>
        <DataTable label={`Knowledge-base entries evaluated for patch ${patch.patch_id}`}>
          <thead><tr><th>Rank</th><th>Algorithm</th><th>KB entry</th><th>Structured filters</th><th>Matched terms</th><th>BM25 score</th><th>Measured capacity</th></tr></thead>
          <tbody>{[...r.candidates].sort((a, b) => (a.rank ?? 99) - (b.rank ?? 99) || a.alg_id - b.alg_id).map((c) => {
            const win = c.algorithm === r.selected;
            const failed = c.filters.filter((x2) => !x2.passed);
            return (
              <tr key={c.algorithm} className={win ? "stego-winner" : c.eligible ? "" : "stego-excluded"} data-testid={`kb-cand-${c.algorithm}`}>
                <td>{c.rank ?? "—"}</td>
                <td><strong>{c.algorithm}{win ? <span className="stego-winner-mark"> ★ SELECTED</span> : null}</strong></td>
                <td><code>{c.kb_entry}</code></td>
                <td>{c.eligible ? <Status tone="success">ALL {c.filters.length} PASSED</Status> : <><Status tone="danger">EXCLUDED</Status>{failed.map((x2) => <small key={x2.filter}>{x2.filter}{x2.detail ? `: ${x2.detail}` : ""}</small>)}</>}</td>
                <td>{c.matched_terms?.length ? c.matched_terms.join(", ") : "—"}</td>
                <td><div className="stego-cellbar">{fmtNum(c.bm25, 4)}<Bar value={num(c.bm25)} max={maxScore} tone={win ? "success" : "info"} /></div></td>
                <td>{fmtNum(c.capacity_bits)} bits</td>
              </tr>
            );
          })}</tbody>
        </DataTable>
      </> : <p className="stego-muted">No retrieval was run for this patch because it carries no payload in this plan (maximum admissible capacity {fmtNum(patch.max_capacity_bytes)} B).</p>}
      {e?.used ? <div className="output-block"><span>EMBEDDING RESULT FOR THIS PATCH</span>
        <KV rows={[["CHANGED SAMPLES", fmtNum(e.changed_samples)], ["PATCH MSE", fmtNum(e.patch_mse, 4)], ["CAPACITY", `${fmtNum(e.capacity_bytes)} B`], ["UTILISATION", fmtPct(patch.utilisation)]]} /></div> : null}
    </div>
  );
}
