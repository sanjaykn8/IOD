// Segmentation overlay, patch table and patch inspector of the patch-wise Stego Lab.
// Everything shown is a value returned by the backend for THIS plan / transaction.
import { useEffect, useState } from "react";
import { ImageOff } from "lucide-react";
import { stegoUrl } from "@/lib/stego-api";
import { DataTable, Empty, Status } from "./core";
import { Bar, KV, fmtMs, fmtNum, fmtPct, isNil, num, patchColor } from "./stego-shared";
import type { EmbedPatch, ExtractedPatch, PlanPatch, StegoPlan } from "@/types/api";

export interface PatchContext {
  plan: StegoPlan;
  coverId?: string | undefined;
  width?: number | undefined;
  height?: number | undefined;
  palette?: number[][] | undefined;
  embed?: EmbedPatch[] | undefined;
  extraction?: ExtractedPatch[] | undefined;
}

/** Segmentation overlay rendered by the image service, with one selectable marker per patch (at its centroid). */
export function PatchOverlay({
  ctx,
  selected,
  onSelect,
}: {
  ctx: PatchContext;
  selected: number | null;
  onSelect: (id: number) => void;
}) {
  const [failed, setFailed] = useState(false);
  const [showIds, setShowIds] = useState(true);
  useEffect(() => setFailed(false), [ctx.coverId]);
  const patches = ctx.plan.patches ?? [];
  const w = ctx.width ?? 0,
    h = ctx.height ?? 0;
  return (
    <figure className="patch-overlay">
      <figcaption>
        Segmentation · {patches.length} patches · {ctx.plan.segmentation?.version ?? "n/a"}
        <label className="patch-toggle">
          <input type="checkbox" checked={showIds} onChange={(e) => setShowIds(e.target.checked)} />{" "}
          patch ids
        </label>
      </figcaption>
      <div className="patch-stage" style={w && h ? { aspectRatio: `${w} / ${h}` } : undefined}>
        {ctx.coverId && !failed ? (
          <img
            src={stegoUrl.artifact(ctx.coverId, "seg")}
            alt={`Cover with ${patches.length} coloured patches`}
            onError={() => setFailed(true)}
          />
        ) : (
          <div className="stego-preview-missing">
            <ImageOff aria-hidden="true" />
            <span>{ctx.coverId ? "overlay unavailable" : "no plan yet"}</span>
          </div>
        )}
        {showIds && w && h
          ? patches.map((p) => {
              const c = p.features.centroid;
              if (!c || c.length < 2) return null;
              return (
                <button
                  key={p.patch_id}
                  type="button"
                  className={`patch-marker ${selected === p.patch_id ? "patch-marker-on" : ""} ${p.used ? "" : "patch-marker-unused"}`}
                  style={{
                    top: `${((c[0] ?? 0) / h) * 100}%`,
                    left: `${((c[1] ?? 0) / w) * 100}%`,
                    borderColor: patchColor(ctx.palette, p.patch_id),
                  }}
                  onClick={() => onSelect(p.patch_id)}
                  aria-pressed={selected === p.patch_id}
                  aria-label={`Patch ${p.patch_id}${p.used ? `, ${p.selected}, ${p.payload_length} bytes` : ", not used"}`}
                  data-testid={`patch-marker-${p.patch_id}`}
                >
                  {p.patch_id}
                </button>
              );
            })
          : null}
      </div>
      <small className="stego-muted">
        Colours are the palette returned with the plan; a dimmed marker is a patch that carries no
        payload. Patches are irregular unions of {ctx.plan.segmentation?.cell_size ?? "?"}×
        {ctx.plan.segmentation?.cell_size ?? "?"} cells. The reserved carrier pixels are scattered
        and deliberately not drawn.
      </small>
    </figure>
  );
}

export function PatchTable({
  ctx,
  selected,
  onSelect,
}: {
  ctx: PatchContext;
  selected: number | null;
  onSelect: (id: number) => void;
}) {
  const patches = ctx.plan.patches ?? [];
  const emb = new Map((ctx.embed ?? []).map((e) => [e.patch_id, e]));
  const ext = new Map((ctx.extraction ?? []).map((e) => [e.patch_id, e]));
  const maxLen = Math.max(1, ...patches.map((p) => p.payload_length ?? 0));
  return (
    <DataTable label="Patches of this plan">
      <thead>
        <tr>
          <th>Patch</th>
          <th>Pixels (usable)</th>
          <th>Gradient</th>
          <th>Selected algorithm</th>
          <th>Risk tier / BM25</th>
          <th>Offset</th>
          <th>Length</th>
          <th>Capacity</th>
          <th>Embedded</th>
          <th>Extracted</th>
        </tr>
      </thead>
      <tbody>
        {patches.map((p) => {
          const top = p.retrieval?.candidates.find((c) => c.algorithm === p.selected);
          const e = emb.get(p.patch_id),
            x = ext.get(p.patch_id);
          return (
            <tr
              key={p.patch_id}
              className={`stego-row ${selected === p.patch_id ? "stego-winner" : p.used ? "" : "stego-excluded"}`}
              onClick={() => onSelect(p.patch_id)}
              tabIndex={0}
              onKeyDown={(k) => {
                if (k.key === "Enter" || k.key === " ") {
                  k.preventDefault();
                  onSelect(p.patch_id);
                }
              }}
              data-testid={`patch-row-${p.patch_id}`}
            >
              <td>
                <span
                  className="patch-swatch"
                  style={{ background: patchColor(ctx.palette, p.patch_id) }}
                  aria-hidden="true"
                />
                <strong>#{p.patch_id}</strong>
              </td>
              <td>
                {p.features.pixels}
                {p.features.usable_pixels !== p.features.pixels ? (
                  <small>{p.features.usable_pixels} usable</small>
                ) : null}
              </td>
              <td>{fmtNum(p.features.gradient_mean, 2)}</td>
              <td>
                {p.used ? (
                  <>
                    <strong>{p.selected}</strong>
                    {!isNil(p.param) && p.param !== 0 ? <small>param {p.param}</small> : null}
                  </>
                ) : (
                  <span className="stego-muted">not used</span>
                )}
              </td>
              <td>
                {top ? (
                  <>
                    <span className={`tier tier-${top.risk?.tier ?? "none"}`}>
                      {top.risk?.tier ?? "n/a"}
                    </span>
                    <small>
                      BM25 {fmtNum(top.bm25, 4)}
                      {p.retrieval?.tie ? " (tie → lower id)" : ""}
                    </small>
                  </>
                ) : (
                  "—"
                )}
              </td>
              <td>{p.used ? p.payload_offset : "—"}</td>
              <td>
                {p.used ? (
                  <div className="stego-cellbar">
                    {p.payload_length} B<Bar value={p.payload_length ?? 0} max={maxLen} />
                  </div>
                ) : (
                  "—"
                )}
              </td>
              <td>
                {p.used
                  ? `${fmtNum(p.measured_capacity_bytes)} B`
                  : `${fmtNum(p.max_capacity_bytes)} B max`}
              </td>
              <td>
                {e?.used ? (
                  <Status tone={e.extraction === "verified_from_saved_png" ? "success" : "warning"}>
                    {e.extraction === "verified_from_saved_png"
                      ? "Verified"
                      : (e.extraction ?? "Embedded")}
                  </Status>
                ) : p.used && ctx.embed ? (
                  <Status tone="danger">Missing</Status>
                ) : (
                  "—"
                )}
              </td>
              <td>
                {x ? (
                  <Status tone={x.status === "extracted" ? "success" : "danger"}>
                    {x.status === "extracted" ? "Extracted" : (x.status ?? "?")}
                  </Status>
                ) : p.used && ctx.extraction ? (
                  <Status tone="danger">Missing</Status>
                ) : (
                  "—"
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </DataTable>
  );
}

const FEATURE_ROWS: [string, string, number][] = [
  ["Mean intensity", "mean", 2],
  ["Variance", "variance", 2],
  ["Entropy (bits)", "entropy", 3],
  ["Gradient mean", "gradient_mean", 3],
  ["Gradient std", "gradient_std", 3],
  ["Edge density", "edge_density", 4],
  ["Texture", "texture", 3],
  ["Smoothness", "smoothness", 4],
  ["High-frequency energy ratio", "hf_energy_ratio", 4],
  ["AC energy", "ac_energy_mean", 2],
  ["Saturation", "saturation", 4],
  ["Compactness", "compactness", 4],
  ["Aspect ratio", "aspect_ratio", 3],
  ["8×8 block fill", "block8_fill", 4],
];

export function PatchInspector({ ctx, patch }: { ctx: PatchContext; patch: PlanPatch | null }) {
  if (!patch)
    return (
      <Empty
        title="No patch selected"
        description="Select a patch on the overlay or in the table to inspect its features and the knowledge-base retrieval that chose its algorithm."
      />
    );
  const f = patch.features;
  const r = patch.retrieval;
  const e = (ctx.embed ?? []).find((x) => x.patch_id === patch.patch_id);
  const x = (ctx.extraction ?? []).find((y) => y.patch_id === patch.patch_id);
  const maxScore = Math.max(0, ...(r?.candidates ?? []).map((c) => c.bm25));
  const bbox =
    f.bbox && f.bbox.length === 4
      ? `rows ${f.bbox[0]}–${f.bbox[2]}, cols ${f.bbox[1]}–${f.bbox[3]}`
      : "n/a";
  return (
    <div className="patch-inspector" data-testid="patch-inspector">
      <div className="stego-chips">
        <Status tone="info">
          <span
            className="patch-swatch"
            style={{ background: patchColor(ctx.palette, patch.patch_id) }}
            aria-hidden="true"
          />{" "}
          Patch {patch.patch_id}
        </Status>
        {patch.used ? (
          <Status tone="success">
            Carries {patch.payload_length} B at offset {patch.payload_offset}
          </Status>
        ) : (
          <Status tone="neutral">Not used for this payload</Status>
        )}
        {patch.used ? (
          <Status tone="neutral">
            {patch.selected}
            {!isNil(patch.param) && patch.param !== 0 ? ` · param ${patch.param}` : ""}
          </Status>
        ) : null}
        {patch.dry_run ? (
          <Status tone={patch.dry_run.ok ? "success" : "danger"}>
            dry run: {patch.dry_run.ok ? "OK" : (patch.dry_run.error ?? "Failed")} (
            {fmtMs(patch.dry_run.ms)})
          </Status>
        ) : null}
        {e?.used ? (
          <Status tone={e.extraction === "verified_from_saved_png" ? "success" : "warning"}>
            saved PNG: {e.extraction ?? "n/a"}
          </Status>
        ) : null}
        {x ? (
          <Status tone={x.status === "extracted" ? "success" : "danger"}>
            receiver: {x.status}
          </Status>
        ) : null}
      </div>
      {patch.variant ? (
        <p className="stego-muted">
          Implemented variant in this repository: <code>{patch.variant}</code>
        </p>
      ) : null}
      <div className="split-grid">
        <div className="output-block">
          <span>Geometry and mask</span>
          <KV
            rows={[
              ["Pixels", String(f.pixels)],
              ["Usable (minus carrier pixels)", String(f.usable_pixels)],
              ["Bounding box", bbox],
              ["Bounding box W × H", `${f.width ?? "n/a"} × ${f.height ?? "n/a"}`],
              ["Perimeter", fmtNum(f.perimeter)],
              [
                "Centroid (row, col)",
                f.centroid ? f.centroid.map((v) => fmtNum(v, 1)).join(", ") : "n/a",
              ],
              ["Complete 8×8 blocks", fmtNum(f.blocks8)],
              ["Complete 2×2 blocks", fmtNum(f.blocks2)],
              [
                "Mean colour",
                f.mean_rgb ? f.mean_rgb.map((v) => fmtNum(v, 0)).join(", ") : "grayscale",
              ],
            ]}
          />
        </div>
        <div className="output-block">
          <span>Feature vector</span>
          <KV
            rows={FEATURE_ROWS.map(([label, key, d]): [string, string] => [
              label,
              fmtNum(f[key], d),
            ])}
          />
        </div>
      </div>
      {f.capacity_bits ? (
        <div className="output-block">
          <span>Measured capacity per algorithm (bits, on this mask)</span>
          <KV
            rows={Object.entries(f.capacity_bits).map(([k, v]): [string, string] => [
              k,
              `${v} (${Math.floor(v / 8)} B)`,
            ])}
          />
        </div>
      ) : null}
      {r ? (
        <>
          <div className="output-block output-primary">
            <span>
              Selection · {r.kb_version} · {r.selector_version}
              {r.risk_table ? ` · ${r.risk_table}` : ""} · needs {r.required_bits} bits
            </span>
            <div className="stego-chips">
              {r.query_terms.length ? (
                r.query_terms.map((t) => (
                  <Status key={t} tone="info">
                    {t}
                  </Status>
                ))
              ) : (
                <Status tone="neutral">no descriptive term matched</Status>
              )}
            </div>
            <p className="stego-muted">
              Structured filters (operational policy, knowledge-base requirements, measured
              capacity) run first. Eligible algorithms are ranked by risk tier, changes per embedded
              bit and processing cost from the versioned risk table, then by BM25 over the query
              terms derived from the feature vector; the first one is used. No language model is
              involved.
            </p>
          </div>
          <DataTable label={`Knowledge-base entries evaluated for patch ${patch.patch_id}`}>
            <thead>
              <tr>
                <th>Rank</th>
                <th>Algorithm</th>
                <th>Filters</th>
                <th>Risk tier</th>
                <th>Changes / bit</th>
                <th>ms / KiB</th>
                <th>BM25</th>
                <th>Capacity</th>
              </tr>
            </thead>
            <tbody>
              {[...r.candidates]
                .sort((a, b) => (a.rank ?? 99) - (b.rank ?? 99) || a.alg_id - b.alg_id)
                .map((c) => {
                  const win = c.algorithm === r.selected;
                  const failed = c.filters.filter((x2) => !x2.passed);
                  return (
                    <tr
                      key={c.algorithm}
                      className={win ? "stego-winner" : c.eligible ? "" : "stego-excluded"}
                      data-testid={`kb-cand-${c.algorithm}`}
                    >
                      <td>{c.rank ?? "—"}</td>
                      <td>
                        <strong>
                          {c.algorithm}
                          {win ? <span className="stego-winner-mark"> selected</span> : null}
                        </strong>
                        <small>{c.kb_entry}</small>
                      </td>
                      <td>
                        {c.eligible ? (
                          <Status tone="success">All {c.filters.length} passed</Status>
                        ) : (
                          <>
                            <Status tone="danger">Excluded</Status>
                            {failed.map((x2) => (
                              <small key={x2.filter}>
                                {x2.filter}
                                {x2.detail ? `: ${x2.detail}` : ""}
                              </small>
                            ))}
                          </>
                        )}
                      </td>
                      <td>
                        <span className={`tier tier-${c.risk?.tier ?? "none"}`}>
                          {c.risk?.tier ?? "n/a"}
                        </span>
                        {!isNil(c.risk?.auc) ? <small>AUC {fmtNum(c.risk?.auc, 3)}</small> : null}
                      </td>
                      <td>{fmtNum(c.risk?.changes_per_bit, 3)}</td>
                      <td>{fmtNum(c.risk?.ms_per_kib, 1)}</td>
                      <td>
                        <div className="stego-cellbar">
                          {fmtNum(c.bm25, 4)}
                          <Bar value={num(c.bm25)} max={maxScore} tone={win ? "success" : "info"} />
                        </div>
                        {c.matched_terms?.length ? (
                          <small>{c.matched_terms.join(", ")}</small>
                        ) : null}
                      </td>
                      <td>{fmtNum(c.capacity_bits)} bits</td>
                    </tr>
                  );
                })}
            </tbody>
          </DataTable>
        </>
      ) : (
        <p className="stego-muted">
          No retrieval was run for this patch because it carries no payload in this plan (maximum
          admissible capacity {fmtNum(patch.max_capacity_bytes)} B).
        </p>
      )}
      {e?.used ? (
        <div className="output-block">
          <span>Embedding result for this patch</span>
          <KV
            rows={[
              ["Changed samples", fmtNum(e.changed_samples)],
              ["Patch MSE", fmtNum(e.patch_mse, 4)],
              ["Capacity", `${fmtNum(e.capacity_bytes)} B`],
              ["Utilisation", fmtPct(patch.utilisation)],
            ]}
          />
        </div>
      ) : null}
    </div>
  );
}
