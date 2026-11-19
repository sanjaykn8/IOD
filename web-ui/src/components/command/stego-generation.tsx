// Generated-cover configuration and diagnostics (shared by the Stego Lab and the Knowledge Base monitor).
// The browser can only TIGHTEN the cover-generation settings of the active resource profile; it cannot
// choose a seed, a file, a camera, an artifact or an algorithm. Everything shown here is returned by the core.
import { Input } from "@/components/ui/input";
import { DataTable, Field, Status } from "./core";
import { KV, Notice, fmtMs, fmtNum, isNil } from "./stego-shared";
import type {
  CoverGenerationRequest,
  GenerationCandidate,
  GenerationInfo,
  GeneratorConfig,
  StegoStatus,
} from "@/types/api";

export interface CoverGenForm {
  width: string;
  height: string;
  budget: string;
  candidates: string;
  resize: boolean;
}
export const EMPTY_COVER_FORM: CoverGenForm = {
  width: "",
  height: "",
  budget: "",
  candidates: "",
  resize: false,
};

type GeneratorView = NonNullable<NonNullable<StegoStatus["config"]>["cover_generation"]>;

function int(s: string): number | undefined {
  const n = parseInt(s.trim(), 10);
  return Number.isFinite(n) ? n : undefined;
}

/** Only the fields the operator changed are sent; everything else stays at the profile value. */
export function coverGenerationRequest(
  f: CoverGenForm,
  eff: GeneratorConfig | undefined,
): CoverGenerationRequest {
  const out: CoverGenerationRequest = {};
  const w = int(f.width),
    h = int(f.height),
    b = int(f.budget),
    c = int(f.candidates);
  if (w !== undefined && w !== eff?.width) out.width = w;
  if (h !== undefined && h !== eff?.height) out.height = h;
  if (b !== undefined && b !== eff?.processing_budget_ms) out.processing_budget_ms = b;
  if (c !== undefined && c !== eff?.max_candidates) out.max_candidates = c;
  if (f.resize !== !!eff?.allow_payload_driven_resize) out.allow_payload_driven_resize = f.resize;
  return out;
}

/** Client-side hints only; the core and the image service validate again and are authoritative. */
export function coverFormProblems(f: CoverGenForm, eff: GeneratorConfig | undefined): string[] {
  if (!eff) return [];
  const p: string[] = [];
  const w = int(f.width) ?? eff.width,
    h = int(f.height) ?? eff.height,
    b = int(f.budget) ?? eff.processing_budget_ms,
    c = int(f.candidates) ?? eff.max_candidates;
  if (w < 96 || w > eff.max_width || w % 8)
    p.push(`width must be a multiple of 8 within 96..${eff.max_width}`);
  if (h < 96 || h > eff.max_height || h % 8)
    p.push(`height must be a multiple of 8 within 96..${eff.max_height}`);
  if (w * h > eff.max_pixels) p.push(`width × height must not exceed ${eff.max_pixels} pixels`);
  if (b < 200 || b > eff.processing_budget_ms)
    p.push(`processing budget must be within 200..${eff.processing_budget_ms} ms`);
  if (c < 1 || c > eff.max_candidates) p.push(`candidates must be within 1..${eff.max_candidates}`);
  return p;
}

export function GeneratedCoverConfig({
  view,
  form,
  onChange,
  disabled,
}: {
  view: GeneratorView | undefined;
  form: CoverGenForm;
  onChange: (f: CoverGenForm) => void;
  disabled?: boolean;
}) {
  const eff = view?.effective;
  const problems = coverFormProblems(form, eff);
  const set = (k: keyof CoverGenForm) => (ev: { target: { value: string } }) =>
    onChange({ ...form, [k]: ev.target.value });
  return (
    <div className="stego-gen-config" data-testid="cover-generation-config">
      <h3 className="stego-h3">Generated Cover Configuration</h3>
      <div className="form-grid stego-grid-4">
        <div className="field">
          <span>Resource profile</span>
          <strong data-testid="gen-profile">{view?.active_profile ?? "n/a"}</strong>
          <small>set by the service environment; a request cannot switch it</small>
        </div>
        <Field label="Width (px)" hint={eff ? `default ${eff.width}, max ${eff.max_width}` : ""}>
          <Input
            type="number"
            step={8}
            min={96}
            max={eff?.max_width}
            value={form.width}
            placeholder={eff ? String(eff.width) : ""}
            onChange={set("width")}
            disabled={!!disabled}
            aria-label="Cover width"
          />
        </Field>
        <Field label="Height (px)" hint={eff ? `default ${eff.height}, max ${eff.max_height}` : ""}>
          <Input
            type="number"
            step={8}
            min={96}
            max={eff?.max_height}
            value={form.height}
            placeholder={eff ? String(eff.height) : ""}
            onChange={set("height")}
            disabled={!!disabled}
            aria-label="Cover height"
          />
        </Field>
        <Field label="Processing budget (ms)" hint={eff ? `max ${eff.processing_budget_ms}` : ""}>
          <Input
            type="number"
            min={200}
            max={eff?.processing_budget_ms}
            value={form.budget}
            placeholder={eff ? String(eff.processing_budget_ms) : ""}
            onChange={set("budget")}
            disabled={!!disabled}
            aria-label="Processing budget"
          />
        </Field>
        <Field label="Candidate covers" hint={eff ? `max ${eff.max_candidates}` : ""}>
          <Input
            type="number"
            min={1}
            max={eff?.max_candidates}
            value={form.candidates}
            placeholder={eff ? String(eff.max_candidates) : ""}
            onChange={set("candidates")}
            disabled={!!disabled}
            aria-label="Candidate covers"
          />
        </Field>
        <label className="field stego-check">
          <span>Payload-driven resize</span>
          <span>
            <input
              type="checkbox"
              checked={form.resize}
              onChange={(ev) => onChange({ ...form, resize: ev.target.checked })}
              disabled={!!disabled}
              aria-label="Allow payload-driven resize"
            />{" "}
            allow a larger cover (within the profile ceiling) when the message needs it
          </span>
        </label>
        <div className="field">
          <span>Quality floor / embedding-rate limit</span>
          <small>
            score ≥ {fmtNum(eff?.min_quality_score, 2)} · ≤ {fmtNum(eff?.max_embedding_rate, 2)}{" "}
            payload bits per cover sample · families: {eff?.families?.join(", ") ?? "n/a"} ·{" "}
            {eff?.mode ?? "RGB"} · memory ≤ {eff?.max_working_memory_mb ?? "n/a"} MB
          </small>
        </div>
      </div>
      {problems.length ? (
        <Notice tone="warning" title="These settings will be rejected">
          {problems.join("; ")}.
        </Notice>
      ) : null}
      <p className="stego-muted" data-testid="fresh-cover-note">
        Every transmission generates a fresh cover on this machine from operating-system randomness
        (procedural noise; no pretrained model, no network). There is no camera, upload or reusable
        cover, and no seed to choose. {view?.note ? `The profile is a ${view.note}.` : ""}
      </p>
    </div>
  );
}

const OUTCOME_TEXT: Record<string, string> = {
  selected: "selected",
  not_needed: "not needed (a better candidate fitted)",
  rejected_quality: "rejected: quality",
  capacity_insufficient: "rejected: capacity",
  no_eligible_algorithm: "rejected: no eligible algorithm",
  not_planned_budget: "not planned: budget",
  not_evaluated_budget: "not evaluated: budget",
  planning_stopped_budget: "planning stopped: budget",
};

export function CandidateTable({ candidates }: { candidates: GenerationCandidate[] }) {
  return (
    <DataTable label="Cover candidates">
      <thead>
        <tr>
          <th>#</th>
          <th>Family</th>
          <th>Size</th>
          <th>Quality score</th>
          <th>Gates</th>
          <th>Outcome</th>
          <th>Rejection reasons</th>
          <th>Capacity</th>
          <th>Generate</th>
          <th>Pre-screen</th>
          <th>Plan</th>
          <th>Seed fingerprint</th>
        </tr>
      </thead>
      <tbody>
        {candidates.map((c, i) => (
          <tr
            key={i}
            className={c.outcome === "selected" ? "" : "stego-excluded"}
            data-testid="gen-candidate"
          >
            <td>{c.index ?? i}</td>
            <td>{c.family ?? "n/a"}</td>
            <td>{isNil(c.width) ? "n/a" : `${c.width}×${c.height}`}</td>
            <td>{fmtNum(c.quality_score, 4)}</td>
            <td>
              <Status
                tone={c.gates_passed ? "success" : c.gates_passed === false ? "danger" : "neutral"}
              >
                {c.gates_passed ? "Pass" : c.gates_passed === false ? "Fail" : "n/a"}
              </Status>
            </td>
            <td>
              <Status
                tone={
                  c.outcome === "selected"
                    ? "success"
                    : c.outcome === "not_needed"
                      ? "neutral"
                      : "warning"
                }
              >
                {OUTCOME_TEXT[c.outcome ?? ""] ?? c.outcome ?? "n/a"}
              </Status>
            </td>
            <td>{c.rejection_reasons?.length ? c.rejection_reasons.join(", ") : "—"}</td>
            <td>{isNil(c.capacity_bytes) ? "—" : `${c.capacity_bytes} B`}</td>
            <td>{fmtMs(c.generate_ms)}</td>
            <td>{fmtMs(c.prescreen_ms)}</td>
            <td>{isNil(c.plan_ms) ? "—" : fmtMs(c.plan_ms)}</td>
            <td>
              <code>{c.seed_fingerprint ?? "n/a"}</code>
            </td>
          </tr>
        ))}
      </tbody>
    </DataTable>
  );
}

export function GenerationDiagnostics({ g, table = true }: { g: GenerationInfo; table?: boolean }) {
  const b = g.budget;
  return (
    <div data-testid="generation-diagnostics">
      <KV
        rows={[
          ["Generator", `${g.generator_version ?? "n/a"} · quality ${g.quality_version ?? "n/a"}`],
          ["Profile", g.profile ?? "n/a"],
          ["Family", g.family ?? "n/a"],
          ["Requested size", g.requested ? `${g.requested.width}×${g.requested.height}` : "n/a"],
          [
            "Actual size",
            g.actual
              ? `${g.actual.width}×${g.actual.height}${g.resized ? " (payload-driven resize)" : ""}`
              : "n/a",
          ],
          ["Cover quality score", fmtNum(g.quality_score, 4)],
          [
            "Candidates generated",
            `${fmtNum(g.candidate_count)} of max ${fmtNum(g.max_candidates ?? g.config?.max_candidates)}`,
          ],
          ["Planner runs", fmtNum(g.planner_invocations)],
          [
            "Generate / pre-screen / plan",
            `${fmtMs(g.timings_ms?.generate)} / ${fmtMs(g.timings_ms?.prescreen)} / ${fmtMs(g.timings_ms?.plan)}`,
          ],
          [
            "Budget used",
            b
              ? `${fmtMs(b.used_ms)} of ${fmtNum(b.limit_ms)} ms${b.exceeded ? " — Exceeded" : b.approached ? " — close to the limit" : ""}`
              : "n/a",
          ],
          [
            "Embedding rate",
            isNil(g.embedding_rate?.actual_bits_per_sample)
              ? "n/a"
              : `${fmtNum(g.embedding_rate?.actual_bits_per_sample, 4)} of ≤ ${fmtNum(g.embedding_rate?.max_embedding_rate, 2)} bits/sample`,
          ],
          [
            "Memory (preflight estimate)",
            g.memory
              ? `${fmtNum(g.memory.estimate_mb, 1)} of ${fmtNum(g.memory.limit_mb)} MB`
              : "n/a",
          ],
          ["Seed fingerprint", g.seed_fingerprint ?? "n/a"],
          ["Seeding", g.seeding ?? "n/a"],
        ]}
      />
      {b?.exceeded ? (
        <Notice tone="warning" title="Processing budget exceeded">
          Work that had already started was allowed to finish; the result is flagged instead of
          being discarded.
        </Notice>
      ) : null}
      {table && g.candidates?.length ? <CandidateTable candidates={g.candidates} /> : null}
      <p className="stego-muted">
        The quality score is a documented heuristic for natural-looking structure (variance,
        entropy, gradients, correlation, spectrum, clipping, flat areas, tiling, contrast) measured
        before embedding. It is not a steganalysis detector and says nothing about detectability.
        Only the fingerprint of the random seed is recorded.
      </p>
    </div>
  );
}
