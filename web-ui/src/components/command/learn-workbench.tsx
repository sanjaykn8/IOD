// Algorithm Learning — Worked Calculations and Experiments (EDUCATIONAL ONLY).
// Separate state, API namespace (/api/learn/*) and labels from the operational UAV flow.
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { BookOpen, ChevronDown, ChevronRight, Download, FlaskConical, GraduationCap, Play, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { BusyLabel, DataTable, Empty, Field, Panel, Status, selectClass } from "./core";
import {
  downloadLearnExport, learnApi, type LearnExperiment, type LearnExperimentRequest, type LearnRegistry, type LearnRow,
  type LearnStep, type LearnWalkthrough,
} from "@/lib/learn-api";

const SAMPLE_LABELS: Record<string, string> = {
  natural_rgb_256: "Natural-looking RGB 256×256 (generated)",
  natural_gray_256: "Natural-looking grayscale 256×256 (generated)",
  gray_64: "Small grayscale 64×64 (generated)",
  bw_procedural_256: "Black-and-white procedural 256×256 (operational fallback generator)",
};
const ALG_ORDER = ["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct", "dwt", "dct_svd", "hugo", "wow", "s_uniward"];

const fmt = (v: unknown, d = 3): string => {
  if (v === null || v === undefined) return "n/a";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(d);
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
};

function EduBanner() {
  return (
    <div className="notice notice-warning learn-banner" role="note">
      <GraduationCap aria-hidden="true" />
      <div>
        <strong>Educational experiment — not a live UAV transmission</strong>
        <p>Nothing on this tab touches authentication, group keys, sequence numbers, the operational image transport or its event log.
          Experiments run the same tested algorithm library in isolation; the “readable message” mode uses the production AEAD code path
          with a <b>test-only key</b> derived from a public label (never an operational key, never displayed).</p>
      </div>
    </div>
  );
}

function Matrix({ name, data }: { name: string; data: unknown }) {
  if (!Array.isArray(data)) return <div className="learn-matrix"><span>{name}</span><code>{JSON.stringify(data)}</code></div>;
  const rows = (Array.isArray(data[0]) ? data : [data]) as unknown[][];
  return (
    <div className="learn-matrix">
      <span>{name}</span>
      <table><tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{fmt(c, 3)}</td>)}</tr>)}</tbody></table>
    </div>
  );
}

function StepView({ s, open }: { s: LearnStep; open: boolean }) {
  const [show, setShow] = useState(open);
  useEffect(() => setShow(open), [open]);
  const hasDetail = !!s.table || !!s.matrices;
  return (
    <li className="learn-step" data-testid={`learn-step-${s.n}`}>
      <div className="learn-step-head"><span className="learn-step-n">Step {s.n}</span><strong>{s.title}</strong></div>
      <dl className="learn-step-body">
        <div><dt>Formula</dt><dd><code>{s.formula}</code></dd></div>
        <div><dt>Substituted values</dt><dd><code>{s.substitution}</code></dd></div>
        <div><dt>Result</dt><dd><code>{s.result}</code></dd></div>
      </dl>
      {s.note ? <p className="stego-muted">{s.note}</p> : null}
      {hasDetail ? (
        <>
          <button type="button" className="learn-toggle" onClick={() => setShow(!show)} aria-expanded={show}>
            {show ? <ChevronDown aria-hidden="true" /> : <ChevronRight aria-hidden="true" />} {show ? "Hide" : "Show"} detailed calculations
          </button>
          {show ? (
            <div className="learn-detail">
              {s.table ? (
                <DataTable label={`Step ${s.n} table`}>
                  <thead><tr>{s.table.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
                  <tbody>{s.table.rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{fmt(c, 4)}</td>)}</tr>)}</tbody>
                </DataTable>
              ) : null}
              {s.matrices ? <div className="learn-matrices">{Object.entries(s.matrices).map(([k, v]) => <Matrix key={k} name={k} data={v} />)}</div> : null}
            </div>
          ) : null}
        </>
      ) : null}
    </li>
  );
}

function WalkthroughView({ alg }: { alg: string }) {
  const [wt, setWt] = useState<LearnWalkthrough | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [allOpen, setAllOpen] = useState(false);
  useEffect(() => {
    let live = true;
    setWt(null); setErr(null);
    void learnApi.walkthrough(alg).then((r) => { if (live) { if (r.ok) setWt(r.data); else setErr(`${r.error.code}: ${r.error.message}`); } });
    return () => { live = false; };
  }, [alg]);
  if (err) return <div className="notice notice-danger" role="alert"><div><strong>Walkthrough unavailable</strong><p>{err}</p></div></div>;
  if (!wt) return <p className="stego-muted">Loading worked example…</p>;
  return (
    <div data-testid="learn-walkthrough">
      <div className="learn-wt-head">
        <div><h3>{wt.title}</h3><small>Runtime variant: {wt.runtime_variant} · bit order {wt.bit_order}</small></div>
        <div className="button-row">
          <Status tone={wt.exact_match ? "success" : "danger"}>{wt.exact_match ? "EXACT MATCH" : "MISMATCH"}</Status>
          <Status tone={wt.all_checks_passed ? "success" : "danger"}>{wt.checks.filter((c) => c.passed).length}/{wt.checks.length} checks</Status>
          <Button variant="outline" size="sm" onClick={() => setAllOpen(!allOpen)}>{allOpen ? "Collapse" : "Expand"} all calculations</Button>
        </div>
      </div>
      {wt.teaching_model ? (
        <div className="notice notice-info" role="note"><BookOpen aria-hidden="true" /><div><strong>Teaching model — simplified illustration</strong><p>{wt.simplification}</p></div></div>
      ) : null}
      <ol className="learn-steps">{wt.steps.map((s) => <StepView key={s.n} s={s} open={allOpen} />)}</ol>
      <dl className="stego-kv">
        <div><dt>EMBEDDED BITS</dt><dd>{wt.embedded_bits}</dd></div>
        <div><dt>RECOVERED BITS</dt><dd>{wt.recovered_bits}</dd></div>
        <div><dt>PAYLOAD FIXTURE</dt><dd>{wt.fixtures.synthetic_ciphertext_hex} (synthetic)</dd></div>
      </dl>
      <p className="stego-muted">{wt.fixtures.synthetic_label}. {wt.runtime_link}</p>
    </div>
  );
}

/** Image with click-to-inspect pixel values (and the same pixel in a paired image). */
function Inspectable({ src, pair, label, testid }: { src: string; pair?: string | undefined; label: string; testid?: string }) {
  const [zoom, setZoom] = useState(false);
  const [info, setInfo] = useState<string | null>(null);
  const ref = useRef<HTMLImageElement>(null);
  function read(url: string, x: number, y: number): Promise<number[]> {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        const c = document.createElement("canvas");
        c.width = img.naturalWidth; c.height = img.naturalHeight;
        const ctx = c.getContext("2d");
        if (!ctx) return resolve([]);
        ctx.drawImage(img, 0, 0);
        resolve(Array.from(ctx.getImageData(x, y, 1, 1).data.slice(0, 3)));
      };
      img.src = url;
    });
  }
  async function onClick(ev: React.MouseEvent<HTMLImageElement>) {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const x = Math.floor(((ev.clientX - r.left) / r.width) * el.naturalWidth);
    const y = Math.floor(((ev.clientY - r.top) / r.height) * el.naturalHeight);
    const a = await read(src, x, y);
    const b = pair ? await read(pair, x, y) : null;
    setInfo(`(${x}, ${y}) = [${a.join(", ")}]${b ? ` · paired [${b.join(", ")}] Δ [${a.map((v, i) => (b[i] ?? 0) - v).join(", ")}]` : ""}`);
  }
  return (
    <figure className="stego-preview learn-figure" data-testid={testid}>
      <figcaption>{label} <button type="button" className="learn-toggle" onClick={() => setZoom(!zoom)}>{zoom ? "1×" : "zoom 3×"}</button></figcaption>
      <div className={zoom ? "learn-zoom" : ""}><img ref={ref} src={src} alt={label} onClick={(e) => void onClick(e)} style={zoom ? { width: "300%", maxWidth: "none" } : undefined} /></div>
      <small className="stego-muted">{info ?? "click a pixel to inspect its value"}</small>
    </figure>
  );
}

function RowDetail({ row, cover }: { row: LearnRow; cover?: string | undefined }) {
  const v = row.verification;
  return (
    <div className="learn-row-detail" data-testid={`learn-detail-${row.algorithm}`}>
      <div className="learn-wt-head">
        <div><h3>{row.algorithm}</h3><small>{row.variant} · {row.domain} · coding: {row.coding}</small></div>
        <div className="button-row">
          <Status tone={row.status === "ok" ? "success" : "warning"}>{row.status.toUpperCase()}</Status>
          {v ? <Status tone={v.status === "aead_verified" ? "success" : v.status === "not_applicable_synthetic" ? "info" : "danger"}>{v.status.replace(/_/g, " ").toUpperCase()}</Status> : null}
        </div>
      </div>
      {row.error ? <p className="stego-muted">{row.error.code}: {row.error.message}</p> : null}
      {row.images ? (
        <div className="learn-images">
          {cover ? <Inspectable src={cover} pair={row.images.stego} label="Cover" /> : null}
          <Inspectable src={row.images.stego} pair={cover} label="Stego (saved PNG)" testid={`learn-stego-${row.algorithm}`} />
          {row.images.difference_x64 ? <Inspectable src={row.images.difference_x64.png} label={row.images.difference_x64.title} /> : null}
          {row.images.changed_locations ? <Inspectable src={row.images.changed_locations.png} label={row.images.changed_locations.title} /> : null}
          {row.images.specific ? <Inspectable src={row.images.specific.png} label={row.images.specific.title} /> : null}
        </div>
      ) : null}
      <dl className="stego-kv">
        {([
          ["CAPACITY (RAW / VERIFIED)", `${fmt(row.capacity_bits_raw)} / ${fmt(row.capacity_bits_verified)} bits`],
          ["PAYLOAD", `${row.payload_bytes} B = ${row.payload_bits} bits · ${fmt(row.bits_per_pixel, 6)} bpp`],
          ["MSE", fmt(row.mse, 6)], ["PSNR", row.psnr_db === null && row.status === "ok" ? "∞ (identical)" : `${fmt(row.psnr_db, 3)} dB`],
          ["SSIM", fmt(row.ssim, 6)], ["EMBED", `${fmt(row.embed_ms, 2)} ms${row.setup_ms ? ` (cost map ${fmt(row.setup_ms, 1)} ms)` : ""}`],
          ["EXTRACT", `${fmt(row.extract_ms, 2)} ms`], ["BIT ACCURACY", fmt(row.bit_accuracy, 6)], ["BER", fmt(row.ber, 6)],
          ["CHANGED SAMPLES", fmt(row.changed_samples)], ["EXTRACTED (HEX)", row.extracted_hex_preview ?? "n/a"],
          ["AEAD", v?.status === "aead_verified" ? `verified · plaintext matches: ${fmt(v.plaintext_matches)}` : v?.status === "not_applicable_synthetic" ? "not applicable (synthetic bytes)" : (v?.error ?? v?.status ?? "n/a")],
        ] as [string, ReactNode][]).map(([k, val]) => <div key={k}><dt>{k}</dt><dd>{val}</dd></div>)}
      </dl>
      {row.robustness ? (
        <DataTable label={`Robustness of ${row.algorithm}`}>
          <thead><tr><th>Attack</th><th>Parameters</th><th>Full pipeline</th><th>Oracle BER</th><th>Outcome</th></tr></thead>
          <tbody>{row.robustness.map((r) => <tr key={r.attack}><td>{r.label}</td><td><code>{JSON.stringify(r.params)}</code></td><td>{r.full_pipeline}{r.full_error ? <small>{r.full_error}</small> : null}</td><td>{fmt(r.oracle_ber, 4)}</td><td>{r.outcome}</td></tr>)}</tbody>
        </DataTable>
      ) : null}
    </div>
  );
}

function ComparisonTable({ exp, pick, picked }: { exp: LearnExperiment; pick: (a: string) => void; picked: string | null }) {
  const attacks = exp.results.find((r) => r.robustness)?.robustness?.map((r) => r.attack) ?? [];
  return (
    <>
      <DataTable label="Comparison of all algorithms">
        <thead><tr><th>Algorithm</th><th>Status</th><th>Capacity raw / verified (bits)</th><th>bpp</th><th>MSE</th><th>PSNR dB</th><th>SSIM</th><th>Embed ms</th><th>Extract ms</th><th>Bit acc.</th><th>BER</th><th>Verification</th></tr></thead>
        <tbody>{exp.results.map((r) => (
          <tr key={r.algorithm} className={picked === r.algorithm ? "stego-winner" : r.status === "ok" ? "" : "stego-excluded"} data-testid={`learn-cmp-${r.algorithm}`}>
            <td><button type="button" className="learn-link" onClick={() => pick(r.algorithm)}>{r.algorithm}</button><small className="stego-variant">{r.variant}</small></td>
            <td>{r.status}{r.error ? <small>{r.error.code}</small> : null}</td><td>{fmt(r.capacity_bits_raw)} / {fmt(r.capacity_bits_verified)}</td>
            <td>{fmt(r.bits_per_pixel, 5)}</td><td>{fmt(r.mse, 5)}</td><td>{r.psnr_db === null && r.status === "ok" ? "∞" : fmt(r.psnr_db, 2)}</td>
            <td>{fmt(r.ssim, 5)}</td><td>{fmt(r.embed_ms, 1)}</td><td>{fmt(r.extract_ms, 1)}</td><td>{fmt(r.bit_accuracy, 4)}</td><td>{fmt(r.ber, 4)}</td>
            <td>{r.verification?.status?.replace(/_/g, " ") ?? "n/a"}</td>
          </tr>))}</tbody>
      </DataTable>
      {attacks.length ? (
        <DataTable label="Robustness matrix">
          <thead><tr><th>Algorithm</th>{attacks.map((a) => <th key={a}>{a}</th>)}</tr></thead>
          <tbody>{exp.results.filter((r) => r.robustness).map((r) => (
            <tr key={r.algorithm}><td>{r.algorithm}</td>{(r.robustness ?? []).map((x) => (
              <td key={x.attack} className={`learn-rob learn-rob-${x.outcome}`} title={`oracle BER ${x.oracle_ber}`}>{x.outcome === "recovered" ? "✓" : x.outcome === "failed" ? "✗" : x.outcome === "recovered_oracle_only" ? "◐" : "~"} <small>{fmt(x.oracle_ber, 2)}</small></td>))}</tr>))}</tbody>
        </DataTable>
      ) : null}
      {attacks.length ? <p className="stego-muted">✓ full pipeline (bootstrap + payload) recovered the exact payload · ◐ exact only with known parameters (bootstrap lost) · ~ partial (oracle BER ≤ 0.1) · ✗ failed (BER ≈ 0.5 is chance level, i.e. no information). Oracle BER = direct extraction with the known algorithm, length and parameter. No failure is repaired or hidden.</p> : null}
    </>
  );
}

export function LearningWorkbench() {
  const [reg, setReg] = useState<LearnRegistry | null>(null);
  const [regErr, setRegErr] = useState<string | null>(null);
  const [alg, setAlg] = useState("dwt");
  const [view, setView] = useState<"math" | "run" | "compare">("math");
  const [mode, setMode] = useState<"aead_fixture" | "synthetic">("aead_fixture");
  const [message, setMessage] = useState("");
  const [sample, setSample] = useState("natural_rgb_256");
  const [upload, setUpload] = useState<string | null>(null);
  const [robust, setRobust] = useState(true);
  const [verifyCap, setVerifyCap] = useState(true);
  const [busy, setBusy] = useState(false);
  const [exp, setExp] = useState<LearnExperiment | null>(null);
  const [expErr, setExpErr] = useState<string | null>(null);
  const [picked, setPicked] = useState<string | null>(null);

  useEffect(() => {
    void learnApi.registry().then((r) => {
      if (r.ok) { setReg(r.data); setMessage(r.data.sample_message); } else setRegErr(`${r.error.code}: ${r.error.message}`);
    });
  }, []);
  const algInfo = useMemo(() => reg?.algorithms.find((a) => a.name === alg), [reg, alg]);

  async function onUpload(f: File | undefined) {
    if (!f) return;
    if (f.type !== "image/png") { setExpErr("Only PNG covers are accepted (lossless)."); return; }
    const buf = new Uint8Array(await f.arrayBuffer());
    let s = "";
    for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
    setUpload(btoa(s));
  }

  async function run(all: boolean) {
    setBusy(true); setExpErr(null);
    const req: LearnExperimentRequest = {
      algorithms: all ? "all" : [alg], payload_mode: mode, ...(mode === "aead_fixture" ? { message } : {}),
      cover: upload ? { upload_b64: upload } : { sample }, robustness: robust, verify_capacity: verifyCap, include_images: true,
    };
    const r = await learnApi.experiment(req);
    setBusy(false);
    if (r.ok) { setExp(r.data); setPicked(all ? null : alg); } else setExpErr(`${r.error.code}: ${r.error.message}`);
  }

  const pickedRow = exp?.results.find((r) => r.algorithm === picked) ?? (exp && exp.results.length === 1 ? exp.results[0] : undefined);
  const pc = exp?.payload_construction as Record<string, unknown> | undefined;

  return (
    <div className="learn-root" data-testid="learning-workbench">
      <EduBanner />
      {regErr ? <div className="notice notice-danger" role="alert"><div><strong>Learning service unavailable</strong><p>{regErr}</p></div></div> : null}

      <Panel title="A / Choose an algorithm" meta={<Status tone="info">10 ALGORITHMS</Status>}>
        <div className="learn-alg-grid" role="radiogroup" aria-label="Algorithm">
          {ALG_ORDER.map((a) => (
            <button key={a} type="button" role="radio" aria-label={a} aria-checked={alg === a} className={`learn-alg ${alg === a ? "learn-alg-on" : ""}`} onClick={() => setAlg(a)}>
              <strong>{a}</strong><small>{reg?.algorithms.find((x) => x.name === a)?.domain ?? ""}</small>
            </button>
          ))}
        </div>
        {algInfo ? <dl className="stego-kv learn-kv"><div><dt>VARIANT</dt><dd>{algInfo.variant}</dd></div><div><dt>CODING</dt><dd>{algInfo.coding}</dd></div><div><dt>REFERENCE</dt><dd>{algInfo.reference}</dd></div></dl> : null}
        <div className="learn-tabs" role="tablist" aria-label="Learning views">
          {([["math", "Walk me through the mathematics"], ["run", "Run actual example"], ["compare", "Compare all ten"]] as const).map(([k, l]) => (
            <button key={k} type="button" role="tab" aria-selected={view === k} className={`learn-tab ${view === k ? "learn-tab-on" : ""}`} onClick={() => setView(k)}>{l}</button>
          ))}
        </div>
      </Panel>

      {view === "math" ? (
        <Panel title="B / Worked calculation (small fixed values)" meta={<Status tone="neutral">DETERMINISTIC</Status>}>
          <WalkthroughView alg={alg} />
        </Panel>
      ) : (
        <Panel title={view === "run" ? `B / Run actual example — ${alg}` : "B / Compare all ten on the same cover and payload"} meta={<Status tone="warning">EDUCATIONAL EXPERIMENT</Status>}>
          <div className="form-grid stego-grid-4">
            <Field label="Payload">
              <select className={selectClass} value={mode} onChange={(e) => setMode(e.target.value as typeof mode)} aria-label="Payload mode">
                <option value="aead_fixture">Readable message → real AEAD encryption (test-only key)</option>
                <option value="synthetic">Synthetic ciphertext fixture A6 3C 91 5E</option>
              </select>
            </Field>
            <Field label="Cover">
              <select className={selectClass} value={upload ? "__upload" : sample} onChange={(e) => { if (e.target.value !== "__upload") { setUpload(null); setSample(e.target.value); } }} aria-label="Sample cover">
                {(reg?.samples ?? Object.keys(SAMPLE_LABELS)).map((s) => <option key={s} value={s}>{SAMPLE_LABELS[s] ?? s}</option>)}
                {upload ? <option value="__upload">Uploaded PNG</option> : null}
              </select>
            </Field>
            <label className="field"><span>Upload test image (PNG ≤ 512×512)</span><span className="learn-upload"><Upload aria-hidden="true" /><input type="file" accept="image/png" onChange={(e) => void onUpload(e.target.files?.[0])} aria-label="Upload test PNG" /></span></label>
            <div className="field"><span>Options</span>
              <label className="learn-check"><input type="checkbox" checked={robust} onChange={(e) => setRobust(e.target.checked)} /> robustness attack suite</label>
              <label className="learn-check"><input type="checkbox" checked={verifyCap} onChange={(e) => setVerifyCap(e.target.checked)} /> verify capacity</label>
            </div>
          </div>
          {mode === "aead_fixture" ? <Field label="Readable sample message (serialised as UTF-8, then sealed)"><Textarea rows={4} value={message} onChange={(e) => setMessage(e.target.value)} aria-label="Sample message" /></Field>
            : <p className="stego-muted">{reg?.synthetic_label ?? "Synthetic bytes for bit-level illustration; not a real ciphertext."}</p>}
          <div className="button-row">
            {view === "run"
              ? <Button disabled={busy || (mode === "aead_fixture" && !message)} onClick={() => void run(false)}><Play /><BusyLabel busy={busy} idle={`Run ${alg} example`} busyText="Embedding, saving PNG, extracting" /></Button>
              : <Button disabled={busy || (mode === "aead_fixture" && !message)} onClick={() => void run(true)}><FlaskConical /><BusyLabel busy={busy} idle="Compare all ten" busyText="Running ten algorithms" /></Button>}
            {exp ? (["json", "csv", "md"] as const).map((f) => <Button key={f} variant="outline" size="sm" onClick={() => void downloadLearnExport(exp.experiment_id, f).catch((e: Error) => setExpErr(e.message))}><Download />{f.toUpperCase()}</Button>) : null}
          </div>
          {expErr ? <div className="notice notice-danger" role="alert"><div><strong>Experiment failed</strong><p>{expErr}</p></div></div> : null}
          {!exp ? <Empty title="No experiment yet" description="Run an example to see the cover, stego image, difference and algorithm-specific maps, metrics and verification." /> : (
            <div className="learn-results" data-testid="learn-results">
              <dl className="stego-kv learn-kv">
                <div><dt>EXPERIMENT</dt><dd>{exp.experiment_id.slice(0, 16)}…</dd></div>
                <div><dt>COVER</dt><dd>{exp.cover.description} · {exp.cover.width}×{exp.cover.height} {exp.cover.mode}</dd></div>
                <div><dt>PAYLOAD</dt><dd>{exp.payload.bytes} B = {exp.payload.bits} bits ({exp.payload.kind}) · {exp.payload.bit_order}</dd></div>
                <div><dt>PAYLOAD HEX</dt><dd>{exp.payload.hex_preview}</dd></div>
                {exp.payload_mode === "aead_fixture" && pc ? <>
                  <div><dt>PLAINTEXT</dt><dd>{fmt(pc["plaintext_bytes"])} bytes</dd></div>
                  <div><dt>ENCRYPTED WIRE</dt><dd>{fmt(pc["wire_bytes"])} bytes ({fmt(pc["appwire_header_bytes"])}-byte header + ciphertext incl. {fmt(pc["aead_tag_bytes"])}-byte tag)</dd></div>
                  <div><dt>WIRE (BINARY, FIRST BYTES)</dt><dd>{fmt(pc["wire_binary_preview"])}</dd></div>
                  <div><dt>KEY</dt><dd>{fmt(pc["key"])}</dd></div>
                </> : null}
                <div><dt>DURATION</dt><dd>{fmt(exp.duration_ms, 0)} ms</dd></div>
              </dl>
              {exp.payload_mode === "aead_fixture" && pc ? <p className="stego-muted">{fmt(pc["note"])}</p> : null}
              {exp.results.length > 1 ? <ComparisonTable exp={exp} pick={setPicked} picked={picked} /> : null}
              {pickedRow ? <RowDetail row={pickedRow} cover={exp.cover.png} /> : exp.results.length > 1 ? <p className="stego-muted">Select an algorithm in the table for its images, maps and robustness details.</p> : null}
              <div className="notice notice-info" role="note"><BookOpen aria-hidden="true" /><div><strong>How to read these numbers</strong><p>{exp.interpretation.join(" ")}</p></div></div>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
