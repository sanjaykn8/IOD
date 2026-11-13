// Small presentational helpers shared by the patch-wise Stego Lab and the Knowledge Base monitor.
// They only format values that came from the backend; a missing value is shown as "n/a".
import { useEffect, useState, type ReactNode } from "react";
import { ImageOff, Info } from "lucide-react";
import { stegoUrl, type ArtifactKind } from "@/lib/stego-api";
import { Status, type Tone } from "./core";
import type { StegoNum } from "@/types/api";

export const isNil = (v: unknown): v is null | undefined => v === null || v === undefined;
export function fmtNum(v: unknown, digits = 3, unit = ""): string {
  if (isNil(v)) return "n/a";
  if (typeof v === "string") return /^[+]?inf(inity)?$/i.test(v) ? "∞ (identical)" : v;
  if (typeof v !== "number") return String(v);
  if (!Number.isFinite(v)) return v > 0 ? "∞ (identical)" : "n/a";
  return `${Number.isInteger(v) ? v : v.toFixed(digits)}${unit}`;
}
/** Quality metrics: a null means "undefined" in the core's sense -- never substitute a number. */
export function fmtMetric(v: StegoNum, digits = 3, unit = ""): string {
  return isNil(v) ? "undefined" : fmtNum(v, digits, unit);
}
export const fmtPct = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? `${(v * 100).toFixed(1)}%` : "n/a");
export const fmtMs = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? `${v < 10 ? v.toFixed(2) : v.toFixed(1)} ms` : "n/a");
export const fmtTime = (ms?: number) => (typeof ms === "number" ? new Date(ms).toLocaleString() : "n/a");
export const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
export const short = (s?: string | null, n = 8) => (s ? (s.length > n ? `${s.slice(0, n)}…` : s) : "—");
export const ALGORITHMS = ["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct", "dwt", "dct_svd", "hugo", "wow", "s_uniward"] as const;

export function Bar({ value, max, tone = "info" }: { value: number | null; max: number; tone?: Tone }) {
  const pct = value === null || max <= 0 ? 0 : Math.max(0, Math.min(100, (value / max) * 100));
  return <span className={`stego-bar stego-bar-${tone}`} aria-hidden="true"><i style={{ width: `${pct}%` }} /></span>;
}
export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="stego-kv">{rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>;
}
export function Notice({ tone, title, children }: { tone: "danger" | "warning" | "info"; title: string; children: ReactNode }) {
  return <div className={`notice notice-${tone === "info" ? "info" : tone}`} role={tone === "danger" ? "alert" : "status"}><Info aria-hidden="true" /><div><strong>{title}</strong><p>{children}</p></div></div>;
}
export function Flag({ label, v }: { label: string; v: boolean | null | undefined }) {
  return <Status tone={v === true ? "success" : v === false ? "danger" : "neutral"}>{label}: {v === true ? "OK" : v === false ? "FAILED" : "n/a"}</Status>;
}
export function Preview({ id, kind, label, note }: { id?: string | undefined; kind: ArtifactKind; label: string; note?: string }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [id, kind]);
  return (
    <figure className="stego-preview">
      <figcaption>{label}</figcaption>
      {id && !failed
        ? <img src={stegoUrl.artifact(id, kind)} alt={`${label} image`} onError={() => setFailed(true)} />
        : <div className="stego-preview-missing"><ImageOff aria-hidden="true" /><span>{id ? "preview unavailable (image failed to load)" : "no image yet"}</span></div>}
      {note ? <small className="stego-muted">{note}</small> : null}
    </figure>
  );
}
/** rgb() string for a patch from the palette the backend returned (falls back to a neutral grey). */
export function patchColor(palette: number[][] | undefined, id: number): string {
  const c = palette?.[id];
  return c && c.length >= 3 ? `rgb(${c[0]}, ${c[1]}, ${c[2]})` : "rgb(140,140,140)";
}
