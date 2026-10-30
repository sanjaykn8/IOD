// Algorithm Learning workbench client (EDUCATIONAL). Talks only to the gateway's
// `/api/learn/*` namespace, which never reaches the operational UAV transport.
const BASE = import.meta.env["VITE_API_BASE"] || "http://127.0.0.1:4000/api";

export interface LearnError { code: string; message: string }
export type LearnResult<T> = { ok: true; data: T } | { ok: false; error: LearnError };

export interface LearnAlgorithm { id: number; name: string; variant: string; domain: string; reference: string; coding: string; default_param: number; param_range: number[] }
export interface LearnRegistry {
  algorithms: LearnAlgorithm[]; samples: string[]; label: string; synthetic_ciphertext_hex: string; synthetic_label: string;
  sample_message: string; metric_definitions: Record<string, string>; test_only_key_notice?: string;
}
export interface LearnTable { columns: string[]; rows: (string | number | boolean | null)[][] }
export interface LearnStep {
  n: number; title: string; formula: string; substitution: string; result: string;
  table?: LearnTable; matrices?: Record<string, unknown>; note?: string;
}
export interface LearnWalkthrough {
  algorithm: string; title: string; runtime_variant: string; teaching_model: boolean; simplification: string | null;
  bit_order: string; inputs: Record<string, unknown>; steps: LearnStep[]; checks: { name: string; passed: boolean }[];
  embedded_bits: string; recovered_bits: string; exact_match: boolean; all_checks_passed: boolean; runtime_link: string;
  fixtures: { synthetic_ciphertext_hex: string; synthetic_label: string };
}
export interface LearnImage { title: string; png: string }
export interface LearnRobustness { attack: string; label: string; params: Record<string, unknown>; full_pipeline: string; oracle_ber: number; outcome: string; full_error?: string }
export interface LearnRow {
  algorithm: string; alg_id: number; variant: string; domain: string; coding: string; reference: string; status: string;
  capacity_bits_raw: number; capacity_bits_verified?: number | null; payload_bytes: number; payload_bits: number; bits_per_pixel: number;
  utilisation?: number | null; embed_ms?: number; setup_ms?: number | null; extract_ms?: number; mse?: number; psnr_db?: number | null;
  ssim?: number | null; bit_accuracy?: number; byte_accuracy?: number; ber?: number; exact_recovery?: boolean; changed_samples?: number;
  max_abs_diff?: number; error?: LearnError; extracted_hex_preview?: string; detail?: Record<string, unknown>;
  verification?: { status: string; aead_verified?: boolean; plaintext_matches?: boolean; bit_exact?: boolean; error?: string; note?: string };
  robustness?: LearnRobustness[];
  images?: { stego: string; difference_x64?: LearnImage; changed_locations?: LearnImage; specific?: LearnImage };
}
export interface LearnExperiment {
  experiment_id: string; label: string; operational: false; payload_mode: string;
  cover: { description: string; width: number; height: number; mode: string; sha256: string; png?: string; source: string };
  payload: { kind: string; bytes: number; bits: number; sha256: string; hex_preview: string; bit_order: string };
  payload_construction: Record<string, unknown>; results: LearnRow[]; attacks: { id: string; label: string; params: Record<string, unknown> }[];
  metric_definitions: Record<string, string>; interpretation: string[]; duration_ms: number; persist_error?: string;
}
export interface LearnExperimentRequest {
  algorithms: string[] | "all"; payload_mode: "aead_fixture" | "synthetic"; message?: string;
  cover: { sample: string } | { upload_b64: string }; robustness: boolean; verify_capacity: boolean; include_images: boolean;
}

async function call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<LearnResult<T>> {
  let res: Response;
  try {
    res = await fetch(`${BASE}/learn${path}`, {
      method,
      ...(body !== undefined ? { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}),
    });
  } catch (e) {
    return { ok: false, error: { code: "GATEWAY_UNREACHABLE", message: e instanceof Error ? e.message : "network error" } };
  }
  const j = (await res.json().catch(() => null)) as { ok?: boolean; error?: LearnError } | null;
  if (!res.ok || j?.ok === false || !j) return { ok: false, error: j?.error ?? { code: `HTTP_${res.status}`, message: "request failed" } };
  return { ok: true, data: j as unknown as T };
}

export const learnApi = {
  registry: () => call<LearnRegistry>("GET", "/registry"),
  walkthrough: (alg: string) => call<LearnWalkthrough>("GET", `/walkthrough/${encodeURIComponent(alg)}`),
  experiment: (req: LearnExperimentRequest) => call<LearnExperiment>("POST", "/experiment", req),
};

export async function downloadLearnExport(id: string, format: "json" | "csv" | "md"): Promise<void> {
  const res = await fetch(`${BASE}/learn/experiments/${encodeURIComponent(id)}/export?format=${format}`);
  if (!res.ok) throw new Error(`Export failed (${res.status})`);
  const href = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = href;
  a.download = `learn-${id.slice(0, 12)}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}
