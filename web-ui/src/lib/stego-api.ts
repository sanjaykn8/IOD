// Steganography Lab client. Talks ONLY to the Node gateway (`/api/stego/*`),
// which relays 1:1 to the Rust core. No keys, no policy, no crypto here.
import type {
  StegoAnalyzeResult, StegoBenchmarkRequest, StegoBenchmarkResult, StegoCameraProbe, StegoCoverRequest, StegoErrorBody, StegoEvent,
  StegoEventFilter, StegoFailure, StegoMessageResult, StegoPriority, StegoReport, StegoStage, StegoStatus,
} from "../types/api";

const BASE = import.meta.env["VITE_API_BASE"] || "http://127.0.0.1:4000/api";

export type StegoResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; error: StegoErrorBody; stages?: StegoStage[] | undefined; eventId?: string | number | undefined };

function toError(body: unknown, status: number): StegoErrorBody {
  const b = body as { error?: unknown } | null;
  const e = b?.error;
  if (e && typeof e === "object" && "code" in e) return e as StegoErrorBody;
  if (typeof e === "string") return { code: `HTTP_${status}`, message: e };
  return { code: status ? `HTTP_${status}` : "GATEWAY_UNREACHABLE", message: status ? `Request failed (${status})` : "The gateway could not be reached" };
}

async function call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<StegoResult<T>> {
  let res: Response;
  try {
    res = await fetch(`${BASE}/stego${path}`, {
      method,
      ...(body !== undefined ? { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}),
    });
  } catch (e) {
    return { ok: false, status: 0, error: { code: "GATEWAY_UNREACHABLE", message: e instanceof Error ? e.message : "Network error" } };
  }
  const json: unknown = await res.json().catch(() => null);
  const j = json as { ok?: boolean; stages?: StegoStage[]; event_id?: string | number } | null;
  if (!res.ok || j?.ok === false) {
    return { ok: false, status: res.status, error: toError(json, res.status), stages: j?.stages, eventId: j?.event_id };
  }
  return { ok: true, status: res.status, data: json as T };
}

function qs(f: StegoEventFilter): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== "" && v !== null) p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}

export interface StegoMessageRequest {
  session_id?: string; d1_id?: string; d2_id?: string; from_id: string; plaintext: string;
  algorithm?: string; cover?: StegoCoverRequest; priority?: StegoPriority;
}

export const stegoApi = {
  status: () => call<StegoStatus>("GET", "/status"),
  probeCamera: (camera_index?: number) => call<StegoCameraProbe>("POST", "/camera/probe", camera_index === undefined ? {} : { camera_index }),
  analyze: (body: { frame_bytes?: number; cover?: StegoCoverRequest; priority?: StegoPriority }) => call<StegoAnalyzeResult>("POST", "/analyze", body),
  /** Full send -> save -> receive -> verify transaction. Failures keep `stages` and `error.stage`. */
  message: (body: StegoMessageRequest) => call<StegoMessageResult>("POST", "/message", body),
  events: (f: StegoEventFilter = {}) => call<{ events: StegoEvent[] }>("GET", `/events${qs(f)}`),
  report: () => call<StegoReport>("GET", "/report?format=json"),
  benchmark: (body: StegoBenchmarkRequest) => call<StegoBenchmarkResult>("POST", "/benchmark", body),
};

export type { StegoFailure };

export const stegoUrl = {
  artifact: (id: string, kind: "stego" | "cover") => `${BASE}/stego/artifacts/${encodeURIComponent(id)}/${kind}`,
  report: (format: "json" | "csv") => `${BASE}/stego/report?format=${format}`,
};

/** Fetch a report as a Blob and trigger a browser download (works cross-origin, unlike <a download>). */
export async function downloadStegoReport(format: "json" | "csv"): Promise<void> {
  const res = await fetch(stegoUrl.report(format));
  if (!res.ok) throw new Error(`Report download failed (${res.status})`);
  const blob = await res.blob();
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = `stego-report.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}
