// Every call in this file talks only to the Node.js gateway
// (`/api/...`), never directly to the Rust core or Python service —
// the gateway is the single browser-facing boundary, per the intended
// architecture (React -> Node -> Rust core / Python RAG).
import type {
  StateOverview,
  GroupView,
  DroneView,
  AuthResultView,
  ProtocolEvent,
  RagRunResult,
  Contribution,
  TraceFlag,
  TraceRecord,
} from "../types/api";

const BASE = import.meta.env["VITE_API_BASE"] || "http://127.0.0.1:4000/api";

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(`${BASE}${path}`, init);
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(json?.error || `Request failed (${res.status})`);
  }
  return json as T;
}

export const api = {
  reset: () => req<{ status: string }>("POST", "/reset"),
  getState: () => req<StateOverview>("GET", "/state"),

  createGroup: (group_id: string) => req<{ status: string }>("POST", "/groups", { group_id }),
  getGroups: () => req<{ groups: GroupView[] }>("GET", "/groups"),
  getGroup: (id: string) => req<GroupView>("GET", `/groups/${encodeURIComponent(id)}`),

  createDrone: (drone_id: string) => req<{ status: string }>("POST", "/drones", { drone_id }),
  getDrones: () => req<{ drones: DroneView[] }>("GET", "/drones"),
  registerDrone: (id: string, group_id: string, role: string) =>
    req<{ status: string; leaf_index: number }>("POST", `/drones/${encodeURIComponent(id)}/register`, { group_id, role }),
  revokeDrone: (id: string) => req<{ status: string }>("POST", `/drones/${encodeURIComponent(id)}/revoke`),
  reactivateDrone: (id: string) => req<{ status: string; leaf_index: number }>("POST", `/drones/${encodeURIComponent(id)}/reactivate`),
  moveDrone: (id: string, group_id: string) =>
    req<{ status: string; leaf_index: number }>("POST", `/drones/${encodeURIComponent(id)}/move`, { group_id }),

  authenticate: (d1_id: string, d2_id: string) =>
    req<AuthResultView>("POST", "/authenticate", { d1_id, d2_id }),
  establishGroupKey: (d1_id: string, d2_id: string, mission_id: string) =>
    req<{ status: string }>("POST", "/group-key", { d1_id, d2_id, mission_id }),
  sendSecureMessage: (from_id: string, to_id: string, plaintext: string) =>
    req<{ status: string; decrypted_by_receiver: string }>("POST", "/secure-message", { from_id, to_id, plaintext }),

  getEventsHistory: (limit = 200) => req<{ events: ProtocolEvent[] }>("GET", `/events/history?limit=${limit}`),

  ragContribute: (drone_id: string, content: string, confidence: number) =>
    req<{ status: string; contribution: Contribution }>("POST", "/rag/contribute", { drone_id, content, confidence }),
  ragRun: (query: string, top_k = 5) => req<RagRunResult>("POST", "/rag/run", { query, top_k }),
  ragState: () => req<{ contributions: Contribution[]; last_run_result: Partial<RagRunResult>; llm_provider: string }>("GET", "/rag/state"),
  ragReset: () => req<{ status: string }>("POST", "/rag/reset"),

  flagSession: (session_id: string, flagged_by: string, reason: string) =>
    req<TraceFlag>("POST", "/trace/flag", { session_id, flagged_by, reason }),
  requestTrace: (requested_by: string, requester_role: string, reason: string, target_pid_hex: string) =>
    req<TraceRecord>("POST", "/trace/request", { requested_by, requester_role, reason, target_pid_hex }),
  getTrace: () => req<{ flags: TraceFlag[]; trace_records: TraceRecord[] }>("GET", "/trace"),
};

export function streamEvents(onEvent: (ev: ProtocolEvent) => void): () => void {
  const source = new EventSource(`${BASE}/events/stream`);
  source.onmessage = (msg) => {
    try {
      onEvent(JSON.parse(msg.data));
    } catch {
      /* ignore malformed event */
    }
  };
  return () => source.close();
}
