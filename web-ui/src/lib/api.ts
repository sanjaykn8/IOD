export interface DroneView {
  drone_id: string;
  group_id: string | null;
  registered: boolean;
  active: boolean;
  revoked_flag: boolean;
  crypto_suite: string | null;
  kem_pk_fingerprint: string | null;
  sig_pk_fingerprint: string | null;
  role: string | null;
  leaf_index: number | null;
  cached_root_hex: string | null;
  cached_version: number | null;
}
export interface GroupView {
  group_id: string;
  root_hex: string;
  version: number;
  capacity: number;
  active_members: string[];
}
export interface AuthResultView {
  session_id: string;
  freshness_ok: boolean;
  credential_ok?: boolean;
  commitment_ok?: boolean;
  session_binding_ok?: boolean;
  authenticated?: boolean;
  zk_membership_ok: boolean;
  signature_ok: boolean;
  puf_ok: boolean;
  root_version_ok: boolean;
  decision: "ALLOW" | "DENY";
  reason_code: string;
}
export interface ProtocolEvent {
  session_id: string;
  stage: string;
  sender: string;
  receiver: string;
  timestamp_unix_ms: number;
  status: "Info" | "Ok" | "Fail";
  detail: string;
}
export interface StateOverview {
  group_count: number;
  drone_count: number;
  groups: GroupView[];
  drones: DroneView[];
  event_count: number;
}
export interface SuiteSizes {
  public_key: number;
  private_key_expanded: number;
  private_key_seed: number;
  ciphertext?: number;
  shared_secret?: number;
  signature?: number;
}
export interface CryptoSuite {
  suite_id: string;
  kem: string;
  kem_implementation: string;
  signature: string;
  signature_implementation: string;
  signature_mode: string;
  aead: string;
  kdf: string;
  transcript_hash: string;
  sizes: { ml_kem_768: SuiteSizes; ml_dsa_44: SuiteSizes };
  private_key_storage: string;
  key_generation: string;
  conformance: string;
  validation: string;
  legacy_suite: string;
}
export interface SystemCrypto {
  suite: CryptoSuite;
  migration: {
    state: string;
    archived_at_startup: unknown;
    legacy_snapshots: { count: number | null };
    action: string;
  };
  puf: string;
}
export interface TraceFlag {
  flag_id: string;
  session_id: string;
  flagged_by: string;
  reason: string;
  timestamp_unix_ms: number;
}
export interface TraceRecord {
  trace_id: string;
  requested_by: string;
  requester_role: string;
  reason: string;
  target_pid_hex: string;
  authorized: boolean;
  outcome?: string;
  resolved_drone_id: string | null;
  timestamp_unix_ms: number;
}
const BASE = import.meta.env["VITE_API_BASE"] || "http://127.0.0.1:4000/api";
async function req<T>(
  method: string,
  path: string,
  body?: unknown,
  extra?: Record<string, string>,
): Promise<T> {
  const init: RequestInit = { method };
  if (body !== undefined || extra) {
    init.headers = {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(extra ?? {}),
    };
  }
  if (body !== undefined) init.body = JSON.stringify(body);
  const res = await fetch(`${BASE}${path}`, init);
  const json = await res.json().catch(() => ({}));
  if (!res.ok)
    throw new Error((json as { error?: string }).error || `Request failed (${res.status})`);
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
    req<{ status: string; leaf_index: number }>(
      "POST",
      `/drones/${encodeURIComponent(id)}/register`,
      { group_id, role },
    ),
  revokeDrone: (id: string) =>
    req<{ status: string }>("POST", `/drones/${encodeURIComponent(id)}/revoke`),
  reactivateDrone: (id: string) =>
    req<{ status: string; leaf_index: number }>(
      "POST",
      `/drones/${encodeURIComponent(id)}/reactivate`,
    ),
  moveDrone: (id: string, group_id: string) =>
    req<{ status: string; leaf_index: number }>("POST", `/drones/${encodeURIComponent(id)}/move`, {
      group_id,
    }),
  authenticate: (d1_id: string, d2_id: string) =>
    req<AuthResultView>("POST", "/authenticate", { d1_id, d2_id }),
  establishGroupKey: (d1_id: string, d2_id: string, mission_id: string) =>
    req<{ status: string }>("POST", "/group-key", { d1_id, d2_id, mission_id }),
  sendSecureMessage: (from_id: string, to_id: string, plaintext: string) =>
    req<{ status: string; decrypted_by_receiver: string }>("POST", "/secure-message", {
      from_id,
      to_id,
      plaintext,
    }),
  getEventsHistory: (limit = 200) =>
    req<{ events: ProtocolEvent[] }>("GET", `/events/history?limit=${limit}`),
  flagSession: (session_id: string, flagged_by: string, reason: string) =>
    req<TraceFlag>("POST", "/trace/flag", { session_id, flagged_by, reason }),
  requestTrace: (
    requested_by: string,
    reason: string,
    target_pid_hex: string,
    adminToken: string,
  ) =>
    req<TraceRecord>(
      "POST",
      "/trace/request",
      { requested_by, reason, target_pid_hex },
      adminToken ? { "X-Admin-Token": adminToken } : undefined,
    ),
  getTrace: () => req<{ flags: TraceFlag[]; trace_records: TraceRecord[] }>("GET", "/trace"),
  getSystemCrypto: () => req<SystemCrypto>("GET", "/system/crypto"),
};
export function streamEvents(
  onEvent: (ev: ProtocolEvent) => void,
  onState?: (connected: boolean) => void,
) {
  const source = new EventSource(`${BASE}/events/stream`);
  source.onopen = () => onState?.(true);
  source.onerror = () => onState?.(false);
  source.onmessage = (msg) => {
    try {
      onEvent(JSON.parse(msg.data) as ProtocolEvent);
    } catch {
      /* ignore malformed event */
    }
  };
  return () => source.close();
}

export { stegoApi, stegoUrl, downloadStegoReport } from "./stego-api";
