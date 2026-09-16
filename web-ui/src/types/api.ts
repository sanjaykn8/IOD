export interface DroneView {
  drone_id: string;
  group_id: string | null;
  registered: boolean;
  active: boolean;
  revoked_flag: boolean;
  kem_pk_fingerprint: string | null;
  dil_pk_fingerprint: string | null;
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

export interface Contribution {
  drone_id: string;
  content: string;
  confidence: number;
  timestamp_unix_ms: number;
  trust_score: number;
  flagged_suspicious: boolean;
  flag_reason: string;
}

export interface RagRunResult {
  query: string;
  llm_provider: string;
  retrieved_count: number;
  contributions: Contribution[];
  fused_context: string;
  included_drone_ids: string[];
  excluded_drone_ids: string[];
  generated_output: string;
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
  resolved_drone_id: string | null;
  timestamp_unix_ms: number;
}
