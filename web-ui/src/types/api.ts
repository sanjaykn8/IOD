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

// ---------------------------------------------------------------------
// Steganography Lab (docs/stego-implementation-note.md sections 4.2, 4.3, 5).
// Most fields are optional/nullable on purpose: the UI renders what the core
// returns and shows "n/a" for anything missing -- it never invents values.
// ---------------------------------------------------------------------
export type StegoAlgorithm = "lsb_replacement" | "lsb_matching" | "pvd" | "edge_adaptive_lsb" | "dct";
export type StegoPriority = "urgent" | "normal" | "background";
export type StegoCoverSource = "webcam" | "procedural" | "test_cover";
export interface StegoCoverRequest { source: StegoCoverSource; camera_index?: number; test_cover_id?: string; seed?: string }
export interface StegoErrorBody { code: string; message: string; stage?: string | null; details?: Record<string, unknown> | null }
export type StegoStageStatus = "ok" | "failed" | "skipped" | string;
export interface StegoStage { name: string; status: StegoStageStatus; ms?: number | null; detail?: string | null }
/** A metric that may be a number, null (undefined) or a string such as "inf". */
export type StegoNum = number | string | null | undefined;
export interface StegoCandidate {
  algorithm: string; eligible: boolean; exclusion_reason?: string | null;
  capacity_bits?: number | null; capacity_bytes?: number | null; utilization?: number | null; headroom_bits?: number | null;
  est_cost_units?: number | null; mse?: StegoNum; psnr?: StegoNum; ssim?: StegoNum; score?: number | null; trial_ms?: number | null;
}
export interface StegoSelection {
  selected?: string | null; reason_code?: string | null; policy_version?: string | null; mode?: string | null;
  features?: Record<string, unknown> | null; candidates?: StegoCandidate[] | null;
}
export interface StegoMetrics { mse?: StegoNum; psnr?: StegoNum; ssim?: StegoNum; changed_samples?: number | null; changed_fraction?: number | null; max_abs_diff?: number | null }
export interface StegoEmbed {
  algorithm?: string; alg_id?: number; param?: unknown; params?: Record<string, unknown> | null;
  capacity_bytes?: number | null; frame_len?: number | null; used_fraction?: number | null; metrics?: StegoMetrics | null;
}
export interface StegoCoverInfo {
  artifact_id?: string; source?: string; fallback_reason?: string | null; width?: number; height?: number; mode?: string; channels?: number;
  transforms?: unknown; sha256?: string; seed?: string | null;
}
export interface StegoArtifactRef {
  id: string; stego_sha256?: string; size?: number; preview_url?: string; cover_preview_url?: string;
  width?: number; height?: number; mode?: string; channels?: number; format?: string;
}
export interface StegoVerification { frame_match?: boolean | null; header_mac_ok?: boolean | null; algorithm_consistent?: boolean | null; aead_ok?: boolean | null }
export interface StegoExplanation {
  status?: string; narrative?: string | null; evidence?: unknown; retrieved?: unknown; kb_version?: string | null;
  fallback?: boolean; selected_unchanged?: boolean;
}
export type StegoTimings = Record<string, number | null | undefined>;
export interface StegoMessageResult {
  ok: true; event_id?: string | number; session_id?: string; direction?: string | number; seq?: number; from_role?: string; to_role?: string;
  delivered_message?: string; artifact?: StegoArtifactRef; cover?: StegoCoverInfo; selection?: StegoSelection; embed?: StegoEmbed;
  verification?: StegoVerification; timings_ms?: StegoTimings; stages?: StegoStage[]; explanation?: StegoExplanation;
}
export interface StegoFailure { ok: false; event_id?: string | number; error: StegoErrorBody; stages?: StegoStage[] }
export interface StegoStatus {
  backend: { reachable: boolean; error?: string | null; health?: {
    ok?: boolean; version?: string; algorithms?: { id: number | string; name: string }[]; artifact_dir_writable?: boolean;
    camera?: { backend?: string; opencv_available?: boolean; mode?: string }; numpy?: string; pillow?: string; limits?: Record<string, unknown>;
  } | null };
  config?: { limits?: Record<string, unknown>; policy?: Record<string, unknown>; artifact_dir_name?: string; retention?: unknown };
  counts?: { events?: number; ok?: number; failed?: number };
}
export interface StegoCameraProbe { available: boolean; reason?: string | null; width?: number; height?: number }
export interface StegoAnalyzeResult { selection?: StegoSelection; cover?: StegoCoverInfo }
export interface StegoEvent {
  event_id?: string | number; ts_ms: number; kind?: string; session_id?: string; direction?: string | number; direction_label?: string; seq?: number; from_role?: string; to_role?: string;
  algorithm?: string | null; param?: unknown; outcome?: string; success?: boolean; selection_policy_version?: string; selection_mode?: string;
  selection_reason_code?: string; explanation_status?: string; cover_source?: string; cover_fallback_reason?: string | null;
  width?: number; height?: number; mode?: string; channels?: number; output_format?: string; frame_bytes?: number; wire_bytes?: number;
  image_bytes?: number; capacity_bytes?: number; capacity_margin_bytes?: number; timings_ms?: StegoTimings;
  mse?: StegoNum; psnr?: StegoNum; ssim?: StegoNum; error_code?: string | null; error_message?: string | null; error_stage?: string | null;
  artifact_id?: string | null; stego_sha256?: string | null; cover_sha256?: string | null; frame_sha256_prefix?: string | null;
  frame_match?: boolean | null; header_mac_ok?: boolean | null; aead_ok?: boolean | null; candidates?: StegoCandidate[];
  [k: string]: unknown;
}
export interface StegoEventFilter { session_id?: string; direction?: string; algorithm?: string; outcome?: string; since_ms?: number; until_ms?: number; limit?: number }
export interface StegoMeanN { mean: number | null; n?: number }
export interface StegoTimingStat { n?: number; mean?: number | null; p50?: number | null; p95?: number | null }
export interface StegoReportAlgorithm {
  algorithm: string; n_ok: number; n_failed: number; capacity_bytes?: { mean: number | null }; frame_bytes?: { mean: number | null };
  mse?: StegoMeanN; psnr?: StegoMeanN; ssim?: StegoMeanN; timings_ms?: Record<string, StegoTimingStat>;
}
export interface StegoReport {
  schema: string; generated_ms?: number;
  environment?: { os?: string; rustc?: string; python_service?: { version?: string; numpy?: string; pillow?: string }; camera_mode?: string };
  totals?: { events?: number; ok?: number; failed?: number; fallback_cover_count?: number; error_counts?: Record<string, number> };
  per_algorithm?: StegoReportAlgorithm[]; limitations?: string[];
}
export interface StegoBenchmarkRequest { session_id: string; iterations?: number; frame_sizes?: number[]; algorithms?: string[]; cover?: StegoCoverRequest }
export interface StegoBenchmarkResult { runs?: unknown[]; summary?: unknown }
