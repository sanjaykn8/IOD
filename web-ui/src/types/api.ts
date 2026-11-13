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
// Patch-wise Steganography Lab + Knowledge Base monitor (docs/api.md, contract
// "frame-v2/appwire-v1/bootstrap-v2/manifest-v1"). Most fields are optional/nullable on
// purpose: the UI renders what the core returns and shows "n/a" for anything missing --
// it never invents values.
// ---------------------------------------------------------------------
export type StegoAlgorithm = "lsb_replacement" | "lsb_matching" | "pvd" | "edge_adaptive_lsb" | "dct" | "dwt" | "dct_svd" | "hugo" | "wow" | "s_uniward";
export type StegoCoverSource = "webcam" | "procedural" | "test_cover" | "browser_webcam" | "uploaded";
export interface StegoCoverRequest { source: StegoCoverSource; camera_index?: number; test_cover_id?: string; cover_id?: string; seed?: string }
export interface StegoUploadedCover { artifact_id: string; source: string; width: number; height: number; mode?: string; sha256?: string; transforms?: string[] }
export interface StegoCoverUploadResult { ok: true; cover: StegoUploadedCover }
export interface StegoErrorBody { code: string; message: string; stage?: string | null; details?: Record<string, unknown> | null }
export type StegoStageStatus = "ok" | "failed" | "skipped" | string;
export interface StegoStage { name: string; status: StegoStageStatus; ms?: number | null; detail?: string | null }
/** A metric that may be a number, null (undefined) or a string such as "inf". */
export type StegoNum = number | string | null | undefined;

/** Feature vector of one patch (computed by the image service on the cover). */
export interface PatchFeatures {
  patch_id: number; pixels: number; usable_pixels: number; bbox?: number[]; width?: number; height?: number; aspect_ratio?: number;
  compactness?: number; perimeter?: number; centroid?: number[]; mean?: number; mean_rgb?: number[] | null; variance?: number; entropy?: number;
  gradient_mean?: number; gradient_std?: number; edge_density?: number; texture?: number; smoothness?: number; hf_energy_ratio?: number;
  ac_energy_mean?: number; saturation?: number; channels?: number; blocks8?: number; blocks2?: number; block8_fill?: number;
  capacity_bits?: Record<string, number>; carriers?: Record<string, number>;
  [k: string]: unknown;
}
export interface KbFilterResult { filter: string; passed: boolean; detail?: string | null }
/** One knowledge-base entry evaluated for one patch: structured filters first, then the BM25 score. */
export interface KbCandidate {
  algorithm: string; alg_id: number; kb_entry: string; eligible: boolean; filters: KbFilterResult[]; exclusion_reason?: string | null;
  bm25: number; matched_terms?: string[]; capacity_bits?: number; advisory_bits_per_sample?: number | null; rank?: number;
}
export interface PatchRetrieval {
  selector_version: string; kb_version: string; query_terms: string[]; required_bits: number; candidates: KbCandidate[];
  ranking: string[]; selected: string | null; tie?: boolean; query_features?: Record<string, unknown>;
}
export interface PlanPatch {
  patch_id: number; used: boolean; features: PatchFeatures; max_capacity_bytes?: number; selected?: string | null; alg_id?: number; param?: number;
  variant?: string; payload_offset?: number | null; payload_length?: number; measured_capacity_bytes?: number; utilisation?: number | null;
  retrieval?: PatchRetrieval | null; dry_run?: { ok: boolean; error?: string | null; ms?: number } | null;
}
export interface PlanAttempt { level: number; regions?: number; outcome?: string | null; manifest_bytes?: number; reserved_rows?: number; usable_patches?: number; capacity_bytes?: number; failed_patch?: number; ms?: number }
export interface SegmentationInfo {
  version?: string; method?: string; level?: number; cell_size?: number; grid_rows?: number; grid_cols?: number; complexity?: number;
  target_regions?: number; regions?: number; regions_before_merge?: number; merges?: number; tau?: number; min_region_px?: number;
  max_region_px?: number; settings?: Record<string, number>; tau_search?: unknown[];
}
export interface StegoPlan {
  selector_version?: string; kb_version?: string; segmentation?: SegmentationInfo; refinement_level?: number; attempts?: PlanAttempt[];
  payload_bytes?: number; manifest_bytes?: number; reserved_rows?: number; bootstrap_carrier_bits?: number; patch_count?: number; used_patches?: number;
  algorithms_used?: Record<string, number>; target_chunk_bytes?: number; allocation_rule?: string; patches?: PlanPatch[]; plan_ms?: number;
}
export interface ManifestPatch { patch_id: number; used: boolean; cells?: number; alg_id?: number; algorithm?: string; param?: number; payload_offset?: number; payload_length?: number }
export interface ManifestSummary {
  version?: number; segmentation_version?: string; selector_version?: string; width?: number; height?: number; channels?: number; cell_size?: number;
  patch_count?: number; used_patches?: number; reserved_rows?: number; payload_len?: number; patches?: ManifestPatch[];
}
export interface StegoMetrics { mse?: StegoNum; psnr?: StegoNum; ssim?: StegoNum; changed_samples?: number | null; changed_fraction?: number | null; max_abs_diff?: number | null }
export interface EmbedPatch {
  patch_id: number; used: boolean; algorithm?: string; alg_id?: number; param?: number; payload_offset?: number; payload_length?: number;
  capacity_bytes?: number; changed_samples?: number; patch_mse?: number; extraction?: string; detail?: Record<string, unknown>;
}
export interface StegoEmbed {
  frame_len?: number | null; manifest_len?: number | null; payload_len?: number | null; patch_count?: number; used_patches?: number; reserved_rows?: number;
  patches?: EmbedPatch[]; metrics?: StegoMetrics | null; exact_frame_recovery_from_saved_png?: boolean;
}
export interface ExtractedPatch { patch_id: number; algorithm?: string; alg_id?: number; param?: number; payload_offset?: number; payload_length?: number; status?: string }
export interface StegoCoverInfo {
  artifact_id?: string; source?: string; fallback_reason?: string | null; width?: number; height?: number; mode?: string; channels?: number;
  transforms?: unknown; sha256?: string; seed?: string | null;
}
export interface StegoArtifactRef {
  id?: string; cover_id?: string; stego_sha256?: string; size?: number; width?: number; height?: number; mode?: string; channels?: number; format?: string;
}
export interface StegoVerification {
  frame_match?: boolean | null; header_mac_ok?: boolean | null; manifest_authenticated?: boolean | null; aead_ok?: boolean | null;
  resegmented?: boolean | null; full_frame_recovered?: boolean | null;
}
export interface StegoTransport { format_version?: string; frame_bytes?: number; wire_bytes?: number; manifest_bytes?: number; payload_section_bytes?: number; mac?: string }
export interface StegoInspection { segmentation_overlay?: string; label_map?: string; palette?: number[][] }
export type StegoTimings = Record<string, number | null | undefined>;
export interface StegoMessageResult {
  ok: true; event_id?: string | number; session_id?: string; direction?: string | number; seq?: number; from_role?: string; to_role?: string;
  delivered_message?: string; artifact?: StegoArtifactRef; cover?: StegoCoverInfo; plan?: StegoPlan; inspection?: StegoInspection;
  manifest?: ManifestSummary; received_manifest?: ManifestSummary; embed?: StegoEmbed; extraction?: ExtractedPatch[];
  bootstrap?: { version?: number; manifest_len?: number; frame_len?: number }; received_image?: Record<string, unknown>;
  verification?: StegoVerification; timings_ms?: StegoTimings; stages?: StegoStage[]; transport?: StegoTransport;
}
export interface StegoPlanPreview {
  ok: true; plan?: StegoPlan; manifest?: ManifestSummary; manifest_bytes?: number; cover?: StegoCoverInfo; inspection?: StegoInspection;
  artifact?: StegoArtifactRef; timings_ms?: StegoTimings; wall_ms?: number; note?: string;
}
export interface StegoFailure { ok: false; event_id?: string | number; error: StegoErrorBody; stages?: StegoStage[] }
export interface StegoStatus {
  backend: { reachable: boolean; error?: StegoErrorBody | string | null; health?: {
    ok?: boolean; version?: string; format_version?: string; segmentation_version?: string; selector_version?: string; kb_version?: string;
    algorithms?: { id: number | string; name: string; variant?: string }[]; artifact_dir_writable?: boolean;
    camera?: { backend?: string; opencv_available?: boolean; mode?: string }; numpy?: string; pillow?: string; limits?: Record<string, unknown>;
  } | null };
  config?: { limits?: Record<string, unknown>; segmentation_overrides?: Record<string, number>; target_chunk_bytes?: number; max_replans?: number; artifact_dir_name?: string };
  counts?: { events?: number; ok?: number; failed?: number };
  transport?: { format_version?: string; passthrough_fallback?: boolean };
}
export interface StegoCameraProbe { available: boolean; reason?: string | null; width?: number; height?: number }
/** Compact per-patch record kept in a persisted event. */
export interface EventPatch {
  patch_id: number; used: boolean; pixels?: number; usable_pixels?: number; gradient_mean?: number; variance?: number; entropy?: number;
  algorithm?: string | null; alg_id?: number | null; param?: number | null; payload_offset?: number | null; payload_length?: number | null;
  capacity_bytes?: number | null; kb_entry?: string | null; bm25?: number | null; query_terms?: string[] | null; ranking?: string[] | null;
}
export interface StegoEvent {
  event_id?: string | number; ts_ms: number; kind?: string; session_id?: string; direction?: string | number; direction_label?: string; seq?: number; from_role?: string; to_role?: string;
  algorithm?: string | null; algorithms_used?: Record<string, { patches: number; payload_bytes: number }>; outcome?: string; success?: boolean;
  segmentation_version?: string; selector_version?: string; kb_version?: string; refinement_level?: number; replans?: unknown[]; plan_attempts?: PlanAttempt[];
  patch_count?: number; used_patches?: number; reserved_rows?: number; manifest_bytes?: number; patches?: EventPatch[];
  cover_source?: string; cover_fallback_reason?: string | null; cover_artifact_id?: string | null;
  width?: number; height?: number; mode?: string; channels?: number; output_format?: string; frame_bytes?: number; wire_bytes?: number; payload_bytes?: number;
  image_bytes?: number; timings_ms?: StegoTimings; stages?: StegoStage[];
  mse?: StegoNum; psnr?: StegoNum; ssim?: StegoNum; error_code?: string | null; error_message?: string | null; error_stage?: string | null;
  artifact_id?: string | null; stego_sha256?: string | null; cover_sha256?: string | null; frame_sha256_prefix?: string | null;
  frame_match?: boolean | null; header_mac_ok?: boolean | null; aead_ok?: boolean | null;
  [k: string]: unknown;
}
export interface StegoEventFilter { session_id?: string; direction?: string; algorithm?: string; outcome?: string; since_ms?: number; until_ms?: number; limit?: number }
export interface StegoStat { n?: number; mean?: number | null; p50?: number | null; p95?: number | null }
export interface StegoReportAlgorithm { algorithm: string; events: number; patches: number; payload_bytes: number }
export interface StegoReport {
  schema: string; generated_ms?: number;
  environment?: { os?: string; arch?: string; rust_core_version?: string; python_service?: { version?: string; numpy?: string; pillow?: string; camera_mode?: string } | null };
  totals?: { events?: number; ok?: number; failed?: number; fallback_cover_count?: number; cover_sources?: Record<string, number>; error_counts?: Record<string, number> };
  overall?: { n_ok?: number; patch_count?: StegoStat; used_patches?: StegoStat; refinement_level?: StegoStat; manifest_bytes?: StegoStat; frame_bytes?: StegoStat;
              image_bytes?: StegoStat; mse?: StegoStat; psnr?: StegoStat; ssim?: StegoStat; timings_ms?: Record<string, StegoStat> };
  per_algorithm?: StegoReportAlgorithm[]; limitations?: string[];
}
export interface StegoBenchmarkRequest { session_id: string; iterations?: number; frame_sizes?: number[]; cover?: StegoCoverRequest }
export interface StegoBenchmarkRun { payload_bytes: number; iteration: number; ok: boolean; event_id?: number; error_code?: string | null; total_ms?: number | null; algorithms_used?: Record<string, number> | null }
export interface StegoBenchmarkResult { runs?: StegoBenchmarkRun[]; summary?: StegoReport; samples?: number }

// ---- static algorithm knowledge base (GET /api/stego/kb)
export interface KbReference { id: string; title: string; authors: string; year: number; venue?: string; doi?: string; url?: string; verified?: string; note?: string }
export interface KbEvidence { claim: string; kind: "published" | "implementation" | "local_heuristic"; refs?: string[]; validate?: string; note?: string }
export interface KbEntry {
  id: number; name: string; variant: string; domain: string; sub_domain?: string; summary: string; suitable_terms: string[]; suitable_when: string[];
  avoid_when: string[]; requirements: { min_usable_pixels?: number; block?: number; min_blocks?: number; [k: string]: unknown };
  hard_avoid: { feature: string; op: string; value: unknown; reason: string }[];
  capacity: { behavior?: string; factors?: string[]; advisory_bits_per_sample?: number | null };
  distortion: { impact?: string; metrics?: string[] }; cost: { relative?: string; notes?: string }; assumptions: string; extraction: string;
  limitations: string[]; references: string[]; evidence: KbEvidence[];
}
export interface KbQueryRule { term: string; feature: string; op: string; value: unknown }
export interface KnowledgeBase {
  ok?: boolean; kb_version: string; schema_version?: string | number; description?: string;
  selector: { version: string; bm25: { k1: number; b: number }; field_weights: Record<string, number>; tie_break?: string; capacity_source?: string };
  query_terms: KbQueryRule[]; query_terms_note?: string; evidence_kinds?: Record<string, string>; citation_note?: string;
  references: KbReference[]; entries: KbEntry[];
  bm25_stats?: { documents: number; avg_doc_len: number; idf: Record<string, number> };
  registry?: { id: number; name: string; variant: string; domain: string; coding?: string; block?: number; mask_support?: string; param_range?: number[]; default_param?: number }[];
  format_version?: string; segmentation_version?: string; segmentation_defaults?: Record<string, number>;
}
