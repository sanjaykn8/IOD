# HTTP API (Rust core, `iod-server`; relayed by the Node gateway)

JSON over HTTP. Env: `IOD_BIND_ADDR` (default `127.0.0.1:8787`), `IOD_DB_PATH`, `IOD_ADMIN_TOKEN` (≥16 chars; if unset nobody is an administrator). No response contains private keys, PUF data, `rho`, Merkle witnesses, AEAD keys or KEM secrets (views are hand-built: `api/views.rs`).

| Method & path | Body | Result |
|---|---|---|
| `POST /api/reset` | — | wipe state |
| `GET /api/state` | — | counts, groups, drones |
| `POST /api/groups`, `GET /api/groups[/id]` | `{group_id}` | group views (`root_hex` = 32-byte hex Poseidon2 digest, `version`) |
| `POST /api/drones`, `GET /api/drones[/id]` | `{drone_id}` | drone view (public-key fingerprints only) |
| `POST /api/drones/{id}/register` | `{group_id, role}` | R1–R3; `leaf_index` |
| `POST /api/drones/{id}/revoke` / `reactivate` / `move` | `{group_id}` for move | revocation expires PIDs and fails open sessions |
| `POST /api/authenticate` | `{d1_id, d2_id}` | M1–M8: `{session_id, decision, reason_code, freshness_ok, credential_ok, commitment_ok, zk_membership_ok, signature_ok, puf_ok, root_version_ok, session_binding_ok, authenticated}`; HTTP 400 with a reason code when the GCS/drones reject before a verdict |
| `POST /api/group-key` | `{session_id, mission_id}` (or `{d1_id,d2_id}` → that pair's latest session) | K1–K3 for a **completed** session only; 409 `NO_AUTH_SESSION`, 403 with the GCS reason (`SESSION_NOT_AUTHENTICATED`, `SESSION_DENIED`, `NOT_ALLOWED`, `D1_CONFIRM_INVALID`, `SESSION_REPLAY`, …) |
| `POST /api/secure-message` | `{session_id, from_id, plaintext}` (or `to_id` instead of session) | K4 message sent and decrypted by the peer |
| `GET /api/events?since=n`, `GET /api/events/history` | — | protocol events |
| `POST /api/trace/flag` | `{session_id, flagged_by, reason}` | suspicion flag |
| `POST /api/trace/request` | `{requested_by, reason, target_pid_hex}` + header `X-Admin-Token` | 200 resolved; 403 `NOT_ADMIN`; 422 `EMPTY_REASON`/`PID_NOT_FLAGGED`/`UNKNOWN_PID`. A `requester_role` in the body is ignored. Every attempt is audited |
| `GET /api/trace` | — | flags and audit records |
| `GET /api/system/crypto` | — | active suite `iod-fips203-mlkem768-fips204-mldsa44-v1`: algorithms, parameter sets, key/ciphertext/signature sizes, libraries, KAT/interop status, "not FIPS 140-3 validated", PUF simulated, legacy-snapshot archive summary |

Session objects needed for K1 live in process memory; after a server restart a new authentication is required before K1 (the GCS-side session record persists).

## Patch-wise steganography endpoints (Rust; relayed 1:1 by Node under `/api/stego/*`)

Contract `frame-v3/appwire-v1/bootstrap-v3/manifest-v2`; TypeScript types in `web-ui/src/types/api.ts`. Errors are
`{"ok": false, "error": {"code", "message", "stage", "details"}, "event_id"?, "stages"?}` with the stable codes of
`patchwise-transport.md` section 12. No response contains a key, a MAC key, ciphertext or (except `delivered_message`
on success) plaintext. Bodies are size-limited and unknown/removed fields are rejected.

| Method & path | Body | Result |
|---|---|---|
| `GET /api/stego/status` | — | backend health (versions, ten algorithms, `cover_generator`: version, active profile, families, seeding, `pretrained_models: false`), limits, segmentation overrides, `config.cover_generation` (active profile, effective settings, hard ceilings, accepted request fields), `config.algorithm_policy` (name, allowed, excluded with reasons), `config.bootstrap` (version 3, sync window, replay lookback), counts |
| `GET /api/stego/kb` | — | the static knowledge base: `kb_version`, `selector` (BM25 `k1`, `b`, field weights, tie break), `query_terms` rules, `entries[10]`, `references`, `bm25_stats`, `registry`, `segmentation_defaults` |
| `POST /api/stego/plan` | `{payload_bytes? (33..max frame, default 256), cover_generation?, min_level? (0..6)}` | plan preview on a **fresh generated cover**, nothing sealed or embedded: `generation` (candidates, scores, rejection reasons, timings, budget), `plan` (segmentation info, attempts, `patches[]` with `features`, `retrieval`, `selected`, `payload_offset`, `payload_length`, `dry_run`), validated `manifest` summary, `cover`, `inspection.palette`, `artifact.cover_id` |
| `POST /api/stego/message` | `{session_id \| (d1_id, d2_id), from_id, plaintext, cover_generation?}` | full transaction on a fresh generated cover: `delivered_message`, `artifact`, `cover`, `generation`, `plan`, `manifest`, `received_manifest`, `embed` (per-patch results, whole-image `metrics`, `exact_frame_recovery_from_saved_png`), `extraction[]`, `verification`, `transport` (byte counts), `timings_ms`, `stages[]` |
| `POST /api/stego/send` | same as `message` | sender half; returns `artifact.id` |
| `POST /api/stego/receive` | `{session_id, recipient_id, artifact_id}` | receiver half from the saved file only |
| `GET /api/stego/events[?session_id&direction&algorithm&outcome&since_ms&until_ms&limit]`, `GET /api/stego/events/{id}` | — | persisted events incl. `bootstrap_version`, `carrier_pixels`, `carrier_bits`, `discovered_seq` (receive), `operational_policy`, compact per-patch records (`patches[]`: algorithm, KB entry, BM25, query terms, ranking, offset, length), `algorithms_used`, `plan_attempts`, `replans`, and the generation record (`generator_profile`, `generator_version`, `cover_family`, `seed_fingerprint`, `cover_quality_score`, `generation` with the candidate table, requested/actual size, budget use); `algorithm` filters by the dominant algorithm |
| `GET /api/stego/report[?format=json\|csv\|patches_csv]` | — | schema `stego-report-3`: totals, `overall` statistics, `cover_generation` statistics (families, quality score, candidates per transmission, budget overruns, resizes, failures, candidate rejection reasons), `environment.host`, `per_algorithm` usage (events, patches, payload bytes); CSV of events; CSV with one row per patch |
| `POST /api/stego/benchmark` | `{session_id, iterations (≤50), frame_sizes[] (message bytes, ≤8), cover_generation?}` | real transactions through the whole pipeline, **a fresh cover per run**, + a report over them; `host`, `cover_generation.profile` and a `measurement_label` that says the figures are a profile-constrained host benchmark unless the host is the profile's target device |
| `GET /api/stego/artifacts/{id}/{stego\|cover\|seg\|labels\|diff}` | — | PNG (id must match `^[0-9a-f]{32}$`): stego image, cover, segmentation overlay, label map (pixel value = patch id), difference ×64 |

`cover_generation` (optional, every field optional): `{"profile"?, "width"?, "height"?, "max_width"?, "max_height"?, "max_pixels"?, "max_candidates"?,
"processing_budget_ms"?, "max_working_memory_mb"?, "min_quality_score"?, "max_embedding_rate"?, "allow_payload_driven_resize"?, "families"?, "workers"?, "mode"?}`.
It can only tighten the active resource profile (default `raspberry_pi_5_cpu`: 320×240 RGB, ceiling 640×480, 2 candidates, 2500 ms, 96 MB); see
`cover-generation.md` §6 for bounds. Any other field in it — `seed`, `cover_id`, `source`, `file`, `image_b64`, `family`, `algorithm`, … — is
`400 GENERATOR_CONFIG_INVALID`. There is no public way to choose a seed, a file, a stored cover or an algorithm.

`cover` in responses: `{artifact_id, source: "generated", width, height, mode, channels, sha256, generator_version, profile, family, seed_fingerprint, quality_score}`.
`generation`: `{generator_version, quality_version, profile, config, requested, actual, resized, family, seed_fingerprint, quality_score, candidate_count,
planner_invocations, candidates[{index, family, width, height, seed_fingerprint, quality_score, gates_passed, rejection_reasons[], outcome, capacity_bytes,
generate_ms, prescreen_ms, plan_ms}], timings_ms{generate, prescreen, plan, total}, budget{limit_ms, used_ms, exceeded, approached}, memory, embedding_rate, seeding}`.
A generation failure returns the same structure (with `reason`) as `error.details`.

Removed cover acquisition (cameras, uploads, client-selected covers): `POST /api/stego/camera/probe` and `POST /api/stego/cover/upload` return 404;
the top-level request fields `cover`, `source`, `seed`, `cover_id`, `test_cover_id`, `image_b64`, `camera_index` are `400 INVALID_REQUEST`.
Removed: `POST /api/stego/analyze`, the `priority`, `algorithm`, `param` and `policy` request fields (now `400 INVALID_REQUEST`), the
`explanation` and `selection` response objects, and all `/api/rag/*` routes. `POST /api/secure-message` routes through the same transport.

Internal Rust → Python contract (loopback, never exposed by Node): `POST /stego/plan {payload_bytes, cover_generation, limits, segmentation, min_level, target_chunk_bytes,
carrier: {version: 3, values_b64}, policy: {name, allowed}}` for a new transmission or `{payload_bytes, replan_cover_id, carrier, policy, …}` for a re-plan on the stored
cover (no generation; same value stream); the response adds `manifest_deflate_b64`. `POST /stego/encode {frame_b64, cover_id, limits, carrier: {values_b64, bits_b64, n_bits}}`.
Receive: `POST /stego/carrier/probe {artifact_id, limits, locator_bits: 96, candidates: [{id, values_b64}] (≤ 1088, ≤ 1024 values each)}` → `{probes: [{id, bits_b64 | null}],
legacy_bootstrap_v2, image}`; `POST /stego/carrier/read {artifact_id, limits, values_b64, skip_bits, n_bits}` → `{bits_b64, image}`; `POST /stego/extract {artifact_id,
limits, manifest_b64, values_b64}` → `{frame_b64, manifest, patches, resegmented: false, image}`. `GET /stego/kb`, `GET /stego/health`. Value streams are pseudo-random
u32 values derived in Rust from a per-frame placement key that never leaves Rust; carrier bits arrive already encrypted. Requests containing `key`, `mac_key`, `plaintext`, `payload`, `payload_b64`, `wire`,
`wire_b64`, `ciphertext`, `message`, `path` or `artifact_dir` are rejected by the Python service, as are the removed fields `cover`, `seed`, `cover_id` (in plan),
`test_cover_id`, `image_b64`, `algorithm(s)`, `priority`, `source`. `/stego/camera/probe`, `/stego/cover/upload` and `/stego/capture` no longer exist (404).

## Algorithm Learning workbench (EDUCATIONAL; `/api/learn/*`, never reaches the UAV transport)
* `GET /api/learn/registry` - ten algorithms with variant/domain/reference/coding, sample covers, attacks, metric definitions.
* `GET /api/learn/walkthrough/{alg}` - deterministic worked calculation: `steps[{n,title,formula,substitution,result,table?,matrices?}]`, `checks`, `embedded_bits`, `recovered_bits`, `exact_match`, `teaching_model`, `simplification`.
* `POST /api/learn/experiment` - body `{"payload_mode": "aead_fixture"|"synthetic", "message"?: str (<=2048 B), "algorithms": "all"|[names], "cover": {"sample": "natural_rgb_256"|"natural_gray_256"|"gray_64"|"bw_procedural_256"} | {"upload_b64": PNG <= 512x512}, "patch": "most_textured"|"smoothest"|"largest"|"smallest"|<patch id>, "robustness": bool, "survey": bool, "include_images": bool}`. Returns `experiment_id`, `label`, `operational: false`, `production_kb_modified: false`, `segmentation` (version, patch count, overlay), `patch` (id, features, read-only KB ranking), `survey[]` (per patch: measured capacity per algorithm, geometry support, read-only KB top-1), `payload_construction`, per-algorithm `results[]` on that patch (`capacity_bits`, `geometry_supported`, `patch_mse`, `outside_patch_changes`, …), `verification` (`aead_verified` | `aead_failed` | `not_applicable_synthetic` | `not_extracted`), robustness, images as data URIs.
* `GET /api/learn/experiments[?limit=]`, `GET /api/learn/experiments/{id}/export?format=json|csv|md`.
