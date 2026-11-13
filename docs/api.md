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

Session objects needed for K1 live in process memory; after a server restart a new authentication is required before K1 (the GCS-side session record persists).

## Patch-wise steganography endpoints (Rust; relayed 1:1 by Node under `/api/stego/*`)

Contract `frame-v2/appwire-v1/bootstrap-v2/manifest-v1`; TypeScript types in `web-ui/src/types/api.ts`. Errors are
`{"ok": false, "error": {"code", "message", "stage", "details"}, "event_id"?, "stages"?}` with the stable codes of
`patchwise-transport.md` section 12. No response contains a key, a MAC key, ciphertext or (except `delivered_message`
on success) plaintext. Bodies are size-limited and unknown/removed fields are rejected.

| Method & path | Body | Result |
|---|---|---|
| `GET /api/stego/status` | — | backend health (versions, ten algorithms, camera mode), limits, segmentation overrides, counts |
| `GET /api/stego/kb` | — | the static knowledge base: `kb_version`, `selector` (BM25 `k1`, `b`, field weights, tie break), `query_terms` rules, `entries[10]`, `references`, `bm25_stats`, `registry`, `segmentation_defaults` |
| `POST /api/stego/plan` | `{payload_bytes? (33..max frame, default 256), cover?, min_level? (0..6)}` | plan preview, nothing sealed or embedded: `plan` (segmentation info, attempts, `patches[]` with `features`, `retrieval`, `selected`, `payload_offset`, `payload_length`, `dry_run`), validated `manifest` summary, `cover`, `inspection.palette`, `artifact.cover_id` |
| `POST /api/stego/message` | `{session_id \| (d1_id, d2_id), from_id, plaintext, cover?}` | full transaction: `delivered_message`, `artifact`, `cover`, `plan`, `manifest`, `received_manifest`, `embed` (per-patch results, whole-image `metrics`, `exact_frame_recovery_from_saved_png`), `extraction[]`, `verification`, `transport` (byte counts), `timings_ms`, `stages[]` |
| `POST /api/stego/send` | same as `message` | sender half; returns `artifact.id` |
| `POST /api/stego/receive` | `{session_id, recipient_id, artifact_id}` | receiver half from the saved file only |
| `GET /api/stego/events[?session_id&direction&algorithm&outcome&since_ms&until_ms&limit]`, `GET /api/stego/events/{id}` | — | persisted events incl. compact per-patch records (`patches[]`: algorithm, KB entry, BM25, query terms, ranking, offset, length), `algorithms_used`, `plan_attempts`, `replans`; `algorithm` filters by the dominant algorithm |
| `GET /api/stego/report[?format=json\|csv\|patches_csv]` | — | schema `stego-report-2`: totals, `overall` statistics, `per_algorithm` usage (events, patches, payload bytes); CSV of events; CSV with one row per patch |
| `POST /api/stego/benchmark` | `{session_id, iterations (≤50), frame_sizes[] (message bytes, ≤8), cover?}` | real transactions through the whole pipeline + a report over them |
| `POST /api/stego/camera/probe` | `{camera_index?}` | `{available, reason?}` |
| `GET /api/stego/artifacts/{id}/{stego\|cover\|seg\|labels\|diff}` | — | PNG (id must match `^[0-9a-f]{32}$`): stego image, cover, segmentation overlay, label map (pixel value = patch id), difference ×64 |

`cover`: `{"source": "webcam" \| "procedural" \| "test_cover" \| "browser_webcam" \| "uploaded", "test_cover_id"?/"cover_id"?, "seed"?, "camera_index"?}`.
Removed: `POST /api/stego/analyze`, the `priority`, `algorithm`, `param` and `policy` request fields (now `400 INVALID_REQUEST`), the
`explanation` and `selection` response objects, and all `/api/rag/*` routes. `POST /api/secure-message` routes through the same transport.

Internal Rust → Python contract (loopback, never exposed by Node): `POST /stego/plan`, `POST /stego/encode {frame_b64, cover}`,
`POST /stego/extract {artifact_id}`, `GET /stego/kb`, `POST /stego/cover/upload`, `POST /stego/capture`, `POST /stego/camera/probe`,
`GET /stego/health`. Requests containing `key`, `mac_key`, `plaintext`, `path` or `artifact_dir` are rejected by the Python service.

### `POST /api/stego/cover/upload`
Body `{"image_b64": "<base64 PNG, <= 8 MiB>", "origin": "browser_webcam" | "uploaded"}`. Python accepts PNG only, enforces the size limits, re-encodes the image and stores it as a cover. Returns `{"ok": true, "cover": {"artifact_id", "source": origin, "width", "height", "mode", "sha256", "transforms"}}`. Use it afterwards as `"cover": {"source": "browser_webcam" | "uploaded", "cover_id": "<artifact_id>"}` in `plan`, `message`, `send` and `benchmark`. Errors: `IMAGE_DECODE_ERROR` (not PNG/corrupt), `IMAGE_TOO_SMALL`/`IMAGE_TOO_LARGE`, `INVALID_REQUEST`, `FRAME_TOO_LARGE`. Node accepts up to 14 MB on this route only; everything else keeps the small default.

## Algorithm Learning workbench (EDUCATIONAL; `/api/learn/*`, never reaches the UAV transport)
* `GET /api/learn/registry` - ten algorithms with variant/domain/reference/coding, sample covers, attacks, metric definitions.
* `GET /api/learn/walkthrough/{alg}` - deterministic worked calculation: `steps[{n,title,formula,substitution,result,table?,matrices?}]`, `checks`, `embedded_bits`, `recovered_bits`, `exact_match`, `teaching_model`, `simplification`.
* `POST /api/learn/experiment` - body `{"payload_mode": "aead_fixture"|"synthetic", "message"?: str (<=2048 B), "algorithms": "all"|[names], "cover": {"sample": "natural_rgb_256"|"natural_gray_256"|"gray_64"|"bw_procedural_256"} | {"upload_b64": PNG <= 512x512}, "patch": "most_textured"|"smoothest"|"largest"|"smallest"|<patch id>, "robustness": bool, "survey": bool, "include_images": bool}`. Returns `experiment_id`, `label`, `operational: false`, `production_kb_modified: false`, `segmentation` (version, patch count, overlay), `patch` (id, features, read-only KB ranking), `survey[]` (per patch: measured capacity per algorithm, geometry support, read-only KB top-1), `payload_construction`, per-algorithm `results[]` on that patch (`capacity_bits`, `geometry_supported`, `patch_mse`, `outside_patch_changes`, …), `verification` (`aead_verified` | `aead_failed` | `not_applicable_synthetic` | `not_extracted`), robustness, images as data URIs.
* `GET /api/learn/experiments[?limit=]`, `GET /api/learn/experiments/{id}/export?format=json|csv|md`.
