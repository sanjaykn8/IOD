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

## Steganography endpoints (Rust; relayed by Node under `/api/stego/*`)
`GET /api/stego/status`, `POST /api/stego/camera/probe`, `POST /api/stego/analyze`, `POST /api/stego/message` (analyze+send+receive), `POST /api/stego/send`, `POST /api/stego/receive` (artifact id only), `GET /api/stego/events[?direction&outcome&since_ms&limit]`, `GET /api/stego/events/{id}`, `GET /api/stego/report[?format=csv]`, `POST /api/stego/benchmark`, `GET /api/stego/artifacts/{id}/{stego|cover}` (id must match `^[0-9a-f]{32}$`). Errors: `{code,message,stage,details}` with stable codes. `POST /api/secure-message` now routes through the same image transport. Details and examples: `docs/stego-transport.md`.

### `POST /api/stego/cover/upload`
Body `{"image_b64": "<base64 PNG, <= 8 MiB>", "origin": "browser_webcam" | "uploaded"}`. Python accepts PNG only, enforces the size limits, re-encodes the image and stores it as a cover. Returns `{"ok": true, "cover": {"artifact_id", "source": origin, "width", "height", "mode", "sha256", "transforms"}}`. Use it afterwards as `"cover": {"source": "browser_webcam" | "uploaded", "cover_id": "<artifact_id>"}` in `analyze`, `message`, `send` and `benchmark`. Errors: `IMAGE_DECODE_ERROR` (not PNG/corrupt), `IMAGE_TOO_SMALL`/`IMAGE_TOO_LARGE`, `INVALID_REQUEST`, `FRAME_TOO_LARGE`. Node accepts up to 14 MB on this route only; everything else keeps the small default.
