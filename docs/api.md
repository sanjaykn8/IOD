# API Reference

All endpoints below are served by the Node.js gateway at
`http://127.0.0.1:4000/api` (configurable via `IOD_NODE_PORT`). Every
endpoint except the `/rag/*` ones is a direct, unmodified proxy to the
Rust core's HTTP API at `http://127.0.0.1:8787/api` (same paths, minus
the gateway's `/api` prefix duplication — see
`node-server/src/api/routes.ts` for the exact 1:1 mapping). The `/rag/*`
endpoints proxy to the Python service at `http://127.0.0.1:5001`.

Request/response bodies are JSON. All examples use `curl`.

## Simulation control

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/reset` | — | Deletes every drone, group, session, and log entry. Irreversible. |
| GET | `/state` | — | Overview: drone/group counts, full group list, full drone list. |
| GET | `/health` | — | Node's own health, plus whether it can reach the Rust core. |

## Groups

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/groups` | `{"group_id": "alpha"}` | Creates a group with a fresh Merkle tree (depth from server config, default 8 → capacity 256). |
| GET | `/groups` | — | List all groups with root/version/members. |
| GET | `/groups/:id` | — | One group's detail. |

## Drones

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/drones` | `{"drone_id": "drone-3"}` | Creates a simulated device (SRAM PUF initialized), not yet registered to any group. |
| GET | `/drones` | — | List all drones (public fingerprints only — see "Secret redaction" below). |
| GET | `/drones/:id` | — | One drone's detail. |
| POST | `/drones/:id/register` | `{"group_id": "alpha", "role": "recon"}` | Runs R1-R3; refreshes every other active member's witness cache in that group afterward. |
| POST | `/drones/:id/revoke` | — | Zeroes the drone's Merkle leaf, bumps the group version, marks it inactive. |
| POST | `/drones/:id/reactivate` | — | Re-registers a previously-revoked drone with a FRESH leaf (new `rho`), reusing its original Merkle slot. |
| POST | `/drones/:id/move` | `{"group_id": "bravo"}` | Revokes from the old group, registers fresh into the new one. |

## Authentication and key establishment

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/authenticate` | `{"d1_id": "drone-1", "d2_id": "drone-2"}` | Runs the full M1-M8 flow; returns the `VerificationReport` (5 sub-checks + decision + reason code). |
| POST | `/group-key` | `{"d1_id": "...", "d2_id": "...", "mission_id": "m1"}` | Runs K1-K4; the resulting AEAD session key is held server-side (Rust), never returned to any caller. |
| POST | `/secure-message` | `{"from_id": "...", "to_id": "...", "plaintext": "..."}` | Requires a prior `/group-key` call for that pair. Seals with AEAD, "transmits" over the passthrough transport, opens on the "receiver" side, and returns the receiver's decrypted plaintext (a simulation convenience — in the browser this demonstrates round-trip correctness; it does not imply that the server is a message relay for a real deployment). |

## Events

| Method | Path | Notes |
|---|---|---|
| GET | `/events?since=<cursor>` | Incremental fetch from the CURRENT process's in-memory log (Rust-side path; not directly exposed by the Node gateway — used internally by the SSE relay). |
| GET | `/events/history?limit=<n>` | Reads from the durable SQLite `protocol_events` table — survives process restarts. |
| GET | `/events/stream` | Server-Sent-Events stream (Node-side only; polls the Rust core's `/events` endpoint internally, see `docs/architecture.md`). |

## Trace Manager

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/trace/flag` | `{"session_id": "...", "flagged_by": "...", "reason": "..."}` | Records a suspicion flag. |
| POST | `/trace/request` | `{"requested_by": "...", "requester_role": "administrator", "reason": "...", "target_pid_hex": "..."}` | Only resolves a DroneID when `requester_role == "administrator"`; every attempt is logged regardless. |
| GET | `/trace` | — | Full flag + trace-record audit trail. |

## RAG (proxied to Python)

| Method | Path | Body | Notes |
|---|---|---|---|
| POST | `/rag/contribute` | `{"drone_id": "...", "content": "...", "confidence": 0.85}` | |
| POST | `/rag/run` | `{"query": "...", "top_k": 5}` | Runs retrieval → validation → fusion → mock-LLM generation. |
| GET | `/rag/state` | — | Current contributions + last run result. |
| POST | `/rag/reset` | — | Clears in-memory RAG state (independent of `/reset`, which only clears Rust-side state). |

## Secret redaction (structural, not a formatting choice)

Every Rust-side response is built from a hand-written `*View` DTO
(`rust-core/src/api/views.rs`) — there is no code path from an internal
`DroneState`/`GcsState` (which hold private keys, PUF golden patterns,
KEM shared secrets, and AEAD keys) to an HTTP response body that
bypasses these DTOs. Fields you will see: `kem_pk_fingerprint` /
`dil_pk_fingerprint` (an 8-byte SHAKE256-derived fingerprint, not the
key itself), `root_hex` (a public Merkle root), `cached_version`, and
boolean/string verification results. Fields you will NEVER see from any
endpoint: a private key, a PUF seed or golden pattern, a KEM shared
secret, or an AEAD key.
