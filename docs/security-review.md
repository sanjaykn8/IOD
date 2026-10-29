# Security Review (protocol v2 hardening)

Scope: this review covers the v2 changes; the v1 review is superseded (see git history `baseline-upload`). Nothing here is an external audit.

## Findings fixed in v2
| # | Finding (v1) | Severity | Fix |
|---|---|---|---|
| 1 | "ZK" backend transmitted the full witness (leaf, path, keys, rho) | Critical | Plonky3 hiding-FRI STARK; no witness on the wire; backend deleted |
| 2 | Goldilocks Poseidon, 64-bit digest (≈2^32 collision) | Critical | Poseidon2/BabyBear, 248-bit digest |
| 3 | D2's key accepted from an unsigned M4 field | High | GCS-signed credentials + pinned anchor |
| 4 | M3 and M6 results unauthenticated / failures unsigned | High | GCS signatures on M3 and every M6 outcome |
| 5 | K1 accepted without a completed session; literal nonces, `[0u8;32]` context | High | session state machine, D1 confirmation, canonical KDF context |
| 6 | PIDs reusable | Medium | PID lifecycle `Active/Consumed/Expired` |
| 7 | Replay set not durable | Medium | nonces and sessions persisted |
| 8 | Trace endpoint trusted a body role string | High | admin token, reason, flagged-session rule, audit |
| 9 | M8 carried a public key and was not session-bound | High | no key field; bound to `session_ctx`; replay flag |
| 10 | Secure-message headers carried identities | Low | pseudonymous channel tag |

## Findings found while testing v2
* A replayed M6 initially looked "accepted": it returns a GCS-signed `Invalid(SESSION_REPLAY_OR_WRONG_STATE)` and leaves the session untouched; the test now asserts exactly that.
* The CRP pool (16) is exhausted after 16 sessions per drone and there is no refill; documented, bench re-enrolls.
* Plonky3 estimator with a degree-4 challenge field gave only 111/102/74 bits; moved to degree 5 (128/120/74).

## Open items (not fixed)
GCS-known group key; linkable sessions; ZK adds little to authenticity in the moderate model (see `zk-security-analysis.md`); no statistical privacy experiment; RC-version Plonky3; Round-3 PQ libraries; `iod_simulation.db` stores private keys; no constant-time claims; JSON wire format; trace flagging is unauthenticated (anyone can flag).

## Steganography integration review (2026-10-29)
Checks done: MAC verified before AppWire parse and before AEAD open; constant-time compare; `recv_seen` committed only after successful open; bootstrap validated (CRC, length bounds vs capacity) before extraction; artifact ids whitelisted; atomic exclusive writes; state mutex not held across Python calls; secrets/witness never logged. Open: no TLS on the loopback hop (deliberate, ECC avoidance); no steganalysis resistance; camera path untested on hardware.

## Webcam / cover upload review (2026-10-30)
Upload route validated by tests (non-PNG, JPEG, garbage PNG, bad base64, size limits, id traversal) and a real-browser run. Body limits are raised only for `/api/stego/cover/upload`. The captured frame is re-encoded server-side, so the saved cover contains only decoded pixels. Open: no camera hardware test; frames are not liveness-checked (the simulator does not claim that the cover proves anything).
