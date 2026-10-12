# Protocol v2 (post-quantum, no ECC) — as implemented

> **Protocol-correction / migration note.** v1 had these defects, all fixed in v2:
> (1) the ZK backend sent the whole witness; (2) D1 learned D2's key from an
> unsigned, self-attested M4 field; (3) M3 was not authenticated by the GCS; (4) M6
> failures were unsigned errors; (5) M8 carried a public key and was not
> session-bound; (6) K1 used literal `"n1"/"n2"/"n6"/"n7"` nonces and a `[0u8;32]`
> context and was not tied to a completed authentication session; (7) PIDs were not
> single-use; (8) the trace endpoint trusted a caller-supplied role string.
> v1 snapshots/JSON/hashes are not readable by v2 (re-enroll all drones).
> Source of truth: `rust-core/src/protocol/*.rs`. Encodings: `zk-specification.md` §2–§5.

## Trust anchors
Each drone pins, at enrollment (R3), the **GCS ML-DSA-44 public key** (trust anchor)
and the **GCS ML-KEM-768 public key**. Every key used to verify a message comes from
a **GCS-signed credential** (`SignedCredential`, ML-DSA over canonical bytes) verified
against the anchor — never from the message being verified. No certificates other than
these ML-DSA credentials exist; no ECC anywhere.

## Entities and state
* **Drone**: SRAM-PUF simulator + fuzzy extractor (seed `s_D`), ML-KEM/ML-DSA keypairs (random, persisted; not derived from the PUF), `rho_D`, credential, cached Merkle witness/root/version, PID counter.
* **GCS**: ML-DSA/ML-KEM keys, per-group Poseidon2 Merkle trees, drone records (public keys, comm_PK, credential, CRP table), `cred_index`, PID pool (`Active→Consumed(session)→Expired`, 24 h validity), **durable session records** (`CredIssued→PufVerified→KeyIssued` or `Failed`), seen-nonce set, enrollment nonces. Sessions, PIDs, CRPs and nonces are persisted in the SQLite snapshot.
* CRP lifecycle: `Fresh → Reserved(session) → Used` (16 CRPs per drone; no refill in the simulator — re-enroll).

## Enrollment R1–R3
* **R1** (device): PUF read → fuzzy-extractor `generate` (seed `s_D`, helper data); factory provisioning of 16 CRPs `(challenge, response)` (**simulated**: the GCS table is filled by querying the PUF simulator directly); 64 PIDs `PID_i = KDF(s_D, i)`.
* **R2** (drone → GCS): `EnrollmentBody{drone_id, group, pk_kem, pk_dil, comm_PK, rho, metadata, pid_batch, gcs_nonce, ts}` with an **ML-DSA proof-of-possession** and a **PUF MAC** (key = HKDF(PUF response of a provisioned CRP)) over the canonical body, bound to a fresh GCS nonce.
* **R3** (GCS): checks nonce, freshness, PoP, `comm_PK == H(pk_kem, pk_dil)`, canonical `rho`, MAC; computes the leaf, inserts it (version++), issues a 30-day `SignedCredential{cred_id (random 16 B), group, keys, comm_PK, metadata}` (no permanent DroneID), registers the PIDs and returns credential, trust anchors, Merkle witness, `R_G`, `V_G`.
The GCS knows `rho`; privacy is vs. other drones, not vs. the GCS.

## Authentication M1–M8
| Msg | From → To | Content | Verified by |
|---|---|---|---|
| M1 | D1→D2 | `CommReq{G, PID1, ts1, n1}` | — |
| M2 | D2→GCS | `{G, PID1, n1, ts1, D2 cred id, ts2, n2}` + `sig2`, sealed (KEM+HKDF+ChaCha20-Poly1305) to the pinned GCS KEM key | GCS: D2 registered/active/in group, sig2 under D2's registered key, freshness, PID1 `Active` and unexpired, D1 active & in tree, nonces unseen |
| M3 | GCS→D2 | `SignedCredResp{session_id, PID1, D2 cred id, n2, cred_D1, R_G, V_G, C_PUF, ts3, expiry}` signed `sig3`, sealed to D2's registered KEM key | creating it **consumes PID1** (bound to the session), reserves one CRP and creates the durable session. D2 checks `sig3` under the anchor, echoes, group, freshness, and cred_D1 against the anchor |
| M4 | D2→D1 | `Challenge{session, G, PID1, C_PUF, n2, ts4, D2 cred id}` + `sig4` + D2's credential + the **GCS-signed M3** | D1: GCS signature on M3, echo of its own PID1, its own credential equals cred_D1, D2's credential verifies against the anchor, **sig4 under the certified D2 key**, freshness. D1 thereby learns `R_G, V_G, C_PUF` from the GCS, not from D2 |
| M5 | D1→D2 | `ProofBundle{session, PID1, cred_id, comm_PK, ZK proof, mac1, sig1, ts5, n5}` — no keys, no witness | D1 first requires cached root/version == the GCS-signed `R_G/V_G` (else `STALE_MEMBERSHIP`). `mac1` = HMAC(HKDF(PUF(C_PUF)), T_base); `sig1` = ML-DSA over T (see spec §5) |
| M6 | D2→GCS | raw fields + `sig6`, sealed to GCS | GCS recomputes `session_ctx`/`T_base` from its **own** values; checks D2 signature, session state, expiry, freshness, nonce, PID `Consumed` and bound, both drones active, comm_PK equals its record, CRP `Reserved(session)`, root/version unchanged since M3, then the PUF MAC. A replay/wrong state yields `SESSION_REPLAY_OR_WRONG_STATE` without touching the session. **Every authenticated failure returns a GCS-signed `Invalid` with a reason code**; the CRP is burned |
| M7 | D2 (local) | `m7_verify_and_decide` | freshness, credential, commitment (`proof.comm_PK` = cred_D1's, ids), **ZK verify** with public inputs rebuilt by D2, `sig1` under the certified D1 key, GCS-signed M6 result bound to the session, root/version equality, session binding ⇒ `authenticated`. **Authorization is separate**: `PolicyEngine` (Zero Trust) returns ALLOW/DENY + reason code |
| M8 | D2→D1 | `AuthResult{session, session_ctx, ALLOW/DENY, reason, D2 cred id, ts8, n8}` + `sig8`, no key field | D1 verifies under D2's certified key, session binding, freshness, `completed` flag blocks replay. D1 then signs a `SessionConfirm` |

## Group key K1–K4
* **K1** D2→GCS: `GroupKeyReq{session, mission, D2 cred id, session_ctx, D2 result, D1's signed confirm, ts6, n6}` + `sig6`, sealed to GCS.
* GCS (`gcs_handle_k1`) requires: session exists and is **`PufVerified`** (so M1–M8 reached the GCS's own M6 verification), D2's signature, D2 result **ALLOW**, D1's confirmation (signature under D1's registered key, same session/ctx, result_seen ALLOW), matching `session_ctx`, both drones still active, fresh `n6`, session not expired. It then sets `KeyIssued` (**one key per session**).
* **K1 response**: GCS generates `K_G,M` and puts it into `SignedGroupKeyInner` (GCS-signed; includes session, ctx, recipient cred id, epoch, n6, n7) sealed separately to D1 and D2. **The GCS knows the group key** (documented trust assumption).
* **K2** D2→D1 forwards D1's sealed copy with `sig8`; D1 checks it under D2's certified key. **K3** both decapsulate, verify the GCS signature and session binding.
* **K4** `derive_channel_keys`: HKDF over `K_G,M` with the full canonical context (group, mission, session, ctx, both credential ids, epoch, n6, n7) → two **directional** AEAD keys plus a 16-byte channel tag. No key/nonce reuse across sessions or directions.
* **Secure messages**: header `{channel_tag, direction, seq, ts}` is AAD; no DroneID/PID; strictly increasing `seq` per direction (replay rejected).

## Revocation
`revoke_drone`: record inactive, Merkle leaf zeroed (V_G++), all PIDs expired, open sessions failed (`MEMBER_REVOKED`). Other members must refresh witnesses; stale caches cannot prove.

## Trace Manager (not in the auth path)
Admin token (`IOD_ADMIN_TOKEN`, ≥16 chars, constant-time HMAC compare, fail closed), non-empty reason, target PID must belong to a **flagged** session; every attempt is audited with an outcome.

## Known limitations
GCS knows `K_G,M`, `rho`, and all identities; sessions are linkable; private keys are not PUF-derived (library has no seeded keygen); CRP provisioning is simulated and there is no CRP refill; GCS does not itself verify the ZK proof; pqcrypto Round-3 Kyber/Dilithium rather than final FIPS 203/204 encodings; wire format is JSON (byte arrays as number lists), so message sizes are inflated; no real network transport.
