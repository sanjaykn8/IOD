# Protocol

This document describes the protocol as actually implemented, and lists
every implementation-level correction applied to the frozen
specification, per the project's own ground rule: corrections are only
made where the spec has an API-level, serialization, typing, or library
incompatibility, and every correction preserves the intended security
property, message sequence, and data flow.

## Message stages

- **R1-R3**: drone registration/enrollment (trusted channel).
- **M1-M8**: D1 → D2 authentication, GCS-assisted.
- **K1-K4**: GCS-assisted group-key establishment.
- Application messages: AEAD-protected, sent after K1-K4.

All of these are implemented as individually-callable, individually
testable functions in `rust-core/src/protocol/auth_flow.rs` (M1-M8),
`registration.rs` (R1-R3), and `group_key.rs` (K1-K4) — not as one
monolithic function — specifically so tests can corrupt one message
field between steps and observe exactly which check catches it.

## Implementation-level corrections applied (documented, spec-preserving)

### 1. ML-KEM is a KEM, not textbook public-key encryption

The specification's pseudocode writes `(ct, K) = Enc_KEM(pk, payload)`
as if a KEM could directly encrypt a structured payload. It cannot —
`encapsulate(pk)` only ever produces `(ciphertext, fresh_shared_secret)`.
**Correction**: every such call site now does
`encapsulate → HKDF-derive an AEAD key from the shared secret → AEAD.seal(payload)`,
implemented once in `protocol::envelope::seal_for_recipient` /
`open_as_recipient` and reused for M2, M3, M6, K1, and the group-key
envelopes. See `docs/cryptography.md` for the exact KDF domain and nonce
policy.

### 2. PID → DroneID resolution mechanism (M2, underspecified in the source spec)

The spec says "GCS: Resolves PID1 → DroneID_D1 (internal mapping)"
without saying how, and GCS by design never holds `s_D` (the PUF seed a
PID is derived from), so it cannot recompute a PID on demand.
**Correction**: a pre-registered pseudonym pool — each drone derives a
batch of upcoming PIDs at registration time and submits the
`(pid → drone_id)` bindings to GCS over the same trusted enrollment
channel. See `protocol::entities` module docs for the full reasoning and
the documented trade-off (a finite pool needing periodic top-up).

### 3. C_PUF challenge delivery (M4, underspecified in the source spec)

The spec doesn't say how D2 learns which CRP challenge to forward to
D1. **Correction**: GCS includes the drone's registered CRP challenge in
`CredResp` (`CredD1.crp_challenge`), since GCS is the natural CRP
authority.

### 4. K1's `GroupKeyReq` leaking D1's permanent DroneID (a genuine spec contradiction)

The specification's own K1 payload literally contains
`"D1_ID": DroneID_D1` inside a message *sent by D2* — directly
contradicting the project's own non-negotiable "D2 must not learn D1's
permanent DroneID" requirement. **Correction**: `GroupKeyReq` carries
D1's session PID (`d1_pid1`) instead, resolved by GCS via the same
pseudonym pool as M2. This preserves the message's purpose (GCS learns
which two drones are establishing a key) without the privacy leak.

### 5. G_public / G_witness binding (ZK circuit correction #3 in the brief)

The verifier's leaf recomputation inside `zk::backend::verify` uses the
**public statement's** group field element directly — there is no
separate "G_witness" copy anywhere a malicious prover could splice a
different value into. See `docs/zk-membership.md`.

### 6. V_G actually binds the proof, not just appears as an input (correction #4/#5 in the brief)

The Fiat-Shamir challenge inside the ZK proof folds in `V_G`, and the
verifier recomputes that challenge using **its own** independently-known
current version — not a copy carried inside the proof. A stale proof
(generated against an old version) is rejected even if every other
equation in it still holds. Directly unit-tested
(`zk::backend::tests::stale_version_is_rejected_even_if_root_unchanged_in_the_proof`).

### 7. Canonical, unambiguous encoding everywhere a hash covers multiple fields

Both for Poseidon (leaf, commitment — see `crypto::canonical`) and for
SHAKE256 transcripts and Dilithium signing payloads (see
`crypto::kdf::length_prefixed_concat`), every variable-length field is
explicitly length-prefixed before concatenation, closing the "do not
concatenate variable-length byte arrays ambiguously" requirement.

### 8. Deterministic `seed -> keypair` regeneration is not literally achievable with the chosen library

See `docs/cryptography.md`, "Deterministic key generation limitation."

## What the ZK layer actually hides — and what it does not

D2 learns `PK_KEM_D1`, `PK_Dil_D1`, and `membership_metadata_1` directly
from `CredResp` (M3), by the specification's own design, regardless of
the ZK layer. The ZK proof's witness therefore only needs to keep two
things hidden to add privacy value beyond what M3 already discloses:
`rho` (leaf randomness) and the Merkle path/leaf-index (tree position).
The implemented backend does NOT achieve this hiding — see
`docs/zk-membership.md` for the full, honest accounting.

## Freshness, replay, and staleness

- Timestamp skew window: 5 minutes (`auth_flow::MAX_TIMESTAMP_SKEW_MS`),
  applied to `ts1`, `ts4`, and `ts5`.
- Nonce replay: GCS tracks used `N2` values at the M6 step
  (`GcsState::used_nonces`) and rejects a repeat.
- Root/version staleness: two independent, complementary mechanisms —
  (a) the ZK proof's Fiat-Shamir binding (see correction #6 above), and
  (b) a direct live-state comparison: GCS reports its current
  `(R_G, V_G)` back inside the (signed) `PUFVerifyResp`, letting D2
  detect a concurrent membership mutation without needing the whole
  tree. Both are exercised by dedicated tests.

## Group-key trust assumption (stated plainly, not hidden)

GCS generates `K_G,M` itself and therefore knows the group key. GCS
compromise breaks confidentiality of all traffic protected under that
key. See `docs/threat-model.md`.
