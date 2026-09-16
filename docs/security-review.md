# Security Review

Self-review conducted against the 18 points the project brief requires,
performed after Phase 10's integration testing and ECC audit, over the
actual final code (not a design document).

## 1. Transcript binding

`T_base` and `T` (`protocol::transcript`) both fold in `G, V_G, R_G,
comm_PK_D1, N1, N2, TS1, TS4, PID1` (and `T` additionally the ZK proof
digest), built via explicit length-prefixed concatenation
(`crypto::kdf::length_prefixed_concat`), never raw JSON. **Finding**:
none — this matches the spec's transcript composition exactly, and
every signed/MAC'd object in the protocol goes through an equivalent
explicit-field-list builder (see each `*Payload::signing_bytes()` in
`protocol::messages`). **Fix**: none required.

## 2. Nonce handling

`N1`/`N2`/`N5` etc. are 16-byte random values, freshly generated per
message (`auth_flow::fresh_nonce`). AEAD nonces are handled separately
and correctly (see point 3). **Finding**: `PufVerifyReq.n2` reuse is
checked at GCS (`GcsState::used_nonces`), but this set grows
unboundedly for the life of the process — a real deployment would want
a time-windowed eviction policy. **Fix applied**: documented as an
accepted limitation in `protocol::entities` module docs (not fixed —
correctness is unaffected, only long-run memory growth, acceptable for
a bounded demo).

## 3. Replay protection

Three independent mechanisms, each tested: (a) N2 reuse detection at
M6 GCS-side; (b) timestamp skew window (5 min) on ts1/ts4/ts5; (c) AEAD
sequence-number strictly-increasing check for application messages
(`crypto::aead::open`). **Finding**: none. **Fix**: none required.

## 4. Key separation

Every domain-separated derivation goes through `crypto::domains`'
centralized constant list — verified by inspection that no two
semantically different purposes share a tag. **Finding**: `identity::
keys::derive_device_keys` derives domain-separated seed material for
KEM/Dilithium but (per the documented library limitation) does not feed
it into the actual keygen call. **Fix**: not fixable without a
different PQ library (see `docs/cryptography.md` and
`docs/research-notes.md`); documented, not hidden.

## 5. Domain separation (Poseidon specifically)

`crypto::domains` lists every Poseidon domain tag
(`POSEIDON_LEAF=0x01`, `POSEIDON_PK_COMMITMENT=0x02`,
`POSEIDON_MERKLE_NODE=0x10`, `POSEIDON_ZK_WITNESS_COMMITMENT=0x20`,
`POSEIDON_ZK_FS_CHALLENGE=0x21`, `POSEIDON_GROUP_ID=0x30`) — all
distinct. Directly tested
(`poseidon::tests::domain_separation_changes_output`,
`identity::commitment::tests::distinct_from_leaf_domain`). **Finding**:
none. **Fix**: none required.

## 6. Merkle root/version binding

Two independent, complementary mechanisms (see `docs/protocol.md`
section on freshness): the ZK proof's Fiat-Shamir challenge, and GCS's
live root/version echoed back in `PufVerifyResp`. Both directly tested.
**Finding**: none. **Fix**: none required.

## 7. Proof/key consistency (anti-splicing)

The PK commitment and the leaf both consume the SAME `PK_KEM`/`PK_Dil`
bytes from the same `DeviceKeys` struct; the ZK verifier's leaf
recomputation uses the statement's own `G`, not a witness-side copy
(see `docs/zk-membership.md`, G_public/G_witness binding). **Finding**:
none. **Fix**: none required.

## 8. PUF response handling

The raw PUF response `r1` is never transmitted — only `mac1` (an
HMAC over `T_base` under a key derived from `r1`) crosses the network,
exactly matching the spec's "PUF response -> KDF -> authentication
proof/MAC" chain. Verified by inspection of every M5/M6 message
struct — none contains a raw PUF response field. **Finding**: none.
**Fix**: none required.

## 9. Private-key storage

GCS's persisted state (`storage::snapshots::GcsSnapshot` /
`gcs_state` table) contains only public keys, public metadata, `rho`,
and CRP *reference responses* — never a private key or PUF golden
pattern. Private keys and PUF state live only in
`storage::snapshots::DroneLocalSnapshot` / the `drones_local` table,
modeling per-device flash storage. Directly tested
(`storage::db::tests::gcs_round_trip_preserves_group_root_and_drone_records`
asserts only public fields survive; `drone_local_round_trip_preserves_private_keys_and_cache`
confirms the separate table does carry them). **Finding**: none — the
boundary is structural (two distinct Rust types), not just convention.
**Fix**: none required.

## 10. Group-key lifecycle

GCS generates `K_G,M` fresh per `POST /group-key` call (no reuse across
calls), wraps it individually per recipient via KEM-then-AEAD envelopes,
and the derived `K_AEAD` is session-scoped (folds in N1/N2/N6/N7).
**Finding**: no key-rotation or expiry mechanism exists for an
established group key — it lives for the process lifetime once
established. **Fix**: documented as a known limitation in
`docs/research-notes.md`'s "Threshold or distributed GCS" adjacent
discussion; out of scope for this version (the frozen spec does not
define a rotation protocol either).

## 11. Revocation

`merkle::group_tree::revoke` zeroes the leaf and bumps the version
atomically (one function call, one mutation). `api::state::
SimulationState::revoke_drone` additionally marks the GCS-side record
inactive and refreshes every other active member's cache. Directly
tested end-to-end (`tests/end_to_end.rs::revoke_then_reauthenticate_is_cleanly_denied_end_to_end`,
plus the live curl/Playwright sessions documented in
`docs/IMPLEMENTATION_STATUS.md`). **Finding**: none. **Fix**: none
required.

## 12. Stale witness handling

See `docs/merkle-tree.md`'s "Staleness is a first-class, tested
concern." **Finding**: none. **Fix**: none required.

## 13. Authorization (Zero Trust)

Cleanly separated from authentication (`docs/zero-trust.md`) — the
policy engine never re-derives a cryptographic check, only consumes
booleans. **Finding**: `mission_active`/`device_health_ok` are
structural placeholders always `true`. **Fix**: not a security bug
(they fail closed if ever wired to real `false` data, per the
`DefaultPolicy` check order) — documented as future work, not hidden.

## 14. Identity privacy

MODERATE anonymity model, stated precisely and repeatedly (see
`docs/security-assumptions.md`) — D2 never learns the permanent
DroneID, but CAN link sessions via the stable `comm_PK_D1`. **Finding**:
this is inherent to the frozen specification's own M3 design (sending
PK_KEM_D1/PK_Dil_D1 to D2 in cleartext), not an implementation defect.
**Fix**: none available without redesigning the frozen protocol;
documented instead.

## 15. Logging secrecy

`protocol::events::ProtocolEvent.detail` is always a `String` built
explicitly by call sites from already-public values — never a `Debug`
dump of a struct that might contain secret material. Verified by
inspection of every `log.push(...)`/`self.record(...)` call site in
`api::state` and `protocol::simulation`. **Finding**: none. **Fix**:
none required.

## 16. ZK assumptions

Fully accounted in `docs/zk-membership.md` — soundness is real, hiding
is not achieved, and this is stated as prominently as possible
(module-level doc comment in the source itself, not just in `docs/`).
**Finding**: this is the single largest scope limitation in the project.
**Fix**: not fixable within this session's scope without unacceptable
risk of a subtly-broken from-scratch STARK/MPC construction; documented
extensively instead, with a clean substitution interface for future work.

## 17. Dependency risks

See `docs/dependency-rationale.md` and `docs/ecc-audit.md`. All
dependencies are permissively licensed, actively maintained crates from
reputable sources (RustCrypto, dtolnay, the PQClean/pqcrypto project).
**Finding**: several version pins are required by this sandbox's old
toolchain (see above) — not a security risk per se, but worth revisiting
on a newer toolchain. **Fix**: documented migration path in
`docs/troubleshooting.md`.

## 18. ECC violations

Zero found — full audit in `docs/ecc-audit.md` (dependency graph
inspection across all three language runtimes plus a compiled-binary
string scan). **Finding**: none. **Fix**: none required.

## Bugs found and fixed during this review process (cross-referenced)

1. Fuzzy-extractor reliability parameter (Phase 1) — see `docs/puf.md`.
2. Duplicate/misordered persisted events (Phase 7) — see
   `docs/IMPLEMENTATION_STATUS.md`.
3. Benchmark harness group-ID mismatch (Phase 10) — see
   `docs/benchmarking.md`/`docs/testing.md`.
4. React "Reactivate" button UX bug (Phase 9) — see
   `docs/IMPLEMENTATION_STATUS.md`.

Each was caught by either automated tests or live end-to-end
verification (curl or Playwright), not by static code review alone —
consistent with this project's emphasis on actually running the system
rather than only reasoning about it.
