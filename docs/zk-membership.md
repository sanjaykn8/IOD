# ZK Membership Proof

**Read this document before citing this project's "zero-knowledge
proof" as providing witness privacy. It does not, in the currently
implemented backend — see "What is NOT achieved" below.**

## The statement being proven

Public inputs: `G, R_G, V_G, comm_PK`.
Private witness: `leaf, siblings[], path_indices[], PK_KEM, PK_Dil, metadata, rho`.

```
leaf     = Poseidon(0x01, PK_KEM, PK_Dil, G, metadata, rho)
comm_PK  = Poseidon(0x02, PK_KEM, PK_Dil)
MerklePath(leaf, siblings, path_indices) == R_G
proof is bound to (G, R_G, V_G, comm_PK)
```

This is exactly the statement in the specification's Circom-style
circuit — which the project brief is explicit is "the logical statement
specification, NOT a mandate to use Groth16." Using Circom + Groth16 (or
any ECC-backed SNARK) is prohibited by the project's non-negotiable
no-ECC requirement.

## Why not a hash-based SNARK/STARK, or MPC-in-the-head, instead?

These were seriously considered and are the technically correct way to
get true zero-knowledge hiding for this kind of statement without ECC.
Concretely:

- A **FRI-based STARK** (transparent, hash-based, matches "no trusted
  setup") would require implementing a polynomial IOP over an
  AIR/algebraic circuit representing the entire Poseidon permutation and
  Merkle-path computation, plus the FRI low-degree test itself — a
  substantial, easy-to-get-subtly-wrong undertaking on its own.
- An **MPC-in-the-head** construction (à la ZKBoo/ZKB++/Ligero) achieves
  ZK for generic circuits from symmetric primitives alone, but correctly
  implementing the "commit to N MPC-party views, open N-1 under a
  Fiat-Shamir challenge" machinery with the right soundness/hiding
  balance is comparably substantial.
- A **lattice-based homomorphic commitment** scheme (to get a
  Pedersen-like additively-blindable Merkle tree without ECC) is its own
  significant construction.

All three are legitimate, buildable-in-principle answers to "transparent
ZK without ECC." None of them could be implemented correctly, safely,
and honestly-verified within this session's scope. Rather than attempt
one under time pressure and risk presenting a subtly-broken construction
as a real security mechanism — which would be a far worse outcome than
an honestly-scoped simplification — this project implements a backend
with the classification below, and isolates it behind a clean
`ZkStatement`/`ZkWitness`/`ZkProof` interface (`rust-core/src/zk/`) so a
real backend could be substituted later without changing any protocol
call site.

## What IS real in the implemented backend (`zk::backend`)

- **Soundness of the algebraic relation.** `verify()` genuinely
  recomputes the leaf Poseidon hash, the PK-commitment Poseidon hash,
  and folds the real Merkle path up to the claimed root, using the same
  code (`merkle::tree::verify_witness`) the rest of the system uses. A
  prover without a witness satisfying every equation cannot produce an
  accepting proof except by breaking Poseidon's collision/preimage
  resistance.
- **G_public/G_witness binding** (spec correction #3): the verifier
  recomputes the leaf hash using the statement's own `G`, not a
  separate witness-side copy. Structurally impossible to splice a
  different group into just the Merkle-path check.
- **V_G actually binds the proof** (spec correction #4/#5): the
  Fiat-Shamir challenge folds in `V_G`, recomputed by the verifier from
  its OWN independently-known current version. A proof generated
  against a stale version is rejected even if every other equation
  still holds — directly tested
  (`stale_version_is_rejected_even_if_root_unchanged_in_the_proof`).
- **Session/replay binding**: the challenge binds the proof to the exact
  `(G, R_G, V_G, comm_PK)` tuple.
- **Transparency**: every hash is a fixed, published, unkeyed function.
  No structured reference string, no trusted setup, no elliptic curve
  anywhere in this module or its dependencies (see `docs/ecc-audit.md`).
- **A genuine hiding commitment primitive** (`witness_commitment`): a
  Poseidon hash of the full witness plus 256 bits of fresh randomness.
  In isolation, this commitment reveals nothing about the witness.

## What is NOT achieved — the honest limitation

A real zero-knowledge proof lets a verifier become convinced a statement
is true **without learning the witness**. This backend's `ZkProof`
carries the hiding `witness_commitment` alongside an `opening` containing
the actual witness values, because `verify()` needs them to run the real
algebraic checks above. **Whoever runs `verify()` — D2, in this
protocol — therefore fully learns `rho` and the Merkle siblings/path
(the leaf's tree position)**, in addition to `PK_KEM`/`PK_Dil`/
`metadata`, which D2 already receives in cleartext via `CredResp` (M3)
regardless of the ZK layer.

**Net effect**: this backend provides a real, checked, Fiat-Shamir-bound
**non-interactive proof of knowledge with full witness disclosure to the
verifier** — not a hiding zero-knowledge proof. It is suitable for
demonstrating the protocol's structure and binding properties in a
research prototype; it must not be cited as providing witness privacy
against the specific verifier the proof is shown to.

## What D2 learns, concretely, with vs. without the ZK layer

| Value | Learned via M3 `CredResp` regardless | Additionally learned via this ZK backend's `opening` |
|---|---|---|
| `PK_KEM_D1`, `PK_Dil_D1` | Yes | (already known) |
| `membership_metadata_1` | Yes | (already known) |
| `rho` | No | **Yes** |
| Merkle siblings / path / leaf index | No | **Yes** |

A hiding backend's entire value-add over the current one is closing
exactly the two "Yes" cells in the right column.

## Swapping in a real backend later

Implement `zk::backend`'s `prove`/`verify` function signatures (same
`ZkStatement`/`ZkWitness`/`ZkProof` types, or a new `ZkProof` variant) as
a FRI-STARK, MPC-in-the-head, or lattice-commitment construction. No
change is required in `protocol::auth_flow` or anywhere else that calls
`zk::backend::prove`/`verify` — this is the "clean interface" and
"document how the real proof backend can later be substituted"
requirement satisfied structurally, not just in prose.
