# Merkle Tree

## Leaf construction

```
L_D,G = Poseidon(0x01, PK_KEM, PK_Dil, G, metadata, rho)
```

Every variable-length input (`PK_KEM`, `PK_Dil`, `metadata`'s role
string) is canonically encoded via `crypto::canonical::encode_bytes`
before hashing: a length-prefix field element, then 8-byte little-endian
chunks. The whole record is wrapped in `encode_record`, which also
prefixes a field-count, so two different field-layouts can never collide
even if their flattened element streams would otherwise match. `G` (a
string group identifier) is mapped to a single canonical field element
via a dedicated Poseidon domain (`identity::group_id::group_field`)
before being folded into the leaf — see `docs/protocol.md` correction
for the reasoning.

## PK commitment

```
comm_PK_D = Poseidon(0x02, PK_KEM, PK_Dil)
```

Sourced from the exact same `PK_KEM`/`PK_Dil` bytes used for real
Dilithium/ML-DSA signature verification elsewhere in the protocol (both
come from the same `identity::keys::DeviceKeys` struct), preventing
proof/key splicing by construction.

## Tree structure (`merkle::tree::MerkleTree`)

A complete binary tree of fixed `depth`, stored as a flat 1-indexed
array (`nodes[1]` = root; children of `nodes[i]` are `nodes[2i]` and
`nodes[2i+1]`). Empty/unassigned/revoked leaf slots hold `Fp::ZERO` as a
sentinel — a legitimately computed leaf collides with `Fp::ZERO` only
with cryptographically negligible probability (Poseidon's output is
effectively uniform over the field), so this is a safe, standard
"sparse-tree-via-zero-sentinel" simplification.

Witness convention: `path_indices[i] == 1` means "the current node is
the RIGHT child at this level" (verify with `hash(sibling, current)`);
`0` means LEFT child (`hash(current, sibling)`) — matching the
specification's own `PositionSwitcher` convention (`s == 1` swaps the
pair) exactly.

## Group-level membership manager (`merkle::group_tree::GroupMembershipTree`)

One tree per group, owned entirely by GCS. Tracks:
- `version` (`V_G`), incremented on every mutation (register, revoke).
- `member_index` (drone_id → leaf index, active members only).
- `all_index` (drone_id → leaf index, ever registered) — so a revoked
  slot can only ever be reused by the SAME drone re-registering, never a
  different drone, avoiding identity confusion under churn (a documented
  trade-off: the tree "fills up" faster than if slots were freely
  reused, acceptable for a research prototype).

Operations: `register`, `revoke` (zeroes the leaf, bumps version),
`witness_for`, `refresh_all_witnesses` (recomputes every active member's
witness from the current tree — the concrete implementation of "drones
must not need the entire tree" combined with "regenerate affected
witnesses").

## Staleness is a first-class, tested concern

A drone's locally cached `(root, version, witness)` can go stale the
moment any OTHER drone registers, is revoked, or moves — this is
demonstrated directly by
`protocol::simulation::tests::stale_witness_after_another_member_joins_still_authenticates_since_d1_never_refreshed_its_own_slot`,
which shows authentication correctly DENYING until the stale drone's
cache is refreshed. Detection happens at two layers (see
`docs/protocol.md`): the ZK proof's version binding, and GCS's live
root/version comparison inside `PUFVerifyResp`.
