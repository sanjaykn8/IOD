# ZK Membership Specification (frozen statement, protocol v2)

Status: **normative for protocol version 2 / parameter set 1.**
Note on ordering: the implementation was written first and this document
was frozen against it afterwards; every definition below is asserted by a
unit test or by the reference code named in the section header.

Conventions. `A || B` is byte concatenation; a comma separates function
arguments. **No hash input is ever formed by ambiguous concatenation**: every
variable-length item is length-prefixed (§2). Nothing in this document
assumes that reduction modulo p is injective; byte strings are mapped to
field elements only by the injective 3-byte packing of §3.

## 1. Threat/anonymity model (moderate anonymity)

* D2 (the verifier) must **not learn D1's permanent DroneID**.
* Sessions are **linkable**: D1's public keys, `comm_PK` and credential id are
  stable and are revealed in M3/M4. **Unlinkability is not claimed.**
* Membership metadata (`role`, `issued_at`) is **public**, because the
  GCS-signed credential delivered in M3 carries it.
* What the zero-knowledge proof hides: D1's **leaf index / Merkle path** and
  the **leaf blinding `rho_D1`**. It does *not* hide D1's keys or metadata.
* The GCS knows the full tree (including every leaf index and `rho`); the
  proof is not hiding against the GCS.

## 2. Canonical serialization (`rust-core/src/protocol/canon.rs`)

`Canon(domain)` starts with `bytes("IOD-CANON-v2")` then `bytes(domain)`.

| Item | Encoding |
|---|---|
| `u64` | 8 bytes, little-endian |
| `u32` | widened to `u64`, 8 bytes little-endian |
| `bytes(b)` | `u64_le(len(b)) || b` |
| `str(s)` | `bytes(utf8(s))` |
| `limbs(l)` | `u64_le(len(l)) ||` each limb as 4 bytes little-endian |

There is no JSON, delimiter or optional field in anything signed, MAC'd or
hashed. All signatures/MACs are over `Canon` output (or a fixed-width SHAKE256
digest of it).

## 3. Field, hash, packing (`rust-core/src/zkhash.rs`)

* Field: BabyBear, `p = 2013265921 = 2^31 - 2^27 + 1`.
* Permutation `P`: Poseidon2 (Grassi, Khovratovich, Schofnegger, ePrint 2023/323),
  width 16, S-box `x^7`, 8 full + 13 partial rounds, constants of Plonky3
  `p3-baby-bear 0.9.0-rc.1` (`default_babybear_poseidon2_16`). A unit test
  asserts that the AIR's permutation equals the native one.
* Digest: 8 field elements (`Digest`), 248 bits. Sponge rate 8, capacity 8.
* `pack3(bytes)`: split into 3-byte chunks, each chunk (zero-padded to 4 bytes)
  read little-endian. Every value is `< 2^24 < p`, so the map is injective for
  inputs of known length. Callers always length-prefix.
* `shake_limbs(domain, parts)`: SHAKE256 over
  `u64_le(len(domain)) || domain || u64_le(#parts) || for each part: u64_le(len) || part`,
  first 32 output bytes, `pack3` → **11 limbs** (`Limbs`).
* Byte order of a `Digest`/limb vector on the wire: each limb a `u32`
  little-endian; JSON/DB form is the lowercase hex of the 32 bytes. Parsers
  **reject limbs `>= p`**.

## 4. Statement

### 4.1 Domain separators

| Name | Value | Use |
|---|---|---|
| `IOD/v2/GROUP` | SHAKE domain | `G = shake_limbs(.., [group_id_utf8])` |
| `IOD/v2/COMM-PK` | SHAKE domain | `comm_PK = shake_limbs(.., [PK_KEM, PK_Dil])` |
| `IOD/v2/METADATA` | SHAKE domain | `meta = shake_limbs(.., [role_utf8, issued_at_u64_le])` |
| `IOD/v2/SESSION-CTX` | SHAKE domain | `session_context_digest` (§4.4) |
| `DOMAIN_LEAF = 0x4C454146 mod p` | capacity[0] | leaf sponge |
| `PARAM_SET_ID = 1` | capacity[2] | parameter set |
| `LEAF_FORMAT_VERSION = 1` | stream limb 0 | leaf layout version |

### 4.2 Leaf

The leaf stream is 48 field elements:

```
[0]      LEAF_FORMAT_VERSION (=1)
[1..12)  G                (11 limbs)
[12..23) comm_PK          (11 limbs)
[23..34) meta_digest      (11 limbs)
[34..42) rho_D1           (8 uniform field elements, PRIVATE)
[42..48) 0
```

Sponge: state `s = (0^8 || iv)`, `iv = (DOMAIN_LEAF, 48, PARAM_SET_ID, 0,0,0,0,0)`;
for each of the 6 blocks `k`: `s[0..8] += stream[8k..8k+8]`, `s = P(s)`.
`leaf = s[0..8]` after the sixth permutation. A revoked/empty slot is
`Digest::ZERO`; a proof for the zero leaf cannot be produced (checked by prover
and by a test).

### 4.3 Merkle tree

`node(L, R) = (P(L || R))[0..8]` (truncated permutation, 16 → 8). Depth `D`
is a per-group parameter (fixed per proof, part of `ZkParams`, not read from the
proof). `path_bit[i] = 1` means the current node is the right child at level `i`
and the hash order is `node(sibling, current)`.

### 4.4 Public inputs (54 field elements)

```
MembershipPublicInputs = {
  protocol_version (u32 = 2),
  group_version V_G (u32),
  G (11), R_G (8), comm_PK (11), meta_digest (11), session_context_digest (11)
}
```

Order of the field vector: `[protocol_version, V_G, G(11), R_G(8), comm_PK(11), meta(11), session(11)]`.
(`PK_KEM_D1` and `PK_Dil_D1` are public bytes delivered in the GCS-signed
credential; the statement binds them through `comm_PK`, which the **verifier
recomputes natively** from the credential's keys — keys are *not* modelled as
secret witnesses.) Verification additionally requires every limb `< p`.

`session_context_digest = shake_limbs("IOD/v2/SESSION-CTX", [Canon("SESSION-CTX")
(protocol_version, session_id, group_id, V_G, R_G limbs, PID1, D2 credential id,
n1, ts1, n2, ts4, C_PUF)])` — see `transcript.rs`. The GCS recomputes it from its
own session record.

### 4.5 Private witness

`rho_D1` (8 elements), `siblings` (D digests), `path_bits` (D bits). The witness
type is not `Serialize`, its `Debug` is redacted and it is zeroized on drop.

### 4.6 Relation

`R(pub; wit)` holds iff
1. `leaf = LeafSponge(1, G, comm_PK, meta_digest, rho_D1)` (commitment correctness,
   domain-separated, bound to group `G`, metadata and `comm_PK`),
2. folding `leaf` along `(siblings, path_bits)` with `node` yields `R_G`,
3. `protocol_version`, `V_G`, `G`, `R_G`, `comm_PK`, `meta`, `session_context_digest`
   are exactly the public values (they enter the Fiat–Shamir transcript and the
   AIR constrains copies of them), so a proof cannot be replayed for another
   group, root, version, key set or session.

## 5. Proof and transcript serialization

`MembershipProof.bytes = "IMP2" (4 bytes) || param_id (1 byte) || postcard(Proof)`.
`param_id` is checked against the verifier's own `ZkParams`. The proof contains
no witness field. The JSON/DB form is lowercase hex. The M5 `ProofBundle` carries
`session_id, pid1, cred_id_d1, comm_pk, proof, mac1, sig1, ts5, n5` — **no key
fields**.

* `T_base = SHAKE256("PUFBaseTranscript-v1", [limbs_to_bytes(session_ctx), limbs_to_bytes(comm_PK)])` — input of the PUF MAC `mac1`.
* `T = SHAKE256("AuthTranscript-v1", [session_ctx, comm_PK, cred_id_D1, SHAKE256("IOD-ZKPROOF-DIGEST-v2", proof.bytes)])` — signed by D1 with ML-DSA (`sig1`).

## 6. Parameters (`ZkParams::standard`)

BabyBear, degree-5 extension challenge field (155 bits), Keccak-256 Merkle
commitments with random salts, hiding FRI, `log_blowup=3`, `num_queries=70`,
`query_pow=16`, `batch_pow=10`, 5 random codewords. Trace is padded to ≥ 256
rows (`2*(queries + 4*2 opening points)` rounded to a power of two), width ≈ 343
at depth 8. Estimator output (Plonky3): **conjectured 128 bits, proven
(list-decoding) 120 bits, proven (unique-decoding) 74 bits.**
