# Security Assumptions

This document collects, in one place, every assumption a reader should
know before trusting any security claim elsewhere in this repository.
Cross-referenced from `docs/threat-model.md`, `docs/cryptography.md`,
and `docs/zk-membership.md`, which go into more depth on each item.

## Privacy model: MODERATE anonymity, not unlinkable anonymity

`PID_D = SHAKE256(0x03 || s_D || "PID" || counter)` rotates every
session, so a bare PID does not reveal a drone's permanent `DroneID` to
D2 or a network observer. **However**, D2 also receives `PK_KEM_D1`,
`PK_Dil_D1` (and thus can compute `comm_PK_D1`) in cleartext via M3's
`CredResp`, by the specification's own design. These values are STABLE
across sessions. An observer who sees two sessions can link them by
comparing `comm_PK_D1`, without ever learning the permanent `DroneID`.
**This is a moderate anonymity model. It must never be described as
unlinkable anonymity** — this exact phrase is in the code comments of
`identity::pid` and is repeated here because it is a common way this
kind of system gets over-claimed.

## The ZK membership proof does not hide the witness from the verifier

See `docs/zk-membership.md` in full. Summary: `rho` and the Merkle
path/leaf-index are disclosed to whoever runs `verify()` (D2, in this
protocol). Only a hiding-commitment step exists; the corresponding
opening travels with it.

## GCS knows the group key

See `docs/threat-model.md`, "GCS compromise." Stated here again because
it is the single most consequential trust assumption in the K1-K4 flow
and should not require reading two documents to find.

## Poseidon parameters are research-chosen, not production-audited

See `docs/cryptography.md`. The permutation is a real, from-scratch
implementation with a real (if simple) round-constant generation
process, but has not been run through formal parameter-selection
tooling or independent audit.

## Deterministic key regeneration is not literally achieved

See `docs/cryptography.md`, "Deterministic key generation limitation."
Keys are generated once from real entropy and persisted on-device; they
are not regenerated bit-for-bit from the PUF seed on every boot as the
specification's pseudocode implies, because the underlying pqcrypto
library exposes no seeded keygen entry point.

## PUF simulation reliability is probabilistic, not absolute

See `docs/puf.md`'s reliability table. At the default 5% simulated
noise level, the per-authentication-attempt fuzzy-extraction failure
probability is below 10⁻⁶ — small enough to ignore for a bounded demo,
not exactly zero.

## No TLS between local services

See `docs/threat-model.md`. Acceptable only because every service in
this project binds to `127.0.0.1` and nothing crosses a real network.

## Steganographic concealment is not, and does not substitute for, encryption

Registration (R1-R3) can be transported by embedding a KEM-then-AEAD
**already-sealed** envelope into a cover image (`docs/registration-
stego.md`). The steganographic layer's job is concealment (making the
transmitted image not obviously carry hidden data); it contributes
nothing to confidentiality or integrity, both of which come entirely
from the encryption applied before embedding. This assumption is
stated explicitly because steganography is a common source of
over-claiming in exactly the direction this project avoids elsewhere:
"hidden" must never be read as "secure" on its own. See
`docs/data-and-evaluation.md` for what was and wasn't evaluated about
the concealment itself (no steganalysis-resistance claim is made).

## Classical vs. post-quantum security levels, stated per-primitive

| Primitive | Classical security basis | Post-quantum consideration |
|---|---|---|
| Kyber768 (ML-KEM-768 predecessor) | Module-LWE hardness | Believed PQ-secure (no known efficient quantum attack); standardized as ML-KEM-768 (FIPS 203) |
| Dilithium2 (ML-DSA-44 predecessor) | Module-LWE/Module-SIS hardness | Believed PQ-secure; standardized as ML-DSA-44 (FIPS 204) |
| Poseidon / SHAKE256 | Collision/preimage resistance of the hash construction | Symmetric primitives generally considered PQ-robust at roughly halved security level against Grover's algorithm; Poseidon here is research-parameterized (see above), so no specific bit-security figure is claimed |
| ChaCha20-Poly1305 | IND-CPA + INT-CTXT under standard AEAD definitions | Symmetric; considered PQ-robust at roughly halved key-search security against Grover's algorithm (256-bit key here, so this is not a practical concern) |
| ZK membership proof | Soundness reduces to Poseidon collision resistance + Merkle binding | Hash-based, so no ECC-style quantum vulnerability from Shor's algorithm; **hiding property not achieved by the current backend regardless of PQ status — see docs/zk-membership.md** |

No number in the table above should be read as a formal, audited
security-level claim (e.g. "128-bit post-quantum security") — these are
qualitative characterizations of the underlying hardness assumptions,
consistent with the project's "no silent cryptographic claims"
requirement.
