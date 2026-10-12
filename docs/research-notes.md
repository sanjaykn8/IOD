# Research Notes

This project is intended as a base for further research work, not a
finished product. This document collects the specific places where a
follow-on research effort would plug in, and the trade-offs made in this
version that a paper or thesis building on this codebase should
acknowledge explicitly.

## Resolved in v2: hiding-ZK for the membership relation

The v1 open problem (a transparent, non-ECC proof that hides `rho` and the Merkle path) is addressed by the hiding-FRI zk-STARK described in `zk-design.md` and `zk-security-analysis.md`. Remaining research questions: unlinkable (anonymous-credential) membership that also hides keys and metadata; quantum-ROM soundness of the FRI-based proof; smaller proofs (currently ≈250 KB); PUF-derived keys; removing the GCS from the group-key trust base.
## Poseidon parameterization needs formal review

The current instantiation (t=3, 8 full + 22 partial rounds, x^7 S-box,
Goldilocks-style field) is a reasonable, conservative, from-scratch
choice, but has not been run through the reference Poseidon
parameter-selection scripts or received independent cryptanalysis. A
research contribution here: run the formal security-margin analysis and
either confirm these parameters or publish a corrected set, ideally with
a documented performance/security trade-off curve.

## PID pool exhaustion and top-up

The pre-registered pseudonym pool (see `docs/protocol.md` correction
#2) is provisioned in fixed batches
(`registration::PID_POOL_BATCH_SIZE = 64`) at registration time, with no
automatic top-up mechanism implemented. A research/engineering
extension: design and implement a top-up protocol (drone periodically
submits a fresh batch over the enrollment channel) and analyze the
availability trade-off if a drone is offline for longer than its pool
lasts.

## CRP reconciliation for the challenge-response path

`puf::crp` deliberately does not apply fuzzy-extractor-style error
correction (see `docs/puf.md`). Extending the code-offset construction
(or a different reconciliation mechanism entirely) to the CRP path would
make the PUF-MAC step robust to the same noise level as the seed-
reconstruction path, closing a real (if currently simulated-away) gap.

## Deterministic PQ keygen

If a future toolchain upgrade allows using `pqcrypto-mlkem`/
`pqcrypto-mldsa` (which still don't expose seeded keygen either, as of
this writing) or a different PQ library that does support
deterministic/seeded key generation, revisiting
`identity::keys::derive_device_keys` to achieve the specification's
original "regenerate keys from the PUF seed with zero persistent
storage" property would be a meaningful fidelity improvement over the
current "generate once, persist on-device" compromise.

## Threshold or distributed GCS

`docs/threat-model.md`'s single largest stated risk (GCS compromise
breaks group-key confidentiality) could be addressed by a
threshold-cryptography redesign of the K1-K4 flow — a substantial
protocol change, explicitly out of scope for "the specification is
frozen" in this version, but a natural next research question.

## What would change if steganography is added later

`transport::TransportProvider` is the intended seam
(`rust-core/src/transport/mod.rs`). A `SteganographyTransportProvider`
implementing the same trait would need: an embedding capacity analysis
(how many AEAD-ciphertext bytes fit per carrier image at what
detectability cost), a decision on carrier acquisition/management, and
almost certainly a larger `NONCE_LEN`/message-chunking scheme if
ciphertexts exceed single-image capacity. None of `protocol::
secure_messaging` or anything upstream of it should need to change.
