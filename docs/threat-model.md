# Threat Model

## Trusted

- **GCS** — the root of trust for group membership, PUF CRP references,
  and group-key generation. GCS compromise is explicitly IN the threat
  model's consequence set (see "GCS compromise" below) but GCS's honest
  operation is an assumption of the base protocol, matching the frozen
  specification's design.
- **Cryptographic libraries** — `pqcrypto-kyber`/`pqcrypto-dilithium`
  (PQClean-derived), RustCrypto's `chacha20poly1305`/`sha2`/`sha3`/
  `hkdf`/`hmac`, and this project's own from-scratch Poseidon
  implementation (the last of these is research-parameterized and NOT
  independently audited — see `docs/cryptography.md`).
- **The local execution environment** — this is a single-machine
  research simulator; all inter-service traffic (React↔Node↔Rust↔Python)
  travels over plaintext HTTP on `127.0.0.1`. No TLS is used anywhere in
  this demo, which is acceptable ONLY because nothing crosses a real
  network boundary. Deploying any of these services across a real
  network without adding TLS (or another confidentiality/integrity
  layer) between them would be a meaningful gap — noted here explicitly
  so it is not accidentally carried into a future networked deployment.

## Potentially malicious / untrusted

- **An unregistered or revoked drone** attempting to authenticate.
  Defended against: `GcsState::drones` active-flag checks (M3, K1),
  Merkle non-membership (ZK proof fails), CRP mismatch (PUF-MAC fails).
- **A compromised, previously-legitimate drone** (its private keys and
  PUF golden pattern known to an attacker). This is a genuine gap in
  ANY system: a fully compromised endpoint can do anything the
  legitimate endpoint could. The mitigation is operational
  (revocation) and detective (Trace Manager), not preventive at the
  cryptographic layer — a compromised-but-not-yet-revoked drone
  authenticates successfully by design.
- **A network attacker** (passive eavesdropper or active
  man-in-the-middle) — relevant conceptually even though this demo runs
  entirely on localhost. Defended against: KEM-then-AEAD envelopes for
  M2/M3/M6/K1/group-key delivery, Dilithium signatures over canonical
  transcripts for M4/M5/M8, nonce/timestamp freshness checks, AEAD
  authentication tags on application messages.
- **A replay attacker** — defended against via the nonce-reuse check at
  M6 and the timestamp-skew window; AEAD sequence-number replay
  protection for application messages.
- **A message-tampering attacker** — any bit-flip in a signed transcript
  invalidates the signature (tested); any bit-flip in an AEAD ciphertext
  or its associated data fails the authentication tag (tested); any
  bit-flip in a ZK proof's opening fails the commitment-binding check
  (tested).
- **A malicious RAG contributor** — partially mitigated by the
  similarity-outlier heuristic in `rag/validation.py`, explicitly
  documented as a demonstration-level defense with no characterized
  error rate, not a real Byzantine fault-tolerant mechanism.
- **A non-administrator attempting to de-anonymize a drone via the
  Trace Manager** — defended against structurally: `TraceManager::
  request_trace` only resolves a PID when `requester_role ==
  "administrator"`, and every attempt (authorized or not) is logged.

## GCS compromise: explicitly IN scope, with stated consequences

Per the frozen specification's design, **GCS generates the group key
`K_G,M` itself** (see `docs/protocol.md`, K1-K4). This means:

- **Confidentiality**: a compromised GCS can decrypt all group traffic
  protected under any key it issued (past or future, until keys are
  rotated and old ones are no longer in use).
- **Integrity of membership**: a compromised GCS can forge Merkle
  roots/versions and CRP reference responses, since it is the sole
  authority for both.
- **Availability**: GCS is a single point of failure for authentication
  and group-key establishment (no distributed/threshold GCS is
  implemented).

This is a deliberate, spec-mandated design choice, not an oversight —
and it is exactly why the project brief requires it to be stated
plainly rather than glossed over. A deployment wanting to reduce this
exposure would need a redesigned (threshold or distributed) GCS, which
is explicitly out of scope for this frozen-specification implementation.

## Explicitly out of scope for this version

- **Steganography** — no image/media embedding is implemented; only the
  clean `transport::TransportProvider` interface exists for future work.
- **A distributed or threshold GCS.**
- **Network-layer TLS between the four local services** (see "local
  execution environment" above).
- **Formal verification of the protocol state machine or the Poseidon
  parameterization.**
