# Threat Model (protocol v2)

Adversary: network attacker (Dolev–Yao over the simulated channel, harvest-now-decrypt-later quantum capability), a malicious or compromised **member drone**, a **revoked** drone, a curious **peer** (D2), and an unauthorized operator. The **GCS is trusted** (it knows all identities, `rho`, PUF CRPs and issues `K_G,M`).

| Threat | Mitigation (code) | Test |
|---|---|---|
| Key substitution in M4 | D2's key only from a GCS-signed credential verified against the pinned ML-DSA anchor | `t01_forged_m4_key_rejected` |
| Forged/modified GCS messages | `sig3`, M6 result, credentials, group key all GCS-signed | `t02`, `t13` |
| Replay of M2/M6/M8/K1 | nonces in the GCS, single-use PIDs, session state machine, `completed` flag, per-direction `seq` | `t04`, `t09`, `t14`, `t15` |
| Stale PID / expired session | PID `Active→Consumed→Expired`, 24 h validity, 10 min session | `t03` |
| Stale clock/timestamps | ±5 min window everywhere | `t12` |
| Membership not current (revoked/stale cache) | `R_G/V_G` signed by the GCS in M3; D1 refuses stale; GCS re-checks at M6 | `t11`, `t08` |
| Peer learns DroneID | only pseudonymous credential id and PID; ZK hides leaf/path | e2e log check, `zk::tests` |
| Witness leakage | no witness on the wire; type not serializable; redacted Debug | `zk::tests::proof_contains_no_witness_bytes`, `t10` |
| Key issuance without authentication / after DENY | GCS K1 gate: `PufVerified` + ALLOW + D1 confirm + exact session | `t05`, `t06`, `t07`, `t16` |
| Revoked member keeps channel | revocation fails sessions; K1 re-checks activity | `t08` |
| Unauthorized de-anonymization | admin token, reason, flagged session, audit | `trace::tests` |
| Eavesdropping | KEM+HKDF+ChaCha20-Poly1305 envelopes; directional AEAD keys | `envelope`, `t15` |

Out of scope / not mitigated: compromised GCS; physical PUF cloning/modelling attacks (the PUF is a simulator); traffic analysis and linkability; denial of service; side channels; compromise of a drone's stored private keys; real network transport security.

## Steganography transport (added 2026-10-29)
Defended: tampered or truncated stego files, wrong algorithm/metadata (keyed MAC before parse), replay, wrong channel/direction, path traversal via artifact ids, oversize payloads, formula injection in CSV. **Not** defended: steganalysis (detectability is not claimed to be low), lossy handoff (fails closed), a malicious local Python service or loopback eavesdropper (plaintext HTTP carries cover and stego images, not plaintext messages), GCS visibility of plaintext in the simulation, side channels. Artifacts on disk are unencrypted.

### Cover generation (replaces camera / upload covers, 2026-11-15)
The operational transport no longer accepts any image from a client: the upload and camera routes were removed, so the image-parsing attack surface of the transport is gone (the educational workbench keeps its own bounded PNG upload, isolated from sessions and events). What a client can still influence is the `cover_generation` object. Mitigations: whitelist of fields, tighten-only resolution against the process profile, hard ceilings in **both** Rust and Python (size, pixels, candidates, time budget, memory pre-flight, one worker), no seed / file / artifact / source / algorithm field, validation before a sequence number is reserved. Covers usable for re-plan and encode must carry a generation sidecar whose hash matches the PNG, so a file dropped into the artifact directory is not accepted as a cover through the API.

Properties and non-properties of the generated cover:
* The seed is 16 bytes from the OS CSPRNG, independent of plaintext, ciphertext and keys; only a SHA-256 fingerprint is recorded. The cover carries no secret and provides no confidentiality or integrity — those come from the AEAD and the frame MAC.
* Only the payload **length** reaches the selection. The chosen image size (when payload-driven resize is enabled) and the event log therefore reveal a coarse length class to anyone who sees the image or the logs; the image size is visible in the PNG anyway.
* The generator is public. An adversary can produce unlimited covers of the same distribution and train a detector on them; synthetic procedural imagery is also recognisable as such. **No undetectability is claimed.** The offline evaluation (`detectability-evaluation.md`) shows that a small classical detector already separates transport images from covers almost perfectly, mainly through the plain-LSB bootstrap carrier.
* Denial of service: generation cost per request is bounded by the profile (candidates × size × budget); there is still no rate limiting or authentication on the simulator's HTTP API.
* Not defended: a malicious local Python service (it produces the cover and could bias it), a local user writing both a PNG and a matching sidecar into the artifact directory, disk exhaustion by stored covers (use `IOD_STEGO_RETENTION_MAX_ARTIFACTS`).

### Learning workbench (2026-10-30)
The workbench's "real encryption" mode uses a key derived from a **public** label: it provides no confidentiality and is never used operationally; it exists only to demonstrate a valid AEAD envelope surviving extraction. It shares no state with sessions, keys, replay windows or operational events (tested). Uploaded learning covers are limited to 512x512 PNG and are not stored.
STC methods: the element permutation is public (no stego key), which helps a steganalyst but does not affect confidentiality or integrity (AEAD + frame MAC).
