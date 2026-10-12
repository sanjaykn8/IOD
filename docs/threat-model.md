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
