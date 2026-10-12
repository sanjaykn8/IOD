# Protocol Walkthrough with a real numeric run (R1–R3, M1–M8, K1–K3)

All numbers in the block at the end come from one real execution of
`cargo run --release --example walkthrough` (`rust-core/examples/walkthrough.rs`). Values change on every run (random keys, nonces, PUF noise). Secrets appear only as 4-byte fingerprints. Notation and encodings: `protocol.md`, `zk-specification.md`.

## Your four questions

**1. Why does D2 verify again if the GCS already has the membership details?**
The two checks cover different things. The GCS (M6) checks *registry facts it owns*: PID1 is Consumed for this session, both drones active and in its tree, comm_PK equals its record, the CRP was reserved for this session, root/version unchanged, and the **PUF MAC** (`mac1`, proving the physical device behind PID1 answered `C_PUF` for this exact session). The GCS never receives the ZK proof or `sig1`, so it cannot know that the party talking to D2 *holds* the ML-DSA key in the credential, or that the proof was made for *this* session. D2 is also the relying party that makes the Zero-Trust decision, so it must not outsource trust to a relayed claim: it verifies the proof (leaf under R_G containing this comm_PK, bound to the session digest), `sig1` under the certified D1 key, the credential against the pinned anchor, and the **GCS-signed** M6 result bound to the session. Honest note: in the moderate-anonymity model the GCS-signed credential already authenticates D1's keys, so the ZK proof mainly adds a machine-checked "this leaf under the current root" statement with D1's tree position and `rho` hidden; it is not the only line of defence.

**2. How does D1 have D2's public key to verify sig4? Is M4 KEM-encrypted to PK_KEM_GCS?**
M4 is **not encrypted** and not sent to the GCS; it goes D2→D1 in the clear (it contains only credentials and signed public data). It is *signed* with D2's ML-DSA key (`sig4` is a signature, not a KEM operation). D1 obtains D2's `pk_dil` from **D2's GCS-issued credential carried inside M4**, after verifying that credential's GCS signature against the trust anchor D1 pinned at R3; only then does D1 verify `sig4` with that key. In v1 the key was an unsigned field of M4 itself (self-attested) — fixed. Encryption to `PK_KEM_GCS` is used for M2, M6 and K1 (D2→GCS). M3 is sealed to D2's registered KEM key; K-keys are sealed to each drone's KEM key.

**3. What is C_PUF and what does the PUF simulator do?**
`C_PUF` is the *challenge* of one entry of D1's CRP (challenge-response pair) table that the GCS holds. In M3 the GCS picks a `Fresh` CRP, marks it `Reserved(session)` and signs `C_PUF` into M3. D1 computes `r = PUF(C_PUF)`, derives `k = HKDF(r)` and sends `mac1 = HMAC(k, T_base)` where `T_base` binds the session context and comm_PK; the GCS recomputes it from its stored reference response, then burns the CRP (never reused). The simulator (`puf/sram_puf.rs`) models an SRAM PUF: a 7,936-bit "golden pattern" from the device entropy; `read()` returns it XOR independent per-bit noise (5 %); a code-offset **fuzzy extractor** (repetition code ×31, helper data 992 B) turns a noisy reading into the stable 256-bit seed `s_D` (used for PIDs). The challenge-response function is simulated as a noise-free domain-separated hash of the golden pattern and the challenge, and the GCS table is filled by querying the simulator at provisioning time. There is no physical silicon; the ML-KEM/ML-DSA keys are *not* derived from the PUF.

**4. How is zk_membership done?**
D1 proves knowledge of `rho` and a Merkle path such that `leaf = Poseidon2-sponge(1, G, comm_PK, meta, rho)` and folding the leaf along the path with Poseidon2 nodes gives the public root `R_G`; public inputs are protocol version, `V_G`, `G`, `R_G`, `comm_PK`, metadata digest and the session digest (54 field elements). The relation is arithmetized as an AIR (one Poseidon2 permutation per row, a selector state machine: 6 leaf rows, D Merkle rows, padding) and proven with a transparent STARK with a hiding FRI commitment (random codewords, salted Merkle commitments). The proof (~250 KB) is all D2 receives; D2 rebuilds the public inputs from the GCS-signed M3 data and runs `verify_membership`. Details: `zk-design.md`, `zk-specification.md`.

## Step by step

* **R1** Device enrollment. PUF read → fuzzy extractor `generate` → helper data `W` (public) and seed `s_D` (secret). 16 CRPs and 64 pseudonyms `PID_i = KDF(s_D, i)` are prepared.
* **R2** Drone → GCS: keys, `comm_PK = SHAKE256("IOD/v2/COMM-PK", pk_kem, pk_dil)` packed into 11 limbs, random `rho` (8 field elements), metadata (role, issued_at), PID batch, with an ML-DSA proof of possession and a PUF MAC over the canonical body, bound to a one-time GCS nonce.
* **R3** GCS verifies, computes `leaf`, inserts it in the group tree (V_G ← V_G+1), issues the credential (random 16-byte id, 30 days), registers the PIDs, returns credential, anchors, witness (siblings + path bits), `R_G`, `V_G`. Every other member's cached witness is now stale until refreshed.
* **M1** D1 → D2: `(G, PID1, ts1, n1)`; PID1 is a one-time pseudonym.
* **M2** D2 → GCS (sealed to the GCS KEM key, signed `sig2`): adds D2's credential id, `ts2`, `n2`. GCS resolves PID1→D1 *internally*, checks everything, records nonces. D2 never learns D1's DroneID.
* **M3** GCS → D2 (signed `sig3`, sealed to D2): D1's credential, `R_G`, `V_G`, `C_PUF`, session id; PID1 becomes Consumed; session record created.
* **M4** D2 → D1: challenge + D2's credential + GCS-signed M3 + `sig4`. D1 checks the GCS signature (so `R_G/V_G/C_PUF` really come from the GCS), its own PID/credential, D2's credential against its anchor, then `sig4`.
* **M5** D1 → D2: proof bundle (ZK proof, `mac1`, `sig1`, comm_PK, ids). D1 refuses if its cached root/version differ from the signed ones.
* **M6** D2 → GCS: raw fields + `sig6`; GCS recomputes the transcript from its own state, checks the PUF MAC and the registry, replies with a **GCS-signed** `Valid`/`Invalid` + reason; CRP burned.
* **M7** D2 verifies ZK, `sig1`, the GCS result, binding, freshness, credential → `authenticated`; then the policy engine → ALLOW/DENY + reason.
* **M8** D2 → D1: signed, session-bound result; D1 verifies under D2's certified key and signs a confirmation.
* **K1** D2 → GCS: signed request carrying D1's confirmation. GCS requires session `PufVerified`, ALLOW from D2 and a valid D1 confirmation for exactly this session, both still active; sets `KeyIssued`.
* **K2/K3** GCS returns `K_G,M` sealed separately to D1 and D2 (GCS-signed, session-bound); D2 forwards D1's copy; both decrypt and verify.
* **K4** HKDF with the full context → two directional AEAD keys + channel tag; messages use header `(tag, direction, seq, ts)` as AAD.

## Real run
```
##### Tiny Merkle example (depth 3, 3 members) #####
leaf1 = 1600000016000000…  index=1  path_bits=[1, 0, 0]
  level 0: sibling=0b0000000b000000… bit=1 -> parent=a10da64da43a1641…
  level 1: sibling=11ef9c2ed76e5849… bit=0 -> parent=14840f370ee9471a…
  level 2: sibling=0000000000000000… bit=0 -> parent=b967b60d6d1aa210…
  root = b967b60d6d1aa210…  (tree.root() = b967b60d6d1aa210…)

##### R1-R3 #####
R1 PUF read: 7936 bits; fingerprint of one noisy reading = d3eadf42; two readings differ in 768 bits (noise)
R1 helper data = 992 B (public); seed fingerprint = 33205cb9 (secret, not shown)
R1 CRP table at GCS: 16 entries; CRP[0].challenge = 7d758e0672b0fd2e02f163fb…(16 B) ; reference response fp = 07cb30f2
R2 pk_kem=1184 B, pk_dil=1312 B, comm_PK[0..3]=[15895686, 9874217, 13435150]
R3 leaf = 28309060ed446c3d… ; leaf index = Some(0) ; R_G = 9173e80abe2e3471… ; V_G = 2
R3 credential id = 32dc4909db477241d8fc36f4c2cd4a43 (random, not the DroneID), expires_at_ms - issued = 30 days
R3 PIDs registered: 64 ; PID[0] = fd6dc12f4d893fc5e963f536…(16 B)

##### M1-M8 #####
M1 CommReq: G=alpha PID1=fd6dc12f4d893fc5e963f536…(16 B) ts1=1791804682456 n1=80e2eaa460ed27dfbbea4938…(16 B)
M2 body: d2_cred_id=19838735f2937c61822364249872bca2 ts2=1791804682456 n2=ede58c045ff6214ced6c9c8f…(16 B); sealed wire = 35974 B JSON
   GCS: PID1 resolves internally to 'drone-1' (D2 never sees this); PID state before M3 = Active
M3 session_id=5429ed86ace343b22b743ec34e3beb92 C_PUF=1378738bf9bbab6b3701824e…(16 B) R_G=9173e80abe2e3471… V_G=2 sig3=2420 B; PID state now Consumed; CRP reserved
M4 ts4=1791804682457 sig4=2420 B; carries D2 credential (1312 B pk_dil) and GCS-signed M3
   D1 verified: GCS sig on M3, D2 credential vs anchor, sig4 vs certified D2 key. session_ctx limbs[0..3]=[9313375, 170000, 14063476]
M5 proof = 246022 B (IMP2 header [73, 77, 80, 50]), mac1=90a30a4ad287659afb2956d7…(32 B) sig1=2420 B; bundle JSON has no key/witness fields
M6 GCS result=Valid reason=OK current R_G=9173e80abe2e3471… V_G=2 sig7=2420 B; session state=PufVerified; CRP now Used
M7 VerificationReport { freshness_ok: true, credential_ok: true, commitment_ok: true, zk_membership_ok: true, signature_ok: true, puf_ok: true, root_version_ok: true, session_binding_ok: true, authenticated: true, zero_trust: Allow, reason_code: "ALL_CHECKS_PASSED", session_ctx: [9313375, 170000, 14063476, 4722162, 3897096, 9154886, 1840780, 14165648, 12633271, 15970294, 40670] }
M8 D1 read Allow under D2's certified key; sig8=2420 B; D1 confirm sig=2420 B

##### K1-K3 #####
K1 accepted; session state=KeyIssued
K2 forwarded D1's sealed key; D1 verifies sig8 = true
K3 both hold the same K_G,M: true (fp 23ea135c); epoch=1791804682564 n6=cadf7cd23d715a3af1462e7b…(16 B) n7=12033879bb2bb1b884f31b8a…(16 B)
K4 channel tag = db04d9102b45b28274c186f85be93047 ; d1->d2 key fp = 7139bad9 ; d2->d1 key fp = 71b01e22
```
