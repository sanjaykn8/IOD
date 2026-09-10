## Part 1 — Complete workflow from start to end

### 0) Global notation and primitives

**Entities**
- **GCS**: Ground Control Station (trusted authority).
- **D1**: Initiator drone.
- **D2**: Receiver/verifier drone.

**Groups and membership**
- **G**: Group identifier (e.g., mission group).
- **R_G**: Merkle root for group G’s membership tree.
- **V_G**: Monotonic version number for group G (incremented on join/revoke).
- **L_D,G**: Leaf for drone D in group G.
- **Path_D,G**: Merkle authentication path (witness) for leaf L_D,G.
- **index_D,G**: Leaf index in the Merkle tree (0-based integer).
- **membership_metadata_D**: Public, non-sensitive metadata (role, issue time, etc.).
- **ρ_D**: Randomness for leaf commitment (32 bytes).

**Cryptographic primitives**
- **Poseidon**: ZK-friendly hash used inside the ZK circuit.
  - Leaf:  
    \[
      L_{D,G} = \text{Poseidon}(0x01 \,\|\, PK\_KEM_D \,\|\, PK\_Dil_D \,\|\, G \,\|\, metadata_D \,\|\, \rho_D)
    \]
  - PK commitment:  
    \[
      comm\_PK_D = \text{Poseidon}(0x02 \,\|\, PK\_KEM_D \,\|\, PK\_Dil_D)
    \]
- **SHAKE256**: Used outside ZK for transcripts and non-ZK hashes.
- **KDF**: HKDF-SHA256 or SHAKE-based KDF.
- **MAC_k(m)**: HMAC-SHA256(m) under key k.
- **Kyber768 (ML-KEM)**:  
  - Enc_KEM(pk, m) → (ct, K_shared)  
  - Dec_KEM(sk, ct) → K_shared 
- **Dilithium2 (ML-DSA)**:  
  - Sign_Dilithium(sk, m) → σ  
  - Verify_Dilithium(pk, m, σ) → accept/reject
- **PUF**:  
  - PUF(D, C) → r (device D, challenge C).  
  - GCS stores CRP: (C, r_ref) per drone.

**Keys (per drone D)**
- **s_D**: PUF-derived seed (from SRAM PUF + helper data).
- **(PK_KEM_D, SK_KEM_D)**: Kyber768 key pair derived deterministically from s_D.
- **(PK_Dil_D, SK_Dil_D)**: Dilithium2 key pair derived deterministically from s_D.
- **PK_KEM_GCS, SK_KEM_GCS**: GCS Kyber768 key pair (PK known to all drones).

**Identifiers**
- **DroneID_D**: Permanent logical identity (GCS-only; not sent to D2).
- **PID_D**: Ephemeral pseudonym for session (e.g., PID_D = SHAKE256(0x03 || s_D || “PID” || counter)).

**Timestamps and nonces**
- **TS_i**: Timestamp for message i.
- **N_i**: Random nonce (16–32 bytes) for message i.

**Transcripts**
- **T_base** (for PUF-MAC):  
  \[
    T_{base} = (G, V_G, R_G, comm\_PK_{D1}, N_1, N_2, TS_1, TS_4, PID_1)
  \]
- **T** (full auth transcript):  
  \[
    T = \text{SHAKE256}(
      \text{"AuthTranscript"} \,\|\, 
      G \,\|\, V_G \,\|\, R_G \,\|\, 
      comm\_PK_{D1} \,\|\, 
      \pi_M \,\|\, 
      N_1 \,\|\, N_2 \,\|\, 
      TS_1 \,\|\, TS_4 \,\|\, 
      PID_1
    )
  \]
  where \(\pi_M\) is the ZK membership proof (or its hash if large).

***

### 1) Registration (GCS enrolls D into group G)

**R1 — D generates PUF-derived keys (on-device)**  
On drone D:
- \(s_D \leftarrow\) PUF_seed_from_SRAM() (with helper data).
- \((PK\_KEM_D, SK\_KEM_D) \leftarrow\) Kyber768.KeyGen_from_seed(\(s_D\), domain="KEM").
- \((PK\_Dil_D, SK\_Dil_D) \leftarrow\) Dilithium2.KeyGen_from_seed(\(s_D\), domain="DIL"). 
Derive domain-separated deterministic randomness from the reconstructed PUF seed and feed that randomness into the exact deterministic key-generation interface supported by the selected ML-KEM/ML-DSA implementation. Do not assume the library exposes a function literally named KeyGen_from_seed
- Send to GCS over secure enrollment channel (e.g., TLS):
  - EnrollmentRequest = { DroneID_D, G, PK_KEM_D, PK_Dil_D, membership_metadata_D }

**R2 — GCS creates leaf and updates Merkle tree**  
GCS:
- Chooses randomness \(\rho_D\) (32 bytes).
- Computes leaf:
  \[
    L_{D,G} = \text{Poseidon}(0x01 \,\|\, PK\_KEM_D \,\|\, PK\_Dil_D \,\|\, G \,\|\, metadata_D \,\|\, \rho_D)
  \]
- Updates group G’s Merkle tree:
  - Insert \(L_{D,G}\) at position index_D,G.
  - Recompute affected hashes → new root \(R_G'\).
  - Increment version: \(V_G' = V_G + 1\).
- Computes Path_D,G (authentication path for \(L_{D,G}\)).
- Stores:
  - (DroneID_D, G, PK_KEM_D, PK_Dil_D, metadata_D, \(\rho_D\), \(L_{D,G}\), \(V_G'\), index_D,G).
  - CRP for PUF: (C_default, r_ref) or helper data.

**R3 — GCS → D: EnrollmentResponse**  
GCS sends (secure channel):
- { G, R_G', V_G', Path_D,G, index_D,G, PK_KEM_GCS }

Drone D stores:
- G, R_G, V_G, Path_D,G, index_D,G, PK_KEM_GCS.
- Does not store long-term secrets; s_D is regenerated from PUF when needed.

### 2) Authentication and key establishment (D1 initiates with D2)

#### M1 — D1 → D2: CommReq

D1 computes:
- G: from local state.
- PID1: ephemeral pseudonym:
  \[
    PID_1 = \text{SHAKE256}(0x03 \,\|\, s_{D1} \,\|\, \text{"PID"} \,\|\, counter_1)
  \]
- TS1, N1.

M1 payload:
```json
{
  "msg_type": "CommReq",
  "G": G,
  "PID1": PID1,
  "TS1": TS1,
  "N1": N1
}
```

D2 receives M1 and stores (G, PID1, TS1, N1) as session context.

***

#### M2 — D2 → GCS: CredReq (encrypted with PK_KEM_GCS)

D2 computes:
- G, PID1 from M1.
- D2_ID: its own DroneID (local).
- TS2, N2.

Plaintext payload:
```json
{
  "msg_type": "CredReq",
  "G": G,
  "PID1": PID1,
  "D2_ID": D2_ID,
  "TS2": TS2,
  "N2": N2
}
```

D2 encrypts:
- (ct2, K_sess_D2GCS) = Enc_KEM(PK_KEM_GCS, payload2)

M2 payload:
```json
{ "ct2": ct2 }
```

GCS:
- Decrypts: (payload2, K_sess_D2GCS) = Dec_KEM(SK_KEM_GCS, ct2).
- Resolves PID1 → DroneID_D1 (internal mapping).
- Verifies D2_ID authorized for G and PID1 maps to active D1.

***

#### M3 — GCS → D2: CredResp (encrypted with PK_KEM_D2)

GCS retrieves:
- PK_KEM_D1, PK_Dil_D1, metadata_1, \(\rho_{D1}\).
- Current group state: R_G, V_G.

GCS computes (for its own use; not sent):
- comm_PK_D1 = Poseidon(0x02 || PK_KEM_D1 || PK_Dil_D1).

Cred structure (no DroneID):
```json
{
  "PK_KEM_D1": PK_KEM_D1,
  "PK_Dil_D1": PK_Dil_D1,
  "membership_metadata_1": metadata_1,
  "R_G": R_G,
  "V_G": V_G
}
```

Plaintext payload:
```json
{
  "msg_type": "CredResp",
  "cred_D1": cred_D1,
  "TS3": TS3,
  "N3": N3
}
```

Encrypt:
- (ct3, K_sess_GCSD2) = Enc_KEM(PK_KEM_D2, payload3)

M3 payload:
```json
{ "ct3": ct3 }
```

D2:
- Decrypts: (payload3, K_sess_GCSD2) = Dec_KEM(SK_KEM_D2, ct3).
- Extracts PK_KEM_D1, PK_Dil_D1, metadata_1, R_G, V_G.
- Computes:
  \[
    comm\_PK_{D1} = \text{Poseidon}(0x02 \,\|\, PK\_KEM_{D1} \,\|\, PK\_Dil_{D1})
  \]
- Stores session context: (G, PID1, PK_KEM_D1, PK_Dil_D1, R_G, V_G, N1, N2, TS1, TS2, TS3).

***

#### M4 — D2 → D1: Challenge

D2 constructs:
- G, N2 (from M2), TS4.
- C_PUF: PUF challenge identifier for D1 (GCS-managed).
- Optional ct_KEM_D2D1:
  - (ct_KEM_D2D1, K_temp_D2D1) = Enc_KEM(PK_KEM_D1, { "purpose": "session_bootstrap", N2, TS4 })

Challenge payload:
```json
{
  "msg_type": "Challenge",
  "G": G,
  "C_PUF": C_PUF,
  "N2": N2,
  "TS4": TS4,
  "ct_KEM_D2D1": ct_KEM_D2D1
}
```

D2 signs:
- sig4 = Sign_Dilithium(SK_Dil_D2, Hash(challenge_payload))

M4 payload:
```json
{
  "challenge_payload": challenge_payload,
  "sig4": sig4,
  "PK_Dil_D2": PK_Dil_D2
}
```

D1:
- Verifies sig4 with PK_Dil_D2.
- Checks freshness (TS4, N2).

***

#### M5 — D1 → D2: Composite proof bundle

**A) PUF proof (on D1)**
- r1 = PUF(D1, C_PUF)
- k_PUF = KDF(r1, N2, "PUF-MAC")
- T_base = (G, V_G, R_G, comm_PK_D1, N1, N2, TS1, TS4, PID1)
- mac1 = HMAC(k_PUF, Hash(T_base))

**B) ZK Merkle membership proof (on D1)**
- Witness:
  - L_D1,G = Poseidon(0x01 || PK_KEM_D1 || PK_Dil_D1 || G || metadata_1 || \(\rho_{D1}\))
  - Path_D1,G, index_D1,G (from registration).
  - PK_KEM_D1, PK_Dil_D1, metadata_1, \(\rho_{D1}\).
- Public inputs:
  - G, R_G, V_G, comm_PK_D1.
- proof_ZK = ZK_ProveMembership(G, R_G, V_G, comm_PK_D1; witness)

**C) Dilithium signature (on D1)**
- T = SHAKE256("AuthTranscript" || G || V_G || R_G || comm_PK_D1 || proof_ZK || N1 || N2 || TS1 || TS4 || PID1)
- sig1 = Sign_Dilithium(SK_Dil_D1, T)

**D) Optional KEM response**
- If ct_KEM_D2D1 received:
  - K_temp_D1D2 = Dec_KEM(SK_KEM_D1, ct_KEM_D2D1)
  - Optionally create ct_KEM_D1D2.

**E) Assemble ProofBundle**
- TS5, N5 fresh.

M5 payload:
```json
{
  "msg_type": "ProofBundle",
  "PID1": PID1,
  "comm_PK_D1": comm_PK_D1,
  "proof_ZK": proof_ZK,
  "mac1": mac1,
  "sig1": sig1,
  "PK_Dil_D1": PK_Dil_D1,
  "PK_KEM_D1": PK_KEM_D1,
  "TS5": TS5,
  "N5": N5,
  "ct_KEM_D1D2": ct_KEM_D1D2
}
```

D2 receives M5 and stores all fields.

***

#### M6 — D2 → GCS: PUFVerifyReq

D2 reconstructs T_base exactly as D1 did:
- T_base = (G, V_G, R_G, comm_PK_D1, N1, N2, TS1, TS4, PID1)

Sends to GCS (secure channel):
```json
{
  "msg_type": "PUFVerifyReq",
  "PID1": PID1,
  "G": G,
  "V_G": V_G,
  "C_PUF": C_PUF,
  "N2": N2,
  "T_base": T_base,
  "mac1": mac1
}
```

GCS:
- Resolves PID1 → D1.
- Looks up r_ref for (D1, C_PUF).
- k_PUF_ref = KDF(r_ref, N2, "PUF-MAC")
- mac1_ref = HMAC(k_PUF_ref, Hash(T_base))
- If mac1 == mac1_ref → result = "VALID", else "INVALID".

Returns:
```json
{
  "msg_type": "PUFVerifyResp",
  "PID1": PID1,
  "result": "VALID" or "INVALID",
  "TS7": TS7,
  "sig7": Sign_Dilithium(SK_Dil_GCS, Hash(payload7))
}
```

D2 verifies sig7 and extracts result.

***

#### M7 — D2 local verification and Zero Trust decision

D2 verifies:

1. **Freshness**: TS1, TS4, TS5 valid; N1, N2, N5 not reused.
2. **ZK membership**:
   - ZK_VerifyMembership(G, R_G, V_G, comm_PK_D1, proof_ZK) = accept.
3. **Dilithium signature**:
   - Recompute T (same as D1).
   - Verify_Dilithium(PK_Dil_D1, T, sig1) = accept.
4. **PUF proof**:
   - GCS result == "VALID".
5. **Root/version**:
   - R_G, V_G match M3.

**Zero Trust policy**:
- Inputs: G, V_G, PID1, metadata_1, mission context, time, location, device health, requested operation.
- Output: result ∈ { "ALLOW", "DENY" }, reason_code.

***

#### M8 — D2 → D1: AuthResult

Payload:
```json
{
  "msg_type": "AuthResult",
  "result": result,
  "reason_code": reason_code,
  "TS9": TS9,
  "N9": N9
}
```

sig9 = Sign_Dilithium(SK_Dil_D2, Hash(payload9))

M8:
```json
{
  "payload9": payload9,
  "sig9": sig9,
  "PK_Dil_D2": PK_Dil_D2
}
```

D1 verifies sig9 and checks result.

***

### 3) Group key establishment and secure channel

**K1 — D2 → GCS: GroupKeyReq**

Payload:
```json
{
  "msg_type": "GroupKeyReq",
  "G": G,
  "D1_ID": DroneID_D1,
  "D2_ID": DroneID_D2,
  "mission_id": M,
  "TS6": TS6,
  "N6": N6,
  "auth_evidence_hash": Hash(proof_ZK || sig1 || mac1)
}
```

Encrypt:
- ct6 = Enc_KEM(PK_KEM_GCS, payload6)

GCS:
- Decrypts, verifies authorization.
- Generates K_G,M ← random 256-bit key.
- env1 = { "K_G_M": K_G,M, "G": G, "mission_id": M, "TS7": TS7 }
- env2 = { "K_G_M": K_G,M, "G": G, "mission_id": M, "TS7": TS7 }
- ct_KEM_G_D1 = Enc_KEM(PK_KEM_D1, env1)
- ct_KEM_G_D2 = Enc_KEM(PK_KEM_D2, env2)

payload7b:
```json
{
  "msg_type": "GroupKeyResp",
  "ct_KEM_G_D1": ct_KEM_G_D1,
  "ct_KEM_G_D2": ct_KEM_G_D2,
  "TS7": TS7,
  "N7": N7
}
```

Encrypt for D2:
- ct7 = Enc_KEM(PK_KEM_D2, payload7b)

Send ct7 to D2.

**K2 — D2 → D1: KeyDelivery**

D2 decrypts ct7 → ct_KEM_G_D1, ct_KEM_G_D2.

Forwards to D1:
```json
{
  "msg_type": "KeyDelivery",
  "ct_KEM_G_D1": ct_KEM_G_D1,
  "TS8": TS8,
  "N8": N8
}
```

sig8 = Sign_Dilithium(SK_Dil_D2, Hash(payload8))

M8 = { payload8, sig8, PK_Dil_D2 }

D1:
- Verifies sig8.
- Decapsulates: (env1, K_G,M) = Dec_KEM(SK_KEM_D1, ct_KEM_G_D1).

D2:
- Decapsulates: (env2, K_G,M) = Dec_KEM(SK_KEM_D2, ct_KEM_G_D2).

**K3 — Derive AEAD key**
- K_AEAD = KDF(K_G,M, "AEAD-key", N1, N2, N6, N7)

**K4 — Secure communication**
For each message M:
- header = { seq_num, TS, src=PID1, dst=PID2 }
- C = AEAD_Enc(K_AEAD, M, header)
- stego_carrier = Stego_Encode(carrier, C)
- Send stego_carrier.

Receiver:
- C = Stego_Decode(stego_carrier)
- M = AEAD_Dec(K_AEAD, C, header)

***

## Part 2 — Circom-style circuit specification for ZK_ProveMembership

We now specify the ZK circuit that D1 uses to prove membership.

### Design choices
- Hash inside circuit: **Poseidon** (ZK-friendly). [github](https://github.com/mjerkov/membership)
- Leaf:  
  \[
    L = \text{Poseidon}(0x01 \,\|\, PK\_KEM \,\|\, PK\_Dil \,\|\, G \,\|\, metadata \,\|\, \rho)
  \]
- PK commitment:  
  \[
    comm\_PK = \text{Poseidon}(0x02 \,\|\, PK\_KEM \,\|\, PK\_Dil)
  \]
- Merkle tree: binary, Poseidon at each node.
- Depth: `DEPTH` (e.g., 10–20 depending on max members).

### Public inputs

These are visible to the verifier and included in the proof’s public statement:

- `G`: group ID (as a fixed-size array of field elements, e.g., 8 bytes → 1 field).
- `R_G`: Merkle root (1 field element, Poseidon output).
- `V_G`: version (1 field element, or multiple if large).
- `comm_PK`: PK commitment (1 field element).

Optionally:
- `domain_separator`: to avoid cross-protocol reuse.

In Circom, we declare these as public inputs in the `main` component.

### Private witness (private inputs)

Known only to the prover (D1):

- `leaf`: L_D1,G (1 field).
- `pathElements[DEPTH]`: sibling hashes along the path (array of field elements).
- `pathIndices[DEPTH]`: bits indicating left/right at each level (0/1).
- `PK_KEM`: Kyber768 public key (as array of field elements; may need to be split into chunks).
- `PK_Dil`: Dilithium2 public key (similarly chunked).
- `G_witness`: group ID (same as public G, but as witness for hashing).
- `metadata`: membership metadata (array of fields).
- `rho`: randomness ρ_D1 (array of fields).

### Logical constraints

The circuit must enforce:

1. **Leaf construction**
   - Compute:
     \[
       L_{check} = \text{Poseidon}(0x01 \,\|\, PK\_KEM \,\|\, PK\_Dil \,\|\, G_{witness} \,\|\, metadata \,\|\, \rho)
     \]
   - Constrain:
     \[
       L_{check} == leaf
     \]

2. **PK commitment**
   - Compute:
     \[
       comm_{check} = \text{Poseidon}(0x02 \,\|\, PK\_KEM \,\|\, PK\_Dil)
     \]
   - Constrain:
     \[
       comm_{check} == comm\_PK
     \]

3. **Merkle membership**
   - Starting from `leaf`, apply the Merkle path using `pathElements` and `pathIndices` with Poseidon at each level to compute `root_check`.
   - Constrain:
     \[
       root\_check == R_G
     \]

4. **Version binding**
   - `V_G` is a public input.
   - You can either:
     - Include `V_G` in a final hash together with `R_G` and `comm_PK` inside the circuit, or
     - Simply treat `V_G` as part of the public statement and enforce in the application layer that proofs are only accepted for the current `V_G`.

For simplicity, we’ll include `V_G` in a final consistency hash.

### Circom-style specification

Below is a conceptual Circom 2 specification. It assumes:
- `include "circomlib/circuits/poseidon.circom"` for Poseidon.
- `Poseidon(n)` takes `n` inputs and outputs 1 field.
- `PositionSwitcher()` or equivalent to handle left/right based on `pathIndices`.

```circom
pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// Position switcher: selects (left, right) based on selector bit s
template PositionSwitcher() {
    signal input in[2];
    signal input s;
    signal output out[2];

    // if s == 0: out[0] = in[0], out[1] = in[1]
    // if s == 1: out[0] = in[1], out[1] = in[0]
    // Implemented via constraints:
    out[0] <== (1 - s) * in[0] + s * in[1];
    out[1] <== (1 - s) * in[1] + s * in[0];
}

// Template to verify one Merkle level using Poseidon
template MerkleLevel() {
    signal input sibling;
    signal input low;      // current hash from lower level
    signal input selector; // 0 if sibling on right, 1 if on left
    signal output root;

    component sw = PositionSwitcher();
    component hash = Poseidon(2);

    sw.in[0] <== low;
    sw.in[1] <== sibling;
    sw.s <== selector;

    hash.inputs[0] <== sw.out[0];
    hash.inputs[1] <== sw.out[1];

    root <== hash.out;
}

// Main Merkle verifier for DEPTH levels
template MerkleVerifier(DEPTH) {
    signal input leaf;
    signal input root;
    signal input siblings[DEPTH];
    signal input pathIndices[DEPTH]; // 0/1 bits

    signal computed[DEPTH];

    component levels[DEPTH];

    // Level 0
    levels[0] = MerkleLevel();
    levels[0].sibling <== siblings[0];
    levels[0].low <== leaf;
    levels[0].selector <== pathIndices[0];
    computed[0] <== levels[0].root;

    // Higher levels
    for (var i = 1; i < DEPTH; i++) {
        levels[i] = MerkleLevel();
        levels[i].sibling <== siblings[i];
        levels[i].low <== computed[i-1];
        levels[i].selector <== pathIndices[i];
        computed[i] <== levels[i].root;
    }

    // Final root must match public root
    root === computed[DEPTH - 1];
}

// Main circuit: ZK Merkle membership with PK commitment
template ZK_Merkle_Membership(DEPTH, N_PK_KEM, N_PK_DIL, N_META, N_RHO) {
    // Public inputs
    signal input G_public;      // group ID (1 or more fields)
    signal input R_G;           // Merkle root
    signal input V_G;           // version
    signal input comm_PK;       // PK commitment

    // Private inputs
    signal input leaf;
    signal input siblings[DEPTH];
    signal input pathIndices[DEPTH];

    signal input PK_KEM[N_PK_KEM];
    signal input PK_DIL[N_PK_DIL];
    signal input G_witness;     // should match G_public
    signal input metadata[N_META];
    signal input rho[N_RHO];

    // 1. Leaf construction: L_check = Poseidon(0x01 || PK_KEM || PK_DIL || G_witness || metadata || rho)
    component leafHash = Poseidon(4 + N_PK_KEM + N_PK_DIL + N_META + N_RHO);
    // inputs: [0x01, PK_KEM..., PK_DIL..., G_witness, metadata..., rho...]
    leafHash.inputs[0] <== 1; // 0x01 as field element
    var idx = 1;
    for (var i = 0; i < N_PK_KEM; i++) {
        leafHash.inputs[idx] <== PK_KEM[i];
        idx++;
    }
    for (var i = 0; i < N_PK_DIL; i++) {
        leafHash.inputs[idx] <== PK_DIL[i];
        idx++;
    }
    leafHash.inputs[idx] <== G_witness;
    idx++;
    for (var i = 0; i < N_META; i++) {
        leafHash.inputs[idx] <== metadata[i];
        idx++;
    }
    for (var i = 0; i < N_RHO; i++) {
        leafHash.inputs[idx] <== rho[i];
        idx++;
    }

    // Constrain leafHash.out == leaf
    leafHash.out === leaf;

    // 2. PK commitment: comm_check = Poseidon(0x02 || PK_KEM || PK_DIL)
    component commHash = Poseidon(2 + N_PK_KEM + N_PK_DIL);
    commHash.inputs[0] <== 2; // 0x02
    idx = 1;
    for (var i = 0; i < N_PK_KEM; i++) {
        commHash.inputs[idx] <== PK_KEM[i];
        idx++;
    }
    for (var i = 0; i < N_PK_DIL; i++) {
        commHash.inputs[idx] <== PK_DIL[i];
        idx++;
    }

    // Constrain commHash.out == comm_PK
    commHash.out === comm_PK;

    // 3. Merkle membership
    component merkle = MerkleVerifier(DEPTH);
    merkle.leaf <== leaf;
    merkle.root <== R_G;
    for (var i = 0; i < DEPTH; i++) {
        merkle.siblings[i] <== siblings[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }

    // 4. Version binding (simple: include V_G in a final hash with R_G and comm_PK)
    component finalHash = Poseidon(3);
    finalHash.inputs[0] <== R_G;
    finalHash.inputs[1] <== comm_PK;
    finalHash.inputs[2] <== V_G;

    // Optionally constrain finalHash.out to some public value; 
    // for now, we just ensure V_G is used in-circuit.
}

// Main component
// Adjust DEPTH and sizes as needed
component main { public [G_public, R_G, V_G, comm_PK] } = 
    ZK_Merkle_Membership(DEPTH=10, N_PK_KEM=..., N_PK_DIL=..., N_META=..., N_RHO=...);```

Notes:
- You must choose `N_PK_KEM`, `N_PK_DIL`, `N_META`, `N_RHO` based on how you encode keys and metadata as field elements (e.g., split bytes into chunks fitting the field).
- `G_public` and `G_witness` should be constrained equal if needed (e.g., `G_public === G_witness;`).
- The final hash with `V_G` ensures the proof is bound to the version; you can expose `finalHash.out` as an additional public output if desired.

This circuit enforces exactly the four properties we require:
1. Correct leaf construction from PKs, G, metadata, ρ.
2. Leaf membership in the Merkle tree with root R_G.
3. PK commitment matches the PKs in the leaf.
4. Proof is bound to group state (G, R_G, V_G).
