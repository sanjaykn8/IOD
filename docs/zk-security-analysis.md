# ZK Security Analysis

## Properties and assumptions
| Property | Argument | Assumption |
|---|---|---|
| Completeness | honest prover with a valid path always verifies (tests: every leaf position, several depths) | — |
| Soundness | AIR constraints + FRI proximity; a cheating prover must forge a Poseidon2 collision/preimage along the path or break FRI | FRI soundness (conjectured), collision/preimage resistance of Poseidon2-BabyBear (tree) and Keccak-256 (commitments, Fiat–Shamir), random-oracle model for Fiat–Shamir |
| Zero knowledge (witness hiding) | hiding FRI: every opened trace value is masked by random codewords of the PCS; MMCS leaves are salted | statistical ZK of the hiding-FRI construction (Haböck 2024) with `N ≥ 2(q+4·points)` trace rows, fresh OS randomness per proof |
| Binding to session/group/version/keys | all appear in the 54 public values, which enter the Fiat–Shamir transcript and are constrained in the AIR | as above |

## Numbers (Plonky3 estimator, `ZkParams::standard`)
Conjectured **128 bits**, proven list-decoding **120 bits**, proven unique-decoding
**74 bits**. The challenge field is the degree-5 extension of BabyBear (155 bits);
with the degree-4 extension the estimator gave only 111/102/74 and this was
rejected. Grinding (query 16 bits, batch 10 bits) is included in those figures.
Classical collision resistance of Poseidon2 digest ≈ 2^124; quantum (BHT) ≈ 2^83;
Keccak-256 commitments ≈ 2^128 / ≈ 2^85.

## Post-quantum status
No discrete-log, pairing or factoring assumption anywhere. Fiat–Shamir is in the
(quantum) random-oracle model: tight quantum-ROM soundness for FRI-based STARKs is
an open research area; the figures above are classical.

## Privacy: what is and is not claimed
Claimed: the proof reveals nothing about `rho_D1`, the Merkle siblings or the leaf
index beyond the public inputs. Proof size is independent of position (tested).
Not claimed: unlinkability (stable keys/credential id), metadata hiding, hiding
against the GCS, hiding of group/root/version, traffic-analysis resistance.
**Honest limitation:** because D1's GCS-signed credential (comm_PK, role, group) is
sent to D2, the ZK proof is *not needed for authenticity* in this moderate-anonymity
model; what it adds is hiding D1's tree position and `rho` and a machine-checked
link "leaf under the current root contains this comm_PK". Stronger anonymity (hiding
keys behind a group signature/anonymous credential) is future work.

## Caveats
* Plonky3 `0.9.0-rc.1` is a release candidate; its hiding mode has not been independently audited.
* Poseidon2 cryptanalysis is ongoing.
* Privacy is established by construction and by structural tests (no witness bytes in
  the proof, randomized proofs, size independence), **not** by a statistical
  distinguishing experiment.
* Proofs are ≈ 250 KB; each is verified once per session (≈ 3.5–5 ms host).
* GCS does not verify the ZK proof; it checks membership in its own tree.
* The prover's native check (`check_relation`) is a fail-fast convenience; the verifier
  never relies on it (test `malicious_prover_bypassing_native_check…`).
