//! Transparent, hash-based, non-ECC "ZK membership" proof subsystem.
//!
//! # READ THIS BEFORE TRUSTING ANY "ZERO-KNOWLEDGE" CLAIM IN THIS MODULE
//!
//! This module implements the *logical statement* from the
//! specification's Circom-style circuit:
//!
//!   Public:  G, R_G, V_G, comm_PK
//!   Witness: leaf, siblings[], path_indices[], PK_KEM, PK_Dil, metadata, rho
//!   Prove:   leaf = Poseidon(0x01, PK_KEM, PK_Dil, G, metadata, rho)
//!         AND comm_PK = Poseidon(0x02, PK_KEM, PK_Dil)
//!         AND MerklePath(leaf, siblings, path_indices) == R_G
//!         AND the proof is cryptographically bound to (G, R_G, V_G, comm_PK)
//!
//! per the explicit project requirement to avoid Circom+Groth16 (or any
//! other elliptic-curve-backed SNARK) and instead use "the strongest
//! feasible transparent, hash-based/post-quantum-compatible approach
//! available without ECC."
//!
//! ## What IS real in this implementation
//!
//! - **Soundness of the algebraic relation**: `verify()` really
//!   recomputes the leaf Poseidon hash, the PK-commitment Poseidon hash,
//!   and folds the real Merkle path (via `merkle::tree::verify_witness`)
//!   up to the claimed root. A prover without a witness satisfying every
//!   one of these equations cannot produce an accepting proof, except by
//!   breaking Poseidon's collision/preimage resistance — a real security
//!   property, not a stub.
//! - **G_public / G_witness binding** (spec correction #3): `verify()`
//!   recomputes the leaf hash using the VERIFIER's own trusted `G` from
//!   the public statement, not a separate copy carried inside the
//!   witness/opening. There is structurally no way for a proof to bind
//!   to one group in the Merkle-path check and a different group in the
//!   leaf-construction check.
//! - **V_G actually binds the proof** (spec correction #4/#5): the
//!   Fiat-Shamir challenge `fs_challenge = Poseidon(FS_DOMAIN, G, R_G,
//!   V_G, comm_PK, witness_commitment)` is recomputed by the verifier
//!   using ITS OWN current, trusted `V_G` (obtained independently, e.g.
//!   from the verifier's own group state / from `CredResp`), not a copy
//!   embedded in the proof. If the group's version has since advanced
//!   (a revocation or new registration happened), a verifier holding the
//!   new `V_G` will recompute a different challenge and REJECT a proof
//!   generated against the old version, even if every other equation
//!   still happens to hold. This is exercised directly in the "stale
//!   version is rejected" unit test below.
//! - **Session/replay binding**: because the Fiat-Shamir challenge folds
//!   in the live public statement, a proof cannot be replayed against a
//!   different `(G, R_G, V_G, comm_PK)` tuple.
//! - **Transparency**: every hash used (Poseidon, SHAKE256) is a fixed,
//!   published, unkeyed function; there is no structured reference
//!   string, no trusted setup ceremony, and no elliptic curve of any
//!   kind anywhere in this module or its dependencies.
//!
//! ## What is a DOCUMENTED SIMULATION / NOT achieved
//!
//! - **Zero-knowledge hiding of the witness from the verifier.** A
//!   genuine ZK proof lets a verifier become convinced a statement is
//!   true *without learning the witness*. Achieving that for an
//!   arbitrary hash-based relation like this one (a Merkle path plus a
//!   Poseidon preimage), without ECC-based SNARKs, requires either a
//!   hash-based polynomial-IOP/STARK (FRI), an MPC-in-the-head
//!   construction (e.g. ZKBoo/Ligero-style), or a lattice-based
//!   homomorphic commitment scheme. All three are substantial standalone
//!   research/engineering undertakings; a subtly-incorrect from-scratch
//!   attempt at one of them, built under time pressure and *presented as
//!   real*, would be a materially worse outcome than an honestly-labeled
//!   simplification. This module therefore does NOT attempt one.
//!   Instead: `ZkProof` DOES include a genuine hiding Poseidon commitment
//!   to the full witness (`witness_commitment`, freshly blinded with 256
//!   random bits — this alone reveals nothing), but the proof ALSO
//!   carries an `opening` with the actual witness values, because
//!   `verify()` needs them to run the real algebraic checks above. Any
//!   party that runs `verify()` (in this protocol, that is D2 for the
//!   M5→M7 step) therefore fully learns `rho` and the Merkle
//!   siblings/path (i.e. the leaf's tree position). Note this does not
//!   change what D2 already learns from `CredResp` (M3): `PK_KEM_D1`,
//!   `PK_Dil_D1`, and `membership_metadata_1` are sent to D2 in the
//!   clear by the specification's own M3 design regardless of the ZK
//!   layer. The *additional* information this backend's `opening`
//!   discloses to D2, beyond what M3 already discloses, is exactly
//!   `rho` and the Merkle path/index — i.e. the drone's position within
//!   the group's tree.
//! - **Practical implication**: with this backend, this system provides
//!   a real, checked, Fiat-Shamir-bound **non-interactive proof of
//!   knowledge with full witness disclosure to the verifier** — not a
//!   hiding zero-knowledge proof. It is suitable for demonstrating the
//!   protocol's structure, binding properties, and message flow, and
//!   for a research prototype's threat-model discussion, but must not be
//!   cited as providing witness privacy against the specific verifier
//!   the proof is shown to.
//!
//! ## How a real hiding backend would slot in later
//!
//! `ZkBackend` (see `backend.rs`) is a trait with `prove` and `verify`
//! methods over the same `ZkStatement`/`ZkWitness`/`ZkProof` types used
//! throughout the `protocol` module. A future FRI-based STARK backend,
//! or an MPC-in-the-head backend, could implement the same trait and be
//! swapped in via `protocol::config` without touching any call site in
//! `protocol/messages.rs` — this is the "clean interface" the project
//! brief requires for exactly this situation.

pub mod backend;
pub mod statement;
pub mod witness;
