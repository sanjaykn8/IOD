//! STARK configuration: BabyBear, degree-5 extension challenge field (155-bit),
//! Keccak-256 Merkle commitments with random salts (hiding MMCS), hiding
//! FRI PCS. The PCS/MMCS randomness is drawn from the OS CSPRNG for every
//! proof (never seeded from public data).

use super::air::MembershipAir;
use super::ZkError;
use crate::zkhash::Bb;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove as p3_prove, verify as p3_verify, Proof, StarkConfig};
use rand10::rngs::StdRng;
use rand10::SeedableRng;
use serde::{Deserialize, Serialize};

type Val = Bb;
type Challenge = BinomialExtensionField<Val, 5>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    Compress,
    StdRng,
    2,
    4,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
pub type ZkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Proof-system parameters. The verifier must use the same values as the
/// prover; they are part of the protocol configuration, never read from
/// the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkParams {
    pub depth: usize,
    pub log_blowup: usize,
    pub num_queries: usize,
    pub query_pow_bits: usize,
    pub batch_pow_bits: usize,
    /// Independent random codewords of the hiding PCS (must be >= extension degree 5).
    pub num_random_codewords: usize,
}

impl ZkParams {
    /// Production-intent parameters (target >= 100-bit conjectured).
    pub fn standard(depth: usize) -> Self {
        ZkParams {
            depth,
            log_blowup: 3,
            num_queries: 70,
            query_pow_bits: 16,
            batch_pow_bits: 10,
            num_random_codewords: 5,
        }
    }
    /// Fast parameters for unit tests only (NOT a security level).
    pub fn testing(depth: usize) -> Self {
        ZkParams {
            depth,
            log_blowup: 2,
            num_queries: 12,
            query_pow_bits: 1,
            batch_pow_bits: 0,
            num_random_codewords: 5,
        }
    }
    pub fn param_id(&self) -> u8 {
        // Distinguishes parameter sets inside the proof header.
        (self.log_blowup as u8) ^ ((self.num_queries as u8).rotate_left(3)) ^ (self.depth as u8).rotate_left(5)
    }
    /// Hiding-FRI budget: N >= 2*(num_queries + 4 * opening_points); we
    /// open at 2 points (zeta, g*zeta). Rows are padded to a power of two.
    pub fn trace_height(&self, air: &MembershipAir) -> usize {
        let budget = 2 * (self.num_queries + 4 * 2);
        budget.max(air.min_rows()).next_power_of_two()
    }
}

fn make_config(p: &ZkParams, rng_seed: Option<u64>) -> ZkConfig {
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = Compress::new(u64_hash);
    let mk_rng = |salt: u64| match rng_seed {
        Some(s) => StdRng::seed_from_u64(s ^ salt),
        None => rand10::make_rng::<StdRng>(),
    };
    let val_mmcs = ValMmcs::new(field_hash, compress, 0, mk_rng(1));
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri = FriParameters {
        log_blowup: p.log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: p.num_queries,
        batch_proof_of_work_bits: p.batch_pow_bits,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: p.query_pow_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri, p.num_random_codewords, mk_rng(2));
    let challenger = Challenger::from_hasher(vec![], ByteHash {});
    ZkConfig::new(pcs, challenger)
}

pub fn prove(
    p: &ZkParams,
    air: &MembershipAir,
    trace: RowMajorMatrix<Bb>,
    pv: &[Bb],
) -> Result<Vec<u8>, ZkError> {
    let cfg = make_config(p, None);
    let proof: Proof<ZkConfig> =
        p3_prove(&cfg, air, trace, pv).map_err(|e| ZkError::Prover(format!("{e:?}")))?;
    postcard::to_allocvec(&proof).map_err(|e| ZkError::Prover(e.to_string()))
}

pub fn verify(p: &ZkParams, air: &MembershipAir, bytes: &[u8], pv: &[Bb]) -> Result<(), ZkError> {
    let cfg = make_config(p, Some(0));
    let proof: Proof<ZkConfig> = postcard::from_bytes(bytes).map_err(|_| ZkError::Malformed)?;
    // Defence in depth: a proof for a different trace height is rejected
    // before any heavy work.
    let want = p.trace_height(air).trailing_zeros() as usize;
    if std::env::var("IOD_ZK_DEBUG").is_ok() {
        eprintln!("degree_bits={} want={}", proof.degree_bits, want);
    }
    // hiding PCS doubles the committed domain (+1 bit)
    if proof.degree_bits != want + 1 {
        return Err(ZkError::Rejected);
    }
    // Plonky3 may panic on adversarial malformed shapes; contain it.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p3_verify(&cfg, air, &proof, pv)));
    match r {
        Ok(Ok(())) => Ok(()),
        other => {
            if std::env::var("IOD_ZK_DEBUG").is_ok() {
                eprintln!("verify error: {:?}", other.map(|r| r.map_err(|e| format!("{e:?}"))));
            }
            Err(ZkError::Rejected)
        }
    }
}

/// Security estimates computed by Plonky3's own estimator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEstimate {
    pub conjectured_bits: usize,
    pub proven_unique_decoding_bits: usize,
    pub proven_list_decoding_bits: usize,
    pub trace_height: usize,
    pub trace_width: usize,
    /// Commitment (Keccak-256) classical collision resistance assumed.
    pub collision_resistance_bits: usize,
}

pub fn security_estimate(p: &ZkParams) -> SecurityEstimate {
    use p3_air::symbolic::AirLayout;
    use p3_field::coset::TwoAdicMultiplicativeCoset;
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{ConjecturedSecurity, OpeningShape, ProvenSecurity, StarkSecurityParams};
    let air = MembershipAir::new(p.depth);
    let height = p.trace_height(&air);
    let log_h = height.trailing_zeros() as usize;
    let cfg = make_config(p, Some(0));
    let _ = &cfg;
    let fri = FriParameters {
        log_blowup: p.log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: p.num_queries,
        batch_proof_of_work_bits: p.batch_pow_bits,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: p.query_pow_bits,
        mmcs: (),
    };
    let params = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        &air,
        AirLayout::from_air::<Val>(&air),
        TwoAdicMultiplicativeCoset::new(Val::ONE, log_h).unwrap(),
        155,
        128,
        2,
        OpeningShape::hiding(p.num_random_codewords),
        fri.grinding_sites(),
    );
    let degree_bits = log_h + 1;
    let c = ConjecturedSecurity::compute_from_params(&params, degree_bits);
    let pr = ProvenSecurity::compute_from_proof(degree_bits, &params);
    SecurityEstimate {
        conjectured_bits: c.security_bits,
        proven_unique_decoding_bits: pr.unique_decoding_bits,
        proven_list_decoding_bits: pr.list_decoding_bits,
        trace_height: height,
        trace_width: air.trace_width(),
        collision_resistance_bits: 128,
    }
}

/// Human-readable parameter/security summary for docs and benchmarks.
pub fn security_report(p: &ZkParams) -> String {
    let e = security_estimate(p);
    format!(
        "depth={} trace={}x{} log_blowup={} queries={} query_pow={} batch_pow={} ext_degree=5 field=BabyBear(31b) | conjectured={}b proven(unique)={}b proven(list)={}b",
        p.depth, e.trace_height, e.trace_width, p.log_blowup, p.num_queries, p.query_pow_bits,
        p.batch_pow_bits, e.conjectured_bits, e.proven_unique_decoding_bits, e.proven_list_decoding_bits
    )
}
