//! Code-offset construction fuzzy extractor over the SRAM-PUF reading.
//!
//! Standard code-offset construction (Dodis, Ostrovsky, Reyzin, Smith):
//!   Gen(R):  choose random codeword-message C (secret_bits long);
//!            encode it with an error-correcting code -> codeword(C);
//!            helper W = R XOR codeword(C);
//!            output (W, seed = H(C))
//!   Rep(R', W): masked = R' XOR W = codeword(C) XOR (R XOR R') = codeword(C) XOR noise;
//!               decode masked -> recovered C' (equals C if noise is within
//!               the code's correction capability);
//!               output seed' = H(C')  (== seed iff decoding succeeded)
//!
//! Error-correcting code used: a simple binary repetition code
//! (`REPEAT` copies per message bit, majority-vote decoding). This is a
//! deliberate simplification: production fuzzy extractors typically use
//! BCH or Reed-Solomon codes for much better code rate at the same error
//! tolerance. A repetition code is far easier to implement *correctly*
//! and to audit by inspection, which we prioritize for a research
//! prototype; see docs/puf.md for the honest trade-off discussion and
//! how a BCH-based extractor could later be substituted behind the same
//! `FuzzyExtractor` interface without touching any caller.
//!
//! With REPEAT = 31, each block of 31 noisy bits can be reconstructed by
//! majority vote as long as fewer than 16 of the 31 have flipped between
//! the enrollment reading and a later reproduction reading. Two
//! *independent* noisy readings of the same chip (each with independent
//! per-bit flip probability `q` relative to the invisible golden
//! pattern) differ from each other with probability `p = 2q(1-q)`. At
//! the project's default `q = 5%` SRAM-PUF noise level, `p ≈ 9.5%`, and
//! the resulting per-block decoding-failure probability is below
//! `4×10⁻⁹`; across the 256 blocks needed to reconstruct the full 256-bit
//! seed, the overall reconstruction-failure probability per attempt is
//! below `10⁻⁶` — see `docs/puf.md` for the full reliability table
//! across other noise levels (this is a real, computed reliability bound
//! for the exact repetition code implemented here, not an assumed
//! figure). This is not "zero failure probability" — no real fuzzy
//! extractor has that — but it is small enough to be a non-issue for a
//! research simulation running a bounded number of authentication
//! rounds, while remaining honest about the residual (nonzero) failure
//! rate.
//!
//! The extractor additionally hashes the recovered message `C` through
//! SHAKE256 before use (a "strong extractor" step), rather than treating
//! `C`'s raw bits as the seed, so that the output is uniform even though
//! the repetition code itself is not a universal hash.

use super::sram_puf::{PUF_BITS, PUF_BYTES};
use crate::crypto::domains::SEED_DOMAIN_FUZZY_EXTRACTOR;
use crate::crypto::kdf::shake256_bytes;
use rand::RngCore;

pub const REPEAT: usize = 31;
pub const SECRET_BITS: usize = PUF_BITS / REPEAT; // 256 bits message
pub const SECRET_BYTES: usize = SECRET_BITS / 8;

/// Default simulated SRAM-PUF per-bit noise level used across this
/// project's demo/registration flow (see the reliability analysis above
/// and in docs/puf.md — at this noise level the full-seed reconstruction
/// failure probability per attempt is below 10⁻⁶ for REPEAT=31).
pub const DEFAULT_BIT_FLIP_PROB: f64 = 0.05;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HelperData(pub Vec<u8>); // PUF_BYTES long, safe to store non-secretly

fn get_bit(bytes: &[u8], i: usize) -> u8 {
    (bytes[i / 8] >> (i % 8)) & 1
}
fn set_bit(bytes: &mut [u8], i: usize, v: u8) {
    if v == 1 {
        bytes[i / 8] |= 1 << (i % 8);
    } else {
        bytes[i / 8] &= !(1 << (i % 8));
    }
}

fn encode_repetition(message: &[u8; SECRET_BYTES]) -> [u8; PUF_BYTES] {
    let mut out = [0u8; PUF_BYTES];
    for i in 0..SECRET_BITS {
        let bit = get_bit(message, i);
        for r in 0..REPEAT {
            set_bit(&mut out, i * REPEAT + r, bit);
        }
    }
    out
}

fn decode_repetition(codeword_with_noise: &[u8; PUF_BYTES]) -> [u8; SECRET_BYTES] {
    let mut out = [0u8; SECRET_BYTES];
    for i in 0..SECRET_BITS {
        let mut ones = 0u32;
        for r in 0..REPEAT {
            ones += get_bit(codeword_with_noise, i * REPEAT + r) as u32;
        }
        let majority = if ones * 2 > REPEAT as u32 { 1 } else { 0 };
        set_bit(&mut out, i, majority);
    }
    out
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub struct EnrollmentOutput {
    pub helper_data: HelperData,
    pub seed: [u8; 32],
}

/// Gen(R): run once, at drone registration time, using an initial PUF
/// reading. Produces public (non-secret) helper data plus the
/// reconstructable 32-byte seed `s_D`.
pub fn generate(reference_reading: &[u8; PUF_BYTES]) -> EnrollmentOutput {
    let mut message = [0u8; SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut message);
    let codeword = encode_repetition(&message);
    let helper: Vec<u8> = xor_bytes(reference_reading, &codeword);
    let seed_vec = shake256_bytes(SEED_DOMAIN_FUZZY_EXTRACTOR, &message, 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_vec);
    EnrollmentOutput {
        helper_data: HelperData(helper),
        seed,
    }
}

/// Rep(R', W): run every time the device needs to reconstruct `s_D` from
/// a fresh (noisy) PUF reading plus the previously-stored helper data.
pub fn reproduce(noisy_reading: &[u8; PUF_BYTES], helper: &HelperData) -> [u8; 32] {
    let masked: Vec<u8> = xor_bytes(noisy_reading, &helper.0);
    let mut masked_arr = [0u8; PUF_BYTES];
    masked_arr.copy_from_slice(&masked);
    let recovered_message = decode_repetition(&masked_arr);
    let seed_vec = shake256_bytes(SEED_DOMAIN_FUZZY_EXTRACTOR, &recovered_message, 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_vec);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::puf::sram_puf::SramPuf;

    /// Default simulated SRAM-PUF per-bit noise level used across this
    /// project's demo/registration flow (see reliability analysis in the
    /// module docs above and in docs/puf.md).
    pub const DEFAULT_BIT_FLIP_PROB: f64 = 0.05;

    #[test]
    fn reconstructs_identical_seed_despite_noise() {
        let puf = SramPuf::new([42u8; 32], DEFAULT_BIT_FLIP_PROB);
        let reference = puf.read();
        let enrolled = generate(&reference);
        for _ in 0..25 {
            let noisy = puf.read();
            let reproduced = reproduce(&noisy, &enrolled.helper_data);
            assert_eq!(
                reproduced, enrolled.seed,
                "fuzzy extractor failed to reconstruct the seed under normal noise"
            );
        }
    }

    #[test]
    fn different_devices_yield_different_seeds() {
        let puf_a = SramPuf::new([1u8; 32], DEFAULT_BIT_FLIP_PROB);
        let puf_b = SramPuf::new([2u8; 32], DEFAULT_BIT_FLIP_PROB);
        let enrolled_a = generate(&puf_a.read());
        let seed_b = reproduce(&puf_b.read(), &enrolled_a.helper_data);
        assert_ne!(seed_b, enrolled_a.seed);
    }

    #[test]
    fn excessive_noise_can_cause_reconstruction_failure() {
        // Sanity check that the code has a real error-correction limit:
        // at p=0.5 (pure noise, no signal) reconstruction essentially
        // never matches.
        let puf = SramPuf::new([5u8; 32], 0.5);
        let reference = puf.read();
        let enrolled = generate(&reference);
        let very_noisy = puf.read();
        let reproduced = reproduce(&very_noisy, &enrolled.helper_data);
        assert_ne!(
            reproduced, enrolled.seed,
            "expected reconstruction to fail under pathological 50% noise"
        );
    }
}
