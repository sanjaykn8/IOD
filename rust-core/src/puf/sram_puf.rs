//! SRAM-PUF simulation.
//!
//! Real SRAM PUFs exploit the fact that, at power-up, uninitialized SRAM
//! cells settle into a 0 or 1 state determined by microscopic
//! manufacturing variation, and that this pattern is *mostly* stable
//! across power cycles but not perfectly so (a few percent of cells
//! "flip" between readings due to thermal noise, voltage variation,
//! etc.).
//!
//! We simulate this with:
//!   - a fixed, per-device "ground truth" bit pattern (`golden_pattern`),
//!     generated once and treated as the device's physical secret — it
//!     is never sent anywhere and is not stored in the shared
//!     application database; it lives only in the simulated device's own
//!     local state, modeling the fact that a real PUF's ground truth
//!     exists only in silicon and cannot be read out directly.
//!   - a noise model: each `read()` call flips each bit independently
//!     with probability `bit_flip_prob` (a configurable simulation
//!     parameter; this project defaults to 5%, within the range
//!     reported for real SRAM PUFs (typically 2-15% depending on
//!     temperature/voltage corner), and large enough to meaningfully
//!     exercise the fuzzy extractor's error correction while remaining
//!     reliably correctable by the chosen repetition code (see
//!     `puf::fuzzy_extractor` and docs/puf.md for the exact reliability
//!     analysis and trade-off table for other noise levels).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

pub const PUF_BITS: usize = 7936; // must match FuzzyExtractor codeword length (256-bit secret * REPEAT=31)
pub const PUF_BYTES: usize = PUF_BITS / 8;

#[derive(Clone)]
pub struct SramPuf {
    golden_pattern: [u8; PUF_BYTES],
    pub bit_flip_prob: f64,
}

impl SramPuf {
    /// Instantiate a simulated chip. `device_entropy` should be a locally
    /// generated random seed (e.g. from `rand::thread_rng()` at drone
    /// creation time) — NOT derived from any value known to the GCS.
    pub fn new(device_entropy: [u8; 32], bit_flip_prob: f64) -> Self {
        let mut rng = StdRng::from_seed(device_entropy);
        let mut golden_pattern = [0u8; PUF_BYTES];
        rng.fill(&mut golden_pattern[..]);
        SramPuf {
            golden_pattern,
            bit_flip_prob,
        }
    }

    /// Simulate one power-up reading: golden pattern XOR independent
    /// per-bit noise.
    pub fn read(&self) -> [u8; PUF_BYTES] {
        let mut rng = rand::thread_rng();
        let mut out = self.golden_pattern;
        for byte_idx in 0..PUF_BYTES {
            let mut flips = 0u8;
            for bit in 0..8 {
                if rng.gen::<f64>() < self.bit_flip_prob {
                    flips |= 1 << bit;
                }
            }
            out[byte_idx] ^= flips;
        }
        out
    }

    /// Challenge-response function PUF(D, C) -> r. Modeled as a
    /// domain-separated hash of the golden pattern and the challenge.
    /// See module docs on the "noise-free CRP" simplification.
    pub fn challenge_response(&self, challenge: &[u8]) -> [u8; 32] {
        super::crp::derive_response(&self.golden_pattern, challenge)
    }

    /// Export the simulated device's persistent "golden pattern" for
    /// this simulator's own device-local persistence layer (see
    /// `storage` module). In a real deployment this value never leaves
    /// the physical chip and is never written to any database; here it
    /// is written ONLY to a `drones_local` table explicitly modeled as
    /// "what would live on the device's own flash," never to the GCS
    /// public-record tables. See `docs/security-review.md`.
    pub fn export_golden_pattern(&self) -> [u8; PUF_BYTES] {
        self.golden_pattern
    }

    pub fn from_golden_pattern(golden_pattern: [u8; PUF_BYTES], bit_flip_prob: f64) -> Self {
        SramPuf { golden_pattern, bit_flip_prob }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readings_are_noisy_but_close_to_golden() {
        let puf = SramPuf::new([7u8; 32], 0.08);
        let r1 = puf.read();
        let r2 = puf.read();
        assert_ne!(r1, r2, "two readings should essentially never be identical with 8% noise");
        let hamming: u32 = r1
            .iter()
            .zip(r2.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        // Expected Hamming distance between two noisy readings of the
        // same chip ~ 2 * p * (1-p) * N bits. For N=7936, p=0.08 this is
        // ~566 bits; assert a generous bound to avoid test flakiness.
        assert!(hamming > 50, "noise seems implausibly low: {hamming} bits differ");
        assert!(hamming < (PUF_BITS as u32) / 2, "noise implausibly high: {hamming} bits differ");
    }

    #[test]
    fn different_devices_have_different_golden_patterns() {
        let a = SramPuf::new([1u8; 32], 0.08);
        let b = SramPuf::new([2u8; 32], 0.08);
        assert_ne!(a.read(), b.read());
    }

    #[test]
    fn challenge_response_deterministic_for_same_challenge() {
        let puf = SramPuf::new([9u8; 32], 0.08);
        let r1 = puf.challenge_response(b"challenge-1");
        let r2 = puf.challenge_response(b"challenge-1");
        assert_eq!(r1, r2);
    }

    #[test]
    fn challenge_response_differs_per_challenge() {
        let puf = SramPuf::new([9u8; 32], 0.08);
        let r1 = puf.challenge_response(b"challenge-1");
        let r2 = puf.challenge_response(b"challenge-2");
        assert_ne!(r1, r2);
    }
}
