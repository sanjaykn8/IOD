//! Poseidon hash over the field defined in `field.rs`.
//!
//! This is a from-scratch, documented implementation (not a wrapper
//! around an arkworks/curve-tied Poseidon crate, precisely to avoid any
//! accidental ECC association). Parameters are generated
//! deterministically from a fixed seed via SHAKE256 ("Grain-like" round
//! constant generation, following the spirit of the original Poseidon
//! paper's constant-generation approach), so the whole construction is
//! transparent (nothing up my sleeve beyond a fixed, published seed).
//!
//! # Domain separation
//! Every call site in this codebase MUST pass a distinct `domain` tag
//! (see `crypto::domains`) as the first absorbed element, so that the
//! same permutation is never reused across semantically different
//! statements (leaf hashing vs. PK commitment vs. Merkle-tree nodes vs.
//! ZK transcript hashing). This directly implements the "do not mix
//! Poseidon configurations between components unless deliberately
//! domain-separated" requirement.
//!
//! # Parameters (documented explicitly, per project requirements)
//! - Field: Goldilocks prime p = 2^64 - 2^32 + 1 (see `field.rs`).
//! - State width t = 3 (rate 2, capacity 1) — sufficient for this
//!   project's 2-ary Merkle tree (2 children) and small fixed-arity
//!   absorption use (we chunk larger inputs across multiple
//!   permutation calls, sponge-style).
//! - S-box: x^7 (full rounds) — 7 is coprime to p-1 for this field.
//! - Full rounds: 8 (4 before, 4 after partial rounds).
//! - Partial rounds: 22 (conservative choice; Poseidon security margins
//!   for t=3 over ~64-bit fields are typically well under 22 with the
//!   published formulas, so this is intentionally conservative for a
//!   research prototype rather than an optimized production parameter
//!   set).
//! - MDS matrix: fixed 3x3 Cauchy-style matrix generated deterministically
//!   (documented below), chosen for simplicity of implementation and
//!   auditability rather than maximal performance.
//!
//! This is a *research-prototype* Poseidon instantiation. It has not
//! been through the formal Poseidon parameter-selection tooling used by
//! production deployments (e.g. the reference sage scripts), and it has
//! not been independently audited. It is suitable for a research
//! simulation and for demonstrating the protocol's structure, not for
//! production deployment. See docs/cryptography.md.

use super::field::Fp;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const T: usize = 3; // state width
pub const RATE: usize = 2; // absorb 2 field elements per permutation call
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 22;

fn generate_constants(tag: &str, count: usize) -> Vec<Fp> {
    let mut hasher = Shake256::default();
    hasher.update(b"IOD-POSEIDON-RC-V1");
    hasher.update(tag.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut buf = [0u8; 8];
        reader.read(&mut buf);
        // Reject-free: just reduce mod p (uniform enough for constants).
        out.push(Fp::new(u64::from_le_bytes(buf)));
    }
    out
}

fn mds_matrix() -> [[Fp; T]; T] {
    // Deterministic Cauchy-style matrix: M[i][j] = 1 / (x_i + y_j) is the
    // textbook MDS-guaranteeing construction, but division in this field
    // requires modular inverse (extended Euclid), which we implement via
    // Fermat's little theorem (p is prime): a^-1 = a^(p-2).
    let xs: [u64; T] = [0, 1, 2];
    let ys: [u64; T] = [T as u64, T as u64 + 1, T as u64 + 2];
    let mut m = [[Fp::ZERO; T]; T];
    for i in 0..T {
        for j in 0..T {
            let sum = Fp::new(xs[i]).add(Fp::new(ys[j]));
            m[i][j] = mod_inverse(sum);
        }
    }
    m
}

fn mod_inverse(a: Fp) -> Fp {
    // a^(p-2) mod p, via the generic pow() (p-1 fits u64 for this field).
    a.pow(super::field::MODULUS - 2)
}

pub struct PoseidonParams {
    pub round_constants: Vec<Fp>, // (FULL_ROUNDS + PARTIAL_ROUNDS) * T
    pub mds: [[Fp; T]; T],
}

impl PoseidonParams {
    pub fn new() -> Self {
        let total_rounds = FULL_ROUNDS + PARTIAL_ROUNDS;
        PoseidonParams {
            round_constants: generate_constants("round-constants-t3", total_rounds * T),
            mds: mds_matrix(),
        }
    }
}

thread_local! {
    static PARAMS: PoseidonParams = PoseidonParams::new();
}

fn permute(state: &mut [Fp; T], params: &PoseidonParams) {
    let half_full = FULL_ROUNDS / 2;
    let mut round = 0usize;

    let apply_round_constants = |state: &mut [Fp; T], round: usize| {
        for i in 0..T {
            state[i] = state[i].add(params.round_constants[round * T + i]);
        }
    };
    let apply_mds = |state: &mut [Fp; T]| {
        let mut new_state = [Fp::ZERO; T];
        for i in 0..T {
            let mut acc = Fp::ZERO;
            for j in 0..T {
                acc = acc.add(params.mds[i][j].mul(state[j]));
            }
            new_state[i] = acc;
        }
        *state = new_state;
    };

    // First half of full rounds: full S-box layer.
    for _ in 0..half_full {
        apply_round_constants(state, round);
        for i in 0..T {
            state[i] = state[i].sbox();
        }
        apply_mds(state);
        round += 1;
    }
    // Partial rounds: S-box only on state[0].
    for _ in 0..PARTIAL_ROUNDS {
        apply_round_constants(state, round);
        state[0] = state[0].sbox();
        apply_mds(state);
        round += 1;
    }
    // Second half of full rounds.
    for _ in 0..half_full {
        apply_round_constants(state, round);
        for i in 0..T {
            state[i] = state[i].sbox();
        }
        apply_mds(state);
        round += 1;
    }
}

/// Sponge-hash an arbitrary-length slice of field elements down to a
/// single field element. `domain` MUST be a distinct constant per call
/// site (see `crypto::domains`) and is absorbed as the very first
/// element, achieving Poseidon-level domain separation as required.
pub fn hash(domain: u64, inputs: &[Fp]) -> Fp {
    PARAMS.with(|params| {
        let mut state = [Fp::ZERO; T];
        // Capacity element seeded with domain tag + input length (also
        // binds the length, preventing trivial padding-collision issues).
        state[T - 1] = Fp::new(domain).add(Fp::new(inputs.len() as u64));

        let mut absorbed = 0usize;
        while absorbed < inputs.len() {
            let take = RATE.min(inputs.len() - absorbed);
            for i in 0..take {
                state[i] = state[i].add(inputs[absorbed + i]);
            }
            permute(&mut state, params);
            absorbed += take;
        }
        // Ensure at least one permutation happens even for empty input.
        if inputs.is_empty() {
            permute(&mut state, params);
        }
        state[0]
    })
}

/// Two-to-one compression used by the Merkle tree (fixed arity 2).
pub fn hash2(domain: u64, left: Fp, right: Fp) -> Fp {
    hash(domain, &[left, right])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = hash(1, &[Fp::new(1), Fp::new(2), Fp::new(3)]);
        let b = hash(1, &[Fp::new(1), Fp::new(2), Fp::new(3)]);
        assert_eq!(a, b);
    }

    #[test]
    fn domain_separation_changes_output() {
        let a = hash(1, &[Fp::new(1), Fp::new(2)]);
        let b = hash(2, &[Fp::new(1), Fp::new(2)]);
        assert_ne!(a, b);
    }

    #[test]
    fn different_inputs_differ() {
        let a = hash(1, &[Fp::new(1), Fp::new(2)]);
        let b = hash(1, &[Fp::new(1), Fp::new(3)]);
        assert_ne!(a, b);
    }

    #[test]
    fn length_extension_style_inputs_do_not_collide_trivially() {
        // [1,2] vs [1,2,0] must not collide just because of padding,
        // since we bind the input length into the capacity element.
        let a = hash(1, &[Fp::new(1), Fp::new(2)]);
        let b = hash(1, &[Fp::new(1), Fp::new(2), Fp::new(0)]);
        assert_ne!(a, b);
    }

    #[test]
    fn mds_is_deterministic_across_calls() {
        let m1 = mds_matrix();
        let m2 = mds_matrix();
        assert_eq!(m1, m2);
    }
}
