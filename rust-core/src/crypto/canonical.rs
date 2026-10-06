//! Canonical field-element encoding for variable-length byte strings.
//!
//! Poseidon (like any fixed-arity algebraic hash) operates over field
//! elements, not raw bytes, and its security proofs assume a *canonical,
//! unambiguous* mapping from application data to the sequence of field
//! elements absorbed. Simply concatenating raw bytes from several
//! variable-length fields (e.g. a KEM public key and a signature public
//! key back to back) is ambiguous: `("AB", "C")` and `("A", "BC")`
//! concatenate to the same byte string. This module fixes that by
//! explicitly length-prefixing every variable-length field before
//! chunking it into field elements, and by fixing the *order* of fields
//! for every structure that gets hashed (leaf, PK commitment, ...).
//!
//! Encoding rule for one byte string `b`:
//!   1. Emit one `Fp` element equal to `len(b)` (as a plain integer,
//!      values here are always small, far below the field modulus).
//!   2. Split `b` into 7-byte (56-bit) little-endian chunks, zero-padding
//!      the final chunk, and emit one `Fp::new(u64::from_le_bytes(chunk))`
//!      per chunk (each chunk's numeric value is < 2^56, strictly below
//!      the Goldilocks modulus `p = 2^64 - 2^32 + 1`, so `Fp::new` never
//!      performs a modular reduction on it — the byte-string -> element
//!      map is a true bijection, not merely "astronomically unlikely to
//!      collide").
//!
//! SECURITY FIX (previously a real bug, found during source review and
//! required by the project's security-fix list, item 25-J): the original
//! version of this module used 8-byte (64-bit) chunks. A `u64` built from
//! 8 arbitrary bytes can exceed the field modulus `p = 2^64 - 2^32 + 1
//! = 0xFFFFFFFF00000001`, in which case `Fp::new` reduces it mod `p`.
//! Two distinct 8-byte windows that differ only in their high bits above
//! `p` (or that straddle a reduction boundary) could therefore map to the
//! same field element, making `encode_bytes` non-injective. Poseidon's
//! security properties (collision resistance of the *hash*) do not by
//! themselves require the *input encoding* to be injective, but every
//! consumer in this codebase (`identity::leaf`, `identity::commitment`,
//! the Merkle tree, the ZK membership binding) relies on distinct
//! application-level records producing distinct field-element streams —
//! an encoding collision there would mean two different byte strings
//! hash identically, which breaks the intended "leaf uniquely identifies
//! a drone's bound credentials" property. Switching to 7-byte chunks
//! removes the reduction entirely: `0xFF_FF_FF_FF_FF_FF_FF` (7 bytes of
//! 0xFF) = `2^56 - 1 = 72,057,594,037,927,935`, which is far below
//! `p ≈ 1.8 x 10^19`, so no chunk value can ever reach the modulus.
//!
//! Field size: Goldilocks prime `p = 2^64 - 2^32 + 1`. Byte order:
//! little-endian, matching `Fp`'s own `to_bytes_le`/internal
//! representation used throughout this crate. Chunking: 7 bytes (56
//! bits) per element, final chunk zero-padded on the high end. Domain
//! separation between different logical fields of a record is provided
//! by `encode_record`'s per-field length prefix plus the fixed, documented
//! field order each caller uses — this module only guarantees that
//! *one* byte string maps injectively to its element sequence.
//!
//! A "record" (e.g. the drone leaf) is encoded as the concatenation of
//! the field-encodings of each of its members, in a fixed documented
//! order (see `identity::leaf` and `identity::commitment`).

use super::field::Fp;

/// Bytes per field element: 56 bits. Strictly less than any value that
/// would trigger a modular reduction in `Fp::new` (the Goldilocks
/// modulus is `2^64 - 2^32 + 1`, far above `2^56 - 1`), which is what
/// makes `encode_bytes` injective rather than merely collision-unlikely.
const CHUNK_BYTES: usize = 7;

pub fn encode_bytes(b: &[u8]) -> Vec<Fp> {
    let mut out = Vec::with_capacity(1 + (b.len() + CHUNK_BYTES - 1) / CHUNK_BYTES);
    out.push(Fp::new(b.len() as u64));
    for chunk in b.chunks(CHUNK_BYTES) {
        let mut buf = [0u8; 8]; // top byte stays 0 => value < 2^56 < p, no reduction possible
        buf[..chunk.len()].copy_from_slice(chunk);
        out.push(Fp::new(u64::from_le_bytes(buf)));
    }
    out
}

/// Encode a small non-negative integer (e.g. a version counter) as a
/// single field element. Values must fit within the field (well under
/// 2^64 in practice for version counters / group ids in this project).
pub fn encode_u64(v: u64) -> Fp {
    Fp::new(v)
}

/// Encode a whole record as the ordered concatenation of each member's
/// canonical encoding, with an explicit field-count element first (binds
/// the *arity* of the record, preventing two different field layouts
/// with the same flattened element stream from being confused).
pub fn encode_record(fields: &[Vec<Fp>]) -> Vec<Fp> {
    let mut out = Vec::new();
    out.push(Fp::new(fields.len() as u64));
    for f in fields {
        out.extend_from_slice(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_splits_do_not_collide() {
        // ("AB","C") vs ("A","BC") — ambiguous if naively concatenated,
        // but distinguishable once length-prefixed.
        let a = encode_record(&[encode_bytes(b"AB"), encode_bytes(b"C")]);
        let b = encode_record(&[encode_bytes(b"A"), encode_bytes(b"BC")]);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_vs_nonempty_distinguished() {
        let a = encode_bytes(b"");
        let b = encode_bytes(b"\0");
        assert_ne!(a, b);
    }

    #[test]
    fn chunking_never_reaches_the_field_modulus_so_no_reduction_can_occur() {
        // The Goldilocks modulus is 2^64 - 2^32 + 1. The largest possible
        // 7-byte chunk value is 2^56 - 1, which is many orders of
        // magnitude below the modulus, so `Fp::new` is the identity on
        // every chunk value `encode_bytes` can ever produce.
        let max_chunk = [0xFFu8; 7];
        let max_chunk_value = {
            let mut buf = [0u8; 8];
            buf[..7].copy_from_slice(&max_chunk);
            u64::from_le_bytes(buf)
        };
        let modulus: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1
        assert!(max_chunk_value < modulus, "max 7-byte chunk must be < field modulus");
        // And a genuine 8-byte chunk's max value WOULD have exceeded it
        // (this is exactly the bug being fixed):
        assert!(u64::MAX > modulus, "an 8-byte chunk could previously overflow the modulus");
    }

    #[test]
    fn many_random_byte_strings_round_trip_without_collision() {
        use std::collections::HashSet;
        // Deterministic PRNG substitute: splitmix64, seeded fixed, so the
        // test is reproducible without pulling in a `rand` dev-dependency
        // here.
        fn splitmix64(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        let mut seed: u64 = 0xA5A5_1234_9876_FEDC;
        let mut seen_inputs: HashSet<Vec<u8>> = HashSet::new();
        let mut seen_encodings: HashSet<Vec<Fp>> = HashSet::new();
        for len in 0..=40usize {
            for _ in 0..12 {
                let mut bytes = Vec::with_capacity(len);
                for _ in 0..len {
                    bytes.push((splitmix64(&mut seed) & 0xFF) as u8);
                }
                // Only assert "no collision" between genuinely distinct
                // inputs; a repeated random draw (e.g. the single
                // possible `len == 0` input, or an accidental repeat at
                // higher lengths) must of course re-encode identically —
                // that is correctness, not a collision.
                if !seen_inputs.insert(bytes.clone()) {
                    continue;
                }
                let enc = encode_bytes(&bytes);
                assert!(seen_encodings.insert(enc), "collision detected for a byte string of length {len}");
            }
        }
    }
}
