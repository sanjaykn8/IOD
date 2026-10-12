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
//!   2. Split `b` into 8-byte little-endian chunks, zero-padding the
//!      final chunk, and emit one `Fp::new(u64::from_le_bytes(chunk))`
//!      per chunk (this can, with astronomically low probability,
//!      collide mod p for two different 8-byte windows; that is
//!      acceptable for a hash *input* encoding — it does not weaken the
//!      hash's collision resistance property, which depends on the
//!      permutation, not on this packing being a bijection).
//!
//! A "record" (e.g. the drone leaf) is encoded as the concatenation of
//! the field-encodings of each of its members, in a fixed documented
//! order (see `identity::leaf` and `identity::commitment`).

use super::field::Fp;

pub fn encode_bytes(b: &[u8]) -> Vec<Fp> {
    let mut out = Vec::with_capacity(1 + (b.len() + 7) / 8);
    out.push(Fp::new(b.len() as u64));
    for chunk in b.chunks(8) {
        let mut buf = [0u8; 8];
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
}
