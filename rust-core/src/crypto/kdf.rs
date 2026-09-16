//! KDF (HKDF-SHA256), HMAC-SHA256, and SHAKE256 helpers.
//!
//! `hkdf_expand` is used for every domain-separated key/seed derivation
//! in the system (KEM domain, Dilithium domain, PID domain, PUF-MAC
//! domain, AEAD-key domain, fuzzy-extractor domain — see
//! `crypto::domains`). Per-domain outputs are cryptographically
//! independent even though they all originate from the same underlying
//! PUF-reconstructed seed, because HKDF's `info` parameter is bound into
//! every output block.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub fn hkdf_expand(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .expect("HKDF expand should not fail for reasonable output lengths");
    okm
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, msg);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn hmac_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let expected = hmac_sha256(key, msg);
    // Constant-time compare via subtle-equivalent manual loop (avoids
    // pulling in an extra dependency just for this).
    if expected.len() != tag.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// SHAKE256 over a set of already-length-prefixed byte segments. Callers
/// MUST length-prefix each segment (see `crypto::canonical` for the
/// analogous concern on the Poseidon/field side) so that transcript
/// construction is unambiguous.
pub fn shake256_transcript(domain: &[u8], segments: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for seg in segments {
        hasher.update(&(seg.len() as u64).to_le_bytes());
        hasher.update(seg);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

pub fn shake256_bytes(domain: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// Length-prefix every segment then concatenate. Used to build canonical
/// byte transcripts for objects that get Dilithium-signed directly
/// (Dilithium hashes its input internally, so no separate pre-hash is
/// required — we only need an unambiguous byte encoding of the fields).
pub fn length_prefixed_concat(segments: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for seg in segments {
        out.extend_from_slice(&(seg.len() as u64).to_le_bytes());
        out.extend_from_slice(seg);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_is_deterministic() {
        let a = hkdf_expand(b"ikm", Some(b"salt"), b"info-a", 32);
        let b = hkdf_expand(b"ikm", Some(b"salt"), b"info-a", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_domain_separation() {
        let a = hkdf_expand(b"ikm", Some(b"salt"), b"info-a", 32);
        let b = hkdf_expand(b"ikm", Some(b"salt"), b"info-b", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_round_trip() {
        let tag = hmac_sha256(b"key", b"message");
        assert!(hmac_verify(b"key", b"message", &tag));
        assert!(!hmac_verify(b"key", b"tampered", &tag));
        assert!(!hmac_verify(b"wrong-key", b"message", &tag));
    }

    #[test]
    fn transcript_hash_unambiguous_segmentation() {
        let a = shake256_transcript(b"D", &[b"AB", b"C"]);
        let b = shake256_transcript(b"D", &[b"A", b"BC"]);
        assert_ne!(a, b);
    }
}
