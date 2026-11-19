//! Cryptographic-suite identity.
//!
//! Every persisted identity, credential, enrollment request, KEM envelope and
//! signature in this system belongs to exactly one suite. The active suite is
//!
//! ```text
//! iod-fips203-mlkem768-fips204-mldsa44-v1
//!   KEM        ML-KEM-768 (FIPS 203, final), RustCrypto `ml-kem` 0.3.4
//!   Signature  ML-DSA-44  (FIPS 204, final, "pure" mode, hedged signing), RustCrypto `ml-dsa` 0.1.2
//!   AEAD       ChaCha20-Poly1305;  KDF HKDF-SHA-256;  transcripts SHAKE-256
//! ```
//!
//! The previous suite (NIST Round-3 Kyber768 + Dilithium2) used the SAME byte
//! lengths for public keys (1184 / 1312), KEM ciphertexts (1088) and signatures
//! (2420). Length checks therefore cannot tell the suites apart, which is why the
//! suite is carried explicitly and bound cryptographically:
//!
//! * signed into credentials (`CredentialBody::suite`) and enrollment bodies,
//! * used as the FIPS 204 context string of every ML-DSA signature
//!   ([`crate::crypto::sign`]), so a signature cannot verify under another suite,
//! * mixed into the HKDF `info` of every KEM envelope key and recorded on the
//!   envelope ([`crate::protocol::envelope`]),
//! * stored in every persisted snapshot ([`crate::storage::snapshots`]); a
//!   snapshot from another suite is archived, never reinterpreted.
//!
//! There is no negotiation and no fallback: anything that does not name exactly
//! [`SUITE_ID`] is rejected.
//!
//! Implementing FIPS-specified algorithms does **not** make this software
//! FIPS 140-3 validated; no module validation has been performed.

/// Identifier of the active (and only accepted) suite.
pub const SUITE_ID: &str = "iod-fips203-mlkem768-fips204-mldsa44-v1";

/// Label for state written by releases before 2026-11-19 (Round-3 Kyber768 /
/// Dilithium2). Used only to report and archive such state; it is never accepted.
pub const LEGACY_SUITE_ID: &str = "iod-round3-kyber768-dilithium2-v0";

/// Human-readable algorithm names for API views.
pub const KEM_NAME: &str = "ML-KEM-768 (FIPS 203)";
pub const SIGNATURE_NAME: &str = "ML-DSA-44 (FIPS 204)";
pub const KEM_IMPLEMENTATION: &str = "ml-kem 0.3.4 (RustCrypto, pure Rust)";
pub const SIGNATURE_IMPLEMENTATION: &str = "ml-dsa 0.1.2 (RustCrypto, pure Rust)";

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("cryptographic suite mismatch: expected {expected}, found {found}")]
pub struct SuiteMismatch {
    pub expected: &'static str,
    pub found: String,
}

/// Accept exactly the active suite. Empty, legacy or unknown identifiers are errors.
pub fn require(found: &str) -> Result<(), SuiteMismatch> {
    if found == SUITE_ID {
        Ok(())
    } else {
        Err(SuiteMismatch { expected: SUITE_ID, found: if found.is_empty() { "<none>".into() } else { found.to_string() } })
    }
}

/// Non-secret description for API views (`/api/system/crypto`).
pub fn describe() -> serde_json::Value {
    serde_json::json!({
        "suite_id": SUITE_ID,
        "kem": KEM_NAME,
        "kem_implementation": KEM_IMPLEMENTATION,
        "signature": SIGNATURE_NAME,
        "signature_implementation": SIGNATURE_IMPLEMENTATION,
        "signature_mode": "pure ML-DSA, hedged signing, context string = suite id",
        "aead": "ChaCha20-Poly1305",
        "kdf": "HKDF-SHA-256",
        "transcript_hash": "SHAKE-256",
        "sizes": {
            "ml_kem_768": {"public_key": crate::crypto::kem::PUBLIC_KEY_BYTES, "private_key_expanded": crate::crypto::kem::EXPANDED_SECRET_KEY_BYTES,
                           "private_key_seed": crate::crypto::kem::SECRET_SEED_BYTES, "ciphertext": crate::crypto::kem::CIPHERTEXT_BYTES,
                           "shared_secret": crate::crypto::kem::SHARED_SECRET_BYTES},
            "ml_dsa_44": {"public_key": crate::crypto::sign::PUBLIC_KEY_BYTES, "private_key_expanded": crate::crypto::sign::EXPANDED_SECRET_KEY_BYTES,
                          "private_key_seed": crate::crypto::sign::SECRET_SEED_BYTES, "signature": crate::crypto::sign::SIGNATURE_BYTES},
        },
        "private_key_storage": "seed form (ML-KEM d||z, 64 B; ML-DSA xi, 32 B), permitted by FIPS 203 s3.3 / FIPS 204 s3.6.3; device-local only",
        "key_generation": "operating-system CSPRNG at registration; not derived from the simulated PUF",
        "conformance": "NIST ACVP vectors (keyGen, encap/decap incl. implicit rejection and key checks, sigGen, sigVer) pass in tests/fips_kat.rs; cross-checked against PQClean in tests/fips_interop.rs",
        "validation": "not FIPS 140-3 validated",
        "legacy_suite": LEGACY_SUITE_ID,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_active_suite_is_accepted() {
        assert!(require(SUITE_ID).is_ok());
        for bad in ["", LEGACY_SUITE_ID, "iod-fips203-mlkem768-fips204-mldsa44-v2", "IOD-FIPS203-MLKEM768-FIPS204-MLDSA44-V1", "kyber768"] {
            assert!(require(bad).is_err(), "{bad}");
        }
        assert_eq!(require("").unwrap_err().found, "<none>");
    }
}
