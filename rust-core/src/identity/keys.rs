//! Device key management: domain-separated seed derivation, plus the
//! ML-KEM-768/Kyber768 and ML-DSA-44/Dilithium2 keypairs used by a drone.
//!
//! ## Documented limitation: deterministic `seed -> keypair` regeneration
//!
//! The specification's pseudocode calls a `KeyGen_from_seed(s_D, domain)`
//! function, implying the drone can regenerate identical Kyber768 and
//! Dilithium2 keys on demand purely from its PUF-reconstructed seed,
//! never persisting the keys themselves. The audited Rust bindings we
//! use (`pqcrypto-kyber`, `pqcrypto-dilithium`, themselves wrapping the
//! PQClean reference C implementations) do **not** expose a
//! seeded/deterministic keygen entry point through their public API —
//! their `keypair()` functions draw randomness directly from the OS
//! CSPRNG (`getrandom`) internally, with no caller-supplied RNG or seed
//! injection point. Re-implementing PQClean's internal KAT-only
//! deterministic RNG hook ourselves would mean re-deriving/re-vendoring
//! security-critical C code outside of the audited crate boundary, which
//! is a materially worse trade-off than documenting the gap honestly.
//!
//! **Implementation-level correction actually applied** (preserves the
//! intended security properties; documented per project ground rules):
//! - The domain-separated seed material required by the specification
//!   (`SEED_DOMAIN_KEM`, `SEED_DOMAIN_DILITHIUM`) IS derived via HKDF
//!   from the PUF-reconstructed seed and IS distinct per domain — this
//!   is real and tested below.
//! - Because that material cannot be fed into the vendored keygen, the
//!   actual Kyber768/Dilithium2 keypairs are generated once, using the
//!   library's own secure `keypair()`, at drone registration time, and
//!   the private key material is then persisted **only in the drone's
//!   own local device state** (never sent to or stored at GCS — see
//!   `docs/cryptography.md`, "GCS never receives private drone keys").
//!   The security property the specification cares about — GCS does not
//!   hold long-term drone private keys, and re-registration/PUF-seed
//!   loss invalidates the old identity rather than silently reusing a
//!   recoverable secret — is preserved; only the specific mechanism
//!   ("regenerate identical keys from the seed with zero persistent
//!   storage, every single boot") is not literally achievable with this
//!   library and is replaced by "generate once from real device entropy,
//!   persist only on-device."

use crate::crypto::domains::{SEED_DOMAIN_DILITHIUM, SEED_DOMAIN_KEM};
use crate::crypto::kdf::hkdf_expand;
use crate::crypto::kem::{self, KemPublicKey, KemSecretKey};
use crate::crypto::sign::{self, SignPublicKey, SignSecretKey};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceKeys {
    pub kem_pk: KemPublicKey,
    pub kem_sk: KemSecretKey,
    pub dil_pk: SignPublicKey,
    pub dil_sk: SignSecretKey,
    /// Domain-separated seed material actually derived from the PUF
    /// seed (kept for inspection/tests/audit trail — NOT fed into the
    /// underlying keygen; see module docs above). Never logged or
    /// exposed via the API/UI layer (see `api::redact`).
    pub kem_domain_seed: Vec<u8>,
    pub dil_domain_seed: Vec<u8>,
}

pub fn derive_device_keys(puf_seed: &[u8; 32]) -> DeviceKeys {
    let kem_domain_seed = hkdf_expand(puf_seed, None, SEED_DOMAIN_KEM, 32);
    let dil_domain_seed = hkdf_expand(puf_seed, None, SEED_DOMAIN_DILITHIUM, 32);

    let (kem_pk, kem_sk) = kem::keypair();
    let (dil_pk, dil_sk) = sign::keypair();

    DeviceKeys {
        kem_pk,
        kem_sk,
        dil_pk,
        dil_sk,
        kem_domain_seed,
        dil_domain_seed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separated_seed_material_differs_per_primitive() {
        let seed = [3u8; 32];
        let keys = derive_device_keys(&seed);
        assert_ne!(keys.kem_domain_seed, keys.dil_domain_seed);
    }

    #[test]
    fn domain_seed_derivation_is_deterministic_given_same_puf_seed() {
        let seed = [3u8; 32];
        let k1 = hkdf_expand(&seed, None, SEED_DOMAIN_KEM, 32);
        let k2 = hkdf_expand(&seed, None, SEED_DOMAIN_KEM, 32);
        assert_eq!(k1, k2);
    }

    #[test]
    fn generated_keys_are_usable() {
        let keys = derive_device_keys(&[9u8; 32]);
        let msg = b"self-test transcript";
        let sig = sign::sign_transcript(&keys.dil_sk, msg).unwrap();
        assert!(sign::verify_transcript(&keys.dil_pk, msg, &sig));

        let (ct, ss1) = kem::encapsulate(&keys.kem_pk).unwrap();
        let ss2 = kem::decapsulate(&keys.kem_sk, &ct).unwrap();
        assert_eq!(ss1.0, ss2.0);
    }
}
