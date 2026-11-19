//! Device key management: domain-separated seed derivation, plus the
//! ML-KEM-768 (FIPS 203) and ML-DSA-44 (FIPS 204) keypairs used by a drone.
//!
//! ## What is (and is not) derived from the PUF
//!
//! The specification's pseudocode calls `KeyGen_from_seed(s_D, domain)`, i.e. the
//! drone would regenerate its ML-KEM / ML-DSA keys from its PUF-reconstructed seed
//! and never store them. The final-standard libraries now used DO offer the
//! standard deterministic entry points (FIPS 203 `ML-KEM.KeyGen_internal(d, z)`,
//! FIPS 204 `ML-DSA.KeyGen_internal(xi)`; exposed here as
//! `kem::keypair_from_seed` / `sign::keypair_from_seed` and exercised by the NIST
//! known-answer tests). They are deliberately **not** wired to the simulated PUF:
//!
//! * the PUF in this repository is a software simulation; deriving long-term keys
//!   from it would present simulated entropy as hardware-rooted key material;
//! * the behaviour of the previous releases ("generate once from real OS entropy,
//!   persist only on the device") is preserved, so no persisted semantics change.
//!
//! What actually happens:
//! - The domain-separated seed material (`SEED_DOMAIN_KEM`, `SEED_DOMAIN_DILITHIUM`)
//!   IS derived with HKDF from the PUF-reconstructed seed and is distinct per domain.
//!   It is kept for inspection/tests only and is NOT fed into key generation.
//! - The ML-KEM-768 and ML-DSA-44 keypairs are generated at registration with the
//!   operating-system CSPRNG and persisted, in seed form, **only in the drone's own
//!   local device state** (never sent to or stored at the GCS).
//! - The future seam: a physical PUF-backed provisioning step can produce `d || z`
//!   and `xi` and call the `*_from_seed` functions; nothing else would change.
//!   Physical PUF integration is deferred.

use crate::crypto::domains::{SEED_DOMAIN_DILITHIUM, SEED_DOMAIN_KEM};
use crate::crypto::kdf::hkdf_expand;
use crate::crypto::kem::{self, KemPublicKey, KemSecretKey};
use crate::crypto::sign::{self, SignPublicKey, SignSecretKey};
use crate::crypto::suite::SUITE_ID;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceKeys {
    /// Cryptographic suite of all four keys. Required when deserializing: key sets
    /// from earlier releases (no field, Round-3 keys) fail to load instead of being
    /// reinterpreted.
    pub suite: String,
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

impl DeviceKeys {
    /// Check a loaded key set: right suite, right lengths, and each public key
    /// re-derived from its stored private seed.
    pub fn validate(&self) -> anyhow::Result<()> {
        crate::crypto::suite::require(&self.suite)?;
        anyhow::ensure!(kem::public_from_secret(&self.kem_sk)? == self.kem_pk, "ML-KEM public key does not match the stored private key");
        anyhow::ensure!(sign::public_from_secret(&self.dil_sk)? == self.dil_pk, "ML-DSA public key does not match the stored private key");
        Ok(())
    }
}

pub fn derive_device_keys(puf_seed: &[u8; 32]) -> DeviceKeys {
    let kem_domain_seed = hkdf_expand(puf_seed, None, SEED_DOMAIN_KEM, 32);
    let dil_domain_seed = hkdf_expand(puf_seed, None, SEED_DOMAIN_DILITHIUM, 32);

    let (kem_pk, kem_sk) = kem::keypair();
    let (dil_pk, dil_sk) = sign::keypair();

    DeviceKeys {
        suite: SUITE_ID.to_string(),
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
    fn stored_keys_validate_and_mismatches_are_detected() {
        let k = derive_device_keys(&[4u8; 32]);
        k.validate().unwrap();
        let mut legacy = k.clone();
        legacy.suite = crate::crypto::suite::LEGACY_SUITE_ID.into();
        assert!(legacy.validate().is_err());
        let mut swapped = k.clone();
        swapped.kem_pk = derive_device_keys(&[5u8; 32]).kem_pk;
        assert!(swapped.validate().is_err());
        let mut round3 = k.clone();
        round3.dil_sk = SignSecretKey(vec![0; 2528]);
        assert!(round3.validate().is_err(), "a Dilithium2-sized private key is not an ML-DSA seed");
        // a key set serialized without a suite (earlier releases) does not deserialize
        let mut v = serde_json::to_value(&k).unwrap();
        v.as_object_mut().unwrap().remove("suite");
        assert!(serde_json::from_value::<DeviceKeys>(v).is_err());
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
