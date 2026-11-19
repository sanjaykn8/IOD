//! Post-quantum KEM wrapper: **ML-KEM-768 (FIPS 203, final)** via the RustCrypto
//! `ml-kem` crate (pinned `=0.3.4`).
//!
//! IMPORTANT (KEM, not PKE): ML-KEM is a *Key Encapsulation Mechanism*.
//! `encapsulate` does not "encrypt an arbitrary plaintext" — it produces a fresh
//! ciphertext bound to a fresh 32-byte shared secret. To send a structured
//! payload confidentially and authentically, the protocol layer
//! (`protocol/envelope.rs`) does
//!     (ct, shared_secret) = kem::encapsulate(pk)
//!     aead_key = HKDF(shared_secret, info = domain || suite)
//!     ciphertext = ChaCha20-Poly1305(aead_key, associated_data, plaintext)
//! and transmits `(ct, ciphertext)` together. This module intentionally does NOT
//! expose an `encrypt(pk, plaintext)` function.
//!
//! ## Encodings
//! * Public (encapsulation) key: the FIPS 203 `ek` byte string, 1184 bytes. Decoding
//!   runs the crate's FIPS 203 §7.2 modulus check; non-canonical keys are rejected.
//! * Private (decapsulation) key: stored in **seed form** `d || z` (64 bytes), the
//!   crate's preferred serialization and permitted by FIPS 203 §3.3. The expanded
//!   2400-byte `dk` encoding is checked in tests only.
//! * Ciphertext 1088 bytes, shared secret 32 bytes.
//!
//! ## Implicit rejection
//! FIPS 203 decapsulation never reports "invalid ciphertext": a well-formed-length
//! but tampered ciphertext yields a pseudo-random shared secret `J(z || c)`. The
//! protocol therefore relies on the AEAD tag under the derived key to reject such
//! envelopes. Only a ciphertext of the wrong LENGTH is a decoding error here.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, Generate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};

pub const PUBLIC_KEY_BYTES: usize = 1184;
pub const EXPANDED_SECRET_KEY_BYTES: usize = 2400;
pub const SECRET_SEED_BYTES: usize = 64;
pub const CIPHERTEXT_BYTES: usize = 1088;
pub const SHARED_SECRET_BYTES: usize = 32;

type Dk = DecapsulationKey<MlKem768>;
type Ek = EncapsulationKey<MlKem768>;

/// FIPS 203 encapsulation key bytes (1184).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct KemPublicKey(pub Vec<u8>);
/// Decapsulation key in seed form `d || z` (64 bytes). Device-local only.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct KemSecretKey(pub Vec<u8>);
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct KemCiphertext(pub Vec<u8>);
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct KemSharedSecret(pub Vec<u8>);

impl std::fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KemSecretKey(<redacted>)")
    }
}
impl std::fmt::Debug for KemSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KemSharedSecret(<redacted>)")
    }
}

fn parse_ek(pk: &KemPublicKey) -> anyhow::Result<Ek> {
    let arr = Array::try_from(pk.0.as_slice())
        .map_err(|_| anyhow::anyhow!("ML-KEM-768 public key must be {PUBLIC_KEY_BYTES} bytes, got {}", pk.0.len()))?;
    Ek::new(&arr).map_err(|_| anyhow::anyhow!("ML-KEM-768 public key failed the FIPS 203 modulus check"))
}

fn parse_dk(sk: &KemSecretKey) -> anyhow::Result<Dk> {
    let seed = Array::try_from(sk.0.as_slice())
        .map_err(|_| anyhow::anyhow!("ML-KEM-768 private key seed must be {SECRET_SEED_BYTES} bytes, got {}", sk.0.len()))?;
    Ok(Dk::from_seed(seed))
}

fn export(dk: &Dk) -> (KemPublicKey, KemSecretKey) {
    let seed = dk.to_seed().expect("key was created from a seed");
    (KemPublicKey(dk.encapsulation_key().to_bytes().to_vec()), KemSecretKey(seed.to_vec()))
}

/// Fresh keypair from the operating-system CSPRNG (FIPS 203 ML-KEM.KeyGen).
pub fn keypair() -> (KemPublicKey, KemSecretKey) {
    export(&Dk::generate())
}

/// Deterministic keypair from a 64-byte seed `d || z` (FIPS 203 ML-KEM.KeyGen_internal).
///
/// Used by the NIST known-answer tests. It is also the documented seam for future
/// provisioning from a physical PUF; the simulator does NOT derive device keys
/// from the simulated PUF (see `identity::keys`).
pub fn keypair_from_seed(seed: &[u8; SECRET_SEED_BYTES]) -> (KemPublicKey, KemSecretKey) {
    export(&Dk::from_seed(Array::from(*seed)))
}

/// Derive the public key from a stored private key (used to check stored state).
pub fn public_from_secret(sk: &KemSecretKey) -> anyhow::Result<KemPublicKey> {
    Ok(export(&parse_dk(sk)?).0)
}

/// FIPS 203 ML-KEM.Encaps with fresh OS randomness.
pub fn encapsulate(pk: &KemPublicKey) -> anyhow::Result<(KemCiphertext, KemSharedSecret)> {
    let ek = parse_ek(pk)?;
    let (ct, ss) = ek.encapsulate();
    Ok((KemCiphertext(ct.to_vec()), KemSharedSecret(ss.to_vec())))
}

/// FIPS 203 ML-KEM.Decaps. Wrong-length inputs are errors; a tampered ciphertext of
/// the right length returns the implicit-rejection secret (see module docs).
pub fn decapsulate(sk: &KemSecretKey, ct: &KemCiphertext) -> anyhow::Result<KemSharedSecret> {
    let dk = parse_dk(sk)?;
    let c = Array::try_from(ct.0.as_slice())
        .map_err(|_| anyhow::anyhow!("ML-KEM-768 ciphertext must be {CIPHERTEXT_BYTES} bytes, got {}", ct.0.len()))?;
    Ok(KemSharedSecret(dk.decapsulate(&c).to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_sizes() {
        let (pk, sk) = keypair();
        assert_eq!(pk.0.len(), PUBLIC_KEY_BYTES);
        assert_eq!(sk.0.len(), SECRET_SEED_BYTES);
        let (ct, ss) = encapsulate(&pk).unwrap();
        assert_eq!(ct.0.len(), CIPHERTEXT_BYTES);
        assert_eq!(ss.0.len(), SHARED_SECRET_BYTES);
        #[allow(deprecated)]
        {
            use ml_kem::ExpandedKeyEncoding;
            let dk = parse_dk(&sk).unwrap();
            assert_eq!(dk.to_expanded_bytes().len(), EXPANDED_SECRET_KEY_BYTES);
        }
    }

    #[test]
    fn encapsulate_decapsulate_agree() {
        let (pk, sk) = keypair();
        let (ct, ss1) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1.0, ss2.0);
        assert_eq!(public_from_secret(&sk).unwrap(), pk);
    }

    #[test]
    fn seeded_keygen_is_deterministic_and_seeds_differ() {
        let a = keypair_from_seed(&[7u8; 64]);
        let b = keypair_from_seed(&[7u8; 64]);
        let c = keypair_from_seed(&[8u8; 64]);
        assert_eq!(a.0, b.0);
        assert_eq!(a.1 .0, b.1 .0);
        assert_ne!(a.0, c.0);
        assert_ne!(keypair().0, keypair().0, "OS-random keys differ");
    }

    #[test]
    fn wrong_secret_key_gives_different_secret() {
        let (pk, _sk1) = keypair();
        let (_pk2, sk2) = keypair();
        let (ct, ss1) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk2, &ct).unwrap();
        assert_ne!(ss1.0, ss2.0);
    }

    #[test]
    fn tampered_ciphertext_gets_the_implicit_rejection_secret() {
        let (pk, sk) = keypair();
        let (ct, ss1) = encapsulate(&pk).unwrap();
        for pos in [0usize, 500, CIPHERTEXT_BYTES - 1] {
            let mut bad = ct.clone();
            bad.0[pos] ^= 0x01;
            let ss2 = decapsulate(&sk, &bad).unwrap();
            assert_ne!(ss1.0, ss2.0, "pos {pos}");
            // implicit rejection is deterministic for a given (dk, c)
            assert_eq!(ss2.0, decapsulate(&sk, &bad).unwrap().0);
            assert_eq!(ss2.0.len(), SHARED_SECRET_BYTES);
        }
    }

    #[test]
    fn malformed_encodings_are_rejected() {
        let (pk, sk) = keypair();
        let (ct, _) = encapsulate(&pk).unwrap();
        assert!(encapsulate(&KemPublicKey(pk.0[..PUBLIC_KEY_BYTES - 1].to_vec())).is_err());
        assert!(encapsulate(&KemPublicKey(vec![])).is_err());
        // a coefficient >= q (all-ones 12-bit fields) fails the FIPS 203 modulus check
        let mut nc = pk.0.clone();
        nc[0] = 0xFF;
        nc[1] = 0xFF;
        assert!(encapsulate(&KemPublicKey(nc)).is_err());
        assert!(decapsulate(&sk, &KemCiphertext(ct.0[..100].to_vec())).is_err());
        assert!(decapsulate(&KemSecretKey(vec![0; 2400]), &ct).is_err(), "expanded/legacy-length private keys are not accepted");
        assert!(decapsulate(&KemSecretKey(vec![0; 2400 - 64]), &ct).is_err());
    }

    #[test]
    fn secrets_are_redacted_in_debug_output() {
        let (_, sk) = keypair();
        assert_eq!(format!("{sk:?}"), "KemSecretKey(<redacted>)");
    }
}
