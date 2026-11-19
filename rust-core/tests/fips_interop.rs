//! Cross-implementation interoperability: the system's wrappers (RustCrypto `ml-kem` /
//! `ml-dsa`, pure Rust) against PQClean's independent C implementations of the final
//! FIPS 203 / FIPS 204 algorithms (`pqcrypto-mlkem`, `pqcrypto-mldsa`; test-only).

use iod_core::crypto::{kem, sign, suite};
use pqcrypto_mldsa::mldsa44;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

#[test]
fn sizes_agree_with_the_independent_implementation() {
    assert_eq!(mlkem768::public_key_bytes(), kem::PUBLIC_KEY_BYTES);
    assert_eq!(mlkem768::secret_key_bytes(), kem::EXPANDED_SECRET_KEY_BYTES);
    assert_eq!(mlkem768::ciphertext_bytes(), kem::CIPHERTEXT_BYTES);
    assert_eq!(mlkem768::shared_secret_bytes(), kem::SHARED_SECRET_BYTES);
    assert_eq!(mldsa44::public_key_bytes(), sign::PUBLIC_KEY_BYTES);
    assert_eq!(mldsa44::secret_key_bytes(), sign::EXPANDED_SECRET_KEY_BYTES);
    assert_eq!(mldsa44::signature_bytes(), sign::SIGNATURE_BYTES);
}

#[test]
fn ml_kem_768_both_directions() {
    for _ in 0..20 {
        // PQClean encapsulates to our key; we decapsulate
        let (pk, sk) = kem::keypair();
        let (ss_c, ct_c) = mlkem768::encapsulate(&mlkem768::PublicKey::from_bytes(&pk.0).unwrap());
        let ss_r = kem::decapsulate(&sk, &kem::KemCiphertext(ct_c.as_bytes().to_vec())).unwrap();
        assert_eq!(ss_r.0, ss_c.as_bytes());
        // we encapsulate to a PQClean key; PQClean decapsulates
        let (pk_c, sk_c) = mlkem768::keypair();
        let (ct_r, ss_r) = kem::encapsulate(&kem::KemPublicKey(pk_c.as_bytes().to_vec())).unwrap();
        let ss_c = mlkem768::decapsulate(&mlkem768::Ciphertext::from_bytes(&ct_r.0).unwrap(), &sk_c);
        assert_eq!(ss_r.0, ss_c.as_bytes());
    }
}

#[test]
fn ml_kem_768_tampered_ciphertext_gives_the_same_rejection_secret_in_both() {
    // Implicit rejection: both implementations must derive the identical J(z || c)
    // for a tampered ciphertext, given the same expanded decapsulation key.
    #[allow(deprecated)]
    {
        use ml_kem::{kem::Decapsulate, DecapsulationKey, ExpandedKeyEncoding, MlKem768};
        let (pk_c, sk_c) = mlkem768::keypair();
        use pqcrypto_traits::kem::SecretKey as _;
        let dk = DecapsulationKey::<MlKem768>::from_expanded_bytes(&hybrid_array::Array::try_from(sk_c.as_bytes()).unwrap()).unwrap();
        let (mut ct, _) = kem::encapsulate(&kem::KemPublicKey(pk_c.as_bytes().to_vec())).unwrap();
        ct.0[17] ^= 0x40;
        let ours = dk.decapsulate(&hybrid_array::Array::try_from(ct.0.as_slice()).unwrap());
        let theirs = mlkem768::decapsulate(&mlkem768::Ciphertext::from_bytes(&ct.0).unwrap(), &sk_c);
        assert_eq!(ours.as_slice(), theirs.as_bytes());
    }
}

#[test]
fn ml_dsa_44_both_directions_with_the_suite_context() {
    let msg = b"canonical transcript bytes under test";
    for _ in 0..10 {
        // our hedged signature verifies under PQClean with the same context string
        let (pk, sk) = sign::keypair();
        let sig = sign::sign_transcript(&sk, msg).unwrap();
        let pk_c = mldsa44::PublicKey::from_bytes(&pk.0).unwrap();
        let sig_c = mldsa44::DetachedSignature::from_bytes(&sig.0).unwrap();
        assert!(mldsa44::verify_detached_signature_ctx(&sig_c, msg, suite::SUITE_ID.as_bytes(), &pk_c).is_ok());
        assert!(mldsa44::verify_detached_signature_ctx(&sig_c, msg, b"", &pk_c).is_err(), "context binds");
        // PQClean's signature (suite context) verifies under our wrapper; other contexts do not
        let (pk_c, sk_c) = mldsa44::keypair();
        let pk = sign::SignPublicKey(pk_c.as_bytes().to_vec());
        let s = mldsa44::detached_sign_ctx(msg, suite::SUITE_ID.as_bytes(), &sk_c);
        assert!(sign::verify_transcript(&pk, msg, &sign::Signature(s.as_bytes().to_vec())));
        let s_plain = mldsa44::detached_sign(msg, &sk_c);
        assert!(!sign::verify_transcript(&pk, msg, &sign::Signature(s_plain.as_bytes().to_vec())));
        let s_legacy = mldsa44::detached_sign_ctx(msg, suite::LEGACY_SUITE_ID.as_bytes(), &sk_c);
        assert!(!sign::verify_transcript(&pk, msg, &sign::Signature(s_legacy.as_bytes().to_vec())));
    }
}

#[test]
fn ml_dsa_44_seed_keys_match_the_expanded_form_the_other_implementation_uses() {
    #[allow(deprecated)]
    {
        use ml_dsa::{MlDsa44, SigningKey};
        let (pk, sk) = sign::keypair();
        let k = SigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::try_from(sk.0.as_slice()).unwrap());
        let expanded = k.expanded_key().to_expanded();
        // PQClean signs with the expanded key derived from our seed; we verify
        let sk_c = <mldsa44::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(&expanded).unwrap();
        let s = mldsa44::detached_sign_ctx(b"m", suite::SUITE_ID.as_bytes(), &sk_c);
        assert!(sign::verify_transcript(&pk, b"m", &sign::Signature(s.as_bytes().to_vec())));
    }
}
