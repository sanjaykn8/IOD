//! NIST ACVP known-answer tests for the exact parameter sets and library versions
//! this system uses: ML-KEM-768 (FIPS 203) via `ml-kem` 0.3.4 and ML-DSA-44
//! (FIPS 204) via `ml-dsa` 0.1.2.
//!
//! Vectors: `tests/kat/acvp-ml-kem-768.json`, `tests/kat/acvp-ml-dsa-44.json`, extracted
//! from the NIST ACVP-Server "internalProjection" files (URLs and SHA-256 of the source
//! files are recorded in each fixture's `provenance`). Every vector of the included
//! groups is checked; counts are asserted so a truncated fixture fails loudly.
//!
//! Also checks that the wrappers in `iod_core::crypto` produce the same bytes as the
//! crate APIs used here (seed-based key generation).

use hybrid_array::Array;
use iod_core::crypto::{kem as wkem, sign as wsign};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa44, Signature, SigningKey, VerifyingKey, B32};
use ml_dsa::signature::Keypair;
type B64 = Array<u8, hybrid_array::sizes::U64>;
use ml_kem::kem::{Decapsulate, KeyExport};
#[allow(deprecated)] // the expanded FIPS 203 key encoding is used only to check sizes and the ACVP dk vectors
use ml_kem::{DecapsulationKey, EncapsulationKey, ExpandedKeyEncoding, MlKem768};
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = format!("{}/tests/kat/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).expect("fixture present")).expect("fixture parses")
}
fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

/// Returns the NIST-given `rnd` as the "random" bytes the signer draws (test only).
struct FixedRng(Vec<u8>);
impl rand_core010::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!("ML-DSA draws rnd with fill_bytes")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!("ML-DSA draws rnd with fill_bytes")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(dst.len(), self.0.len(), "signer asked for exactly 32 bytes of rnd");
        dst.copy_from_slice(&self.0);
        Ok(())
    }
}
impl rand_core010::TryCryptoRng for FixedRng {}

// ------------------------------------------------------------------ ML-KEM-768

#[test]
#[allow(deprecated)]
fn ml_kem_768_keygen_vectors() {
    let v = load("acvp-ml-kem-768.json");
    let cases = v["keygen"].as_array().unwrap();
    assert_eq!(cases.len(), 25);
    for t in cases {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&hx(&t["d"]));
        seed[32..].copy_from_slice(&hx(&t["z"]));
        let dk = DecapsulationKey::<MlKem768>::from_seed(Array::from(seed));
        assert_eq!(dk.encapsulation_key().to_bytes().to_vec(), hx(&t["ek"]), "tcId {}", t["tcId"]);
        assert_eq!(dk.to_expanded_bytes().to_vec(), hx(&t["dk"]), "tcId {}", t["tcId"]);
        assert_eq!(hx(&t["ek"]).len(), wkem::PUBLIC_KEY_BYTES);
        assert_eq!(hx(&t["dk"]).len(), wkem::EXPANDED_SECRET_KEY_BYTES);
        // the wrapper's seed-form keygen yields the same public key
        let (pk, sk) = wkem::keypair_from_seed(&seed);
        assert_eq!(pk.0, hx(&t["ek"]));
        assert_eq!(sk.0, seed.to_vec());
    }
}

#[test]
fn ml_kem_768_encapsulation_vectors() {
    let v = load("acvp-ml-kem-768.json");
    let cases = v["encapsulation"].as_array().unwrap();
    assert_eq!(cases.len(), 25);
    for t in cases {
        let ek = EncapsulationKey::<MlKem768>::new(&Array::try_from(hx(&t["ek"]).as_slice()).unwrap()).unwrap();
        let m: [u8; 32] = hx(&t["m"]).try_into().unwrap();
        let (c, k) = ek.encapsulate_deterministic(&Array::from(m));
        assert_eq!(c.to_vec(), hx(&t["c"]), "tcId {}", t["tcId"]);
        assert_eq!(k.to_vec(), hx(&t["k"]), "tcId {}", t["tcId"]);
        assert_eq!(c.len(), wkem::CIPHERTEXT_BYTES);
        assert_eq!(k.len(), wkem::SHARED_SECRET_BYTES);
    }
}

#[test]
#[allow(deprecated)]
fn ml_kem_768_decapsulation_vectors_including_implicit_rejection() {
    let v = load("acvp-ml-kem-768.json");
    let cases = v["decapsulation"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    let mut rejected = 0;
    for t in cases {
        let dk = DecapsulationKey::<MlKem768>::from_expanded_bytes(&Array::try_from(hx(&t["dk"]).as_slice()).unwrap()).unwrap();
        let c = Array::try_from(hx(&t["c"]).as_slice()).unwrap();
        // for "modified ciphertext" cases the expected k IS the implicit-rejection value J(z||c)
        assert_eq!(dk.decapsulate(&c).to_vec(), hx(&t["k"]), "tcId {} ({})", t["tcId"], t["reason"]);
        rejected += (t["reason"] == "modified ciphertext") as usize;
    }
    assert!(rejected >= 1, "fixture covers implicit rejection");
}

#[test]
#[allow(deprecated)]
fn ml_kem_768_key_check_vectors() {
    let v = load("acvp-ml-kem-768.json");
    let dkc = v["decapsulation_key_check"].as_array().unwrap();
    let ekc = v["encapsulation_key_check"].as_array().unwrap();
    assert_eq!((dkc.len(), ekc.len()), (10, 10));
    for t in dkc {
        let ok = DecapsulationKey::<MlKem768>::from_expanded_bytes(&Array::try_from(hx(&t["dk"]).as_slice()).unwrap()).is_ok();
        assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "tcId {} ({})", t["tcId"], t["reason"]);
    }
    for t in ekc {
        let ok = EncapsulationKey::<MlKem768>::new(&Array::try_from(hx(&t["ek"]).as_slice()).unwrap()).is_ok();
        assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "tcId {} ({})", t["tcId"], t["reason"]);
        // the wrapper applies the same check before encapsulating
        assert_eq!(wkem::encapsulate(&wkem::KemPublicKey(hx(&t["ek"]))).is_ok(), ok, "wrapper tcId {}", t["tcId"]);
    }
}

// ------------------------------------------------------------------ ML-DSA-44

#[test]
#[allow(deprecated)]
fn ml_dsa_44_keygen_vectors() {
    let v = load("acvp-ml-dsa-44.json");
    let cases = v["keygen"].as_array().unwrap();
    assert_eq!(cases.len(), 25);
    for t in cases {
        let xi: [u8; 32] = hx(&t["seed"]).try_into().unwrap();
        let sk = SigningKey::<MlDsa44>::from_seed(&B32::from(xi));
        assert_eq!(sk.verifying_key().encode().to_vec(), hx(&t["pk"]), "tcId {}", t["tcId"]);
        assert_eq!(sk.expanded_key().to_expanded().to_vec(), hx(&t["sk"]), "tcId {}", t["tcId"]);
        assert_eq!(hx(&t["pk"]).len(), wsign::PUBLIC_KEY_BYTES);
        assert_eq!(hx(&t["sk"]).len(), wsign::EXPANDED_SECRET_KEY_BYTES);
        let (pk, ssk) = wsign::keypair_from_seed(&xi);
        assert_eq!(pk.0, hx(&t["pk"]));
        assert_eq!(ssk.0, xi.to_vec());
    }
}

#[test]
#[allow(deprecated)]
fn ml_dsa_44_siggen_vectors() {
    let v = load("acvp-ml-dsa-44.json");
    let cases = v["siggen"].as_array().unwrap();
    assert_eq!(cases.len(), 90);
    let mut seen = std::collections::BTreeMap::new();
    for t in cases {
        let skb = ExpandedSigningKeyBytes::<MlDsa44>::try_from(hx(&t["sk"]).as_slice()).unwrap();
        let sk = ExpandedSigningKey::<MlDsa44>::from_expanded(&skb);
        let det = t["deterministic"].as_bool().unwrap();
        let rnd: Vec<u8> = if det { vec![0u8; 32] } else { hx(&t["rnd"]) };
        let rnd32 = B32::try_from(rnd.as_slice()).unwrap();
        let sig: Signature<MlDsa44> = match (t["interface"].as_str().unwrap(), t["externalMu"].as_bool().unwrap()) {
            ("external", false) => {
                let (m, ctx) = (hx(&t["message"]), hx(&t["context"]));
                if det {
                    sk.sign_deterministic(&m, &ctx).unwrap()
                } else {
                    sk.sign_randomized(&m, &ctx, &mut FixedRng(rnd.clone())).unwrap()
                }
            }
            ("internal", false) => sk.sign_internal(&[&hx(&t["message"])], &rnd32),
            ("internal", true) => {
                let mu = B64::try_from(hx(&t["mu"]).as_slice()).unwrap();
                if det {
                    sk.sign_mu_deterministic(&mu)
                } else {
                    sk.sign_mu_randomized(&mu, &mut FixedRng(rnd.clone())).unwrap()
                }
            }
            other => panic!("unexpected group {other:?}"),
        };
        assert_eq!(sig.encode().to_vec(), hx(&t["signature"]), "tcId {}", t["tcId"]);
        assert_eq!(sig.encode().len(), wsign::SIGNATURE_BYTES);
        *seen.entry((t["interface"].as_str().unwrap().to_string(), t["externalMu"].as_bool().unwrap(), det)).or_insert(0) += 1;
    }
    assert_eq!(seen.len(), 6, "external/internal/external-mu x deterministic/hedged all covered: {seen:?}");
}

#[test]
fn ml_dsa_44_sigver_vectors() {
    let v = load("acvp-ml-dsa-44.json");
    let cases = v["sigver"].as_array().unwrap();
    assert_eq!(cases.len(), 45);
    let (mut accepted, mut rejected) = (0, 0);
    for t in cases {
        let vk = VerifyingKey::<MlDsa44>::decode(&EncodedVerifyingKey::<MlDsa44>::try_from(hx(&t["pk"]).as_slice()).unwrap());
        let sig = EncodedSignature::<MlDsa44>::try_from(hx(&t["signature"]).as_slice()).ok().and_then(|e| Signature::<MlDsa44>::decode(&e));
        let ok = match sig {
            None => false,
            Some(sig) => match (t["interface"].as_str().unwrap(), t["externalMu"].as_bool().unwrap()) {
                ("external", false) => vk.verify_with_context(&hx(&t["message"]), &hx(&t["context"]), &sig),
                ("internal", false) => vk.verify_internal(&hx(&t["message"]), &sig),
                ("internal", true) => vk.verify_mu(&B64::try_from(hx(&t["mu"]).as_slice()).unwrap(), &sig),
                other => panic!("unexpected group {other:?}"),
            },
        };
        assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "tcId {} ({})", t["tcId"], t["reason"]);
        if ok { accepted += 1 } else { rejected += 1 }
        // the wrapper (context = suite id) must accept none of these: they were made under other contexts
        if t["interface"] == "external" {
            assert!(!wsign::verify_transcript(&wsign::SignPublicKey(hx(&t["pk"])), &hx(&t["message"]), &wsign::Signature(hx(&t["signature"]))));
        }
    }
    assert_eq!((accepted, rejected), (9, 36), "valid and modified (z, hint, commitment, message) cases");
}
