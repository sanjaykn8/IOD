//! Centralized domain-separation tags.
//!
//! Every Poseidon call, every KDF call, and every derived-key call in
//! this project must go through one of these constants rather than an
//! ad-hoc string/number, so that a code reviewer (or future contributor)
//! can see at a glance every distinct cryptographic "purpose" in the
//! system and confirm none of them collide. This directly implements the
//! "domain separation" and "do not reuse the same raw seed across
//! unrelated primitives" requirements.

// --- Poseidon domains (u64 tags absorbed as the sponge capacity seed) ---
pub const POSEIDON_LEAF: u64 = 0x01;
pub const POSEIDON_PK_COMMITMENT: u64 = 0x02;
pub const POSEIDON_MERKLE_NODE: u64 = 0x10;
pub const POSEIDON_ZK_WITNESS_COMMITMENT: u64 = 0x20;
pub const POSEIDON_ZK_FS_CHALLENGE: u64 = 0x21;
pub const POSEIDON_GROUP_ID: u64 = 0x30;

// --- KDF / seed-derivation domain strings (HKDF "info" parameters) ---
pub const SEED_DOMAIN_KEM: &[u8] = b"IOD-SEED-KEM-v1";
pub const SEED_DOMAIN_DILITHIUM: &[u8] = b"IOD-SEED-DILITHIUM-v1";
pub const SEED_DOMAIN_PID: &[u8] = b"IOD-SEED-PID-v1";
pub const SEED_DOMAIN_PUF_MAC: &[u8] = b"IOD-SEED-PUF-MAC-v1";
pub const SEED_DOMAIN_AEAD: &[u8] = b"IOD-SEED-AEAD-KEY-v1";
pub const SEED_DOMAIN_FUZZY_EXTRACTOR: &[u8] = b"IOD-SEED-FUZZY-EXTRACTOR-v1";
pub const SEED_DOMAIN_ENVELOPE: &[u8] = b"IOD-SEED-ENVELOPE-KEY-v1";
pub const SEED_DOMAIN_GROUP_KEY_AEAD: &[u8] = b"IOD-SEED-GROUPKEY-AEAD-v1";

// --- SHAKE256 transcript domains (byte string prefixes) ---
pub const TRANSCRIPT_AUTH: &[u8] = b"AuthTranscript-v1";
pub const TRANSCRIPT_BASE_PUF: &[u8] = b"PUFBaseTranscript-v1";
