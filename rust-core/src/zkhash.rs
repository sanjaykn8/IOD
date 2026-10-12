//! Native (non-circuit) hash primitives used by the membership tree and
//! the zero-knowledge membership proof. See `docs/zk-specification.md`
//! §3-§5 for the normative definitions; this file is the reference
//! implementation.
//!
//! * Field: BabyBear, p = 2^31 - 2^27 + 1 = 2013265921.
//! * Permutation: Poseidon2 (Grassi–Khovratovich–Schofnegger, ePrint
//!   2023/323), width 16, S-box x^7, 8 full + 13 partial rounds, with the
//!   constants shipped in `p3-baby-bear` (the same instance the STARK
//!   circuit proves; this equality is asserted by a unit test).
//! * Digest: 8 field elements (248 bits). Rate 8, capacity 8.
//! * Byte -> field: always 3 bytes per element, little-endian (24 bits,
//!   strictly below p), so the packing is injective. No reduction mod p is
//!   ever relied upon to be injective.
//!
//! Replaces the earlier Goldilocks (64-bit) Poseidon whose single-element
//! output offered only ~2^32 classical collision resistance.

use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::sync::OnceLock;

pub type Bb = BabyBear;

pub const P: u32 = 2_013_265_921;
pub const DIGEST_LEN: usize = 8;
/// A 256-bit SHAKE256 output packed injectively into 3-byte limbs.
pub const HASH_LIMBS: usize = 11;
pub const RHO_LIMBS: usize = 8;
/// Leaf stream length (see `leaf_stream`): padded to 6 rate blocks.
pub const LEAF_STREAM_LEN: usize = 48;
pub const LEAF_BLOCKS: usize = LEAF_STREAM_LEN / 8;
/// Leaf format version absorbed as limb 0 of every leaf preimage.
pub const LEAF_FORMAT_VERSION: u32 = 1;
/// Sponge-capacity domain tags (capacity[0]); capacity[1] = stream length,
/// capacity[2] = parameter-set id.
pub const DOMAIN_LEAF: u32 = 0x4C45_4146 % P; // "LEAF"
pub const PARAM_SET_ID: u32 = 1;

pub type Limbs = [u32; HASH_LIMBS];

static PERM: OnceLock<Poseidon2BabyBear<16>> = OnceLock::new();

pub fn perm() -> &'static Poseidon2BabyBear<16> {
    PERM.get_or_init(default_babybear_poseidon2_16)
}

#[inline]
pub fn bb(x: u32) -> Bb {
    debug_assert!(x < P);
    Bb::from_u32(x)
}

#[inline]
pub fn to_u32(x: Bb) -> u32 {
    x.as_canonical_u32()
}

/// A canonical 8-element BabyBear digest. `ZERO` is the empty/revoked-leaf
/// sentinel of the membership tree.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Digest(pub [u32; DIGEST_LEN]);

impl Digest {
    pub const ZERO: Digest = Digest([0; DIGEST_LEN]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0; DIGEST_LEN]
    }

    pub fn from_bb(a: [Bb; DIGEST_LEN]) -> Self {
        Digest(core::array::from_fn(|i| to_u32(a[i])))
    }

    pub fn to_bb(&self) -> [Bb; DIGEST_LEN] {
        core::array::from_fn(|i| bb(self.0[i]))
    }

    /// 32 bytes, each limb as u32 little-endian.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, l) in self.0.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&l.to_le_bytes());
        }
        out
    }

    /// Rejects non-canonical limbs (>= p).
    pub fn from_bytes(b: &[u8; 32]) -> Option<Self> {
        let mut l = [0u32; DIGEST_LEN];
        for i in 0..DIGEST_LEN {
            l[i] = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
            if l[i] >= P {
                return None;
            }
        }
        Some(Digest(l))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let v = hex::decode(s).ok()?;
        let a: [u8; 32] = v.try_into().ok()?;
        Self::from_bytes(&a)
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Digest::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid digest hex"))
    }
}

/// Injective packing: 3 bytes (LE) per limb, final chunk zero-padded.
/// The byte length must be carried separately by the caller (every use
/// below length-prefixes the bytes before hashing).
pub fn pack3(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(3)
        .map(|c| {
            let mut b = [0u8; 4];
            b[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(b)
        })
        .collect()
}

/// SHAKE256 over `domain` and length-prefixed parts (8-byte LE length each;
/// the domain is itself length-prefixed), 32-byte output packed into
/// 11 three-byte limbs. Used for G, comm_PK, metadata digests and the
/// session context digest.
pub fn shake_limbs(domain: &[u8], parts: &[&[u8]]) -> Limbs {
    let mut h = Shake256::default();
    h.update(&(domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update(&(parts.len() as u64).to_le_bytes());
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let mut out = [0u8; 33];
    h.finalize_xof().read(&mut out[..32]);
    let v = pack3(&out);
    let mut l = [0u32; HASH_LIMBS];
    l.copy_from_slice(&v[..HASH_LIMBS]);
    l
}

pub fn limbs_to_bytes(l: &Limbs) -> Vec<u8> {
    l.iter().flat_map(|x| x.to_le_bytes()).collect()
}

/// Leaf preimage stream (48 limbs, fixed layout, see spec §4):
///   [0]      LEAF_FORMAT_VERSION
///   [1..12)  group digest G
///   [12..23) comm_PK
///   [23..34) metadata digest
///   [34..42) rho (8 uniform field elements, PRIVATE)
///   [42..48) zero padding
pub fn leaf_stream(g: &Limbs, comm: &Limbs, meta: &Limbs, rho: &[u32; RHO_LIMBS]) -> [Bb; LEAF_STREAM_LEN] {
    let mut s = [Bb::ZERO; LEAF_STREAM_LEN];
    s[0] = bb(LEAF_FORMAT_VERSION);
    for i in 0..HASH_LIMBS {
        s[1 + i] = bb(g[i]);
        s[12 + i] = bb(comm[i]);
        s[23 + i] = bb(meta[i]);
    }
    for i in 0..RHO_LIMBS {
        s[34 + i] = bb(rho[i]);
    }
    s
}

pub fn leaf_iv() -> [Bb; 8] {
    let mut iv = [Bb::ZERO; 8];
    iv[0] = bb(DOMAIN_LEAF);
    iv[1] = bb(LEAF_STREAM_LEN as u32);
    iv[2] = bb(PARAM_SET_ID);
    iv
}

/// Sponge states after each of the six leaf permutations (inputs and
/// outputs), used by the prover to build the trace.
pub fn leaf_sponge_states(stream: &[Bb; LEAF_STREAM_LEN]) -> Vec<([Bb; 16], [Bb; 16])> {
    let p = perm();
    let iv = leaf_iv();
    let mut state = [Bb::ZERO; 16];
    state[8..16].copy_from_slice(&iv);
    let mut rec = Vec::with_capacity(LEAF_BLOCKS);
    for k in 0..LEAF_BLOCKS {
        for j in 0..8 {
            state[j] += stream[8 * k + j];
        }
        let input = state;
        p.permute_mut(&mut state);
        rec.push((input, state));
    }
    rec
}

pub fn leaf_hash(g: &Limbs, comm: &Limbs, meta: &Limbs, rho: &[u32; RHO_LIMBS]) -> Digest {
    let st = leaf_sponge_states(&leaf_stream(g, comm, meta, rho));
    let out = st.last().unwrap().1;
    Digest::from_bb(core::array::from_fn(|i| out[i]))
}

/// Merkle node: first 8 outputs of P(left || right) (truncated
/// permutation, as in Plonky3's `TruncatedPermutation`).
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut st = [Bb::ZERO; 16];
    st[..8].copy_from_slice(&left.to_bb());
    st[8..].copy_from_slice(&right.to_bb());
    perm().permute_mut(&mut st);
    Digest::from_bb(core::array::from_fn(|i| st[i]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack3_is_injective_on_distinct_inputs() {
        assert_ne!(pack3(b"AB"), pack3(b"A"));
        assert!(pack3(&[0xff; 30]).iter().all(|&x| x < P));
    }

    #[test]
    fn shake_limbs_domain_separated_and_canonical() {
        let a = shake_limbs(b"d1", &[b"x"]);
        let b = shake_limbs(b"d2", &[b"x"]);
        assert_ne!(a, b);
        assert!(a.iter().all(|&x| x < P));
        assert_ne!(shake_limbs(b"d", &[b"AB", b"C"]), shake_limbs(b"d", &[b"A", b"BC"]));
    }

    #[test]
    fn digest_roundtrip_and_noncanonical_rejected() {
        let d = Digest([1, 2, 3, 4, 5, 6, 7, P - 1]);
        assert_eq!(Digest::from_hex(&d.to_hex()), Some(d));
        let mut b = d.to_bytes();
        b[28..32].copy_from_slice(&P.to_le_bytes());
        assert!(Digest::from_bytes(&b).is_none());
    }

    #[test]
    fn leaf_hash_binds_every_input() {
        let g = shake_limbs(b"g", &[b"alpha"]);
        let c = shake_limbs(b"c", &[b"pk"]);
        let m = shake_limbs(b"m", &[b"role"]);
        let rho = [1u32; 8];
        let base = leaf_hash(&g, &c, &m, &rho);
        let mut rho2 = rho;
        rho2[7] ^= 1;
        assert_ne!(base, leaf_hash(&g, &c, &m, &rho2));
        assert_ne!(base, leaf_hash(&c, &g, &m, &rho));
        assert_ne!(base, leaf_hash(&g, &c, &g, &rho));
        assert!(!base.is_zero());
    }

    #[test]
    fn node_hash_is_ordered() {
        let a = Digest([1; 8]);
        let b = Digest([2; 8]);
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
    }
}
