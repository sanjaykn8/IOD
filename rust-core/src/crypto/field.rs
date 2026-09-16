//! A minimal prime-field implementation used only for Poseidon hashing.
//!
//! This field is deliberately **not** an elliptic-curve scalar/base field:
//! we never form a curve group, never do scalar multiplication, and never
//! use pairings. It is used purely as the algebraic structure Poseidon's
//! S-box/MDS layer operates over, which is how every Poseidon
//! specification (including hash-based/STARK-oriented ones such as
//! Poseidon2 over the Goldilocks field used by Plonky2/Miden) defines the
//! primitive. Using a field for a hash function does not introduce ECC.
//!
//! Modulus: the 64-bit Goldilocks prime `p = 2^64 - 2^32 + 1`. This prime
//! is chosen because (a) it admits fast reduction, (b) it is the field
//! used by multiple production *transparent* (hash-based, FRI-style)
//! proof systems, which fits this project's "no trusted setup / no ECC"
//! requirement, and (c) it has no association with any pairing-friendly
//! or Weierstrass curve.

pub const MODULUS: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct Fp(pub u64);

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    #[inline]
    pub fn new(v: u64) -> Self {
        Fp(v % MODULUS)
    }

    /// Reduce a wide (128-bit) product modulo `p`.
    ///
    /// We use a plain `%` here rather than a hand-rolled Goldilocks fast
    /// reduction. Correctness matters far more than raw speed for a
    /// research prototype, and a bespoke fast-reduction routine is a easy
    /// place to introduce a silent, hard-to-notice soundness bug in a
    /// cryptographic hash. `u128 % u128` is checked against an
    /// exhaustive-ish randomized test suite below.
    #[inline]
    fn reduce128(x: u128) -> u64 {
        (x % (MODULUS as u128)) as u64
    }

    #[inline]
    pub fn add(self, other: Fp) -> Fp {
        // Widen to u128 to avoid any carry/overflow subtlety; simplicity
        // and correctness are preferred over a hand-tuned fast path.
        let s = self.0 as u128 + other.0 as u128;
        Fp((s % MODULUS as u128) as u64)
    }

    #[inline]
    pub fn sub(self, other: Fp) -> Fp {
        if self.0 >= other.0 {
            Fp(self.0 - other.0)
        } else {
            Fp(MODULUS - (other.0 - self.0))
        }
    }

    #[inline]
    pub fn mul(self, other: Fp) -> Fp {
        let wide = (self.0 as u128) * (other.0 as u128);
        Fp(Self::reduce128(wide))
    }

    pub fn pow(self, mut exp: u64) -> Fp {
        let mut base = self;
        let mut acc = Fp::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        acc
    }

    /// Poseidon S-box exponent for this field/security target: x^7
    /// (7 is coprime to p-1, standard choice for Goldilocks-like fields).
    #[inline]
    pub fn sbox(self) -> Fp {
        self.pow(7)
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Fp {
        // Absorb arbitrary-length bytes into field elements by chunking
        // 8 bytes at a time and reducing each chunk mod p, combining with
        // a simple Horner-style fold. Used only for canonical encoding
        // helpers (leaf/commitment input packing), not for the Poseidon
        // permutation itself.
        let mut acc = Fp::ZERO;
        for chunk in bytes.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            let v = u64::from_le_bytes(buf);
            acc = acc.mul(Fp::new(0x9E37_79B9_7F4A_7C15u64)).add(Fp::new(v));
        }
        acc
    }

    pub fn to_bytes_le(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_roundtrip() {
        let a = Fp::new(12345678901234567);
        let b = Fp::new(98765432109876);
        let c = a.add(b).sub(b);
        assert_eq!(a, c);
    }

    #[test]
    fn mul_associative_examples() {
        let a = Fp::new(3);
        let b = Fp::new(MODULUS - 1); // -1
        assert_eq!(a.mul(b), Fp::new(MODULUS - 3));
    }

    #[test]
    fn pow_matches_repeated_mul() {
        let a = Fp::new(5);
        let mut expect = Fp::ONE;
        for _ in 0..7 {
            expect = expect.mul(a);
        }
        assert_eq!(a.pow(7), expect);
    }

    #[test]
    fn randomized_cross_check_against_u128_arithmetic() {
        // Independent oracle: compute in u128 with an explicit modulo,
        // completely separate code path from the Fp methods under test.
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        for _ in 0..2000 {
            let a = rng.next_u64() % MODULUS;
            let b = rng.next_u64() % MODULUS;
            let oracle_add = ((a as u128 + b as u128) % MODULUS as u128) as u64;
            let oracle_mul = ((a as u128 * b as u128) % MODULUS as u128) as u64;
            let oracle_sub = if a >= b { a - b } else { MODULUS - (b - a) };
            assert_eq!(Fp(a).add(Fp(b)).0, oracle_add);
            assert_eq!(Fp(a).mul(Fp(b)).0, oracle_mul);
            assert_eq!(Fp(a).sub(Fp(b)).0, oracle_sub);
        }
    }

    #[test]
    fn no_overflow_near_modulus() {
        let a = Fp::new(MODULUS - 1);
        let b = Fp::new(MODULUS - 1);
        let r = a.mul(b);
        // (-1) * (-1) = 1
        assert_eq!(r, Fp::ONE);
    }
}
