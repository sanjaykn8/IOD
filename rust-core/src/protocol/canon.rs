//! Canonical, unambiguous byte encoding for everything that is signed,
//! MAC'd or hashed into a transcript (spec: docs/zk-specification.md §2).
//!
//! Rules: every item is a typed field. Integers are fixed-width
//! little-endian (u64). Byte strings and text are length-prefixed with a
//! u64 LE. A message starts with a domain-separation label (itself
//! length-prefixed) and a field count. There is no JSON, no delimiter, no
//! optional field that can be confused with an absent one (absent items
//! are encoded as an empty byte string with an explicit tag byte).

#[derive(Default, Clone)]
pub struct Canon(Vec<u8>);

impl Canon {
    pub fn new(domain: &str) -> Self {
        let mut c = Canon(Vec::new());
        c.bytes(b"IOD-CANON-v2");
        c.bytes(domain.as_bytes());
        c
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.u64(v as u64)
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&(b.len() as u64).to_le_bytes());
        self.0.extend_from_slice(b);
        self
    }
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }
    pub fn limbs(&mut self, l: &[u32]) -> &mut Self {
        self.u64(l.len() as u64);
        for x in l {
            self.0.extend_from_slice(&x.to_le_bytes());
        }
        self
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_do_not_collide() {
        let mut a = Canon::new("t");
        a.bytes(b"AB").bytes(b"C");
        let mut b = Canon::new("t");
        b.bytes(b"A").bytes(b"BC");
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn domain_separated() {
        let mut a = Canon::new("x");
        a.u64(1);
        let mut b = Canon::new("y");
        b.u64(1);
        assert_ne!(a.as_slice(), b.as_slice());
    }
}
