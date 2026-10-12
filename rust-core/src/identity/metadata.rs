//! Public membership metadata attached to a drone's leaf. Because the
//! metadata is revealed to the peer (credential in M3), it is treated as
//! PUBLIC; the circuit binds its digest into the leaf so it cannot be
//! swapped.

use crate::zkhash::{shake_limbs, Limbs};
use serde::{Deserialize, Serialize};

pub const DOMAIN_META: &[u8] = b"IOD/v2/METADATA";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipMetadata {
    pub role: String,
    pub issued_at_unix: u64,
}

impl MembershipMetadata {
    pub fn digest(&self) -> Limbs {
        shake_limbs(DOMAIN_META, &[self.role.as_bytes(), &self.issued_at_unix.to_le_bytes()])
    }
}
