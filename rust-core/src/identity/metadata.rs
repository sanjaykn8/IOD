//! Public, non-sensitive membership metadata attached to a drone's leaf.

use crate::crypto::canonical::{encode_bytes, encode_record, encode_u64};
use crate::crypto::field::Fp;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipMetadata {
    pub role: String,
    pub issued_at_unix: u64,
}

impl MembershipMetadata {
    pub fn to_field_vec(&self) -> Vec<Fp> {
        encode_record(&[
            encode_bytes(self.role.as_bytes()),
            vec![encode_u64(self.issued_at_unix)],
        ])
    }
}
