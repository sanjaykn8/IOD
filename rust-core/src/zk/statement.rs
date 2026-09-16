//! Public statement for the ZK membership relation.

use crate::crypto::canonical::encode_u64;
use crate::crypto::field::Fp;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZkStatement {
    pub g: Fp,
    pub r_g: Fp,
    pub v_g: u64,
    pub comm_pk: Fp,
}

impl ZkStatement {
    pub fn v_g_field(&self) -> Fp {
        encode_u64(self.v_g)
    }
}
