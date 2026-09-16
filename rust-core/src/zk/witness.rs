//! Private witness for the ZK membership relation.

use crate::crypto::field::Fp;
use crate::identity::metadata::MembershipMetadata;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZkWitness {
    pub leaf: Fp,
    pub siblings: Vec<Fp>,
    pub path_indices: Vec<u8>,
    pub pk_kem: Vec<u8>,
    pub pk_dil: Vec<u8>,
    pub metadata: MembershipMetadata,
    pub rho: [u8; 32],
}
