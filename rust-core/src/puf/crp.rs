//! Challenge-response PUF interface: `PUF(D, C) -> r`.
//!
//! GCS stores, per drone, a Challenge-Response Pair reference
//! `(C_default, r_ref)` captured once (e.g. at registration time, over a
//! channel the device is trusted on). Later, during authentication, the
//! *drone* recomputes `r1 = PUF(D1, C_PUF)` locally and uses it to derive
//! a MAC key; it never transmits `r1` itself (see `protocol` module —
//! only `mac1` travels over the network). GCS, holding `r_ref`,
//! recomputes the same MAC key and checks the MAC, which is exactly the
//! "PUF response -> KDF -> authentication proof/MAC" chain the
//! specification requires, and it means a network observer (including
//! D2) never sees the raw PUF response.

use super::sram_puf::PUF_BYTES;
use crate::crypto::kdf::shake256_bytes;

pub fn derive_response(golden_pattern: &[u8; PUF_BYTES], challenge: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(PUF_BYTES + challenge.len());
    input.extend_from_slice(golden_pattern);
    input.extend_from_slice(challenge);
    let out = shake256_bytes(b"IOD-PUF-CRP-v1", &input, 32);
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// GCS-side reference record for one (drone, challenge) pair.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CrpReference {
    pub challenge: Vec<u8>,
    pub reference_response: [u8; 32],
}
