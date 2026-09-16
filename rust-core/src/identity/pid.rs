//! Ephemeral session pseudonym: PID_D = SHAKE256(0x03 || s_D || "PID" || counter)
//!
//! Privacy model (MODERATE ANONYMITY — documented per spec requirement):
//! PID rotates per session/counter, so a bare PID does not reveal the
//! permanent DroneID to D2 or to a network observer. However, D2 *does*
//! learn other stable per-device values during authentication (the
//! public keys `PK_KEM_D1`/`PK_Dil_D1`, and the commitment `comm_PK_D1`
//! derived from them, both delivered in cleartext inside `CredResp`).
//! Because those values are stable across sessions, an observer who sees
//! two sessions can link them by comparing `comm_PK_D1`, even without
//! ever learning the permanent `DroneID`. This is a MODERATE anonymity
//! model, not unlinkable anonymity, and must never be described as the
//! latter (see docs/security-assumptions.md).

use crate::crypto::domains::SEED_DOMAIN_PID;
use crate::crypto::kdf::shake256_bytes;

pub fn derive_pid(seed: &[u8], counter: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(1 + seed.len() + 3 + 8);
    input.push(0x03);
    input.extend_from_slice(seed);
    input.extend_from_slice(b"PID");
    input.extend_from_slice(&counter.to_le_bytes());
    shake256_bytes(SEED_DOMAIN_PID, &input, 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_with_counter() {
        let seed = [1u8; 32];
        let pid1 = derive_pid(&seed, 1);
        let pid2 = derive_pid(&seed, 2);
        assert_ne!(pid1, pid2);
    }

    #[test]
    fn differs_across_devices() {
        let pid_a = derive_pid(&[1u8; 32], 1);
        let pid_b = derive_pid(&[2u8; 32], 1);
        assert_ne!(pid_a, pid_b);
    }
}
