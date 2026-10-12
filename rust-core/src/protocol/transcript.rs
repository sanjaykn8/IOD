//! Session context digest, T_base (PUF MAC input) and the auth
//! transcript T (ML-DSA signature input). All use `canon::Canon`.

use crate::crypto::domains::{TRANSCRIPT_AUTH, TRANSCRIPT_BASE_PUF};
use crate::crypto::kdf::shake256_transcript;
use crate::protocol::canon::Canon;
use crate::zkhash::{shake_limbs, Digest, Limbs};

pub const DOMAIN_SESSION_CTX: &[u8] = b"IOD/v2/SESSION-CTX";

/// Everything both drones and the GCS agree on for one session.
pub struct SessionCtxInputs<'a> {
    pub protocol_version: u32,
    pub session_id: &'a str,
    pub group_id: &'a str,
    pub v_g: u64,
    pub r_g: &'a Digest,
    pub pid1: &'a [u8],
    pub d2_cred_id: &'a [u8; 16],
    pub n1: &'a [u8],
    pub ts1: u64,
    pub n2: &'a [u8],
    pub ts4: u64,
    pub c_puf: &'a [u8],
}

pub fn session_ctx_bytes(i: &SessionCtxInputs) -> Vec<u8> {
    let mut c = Canon::new("SESSION-CTX");
    c.u32(i.protocol_version)
        .str(i.session_id)
        .str(i.group_id)
        .u64(i.v_g)
        .limbs(&i.r_g.0)
        .bytes(i.pid1)
        .bytes(i.d2_cred_id)
        .bytes(i.n1)
        .u64(i.ts1)
        .bytes(i.n2)
        .u64(i.ts4)
        .bytes(i.c_puf);
    c.into_vec()
}

/// `session_context_digest`: public input of the ZK statement.
pub fn session_ctx_digest(i: &SessionCtxInputs) -> Limbs {
    shake_limbs(DOMAIN_SESSION_CTX, &[&session_ctx_bytes(i)])
}

pub fn build_t_base(session_ctx: &Limbs, comm_pk: &Limbs) -> [u8; 32] {
    let sc = crate::zkhash::limbs_to_bytes(session_ctx);
    let cm = crate::zkhash::limbs_to_bytes(comm_pk);
    shake256_transcript(TRANSCRIPT_BASE_PUF, &[&sc, &cm])
}

pub fn build_auth_transcript(
    session_ctx: &Limbs,
    comm_pk: &Limbs,
    cred_id_d1: &[u8; 16],
    proof_digest: &[u8; 32],
) -> [u8; 32] {
    let sc = crate::zkhash::limbs_to_bytes(session_ctx);
    let cm = crate::zkhash::limbs_to_bytes(comm_pk);
    shake256_transcript(TRANSCRIPT_AUTH, &[&sc, &cm, cred_id_d1, proof_digest])
}

pub fn proof_digest(proof_bytes: &[u8]) -> [u8; 32] {
    let d = crate::crypto::kdf::shake256_bytes(b"IOD-ZKPROOF-DIGEST-v2", proof_bytes, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(v: u64, n1: &'a [u8], cid: &'a [u8; 16], r: &'a Digest) -> SessionCtxInputs<'a> {
        SessionCtxInputs {
            protocol_version: 2, session_id: "s", group_id: "g", v_g: v, r_g: r, pid1: b"p",
            d2_cred_id: cid, n1, ts1: 1, n2: b"n2", ts4: 2, c_puf: b"c",
        }
    }

    #[test]
    fn digest_binds_every_field() {
        let r = Digest([1; 8]);
        let cid = [3u8; 16];
        let base = session_ctx_digest(&inputs(1, b"n1", &cid, &r));
        assert_eq!(base, session_ctx_digest(&inputs(1, b"n1", &cid, &r)));
        assert_ne!(base, session_ctx_digest(&inputs(2, b"n1", &cid, &r)));
        assert_ne!(base, session_ctx_digest(&inputs(1, b"nX", &cid, &r)));
        assert_ne!(base, session_ctx_digest(&inputs(1, b"n1", &[4u8; 16], &r)));
        assert_ne!(base, session_ctx_digest(&inputs(1, b"n1", &cid, &Digest([2; 8]))));
    }

    #[test]
    fn t_base_and_transcript_depend_on_session_and_comm() {
        let a = [1u32; 11];
        let b = [2u32; 11];
        assert_ne!(build_t_base(&a, &b), build_t_base(&b, &b));
        assert_ne!(build_t_base(&a, &a), build_t_base(&a, &b));
        let cid = [0u8; 16];
        assert_ne!(
            build_auth_transcript(&a, &b, &cid, &[0u8; 32]),
            build_auth_transcript(&a, &b, &cid, &[1u8; 32])
        );
    }
}
