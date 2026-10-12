//! Wire messages for R2/R3, M1-M8 and K1-K3. Everything signed exposes
//! `signing_bytes()` built with `canon::Canon` (typed, length-prefixed,
//! domain-separated). The serde derives are for transport/UI only and are
//! never what is signed.

use crate::merkle::tree::MerkleWitness;
use crate::protocol::canon::Canon;
use crate::protocol::credentials::SignedCredential;
use crate::protocol::envelope::SecureEnvelope;
use crate::zk::MembershipProof;
use crate::zkhash::{Digest, Limbs};
use serde::{Deserialize, Serialize};

// ------------------------------------------------------------- R2/R3 ---

/// Enrollment request (R2). `pop_sig` proves possession of the ML-DSA
/// key; `pop_mac` proves the sender holds the PUF whose CRP the GCS
/// holds (key = HKDF(PUF response)), over the same canonical body and a
/// fresh GCS nonce.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentBody {
    pub drone_id: String,
    pub group_id: String,
    pub pk_kem: Vec<u8>,
    pub pk_dil: Vec<u8>,
    pub comm_pk: Limbs,
    pub rho: [u32; 8],
    pub metadata: crate::identity::metadata::MembershipMetadata,
    pub pid_batch: Vec<Vec<u8>>,
    pub gcs_nonce: Vec<u8>,
    pub ts: u64,
}

impl EnrollmentBody {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("ENROLL");
        c.str(&self.drone_id)
            .str(&self.group_id)
            .bytes(&self.pk_kem)
            .bytes(&self.pk_dil)
            .limbs(&self.comm_pk)
            .limbs(&self.rho)
            .str(&self.metadata.role)
            .u64(self.metadata.issued_at_unix)
            .u64(self.pid_batch.len() as u64);
        for p in &self.pid_batch {
            c.bytes(p);
        }
        c.bytes(&self.gcs_nonce).u64(self.ts);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub body: EnrollmentBody,
    pub pop_sig: Vec<u8>,
    pub pop_mac: Vec<u8>,
    /// Challenge used for pop_mac (one of the CRPs provisioned at R1).
    pub pop_challenge: Vec<u8>,
}

/// Enrollment response (R3): everything the drone stores.
#[derive(Clone, Debug)]
pub struct EnrollmentResponse {
    pub credential: SignedCredential,
    pub trust_anchor: Vec<u8>,
    pub gcs_kem_pk: Vec<u8>,
    pub witness: MerkleWitness,
    pub root: Digest,
    pub version: u64,
    pub leaf_index: usize,
}

// ---------------------------------------------------------------- M1 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommReq {
    pub g: String,
    pub pid1: Vec<u8>,
    pub ts1: u64,
    pub n1: Vec<u8>,
}

// ---------------------------------------------------------------- M2 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredReqBody {
    pub g: String,
    pub pid1: Vec<u8>,
    pub n1: Vec<u8>,
    pub ts1: u64,
    pub d2_cred_id: [u8; 16],
    pub ts2: u64,
    pub n2: Vec<u8>,
}

impl CredReqBody {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("M2");
        c.str(&self.g)
            .bytes(&self.pid1)
            .bytes(&self.n1)
            .u64(self.ts1)
            .bytes(&self.d2_cred_id)
            .u64(self.ts2)
            .bytes(&self.n2);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredReqPlain {
    pub body: CredReqBody,
    pub sig2: Vec<u8>,
}
pub type CredReqWire = SecureEnvelope;

// ---------------------------------------------------------------- M3 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredRespBody {
    pub session_id: String,
    pub group_id: String,
    pub pid1: Vec<u8>,
    pub d2_cred_id: [u8; 16],
    pub n2: Vec<u8>,
    pub cred_d1: SignedCredential,
    pub r_g: Digest,
    pub v_g: u64,
    /// GCS-managed PUF challenge for D1, single use.
    pub c_puf: Vec<u8>,
    pub ts3: u64,
    pub n3: Vec<u8>,
    pub expires_ms: u64,
}

impl CredRespBody {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("M3");
        c.str(&self.session_id)
            .str(&self.group_id)
            .bytes(&self.pid1)
            .bytes(&self.d2_cred_id)
            .bytes(&self.n2)
            .bytes(&self.cred_d1.body.signing_bytes())
            .bytes(&self.cred_d1.sig)
            .limbs(&self.r_g.0)
            .u64(self.v_g)
            .bytes(&self.c_puf)
            .u64(self.ts3)
            .bytes(&self.n3)
            .u64(self.expires_ms);
        c.into_vec()
    }
}

/// GCS-signed M3 body. D2 verifies `sig3` against the trust anchor and
/// forwards the whole object to D1 in M4, so D1 can verify the same
/// signature (this is how D1 learns R_G/V_G/C_PUF from the GCS, not
/// from D2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCredResp {
    pub body: CredRespBody,
    pub sig3: Vec<u8>,
}
pub type CredRespWire = SecureEnvelope;

// ---------------------------------------------------------------- M4 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengePayload {
    pub session_id: String,
    pub group_id: String,
    pub pid1: Vec<u8>,
    pub c_puf: Vec<u8>,
    pub n2: Vec<u8>,
    pub ts4: u64,
    pub d2_cred_id: [u8; 16],
}

impl ChallengePayload {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("M4");
        c.str(&self.session_id)
            .str(&self.group_id)
            .bytes(&self.pid1)
            .bytes(&self.c_puf)
            .bytes(&self.n2)
            .u64(self.ts4)
            .bytes(&self.d2_cred_id);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeMsg {
    pub payload: ChallengePayload,
    pub sig4: Vec<u8>,
    /// D2's GCS-issued credential: D1 takes D2's ML-DSA key from HERE
    /// after verifying it against its trust anchor (never from sig4's
    /// sender).
    pub d2_cred: SignedCredential,
    pub m3: SignedCredResp,
}

// ---------------------------------------------------------------- M5 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub session_id: String,
    pub pid1: Vec<u8>,
    pub cred_id_d1: [u8; 16],
    pub comm_pk_d1: Limbs,
    pub proof: MembershipProof,
    pub mac1: Vec<u8>,
    pub sig1: Vec<u8>,
    pub ts5: u64,
    pub n5: Vec<u8>,
}

// ---------------------------------------------------------------- M6 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PufVerifyReqBody {
    pub session_id: String,
    pub pid1: Vec<u8>,
    pub d2_cred_id: [u8; 16],
    pub g: String,
    pub n1: Vec<u8>,
    pub ts1: u64,
    pub n2: Vec<u8>,
    pub ts4: u64,
    pub c_puf: Vec<u8>,
    pub comm_pk: Limbs,
    pub mac1: Vec<u8>,
    pub ts6: u64,
    pub n6: Vec<u8>,
}

impl PufVerifyReqBody {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("M6");
        c.str(&self.session_id)
            .bytes(&self.pid1)
            .bytes(&self.d2_cred_id)
            .str(&self.g)
            .bytes(&self.n1)
            .u64(self.ts1)
            .bytes(&self.n2)
            .u64(self.ts4)
            .bytes(&self.c_puf)
            .limbs(&self.comm_pk)
            .bytes(&self.mac1)
            .u64(self.ts6)
            .bytes(&self.n6);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PufVerifyReqPlain {
    pub body: PufVerifyReqBody,
    pub sig6: Vec<u8>,
}
pub type PufVerifyReqWire = SecureEnvelope;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PufVerifyResult {
    Valid,
    Invalid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PufVerifyRespBody {
    pub session_id: String,
    pub pid1: Vec<u8>,
    pub result: PufVerifyResult,
    pub reason_code: String,
    pub current_r_g: Digest,
    pub current_v_g: u64,
    pub session_ctx: Limbs,
    pub ts7: u64,
    pub n7: Vec<u8>,
}

impl PufVerifyRespBody {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("M6R");
        c.str(&self.session_id)
            .bytes(&self.pid1)
            .u64(if self.result == PufVerifyResult::Valid { 1 } else { 0 })
            .str(&self.reason_code)
            .limbs(&self.current_r_g.0)
            .u64(self.current_v_g)
            .limbs(&self.session_ctx)
            .u64(self.ts7)
            .bytes(&self.n7);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PufVerifyResp {
    pub body: PufVerifyRespBody,
    pub sig7: Vec<u8>,
}

// ---------------------------------------------------------------- M7 ---

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroTrustDecision {
    Allow,
    Deny,
}

/// Outcome of D2's verification (M7). Authentication results are
/// separate from the authorization decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationReport {
    pub freshness_ok: bool,
    pub credential_ok: bool,
    pub commitment_ok: bool,
    pub zk_membership_ok: bool,
    pub signature_ok: bool,
    pub puf_ok: bool,
    pub root_version_ok: bool,
    pub session_binding_ok: bool,
    /// All cryptographic/authentication checks passed.
    pub authenticated: bool,
    /// Zero Trust authorization decision (policy), separate from the above.
    pub zero_trust: ZeroTrustDecision,
    pub reason_code: String,
    pub session_ctx: Limbs,
}

impl VerificationReport {
    pub fn denied(reason: &str) -> Self {
        VerificationReport {
            freshness_ok: false,
            credential_ok: false,
            commitment_ok: false,
            zk_membership_ok: false,
            signature_ok: false,
            puf_ok: false,
            root_version_ok: false,
            session_binding_ok: false,
            authenticated: false,
            zero_trust: ZeroTrustDecision::Deny,
            reason_code: reason.to_string(),
            session_ctx: [0; 11],
        }
    }
}

// ---------------------------------------------------------------- M8 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthResultPayload {
    pub session_id: String,
    pub session_ctx: Limbs,
    pub result: ZeroTrustDecision,
    pub reason_code: String,
    pub d2_cred_id: [u8; 16],
    pub ts8: u64,
    pub n8: Vec<u8>,
}

impl AuthResultPayload {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("M8");
        c.str(&self.session_id)
            .limbs(&self.session_ctx)
            .u64(if self.result == ZeroTrustDecision::Allow { 1 } else { 0 })
            .str(&self.reason_code)
            .bytes(&self.d2_cred_id)
            .u64(self.ts8)
            .bytes(&self.n8);
        c.into_vec()
    }
}

/// M8 carries NO key: D1 verifies `sig8` with the ML-DSA key of the
/// D2 credential it already verified against the trust anchor in M4.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthResultMsg {
    pub payload: AuthResultPayload,
    pub sig8: Vec<u8>,
}

/// D1's signed confirmation that it received and verified M8 (sent to
/// the GCS inside K1; the GCS requires it).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionConfirmBody {
    pub session_id: String,
    pub session_ctx: Limbs,
    pub result_seen: ZeroTrustDecision,
    pub d1_cred_id: [u8; 16],
    pub ts: u64,
    pub n: Vec<u8>,
}

impl SessionConfirmBody {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("SESSION-CONFIRM");
        c.str(&self.session_id)
            .limbs(&self.session_ctx)
            .u64(if self.result_seen == ZeroTrustDecision::Allow { 1 } else { 0 })
            .bytes(&self.d1_cred_id)
            .u64(self.ts)
            .bytes(&self.n);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedSessionConfirm {
    pub body: SessionConfirmBody,
    pub sig: Vec<u8>,
}

// ---------------------------------------------------------------- K1 ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupKeyReqBody {
    pub session_id: String,
    pub mission_id: String,
    pub d2_cred_id: [u8; 16],
    pub session_ctx: Limbs,
    /// D2's own decision for this session (must be ALLOW).
    pub d2_result: ZeroTrustDecision,
    pub d1_confirm: SignedSessionConfirm,
    pub ts6: u64,
    pub n6: Vec<u8>,
}

impl GroupKeyReqBody {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("K1");
        c.str(&self.session_id)
            .str(&self.mission_id)
            .bytes(&self.d2_cred_id)
            .limbs(&self.session_ctx)
            .u64(if self.d2_result == ZeroTrustDecision::Allow { 1 } else { 0 })
            .bytes(&self.d1_confirm.body.signing_bytes())
            .bytes(&self.d1_confirm.sig)
            .u64(self.ts6)
            .bytes(&self.n6);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupKeyReq {
    pub body: GroupKeyReqBody,
    pub sig6: Vec<u8>,
}
pub type GroupKeyReqWire = SecureEnvelope;

/// What the GCS seals for each recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupKeyInner {
    pub k_g_m: Vec<u8>,
    pub group_id: String,
    pub mission_id: String,
    pub session_id: String,
    pub session_ctx: Limbs,
    pub recipient_cred_id: [u8; 16],
    pub key_epoch: u64,
    pub ts: u64,
    pub n6: Vec<u8>,
    pub n7: Vec<u8>,
}

impl GroupKeyInner {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("K-INNER");
        c.bytes(&self.k_g_m)
            .str(&self.group_id)
            .str(&self.mission_id)
            .str(&self.session_id)
            .limbs(&self.session_ctx)
            .bytes(&self.recipient_cred_id)
            .u64(self.key_epoch)
            .u64(self.ts)
            .bytes(&self.n6)
            .bytes(&self.n7);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedGroupKeyInner {
    pub inner: GroupKeyInner,
    pub gcs_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupKeyResp {
    pub session_id: String,
    pub ct_d1: SecureEnvelope,
    pub ct_d2: SecureEnvelope,
    pub ts7: u64,
    pub n7: Vec<u8>,
}
pub type GroupKeyRespWire = SecureEnvelope;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyDeliveryPayload {
    pub session_id: String,
    pub ct_d1: SecureEnvelope,
    pub ts8: u64,
    pub n8: Vec<u8>,
}

impl KeyDeliveryPayload {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canon::new("K2");
        c.str(&self.session_id)
            .bytes(&self.ct_d1.kem_ciphertext)
            .bytes(&self.ct_d1.sealed.ciphertext)
            .u64(self.ts8)
            .bytes(&self.n8);
        c.into_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyDeliveryMsg {
    pub payload: KeyDeliveryPayload,
    pub sig8: Vec<u8>,
}

// -------------------------------------------------- secure messaging ---

/// Application message header uses only a session-derived channel tag
/// and a direction bit — never a permanent DroneID or a PID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecureAppMessage {
    pub channel_tag: [u8; 16],
    pub direction: u8,
    pub header_seq: u32,
    pub header_ts: u64,
    pub sealed: crate::crypto::aead::SealedMessage,
}

impl SecureAppMessage {
    pub fn associated_data(&self) -> Vec<u8> {
        let mut c = Canon::new("APPMSG");
        c.bytes(&self.channel_tag)
            .u64(self.direction as u64)
            .u32(self.header_seq)
            .u64(self.header_ts);
        c.into_vec()
    }
}
