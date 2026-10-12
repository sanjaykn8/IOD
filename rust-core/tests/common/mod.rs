#![allow(dead_code)]
use iod_core::identity::metadata::MembershipMetadata;
use iod_core::protocol::auth_flow::*;
use iod_core::protocol::entities::{DroneState, GcsState};
use iod_core::protocol::messages::*;
use iod_core::protocol::registration::{refresh_drone_cache, register_drone};
use iod_core::zero_trust::DefaultPolicy;

pub const DEPTH: usize = 4;

pub fn md() -> MembershipMetadata {
    MembershipMetadata { role: "recon".into(), issued_at_unix: 1_700_000_000 }
}

pub fn setup() -> (GcsState, DroneState, DroneState) {
    let mut gcs = GcsState::new();
    let mut d1 = DroneState::new("drone-1", [11u8; 32]);
    let mut d2 = DroneState::new("drone-2", [22u8; 32]);
    register_drone(&mut gcs, &mut d1, "alpha", md(), DEPTH).unwrap();
    register_drone(&mut gcs, &mut d2, "alpha", md(), DEPTH).unwrap();
    refresh_drone_cache(&gcs, &mut d1);
    refresh_drone_cache(&gcs, &mut d2);
    (gcs, d1, d2)
}

pub struct Stage {
    pub comm_req: CommReq,
    pub m2: M2Output,
    pub m3_wire: CredRespWire,
    pub d2s: D2Session,
    pub challenge: ChallengeMsg,
    pub d1s: D1Session,
    pub proof: ProofBundle,
}

pub fn up_to_m5(gcs: &mut GcsState, d1: &mut DroneState, d2: &DroneState) -> Stage {
    let comm_req = m1_comm_req(d1).unwrap();
    let m2 = m2_cred_req(d2, &comm_req).unwrap();
    let acc = gcs_receive_m2(gcs, &m2.wire).unwrap();
    let (m3_wire, _) = gcs_m3_cred_resp(gcs, &acc).unwrap();
    let mut d2s = d2_receive_m3(d2, &m3_wire, &comm_req, &m2).unwrap();
    let challenge = m4_challenge(d2, &mut d2s).unwrap();
    let d1s = d1_verify_challenge(d1, &challenge, &comm_req).unwrap();
    let proof = m5_proof_bundle(d1, &d1s).unwrap();
    Stage { comm_req, m2, m3_wire, d2s, challenge, d1s, proof }
}

pub fn m6_m7(gcs: &mut GcsState, d2: &DroneState, st: &Stage, proof: &ProofBundle) -> (PufVerifyResp, VerificationReport) {
    let w = m6_puf_verify_req(d2, &st.d2s, proof).unwrap();
    let resp = gcs_m6_verify(gcs, &w).unwrap();
    let rep = m7_verify_and_decide(d2, &st.d2s, proof, &resp, &DefaultPolicy::default()).report;
    (resp, rep)
}
