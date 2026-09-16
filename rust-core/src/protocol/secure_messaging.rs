//! Application-layer secure messaging: `plaintext -> AEAD -> ciphertext
//! -> transport abstraction` (spec's K4).

use crate::crypto::aead::{self, AeadKey};
use crate::protocol::messages::SecureAppMessage;
use crate::transport::TransportProvider;

#[derive(thiserror::Error, Debug)]
pub enum SecureMessagingError {
    #[error(transparent)]
    Aead(#[from] aead::AeadError),
    #[error(transparent)]
    Transport(#[from] anyhow::Error),
}

pub fn send_message(
    key: &AeadKey,
    transport: &dyn TransportProvider,
    seq: u32,
    src_pid: &[u8],
    dst_pid: &[u8],
    plaintext: &[u8],
) -> Result<(SecureAppMessage, Vec<u8>), SecureMessagingError> {
    let header_ts = crate::protocol::events::now_unix_ms();
    // Associated data must be bound BEFORE sealing (it's covered by the
    // AEAD tag), so we compute it from a header built with a
    // placeholder sealed value, then re-seal with the real AD — done in
    // two passes here for clarity, since seq/ts/pids are all known
    // upfront and don't depend on the ciphertext itself.
    let header_seq = seq;
    let ad = crate::crypto::kdf::length_prefixed_concat(&[
        &header_seq.to_le_bytes(),
        &header_ts.to_le_bytes(),
        src_pid,
        dst_pid,
    ]);
    let sealed = aead::seal(key, seq, &ad, plaintext);
    let msg = SecureAppMessage {
        header_seq,
        header_ts,
        src_pid: src_pid.to_vec(),
        dst_pid: dst_pid.to_vec(),
        sealed,
    };
    let ciphertext_bytes = serde_json::to_vec(&msg.sealed).map_err(anyhow::Error::from)?;
    let wire = transport.encode(&ciphertext_bytes)?;
    Ok((msg, wire))
}

pub fn receive_message(
    key: &AeadKey,
    msg: &SecureAppMessage,
    last_seen_seq: u32,
) -> Result<Vec<u8>, SecureMessagingError> {
    let ad = msg.associated_data();
    Ok(aead::open(key, &ad, &msg.sealed, last_seen_seq)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::PassthroughTransport;

    #[test]
    fn round_trip_over_passthrough_transport() {
        let key = AeadKey([7u8; 32]);
        let transport = PassthroughTransport;
        let (msg, _wire) = send_message(&key, &transport, 1, b"pid-src", b"pid-dst", b"hello D2").unwrap();
        let opened = receive_message(&key, &msg, 0).unwrap();
        assert_eq!(opened, b"hello D2");
    }

    #[test]
    fn replay_of_same_sequence_number_rejected() {
        let key = AeadKey([7u8; 32]);
        let transport = PassthroughTransport;
        let (msg, _wire) = send_message(&key, &transport, 3, b"a", b"b", b"msg").unwrap();
        assert!(receive_message(&key, &msg, 3).is_err());
    }

    #[test]
    fn tampered_header_fields_break_authentication() {
        let key = AeadKey([7u8; 32]);
        let transport = PassthroughTransport;
        let (mut msg, _wire) = send_message(&key, &transport, 1, b"pid-src", b"pid-dst", b"hello").unwrap();
        msg.dst_pid = b"attacker-pid".to_vec(); // AD tampering
        assert!(receive_message(&key, &msg, 0).is_err());
    }
}
