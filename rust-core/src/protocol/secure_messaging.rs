//! K4: application messaging under the directional session keys.
//! Headers carry only a session-derived channel tag, a direction bit, a
//! sequence number and a timestamp -- never a permanent DroneID or PID.

use crate::crypto::aead::{self, AeadKey};
use crate::protocol::messages::SecureAppMessage;
use crate::transport::TransportProvider;

#[derive(thiserror::Error, Debug)]
pub enum SecureMessagingError {
    #[error(transparent)]
    Aead(#[from] aead::AeadError),
    #[error(transparent)]
    Transport(#[from] anyhow::Error),
    #[error("message is not for this channel/direction")]
    WrongChannel,
}

pub fn send_message(
    key: &AeadKey,
    transport: &dyn TransportProvider,
    channel_tag: [u8; 16],
    direction: u8,
    seq: u32,
    plaintext: &[u8],
) -> Result<(SecureAppMessage, Vec<u8>), SecureMessagingError> {
    let mut msg = SecureAppMessage {
        channel_tag,
        direction,
        header_seq: seq,
        header_ts: crate::protocol::events::now_unix_ms(),
        sealed: aead::SealedMessage { seq, nonce: [0; aead::NONCE_LEN], ciphertext: vec![] },
    };
    msg.sealed = aead::seal(key, seq, &msg.associated_data(), plaintext);
    let bytes = serde_json::to_vec(&msg.sealed).map_err(anyhow::Error::from)?;
    let wire = transport.encode(&bytes)?;
    Ok((msg, wire))
}

pub fn receive_message(
    key: &AeadKey,
    channel_tag: [u8; 16],
    expected_direction: u8,
    msg: &SecureAppMessage,
    last_seen_seq: u32,
) -> Result<Vec<u8>, SecureMessagingError> {
    if msg.channel_tag != channel_tag || msg.direction != expected_direction || msg.header_seq != msg.sealed.seq {
        return Err(SecureMessagingError::WrongChannel);
    }
    Ok(aead::open(key, &msg.associated_data(), &msg.sealed, last_seen_seq)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::PassthroughTransport;

    #[test]
    fn round_trip_and_directional_binding() {
        let key = AeadKey([7u8; 32]);
        let other = AeadKey([8u8; 32]);
        let tag = [1u8; 16];
        let (msg, _) = send_message(&key, &PassthroughTransport, tag, 0, 1, b"hello D2").unwrap();
        assert_eq!(receive_message(&key, tag, 0, &msg, 0).unwrap(), b"hello D2");
        assert!(receive_message(&other, tag, 0, &msg, 0).is_err(), "other direction key must fail");
        assert!(matches!(receive_message(&key, tag, 1, &msg, 0), Err(SecureMessagingError::WrongChannel)));
        assert!(matches!(receive_message(&key, [2u8; 16], 0, &msg, 0), Err(SecureMessagingError::WrongChannel)));
    }

    #[test]
    fn replay_and_tamper_rejected() {
        let key = AeadKey([7u8; 32]);
        let tag = [1u8; 16];
        let (msg, _) = send_message(&key, &PassthroughTransport, tag, 0, 3, b"m").unwrap();
        assert!(receive_message(&key, tag, 0, &msg, 3).is_err());
        let mut t = msg.clone();
        t.sealed.ciphertext[0] ^= 1;
        assert!(receive_message(&key, tag, 0, &t, 0).is_err());
        let mut h = msg.clone();
        h.header_ts += 1;
        assert!(receive_message(&key, tag, 0, &h, 0).is_err(), "header is authenticated as AAD");
    }

    #[test]
    fn headers_contain_no_identity() {
        let (m, _) = send_message(&AeadKey([1; 32]), &PassthroughTransport, [9; 16], 0, 1, b"x").unwrap();
        let j = serde_json::to_string(&m).unwrap();
        assert!(!j.contains("drone") && !j.contains("pid"));
    }
}
