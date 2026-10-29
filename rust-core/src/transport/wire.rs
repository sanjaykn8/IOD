//! AppWire v1: the complete binary wire form of a `SecureAppMessage`
//! (docs/stego-implementation-note.md §1.1). Strict, bounded, big-endian.
//! Contains no DroneID / PID.

use crate::crypto::aead::{SealedMessage, NONCE_LEN};
use crate::protocol::messages::SecureAppMessage;
use crate::transport::error::{stage, StegoError};

pub const WIRE_VERSION: u8 = 1;
pub const WIRE_HEADER_LEN: usize = 50;

/// Strictly parsed wire (carrier for the reconstructed message).
pub struct Parsed {
    pub msg: SecureAppMessage,
}

pub fn encode_app_wire(msg: &SecureAppMessage) -> Vec<u8> {
    let mut v = Vec::with_capacity(WIRE_HEADER_LEN + msg.sealed.ciphertext.len());
    v.push(WIRE_VERSION);
    v.extend_from_slice(&msg.channel_tag);
    v.push(msg.direction);
    v.extend_from_slice(&msg.header_seq.to_be_bytes());
    v.extend_from_slice(&msg.header_ts.to_be_bytes());
    v.extend_from_slice(&msg.sealed.seq.to_be_bytes());
    v.extend_from_slice(&msg.sealed.nonce);
    v.extend_from_slice(&(msg.sealed.ciphertext.len() as u32).to_be_bytes());
    v.extend_from_slice(&msg.sealed.ciphertext);
    v
}

fn bad(code: &str, msg: &str) -> StegoError {
    StegoError::new(code, stage::VERIFY, 422, msg)
}

pub fn decode_app_wire(b: &[u8], max_ct: usize) -> Result<SecureAppMessage, StegoError> {
    if b.len() < WIRE_HEADER_LEN {
        return Err(bad("WIRE_MALFORMED", "wire shorter than header"));
    }
    if b[0] != WIRE_VERSION {
        return Err(bad("WIRE_VERSION_UNSUPPORTED", "unsupported AppWire version"));
    }
    let mut channel_tag = [0u8; 16];
    channel_tag.copy_from_slice(&b[1..17]);
    let direction = b[17];
    let header_seq = u32::from_be_bytes(b[18..22].try_into().unwrap());
    let header_ts = u64::from_be_bytes(b[22..30].try_into().unwrap());
    let sealed_seq = u32::from_be_bytes(b[30..34].try_into().unwrap());
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&b[34..34 + NONCE_LEN]);
    let ct_len = u32::from_be_bytes(b[46..50].try_into().unwrap()) as usize;
    if ct_len > max_ct {
        return Err(bad("WIRE_MALFORMED", "ciphertext length exceeds limit"));
    }
    if b.len() != WIRE_HEADER_LEN + ct_len {
        return Err(bad("WIRE_MALFORMED", "ciphertext length does not match wire length"));
    }
    if header_seq != sealed_seq {
        return Err(bad("WIRE_MALFORMED", "header and sealed sequence differ"));
    }
    Ok(SecureAppMessage {
        channel_tag,
        direction,
        header_seq,
        header_ts,
        sealed: SealedMessage { seq: sealed_seq, nonce, ciphertext: b[WIRE_HEADER_LEN..].to_vec() },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(ct: Vec<u8>) -> SecureAppMessage {
        SecureAppMessage {
            channel_tag: [3; 16],
            direction: 1,
            header_seq: 7,
            header_ts: 1_700_000_000_123,
            sealed: SealedMessage { seq: 7, nonce: [9; NONCE_LEN], ciphertext: ct },
        }
    }
    #[test]
    fn round_trip_including_non_utf8() {
        let m = sample(vec![0xff, 0xfe, 0x00, 0x80, 1, 2, 3]);
        let w = encode_app_wire(&m);
        let d = decode_app_wire(&w, 1 << 16).unwrap();
        assert_eq!(d.channel_tag, m.channel_tag);
        assert_eq!(d.direction, 1);
        assert_eq!(d.header_ts, m.header_ts);
        assert_eq!(d.sealed.ciphertext, m.sealed.ciphertext);
        assert_eq!(d.associated_data(), m.associated_data());
    }
    #[test]
    fn strict_rejections() {
        let w = encode_app_wire(&sample(vec![1; 20]));
        assert!(decode_app_wire(&w[..10], 99).is_err());
        let mut v = w.clone();
        v[0] = 2;
        assert_eq!(decode_app_wire(&v, 99).unwrap_err().code, "WIRE_VERSION_UNSUPPORTED");
        let mut t = w.clone();
        t.push(0);
        assert!(decode_app_wire(&t, 99).is_err(), "trailing byte");
        assert!(decode_app_wire(&w[..w.len() - 1], 99).is_err(), "truncated");
        assert!(decode_app_wire(&w, 10).is_err(), "ct cap");
        let mut s = w.clone();
        s[33] ^= 1;
        assert!(decode_app_wire(&s, 99).is_err(), "seq mismatch");
        let mut l = w.clone();
        l[46..50].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_app_wire(&l, 1 << 20).is_err(), "huge declared length");
    }
}
