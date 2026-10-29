//! Transport Frame v1 (docs/stego-implementation-note.md §1.2).
//!
//! `frame = "IODF" | ver | alg_id | param | flags | wire_len(4) | wire | tag(32)`,
//! `tag = HMAC-SHA256(meta_key, "IOD-STEGO-FRAME-v1" | header | wire)`,
//! `meta_key = HKDF(directional AEAD key, info = "IOD-STEGO-META-v1" | channel_tag | direction)`.
//! The MAC key is domain-separated from the AEAD key and never leaves Rust.

use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::{hkdf_expand, hmac_sha256, hmac_verify};
use crate::transport::error::{stage, StegoError};

pub const FRAME_MAGIC: &[u8; 4] = b"IODF";
pub const FRAME_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 12;
pub const TAG_LEN: usize = 32;
const MAC_DOMAIN: &[u8] = b"IOD-STEGO-FRAME-v1";
const META_INFO: &[u8] = b"IOD-STEGO-META-v1";

/// Dedicated metadata-authentication key. No `Debug`/`Clone`/`Serialize` on purpose.
pub struct MetaKey([u8; 32]);

pub fn derive_meta_key(aead_key: &AeadKey, channel_tag: &[u8; 16], direction: u8) -> MetaKey {
    let mut info = Vec::with_capacity(META_INFO.len() + 17);
    info.extend_from_slice(META_INFO);
    info.extend_from_slice(channel_tag);
    info.push(direction);
    let okm = hkdf_expand(&aead_key.0, None, &info, 32);
    let mut k = [0u8; 32];
    k.copy_from_slice(&okm);
    MetaKey(k)
}

fn err(code: &str, msg: &str) -> StegoError {
    StegoError::new(code, stage::VERIFY, 422, msg)
}

fn mac_input(header: &[u8], wire: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MAC_DOMAIN.len() + header.len() + wire.len());
    m.extend_from_slice(MAC_DOMAIN);
    m.extend_from_slice(header);
    m.extend_from_slice(wire);
    m
}

fn mac(key: &MetaKey, header: &[u8], wire: &[u8]) -> [u8; 32] {
    hmac_sha256(&key.0, &mac_input(header, wire))
}

pub fn frame_len_for(wire_len: usize) -> usize {
    HEADER_LEN + wire_len + TAG_LEN
}

pub fn build_frame(key: &MetaKey, alg_id: u8, param: u8, wire: &[u8], max_frame: usize) -> Result<Vec<u8>, StegoError> {
    let total = frame_len_for(wire.len());
    if total > max_frame {
        return Err(StegoError::new("FRAME_TOO_LARGE", stage::PREPARE, 413, format!("frame of {total} bytes exceeds the configured maximum of {max_frame}")));
    }
    let mut f = Vec::with_capacity(total);
    f.extend_from_slice(FRAME_MAGIC);
    f.push(FRAME_VERSION);
    f.push(alg_id);
    f.push(param);
    f.push(0);
    f.extend_from_slice(&(wire.len() as u32).to_be_bytes());
    let tag = mac(key, &f[..HEADER_LEN], wire);
    f.extend_from_slice(wire);
    f.extend_from_slice(&tag);
    Ok(f)
}

/// Strictly parse and authenticate. `expect_*` come from the (unauthenticated)
/// image bootstrap and must match the authenticated header. Returns the AppWire bytes.
pub fn parse_and_verify<'a>(
    key: &MetaKey,
    frame: &'a [u8],
    expect_alg: u8,
    expect_param: u8,
    max_frame: usize,
) -> Result<&'a [u8], StegoError> {
    if frame.len() > max_frame {
        return Err(err("FRAME_TOO_LARGE", "frame exceeds configured maximum"));
    }
    if frame.len() < HEADER_LEN + TAG_LEN {
        return Err(err("FRAME_MALFORMED", "frame shorter than header plus tag"));
    }
    if &frame[..4] != FRAME_MAGIC {
        return Err(err("FRAME_MALFORMED", "bad frame magic"));
    }
    if frame[4] != FRAME_VERSION {
        return Err(err("FRAME_VERSION_UNSUPPORTED", "unsupported frame version"));
    }
    if frame[7] != 0 {
        return Err(err("FRAME_MALFORMED", "non-zero reserved flags"));
    }
    let wire_len = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
    if frame.len() != frame_len_for(wire_len) {
        return Err(err("FRAME_MALFORMED", "declared payload length does not match frame length"));
    }
    let (header, rest) = frame.split_at(HEADER_LEN);
    let (wire, tag) = rest.split_at(wire_len);
    // Authenticate FIRST; only then trust any header field semantically.
    if !hmac_verify(&key.0, &mac_input(header, wire), tag) {
        return Err(err("FRAME_AUTH_FAILED", "frame metadata authentication failed"));
    }
    if frame[5] != expect_alg || frame[6] != expect_param {
        return Err(err("FRAME_ALGORITHM_MISMATCH", "authenticated algorithm differs from the image bootstrap"));
    }
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(b: u8, dir: u8) -> MetaKey {
        derive_meta_key(&AeadKey([b; 32]), &[5; 16], dir)
    }
    #[test]
    fn build_parse_round_trip() {
        let k = key(1, 1);
        let f = build_frame(&k, 3, 0, b"wire-bytes", 4096).unwrap();
        assert_eq!(f.len(), frame_len_for(10));
        assert_eq!(parse_and_verify(&k, &f, 3, 0, 4096).unwrap(), b"wire-bytes");
    }
    #[test]
    fn every_single_byte_flip_is_rejected() {
        let k = key(1, 1);
        let f = build_frame(&k, 2, 0, &[0xAB; 40], 4096).unwrap();
        for i in 0..f.len() {
            let mut t = f.clone();
            t[i] ^= 0x01;
            assert!(parse_and_verify(&k, &t, 2, 0, 4096).is_err(), "flip at {i} accepted");
        }
    }
    #[test]
    fn wrong_key_direction_or_channel_fails() {
        let f = build_frame(&key(1, 1), 1, 0, b"x", 4096).unwrap();
        assert_eq!(parse_and_verify(&key(2, 1), &f, 1, 0, 4096).unwrap_err().code, "FRAME_AUTH_FAILED");
        assert_eq!(parse_and_verify(&key(1, 2), &f, 1, 0, 4096).unwrap_err().code, "FRAME_AUTH_FAILED");
        let other_ch = derive_meta_key(&AeadKey([1; 32]), &[6; 16], 1);
        assert_eq!(parse_and_verify(&other_ch, &f, 1, 0, 4096).unwrap_err().code, "FRAME_AUTH_FAILED");
    }
    #[test]
    fn bootstrap_mismatch_truncation_and_limits() {
        let k = key(1, 1);
        let f = build_frame(&k, 4, 6, b"abc", 4096).unwrap();
        assert_eq!(parse_and_verify(&k, &f, 5, 6, 4096).unwrap_err().code, "FRAME_ALGORITHM_MISMATCH");
        assert_eq!(parse_and_verify(&k, &f, 4, 7, 4096).unwrap_err().code, "FRAME_ALGORITHM_MISMATCH");
        assert!(parse_and_verify(&k, &f[..f.len() - 1], 4, 6, 4096).is_err());
        assert!(parse_and_verify(&k, &f, 4, 6, 20).is_err());
        assert_eq!(build_frame(&k, 1, 0, &[0; 100], 50).unwrap_err().code, "FRAME_TOO_LARGE");
        let mut v = f.clone();
        v[4] = 9;
        assert_eq!(parse_and_verify(&k, &v, 4, 6, 4096).unwrap_err().code, "FRAME_VERSION_UNSUPPORTED");
    }
    #[test]
    fn meta_key_is_not_the_aead_key() {
        let a = AeadKey([7; 32]);
        let m = derive_meta_key(&a, &[0; 16], 1);
        assert_ne!(m.0, a.0);
    }
}
