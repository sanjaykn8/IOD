//! Transport Frame v3 (docs/patchwise-transport.md section 3, docs/bootstrap-v3-design.md).
//!
//! ```text
//! frame = "IOD3" | ver=3 | flags=0 | reserved u16=0 | manifest_len u32 | wire_len u32   (16 bytes, BE)
//!         | manifest-v2 | wire | tag(32)
//! tag      = HMAC-SHA256(meta_key, "IOD-STEGO-FRAME-v3" | header | manifest | wire)
//! meta_key = HKDF(directional AEAD key, info = "IOD-STEGO-META-v1" | channel_tag | direction)
//! ```
//! The MAC therefore covers the complete patch manifest (image dimensions, segmentation and selector
//! versions, the patch map, every patch's algorithm id, parameter, payload offset and payload length)
//! and the AppWire payload. The MAC key is domain-separated from the AEAD key and never leaves Rust;
//! the image service neither creates nor checks the tag.
//!
//! Frame v3 has the v2 layout; the version bump marks manifest-v2 + bootstrap-v3. Frame v1 ("IODF")
//! and Frame v2 ("IOD2", top-row bootstrap) images are not accepted.

use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::{hkdf_expand, hmac_sha256, hmac_verify};
use crate::transport::error::{stage, StegoError};
use crate::transport::manifest::{FIXED_LEN, ENTRY_LEN, MAX_MANIFEST_BYTES};

pub const FRAME_MAGIC: &[u8; 4] = b"IOD3";
pub const FRAME_VERSION: u8 = 3;
pub const HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 32;
const MAC_DOMAIN: &[u8] = b"IOD-STEGO-FRAME-v3";
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

fn mac_input(authenticated: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MAC_DOMAIN.len() + authenticated.len());
    m.extend_from_slice(MAC_DOMAIN);
    m.extend_from_slice(authenticated);
    m
}

pub fn frame_len_for(manifest_len: usize, wire_len: usize) -> usize {
    HEADER_LEN + manifest_len + wire_len + TAG_LEN
}

/// Length of the part of the frame that the patches carry (`wire | tag`).
pub fn payload_section_len(wire_len: usize) -> usize {
    wire_len + TAG_LEN
}

pub fn build_frame(key: &MetaKey, manifest: &[u8], wire: &[u8], max_frame: usize) -> Result<Vec<u8>, StegoError> {
    if manifest.len() > MAX_MANIFEST_BYTES || wire.is_empty() || wire.len() > u32::MAX as usize {
        return Err(StegoError::new("FRAME_MALFORMED", stage::PREPARE, 422, "manifest or payload size out of range"));
    }
    let total = frame_len_for(manifest.len(), wire.len());
    if total > max_frame {
        return Err(StegoError::new("FRAME_TOO_LARGE", stage::PREPARE, 413, format!("frame of {total} bytes exceeds the configured maximum of {max_frame}")));
    }
    let mut f = Vec::with_capacity(total);
    f.extend_from_slice(FRAME_MAGIC);
    f.extend_from_slice(&[FRAME_VERSION, 0, 0, 0]);
    f.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
    f.extend_from_slice(&(wire.len() as u32).to_be_bytes());
    f.extend_from_slice(manifest);
    f.extend_from_slice(wire);
    let tag = hmac_sha256(&key.0, &mac_input(&f));
    f.extend_from_slice(&tag);
    Ok(f)
}

/// Strictly parse the frame structure and authenticate it. Returns `(manifest_bytes, wire_bytes)`;
/// both are authenticated but the manifest still has to pass `manifest::parse`.
/// Nothing from the frame is interpreted semantically before the MAC verified.
pub fn parse_and_verify<'a>(key: &MetaKey, frame: &'a [u8], max_frame: usize) -> Result<(&'a [u8], &'a [u8]), StegoError> {
    if frame.len() > max_frame {
        return Err(err("FRAME_TOO_LARGE", "frame exceeds configured maximum"));
    }
    if frame.len() < HEADER_LEN + FIXED_LEN + ENTRY_LEN + 1 + 1 + TAG_LEN {
        return Err(err("FRAME_MALFORMED", "frame shorter than the minimum frame"));
    }
    if &frame[..4] != FRAME_MAGIC {
        return Err(err("FRAME_MALFORMED", "bad frame magic (Frame v1/v2 images are not accepted)"));
    }
    if frame[4] != FRAME_VERSION {
        return Err(err("FRAME_VERSION_UNSUPPORTED", "unsupported frame version"));
    }
    if frame[5] != 0 || frame[6] != 0 || frame[7] != 0 {
        return Err(err("FRAME_MALFORMED", "non-zero reserved flags"));
    }
    let mlen = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
    let wlen = u32::from_be_bytes(frame[12..16].try_into().unwrap()) as usize;
    if mlen > MAX_MANIFEST_BYTES || wlen == 0 {
        return Err(err("FRAME_MALFORMED", "declared manifest or payload length out of range"));
    }
    // checked arithmetic: both lengths are attacker-controlled
    let expect = HEADER_LEN.checked_add(mlen).and_then(|x| x.checked_add(wlen)).and_then(|x| x.checked_add(TAG_LEN));
    if expect != Some(frame.len()) {
        return Err(err("FRAME_MALFORMED", "declared lengths do not match the frame length"));
    }
    let (authed, tag) = frame.split_at(frame.len() - TAG_LEN);
    if !hmac_verify(&key.0, &mac_input(authed), tag) {
        return Err(err("FRAME_AUTH_FAILED", "frame authentication failed (manifest or payload modified, or wrong channel/direction)"));
    }
    Ok((&authed[HEADER_LEN..HEADER_LEN + mlen], &authed[HEADER_LEN + mlen..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::manifest;

    fn key(b: u8, dir: u8) -> MetaKey {
        derive_meta_key(&AeadKey([b; 32]), &[5; 16], dir)
    }
    fn man(payload: u32) -> Vec<u8> {
        manifest::sample(64, 64, 1, payload, &[(1, 0), (6, 4)]).encode()
    }

    #[test]
    fn build_parse_round_trip_and_layout() {
        let k = key(1, 1);
        let m = man(10 + 32);
        let f = build_frame(&k, &m, b"wire-bytes", 4096).unwrap();
        assert_eq!(f.len(), frame_len_for(m.len(), 10));
        assert_eq!(&f[..8], b"IOD3\x03\x00\x00\x00");
        assert_eq!(u32::from_be_bytes(f[8..12].try_into().unwrap()) as usize, m.len());
        assert_eq!(u32::from_be_bytes(f[12..16].try_into().unwrap()), 10);
        let (pm, w) = parse_and_verify(&k, &f, 4096).unwrap();
        assert_eq!(pm, &m[..]);
        assert_eq!(w, b"wire-bytes");
        assert_eq!(payload_section_len(10), 42);
    }

    #[test]
    fn test_vector_tag_is_hmac_over_domain_header_manifest_wire() {
        let k = key(1, 1);
        let m = man(40);
        let f = build_frame(&k, &m, &[0xAB; 8], 4096).unwrap();
        let mut input = b"IOD-STEGO-FRAME-v3".to_vec();
        input.extend_from_slice(&f[..f.len() - 32]);
        assert_eq!(&f[f.len() - 32..], &hmac_sha256(&k.0, &input)[..]);
    }

    #[test]
    fn every_single_byte_flip_is_rejected() {
        let k = key(1, 1);
        let m = man(72);
        let f = build_frame(&k, &m, &[0xAB; 40], 4096).unwrap();
        for i in 0..f.len() {
            for bit in [0x01u8, 0x80] {
                let mut t = f.clone();
                t[i] ^= bit;
                assert!(parse_and_verify(&k, &t, 4096).is_err(), "flip at {i} accepted");
            }
        }
    }

    #[test]
    fn manifest_field_changes_fail_authentication() {
        let k = key(1, 1);
        let m = man(72);
        let f = build_frame(&k, &m, &[0xAB; 40], 4096).unwrap();
        let e1 = HEADER_LEN + manifest::FIXED_LEN + manifest::ENTRY_LEN;
        // algorithm id, parameter, offset, length, width, a map label
        for off in [e1, e1 + 1, e1 + 7, e1 + 11, HEADER_LEN + 9, HEADER_LEN + m.len() - 2] {
            let mut t = f.clone();
            t[off] ^= 0x01;
            assert_eq!(parse_and_verify(&k, &t, 4096).unwrap_err().code, "FRAME_AUTH_FAILED", "offset {off}");
        }
    }

    #[test]
    fn wrong_key_direction_or_channel_fails() {
        let m = man(33);
        let f = build_frame(&key(1, 1), &m, b"x", 4096).unwrap();
        assert_eq!(parse_and_verify(&key(2, 1), &f, 4096).unwrap_err().code, "FRAME_AUTH_FAILED");
        assert_eq!(parse_and_verify(&key(1, 2), &f, 4096).unwrap_err().code, "FRAME_AUTH_FAILED");
        let other_ch = derive_meta_key(&AeadKey([1; 32]), &[6; 16], 1);
        assert_eq!(parse_and_verify(&other_ch, &f, 4096).unwrap_err().code, "FRAME_AUTH_FAILED");
    }

    #[test]
    fn structure_limits_versions_and_v1_frames() {
        let k = key(1, 1);
        let m = man(35);
        let f = build_frame(&k, &m, b"abc", 4096).unwrap();
        assert!(parse_and_verify(&k, &f[..f.len() - 1], 4096).is_err());
        assert_eq!(parse_and_verify(&k, &f, 50).unwrap_err().code, "FRAME_TOO_LARGE");
        assert_eq!(build_frame(&k, &m, &[0; 100], 50).unwrap_err().code, "FRAME_TOO_LARGE");
        assert_eq!(build_frame(&k, &m, &[], 4096).unwrap_err().code, "FRAME_MALFORMED");
        let mut v = f.clone();
        v[4] = 1;
        assert_eq!(parse_and_verify(&k, &v, 4096).unwrap_err().code, "FRAME_VERSION_UNSUPPORTED");
        let mut v1 = f.clone();
        v1[..4].copy_from_slice(b"IODF");
        assert_eq!(parse_and_verify(&k, &v1, 4096).unwrap_err().code, "FRAME_MALFORMED");
        // a Frame v2 header ("IOD2", version 2) is rejected before the MAC is even computed
        let mut v2 = f.clone();
        v2[..5].copy_from_slice(b"IOD2\x02");
        assert_eq!(parse_and_verify(&k, &v2, 4096).unwrap_err().code, "FRAME_MALFORMED");
        let mut big = f.clone();
        big[8..12].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        assert_eq!(parse_and_verify(&k, &big, 4096).unwrap_err().code, "FRAME_MALFORMED");
        let mut fl = f.clone();
        fl[6] = 1;
        assert_eq!(parse_and_verify(&k, &fl, 4096).unwrap_err().code, "FRAME_MALFORMED");
    }

    #[test]
    fn meta_key_is_not_the_aead_key() {
        let a = AeadKey([7; 32]);
        let m = derive_meta_key(&a, &[0; 16], 1);
        assert_ne!(m.0, a.0);
    }
}
