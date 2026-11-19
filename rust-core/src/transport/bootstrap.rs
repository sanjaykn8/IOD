//! Bootstrap-v3: keyed, distributed, encrypted carrier for the patch manifest
//! (design: docs/bootstrap-v3-design.md).
//!
//! Everything secret lives here and never leaves Rust: the placement key `PK`, the sync word and
//! the keystream. The image service only ever sees
//! * the **value stream** (pseudo-random u32 values; the service maps them to pixel indices of the
//!   actual image as `v mod (W*H)`, keeping first occurrences), and
//! * the **carrier bits**, already encrypted.
//!
//! ```text
//! PK   = HKDF(dir_key, info = "IOD-STEGO-PLACE-v3" | channel_tag | direction | seq_be32)
//! v_i  = SHAKE-256("IOD-BOOT3-VALUES" | PK) as BE u32
//! S    = HMAC-SHA256(PK, "IOD-BOOT3-SYNC")[..8]
//! KS   = SHAKE-256("IOD-BOOT3-STREAM" | PK)
//! bits = S | (header XOR KS[0..4]) | (body XOR KS[4..])
//! header = 3 | 0 | body_len u16 ;  body = DEFLATE(manifest-v2) | CRC32
//! ```
//! CRC32 only separates accidental corruption from forgery in diagnostics; it is NOT authentication.
//! The manifest is authenticated by the frame MAC.

use crate::crypto::aead::AeadKey;
use crate::crypto::kdf::{hkdf_expand, hmac_sha256};
use crate::transport::error::{stage, StegoError};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const VERSION: u8 = 3;
pub const SYNC_BITS: usize = 64;
pub const HEADER_BITS: usize = 32;
pub const LOCATOR_BITS: usize = SYNC_BITS + HEADER_BITS;
/// Values sent per probe candidate: the 96 locator bits need 32 distinct pixels (RGB) or 96 (grey);
/// 128 leaves room for duplicate removal.
pub const PROBE_VALUES: usize = 128;
/// Length of the full value stream (bounds the number of reservable carrier pixels).
pub const STREAM_VALUES: usize = 8192;
pub const MAX_BODY_BYTES: usize = 65_535;
/// Look-back below the last accepted sequence number, used only to report replays explicitly.
pub const REPLAY_LOOKBACK: u32 = 63;
pub const DEFAULT_SYNC_WINDOW: u32 = 64;
pub const MAX_SYNC_WINDOW: u32 = 1024;
const PLACE_INFO: &[u8] = b"IOD-STEGO-PLACE-v3";

/// Per-frame placement key. No `Debug`/`Clone`/`Serialize` on purpose.
pub struct PlacementKey([u8; 32]);

pub fn placement_key(dir_key: &AeadKey, channel_tag: &[u8; 16], direction: u8, seq: u32) -> PlacementKey {
    let mut info = Vec::with_capacity(PLACE_INFO.len() + 21);
    info.extend_from_slice(PLACE_INFO);
    info.extend_from_slice(channel_tag);
    info.push(direction);
    info.extend_from_slice(&seq.to_be_bytes());
    let okm = hkdf_expand(&dir_key.0, None, &info, 32);
    let mut k = [0u8; 32];
    k.copy_from_slice(&okm);
    PlacementKey(k)
}

fn shake(label: &[u8], pk: &PlacementKey, n: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(label);
    h.update(&pk.0);
    let mut out = vec![0u8; n];
    h.finalize_xof().read(&mut out);
    out
}

/// The first `n` values of the frame's value stream, as big-endian u32 bytes (4n bytes).
pub fn value_stream(pk: &PlacementKey, n: usize) -> Vec<u8> {
    shake(b"IOD-BOOT3-VALUES", pk, 4 * n)
}

pub fn sync_word(pk: &PlacementKey) -> [u8; 8] {
    let t = hmac_sha256(&pk.0, b"IOD-BOOT3-SYNC");
    t[..8].try_into().expect("8 bytes")
}

fn keystream(pk: &PlacementKey, n: usize) -> Vec<u8> {
    shake(b"IOD-BOOT3-STREAM", pk, n)
}

/// CRC-32 (IEEE 802.3, reflected, as zlib.crc32). Corruption check only.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

fn bad(code: &str, msg: &str) -> StegoError {
    StegoError::new(code, stage::EXTRACT, 422, msg)
}

/// Inflate a raw DEFLATE stream with a hard output limit (no unbounded allocation).
pub fn inflate_bounded(data: &[u8], limit: usize) -> Result<Vec<u8>, StegoError> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(data, limit)
        .map_err(|_| bad("BOOTSTRAP_CORRUPT", "bootstrap body does not inflate within the manifest size limit"))
}

/// Sender: carrier bytes (`S | E(header) | E(body)`) for an already-compressed manifest.
/// `deflated` is the service's DEFLATE output; it must inflate to exactly `manifest`.
pub fn build_carrier(pk: &PlacementKey, manifest: &[u8], deflated: &[u8]) -> Result<Vec<u8>, StegoError> {
    let back = inflate_bounded(deflated, crate::transport::manifest::MAX_MANIFEST_BYTES)
        .map_err(|_| StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::PLAN, 502, "compressed manifest from the image service does not inflate"))?;
    if back != manifest {
        return Err(StegoError::new("BACKEND_MALFORMED_RESPONSE", stage::PLAN, 502, "compressed manifest does not inflate to the planned manifest"));
    }
    let mut body = deflated.to_vec();
    body.extend_from_slice(&crc32(deflated).to_be_bytes());
    if body.len() > MAX_BODY_BYTES {
        return Err(StegoError::new("MANIFEST_TOO_LARGE", stage::PLAN, 422, "bootstrap body exceeds 65535 bytes"));
    }
    let ks = keystream(pk, 4 + body.len());
    let header = [VERSION, 0, (body.len() >> 8) as u8, body.len() as u8];
    let mut out = Vec::with_capacity(8 + 4 + body.len());
    out.extend_from_slice(&sync_word(pk));
    out.extend(header.iter().zip(&ks[..4]).map(|(a, b)| a ^ b));
    out.extend(body.iter().zip(&ks[4..]).map(|(a, b)| a ^ b));
    Ok(out)
}

/// Number of carrier pixels the sender reserves for a manifest of `manifest_len` bytes
/// (upper bound: the DEFLATE output never exceeds the input by more than the slack used here).
pub fn reserve_pixels_for(manifest_len: usize, channels: usize) -> usize {
    let bits = LOCATOR_BITS + 8 * (manifest_len + 64 + 4);
    bits.div_ceil(channels.max(1))
}

/// Receiver: decode the 4 header bytes (bits 64..96 of the locator, still encrypted). Returns body length.
pub fn open_header(pk: &PlacementKey, enc: &[u8]) -> Result<usize, StegoError> {
    if enc.len() != 4 {
        return Err(bad("BOOTSTRAP_CORRUPT", "locator header has the wrong size"));
    }
    let ks = keystream(pk, 4);
    let h: Vec<u8> = enc.iter().zip(&ks).map(|(a, b)| a ^ b).collect();
    if h[0] != VERSION {
        return Err(bad("BOOTSTRAP_VERSION_UNSUPPORTED", "unsupported bootstrap version"));
    }
    if h[1] != 0 {
        return Err(bad("BOOTSTRAP_CORRUPT", "non-zero bootstrap flags"));
    }
    let len = ((h[2] as usize) << 8) | h[3] as usize;
    if len < 4 + 2 {
        return Err(bad("BOOTSTRAP_CORRUPT", "bootstrap body length out of range"));
    }
    Ok(len)
}

/// Receiver: decrypt the body, check the CRC and inflate. Returns the (still untrusted) manifest bytes.
pub fn open_body(pk: &PlacementKey, enc: &[u8]) -> Result<Vec<u8>, StegoError> {
    let ks = keystream(pk, 4 + enc.len());
    let body: Vec<u8> = enc.iter().zip(&ks[4..]).map(|(a, b)| a ^ b).collect();
    if body.len() < 6 {
        return Err(bad("BOOTSTRAP_CORRUPT", "bootstrap body too short"));
    }
    let (deflated, crc) = body.split_at(body.len() - 4);
    if crc32(deflated).to_be_bytes() != crc {
        return Err(bad("BOOTSTRAP_CORRUPT", "bootstrap body CRC mismatch (accidental corruption or wrong key)"));
    }
    inflate_bounded(deflated, crate::transport::manifest::MAX_MANIFEST_BYTES)
}

/// Candidate sequence numbers for discovery, given the last accepted one.
pub fn candidates(last_accepted: u32, window: u32) -> Vec<u32> {
    let lo = last_accepted.saturating_sub(REPLAY_LOOKBACK).max(1);
    let hi = last_accepted.saturating_add(window.clamp(1, MAX_SYNC_WINDOW));
    (lo..=hi).collect()
}

/// Outcome of comparing the probed locator bits with the expected sync words.
#[derive(Debug, PartialEq, Eq)]
pub enum Discovery {
    Found { seq: u32, header: [u8; 4] },
    Replay { seq: u32 },
    NotFound,
    Ambiguous { seqs: Vec<u32> },
}

/// `probed[i]` = the 12 locator bytes read for `cands[i]` (None if the service could not map them).
pub fn discover(cands: &[u32], probed: &[Option<Vec<u8>>], sync: impl Fn(u32) -> [u8; 8], last_accepted: u32) -> Discovery {
    let mut hits = Vec::new();
    for (s, p) in cands.iter().zip(probed) {
        if let Some(b) = p {
            if b.len() == LOCATOR_BITS / 8 && b[..8] == sync(*s) {
                hits.push((*s, [b[8], b[9], b[10], b[11]]));
            }
        }
    }
    match hits.len() {
        0 => Discovery::NotFound,
        1 if hits[0].0 <= last_accepted => Discovery::Replay { seq: hits[0].0 },
        1 => Discovery::Found { seq: hits[0].0, header: hits[0].1 },
        _ => Discovery::Ambiguous { seqs: hits.into_iter().map(|h| h.0).collect() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seq: u32, dir: u8) -> PlacementKey {
        placement_key(&AeadKey([7; 32]), &[3; 16], dir, seq)
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec(data, 9)
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn placement_material_is_bound_to_key_channel_direction_and_sequence() {
        let base = value_stream(&pk(5, 1), 16);
        assert_eq!(base, value_stream(&pk(5, 1), 16));
        assert_ne!(base, value_stream(&pk(6, 1), 16));
        assert_ne!(base, value_stream(&pk(5, 2), 16));
        assert_ne!(base, value_stream(&placement_key(&AeadKey([8; 32]), &[3; 16], 1, 5), 16));
        assert_ne!(base, value_stream(&placement_key(&AeadKey([7; 32]), &[4; 16], 1, 5), 16));
        assert_ne!(sync_word(&pk(5, 1)), sync_word(&pk(6, 1)));
        // a prefix of the stream is the stream's prefix (probe values == first values of the full stream)
        assert_eq!(value_stream(&pk(5, 1), STREAM_VALUES)[..4 * PROBE_VALUES], value_stream(&pk(5, 1), PROBE_VALUES)[..]);
    }

    #[test]
    fn carrier_round_trip_and_bit_layout() {
        let manifest: Vec<u8> = (0..500u32).map(|i| (i % 7) as u8).collect();
        let p = pk(9, 1);
        let c = build_carrier(&p, &manifest, &deflate(&manifest)).unwrap();
        assert_eq!(&c[..8], &sync_word(&p));
        let len = open_header(&p, &c[8..12]).unwrap();
        assert_eq!(len, c.len() - 12);
        assert_eq!(open_body(&p, &c[12..]).unwrap(), manifest);
        // the encrypted part does not show the plaintext header or the DEFLATE stream
        assert_ne!(c[8], VERSION);
        assert_ne!(&c[12..20], &deflate(&manifest)[..8]);
    }

    #[test]
    fn wrong_key_or_sequence_cannot_open_and_tampering_is_detected() {
        let manifest = vec![1u8; 300];
        let p = pk(9, 1);
        let c = build_carrier(&p, &manifest, &deflate(&manifest)).unwrap();
        assert!(open_header(&pk(10, 1), &c[8..12]).is_err() || open_body(&pk(10, 1), &c[12..]).is_err());
        assert!(open_body(&pk(9, 2), &c[12..]).is_err());
        let mut t = c.clone();
        let n = t.len();
        t[n / 2] ^= 0x10;
        assert_eq!(open_body(&p, &t[12..]).unwrap_err().code, "BOOTSTRAP_CORRUPT");
        // header with a bad version / flags
        let ks = keystream(&p, 4);
        let enc = |h: [u8; 4]| -> Vec<u8> { h.iter().zip(&ks).map(|(a, b)| a ^ b).collect() };
        assert_eq!(open_header(&p, &enc([2, 0, 0, 40])).unwrap_err().code, "BOOTSTRAP_VERSION_UNSUPPORTED");
        assert_eq!(open_header(&p, &enc([3, 1, 0, 40])).unwrap_err().code, "BOOTSTRAP_CORRUPT");
        assert_eq!(open_header(&p, &enc([3, 0, 0, 2])).unwrap_err().code, "BOOTSTRAP_CORRUPT");
    }

    #[test]
    fn inflation_is_bounded_against_compression_bombs() {
        let bomb = deflate(&vec![0u8; 10_000_000]);
        assert!(bomb.len() < 20_000);
        assert_eq!(inflate_bounded(&bomb, 65_536).unwrap_err().code, "BOOTSTRAP_CORRUPT");
        assert!(inflate_bounded(&[0xFF, 0xFF, 0xFF], 65_536).is_err());
    }

    #[test]
    fn the_sender_rejects_a_service_compression_that_does_not_match_the_manifest() {
        let p = pk(1, 1);
        assert!(build_carrier(&p, b"abc", &deflate(b"abd")).is_err());
        assert!(build_carrier(&p, b"abc", b"\x00\x01").is_err());
    }

    #[test]
    fn discovery_windows_and_outcomes() {
        assert_eq!(candidates(0, 64), (1..=64).collect::<Vec<_>>());
        assert_eq!(candidates(100, 4), (37..=104).collect::<Vec<_>>());
        assert_eq!(candidates(5, 0).last(), Some(&6), "window is at least 1");
        assert_eq!(*candidates(0, 99_999).last().unwrap(), MAX_SYNC_WINDOW);
        let sync = |s: u32| sync_word(&pk(s, 1));
        let loc = |s: u32| -> Option<Vec<u8>> { let mut v = sync(s).to_vec(); v.extend_from_slice(&[1, 2, 3, 4]); Some(v) };
        let cands = candidates(10, 8);
        let junk: Vec<Option<Vec<u8>>> = cands.iter().map(|_| Some(vec![0u8; 12])).collect();
        assert_eq!(discover(&cands, &junk, sync, 10), Discovery::NotFound);
        let mut one = junk.clone();
        let i = cands.iter().position(|&s| s == 13).unwrap();
        one[i] = loc(13);
        assert_eq!(discover(&cands, &one, sync, 10), Discovery::Found { seq: 13, header: [1, 2, 3, 4] });
        let mut old = junk.clone();
        old[cands.iter().position(|&s| s == 7).unwrap()] = loc(7);
        assert_eq!(discover(&cands, &old, sync, 10), Discovery::Replay { seq: 7 });
        let mut two = one.clone();
        two[cands.iter().position(|&s| s == 15).unwrap()] = loc(15);
        assert_eq!(discover(&cands, &two, sync, 10), Discovery::Ambiguous { seqs: vec![13, 15] });
        let missing: Vec<Option<Vec<u8>>> = cands.iter().map(|_| None).collect();
        assert_eq!(discover(&cands, &missing, sync, 10), Discovery::NotFound);
    }

    #[test]
    fn reserve_bound_covers_the_worst_case_deflate_output() {
        for len in [40usize, 300, 2000, 20_000] {
            let incompressible: Vec<u8> = value_stream(&pk(len as u32, 1), len.div_ceil(4))[..len].to_vec();
            let d = deflate(&incompressible);
            let bits = LOCATOR_BITS + 8 * (d.len() + 4);
            for ch in [1usize, 3] {
                assert!(reserve_pixels_for(len, ch) * ch >= bits, "len {len} ch {ch}");
            }
        }
    }
}
