//! Patch manifest v2 (docs/patchwise-transport.md section 4, docs/bootstrap-v3-design.md):
//! strict parser + canonical encoder.
//!
//! The manifest is produced by the image service (it holds no keys), validated here BEFORE the
//! frame is authenticated on the sender, and parsed here again AFTER the frame MAC verified on
//! the receiver. Everything is bounds-checked; any deviation from the canonical encoding fails.
//!
//! ```text
//! "IOPM" | ver=2 | seg_ver=1 | sel_ver=2 | channels | width u16 | height u16 | cell u8 | n u8
//!        | carrier_pixels u16 | payload_len u32 | map_len u32                     (24 bytes, BE)
//! n x ( alg_id u8 | param u8 | flags u16 = 0 | offset u32 | length u32 )          (12 bytes each)
//! map: run-length code over the cell grid in raster order: ( label u8 | run LEB128 )*
//! ```
//! `carrier_pixels` (R) is canonical: R = `bootstrap::reserve_pixels_for(manifest_len, channels)` and
//! R <= width*height/8. The first R distinct carrier pixels of the frame's value stream are excluded from
//! every patch mask; no rows are reserved. (v1 had `reserved_rows` here and is not accepted.)

use crate::transport::backend::ALGS;
use crate::transport::error::{stage, StegoError};
use serde_json::{json, Value};

pub const MAGIC: &[u8; 4] = b"IOPM";
pub const VERSION: u8 = 2;
pub const SEG_VERSION: u8 = 1;
pub const SEL_VERSION: u8 = 2;
pub const SEG_VERSION_NAME: &str = "arg-cells-1";
pub const SEL_VERSION_NAME: &str = "kb-risk-1";
pub const FIXED_LEN: usize = 24;
pub const ENTRY_LEN: usize = 12;
pub const MAX_PATCHES: usize = 255;
pub const MAX_MANIFEST_BYTES: usize = 65_536;
pub const TAG_LEN: usize = 32;

/// Inclusive explicit-parameter range per algorithm id (index = id - 1); (0, 0) = parameter must be 0.
const PARAM_RANGE: [(u8, u8); 10] = [(0, 0), (0, 0), (0, 0), (1, 255), (4, 64), (4, 64), (8, 64), (2, 64), (2, 64), (2, 64)];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchEntry {
    pub alg_id: u8,
    pub param: u8,
    pub offset: u32,
    pub length: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub channels: u8,
    pub width: u16,
    pub height: u16,
    pub cell: u8,
    /// Number of reserved bootstrap-v3 carrier pixels (canonical, see module docs).
    pub carrier_pixels: u16,
    pub payload_len: u32,
    pub patches: Vec<PatchEntry>,
    /// rows * cols labels, raster order
    pub cell_labels: Vec<u8>,
}

fn bad(msg: &str) -> StegoError {
    StegoError::new("MANIFEST_INVALID", stage::VERIFY, 422, msg)
}

pub fn grid(height: u16, width: u16, cell: u8) -> (usize, usize) {
    let c = cell as usize;
    ((height as usize + c - 1) / c, (width as usize + c - 1) / c)
}

/// Canonical number of reserved carrier pixels for a manifest of `manifest_len` bytes.
pub fn carrier_pixels_for(manifest_len: usize, channels: u8) -> usize {
    crate::transport::bootstrap::reserve_pixels_for(manifest_len, channels as usize)
}

pub fn rle_encode(labels: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < labels.len() {
        let mut j = i;
        while j < labels.len() && labels[j] == labels[i] {
            j += 1;
        }
        out.push(labels[i]);
        let mut run = j - i;
        loop {
            let b = (run & 0x7F) as u8;
            run >>= 7;
            if run == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
        i = j;
    }
    out
}

fn rle_decode(data: &[u8], n_cells: usize, n_patches: usize) -> Result<Vec<u8>, StegoError> {
    let mut out = Vec::with_capacity(n_cells);
    let mut i = 0;
    let mut prev: Option<u8> = None;
    while i < data.len() {
        let label = data[i];
        i += 1;
        if label as usize >= n_patches {
            return Err(bad("map label is not a patch id"));
        }
        if prev == Some(label) {
            return Err(bad("map is not canonical (adjacent runs with the same label)"));
        }
        let mut run: usize = 0;
        let mut shift = 0u32;
        loop {
            let Some(&b) = data.get(i) else { return Err(bad("map truncated inside a run length")) };
            i += 1;
            if shift >= 28 {
                return Err(bad("map run length too large"));
            }
            run |= ((b & 0x7F) as usize) << shift;
            if b & 0x80 == 0 {
                if b == 0 && shift > 0 {
                    return Err(bad("map run length is not minimally encoded"));
                }
                break;
            }
            shift += 7;
        }
        if run == 0 || run > n_cells - out.len() {
            return Err(bad("map run length out of range"));
        }
        out.resize(out.len() + run, label);
        prev = Some(label);
    }
    if out.len() != n_cells {
        return Err(bad("map does not cover the cell grid exactly"));
    }
    Ok(out)
}

impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let map = rle_encode(&self.cell_labels);
        let mut o = Vec::with_capacity(FIXED_LEN + ENTRY_LEN * self.patches.len() + map.len());
        o.extend_from_slice(MAGIC);
        o.extend_from_slice(&[VERSION, SEG_VERSION, SEL_VERSION, self.channels]);
        o.extend_from_slice(&self.width.to_be_bytes());
        o.extend_from_slice(&self.height.to_be_bytes());
        o.push(self.cell);
        o.push(self.patches.len() as u8);
        o.extend_from_slice(&self.carrier_pixels.to_be_bytes());
        o.extend_from_slice(&self.payload_len.to_be_bytes());
        o.extend_from_slice(&(map.len() as u32).to_be_bytes());
        for p in &self.patches {
            o.push(p.alg_id);
            o.push(p.param);
            o.extend_from_slice(&[0, 0]);
            o.extend_from_slice(&p.offset.to_be_bytes());
            o.extend_from_slice(&p.length.to_be_bytes());
        }
        o.extend_from_slice(&map);
        o
    }

    pub fn used(&self) -> impl Iterator<Item = (usize, &PatchEntry)> {
        self.patches.iter().enumerate().filter(|(_, p)| p.alg_id != 0)
    }

    /// Number of grid cells per patch (derived from the authenticated map).
    pub fn cell_counts(&self) -> Vec<usize> {
        let mut c = vec![0usize; self.patches.len()];
        for &l in &self.cell_labels {
            c[l as usize] += 1;
        }
        c
    }

    /// Non-secret summary for events / API responses.
    pub fn summary(&self) -> Value {
        let counts = self.cell_counts();
        let patches: Vec<Value> = self.patches.iter().enumerate().map(|(i, p)| {
            if p.alg_id == 0 {
                json!({"patch_id": i, "used": false, "cells": counts[i]})
            } else {
                json!({"patch_id": i, "used": true, "cells": counts[i], "alg_id": p.alg_id, "algorithm": ALGS[p.alg_id as usize - 1],
                       "param": p.param, "payload_offset": p.offset, "payload_length": p.length})
            }
        }).collect();
        json!({"version": VERSION, "segmentation_version": SEG_VERSION_NAME, "selector_version": SEL_VERSION_NAME,
               "width": self.width, "height": self.height, "channels": self.channels, "cell_size": self.cell,
               "patch_count": self.patches.len(), "used_patches": self.used().count(), "carrier_pixels": self.carrier_pixels,
               "payload_len": self.payload_len, "patches": patches})
    }

    /// algorithm name -> (patches, payload bytes), in algorithm-id order.
    pub fn algorithms_used(&self) -> Vec<(&'static str, usize, u64)> {
        let mut acc = [(0usize, 0u64); 10];
        for (_, p) in self.used() {
            acc[p.alg_id as usize - 1].0 += 1;
            acc[p.alg_id as usize - 1].1 += p.length as u64;
        }
        acc.iter().enumerate().filter(|(_, a)| a.0 > 0).map(|(i, a)| (ALGS[i], a.0, a.1)).collect()
    }
}

/// Strict parse. `max_dim` bounds width/height. Every reachable failure is `MANIFEST_INVALID`,
/// `MANIFEST_TOO_LARGE`, `UNSUPPORTED_VERSION` or `UNKNOWN_ALGORITHM`.
pub fn parse(data: &[u8], max_dim: u32) -> Result<Manifest, StegoError> {
    if data.len() > MAX_MANIFEST_BYTES {
        return Err(StegoError::new("MANIFEST_TOO_LARGE", stage::VERIFY, 422, "manifest exceeds the maximum size"));
    }
    if data.len() < FIXED_LEN + ENTRY_LEN {
        return Err(bad("manifest truncated"));
    }
    if &data[..4] != MAGIC {
        return Err(bad("bad manifest magic"));
    }
    if data[4] != VERSION || data[5] != SEG_VERSION || data[6] != SEL_VERSION {
        return Err(StegoError::new("UNSUPPORTED_VERSION", stage::VERIFY, 422, "unsupported manifest, segmentation or selector version"));
    }
    let channels = data[7];
    let width = u16::from_be_bytes([data[8], data[9]]);
    let height = u16::from_be_bytes([data[10], data[11]]);
    let cell = data[12];
    let n = data[13] as usize;
    let carrier_pixels = u16::from_be_bytes([data[14], data[15]]);
    let payload_len = u32::from_be_bytes(data[16..20].try_into().unwrap());
    let map_len = u32::from_be_bytes(data[20..24].try_into().unwrap()) as usize;
    if !(channels == 1 || channels == 3) || !matches!(cell, 4 | 8 | 16) {
        return Err(bad("invalid channel count or cell size"));
    }
    if width == 0 || height == 0 || width as u32 > max_dim || height as u32 > max_dim {
        return Err(bad("image dimensions out of bounds"));
    }
    if n == 0 || n > MAX_PATCHES {
        return Err(bad("patch count out of range"));
    }
    // checked: map_len is attacker-controlled
    let expect_len = FIXED_LEN.checked_add(ENTRY_LEN * n).and_then(|x| x.checked_add(map_len)).ok_or_else(|| bad("manifest length overflow"))?;
    if data.len() != expect_len {
        return Err(bad("manifest length does not match its declared sizes"));
    }
    let r = carrier_pixels_for(data.len(), channels);
    if carrier_pixels as usize != r || r > (width as usize * height as usize) / 8 {
        return Err(bad("carrier_pixels inconsistent with the manifest size or the image"));
    }
    if (payload_len as usize) < TAG_LEN + 1 {
        return Err(bad("payload length too small"));
    }
    let mut patches = Vec::with_capacity(n);
    let mut expect: u64 = 0;
    for i in 0..n {
        let e = &data[FIXED_LEN + ENTRY_LEN * i..FIXED_LEN + ENTRY_LEN * (i + 1)];
        let (alg, param) = (e[0], e[1]);
        let offset = u32::from_be_bytes(e[4..8].try_into().unwrap());
        let length = u32::from_be_bytes(e[8..12].try_into().unwrap());
        if e[2] != 0 || e[3] != 0 {
            return Err(bad("non-zero patch flags"));
        }
        if alg == 0 {
            if param != 0 || offset != 0 || length != 0 {
                return Err(bad("unused patch must have zero parameter, offset and length"));
            }
        } else {
            if alg as usize > ALGS.len() {
                return Err(StegoError::new("UNKNOWN_ALGORITHM", stage::VERIFY, 422, "manifest names an algorithm id outside the whitelist"));
            }
            let (lo, hi) = PARAM_RANGE[alg as usize - 1];
            if param < lo || param > hi {
                return Err(bad("patch parameter outside the range allowed for its algorithm"));
            }
            if length == 0 || offset as u64 != expect {
                return Err(bad("payload chunks are not sequential and contiguous"));
            }
            expect += length as u64; // u64: cannot overflow with u32 operands
            if expect > payload_len as u64 {
                return Err(bad("payload chunks exceed the payload length"));
            }
        }
        patches.push(PatchEntry { alg_id: alg, param, offset, length });
    }
    if expect != payload_len as u64 {
        return Err(bad("payload chunks do not cover the payload exactly once"));
    }
    let (rows, cols) = grid(height, width, cell);
    let cell_labels = rle_decode(&data[FIXED_LEN + ENTRY_LEN * n..], rows * cols, n)?;
    let mut seen = vec![false; n];
    for &l in &cell_labels {
        seen[l as usize] = true;
    }
    if seen.iter().any(|s| !s) {
        return Err(bad("a patch id has no cells in the map"));
    }
    Ok(Manifest { channels, width, height, cell, carrier_pixels, payload_len, patches, cell_labels })
}

/// Deterministic sample manifest (used by the in-process fake backend and by tests).
pub fn sample(width: u16, height: u16, channels: u8, payload_len: u32, algs: &[(u8, u8)]) -> Manifest {
    let cell = 8u8;
    let (rows, cols) = grid(height, width, cell);
    let n = algs.len() + 1; // patch 0 stays unused
    let mut labels = vec![0u8; rows * cols];
    for r in 0..rows {
        for c in 0..cols {
            // diagonal bands -> irregular (non-rectangular) patches
            labels[r * cols + c] = (((r + 2 * c) * n) / (rows + 2 * cols)) as u8;
        }
    }
    let map_len = rle_encode(&labels).len();
    let mlen = FIXED_LEN + ENTRY_LEN * n + map_len;
    let mut patches = vec![PatchEntry { alg_id: 0, param: 0, offset: 0, length: 0 }];
    let k = algs.len() as u32;
    let mut off = 0u32;
    for (i, (alg, param)) in algs.iter().enumerate() {
        let len = if i as u32 == k - 1 { payload_len - off } else { payload_len / k };
        patches.push(PatchEntry { alg_id: *alg, param: *param, offset: off, length: len });
        off += len;
    }
    Manifest { channels, width, height, cell, carrier_pixels: carrier_pixels_for(mlen, channels) as u16, payload_len, patches, cell_labels: labels }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> Manifest {
        sample(128, 96, 3, 200, &[(1, 0), (6, 4), (9, 8)])
    }

    #[test]
    fn documented_test_vector_matches_the_python_encoder() {
        // docs/patchwise-transport.md section 6 (python-service/tests/test_patch_manifest.py pins the same bytes)
        let labels = vec![0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1];
        let man = Manifest { channels: 3, width: 64, height: 64, cell: 16, carrier_pixels: 384, payload_len: 40,
            patches: vec![PatchEntry { alg_id: 0, param: 0, offset: 0, length: 0 }, PatchEntry { alg_id: 1, param: 0, offset: 0, length: 40 }], cell_labels: labels };
        let bytes = man.encode();
        assert_eq!(hex::encode(&bytes), "494f504d020102030040004010020180000000280000001000000000000000000000000001000000000000000000002800020102000101030001010300030101");
        assert_eq!(parse(&bytes, 4096).unwrap(), man);
        assert_eq!(carrier_pixels_for(64, 3), 384);
        // a v1 manifest (version byte 1, reserved_rows field) is not accepted
        let mut v1 = bytes.clone();
        v1[4] = 1;
        assert_eq!(parse(&v1, 4096).unwrap_err().code, "UNSUPPORTED_VERSION");
    }

    #[test]
    fn round_trip_and_summary() {
        let man = m();
        let b = man.encode();
        let p = parse(&b, 4096).unwrap();
        assert_eq!(p, man);
        assert_eq!(p.used().count(), 3);
        let s = p.summary();
        assert_eq!(s["patch_count"], 4);
        assert_eq!(s["patches"][2]["algorithm"], "dwt");
        assert_eq!(p.algorithms_used().iter().map(|a| a.0).collect::<Vec<_>>(), vec!["lsb_replacement", "dwt", "wow"]);
        assert_eq!(p.cell_counts().iter().sum::<usize>(), 12 * 16);
    }

    fn put(b: &[u8], off: usize, v: &[u8]) -> Vec<u8> {
        let mut o = b.to_vec();
        o[off..off + v.len()].copy_from_slice(v);
        o
    }

    #[test]
    fn every_malformed_field_is_rejected() {
        let b = m().encode();
        let e1 = FIXED_LEN + ENTRY_LEN; // first used entry
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (put(&b, 0, b"XOPM"), "MANIFEST_INVALID"),
            (put(&b, 4, &[3]), "UNSUPPORTED_VERSION"),
            (put(&b, 4, &[1]), "UNSUPPORTED_VERSION"), // manifest-v1 (bootstrap-v2 era)
            (put(&b, 5, &[2]), "UNSUPPORTED_VERSION"),
            (put(&b, 6, &[1]), "UNSUPPORTED_VERSION"),           // selector kb-bm25-1 (id 1) is retired
            (put(&b, 6, &[3]), "UNSUPPORTED_VERSION"),
            (put(&b, 7, &[2]), "MANIFEST_INVALID"),
            (put(&b, 8, &[0, 0]), "MANIFEST_INVALID"),
            (put(&b, 8, &[0xFF, 0xFF]), "MANIFEST_INVALID"),
            (put(&b, 10, &[0, 88]), "MANIFEST_INVALID"),          // height changed -> grid mismatch
            (put(&b, 12, &[5]), "MANIFEST_INVALID"),
            (put(&b, 12, &[16]), "MANIFEST_INVALID"),             // valid cell, wrong grid
            (put(&b, 13, &[0]), "MANIFEST_INVALID"),
            (put(&b, 13, &[5]), "MANIFEST_INVALID"),
            (put(&b, 14, &[0, 1]), "MANIFEST_INVALID"),
            (put(&b, 14, &(m().carrier_pixels + 1).to_be_bytes()), "MANIFEST_INVALID"),
            (put(&b, 16, &[0, 0, 0, 201]), "MANIFEST_INVALID"),
            (put(&b, 16, &[0xFF; 4]), "MANIFEST_INVALID"),
            (put(&b, 20, &[0xFF, 0xFF, 0xFF, 0xF0]), "MANIFEST_INVALID"),
            (put(&b, e1, &[11]), "UNKNOWN_ALGORITHM"),
            (put(&b, e1, &[0xFF]), "UNKNOWN_ALGORITHM"),
            (put(&b, e1 + 1, &[3]), "MANIFEST_INVALID"),          // lsb_replacement takes no parameter
            (put(&b, e1 + ENTRY_LEN + 1, &[0]), "MANIFEST_INVALID"), // dwt needs an explicit step
            (put(&b, e1 + 2 * ENTRY_LEN + 1, &[1]), "MANIFEST_INVALID"), // STC rate below 1/2
            (put(&b, e1 + 2, &[0, 1]), "MANIFEST_INVALID"),
            (put(&b, e1 + 4, &[0, 0, 0, 1]), "MANIFEST_INVALID"),
            (put(&b, e1 + ENTRY_LEN + 4, &[0, 0, 0, 65]), "MANIFEST_INVALID"), // overlap
            (put(&b, e1 + ENTRY_LEN + 4, &[0, 0, 0, 67]), "MANIFEST_INVALID"), // gap
            (put(&b, e1 + 8, &[0, 0, 0, 0]), "MANIFEST_INVALID"),
            (put(&b, e1 + 8, &[0xFF; 4]), "MANIFEST_INVALID"),
            (put(&b, FIXED_LEN + 4, &[0, 0, 0, 9]), "MANIFEST_INVALID"), // unused patch with an offset
            (b[..b.len() - 1].to_vec(), "MANIFEST_INVALID"),
            ([b.clone(), vec![0]].concat(), "MANIFEST_INVALID"),
            (b[..30].to_vec(), "MANIFEST_INVALID"),
            (vec![], "MANIFEST_INVALID"),
            (vec![0; MAX_MANIFEST_BYTES + 1], "MANIFEST_TOO_LARGE"),
        ];
        for (i, (bytes, code)) in cases.iter().enumerate() {
            assert_eq!(parse(bytes, 4096).map(|_| ()).map_err(|e| e.code).err().as_deref(), Some(*code), "case {i}");
        }
        assert_eq!(parse(&b, 100).unwrap_err().code, "MANIFEST_INVALID", "dimension limit");
    }

    #[test]
    fn map_must_be_canonical_complete_and_reference_every_patch() {
        let man = m();
        let n_cells = man.cell_labels.len();
        assert!(rle_decode(&rle_encode(&man.cell_labels), n_cells, 4).is_ok());
        let bad_maps: Vec<Vec<u8>> = vec![
            vec![0, 3, 1, 3, 2, 5],                    // too few
            vec![0, 3, 1, 3, 2, 7],                    // too many
            vec![0, 3, 1, 3, 3, 6],                    // label >= n
            vec![0, 2, 0, 1, 1, 3, 2, 6],              // non-canonical
            vec![0, 0, 1, 6, 2, 6],                    // zero run
            vec![0, 0x83, 0x00, 1, 3, 2, 6],           // non-minimal varint
            vec![0, 3, 1, 3, 2],                       // truncated
            vec![0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1],  // run too large
        ];
        for (i, mp) in bad_maps.iter().enumerate() {
            assert!(rle_decode(mp, 12, 3).is_err(), "map case {i}");
        }
        assert_eq!(rle_decode(&[0, 3, 1, 3, 2, 6], 12, 3).unwrap().len(), 12);
        // patch 3 erased from the map
        let mut lab = man.cell_labels.clone();
        for l in lab.iter_mut() {
            if *l == 3 { *l = 2; }
        }
        let mut broken = man.clone();
        broken.cell_labels = lab;
        let mut enc = broken.encode();
        // keep carrier_pixels consistent with the (shorter) manifest so that only the map check can fail
        let rr = carrier_pixels_for(enc.len(), 3) as u16;
        enc[14..16].copy_from_slice(&rr.to_be_bytes());
        assert_eq!(parse(&enc, 4096).unwrap_err().code, "MANIFEST_INVALID");
    }
}
