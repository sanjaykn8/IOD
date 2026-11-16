"""Sender-side planning: segmentation -> features -> capacity -> sequential allocation ->
per-patch KB retrieval (top-1) -> dry run -> manifest. No keys, no payload bytes: the planner
only knows the payload LENGTH (wire + tag) that the patches must carry.

Allocation rule (deterministic, documented in docs/patchwise-transport.md):
  1. usable patches = patches where at least one algorithm passes the structural filters
     with a measured capacity of >= 1 byte; cap_i = the largest such capacity (bytes).
  2. k = clamp(ceil(L / target_chunk_bytes), 1, #usable). Patches are ranked by
     gradient_mean (descending; ties: lower id) and the shortest prefix with >= k patches
     whose capacities sum to >= L is chosen. If all usable patches cannot hold L -> refine.
  3. Water-filling over the chosen patches in order of increasing cap_i (ties: lower id):
     chunk_i = min(cap_i, ceil(remaining / patches_left)).
  4. Offsets are assigned in ascending patch id: the payload is cut into contiguous,
     non-overlapping chunks covering [0, L) exactly once.
"""

import hashlib
import time
from dataclasses import dataclass

import numpy as np

from ..algorithms import BY_NAME, NAMES
from ..algorithms.adaptive import AdaptiveStc
from ..errors import StegoError
from . import SELECTOR_VERSION, features as F, kb as KB, manifest as M, segment as S
from .region import CoverCtx, Region

DEFAULT_TARGET_CHUNK = 48


@dataclass
class Plan:
    manifest: bytes
    parsed: M.Manifest
    seg: S.Segmentation
    diagnostics: dict


def test_bytes(n, patch_id):
    """Deterministic pseudo-random bytes for the dry run (never real payload)."""
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(b"IOD-DRYRUN-v1" + patch_id.to_bytes(2, "big") + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return bytes(out[:n])


def _patch_tables(arr, eff, feats, n):
    ch = 1 if arr.ndim == 2 else 3
    regions, caps, sups = [], [], []
    for i in range(n):
        reg = Region.from_labels(eff, i)
        regions.append(reg)
        sup, cap = {}, {}
        for name in NAMES:
            alg = BY_NAME[name]
            ok, why = alg.support(arr, reg)
            sup[name] = (ok, why)
            cap[name] = int(alg.capacity_bits(arr, reg)) if ok else 0
        f = feats[i]
        f["channels"] = ch
        f["blocks8"] = int(reg.blocks(8)[0].size)
        f["blocks2"] = int(reg.blocks(2)[0].size)
        f["block8_fill"] = round(64.0 * f["blocks8"] / f["usable_pixels"], 6) if f["usable_pixels"] else 0.0
        f["capacity_bits"] = dict(cap)
        f["carriers"] = {"samples": reg.n_pixels * ch, "blocks8": f["blocks8"], "blocks2": f["blocks2"]}
        caps.append(cap)
        sups.append(sup)
    return regions, caps, sups


def _allocate(feats, struct_caps, total, target_chunk):
    usable = [i for i, c in enumerate(struct_caps) if c >= 1]
    if sum(struct_caps[i] for i in usable) < total:
        return None, usable
    k = max(1, min(len(usable), -(-total // target_chunk)))
    ranked = sorted(usable, key=lambda i: (-feats[i]["gradient_mean"], i))
    chosen, acc = [], 0
    for i in ranked:
        chosen.append(i)
        acc += struct_caps[i]
        if len(chosen) >= k and acc >= total:
            break
    remaining, left = total, len(chosen)
    chunk = {}
    for i in sorted(chosen, key=lambda i: (struct_caps[i], i)):
        c = min(struct_caps[i], -(-remaining // left))
        chunk[i] = c
        remaining -= c
        left -= 1
    if remaining:
        return None, usable
    return {i: c for i, c in chunk.items() if c > 0}, usable


def plan(arr, payload_len, seg_cfg=None, min_level=0, target_chunk=DEFAULT_TARGET_CHUNK, dry_run=True, should_stop=None):
    """`should_stop()` (optional) is polled before every refinement level after the first; when it returns
    True the planner gives up with GENERATION_BUDGET_EXCEEDED instead of starting another level."""
    seg_cfg = seg_cfg or S.SegConfig()
    if isinstance(payload_len, bool) or not isinstance(payload_len, int) or payload_len < M.TAG_LEN + 1:
        raise StegoError("INVALID_REQUEST", "payload_bytes must be an integer > 32")
    if not 8 <= target_chunk <= 65536:
        raise StegoError("INVALID_REQUEST", "target_chunk_bytes out of range")
    h, w = arr.shape[:2]
    ch = 1 if arr.ndim == 2 else 3
    kbv = KB.load()["kb_version"]
    attempts = []
    t_all = time.perf_counter()
    for level in range(min_level, seg_cfg.max_refine_levels + 1):
        if attempts and should_stop is not None and should_stop():
            raise StegoError("GENERATION_BUDGET_EXCEEDED", "processing budget reached between refinement levels",
                             {"attempts": attempts, "payload_bytes": payload_len})
        t0 = time.perf_counter()
        seg = S.segment(arr, seg_cfg, level)
        n = seg.n_regions
        att = {"level": level, "regions": n, "outcome": None}
        attempts.append(att)
        map_bytes = M.rle_encode(seg.cell_labels)
        mlen = M.manifest_len_for(n, len(map_bytes))
        rrows = M.reserved_rows_for(mlen, w, ch)
        att.update(manifest_bytes=mlen, reserved_rows=rrows)
        if mlen > M.MAX_MANIFEST_BYTES or rrows * 2 > h:
            att["outcome"] = "MANIFEST_DOES_NOT_FIT"
            continue
        eff = seg.labels.copy()
        eff[:rrows, :] = 255
        feats = F.compute(arr, seg.labels, n, rrows)
        regions, caps, sups = _patch_tables(arr, eff, feats, n)
        # largest structurally admissible capacity per patch (bytes)
        struct_caps = []
        for i in range(n):
            ok_names = KB.structural(feats[i], sups[i])
            struct_caps.append(max([caps[i][nm] // 8 for nm, ok in ok_names.items() if ok] or [0]))
        alloc, usable = _allocate(feats, struct_caps, payload_len, target_chunk)
        att.update(usable_patches=len(usable), capacity_bytes=int(sum(struct_caps)))
        if alloc is None:
            att["outcome"] = "CAPACITY_INSUFFICIENT"
            continue
        ctx = CoverCtx(arr)
        scratch = arr.copy() if dry_run else None
        entries, patches, failed = [], [], None
        offset = 0
        for i in range(n):
            f = feats[i]
            rec = {"patch_id": i, "used": i in alloc, "features": f, "max_capacity_bytes": struct_caps[i]}
            if i not in alloc:
                entries.append(M.PatchEntry(0, 0, 0, 0))
                rec.update(selected=None, payload_offset=None, payload_length=0, retrieval=None)
                patches.append(rec)
                continue
            c = alloc[i]
            q = dict(f)
            q["bits_per_sample"] = round(8.0 * c / max(1, f["usable_pixels"] * ch), 8)
            res = KB.retrieve(q, c, caps[i], sups[i])
            res["query_features"] = {k: q[k] for k in ("usable_pixels", "variance", "entropy", "gradient_mean", "edge_density", "texture",
                                                         "saturation", "hf_energy_ratio", "compactness", "aspect_ratio", "block8_fill",
                                                         "bits_per_sample", "channels", "mean")}
            rec["retrieval"] = res
            name = res["selected"]
            if name is None:
                failed = (i, "NO_ELIGIBLE_ALGORITHM")
                rec.update(selected=None, payload_offset=offset, payload_length=c)
                patches.append(rec)
                break
            alg = BY_NAME[name]
            param = alg.choose_w(arr, regions[i], c) if isinstance(alg, AdaptiveStc) else alg.resolve_param(0)
            cap_bits = int(alg.capacity_bits(arr, regions[i], param))
            rec.update(selected=name, alg_id=alg.id, param=param, variant=alg.variant, payload_offset=offset, payload_length=c,
                       measured_capacity_bytes=cap_bits // 8, utilisation=round(8.0 * c / cap_bits, 6) if cap_bits else None)
            if cap_bits < 8 * c or (isinstance(alg, AdaptiveStc) and param < 2):
                failed = (i, "CAPACITY_CHECK_FAILED")
                patches.append(rec)
                break
            if dry_run:
                td = time.perf_counter()
                data = test_bytes(c, i)
                try:
                    alg.embed(ctx, regions[i], scratch, data, param)
                    ok = alg.extract(scratch, regions[i], c, param) == data
                    err = None if ok else "DRY_RUN_MISMATCH"
                except StegoError as exc:
                    ok, err = False, exc.code
                rec["dry_run"] = {"ok": ok, "error": err, "ms": round((time.perf_counter() - td) * 1000, 3)}
                if not ok:
                    failed = (i, "DRY_RUN_FAILED:" + str(err))
                    patches.append(rec)
                    break
            entries.append(M.PatchEntry(alg.id, param, offset, c))
            offset += c
            patches.append(rec)
        if failed is not None:
            att.update(outcome=failed[1], failed_patch=failed[0])
            continue
        man = M.Manifest(ch, w, h, seg.cell, rrows, payload_len, tuple(entries), seg.cell_labels)
        data = M.pack(man)
        if len(data) != mlen:
            raise StegoError("INTERNAL_ERROR", "manifest size prediction mismatch")
        att["outcome"] = "OK"
        att["ms"] = round((time.perf_counter() - t0) * 1000, 3)
        used = [p for p in patches if p["used"]]
        counts = {}
        for p in used:
            counts[p["selected"]] = counts.get(p["selected"], 0) + 1
        diag = {
            "selector_version": SELECTOR_VERSION, "kb_version": kbv, "segmentation": seg.info, "refinement_level": level,
            "attempts": attempts, "payload_bytes": payload_len, "manifest_bytes": mlen, "reserved_rows": rrows,
            "bootstrap_carrier_bits": M.carrier_bits(mlen), "patch_count": n, "used_patches": len(used),
            "algorithms_used": dict(sorted(counts.items())), "target_chunk_bytes": target_chunk,
            "allocation_rule": "texture-ranked prefix, water-filling by capacity, offsets in ascending patch id",
            "patches": patches, "plan_ms": round((time.perf_counter() - t_all) * 1000, 3),
        }
        return Plan(data, M.parse(data), seg, diag)
    last = attempts[-1]["outcome"] if attempts else "NO_ATTEMPT"
    code = "PATCH_CAPACITY_INSUFFICIENT" if last in ("CAPACITY_INSUFFICIENT", "MANIFEST_DOES_NOT_FIT") else "NO_ELIGIBLE_ALGORITHM"
    raise StegoError(code, "the cover cannot carry this frame patch-wise within the refinement limit",
                     {"attempts": attempts, "payload_bytes": payload_len, "last_outcome": last})
