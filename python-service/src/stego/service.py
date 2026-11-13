"""Orchestration of the patch-wise transport (image side only; no keys, no MAC).

plan    : cover -> adaptive segmentation -> patch features -> KB retrieval -> allocation -> manifest
encode  : Frame v2 (built and authenticated by Rust) -> patch embedding -> PNG save -> re-read -> verify
extract : saved PNG -> preamble -> manifest -> patch chunks -> reconstructed frame (for Rust to verify)
"""

import base64
import binascii
import hashlib
import logging
import time

import numpy as np

from . import artifacts, codec, config, cover as cover_mod, images, metrics
from .algorithms import BY_ID, BY_NAME
from .errors import StegoError
from .patch import FORMAT_VERSION, SEGMENTATION_VERSION, SELECTOR_VERSION, kb as KB, manifest as M, planner, segment as S

log = logging.getLogger("stego")


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000.0, 3)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def get_store():
    return artifacts.default_store()


def cover_descriptor(cov, artifact_id, png_bytes):
    arr = cov.array
    d = {
        "artifact_id": artifact_id, "source": cov.source, "fallback_reason": cov.fallback_reason,
        "width": int(arr.shape[1]), "height": int(arr.shape[0]), "mode": images.mode_of(arr),
        "channels": images.channels_of(arr), "transforms": list(cov.transforms), "sha256": _sha(png_bytes),
    }
    if cov.seed is not None:
        d["seed"] = cov.seed
    return d


def _persist_cover(cov, store, artifact_id=None):
    """Save the cover as <id>.cover.png (unless it already is a stored cover)."""
    if cov.artifact_id is not None:
        return cov.artifact_id, store.read(cov.artifact_id, "cover")
    aid = artifact_id or artifacts.new_id()
    png = images.encode_png(cov.array)
    store.write(aid, "cover", png)
    return aid, png


def capture(req, store=None):
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    t0 = time.perf_counter()
    cov = cover_mod.acquire(req.get("cover"), limits, store)
    t1 = _ms(t0)
    aid, png = _persist_cover(cov, store)
    store.enforce_retention(keep_id=aid)
    return {"ok": True, "cover": cover_descriptor(cov, aid, png), "timings_ms": {"capture": t1, "save": _ms(t0) - t1}}


def upload_cover(req, store=None):
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    t0 = time.perf_counter()
    cov, aid, png = cover_mod.store_uploaded_cover(req.get("image_b64"), req.get("origin", "browser_webcam"), limits, store)
    return {"ok": True, "cover": cover_descriptor(cov, aid, png), "timings_ms": {"store": _ms(t0)}}


from .patch.render import overlay_png, palette  # noqa: E402,F401


def _seg_config(req):
    return S.parse_config(req.get("segmentation"))


def plan(req, store=None):
    """Cover analysis + segmentation + per-patch retrieval + allocation -> manifest (no payload bytes)."""
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    pb = req.get("payload_bytes")
    if isinstance(pb, bool) or not isinstance(pb, int) or not M.TAG_LEN < pb <= limits.max_frame_bytes:
        raise StegoError("INVALID_REQUEST", "payload_bytes must be an integer in (32, max_frame_bytes]")
    ml = req.get("min_level", 0)
    seg_cfg = _seg_config(req)
    if isinstance(ml, bool) or not isinstance(ml, int) or not 0 <= ml <= seg_cfg.max_refine_levels:
        raise StegoError("SEGMENTATION_FAILED" if isinstance(ml, int) and not isinstance(ml, bool) and ml > seg_cfg.max_refine_levels else "INVALID_REQUEST",
                         "refinement level exhausted or invalid", {"max_refine_levels": seg_cfg.max_refine_levels})
    tc = req.get("target_chunk_bytes", planner.DEFAULT_TARGET_CHUNK)
    if isinstance(tc, bool) or not isinstance(tc, int):
        raise StegoError("INVALID_REQUEST", "target_chunk_bytes must be an integer")
    t0 = time.perf_counter()
    cov = cover_mod.acquire(req.get("cover"), limits, store)
    t_cap = _ms(t0)
    t1 = time.perf_counter()
    pl = planner.plan(cov.array, pb, seg_cfg, ml, tc)
    t_plan = _ms(t1)
    t2 = time.perf_counter()
    aid, png = _persist_cover(cov, store)
    store.write_replace(aid, "seg", overlay_png(cov.array, pl.seg.labels, pl.seg.n_regions, pl.parsed.reserved_rows))
    store.write_replace(aid, "labels", images.encode_png(pl.seg.labels))
    store.enforce_retention(keep_id=aid)
    d = pl.diagnostics
    log.info("plan ok payload_bytes=%d patches=%d used=%d level=%d", pb, d["patch_count"], d["used_patches"], d["refinement_level"])
    return {"ok": True, "format_version": FORMAT_VERSION, "manifest_b64": base64.b64encode(pl.manifest).decode("ascii"),
            "manifest_sha256": _sha(pl.manifest), "plan": d, "cover": cover_descriptor(cov, aid, png),
            "inspection": {"segmentation_overlay": f"{aid}.seg.png", "label_map": f"{aid}.labels.png",
                           "palette": palette(pl.seg.n_regions).tolist()},
            "timings_ms": {"capture": t_cap, "plan": t_plan, "save": _ms(t2)}}


def _decode_frame(req, limits):
    b64 = req.get("frame_b64")
    if not isinstance(b64, str):
        raise StegoError("INVALID_REQUEST", "frame_b64 must be a base64 string")
    if len(b64) > ((limits.max_frame_bytes + 2) // 3) * 4 + 4:
        raise StegoError("FRAME_TOO_LARGE", "frame exceeds maximum", {"max_frame_bytes": limits.max_frame_bytes})
    try:
        frame = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StegoError("INVALID_REQUEST", "frame_b64 is not valid base64") from exc
    if len(frame) > limits.max_frame_bytes:
        raise StegoError("FRAME_TOO_LARGE", "frame exceeds maximum", {"max_frame_bytes": limits.max_frame_bytes})
    return frame


def manifest_summary(man):
    return {"version": M.MANIFEST_VERSION, "segmentation_version": SEGMENTATION_VERSION, "selector_version": SELECTOR_VERSION,
            "width": man.width, "height": man.height, "channels": man.channels, "cell_size": man.cell,
            "patch_count": len(man.patches), "reserved_rows": man.reserved_rows, "payload_len": man.payload_len,
            "patches": [{"patch_id": i, "alg_id": e.alg_id, "algorithm": BY_ID[e.alg_id].name if e.alg_id else None,
                         "param": e.param, "payload_offset": e.offset if e.alg_id else None, "payload_length": e.length}
                        for i, e in enumerate(man.patches)]}


def encode(req, store=None):
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    frame = _decode_frame(req, limits)
    spec = req.get("cover")
    if not isinstance(spec, dict) or spec.get("source") not in cover_mod.STORED_SOURCES:
        raise StegoError("INVALID_REQUEST", "encode needs the stored cover that was planned (cover.source test_cover/browser_webcam/uploaded)")
    timings = {}
    t = time.perf_counter()
    cov = cover_mod.acquire(spec, limits, store)
    timings["capture"] = _ms(t)

    t = time.perf_counter()
    stego, man, per_patch = codec.embed_frame(cov.array, frame, limits)
    timings["embed"] = _ms(t)

    t = time.perf_counter()
    got, _, _, _ = codec.extract_frame(stego, limits)
    if got != frame:
        raise StegoError("EMBED_VERIFY_FAILED", "in-process extract did not match the frame")
    m = metrics.compute(cov.array, stego)
    png = images.encode_png(stego)
    timings["verify"] = _ms(t)

    t = time.perf_counter()
    aid = artifacts.new_id()
    cover_id = cov.artifact_id
    cover_png = store.read(cover_id, "cover")
    try:
        store.write(aid, "stego", png)
        timings["save"] = _ms(t)
        t = time.perf_counter()
        reread, _tr = images.decode_png(store.read(aid, "stego"), limits)
        got2, _, _, ext = codec.extract_frame(reread, limits)   # the saved file, re-opened from disk
        if got2 != frame or not np.array_equal(reread, stego):
            raise StegoError("EMBED_VERIFY_FAILED", "saved PNG did not round-trip")
        status = {e["patch_id"]: e["status"] for e in ext}
        for p in per_patch:
            if p["used"]:
                p["extraction"] = "verified_from_saved_png" if status.get(p["patch_id"]) == "extracted" else "missing"
        diff = np.abs(stego.astype(np.int16) - cov.array.astype(np.int16))
        dmap = diff if diff.ndim == 2 else diff.max(axis=2)
        store.write(aid, "diff", images.encode_png(np.clip(dmap * 64, 0, 255).astype(np.uint8)))
        timings["verify"] = round(timings["verify"] + _ms(t), 3)
    except Exception:
        store.delete(aid, ("stego", "diff"))
        raise
    store.enforce_retention(keep_id=aid)
    used = [p for p in per_patch if p["used"]]
    log.info("encode ok frame_bytes=%d patches_used=%d size=%d", len(frame), len(used), len(png))
    return {
        "ok": True, "artifact_id": aid, "format_version": FORMAT_VERSION,
        "stego": {"path_name": f"{aid}.png", "sha256": _sha(png), "size": len(png),
                  "width": int(stego.shape[1]), "height": int(stego.shape[0]),
                  "mode": images.mode_of(stego), "channels": images.channels_of(stego), "format": "PNG"},
        "cover": cover_descriptor(cov, cover_id, cover_png),
        "embed": {"frame_len": len(frame), "manifest_len": len(frame) - M.FRAME_HEADER_LEN - man.payload_len,
                  "payload_len": man.payload_len, "patch_count": len(man.patches), "used_patches": len(used),
                  "reserved_rows": man.reserved_rows, "patches": per_patch, "metrics": m,
                  "exact_frame_recovery_from_saved_png": True},
        "timings_ms": timings,
    }


def extract_artifact(req, store=None):
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    aid = artifacts.validate_id(req.get("artifact_id"))
    t = time.perf_counter()
    data = store.read(aid, "stego")
    arr, _ = images.decode_png(data, limits)
    t_read = _ms(t)
    t = time.perf_counter()
    frame, man, pre, per_patch = codec.extract_frame(arr, limits)
    t_ext = _ms(t)
    return {
        "ok": True, "frame_b64": base64.b64encode(frame).decode("ascii"), "format_version": FORMAT_VERSION,
        "bootstrap": {"version": pre.version, "manifest_len": pre.manifest_len, "frame_len": pre.frame_len},
        "manifest": manifest_summary(man), "patches": per_patch, "resegmented": False,
        "image": {"width": int(arr.shape[1]), "height": int(arr.shape[0]), "mode": images.mode_of(arr),
                  "channels": images.channels_of(arr), "format": "PNG", "size": len(data), "sha256": _sha(data)},
        "timings_ms": {"read": t_read, "extract": t_ext},
    }


def knowledge_base():
    return dict(KB.public_view(), ok=True, format_version=FORMAT_VERSION, segmentation_version=SEGMENTATION_VERSION,
                segmentation_defaults=S.SegConfig().to_dict())


def health(store=None):
    import PIL
    from . import SERVICE_VERSION
    store = store or get_store()
    adapter = cover_mod.get_camera_adapter()
    lim = config.Limits()
    kb = KB.load()
    return {
        "ok": True, "service": "python-stego", "version": SERVICE_VERSION, "format_version": FORMAT_VERSION,
        "segmentation_version": SEGMENTATION_VERSION, "selector_version": SELECTOR_VERSION, "kb_version": kb["kb_version"],
        "algorithms": [a.describe() for a in sorted(BY_NAME.values(), key=lambda a: a.id)],
        "limits": {"max_width": lim.max_width, "max_height": lim.max_height,
                   "max_frame_bytes": lim.max_frame_bytes, "min_dim": lim.min_dim,
                   "max_patches": M.MAX_PATCHES, "max_manifest_bytes": M.MAX_MANIFEST_BYTES},
        "artifact_dir_writable": store.writable(),
        "camera": {"backend": adapter.backend, "opencv_available": adapter.opencv_available(),
                   "mode": config.camera_mode()},
        "numpy": np.__version__, "pillow": PIL.__version__,
    }
