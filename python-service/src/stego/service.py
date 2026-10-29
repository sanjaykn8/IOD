"""Orchestration: cover -> select -> embed -> verify -> save -> verify -> descriptor."""

import base64
import binascii
import hashlib
import logging
import time

import numpy as np

from . import artifacts, codec, config, cover as cover_mod, images, metrics, selector
from .algorithms import BY_NAME, get_by_name
from .errors import StegoError

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
    """Save the cover as <id>.cover.png (unless it already is a stored test cover)."""
    if cov.source == "test_cover":
        return cov.artifact_id, store.read(cov.artifact_id, "cover")
    aid = artifact_id or artifacts.new_id()
    png = images.encode_png(cov.array)
    store.write(aid, "cover", png)
    return aid, png


def _parse_algorithm(req):
    alg = req.get("algorithm")
    if alg is None:
        return None, None
    get_by_name(alg)
    param = req.get("param")
    if param is not None:
        BY_NAME[alg].resolve_param(param)
    return alg, param


def capture(req, store=None):
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    t0 = time.perf_counter()
    cov = cover_mod.acquire(req.get("cover"), limits, store)
    t1 = _ms(t0)
    aid, png = _persist_cover(cov, store)
    store.enforce_retention(keep_id=aid)
    return {"ok": True, "cover": cover_descriptor(cov, aid, png), "timings_ms": {"capture": t1, "save": _ms(t0) - t1}}


def analyze(req, store=None):
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    fb = req.get("frame_bytes")
    if isinstance(fb, bool) or not isinstance(fb, int):
        raise StegoError("INVALID_REQUEST", "frame_bytes must be an integer")
    algorithm, param = _parse_algorithm(req)
    t0 = time.perf_counter()
    cov = cover_mod.acquire(req.get("cover"), limits, store)
    t_cap = _ms(t0)
    t1 = time.perf_counter()
    selection = selector.select(cov.array, fb, req.get("priority"), req.get("policy"), forced=algorithm,
                                forced_param=param, max_frame_bytes=limits.max_frame_bytes)
    t_sel = _ms(t1)
    t2 = time.perf_counter()
    aid, png = _persist_cover(cov, store)
    store.enforce_retention(keep_id=aid)
    log.info("analyze ok frame_bytes=%d selected=%s", fb, selection["selected"])
    return {"ok": True, "selection": selection, "cover": cover_descriptor(cov, aid, png),
            "timings_ms": {"capture": t_cap, "select": t_sel, "save": _ms(t2)}}


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
    if len(frame) < 1:
        raise StegoError("INVALID_REQUEST", "frame must not be empty")
    return frame


def encode(req, store=None):
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    frame = _decode_frame(req, limits)
    algorithm, param = _parse_algorithm(req)
    timings = {}
    t = time.perf_counter()
    cov = cover_mod.acquire(req.get("cover"), limits, store)
    timings["capture"] = _ms(t)

    t = time.perf_counter()
    selection = selector.select(cov.array, len(frame), req.get("priority"), req.get("policy"), forced=algorithm,
                                forced_param=param, max_frame_bytes=limits.max_frame_bytes)
    timings["select"] = _ms(t)
    alg = BY_NAME[selection["selected"]]
    eff_param = selection["selected_param"]

    t = time.perf_counter()
    stego, outcome = codec.embed_frame(cov.array, alg, eff_param, frame)
    timings["embed"] = _ms(t)

    t = time.perf_counter()
    got, bs, _ = codec.extract_frame(stego, limits)
    if got != frame or bs.alg_id != alg.id or bs.param != eff_param or bs.frame_len != len(frame):
        raise StegoError("EMBED_VERIFY_FAILED", "in-process extract did not match embedded frame")
    m = metrics.compute(cov.array, stego)
    png = images.encode_png(stego)
    timings["verify"] = _ms(t)

    t = time.perf_counter()
    aid = artifacts.new_id()
    wrote_cover = cov.source != "test_cover"
    cover_png = None
    try:
        if wrote_cover:
            cover_png = images.encode_png(cov.array)
            store.write(aid, "cover", cover_png)
            cover_id = aid
        else:
            cover_id = cov.artifact_id
            cover_png = store.read(cover_id, "cover")
        store.write(aid, "stego", png)
        timings["save"] = _ms(t)
        t = time.perf_counter()
        reread, _tr = images.decode_png(store.read(aid, "stego"), limits)
        got2, _, _ = codec.extract_frame(reread, limits)
        if got2 != frame or not np.array_equal(reread, stego):
            raise StegoError("EMBED_VERIFY_FAILED", "saved PNG did not round-trip")
        timings["verify"] = round(timings["verify"] + _ms(t), 3)
    except Exception:
        store.delete(aid, ("stego", "cover") if wrote_cover else ("stego",))
        raise
    store.enforce_retention(keep_id=aid)
    log.info("encode ok alg=%s frame_bytes=%d size=%d", alg.name, len(frame), len(png))
    return {
        "ok": True, "artifact_id": aid,
        "stego": {"path_name": f"{aid}.png", "sha256": _sha(png), "size": len(png),
                  "width": int(stego.shape[1]), "height": int(stego.shape[0]),
                  "mode": images.mode_of(stego), "channels": images.channels_of(stego), "format": "PNG"},
        "cover": cover_descriptor(cov, cover_id, cover_png),
        "selection": selection,
        "embed": {"algorithm": alg.name, "alg_id": alg.id, "param": eff_param,
                  "params": {"requested": eff_param, "effective": outcome.param, **outcome.detail},
                  "capacity_bytes": outcome.capacity_bits // 8, "frame_len": len(frame),
                  "used_fraction": round(len(frame) * 8 / outcome.capacity_bits, 8),
                  "metrics": m},
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
    frame, bs, alg = codec.extract_frame(arr, limits)
    t_ext = _ms(t)
    return {
        "ok": True, "frame_b64": base64.b64encode(frame).decode("ascii"),
        "bootstrap": {"version": bs.version, "alg_id": bs.alg_id, "algorithm": alg.name,
                      "param": bs.param, "frame_len": bs.frame_len},
        "image": {"width": int(arr.shape[1]), "height": int(arr.shape[0]), "mode": images.mode_of(arr),
                  "channels": images.channels_of(arr), "format": "PNG", "size": len(data), "sha256": _sha(data)},
        "timings_ms": {"read": t_read, "extract": t_ext},
    }


def health(store=None):
    import PIL
    from . import SERVICE_VERSION
    store = store or get_store()
    adapter = cover_mod.get_camera_adapter()
    lim = config.Limits()
    return {
        "ok": True, "service": "python-stego", "version": SERVICE_VERSION,
        "algorithms": [{"id": a.id, "name": a.name} for a in BY_NAME.values()],
        "limits": {"max_width": lim.max_width, "max_height": lim.max_height,
                   "max_frame_bytes": lim.max_frame_bytes, "min_dim": lim.min_dim},
        "artifact_dir_writable": store.writable(),
        "camera": {"backend": adapter.backend, "opencv_available": adapter.opencv_available(),
                   "mode": config.camera_mode()},
        "numpy": np.__version__, "pillow": PIL.__version__,
    }
