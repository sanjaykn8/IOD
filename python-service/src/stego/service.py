"""Orchestration of the patch-wise transport (image side only; no keys, no MAC).

plan    : payload LENGTH -> fresh procedural cover candidates -> pre-screen -> adaptive segmentation ->
          patch features -> KB retrieval -> allocation -> manifest (for the best feasible candidate)
re-plan : the SAME stored generated cover, coarser segmentation (never a new image)
encode  : Frame v3 (built and authenticated by Rust) -> patch embedding into that stored cover ->
          bootstrap-v3 carrier (encrypted bits from Rust, written at the pixels its value stream maps to)
          -> PNG save -> re-read -> verify
carrier : saved PNG + value streams from Rust -> raw carrier bits (probe for discovery, then read)
extract : saved PNG + manifest validated by Rust + value stream -> patch chunks -> reconstructed frame

The service never derives, sees or stores a key: it maps the value streams Rust sends onto pixels.

The only operational cover source is the local generator (`stego.generator`). There is no camera, no
upload and no client-selected image, seed or algorithm.
"""

import base64
import binascii
import functools
import hashlib
import json
import logging
import time

import numpy as np

from . import artifacts, bootstrap as B, codec, config, images, metrics
from .algorithms import BY_ID, BY_NAME
from .errors import StegoError
from .generator import GENERATOR_VERSION, QUALITY_VERSION, families, profile, select
from .patch import FORMAT_VERSION, SEGMENTATION_VERSION, SELECTOR_VERSION, kb as KB, manifest as M, planner, policy as P, segment as S
from .patch.render import overlay_png, palette

log = logging.getLogger("stego")
COVER_SOURCE = "generated"
REMOVED_PLAN_FIELDS = ("cover", "seed", "cover_id", "test_cover_id", "image_b64", "algorithm", "algorithms", "priority", "source")


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000.0, 3)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def get_store():
    return artifacts.default_store()


def cover_descriptor(arr, artifact_id, png_bytes, gen):
    return {
        "artifact_id": artifact_id, "source": COVER_SOURCE, "width": int(arr.shape[1]), "height": int(arr.shape[0]),
        "mode": images.mode_of(arr), "channels": images.channels_of(arr), "sha256": _sha(png_bytes),
        "generator_version": gen.get("generator_version"), "profile": gen.get("profile"), "family": gen.get("family"),
        "seed_fingerprint": gen.get("seed_fingerprint"), "quality_score": gen.get("quality_score"),
    }


def _load_generated_cover(store, cover_id, limits):
    """Load a cover that THIS service generated (it has a generation record whose hash matches the PNG)."""
    artifacts.validate_id(cover_id, "cover_id")
    if not store.exists(cover_id, "gen") or not store.exists(cover_id, "cover"):
        raise StegoError("ARTIFACT_NOT_FOUND", "no generated cover with this id (only covers produced by the generator can be used)")
    png = store.read(cover_id, "cover")
    try:
        gen = json.loads(store.read(cover_id, "gen").decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise StegoError("ARTIFACT_NOT_FOUND", "generation record unreadable") from exc
    if not isinstance(gen, dict) or gen.get("cover_sha256") != _sha(png):
        raise StegoError("ARTIFACT_NOT_FOUND", "stored cover does not match its generation record")
    arr, _ = images.decode_png(png, limits)
    return arr, png, gen


def _reject_removed(req, what, allow=()):
    bad = sorted(k for k in REMOVED_PLAN_FIELDS if k in req and k not in allow)
    if bad:
        raise StegoError("INVALID_REQUEST", f"{what}: covers are generated locally; a cover source, image, seed or algorithm cannot be supplied",
                         {"fields": bad})


def _seg_config(req):
    return S.parse_config(req.get("segmentation"))


def _plan_carrier(req):
    """The frame's bootstrap-v3 value stream (Rust derives it from the placement key; we only map it)."""
    c = req.get("carrier")
    if not isinstance(c, dict) or c.get("version") != B.VERSION or set(c) - {"version", "values_b64"}:
        raise StegoError("INVALID_REQUEST", "plan needs carrier = {version: 3, values_b64} (bootstrap-v3 value stream)")
    return B.decode_values(c.get("values_b64"), "carrier.values_b64").astype(">u4").tobytes()


def plan(req, store=None):
    """Generate (or, for a re-plan, reload) the cover and plan the payload on it. No payload bytes involved."""
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    _reject_removed(req, "plan")
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
    values = _plan_carrier(req)
    pol = P.parse(req.get("policy"))
    plan_fn = functools.partial(planner.plan, carrier_values=values, policy=pol)
    replan_id = req.get("replan_cover_id")
    t0 = time.perf_counter()
    if replan_id is not None:
        # internal re-plan of ONE transmission: the exact stored cover, a coarser segmentation, no generation
        if req.get("cover_generation") is not None:
            raise StegoError("INVALID_REQUEST", "a re-plan reuses the stored cover; cover_generation must not be sent with replan_cover_id")
        arr, png, stored = _load_generated_cover(store, replan_id, limits)
        t1 = time.perf_counter()
        pl = plan_fn(arr, pb, seg_cfg, ml, tc)
        gen = dict(stored["generation"], reused_for_replan=True, replan_min_level=ml)
        timings = {"generate": 0.0, "prescreen": 0.0, "plan": _ms(t1), "selection_total": _ms(t0)}
        aid = replan_id
    else:
        cfg = profile.resolve(req.get("cover_generation"))
        if cfg.max_width > limits.max_width or cfg.max_height > limits.max_height:
            cfg = profile.resolve(dict(req.get("cover_generation") or {}, max_width=min(cfg.max_width, limits.max_width),
                                       max_height=min(cfg.max_height, limits.max_height)))
        sel = select.select_cover(pb, cfg, seg_cfg, ml, tc, plan_fn=plan_fn)
        arr, pl, gen = sel.array, sel.plan, dict(sel.generation, reused_for_replan=False)
        images.check_array(arr, limits)
        t = gen["timings_ms"]
        timings = {"generate": t["generate"], "prescreen": t["prescreen"], "plan": t["plan"], "selection_total": t["total"]}
        aid = artifacts.new_id()
        png = images.encode_png(arr)
    t2 = time.perf_counter()
    if replan_id is None:
        store.write(aid, "cover", png)
        store.write(aid, "gen", json.dumps({"cover_sha256": _sha(png), "created_ms": int(time.time() * 1000),
                                            "generation": gen}, separators=(",", ":")).encode("utf-8"))
    store.write_replace(aid, "seg", overlay_png(arr, pl.seg.labels, pl.seg.n_regions))
    store.write_replace(aid, "labels", images.encode_png(pl.seg.labels))
    store.enforce_retention(keep_id=aid)
    timings["save"] = _ms(t2)
    d = pl.diagnostics
    log.info("plan ok payload_bytes=%d family=%s size=%dx%d patches=%d used=%d level=%d replan=%s", pb, gen.get("family"),
             arr.shape[1], arr.shape[0], d["patch_count"], d["used_patches"], d["refinement_level"], replan_id is not None)
    return {"ok": True, "format_version": FORMAT_VERSION, "manifest_b64": base64.b64encode(pl.manifest).decode("ascii"),
            "manifest_deflate_b64": base64.b64encode(pl.deflated).decode("ascii"), "manifest_sha256": _sha(pl.manifest), "plan": d, "cover": cover_descriptor(arr, aid, png, gen), "generation": gen,
            "inspection": {"segmentation_overlay": f"{aid}.seg.png", "label_map": f"{aid}.labels.png",
                           "palette": palette(pl.seg.n_regions).tolist()},
            "timings_ms": timings}


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
            "patch_count": len(man.patches), "carrier_pixels": man.carrier_pixels, "payload_len": man.payload_len,
            "patches": [{"patch_id": i, "alg_id": e.alg_id, "algorithm": BY_ID[e.alg_id].name if e.alg_id else None,
                         "param": e.param, "payload_offset": e.offset if e.alg_id else None, "payload_length": e.length}
                        for i, e in enumerate(man.patches)]}


def encode(req, store=None):
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    frame = _decode_frame(req, limits)
    _reject_removed(req, "encode", allow=("cover_id",))
    if "cover_generation" in req:
        raise StegoError("INVALID_REQUEST", "encode embeds into the cover that was planned; it never generates an image")
    c = req.get("carrier")
    if not isinstance(c, dict) or set(c) != {"values_b64", "bits_b64", "n_bits"}:
        raise StegoError("INVALID_REQUEST", "encode needs carrier = {values_b64, bits_b64, n_bits}")
    values = B.decode_values(c["values_b64"], "carrier.values_b64")
    bits = B.decode_bits(c["bits_b64"], "carrier.bits_b64")
    n_bits = c["n_bits"]
    if isinstance(n_bits, bool) or not isinstance(n_bits, int) or n_bits != 8 * len(bits):
        raise StegoError("INVALID_REQUEST", "carrier.n_bits must equal 8 * len(bits)")
    timings = {}
    t = time.perf_counter()
    cover_id = req.get("cover_id")
    cover_arr, cover_png, stored = _load_generated_cover(store, cover_id, limits)   # the exact planned artifact
    gen = stored["generation"]
    timings["load_cover"] = _ms(t)

    t = time.perf_counter()
    stego, man, per_patch, carrier_info = codec.embed_frame(cover_arr, frame, limits, values, bits, n_bits)
    man_bytes, _ = M.split_frame(frame, limits.max_frame_bytes)
    timings["embed"] = _ms(t)

    t = time.perf_counter()
    got, _, _ = codec.extract_frame(stego, man_bytes, values, limits)
    if got != frame:
        raise StegoError("EMBED_VERIFY_FAILED", "in-process extract did not match the frame")
    m = metrics.compute(cover_arr, stego)
    png = images.encode_png(stego)
    timings["verify"] = _ms(t)

    t = time.perf_counter()
    aid = artifacts.new_id()
    try:
        store.write(aid, "stego", png)
        timings["save"] = _ms(t)
        t = time.perf_counter()
        reread, _tr = images.decode_png(store.read(aid, "stego"), limits)
        got2, _, ext = codec.extract_frame(reread, man_bytes, values, limits)   # the saved file, re-opened from disk
        pos = B.positions(values, reread.shape[0] * reread.shape[1])
        if got2 != frame or not np.array_equal(reread, stego) or B.read_bits(reread, pos, 0, n_bits) != bits:
            raise StegoError("EMBED_VERIFY_FAILED", "saved PNG did not round-trip")
        status = {e["patch_id"]: e["status"] for e in ext}
        for p in per_patch:
            if p["used"]:
                p["extraction"] = "verified_from_saved_png" if status.get(p["patch_id"]) == "extracted" else "missing"
        diff = np.abs(stego.astype(np.int16) - cover_arr.astype(np.int16))
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
        "cover": cover_descriptor(cover_arr, cover_id, cover_png, gen),
        "embed": {"frame_len": len(frame), "manifest_len": len(frame) - M.FRAME_HEADER_LEN - man.payload_len,
                  "payload_len": man.payload_len, "patch_count": len(man.patches), "used_patches": len(used),
                  "carrier_pixels": man.carrier_pixels, "carrier_bits": carrier_info["carrier_bits"],
                  "carrier_changed_samples": carrier_info["carrier_changed_samples"], "patches": per_patch, "metrics": m,
                  "per_patch_summary": _per_patch_summary(used),
                  "exact_frame_recovery_from_saved_png": True},
        "timings_ms": timings,
    }


def _per_patch_summary(used):
    """Aggregation of the per-patch distortion figures (used patches only)."""
    mses = [float(p["patch_mse"]) for p in used if p.get("patch_mse") is not None]
    chg = [int(p.get("changed_samples") or 0) for p in used]
    if not mses:
        return {"patches": len(used)}
    worst = max(used, key=lambda p: p.get("patch_mse") or 0.0)
    return {"patches": len(used), "patch_mse_mean": round(float(np.mean(mses)), 6), "patch_mse_max": round(max(mses), 6),
            "patch_psnr_min_db": None if max(mses) == 0 else round(float(10 * np.log10(255.0 ** 2 / max(mses))), 3),
            "worst_patch_id": worst["patch_id"], "changed_samples_total": int(sum(chg)), "changed_samples_max": int(max(chg))}


def _load_stego(req, store, limits):
    aid = artifacts.validate_id(req.get("artifact_id"))
    data = store.read(aid, "stego")
    arr, _ = images.decode_png(data, limits)
    return arr, data


def _image_info(arr, data):
    return {"width": int(arr.shape[1]), "height": int(arr.shape[0]), "mode": images.mode_of(arr),
            "channels": images.channels_of(arr), "format": "PNG", "size": len(data), "sha256": _sha(data)}


def carrier_probe(req, store=None):
    """Discovery: for every candidate value stream, the locator bits at the pixels it maps to.
    Rust compares them with its sync words; this service cannot tell which (if any) is real."""
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    if req.get("locator_bits") != B.LOCATOR_BITS:
        raise StegoError("INVALID_REQUEST", f"locator_bits must be {B.LOCATOR_BITS}")
    cands = req.get("candidates")
    if not isinstance(cands, list) or not 1 <= len(cands) <= B.MAX_CANDIDATES:
        raise StegoError("INVALID_REQUEST", f"candidates must be a list of 1..{B.MAX_CANDIDATES}")
    t = time.perf_counter()
    arr, data = _load_stego(req, store, limits)
    n_pix = arr.shape[0] * arr.shape[1]
    probes = []
    for c in cands:
        if not isinstance(c, dict) or set(c) != {"id", "values_b64"} or isinstance(c["id"], bool) or not isinstance(c["id"], int):
            raise StegoError("INVALID_REQUEST", "candidate must be {id: int, values_b64}")
        pos = B.positions(B.decode_values(c["values_b64"], "candidate.values_b64", 1024), n_pix)
        try:
            bits = base64.b64encode(B.read_bits(arr, pos, 0, B.LOCATOR_BITS)).decode("ascii")
        except StegoError:
            bits = None          # too few distinct pixels for this stream: cannot be the carrier
        probes.append({"id": c["id"], "bits_b64": bits})
    return {"ok": True, "probes": probes, "legacy_bootstrap_v2": B.legacy_v2_preamble(arr),
            "image": _image_info(arr, data), "timings_ms": {"probe": _ms(t)}}


def carrier_read(req, store=None):
    """Carrier bits [skip_bits, skip_bits + n_bits) at the pixels of one value stream."""
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    skip, n = req.get("skip_bits"), req.get("n_bits")
    for v in (skip, n):
        if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v % 8:
            raise StegoError("INVALID_REQUEST", "skip_bits and n_bits must be non-negative multiples of 8")
    if not 0 < n <= 8 * B.MAX_BODY_BYTES or skip > 8 * (B.MAX_BODY_BYTES + 12):
        raise StegoError("INVALID_REQUEST", "carrier read range out of bounds")
    t = time.perf_counter()
    arr, data = _load_stego(req, store, limits)
    bits = codec.read_carrier(arr, B.decode_values(req.get("values_b64")), skip, n)
    return {"ok": True, "bits_b64": base64.b64encode(bits).decode("ascii"), "image": _image_info(arr, data),
            "timings_ms": {"read": _ms(t)}}


def extract_artifact(req, store=None):
    """Extract the payload section with the manifest Rust decoded from the carrier and validated."""
    store = store or get_store()
    limits = config.parse_limits(req.get("limits"))
    mb = req.get("manifest_b64")
    if not isinstance(mb, str) or not mb or len(mb) > ((M.MAX_MANIFEST_BYTES + 2) // 3) * 4 + 4:
        raise StegoError("INVALID_REQUEST", "manifest_b64 must be a base64 string")
    try:
        man_bytes = base64.b64decode(mb, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StegoError("INVALID_REQUEST", "manifest_b64 is not valid base64") from exc
    values = B.decode_values(req.get("values_b64"))
    t = time.perf_counter()
    arr, data = _load_stego(req, store, limits)
    t_read = _ms(t)
    t = time.perf_counter()
    frame, man, per_patch = codec.extract_frame(arr, man_bytes, values, limits)
    t_ext = _ms(t)
    return {
        "ok": True, "frame_b64": base64.b64encode(frame).decode("ascii"), "format_version": FORMAT_VERSION,
        "manifest": manifest_summary(man), "patches": per_patch, "resegmented": False,
        "image": _image_info(arr, data), "timings_ms": {"read": t_read, "extract": t_ext},
    }


def knowledge_base():
    return dict(KB.public_view(), ok=True, format_version=FORMAT_VERSION, segmentation_version=SEGMENTATION_VERSION,
                segmentation_defaults=S.SegConfig().to_dict())


def generator_info():
    return dict(profile.public_view(), generator_version=GENERATOR_VERSION, quality_version=QUALITY_VERSION,
                families=list(families.FAMILIES), modes=list(families.MODES), seeding=select.seeding_mode(),
                models="none (no pretrained model, no network, NumPy only)", pretrained_models=False, network=False)


def health(store=None):
    import PIL
    from . import SERVICE_VERSION
    store = store or get_store()
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
        "cover_source": COVER_SOURCE, "cover_generator": generator_info(),
        "numpy": np.__version__, "pillow": PIL.__version__,
    }
