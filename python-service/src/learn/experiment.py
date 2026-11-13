"""Patch-level experiments for the Algorithm Learning workbench (EDUCATIONAL).

* Uses the SAME segmentation, feature, knowledge-base and algorithm code as the operational
  transport, but in isolation: nothing is written to the operational artifact store, no event
  is logged, no protocol state is touched, and the static knowledge base / selector policy are
  only READ (an experiment can never change what production selects).
* One experiment = one cover + one payload + one chosen irregular patch; every algorithm
  embeds the same bytes into that same patch mask (no bootstrap carrier in experiments).
* "Saved image": the stego array is PNG-encoded and extraction runs on the decoded PNG.
* `survey` lists, for every patch of the segmentation, each algorithm's geometry support,
  measured capacity and the ranking the knowledge-base selector would produce for this payload.
* Results describe this repository's implemented variants, not canonical paper implementations.
"""

import base64
import binascii
import hashlib
import io
import time
import uuid

import numpy as np
from PIL import Image

from stego import images, metrics
from stego.algorithms import BY_NAME, NAMES
from stego.algorithms.adaptive import AdaptiveStc
from stego.config import Limits
from stego.errors import StegoError
from stego.patch import SEGMENTATION_VERSION, SELECTOR_VERSION, features as PF, kb as KB, segment as S
from stego.patch.planner import _patch_tables
from stego.patch.region import CoverCtx, Region
from stego.patch.render import overlay_png, palette

from . import LABEL, LEARN_VERSION, fixtures as F
from .walkthrough import clean

MAX_UPLOAD_DIM = 512
PARTIAL_BER = 0.1  # oracle BER above this is reported as failed (0.5 = random guessing)
MAX_PAYLOAD = 16384
PATCH_CHOICES = ("most_textured", "smoothest", "largest", "smallest")

METRIC_DEFINITIONS = {
    "mse": "mean over all samples of the IMAGE of (cover - stego)^2",
    "patch_mse": "mean over the samples of the chosen PATCH only of (cover - stego)^2",
    "psnr_db": "10 log10(255^2 / MSE) over the image; null when MSE = 0 (identical images)",
    "patch_psnr_db": "10 log10(255^2 / patch_mse); null when the patch is unchanged",
    "ssim": "mean SSIM over the image, uniform 7x7 window, K1=0.01, K2=0.03, L=255",
    "capacity_bits": "capacity measured by the algorithm implementation on this patch mask (not a knowledge-base estimate)",
    "payload_bits": "payload bytes x 8",
    "bits_per_patch_sample": "payload_bits / (patch pixels x channels)",
    "embed_ms": "patch embedding duration (perf_counter); setup_ms = cost evaluation inside it (STC methods)",
    "extract_ms": "PNG decode + patch extraction",
    "bit_accuracy": "matching bits / expected payload bits",
    "ber": "(wrong bits + missing bits) / expected payload bits; 1.0 if extraction failed entirely",
    "outside_patch_changes": "samples changed outside the patch mask (must be 0)",
    "robustness": "per attack: extraction from the attacked image with the known patch mask and parameters "
                  "(oracle); outcome recovered (BER 0) / partial (BER <= 0.1) / failed (BER ~0.5 is chance level)",
}

ATTACKS = [
    {"id": "none", "label": "No attack (lossless PNG)", "params": {}},
    {"id": "jpeg95", "label": "JPEG recompression", "params": {"quality": 95}},
    {"id": "jpeg75", "label": "JPEG recompression", "params": {"quality": 75}},
    {"id": "jpeg50", "label": "JPEG recompression", "params": {"quality": 50}},
    {"id": "resize50", "label": "Resize down 50% and back (bilinear)", "params": {"factor": 0.5}},
    {"id": "crop4", "label": "Crop 4 px from left and top (image becomes smaller)", "params": {"pixels": 4}},
    {"id": "gauss1", "label": "Gaussian noise", "params": {"sigma": 1.0, "seed": 11}},
    {"id": "gauss3", "label": "Gaussian noise", "params": {"sigma": 3.0, "seed": 12}},
    {"id": "saltpepper", "label": "Salt-and-pepper noise", "params": {"fraction": 0.005, "seed": 13}},
    {"id": "blur3", "label": "Gaussian blur 3x3", "params": {"sigma": 0.8}},
    {"id": "bright2", "label": "Brightness +2", "params": {"offset": 2}},
]


def _pil(arr):
    return Image.fromarray(arr, "L" if arr.ndim == 2 else "RGB")


def apply_attack(arr, attack):
    a, p = attack["id"], attack["params"]
    if a == "none":
        return arr.copy()
    if a.startswith("jpeg"):
        buf = io.BytesIO()
        _pil(arr).save(buf, "JPEG", quality=p["quality"])
        return np.array(Image.open(io.BytesIO(buf.getvalue())).convert("L" if arr.ndim == 2 else "RGB"), dtype=np.uint8)
    if a == "resize50":
        h, w = arr.shape[:2]
        small = _pil(arr).resize((max(1, int(w * p["factor"])), max(1, int(h * p["factor"]))), Image.BILINEAR)
        return np.array(small.resize((w, h), Image.BILINEAR), dtype=np.uint8)
    if a == "crop4":
        k = p["pixels"]
        return arr[k:, k:].copy()
    if a.startswith("gauss"):
        rng = np.random.default_rng(p["seed"])
        return np.clip(np.rint(arr + rng.normal(0, p["sigma"], arr.shape)), 0, 255).astype(np.uint8)
    if a == "saltpepper":
        rng = np.random.default_rng(p["seed"])
        out = arr.copy()
        m = rng.random(arr.shape[:2]) < p["fraction"]
        v = rng.integers(0, 2, arr.shape[:2]) * 255
        out[m] = v[m][:, None] if arr.ndim == 3 else v[m]
        return out
    if a == "blur3":
        s = p["sigma"]
        k1 = np.exp(-np.array([-1.0, 0.0, 1.0]) ** 2 / (2 * s * s))
        k1 /= k1.sum()
        f = arr.astype(np.float64)
        pad = [(1, 1), (1, 1)] + ([(0, 0)] if arr.ndim == 3 else [])
        fp = np.pad(f, pad, mode="edge")
        rows = k1[0] * fp[:-2] + k1[1] * fp[1:-1] + k1[2] * fp[2:]
        out = k1[0] * rows[:, :-2] + k1[1] * rows[:, 1:-1] + k1[2] * rows[:, 2:]
        return np.clip(np.rint(out), 0, 255).astype(np.uint8)
    if a == "bright2":
        return np.clip(arr.astype(np.int16) + p["offset"], 0, 255).astype(np.uint8)
    raise ValueError(a)


def bit_compare(expected, got):
    """(matching_bits, wrong_bits, missing_bits, ber, byte_matches)."""
    eb = np.unpackbits(np.frombuffer(expected, np.uint8))
    gb = np.unpackbits(np.frombuffer(got or b"", np.uint8))
    n = min(eb.size, gb.size)
    wrong = int((eb[:n] != gb[:n]).sum())
    missing = int(eb.size - n)
    match = int(n - wrong)
    ber = (wrong + missing) / eb.size if eb.size else 0.0
    bytes_ok = sum(1 for a, b in zip(expected, got or b"") if a == b)
    return match, wrong, missing, ber, bytes_ok


def _png_data_uri(arr):
    buf = io.BytesIO()
    _pil(arr).save(buf, "PNG", compress_level=6)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _norm8(x):
    x = np.asarray(x, dtype=np.float64)
    finite = np.isfinite(x)
    if not finite.any():
        return np.zeros(x.shape, np.uint8)
    lo, hi = np.nanmin(x[finite]), np.nanmax(x[finite])
    y = np.where(finite, x, hi)
    if hi - lo < 1e-12:
        return np.full(x.shape, 128, np.uint8)
    return np.clip((y - lo) / (hi - lo) * 255, 0, 255).astype(np.uint8)


def _cover_from(req):
    c = req.get("cover") or {"sample": "natural_rgb_256"}
    if not isinstance(c, dict):
        raise StegoError("INVALID_REQUEST", "cover must be an object")
    if "upload_b64" in c:
        try:
            raw = base64.b64decode(c["upload_b64"], validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise StegoError("INVALID_REQUEST", "upload_b64 is not valid base64") from exc
        if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
            raise StegoError("IMAGE_DECODE_ERROR", "only PNG covers are accepted")
        arr, tr = images.decode_png(raw, Limits(max_width=MAX_UPLOAD_DIM, max_height=MAX_UPLOAD_DIM), convert=True)
        return arr, {"source": "upload", "description": "uploaded PNG (decoded, mode-normalised)", "transforms": tr}
    name = c.get("sample", "natural_rgb_256")
    if name not in F.SAMPLES:
        raise StegoError("INVALID_REQUEST", "unknown sample cover", {"allowed": F.SAMPLES})
    arr, desc = F.sample_cover(name)
    return arr, {"source": "sample", "sample": name, "description": desc, "transforms": []}


def _payload_from(req):
    pb = req.get("payload_b64")
    if pb is None:
        return F.SYNTHETIC_CIPHERTEXT, "synthetic"
    try:
        raw = base64.b64decode(pb, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise StegoError("INVALID_REQUEST", "payload_b64 is not valid base64") from exc
    if not 1 <= len(raw) <= MAX_PAYLOAD:
        raise StegoError("INVALID_REQUEST", f"payload must be 1..{MAX_PAYLOAD} bytes")
    return raw, req.get("payload_kind", "custom")



def _choose_patch(req, feats):
    want = req.get("patch", "most_textured")
    n = len(feats)
    if isinstance(want, bool):
        raise StegoError("INVALID_REQUEST", "patch must be a patch id or a selection keyword")
    if isinstance(want, int):
        if not 0 <= want < n:
            raise StegoError("INVALID_REQUEST", "patch id out of range", {"patch_count": n})
        return want, "explicit"
    if want not in PATCH_CHOICES:
        raise StegoError("INVALID_REQUEST", "unknown patch selection", {"allowed": list(PATCH_CHOICES)})
    key = {"most_textured": lambda f: (-f["gradient_mean"], f["patch_id"]), "smoothest": lambda f: (f["gradient_mean"], f["patch_id"]),
           "largest": lambda f: (-f["pixels"], f["patch_id"]), "smallest": lambda f: (f["pixels"], f["patch_id"])}[want]
    return sorted(feats, key=key)[0]["patch_id"], want


def _highlight_png(cover, labels, pid):
    gray = S.luma_of(cover)
    out = np.repeat(gray[:, :, None], 3, axis=2) * 0.45
    m = labels == pid
    src = cover if cover.ndim == 3 else np.repeat(cover[:, :, None], 3, axis=2)
    out[m] = src[m]
    edge = np.zeros(m.shape, dtype=bool)
    edge[:, 1:] |= m[:, 1:] != m[:, :-1]
    edge[1:, :] |= m[1:, :] != m[:-1, :]
    out[edge] = (255, 200, 0)
    return _png_data_uri(np.clip(out, 0, 255).astype(np.uint8))


def _one(name, cover, ctx, region, feat, caps, sups, payload, attacks, include_images):
    alg = BY_NAME[name]
    ch = ctx.channels
    pbits = len(payload) * 8
    ok, why = sups[name]
    cap = int(caps[name])
    structural = KB.structural(feat, sups)[name]
    row = {"algorithm": name, "alg_id": alg.id, "variant": alg.variant, "domain": alg.domain, "coding": alg.coding,
           "reference": alg.reference, "mask_support": alg.mask_support, "block": alg.block,
           "geometry_supported": bool(ok), "geometry_reason": why, "kb_structural_filters_pass": bool(structural),
           "capacity_bits": cap, "capacity_bytes": cap // 8, "payload_bytes": len(payload), "payload_bits": pbits,
           "bits_per_patch_sample": round(pbits / max(1, region.n_pixels * ch), 8),
           "utilisation": round(pbits / cap, 6) if cap else None}
    if not ok:
        row.update(status="unsupported_geometry", error={"code": "PATCH_UNSUPPORTED", "message": f"patch geometry not supported: {why}"})
        return row
    if pbits > cap:
        row.update(status="rejected_capacity", error={"code": alg.capacity_code,
                   "message": f"payload ({pbits} bits) exceeds the measured patch capacity ({cap} bits); not shortened"})
        return row
    param = alg.choose_w(cover, region, len(payload)) if isinstance(alg, AdaptiveStc) else alg.resolve_param(0)
    row["param"] = param
    stego = cover.copy()
    t0 = time.perf_counter()
    try:
        detail = alg.embed(ctx, region, stego, payload, param)
    except StegoError as exc:
        row.update(status="embed_failed", error={"code": exc.code, "message": str(exc)}, embed_ms=round((time.perf_counter() - t0) * 1000, 3))
        return row
    embed_ms = (time.perf_counter() - t0) * 1000
    png = images.encode_png(stego)
    t1 = time.perf_counter()
    try:
        decoded, _ = images.decode_png(png, Limits())
        got, ext_err = alg.extract(decoded, region, len(payload), param), None
    except StegoError as exc:
        got, ext_err = b"", {"code": exc.code, "message": str(exc)}
    extract_ms = (time.perf_counter() - t1) * 1000
    match, wrong, missing, ber, bytes_ok = bit_compare(payload, got)
    m = metrics.compute(cover, stego)
    mask3 = region.mask if cover.ndim == 2 else region.mask[:, :, None]
    diff = stego.astype(np.int16) - cover.astype(np.int16)
    outside = int(np.count_nonzero(diff * (~mask3)))
    pd = diff[region.mask].astype(np.float64)
    pmse = float(np.mean(pd ** 2)) if pd.size else 0.0
    row.update(status="ok" if got == payload else "extract_mismatch",
               embed_ms=round(embed_ms, 3), setup_ms=detail.get("cost_ms"), extract_ms=round(extract_ms, 3),
               mse=m["mse"], psnr_db=m["psnr"], ssim=m["ssim"], patch_mse=round(pmse, 6),
               patch_psnr_db=None if pmse == 0 else round(10 * np.log10(255.0 ** 2 / pmse), 4),
               changed_samples=m["changed_samples"], max_abs_diff=m["max_abs_diff"], outside_patch_changes=outside,
               bit_accuracy=round(match / pbits, 8), byte_accuracy=round(bytes_ok / len(payload), 8), ber=round(ber, 8),
               exact_recovery=(got == payload), extract_error=ext_err, stego_sha256=hashlib.sha256(png).hexdigest(),
               extracted_b64=base64.b64encode(got).decode(), detail=clean(detail))
    if attacks:
        rob = []
        for at in ATTACKS:
            attacked = apply_attack(stego, at)
            r = {"attack": at["id"], "label": at["label"], "params": at["params"]}
            try:
                if attacked.shape != stego.shape:
                    raise StegoError("DESYNCHRONISED", "image geometry changed")
                _, _, _, ober, _ = bit_compare(payload, alg.extract(attacked, region, len(payload), param))
                r["oracle_ber"] = round(ober, 6)
            except StegoError as exc:
                r["oracle_ber"] = 1.0
                r["oracle_error"] = exc.code
            r["outcome"] = "recovered" if r["oracle_ber"] == 0 else "partial" if r["oracle_ber"] <= PARTIAL_BER else "failed"
            rob.append(r)
        row["robustness"] = rob
    if include_images:
        dmap = np.abs(diff) if diff.ndim == 2 else np.abs(diff).max(axis=2)
        row["images"] = {"stego": _png_data_uri(stego),
                         "difference_x64": {"title": "|stego - cover| x 64 (changes stay inside the patch)", "png": _png_data_uri(np.clip(dmap * 64, 0, 255).astype(np.uint8))}}
    return row


def run(req):
    """Patch-level experiment. req: {algorithms: [...]|'all', cover, payload_b64, payload_kind,
    patch: id | keyword, robustness, include_images, survey, segmentation}."""
    if not isinstance(req, dict):
        raise StegoError("INVALID_REQUEST", "JSON object required")
    algs = req.get("algorithms", "all")
    if algs == "all":
        algs = list(NAMES)
    if not isinstance(algs, list) or not algs or not all(a in NAMES for a in algs) or len(set(algs)) != len(algs):
        raise StegoError("INVALID_REQUEST", "algorithms must be 'all' or a list of distinct algorithm names")
    cover, cinfo = _cover_from(req)
    payload, kind = _payload_from(req)
    seg_cfg = S.parse_config(req.get("segmentation"))
    rob = bool(req.get("robustness", False))
    imgs = bool(req.get("include_images", True))
    t0 = time.perf_counter()
    seg = S.segment(cover, seg_cfg, 0)
    feats = PF.compute(cover, seg.labels, seg.n_regions, 0)
    regions, caps, sups = _patch_tables(cover, seg.labels, feats, seg.n_regions)
    pid, how = _choose_patch(req, feats)
    ctx = CoverCtx(cover)
    results = [_one(a, cover, ctx, regions[pid], feats[pid], caps[pid], sups[pid], payload, rob, imgs)
               for a in sorted(algs, key=lambda n: BY_NAME[n].id)]
    ch = ctx.channels
    q = dict(feats[pid])
    q["bits_per_sample"] = round(8.0 * len(payload) / max(1, feats[pid]["usable_pixels"] * ch), 8)
    retrieval = KB.retrieve(q, len(payload), caps[pid], sups[pid])
    survey = None
    if req.get("survey", True):
        survey = []
        for i, f in enumerate(feats):
            qq = dict(f)
            qq["bits_per_sample"] = round(8.0 * len(payload) / max(1, f["usable_pixels"] * ch), 8)
            r = KB.retrieve(qq, len(payload), caps[i], sups[i])
            survey.append({"patch_id": i, "pixels": f["pixels"], "gradient_mean": f["gradient_mean"], "variance": f["variance"],
                           "entropy": f["entropy"], "saturation": f["saturation"], "compactness": f["compactness"],
                           "blocks8": f["blocks8"], "blocks2": f["blocks2"], "query_terms": r["query_terms"],
                           "capacity_bits": caps[i], "supported": {k: v[0] for k, v in sups[i].items()},
                           "unsupported_reasons": {k: v[1] for k, v in sups[i].items() if not v[0]},
                           "kb_ranking": r["ranking"], "kb_selected": r["selected"],
                           "bm25": {c["algorithm"]: c["bm25"] for c in r["candidates"]}})
    h, w = cover.shape[:2]
    cinfo.update(width=w, height=h, channels=ch, mode="L" if cover.ndim == 2 else "RGB",
                 sha256=hashlib.sha256(cover.tobytes()).hexdigest())
    out = {
        "experiment_id": uuid.uuid4().hex, "learn_version": LEARN_VERSION, "mode": "educational", "label": LABEL,
        "operational": False, "production_kb_modified": False, "cover": cinfo,
        "segmentation": dict(seg.info, patch_count=seg.n_regions, palette=palette(seg.n_regions).tolist()),
        "selector_version": SELECTOR_VERSION, "kb_version": KB.load()["kb_version"],
        "patch": {"patch_id": pid, "chosen_by": how, "features": feats[pid], "kb_retrieval_readonly": retrieval,
                  "note": "kb_retrieval_readonly shows what the production selector would rank for this patch and payload; "
                          "the experiment runs every requested algorithm regardless and changes nothing in production."},
        "payload": {"kind": kind, "bytes": len(payload), "bits": len(payload) * 8, "sha256": hashlib.sha256(payload).hexdigest(),
                    "hex_preview": payload[:64].hex(" ").upper() + (" ..." if len(payload) > 64 else ""),
                    "bit_order": F.BIT_ORDER},
        "same_inputs_for_all_algorithms": True, "results": results, "survey": survey, "attacks": ATTACKS if rob else [],
        "metric_definitions": METRIC_DEFINITIONS, "duration_ms": round((time.perf_counter() - t0) * 1000, 3),
        "variant_notice": "Results describe this repository's implemented variants (see each row's 'variant'), not canonical paper implementations.",
        "interpretation": [
            "High PSNR/SSIM means the stego image looks like the cover; it does not prove resistance to steganalysis.",
            "Capacity depends on the patch: block methods need complete 8x8 / 2x2 blocks inside the mask, edge-adaptive LSB needs edges.",
            "Exact extraction from an unmodified PNG does not establish robustness to lossy transforms.",
            "HUGO/WOW/S-UNIWARD minimise a distortion model; that is not a proof that no steganalyst can detect the message.",
        ],
    }
    if imgs:
        out["cover"]["png"] = _png_data_uri(cover)
        out["segmentation"]["overlay_png"] = "data:image/png;base64," + base64.b64encode(overlay_png(cover, seg.labels, seg.n_regions)).decode()
        out["patch"]["highlight_png"] = _highlight_png(cover, seg.labels, pid)
    return clean(out)


def registry():
    return clean({"algorithms": [BY_NAME[n].describe() for n in NAMES], "samples": F.SAMPLES, "patch_choices": list(PATCH_CHOICES),
                  "attacks": ATTACKS, "metric_definitions": METRIC_DEFINITIONS, "label": LABEL,
                  "segmentation_version": SEGMENTATION_VERSION, "selector_version": SELECTOR_VERSION,
                  "synthetic_ciphertext_hex": F.SYNTHETIC_CIPHERTEXT.hex().upper(), "synthetic_label": F.SYNTHETIC_LABEL,
                  "sample_message": F.SAMPLE_MESSAGE})
