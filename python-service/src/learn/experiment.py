"""Isolated execution experiments for the Algorithm Learning workbench (EDUCATIONAL).

* Runs the real operational algorithm implementations (stego.algorithms + stego.codec) on a
  sample or uploaded cover with caller-supplied payload bytes; nothing is written to the
  operational artifact store, no event is logged there, no protocol state is touched.
* "Saved image": the stego array is PNG-encoded and the extraction runs on the decoded PNG
  bytes (lossless round trip), not on the in-memory array.
* Every algorithm in one comparison gets the SAME cover array and the SAME payload bytes.
"""

import base64
import binascii
import hashlib
import io
import time
import uuid

import numpy as np
from PIL import Image

from stego import codec, images, metrics
from stego.algorithms import BY_NAME, NAMES
from stego.algorithms.adaptive import AdaptiveStc
from stego.config import Limits
from stego.errors import StegoError

from . import LABEL, LEARN_VERSION, fixtures as F
from .walkthrough import clean

MAX_UPLOAD_DIM = 512
PARTIAL_BER = 0.1  # oracle BER above this is reported as failed (0.5 = random guessing)
MAX_PAYLOAD = 16384
BOOTSTRAP_BITS = 128

METRIC_DEFINITIONS = {
    "mse": "mean over all samples (pixels x channels) of (cover - stego)^2",
    "psnr_db": "10 log10(255^2 / MSE); null when MSE = 0 (identical images, infinite PSNR)",
    "ssim": "mean SSIM, uniform 7x7 window, K1=0.01, K2=0.03, L=255, data range 0..255, averaged over all windows and channels",
    "capacity_bits_raw": "algorithm capacity for this cover excluding the 128 bootstrap samples (estimated from the cover)",
    "capacity_bits_verified": "largest payload actually embedded AND extracted exactly in a verification run (bytes x 8)",
    "payload_bits": "payload bytes x 8 (the complete payload: AEAD test envelope or synthetic fixture)",
    "bits_per_pixel": "payload_bits / (width x height)",
    "embed_ms": "sender-side codec.embed_frame duration (monotonic perf_counter); setup_ms = cost-map time inside it (STC methods)",
    "extract_ms": "receiver-side PNG decode + bootstrap validation + extraction (perf_counter)",
    "bit_accuracy": "matching bits / expected payload bits",
    "ber": "(wrong bits + missing bits) / expected payload bits; 1.0 if extraction failed entirely",
    "robustness": "per attack: 'recovered' = full pipeline (bootstrap + payload) returned the exact payload; "
                  "'recovered_oracle_only' = only a direct extraction with the known algorithm/length/parameter was exact; "
                  "'partial' = oracle BER in (0, 0.1]; 'failed' = otherwise (BER ~0.5 is chance level). "
                  "oracle_ber = BER of that direct extraction",
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


def _gray(a):
    return a if a.ndim == 2 else a.max(axis=2) if a.dtype == bool else a.mean(axis=2)


def visualisations(name, cover, stego):
    """Algorithm-specific maps as PNG data URIs (amplified so they are visible)."""
    diff = np.abs(stego.astype(np.int16) - cover.astype(np.int16))
    dmap = diff.max(axis=2) if diff.ndim == 3 else diff
    out = {
        "difference_x64": {"title": "|stego - cover| x 64 (max over channels)", "png": _png_data_uri(np.clip(dmap * 64, 0, 255).astype(np.uint8))},
        "changed_locations": {"title": "Changed locations (white)", "png": _png_data_uri(((dmap > 0) * 255).astype(np.uint8))},
    }
    alg = BY_NAME[name]
    g = cover if cover.ndim == 2 else cover[:, :, 2]
    if name in ("lsb_replacement", "lsb_matching"):
        out["specific"] = {"title": "Cover LSB plane", "png": _png_data_uri(((cover if cover.ndim == 2 else cover[:, :, 0]) & 1) * 255)}
    elif name == "pvd":
        flat = g.astype(np.int16)
        d = np.abs(flat[:, 0::2][:, : flat.shape[1] // 2] - flat[:, 1::2][:, : flat.shape[1] // 2])
        out["specific"] = {"title": "Pair difference |a-b| (row pairs, larger = more bits)", "png": _png_data_uri(_norm8(np.repeat(d, 2, axis=1)))}
    elif name == "edge_adaptive_lsb":
        from stego.algorithms.edge_adaptive import edge_mask
        out["specific"] = {"title": "Edge mask (eligible pixels, T=6)", "png": _png_data_uri(edge_mask(cover, 6).astype(np.uint8) * 255)}
    elif name == "dwt":
        h2, w2 = (g.shape[0] // 2) * 2, (g.shape[1] // 2) * 2
        x = g[:h2, :w2].astype(np.float64)
        hh = (x[0::2, 0::2] - x[0::2, 1::2] - x[1::2, 0::2] + x[1::2, 1::2]) / 2
        out["specific"] = {"title": "Haar HH sub-band |HH| of the embedding plane", "png": _png_data_uri(_norm8(np.abs(hh)))}
    elif name in ("dct", "dct_svd"):
        from stego.algorithms import dct_svd as DS
        nbr, nbc = g.shape[0] // 8, g.shape[1] // 8
        blk = g[:nbr * 8, :nbc * 8].reshape(nbr, 8, nbc, 8).transpose(0, 2, 1, 3).reshape(-1, 8, 8).astype(np.float64)
        s1 = DS.read_s1(blk).reshape(nbr, nbc)
        title = "Largest singular value s1 per 8x8 block (embedding plane)" if name == "dct_svd" else "Block energy proxy s1 per 8x8 block"
        out["specific"] = {"title": title, "png": _png_data_uri(np.kron(_norm8(s1), np.ones((8, 8), np.uint8)))}
    elif isinstance(alg, AdaptiveStc):
        cmap = alg.cost_map(cover)
        cm = cmap if cmap.ndim == 2 else np.fmin.reduce(cmap, axis=2)  # NaN-ignoring, no warning
        out["specific"] = {"title": "Embedding cost map, log scale (dark = cheap)", "png": _png_data_uri(_norm8(np.log10(np.maximum(cm, 1e-6))))}
    return out


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


def _one(name, cover, payload, attacks, verify_capacity, include_images):
    alg = BY_NAME[name]
    h, w = cover.shape[:2]
    cap = int(alg.capacity_bits(cover))
    pbits = len(payload) * 8
    row = {"algorithm": name, "alg_id": alg.id, "variant": alg.variant, "domain": alg.domain, "coding": alg.coding,
           "reference": alg.reference, "capacity_bits_raw": cap, "capacity_bytes_raw": cap // 8,
           "bootstrap_bits": BOOTSTRAP_BITS, "payload_bytes": len(payload), "payload_bits": pbits,
           "bits_per_pixel": round(pbits / (h * w), 8), "utilisation": round(pbits / cap, 6) if cap else None}
    if pbits > cap:
        row.update(status="rejected_capacity", error={"code": alg.capacity_code,
                   "message": f"payload ({pbits} bits) exceeds capacity ({cap} bits); not shortened"})
        return row
    t0 = time.perf_counter()
    try:
        stego, outcome = codec.embed_frame(cover, alg, 0, payload)
    except StegoError as exc:
        row.update(status="embed_failed", error={"code": exc.code, "message": str(exc)},
                   embed_ms=round((time.perf_counter() - t0) * 1000, 3))
        return row
    embed_ms = (time.perf_counter() - t0) * 1000
    png = images.encode_png(stego)
    t1 = time.perf_counter()
    try:
        decoded, _ = images.decode_png(png, Limits())
        got, bs, _ = codec.extract_frame(decoded, Limits())
        ext_err = None
    except StegoError as exc:
        got, ext_err = b"", {"code": exc.code, "message": str(exc)}
    extract_ms = (time.perf_counter() - t1) * 1000
    match, wrong, missing, ber, bytes_ok = bit_compare(payload, got)
    m = metrics.compute(cover, stego)
    row.update(status="ok" if (got == payload) else "extract_mismatch",
               embed_ms=round(embed_ms, 3), setup_ms=outcome.detail.get("cost_ms"), extract_ms=round(extract_ms, 3),
               mse=m["mse"], psnr_db=m["psnr"], psnr_defined=m["psnr_defined"], ssim=m["ssim"],
               changed_samples=m["changed_samples"], max_abs_diff=m["max_abs_diff"],
               bit_accuracy=round(match / pbits, 8), byte_accuracy=round(bytes_ok / len(payload), 8), ber=round(ber, 8),
               exact_recovery=(got == payload), extract_error=ext_err,
               stego_png_bytes=len(png), stego_sha256=hashlib.sha256(png).hexdigest(),
               extracted_b64=base64.b64encode(got).decode(),
               detail=clean(outcome.detail))
    if verify_capacity:
        nb = cap // 8
        vrow = {"tested_bytes": nb}
        try:
            test = np.random.default_rng(7).integers(0, 256, nb, dtype=np.uint8).tobytes()
            st2, _ = codec.embed_frame(cover, alg, 0, test)
            ok = codec.extract_frame(images.decode_png(images.encode_png(st2), Limits())[0], Limits())[0] == test
            vrow["passed"] = bool(ok)
        except StegoError as exc:
            vrow.update(passed=False, error=exc.code)
        row["capacity_bits_verified"] = nb * 8 if vrow.get("passed") else None
        row["capacity_verification"] = vrow
    if attacks:
        rob = []
        for at in ATTACKS:
            attacked = apply_attack(stego, at)
            r = {"attack": at["id"], "label": at["label"], "params": at["params"]}
            try:
                full = codec.extract_frame(attacked, Limits())[0]
                r["full_pipeline"] = "recovered" if full == payload else "wrong_payload"
            except StegoError as exc:
                r["full_pipeline"] = "failed"
                r["full_error"] = exc.code
            try:
                if attacked.shape != stego.shape:
                    raise StegoError("DESYNCHRONISED", "image geometry changed")
                ob = alg.extract(attacked, len(payload), 0)
                _, _, _, ober, _ = bit_compare(payload, ob)
                r["oracle_ber"] = round(ober, 6)
            except StegoError as exc:
                r["oracle_ber"] = 1.0
                r["oracle_error"] = exc.code
            # BER near 0.5 is chance level (no information), so it counts as failed, not partial
            r["outcome"] = ("recovered" if r["full_pipeline"] == "recovered" else
                            "recovered_oracle_only" if r["oracle_ber"] == 0 else
                            "partial" if r["oracle_ber"] <= PARTIAL_BER else "failed")
            rob.append(r)
        row["robustness"] = rob
    if include_images:
        row["images"] = {"stego": _png_data_uri(stego), **visualisations(name, cover, stego)}
    return row


def run(req):
    """Run one experiment. req: {algorithms: [...] | 'all', cover: {...}, payload_b64, payload_kind,
    robustness: bool, verify_capacity: bool, include_images: bool}."""
    if not isinstance(req, dict):
        raise StegoError("INVALID_REQUEST", "JSON object required")
    algs = req.get("algorithms", "all")
    if algs == "all":
        algs = list(NAMES)
    if not isinstance(algs, list) or not algs or not all(a in NAMES for a in algs) or len(set(algs)) != len(algs):
        raise StegoError("INVALID_REQUEST", "algorithms must be 'all' or a list of distinct algorithm names")
    cover, cinfo = _cover_from(req)
    payload, kind = _payload_from(req)
    rob = bool(req.get("robustness", False))
    verify = bool(req.get("verify_capacity", True))
    imgs = bool(req.get("include_images", True))
    t0 = time.perf_counter()
    results = [_one(a, cover, payload, rob, verify, imgs) for a in sorted(algs, key=lambda n: BY_NAME[n].id)]
    h, w = cover.shape[:2]
    cinfo.update(width=w, height=h, channels=1 if cover.ndim == 2 else 3, mode="L" if cover.ndim == 2 else "RGB",
                 sha256=hashlib.sha256(cover.tobytes()).hexdigest())
    out = {
        "experiment_id": uuid.uuid4().hex, "learn_version": LEARN_VERSION, "mode": "educational", "label": LABEL,
        "operational": False, "cover": cinfo,
        "payload": {"kind": kind, "bytes": len(payload), "bits": len(payload) * 8, "sha256": hashlib.sha256(payload).hexdigest(),
                    "hex_preview": payload[:64].hex(" ").upper() + (" ..." if len(payload) > 64 else ""),
                    "bit_order": F.BIT_ORDER},
        "same_inputs_for_all_algorithms": True, "results": results, "attacks": ATTACKS if rob else [],
        "metric_definitions": METRIC_DEFINITIONS, "duration_ms": round((time.perf_counter() - t0) * 1000, 3),
        "interpretation": [
            "High PSNR/SSIM means the stego image looks like the cover; it does not prove resistance to steganalysis.",
            "Low MSE is not a proof of security.",
            "Exact extraction from an unmodified PNG does not establish robustness to lossy transforms.",
            "Robustness, imperceptibility, capacity, speed and statistical undetectability are different objectives and trade off.",
            "HUGO/WOW/S-UNIWARD minimise a distortion model; that is not a proof that no steganalyst can detect the message.",
        ],
    }
    if imgs:
        out["cover"]["png"] = _png_data_uri(cover)
    return clean(out)


def registry():
    return clean({"algorithms": [BY_NAME[n].describe() for n in NAMES], "samples": F.SAMPLES,
                  "attacks": ATTACKS, "metric_definitions": METRIC_DEFINITIONS, "label": LABEL,
                  "synthetic_ciphertext_hex": F.SYNTHETIC_CIPHERTEXT.hex().upper(), "synthetic_label": F.SYNTHETIC_LABEL,
                  "sample_message": F.SAMPLE_MESSAGE})
