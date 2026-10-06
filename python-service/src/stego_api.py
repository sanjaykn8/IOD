"""Flask blueprint: registration-time steganography selection + embed/
extract HTTP endpoints. Mounted by `app.py` under `/stego/*` (proxied
by the Node.js gateway under `/api/stego/*`, same pattern as the
existing `/rag/*` endpoints).

This module is pure plumbing: image<->base64, bytes<->base64, and
wiring the three already-separated pieces together --
`stego.benchmark` (real measurement), `rag.selector` (deterministic
decision from those measurements), and `rag.stego_knowledge` (real
retrieval-backed narrative). It adds no new numbers of its own.
"""

from __future__ import annotations

import base64
import io

from flask import Blueprint, request, jsonify
from PIL import Image
import numpy as np

from stego.benchmark import measure_all
from stego.registry import get_algorithm, all_algorithm_ids
from rag.selector import select_algorithm
from rag.stego_knowledge import explain_selection

stego_bp = Blueprint("stego", __name__)


def _decode_image(b64: str) -> np.ndarray:
    raw = base64.b64decode(b64)
    img = Image.open(io.BytesIO(raw)).convert("RGB")
    return np.array(img)


def _encode_image(pixels: np.ndarray) -> str:
    img = Image.fromarray(pixels.astype(np.uint8), mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


@stego_bp.post("/stego/select-and-embed")
def select_and_embed():
    """Request: {cover_image_b64, payload_b64, importance?}.

    Response: {stego_image_b64, stego_hint, selection, explanation}.
    `selection` carries every candidate's real measurements and scores
    (so the UI can show the full comparison, not just the winner);
    `explanation` carries the RAG narrative for the winner only.
    """
    body = request.get_json(force=True, silent=True) or {}
    cover_b64 = body.get("cover_image_b64")
    payload_b64 = body.get("payload_b64")
    importance = body.get("importance", "CRITICAL")
    if not cover_b64 or payload_b64 is None:
        return jsonify({"error": "cover_image_b64 and payload_b64 are required"}), 400
    try:
        cover_pixels = _decode_image(cover_b64)
        payload = base64.b64decode(payload_b64)
    except Exception as e:
        return jsonify({"error": f"invalid cover_image_b64/payload_b64: {e}"}), 400

    measurements = measure_all(cover_pixels, payload)
    selection = select_algorithm(measurements, importance=importance)
    if selection.winner_algorithm_id is None:
        return jsonify({
            "error": "no feasible steganography algorithm for this image/payload combination",
            "selection": selection.to_dict(),
        }), 422

    winner_id = selection.winner_algorithm_id
    algo = get_algorithm(winner_id)
    embed_result = algo.embed(cover_pixels, payload)
    stego_image_b64 = _encode_image(embed_result.stego_pixels)

    winner_measurement = next(m.to_dict() for m in measurements if m.algorithm_id == winner_id)
    explanation = explain_selection(winner_id, importance, winner_measurement)

    stego_hint = {
        "stego_algorithm_id": winner_id,
        "algorithm_version": algo.algorithm_version,
        "stego_profile_id": importance,
        "payload_length": len(payload),
        "image_format": "PNG",
        "algorithm_params": embed_result.algorithm_params,
    }
    return jsonify({
        "stego_image_b64": stego_image_b64,
        "stego_hint": stego_hint,
        "selection": selection.to_dict(),
        "explanation": explanation,
    })


@stego_bp.post("/stego/extract")
def extract():
    """Request: {stego_image_b64, stego_hint: {stego_algorithm_id, payload_length, algorithm_params}}.
    Response: {payload_b64}.
    """
    body = request.get_json(force=True, silent=True) or {}
    stego_b64 = body.get("stego_image_b64")
    hint = body.get("stego_hint") or {}
    if not stego_b64 or "stego_algorithm_id" not in hint or "payload_length" not in hint:
        return jsonify({"error": "stego_image_b64 and stego_hint.{stego_algorithm_id,payload_length} are required"}), 400
    try:
        stego_pixels = _decode_image(stego_b64)
        algo = get_algorithm(hint["stego_algorithm_id"])
        payload = algo.extract(stego_pixels, int(hint["payload_length"]), hint.get("algorithm_params") or {})
    except Exception as e:
        return jsonify({"error": f"extraction failed: {e}"}), 422
    return jsonify({"payload_b64": base64.b64encode(payload).decode("ascii")})


@stego_bp.get("/stego/algorithms")
def list_algorithms():
    return jsonify({"algorithms": all_algorithm_ids()})
