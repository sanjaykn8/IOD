"""Tests for the Flask /stego/* endpoints (stego_api.py), using Flask's
real test client (no live network) but exercising the real algorithm +
selector + RAG code paths end to end inside the process."""

import sys
import os
import base64
import io

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import numpy as np
from PIL import Image
import pytest

from app import app


@pytest.fixture
def client():
    return app.test_client()


def _make_cover_png_b64(h=96, w=96, seed=0):
    rng = np.random.default_rng(seed)
    yy, xx = np.meshgrid(np.linspace(0, 255, h), np.linspace(0, 255, w), indexing="ij")
    base = np.clip(0.5 * yy + 0.5 * xx + rng.normal(0, 8, size=(h, w)), 0, 255)
    rgb = np.stack([base, np.roll(base, 5, axis=0), np.roll(base, 5, axis=1)], axis=2).astype(np.uint8)
    buf = io.BytesIO()
    Image.fromarray(rgb, mode="RGB").save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def test_select_and_embed_then_extract_round_trip(client):
    cover_b64 = _make_cover_png_b64()
    payload = b"R1-ENROLLMENT-CIPHERTEXT-STAND-IN-BYTES"
    payload_b64 = base64.b64encode(payload).decode("ascii")

    resp = client.post("/stego/select-and-embed", json={"cover_image_b64": cover_b64, "payload_b64": payload_b64, "importance": "CRITICAL"})
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    assert data["stego_hint"]["payload_length"] == len(payload)
    assert data["selection"]["winner_algorithm_id"] == data["stego_hint"]["stego_algorithm_id"]
    assert len(data["explanation"]["evidence"]) >= 0  # may be empty for a very narrow query, but must exist as a field

    extract_resp = client.post("/stego/extract", json={"stego_image_b64": data["stego_image_b64"], "stego_hint": data["stego_hint"]})
    assert extract_resp.status_code == 200, extract_resp.get_json()
    recovered = base64.b64decode(extract_resp.get_json()["payload_b64"])
    assert recovered == payload


def test_select_and_embed_rejects_missing_fields(client):
    resp = client.post("/stego/select-and-embed", json={})
    assert resp.status_code == 400


def test_select_and_embed_importance_changes_winner_possible(client):
    cover_b64 = _make_cover_png_b64()
    payload = b"short-payload"
    payload_b64 = base64.b64encode(payload).decode("ascii")
    r_low = client.post("/stego/select-and-embed", json={"cover_image_b64": cover_b64, "payload_b64": payload_b64, "importance": "LOW"}).get_json()
    r_crit = client.post("/stego/select-and-embed", json={"cover_image_b64": cover_b64, "payload_b64": payload_b64, "importance": "CRITICAL"}).get_json()
    # Not asserting they MUST differ (that depends on the real
    # measurements for this image), just that both are valid, known
    # algorithm ids and the endpoint is importance-sensitive in general
    # (covered more rigorously in test_selector.py).
    assert r_low["stego_hint"]["stego_algorithm_id"] in {"adaptive_lsb", "pvd", "dct", "dwt", "svd"}
    assert r_crit["stego_hint"]["stego_algorithm_id"] in {"adaptive_lsb", "pvd", "dct", "dwt", "svd"}


def test_list_algorithms(client):
    resp = client.get("/stego/algorithms")
    assert resp.status_code == 200
    assert set(resp.get_json()["algorithms"]) == {"adaptive_lsb", "pvd", "dct", "dwt", "svd"}


def test_extract_with_wrong_payload_length_fails_cleanly(client):
    cover_b64 = _make_cover_png_b64()
    payload_b64 = base64.b64encode(b"payload-bytes-here").decode("ascii")
    embed_resp = client.post("/stego/select-and-embed", json={"cover_image_b64": cover_b64, "payload_b64": payload_b64}).get_json()
    bad_hint = dict(embed_resp["stego_hint"])
    bad_hint["payload_length"] = 10_000_000
    resp = client.post("/stego/extract", json={"stego_image_b64": embed_resp["stego_image_b64"], "stego_hint": bad_hint})
    assert resp.status_code == 422
