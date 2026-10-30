import base64
import io
import json

import numpy as np
import pytest
from flask import Flask
from PIL import Image

from stego import artifacts, cover as cover_mod, images, service
from stego.algorithms import NAMES
from stego.api import bp
from stego_helpers import natural_cover, payload

COVER = natural_cover(120, 160, 3)


@pytest.fixture
def adir(tmp_path, monkeypatch):
    d = tmp_path / "artifacts"
    monkeypatch.setenv("IOD_STEGO_ARTIFACT_DIR", str(d))
    monkeypatch.delenv("IOD_STEGO_RETENTION_MAX_ARTIFACTS", raising=False)
    monkeypatch.setenv("IOD_STEGO_CAMERA", "disabled")
    return d


@pytest.fixture
def client(adir):
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app.test_client()


@pytest.fixture
def cover_id(adir):
    store = service.get_store()
    aid = artifacts.new_id()
    store.write(aid, "cover", images.encode_png(COVER))
    return aid


def post(client, path, body):
    r = client.post(path, data=json.dumps(body), content_type="application/json")
    return r.status_code, r.get_json()


def b64(b):
    return base64.b64encode(b).decode()


def tc(cid):
    return {"source": "test_cover", "test_cover_id": cid}


def test_health(client):
    r = client.get("/stego/health")
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and j["service"] == "python-stego"
    assert [a["name"] for a in j["algorithms"]] == NAMES and j["limits"]["max_frame_bytes"] == 1048576
    assert j["artifact_dir_writable"] is True and j["camera"]["mode"] == "disabled"
    assert "numpy" in j and "pillow" in j and "opencv_available" in j["camera"]


@pytest.mark.parametrize("alg", NAMES)
def test_encode_extract_roundtrip_each_algorithm(client, cover_id, adir, alg):
    frame = payload(30, seed=len(alg))  # fits dct_svd (1 bit per 8x8 block) in the 120x160 cover
    code, j = post(client, "/stego/encode", {"frame_b64": b64(frame), "cover": tc(cover_id), "algorithm": alg})
    assert code == 200 and j["ok"] and j["embed"]["algorithm"] == alg
    assert j["selection"]["reason_code"] == "MANUAL_OVERRIDE" and j["stego"]["format"] == "PNG"
    aid = j["artifact_id"]
    assert (adir / f"{aid}.png").is_file() and j["stego"]["path_name"] == f"{aid}.png"
    assert j["cover"]["artifact_id"] == cover_id and j["cover"]["source"] == "test_cover"
    code, e = post(client, "/stego/extract", {"artifact_id": aid})
    assert code == 200 and base64.b64decode(e["frame_b64"]) == frame
    assert e["bootstrap"] == {"version": 1, "alg_id": NAMES.index(alg) + 1, "algorithm": alg, "param": 0, "frame_len": 30}
    assert e["image"]["sha256"] == j["stego"]["sha256"] and e["image"]["size"] == j["stego"]["size"]


def test_encode_auto_standalone_flow(client, adir):
    frame = payload(90)
    code, j = post(client, "/stego/encode", {"frame_b64": b64(frame), "cover": {"source": "procedural", "seed": "s1"}})
    assert code == 200 and j["selection"]["mode"] == "auto"
    assert j["cover"]["source"] == "procedural" and j["cover"]["seed"] == "s1" and j["cover"]["transforms"] == ["mode:1->L"]
    assert j["cover"]["artifact_id"] == j["artifact_id"] and (adir / f"{j['artifact_id']}.cover.png").is_file()
    assert set(j["timings_ms"]) == {"capture", "select", "embed", "verify", "save"}
    m = j["embed"]["metrics"]
    assert {"mse", "psnr", "ssim", "changed_samples", "changed_fraction", "max_abs_diff"} <= set(m)
    _, e = post(client, "/stego/extract", {"artifact_id": j["artifact_id"]})
    assert base64.b64decode(e["frame_b64"]) == frame


def test_webcam_default_falls_back_and_records_reason(client):
    code, j = post(client, "/stego/encode", {"frame_b64": b64(b"hello-frame")})
    assert code == 200 and j["cover"]["source"] == "procedural_fallback" and j["cover"]["fallback_reason"] == "CAMERA_DISABLED"


def test_two_step_analyze_then_encode_same_cover_and_algorithm(client, adir):
    frame = payload(120, seed=42)
    code, a = post(client, "/stego/analyze", {"frame_bytes": len(frame), "cover": {"source": "procedural", "seed": "two-step"},
                                              "priority": "urgent"})
    assert code == 200 and a["ok"]
    sel, cov = a["selection"], a["cover"]
    assert sel["selected"] in NAMES and sel["selected_alg_id"] == NAMES.index(sel["selected"]) + 1
    assert "selected_param" in sel and cov["artifact_id"] and (adir / f"{cov['artifact_id']}.cover.png").is_file()
    assert cov["source"] == "procedural" and cov["seed"] == "two-step"
    # encode with the EXACT saved cover and the algorithm chosen by analyze
    code, e = post(client, "/stego/encode", {"frame_b64": b64(frame), "cover": tc(cov["artifact_id"]),
                                             "algorithm": sel["selected"], "param": sel["selected_param"],
                                             "priority": "urgent"})
    assert code == 200 and e["embed"]["algorithm"] == sel["selected"]
    assert e["cover"]["source"] == "test_cover" and e["cover"]["artifact_id"] == cov["artifact_id"]
    assert e["cover"]["sha256"] == cov["sha256"]  # same cover pixels/file
    # eligibility re-validation is deterministic: candidate rows agree with analyze
    strip = lambda rows: [{k: v for k, v in r.items() if k != "trial_ms"} for r in rows]
    # encode re-validates only the algorithm chosen by analyze; that row must equal analyze's row
    (row,) = strip(e["selection"]["candidates"])
    ref = next(r for r in strip(sel["candidates"]) if r["algorithm"] == sel["selected"])
    assert row == ref and row["eligible"]
    assert (adir / f"{e['artifact_id']}.png").is_file()
    assert not (adir / f"{e['artifact_id']}.cover.png").exists()  # exact saved cover reused, no copy
    _, x = post(client, "/stego/extract", {"artifact_id": e["artifact_id"]})
    assert base64.b64decode(x["frame_b64"]) == frame
    # cover pixels in the stego differ only where the algorithm embedded (same dims, mode)
    stego = Image.open(adir / f"{e['artifact_id']}.png")
    cover = Image.open(adir / f"{cov['artifact_id']}.cover.png")
    assert stego.size == cover.size and stego.mode == cover.mode


def test_analyze_auto_matches_standalone_encode_selection(client, cover_id):
    frame = payload(70)
    _, a = post(client, "/stego/analyze", {"frame_bytes": 70, "cover": tc(cover_id)})
    _, e = post(client, "/stego/encode", {"frame_b64": b64(frame), "cover": tc(cover_id)})
    assert a["selection"]["selected"] == e["selection"]["selected"] == e["embed"]["algorithm"]
    assert a["selection"]["reason_code"] == e["selection"]["reason_code"]
    assert a["cover"]["artifact_id"] == cover_id  # test cover is reused, not copied


def test_analyze_manual_override_and_errors(client, cover_id):
    code, a = post(client, "/stego/analyze", {"frame_bytes": 50, "cover": tc(cover_id), "algorithm": "pvd"})
    assert code == 200 and a["selection"]["selected"] == "pvd" and a["selection"]["reason_code"] == "MANUAL_OVERRIDE"
    code, a = post(client, "/stego/analyze", {"frame_bytes": 100000, "cover": tc(cover_id), "algorithm": "dct"})
    assert code == 422 and a["error"]["code"] == "ALGORITHM_NOT_ELIGIBLE" and len(a["error"]["details"]["candidates"]) == 10
    code, a = post(client, "/stego/analyze", {"frame_bytes": 100000, "cover": tc(cover_id)})
    assert code == 422 and a["error"]["code"] == "NO_ELIGIBLE_ALGORITHM" and a["ok"] is False
    code, a = post(client, "/stego/analyze", {"frame_bytes": "x", "cover": tc(cover_id)})
    assert code == 400 and a["error"]["code"] == "INVALID_REQUEST"
    code, a = post(client, "/stego/analyze", {"frame_bytes": 5000000, "cover": tc(cover_id)})
    assert code == 413 and a["error"]["code"] == "FRAME_TOO_LARGE"


def test_analyze_saves_no_stego_image(client, adir):
    _, a = post(client, "/stego/analyze", {"frame_bytes": 64, "cover": {"source": "procedural"}})
    files = sorted(p.name for p in adir.iterdir())
    assert files == [f"{a['cover']['artifact_id']}.cover.png"]


def test_capture_endpoint(client, adir):
    code, c = post(client, "/stego/capture", {"cover": {"source": "procedural", "seed": "cap"}})
    assert code == 200 and (adir / f"{c['cover']['artifact_id']}.cover.png").is_file()
    code, j = post(client, "/stego/encode", {"frame_b64": b64(b"x" * 20), "cover": tc(c["cover"]["artifact_id"])})
    assert code == 200


def test_encode_param_forced(client, cover_id):
    code, j = post(client, "/stego/encode", {"frame_b64": b64(payload(40)), "cover": tc(cover_id),
                                             "algorithm": "dct", "param": 20})
    assert code == 200 and j["embed"]["param"] == 20
    _, e = post(client, "/stego/extract", {"artifact_id": j["artifact_id"]})
    assert e["bootstrap"]["param"] == 20 and base64.b64decode(e["frame_b64"]) == payload(40)
    code, j = post(client, "/stego/encode", {"frame_b64": b64(b"x"), "cover": tc(cover_id), "algorithm": "dct", "param": 2})
    assert code == 400 and j["error"]["code"] == "INVALID_REQUEST"


def test_extract_tampered_png(client, adir, cover_id):
    _, j = post(client, "/stego/encode", {"frame_b64": b64(payload(40)), "cover": tc(cover_id), "algorithm": "lsb_replacement"})
    path = adir / f"{j['artifact_id']}.png"
    arr = np.array(Image.open(path))
    arr.reshape(-1)[5] ^= 1  # inside the bootstrap
    bad = artifacts.new_id()
    (adir / f"{bad}.png").write_bytes(images.encode_png(arr))
    code, e = post(client, "/stego/extract", {"artifact_id": bad})
    assert code == 422 and e["error"]["code"] in ("BOOTSTRAP_MISSING", "BOOTSTRAP_CORRUPT") and e["ok"] is False
    junk = artifacts.new_id()
    (adir / f"{junk}.png").write_bytes(b"not a png")
    code, e = post(client, "/stego/extract", {"artifact_id": junk})
    assert code == 422 and e["error"]["code"] == "IMAGE_DECODE_ERROR"


def test_artifact_not_found_and_bad_ids(client):
    code, e = post(client, "/stego/extract", {"artifact_id": artifacts.new_id()})
    assert code == 404 and e["error"]["code"] == "ARTIFACT_NOT_FOUND"
    for bad in ("../../etc/passwd", "x", "", None, 5, "A" * 32):
        code, e = post(client, "/stego/extract", {"artifact_id": bad})
        assert code == 400 and e["error"]["code"] == "INVALID_REQUEST"
    code, e = post(client, "/stego/encode", {"frame_b64": b64(b"abc"), "cover": tc("../../etc/passwd")})
    assert code == 400


def test_frame_too_large(client, cover_id):
    code, e = post(client, "/stego/encode", {"frame_b64": b64(b"\0" * (1024 * 1024 + 1)), "cover": tc(cover_id)})
    assert code == 413 and e["error"]["code"] == "FRAME_TOO_LARGE"
    code, e = post(client, "/stego/encode", {"frame_b64": b64(b"\0" * 5000), "cover": tc(cover_id),
                                             "limits": {"max_frame_bytes": 4096}})
    assert code == 413 and e["error"]["code"] == "FRAME_TOO_LARGE"
    code, e = post(client, "/stego/encode", {"frame_b64": "A" * (6 * 1024 * 1024)})
    assert code == 413 and e["error"]["code"] == "FRAME_TOO_LARGE"


def test_forced_ineligible_algorithm(client, cover_id, adir):
    big = payload(2000)  # exceeds DCT capacity of the 120x160 cover
    code, e = post(client, "/stego/encode", {"frame_b64": b64(big), "cover": tc(cover_id), "algorithm": "dct"})
    assert code == 422 and e["error"]["code"] == "ALGORITHM_NOT_ELIGIBLE" and e["error"]["details"]["reason"] == "CAPACITY_INSUFFICIENT"
    assert not [p for p in adir.iterdir() if not p.name.endswith(".cover.png")]  # nothing was saved
    code, e = post(client, "/stego/encode", {"frame_b64": b64(b"x"), "cover": tc(cover_id), "algorithm": "rot13"})
    assert code == 400 and e["error"]["code"] == "INVALID_REQUEST"


def test_invalid_requests(client):
    for body in ({}, {"frame_b64": 5}, {"frame_b64": "!!notbase64!!"}, {"frame_b64": ""}, {"frame_b64": b64(b"x"), "priority": "x"},
                 {"frame_b64": b64(b"x"), "policy": 3}, {"frame_b64": b64(b"x"), "limits": {"max_width": 0}},
                 {"frame_b64": b64(b"x"), "cover": {"source": "bogus"}}):
        code, e = post(client, "/stego/encode", body)
        assert code == 400 and e["error"]["code"] == "INVALID_REQUEST", body
    r = client.post("/stego/encode", data="[1,2]", content_type="application/json")
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_REQUEST"
    r = client.post("/stego/encode", data="not json")
    assert r.status_code == 400 and r.get_json()["ok"] is False


def test_never_accepts_client_paths_or_keys(client, adir, cover_id, tmp_path):
    outside = tmp_path / "outside.png"
    outside.write_bytes(images.encode_png(COVER))
    for field in ("path", "file", "artifact_path", "artifact_dir", "key", "mac_key", "aead_key", "secret", "directory"):
        for ep, body in (("/stego/extract", {"artifact_id": cover_id}), ("/stego/encode", {"frame_b64": b64(b"x"), "cover": tc(cover_id)}),
                         ("/stego/analyze", {"frame_bytes": 3, "cover": tc(cover_id)})):
            code, e = post(client, ep, dict(body, **{field: str(outside)}))
            assert code == 400 and e["error"]["code"] == "INVALID_REQUEST", (ep, field)
    # a path-like cover id / artifact id is never opened
    code, e = post(client, "/stego/extract", {"artifact_id": str(outside)})
    assert code == 400
    code, e = post(client, "/stego/encode", {"frame_b64": b64(b"x"), "cover": {"source": "test_cover", "test_cover_id": str(outside)}})
    assert code == 400
    code, e = post(client, "/stego/encode", {"frame_b64": b64(b"x"), "cover": {"source": "test_cover", "test_cover_id": cover_id, "path": str(outside)}})
    assert code == 200  # unknown cover keys are ignored, never used


def test_limits_cannot_raise_ceilings(client, adir):
    code, e = post(client, "/stego/capture", {"cover": {"source": "procedural"}, "limits": {"max_width": 100}})
    assert code == 413 and e["error"]["code"] == "IMAGE_TOO_LARGE"
    code, e = post(client, "/stego/capture", {"cover": {"source": "procedural"}, "limits": {"max_dim": 10**9}})
    assert code == 200


def test_retention_via_service(client, adir, monkeypatch, cover_id):
    monkeypatch.setenv("IOD_STEGO_RETENTION_MAX_ARTIFACTS", "2")
    ids = []
    for k in range(4):
        _, j = post(client, "/stego/encode", {"frame_b64": b64(payload(10, k)), "cover": {"source": "procedural", "seed": f"r{k}"},
                                              "algorithm": "lsb_replacement"})
        ids.append(j["artifact_id"])
    store = service.get_store()
    assert len(store.list_ids()) == 2 and ids[-1] in store.list_ids()


def test_camera_probe_endpoint(client):
    code, j = post(client, "/stego/camera/probe", {})
    assert code == 200 and j == {"available": False, "reason": "CAMERA_DISABLED"}
    r = client.post("/stego/camera/probe")
    assert r.status_code == 200
    code, j = post(client, "/stego/camera/probe", {"camera_index": "a"})
    assert code == 400


def test_no_payload_in_logs(client, cover_id, caplog):
    caplog.set_level("DEBUG")
    frame = b"SECRET-FRAME-BYTES-" + payload(30)
    post(client, "/stego/encode", {"frame_b64": b64(frame), "cover": tc(cover_id)})
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert b64(frame) not in text and "SECRET-FRAME" not in text


def test_internal_error_is_structured(client, cover_id, monkeypatch):
    monkeypatch.setattr(service, "encode", lambda req, store=None: (_ for _ in ()).throw(RuntimeError("boom secret")))
    code, e = post(client, "/stego/encode", {"frame_b64": b64(b"x"), "cover": tc(cover_id)})
    assert code == 500 and e["error"]["code"] == "INTERNAL_ERROR" and "secret" not in json.dumps(e)


def test_all_embedding_roundtrips_exact_for_grayscale_procedural(client):
    for alg in ("lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb"):
        frame = payload(25, seed=9)
        code, j = post(client, "/stego/encode", {"frame_b64": b64(frame), "cover": {"source": "procedural", "seed": "bw"}, "algorithm": alg})
        if code == 200:
            _, e = post(client, "/stego/extract", {"artifact_id": j["artifact_id"]})
            assert base64.b64decode(e["frame_b64"]) == frame
        else:
            assert j["error"]["code"] == "ALGORITHM_NOT_ELIGIBLE"
