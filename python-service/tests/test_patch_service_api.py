"""Service + HTTP boundary: plan -> encode (saved PNG re-read) -> extract; KB endpoint; strict validation."""
import base64
import io
import json

import numpy as np
import pytest
from PIL import Image

from stego import images, service
from stego.artifacts import ArtifactStore
from stego.config import Limits
from stego.errors import StegoError
from stego.patch import manifest as M
from stego_helpers import mixed_cover, payload

LIM = Limits()


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(str(tmp_path))


def b64(b):
    return base64.b64encode(b).decode()


def upload(store, arr):
    return service.upload_cover({"image_b64": b64(images.encode_png(arr)), "origin": "uploaded"}, store)["cover"]["artifact_id"]


def overwrite(store, aid, data):
    """Test-only tampering with a saved transport file (the store itself never overwrites one)."""
    with open(store._path(aid, "stego"), "wb") as fh:
        fh.write(data)


def frame_from(plan, wire):
    man = base64.b64decode(plan["manifest_b64"])
    return M.frame_header(len(man), len(wire)) + man + wire + bytes(32)


def plan_encode(store, wire_len=200, arr=None, **extra):
    cid = upload(store, mixed_cover() if arr is None else arr)
    spec = {"source": "uploaded", "cover_id": cid}
    pl = service.plan(dict({"payload_bytes": wire_len + 32, "cover": spec}, **extra), store)
    frame = frame_from(pl, payload(wire_len))
    enc = service.encode({"frame_b64": b64(frame), "cover": spec}, store)
    return pl, frame, enc, spec


def test_full_cycle_reads_the_saved_png_and_reports_real_values(store):
    pl, frame, enc, spec = plan_encode(store)
    aid = enc["artifact_id"]
    for kind in ("stego", "diff"):
        assert store.exists(aid, kind)
    cid = pl["cover"]["artifact_id"]
    for kind in ("cover", "seg", "labels"):
        assert store.exists(cid, kind)
    # the file on disk, opened independently of the service
    with Image.open(io.BytesIO(store.read(aid, "stego"))) as im:
        assert im.format == "PNG" and im.size == (enc["stego"]["width"], enc["stego"]["height"])
    ex = service.extract_artifact({"artifact_id": aid}, store)
    assert base64.b64decode(ex["frame_b64"]) == frame
    assert ex["resegmented"] is False and ex["bootstrap"]["frame_len"] == len(frame)
    e = enc["embed"]
    assert e["exact_frame_recovery_from_saved_png"] is True and e["used_patches"] == pl["plan"]["used_patches"]
    used = [p for p in e["patches"] if p["used"]]
    assert all(p["extraction"] == "verified_from_saved_png" for p in used)
    assert sum(p["payload_length"] for p in used) == 232
    assert e["metrics"]["psnr"] > 30 and 0 < e["metrics"]["mse"] and e["metrics"]["ssim"] <= 1
    assert [p["patch_id"] for p in ex["patches"]] == [p["patch_id"] for p in used]
    summ = ex["manifest"]
    assert summ["patch_count"] == pl["plan"]["patch_count"] and summ["payload_len"] == 232
    labels, _ = images.decode_png(store.read(cid, "labels"), LIM)
    assert labels.shape == (192, 256) and int(labels.max()) == summ["patch_count"] - 1
    assert len(pl["inspection"]["palette"]) == summ["patch_count"]
    json.dumps([pl, enc, ex])


def test_plan_reports_selection_details_and_no_priority_or_explanation(store):
    pl, _, enc, _ = plan_encode(store, 300)
    text = json.dumps([pl, enc]).lower()
    for word in ("priority", "urgent", "explanation", "llm"):
        assert word not in text, word
    d = pl["plan"]
    assert d["selector_version"] == "kb-bm25-1" and d["segmentation"]["version"] == "arg-cells-1"
    p = next(p for p in d["patches"] if p["used"])
    assert p["retrieval"]["candidates"] and p["retrieval"]["query_terms"] is not None
    assert "timings_ms" in pl and set(enc["timings_ms"]) == {"capture", "embed", "verify", "save"}


def test_encode_requires_the_planned_stored_cover_and_matching_manifest(store):
    pl, frame, enc, spec = plan_encode(store)
    for bad in (None, {"source": "procedural"}, {"source": "webcam"}, {}):
        with pytest.raises(StegoError) as e:
            service.encode({"frame_b64": b64(frame), "cover": bad}, store)
        assert e.value.code == "INVALID_REQUEST"
    other = upload(store, mixed_cover(96, 128))
    with pytest.raises(StegoError) as e:
        service.encode({"frame_b64": b64(frame), "cover": {"source": "uploaded", "cover_id": other}}, store)
    assert e.value.code == "MANIFEST_INVALID"
    for bad in ("!!", 5, None):
        with pytest.raises(StegoError):
            service.encode({"frame_b64": bad, "cover": spec}, store)
    with pytest.raises(StegoError) as e:
        service.encode({"frame_b64": b64(frame[:40]), "cover": spec}, store)
    assert e.value.code == "FRAME_MALFORMED"
    with pytest.raises(StegoError) as e:
        service.encode({"frame_b64": b64(frame), "cover": spec, "limits": {"max_frame_bytes": 100}}, store)
    assert e.value.code == "FRAME_TOO_LARGE"


def test_failed_encode_leaves_no_stego_artifact(store, monkeypatch):
    cid = upload(store, mixed_cover())
    spec = {"source": "uploaded", "cover_id": cid}
    pl = service.plan({"payload_bytes": 232, "cover": spec}, store)
    frame = frame_from(pl, payload(200))
    before = set(store.list_ids())
    monkeypatch.setattr(images, "decode_png", lambda *a, **k: (_ for _ in ()).throw(StegoError("IMAGE_DECODE_ERROR", "forced")))
    with pytest.raises(StegoError):
        service.encode({"frame_b64": b64(frame), "cover": spec}, store)
    assert set(store.list_ids()) == before


def test_plan_validation_and_capacity_rejection(store):
    cid = upload(store, mixed_cover(64, 64))
    spec = {"source": "uploaded", "cover_id": cid}
    for bad in (None, 32, 0, "200", True, 10 ** 9):
        with pytest.raises(StegoError) as e:
            service.plan({"payload_bytes": bad, "cover": spec}, store)
        assert e.value.code == "INVALID_REQUEST"
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 60000, "cover": spec, "limits": {"max_frame_bytes": 65536}}, store)
    assert e.value.code == "PATCH_CAPACITY_INSUFFICIENT" and len(e.value.details["attempts"]) == 4
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 100, "cover": spec, "min_level": 4}, store)
    assert e.value.code == "SEGMENTATION_FAILED"
    for seg in ({"bogus": 1}, {"max_regions": 0}, "x"):
        with pytest.raises(StegoError) as e:
            service.plan({"payload_bytes": 100, "cover": spec, "segmentation": seg}, store)
        assert e.value.code == "INVALID_REQUEST"
    ok = service.plan({"payload_bytes": 100, "cover": spec, "min_level": 1, "segmentation": {"min_region_px": 128}}, store)
    assert ok["plan"]["refinement_level"] >= 1 and ok["plan"]["segmentation"]["settings"]["min_region_px"] == 128


def test_min_level_gives_a_coarser_plan(store):
    cid = upload(store, mixed_cover(256, 320))
    spec = {"source": "uploaded", "cover_id": cid}
    a = service.plan({"payload_bytes": 200, "cover": spec}, store)
    b = service.plan({"payload_bytes": 200, "cover": spec, "min_level": 2}, store)
    assert b["plan"]["patch_count"] < a["plan"]["patch_count"] and b["plan"]["refinement_level"] == 2


def test_extract_tamper_cases(store):
    pl, frame, enc, _ = plan_encode(store)
    aid = enc["artifact_id"]
    arr, _ = images.decode_png(store.read(aid, "stego"), LIM)
    # (a) carrier bit -> fails closed in Python
    t = arr.copy()
    t.reshape(-1)[200] ^= 1
    overwrite(store, aid, images.encode_png(t))
    with pytest.raises(StegoError) as e:
        service.extract_artifact({"artifact_id": aid}, store)
    assert e.value.code in ("BOOTSTRAP_CORRUPT", "BOOTSTRAP_MISSING", "UNSUPPORTED_VERSION", "FRAME_LENGTH_INVALID", "MANIFEST_TOO_LARGE")
    # (b) payload area -> a different frame comes back (the MAC check in Rust rejects it)
    t = arr.copy()
    t[60:] ^= 1
    overwrite(store, aid, images.encode_png(t))
    try:
        got = base64.b64decode(service.extract_artifact({"artifact_id": aid}, store)["frame_b64"])
        assert got != frame
    except StegoError:
        pass
    # (c) not a PNG / truncated / unknown id
    overwrite(store, aid, b"\x89PNG\r\n\x1a\nnope")
    with pytest.raises(StegoError) as e:
        service.extract_artifact({"artifact_id": aid}, store)
    assert e.value.code == "IMAGE_DECODE_ERROR"
    with pytest.raises(StegoError) as e:
        service.extract_artifact({"artifact_id": "0" * 32}, store)
    assert e.value.code == "ARTIFACT_NOT_FOUND"
    for bad in ("../x", "A" * 32, None, 7):
        with pytest.raises(StegoError):
            service.extract_artifact({"artifact_id": bad}, store)


def test_capture_and_procedural_plan(store, monkeypatch):
    monkeypatch.setenv("IOD_STEGO_CAMERA", "off")
    c = service.capture({"cover": {"source": "procedural", "seed": "t-1"}}, store)["cover"]
    assert c["source"] == "procedural" and store.exists(c["artifact_id"], "cover")
    pl = service.plan({"payload_bytes": 150, "cover": {"source": "test_cover", "test_cover_id": c["artifact_id"]}}, store)
    assert pl["cover"]["artifact_id"] == c["artifact_id"] and pl["plan"]["used_patches"] >= 1
    w = service.plan({"payload_bytes": 150, "cover": {"source": "webcam"}}, store)
    assert w["cover"]["source"] in ("procedural_fallback", "webcam")
    if w["cover"]["source"] == "procedural_fallback":
        assert w["cover"]["fallback_reason"]


# ------------------------------------------------------------------ HTTP
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("IOD_STEGO_ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setenv("IOD_STEGO_CAMERA", "off")
    from stego import artifacts
    if hasattr(artifacts, "_default"):
        monkeypatch.setattr(artifacts, "_default", None, raising=False)
    from app import app
    return app.test_client()


def test_http_flow_and_removed_routes(client):
    h = client.get("/stego/health").get_json()
    assert h["format_version"] == "frame-v2/appwire-v1/bootstrap-v2/manifest-v1" and len(h["algorithms"]) == 10
    assert h["selector_version"] == "kb-bm25-1" and h["segmentation_version"] == "arg-cells-1"
    up = client.post("/stego/cover/upload", json={"image_b64": b64(images.encode_png(mixed_cover())), "origin": "uploaded"}).get_json()
    spec = {"source": "uploaded", "cover_id": up["cover"]["artifact_id"]}
    r = client.post("/stego/plan", json={"payload_bytes": 232, "cover": spec})
    assert r.status_code == 200
    frame = frame_from(r.get_json(), payload(200))
    r = client.post("/stego/encode", json={"frame_b64": b64(frame), "cover": spec})
    assert r.status_code == 200
    r = client.post("/stego/extract", json={"artifact_id": r.get_json()["artifact_id"]})
    assert r.status_code == 200 and base64.b64decode(r.get_json()["frame_b64"]) == frame
    kb = client.get("/stego/kb").get_json()
    assert kb["ok"] and len(kb["entries"]) == 10 and kb["segmentation_defaults"]["max_regions"] == 96
    # removed generic-RAG / explanation / whole-image endpoints
    for path in ("/stego/explain", "/stego/analyze", "/rag/run", "/rag/contribute", "/rag/status"):
        assert client.post(path, json={}).status_code in (404, 405), path
    assert client.get("/rag/status").status_code == 404


def test_http_rejects_bad_bodies_keys_paths_and_reports_codes(client):
    assert client.post("/stego/plan", data="[1]", content_type="application/json").status_code == 400
    assert client.post("/stego/plan", data="not json", content_type="application/json").status_code == 400
    for field in ("key", "mac_key", "path", "plaintext", "artifact_dir"):
        r = client.post("/stego/plan", json={"payload_bytes": 100, field: "x"})
        assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_REQUEST"
    r = client.post("/stego/extract", json={"artifact_id": "f" * 32})
    assert r.status_code == 404 and r.get_json()["error"]["code"] == "ARTIFACT_NOT_FOUND"
    up = client.post("/stego/cover/upload", json={"image_b64": b64(images.encode_png(mixed_cover(64, 64)))}).get_json()
    r = client.post("/stego/plan", json={"payload_bytes": 40000, "cover": {"source": "browser_webcam", "cover_id": up["cover"]["artifact_id"]},
                                         "limits": {"max_frame_bytes": 65536}})
    j = r.get_json()
    assert r.status_code == 422 and j["ok"] is False and j["error"]["code"] in ("PATCH_CAPACITY_INSUFFICIENT", "NO_ELIGIBLE_ALGORITHM")
    assert "attempts" in j["error"]["details"]
