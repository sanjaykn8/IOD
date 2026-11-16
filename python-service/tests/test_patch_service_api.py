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
from stego_helpers import payload

LIM = Limits()


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(str(tmp_path))


def b64(b):
    return base64.b64encode(b).decode()


def overwrite(store, aid, data):
    """Test-only tampering with a saved transport file (the store itself never overwrites one)."""
    with open(store._path(aid, "stego"), "wb") as fh:
        fh.write(data)


def frame_from(plan, wire):
    man = base64.b64decode(plan["manifest_b64"])
    return M.frame_header(len(man), len(wire)) + man + wire + bytes(32)


def plan_encode(store, wire_len=200, **extra):
    """plan on a freshly generated cover, then embed a frame-shaped byte string into exactly that cover."""
    pl = service.plan(dict({"payload_bytes": wire_len + 32}, **extra), store)
    frame = frame_from(pl, payload(wire_len))
    cid = pl["cover"]["artifact_id"]
    enc = service.encode({"frame_b64": b64(frame), "cover_id": cid}, store)
    return pl, frame, enc, cid


def test_full_cycle_reads_the_saved_png_and_reports_real_values(store):
    pl, frame, enc, cid = plan_encode(store)
    aid = enc["artifact_id"]
    for kind in ("stego", "diff"):
        assert store.exists(aid, kind)
    for kind in ("cover", "seg", "labels", "gen"):
        assert store.exists(cid, kind)
    # the file on disk, opened independently of the service
    with Image.open(io.BytesIO(store.read(aid, "stego"))) as im:
        assert im.format == "PNG" and im.size == (enc["stego"]["width"], enc["stego"]["height"]) == (320, 240) and im.mode == "RGB"
    ex = service.extract_artifact({"artifact_id": aid}, store)
    assert base64.b64decode(ex["frame_b64"]) == frame
    assert ex["resegmented"] is False and ex["bootstrap"]["frame_len"] == len(frame)
    e = enc["embed"]
    assert e["exact_frame_recovery_from_saved_png"] is True and e["used_patches"] == pl["plan"]["used_patches"]
    used = [p for p in e["patches"] if p["used"]]
    assert all(p["extraction"] == "verified_from_saved_png" for p in used)
    assert sum(p["payload_length"] for p in used) == 232
    assert e["metrics"]["psnr"] > 30 and 0 < e["metrics"]["mse"] and e["metrics"]["ssim"] <= 1
    pps = e["per_patch_summary"]
    assert pps["patches"] == len(used) and pps["patch_mse_max"] >= pps["patch_mse_mean"] > 0
    assert pps["changed_samples_total"] == sum(p["changed_samples"] for p in used) and pps["worst_patch_id"] in [p["patch_id"] for p in used]
    assert [p["patch_id"] for p in ex["patches"]] == [p["patch_id"] for p in used]
    summ = ex["manifest"]
    assert summ["patch_count"] == pl["plan"]["patch_count"] and summ["payload_len"] == 232
    labels, _ = images.decode_png(store.read(cid, "labels"), LIM)
    assert labels.shape == (240, 320) and int(labels.max()) == summ["patch_count"] - 1
    assert len(pl["inspection"]["palette"]) == summ["patch_count"]
    json.dumps([pl, enc, ex])


def test_plan_generates_a_fresh_cover_and_reports_generation_metadata(store):
    a = service.plan({"payload_bytes": 232}, store)
    b = service.plan({"payload_bytes": 232}, store)
    assert a["cover"]["artifact_id"] != b["cover"]["artifact_id"] and a["cover"]["sha256"] != b["cover"]["sha256"]
    assert a["cover"]["seed_fingerprint"] != b["cover"]["seed_fingerprint"]
    for pl in (a, b):
        c, g = pl["cover"], pl["generation"]
        assert c["source"] == "generated" and (c["width"], c["height"], c["mode"]) == (320, 240, "RGB")
        assert c["generator_version"] == "procgen-1" and c["profile"] == "raspberry_pi_5_cpu" and c["family"] == g["family"]
        assert c["quality_score"] == g["quality_score"] >= 0.70 and g["reused_for_replan"] is False
        assert 1 <= g["candidate_count"] <= 2 and g["budget"]["limit_ms"] == 2500 and g["payload_bytes"] == 232
        assert all(x["passed"] for x in g["quality"]["gates"])
        assert set(pl["timings_ms"]) == {"generate", "prescreen", "plan", "selection_total", "save"}
        # the stored PNG is exactly the selected cover and the record ties them together
        rec = json.loads(store.read(c["artifact_id"], "gen"))
        assert rec["cover_sha256"] == c["sha256"] == __import__("hashlib").sha256(store.read(c["artifact_id"], "cover")).hexdigest()
        text = json.dumps(pl).lower()
        for word in ("webcam", "fallback", "uploaded", '"seed"', "priority", "explanation", "llm"):
            assert word not in text, word
    d = a["plan"]
    assert d["selector_version"] == "kb-bm25-1" and d["segmentation"]["version"] == "arg-cells-1"
    for p in (p for p in d["patches"] if p["used"]):      # the knowledge base is consulted for every used patch
        r = p["retrieval"]
        assert len(r["candidates"]) == 10 and r["ranking"][0] == p["selected"] and r["query_terms"] is not None
        assert p["dry_run"]["ok"]


def test_cover_generation_settings_are_applied_and_validated(store):
    pl = service.plan({"payload_bytes": 232, "cover_generation": {"width": 400, "height": 304, "max_candidates": 1, "mode": "L",
                                                                 "families": ["cells"], "processing_budget_ms": 2000}}, store)
    c, g = pl["cover"], pl["generation"]
    assert (c["width"], c["height"], c["mode"], c["family"]) == (400, 304, "L", "cells") and g["candidate_count"] == 1
    assert g["config"]["processing_budget_ms"] == 2000 and g["config"]["families"] == ["cells"]
    for bad in ({"width": 2000}, {"max_candidates": 5}, {"seed": "x"}, {"profile": "development_host"}, {"cover_id": "a" * 32},
                {"processing_budget_ms": 99999}, {"min_quality_score": 0.1}, {"algorithm": "pvd"}, "terrain"):
        with pytest.raises(StegoError) as e:
            service.plan({"payload_bytes": 232, "cover_generation": bad}, store)
        assert e.value.code == "GENERATOR_CONFIG_INVALID", bad
    # request limits of the transport still bound the image
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 232, "limits": {"max_width": 200, "max_height": 200}}, store)
    assert e.value.code == "GENERATOR_CONFIG_INVALID"
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 232, "cover_generation": {"max_working_memory_mb": 16}}, store)
    assert e.value.code == "GENERATOR_MEMORY_LIMIT"
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 6000}, store)
    assert e.value.code == "PATCH_CAPACITY_INSUFFICIENT" and e.value.details["reason"] == "embedding_rate_above_limit"
    ok = service.plan({"payload_bytes": 6000, "cover_generation": {"allow_payload_driven_resize": True}}, store)
    assert ok["generation"]["resized"] and ok["cover"]["width"] > 320


@pytest.mark.parametrize("field,value", [
    ("cover", {"source": "webcam"}), ("cover", {"source": "browser_webcam", "cover_id": "a" * 32}), ("cover", {"source": "uploaded", "cover_id": "a" * 32}),
    ("cover", {"source": "test_cover", "test_cover_id": "a" * 32}), ("cover", {"source": "procedural", "seed": "s"}), ("seed", "abc"),
    ("cover_id", "a" * 32), ("test_cover_id", "a" * 32), ("image_b64", "iVBORw0KGgo="), ("algorithm", "pvd"), ("priority", "urgent"),
])
def test_old_cover_sources_seeds_and_images_cannot_be_injected(store, field, value):
    before = set(store.list_ids())
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 232, field: value}, store)
    assert e.value.code == "INVALID_REQUEST" and field in e.value.details["fields"]
    assert set(store.list_ids()) == before, "nothing was generated or stored"


def test_replan_reuses_the_exact_cover_and_never_generates(store, monkeypatch):
    first = service.plan({"payload_bytes": 232}, store)
    cid = first["cover"]["artifact_id"]
    png = store.read(cid, "cover")
    calls = []
    monkeypatch.setattr(service.select, "select_cover", lambda *a, **k: calls.append(1))
    monkeypatch.setattr(service.families, "generate", lambda *a, **k: calls.append(1))
    again = service.plan({"payload_bytes": 232, "replan_cover_id": cid, "min_level": 2}, store)
    assert calls == [], "a re-plan must not call the generator"
    assert again["cover"]["artifact_id"] == cid and again["cover"]["sha256"] == first["cover"]["sha256"]
    assert store.read(cid, "cover") == png, "the stored cover is untouched"
    assert again["generation"]["reused_for_replan"] is True and again["generation"]["seed_fingerprint"] == first["generation"]["seed_fingerprint"]
    assert again["plan"]["refinement_level"] == 2 and again["plan"]["patch_count"] <= first["plan"]["patch_count"]
    assert again["timings_ms"]["generate"] == 0.0
    # the coarser manifest embeds into the same image
    frame = frame_from(again, payload(200))
    enc = service.encode({"frame_b64": b64(frame), "cover_id": cid}, store)
    assert enc["cover"]["sha256"] == first["cover"]["sha256"]
    assert base64.b64decode(service.extract_artifact({"artifact_id": enc["artifact_id"]}, store)["frame_b64"]) == frame
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 232, "replan_cover_id": cid, "cover_generation": {}}, store)
    assert e.value.code == "INVALID_REQUEST"


def test_only_covers_generated_by_the_service_can_be_replanned_or_embedded(store):
    pl, frame, enc, cid = plan_encode(store)
    # a PNG dropped into the artifact directory (no generation record) is not a cover
    planted = "ab" * 16
    store.write(planted, "cover", store.read(cid, "cover"))
    for call in (lambda: service.plan({"payload_bytes": 232, "replan_cover_id": planted}, store),
                 lambda: service.encode({"frame_b64": b64(frame), "cover_id": planted}, store)):
        with pytest.raises(StegoError) as e:
            call()
        assert e.value.code == "ARTIFACT_NOT_FOUND"
    # a cover whose pixels were replaced after planning no longer matches its record
    other = service.plan({"payload_bytes": 232}, store)["cover"]["artifact_id"]
    with open(store._path(cid, "cover"), "wb") as fh:
        fh.write(store.read(other, "cover"))
    with pytest.raises(StegoError) as e:
        service.encode({"frame_b64": b64(frame), "cover_id": cid}, store)
    assert e.value.code == "ARTIFACT_NOT_FOUND"
    for bad in ("../x", "A" * 32, None, 7, "0" * 32):
        with pytest.raises(StegoError):
            service.encode({"frame_b64": b64(frame), "cover_id": bad}, store)


def test_encode_uses_the_planned_cover_and_never_generates(store, monkeypatch):
    pl = service.plan({"payload_bytes": 232}, store)
    cid = pl["cover"]["artifact_id"]
    frame = frame_from(pl, payload(200))
    calls = []
    with monkeypatch.context() as m:
        m.setattr(service.select, "select_cover", lambda *a, **k: calls.append(1))
        enc = service.encode({"frame_b64": b64(frame), "cover_id": cid}, store)
    assert calls == [] and enc["cover"]["artifact_id"] == cid and enc["cover"]["sha256"] == pl["cover"]["sha256"]
    assert set(enc["timings_ms"]) == {"load_cover", "embed", "verify", "save"}
    cover, _ = images.decode_png(store.read(cid, "cover"), LIM)
    stego, _ = images.decode_png(store.read(enc["artifact_id"], "stego"), LIM)
    assert cover.shape == stego.shape and 0 < int(np.abs(cover.astype(int) - stego.astype(int)).max()) <= 255
    for bad in ({"cover": {"source": "test_cover", "test_cover_id": cid}}, {"cover_generation": {}}, {"seed": "x"}, {}):
        with pytest.raises(StegoError) as e:
            service.encode(dict({"frame_b64": b64(frame)}, **bad), store)
        assert e.value.code == "INVALID_REQUEST"
    # a manifest planned for one cover does not embed into another generated cover of a different size
    other = service.plan({"payload_bytes": 232, "cover_generation": {"width": 400, "height": 304}}, store)["cover"]["artifact_id"]
    with pytest.raises(StegoError) as e:
        service.encode({"frame_b64": b64(frame), "cover_id": other}, store)
    assert e.value.code == "MANIFEST_INVALID"
    for bad in ("!!", 5, None):
        with pytest.raises(StegoError):
            service.encode({"frame_b64": bad, "cover_id": cid}, store)
    with pytest.raises(StegoError) as e:
        service.encode({"frame_b64": b64(frame[:40]), "cover_id": cid}, store)
    assert e.value.code == "FRAME_MALFORMED"
    with pytest.raises(StegoError) as e:
        service.encode({"frame_b64": b64(frame), "cover_id": cid, "limits": {"max_frame_bytes": 100}}, store)
    assert e.value.code == "FRAME_TOO_LARGE"


def test_failed_encode_leaves_no_stego_artifact(store, monkeypatch):
    pl = service.plan({"payload_bytes": 232}, store)
    frame = frame_from(pl, payload(200))
    before = set(store.list_ids())
    real = images.decode_png
    state = {"n": 0}

    def flaky(*a, **k):                      # the cover loads; re-reading the saved stego PNG fails
        state["n"] += 1
        if state["n"] > 1:
            raise StegoError("IMAGE_DECODE_ERROR", "forced")
        return real(*a, **k)
    monkeypatch.setattr(images, "decode_png", flaky)
    with pytest.raises(StegoError):
        service.encode({"frame_b64": b64(frame), "cover_id": pl["cover"]["artifact_id"]}, store)
    assert set(store.list_ids()) == before


def test_plan_validation(store):
    for bad in (None, 32, 0, "200", True, 10 ** 9):
        with pytest.raises(StegoError) as e:
            service.plan({"payload_bytes": bad}, store)
        assert e.value.code == "INVALID_REQUEST"
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 100, "min_level": 4}, store)
    assert e.value.code == "SEGMENTATION_FAILED"
    for seg in ({"bogus": 1}, {"max_regions": 0}, "x"):
        with pytest.raises(StegoError) as e:
            service.plan({"payload_bytes": 100, "segmentation": seg}, store)
        assert e.value.code == "INVALID_REQUEST"
    ok = service.plan({"payload_bytes": 100, "min_level": 1, "segmentation": {"min_region_px": 128}}, store)
    assert ok["plan"]["refinement_level"] >= 1 and ok["plan"]["segmentation"]["settings"]["min_region_px"] == 128


def test_failed_selection_stores_nothing(store, monkeypatch):
    def reject(*a, **k):
        raise StegoError("COVER_QUALITY_REJECTED", "forced", {"candidates": []})
    monkeypatch.setattr(service.select, "select_cover", reject)
    with pytest.raises(StegoError) as e:
        service.plan({"payload_bytes": 232}, store)
    assert e.value.code == "COVER_QUALITY_REJECTED" and store.list_ids() == []


def test_extract_tamper_cases(store):
    pl, frame, enc, _ = plan_encode(store)
    aid = enc["artifact_id"]
    arr, _ = images.decode_png(store.read(aid, "stego"), LIM)
    rr = pl["plan"]["reserved_rows"]
    # (a) carrier bit -> fails closed in Python
    t = arr.copy()
    t.reshape(-1)[200] ^= 1
    overwrite(store, aid, images.encode_png(t))
    with pytest.raises(StegoError) as e:
        service.extract_artifact({"artifact_id": aid}, store)
    assert e.value.code in ("BOOTSTRAP_CORRUPT", "BOOTSTRAP_MISSING", "UNSUPPORTED_VERSION", "FRAME_LENGTH_INVALID", "MANIFEST_TOO_LARGE")
    # (b) payload area -> a different frame comes back (the MAC check in Rust rejects it)
    t = arr.copy()
    t[rr:] ^= 1
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


# ------------------------------------------------------------------ HTTP
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("IOD_STEGO_ARTIFACT_DIR", str(tmp_path))
    from stego import artifacts
    if hasattr(artifacts, "_default"):
        monkeypatch.setattr(artifacts, "_default", None, raising=False)
    from app import app
    return app.test_client()


def test_http_flow_and_removed_routes(client):
    h = client.get("/stego/health").get_json()
    assert h["format_version"] == "frame-v2/appwire-v1/bootstrap-v2/manifest-v1" and len(h["algorithms"]) == 10
    assert h["selector_version"] == "kb-bm25-1" and h["segmentation_version"] == "arg-cells-1"
    g = h["cover_generator"]
    assert h["cover_source"] == "generated" and g["active_profile"] == "raspberry_pi_5_cpu" and g["generator_version"] == "procgen-1"
    assert g["effective"]["width"] == 320 and g["seeding"] == "os-random" and "camera" not in h
    r = client.post("/stego/plan", json={"payload_bytes": 232, "cover_generation": {"profile": "raspberry_pi_5_cpu", "width": 320, "height": 240}})
    assert r.status_code == 200
    plan = r.get_json()
    frame = frame_from(plan, payload(200))
    r = client.post("/stego/encode", json={"frame_b64": b64(frame), "cover_id": plan["cover"]["artifact_id"]})
    assert r.status_code == 200
    r = client.post("/stego/extract", json={"artifact_id": r.get_json()["artifact_id"]})
    assert r.status_code == 200 and base64.b64decode(r.get_json()["frame_b64"]) == frame
    kb = client.get("/stego/kb").get_json()
    assert kb["ok"] and len(kb["entries"]) == 10 and kb["segmentation_defaults"]["max_regions"] == 96
    # removed generic-RAG / explanation / whole-image endpoints
    for path in ("/stego/explain", "/stego/analyze", "/rag/run", "/rag/contribute", "/rag/status",
                 "/stego/camera/probe", "/stego/cover/upload", "/stego/capture"):       # camera / upload / capture are gone
        assert client.post(path, json={"image_b64": "AAAA", "origin": "uploaded"}).status_code in (404, 405), path
    assert client.get("/rag/status").status_code == 404


def test_http_rejects_bad_bodies_keys_paths_and_reports_codes(client):
    assert client.post("/stego/plan", data="[1]", content_type="application/json").status_code == 400
    assert client.post("/stego/plan", data="not json", content_type="application/json").status_code == 400
    for field in ("key", "mac_key", "path", "plaintext", "artifact_dir"):
        r = client.post("/stego/plan", json={"payload_bytes": 100, field: "x"})
        assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_REQUEST"
    r = client.post("/stego/extract", json={"artifact_id": "f" * 32})
    assert r.status_code == 404 and r.get_json()["error"]["code"] == "ARTIFACT_NOT_FOUND"
    for field in ("payload", "payload_b64", "ciphertext", "message", "wire_b64"):      # planning takes a LENGTH, never bytes
        r = client.post("/stego/plan", json={"payload_bytes": 100, field: "QUJD"})
        assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_REQUEST", field
    r = client.post("/stego/plan", json={"payload_bytes": 232, "cover": {"source": "webcam"}})
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_REQUEST"
    r = client.post("/stego/plan", json={"payload_bytes": 232, "cover_generation": {"seed": "abc"}})
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "GENERATOR_CONFIG_INVALID"
    r = client.post("/stego/plan", json={"payload_bytes": 40000, "limits": {"max_frame_bytes": 65536}})
    j = r.get_json()
    assert r.status_code == 422 and j["ok"] is False and j["error"]["code"] == "PATCH_CAPACITY_INSUFFICIENT"
    assert j["error"]["details"]["reason"] == "embedding_rate_above_limit" and j["error"]["details"]["candidates"] == []
