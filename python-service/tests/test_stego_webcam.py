"""Webcam paths: browser-captured frame upload (validated, stored cover) and the OpenCV adapter (fake cv2)."""
import base64
import sys
import types

import numpy as np
import pytest

from stego import cover, images, service
from stego.artifacts import ArtifactStore
from stego.config import Limits
from stego.errors import StegoError
from stego_helpers import natural_cover

LIM = Limits()


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(str(tmp_path))


def b64png(arr):
    return base64.b64encode(images.encode_png(arr)).decode()


def test_upload_roundtrip_and_use_as_cover(store):
    arr = natural_cover(120, 160)
    out = service.upload_cover({"image_b64": b64png(arr), "origin": "browser_webcam"}, store)
    c = out["cover"]
    assert c["source"] == "browser_webcam" and (c["width"], c["height"]) == (160, 120) and c["mode"] == "RGB"
    assert store.exists(c["artifact_id"], "cover")
    stored, _ = images.decode_png(store.read(c["artifact_id"], "cover"), LIM)
    assert np.array_equal(stored, arr)  # lossless, never resized
    an = service.analyze({"frame_bytes": 200, "cover": {"source": "browser_webcam", "cover_id": c["artifact_id"]}}, store)
    assert an["cover"]["source"] == "browser_webcam" and an["cover"]["artifact_id"] == c["artifact_id"]
    assert an["selection"]["selected"]


def test_encode_with_uploaded_cover_keeps_cover_and_label(store):
    arr = natural_cover(128, 128)
    cid = service.upload_cover({"image_b64": b64png(arr)}, store)["cover"]["artifact_id"]
    res = service.encode({"frame_b64": base64.b64encode(b"x" * 300).decode(), "algorithm": "lsb_matching",
                          "cover": {"source": "browser_webcam", "cover_id": cid}}, store)
    assert res["cover"]["source"] == "browser_webcam" and res["cover"]["artifact_id"] == cid
    assert store.exists(cid, "cover") and store.exists(res["artifact_id"], "stego")


def test_upload_origin_uploaded_label(store):
    out = service.upload_cover({"image_b64": b64png(natural_cover()), "origin": "uploaded"}, store)
    assert out["cover"]["source"] == "uploaded"


@pytest.mark.parametrize("bad,code", [
    (None, "INVALID_REQUEST"), ("", "INVALID_REQUEST"), ("!!notbase64!!", "INVALID_REQUEST"),
    (base64.b64encode(b"GIF89a....").decode(), "IMAGE_DECODE_ERROR"),
    (base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"garbage").decode(), "IMAGE_DECODE_ERROR"),
])
def test_upload_rejects_bad_input(store, bad, code):
    with pytest.raises(StegoError) as e:
        service.upload_cover({"image_b64": bad}, store)
    assert e.value.code == code
    assert list(store.list_ids()) == []


def test_upload_rejects_unknown_origin_and_dimension_limits(store):
    with pytest.raises(StegoError) as e:
        service.upload_cover({"image_b64": b64png(natural_cover()), "origin": "../x"}, store)
    assert e.value.code == "INVALID_REQUEST"
    with pytest.raises(StegoError) as e:
        service.upload_cover({"image_b64": b64png(natural_cover(20, 20))}, store)
    assert e.value.code == "IMAGE_TOO_SMALL"
    with pytest.raises(StegoError) as e:
        service.upload_cover({"image_b64": b64png(natural_cover(100, 100)), "limits": {"max_dim": 64}}, store)
    assert e.value.code == "IMAGE_TOO_LARGE"


def test_upload_converts_rgba_and_jpeg_is_refused(store):
    import io
    from PIL import Image
    rgba = Image.fromarray(np.dstack([natural_cover(64, 64), np.full((64, 64), 255, np.uint8)]), "RGBA")
    buf = io.BytesIO(); rgba.save(buf, "PNG")
    out = service.upload_cover({"image_b64": base64.b64encode(buf.getvalue()).decode()}, store)
    assert out["cover"]["mode"] == "RGB" and any("RGBA" in t for t in out["cover"]["transforms"])
    jb = io.BytesIO(); Image.fromarray(natural_cover(64, 64)).save(jb, "JPEG")
    with pytest.raises(StegoError) as e:
        service.upload_cover({"image_b64": base64.b64encode(jb.getvalue()).decode()}, store)
    assert e.value.code == "IMAGE_DECODE_ERROR"


def test_cover_spec_requires_valid_cover_id():
    for spec in ({"source": "browser_webcam"}, {"source": "uploaded", "cover_id": "../../etc"}, {"source": "browser_webcam", "cover_id": "A" * 32}):
        with pytest.raises(StegoError):
            cover.parse_cover_spec(spec)
    assert cover.parse_cover_spec({"source": "uploaded", "cover_id": "a" * 32})["cover_id"] == "a" * 32


def test_http_upload_route(tmp_path, monkeypatch):
    monkeypatch.setenv("IOD_STEGO_ARTIFACT_DIR", str(tmp_path))
    from app import app
    c = app.test_client()
    r = c.post("/stego/cover/upload", json={"image_b64": b64png(natural_cover(96, 96)), "origin": "browser_webcam"})
    assert r.status_code == 200 and r.get_json()["cover"]["source"] == "browser_webcam"
    r = c.post("/stego/cover/upload", json={"image_b64": "AAAA"})
    assert r.status_code == 422 and r.get_json()["error"]["code"] == "IMAGE_DECODE_ERROR"
    r = c.post("/stego/cover/upload", json={"image_b64": "x", "path": "/etc/passwd"})
    assert r.status_code == 400


# ---- OpenCV adapter with a fake cv2 module (no device needed)
class FakeCap:
    def __init__(self, frames, opened=True):
        self.frames, self.opened, self.released, self.reads = list(frames), opened, False, 0

    def isOpened(self):
        return self.opened

    def read(self):
        self.reads += 1
        return (True, self.frames.pop(0)) if self.frames else (False, None)

    def release(self):
        self.released = True


def install_cv2(monkeypatch, cap):
    m = types.ModuleType("cv2")
    m.VideoCapture = lambda *a, **k: cap
    m.CAP_DSHOW = 700
    monkeypatch.setitem(sys.modules, "cv2", m)


def test_opencv_adapter_warmup_bgr_to_rgb_and_release(monkeypatch):
    dark = np.zeros((48, 64, 3), np.uint8)
    good = np.zeros((48, 64, 3), np.uint8); good[..., 0] = 10; good[..., 1] = 20; good[..., 2] = 30  # BGR
    cap = FakeCap([dark] * (cover.WARMUP_FRAMES - 1) + [good])
    install_cv2(monkeypatch, cap)
    frame = cover.OpenCVCameraAdapter().capture(0, 2.0)
    assert cap.released and cap.reads == cover.WARMUP_FRAMES
    assert tuple(frame[0, 0]) == (30, 20, 10)  # RGB


def test_opencv_adapter_error_mapping(monkeypatch):
    install_cv2(monkeypatch, FakeCap([], opened=False))
    with pytest.raises(cover.CameraError):
        cover.OpenCVCameraAdapter().capture(0, 2.0)
    install_cv2(monkeypatch, FakeCap([]))
    with pytest.raises(cover.CameraCaptureFailed):
        cover.OpenCVCameraAdapter().capture(0, 2.0)
    gray = FakeCap([np.full((40, 40), 90, np.uint8)] * 8)
    install_cv2(monkeypatch, gray)
    assert cover.OpenCVCameraAdapter().capture(0, 2.0).shape == (40, 40, 3)
