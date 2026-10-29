import time

import numpy as np
import pytest

from stego import cover, images
from stego.artifacts import ArtifactStore, new_id
from stego.config import Limits
from stego.errors import StegoError
from stego_helpers import natural_cover

LIM = Limits()


class FakeCamera(cover.CameraAdapter):
    backend = "fake"

    def __init__(self, frame=None, exc=None, delay=0.0):
        self.frame, self.exc, self.delay, self.calls = frame, exc, delay, []

    def capture(self, camera_index=0, timeout_s=3.0):
        self.calls.append((camera_index, timeout_s))
        if self.delay:
            time.sleep(self.delay)
        if self.exc:
            raise self.exc
        return self.frame


@pytest.fixture(autouse=True)
def restore_adapter(monkeypatch):
    monkeypatch.delenv("IOD_STEGO_CAMERA", raising=False)
    yield
    cover.set_camera_adapter(None)


def use(adapter):
    cover.set_camera_adapter(adapter)
    return adapter


def test_available_camera_used():
    frame = natural_cover(48, 64, 3)
    cam = use(FakeCamera(frame))
    c = cover.acquire({"source": "webcam", "camera_index": 2}, LIM)
    assert c.source == "webcam" and c.fallback_reason is None and c.transforms == [] and c.seed is None
    assert np.array_equal(c.array, frame) and cam.calls[0][0] == 2


@pytest.mark.parametrize("exc,reason", [
    (cover.CameraPermissionDenied("x"), "CAMERA_PERMISSION_DENIED"),
    (cover.CameraAbsent("x"), "CAMERA_ABSENT"),
    (cover.CameraTimeout("x"), "CAMERA_TIMEOUT"),
    (cover.CameraBackendUnavailable("x"), "CAMERA_BACKEND_UNAVAILABLE"),
    (cover.CameraCaptureFailed("x"), "CAMERA_CAPTURE_FAILED"),
    (RuntimeError("unexpected"), "CAMERA_CAPTURE_FAILED"),
])
def test_failures_fall_back_with_recorded_reason(exc, reason):
    use(FakeCamera(exc=exc))
    c = cover.acquire({"source": "webcam"}, LIM)
    assert c.source == "procedural_fallback" and c.fallback_reason == reason
    assert c.transforms == ["mode:1->L"] and c.array.ndim == 2 and set(np.unique(c.array)) <= {0, 255}
    assert c.seed and c.array.shape == (512, 512)


def test_disabled_never_touches_adapter(monkeypatch):
    cam = use(FakeCamera(natural_cover(48, 64)))
    monkeypatch.setenv("IOD_STEGO_CAMERA", "disabled")
    c = cover.acquire({"source": "webcam"}, LIM)
    assert c.fallback_reason == "CAMERA_DISABLED" and cam.calls == []
    assert cover.probe() == {"available": False, "reason": "CAMERA_DISABLED"}


def test_invalid_frame_from_camera_is_fallback_not_resize():
    use(FakeCamera(np.zeros((10, 10, 3), np.uint8)))  # too small
    c = cover.acquire({"source": "webcam"}, LIM)
    assert c.source == "procedural_fallback" and c.fallback_reason == "CAMERA_CAPTURE_FAILED"
    use(FakeCamera(np.zeros((64, 64, 4), np.uint8)))
    assert cover.acquire({"source": "webcam"}, LIM).fallback_reason == "CAMERA_CAPTURE_FAILED"
    use(FakeCamera(np.zeros((64, 5000, 3), np.uint8)))  # exceeds ceiling
    assert cover.acquire({"source": "webcam"}, LIM).fallback_reason == "CAMERA_CAPTURE_FAILED"


def test_procedural_forced_and_seed_behaviour():
    cam = use(FakeCamera(natural_cover(48, 64)))
    a = cover.acquire({"source": "procedural", "seed": "abc"}, LIM)
    b = cover.acquire({"source": "procedural", "seed": "abc"}, LIM)
    assert cam.calls == [] and a.source == "procedural" and a.fallback_reason is None
    assert a.seed == "abc" and np.array_equal(a.array, b.array)
    r1, r2 = cover.acquire({"source": "procedural"}, LIM), cover.acquire({"source": "procedural"}, LIM)
    assert r1.seed != r2.seed and not np.array_equal(r1.array, r2.array)  # random per call


def test_probe_results():
    use(FakeCamera(natural_cover(48, 64, 3)))
    assert cover.probe(0, 1.0) == {"available": True, "reason": None, "width": 64, "height": 48}
    use(FakeCamera(exc=cover.CameraAbsent("x")))
    assert cover.probe(0, 1.0) == {"available": False, "reason": "CAMERA_ABSENT"}


def test_test_cover_loading(tmp_path):
    store = ArtifactStore(tmp_path)
    arr = natural_cover(40, 50, 3)
    aid = new_id()
    store.write(aid, "cover", images.encode_png(arr))
    c = cover.acquire({"source": "test_cover", "test_cover_id": aid}, LIM, store)
    assert c.source == "test_cover" and c.artifact_id == aid and np.array_equal(c.array, arr)
    with pytest.raises(StegoError) as ei:
        cover.acquire({"source": "test_cover", "test_cover_id": new_id()}, LIM, store)
    assert ei.value.code == "ARTIFACT_NOT_FOUND"
    for bad in ({"source": "test_cover"}, {"source": "test_cover", "test_cover_id": "../x"}):
        with pytest.raises(StegoError) as ei:
            cover.acquire(bad, LIM, store)
        assert ei.value.code == "INVALID_REQUEST"


@pytest.mark.parametrize("spec", [{"source": "bogus"}, {"source": "webcam", "camera_index": -1},
                                  {"source": "webcam", "camera_index": "0"}, {"source": "procedural", "seed": 5},
                                  {"source": "procedural", "seed": "x" * 300}, "webcam"])
def test_invalid_specs(spec):
    with pytest.raises(StegoError) as ei:
        cover.acquire(spec, LIM)
    assert ei.value.code == "INVALID_REQUEST"


def test_default_spec_is_webcam_with_fallback():
    use(FakeCamera(exc=cover.CameraAbsent("x")))
    assert cover.acquire(None, LIM).source == "procedural_fallback"


# ---- real OpenCV adapter without a device / with a hung backend (no physical camera needed) ----
def test_opencv_adapter_degrades_without_device():
    ad = cover.OpenCVCameraAdapter()
    with pytest.raises(cover.CameraError) as ei:
        ad.capture(7, 2.0)
    assert ei.value.reason in {"CAMERA_ABSENT", "CAMERA_PERMISSION_DENIED", "CAMERA_BACKEND_UNAVAILABLE",
                               "CAMERA_CAPTURE_FAILED", "CAMERA_TIMEOUT"}


def test_opencv_adapter_hard_timeout(monkeypatch):
    ad = cover.OpenCVCameraAdapter()
    monkeypatch.setattr(cover.OpenCVCameraAdapter, "_grab", staticmethod(lambda i: time.sleep(1.5)))
    t = time.perf_counter()
    with pytest.raises(cover.CameraTimeout):
        ad.capture(0, 0.1)
    assert time.perf_counter() - t < 1.0


def test_opencv_adapter_backend_unavailable(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "cv2":
            raise ImportError("no cv2")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    ad = cover.OpenCVCameraAdapter()
    with pytest.raises(cover.CameraBackendUnavailable):
        ad.capture(0, 1.0)
    assert ad.opencv_available() is False


def test_opencv_adapter_frame_conversion(monkeypatch):
    import sys
    import types
    bgr = np.zeros((40, 40, 3), np.uint8)
    bgr[..., 0], bgr[..., 2] = 10, 200  # B=10, R=200

    class Cap:
        def __init__(self, i): pass
        def isOpened(self): return True
        def read(self): return True, bgr
        def release(self): self.released = True

    monkeypatch.setitem(sys.modules, "cv2", types.SimpleNamespace(VideoCapture=Cap))
    monkeypatch.setattr(cover.os.path, "exists", lambda p: False)
    frame = cover.OpenCVCameraAdapter().capture(0, 2.0)
    assert frame.shape == (40, 40, 3) and frame[0, 0].tolist() == [200, 0, 10]
