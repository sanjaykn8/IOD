"""Cover acquisition: webcam adapter (optional, lazy OpenCV) with procedural fallback."""

import os
import secrets
import threading
from dataclasses import dataclass, field

import numpy as np

from . import config, images
from .errors import StegoError
from .procedural import decode_latent, encode_text

SOURCES = ("webcam", "procedural", "test_cover", "browser_webcam", "uploaded")
STORED_SOURCES = ("test_cover", "browser_webcam", "uploaded")  # covers already saved via /cover/upload
WARMUP_FRAMES = 5


class CameraError(Exception):
    reason = "CAMERA_CAPTURE_FAILED"


class CameraAbsent(CameraError):
    reason = "CAMERA_ABSENT"


class CameraPermissionDenied(CameraError):
    reason = "CAMERA_PERMISSION_DENIED"


class CameraTimeout(CameraError):
    reason = "CAMERA_TIMEOUT"


class CameraBackendUnavailable(CameraError):
    reason = "CAMERA_BACKEND_UNAVAILABLE"


class CameraCaptureFailed(CameraError):
    reason = "CAMERA_CAPTURE_FAILED"


class CameraAdapter:
    backend = "none"

    def capture(self, camera_index=0, timeout_s=3.0):
        """Return an RGB uint8 (H,W,3) ndarray or raise a CameraError subclass."""
        raise NotImplementedError

    def opencv_available(self):
        return False


class OpenCVCameraAdapter(CameraAdapter):
    backend = "opencv"

    def opencv_available(self):
        try:
            import cv2  # noqa: F401
            return True
        except Exception:
            return False

    @staticmethod
    def _grab(camera_index):
        try:
            import cv2
        except Exception as exc:
            raise CameraBackendUnavailable("opencv not importable") from exc
        dev = f"/dev/video{camera_index}"
        if os.name == "posix" and os.path.exists(dev) and not os.access(dev, os.R_OK | os.W_OK):
            raise CameraPermissionDenied("no permission for camera device")
        cap = None
        try:
            if os.name == "nt" and hasattr(cv2, "CAP_DSHOW"):
                cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)  # faster, more reliable open on Windows
            else:
                cap = cv2.VideoCapture(camera_index)
            if not cap.isOpened():
                if os.name == "posix" and not os.path.exists(dev):
                    raise CameraAbsent("no camera device")
                raise CameraCaptureFailed("camera could not be opened")
            # Discard a few frames: cameras often deliver dark/unexposed frames right after opening.
            ok, frame = False, None
            for _ in range(WARMUP_FRAMES):
                ok, frame = cap.read()
                if not ok or frame is None:
                    break
            if not ok or frame is None:
                ok, frame = cap.read()
            if not ok or frame is None:
                raise CameraCaptureFailed("camera returned no frame")
            frame = np.asarray(frame)
            if frame.ndim == 2:
                return np.stack([frame] * 3, axis=-1).astype(np.uint8)
            if frame.ndim == 3 and frame.shape[2] >= 3:
                return np.ascontiguousarray(frame[:, :, 2::-1]).astype(np.uint8)  # BGR -> RGB
            raise CameraCaptureFailed("unexpected frame shape")
        finally:
            if cap is not None:
                try:
                    cap.release()
                except Exception:
                    pass

    def capture(self, camera_index=0, timeout_s=3.0):
        box = {}

        def work():
            try:
                box["frame"] = self._grab(camera_index)
            except BaseException as exc:  # noqa: BLE001 - relayed to caller
                box["error"] = exc

        t = threading.Thread(target=work, daemon=True, name="stego-camera")
        t.start()
        t.join(timeout_s)
        if t.is_alive():
            raise CameraTimeout("camera capture timed out")
        if "error" in box:
            err = box["error"]
            if isinstance(err, CameraError):
                raise err
            raise CameraCaptureFailed("camera capture failed") from err
        return box["frame"]


_adapter = None
_adapter_lock = threading.Lock()
_capture_lock = threading.Lock()


def set_camera_adapter(adapter):
    """Install an adapter (tests); None restores the default OpenCV adapter."""
    global _adapter
    with _adapter_lock:
        _adapter = adapter


def get_camera_adapter():
    global _adapter
    with _adapter_lock:
        if _adapter is None:
            _adapter = OpenCVCameraAdapter()
        return _adapter


def _try_camera(camera_index, timeout_s):
    """Returns (frame|None, reason|None)."""
    if config.camera_mode() == "disabled":
        return None, "CAMERA_DISABLED"
    adapter = get_camera_adapter()
    try:
        with _capture_lock:
            frame = adapter.capture(camera_index, timeout_s)
    except CameraError as exc:
        return None, exc.reason
    except Exception:
        return None, "CAMERA_CAPTURE_FAILED"
    return frame, None


def probe(camera_index=0, timeout_s=None):
    timeout_s = config.camera_timeout_s() if timeout_s is None else timeout_s
    frame, reason = _try_camera(camera_index, timeout_s)
    if frame is None:
        return {"available": False, "reason": reason}
    try:
        arr = np.asarray(frame)
        return {"available": True, "reason": None, "width": int(arr.shape[1]), "height": int(arr.shape[0])}
    except Exception:
        return {"available": False, "reason": "CAMERA_CAPTURE_FAILED"}


@dataclass
class Cover:
    array: np.ndarray
    source: str  # webcam | procedural_fallback | procedural | test_cover
    fallback_reason: str = None
    transforms: list = field(default_factory=list)
    seed: str = None
    artifact_id: str = None  # set for test_cover (loaded) or after saving


def procedural_cover(seed=None, size=512, limits=None):
    limits = limits or config.Limits()
    seed = secrets.token_hex(8) if seed is None else seed
    img = decode_latent(encode_text(seed), size)
    arr, transforms = images.from_pil(img, limits)
    return arr, transforms, seed


def parse_cover_spec(spec):
    if spec is None:
        spec = {}
    if not isinstance(spec, dict):
        raise StegoError("INVALID_REQUEST", "cover must be an object")
    source = spec.get("source", "webcam")
    if source not in SOURCES:
        raise StegoError("INVALID_REQUEST", "cover.source must be webcam|procedural|test_cover")
    out = {"source": source}
    if "camera_index" in spec and spec["camera_index"] is not None:
        ci = spec["camera_index"]
        if isinstance(ci, bool) or not isinstance(ci, int) or not 0 <= ci <= 16:
            raise StegoError("INVALID_REQUEST", "cover.camera_index must be an integer 0..16")
        out["camera_index"] = ci
    if "seed" in spec and spec["seed"] is not None:
        sd = spec["seed"]
        if not isinstance(sd, str) or len(sd) > 256:
            raise StegoError("INVALID_REQUEST", "cover.seed must be a string of at most 256 characters")
        out["seed"] = sd
    if source == "test_cover":
        from .artifacts import validate_id
        out["test_cover_id"] = validate_id(spec.get("test_cover_id"), "cover.test_cover_id")
    if source in ("browser_webcam", "uploaded"):
        from .artifacts import validate_id
        out["cover_id"] = validate_id(spec.get("cover_id"), "cover.cover_id")
    return out


def acquire(spec, limits, store=None):
    spec = parse_cover_spec(spec)
    source = spec["source"]
    if source == "test_cover":
        if store is None:
            raise StegoError("INTERNAL_ERROR", "no artifact store")
        data = store.read(spec["test_cover_id"], "cover")
        arr, transforms = images.decode_png(data, limits, convert=True)
        return Cover(arr, "test_cover", None, transforms, None, spec["test_cover_id"])
    if source in ("browser_webcam", "uploaded"):
        if store is None:
            raise StegoError("INTERNAL_ERROR", "no artifact store")
        data = store.read(spec["cover_id"], "cover")
        arr, transforms = images.decode_png(data, limits, convert=True)
        return Cover(arr, source, None, transforms, None, spec["cover_id"])
    if source == "procedural":
        arr, transforms, seed = procedural_cover(spec.get("seed"), limits=limits)
        return Cover(arr, "procedural", None, transforms, seed)
    frame, reason = _try_camera(spec.get("camera_index", 0), config.camera_timeout_s())
    if frame is not None:
        try:
            images.check_array(frame, limits)
            return Cover(np.ascontiguousarray(frame), "webcam", None, [], None)
        except StegoError:
            reason = "CAMERA_CAPTURE_FAILED"  # invalid frame: recorded fallback, never resized
    arr, transforms, seed = procedural_cover(spec.get("seed"), limits=limits)
    return Cover(arr, "procedural_fallback", reason, transforms, seed)


UPLOAD_ORIGINS = ("browser_webcam", "uploaded")
MAX_UPLOAD_B64 = 12 * 1024 * 1024
MAX_UPLOAD_BYTES = 8 * 1024 * 1024


def store_uploaded_cover(image_b64, origin, limits, store):
    """Validate a client-supplied PNG (e.g. a browser-webcam frame) and save it as a cover artifact.

    The image is fully decoded and re-encoded (metadata dropped, mode normalised, never resized),
    so only pixels the service itself produced are stored. Returns (Cover, artifact_id, png_bytes).
    """
    import base64
    import binascii
    from . import artifacts
    if origin not in UPLOAD_ORIGINS:
        raise StegoError("INVALID_REQUEST", "origin must be browser_webcam or uploaded")
    if not isinstance(image_b64, str) or not image_b64 or len(image_b64) > MAX_UPLOAD_B64:
        raise StegoError("INVALID_REQUEST", "image_b64 must be a non-empty base64 string within the size limit")
    try:
        raw = base64.b64decode(image_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StegoError("INVALID_REQUEST", "image_b64 is not valid base64") from exc
    if len(raw) > MAX_UPLOAD_BYTES:
        raise StegoError("FRAME_TOO_LARGE", "uploaded image too large")
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise StegoError("IMAGE_DECODE_ERROR", "only PNG images are accepted (lossless)")
    arr, transforms = images.decode_png(raw, limits, convert=True)
    png = images.encode_png(arr)
    aid = artifacts.new_id()
    store.write(aid, "cover", png)
    store.enforce_retention(keep_id=aid)
    return Cover(arr, origin, None, transforms, None, aid), aid, png
