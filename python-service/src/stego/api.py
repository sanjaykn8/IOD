"""Flask blueprint for the stego endpoints (spec §4.1)."""

import logging

from flask import Blueprint, jsonify, request

from . import cover as cover_mod, config, service
from .errors import StegoError

log = logging.getLogger("stego")
bp = Blueprint("stego", __name__, url_prefix="/stego")

_BODY_LIMIT = 4 * ((config.HARD_MAX_FRAME_BYTES + 2) // 3) + 64 * 1024
_UPLOAD_BODY_LIMIT = cover_mod.MAX_UPLOAD_B64 + 64 * 1024
_FORBIDDEN = {"path", "paths", "file", "filename", "dir", "directory", "artifact_dir", "artifact_path",
              "key", "keys", "secret", "mac_key", "meta_key", "aead_key", "password", "token", "plaintext"}


def _error_response(err):
    log.warning("stego error code=%s status=%s", err.code, err.http_status)
    return jsonify(err.to_dict()), err.http_status


@bp.errorhandler(StegoError)
def _on_stego(err):
    return _error_response(err)


@bp.errorhandler(413)
def _on_413(_e):
    return _error_response(StegoError("FRAME_TOO_LARGE", "request body too large"))


@bp.errorhandler(Exception)
def _on_exc(exc):
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return jsonify({"ok": False, "error": {"code": "INVALID_REQUEST", "message": exc.name}}), exc.code
    log.error("stego internal error type=%s", type(exc).__name__)  # never log payloads
    return _error_response(StegoError("INTERNAL_ERROR", "internal error"))


@bp.before_request
def _limit_body():
    limit = _UPLOAD_BODY_LIMIT if request.path.endswith("/cover/upload") else _BODY_LIMIT
    try:
        request.max_content_length = limit
    except Exception:
        pass
    if request.content_length is not None and request.content_length > limit:
        raise StegoError("FRAME_TOO_LARGE", "request body too large")


def _body(optional=False):
    data = request.get_json(force=True, silent=True)
    if data is None and optional:
        return {}
    if not isinstance(data, dict):
        raise StegoError("INVALID_REQUEST", "JSON object body required")
    bad = sorted(k for k in data if isinstance(k, str) and k.lower() in _FORBIDDEN)
    if bad:
        raise StegoError("INVALID_REQUEST", "client-supplied paths or keys are not accepted", {"fields": bad})
    return data


@bp.get("/health")
def health():
    return jsonify(service.health())


@bp.post("/camera/probe")
def camera_probe():
    body = _body(optional=True)
    ci = body.get("camera_index", 0)
    if isinstance(ci, bool) or not isinstance(ci, int) or not 0 <= ci <= 16:
        raise StegoError("INVALID_REQUEST", "camera_index must be an integer 0..16")
    ts = body.get("timeout_s")
    if ts is not None:
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not 0.05 <= ts <= 30:
            raise StegoError("INVALID_REQUEST", "timeout_s must be a number in [0.05, 30]")
    return jsonify(cover_mod.probe(ci, ts))


@bp.post("/cover/upload")
def cover_upload():
    return jsonify(service.upload_cover(_body()))


@bp.post("/capture")
def capture():
    return jsonify(service.capture(_body()))


@bp.post("/analyze")
def analyze():
    return jsonify(service.analyze(_body()))


@bp.post("/encode")
def encode():
    return jsonify(service.encode(_body()))


@bp.post("/extract")
def extract():
    return jsonify(service.extract_artifact(_body()))


@bp.post("/explain")
def explain():
    from rag.explain import explain as run_explain
    return jsonify(run_explain(_body()))
