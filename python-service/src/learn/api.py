"""Flask blueprint for the EDUCATIONAL workbench: /learn/* (separate from /stego/*)."""

import logging

from flask import Blueprint, jsonify, request

from stego.errors import StegoError

from . import experiment, walkthrough

log = logging.getLogger("learn")
bp = Blueprint("learn", __name__, url_prefix="/learn")
_BODY_LIMIT = 4 * 1024 * 1024  # uploaded sample cover (<= 512x512 PNG) + payload


@bp.errorhandler(StegoError)
def _on_stego(err):
    log.warning("learn error code=%s", err.code)
    return jsonify(err.to_dict()), err.http_status


@bp.errorhandler(Exception)
def _on_exc(exc):
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return jsonify({"ok": False, "error": {"code": "INVALID_REQUEST", "message": exc.name}}), exc.code
    log.error("learn internal error type=%s", type(exc).__name__)
    return jsonify({"ok": False, "error": {"code": "INTERNAL_ERROR", "message": "internal error"}}), 500


@bp.before_request
def _limit():
    try:
        request.max_content_length = _BODY_LIMIT
    except Exception:
        pass
    if request.content_length is not None and request.content_length > _BODY_LIMIT:
        raise StegoError("FRAME_TOO_LARGE", "request body too large")


@bp.get("/registry")
def registry():
    return jsonify(dict(experiment.registry(), ok=True))


@bp.get("/walkthrough/<name>")
def one_walkthrough(name):
    if name not in walkthrough.WALKTHROUGHS:
        raise StegoError("INVALID_REQUEST", "unknown algorithm", {"allowed": list(walkthrough.WALKTHROUGHS)})
    return jsonify(dict(walkthrough.walkthrough(name), ok=True))


@bp.post("/experiment")
def run_experiment():
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        raise StegoError("INVALID_REQUEST", "JSON object body required")
    return jsonify(dict(experiment.run(body), ok=True))
