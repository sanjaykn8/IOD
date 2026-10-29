"""Structured errors with stable codes."""

_HTTP = {
    "INVALID_REQUEST": 400,
    "FRAME_TOO_LARGE": 413,
    "IMAGE_TOO_LARGE": 413,
    "IMAGE_TOO_SMALL": 422,
    "UNSUPPORTED_IMAGE_MODE": 422,
    "IMAGE_DECODE_ERROR": 422,
    "ARTIFACT_NOT_FOUND": 404,
    "BOOTSTRAP_MISSING": 422,
    "BOOTSTRAP_CORRUPT": 422,
    "UNSUPPORTED_VERSION": 422,
    "UNKNOWN_ALGORITHM": 422,
    "FRAME_LENGTH_INVALID": 422,
    "EXTRACT_FAILED": 422,
    "NO_ELIGIBLE_ALGORITHM": 422,
    "ALGORITHM_NOT_ELIGIBLE": 422,
    "ENCODE_VERIFY_FAILED": 422,
    "EMBED_VERIFY_FAILED": 500,
    "IMAGE_WRITE_FAILED": 500,
    "COVER_FAILED": 500,
    "INTERNAL_ERROR": 500,
    # algorithm-level capacity codes (surface to clients only inside
    # candidate tables / ALGORITHM_NOT_ELIGIBLE details)
    "CAPACITY_INSUFFICIENT": 422,
    "EDGE_CAPACITY_INSUFFICIENT": 422,
}

STABLE_CODES = frozenset(_HTTP)


class StegoError(Exception):
    def __init__(self, code, message, details=None, http_status=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details
        self.http_status = http_status or _HTTP.get(code, 500)

    def to_dict(self):
        err = {"code": self.code, "message": self.message}
        if self.details is not None:
            err["details"] = self.details
        return {"ok": False, "error": err}
