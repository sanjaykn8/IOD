"""Resource profiles and validated cover-generation configuration.

Three layers, each can only TIGHTEN the one above it:

    HARD ceilings (constants below)  >  process configuration (profile + IOD_STEGO_GENERATOR_* environment)
                                     >  request (`cover_generation` object)

The same names and bounds are implemented in the Rust core (rust-core/src/transport/generator.rs); the
Rust core sends the effective configuration and this module validates it again against its own process
configuration. A request can never select a seed, a file, an artifact or an algorithm.

`raspberry_pi_5_cpu` is a conservative RESOURCE profile (image size, candidate count, time and memory
budgets) for a CPU-only Raspberry Pi 5. Running it on another machine applies the same limits but does
not reproduce Raspberry Pi execution speed.
"""

import os
from dataclasses import asdict, dataclass, replace

from ..errors import StegoError
from .families import FAMILIES, MODES

# ---- hard ceilings (never exceeded, whatever the profile, environment or request says)
HARD = {
    "min_dim": 96, "max_width": 1920, "max_height": 1080, "max_pixels": 1920 * 1080,
    "max_candidates": 8, "min_budget_ms": 200, "max_budget_ms": 30_000,
    "min_memory_mb": 16, "max_memory_mb": 1024, "max_workers": 1,
    "min_embedding_rate": 0.001, "max_embedding_rate": 1.0,
}
# Peak traced allocation per pixel of generate + pre-screen + plan, measured with tracemalloc on all four
# families at 320x240 and 640x480 (<= 194 bytes/pixel), rounded up. Used for the preflight estimate.
WORKING_BYTES_PER_PIXEL = 220
BASELINE_BYTES = 8 * 1024 * 1024

PROFILES = {
    "raspberry_pi_5_cpu": {
        "width": 320, "height": 240, "max_width": 640, "max_height": 480, "max_pixels": 640 * 480,
        "max_candidates": 2, "processing_budget_ms": 2500, "max_working_memory_mb": 96,
        "min_quality_score": 0.70, "max_embedding_rate": 0.20, "allow_payload_driven_resize": False, "workers": 1,
        "mode": "RGB", "families": FAMILIES,
    },
    # Larger ceilings for development machines; never the default.
    "development_host": {
        "width": 480, "height": 360, "max_width": 1280, "max_height": 960, "max_pixels": 1280 * 960,
        "max_candidates": 4, "processing_budget_ms": 8000, "max_working_memory_mb": 512,
        "min_quality_score": 0.70, "max_embedding_rate": 0.20, "allow_payload_driven_resize": False, "workers": 1,
        "mode": "RGB", "families": FAMILIES,
    },
}
DEFAULT_PROFILE = "raspberry_pi_5_cpu"
REQUEST_FIELDS = ("profile", "width", "height", "max_width", "max_height", "max_candidates", "processing_budget_ms",
                  "max_pixels", "max_working_memory_mb", "min_quality_score", "max_embedding_rate", "allow_payload_driven_resize",
                  "families", "workers", "mode")
ENV = {  # environment variable -> field (process level)
    "IOD_STEGO_GENERATOR_WIDTH": "width", "IOD_STEGO_GENERATOR_HEIGHT": "height",
    "IOD_STEGO_GENERATOR_MAX_WIDTH": "max_width", "IOD_STEGO_GENERATOR_MAX_HEIGHT": "max_height",
    "IOD_STEGO_GENERATOR_MAX_PIXELS": "max_pixels", "IOD_STEGO_GENERATOR_MAX_CANDIDATES": "max_candidates",
    "IOD_STEGO_GENERATOR_BUDGET_MS": "processing_budget_ms", "IOD_STEGO_GENERATOR_MAX_MEMORY_MB": "max_working_memory_mb",
    "IOD_STEGO_GENERATOR_MIN_QUALITY": "min_quality_score", "IOD_STEGO_GENERATOR_MAX_EMBED_RATE": "max_embedding_rate",
    "IOD_STEGO_GENERATOR_ALLOW_RESIZE": "allow_payload_driven_resize",
    "IOD_STEGO_GENERATOR_FAMILIES": "families", "IOD_STEGO_GENERATOR_WORKERS": "workers", "IOD_STEGO_GENERATOR_MODE": "mode",
}


@dataclass(frozen=True)
class GenConfig:
    profile: str
    width: int
    height: int
    max_width: int
    max_height: int
    max_pixels: int
    max_candidates: int
    processing_budget_ms: int
    max_working_memory_mb: int
    min_quality_score: float
    max_embedding_rate: float
    allow_payload_driven_resize: bool
    workers: int
    mode: str
    families: tuple

    def to_dict(self):
        d = asdict(self)
        d["families"] = list(self.families)
        return d


def _bad(msg, **details):
    return StegoError("GENERATOR_CONFIG_INVALID", msg, details or None)


def _int(name, v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise _bad(f"{name} must be an integer within {lo}..{hi}", field=name)
    return v


def _check_absolute(c):
    """Bounds that hold for every configuration (process or request)."""
    _int("max_width", c["max_width"], HARD["min_dim"], HARD["max_width"])
    _int("max_height", c["max_height"], HARD["min_dim"], HARD["max_height"])
    _int("max_pixels", c["max_pixels"], HARD["min_dim"] ** 2, HARD["max_pixels"])
    _int("width", c["width"], HARD["min_dim"], c["max_width"])
    _int("height", c["height"], HARD["min_dim"], c["max_height"])
    if c["width"] * c["height"] > c["max_pixels"]:
        raise _bad("width x height exceeds max_pixels", width=c["width"], height=c["height"], max_pixels=c["max_pixels"])
    if c["width"] % 8 or c["height"] % 8:
        raise _bad("width and height must be multiples of 8 (complete 8x8 blocks in every patch)")
    _int("max_candidates", c["max_candidates"], 1, HARD["max_candidates"])
    _int("processing_budget_ms", c["processing_budget_ms"], HARD["min_budget_ms"], HARD["max_budget_ms"])
    _int("max_working_memory_mb", c["max_working_memory_mb"], HARD["min_memory_mb"], HARD["max_memory_mb"])
    _int("workers", c["workers"], 1, HARD["max_workers"])
    q = c["min_quality_score"]
    if isinstance(q, bool) or not isinstance(q, (int, float)) or not 0.0 <= q <= 1.0:
        raise _bad("min_quality_score must be a number within 0..1")
    e = c["max_embedding_rate"]
    if isinstance(e, bool) or not isinstance(e, (int, float)) or not HARD["min_embedding_rate"] <= e <= HARD["max_embedding_rate"]:
        raise _bad("max_embedding_rate must be a number within 0.001..1 (payload bits per cover sample)")
    if not isinstance(c["allow_payload_driven_resize"], bool):
        raise _bad("allow_payload_driven_resize must be a boolean")
    if c["mode"] not in MODES:
        raise _bad("mode must be RGB or L")
    fam = c["families"]
    if (not isinstance(fam, (list, tuple)) or not fam or len(set(fam)) != len(fam) or not all(f in FAMILIES for f in fam)):
        raise _bad("families must be a non-empty list of distinct family names", allowed=list(FAMILIES))


def _env_value(field, raw):
    raw = raw.strip()
    if field == "families":
        return tuple(x.strip() for x in raw.split(",") if x.strip())
    if field == "allow_payload_driven_resize":
        if raw.lower() in ("1", "true", "yes", "on"):
            return True
        if raw.lower() in ("0", "false", "no", "off"):
            return False
        raise _bad("IOD_STEGO_GENERATOR_ALLOW_RESIZE must be true or false")
    if field == "mode":
        return raw.upper()
    try:
        return float(raw) if field in ("min_quality_score", "max_embedding_rate") else int(raw)
    except ValueError:
        raise _bad(f"invalid value for generator setting '{field}' in the environment") from None


def process_config(environ=None):
    """Profile defaults overridden by IOD_STEGO_GENERATOR_* (validated against the hard ceilings)."""
    environ = os.environ if environ is None else environ
    name = (environ.get("IOD_STEGO_GENERATOR_PROFILE") or DEFAULT_PROFILE).strip()
    if name not in PROFILES:
        raise _bad("unknown generator profile", profile=name, allowed=sorted(PROFILES))
    c = dict(PROFILES[name], profile=name)
    for var, field in ENV.items():
        raw = environ.get(var)
        if raw is not None and raw.strip() != "":
            c[field] = _env_value(field, raw)
    _check_absolute(c)
    c["families"] = tuple(c["families"])
    c["min_quality_score"] = float(c["min_quality_score"])
    c["max_embedding_rate"] = float(c["max_embedding_rate"])
    return GenConfig(**c)


def resolve(request, base=None):
    """Effective configuration for one request. Missing object/fields -> process defaults.

    Tightening only: dimensions within the process maxima, ceilings/candidates/budget/memory/embedding
    rate not above the process values, quality floor not below it, families a subset. Unknown fields are rejected, in
    particular anything that would select a seed, a file, an artifact or an algorithm.
    """
    base = base or process_config()
    if request is None:
        return base
    if not isinstance(request, dict):
        raise _bad("cover_generation must be an object")
    unknown = sorted(k for k in request if k not in REQUEST_FIELDS)
    if unknown:
        raise _bad("unknown cover_generation field(s); a request cannot choose a seed, file, artifact, source or algorithm",
                   fields=unknown, allowed=list(REQUEST_FIELDS))
    r = {k: v for k, v in request.items() if v is not None}
    if "profile" in r and r["profile"] != base.profile:
        raise _bad("profile differs from the active process profile (a request cannot switch profiles)",
                   active=base.profile, requested=r["profile"])
    c = base.to_dict()
    for k in ("max_width", "max_height", "max_pixels", "max_candidates", "processing_budget_ms", "max_working_memory_mb"):
        if k in r:
            if isinstance(r[k], bool) or not isinstance(r[k], int):
                raise _bad(f"{k} must be an integer", field=k)
            if r[k] > c[k]:
                raise _bad(f"{k} cannot be raised above the configured limit", field=k, limit=c[k], requested=r[k])
            c[k] = r[k]
    for k in ("width", "height"):
        if k in r:
            c[k] = r[k]
    if "min_quality_score" in r:
        q = r["min_quality_score"]
        if isinstance(q, bool) or not isinstance(q, (int, float)):
            raise _bad("min_quality_score must be a number")
        if q < base.min_quality_score:
            raise _bad("min_quality_score cannot be lowered below the configured floor", floor=base.min_quality_score, requested=q)
        c["min_quality_score"] = float(q)
    if "max_embedding_rate" in r:
        e = r["max_embedding_rate"]
        if isinstance(e, bool) or not isinstance(e, (int, float)):
            raise _bad("max_embedding_rate must be a number")
        if e > base.max_embedding_rate:
            raise _bad("max_embedding_rate cannot be raised above the configured limit", limit=base.max_embedding_rate, requested=e)
        c["max_embedding_rate"] = float(e)
    if "allow_payload_driven_resize" in r:
        c["allow_payload_driven_resize"] = r["allow_payload_driven_resize"]
    if "families" in r:
        fam = r["families"]
        if not isinstance(fam, (list, tuple)) or not all(isinstance(f, str) for f in fam) or not set(fam) <= set(base.families):
            raise _bad("families must be a subset of the enabled families", enabled=list(base.families))
        c["families"] = tuple(f for f in base.families if f in fam)      # canonical order
    if "workers" in r:
        c["workers"] = r["workers"]
    if "mode" in r:
        c["mode"] = r["mode"]
    # a tightened ceiling may now be below the default size: the request must then state a size that fits
    _check_absolute(c)
    c["families"] = tuple(c["families"])
    return GenConfig(**c)


def memory_estimate_bytes(width, height, candidates_held=1):
    return BASELINE_BYTES + WORKING_BYTES_PER_PIXEL * width * height + 3 * width * height * max(1, candidates_held)


def preflight_memory(cfg, width, height, candidates_held=1):
    """Estimate BEFORE any image allocation; raise GENERATOR_MEMORY_LIMIT if it would exceed the budget."""
    est = memory_estimate_bytes(width, height, candidates_held)
    limit = cfg.max_working_memory_mb * 1024 * 1024
    if est > limit:
        raise StegoError("GENERATOR_MEMORY_LIMIT", "estimated working memory exceeds the configured limit",
                         {"width": width, "height": height, "estimate_mb": round(est / 1048576, 2),
                          "limit_mb": cfg.max_working_memory_mb})
    return est


def with_size(cfg, width, height):
    return replace(cfg, width=width, height=height)


def public_view():
    """Non-secret description for health / UI."""
    cfg = process_config()
    return {"active_profile": cfg.profile, "effective": cfg.to_dict(), "hard_ceilings": dict(HARD),
            "profiles": {k: dict(v, families=list(v["families"])) for k, v in PROFILES.items()},
            "request_fields": list(REQUEST_FIELDS), "working_bytes_per_pixel": WORKING_BYTES_PER_PIXEL,
            "note": "resource profile only: limits are enforced, hardware speed is not emulated"}
