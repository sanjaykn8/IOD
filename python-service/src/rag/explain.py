"""SIMULATED RAG explanation of an already-made stego algorithm selection.

Pure function of its input: it reads the finished selection report, retrieves
curated knowledge-base entries with the existing word-overlap retrieval,
renders a template narrative (mock generator) and claim-checks it. It has no
write path to the decision. This is not a learned selector.
"""

import copy
import json
import math
import os
import re

from stego.algorithms import NAMES
from stego.errors import StegoError

from .models import Contribution
from .retrieval import jaccard, retrieve

_KB_PATH = os.path.join(os.path.dirname(__file__), "knowledge", "stego_algorithms.json")
_REASONS = {"BEST_SCORE", "TIE_BREAK_ORDER", "ONLY_ELIGIBLE", "MANUAL_OVERRIDE"}
_EXCL = {"CAPACITY_INSUFFICIENT", "EDGE_CAPACITY_INSUFFICIENT", "ENCODE_VERIFY_FAILED", "MSE_LIMIT",
         "PSNR_LIMIT", "COST_LIMIT", "INVALID_REQUEST", "INTERNAL_ERROR"}
_PRIORITIES = {"urgent", "normal", "background"}
_REASON_TEXT = {
    "BEST_SCORE": "it had the lowest weighted score among eligible candidates",
    "TIE_BREAK_ORDER": "several candidates scored within the tie epsilon, so the fixed tie-break order decided",
    "ONLY_ELIGIBLE": "it was the only candidate that passed capacity and constraint checks",
    "MANUAL_OVERRIDE": "the algorithm was forced manually and still passed the capacity and constraint checks",
}
_NUM_RE = re.compile(r"-?\d+(?:\.\d+)?")
_US_RE = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")
_PLAIN = [n for n in NAMES if "_" not in n]
_KB_CACHE = None


def load_kb():
    global _KB_CACHE
    if _KB_CACHE is None:
        with open(_KB_PATH, encoding="utf-8") as fh:
            _KB_CACHE = json.load(fh)
    return _KB_CACHE


def fmt(x):
    """Canonical number format used both in evidence and narrative."""
    if isinstance(x, int):
        return str(x)
    s = f"{x:.4f}".rstrip("0").rstrip(".")
    return s if s not in ("", "-0") else "0"


def _bad(msg):
    raise StegoError("INVALID_REQUEST", msg)


def _int(v, name, lo=0, hi=2**40):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        _bad(f"{name} must be an integer")
    return v


def _flt(v, name):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        _bad(f"{name} must be a finite number")
    return float(v)


def _opt_flt(v, name):
    return None if v is None else _flt(v, name)


def _validate(body):
    """Return a sanitised copy of the report; only whitelisted fields and values survive."""
    rep = body.get("selection") if isinstance(body.get("selection"), dict) else body
    if not isinstance(rep, dict):
        _bad("selection report required")
    sel = rep.get("selected")
    if not isinstance(sel, str) or sel not in NAMES:
        _bad("selection.selected must be a known algorithm name")
    reason = rep.get("reason_code")
    if reason not in _REASONS:
        _bad("selection.reason_code invalid")
    pv = rep.get("policy_version")
    if not isinstance(pv, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", pv):
        _bad("selection.policy_version invalid")
    prio = rep.get("priority", (rep.get("features") or {}).get("priority", "normal"))
    if prio not in _PRIORITIES:
        _bad("selection.priority invalid")
    f = rep.get("features")
    if not isinstance(f, dict):
        _bad("selection.features required")
    feats = {"width": _int(f.get("width"), "features.width", 1, 1 << 20),
             "height": _int(f.get("height"), "features.height", 1, 1 << 20),
             "frame_bytes": _int(f.get("frame_bytes"), "features.frame_bytes", 1, 1 << 30),
             "mode": f.get("mode") if f.get("mode") in ("L", "RGB") else _bad("features.mode invalid")}
    cands = rep.get("candidates")
    if not isinstance(cands, list) or not 1 <= len(cands) <= 16:
        _bad("selection.candidates must be a list of 1..16 entries")
    rows = []
    for c in cands:
        if not isinstance(c, dict) or c.get("algorithm") not in NAMES:
            _bad("candidate.algorithm invalid")
        ex = c.get("exclusion_reason")
        if ex is not None and ex not in _EXCL:
            _bad("candidate.exclusion_reason invalid")
        rows.append({"algorithm": c["algorithm"], "eligible": bool(c.get("eligible")), "exclusion_reason": ex,
                     "capacity_bytes": _int(c.get("capacity_bytes"), "candidate.capacity_bytes"),
                     "utilization": _opt_flt(c.get("utilization"), "candidate.utilization"),
                     "est_cost_units": _opt_flt(c.get("est_cost_units"), "candidate.est_cost_units"),
                     "mse": _opt_flt(c.get("mse"), "candidate.mse"), "psnr": _opt_flt(c.get("psnr"), "candidate.psnr"),
                     "ssim": _opt_flt(c.get("ssim"), "candidate.ssim"), "score": _opt_flt(c.get("score"), "candidate.score")})
    chosen = next((r for r in rows if r["algorithm"] == sel), None)
    if chosen is None or not chosen["eligible"]:
        _bad("selected algorithm must be an eligible candidate")
    return {"selected": sel, "reason_code": reason, "policy_version": pv, "priority": prio,
            "features": feats, "candidates": rows, "chosen": chosen}


def _report_evidence(rep):
    ev = []

    def add(text):
        ev.append({"id": f"r{len(ev) + 1}", "source": "report", "text": text})

    f, c = rep["features"], rep["chosen"]
    add(f"selected algorithm: {rep['selected']}")
    add(f"reason_code: {rep['reason_code']}")
    add(f"policy_version: {rep['policy_version']}; priority: {rep['priority']}")
    add(f"cover: {f['width']}x{f['height']} mode {f['mode']}; frame_bytes: {fmt(f['frame_bytes'])}")
    parts = [f"capacity_bytes: {fmt(c['capacity_bytes'])}"]
    for key, label in (("utilization", "utilization"), ("est_cost_units", "est_cost_units"), ("mse", "mse"),
                       ("psnr", "psnr_db"), ("ssim", "ssim"), ("score", "score")):
        if c[key] is not None:
            parts.append(f"{label}: {fmt(c[key])}")
    if c["psnr"] is None:
        parts.append("psnr: undefined (identical images)")
    add(f"measured for {rep['selected']}: " + "; ".join(parts))
    elig = [r["algorithm"] for r in rep["candidates"] if r["eligible"]]
    add(f"eligible candidates: {', '.join(elig)}; count: {len(elig)}")
    for r in rep["candidates"]:
        if not r["eligible"]:
            add(f"excluded: {r['algorithm']} reason {r['exclusion_reason']}")
    return ev


def _kb_text(e):
    return " ".join(e[k] for k in ("mechanics", "capacity", "distortion", "cost", "limitations"))


def _retrieve(rep, kb):
    contribs = [Contribution(drone_id=e["id"], content=f"{e['title']} {_kb_text(e)} {e['keywords']}", confidence=1.0,
                             timestamp_unix_ms=0) for e in kb["entries"]]
    query = f"{rep['selected']} {rep['reason_code']} {rep['policy_version']} selector policy png lossless " \
            f"{rep['priority']} capacity distortion cost limitations"
    by_id = {e["id"]: e for e in kb["entries"]}
    out = []
    for c in retrieve(query, contribs, top_k=3):
        e = by_id[c.drone_id]
        out.append({"kb_id": e["id"], "title": e["title"], "score": round(jaccard(query, c.content), 6),
                    "snippet": e["mechanics"][:160]})
    return out


def _generate_narrative(rep, kb_entry, policy_entry):
    """Mock template generator (no model, no randomness)."""
    f, c = rep["features"], rep["chosen"]
    s = [f"SIMULATED explanation (template text, not a learned selector): policy {rep['policy_version']} selected "
         f"{rep['selected']} for a {fmt(f['frame_bytes'])} byte frame on a {f['width']}x{f['height']} {f['mode']} cover "
         f"because {_REASON_TEXT[rep['reason_code']]}."]
    m = []
    if c["psnr"] is not None:
        m.append(f"psnr_db: {fmt(c['psnr'])}")
    if c["mse"] is not None:
        m.append(f"mse: {fmt(c['mse'])}")
    if c["ssim"] is not None:
        m.append(f"ssim: {fmt(c['ssim'])}")
    if c["est_cost_units"] is not None:
        m.append(f"est_cost_units: {fmt(c['est_cost_units'])}")
    m.append(f"capacity_bytes: {fmt(c['capacity_bytes'])}")
    s.append("Trial encode on this cover gave " + ", ".join(m) + ".")
    for r in rep["candidates"]:
        if not r["eligible"]:
            s.append(f"{r['algorithm']} was excluded ({r['exclusion_reason']}).")
    s.append(f"How it works: {kb_entry['mechanics']}")
    s.append(f"Known limitations: {kb_entry['limitations']}")
    s.append(f"Handoff: {policy_entry['limitations']}")
    return " ".join(s)


def _numbers(text):
    return {round(float(x), 6) for x in _NUM_RE.findall(text)}


def claim_check(narrative, evidence):
    """Every number and algorithm name in the narrative must appear in the evidence."""
    ev_text = " ".join(e["text"] for e in evidence)
    ev_nums = _numbers(ev_text)
    bad = [x for x in _NUM_RE.findall(narrative) if round(float(x), 6) not in ev_nums]
    ev_us = set(_US_RE.findall(ev_text))
    bad += [t for t in _US_RE.findall(narrative) if t not in ev_us]
    for n in _PLAIN:
        if re.search(rf"\b{n}\b", narrative) and not re.search(rf"\b{n}\b", ev_text):
            bad.append(n)
    return {"ok": not bad, "unsupported": sorted(set(bad))}


def explain(body):
    if not isinstance(body, dict):
        _bad("JSON object required")
    rep = _validate(copy.deepcopy(body))
    kb = load_kb()
    by_id = {e["id"]: e for e in kb["entries"]}
    alg_entry = by_id[f"alg-{rep['selected']}"]
    pol_entry = by_id["handoff-png-lossless"]
    evidence = _report_evidence(rep)
    for e in (alg_entry, pol_entry, by_id["policy-sel-policy-1"]):
        evidence.append({"id": f"kb:{e['id']}", "source": "kb", "text": f"{e['title']}. {_kb_text(e)}"})
    narrative = _generate_narrative(rep, alg_entry, pol_entry)
    check = claim_check(narrative, evidence)
    result = {
        "status": "simulated_rag" if check["ok"] else "unsupported_claims",
        "simulated": True,
        "narrative": narrative if check["ok"] else "",
        "evidence": evidence,
        "retrieved": _retrieve(rep, kb),
        "kb_version": kb["kb_version"],
        "generator": "mock-template",
        "selected_unchanged": True,
        "selected": rep["selected"],
    }
    if not check["ok"]:
        result["unsupported"] = check["unsupported"]
    return result
