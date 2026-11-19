"""Static knowledge base + risk-aware retrieval (selector `kb-risk-1`).

Per patch: structured hard filters (operational policy, the KB's geometry/size/hard-avoid rules, measured
capacity) -> ranking of the eligible algorithms by
    1. risk tier from the versioned risk table (`kb/risk_table.json`, built on the validation split only),
    2. expected distortion: measured changes per embedded bit (same table),
    3. processing cost: measured milliseconds per KiB (same table),
    4. BM25 suitability of the KB text for the patch's descriptive terms (higher first),
    5. lower algorithm id.
Top-1 wins. No LLM, no embeddings, no network; deterministic.
"""

import json
import math
import os
import re
from functools import lru_cache

from ..algorithms import BY_ID, BY_NAME
from ..errors import StegoError
from . import SELECTOR_VERSION

KB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "kb", "algorithm_kb.json")
RISK_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "kb", "risk_table.json")
TIER_RANK = {"low": 0, "medium": 1, "high": 2, "not_measured": 3}
_TOKEN = re.compile(r"[a-z0-9][a-z0-9\-_]*")
_REQ_ENTRY = ("id", "name", "variant", "domain", "summary", "suitable_terms", "suitable_when", "avoid_when", "requirements",
              "hard_avoid", "capacity", "distortion", "cost", "assumptions", "extraction", "limitations", "references", "evidence")
_OPS = ("<", "<=", ">", ">=", "==", "between")


def tokenize(text):
    return _TOKEN.findall(str(text).lower())


def _fail(msg):
    raise StegoError("KB_INVALID", f"knowledge base invalid: {msg}")


def validate(kb):
    for k in ("kb_version", "schema_version", "selector", "query_terms", "references", "entries"):
        if k not in kb:
            _fail(f"missing '{k}'")
    if kb["selector"].get("version") != SELECTOR_VERSION:
        _fail("selector version mismatch")
    ref_ids = set()
    for r in kb["references"]:
        for k in ("id", "title", "authors", "year"):
            if not r.get(k):
                _fail(f"reference missing '{k}'")
        ref_ids.add(r["id"])
    terms = set()
    for q in kb["query_terms"]:
        if q.get("op") not in _OPS or not q.get("term") or not q.get("feature"):
            _fail("bad query term rule")
        terms.add(q["term"])
    ids = set()
    for e in kb["entries"]:
        for k in _REQ_ENTRY:
            if k not in e:
                _fail(f"entry {e.get('name')} missing '{k}'")
        alg = BY_ID.get(e["id"])
        if alg is None or alg.name != e["name"]:
            _fail(f"entry {e['name']} does not match the algorithm registry id")
        if e["id"] in ids:
            _fail("duplicate entry id")
        ids.add(e["id"])
        if not e["suitable_terms"] or any(t not in terms for t in e["suitable_terms"]):
            _fail(f"entry {e['name']} uses a suitable term without a query rule")
        for r in e["references"]:
            if r not in ref_ids:
                _fail(f"entry {e['name']} cites unknown reference {r}")
        for ev in e["evidence"]:
            if ev.get("kind") not in ("published", "implementation", "local_heuristic") or not ev.get("claim"):
                _fail(f"entry {e['name']} has an unlabelled evidence note")
            if ev["kind"] == "published" and not ev.get("refs"):
                _fail(f"entry {e['name']}: published evidence needs refs")
        for rule in e["hard_avoid"]:
            if rule.get("op") not in _OPS or "feature" not in rule or "reason" not in rule:
                _fail(f"entry {e['name']} has a bad hard_avoid rule")
        if e["requirements"].get("block", 0) != alg.block:
            _fail(f"entry {e['name']} block requirement differs from the implementation")
    if ids != set(BY_ID):
        _fail("entries must cover exactly the ten registered algorithms")
    return kb


@lru_cache(maxsize=1)
def load():
    with open(KB_PATH, encoding="utf-8") as fh:
        kb = json.load(fh)
    risk_table()                      # the selector needs both files; fail at start-up, not mid-plan
    return validate(kb)


def validate_risk(t):
    if not isinstance(t, dict) or not str(t.get("version", "")).startswith("risk-table-") or not isinstance(t.get("algorithms"), dict):
        _fail("risk table: missing version or algorithms")
    if set(t["algorithms"]) != set(BY_NAME):
        _fail("risk table must cover exactly the ten registered algorithms")
    for name, r in t["algorithms"].items():
        if r.get("tier") not in TIER_RANK:
            _fail(f"risk table: bad tier for {name}")
        for k in ("changes_per_bit", "ms_per_kib"):
            if not isinstance(r.get(k), (int, float)) or r[k] < 0:
                _fail(f"risk table: {name}.{k} must be a non-negative number")
        if r["tier"] != "not_measured" and not isinstance(r.get("auc"), (int, float)):
            _fail(f"risk table: {name} has a tier but no measured AUC")
    return t


@lru_cache(maxsize=1)
def risk_table():
    with open(RISK_PATH, encoding="utf-8") as fh:
        return validate_risk(json.load(fh))


def risk_key(name):
    r = risk_table()["algorithms"][name]
    return TIER_RANK[r["tier"]], float(r["changes_per_bit"]), float(r["ms_per_kib"])


def _cmp(value, op, ref):
    if value is None:
        return False
    if op == "between":
        return ref[0] <= value < ref[1]
    return {"<": value < ref, "<=": value <= ref, ">": value > ref, ">=": value >= ref, "==": value == ref}[op]


class Index:
    """BM25 (Okapi) over one document per algorithm; field weights via term repetition."""

    def __init__(self, kb):
        self.kb = kb
        self.k1 = float(kb["selector"]["bm25"]["k1"])
        self.b = float(kb["selector"]["bm25"]["b"])
        fw = kb["selector"]["field_weights"]
        self.docs = {}
        for e in kb["entries"]:
            toks = []
            for field, wt in sorted(fw.items()):
                val = e.get(field, "")
                text = " ".join(val) if isinstance(val, list) else str(val)
                toks += tokenize(text) * int(wt)
            tf = {}
            for t in toks:
                tf[t] = tf.get(t, 0) + 1
            self.docs[e["name"]] = (tf, len(toks))
        self.n = len(self.docs)
        self.avgdl = sum(dl for _, dl in self.docs.values()) / self.n
        df = {}
        for tf, _ in self.docs.values():
            for t in tf:
                df[t] = df.get(t, 0) + 1
        self.idf = {t: math.log(1.0 + (self.n - d + 0.5) / (d + 0.5)) for t, d in df.items()}

    def score(self, name, terms):
        tf, dl = self.docs[name]
        total, matched = 0.0, []
        for t in terms:
            f = tf.get(t, 0)
            if not f:
                continue
            total += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
            matched.append(t)
        return total, matched


@lru_cache(maxsize=1)
def index():
    return Index(load())


def query_terms(features):
    """Descriptive terms for a patch (deterministic order = KB rule order)."""
    return [q["term"] for q in load()["query_terms"] if _cmp(features.get(q["feature"]), q["op"], q["value"])]


def structural(features, supports):
    """{name: passes every structured filter except measured capacity}."""
    out = {}
    for e in load()["entries"]:
        ok = bool(supports[e["name"]][0]) and features["usable_pixels"] >= e["requirements"].get("min_usable_pixels", 1)
        if ok and e["requirements"].get("block"):
            ok = features.get(f"blocks{e['requirements']['block']}", 0) >= e["requirements"].get("min_blocks", 1)
        if ok:
            ok = not any(_cmp(features.get(r["feature"]), r["op"], r["value"]) for r in e["hard_avoid"])
        out[e["name"]] = ok
    return out


def retrieve(features, chunk_bytes, capacities, supports, allowed=None):
    """Structured filters -> risk-aware ranking (tier, distortion, cost, BM25, id) for one patch.

    features: patch feature dict (+ channels, block8_fill, bits_per_sample)
    capacities: {name: measured capacity bits}; supports: {name: (ok, reason)}
    allowed: operational policy (iterable of names); None = all ten (educational use)
    Returns an inspectable result; `selected` is None when nothing is eligible.
    """
    kb, idx, rt = load(), index(), risk_table()
    terms = query_terms(features)
    need = chunk_bytes * 8
    rows = []
    for e in kb["entries"]:
        name = e["name"]
        filters = []
        if allowed is not None:
            filters.append({"filter": "operational_policy", "passed": name in allowed,
                            "detail": None if name in allowed else "excluded by the operational algorithm policy"})
        ok, why = supports[name]
        filters.append({"filter": "geometry_support", "passed": bool(ok), "detail": why})
        req = e["requirements"]
        fp = features["usable_pixels"] >= req.get("min_usable_pixels", 1)
        filters.append({"filter": "min_usable_pixels", "passed": fp, "detail": f"{features['usable_pixels']} >= {req.get('min_usable_pixels', 1)}"})
        if req.get("block"):
            nb = features.get(f"blocks{req['block']}", 0)
            filters.append({"filter": "min_blocks", "passed": nb >= req.get("min_blocks", 1), "detail": f"{nb} complete {req['block']}x{req['block']} blocks >= {req.get('min_blocks', 1)}"})
        for rule in e["hard_avoid"]:
            hit = _cmp(features.get(rule["feature"]), rule["op"], rule["value"])
            filters.append({"filter": "hard_avoid:" + rule["feature"], "passed": not hit, "detail": rule["reason"] if hit else None})
        cap = int(capacities.get(name, 0))
        filters.append({"filter": "measured_capacity", "passed": cap >= need and need > 0, "detail": f"{cap} bits measured, {need} bits required"})
        eligible = all(f["passed"] for f in filters)
        score, matched = idx.score(name, terms)
        risk = rt["algorithms"][name]
        tier, cpb, cost = risk_key(name)
        rows.append({"algorithm": name, "alg_id": e["id"], "kb_entry": f"{kb['kb_version']}#{e['id']}", "eligible": eligible, "filters": filters,
                     "exclusion_reason": None if eligible else next(f["filter"] for f in filters if not f["passed"]),
                     "bm25": round(score, 6), "matched_terms": matched, "capacity_bits": cap,
                     "advisory_bits_per_sample": e["capacity"].get("advisory_bits_per_sample"),
                     "risk": {"tier": risk["tier"], "auc": risk.get("auc"), "changes_per_bit": cpb, "ms_per_kib": cost},
                     "expected_changes": int(round(cpb * need)), "expected_ms": round(cost * chunk_bytes / 1024.0, 3),
                     "_key": (tier, cpb, cost, -round(score, 6), e["id"])})
    ranked = sorted((r for r in rows if r["eligible"]), key=lambda r: r["_key"])
    for i, r in enumerate(ranked):
        r["rank"] = i + 1
    tie = len(ranked) > 1 and ranked[0]["_key"][:4] == ranked[1]["_key"][:4]
    for r in rows:
        del r["_key"]
    return {"selector_version": SELECTOR_VERSION, "kb_version": kb["kb_version"], "risk_table": rt["version"], "query_terms": terms,
            "required_bits": need, "selection_rule": "eligible -> risk tier -> changes per bit -> ms per KiB -> BM25 (higher) -> algorithm id",
            "candidates": rows, "ranking": [r["algorithm"] for r in ranked],
            "selected": ranked[0]["algorithm"] if ranked else None, "tie": tie}


def public_view():
    """KB for the UI/API (already static, non-secret)."""
    kb = load()
    idx = index()
    out = dict(kb)
    out["bm25_stats"] = {"documents": idx.n, "avg_doc_len": round(idx.avgdl, 3),
                         "idf": {t: round(v, 6) for t, v in sorted(idx.idf.items()) if t in {q["term"] for q in kb["query_terms"]}}}
    out["registry"] = [BY_NAME[e["name"]].describe() for e in kb["entries"]]
    out["risk_table"] = risk_table()
    return out
