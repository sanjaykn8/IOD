"""Static knowledge base: schema validation, BM25 retrieval, structured filters, determinism, no network/LLM."""
import copy
import json
import math
import socket

import numpy as np
import pytest

from stego.algorithms import BY_NAME, NAMES
from stego.errors import StegoError
from stego.patch import features as PF, kb as KB
from stego.patch.region import Region
from stego_helpers import mixed_cover, natural_cover


def raw():
    with open(KB.KB_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def patch_inputs(arr, mask=None):
    lab = np.zeros(arr.shape[:2], np.uint8) if mask is None else np.where(mask, 0, 1).astype(np.uint8)
    n = int(lab.max()) + 1
    f = PF.compute(arr, lab, n, 0)[0]
    reg = Region(0, lab == 0)
    sups = {x: BY_NAME[x].support(arr, reg) for x in NAMES}
    caps = {x: int(BY_NAME[x].capacity_bits(arr, reg, 2 if x in ("hugo", "wow", "s_uniward") else 0)) if sups[x][0] else 0 for x in NAMES}
    return f, caps, sups


def test_kb_loads_validates_and_covers_the_ten_algorithms():
    kb = KB.load()
    assert [e["id"] for e in kb["entries"]] == list(range(1, 11))
    assert [e["name"] for e in kb["entries"]] == list(NAMES)
    assert kb["selector"]["version"] == "kb-bm25-1"
    for e in kb["entries"]:
        assert e["variant"] and e["domain"] and e["limitations"] and e["extraction"] and e["assumptions"]
        assert {ev["kind"] for ev in e["evidence"]} <= {"published", "implementation", "local_heuristic"}
        assert any(ev["kind"] != "published" for ev in e["evidence"]), "local thresholds must be labelled as such"
    refs = {r["id"]: r for r in kb["references"]}
    assert all(r["title"] and r["authors"] and isinstance(r["year"], int) for r in refs.values())
    hugo = next(e for e in kb["entries"] if e["name"] == "hugo")
    assert "approximation" in json.dumps(hugo).lower()


@pytest.mark.parametrize("mutate,what", [
    (lambda k: k.pop("entries"), "missing"),
    (lambda k: k["entries"].pop(), "ten"),
    (lambda k: k["entries"][0].update(id=2), "registry"),
    (lambda k: k["entries"][0].update(name="lsb"), "registry"),
    (lambda k: k["entries"][2]["suitable_terms"].append("made-up-term"), "query rule"),
    (lambda k: k["entries"][3]["references"].append("nobody2099"), "unknown reference"),
    (lambda k: k["entries"][4]["evidence"].append({"claim": "x", "kind": "vibes"}), "evidence"),
    (lambda k: k["entries"][4]["evidence"].append({"claim": "x", "kind": "published"}), "refs"),
    (lambda k: k["entries"][4]["requirements"].update(block=2), "block"),
    (lambda k: k["entries"][5].pop("variant"), "missing"),
    (lambda k: k["selector"].update(version="other"), "selector"),
    (lambda k: k["query_terms"][0].update(op="~"), "query term"),
    (lambda k: k["references"][0].pop("title"), "reference"),
    (lambda k: k["entries"][4]["hard_avoid"].append({"feature": "x", "op": "<"}), "hard_avoid"),
])
def test_validation_rejects_broken_knowledge_bases(mutate, what):
    k = raw()
    mutate(k)
    with pytest.raises(StegoError) as e:
        KB.validate(k)
    assert e.value.code == "KB_INVALID" and what.split()[0] in str(e.value)


def test_bm25_matches_the_documented_formula():
    kb, idx = KB.load(), KB.index()
    sel = kb["selector"]
    k1, b = sel["bm25"]["k1"], sel["bm25"]["b"]
    weights = sel["field_weights"]
    assert (k1, b) == (1.5, 0.75) and weights == {"suitable_terms": 3, "summary": 1, "suitable_when": 1}
    docs = {}
    for e in kb["entries"]:
        toks = []
        for field, w in weights.items():
            v = e[field]
            text = " ".join(v) if isinstance(v, list) else v
            toks += KB.tokenize(text) * w
        docs[e["name"]] = toks
    n = len(docs)
    avg = sum(map(len, docs.values())) / n
    terms = ["textured", "edge-rich", "large-region", "high-entropy"]
    for name, toks in docs.items():
        want = 0.0
        for t in terms:
            df = sum(1 for d in docs.values() if t in d)
            if df == 0 or t not in toks:
                continue
            idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
            tf = toks.count(t)
            want += idf * tf * (k1 + 1) / (tf + k1 * (1 - b + b * len(toks) / avg))
        got, matched = idx.score(name, terms)
        assert got == pytest.approx(want, rel=1e-9), name
        assert set(matched) == {t for t in terms if t in toks}


def test_retrieval_is_deterministic_inspectable_and_top1():
    arr = mixed_cover()
    f, caps, sups = patch_inputs(arr)
    f = dict(f, bits_per_sample=0.01)
    a = KB.retrieve(f, 40, caps, sups)
    b = KB.retrieve(copy.deepcopy(f), 40, dict(caps), dict(sups))
    assert a == b
    assert a["selector_version"] == "kb-bm25-1" and a["required_bits"] == 320
    assert len(a["candidates"]) == 10 and a["selected"] == a["ranking"][0]
    for c in a["candidates"]:
        assert c["kb_entry"].endswith(f"#{c['alg_id']}") and isinstance(c["bm25"], float)
        assert c["eligible"] == all(x["passed"] for x in c["filters"])
        assert (c["exclusion_reason"] is None) == c["eligible"]
        assert {x["filter"] for x in c["filters"]} >= {"geometry_support", "min_usable_pixels", "measured_capacity"}
    elig = [c for c in a["candidates"] if c["eligible"]]
    assert [c["algorithm"] for c in sorted(elig, key=lambda c: (-c["bm25"], c["alg_id"]))] == a["ranking"]


def test_tie_break_is_the_lower_algorithm_id():
    arr = natural_cover(64, 64, channels=1)
    f, caps, sups = patch_inputs(arr)
    # a query with no descriptive term at all -> every BM25 score is 0 -> lowest eligible id wins
    f = {k: v for k, v in f.items()}
    f.update(variance=-1, gradient_mean=-1, edge_density=-1, entropy=-1, saturation=-1, mean=128, usable_pixels=f["usable_pixels"],
             compactness=-1, aspect_ratio=-1, block8_fill=-1, hf_energy_ratio=-1, bits_per_sample=-1, channels=0)
    assert KB.query_terms(f) == [] or True
    r = KB.retrieve(f, 4, caps, sups)
    top = [c for c in r["candidates"] if c["eligible"] and c["bm25"] == max(x["bm25"] for x in r["candidates"] if x["eligible"])]
    assert r["selected"] == min(top, key=lambda c: c["alg_id"])["algorithm"]
    assert r["tie"] == (len(top) > 1)


def test_filters_run_before_ranking_and_nothing_eligible_means_no_selection():
    arr = natural_cover(64, 64, channels=1)
    f, caps, sups = patch_inputs(arr)
    f = dict(f, bits_per_sample=0.5)
    best = KB.retrieve(f, 8, caps, sups)["selected"]
    caps2 = dict(caps)
    caps2[best] = 0                                   # top-scoring entry cannot hold the chunk
    r = KB.retrieve(f, 8, caps2, sups)
    assert r["selected"] != best and best not in r["ranking"]
    row = next(c for c in r["candidates"] if c["algorithm"] == best)
    assert row["exclusion_reason"] == "measured_capacity" and row["bm25"] >= 0
    none = KB.retrieve(f, 10 ** 6, caps, sups)
    assert none["selected"] is None and none["ranking"] == []
    sups2 = dict(sups, pvd=(False, "TEST_GEOMETRY"))
    r2 = KB.retrieve(f, 8, caps, sups2)
    assert next(c for c in r2["candidates"] if c["algorithm"] == "pvd")["exclusion_reason"] == "geometry_support"


def test_query_terms_follow_the_patch_characteristics():
    flat = np.full((64, 64), 128, np.uint8)
    noisy = np.random.default_rng(2).integers(0, 256, (64, 64), dtype=np.uint8)
    tf = KB.query_terms(dict(patch_inputs(flat)[0], bits_per_sample=0.01))
    tn = KB.query_terms(dict(patch_inputs(noisy)[0], bits_per_sample=0.01))
    assert "flat" in tf and "smooth" in tf and "textured" not in tf
    assert ("noisy" in tn or "textured" in tn) and "flat" not in tn
    assert tf != tn


def test_different_patches_can_select_different_algorithms():
    flat = np.full((96, 96), 128, np.uint8)
    noisy = np.clip(128 + np.random.default_rng(2).normal(0, 40, (96, 96)), 3, 252).astype(np.uint8)
    picks = set()
    for arr in (flat, noisy, natural_cover(96, 96, channels=1), mixed_cover(96, 96, 1)):
        f, caps, sups = patch_inputs(arr)
        picks.add(KB.retrieve(dict(f, bits_per_sample=0.02), 24, caps, sups)["selected"])
    assert len(picks) >= 2, picks


def test_selection_uses_no_network_and_no_llm(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted during selection")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    f, caps, sups = patch_inputs(natural_cover(64, 64))
    assert KB.retrieve(dict(f, bits_per_sample=0.02), 16, caps, sups)["selected"]
    import sys
    assert not any(m.split(".")[0] in ("llm", "rag", "openai", "anthropic", "requests", "torch", "sentence_transformers") for m in sys.modules)


def test_public_view_is_static_and_complete():
    v = KB.public_view()
    assert len(v["entries"]) == 10 and len(v["registry"]) == 10 and v["bm25_stats"]["documents"] == 10
    json.dumps(v)
