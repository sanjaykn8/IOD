"""Educational workbench: deterministic walkthroughs, isolated experiments, metrics consistency."""
import base64
import io
import json
import os

import numpy as np
import pytest
from flask import Flask
from PIL import Image

from learn import experiment as E, fixtures as F, walkthrough as W
from learn.api import bp
from stego import metrics
from stego.algorithms import NAMES


def test_ten_walkthroughs_exact_and_deterministic():
    assert sorted(W.WALKTHROUGHS) == sorted(NAMES)
    for name in NAMES:
        a, b = W.walkthrough(name), W.walkthrough(name)
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True), name
        assert a["exact_match"] and a["all_checks_passed"], (name, a["checks"])
        assert a["embedded_bits"] == a["recovered_bits"] and len(a["embedded_bits"]) >= 1
        assert len(a["steps"]) >= 4
        for i, s in enumerate(a["steps"], 1):
            assert s["n"] == i and s["title"] and s["formula"] and s["substitution"] and s["result"]
        assert a["fixtures"]["synthetic_ciphertext_hex"] == "A63C915E"
        assert "not a real ciphertext" in a["fixtures"]["synthetic_label"]
        assert a["runtime_link"]


@pytest.mark.parametrize("name", ["hugo", "wow", "s_uniward"])
def test_teaching_models_are_labelled_with_their_simplification(name):
    d = W.walkthrough(name)
    assert d["teaching_model"] is True and len(d["simplification"]) > 60
    assert "h = 2" in json.dumps(d) and "h = 7" in json.dumps(d)


def test_payload_bits_are_the_fixed_fixture_msb_first():
    d = W.walkthrough("lsb_replacement")
    assert d["embedded_bits"] == format(0xA6, "08b")
    assert F.bits_of(b"\xa6")[:3] == [1, 0, 1]


def test_lsb_table_numbers_trace_to_the_formula():
    d = W.walkthrough("lsb_replacement")
    table = d["steps"][1]["table"]
    for i, p, _, b, new, _, ch in table["rows"]:
        assert new == (p & 0xFE) | b and ch == new - p and p == int(F.HAND_MATRIX[0, i])


def test_dct_first_coefficient_is_block_sum_over_eight():
    d = W.walkthrough("dct")
    X = d["steps"][1]["matrices"]["X (rounded)"]
    assert X[0][0] == pytest.approx(F.HAND_MATRIX.sum() / 8, abs=0.01)


def test_dwt_hh_values_match_formula():
    d = W.walkthrough("dwt")
    for row in d["steps"][1]["table"]["rows"]:
        _, a, b, c, dd, ll, hl, lh, hh = row
        assert hh == pytest.approx((a - b - c + dd) / 2) and ll == pytest.approx((a + b + c + dd) / 2)


def test_dct_svd_shows_svd_factors_that_reconstruct_s():
    d = W.walkthrough("dct_svd")
    st = next(s for s in d["steps"] if s["title"].endswith("SVD"))
    U, S, Vt = (np.array(st["matrices"][k]) for k in ("U", "Sigma", "V^T"))
    S_prev = np.array(next(s for s in d["steps"] if "sub-matrix" in s["title"])["matrices"]["S"])
    assert np.allclose(U @ S @ Vt, S_prev, atol=0.01)


# ------------------------------------------------------------------ experiments
def _decode(uri):
    return np.array(Image.open(io.BytesIO(base64.b64decode(uri.split(",", 1)[1]))), dtype=np.uint8)


def test_patch_experiment_uses_same_inputs_and_metrics_are_consistent(tmp_path, monkeypatch):
    monkeypatch.setenv("IOD_STEGO_ARTIFACT_DIR", str(tmp_path / "ops"))
    payload = bytes(range(24))
    r = E.run({"algorithms": "all", "cover": {"sample": "natural_gray_256"}, "payload_b64": base64.b64encode(payload).decode(),
               "robustness": False, "patch": "largest"})
    assert r["mode"] == "educational" and r["operational"] is False and "not a live UAV" in r["label"]
    assert r["production_kb_modified"] is False and "repository's implemented variants" in r["variant_notice"]
    assert r["same_inputs_for_all_algorithms"] and r["payload"]["bytes"] == 24
    seg = r["segmentation"]
    assert seg["version"] == "arg-cells-1" and seg["patch_count"] == len(r["survey"]) >= 2
    pid = r["patch"]["patch_id"]
    assert r["patch"]["chosen_by"] == "largest"
    assert r["patch"]["features"]["pixels"] == max(s["pixels"] for s in r["survey"])
    cover = _decode(r["cover"]["png"])
    assert len(r["results"]) == 10
    done = 0
    for row in r["results"]:
        assert row["variant"] and row["mask_support"]
        if row["status"] in ("rejected_capacity", "unsupported_geometry"):
            assert "extracted_b64" not in row
            continue
        done += 1
        assert row["status"] == "ok" and row["exact_recovery"] and row["ber"] == 0.0 and row["bit_accuracy"] == 1.0
        assert row["outside_patch_changes"] == 0
        stego = _decode(row["images"]["stego"])
        m = metrics.compute(cover, stego)
        assert row["mse"] == pytest.approx(m["mse"]) and row["psnr_db"] == pytest.approx(m["psnr"])
        assert row["bits_per_patch_sample"] == pytest.approx(192 / r["patch"]["features"]["pixels"])
        assert base64.b64decode(row["extracted_b64"]) == payload
        assert row["capacity_bits"] == r["survey"][pid]["capacity_bits"][row["algorithm"]]
        assert row["images"]["difference_x64"]["png"].startswith("data:image/png;base64,")
    assert done >= 7
    assert r["segmentation"]["overlay_png"].startswith("data:image/png") and r["patch"]["highlight_png"].startswith("data:image/png")
    assert not (tmp_path / "ops").exists(), "the workbench must not write to the operational artifact store"


def test_patch_choice_keywords_ids_and_survey():
    base = {"algorithms": ["lsb_replacement", "dct"], "cover": {"sample": "natural_rgb_256"}, "include_images": False}
    tex = E.run(dict(base, patch="most_textured"))
    smo = E.run(dict(base, patch="smoothest"))
    assert tex["patch"]["features"]["gradient_mean"] >= smo["patch"]["features"]["gradient_mean"]
    n = tex["segmentation"]["patch_count"]
    one = E.run(dict(base, patch=n - 1))
    assert one["patch"]["patch_id"] == n - 1 and one["patch"]["chosen_by"] == "explicit"
    for bad in (n, -1, "biggest", True, 1.5):
        with pytest.raises(Exception) as e:
            E.run(dict(base, patch=bad))
        assert getattr(e.value, "code", None) == "INVALID_REQUEST"
    for s in tex["survey"]:
        assert set(s["capacity_bits"]) == set(NAMES) and set(s["supported"]) == set(NAMES)
        assert s["kb_selected"] in (None, *NAMES) and (s["kb_ranking"][:1] == [s["kb_selected"]] or s["kb_selected"] is None)
        assert s["blocks8"] >= 0 and isinstance(s["query_terms"], list)
    ro = tex["patch"]["kb_retrieval_readonly"]
    assert ro["selector_version"] == "kb-risk-1" and len(ro["candidates"]) == 10


def test_experiments_never_modify_the_production_knowledge_base():
    from stego.patch import kb as KB
    before = json.dumps(KB.load(), sort_keys=True)
    mtime = os.path.getmtime(KB.KB_PATH)
    E.run({"algorithms": "all", "include_images": False, "robustness": True})
    assert json.dumps(KB.load(), sort_keys=True) == before and os.path.getmtime(KB.KB_PATH) == mtime


def test_insufficient_capacity_is_rejected_not_shortened():
    r = E.run({"algorithms": ["dct_svd", "lsb_replacement"], "cover": {"sample": "gray_64"},
               "payload_b64": base64.b64encode(b"x" * 40).decode(), "include_images": False})
    by = {x["algorithm"]: x for x in r["results"]}
    assert by["dct_svd"]["status"] in ("rejected_capacity", "unsupported_geometry")
    if by["dct_svd"]["status"] == "rejected_capacity":
        assert "not shortened" in by["dct_svd"]["error"]["message"]
    assert "extracted_b64" not in by["dct_svd"]
    assert by["lsb_replacement"]["status"] == "ok"


def test_robustness_is_deterministic_and_labelled_oracle():
    req = {"algorithms": ["lsb_matching", "dwt", "s_uniward"], "cover": {"sample": "natural_rgb_256"}, "robustness": True,
           "include_images": False, "patch": "largest"}
    a, b = E.run(req), E.run(req)
    for x, y in zip(a["results"], b["results"]):
        assert x["status"] == "ok"
        assert [r["outcome"] for r in x["robustness"]] == [r["outcome"] for r in y["robustness"]]
        assert [r["oracle_ber"] for r in x["robustness"]] == [r["oracle_ber"] for r in y["robustness"]]
        none = next(r for r in x["robustness"] if r["attack"] == "none")
        assert none["outcome"] == "recovered" and none["oracle_ber"] == 0.0
        for rr in x["robustness"]:
            if rr["outcome"] == "partial":
                assert 0 < rr["oracle_ber"] <= E.PARTIAL_BER
            if rr["oracle_ber"] > E.PARTIAL_BER:
                assert rr["outcome"] == "failed"
        crop = next(r for r in x["robustness"] if r["attack"] == "crop4")
        assert crop["outcome"] == "failed" and crop["oracle_ber"] == 1.0  # geometry change desynchronises
    ids = [at["id"] for at in a["attacks"]]
    assert ids[0] == "none" and {"jpeg75", "resize50", "gauss1", "saltpepper", "blur3"} <= set(ids)
    assert "oracle" in a["metric_definitions"]["robustness"]


def test_default_payload_is_the_synthetic_fixture():
    r = E.run({"algorithms": ["pvd"], "include_images": False})
    assert r["payload"]["kind"] == "synthetic" and r["payload"]["hex_preview"] == "A6 3C 91 5E"


def test_ber_definition_edge_cases():
    assert E.bit_compare(b"\xff", b"\xff")[3] == 0.0
    assert E.bit_compare(b"\xff", b"\xfe")[3] == pytest.approx(1 / 8)
    assert E.bit_compare(b"\xff\xff", b"\xff")[3] == pytest.approx(0.5)   # missing bits count as errors
    assert E.bit_compare(b"\xff", b"")[3] == 1.0


def test_attacks_are_fixed_and_keep_shape_except_crop():
    cov, _ = F.sample_cover("natural_rgb_256")
    for at in E.ATTACKS:
        a1, a2 = E.apply_attack(cov, at), E.apply_attack(cov, at)
        assert np.array_equal(a1, a2) and a1.dtype == np.uint8
        assert a1.shape == cov.shape or at["id"] == "crop4"


def test_samples_are_generated_deterministically():
    for s in F.SAMPLES:
        a, _ = F.sample_cover(s)
        b, _ = F.sample_cover(s)
        assert np.array_equal(a, b) and a.dtype == np.uint8


# ------------------------------------------------------------------ HTTP namespace
@pytest.fixture
def client():
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app.test_client()


def test_http_routes(client):
    r = client.get("/learn/registry")
    j = r.get_json()
    assert r.status_code == 200 and len(j["algorithms"]) == 10 and j["synthetic_ciphertext_hex"] == "A63C915E"
    assert client.get("/learn/walkthrough/dwt").get_json()["exact_match"] is True
    assert client.get("/learn/walkthrough/nope").status_code == 400
    r = client.post("/learn/experiment", json={"algorithms": ["nope"]})
    assert r.status_code == 400
    r = client.post("/learn/experiment", json={"algorithms": ["lsb_replacement"], "payload_b64": "!!"})
    assert r.status_code == 400
    buf = io.BytesIO()
    Image.fromarray(F.sample_cover("gray_64")[0]).save(buf, "PNG")
    r = client.post("/learn/experiment", json={"algorithms": ["lsb_replacement"], "include_images": False,
                                               "cover": {"upload_b64": base64.b64encode(buf.getvalue()).decode()}})
    assert r.status_code == 200 and r.get_json()["cover"]["source"] == "upload"
    jb = io.BytesIO()
    Image.fromarray(F.sample_cover("gray_64")[0]).save(jb, "JPEG")
    r = client.post("/learn/experiment", json={"cover": {"upload_b64": base64.b64encode(jb.getvalue()).decode()}})
    assert r.status_code == 422


def test_learn_package_does_not_import_operational_service_or_store():
    import learn.experiment as ex
    import learn.walkthrough as wt
    src = open(ex.__file__).read() + open(wt.__file__).read()
    assert "stego.service" not in src and "artifacts" not in src.replace("artifact store", "")
    assert "codec" not in src and "bootstrap" not in src.replace("bootstrap carrier", "")
    assert not hasattr(ex, "get_store")
    assert os.path.basename(ex.__file__) == "experiment.py"
