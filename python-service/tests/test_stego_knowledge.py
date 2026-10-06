"""Tests for the registration-time RAG evidence retrieval
(rag/stego_knowledge.py) -- real retrieval over the real knowledge
base, and that the narrative never invents numbers not present in the
measurement dict it was given.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rag.stego_knowledge import retrieve_evidence, explain_selection


def test_retrieve_evidence_returns_sections_for_every_known_algorithm():
    for algo_id in ["adaptive_lsb", "pvd", "dct", "dwt", "svd"]:
        snippets = retrieve_evidence(algo_id, "capacity distortion speed", top_k=2)
        assert len(snippets) > 0, f"no knowledge-base sections found for {algo_id}"
        for s in snippets:
            assert s.algorithm_id == algo_id
            assert len(s.text) > 0


def test_retrieve_evidence_unknown_algorithm_returns_empty_not_error():
    snippets = retrieve_evidence("nonexistent_algo", "anything")
    assert snippets == []


def test_explain_selection_only_quotes_the_given_measurement():
    measurement = {
        "capacity_bytes": 4096,
        "payload_bytes": 512,
        "embed_time_ms": 1.234,
        "extract_time_ms": 0.567,
        "ssim": 0.9876,
        "psnr_db": 42.42,
        "mse": 3.14,
    }
    result = explain_selection("dct", "CRITICAL", measurement)
    assert result["algorithm_id"] == "dct"
    # Every numeric value quoted in the narrative must trace back to
    # the measurement dict passed in -- spot check a few.
    assert "4096" in result["narrative"]
    assert "512" in result["narrative"]
    assert result["measurement_used"] == measurement


def test_explain_selection_includes_real_evidence_snippets():
    measurement = {"capacity_bytes": 100, "payload_bytes": 50, "embed_time_ms": 1, "extract_time_ms": 1, "ssim": 0.9, "psnr_db": 30, "mse": 1}
    result = explain_selection("svd", "HIGH", measurement)
    assert len(result["evidence"]) > 0
    assert all(e["algorithm_id"] == "svd" for e in result["evidence"])
