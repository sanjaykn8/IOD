"""Flask app exposing the collaborative RAG / mock-LLM simulation.

Endpoints (all proxied by the Node.js gateway under `/api/rag/*`):
  POST /rag/contribute  { drone_id, content, confidence } -> stores one contribution
  POST /rag/run         { query, top_k? } -> retrieval -> validation -> fusion -> mock LLM
  GET  /rag/state       -> current contributions + last run result
  POST /rag/reset       -> clear all in-memory RAG state

This service makes NO outbound network calls (no paid API, no external
LLM) — see `llm/mock_provider.py`.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify
from flask_cors import CORS

import state
from rag.retrieval import retrieve
from rag.validation import validate
from rag.fusion import fuse
from llm.mock_provider import MockLLMProvider

app = Flask(__name__)
CORS(app)

llm_provider = MockLLMProvider()


@app.post("/rag/contribute")
def contribute():
    body = request.get_json(force=True, silent=True) or {}
    drone_id = body.get("drone_id")
    content = body.get("content")
    confidence = body.get("confidence", 0.8)
    if not drone_id or not content:
        return jsonify({"error": "drone_id and content are required"}), 400
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        return jsonify({"error": "confidence must be a number"}), 400
    confidence = max(0.0, min(1.0, confidence))
    c = state.add_contribution(drone_id, content, confidence)
    return jsonify({"status": "recorded", "contribution": c.to_dict()})


@app.post("/rag/run")
def run():
    body = request.get_json(force=True, silent=True) or {}
    query = body.get("query", "")
    top_k = int(body.get("top_k", 5))
    if not query:
        return jsonify({"error": "query is required"}), 400

    all_contribs = state.all_contributions()
    retrieved = retrieve(query, all_contribs, top_k=top_k)
    validated = validate(retrieved)
    fusion_result = fuse(validated)
    generated = llm_provider.generate(query, fusion_result["fused_context"])

    result = {
        "query": query,
        "llm_provider": llm_provider.name(),
        "retrieved_count": len(retrieved),
        "contributions": [c.to_dict() for c in validated],
        "fused_context": fusion_result["fused_context"],
        "included_drone_ids": fusion_result["included_drone_ids"],
        "excluded_drone_ids": fusion_result["excluded_drone_ids"],
        "generated_output": generated,
    }
    state.set_last_run_result(result)
    return jsonify(result)


@app.get("/rag/state")
def get_state():
    return jsonify({
        "contributions": [c.to_dict() for c in state.all_contributions()],
        "last_run_result": state.get_last_run_result(),
        "llm_provider": llm_provider.name(),
    })


@app.post("/rag/reset")
def reset():
    state.reset()
    return jsonify({"status": "reset"})


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "python-rag"})


if __name__ == "__main__":
    port = int(os.environ.get("IOD_PYTHON_PORT", "5001"))
    # Default 127.0.0.1 for the native (non-Docker) run path, where every
    # service runs on the same host. Overridable to 0.0.0.0 for Docker
    # (see python-service/Dockerfile), where the Flask process must bind
    # on all interfaces to be reachable from other containers by service
    # name -- binding to 127.0.0.1 inside a container only accepts
    # connections from that same container, which was a real bug caught
    # during a manual review of the Docker deployment path (Rust's
    # iod-server already had this configurable via IOD_BIND_ADDR; this
    # brings the Python service in line with the same pattern).
    host = os.environ.get("IOD_PYTHON_HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)
