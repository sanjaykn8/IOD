"""Flask app of the image service.

Namespaces (reached only through the Rust core; Node relays to Rust):
  /stego/*  patch-wise image transport: cover handling, planning (segmentation +
            knowledge-base retrieval), embedding, extraction, knowledge-base inspection
  /learn/*  educational workbench (isolated from the operational transport)

This service holds no keys, makes no outbound network calls and uses no LLM.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify  # noqa: E402
from flask_cors import CORS  # noqa: E402

from learn.api import bp as learn_bp  # noqa: E402
from stego.api import bp as stego_bp  # noqa: E402
from stego.patch import kb as _kb  # noqa: E402

app = Flask(__name__)
CORS(app)
app.register_blueprint(stego_bp)
app.register_blueprint(learn_bp)
_kb.load()  # validate the static knowledge base at start-up (fail fast on a bad edit)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "python-image-service"})


if __name__ == "__main__":
    port = int(os.environ.get("IOD_PYTHON_PORT", "5001"))
    # 127.0.0.1 for the native run path; set IOD_PYTHON_HOST=0.0.0.0 inside Docker so that
    # other containers can reach the service by name.
    host = os.environ.get("IOD_PYTHON_HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)
