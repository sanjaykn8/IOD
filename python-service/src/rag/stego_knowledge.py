"""Registration-time steganography evidence retrieval.

This is the "RAG" half of the RAG-assisted selection subsystem. It is
STRICTLY a retrieval+formatting layer over the hand-written knowledge
base in `knowledge/steganography/`:

  - `retrieve_evidence(algorithm_id, query)` returns verbatim excerpts
    from that algorithm's `.md` file, ranked by the same lexical
    word-overlap (Jaccard) scoring this project's original RAG module
    (`rag/retrieval.py`) already uses -- deliberately NOT embeddings
    or a vector store, and deliberately not described as one.
  - `explain_selection(...)` combines those excerpts with the REAL
    measurement numbers the selector already computed (passed in,
    never recomputed or guessed here) into a human-readable narrative
    for the UI/API response.

This module is architecturally unable to fabricate a performance
number: it has no embed/extract/timing code of its own, does not import
`stego.benchmark`'s measurement internals, and every number appearing
in its output is a value the CALLER already measured and passed in as
a plain argument. If a future change accidentally gave this module the
ability to invent a number, that would be a regression from this
design, not an extension of it -- see `docs/rag-stego-selection.md`.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

_KB_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "steganography", "algorithms")


def _word_set(text: str) -> set[str]:
    return {w.strip(".,!?;:()[]\"'`*-").lower() for w in text.split() if w.strip(".,!?;:()[]\"'`*-")}


def _jaccard(a: str, b: str) -> float:
    wa, wb = _word_set(a), _word_set(b)
    if not wa or not wb:
        return 0.0
    union = wa | wb
    return len(wa & wb) / len(union) if union else 0.0


@dataclass
class EvidenceSnippet:
    algorithm_id: str
    heading: str
    text: str
    relevance: float

    def to_dict(self) -> dict:
        return {"algorithm_id": self.algorithm_id, "heading": self.heading, "text": self.text, "relevance": round(self.relevance, 4)}


def _load_sections(algorithm_id: str) -> list[tuple[str, str]]:
    """Split one algorithm's knowledge-base markdown file into
    (heading, body) sections on `##` headings. Returns `[]` if the file
    does not exist (never raises -- a missing knowledge-base entry is a
    documentation gap, not a reason to fail a registration)."""
    path = os.path.join(_KB_ROOT, f"{algorithm_id}.md")
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    # Drop YAML frontmatter if present.
    text = re.sub(r"^---.*?---\s*", "", text, flags=re.DOTALL)
    parts = re.split(r"(?m)^##\s+", text)
    sections = []
    for part in parts[1:]:  # parts[0] is content before the first "## "
        lines = part.split("\n", 1)
        heading = lines[0].strip()
        body = lines[1].strip() if len(lines) > 1 else ""
        sections.append((heading, body))
    return sections


def retrieve_evidence(algorithm_id: str, query: str, top_k: int = 2) -> list[EvidenceSnippet]:
    """Real lexical retrieval over the real knowledge-base file for one
    algorithm. Returns the `top_k` sections most relevant to `query` by
    word-overlap score -- verbatim excerpts, never paraphrased or
    generated."""
    sections = _load_sections(algorithm_id)
    scored = [(heading, body, _jaccard(query, heading + " " + body)) for heading, body in sections]
    scored.sort(key=lambda t: t[2], reverse=True)
    return [EvidenceSnippet(algorithm_id, heading, body, score) for heading, body, score in scored[:top_k]]


def explain_selection(algorithm_id: str, importance: str, measurement: dict, query: str | None = None) -> dict:
    """Build the narrative explanation shown to the operator for why
    `algorithm_id` was selected. `measurement` is the REAL,
    already-computed measurement dict for this algorithm (from
    `stego.benchmark.AlgorithmMeasurement.to_dict()`, as the selector
    already has it) -- every number quoted below is read from it
    verbatim, never recomputed or invented here."""
    q = query or f"{algorithm_id} capacity distortion speed {importance.lower()} importance registration payload"
    evidence = retrieve_evidence(algorithm_id, q, top_k=2)
    narrative = (
        f"Selected '{algorithm_id}' for a {importance}-importance payload based on REAL measurements on "
        f"this specific cover image and payload: capacity={measurement.get('capacity_bytes')}B "
        f"(payload={measurement.get('payload_bytes')}B), embed={measurement.get('embed_time_ms', 0):.3f}ms, "
        f"extract={measurement.get('extract_time_ms', 0):.3f}ms, SSIM={measurement.get('ssim', 0):.4f}, "
        f"PSNR={measurement.get('psnr_db', 0):.2f}dB, MSE={measurement.get('mse', 0):.4f}."
    )
    return {
        "algorithm_id": algorithm_id,
        "narrative": narrative,
        "measurement_used": measurement,
        "evidence": [e.to_dict() for e in evidence],
    }
