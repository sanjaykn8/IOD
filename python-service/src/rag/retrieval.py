"""Retrieval abstraction: select the contributions most relevant to a
query.

SIMULATED, not a real retrieval system: relevance is scored via plain
word-overlap (Jaccard similarity between the lowercased word sets of the
query and each contribution's content), not embeddings/vector search.
This is intentionally simple and inspectable rather than presented as a
sophisticated retrieval pipeline it is not.
"""

from typing import List
from .models import Contribution


def _word_set(text: str):
    return set(w.strip(".,!?;:()[]\"'").lower() for w in text.split() if w.strip())


def jaccard(a: str, b: str) -> float:
    wa, wb = _word_set(a), _word_set(b)
    if not wa and not wb:
        return 0.0
    union = wa | wb
    if not union:
        return 0.0
    return len(wa & wb) / len(union)


def retrieve(query: str, contributions: List[Contribution], top_k: int = 5) -> List[Contribution]:
    scored = [(jaccard(query, c.content), c) for c in contributions]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [c for _score, c in scored[:top_k]]
