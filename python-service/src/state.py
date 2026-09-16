"""In-memory RAG simulation state.

Documented scope limitation: this state is process-lifetime only (not
persisted to disk). The Rust core's SQLite database is the durable
source of truth for the security-critical protocol state (drones,
groups, sessions, audit/trace records); RAG contributions are
demonstration content layered on top and are treated as ephemeral
per-session simulation input, consistent with "not everything needs the
same persistence guarantee." If durable RAG history is needed later,
the `rag_contributions` table already scaffolded in
`rust-core/src/storage/db.rs` is the intended home for it.
"""

from typing import List
from rag.models import Contribution

_contributions: List[Contribution] = []
_last_run_result: dict = {}


def add_contribution(drone_id: str, content: str, confidence: float) -> Contribution:
    c = Contribution(drone_id=drone_id, content=content, confidence=confidence)
    _contributions.append(c)
    return c


def all_contributions() -> List[Contribution]:
    return list(_contributions)


def set_last_run_result(result: dict) -> None:
    global _last_run_result
    _last_run_result = result


def get_last_run_result() -> dict:
    return _last_run_result


def reset() -> None:
    global _contributions, _last_run_result
    _contributions = []
    _last_run_result = {}
