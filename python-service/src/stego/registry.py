"""Central registry of the 5 steganography algorithms, so the benchmark
engine / selector / Flask endpoints never hardcode the list in more than
one place."""

from __future__ import annotations

from .adaptive_lsb import AdaptiveLsbStego
from .pvd import PvdStego
from .dct import DctStego
from .dwt import DwtStego
from .svd import SvdStego

ALGORITHMS = {
    "adaptive_lsb": AdaptiveLsbStego(),
    "pvd": PvdStego(),
    "dct": DctStego(),
    "dwt": DwtStego(),
    "svd": SvdStego(),
}


def get_algorithm(algorithm_id: str):
    try:
        return ALGORITHMS[algorithm_id]
    except KeyError:
        raise ValueError(f"unknown stego algorithm id: {algorithm_id!r}; known: {sorted(ALGORITHMS)}")


def all_algorithm_ids() -> list[str]:
    return sorted(ALGORITHMS.keys())
