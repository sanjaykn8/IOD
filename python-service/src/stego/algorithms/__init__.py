from ..errors import StegoError
from .dct import Dct
from .edge_adaptive import EdgeAdaptiveLsb
from .lsb_matching import LsbMatching
from .lsb_replacement import LsbReplacement
from .pvd import Pvd

_ALL = [LsbReplacement(), LsbMatching(), Pvd(), EdgeAdaptiveLsb(), Dct()]
BY_NAME = {a.name: a for a in _ALL}
BY_ID = {a.id: a for a in _ALL}
NAMES = [a.name for a in _ALL]  # canonical (id) order


def get_by_name(name):
    if not isinstance(name, str) or name not in BY_NAME:
        raise StegoError("INVALID_REQUEST", "unknown algorithm name")
    return BY_NAME[name]


def get_by_id(alg_id):
    if alg_id not in BY_ID:
        raise StegoError("UNKNOWN_ALGORITHM", "unknown algorithm id", {"alg_id": alg_id})
    return BY_ID[alg_id]
