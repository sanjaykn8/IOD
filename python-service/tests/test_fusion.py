from rag.models import Contribution
from rag.fusion import fuse, MIN_TRUST_TO_INCLUDE


def test_fuse_orders_by_trust_descending():
    contributions = [
        Contribution(drone_id="low", content="low trust report", confidence=0.5, trust_score=0.5),
        Contribution(drone_id="high", content="high trust report", confidence=0.9, trust_score=0.9),
    ]
    result = fuse(contributions)
    assert result["included_drone_ids"] == ["high", "low"]


def test_fuse_excludes_below_trust_floor():
    contributions = [
        Contribution(drone_id="good", content="reliable", confidence=0.9, trust_score=0.9),
        Contribution(drone_id="bad", content="unreliable", confidence=0.05, trust_score=0.05),
    ]
    assert MIN_TRUST_TO_INCLUDE > 0.05
    result = fuse(contributions)
    assert result["included_drone_ids"] == ["good"]
    assert result["excluded_drone_ids"] == ["bad"]


def test_fuse_empty_input_yields_empty_context():
    result = fuse([])
    assert result["fused_context"] == ""
    assert result["included_drone_ids"] == []
