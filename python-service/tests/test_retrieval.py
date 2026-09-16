from rag.models import Contribution
from rag.retrieval import retrieve, jaccard


def test_jaccard_identical_text_is_one():
    assert jaccard("hello world", "hello world") == 1.0


def test_jaccard_disjoint_text_is_zero():
    assert jaccard("alpha bravo", "charlie delta") == 0.0


def test_retrieve_ranks_relevant_contributions_higher():
    contributions = [
        Contribution(drone_id="d1", content="convoy spotted on route 7", confidence=0.9),
        Contribution(drone_id="d2", content="weather is sunny today", confidence=0.9),
        Contribution(drone_id="d3", content="another convoy on route 7 confirmed", confidence=0.9),
    ]
    results = retrieve("convoy route 7", contributions, top_k=2)
    ids = [c.drone_id for c in results]
    assert "d1" in ids
    assert "d3" in ids
    assert "d2" not in ids


def test_retrieve_respects_top_k():
    contributions = [Contribution(drone_id=f"d{i}", content="convoy route 7", confidence=0.9) for i in range(10)]
    results = retrieve("convoy route 7", contributions, top_k=3)
    assert len(results) == 3
