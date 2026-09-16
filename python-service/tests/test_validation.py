from rag.models import Contribution
from rag.validation import validate, SUSPICION_THRESHOLD


def test_consistent_reports_are_not_flagged():
    contributions = [
        Contribution(drone_id="d1", content="convoy of six vehicles on route seven", confidence=0.9),
        Contribution(drone_id="d2", content="six vehicle convoy spotted on route seven", confidence=0.85),
    ]
    validated = validate(contributions)
    assert all(not c.flagged_suspicious for c in validated)
    assert all(c.trust_score == c.confidence for c in validated)


def test_outlier_report_is_flagged_and_downweighted():
    contributions = [
        Contribution(drone_id="d1", content="convoy of six vehicles on route seven", confidence=0.9),
        Contribution(drone_id="d2", content="six vehicle convoy spotted on route seven", confidence=0.85),
        Contribution(drone_id="d3", content="totally unrelated content about ice cream trucks", confidence=0.95),
    ]
    validated = validate(contributions)
    outlier = next(c for c in validated if c.drone_id == "d3")
    assert outlier.flagged_suspicious
    assert outlier.trust_score < outlier.confidence


def test_single_contribution_is_never_flagged():
    contributions = [Contribution(drone_id="d1", content="anything at all", confidence=0.7)]
    validated = validate(contributions)
    assert not validated[0].flagged_suspicious
    assert validated[0].trust_score == 0.7
