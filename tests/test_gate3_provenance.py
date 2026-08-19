import pytest
from intelligence import ProvenanceRecord


def test_provenance_requires_identity():
    with pytest.raises(ValueError):
        ProvenanceRecord(module="", task_id="t1").validate()


def test_low_confidence_requires_review():
    p = ProvenanceRecord(module="tenders", task_id="t1", source_refs=("doc:1",), confidence=0.60)
    assert p.has_evidence
    assert p.needs_review


def test_assumption_requires_review_even_with_high_confidence():
    p = ProvenanceRecord(module="freshx", task_id="t2", source_refs=("source:1",), assumptions=("availability unverified",), confidence=0.95)
    assert p.needs_review


def test_supported_high_confidence_can_clear_review_flag():
    p = ProvenanceRecord(module="zai-auto", task_id="t3", source_refs=("source:1",), confidence=0.90)
    assert p.has_evidence
    assert not p.needs_review


def test_invalid_confidence_rejected():
    with pytest.raises(ValueError):
        ProvenanceRecord(module="tenders", task_id="t4", confidence=1.2).validate()
