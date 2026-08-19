import pytest
from intelligence import Evaluation


def test_strong_evaluation_passes():
    e = Evaluation(accuracy=5, usefulness=5, clarity=4, speed=4)
    assert e.quality_score >= 80
    assert e.passes


def test_unsupported_assumption_blocks_pass():
    e = Evaluation(accuracy=5, usefulness=5, clarity=5, speed=5, unsupported_assumption=True)
    assert not e.passes


def test_approval_failure_blocks_pass():
    e = Evaluation(accuracy=5, usefulness=5, clarity=5, speed=5, approval_failure=True)
    assert not e.passes


def test_invalid_score_rejected():
    with pytest.raises(ValueError):
        Evaluation(accuracy=6, usefulness=5, clarity=5, speed=5).validate()
