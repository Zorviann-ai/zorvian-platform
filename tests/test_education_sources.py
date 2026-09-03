from datetime import date
import pytest
from intelligence.education.ports import EducationPortDenied
from intelligence.education.sources import EducationSource, SourceCategory, SourceDenied, SourceRegistry, SourceType


def test_restricted_unlicensed_denied_permitted_accepted():
    registry = SourceRegistry()
    registry.register(EducationSource("s1", "Restricted book", "Pub", SourceType.TEXTBOOK, "Maths", "GCSE", "2020", SourceCategory.RESTRICTED, "unknown", ("teach",), "n/a", "ref", date(2020, 1, 1), date(2026, 1, 1), False))
    registry.register(EducationSource("s2", "Internal notes", "Caelomere", SourceType.INTERNAL, "Maths", "GCSE", "2026", SourceCategory.INTERNAL_CAELOMERE, "internal", ("teach", "extract"), "Caelomere", "internal", date(2026, 1, 1), date(2027, 1, 1), True))
    with pytest.raises(SourceDenied):
        registry.require_use("s1", "teach")
    assert registry.require_use("s2", "teach").source_id == "s2"
    with pytest.raises(EducationPortDenied):
        registry.fetch_extract("s2")
