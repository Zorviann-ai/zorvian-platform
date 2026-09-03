from intelligence.education.curriculum import AwardingBody, Country, CurriculumCatalogue, CurriculumDenied, CurriculumNode, EducationSystem, KeyStage, Qualification
from intelligence.education.ports import ClosedCurriculumImport, EducationPortDenied
import pytest


def sample():
    return CurriculumNode("n1", Country.ENGLAND, EducationSystem.ENGLAND_NATIONAL_CURRICULUM, AwardingBody.AQA, Qualification.GCSE, KeyStage.KS4, "Mathematics", "8300", "2015", "Algebra", "Solve linear equations", "U1", "AO1", "src-aqa-8300")


def test_hierarchy_and_provenance():
    cat = CurriculumCatalogue()
    cat.register(sample())
    found = cat.assert_mapping(awarding_body=AwardingBody.AQA, specification_code="8300", subject="Mathematics")
    assert found.specification_version == "2015" and found.source_id == "src-aqa-8300"


def test_invalid_cross_board_mapping_rejected():
    cat = CurriculumCatalogue()
    with pytest.raises(CurriculumDenied):
        cat.reject_cross_board(cat.register(sample()), AwardingBody.OCR)


def test_curriculum_import_port_closed():
    with pytest.raises(EducationPortDenied):
        ClosedCurriculumImport().import_specification({"code": "8300"})
