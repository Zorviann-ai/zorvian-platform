from __future__ import annotations

import ast
from datetime import date
from pathlib import Path

import pytest

from intelligence.education.assessment import AssessmentDenied, AssessmentService, QuestionItem
from intelligence.education.curriculum import (
    AwardingBody,
    Country,
    CurriculumNode,
    EducationSystem,
    KeyStage,
    Qualification,
)
from intelligence.education.knowledge_gateway import (
    EDUCATION_PACK_ID,
    FORBIDDEN_PACKS,
    EducationKnowledgeGateway,
    EducationKnowledgeRequest,
    EvidenceBasis,
    GatewayDenied,
    _to_pack_jurisdiction,
)
from intelligence.education.safeguarding_knowledge import Jurisdiction
from intelligence.education.languages import Formality, LanguagePreference, ScriptPreference, SpokenLanguage
from intelligence.education.safeguarding import SafetyConcern
from intelligence.education.sources import EducationSource, SourceCategory, SourceType
from intelligence.education.teaching import CelesteTeacher, LearningObjective, StudentLessonContext, SubjectContext, TeachingStyle
from intelligence.education.tenancy import EducationDirectory, EducationTenant, IsolationDenied, StudentAccount, TenantKind
from intelligence.knowledge_vault import CONFIDENCE_AMBER, CONFIDENCE_GREEN, CONFIDENCE_RED, build_stage1_vault


REPO = Path(__file__).resolve().parents[1]


def _req(**kwargs) -> EducationKnowledgeRequest:
    base = dict(
        tenant_id="school-a",
        learner_context_id="stu-a",
        jurisdiction="england",
        country="england",
        subject="Mathematics",
        qualification_level="gcse",
        topic="algebra",
        query="AQA GCSE mathematics specification",
        awarding_body="aqa",
    )
    base.update(kwargs)
    return EducationKnowledgeRequest(**base)


def test_education_query_routes_to_education_uk():
    gw = EducationKnowledgeGateway()
    assert gw.pack_for_education() == EDUCATION_PACK_ID
    result = gw.retrieve(_req())
    assert result.pack_id == EDUCATION_PACK_ID
    assert result.pack_id not in FORBIDDEN_PACKS


def test_construction_legal_property_packs_not_selected():
    gw = EducationKnowledgeGateway()
    result = gw.retrieve(_req(query="building regulations CDM asbestos landlord SRA accounts"))
    assert result.pack_id == EDUCATION_PACK_ID
    blob = " ".join(result.source_ids)
    assert "HSE_" not in blob
    assert "SRA_" not in blob
    assert "GOVUK_PRIVATE_RENTING" not in blob
    assert "GOVUK_BUILDING" not in blob


def test_matching_official_source_returns_provenance():
    result = EducationKnowledgeGateway().retrieve(_req())
    assert "AQA_SPECIFICATIONS" in result.source_ids
    assert result.source_authority
    assert result.urls[0].startswith("https://")
    assert "AQA" in result.provenance_summary
    assert result.confidence == CONFIDENCE_AMBER
    assert result.evidence_basis is not EvidenceBasis.SOURCE_BACKED
    assert result.retrieval_reason == "METADATA_ONLY_REFERENCE"


def test_no_match_is_amber_not_verified():
    result = EducationKnowledgeGateway().retrieve(
        _req(query="unrelated underwater basket weaving syllabus", subject="weaving", topic="reeds", awarding_body=None)
    )
    assert result.retrieval_reason == "NO_RELEVANT_SOURCE_MATCH"
    assert result.confidence == CONFIDENCE_AMBER
    assert result.evidence_basis is EvidenceBasis.NO_RELEVANT_SOURCE_MATCH
    assert CONFIDENCE_GREEN.split()[0] not in result.confidence or result.confidence != CONFIDENCE_GREEN


def test_stale_source_cannot_return_green():
    vault = build_stage1_vault()
    vault.mark_stale("AQA_SPECIFICATIONS")
    result = EducationKnowledgeGateway(vault=vault).retrieve(_req())
    assert result.stale is True
    assert result.confidence != CONFIDENCE_GREEN
    assert result.professional_review_required is True


def test_jurisdiction_mismatch_is_flagged():
    result = EducationKnowledgeGateway().retrieve(
        _req(jurisdiction="scotland", country="scotland", query="national curriculum", awarding_body="dfe")
    )
    assert result.retrieval_reason == "JURISDICTION_MISMATCH"
    assert result.confidence != CONFIDENCE_GREEN
    assert result.professional_review_required is True


def test_aqa_pearson_ocr_metadata():
    gw = EducationKnowledgeGateway()
    aqa = gw.retrieve(_req(awarding_body="aqa", query="AQA specification"))
    pearson = gw.retrieve(_req(awarding_body="pearson_edexcel", query="Pearson Edexcel specification"))
    ocr = gw.retrieve(_req(awarding_body="ocr", query="OCR specification"))
    assert aqa.source_ids[0] == "AQA_SPECIFICATIONS"
    assert pearson.source_ids[0] == "PEARSON_EDEXCEL_SPECIFICATIONS"
    assert ocr.source_ids[0] == "OCR_SPECIFICATIONS"


def test_wjec_eduqas_jurisdiction_metadata():
    gw = EducationKnowledgeGateway()
    wjec = gw.retrieve(_req(jurisdiction="wales", country="wales", awarding_body="wjec", query="WJEC specification"))
    eduqas = gw.retrieve(_req(awarding_body="eduqas", query="Eduqas specification"))
    assert wjec.source_ids[0] == "WJEC_SPECIFICATIONS"
    assert wjec.jurisdiction.lower() == "wales"
    assert eduqas.source_ids[0] == "EDUQAS_SPECIFICATIONS"


def test_generated_teaching_is_not_official_because_vault_exists():
    gw = EducationKnowledgeGateway()
    knowledge = gw.retrieve(_req())
    teacher = CelesteTeacher()
    node = CurriculumNode(
        "n1", Country.ENGLAND, EducationSystem.ENGLAND_NATIONAL_CURRICULUM,
        AwardingBody.AQA, Qualification.GCSE, KeyStage.KS4, "Mathematics",
        "8300", "2015", "Algebra", "Solve linear equations", "U1", "AO1", "src",
    )
    source = EducationSource(
        "src", "Internal notes", "Caelomere", SourceType.INTERNAL, "Mathematics", "GCSE", "2026",
        SourceCategory.INTERNAL_CAELOMERE, "internal", ("teach",), "Caelomere", "internal",
        date(2026, 1, 1), date(2027, 1, 1), True,
    )
    ctx = StudentLessonContext(
        "stu-a", "school-a", "KS4", "standard", (TeachingStyle.STEP_BY_STEP,),
        LanguagePreference(SpokenLanguage.ENGLISH, SpokenLanguage.ENGLISH, ScriptPreference.LATIN, "standard", Formality.FRIENDLY),
        SubjectContext("Mathematics", "GCSE", "aqa", "8300"),
    )
    lesson = teacher.teach(ctx, LearningObjective("o1", "Solve linear equations"), node, source, knowledge=knowledge)
    assert lesson.evidence_basis != "SOURCE_BACKED"
    assert "based on the approved curriculum source" not in lesson.answer.lower()
    assert "body text is not ingested" in lesson.answer.lower()
    service = AssessmentService()
    with pytest.raises(AssessmentDenied):
        service.label_generated(QuestionItem("q1", "Solve", 2, "AO1", True, None))


def test_stale_and_metadata_teaching_wording_differ():
    node = CurriculumNode(
        "n1", Country.ENGLAND, EducationSystem.ENGLAND_NATIONAL_CURRICULUM,
        AwardingBody.AQA, Qualification.GCSE, KeyStage.KS4, "Mathematics",
        "8300", "2015", "Algebra", "Solve linear equations", "U1", "AO1", "src",
    )
    source = EducationSource(
        "src", "Internal notes", "Caelomere", SourceType.INTERNAL, "Mathematics", "GCSE", "2026",
        SourceCategory.INTERNAL_CAELOMERE, "internal", ("teach",), "Caelomere", "internal",
        date(2026, 1, 1), date(2027, 1, 1), True,
    )
    ctx = StudentLessonContext(
        "stu-a", "school-a", "KS4", "standard", (TeachingStyle.STEP_BY_STEP,),
        LanguagePreference(SpokenLanguage.ENGLISH, SpokenLanguage.ENGLISH, ScriptPreference.LATIN, "standard", Formality.FRIENDLY),
        SubjectContext("Mathematics", "GCSE", "aqa", "8300"),
    )
    teacher = CelesteTeacher()
    meta = EducationKnowledgeGateway().retrieve(_req())
    meta_lesson = teacher.teach(ctx, LearningObjective("o1", "Solve linear equations"), node, source, knowledge=meta)
    assert meta.retrieval_reason == "METADATA_ONLY_REFERENCE"
    assert meta.evidence_basis is not EvidenceBasis.SOURCE_BACKED
    assert "body text is not ingested" in meta_lesson.answer.lower()

    vault = build_stage1_vault()
    vault.records["AQA_SPECIFICATIONS"].body_ingested = True
    vault.mark_stale("AQA_SPECIFICATIONS")
    stale = EducationKnowledgeGateway(vault=vault).retrieve(_req())
    stale_lesson = teacher.teach(ctx, LearningObjective("o1", "Solve linear equations"), node, source, knowledge=stale)
    assert stale.retrieval_reason == "STALE_SOURCE"
    assert stale.confidence == CONFIDENCE_AMBER
    assert stale.professional_review_required is True
    assert stale.evidence_basis is not EvidenceBasis.SOURCE_BACKED
    assert stale_lesson.evidence_basis != "SOURCE_BACKED"
    assert "body text is not ingested" not in stale_lesson.answer.lower()
    assert "requires revalidation" in stale_lesson.answer.lower()


def test_safeguarding_overrides_teaching_retrieval():
    result = EducationKnowledgeGateway().retrieve(_req(), safety_concern=SafetyConcern.ABUSE_DISCLOSURE)
    assert result.evidence_basis is EvidenceBasis.SAFEGUARDING_OVERRIDE
    assert result.confidence == CONFIDENCE_RED
    assert result.professional_review_required is True
    assert result.retrieval_reason == "SAFEGUARDING_OVERRIDE"


def test_tenant_isolation():
    directory = EducationDirectory()
    directory.add_tenant(EducationTenant("school-a", TenantKind.SCHOOL, "A"))
    directory.add_tenant(EducationTenant("school-b", TenantKind.SCHOOL, "B"))
    directory.add_student(StudentAccount("stu-a", "school-a", "sch-a", None, "c1", "Ada"))
    directory.add_student(StudentAccount("stu-b", "school-b", "sch-b", None, "c2", "Bea"))
    gw = EducationKnowledgeGateway(directory=directory)
    ok = gw.retrieve(_req(), actor_tenant_id="school-a")
    assert ok.pack_id == EDUCATION_PACK_ID
    with pytest.raises(IsolationDenied):
        gw.retrieve(_req(), actor_tenant_id="school-b")
    with pytest.raises(IsolationDenied):
        gw.retrieve(_req(tenant_id="school-b", learner_context_id="stu-a"), actor_tenant_id="school-b")


def test_no_stage4g_private_execution_imports():
    path = REPO / "intelligence" / "education" / "knowledge_gateway.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            names.add(node.func.id)
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
    assert "intelligence.execution_production_webhook" not in imported
    assert "intelligence.execution_pilot_dispatch" not in imported
    assert not ({"_claimed_production_submit", "_stage4f_submit_authority", "submit_production_pilot", "execute_once"} & names)


def test_safeguarding_jurisdiction_does_not_default_to_england():
    assert _to_pack_jurisdiction("wales") is Jurisdiction.WALES
    assert _to_pack_jurisdiction("scotland") is Jurisdiction.SCOTLAND
    assert _to_pack_jurisdiction("northern_ireland") is Jurisdiction.NORTHERN_IRELAND
    assert _to_pack_jurisdiction("england") is Jurisdiction.ENGLAND
    for bad in ("", "uk", "united_kingdom", "unknown", "france"):
        with pytest.raises(GatewayDenied):
            _to_pack_jurisdiction(bad)
    gw = EducationKnowledgeGateway()
    unknown = gw.retrieve(_req(jurisdiction=""), safety_concern=SafetyConcern.ABUSE_DISCLOSURE)
    assert unknown.retrieval_reason == "JURISDICTION_UNSUPPORTED"
    assert "england" not in unknown.provenance_summary.lower() or "not england" in unknown.provenance_summary.lower()
    wales = gw.retrieve(_req(jurisdiction="wales"), safety_concern=SafetyConcern.ABUSE_DISCLOSURE)
    assert "england" not in wales.provenance_summary.split("Primary law:")[-1][:80].lower() or "Wales" in wales.provenance_summary


def test_no_network_side_effect_by_default():
    vault = build_stage1_vault()

    def boom(_url: str) -> str:
        raise AssertionError("network fetch must not run")

    vault.fetcher = boom
    EducationKnowledgeGateway(vault=vault).retrieve(_req())
