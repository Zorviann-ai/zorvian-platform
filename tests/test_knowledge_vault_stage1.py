from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from intelligence.knowledge_sources import OFFICIAL_SOURCES
from intelligence.knowledge_vault import (
    CONFIDENCE_AMBER,
    CONFIDENCE_RED,
    KnowledgeVault,
    RightsDenied,
    SourceRejected,
    build_stage1_vault,
    domain_allowed,
    _query_matches,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_unofficial_domain_rejected():
    vault = KnowledgeVault()
    with pytest.raises(SourceRejected, match="unofficial domain"):
        vault.discover("https://random-blog.example/building-regs")
    assert domain_allowed("https://www.gov.uk/building-regulations") is True
    assert domain_allowed("https://paid-database.example/statutes") is False


def test_restricted_licence_source_rejected_for_body_ingest():
    vault = KnowledgeVault()
    sra = next(s for s in OFFICIAL_SOURCES if s["source_id"] == "SRA_PRINCIPLES")
    with pytest.raises(RightsDenied):
        vault.ingest(sra, ingest_body=True, body="full handbook text")
    rec = vault.ingest(sra, ingest_body=False)
    assert rec.body_ingested is False
    aqa = next(s for s in OFFICIAL_SOURCES if s["source_id"] == "AQA_SPECIFICATIONS")
    with pytest.raises(RightsDenied):
        vault.ingest(aqa, ingest_body=True, body="specification body")


def test_jurisdiction_and_legal_status_retained():
    vault = build_stage1_vault()
    rec = vault.records["SRA_ACCOUNTS_RULES"]
    assert rec.jurisdiction == "England and Wales"
    assert rec.legal_status == "REGULATOR_RULE"
    hse = vault.records["HSE_CDM_2015"]
    assert hse.jurisdiction == "Great Britain"
    assert hse.legal_status == "OFFICIAL_GUIDANCE"
    nc = vault.records["GOVUK_NATIONAL_CURRICULUM"]
    assert nc.jurisdiction == "England"
    assert nc.legal_status == "CURRICULUM_SPECIFICATION"


def test_outdated_source_marked_stale_or_review_required():
    vault = build_stage1_vault()
    vault.mark_stale("GOVUK_PRIVATE_RENTING")
    rec = vault.records["GOVUK_PRIVATE_RENTING"]
    assert rec.stale is True
    assert rec.review_required is True
    answer = vault.answer(business_type="landlord", query="private renting duties")
    assert "STALE" in answer.flags or answer.professional_review_required


def test_superseded_source_not_treated_as_current():
    vault = KnowledgeVault()
    src = dict(next(s for s in OFFICIAL_SOURCES if s["source_id"] == "HSE_CONSTRUCTION"))
    src["source_id"] = "HSE_CONSTRUCTION_OLD"
    src["superseded_by"] = "HSE_CONSTRUCTION"
    rec = vault.ingest(src, ingest_body=False)
    assert rec.active is False
    assert rec.review_required is True
    vault.load_catalog()
    vault.records[rec.source_id] = rec
    vault.packs["CONSTRUCTION_UK"].active_sources.append(rec.source_id)
    answer = vault.answer(business_type="builder", query="construction health and safety")
    live = [s for s in answer.sources if s.get("url") == vault.records["HSE_CONSTRUCTION"].source_url]
    assert live


def test_client_business_type_routes_to_correct_pack():
    vault = build_stage1_vault()
    assert vault.route_client("solicitor").pack_id == "LEGAL_ENGLAND_WALES"
    assert vault.route_client("builder").pack_id == "CONSTRUCTION_UK"
    assert vault.route_client("landlord").pack_id == "PROPERTY_ENGLAND"
    assert vault.route_client("school").pack_id == "EDUCATION_UK"
    assert vault.route_client("tutor").pack_id == "EDUCATION_UK"
    assert vault.route_client("property manager").pack_id == "PROPERTY_ENGLAND"


def test_cross_pack_contamination_prevented():
    vault = build_stage1_vault()
    legal_rec = vault.records["SRA_PRINCIPLES"]
    vault.packs["CONSTRUCTION_UK"].active_sources.append(legal_rec.source_id)
    with pytest.raises(Exception, match="cross-pack contamination"):
        vault.answer(business_type="builder", query="SRA principles for solicitors")


def test_provenance_returned():
    vault = build_stage1_vault()
    answer = vault.answer(
        business_type="solicitor",
        query="SRA accounts rules for client money",
        jurisdiction="England and Wales",
    )
    assert answer.provenance_sentence.startswith("This answer is based on")
    assert "England and Wales" in answer.provenance_sentence
    assert "last verified on" in answer.provenance_sentence
    assert answer.sources
    assert answer.sources[0]["url"].startswith("https://")
    assert answer.sources[0]["authority"]
    assert answer.pack_id == "LEGAL_ENGLAND_WALES"


def test_professional_review_flag_works():
    vault = build_stage1_vault()
    advisory = vault.answer(business_type="tutor", query="national curriculum overview")
    assert advisory.confidence in {CONFIDENCE_AMBER, CONFIDENCE_RED}
    decision = vault.answer(
        business_type="landlord",
        query="Should we evict the tenant and serve notice this week?",
        professional_decision=True,
    )
    assert decision.professional_review_required is True
    assert decision.confidence == CONFIDENCE_RED
    assert "PROFESSIONAL_REVIEW_REQUIRED" in decision.flags


def test_no_external_execution_path():
    vault = build_stage1_vault()
    vault.assert_execution_boundary()
    assert vault.production_enabled is False
    assert vault.external_execution_enabled is False
    src = inspect.getsource(KnowledgeVault)
    assert "_claimed_production_submit" not in src
    assert "/live" not in src
    assert "submit_production_pilot" not in src


def test_no_stage4g_bypass_in_vault_modules():
    vault_src = (REPO_ROOT / "intelligence" / "knowledge_vault.py").read_text()
    sources_src = (REPO_ROOT / "intelligence" / "knowledge_sources.py").read_text()
    blob = vault_src + sources_src
    assert "_claimed_production_submit" not in blob
    assert "execute_once" not in blob
    assert "dispatch_default_off" not in blob
    stage4g = (REPO_ROOT / "intelligence" / "execution_production_webhook.py").read_text()
    assert "def _claimed_production_submit" in stage4g


def test_allowlisted_ogl_body_ingest_hashes_and_sections():
    vault = KnowledgeVault(fetcher=lambda url: "<h1>CDM</h1><p>Dutyholders must plan work.</p>")
    src = next(s for s in OFFICIAL_SOURCES if s["source_id"] == "HSE_CDM_2015")
    rec = vault.ingest(src, ingest_body=True)
    assert rec.body_ingested is True
    assert rec.content_hash
    assert rec.sections
    assert rec.legal_status == "OFFICIAL_GUIDANCE"


def test_catalog_covers_requested_industries():
    vault = build_stage1_vault()
    assert set(vault.packs) >= {
        "CONSTRUCTION_UK",
        "LEGAL_ENGLAND_WALES",
        "PROPERTY_ENGLAND",
        "EDUCATION_UK",
    }
    assert "UK_LEGISLATION_PORTAL" in vault.records
    assert vault.packs["LEGAL_ENGLAND_WALES"].jurisdiction == "England and Wales"
    assert vault.packs["PROPERTY_ENGLAND"].jurisdiction == "England"
    assert "Scotland" not in vault.packs["PROPERTY_ENGLAND"].jurisdiction


def test_https_required_for_approved_domains():
    assert domain_allowed("https://www.gov.uk/building-regulations") is True
    assert domain_allowed("https://www.hse.gov.uk/asbestos/") is True
    assert domain_allowed("http://www.gov.uk/building-regulations") is False
    assert domain_allowed("ftp://www.gov.uk/building-regulations") is False
    assert domain_allowed("file://www.gov.uk/building-regulations") is False
    assert domain_allowed("data://www.gov.uk/building-regulations") is False
    assert domain_allowed("javascript://www.gov.uk/building-regulations") is False
    assert domain_allowed("https://evil-example.com/building-regulations") is False
    vault = KnowledgeVault()
    with pytest.raises(SourceRejected):
        vault.discover("file://www.gov.uk/secret")
    with pytest.raises(SourceRejected):
        vault.discover("ftp://www.gov.uk/construction")
    with pytest.raises(SourceRejected):
        vault.discover("http://www.gov.uk/private-renting")


def test_query_matches_record_fields_not_the_query_text():
    vault = build_stage1_vault()
    asbestos = vault.records["HSE_ASBESTOS"]
    curriculum = vault.records["GOVUK_NATIONAL_CURRICULUM"]
    accounts = vault.records["SRA_ACCOUNTS_RULES"]
    construction = vault.records["HSE_CONSTRUCTION"]
    assert _query_matches("asbestos licensed contractor duties", asbestos) is True
    assert _query_matches("national curriculum key stage", asbestos) is False
    assert _query_matches("national curriculum key stage", construction) is False
    assert _query_matches("SRA accounts rules client money", accounts) is True
    assert _query_matches("SRA accounts rules client money", construction) is False
    assert _query_matches("national curriculum key stage", curriculum) is True


def test_asbestos_query_selects_hse_asbestos_source():
    vault = build_stage1_vault()
    answer = vault.answer(business_type="builder", query="asbestos licensed work on site")
    titles = {s["title"].lower() for s in answer.sources}
    urls = {s["url"] for s in answer.sources}
    assert any("asbestos" in t for t in titles) or any("asbestos" in u for u in urls)
    assert "NO_RELEVANT_SOURCE_MATCH" not in answer.flags


def test_education_query_does_not_match_construction_sources():
    vault = build_stage1_vault()
    answer = vault.answer(
        business_type="builder",
        query="national curriculum AQA specification for schools",
    )
    assert "NO_RELEVANT_SOURCE_MATCH" in answer.flags
    assert answer.confidence == CONFIDENCE_AMBER
    assert answer.sources == []
    for rec in vault.sources_for_pack("CONSTRUCTION_UK"):
        assert _query_matches("national curriculum AQA specification for schools", rec) is False


def test_legal_query_selects_legal_records():
    vault = build_stage1_vault()
    answer = vault.answer(
        business_type="solicitor",
        query="SRA accounts rules for client money",
        jurisdiction="England and Wales",
    )
    assert answer.pack_id == "LEGAL_ENGLAND_WALES"
    assert any("Accounts" in s["title"] or "SRA" in s["title"] for s in answer.sources)
    industries = {vault.records[sid].industry for sid in vault.packs["LEGAL_ENGLAND_WALES"].active_sources if sid in vault.records}
    matched_ids = [
        rec.source_id
        for rec in vault.sources_for_pack("LEGAL_ENGLAND_WALES")
        if _query_matches("SRA accounts rules for client money", rec)
    ]
    assert "SRA_ACCOUNTS_RULES" in matched_ids
    assert all(vault.records[sid].industry in {"legal", "cross"} for sid in matched_ids)


def test_generic_tokens_do_not_create_false_strong_matches():
    vault = build_stage1_vault()
    accounts = vault.records["SRA_ACCOUNTS_RULES"]
    asbestos = vault.records["HSE_ASBESTOS"]
    sra_guidance = vault.records["SRA_GUIDANCE_HUB"]
    building_regs = vault.records["GOVUK_BUILDING_REGULATIONS"]
    curriculum = vault.records["GOVUK_NATIONAL_CURRICULUM"]
    cdm = vault.records["HSE_CDM_2015"]
    assert _query_matches("rules about asbestos", accounts) is False
    assert _query_matches("rules about asbestos", asbestos) is True
    assert _query_matches("guidance for schools", sra_guidance) is False
    assert _query_matches("SRA accounts rules client money", accounts) is True
    assert _query_matches("national curriculum key stage", curriculum) is True
    assert _query_matches("CDM contractor responsibilities", cdm) is True
    assert _query_matches("regulations about landlords", building_regs) is False


def test_generic_legal_query_does_not_select_sra_accounts_on_rules_alone():
    vault = build_stage1_vault()
    answer = vault.answer(business_type="solicitor", query="rules about asbestos")
    titles = [s["title"] for s in answer.sources]
    assert "SRA Accounts Rules" not in titles
    assert "NO_RELEVANT_SOURCE_MATCH" in answer.flags
    assert answer.confidence == CONFIDENCE_AMBER
    assert answer.professional_review_required is True


def test_cdm_query_selects_hse_cdm():
    vault = build_stage1_vault()
    answer = vault.answer(business_type="builder", query="CDM contractor responsibilities")
    urls = {s["url"] for s in answer.sources}
    assert any("cdm" in u.lower() for u in urls)
    assert "NO_RELEVANT_SOURCE_MATCH" not in answer.flags
