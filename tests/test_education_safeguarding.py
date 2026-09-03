import pytest

from intelligence.education.safeguarding import AdultSafeguardingContext, SafetyConcern, SafeguardingDenied, SafeguardingPolicy
from intelligence.education.safeguarding_knowledge import (
    FORBIDDEN_CELESTE_ROLES,
    HumanRole,
    InstrumentKind,
    Jurisdiction,
    PACK_ID,
    PACK_VERSION,
    Population,
    ThresholdKind,
    instruments_for,
    lookup_route,
)


def test_pack_identity_and_instrument_kinds():
    policy = SafeguardingPolicy()
    meta = policy.meta()
    assert meta["pack_id"] == PACK_ID == "caelomere-education-safeguarding-knowledge"
    assert PACK_VERSION
    kinds = {i.kind for i in instruments_for(Jurisdiction.ENGLAND)}
    assert InstrumentKind.PRIMARY_LAW in kinds
    assert InstrumentKind.STATUTORY_GUIDANCE in kinds
    assert InstrumentKind.ORGANISATIONAL_POLICY in kinds


def test_england_s17_and_s47_are_distinct():
    s47 = lookup_route(Jurisdiction.ENGLAND, Population.CHILD, ThresholdKind.SIGNIFICANT_HARM)
    s17 = lookup_route(Jurisdiction.ENGLAND, Population.CHILD, ThresholdKind.CHILD_IN_NEED)
    assert s47.primary_law == "Children Act 1989 s47"
    assert s17.primary_law == "Children Act 1989 s17"
    assert s47.route_id != s17.route_id


def test_scotland_wales_do_not_use_england_s47_label():
    scot = lookup_route(Jurisdiction.SCOTLAND, Population.CHILD, ThresholdKind.SIGNIFICANT_HARM)
    wales = lookup_route(Jurisdiction.WALES, Population.CHILD, ThresholdKind.SIGNIFICANT_HARM)
    assert "s47" not in scot.primary_law.lower()
    assert "Wales" in wales.primary_law or "Wales" in wales.statutory_guidance
    titles = " ".join(i.title for i in instruments_for(Jurisdiction.SCOTLAND))
    assert "Children Act 1989" not in titles


def test_flag_records_versioned_layers_and_queues_human():
    policy = SafeguardingPolicy()
    flag = policy.flag(tenant_id="school-a", student_id="stu", concern=SafetyConcern.ABUSE_DISCLOSURE, jurisdiction=Jurisdiction.ENGLAND, age_or_level="KS3")
    assert flag.threshold is ThresholdKind.SIGNIFICANT_HARM
    assert flag.route.pack_version == PACK_VERSION
    assert flag.route.primary_law == "Children Act 1989 s47"
    assert flag.route.statutory_guidance
    assert flag.route.local_procedure
    assert flag.route.organisational_policy
    assert flag.external_referral_sent is False
    assert flag.emergency_contacted is False
    assert flag.claimed_statutory_role is None
    assert flag.state.value == "queued_for_human"


def test_celeste_cannot_be_statutory_actor_or_send_referrals():
    policy = SafeguardingPolicy()
    for role in (HumanRole.DSL, HumanRole.LADO, HumanRole.POLICE, HumanRole.COURT, HumanRole.LOCAL_AUTHORITY_CHILDRENS_SOCIAL_CARE):
        assert role in FORBIDDEN_CELESTE_ROLES
        with pytest.raises(SafeguardingDenied):
            policy.assume_role(role)
    with pytest.raises(SafeguardingDenied):
        policy.conduct_section_47_enquiry()
    with pytest.raises(SafeguardingDenied):
        policy.send_referral()
    with pytest.raises(SafeguardingDenied):
        policy.contact_authorities()
    with pytest.raises(SafeguardingDenied):
        policy.contact_emergency_services()
    with pytest.raises(SafeguardingDenied):
        policy.transmit_student_data()


def test_staff_allegation_is_lado_not_s47():
    flag = SafeguardingPolicy().flag(tenant_id="school-a", student_id="stu", concern=SafetyConcern.ALLEGATION_AGAINST_STAFF, jurisdiction=Jurisdiction.ENGLAND)
    assert flag.threshold is ThresholdKind.ALLEGATION_AGAINST_STAFF
    assert HumanRole.LADO.value in flag.route.human_roles
    assert "s47" not in flag.route.primary_law


def test_england_adult_abuse_without_threshold_is_human_review():
    flag = SafeguardingPolicy().flag(
        tenant_id="home-a",
        student_id="adult-1",
        concern=SafetyConcern.ABUSE_DISCLOSURE,
        jurisdiction=Jurisdiction.ENGLAND,
        age_or_level="adult",
    )
    assert flag.threshold is ThresholdKind.ADULT_HUMAN_REVIEW
    assert flag.state.value == "queued_for_human"


def test_england_adult_self_harm_is_not_section_42():
    flag = SafeguardingPolicy().flag(
        tenant_id="home-a",
        student_id="adult-1",
        concern=SafetyConcern.SELF_HARM_DISCLOSURE,
        jurisdiction=Jurisdiction.ENGLAND,
        age_or_level="adult",
    )
    assert flag.threshold is not ThresholdKind.ADULT_SECTION_42
    assert flag.threshold is ThresholdKind.ADULT_HUMAN_REVIEW


def test_england_adult_explicit_three_part_threshold_models_s42_for_human():
    ctx = AdultSafeguardingContext(True, True, True)
    flag = SafeguardingPolicy().flag(
        tenant_id="home-a",
        student_id="adult-1",
        concern=SafetyConcern.ABUSE_DISCLOSURE,
        jurisdiction=Jurisdiction.ENGLAND,
        age_or_level="adult",
        adult_context=ctx,
    )
    assert flag.threshold is ThresholdKind.ADULT_SECTION_42
    assert "Care Act 2014" in flag.route.primary_law
    assert "not determined that a local-authority duty is legally engaged" in flag.route.explanation


def test_unknown_threshold_elements_are_human_review():
    ctx = AdultSafeguardingContext(True, True, None)
    flag = SafeguardingPolicy().flag(
        tenant_id="home-a",
        student_id="adult-1",
        concern=SafetyConcern.ABUSE_DISCLOSURE,
        jurisdiction=Jurisdiction.ENGLAND,
        age_or_level="adult",
        adult_context=ctx,
    )
    assert flag.threshold is ThresholdKind.ADULT_HUMAN_REVIEW


def test_devolved_adult_abuse_does_not_use_care_act_s42_wording():
    policy = SafeguardingPolicy()
    for jurisdiction in (Jurisdiction.WALES, Jurisdiction.SCOTLAND, Jurisdiction.NORTHERN_IRELAND):
        flag = policy.flag(
            tenant_id="home-a",
            student_id="adult-1",
            concern=SafetyConcern.ABUSE_DISCLOSURE,
            jurisdiction=jurisdiction,
            age_or_level="adult",
        )
        blob = " ".join([flag.route.primary_law, flag.route.statutory_guidance, flag.route.local_procedure, flag.route.threshold, flag.route.explanation])
        assert "Care Act 2014" not in blob
        assert "section 42" not in blob.lower()
        assert "s42" not in blob.lower()
    with pytest.raises(SafeguardingDenied):
        policy.contact_authorities()
    with pytest.raises(SafeguardingDenied):
        policy.assume_role(HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE)


def test_immediate_danger_keeps_requested_jurisdiction():
    policy = SafeguardingPolicy()
    for jurisdiction in (Jurisdiction.ENGLAND, Jurisdiction.WALES, Jurisdiction.SCOTLAND, Jurisdiction.NORTHERN_IRELAND):
        flag = policy.flag(
            tenant_id="t",
            student_id="stu",
            concern=SafetyConcern.IMMEDIATE_DANGER,
            jurisdiction=jurisdiction,
        )
        assert flag.route.jurisdiction == jurisdiction.value
        assert flag.threshold is ThresholdKind.IMMEDIATE_DANGER
        if jurisdiction is not Jurisdiction.ENGLAND:
            blob = f"{flag.route.primary_law} {flag.route.statutory_guidance} {flag.route.local_procedure}"
            assert "Working together" not in blob
            assert "KCSIE" not in blob
            assert "Children Act 1989" not in blob
    with pytest.raises(SafeguardingDenied):
        policy.contact_emergency_services()


def test_adult_non_abuse_concern_does_not_use_child_statutes():
    flag = SafeguardingPolicy().flag(
        tenant_id="home-a",
        student_id="adult-1",
        concern=SafetyConcern.BULLYING,
        jurisdiction=Jurisdiction.ENGLAND,
        age_or_level="adult",
    )
    assert flag.threshold is ThresholdKind.ADULT_HUMAN_REVIEW
    blob = f"{flag.route.primary_law} {flag.route.statutory_guidance}"
    assert "s17" not in blob
    assert "s47" not in blob
    assert flag.state.value == "queued_for_human"


def test_adult_immediate_danger_is_adult_route():
    flag = SafeguardingPolicy().flag(
        tenant_id="home-a",
        student_id="adult-1",
        concern=SafetyConcern.IMMEDIATE_DANGER,
        jurisdiction=Jurisdiction.SCOTLAND,
        age_or_level="adult",
    )
    assert flag.route.jurisdiction == "scotland"
    assert flag.threshold is ThresholdKind.IMMEDIATE_DANGER
    assert "Children Act 1989" not in flag.route.primary_law
    with pytest.raises(SafeguardingDenied):
        SafeguardingPolicy().contact_emergency_services()
