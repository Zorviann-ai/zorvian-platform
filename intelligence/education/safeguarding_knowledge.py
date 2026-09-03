"""Versioned Education/Safeguarding Knowledge Pack.

Source map, not a persona. Distinguishes primary law, statutory guidance,
local procedure and organisational policy by UK jurisdiction.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


PACK_ID = "caelomere-education-safeguarding-knowledge"
PACK_VERSION = "2026.09.03-rebuild-1"
PACK_STATUS = "foundation_reference"
PACK_DISCLAIMER = (
    "Structured reference for detect/record/classify/explain/flag/"
    "require-human-review/route. Not legal advice. Confers no statutory authority."
)


class InstrumentKind(str, Enum):
    PRIMARY_LAW = "primary_law"
    STATUTORY_GUIDANCE = "statutory_guidance"
    LOCAL_PROCEDURE = "local_procedure"
    ORGANISATIONAL_POLICY = "organisational_policy"
    DUTY = "duty"


class Jurisdiction(str, Enum):
    ENGLAND = "england"
    WALES = "wales"
    SCOTLAND = "scotland"
    NORTHERN_IRELAND = "northern_ireland"


class Population(str, Enum):
    CHILD = "child"
    ADULT = "adult"


class HumanRole(str, Enum):
    DSL = "designated_safeguarding_lead"
    LOCAL_AUTHORITY_CHILDRENS_SOCIAL_CARE = "local_authority_childrens_social_care"
    LOCAL_AUTHORITY_ADULT_SOCIAL_CARE = "local_authority_adult_social_care"
    POLICE = "police"
    LADO = "local_authority_designated_officer"
    COURT = "court"
    NSPCC = "nspcc"
    SAFEGUARDING_ADULTS_BOARD = "safeguarding_adults_board"
    NAMED_PERSON_OR_SOCIAL_WORK = "named_person_or_social_work"
    SBNI_PARTNER = "sbni_partner"
    EMERGENCY_SERVICES = "emergency_services"
    AUTHORISED_HUMAN_REVIEWER = "authorised_human_reviewer"


FORBIDDEN_CELESTE_ROLES = frozenset(
    {
        HumanRole.DSL,
        HumanRole.LOCAL_AUTHORITY_CHILDRENS_SOCIAL_CARE,
        HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE,
        HumanRole.POLICE,
        HumanRole.LADO,
        HumanRole.COURT,
        HumanRole.SAFEGUARDING_ADULTS_BOARD,
        HumanRole.NAMED_PERSON_OR_SOCIAL_WORK,
        HumanRole.SBNI_PARTNER,
        HumanRole.EMERGENCY_SERVICES,
    }
)

CELESTE_MAY = (
    "detect",
    "record",
    "classify",
    "explain",
    "flag",
    "require_human_review",
    "route_to_authorised_human_role",
)

CELESTE_MUST_NOT = (
    "act_as_dsl",
    "act_as_lado",
    "act_as_police",
    "act_as_social_services",
    "act_as_court",
    "conduct_section_47_enquiry",
    "autonomously_contact_authorities",
    "send_safeguarding_referral",
    "contact_emergency_services",
)


class ThresholdKind(str, Enum):
    EARLY_HELP = "early_help"
    CHILD_IN_NEED = "child_in_need"
    SIGNIFICANT_HARM = "significant_harm"
    ADULT_SECTION_42 = "adult_section_42"
    ADULT_HUMAN_REVIEW = "adult_human_review"
    IMMEDIATE_DANGER = "immediate_danger"
    ALLEGATION_AGAINST_STAFF = "allegation_against_staff"


@dataclass(frozen=True)
class LegalInstrument:
    instrument_id: str
    title: str
    kind: InstrumentKind
    citation: str
    year: str
    applies_to: tuple[Jurisdiction, ...]
    notes: str


@dataclass(frozen=True)
class EscalationRoute:
    route_id: str
    jurisdiction: Jurisdiction
    population: Population
    threshold: ThresholdKind
    primary_law: str
    statutory_guidance: str
    local_procedure: str
    organisational_policy: str
    human_roles: tuple[HumanRole, ...]
    celeste_may: tuple[str, ...] = CELESTE_MAY
    celeste_must_not: tuple[str, ...] = CELESTE_MUST_NOT


INSTRUMENTS: tuple[LegalInstrument, ...] = (
    LegalInstrument("ca-1989", "Children Act 1989", InstrumentKind.PRIMARY_LAW, "1989 c. 41", "1989", (Jurisdiction.ENGLAND, Jurisdiction.WALES), "s17 child in need; s47 significant-harm enquiries."),
    LegalInstrument("ca-2004", "Children Act 2004", InstrumentKind.PRIMARY_LAW, "2004 c. 31", "2004", (Jurisdiction.ENGLAND, Jurisdiction.WALES), "Multi-agency co-operation."),
    LegalInstrument("ea-2002-s175", "Education Act 2002 s175", InstrumentKind.DUTY, "2002 c. 32 s.175", "2002", (Jurisdiction.ENGLAND,), "School/FE welfare arrangements."),
    LegalInstrument("wt-2023", "Working together to safeguard children 2023", InstrumentKind.STATUTORY_GUIDANCE, "DfE", "2023", (Jurisdiction.ENGLAND,), "England inter-agency child safeguarding."),
    LegalInstrument("kcsie-2025", "Keeping children safe in education 2025", InstrumentKind.STATUTORY_GUIDANCE, "DfE", "2025", (Jurisdiction.ENGLAND,), "Schools/colleges including LADO pathway."),
    LegalInstrument("info-share-2024", "Information sharing advice for safeguarding practitioners", InstrumentKind.STATUTORY_GUIDANCE, "DfE", "2024", (Jurisdiction.ENGLAND,), "GDPR is not a bar to necessary sharing."),
    LegalInstrument("care-act-2014", "Care Act 2014 ss42-46", InstrumentKind.PRIMARY_LAW, "2014 c. 23", "2014", (Jurisdiction.ENGLAND,), "Adult safeguarding enquiries and SABs."),
    LegalInstrument("care-guidance-ch14", "Care and support statutory guidance ch.14", InstrumentKind.STATUTORY_GUIDANCE, "DHSC", "2014+", (Jurisdiction.ENGLAND,), "Adult safeguarding practice."),
    LegalInstrument("sswb-wales-2014", "Social Services and Well-being (Wales) Act 2014", InstrumentKind.PRIMARY_LAW, "2014 anaw 4", "2014", (Jurisdiction.WALES,), "Wales children and adult framework."),
    LegalInstrument("wales-procedures", "Wales Safeguarding Procedures", InstrumentKind.LOCAL_PROCEDURE, "Wales Safeguarding Procedures Project", "2019+", (Jurisdiction.WALES,), "Used with Keeping Learners Safe."),
    LegalInstrument("scot-cp-2021", "National Guidance for Child Protection in Scotland 2021", InstrumentKind.STATUTORY_GUIDANCE, "Scottish Government", "2021", (Jurisdiction.SCOTLAND,), "Not Children Act 1989 s47."),
    LegalInstrument("asp-scot-2007", "Adult Support and Protection (Scotland) Act 2007", InstrumentKind.PRIMARY_LAW, "2007 asp 10", "2007", (Jurisdiction.SCOTLAND,), "Adults at risk in Scotland."),
    LegalInstrument("children-ni-1995", "Children (Northern Ireland) Order 1995", InstrumentKind.PRIMARY_LAW, "1995 No. 755 (N.I. 2)", "1995", (Jurisdiction.NORTHERN_IRELAND,), "NI child protection foundation."),
    LegalInstrument("sbni-procedures", "SBNI regional child protection policies", InstrumentKind.LOCAL_PROCEDURE, "SBNI", "current", (Jurisdiction.NORTHERN_IRELAND,), "Trust/SBNI local procedures."),
    LegalInstrument("org-policy", "Organisational education safeguarding policy", InstrumentKind.ORGANISATIONAL_POLICY, "tenant policy", "current", (Jurisdiction.ENGLAND, Jurisdiction.WALES, Jurisdiction.SCOTLAND, Jurisdiction.NORTHERN_IRELAND), "School/home/tutor policy. Does not replace statute."),
    LegalInstrument("osa-2023", "Online Safety Act 2023", InstrumentKind.PRIMARY_LAW, "2023 c. 50", "2023", tuple(Jurisdiction), "Platform duties. Does not make Celeste a regulator."),
)


ROUTES: tuple[EscalationRoute, ...] = (
    EscalationRoute(
        "eng-child-s47", Jurisdiction.ENGLAND, Population.CHILD, ThresholdKind.SIGNIFICANT_HARM,
        "Children Act 1989 s47", "Working together to safeguard children 2023",
        "Local Safeguarding Children Partnership procedures", "School child-protection policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.DSL, HumanRole.LOCAL_AUTHORITY_CHILDRENS_SOCIAL_CARE, HumanRole.POLICE),
    ),
    EscalationRoute(
        "eng-child-s17", Jurisdiction.ENGLAND, Population.CHILD, ThresholdKind.CHILD_IN_NEED,
        "Children Act 1989 s17", "Working together to safeguard children 2023",
        "Local early help / CIN procedures", "School pastoral / CP policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.DSL, HumanRole.LOCAL_AUTHORITY_CHILDRENS_SOCIAL_CARE),
    ),
    EscalationRoute(
        "eng-school-staff", Jurisdiction.ENGLAND, Population.CHILD, ThresholdKind.ALLEGATION_AGAINST_STAFF,
        "Education Act 2002 s175", "Keeping children safe in education 2025 Part 4",
        "LADO referral procedure", "School allegations against staff policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.DSL, HumanRole.LADO),
    ),
    EscalationRoute(
        "eng-adult-s42", Jurisdiction.ENGLAND, Population.ADULT, ThresholdKind.ADULT_SECTION_42,
        "Care Act 2014 s42", "Care and support statutory guidance ch.14",
        "Local Safeguarding Adults Board procedures", "Organisational adult-safeguarding policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE, HumanRole.SAFEGUARDING_ADULTS_BOARD),
    ),
    EscalationRoute(
        "wales-child", Jurisdiction.WALES, Population.CHILD, ThresholdKind.SIGNIFICANT_HARM,
        "Social Services and Well-being (Wales) Act 2014", "Keeping Learners Safe",
        "Wales Safeguarding Procedures", "School/setting CP policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.DSL, HumanRole.LOCAL_AUTHORITY_CHILDRENS_SOCIAL_CARE),
    ),
    EscalationRoute(
        "scot-child", Jurisdiction.SCOTLAND, Population.CHILD, ThresholdKind.SIGNIFICANT_HARM,
        "Children (Scotland) Act 1995 / Children and Young People (Scotland) Act 2014",
        "National Guidance for Child Protection in Scotland 2021",
        "Local child protection procedures / GIRFEC", "Setting CP policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.NAMED_PERSON_OR_SOCIAL_WORK, HumanRole.POLICE),
    ),
    EscalationRoute(
        "ni-child", Jurisdiction.NORTHERN_IRELAND, Population.CHILD, ThresholdKind.SIGNIFICANT_HARM,
        "Children (Northern Ireland) Order 1995", "SBNI regional child protection policies",
        "HSC Trust / SBNI procedures", "Setting CP policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.SBNI_PARTNER, HumanRole.POLICE),
    ),
    EscalationRoute(
        "eng-immediate-child", Jurisdiction.ENGLAND, Population.CHILD, ThresholdKind.IMMEDIATE_DANGER,
        "Common law / emergency services", "Working together / KCSIE emergency action",
        "Call 999 (human action)", "England setting emergency policy",
        (HumanRole.EMERGENCY_SERVICES, HumanRole.POLICE, HumanRole.AUTHORISED_HUMAN_REVIEWER),
    ),
    EscalationRoute(
        "wales-immediate-child", Jurisdiction.WALES, Population.CHILD, ThresholdKind.IMMEDIATE_DANGER,
        "Common law / emergency services", "Wales Safeguarding Procedures emergency action",
        "Call 999 (human action)", "Wales setting emergency policy",
        (HumanRole.EMERGENCY_SERVICES, HumanRole.POLICE, HumanRole.AUTHORISED_HUMAN_REVIEWER),
    ),
    EscalationRoute(
        "scot-immediate-child", Jurisdiction.SCOTLAND, Population.CHILD, ThresholdKind.IMMEDIATE_DANGER,
        "Common law / emergency services", "National Guidance for Child Protection in Scotland 2021 emergency action",
        "Call 999 (human action)", "Scotland setting emergency policy",
        (HumanRole.EMERGENCY_SERVICES, HumanRole.POLICE, HumanRole.AUTHORISED_HUMAN_REVIEWER),
    ),
    EscalationRoute(
        "ni-immediate-child", Jurisdiction.NORTHERN_IRELAND, Population.CHILD, ThresholdKind.IMMEDIATE_DANGER,
        "Common law / emergency services", "SBNI emergency action",
        "Call 999 (human action)", "Northern Ireland setting emergency policy",
        (HumanRole.EMERGENCY_SERVICES, HumanRole.POLICE, HumanRole.AUTHORISED_HUMAN_REVIEWER),
    ),
    EscalationRoute(
        "eng-immediate-adult", Jurisdiction.ENGLAND, Population.ADULT, ThresholdKind.IMMEDIATE_DANGER,
        "Common law / emergency services", "Care and support statutory guidance emergency action",
        "Call 999 (human action)", "England adult emergency policy",
        (HumanRole.EMERGENCY_SERVICES, HumanRole.POLICE, HumanRole.AUTHORISED_HUMAN_REVIEWER),
    ),
    EscalationRoute(
        "wales-immediate-adult", Jurisdiction.WALES, Population.ADULT, ThresholdKind.IMMEDIATE_DANGER,
        "Common law / emergency services", "Wales Safeguarding Procedures adult emergency action",
        "Call 999 (human action)", "Wales adult emergency policy",
        (HumanRole.EMERGENCY_SERVICES, HumanRole.POLICE, HumanRole.AUTHORISED_HUMAN_REVIEWER),
    ),
    EscalationRoute(
        "scot-immediate-adult", Jurisdiction.SCOTLAND, Population.ADULT, ThresholdKind.IMMEDIATE_DANGER,
        "Common law / emergency services", "Adult Support and Protection (Scotland) emergency action",
        "Call 999 (human action)", "Scotland adult emergency policy",
        (HumanRole.EMERGENCY_SERVICES, HumanRole.POLICE, HumanRole.AUTHORISED_HUMAN_REVIEWER),
    ),
    EscalationRoute(
        "ni-immediate-adult", Jurisdiction.NORTHERN_IRELAND, Population.ADULT, ThresholdKind.IMMEDIATE_DANGER,
        "Common law / emergency services", "NI adult safeguarding emergency action",
        "Call 999 (human action)", "Northern Ireland adult emergency policy",
        (HumanRole.EMERGENCY_SERVICES, HumanRole.POLICE, HumanRole.AUTHORISED_HUMAN_REVIEWER),
    ),
    EscalationRoute(
        "eng-adult-review", Jurisdiction.ENGLAND, Population.ADULT, ThresholdKind.ADULT_HUMAN_REVIEW,
        "Care Act 2014 framework — threshold not established", "Care and support statutory guidance ch.14",
        "Local Safeguarding Adults Board human review", "Organisational adult-safeguarding policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE),
    ),
    EscalationRoute(
        "wales-adult-review", Jurisdiction.WALES, Population.ADULT, ThresholdKind.ADULT_HUMAN_REVIEW,
        "Social Services and Well-being (Wales) Act 2014", "Wales Safeguarding Procedures",
        "Regional adult safeguarding human review", "Organisational adult-safeguarding policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE),
    ),
    EscalationRoute(
        "scot-adult-review", Jurisdiction.SCOTLAND, Population.ADULT, ThresholdKind.ADULT_HUMAN_REVIEW,
        "Adult Support and Protection (Scotland) Act 2007", "Adult support and protection guidance",
        "Local adult protection committee human review", "Organisational adult-safeguarding policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE),
    ),
    EscalationRoute(
        "ni-adult-review", Jurisdiction.NORTHERN_IRELAND, Population.ADULT, ThresholdKind.ADULT_HUMAN_REVIEW,
        "NI adult safeguarding policy framework", "Adult Safeguarding: Prevention and Protection in Partnership",
        "HSC Trust adult safeguarding human review", "Organisational adult-safeguarding policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE),
    ),
    EscalationRoute(
        "wales-adult-s42-equivalent", Jurisdiction.WALES, Population.ADULT, ThresholdKind.ADULT_SECTION_42,
        "Social Services and Well-being (Wales) Act 2014", "Wales Safeguarding Procedures",
        "Regional adult safeguarding enquiry", "Organisational adult-safeguarding policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE),
    ),
    EscalationRoute(
        "scot-adult-s42-equivalent", Jurisdiction.SCOTLAND, Population.ADULT, ThresholdKind.ADULT_SECTION_42,
        "Adult Support and Protection (Scotland) Act 2007", "Adult support and protection guidance",
        "Local adult protection enquiry", "Organisational adult-safeguarding policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE),
    ),
    EscalationRoute(
        "ni-adult-s42-equivalent", Jurisdiction.NORTHERN_IRELAND, Population.ADULT, ThresholdKind.ADULT_SECTION_42,
        "NI adult safeguarding policy framework", "Adult Safeguarding: Prevention and Protection in Partnership",
        "HSC Trust adult safeguarding enquiry", "Organisational adult-safeguarding policy",
        (HumanRole.AUTHORISED_HUMAN_REVIEWER, HumanRole.LOCAL_AUTHORITY_ADULT_SOCIAL_CARE),
    ),
)


def instruments_for(jurisdiction: Jurisdiction) -> tuple[LegalInstrument, ...]:
    return tuple(i for i in INSTRUMENTS if jurisdiction in i.applies_to)


def lookup_route(jurisdiction: Jurisdiction, population: Population, threshold: ThresholdKind) -> EscalationRoute:
    matches = [r for r in ROUTES if r.jurisdiction is jurisdiction and r.population is population and r.threshold is threshold]
    if matches:
        return matches[0]
    if population is Population.ADULT and threshold not in {ThresholdKind.IMMEDIATE_DANGER, ThresholdKind.ADULT_HUMAN_REVIEW}:
        fallback = [r for r in ROUTES if r.jurisdiction is jurisdiction and r.population is Population.ADULT and r.threshold is ThresholdKind.ADULT_HUMAN_REVIEW]
        if fallback:
            return fallback[0]
    raise KeyError(f"no safeguarding route for {jurisdiction.value}/{population.value}/{threshold.value}")


def pack_meta() -> dict[str, str]:
    return {"pack_id": PACK_ID, "version": PACK_VERSION, "status": PACK_STATUS, "disclaimer": PACK_DISCLAIMER}
