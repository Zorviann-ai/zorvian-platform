"""Safeguarding runtime: detect, record, classify, explain, flag, require review, route."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import uuid

from .safeguarding_knowledge import (
    CELESTE_MAY,
    FORBIDDEN_CELESTE_ROLES,
    HumanRole,
    Jurisdiction,
    PACK_VERSION,
    Population,
    ThresholdKind,
    lookup_route,
    pack_meta,
)


class SafetyConcern(str, Enum):
    AGE_INAPPROPRIATE = "age_inappropriate"
    ADULT_CONTENT = "adult_content"
    SELF_HARM_DISCLOSURE = "self_harm_disclosure"
    ABUSE_DISCLOSURE = "abuse_disclosure"
    BULLYING = "bullying"
    SUSPICIOUS_CONTACT = "suspicious_contact"
    UNSAFE_REQUEST = "unsafe_request"
    ALLEGATION_AGAINST_STAFF = "allegation_against_staff"
    IMMEDIATE_DANGER = "immediate_danger"


class EscalationState(str, Enum):
    DETECTED = "detected"
    RECORDED = "recorded"
    CLASSIFIED = "classified"
    FLAGGED = "flagged"
    HUMAN_REVIEW_REQUIRED = "human_review_required"
    QUEUED_FOR_HUMAN = "queued_for_human"


class SafeguardingDenied(PermissionError):
    pass


@dataclass(frozen=True)
class AdultSafeguardingContext:
    """Facts that a human/statutory body must assess. Unknown does not establish s42."""

    has_care_and_support_needs: bool | None = None
    experiencing_or_at_risk_of_abuse_or_neglect: bool | None = None
    unable_to_protect_due_to_needs: bool | None = None

    def three_part_threshold_explicitly_met(self) -> bool:
        return (
            self.has_care_and_support_needs is True
            and self.experiencing_or_at_risk_of_abuse_or_neglect is True
            and self.unable_to_protect_due_to_needs is True
        )


def infer_threshold(concern: SafetyConcern) -> ThresholdKind:
    if concern is SafetyConcern.IMMEDIATE_DANGER:
        return ThresholdKind.IMMEDIATE_DANGER
    if concern is SafetyConcern.ALLEGATION_AGAINST_STAFF:
        return ThresholdKind.ALLEGATION_AGAINST_STAFF
    if concern in {SafetyConcern.ABUSE_DISCLOSURE, SafetyConcern.SELF_HARM_DISCLOSURE}:
        return ThresholdKind.SIGNIFICANT_HARM
    if concern in {SafetyConcern.BULLYING, SafetyConcern.SUSPICIOUS_CONTACT}:
        return ThresholdKind.CHILD_IN_NEED
    return ThresholdKind.EARLY_HELP


def infer_population(concern: SafetyConcern, age_or_level: str | None) -> Population:
    if age_or_level and age_or_level.lower() in {"adult", "18+", "post-18"}:
        return Population.ADULT
    return Population.CHILD


@dataclass(frozen=True)
class RouteCard:
    pack_version: str
    jurisdiction: str
    primary_law: str
    statutory_guidance: str
    local_procedure: str
    organisational_policy: str
    threshold: str
    human_roles: tuple[str, ...]
    explanation: str
    celeste_actions: tuple[str, ...] = CELESTE_MAY
    celeste_role: str = "detect_record_classify_explain_flag_require_review_route"


@dataclass(frozen=True)
class SafetyFlag:
    flag_id: str
    tenant_id: str
    student_id: str
    concern: SafetyConcern
    jurisdiction: Jurisdiction
    threshold: ThresholdKind
    state: EscalationState
    created_at: datetime
    route: RouteCard
    autonomous_intervention: bool
    external_referral_sent: bool
    emergency_contacted: bool
    claimed_statutory_role: str | None


@dataclass
class SafeguardingPolicy:
    flags: list[SafetyFlag] = field(default_factory=list)

    def detect(self, text: str) -> bool:
        return self.refuse_unsafe(text) or any(
            token in text.lower() for token in ("hurt me", "someone at home hits", "i want to disappear")
        )

    def refuse_unsafe(self, text: str) -> bool:
        lowered = text.lower()
        return any(token in lowered for token in ("adult content", "weapon how-to", "self-harm method"))

    def age_appropriate(self, age_or_level: str, topic: str) -> bool:
        if age_or_level.lower() in {"ks1", "ks2", "primary"} and "adult" in topic.lower():
            return False
        return True

    def classify(
        self,
        concern: SafetyConcern,
        age_or_level: str | None = None,
        adult_context: AdultSafeguardingContext | None = None,
    ) -> tuple[Population, ThresholdKind]:
        population = infer_population(concern, age_or_level)
        if population is Population.ADULT:
            if concern is SafetyConcern.IMMEDIATE_DANGER:
                return population, ThresholdKind.IMMEDIATE_DANGER
            if adult_context is not None and adult_context.three_part_threshold_explicitly_met():
                return population, ThresholdKind.ADULT_SECTION_42
            return population, ThresholdKind.ADULT_HUMAN_REVIEW
        return population, infer_threshold(concern)

    def explain_route(self, *, jurisdiction: Jurisdiction, population: Population, threshold: ThresholdKind) -> RouteCard:
        route = lookup_route(jurisdiction, population, threshold)
        if route.jurisdiction is not jurisdiction:
            raise SafeguardingDenied("safeguarding route jurisdiction must match the requested jurisdiction")
        roles = ", ".join(r.value for r in route.human_roles)
        public_threshold = self._public_threshold_label(jurisdiction, population, threshold)
        modelled = (
            "The recorded facts appear to model an adult-safeguarding enquiry threshold and require "
            "authorised human/statutory assessment. Celeste has not determined that a local-authority "
            "duty is legally engaged."
            if threshold is ThresholdKind.ADULT_SECTION_42
            else "Human review required."
        )
        explanation = (
            f"Pack {PACK_VERSION}: {jurisdiction.value} / {population.value} / {public_threshold}. "
            f"Primary law: {route.primary_law}. Statutory guidance: {route.statutory_guidance}. "
            f"Local procedure: {route.local_procedure}. Organisational policy: {route.organisational_policy}. "
            f"{modelled} Human roles: {roles}. Celeste may only detect, record, classify, explain, "
            "flag, require human review and route. Celeste is not a DSL, LADO, police, social services or court."
        )
        return RouteCard(
            pack_version=PACK_VERSION,
            jurisdiction=route.jurisdiction.value,
            primary_law=route.primary_law,
            statutory_guidance=route.statutory_guidance,
            local_procedure=route.local_procedure,
            organisational_policy=route.organisational_policy,
            threshold=public_threshold,
            human_roles=tuple(r.value for r in route.human_roles),
            explanation=explanation,
        )

    @staticmethod
    def _public_threshold_label(jurisdiction: Jurisdiction, population: Population, threshold: ThresholdKind) -> str:
        if threshold is ThresholdKind.ADULT_SECTION_42 and jurisdiction is Jurisdiction.ENGLAND:
            return "england_care_act_s42_threshold_modelled_requires_human_assessment"
        if threshold is ThresholdKind.ADULT_SECTION_42:
            return "adult_enquiry_threshold_modelled_requires_human_assessment"
        return threshold.value

    def flag(
        self,
        *,
        tenant_id: str,
        student_id: str,
        concern: SafetyConcern,
        jurisdiction: Jurisdiction = Jurisdiction.ENGLAND,
        age_or_level: str | None = None,
        adult_context: AdultSafeguardingContext | None = None,
    ) -> SafetyFlag:
        population, threshold = self.classify(concern, age_or_level, adult_context)
        card = self.explain_route(jurisdiction=jurisdiction, population=population, threshold=threshold)
        item = SafetyFlag(
            flag_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            student_id=student_id,
            concern=concern,
            jurisdiction=jurisdiction,
            threshold=threshold,
            state=EscalationState.QUEUED_FOR_HUMAN,
            created_at=datetime.now(timezone.utc),
            route=card,
            autonomous_intervention=False,
            external_referral_sent=False,
            emergency_contacted=False,
            claimed_statutory_role=None,
        )
        self.flags.append(item)
        return item

    def assume_role(self, role: HumanRole | str) -> None:
        resolved = role if isinstance(role, HumanRole) else HumanRole(role)
        if resolved in FORBIDDEN_CELESTE_ROLES:
            raise SafeguardingDenied(
                f"Celeste cannot assume statutory role {resolved.value}; pack {PACK_VERSION}"
            )
        raise SafeguardingDenied(f"Celeste cannot assume role {resolved.value}")

    def conduct_section_47_enquiry(self, *_a, **_k) -> None:
        raise SafeguardingDenied("Celeste cannot conduct a statutory section 47 enquiry")

    def send_referral(self, *_a, **_k) -> None:
        raise SafeguardingDenied("Celeste cannot send safeguarding referrals")

    def contact_authorities(self, *_a, **_k) -> None:
        raise SafeguardingDenied("Celeste cannot autonomously contact authorities")

    def contact_emergency_services(self, *_a, **_k) -> None:
        raise SafeguardingDenied("Celeste cannot contact emergency services")

    def intervene_autonomously(self, *_a, **_k) -> None:
        raise SafeguardingDenied("education safeguarding cannot autonomously intervene")

    def transmit_student_data(self, *_a, **_k) -> None:
        raise SafeguardingDenied("education Stage 1 cannot transmit student data externally")

    def meta(self) -> dict[str, str]:
        return pack_meta()
