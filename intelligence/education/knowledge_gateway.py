"""Education Knowledge Gateway — Stage 2.

Connects Classroom query context to Knowledge Vault EDUCATION_UK
through public vault interfaces only.
READ / ANALYSE / RETRIEVE / PROPOSE. No Stage 4G execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from intelligence.knowledge_vault import (
    CONFIDENCE_AMBER,
    CONFIDENCE_GREEN,
    CONFIDENCE_RED,
    KnowledgeVault,
    build_stage1_vault,
)

from .curriculum import AwardingBody, Country, CurriculumNode, Qualification
from .safeguarding import SafetyConcern, SafeguardingPolicy
from .tenancy import EducationDirectory, IsolationDenied


EDUCATION_PACK_ID = "EDUCATION_UK"
FORBIDDEN_PACKS = frozenset({"CONSTRUCTION_UK", "LEGAL_ENGLAND_WALES", "PROPERTY_ENGLAND"})

AWARDING_BODY_SOURCE = {
    AwardingBody.AQA: "AQA_SPECIFICATIONS",
    AwardingBody.PEARSON_EDEXCEL: "PEARSON_EDEXCEL_SPECIFICATIONS",
    AwardingBody.OCR: "OCR_SPECIFICATIONS",
    AwardingBody.WJEC: "WJEC_SPECIFICATIONS",
    AwardingBody.EDUQAS: "EDUQAS_SPECIFICATIONS",
    AwardingBody.DFE: "GOVUK_NATIONAL_CURRICULUM",
}

SOURCE_JURISDICTION = {
    "GOVUK_NATIONAL_CURRICULUM": "england",
    "GOVUK_NC_COLLECTIONS": "england",
    "AQA_SPECIFICATIONS": "england",
    "PEARSON_EDEXCEL_SPECIFICATIONS": "england",
    "OCR_SPECIFICATIONS": "england",
    "WJEC_SPECIFICATIONS": "wales",
    "EDUQAS_SPECIFICATIONS": "england",
}


class EvidenceBasis(str, Enum):
    SOURCE_BACKED = "SOURCE_BACKED"
    GENERAL_EXPLANATION = "GENERAL_EXPLANATION"
    PROFESSIONAL_REVIEW_REQUIRED = "PROFESSIONAL_REVIEW_REQUIRED"
    NO_RELEVANT_SOURCE_MATCH = "NO_RELEVANT_SOURCE_MATCH"
    SAFEGUARDING_OVERRIDE = "SAFEGUARDING_OVERRIDE"


class GatewayDenied(PermissionError):
    pass


def _norm_jurisdiction(value: str | Country | None) -> str:
    if value is None:
        return ""
    raw = value.value if isinstance(value, Country) else str(value)
    key = raw.strip().lower().replace(" ", "_")
    aliases = {
        "northernireland": "northern_ireland",
        "ni": "northern_ireland",
        "northern ireland": "northern_ireland",
    }
    return aliases.get(key, key)


@dataclass(frozen=True)
class EducationKnowledgeRequest:
    tenant_id: str
    learner_context_id: str
    jurisdiction: str
    country: str
    subject: str
    qualification_level: str
    topic: str
    query: str
    lesson_mode: str = "learn"
    awarding_body: str | None = None
    specification: str | None = None
    learning_objective: str | None = None
    language: str | None = None


@dataclass(frozen=True)
class EducationKnowledgeResult:
    pack_id: str
    retrieved_context: str
    source_ids: tuple[str, ...]
    source_titles: tuple[str, ...]
    source_authority: tuple[str, ...]
    jurisdiction: str
    urls: tuple[str, ...]
    legal_status: tuple[str, ...]
    confidence: str
    stale: bool
    professional_review_required: bool
    provenance_summary: str
    retrieval_reason: str
    evidence_basis: EvidenceBasis
    versions: tuple[str, ...] = ()


class EducationKnowledgeGateway:
    """Tenant-scoped EDUCATION_UK retrieval. No live network. No execution."""

    def __init__(
        self,
        vault: KnowledgeVault | None = None,
        directory: EducationDirectory | None = None,
        safeguarding: SafeguardingPolicy | None = None,
    ) -> None:
        self.vault = vault or build_stage1_vault()
        self.directory = directory
        self.safeguarding = safeguarding or SafeguardingPolicy()
        self._seen_requests: dict[str, EducationKnowledgeRequest] = {}

    def pack_for_education(self) -> str:
        pack = self.vault.route_client("school")
        if pack.pack_id != EDUCATION_PACK_ID:
            raise GatewayDenied("education queries must route to EDUCATION_UK")
        if pack.pack_id in FORBIDDEN_PACKS:
            raise GatewayDenied("non-education pack blocked")
        return pack.pack_id

    def assert_execution_boundary(self) -> None:
        self.vault.assert_execution_boundary()
        if getattr(self.vault, "production_enabled", False):
            raise GatewayDenied("production must remain OFF")

    def retrieve(
        self,
        request: EducationKnowledgeRequest,
        *,
        actor_tenant_id: str | None = None,
        curriculum_node: CurriculumNode | None = None,
        safety_concern: SafetyConcern | None = None,
    ) -> EducationKnowledgeResult:
        self.assert_execution_boundary()
        actor = actor_tenant_id or request.tenant_id
        if actor != request.tenant_id:
            raise IsolationDenied("cross-tenant knowledge retrieval is denied")
        if self.directory is not None and request.learner_context_id in getattr(self.directory, "students", {}):
            self.directory.get_student(actor_tenant_id=actor, student_id=request.learner_context_id)

        if safety_concern is not None:
            try:
                resolved_j = _to_pack_jurisdiction(request.jurisdiction)
            except GatewayDenied:
                return EducationKnowledgeResult(
                    pack_id=EDUCATION_PACK_ID,
                    retrieved_context="Safeguarding jurisdiction is unsupported; England must not be substituted.",
                    source_ids=(),
                    source_titles=(),
                    source_authority=(),
                    jurisdiction=request.jurisdiction or "unspecified",
                    urls=(),
                    legal_status=(),
                    confidence=CONFIDENCE_RED,
                    stale=False,
                    professional_review_required=True,
                    provenance_summary="Unknown or unsupported jurisdiction. Human review required. Not England by default.",
                    retrieval_reason="JURISDICTION_UNSUPPORTED",
                    evidence_basis=EvidenceBasis.SAFEGUARDING_OVERRIDE,
                )
            flag = self.safeguarding.flag(
                tenant_id=request.tenant_id,
                student_id=request.learner_context_id,
                concern=safety_concern,
                jurisdiction=resolved_j,
            )
            return EducationKnowledgeResult(
                pack_id=EDUCATION_PACK_ID,
                retrieved_context="Safeguarding override: ordinary teaching retrieval is suspended.",
                source_ids=(),
                source_titles=(),
                source_authority=(),
                jurisdiction=request.jurisdiction,
                urls=(),
                legal_status=(),
                confidence=CONFIDENCE_RED,
                stale=False,
                professional_review_required=True,
                provenance_summary=flag.route.explanation,
                retrieval_reason="SAFEGUARDING_OVERRIDE",
                evidence_basis=EvidenceBasis.SAFEGUARDING_OVERRIDE,
            )

        pack_id = self.pack_for_education()
        records = list(self.vault.sources_for_pack(pack_id))
        for rec in records:
            if rec.industry not in {"education", "cross"}:
                raise GatewayDenied("cross-pack contamination blocked")

        awarding = _resolve_awarding_body(request, curriculum_node)
        wanted_source = AWARDING_BODY_SOURCE.get(awarding) if awarding else None
        requested_j = _norm_jurisdiction(request.jurisdiction or request.country)

        scoped = []
        for rec in records:
            if rec.industry == "cross" and not _query_mentions_legislation(request.query):
                continue
            scoped.append(rec)
        if wanted_source:
            matched = [r for r in scoped if r.source_id == wanted_source]
        else:
            matched = [r for r in scoped if _record_matches_request(r, request, curriculum_node)]

        self._seen_requests[f"{request.tenant_id}:{request.learner_context_id}"] = request

        if not matched:
            return EducationKnowledgeResult(
                pack_id=pack_id,
                retrieved_context="No approved EDUCATION_UK source matched this classroom query.",
                source_ids=(),
                source_titles=(),
                source_authority=(),
                jurisdiction=request.jurisdiction,
                urls=(),
                legal_status=(),
                confidence=CONFIDENCE_AMBER,
                stale=False,
                professional_review_required=True,
                provenance_summary="No approved curriculum source matched. Do not treat this as official.",
                retrieval_reason="NO_RELEVANT_SOURCE_MATCH",
                evidence_basis=EvidenceBasis.NO_RELEVANT_SOURCE_MATCH,
            )

        primary = matched[0]
        source_j = _norm_jurisdiction(SOURCE_JURISDICTION.get(primary.source_id, primary.jurisdiction))
        mismatch = bool(requested_j) and source_j and requested_j not in {source_j, "uk"} and source_j != "uk"
        stale = any(r.stale or not r.active or r.superseded_by for r in matched)
        if mismatch:
            return EducationKnowledgeResult(
                pack_id=pack_id,
                retrieved_context=(
                    f"Source {primary.source_id} applies to {primary.jurisdiction}; "
                    f"request jurisdiction is {request.jurisdiction}."
                ),
                source_ids=tuple(r.source_id for r in matched),
                source_titles=tuple(r.source_name for r in matched),
                source_authority=tuple(r.authority for r in matched),
                jurisdiction=primary.jurisdiction,
                urls=tuple(r.source_url for r in matched),
                legal_status=tuple(r.legal_status for r in matched),
                confidence=CONFIDENCE_AMBER,
                stale=stale,
                professional_review_required=True,
                provenance_summary="Jurisdiction mismatch. England sources must not stand in for another nation.",
                retrieval_reason="JURISDICTION_MISMATCH",
                evidence_basis=EvidenceBasis.PROFESSIONAL_REVIEW_REQUIRED,
                versions=tuple(r.source_version for r in matched),
            )

        body_ready = all(r.body_ingested for r in matched)
        if stale:
            confidence = CONFIDENCE_AMBER
            basis = EvidenceBasis.PROFESSIONAL_REVIEW_REQUIRED
            reason = "STALE_SOURCE"
            summary = (
                f"Stale or inactive catalog record {primary.authority} — {primary.source_name}. "
                "Revalidation required. Confidence AMBER."
            )
        elif body_ready:
            confidence = CONFIDENCE_GREEN
            basis = EvidenceBasis.SOURCE_BACKED
            reason = "APPROVED_EDUCATION_SOURCE"
            summary = (
                f"Based on the approved curriculum source {primary.authority} — {primary.source_name} "
                f"({primary.jurisdiction}, version {primary.source_version}). "
                f"Confidence {confidence}."
            )
        else:
            confidence = CONFIDENCE_AMBER
            basis = EvidenceBasis.PROFESSIONAL_REVIEW_REQUIRED
            reason = "METADATA_ONLY_REFERENCE"
            summary = (
                f"An approved curriculum reference is available ({primary.authority} — {primary.source_name}, "
                f"{primary.jurisdiction}, version {primary.source_version}), but its body text is not ingested "
                "in the governed vault. This is metadata/link-only, not source-backed teaching content."
            )

        titles = ", ".join(r.source_name for r in matched)
        return EducationKnowledgeResult(
            pack_id=pack_id,
            retrieved_context=f"Approved EDUCATION_UK catalog evidence: {titles}.",
            source_ids=tuple(r.source_id for r in matched),
            source_titles=tuple(r.source_name for r in matched),
            source_authority=tuple(r.authority for r in matched),
            jurisdiction=primary.jurisdiction,
            urls=tuple(r.source_url for r in matched),
            legal_status=tuple(r.legal_status for r in matched),
            confidence=confidence,
            stale=stale,
            professional_review_required=stale or not body_ready or confidence != CONFIDENCE_GREEN,
            provenance_summary=summary,
            retrieval_reason=reason,
            evidence_basis=basis,
            versions=tuple(r.source_version for r in matched),
        )


def _to_pack_jurisdiction(value: str):
    from .safeguarding_knowledge import Jurisdiction

    key = _norm_jurisdiction(value)
    mapping = {
        "england": Jurisdiction.ENGLAND,
        "wales": Jurisdiction.WALES,
        "scotland": Jurisdiction.SCOTLAND,
        "northern_ireland": Jurisdiction.NORTHERN_IRELAND,
    }
    if key not in mapping:
        raise GatewayDenied("unsupported safeguarding jurisdiction; human review required")
    return mapping[key]


def _resolve_awarding_body(request: EducationKnowledgeRequest, node: CurriculumNode | None) -> AwardingBody | None:
    if node is not None:
        return node.awarding_body
    if not request.awarding_body:
        return None
    raw = request.awarding_body.strip().lower().replace(" ", "_")
    aliases = {
        "pearson": "pearson_edexcel",
        "edexcel": "pearson_edexcel",
        "pearson_edexcel": "pearson_edexcel",
    }
    raw = aliases.get(raw, raw)
    try:
        return AwardingBody(raw)
    except ValueError:
        return None


def _query_mentions_legislation(query: str) -> bool:
    q = query.lower()
    return any(token in q for token in ("legislation", "act 19", "act 20", "statute"))


def _record_matches_request(rec, request: EducationKnowledgeRequest, node: CurriculumNode | None) -> bool:
    blob = " ".join(
        [
            rec.source_id,
            rec.source_name,
            rec.authority,
            rec.topic,
            rec.jurisdiction,
            rec.document_type,
        ]
    ).lower()
    tokens = []
    for part in (request.query, request.subject, request.topic, request.awarding_body, request.qualification_level):
        if part:
            tokens.extend(str(part).lower().replace("_", " ").split())
    if node is not None:
        tokens.extend(
            [
                node.awarding_body.value,
                node.subject.lower(),
                node.topic.lower(),
                node.qualification.value,
            ]
        )
    interesting = [t for t in tokens if len(t) >= 3]
    return any(t in blob for t in interesting)


def curriculum_query_hint(node: CurriculumNode) -> str:
    return f"{node.subject} {node.awarding_body.value} {node.qualification.value} {node.topic}"
