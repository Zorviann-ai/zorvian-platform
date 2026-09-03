"""Caelomere Knowledge Vault — Stage 1 foundation.

READ / ANALYSE / PROPOSE only.
Does not call Stage 4G private execution, /live, or production submit.
Does not deploy or publish.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from intelligence.knowledge_sources import (
    ALLOWLISTED_DOMAINS,
    CLIENT_ROUTES,
    INDUSTRY_PACK_SPECS,
    METADATA_ONLY_DOMAINS,
    OFFICIAL_SOURCES,
)

LEGAL_STATUSES = (
    "PRIMARY_LAW",
    "SECONDARY_LEGISLATION",
    "STATUTORY_GUIDANCE",
    "REGULATOR_RULE",
    "OFFICIAL_GUIDANCE",
    "CURRICULUM_SPECIFICATION",
    "LOCAL_PROCEDURE",
    "OTHER",
)

CONFIDENCE_GREEN = "GREEN / VERIFIED"
CONFIDENCE_AMBER = "AMBER / ADVISORY"
CONFIDENCE_RED = "RED / PROFESSIONAL_REVIEW_REQUIRED"

STAGE_DISCLAIMERS = (
    "THIS STAGE DOES NOT GUARANTEE PROFESSIONAL ADVICE.",
    "THIS STAGE DOES NOT INGEST PAID OR RESTRICTED CONTENT WITHOUT LICENCE.",
    "THIS STAGE DOES NOT EXECUTE PROFESSIONAL DECISIONS.",
    "THIS STAGE DOES NOT DEPLOY TO PRODUCTION.",
)

RESTRICTED_LICENCE_MARKERS = (
    "metadata only",
    "do not ingest",
    "without licence",
    "exam-board copyright",
    "sra copyright",
)

FETCH_DENIED_LICENCES = (
    "SRA copyright",
    "Exam-board copyright",
)


class KnowledgeVaultError(ValueError):
    """Raised when a source or pack fails Stage 1 governance."""


class SourceRejected(KnowledgeVaultError):
    pass


class RightsDenied(KnowledgeVaultError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def domain_allowed(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in ALLOWLISTED_DOMAINS:
        return True
    return any(host.endswith("." + d) for d in ALLOWLISTED_DOMAINS)


def content_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class KnowledgeRecord:
    source_id: str
    source_name: str
    authority: str
    industry: str
    jurisdiction: str
    topic: str
    document_type: str
    legal_status: str
    source_url: str
    source_version: str
    effective_date: str | None
    published_date: str | None
    last_checked: str
    next_review: str
    licence_status: str
    permitted_use: str
    attribution: str
    content_hash: str
    supersedes: str | None
    superseded_by: str | None
    active: bool
    risk_classification: str
    stale: bool = False
    review_required: bool = False
    sections: list[dict[str, str]] = field(default_factory=list)
    body_ingested: bool = False
    ingestion_method: str = "allowlisted_fetch_html_normalise"
    audit: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IndustryKnowledgePack:
    pack_id: str
    industry: str
    jurisdiction: str
    name: str
    version: str
    active_sources: list[str]
    topics: list[str]
    last_updated: str
    review_status: str
    professional_review_rules: list[str]
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProvenanceAnswer:
    text: str
    confidence: str
    professional_review_required: bool
    pack_id: str
    jurisdiction: str
    sources: list[dict[str, Any]]
    provenance_sentence: str
    flags: list[str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_legal_status(status: str) -> str:
    key = (status or "").strip().upper()
    if key not in LEGAL_STATUSES:
        raise KnowledgeVaultError(f"unknown legal_status: {status}")
    return key


def check_rights(source: dict[str, Any], ingest_body: bool) -> None:
    licence = source.get("licence_status") or ""
    method = source.get("ingestion_method") or ""
    use = (source.get("permitted_use") or "").lower()
    host = _host(source.get("source_url") or "")
    if ingest_body and (method == "metadata_only" or host in METADATA_ONLY_DOMAINS):
        raise RightsDenied(f"licence denies body ingest for {source.get('source_id')}")
    if ingest_body and any(licence.startswith(m) or m.lower() in licence.lower() for m in FETCH_DENIED_LICENCES):
        raise RightsDenied(f"restricted licence for {source.get('source_id')}")
    if ingest_body and any(m in use for m in RESTRICTED_LICENCE_MARKERS):
        raise RightsDenied(f"permitted_use denies body ingest for {source.get('source_id')}")


def _default_fetcher(url: str) -> str:
    raise KnowledgeVaultError("Stage 1 fetcher is injected; uncontrolled crawl is forbidden")


class KnowledgeVault:
    """In-memory Stage 1 vault. No production activation."""

    def __init__(self, fetcher: Callable[[str], str] | None = None) -> None:
        self.fetcher = fetcher or _default_fetcher
        self.records: dict[str, KnowledgeRecord] = {}
        self.packs: dict[str, IndustryKnowledgePack] = {}
        self.audit: list[str] = []
        self.production_enabled = False
        self.external_execution_enabled = False

    def log(self, event: str) -> None:
        self.audit.append(f"{_iso(_now())} {event}")

    def discover(self, url: str) -> None:
        if not domain_allowed(url):
            raise SourceRejected(f"unofficial domain rejected: {url}")

    def validate_source(self, source: dict[str, Any]) -> dict[str, Any]:
        url = source.get("source_url") or ""
        self.discover(url)
        status = validate_legal_status(str(source.get("legal_status") or "OTHER"))
        if not source.get("jurisdiction"):
            raise SourceRejected("jurisdiction required")
        if not source.get("source_id"):
            raise SourceRejected("source_id required")
        out = dict(source)
        out["legal_status"] = status
        return out

    def ingest(
        self,
        source: dict[str, Any],
        *,
        body: str | None = None,
        ingest_body: bool = False,
        last_checked: datetime | None = None,
        review_days: int = 30,
        stale: bool = False,
    ) -> KnowledgeRecord:
        self.log(f"DISCOVER {source.get('source_id')}")
        src = self.validate_source(source)
        self.log(f"VALIDATE_SOURCE {src['source_id']}")
        check_rights(src, ingest_body)
        self.log(f"CHECK_RIGHTS {src['source_id']}")
        raw = ""
        sections: list[dict[str, str]] = []
        body_ingested = False
        if ingest_body:
            raw = body if body is not None else self.fetcher(src["source_url"])
            self.log(f"FETCH {src['source_id']}")
            raw = _normalise(raw)
            sections = _split_sections(raw)
            body_ingested = True
            self.log(f"NORMALISE_SPLIT {src['source_id']}")
        else:
            raw = "|".join(
                [
                    src["source_id"],
                    src["source_url"],
                    src.get("source_version") or "",
                    src.get("licence_status") or "",
                ]
            )
        digest = content_hash(raw)
        checked = last_checked or _now()
        superseded = bool(src.get("superseded_by"))
        review_required = stale or superseded or not src.get("active", True)
        record = KnowledgeRecord(
            source_id=src["source_id"],
            source_name=src["source_name"],
            authority=src["authority"],
            industry=src["industry"],
            jurisdiction=src["jurisdiction"],
            topic=src["topic"],
            document_type=src["document_type"],
            legal_status=src["legal_status"],
            source_url=src["source_url"],
            source_version=str(src.get("source_version") or "unknown"),
            effective_date=src.get("effective_date"),
            published_date=src.get("published_date"),
            last_checked=_iso(checked) or "",
            next_review=_iso(checked + timedelta(days=review_days)) or "",
            licence_status=src["licence_status"],
            permitted_use=src["permitted_use"],
            attribution=src["attribution"],
            content_hash=digest,
            supersedes=src.get("supersedes"),
            superseded_by=src.get("superseded_by"),
            active=bool(src.get("active", True)) and not superseded,
            risk_classification=src.get("risk_classification") or "advisory",
            stale=stale,
            review_required=review_required,
            sections=sections,
            body_ingested=body_ingested,
            ingestion_method=src.get("ingestion_method") or "metadata_only",
            audit=list(self.audit[-8:]),
        )
        if stale:
            record.stale = True
            record.review_required = True
        if superseded:
            record.active = False
            record.review_required = True
        self.records[record.source_id] = record
        self.log(f"HASH_VERSION_INDEX_AUDIT {record.source_id} {record.content_hash[:12]}")
        return record

    def load_catalog(self, ingest_bodies: bool = False) -> None:
        for spec in OFFICIAL_SOURCES:
            self.ingest(spec, ingest_body=False)
        now = _iso(_now()) or ""
        for pack_spec in INDUSTRY_PACK_SPECS:
            self.packs[pack_spec["pack_id"]] = IndustryKnowledgePack(
                pack_id=pack_spec["pack_id"],
                industry=pack_spec["industry"],
                jurisdiction=pack_spec["jurisdiction"],
                name=pack_spec["name"],
                version=pack_spec["version"],
                active_sources=list(pack_spec["source_ids"]),
                topics=list(pack_spec["topics"]),
                last_updated=now,
                review_status="STAGE1_CATALOG",
                professional_review_rules=list(pack_spec["professional_review_rules"]),
                notes=pack_spec.get("notes") or "",
            )
        if ingest_bodies:
            raise KnowledgeVaultError("bulk body ingest is disabled in Stage 1")

    def route_client(self, business_type: str) -> IndustryKnowledgePack:
        key = re.sub(r"[\s-]+", "_", (business_type or "").strip().lower())
        pack_id = CLIENT_ROUTES.get(key)
        if not pack_id or pack_id not in self.packs:
            raise KnowledgeVaultError(f"no industry pack for business type: {business_type}")
        return self.packs[pack_id]

    def sources_for_pack(self, pack_id: str) -> list[KnowledgeRecord]:
        pack = self.packs[pack_id]
        return [self.records[sid] for sid in pack.active_sources if sid in self.records]

    def answer(
        self,
        *,
        business_type: str,
        query: str,
        jurisdiction: str | None = None,
        professional_decision: bool = False,
    ) -> ProvenanceAnswer:
        pack = self.route_client(business_type)
        if jurisdiction and _norm_j(jurisdiction) != _norm_j(pack.jurisdiction):
            flags_mismatch = [
                f"requested jurisdiction {jurisdiction} is not the pack jurisdiction {pack.jurisdiction}",
            ]
        else:
            flags_mismatch = []
        pack_sources = self.sources_for_pack(pack.pack_id)
        candidates = [rec for rec in pack_sources if _query_matches(query, rec)]
        industry_hits = [rec for rec in candidates if rec.industry == pack.industry]
        if industry_hits:
            candidates = industry_hits + [rec for rec in candidates if rec.industry != pack.industry]
        no_match = not candidates
        if no_match:
            flags_mismatch.append("NO_RELEVANT_SOURCE_MATCH")

        for rec in candidates:
            if rec.industry not in {pack.industry, "cross"}:
                raise KnowledgeVaultError("cross-pack contamination blocked")

        usable = [r for r in candidates if r.active and not r.stale and not r.superseded_by]
        stale_hits = [r for r in candidates if r.stale or r.superseded_by or not r.active]

        review_rules = pack.professional_review_rules
        high_risk = any(r.risk_classification in {"high", "critical"} for r in candidates)
        if professional_decision or high_risk and _decisionish(query):
            confidence = CONFIDENCE_RED
            review = True
        elif not usable and stale_hits:
            confidence = CONFIDENCE_AMBER
            review = True
        elif usable and not stale_hits and not flags_mismatch:
            confidence = CONFIDENCE_AMBER if any(not r.body_ingested for r in usable) else CONFIDENCE_GREEN
            review = any("requires" in rule.lower() for rule in review_rules) and _decisionish(query)
            if review:
                confidence = CONFIDENCE_RED
        else:
            confidence = CONFIDENCE_AMBER
            review = True

        shown = usable or stale_hits or candidates
        flags = list(flags_mismatch)
        if no_match:
            if not professional_decision:
                confidence = CONFIDENCE_AMBER
            review = True
            provenance = (
                f"No approved source in pack {pack.pack_id} matched this query. "
                f"The pack applies to {pack.jurisdiction}. Treat as advisory only."
            )
            text = f"{provenance} Confidence: {confidence}."
        else:
            primary = shown[0]
            if primary.stale or not primary.active:
                flags.append("STALE" if primary.stale else "REVIEW_REQUIRED")
            if primary.superseded_by:
                flags.append("SUPERSEDED")
                flags.append("REVIEW_REQUIRED")
            provenance = (
                f"This answer is based on {primary.authority} — {primary.source_name}, "
                f"applies to {primary.jurisdiction}, and was last verified on {primary.last_checked}."
            )
            text = (
                f"{provenance} "
                f"Confidence: {confidence}. "
                f"Source URL: {primary.source_url}. "
                f"Legal status: {primary.legal_status}. "
                f"Version: {primary.source_version}."
            )
        if review:
            flags.append("PROFESSIONAL_REVIEW_REQUIRED")
        flags.extend(STAGE_DISCLAIMERS)
        if review:
            text += " A qualified human/professional decision is required before acting."
        return ProvenanceAnswer(
            text=text,
            confidence=confidence,
            professional_review_required=review,
            pack_id=pack.pack_id,
            jurisdiction=pack.jurisdiction,
            sources=[
                {
                    "authority": r.authority,
                    "title": r.source_name,
                    "jurisdiction": r.jurisdiction,
                    "version": r.source_version,
                    "effective_date": r.effective_date,
                    "url": r.source_url,
                    "legal_status": r.legal_status,
                    "stale": r.stale,
                    "active": r.active,
                }
                for r in shown
            ],
            provenance_sentence=provenance,
            flags=flags,
        )

    def mark_stale(self, source_id: str) -> None:
        rec = self.records[source_id]
        rec.stale = True
        rec.review_required = True

    def assert_execution_boundary(self) -> None:
        if self.production_enabled or self.external_execution_enabled:
            raise KnowledgeVaultError("production/external execution is forbidden in Stage 1")


def _normalise(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _split_sections(text: str) -> list[dict[str, str]]:
    if not text:
        return []
    chunks = re.split(r"(?<=[.!?])\s+", text)
    return [{"heading": f"section-{i+1}", "text": chunk} for i, chunk in enumerate(chunks) if chunk]


def _norm_j(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


GENERIC_QUERY_TOKENS = frozenset(
    {
        "guidance",
        "rules",
        "regulations",
        "standards",
        "document",
        "documents",
        "official",
        "information",
        "policy",
        "policies",
        "requirements",
        "requirement",
        "law",
        "legal",
        "government",
        "service",
        "services",
        "professional",
        "work",
        "working",
        "about",
        "from",
        "with",
        "into",
        "for",
        "the",
        "and",
        "duties",
        "duty",
        "responsibilities",
        "responsibility",
    }
)

SPECIFIC_SHORT_TOKENS = frozenset(
    {
        "cdm",
        "sra",
        "hmo",
        "hse",
        "aqa",
        "ocr",
    }
)


def _token_in(token: str, text: str) -> bool:
    if token in text:
        return True
    if token.endswith("s") and len(token) > 4 and token[:-1] in text:
        return True
    return False


def _query_tokens(query: str) -> tuple[list[str], list[str]]:
    raw = [t for t in re.split(r"\W+", query.lower()) if t]
    specific: list[str] = []
    generic: list[str] = []
    for token in raw:
        if token in GENERIC_QUERY_TOKENS:
            generic.append(token)
            continue
        if token in SPECIFIC_SHORT_TOKENS or len(token) >= 4:
            specific.append(token)
    return specific, generic


def _query_matches(query: str, rec: KnowledgeRecord) -> bool:
    topic = f"{rec.topic} {rec.topic.replace('_', ' ')} {rec.source_name}".lower()
    fields = [
        rec.topic,
        rec.topic.replace("_", " "),
        rec.source_name,
        rec.document_type,
        rec.legal_status,
        rec.authority,
        rec.jurisdiction,
    ]
    if rec.body_ingested:
        fields.extend(section.get("text", "") for section in rec.sections)
    blob = " ".join(fields).lower()
    specific, generic = _query_tokens(query)
    if not specific:
        return False
    if any(_token_in(t, topic) for t in specific):
        return True
    specific_hits = [t for t in specific if _token_in(t, blob)]
    if len(specific_hits) >= 2:
        return True
    if specific_hits and any(_token_in(t, blob) for t in generic):
        return True
    return False


def _decisionish(query: str) -> bool:
    q = query.lower()
    return any(
        w in q
        for w in (
            "should we",
            "must we",
            "serve notice",
            "dismiss",
            "litigate",
            "sign off",
            "approve works",
            "remove asbestos",
            "evict",
            "issue proceedings",
        )
    )


def build_stage1_vault(fetcher: Callable[[str], str] | None = None) -> KnowledgeVault:
    vault = KnowledgeVault(fetcher=fetcher)
    vault.load_catalog()
    vault.assert_execution_boundary()
    return vault
