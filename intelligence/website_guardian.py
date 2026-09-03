from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable
from urllib.parse import urlparse


class GuardianMode(str, Enum):
    MONITOR = "monitor"
    MANAGED = "managed"
    AUTONOMOUS = "autonomous"


class FindingSeverity(str, Enum):
    INFO = "info"
    ATTENTION = "attention"
    ACTION_REQUIRED = "action_required"
    CRITICAL = "critical"


@dataclass(frozen=True)
class WebsiteClient:
    client_id: str
    name: str
    subscription_active: bool


@dataclass(frozen=True)
class ManagedWebsite:
    website_id: str
    client_id: str
    base_url: str
    mode: GuardianMode = GuardianMode.MONITOR
    approved_domains: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an absolute http(s) URL")

    @property
    def hostname(self) -> str:
        return (urlparse(self.base_url).hostname or "").lower()

    def domain_allowed(self, hostname: str) -> bool:
        host = hostname.lower().strip(".")
        allowed = {self.hostname, *(d.lower().strip(".") for d in self.approved_domains)}
        return host in allowed


@dataclass(frozen=True)
class WebsiteFinding:
    website_id: str
    url: str
    issue: str
    severity: FindingSeverity
    evidence: str
    recommendation: str
    auto_fix_eligible: bool = False


@dataclass(frozen=True)
class ScanReport:
    website_id: str
    created_at: datetime
    findings: tuple[WebsiteFinding, ...]
    scanned_urls: tuple[str, ...]
    external_changes_made: bool = False

    @property
    def health(self) -> str:
        severities = {f.severity for f in self.findings}
        if FindingSeverity.CRITICAL in severities:
            return "CRITICAL"
        if FindingSeverity.ACTION_REQUIRED in severities:
            return "ACTION REQUIRED"
        if FindingSeverity.ATTENTION in severities:
            return "ATTENTION"
        return "HEALTHY"


@dataclass(frozen=True)
class ProposedWebsiteAction:
    website_id: str
    action_type: str
    target_url: str
    summary: str
    requires_human_approval: bool = True
    executable: bool = False


class WebsiteGuardian:
    """Read/diagnose/propose foundation. Stage 1 never changes a website."""

    def __init__(self, clients: Iterable[WebsiteClient], websites: Iterable[ManagedWebsite]):
        self.clients = {c.client_id: c for c in clients}
        self.websites = {w.website_id: w for w in websites}

    def get_website(self, website_id: str) -> ManagedWebsite:
        website = self.websites[website_id]
        client = self.clients[website.client_id]
        if not client.subscription_active:
            raise PermissionError("Website Guardian subscription is not active")
        return website

    def validate_scan_urls(self, website_id: str, urls: Iterable[str]) -> tuple[str, ...]:
        website = self.get_website(website_id)
        approved: list[str] = []
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"invalid scan URL: {url}")
            if not website.domain_allowed(parsed.hostname):
                raise PermissionError(f"domain is not approved for Website Guardian: {parsed.hostname}")
            approved.append(url)
        return tuple(approved)

    def make_report(self, website_id: str, urls: Iterable[str], findings: Iterable[WebsiteFinding]) -> ScanReport:
        approved_urls = self.validate_scan_urls(website_id, urls)
        findings_tuple = tuple(findings)
        for finding in findings_tuple:
            if finding.website_id != website_id:
                raise ValueError("finding belongs to another website")
            parsed = urlparse(finding.url)
            if not parsed.hostname or not self.websites[website_id].domain_allowed(parsed.hostname):
                raise PermissionError("finding URL is outside the approved website boundary")
        return ScanReport(
            website_id=website_id,
            created_at=datetime.now(timezone.utc),
            findings=findings_tuple,
            scanned_urls=approved_urls,
            external_changes_made=False,
        )

    def propose_fix(self, finding: WebsiteFinding) -> ProposedWebsiteAction:
        self.get_website(finding.website_id)
        return ProposedWebsiteAction(
            website_id=finding.website_id,
            action_type="proposed_fix",
            target_url=finding.url,
            summary=finding.recommendation,
            requires_human_approval=True,
            executable=False,
        )

    def publish(self, *_args, **_kwargs):
        raise PermissionError("Website Guardian Stage 1 cannot publish or modify external websites")
