"""Zorvian Gate 3 intelligence routing foundation.

Provider-neutral by design: business policy selects a capability class; provider
adapters can be added without putting provider-specific logic into business modules.
"""
from dataclasses import dataclass
from enum import Enum


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class IntelligenceRequest:
    module: str
    task: str
    needs_retrieval: bool = False
    needs_tools: bool = False
    consequential_action: bool = False
    requested_by_role: str = "viewer"


@dataclass(frozen=True)
class RouteDecision:
    capability: str
    risk: Risk
    human_approval_required: bool
    provenance_required: bool
    tool_execution_allowed: bool


APPROVER_ROLES = {"owner", "admin", "principal"}
SPECIALISTS = {
    "receptionist": "communications",
    "zai-auto": "automotive",
    "freshx": "fresh-produce",
    "tenders": "contracts-tenders",
    "lead-intelligence": "growth",
    "document-studio": "documents",
    "business-control": "operations",
    "route-intelligence": "mobility",
}


def route(req: IntelligenceRequest) -> RouteDecision:
    capability = SPECIALISTS.get(req.module, "general-business")
    risk = Risk.HIGH if req.consequential_action else (Risk.MEDIUM if req.needs_tools else Risk.LOW)
    approval = req.consequential_action or (req.needs_tools and req.requested_by_role not in APPROVER_ROLES)
    return RouteDecision(
        capability=capability,
        risk=risk,
        human_approval_required=approval,
        provenance_required=req.needs_retrieval or risk != Risk.LOW,
        tool_execution_allowed=req.needs_tools and not approval,
    )
