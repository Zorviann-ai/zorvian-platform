"""Core-connected intelligence service primitives.

This module is framework-neutral so FastAPI routes can call it without placing
provider secrets or routing policy in the browser layer.
"""
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from .context import WorkspaceContext
from .provenance import ProvenanceRecord
from .providers import ModelRequirements, ProviderRegistry
from .router import IntelligenceRequest, route


SUPPORTED_MODULES = {
    "receptionist", "executive-assistant", "calendar-bookings", "reservations",
    "zai-auto", "freshx", "tenders", "lead-intelligence", "social-ai",
    "marketing", "sales-quotes", "customer-support", "tasks-workflow",
    "business-intelligence", "document-studio", "document-proof",
    "business-control", "route-intelligence", "freight-control", "robotics",
    "video-ai", "legal-pathways", "finance-pathways", "mailbox-communications",
    "guardian-security",
}


@dataclass(frozen=True)
class ConnectedRequest:
    module: str
    task: str
    prompt: str
    needs_retrieval: bool = False
    needs_tools: bool = False
    consequential_action: bool = False


@dataclass(frozen=True)
class ConnectedResponse:
    module: str
    capability: str
    output: str
    confidence: float
    provider: str
    human_approval_required: bool
    tool_execution_allowed: bool
    provenance: ProvenanceRecord


class ConnectedIntelligenceService:
    def __init__(self, registry: ProviderRegistry, executor: Callable[[str, str, WorkspaceContext], Mapping]):
        self.registry = registry
        self.executor = executor

    def run(self, req: ConnectedRequest, ctx: WorkspaceContext) -> ConnectedResponse:
        ctx.validate()
        if req.module not in SUPPORTED_MODULES:
            raise ValueError("Unsupported Zorvian intelligence module")
        if req.module != ctx.module:
            raise PermissionError("Module context mismatch")

        decision = route(IntelligenceRequest(
            module=req.module,
            task=req.task,
            needs_retrieval=req.needs_retrieval,
            needs_tools=req.needs_tools,
            consequential_action=req.consequential_action,
            requested_by_role=ctx.role,
        ))

        requirements = ModelRequirements(
            capability=decision.capability,
            needs_tools=req.needs_tools,
            needs_retrieval=req.needs_retrieval,
            high_risk=decision.risk.value == "high",
        )
        failures = []
        result = None
        provider = None
        for candidate in self.registry.eligible(requirements):
            try:
                result = self.executor(candidate.name, req.prompt, ctx)
                provider = candidate
                break
            except RuntimeError:
                failures.append(candidate.name)
        if result is None or provider is None:
            raise RuntimeError("All approved intelligence providers failed safely: " + ", ".join(failures))
        text = str(result.get("output", "")).strip()
        if not text:
            raise RuntimeError("Provider returned no usable output")
        confidence = float(result.get("confidence", 0.0))
        sources = tuple(str(x) for x in result.get("source_refs", ()))
        assumptions = tuple(str(x) for x in result.get("assumptions", ()))
        provenance = ProvenanceRecord(
            module=req.module,
            task_id=str(result.get("task_id", "untracked")),
            source_refs=sources,
            assumptions=assumptions,
            confidence=confidence,
        ).validate()

        return ConnectedResponse(
            module=req.module,
            capability=decision.capability,
            output=text,
            confidence=confidence,
            provider=provider.name,
            human_approval_required=decision.human_approval_required,
            tool_execution_allowed=decision.tool_execution_allowed,
            provenance=provenance,
        )
