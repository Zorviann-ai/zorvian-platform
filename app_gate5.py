"""Gate 5 Core-connected API layer.

Extends the existing Zorvian FastAPI app without changing the proven Gate 2-4 core.
"""
import os
from typing import Optional

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import app, audit, current_user, rate_limit, require, request_fingerprint
from intelligence.connected import ConnectedIntelligenceService, ConnectedRequest, SUPPORTED_MODULES
from intelligence.context import WorkspaceContext
from intelligence.executor import execute_provider
from intelligence.guard import guardian_check
from intelligence.providers import ProviderProfile, ProviderRegistry


_ALL_CAPABILITIES = frozenset({"communications", "automotive", "fresh-produce", "contracts-tenders", "growth", "documents", "operations", "mobility"})


def _registry():
    profiles = [
        ProviderProfile("zorvian-local-beta", _ALL_CAPABILITIES, True, True, False, 40, 5, True),
    ]
    if os.getenv("ZORVIAN_AI_ADAPTER_URL") and os.getenv("ZORVIAN_AI_ADAPTER_KEY"):
        profiles.insert(0, ProviderProfile("zorvian-remote", _ALL_CAPABILITIES, True, True, True, 10, 20, True))
    return ProviderRegistry(profiles)


def _service():
    return ConnectedIntelligenceService(_registry(), execute_provider)


class IntelligenceRunIn(BaseModel):
    module: str = Field(min_length=2, max_length=50)
    task: str = Field(min_length=2, max_length=120)
    prompt: str = Field(min_length=1, max_length=12000)
    needs_retrieval: bool = False
    needs_tools: bool = False
    consequential_action: bool = False


@app.get("/intelligence/capabilities")
def intelligence_capabilities(u=Depends(current_user)):
    return {
        "modules": sorted(SUPPORTED_MODULES),
        "guardian": "active",
        "provider_mode": "remote" if os.getenv("ZORVIAN_AI_ADAPTER_URL") and os.getenv("ZORVIAN_AI_ADAPTER_KEY") else "controlled-local-beta",
        "external_actions": "approval-gated",
    }


@app.post("/intelligence/run")
def intelligence_run(d: IntelligenceRunIn, request: Request, u=Depends(current_user)):
    require(u, "write")
    ip, _ = request_fingerprint(request)
    rate_limit("intelligence:" + u["tenant_id"] + ":" + str(ip), 60, 3600)
    try:
        prompt = guardian_check(d.prompt)
        ctx = WorkspaceContext(
            tenant_id=u["tenant_id"],
            user_id=u["id"],
            role=u["role"],
            module=d.module,
            instructions=("Operate only inside this authenticated Zorvian workspace and module.",),
        )
        result = _service().run(ConnectedRequest(
            module=d.module,
            task=d.task,
            prompt=prompt,
            needs_retrieval=d.needs_retrieval,
            needs_tools=d.needs_tools,
            consequential_action=d.consequential_action,
        ), ctx)
    except PermissionError as e:
        audit(u, "guardian_intelligence_block", str(e), "warning")
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    except LookupError as e:
        audit(u, "intelligence_provider_unavailable", str(e), "warning")
        raise HTTPException(503, str(e))
    except RuntimeError as e:
        audit(u, "intelligence_execution_failed", str(e), "warning")
        raise HTTPException(502, "Intelligence provider failed safely")

    audit(u, "intelligence_run", f"{d.module} · {d.task} · provider={result.provider}")
    return {
        "module": result.module,
        "capability": result.capability,
        "output": result.output,
        "confidence": result.confidence,
        "provider": result.provider,
        "human_approval_required": result.human_approval_required,
        "tool_execution_allowed": result.tool_execution_allowed,
        "provenance": {
            "task_id": result.provenance.task_id,
            "source_refs": list(result.provenance.source_refs),
            "assumptions": list(result.provenance.assumptions),
            "needs_review": result.provenance.needs_review,
        },
    }
