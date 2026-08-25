"""Gate 5 Core-connected API layer.

Extends the existing Zorvian FastAPI app without changing the proven Gate 2-4 core.
"""
import os

from fastapi import Depends, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import app, audit, current_user, rate_limit, require, request_fingerprint
from intelligence.connected import ConnectedIntelligenceService, ConnectedRequest, SUPPORTED_MODULES
from intelligence.context import WorkspaceContext
from intelligence.executor import execute_provider
from intelligence.guard import guardian_check
from intelligence.providers import ProviderProfile, ProviderRegistry


_ALL_CAPABILITIES = frozenset({
    "communications", "executive-operations", "scheduling", "automotive",
    "fresh-produce", "contracts-tenders", "growth", "marketing-content",
    "sales-commercial", "operations", "analytics", "documents",
    "document-assurance", "mobility", "automation-safety", "media-production",
    "legal-workflow", "finance-workflow", "security-analysis",
})


def _registry():
    profiles = []
    if os.getenv("OPENAI_API_KEY"):
        profiles.append(ProviderProfile("openai", _ALL_CAPABILITIES, True, True, True, 10, 20, True))
    if os.getenv("ANTHROPIC_API_KEY"):
        profiles.append(ProviderProfile("anthropic", _ALL_CAPABILITIES, True, True, True, 12, 22, True))
    if os.getenv("ZORVIAN_AI_ADAPTER_URL") and os.getenv("ZORVIAN_AI_ADAPTER_KEY"):
        profiles.append(ProviderProfile("zorvian-remote", _ALL_CAPABILITIES, True, True, True, 15, 25, True))
    if os.getenv("ALLOW_LOCAL_BETA", "1") == "1":
        profiles.append(ProviderProfile("zorvian-local-beta", _ALL_CAPABILITIES, True, True, True, 90, 1, True))
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


@app.middleware("http")
async def gate5_beta_csp(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/beta"):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'"
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/intelligence/capabilities")
def intelligence_capabilities(u=Depends(current_user)):
    configured = []
    if os.getenv("OPENAI_API_KEY"): configured.append("openai")
    if os.getenv("ANTHROPIC_API_KEY"): configured.append("anthropic")
    if os.getenv("ZORVIAN_AI_ADAPTER_URL") and os.getenv("ZORVIAN_AI_ADAPTER_KEY"): configured.append("private-adapter")
    return {
        "modules": sorted(SUPPORTED_MODULES),
        "guardian": "active",
        "provider_mode": "connected" if configured else "controlled-local-beta",
        "configured_provider_count": len(configured),
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


# Served from the same origin as Core so beta clients can authenticate without
# weakening CORS or exposing provider credentials in downloadable HTML files.
if os.path.isdir("beta"):
    app.mount("/beta", StaticFiles(directory="beta", html=True), name="beta")
