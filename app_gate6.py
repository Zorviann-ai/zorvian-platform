"""Gate 6 production-readiness layer.

Extends the proven Gate 5 application without weakening its controls.
"""
import hmac
import os

from fastapi import Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app_gate5 import app
from app import current_user, db, now, require
from deployment.readiness import readiness_report
from intelligence.context import WorkspaceContext
from intelligence.executor import execute_provider
from intelligence.guard import guardian_check


class AdapterRequest(BaseModel):
    provider: str = Field(min_length=2, max_length=80)
    model: str = Field(default="", max_length=120)
    prompt: str = Field(min_length=1, max_length=12000)
    context: dict


@app.post("/internal/ai-adapter")
def first_party_ai_adapter(payload: AdapterRequest, authorization: str | None = Header(None)):
    """Protected first-party adapter boundary.

    The adapter key stays server-side. Gate 6 initially executes the controlled
    Zorvian engine behind this boundary; later provider implementations can be
    swapped behind the same contract without changing browser clients.
    """
    expected = os.getenv("ZORVIAN_AI_ADAPTER_KEY", "").strip()
    supplied = authorization.removeprefix("Bearer ").strip() if authorization else ""
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise HTTPException(401, "Invalid adapter credentials")

    context = payload.context
    required = ("tenant_id", "user_id", "role", "module")
    if any(not str(context.get(name, "")).strip() for name in required):
        raise HTTPException(422, "Complete tenant, user, role and module context required")

    try:
        ctx = WorkspaceContext(
            tenant_id=str(context["tenant_id"]),
            user_id=str(context["user_id"]),
            role=str(context["role"]),
            module=str(context["module"]),
            instructions=("First-party Gate 6 adapter; no external action permitted.",),
        )
        ctx.validate()
        safe_prompt = guardian_check(payload.prompt)
        result = execute_provider("zorvian-local-beta", safe_prompt, ctx)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(422, "Invalid adapter request context") from exc

    result["provider"] = "zorvian-first-party-adapter"
    result["source_refs"] = tuple(result.get("source_refs", ())) + ("zorvian://gate6/first-party-adapter",)
    result["assumptions"] = tuple(result.get("assumptions", ())) + (
        "First-party controlled engine used; consequential external actions remain approval-gated.",
    )
    return result


@app.get("/readiness")
def readiness(u=Depends(current_user)):
    require(u, "admin")
    return readiness_report()


@app.post("/pilot/evidence")
def pilot_evidence(u=Depends(current_user)):
    require(u, "admin")
    report = readiness_report()
    if not report["ready"]:
        raise HTTPException(503, {"message": "Gate 6 environment is not production-ready", "checks": report["checks"]})
    c = db()
    counts = {
        "tenants": c.execute("SELECT COUNT(*) FROM tenants").fetchone()[0],
        "users": c.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "audit_events": c.execute("SELECT COUNT(*) FROM audit").fetchone()[0],
        "security_events": c.execute("SELECT COUNT(*) FROM security_events").fetchone()[0],
    }
    c.close()
    return {
        "gate": 6,
        "status": "environment_ready_for_controlled_pilot",
        "generated_at": now(),
        "tenant_id": u["tenant_id"],
        "guardian": "active",
        "external_actions": "approval-gated",
        "counts": counts,
        "readiness": report,
    }
