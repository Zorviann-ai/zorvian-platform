"""Gate 12 - Autonomous Core + authenticated provider mesh.

This layer extends the working CRM. It never accepts tenant identity from the
browser: all autonomy and provider actions inherit the current authenticated
Zorvian workspace.
"""
import json
import uuid
from typing import Any

import httpx
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app_gate11 import app
from app import audit, current_user, db, now, rate_limit, request_fingerprint, require
from app_gate5 import _service, _configured_remote_providers
from intelligence.autonomy import ensure_tables as ensure_autonomy_tables, get_policy, update_policy, snapshot, create_safe_followups
from intelligence.connected import ConnectedRequest
from intelligence.context import WorkspaceContext
from intelligence.resilience import status_snapshot
from provider_mesh import PROVIDERS, approve as provider_approve, approval_ok, call_provider, ensure_tables as ensure_provider_tables, needs_approval, provider_status, request_approval


class AutonomyPolicyIn(BaseModel):
    mode: str = Field(default="supervised", pattern="^(observe|supervised|active)$")
    auto_create_followup_tasks: bool = True
    max_actions_per_run: int = Field(default=12, ge=1, le=50)
    external_actions_require_approval: bool = True


class AutonomyRunIn(BaseModel):
    trigger: str = Field(default="manual", min_length=2, max_length=80)
    objective: str = Field(default="Review the CRM and prioritise the most useful next work.", min_length=3, max_length=2000)


class ProviderActionIn(BaseModel):
    service: str
    operation: str
    payload: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None


class ProviderApprovalIn(BaseModel):
    service: str
    operation: str
    payload: dict[str, Any] = Field(default_factory=dict)


def _initialise_gate12():
    c = db()
    ensure_autonomy_tables(c)
    ensure_provider_tables(c)
    c.close()


_initialise_gate12()


@app.get("/core/autonomy/status")
def autonomy_status(u=Depends(current_user)):
    c = db()
    policy = get_policy(c, u["tenant_id"])
    snap = snapshot(c, u["tenant_id"]).as_dict()
    latest = c.execute("SELECT id,mode,trigger,summary,actions_count,created_at FROM autonomy_runs WHERE tenant_id=? ORDER BY created_at DESC LIMIT 1", (u["tenant_id"],)).fetchone()
    c.close()
    return {"core": "Zorvian", "autonomy": policy, "snapshot": snap, "last_run": dict(latest) if latest else None, "provider_mesh": provider_status()}


@app.patch("/core/autonomy/settings")
def autonomy_settings(body: AutonomyPolicyIn, u=Depends(current_user)):
    require(u, "admin")
    c = db()
    policy = update_policy(c, u["tenant_id"], mode=body.mode, auto_create_followup_tasks=body.auto_create_followup_tasks, max_actions_per_run=body.max_actions_per_run, external_actions_require_approval=body.external_actions_require_approval)
    c.close()
    audit(u, "autonomy_policy_updated", json.dumps(policy))
    return policy


@app.post("/core/autonomy/run")
def autonomy_run(body: AutonomyRunIn, request: Request, u=Depends(current_user)):
    require(u, "write")
    ip, _ = request_fingerprint(request)
    rate_limit("autonomy:" + u["tenant_id"] + ":" + str(ip), 30, 3600)
    c = db()
    policy = get_policy(c, u["tenant_id"])
    before = snapshot(c, u["tenant_id"])
    run_id = str(uuid.uuid4())
    c.execute("INSERT INTO autonomy_runs VALUES (?,?,?,?,?,?,?,?,?)", (run_id, u["tenant_id"], u["id"], policy["mode"], body.trigger, json.dumps(before.as_dict()), "", 0, now()))
    c.commit()

    actions = []
    try:
        if policy["mode"] != "observe" and policy["auto_create_followup_tasks"]:
            actions = create_safe_followups(c, u["tenant_id"], run_id, policy["max_actions_per_run"])
    except Exception:
        c.rollback()
        c.close()
        audit(u, "autonomy_run_failed", f"run={run_id}; internal action transaction rolled back", "warning")
        raise

    after = snapshot(c, u["tenant_id"])
    prompt = (
        "You are the Zorvian Core business-control layer. Assess this authenticated workspace only. "
        "Prioritise practical next steps, identify risk or neglected work, and do not claim external actions were taken. "
        f"Owner objective: {body.objective}\n"
        f"CRM before: {json.dumps(before.as_dict())}\nCRM after safe housekeeping: {json.dumps(after.as_dict())}\n"
        f"Autonomous internal actions completed: {json.dumps(actions)}"
    )
    try:
        ctx = WorkspaceContext(tenant_id=u["tenant_id"], user_id=u["id"], role=u["role"], module="business-control", instructions=("Operate only inside this authenticated Zorvian workspace.",))
        result = _service().run(ConnectedRequest(module="business-control", task="autonomous CRM control review", prompt=prompt, needs_retrieval=False, needs_tools=False, consequential_action=False), ctx)
    except LookupError as exc:
        failure = "Core AI unavailable: no approved real AI provider is configured or available."
        c.execute("UPDATE autonomy_runs SET summary=?,actions_count=? WHERE id=?", (failure, len(actions), run_id))
        c.commit(); c.close()
        audit(u, "autonomy_ai_unavailable", f"run={run_id}; {exc}", "warning")
        raise HTTPException(503, {"error":"ai_provider_unavailable","message":"Celestial Core intelligence is temporarily unavailable. Please try again shortly.","run_id":run_id,"actions":actions,"ai_complete":False})
    except (RuntimeError, ValueError, PermissionError) as exc:
        failure = "Core AI provider failed; the run was not reported as AI-complete."
        c.execute("UPDATE autonomy_runs SET summary=?,actions_count=? WHERE id=?", (failure, len(actions), run_id))
        c.commit(); c.close()
        audit(u, "autonomy_ai_failed", f"run={run_id}; {exc}", "warning")
        raise HTTPException(502, {"error":"ai_provider_failed","message":"Celestial Core could not complete this intelligence request. Please try again shortly.","run_id":run_id,"actions":actions,"ai_complete":False})

    assessment = result.output
    provider = result.provider
    approval_required = result.human_approval_required
    c.execute("UPDATE autonomy_runs SET summary=?,actions_count=? WHERE id=?", (assessment[:12000], len(actions), run_id))
    c.commit(); c.close()
    if result.failover_from:
        audit(u, "ai_provider_failover", f"run={run_id}; {result.failover_from} -> {provider}")
    audit(u, "autonomy_run", f"run={run_id}; mode={policy['mode']}; actions={len(actions)}; provider={provider}")
    return {"run_id": run_id, "mode": policy["mode"], "before": before.as_dict(), "after": after.as_dict(), "actions": actions, "assessment": assessment, "provider": provider, "failover_from": result.failover_from, "human_approval_required": approval_required, "ai_complete": True}


@app.get("/core/autonomy/runs")
def autonomy_runs(limit: int = 25, u=Depends(current_user)):
    limit = min(max(limit, 1), 100)
    c = db(); rows = c.execute("SELECT id,mode,trigger,summary,actions_count,created_at FROM autonomy_runs WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?", (u["tenant_id"], limit)).fetchall(); c.close()
    return [dict(r) for r in rows]


@app.get("/core/providers")
def core_providers(u=Depends(current_user)):
    configured = _configured_remote_providers()
    return {
        "identity": "Zorvian Core",
        "providers_hidden_from_client_workflows": True,
        "ai_providers": status_snapshot(configured),
        "services": provider_status(),
    }


@app.post("/core/providers/approvals")
def core_provider_approval(body: ProviderApprovalIn, u=Depends(current_user)):
    require(u, "write")
    if body.service not in PROVIDERS:
        raise HTTPException(404, "Unknown service")
    action = f"{body.service}:{body.operation}"
    c = db(); aid = request_approval(c, u["tenant_id"], u["id"], action, body.payload); c.close()
    audit(u, "provider_approval_requested", f"{aid} · {action}")
    return {"approval_id": aid, "action": action, "status": "pending"}


@app.post("/core/providers/approvals/{approval_id}/approve")
def core_provider_approve(approval_id: str, u=Depends(current_user)):
    require(u, "approve")
    c = db(); ok = provider_approve(c, u["tenant_id"], approval_id, u["id"]); c.close()
    if not ok:
        raise HTTPException(404, "Pending approval not found")
    audit(u, "provider_approval_granted", approval_id)
    return {"approval_id": approval_id, "status": "approved"}


@app.post("/core/providers/execute")
async def core_provider_execute(body: ProviderActionIn, u=Depends(current_user)):
    require(u, "write")
    if body.service not in PROVIDERS:
        raise HTTPException(404, "Unknown service")
    action = f"{body.service}:{body.operation}"
    c = db(); ensure_provider_tables(c)
    if needs_approval(body.operation) and not approval_ok(c, u["tenant_id"], body.approval_id, action):
        c.close()
        raise HTTPException(409, {"code": "APPROVAL_REQUIRED", "action": action, "message": "Approval is required before this consequential external action."})
    job_id = str(uuid.uuid4()); provider = PROVIDERS[body.service]["primary"]
    c.execute("INSERT INTO provider_jobs VALUES (?,?,?,?,?,?,?,?,?,?)", (job_id, u["tenant_id"], u["id"], body.service, provider, "running", json.dumps(body.payload), None, now(), now())); c.commit(); c.close()
    try:
        result = await call_provider(body.service, body.operation, body.payload)
    except httpx.HTTPStatusError as exc:
        c = db(); c.execute("UPDATE provider_jobs SET status='failed',response=?,updated_at=? WHERE id=?", (exc.response.text[:5000], now(), job_id)); c.commit(); c.close()
        audit(u, "provider_execution_failed", f"job={job_id}; service={body.service}", "warning")
        raise HTTPException(502, "Provider request failed")
    c = db(); c.execute("UPDATE provider_jobs SET status='completed',response=?,updated_at=? WHERE id=?", (json.dumps(result)[:500000], now(), job_id)); c.commit(); c.close()
    audit(u, "provider_executed", f"job={job_id}; service={body.service}; operation={body.operation}")
    return {"job_id": job_id, "service": body.service, "result": result}
