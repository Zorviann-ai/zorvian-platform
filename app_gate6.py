"""Gate 6 production-readiness layer.

Extends the proven Gate 5 application without weakening its controls.
"""
from fastapi import Depends, HTTPException

from app_gate5 import app
from app import current_user, db, now, require
from deployment.readiness import readiness_report


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
