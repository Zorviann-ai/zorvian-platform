import os
import tempfile
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

DB_PATH = Path(tempfile.gettempdir()) / f"zorvian_orchestrator_{uuid.uuid4().hex}.db"
os.environ["SQLITE_PATH"] = str(DB_PATH)
os.environ["ZORVIAN_ENV"] = "test"
os.environ["DEV_EXPOSE_TOKENS"] = "1"

from app_gate12 import app
import app as core_app

CLIENT = TestClient(app)


def _headers():
    email = f"orch-{uuid.uuid4().hex[:8]}@example.com"
    password = "VeryStrongOrch!Password"
    reg = CLIENT.post("/auth/register", json={"company_name": "Orch Test Co", "name": "Orch User", "email": email, "password": password})
    assert reg.status_code == 201
    token = reg.json()["verification_token"]
    assert CLIENT.post("/auth/verify-email", json={"token": token}).status_code == 200
    login = CLIENT.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"Authorization": "Bearer " + login.json()["token"]}


def test_unauthenticated_rejected():
    response = CLIENT.post("/core/intelligence/decide", json={"action": "read_tenant_profile"})
    assert response.status_code == 401


def test_authenticated_low_risk_allow():
    response = CLIENT.post(
        "/core/intelligence/decide",
        headers=_headers(),
        json={"action": "read_tenant_profile", "facts": "Read own tenant profile", "consequential_action": False},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == "ALLOW"
    assert body["execution_allowed"] is True
    assert "tenant_id" not in body
    assert body["constitutional_control"]["execution_allowed"] is True


def test_tenant_payload_cannot_override():
    response = CLIENT.post(
        "/core/intelligence/decide",
        headers=_headers(),
        json={"action": "read_tenant_profile", "tenant_id": "attacker-tenant"},
    )
    assert response.status_code == 403


def test_consequential_without_authority_not_allow():
    response = CLIENT.post(
        "/core/intelligence/decide",
        headers=_headers(),
        json={
            "action": "approve_supplier_payment",
            "facts": "Pay supplier £25000",
            "financial_domain": "payment",
            "amount": 25000,
            "currency": "GBP",
            "consequential_action": True,
            "approval_present": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["execution_allowed"] is False
    assert body["outcome"] in {"BLOCK", "REVIEW_REQUIRED"}


def test_audit_events_written():
    headers = _headers()
    CLIENT.post(
        "/core/intelligence/decide",
        headers=headers,
        json={"action": "read_tenant_profile", "facts": "profile", "consequential_action": False},
    )
    c = core_app.db()
    rows = c.execute("SELECT event FROM audit").fetchall()
    c.close()
    events = [r["event"] for r in rows]
    assert "constitutional_decision_started" in events
    assert "constitutional_decision_completed" in events
