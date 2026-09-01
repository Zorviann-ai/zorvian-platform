import os
import tempfile
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

DB_PATH = Path(tempfile.gettempdir()) / f"zorvian_exec_gw_{uuid.uuid4().hex}.db"
os.environ["SQLITE_PATH"] = str(DB_PATH)
os.environ["ZORVIAN_ENV"] = "test"
os.environ["DEV_EXPOSE_TOKENS"] = "1"

from app_gate12 import app
import app as core_app

CLIENT = TestClient(app)


def _headers():
    email = f"exec-{uuid.uuid4().hex[:8]}@example.com"
    password = "VeryStrongExec!Password"
    reg = CLIENT.post("/auth/register", json={"company_name": "Exec Test Co", "name": "Exec User", "email": email, "password": password})
    assert reg.status_code == 201
    token = reg.json()["verification_token"]
    assert CLIENT.post("/auth/verify-email", json={"token": token}).status_code == 200
    login = CLIENT.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"Authorization": "Bearer " + login.json()["token"]}


def test_unauthenticated_rejected():
    response = CLIENT.post("/core/execution/prepare", json={"action": "read_tenant_profile"})
    assert response.status_code == 401


def test_authenticated_prepare_authorised():
    headers = _headers()
    response = CLIENT.post(
        "/core/execution/prepare",
        headers=headers,
        json={"action": "read_tenant_profile", "facts": "Read own tenant profile", "consequential_action": False},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["execution_state"] == "AUTHORISED"
    assert body["external_execution_enabled"] is False
    assert "tenant_id" not in body
    ticket_id = body["execution_ticket_id"]
    got = CLIENT.get(f"/core/execution/tickets/{ticket_id}", headers=headers)
    assert got.status_code == 200
    assert got.json()["execution_ticket_id"] == ticket_id


def test_tenant_spoof_rejected():
    response = CLIENT.post(
        "/core/execution/prepare",
        headers=_headers(),
        json={"action": "read_tenant_profile", "tenant_id": "attacker-tenant"},
    )
    assert response.status_code == 403


def test_cross_tenant_ticket_hidden():
    headers_a = _headers()
    created = CLIENT.post(
        "/core/execution/prepare",
        headers=headers_a,
        json={"action": "read_tenant_profile", "facts": "profile"},
    )
    ticket_id = created.json()["execution_ticket_id"]
    headers_b = _headers()
    hidden = CLIENT.get(f"/core/execution/tickets/{ticket_id}", headers=headers_b)
    assert hidden.status_code == 404


def test_client_cannot_set_authorised():
    response = CLIENT.post(
        "/core/execution/prepare",
        headers=_headers(),
        json={
            "action": "approve_supplier_payment",
            "facts": "Pay £25000",
            "financial_domain": "payment",
            "amount": 25000,
            "consequential_action": True,
            "claimed_state": "AUTHORISED",
            "claimed_outcome": "ALLOW",
            "claimed_execution_allowed": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["execution_state"] != "AUTHORISED"


def test_audit_on_prepare():
    headers = _headers()
    CLIENT.post("/core/execution/prepare", headers=headers, json={"action": "read_tenant_profile", "facts": "p"})
    c = core_app.db()
    rows = c.execute("SELECT event FROM audit").fetchall()
    c.close()
    events = [r["event"] for r in rows]
    assert "execution_prepare_started" in events
    assert "execution_ticket_created" in events
