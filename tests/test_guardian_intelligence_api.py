import os
import tempfile
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

DB_PATH = Path(tempfile.gettempdir()) / f"zorvian_guardian_intel_{uuid.uuid4().hex}.db"
os.environ["SQLITE_PATH"] = str(DB_PATH)
os.environ["ZORVIAN_ENV"] = "test"
os.environ["DEV_EXPOSE_TOKENS"] = "1"

from app_gate12 import app
import app as core_app
import app_gate5
from intelligence.connected import ConnectedResponse
from intelligence.provenance import ProvenanceRecord

CLIENT = TestClient(app)


def _headers():
    email = f"guard-{uuid.uuid4().hex[:8]}@example.com"
    password = "VeryStrongGuard!Password"
    reg = CLIENT.post("/auth/register", json={"company_name": "Guard Test Co", "name": "Guard User", "email": email, "password": password})
    assert reg.status_code == 201
    token = reg.json()["verification_token"]
    assert CLIENT.post("/auth/verify-email", json={"token": token}).status_code == 200
    login = CLIENT.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"Authorization": "Bearer " + login.json()["token"]}


def _ok_service(output='{"risk_level":"low","missing_evidence":[],"security_indicators":[]}'):
    class Svc:
        def run(self, req, ctx):
            return ConnectedResponse(
                module=req.module,
                capability="security-analysis",
                output=output,
                confidence=0.5,
                provider="openai",
                human_approval_required=False,
                tool_execution_allowed=False,
                provenance=ProvenanceRecord(module=req.module, task_id="t", source_refs=(), assumptions=(), confidence=0.5).validate(),
            )
    return Svc()


def test_unauthenticated_assessment_rejected():
    response = CLIENT.post("/guardian/intelligence/assess", json={"action": "read_tenant_profile"})
    assert response.status_code == 401


def test_authenticated_low_risk_succeeds():
    response = CLIENT.post(
        "/guardian/intelligence/assess",
        headers=_headers(),
        json={"action": "read_tenant_profile", "facts": "Read own tenant profile", "consequential_action": False},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["execution_allowed"] is True
    assert "tenant_id" not in body


def test_tenant_payload_cannot_override():
    headers = _headers()
    response = CLIENT.post(
        "/guardian/intelligence/assess",
        headers=headers,
        json={"action": "read_tenant_profile", "facts": "draft", "tenant_id": "attacker-tenant", "consequential_action": False},
    )
    assert response.status_code == 403


def test_cross_tenant_attempt_audited():
    headers = _headers()
    CLIENT.post(
        "/guardian/intelligence/assess",
        headers=headers,
        json={"action": "read_tenant_profile", "tenant_id": "attacker-tenant"},
    )
    events = CLIENT.get("/guardian/events", headers=headers)
    assert events.status_code == 200
    names = [row["event"] for row in events.json()]
    assert "guardian_cross_tenant_attempt" in names or "guardian_tenant_violation" in names


def test_provider_unavailable_503_when_ai_required(monkeypatch):
    class Boom:
        def run(self, req, ctx):
            raise LookupError("No approved connected provider is currently available")
    monkeypatch.setattr(app_gate5, "_service", lambda: Boom())
    response = CLIENT.post(
        "/guardian/intelligence/assess",
        headers=_headers(),
        json={"action": "approve_payment", "facts": "Pay £200", "consequential_action": True},
    )
    assert response.status_code == 503


def test_all_providers_failing_502(monkeypatch):
    class Boom:
        def run(self, req, ctx):
            raise RuntimeError("All approved intelligence providers failed safely: openai")
    monkeypatch.setattr(app_gate5, "_service", lambda: Boom())
    response = CLIENT.post(
        "/guardian/intelligence/assess",
        headers=_headers(),
        json={"action": "approve_payment", "facts": "Pay £200", "consequential_action": True},
    )
    assert response.status_code == 502


def test_malformed_ai_502_for_consequential(monkeypatch):
    monkeypatch.setattr(app_gate5, "_service", lambda: _ok_service("this is not structured json"))
    response = CLIENT.post(
        "/guardian/intelligence/assess",
        headers=_headers(),
        json={"action": "approve_payment", "facts": "Pay £200", "consequential_action": True},
    )
    assert response.status_code == 502


def test_failover_still_succeeds(monkeypatch):
    class Failover:
        def run(self, req, ctx):
            return ConnectedResponse(
                module="security-analysis",
                capability="security-analysis",
                output='{"risk_level":"low","missing_evidence":[]}',
                confidence=0.4,
                provider="anthropic",
                human_approval_required=False,
                tool_execution_allowed=False,
                provenance=ProvenanceRecord(module="security-analysis", task_id="t", source_refs=(), assumptions=(), confidence=0.4).validate(),
            )
    monkeypatch.setattr(app_gate5, "_service", lambda: Failover())
    response = CLIENT.post(
        "/guardian/intelligence/assess",
        headers=_headers(),
        json={"action": "approve_payment", "facts": "Pay £50 after approval", "consequential_action": True, "approval_present": True},
    )
    assert response.status_code == 200


def test_pass_block_audit_events_written():
    headers = _headers()
    CLIENT.post(
        "/guardian/intelligence/assess",
        headers=headers,
        json={"action": "read_tenant_profile", "facts": "profile", "consequential_action": False},
    )
    c = core_app.db()
    rows = c.execute("SELECT event FROM audit ORDER BY created_at").fetchall()
    c.close()
    events = [r["event"] for r in rows]
    assert "guardian_assessment_started" in events
    assert "guardian_assessment_completed" in events


def test_secret_not_echoed_in_audit():
    headers = _headers()
    secret = "smtp_password=supersecretvalue99"
    CLIENT.post(
        "/guardian/intelligence/assess",
        headers=headers,
        json={"action": "export_credentials", "facts": secret, "consequential_action": False},
    )
    c = core_app.db()
    rows = c.execute("SELECT event, detail FROM audit").fetchall()
    c.close()
    blob = " ".join(f"{r['event']} {r['detail']}" for r in rows)
    assert "supersecretvalue99" not in blob
