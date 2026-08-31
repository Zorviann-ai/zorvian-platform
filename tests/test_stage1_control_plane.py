import json
import os
import tempfile
import threading

_fd, DB_PATH = tempfile.mkstemp(prefix="zorvian-stage1-", suffix=".db")
os.close(_fd)
os.environ["ZORVIAN_ENV"] = "test"
os.environ["SQLITE_PATH"] = DB_PATH
os.environ["DEV_EXPOSE_TOKENS"] = "1"
os.environ["GUARDIAN_HASH_PEPPER"] = "stage1-test-pepper-not-production"
os.environ["ALLOWED_ORIGINS"] = "https://caelomere.com"

from fastapi.testclient import TestClient
import app
import control_plane

client = TestClient(app.app)


def register_verified(company, name, email, password):
    r = client.post("/auth/register", json={
        "company_name": company,
        "name": name,
        "email": email,
        "password": password,
    })
    assert r.status_code == 201, r.text
    token = r.json()["verification_token"]
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 200
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    return login.json()["token"]


def h(token):
    return {"Authorization": f"Bearer {token}"}



def set_jurisdiction(tenant, jurisdiction):
    c = app.db()
    c.execute("UPDATE control_tenant_profile SET home_jurisdiction=? WHERE tenant_id=?", (jurisdiction, tenant))
    c.commit(); c.close()

def draft(token, recipient="Client Ltd", purpose="client_correspondence", data_classes=None):
    r = client.post("/documents", headers=h(token), json={
        "type": "letter",
        "recipient": recipient,
        "facts": "Matter ref 14. Fee proposal as agreed.",
        "purpose": purpose,
        "data_classes": data_classes or ["personal"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "body" not in body
    return body["id"], body["content_hash"]


def test_happy_path_release_and_trace():
    token = register_verified("Oak Law", "Pat Owner", "pat.owner@example.com", "Stage1-owner-password!")
    me = client.get("/auth/me", headers=h(token)).json()
    c = app.db()
    profile = dict(c.execute("SELECT * FROM control_tenant_profile WHERE tenant_id=?", (me["workspace"]["id"],)).fetchone())
    c.close()
    assert profile["org_type"] == "general"
    assert profile["sectors"] == ""
    assert profile["home_jurisdiction"] == ""
    set_jurisdiction(me["workspace"]["id"], "UK")

    doc_id, digest = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    released = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "client@oaklaw.example"})
    assert released.status_code == 200, released.text
    data = released.json()
    assert data["status"] == "Released"
    assert data["delivery"] == "not_performed"
    assert data["document_hash"] == digest
    assert data["produced_by"] == "human"
    assert data["layer_results"]["financial_intelligence"]["result"] == "not_applicable"
    assert data["layer_results"]["legal_intelligence"]["result"] == "pass"
    assert data["layer_results"]["guardian"]["result"] == "pass"
    assert "DORA" not in data["jurisdiction_rules"]
    assert "NIS2" not in data["jurisdiction_rules"]
    trace = client.get(f"/control/trace/{data['event_id']}", headers=h(token))
    assert trace.status_code == 200, trace.text
    t = trace.json()
    assert t["document_id"] == doc_id
    assert t["purpose"] == "client_correspondence"
    assert t["produced_by"] == "human"
    assert t["model"] is None
    assert "destination" not in t["payload"]
    assert t["destination_hash"]
    assert t["evidence"] == "tamper-evident"
    assert t["chain"]["immutable"] is False
    assert client.get("/control/chain", headers=h(token)).json()["ok"] is True


def test_missing_approval_blocks_release():
    token = register_verified("Birch Law", "Bo Owner", "bo.owner@example.com", "Stage1-owner-password!")
    doc_id, _ = draft(token)
    r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@birch.example"})
    assert r.status_code == 403
    assert "approval" in r.json()["detail"]


def test_missing_permission_blocks_release():
    owner = register_verified("Cedar Law", "Cy Owner", "cy.owner@example.com", "Stage1-owner-password!")
    doc_id, _ = draft(owner)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(owner)).status_code == 200
    tenant = client.get("/auth/me", headers=h(owner)).json()["workspace"]["id"]
    c = app.db()
    c.execute(
        "INSERT INTO users(id,tenant_id,email,password_hash,role,created_at,display_name,email_verified,status) VALUES (?,?,?,?,?,?,?,?,?)",
        ("staff-cedar", tenant, "staff.cedar@example.com", app.hash_password("Stage1-staff-password!"), "staff", app.now(), "Staff", 1, "active"),
    )
    c.commit(); c.close()
    login = client.post("/auth/login", json={"email": "staff.cedar@example.com", "password": "Stage1-staff-password!"})
    r = client.post(f"/documents/{doc_id}/release", headers=h(login.json()["token"]), json={"destination": "a@cedar.example"})
    assert r.status_code == 403


def test_cross_tenant_and_forged_tenant():
    a = register_verified("Tenant A Ltd", "A Owner", "a.owner@example.com", "Stage1-owner-password!")
    b = register_verified("Tenant B Ltd", "B Owner", "b.owner@example.com", "Stage1-owner-password!")
    doc_id, _ = draft(a)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(a)).status_code == 200
    other = client.post(f"/documents/{doc_id}/release", headers=h(b), json={"destination": "a@beta.example"})
    assert other.status_code in (403, 404)
    forged = client.post(f"/documents/{doc_id}/release", headers=h(a), json={"destination": "a@alpha.example", "tenant_id": "forged-tenant"})
    assert forged.status_code == 403


def test_expired_session_and_disabled_actor():
    token = register_verified("Elm Law", "Ed Owner", "ed.owner@example.com", "Stage1-owner-password!")
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    c = app.db()
    c.execute("UPDATE secure_sessions SET expires_at='2000-01-01T00:00:00Z'")
    c.commit(); c.close()
    assert client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@elm.example"}).status_code == 401

    token2 = register_verified("Fir Law", "Fi Owner", "fi.owner@example.com", "Stage1-owner-password!")
    doc_id2, _ = draft(token2)
    assert client.post(f"/documents/{doc_id2}/approve", headers=h(token2)).status_code == 200
    c = app.db()
    c.execute("UPDATE users SET status='disabled' WHERE email=?", ("fi.owner@example.com",))
    c.commit(); c.close()
    assert client.post(f"/documents/{doc_id2}/release", headers=h(token2), json={"destination": "a@fir.example"}).status_code == 401


def test_unapproved_and_mismatched_model_blocked():
    token = register_verified("Yew Law", "Yu Owner", "yu.owner@example.com", "Stage1-owner-password!")
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@yew.example", "model_id": "document-studio-v1"})
    assert r.status_code == 403
    assert "provenance" in r.json()["detail"]


def test_evidence_write_failure_blocks_release():
    token = register_verified("Ash Law", "As Owner", "as.owner@example.com", "Stage1-owner-password!")
    set_jurisdiction(client.get("/auth/me", headers=h(token)).json()["workspace"]["id"], "UK")
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    os.environ["CONTROL_PLANE_FAIL_WRITE"] = "1"
    try:
        r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@ash.example"})
        assert r.status_code == 500
    finally:
        os.environ.pop("CONTROL_PLANE_FAIL_WRITE", None)
    c = app.db()
    row = c.execute("SELECT status,released_at FROM documents WHERE id=?", (doc_id,)).fetchone()
    c.close()
    assert row["status"] == "Principal Approved"
    assert row["released_at"] is None


def test_revoke_then_fresh_approval_succeeds():
    token = register_verified("Pine Law", "Pi Owner", "pi.owner@example.com", "Stage1-owner-password!")
    set_jurisdiction(client.get("/auth/me", headers=h(token)).json()["workspace"]["id"], "UK")
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    assert client.post(f"/documents/{doc_id}/revoke-approval", headers=h(token)).status_code == 200
    blocked = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@pine.example"})
    assert blocked.status_code == 403
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    ok = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@pine.example"})
    assert ok.status_code == 200, ok.text


def test_modify_content_after_approval_blocked():
    token = register_verified("Willow Law", "Wi Owner", "wi.owner@example.com", "Stage1-owner-password!")
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    c = app.db()
    c.execute("UPDATE documents SET body=? WHERE id=?", ("altered after approval", doc_id))
    c.commit(); c.close()
    r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@willow.example"})
    assert r.status_code == 403
    assert "hash" in r.json()["detail"]


def test_altered_chain_detected_and_duplicate_release():
    token = register_verified("Larch Law", "La Owner", "la.owner@example.com", "Stage1-owner-password!")
    set_jurisdiction(client.get("/auth/me", headers=h(token)).json()["workspace"]["id"], "UK")
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    first = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@larch.example"})
    assert first.status_code == 200, first.text
    again = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@larch.example"})
    assert again.status_code == 409
    c = app.db()
    c.execute("UPDATE control_events SET event_hash='deadbeef' WHERE tenant_id=(SELECT tenant_id FROM users WHERE email=?)", ("la.owner@example.com",))
    c.commit(); c.close()
    chain = client.get("/control/chain", headers=h(token))
    assert chain.json()["ok"] is False
    assert chain.json()["immutable"] is False


def test_direct_api_bypass_without_session():
    r = client.post("/documents/not-a-doc/release", json={"destination": "x@y.example"})
    assert r.status_code == 401


def test_missing_and_invalid_destination_blocked():
    token = register_verified("Hazel Law", "Ha Owner", "ha.owner@example.com", "Stage1-owner-password!")
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    missing = client.post(f"/documents/{doc_id}/release", headers=h(token), json={})
    assert missing.status_code == 422
    invalid = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "not-an-email"})
    assert invalid.status_code == 403
    example = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "client@example.test"})
    assert example.status_code == 403


def test_unclassified_tenant_is_general():
    token = register_verified("General Co", "Ge Owner", "ge.owner@example.com", "Stage1-owner-password!")
    tenant = client.get("/auth/me", headers=h(token)).json()["workspace"]["id"]
    c = app.db()
    row = dict(c.execute("SELECT * FROM control_tenant_profile WHERE tenant_id=?", (tenant,)).fetchone())
    c.close()
    assert row["org_type"] == "general"
    assert "legal" not in row["org_type"]
    assert row["sectors"] == ""


def test_concurrent_releases_keep_single_chain():
    token = register_verified("Concurrent Co", "Co Owner", "co.owner@example.com", "Stage1-owner-password!")
    set_jurisdiction(client.get("/auth/me", headers=h(token)).json()["workspace"]["id"], "UK")
    a, _ = draft(token, recipient="One Ltd")
    b, _ = draft(token, recipient="Two Ltd")
    assert client.post(f"/documents/{a}/approve", headers=h(token)).status_code == 200
    assert client.post(f"/documents/{b}/approve", headers=h(token)).status_code == 200
    errors = []

    def release(doc_id, dest):
        r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": dest})
        if r.status_code != 200:
            errors.append((doc_id, r.status_code, r.text))

    t1 = threading.Thread(target=release, args=(a, "one@concurrent.example"))
    t2 = threading.Thread(target=release, args=(b, "two@concurrent.example"))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert errors == []
    tenant = client.get("/auth/me", headers=h(token)).json()["workspace"]["id"]
    c = app.db()
    chain = control_plane.verify_chain(c, tenant)
    c.close()
    assert chain["ok"] is True
    assert chain["events"] == 2


def test_control_models_requires_admin():
    owner = register_verified("Admin Check", "Ad Owner", "ad.owner@example.com", "Stage1-owner-password!")
    tenant = client.get("/auth/me", headers=h(owner)).json()["workspace"]["id"]
    c = app.db()
    c.execute(
        "INSERT INTO users(id,tenant_id,email,password_hash,role,created_at,display_name,email_verified,status) VALUES (?,?,?,?,?,?,?,?,?)",
        ("staff-admincheck", tenant, "staff.admincheck@example.com", app.hash_password("Stage1-staff-password!"), "staff", app.now(), "Staff", 1, "active"),
    )
    c.commit(); c.close()
    staff = client.post("/auth/login", json={"email": "staff.admincheck@example.com", "password": "Stage1-staff-password!"}).json()["token"]
    assert client.get("/control/models", headers=h(staff)).status_code == 403
    assert client.get("/control/models", headers=h(owner)).status_code == 200


def test_legacy_documents_payload_creates_unresolved_draft():
    token = register_verified("Legacy Co", "Le Owner", "le.owner@example.com", "Stage1-owner-password!")
    r = client.post("/documents", headers=h(token), json={
        "type": "letter",
        "recipient": "Client Ltd",
        "facts": "Confirmed facts only.",
    })
    assert r.status_code == 200, r.text
    assert r.json()["declarations"] == "unresolved"
    doc_id = r.json()["id"]
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    blocked = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@legacy.example"})
    assert blocked.status_code == 403
    assert "unresolved" in blocked.json()["detail"]


def _insert_model(tenant, model_id="mdl-studio", provider="caelomere", version="1.0", approved=1, enabled=1):
    c = app.db()
    c.execute(
        "INSERT INTO control_model_cards(id,tenant_id,name,provider,version,purpose,approved,enabled,allowed_actions,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (model_id, tenant, "Studio", provider, version, "draft", approved, enabled, "release_letter", app.now()),
    )
    c.commit(); c.close()


def _mark_model_produced(doc_id, model_id="mdl-studio", provider="caelomere", version="1.0"):
    c = app.db()
    c.execute(
        "UPDATE documents SET produced_by='model', produced_by_model_id=?, produced_by_provider=?, produced_by_version=? WHERE id=?",
        (model_id, provider, version, doc_id),
    )
    c.commit(); c.close()


def test_model_produced_missing_id_blocked():
    token = register_verified("Model Gap Co", "Mg Owner", "mg.owner@example.com", "Stage1-owner-password!")
    doc_id, _ = draft(token)
    c = app.db()
    c.execute("UPDATE documents SET produced_by='model', produced_by_model_id=NULL WHERE id=?", (doc_id,))
    c.commit(); c.close()
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@modelgap.example"})
    assert r.status_code == 403
    assert "missing" in r.json()["detail"]


def test_model_provider_and_version_mismatch_blocked():
    token = register_verified("Model Mis Co", "Mm Owner", "mm.owner@example.com", "Stage1-owner-password!")
    tenant = client.get("/auth/me", headers=h(token)).json()["workspace"]["id"]
    _insert_model(tenant)
    doc_id, _ = draft(token)
    _mark_model_produced(doc_id, provider="other-provider")
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@modelmis.example"})
    assert r.status_code == 403
    assert "provider" in r.json()["detail"]
    doc_id2, _ = draft(token, recipient="Second Ltd")
    _mark_model_produced(doc_id2, version="9.9")
    assert client.post(f"/documents/{doc_id2}/approve", headers=h(token)).status_code == 200
    r2 = client.post(f"/documents/{doc_id2}/release", headers=h(token), json={"destination": "b@modelmis.example"})
    assert r2.status_code == 403
    assert "version" in r2.json()["detail"]


def test_disabled_model_blocked_and_matching_provenance_succeeds():
    token = register_verified("Model Ok Co", "Mo Owner", "mo.owner@example.com", "Stage1-owner-password!")
    tenant = client.get("/auth/me", headers=h(token)).json()["workspace"]["id"]
    set_jurisdiction(tenant, "UK")
    _insert_model(tenant, model_id="mdl-off", approved=0, enabled=0)
    doc_id, _ = draft(token)
    _mark_model_produced(doc_id, model_id="mdl-off")
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@modelok.example"})
    assert r.status_code == 403
    _insert_model(tenant, model_id="mdl-on", approved=1, enabled=1)
    doc_id2, _ = draft(token, recipient="Approved Model Ltd")
    _mark_model_produced(doc_id2, model_id="mdl-on")
    assert client.post(f"/documents/{doc_id2}/approve", headers=h(token)).status_code == 200
    ok = client.post(f"/documents/{doc_id2}/release", headers=h(token), json={"destination": "b@modelok.example"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["produced_by"] == "model"
    assert "AI_ACT" not in ok.json()["jurisdiction_rules"]


def test_unclassified_personal_data_requires_review():
    token = register_verified("Unknown Co", "Un Owner", "un.owner@example.com", "Stage1-owner-password!")
    tenant = client.get("/auth/me", headers=h(token)).json()["workspace"]["id"]
    c = app.db()
    assert c.execute("SELECT home_jurisdiction FROM control_tenant_profile WHERE tenant_id=?", (tenant,)).fetchone()[0] == ""
    c.close()
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@unknown.example"})
    assert r.status_code == 403
    assert "review" in r.json()["detail"]


def test_explicit_uk_personal_data_applies_uk_gdpr():
    token = register_verified("UK Declared Co", "Uk Owner", "uk.owner@example.com", "Stage1-owner-password!")
    set_jurisdiction(client.get("/auth/me", headers=h(token)).json()["workspace"]["id"], "UK")
    doc_id, _ = draft(token)
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    r = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@ukdeclared.example"})
    assert r.status_code == 200, r.text
    assert "UK_GDPR" in r.json()["jurisdiction_rules"]


def test_cross_tenant_model_card_blocked():
    a = register_verified("Model Tenant A", "Ma Owner", "ma.owner@example.com", "Stage1-owner-password!")
    b = register_verified("Model Tenant B", "Mb Owner", "mb.owner@example.com", "Stage1-owner-password!")
    tenant_a = client.get("/auth/me", headers=h(a)).json()["workspace"]["id"]
    tenant_b = client.get("/auth/me", headers=h(b)).json()["workspace"]["id"]
    set_jurisdiction(tenant_a, "UK")
    _insert_model(tenant_b, model_id="mdl-b-only")
    doc_id, _ = draft(a)
    _mark_model_produced(doc_id, model_id="mdl-b-only")
    assert client.post(f"/documents/{doc_id}/approve", headers=h(a)).status_code == 200
    r = client.post(f"/documents/{doc_id}/release", headers=h(a), json={"destination": "a@modeltA.example"})
    assert r.status_code == 403


def test_declare_after_approval_requires_fresh_approval():
    token = register_verified("Declare Co", "De Owner", "de.owner@example.com", "Stage1-owner-password!")
    set_jurisdiction(client.get("/auth/me", headers=h(token)).json()["workspace"]["id"], "UK")
    r = client.post("/documents", headers=h(token), json={"type":"letter","recipient":"Client Ltd","facts":"Facts"})
    doc_id = r.json()["id"]
    assert r.json()["declarations"] == "unresolved"
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    declared = client.post(f"/documents/{doc_id}/declare", headers=h(token), json={"purpose":"client_correspondence","data_classes":["personal"]})
    assert declared.status_code == 200, declared.text
    assert declared.json()["approval_invalidated"] is True
    blocked = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@declare.example"})
    assert blocked.status_code == 403
    assert client.post(f"/documents/{doc_id}/approve", headers=h(token)).status_code == 200
    ok = client.post(f"/documents/{doc_id}/release", headers=h(token), json={"destination": "a@declare.example"})
    assert ok.status_code == 200, ok.text


def test_deploy_layout_includes_control_plane_and_imports_app_gate12():
    text = open("Dockerfile").read()
    assert "control_plane.py" in text
    assert "COPY migrations ./migrations" in text
    assert "uvicorn app_gate12:app" in text
    import subprocess, sys
    r = subprocess.run([sys.executable, "-c", "import app_gate12; assert app_gate12.app is not None"], cwd=".", check=False)
    assert r.returncode == 0, r.stderr
