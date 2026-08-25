import base64
import hashlib
import hmac
import json
import os
import tempfile
import time

_fd, DB_PATH = tempfile.mkstemp(prefix="zorvian-gate7-email-", suffix=".db")
os.close(_fd)
os.environ["ZORVIAN_ENV"] = "test"
os.environ["SQLITE_PATH"] = DB_PATH
os.environ["DEV_EXPOSE_TOKENS"] = "1"
os.environ["GUARDIAN_HASH_PEPPER"] = "gate7-email-test-pepper"
os.environ["RESEND_API_KEY"] = "re_test_only"
os.environ["SMTP_FROM"] = "Caelomere <support@caelomere.com>"
os.environ["RESEND_INBOUND_DOMAIN"] = "inbound.zorvian.test"
WEBHOOK_KEY = b"gate7-test-webhook-key-32-bytes!!"
os.environ["RESEND_WEBHOOK_SECRET"] = "whsec_" + base64.b64encode(WEBHOOK_KEY).decode()

from fastapi.testclient import TestClient
import app_gate8
import app_gate9
import app_gate10

client = TestClient(app_gate10.app)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def account(company="Urban Test Ltd", email="owner@urban.test"):
    r = client.post("/auth/register", json={"company_name":company,"name":"Urban Owner","email":email,"password":"Urban-secure-password-2026!"})
    assert r.status_code == 201, r.text
    token = r.json()["verification_token"]
    assert client.post("/auth/verify-email", json={"token":token}).status_code == 200
    login = client.post("/auth/login", json={"email":email,"password":"Urban-secure-password-2026!"})
    assert login.status_code == 200, login.text
    return login.json()["token"]


def sign(body: bytes, event_id="msg_test_webhook_1"):
    ts = str(int(time.time()))
    signed = f"{event_id}.{ts}.".encode() + body
    sig = base64.b64encode(hmac.new(WEBHOOK_KEY, signed, hashlib.sha256).digest()).decode()
    return {"svix-id":event_id,"svix-timestamp":ts,"svix-signature":f"v1,{sig}"}


def test_operational_email_end_to_end(monkeypatch):
    monkeypatch.setattr(app_gate8, "send_professional_email", lambda *args, **kwargs: True)
    token = account(); headers = auth(token)
    activation = client.post("/mailbox/activate", headers=headers, json={})
    assert activation.status_code == 200, activation.text
    assert activation.json()["status"] == "connected"
    assert activation.json()["inbound_address"].endswith("@inbound.zorvian.test")

    contact = client.post("/contacts", headers=headers, json={"name":"Test Customer","contact":"customer@example.com","need":"Email test","source":"test"})
    assert contact.status_code == 200

    calls = []
    def fake_resend(method, path, payload=None, extra_headers=None):
        calls.append((method,path,payload,extra_headers))
        if method == "POST": return {"id":"provider-outbound-1"}
        return {"id":"provider-inbound-1","from":"Test Customer <customer@example.com>","to":[calls[0][2]["reply_to"]],"subject":"Re: Service update","text":"Thank you. Please proceed.","html":"<p>Thank you. Please proceed.</p>","message_id":"<inbound-1@example.com>"}
    monkeypatch.setattr(app_gate9, "_resend_json", fake_resend)

    sent = client.post("/mailbox/send", headers=headers, json={"to":"customer@example.com","subject":"Service update","body":"Here is your professional update."})
    assert sent.status_code == 200, sent.text
    data = sent.json(); assert data["professional_html"] is True
    assert data["reply_to"].startswith("reply+")
    assert calls[0][2]["html"].find("Urban Test Ltd") >= 0
    assert "Powered by Caelomere Core" in calls[0][2]["html"]

    event = {"type":"email.received","created_at":"2026-08-22T08:00:00Z","data":{"email_id":"provider-inbound-1","from":"Test Customer <customer@example.com>","to":[data["reply_to"]],"subject":"Re: Service update","message_id":"<inbound-1@example.com>","attachments":[]}}
    raw = json.dumps(event, separators=(",",":")).encode()
    inbound = client.post("/webhooks/resend", content=raw, headers={**sign(raw),"content-type":"application/json"})
    assert inbound.status_code == 200, inbound.text
    assert inbound.json()["status"] == "received"
    assert inbound.json()["thread_id"] == data["thread_id"]

    messages = client.get("/mailbox/messages", headers=headers)
    assert messages.status_code == 200
    directions = [m["direction"] for m in messages.json()]
    assert "outbound" in directions and "inbound" in directions

    status = client.get("/mailbox/status", headers=headers).json()
    assert status["status"] == "connected"
    integrations = client.get("/integrations", headers=headers).json()
    email = next(x for x in integrations if x["provider"] == "email")
    assert email["status"] == "connected"


def test_existing_tenant_direct_inbound_is_auto_provisioned(monkeypatch):
    monkeypatch.setattr(app_gate8, "send_professional_email", lambda *args, **kwargs: True)
    token = account("Direct Route Ltd", "owner@direct-route.test")
    headers = auth(token)

    # No /mailbox/activate call: this reproduces tenants that existed before
    # the mailbox feature was deployed.
    integrations = client.get("/integrations", headers=headers)
    assert integrations.status_code == 200
    email = next(x for x in integrations.json() if x["provider"] == "email")
    assert email["status"] == "connected"
    mailbox = client.get("/mailbox/status", headers=headers).json()
    inbound_address = mailbox["inbound_address"]
    assert inbound_address == "direct-route-ltd@inbound.zorvian.test"

    def fake_resend(method, path, payload=None, extra_headers=None):
        assert method == "GET"
        return {"id":"provider-direct-1","from":"Customer <customer2@example.com>","to":[inbound_address],"subject":"Direct inbound","text":"Please call me back.","html":"<p>Please call me back.</p>","message_id":"<direct-1@example.com>"}
    monkeypatch.setattr(app_gate9, "_resend_json", fake_resend)

    event = {"type":"email.received","created_at":"2026-08-22T08:00:00Z","data":{"email_id":"provider-direct-1","from":"Customer <customer2@example.com>","to":[inbound_address],"subject":"Direct inbound","message_id":"<direct-1@example.com>","attachments":[]}}
    raw = json.dumps(event, separators=(",",":")).encode()
    inbound = client.post("/webhooks/resend", content=raw, headers={**sign(raw, "msg_direct_webhook_1"),"content-type":"application/json"})
    assert inbound.status_code == 200, inbound.text
    assert inbound.json()["status"] == "received"

    messages = client.get("/mailbox/messages", headers=headers).json()
    assert any(m["direction"] == "inbound" and m["subject"] == "Direct inbound" for m in messages)


def teardown_module(module):
    try: os.unlink(DB_PATH)
    except FileNotFoundError: pass
