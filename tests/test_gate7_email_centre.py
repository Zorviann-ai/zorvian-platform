import os
import tempfile

_fd, DB_PATH = tempfile.mkstemp(prefix="zorvian-email-centre-", suffix=".db")
os.close(_fd)
os.environ["ZORVIAN_ENV"] = "test"
os.environ["SQLITE_PATH"] = DB_PATH
os.environ["GUARDIAN_HASH_PEPPER"] = "gate7-email-centre-test"
os.environ["RESEND_API_KEY"] = "re_test"
os.environ["SMTP_FROM"] = "Caelomere <support@caelomere.com>"
os.environ["RESEND_INBOUND_DOMAIN"] = "inbound.zorvian.test"
os.environ["RESEND_WEBHOOK_SECRET"] = "whsec_Z2F0ZTctdGVzdC13ZWJob29rLWtleQ=="

from fastapi.testclient import TestClient
import app_gate11

client = TestClient(app_gate11.app)


def test_email_centre_is_served_with_security_headers():
    r = client.get("/mailbox-center")
    assert r.status_code == 200
    assert "Email Centre" in r.text
    assert "INBOX" in r.text and "SENT" in r.text and "COMPOSE" in r.text
    assert "mailbox-centre.js" in r.text
    csp = r.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers.get("cache-control") == "no-store"


def test_email_centre_assets_include_real_mailbox_api_wiring():
    js = client.get("/mailbox-centre.js")
    assert js.status_code == 200
    for endpoint in ["/auth/login", "/mailbox/status", "/mailbox/messages?limit=100", "/mailbox/send"]:
        assert endpoint in js.text
    assert "sessionStorage" in js.text
    assert "thread_id" in js.text
    css = client.get("/mailbox-centre.css")
    assert css.status_code == 200
    assert "text/css" in css.headers.get("content-type", "")


def teardown_module(module):
    try:
        os.unlink(DB_PATH)
    except FileNotFoundError:
        pass
