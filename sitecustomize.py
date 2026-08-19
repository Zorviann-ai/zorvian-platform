"""Gate 6 compatibility transport.

Railway trial/hobby networking blocks outbound SMTP. The Gate 6 app currently
uses smtplib, so this shim replaces SMTP/SMTP_SSL with a Resend HTTPS-backed
transport while preserving the app's existing send_email() interface.

The existing SMTP_PASSWORD variable is expected to contain the scoped Resend
API key. SMTP_FROM remains the authenticated sender address.
"""

import json
import os
import urllib.error
import urllib.request


class _ResendSMTP:
    def __init__(self, host=None, port=None, timeout=15, context=None, **kwargs):
        self.timeout = timeout or 15
        self._api_key = os.getenv("RESEND_API_KEY") or os.getenv("SMTP_PASSWORD")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def starttls(self, context=None):
        return (220, b"HTTPS transport active")

    def login(self, user, password):
        # Keep compatibility with existing app.py; prefer the key passed by the app.
        if password:
            self._api_key = password
        if not self._api_key:
            raise RuntimeError("Resend API key is not configured")
        return (235, b"Authenticated via Resend HTTPS API")

    def send_message(self, msg, from_addr=None, to_addrs=None, **kwargs):
        api_key = self._api_key or os.getenv("RESEND_API_KEY") or os.getenv("SMTP_PASSWORD")
        if not api_key:
            raise RuntimeError("Resend API key is not configured")

        sender = from_addr or msg.get("From") or os.getenv("SMTP_FROM")
        recipients = to_addrs or msg.get_all("To") or []
        if isinstance(recipients, str):
            recipients = [recipients]

        body = msg.get_body(preferencelist=("plain",)) if hasattr(msg, "get_body") else None
        text = body.get_content() if body is not None else str(msg)

        payload = json.dumps({
            "from": sender,
            "to": recipients,
            "subject": msg.get("Subject", "Zorvian notification"),
            "text": text,
        }).encode("utf-8")

        request = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "Zorvian-Gate6/0.9.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = getattr(response, "status", 200)
                if status not in (200, 201):
                    raise RuntimeError(f"Resend returned HTTP {status}")
                return {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"Resend HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Resend HTTPS connection failed: {exc.reason}") from exc

    def quit(self):
        return (221, b"HTTPS transport closed")


# app.py imports the stdlib smtplib module. Python imports sitecustomize during
# startup, so patch the two constructors used by Gate 6 before the app serves.
import smtplib  # noqa: E402

smtplib.SMTP = _ResendSMTP
smtplib.SMTP_SSL = _ResendSMTP
