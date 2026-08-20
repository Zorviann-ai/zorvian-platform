"""Gate 6 staging SMTP compatibility layer backed by Resend HTTPS.

This module intentionally shadows Python's stdlib ``smtplib`` when the app is
run from the repository root. The existing Gate 6 ``app.py`` can therefore keep
its current SMTP-shaped interface while all delivery is performed over HTTPS.
"""

import json
import os
import urllib.error
import urllib.request


class _ResendSMTP:
    def __init__(self, host=None, port=None, timeout=15, context=None, **kwargs):
        self.timeout = timeout or 15
        self.api_key = os.getenv("RESEND_API_KEY") or os.getenv("SMTP_PASSWORD")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def starttls(self, context=None):
        return (220, b"Resend HTTPS transport ready")

    def login(self, user, password):
        if password:
            self.api_key = password
        if not self.api_key:
            raise RuntimeError("Resend API key is not configured")
        return (235, b"Authenticated")

    def send_message(self, msg, from_addr=None, to_addrs=None, **kwargs):
        api_key = self.api_key or os.getenv("RESEND_API_KEY") or os.getenv("SMTP_PASSWORD")
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

        req = urllib.request.Request(
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
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
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
        return (221, b"Closed")


SMTP = _ResendSMTP
SMTP_SSL = _ResendSMTP
