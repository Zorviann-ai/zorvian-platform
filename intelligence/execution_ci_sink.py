"""Phase 3 Stage 3 — hermetic TLS CI sink and pinned-IP client.

Internal/CI only. Not mounted on a production route. The client never uses
environment proxies and never follows redirects. TLS hostname verification is
always performed against the expected sink hostname while connecting to a
pinned, pre-validated IP.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from intelligence.execution_providers_webhook import SandboxDenied, sha256_text


ISOLATED_CI_HOSTNAME = "ci-sink.test"
ISOLATED_CI_PINNED_IP = "127.0.0.1"
DEFAULT_TIMEOUT_SECONDS = 2.0

_PROXY_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


class IsolatedCiDenied(SandboxDenied):
    """Isolated CI sink or transport denied the request."""


class IsolatedCiUncertain(IsolatedCiDenied):
    """Transport outcome is uncertain; caller must not retry automatically."""


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clear_proxy_env() -> dict[str, str]:
    saved: dict[str, str] = {}
    for key in _PROXY_ENV:
        if key in os.environ:
            saved[key] = os.environ.pop(key)
    return saved


def _restore_proxy_env(saved: dict[str, str]) -> None:
    for key, value in saved.items():
        os.environ[key] = value


def generate_ci_tls_material(hostname: str = ISOLATED_CI_HOSTNAME) -> tuple[str, str]:
    """Create a short-lived self-signed cert with SAN DNS:<hostname>."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime as dt

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    except Exception:
        # Fallback: openssl CLI if cryptography is unavailable.
        tmp = tempfile.mkdtemp(prefix="zorvian-ci-tls-")
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        import subprocess

        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-nodes",
                "-subj",
                f"/CN={hostname}",
                "-addext",
                f"subjectAltName=DNS:{hostname}",
            ],
            check=True,
            capture_output=True,
        )
        return str(cert_path), str(key_path)

    tmp = tempfile.mkdtemp(prefix="zorvian-ci-tls-")
    cert_path = Path(tmp) / "cert.pem"
    key_path = Path(tmp) / "key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return str(cert_path), str(key_path)


@dataclass
class IsolatedTlsResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    verified_hostname: str
    pinned_ip: str
    redirected: bool = False


class HermeticTlsCiSink:
    """In-process HTTPS sink bound to the pinned CI IP. Test/CI only."""

    def __init__(
        self,
        *,
        hostname: str = ISOLATED_CI_HOSTNAME,
        pinned_ip: str = ISOLATED_CI_PINNED_IP,
        programmed_status: int = 200,
        reset_next: bool = False,
        hang_seconds: float = 0.0,
    ):
        self.hostname = hostname
        self.pinned_ip = pinned_ip
        self.programmed_status = programmed_status
        self.reset_next = reset_next
        self.hang_seconds = hang_seconds
        self.received: list[dict[str, Any]] = []
        self._by_key: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.cert_file, self.key_file = generate_ci_tls_material(hostname)
        self.port = 0

    def start(self) -> "HermeticTlsCiSink":
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                return

            def do_POST(self) -> None:  # noqa: N802
                if sink.hang_seconds:
                    import time

                    time.sleep(sink.hang_seconds)
                if sink.reset_next:
                    sink.reset_next = False
                    self.close_connection = True
                    try:
                        self.connection.close()
                    except Exception:
                        pass
                    return
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                key = self.headers.get("Idempotency-Key") or ""
                payload_hash = sha256_text(raw.decode("utf-8") if raw else "{}")
                dest_hash = sha256_text(f"https://{sink.hostname}/isolated")
                with sink._lock:
                    existing = sink._by_key.get(key) if key else None
                    if existing is None:
                        receipt = {
                            "receipt_id": str(uuid.uuid4()),
                            "idempotency_key": key,
                            "payload_hash": payload_hash,
                            "destination_hash": dest_hash,
                            "classification": "isolated_ci_recorded",
                            "created_at": _utc_iso(),
                        }
                        if key:
                            sink._by_key[key] = receipt
                    else:
                        if existing["payload_hash"] != payload_hash:
                            self.send_response(409)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error":"idempotency_conflict"}')
                            return
                        receipt = existing
                    sink.received.append(
                        {
                            "path": self.path,
                            "idempotency_key": key,
                            "payload_hash": payload_hash,
                        }
                    )
                status = sink.programmed_status
                body = json.dumps({"ok": status < 300, "receipt": receipt}).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if status in {301, 302, 303, 307, 308}:
                    self.send_header("Location", "https://evil.example/redirect")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            def do_GET(self) -> None:  # noqa: N802
                self.send_response(405)
                self.end_headers()

        httpd = ThreadingHTTPServer((self.pinned_ip, 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_file, self.key_file)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self._server = httpd
        self.port = httpd.server_address[1]
        self._thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def destination(self) -> str:
        return f"https://{self.hostname}/isolated"


def isolated_tls_post(
    *,
    pinned_ip: str,
    port: int,
    hostname: str,
    path: str,
    body: str,
    idempotency_key: str,
    ca_file: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    headers: dict[str, str] | None = None,
) -> IsolatedTlsResponse:
    """POST over TLS to a pinned IP with hostname verification. No proxy, no redirects."""
    if pinned_ip != ISOLATED_CI_PINNED_IP and pinned_ip != "127.0.0.1":
        # Isolated CI sink is hermetic and loopback-only.
        raise IsolatedCiDenied("isolated CI sink IP is not the pinned hermetic address")
    saved = _clear_proxy_env()
    raw = None
    try:
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            sock = socket.create_connection((pinned_ip, port), timeout=timeout)
        except TimeoutError as exc:
            raise IsolatedCiUncertain("connect timeout") from exc
        except OSError as exc:
            raise IsolatedCiUncertain(f"connect reset or failed: {exc}") from exc
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=hostname)
        except ssl.SSLError as exc:
            sock.close()
            raise IsolatedCiDenied(f"TLS hostname verification failed: {exc}") from exc
        request_headers = {
            "Host": hostname,
            "Content-Type": "application/json",
            "Content-Length": str(len(body.encode("utf-8"))),
            "Idempotency-Key": idempotency_key,
            "Connection": "close",
        }
        for key, value in (headers or {}).items():
            if key.lower() in {"authorization", "proxy-authorization", "cookie"}:
                raise IsolatedCiDenied("authorisation headers cannot be attached to isolated CI posts")
            request_headers[key] = value
        req = f"POST {path or '/isolated'} HTTP/1.1\r\n"
        req += "".join(f"{k}: {v}\r\n" for k, v in request_headers.items())
        req += "\r\n" + body
        try:
            ssock.settimeout(timeout)
            ssock.sendall(req.encode("utf-8"))
            chunks: list[bytes] = []
            while True:
                try:
                    block = ssock.recv(65536)
                except TimeoutError as exc:
                    raise IsolatedCiUncertain("read timeout") from exc
                if not block:
                    break
                chunks.append(block)
            raw = b"".join(chunks)
        except IsolatedCiUncertain:
            raise
        except OSError as exc:
            raise IsolatedCiUncertain(f"transport reset: {exc}") from exc
        finally:
            try:
                ssock.close()
            except Exception:
                pass
    finally:
        _restore_proxy_env(saved)

    if not raw:
        raise IsolatedCiUncertain("empty response after TLS POST")
    header_blob, _, rest = raw.partition(b"\r\n\r\n")
    lines = header_blob.split(b"\r\n")
    if not lines:
        raise IsolatedCiUncertain("malformed HTTP response")
    status_line = lines[0].decode("latin1", "replace")
    parts = status_line.split(" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError) as exc:
        raise IsolatedCiUncertain("malformed HTTP status") from exc
    parsed_headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        parsed_headers[name.decode("latin1").lower()] = value.decode("latin1").strip()
    redirected = status in {301, 302, 303, 307, 308} or "location" in parsed_headers
    if redirected:
        raise IsolatedCiDenied("redirects are rejected")
    return IsolatedTlsResponse(
        status=status,
        body=rest,
        headers=parsed_headers,
        verified_hostname=hostname,
        pinned_ip=pinned_ip,
        redirected=False,
    )


@dataclass
class ScriptedTransport:
    """Deterministic in-process transport used by most unit tests."""

    outcomes: list[Any] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def post(self, *, body: str, idempotency_key: str, timeout: float) -> IsolatedTlsResponse:
        self.calls.append({"body": body, "idempotency_key": idempotency_key, "timeout": timeout})
        if not self.outcomes:
            return IsolatedTlsResponse(200, b'{"ok":true}', {}, ISOLATED_CI_HOSTNAME, ISOLATED_CI_PINNED_IP)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, IsolatedTlsResponse):
            return outcome
        if isinstance(outcome, int):
            return IsolatedTlsResponse(outcome, b"{}", {}, ISOLATED_CI_HOSTNAME, ISOLATED_CI_PINNED_IP)
        raise IsolatedCiDenied("unknown scripted transport outcome")
