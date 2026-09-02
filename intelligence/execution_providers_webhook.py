"""Phase 3 Stage 2 — isolated webhook sandbox.

No outbound HTTP, sockets, subprocess or live DNS. A provider instance only
talks to an injected in-process transport.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from intelligence.execution_adapters import ExecutionAdapter, destination_hash, payload_hash
from intelligence.execution_providers import (
    Attempt,
    CancelResult,
    ClosedProvider,
    DryRunPreview,
    ProviderDenied,
    Receipt,
    ShadowResult,
)

try:
    import idna
except ImportError:  # pragma: no cover
    idna = None


class DestinationDenied(ProviderDenied):
    """Webhook destination failed hardened validation."""


class SandboxDenied(ProviderDenied):
    """Sandbox request construction or sink delivery denied."""


SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "key",
    "code",
}

BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal")
BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
    "metadata.aws.internal",
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("2001:db8::/32"),
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _utc_now()).isoformat().replace("+00:00", "Z")


def canonical_json(payload: dict[str, Any] | None) -> str:
    return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def canonicalise_hostname(host: str) -> str:
    raw = (host or "").strip().rstrip(".")
    if not raw:
        raise DestinationDenied("hostname is required")
    if any(ord(ch) < 32 or ch in " /\\" for ch in raw):
        raise DestinationDenied("hostname contains forbidden characters")
    if raw != raw.encode("ascii", "ignore").decode("ascii") and "%" in raw:
        raise DestinationDenied("hostname encoding is ambiguous")
    try:
        if idna is not None:
            encoded = idna.encode(raw, uts46=True).decode("ascii")
            decoded = idna.decode(encoded)
            encoded2 = idna.encode(decoded, uts46=True).decode("ascii")
            if encoded != encoded2:
                raise DestinationDenied("hostname IDNA encoding is ambiguous")
            return encoded.lower()
        import encodings.idna as std_idna

        labels = raw.split(".")
        encoded_labels = [std_idna.ToASCII(label).decode("ascii") for label in labels]
        return ".".join(encoded_labels).lower()
    except DestinationDenied:
        raise
    except Exception as exc:
        raise DestinationDenied(f"hostname is not a valid IDNA name: {exc}") from exc


def _is_obscure_ipv4(host: str) -> bool:
    value = host.strip().lower()
    if not value:
        return False
    if value.startswith("0x") or any(part.startswith("0x") for part in value.split(".")):
        return True
    if re.fullmatch(r"\d+", value):
        number = int(value)
        return 0 <= number <= 0xFFFFFFFF
    parts = value.split(".")
    if not parts or len(parts) > 4:
        return False
    if all(re.fullmatch(r"\d+", part) for part in parts) and len(parts) < 4:
        return True
    for part in parts:
        if re.fullmatch(r"0[0-7]+", part):
            return True
        if re.fullmatch(r"0\d+", part) and part != "0":
            return True
    return False


def classify_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    raw = (address or "").strip()
    if not raw:
        raise DestinationDenied("resolved address is empty")
    if _is_obscure_ipv4(raw):
        raise DestinationDenied("obscure numeric IP encoding is rejected")
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise DestinationDenied(f"address is not a canonical IP: {raw}") from exc
    if ip.version == 6 and getattr(ip, "ipv4_mapped", None) is not None:
        raise DestinationDenied("IPv4-mapped IPv6 addresses are rejected")
    if ip.version == 6 and getattr(ip, "sixtofour", None) is not None:
        raise DestinationDenied("6to4 embedded IPv4 addresses are rejected")
    if ip.version == 6 and getattr(ip, "teredo", None) is not None:
        raise DestinationDenied("Teredo embedded IPv4 addresses are rejected")
    if any(ip in network for network in BLOCKED_NETWORKS):
        raise DestinationDenied("address is in a prohibited network")
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
        raise DestinationDenied("address is not a public unicast destination")
    if ip.is_reserved or ip.is_unspecified or ip.is_multicast:
        raise DestinationDenied("address is reserved, unspecified or multicast")
    if hasattr(ip, "is_global") and ip.is_global is False:
        raise DestinationDenied("address is not globally routable")
    return ip


def mask_webhook_destination(destination: str) -> str:
    parts = urlsplit(destination)
    host = parts.hostname or "unknown"
    port = f":{parts.port}" if parts.port and parts.port != 443 else ""
    query_pairs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS:
            query_pairs.append((key, "***"))
        else:
            query_pairs.append((key, value))
    query = urlencode(query_pairs)
    path = parts.path or "/"
    return urlunsplit(("https", host + port, path, query, ""))


def redacted_headers(headers: dict[str, str] | None) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in (headers or {}).items():
        lowered = key.lower()
        if lowered in {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}:
            safe[key] = "***"
        else:
            safe[key] = value
    return safe


@dataclass(frozen=True)
class ResolutionRecord:
    record_id: str
    plan_id: str
    destination_hash: str
    hostname: str
    addresses: tuple[str, ...]
    record_hash: str
    created_at: str


class ResolverPort(Protocol):
    def resolve(self, hostname: str) -> list[str]:
        ...


class NullResolver:
    """Stage 2 default: no live DNS. Hostnames are not expanded to addresses."""

    def resolve(self, hostname: str) -> list[str]:
        return []


class StaticResolver:
    def __init__(self, mapping: dict[str, list[str]]):
        self.mapping = {canonicalise_hostname(key): list(value) for key, value in mapping.items()}

    def resolve(self, hostname: str) -> list[str]:
        return list(self.mapping.get(canonicalise_hostname(hostname), []))


def validate_resolved_addresses(addresses: list[str]) -> list[str]:
    if not addresses:
        return []
    clean = []
    for item in addresses:
        ip = classify_ip(item)
        clean.append(ip.compressed)
    return clean


def record_resolution(
    *,
    plan_id: str,
    destination_hash_value: str,
    hostname: str,
    addresses: list[str],
    previous: ResolutionRecord | None = None,
) -> ResolutionRecord:
    validated = validate_resolved_addresses(addresses)
    digest = sha256_text("|".join([plan_id, destination_hash_value, hostname, ",".join(sorted(validated))]))
    current = ResolutionRecord(
        record_id=str(uuid.uuid4()),
        plan_id=plan_id,
        destination_hash=destination_hash_value,
        hostname=hostname,
        addresses=tuple(sorted(validated)),
        record_hash=digest,
        created_at=_iso(),
    )
    if previous is not None and set(previous.addresses) != set(current.addresses):
        raise DestinationDenied("DNS_REBINDING_DENIED")
    return current


def validate_hardened_webhook_destination(
    destination: str | None,
    *,
    allowed_hosts: list[str],
    resolver: ResolverPort | None = None,
    allow_non_443: bool = False,
    plan_id: str = "unbound",
    previous_resolution: ResolutionRecord | None = None,
) -> tuple[str, ResolutionRecord]:
    value = (destination or "").strip()
    if not value:
        raise DestinationDenied("destination is required")
    if "\n" in value or "\r" in value or " " in value.strip():
        raise DestinationDenied("destination contains forbidden whitespace")
    parts = urlsplit(value)
    if parts.scheme.lower() != "https":
        raise DestinationDenied("webhook destination must be HTTPS")
    if parts.username or parts.password:
        raise DestinationDenied("webhook destination must not include credentials")
    if parts.fragment:
        raise DestinationDenied("webhook destination must not include a fragment")
    if not parts.hostname:
        raise DestinationDenied("webhook destination must include an explicit host")
    host = canonicalise_hostname(parts.hostname)
    if host in BLOCKED_HOSTS or any(host.endswith(suffix) for suffix in BLOCKED_HOST_SUFFIXES):
        raise DestinationDenied("hostname is prohibited")
    if host.startswith("xn--") is False and any(ord(ch) > 127 for ch in parts.hostname):
        raise DestinationDenied("hostname mixed-encoding is rejected")
    port = parts.port
    if port is None:
        port = 443
    elif port != 443 and not allow_non_443:
        raise DestinationDenied("webhook destination must use port 443")
    if port == 80:
        raise DestinationDenied("webhook destination must not use plaintext ports")

    allowed = {canonicalise_hostname(item) for item in allowed_hosts if item and "://" not in item}
    if allowed and host not in allowed:
        raise DestinationDenied("hostname must match the tenant allowlist")

    dest_h = destination_hash(value) or sha256_text(value.lower())
    addresses: list[str] = []
    try:
        classify_ip(host)
        addresses = [host]
    except DestinationDenied:
        if _is_obscure_ipv4(host):
            raise
        resolver = resolver or NullResolver()
        addresses = list(resolver.resolve(host))
        if addresses:
            validate_resolved_addresses(addresses)
    resolution = record_resolution(
        plan_id=plan_id,
        destination_hash_value=dest_h,
        hostname=host,
        addresses=addresses,
        previous=previous_resolution,
    )
    return value, resolution


@dataclass
class SandboxRequest:
    plan_id: str
    tenant_id: str
    adapter_id: str
    action: str
    destination_hash: str
    payload_hash: str
    resource_hash: str | None
    approval_hash: str | None
    idempotency_key: str
    masked_destination: str
    redacted_headers: dict[str, str]
    resolution_record_hash: str
    created_at: str
    expires_at: str
    method: str = "POST"
    canonical_body: str = "{}"
    redirects: bool = False


@dataclass
class InProcessWebhookSink:
    """Test/sandbox-only sink. Not mounted on any production route."""

    _lock: threading.Lock = field(default_factory=threading.Lock)
    _by_key: dict[str, dict[str, Any]] = field(default_factory=dict)

    def post(self, request: SandboxRequest) -> dict[str, Any]:
        if request.method != "POST":
            raise SandboxDenied("sandbox sink accepts POST only")
        if request.redirects:
            raise DestinationDenied("redirects are rejected")
        if not request.idempotency_key:
            raise SandboxDenied("idempotency key is required")
        with self._lock:
            existing = self._by_key.get(request.idempotency_key)
            if existing is None:
                receipt = {
                    "receipt_id": str(uuid.uuid4()),
                    "idempotency_key": request.idempotency_key,
                    "payload_hash": request.payload_hash,
                    "destination_hash": request.destination_hash,
                    "classification": "sandbox_recorded",
                    "created_at": _iso(),
                }
                self._by_key[request.idempotency_key] = receipt
                return dict(receipt)
            if existing["payload_hash"] != request.payload_hash or existing["destination_hash"] != request.destination_hash:
                raise SandboxDenied("idempotency key reuse with altered payload is rejected")
            return dict(existing)


class WebhookSandboxProvider(ClosedProvider):
    """Constructs the would-be webhook POST and optionally records it in-process."""

    def __init__(
        self,
        adapter: ExecutionAdapter,
        *,
        transport: InProcessWebhookSink | None = None,
        resolver: ResolverPort | None = None,
        production_mode: bool = False,
    ):
        super().__init__(adapter)
        if production_mode:
            raise ProviderDenied("Webhook sandbox provider cannot be selected in production mode")
        if adapter.adapter_id != "webhook.post":
            raise ProviderDenied("WebhookSandboxProvider is only valid for webhook.post")
        self.transport = transport
        self.resolver = resolver or NullResolver()

    def submit(self, plan: dict[str, Any], idempotency_key: str, timeout: float) -> Attempt:
        raise ProviderDenied("Stage 2 does not implement the production submit path")

    def cancel(self, provider_ref: str) -> CancelResult:
        raise ProviderDenied("Stage 2 cancel remains fail-closed")

    def build_sandbox_request(
        self,
        *,
        plan: dict[str, Any],
        payload: dict[str, Any],
        destination: str,
        allowed_hosts: list[str],
        headers: dict[str, str] | None = None,
        previous_resolution: ResolutionRecord | None = None,
        ttl_seconds: int = 600,
    ) -> SandboxRequest:
        if headers:
            lowered = {key.lower() for key in headers}
            if "authorization" in lowered or "proxy-authorization" in lowered:
                raise SandboxDenied("authorisation headers cannot be attached to sandbox requests")
        dest, resolution = validate_hardened_webhook_destination(
            destination,
            allowed_hosts=allowed_hosts,
            resolver=self.resolver,
            plan_id=str(plan.get("id") or plan.get("plan_id") or "unbound"),
            previous_resolution=previous_resolution,
        )
        body = canonical_json(payload)
        computed_payload = sha256_text(body)
        expected_payload = plan.get("payload_hash")
        if expected_payload and expected_payload != payload_hash(payload):
            raise SandboxDenied("payload hash mismatch")
        expected_dest = plan.get("destination_hash")
        if expected_dest and expected_dest != destination_hash(dest):
            raise SandboxDenied("destination hash mismatch")
        created = _utc_now()
        idem = plan.get("idempotency_key") or sha256_text(
            "|".join(
                [
                    str(plan.get("id") or ""),
                    str(plan.get("tenant_id") or ""),
                    computed_payload,
                    destination_hash(dest) or "",
                ]
            )
        )
        return SandboxRequest(
            plan_id=str(plan.get("id") or plan.get("plan_id") or ""),
            tenant_id=str(plan.get("tenant_id") or ""),
            adapter_id=self.adapter_id,
            action=str(plan.get("action") or "post_webhook"),
            destination_hash=destination_hash(dest) or sha256_text(dest),
            payload_hash=computed_payload if not expected_payload else str(expected_payload),
            resource_hash=plan.get("resource_hash"),
            approval_hash=plan.get("approval_hash"),
            idempotency_key=idem,
            masked_destination=mask_webhook_destination(dest),
            redacted_headers=redacted_headers(headers or {"Content-Type": "application/json", "Idempotency-Key": idem}),
            resolution_record_hash=resolution.record_hash,
            created_at=_iso(created),
            expires_at=_iso(created + timedelta(seconds=ttl_seconds)),
            canonical_body=body,
        )

    def record_sandbox(self, request: SandboxRequest) -> dict[str, Any] | None:
        if self.transport is None:
            return None
        return self.transport.post(request)

    def preview(self, plan: dict[str, Any]) -> DryRunPreview:
        return DryRunPreview(
            mode="dry_run",
            adapter_id=self.adapter_id,
            execution_allowed=False,
            reason="Stage 2 webhook sandbox only; live submit disabled",
            destination_hash=plan.get("destination_hash"),
            payload_hash=plan.get("payload_hash"),
        )

    def shadow(self, plan: dict[str, Any]) -> ShadowResult:
        return ShadowResult(
            mode="shadow",
            adapter_id=self.adapter_id,
            execution_allowed=False,
            reason="Stage 2 shadow constructed; live submit disabled",
            destination_hash=plan.get("destination_hash"),
            payload_hash=plan.get("payload_hash"),
        )
