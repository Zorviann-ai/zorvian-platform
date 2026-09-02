"""Phase 3 Stage 1 — provider-neutral port.

No outbound network is permitted. submit() and cancel() always fail closed.
This module must not import outbound HTTP clients or provider SDKs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from intelligence.execution_adapters import AdapterDenied, ExecutionAdapter, validate_destination


class ProviderDenied(AdapterDenied):
    """Live or unsupported provider action denied."""


@dataclass(frozen=True)
class DryRunPreview:
    mode: str
    adapter_id: str
    execution_allowed: bool
    reason: str
    destination_hash: str | None
    payload_hash: str | None


@dataclass(frozen=True)
class ShadowResult:
    mode: str
    adapter_id: str
    execution_allowed: bool
    reason: str
    destination_hash: str | None
    payload_hash: str | None


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    state: str
    provider_ref: str | None = None


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    attempt_id: str
    classification: str
    provider_ref: str | None = None


@dataclass(frozen=True)
class CancelResult:
    attempt_id: str
    state: str
    supported: bool


class ProviderPort(Protocol):
    adapter_id: str
    adapter_type: str

    def validate_destination(self, destination: str | None, allowed: list[str], env: str = "prod") -> str:
        ...

    def preview(self, plan: dict[str, Any]) -> DryRunPreview:
        ...

    def shadow(self, plan: dict[str, Any]) -> ShadowResult:
        ...

    def submit(self, plan: dict[str, Any], idempotency_key: str, timeout: float) -> Attempt:
        ...

    def fetch_receipt(self, provider_ref: str) -> Receipt:
        ...

    def cancel(self, provider_ref: str) -> CancelResult:
        ...


class ClosedProvider:
    """Stage 1 provider: validation and preview only. No I/O."""

    def __init__(self, adapter: ExecutionAdapter):
        self.adapter = adapter
        self.adapter_id = adapter.adapter_id
        self.adapter_type = adapter.adapter_type

    def validate_destination(self, destination: str | None, allowed: list[str], env: str = "prod") -> str:
        return validate_destination(self.adapter, destination, allowed, env=env)

    def preview(self, plan: dict[str, Any]) -> DryRunPreview:
        return DryRunPreview(
            mode="dry_run",
            adapter_id=self.adapter_id,
            execution_allowed=False,
            reason="External execution disabled in Controlled Execution Gateway Phase 3 Stage 1",
            destination_hash=plan.get("destination_hash"),
            payload_hash=plan.get("payload_hash"),
        )

    def shadow(self, plan: dict[str, Any]) -> ShadowResult:
        return ShadowResult(
            mode="shadow",
            adapter_id=self.adapter_id,
            execution_allowed=False,
            reason="Shadow complete; live submit remains disabled in Stage 1",
            destination_hash=plan.get("destination_hash"),
            payload_hash=plan.get("payload_hash"),
        )

    def submit(self, plan: dict[str, Any], idempotency_key: str, timeout: float) -> Attempt:
        raise ProviderDenied("External execution disabled in Controlled Execution Gateway Phase 3 Stage 1")

    def fetch_receipt(self, provider_ref: str) -> Receipt:
        raise ProviderDenied("No provider receipts in Stage 1; live submit is disabled")

    def cancel(self, provider_ref: str) -> CancelResult:
        raise ProviderDenied("Cancel is unavailable until live submit exists; Stage 1 fail closed")


PROVIDERS: dict[str, type[ClosedProvider]] = {
    "email.send": ClosedProvider,
    "sms.send": ClosedProvider,
    "webhook.post": ClosedProvider,
    "document_release.release": ClosedProvider,
    "publication.publish": ClosedProvider,
    "internal.record_transition": ClosedProvider,
}


def get_provider(adapter: ExecutionAdapter, *, mode: str = "production", connection=None, tenant_id: str | None = None) -> ClosedProvider:
    """Production defaults to ClosedProvider. Pilot provider only when every Stage 4A gate passes."""
    if mode in {"production", "pilot", None}:
        if mode == "pilot" or connection is not None:
            from intelligence.execution_production_webhook import select_production_provider

            return select_production_provider(adapter, connection=connection, tenant_id=tenant_id)
        return ClosedProvider(adapter)
    cls = PROVIDERS.get(adapter.adapter_id, ClosedProvider)
    return cls(adapter)
