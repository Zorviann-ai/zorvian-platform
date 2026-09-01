"""In-process AI provider resilience state for the Celestial Core.

State is intentionally process-local in Fix 3: it resets on process restart. No
credentials or raw provider responses are stored here.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

FAILURE_THRESHOLD = 3
COOLDOWN_SECONDS = 60
MAX_RETRIES = 1
RETRY_SLEEP_SECONDS = 0.05


@dataclass
class ProviderHealth:
    state: str = "healthy"
    consecutive_failures: int = 0
    last_success_at: float | None = None
    last_failed_at: float | None = None
    cooldown_until: float | None = None
    last_failure_category: str | None = None


HEALTH: dict[str, ProviderHealth] = {}
EVENTS: list[dict] = []


def _event(name: str, provider: str | None = None, **extra):
    EVENTS.append({"event": name, "provider": provider, "at": time.time(), **extra})
    if len(EVENTS) > 1000:
        del EVENTS[:-1000]


def health(provider: str) -> ProviderHealth:
    return HEALTH.setdefault(provider, ProviderHealth())


def provider_ready(provider: str, now_ts: float | None = None) -> bool:
    now_ts = time.time() if now_ts is None else now_ts
    h = health(provider)
    if h.state != "cooldown":
        return True
    if h.cooldown_until is not None and now_ts >= h.cooldown_until:
        h.state = "degraded"
        h.cooldown_until = None
        _event("ai_provider_recovered", provider, reason="cooldown_expired")
        return True
    return False


def record_selected(provider: str, attempt: int):
    _event("ai_provider_selected", provider, attempt=attempt)


def record_retry(provider: str, attempt: int, category: str):
    _event("ai_provider_retry", provider, attempt=attempt, failure_category=category)


def record_failure(provider: str, category: str):
    h = health(provider)
    h.consecutive_failures += 1
    h.last_failed_at = time.time()
    h.last_failure_category = category
    h.state = "degraded"
    _event("ai_provider_failed", provider, failure_category=category, consecutive_failures=h.consecutive_failures)
    if h.consecutive_failures >= FAILURE_THRESHOLD:
        h.state = "cooldown"
        h.cooldown_until = time.time() + COOLDOWN_SECONDS
        _event("ai_provider_cooldown", provider, cooldown_until=h.cooldown_until)


def record_success(provider: str):
    h = health(provider)
    was_unhealthy = h.state != "healthy" or h.consecutive_failures > 0
    h.state = "healthy"
    h.consecutive_failures = 0
    h.last_success_at = time.time()
    h.cooldown_until = None
    h.last_failure_category = None
    if was_unhealthy:
        _event("ai_provider_recovered", provider, reason="successful_call")
    _event("ai_provider_success", provider)


def record_failover(previous: str, provider: str):
    _event("ai_provider_failover", provider, failover_from=previous)


def record_all_failed(providers: list[str]):
    _event("ai_all_providers_failed", None, providers=list(providers))


def classify_failure(exc: BaseException) -> tuple[str, bool]:
    text = str(exc).lower()
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return "transient", True
    if any(token in text for token in ("timeout", "timed out", "429", "502", "503", "504", "connection", "temporar", "rate limit")):
        return "transient", True
    if any(token in text for token in ("401", "403", "unauthorized", "forbidden", "invalid api key", "authentication", "permission", "validation", "no usable output", "empty output")):
        return "non_retryable", False
    return "provider_error", False


def status_snapshot(configured: list[str]) -> dict[str, dict]:
    result = {}
    for name in configured:
        h = health(name)
        provider_ready(name)
        result[name] = {
            "state": h.state,
            "consecutive_failures": h.consecutive_failures,
            "last_success_at": h.last_success_at,
            "last_failed_at": h.last_failed_at,
            "cooldown_until": h.cooldown_until,
            "last_failure_category": h.last_failure_category,
        }
    return result
