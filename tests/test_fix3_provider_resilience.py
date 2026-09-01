import time

import pytest

from intelligence.connected import ConnectedIntelligenceService, ConnectedRequest
from intelligence.context import WorkspaceContext
from intelligence.providers import ProviderProfile, ProviderRegistry
from intelligence.resilience import (
    COOLDOWN_SECONDS,
    FAILURE_THRESHOLD,
    HEALTH,
    EVENTS,
    health,
    provider_ready,
    record_failure,
    record_success,
)

CAP = frozenset({"analytics"})


def _profile(name, latency):
    return ProviderProfile(name, CAP, True, True, True, latency, 1, True)


def _ctx():
    return WorkspaceContext(tenant_id="t1", user_id="u1", role="admin", module="business-intelligence", instructions=("test",))


def _req(consequential=False):
    return ConnectedRequest(module="business-intelligence", task="analyse", prompt="hello", consequential_action=consequential)


def setup_function():
    HEALTH.clear()
    EVENTS.clear()


def test_primary_success():
    calls = []
    svc = ConnectedIntelligenceService(ProviderRegistry([_profile("p1", 1), _profile("p2", 2)]), lambda name, prompt, ctx: calls.append(name) or {"output":"ok","confidence":.9})
    result = svc.run(_req(), _ctx())
    assert result.provider == "p1"
    assert result.failover_from is None
    assert calls == ["p1"]


def test_primary_retry_then_success():
    calls = []
    def executor(name, prompt, ctx):
        calls.append(name)
        if len(calls) == 1:
            raise RuntimeError("timeout")
        return {"output":"ok","confidence":.9}
    svc = ConnectedIntelligenceService(ProviderRegistry([_profile("p1", 1)]), executor)
    result = svc.run(_req(), _ctx())
    assert result.provider == "p1"
    assert calls == ["p1", "p1"]
    assert any(e["event"] == "ai_provider_retry" for e in EVENTS)


def test_primary_fails_secondary_succeeds():
    calls = []
    def executor(name, prompt, ctx):
        calls.append(name)
        if name == "p1":
            raise RuntimeError("timeout")
        return {"output":"secondary","confidence":.9}
    svc = ConnectedIntelligenceService(ProviderRegistry([_profile("p1", 1), _profile("p2", 2)]), executor)
    result = svc.run(_req(), _ctx())
    assert result.provider == "p2"
    assert result.failover_from == "p1"
    assert calls == ["p1", "p1", "p2"]
    assert any(e["event"] == "ai_provider_failover" for e in EVENTS)


def test_all_fail_is_runtime_error():
    svc = ConnectedIntelligenceService(ProviderRegistry([_profile("p1", 1), _profile("p2", 2)]), lambda *args: (_ for _ in ()).throw(RuntimeError("timeout")))
    with pytest.raises(RuntimeError):
        svc.run(_req(), _ctx())
    assert any(e["event"] == "ai_all_providers_failed" for e in EVENTS)


def test_circuit_breaker_enters_cooldown_and_recovers():
    for _ in range(FAILURE_THRESHOLD):
        record_failure("p1", "transient")
    h = health("p1")
    assert h.state == "cooldown"
    assert provider_ready("p1") is False
    h.cooldown_until = time.time() - 1
    assert provider_ready("p1") is True
    assert h.state == "degraded"
    record_success("p1")
    assert h.state == "healthy"
    assert h.consecutive_failures == 0


def test_cooldown_provider_is_skipped_for_healthy_alternative():
    for _ in range(FAILURE_THRESHOLD):
        record_failure("p1", "transient")
    calls = []
    svc = ConnectedIntelligenceService(ProviderRegistry([_profile("p1", 1), _profile("p2", 2)]), lambda name, prompt, ctx: calls.append(name) or {"output":"ok","confidence":.9})
    result = svc.run(_req(), _ctx())
    assert result.provider == "p2"
    assert calls == ["p2"]


def test_non_retryable_error_fails_over_without_retry():
    calls = []
    def executor(name, prompt, ctx):
        calls.append(name)
        if name == "p1":
            raise RuntimeError("401 invalid api key")
        return {"output":"ok","confidence":.9}
    svc = ConnectedIntelligenceService(ProviderRegistry([_profile("p1", 1), _profile("p2", 2)]), executor)
    result = svc.run(_req(), _ctx())
    assert result.provider == "p2"
    assert calls == ["p1", "p2"]


def test_consequential_request_never_retries_or_fails_over():
    calls = []
    def executor(name, prompt, ctx):
        calls.append(name)
        raise RuntimeError("timeout")
    svc = ConnectedIntelligenceService(ProviderRegistry([_profile("p1", 1), _profile("p2", 2)]), executor)
    with pytest.raises(RuntimeError):
        svc.run(_req(consequential=True), _ctx())
    assert calls == ["p1"]
