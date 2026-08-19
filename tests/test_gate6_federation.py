import pytest
from intelligence.federation import ProviderProfile, FederatedTask, FederationError, select, execute


def providers():
    return [
        ProviderProfile("alpha", frozenset({"reasoning", "documents"}), .95, .35, .55),
        ProviderProfile("beta", frozenset({"reasoning", "documents"}), .90, .20, .25),
        ProviderProfile("vision", frozenset({"vision"}), .96, .40, .60),
    ]


def test_quality_first_selection():
    d = select(FederatedTask("reasoning"), providers())
    assert d.primary == "alpha"
    assert d.verifier is None


def test_high_stakes_uses_independent_verifier():
    d = select(FederatedTask("documents", high_stakes=True), providers())
    assert d.primary != d.verifier
    assert d.verifier is not None


def test_unsupported_capability_fails_closed():
    with pytest.raises(FederationError):
        select(FederatedTask("audio"), providers())


def test_disabled_provider_not_selected():
    ps = [ProviderProfile("best", frozenset({"reasoning"}), 1, 0, 0, enabled=False), ProviderProfile("safe", frozenset({"reasoning"}), .8, .4, .4)]
    assert select(FederatedTask("reasoning"), ps).primary == "safe"


def test_execute_runs_primary_and_verifier_for_high_stakes():
    calls = []
    adapters = {"alpha": lambda p: calls.append(("alpha", p)) or "answer", "beta": lambda p: calls.append(("beta", p)) or "verified"}
    out = execute(FederatedTask("reasoning", high_stakes=True), providers(), adapters, "task")
    assert out["output"] == "answer"
    assert out["verification"] == "verified"
    assert [x[0] for x in calls] == ["alpha", "beta"]


def test_missing_adapter_fails_closed():
    with pytest.raises(FederationError):
        execute(FederatedTask("reasoning"), providers(), {}, "task")
