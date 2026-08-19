import pytest
from intelligence import ProviderModel, ModelRequirement, select_model


def test_selects_best_approved_model_for_capability():
    models = [
        ProviderModel("a", "fast", frozenset({"automotive"}), quality=82, latency=15, cost=40),
        ProviderModel("b", "deep", frozenset({"automotive"}), quality=94, latency=40, cost=60),
    ]
    picked = select_model(models, ModelRequirement("automotive", minimum_quality=80))
    assert picked.model == "deep"


def test_unavailable_model_is_not_selected():
    models = [
        ProviderModel("a", "offline", frozenset({"documents"}), quality=99, latency=5, cost=5, available=False),
        ProviderModel("b", "online", frozenset({"documents"}), quality=85, latency=20, cost=20),
    ]
    assert select_model(models, ModelRequirement("documents")).model == "online"


def test_quality_floor_is_enforced():
    with pytest.raises(LookupError):
        select_model([ProviderModel("a", "weak", frozenset({"contracts-tenders"}), quality=60, latency=10, cost=10)], ModelRequirement("contracts-tenders", minimum_quality=80))
