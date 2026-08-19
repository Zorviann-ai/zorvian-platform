"""Provider-neutral capability registry and deterministic model selection.

No vendor credentials or network calls live here. Adapters register capabilities and
Zorvian selects by business requirements, quality floor and availability.
"""
from dataclasses import dataclass
from typing import Iterable, FrozenSet


@dataclass(frozen=True)
class ProviderModel:
    provider: str
    model: str
    capabilities: FrozenSet[str]
    quality: int
    latency: int
    cost: int
    available: bool = True

    def validate(self):
        if not self.provider or not self.model:
            raise ValueError("Provider and model are required")
        for value in (self.quality, self.latency, self.cost):
            if value < 1 or value > 100:
                raise ValueError("Provider scores must be between 1 and 100")
        return self


@dataclass(frozen=True)
class ModelRequirement:
    capability: str
    minimum_quality: int = 75
    latency_weight: float = 0.20
    cost_weight: float = 0.10


def select_model(models: Iterable[ProviderModel], req: ModelRequirement) -> ProviderModel:
    candidates = []
    for model in models:
        model.validate()
        if model.available and req.capability in model.capabilities and model.quality >= req.minimum_quality:
            score = model.quality - model.latency * req.latency_weight - model.cost * req.cost_weight
            candidates.append((score, model.provider, model.model, model))
    if not candidates:
        raise LookupError("No approved model satisfies this capability requirement")
    candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
    return candidates[0][3]


@dataclass(frozen=True)
class ProviderProfile:
    """A server-side provider adapter profile used by connected intelligence."""
    name: str
    capabilities: FrozenSet[str]
    supports_tools: bool
    supports_retrieval: bool
    high_risk_approved: bool
    latency: int
    cost: int
    available: bool = True


@dataclass(frozen=True)
class ModelRequirements:
    capability: str
    needs_tools: bool = False
    needs_retrieval: bool = False
    high_risk: bool = False


class ProviderRegistry:
    def __init__(self, providers: Iterable[ProviderProfile]):
        self.providers = tuple(providers)

    def select(self, req: ModelRequirements) -> ProviderProfile:
        candidates = []
        for p in self.providers:
            if not p.available or req.capability not in p.capabilities:
                continue
            if req.needs_tools and not p.supports_tools:
                continue
            if req.needs_retrieval and not p.supports_retrieval:
                continue
            if req.high_risk and not p.high_risk_approved:
                continue
            # deterministic preference: lower latency, then lower cost, then name
            candidates.append((p.latency, p.cost, p.name, p))
        if not candidates:
            raise LookupError("No approved connected provider satisfies this request")
        candidates.sort(key=lambda x: (x[0], x[1], x[2]))
        return candidates[0][3]
