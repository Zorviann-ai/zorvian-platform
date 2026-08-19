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
