"""Zorvian Gate 6 model federation.

Zorvian owns routing policy. Providers are interchangeable capability engines.
No provider secret is exposed to browser clients.
"""
from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    capabilities: frozenset[str]
    quality: float
    latency: float
    cost: float
    enabled: bool = True


@dataclass(frozen=True)
class FederatedTask:
    capability: str
    high_stakes: bool = False
    needs_long_context: bool = False
    needs_vision: bool = False


@dataclass(frozen=True)
class FederationDecision:
    primary: str
    verifier: str | None
    candidates: tuple[str, ...]
    reason: str


class FederationError(RuntimeError):
    pass


def _score(p: ProviderProfile, task: FederatedTask) -> float:
    if not p.enabled or task.capability not in p.capabilities:
        return -1.0
    # Quality dominates; latency/cost are optimisation terms, not intelligence policy.
    return (p.quality * 0.72) + ((1.0 - p.latency) * 0.18) + ((1.0 - p.cost) * 0.10)


def select(task: FederatedTask, providers: Sequence[ProviderProfile]) -> FederationDecision:
    ranked = sorted(((p, _score(p, task)) for p in providers), key=lambda x: x[1], reverse=True)
    eligible = [p for p, score in ranked if score >= 0]
    if not eligible:
        raise FederationError(f"No enabled provider supports capability: {task.capability}")
    primary = eligible[0]
    verifier = eligible[1].name if task.high_stakes and len(eligible) > 1 else None
    return FederationDecision(
        primary=primary.name,
        verifier=verifier,
        candidates=tuple(p.name for p in eligible),
        reason="quality-first federation; independent verification for high-stakes tasks" if verifier else "quality-first federation",
    )


def execute(
    task: FederatedTask,
    providers: Sequence[ProviderProfile],
    adapters: Mapping[str, Callable[[str], str]],
    prompt: str,
) -> dict:
    decision = select(task, providers)
    primary_adapter = adapters.get(decision.primary)
    if not primary_adapter:
        raise FederationError(f"Provider adapter unavailable: {decision.primary}")
    primary_output = primary_adapter(prompt)
    if not primary_output or not primary_output.strip():
        raise FederationError("Primary provider returned empty output")
    result = {"decision": decision, "output": primary_output, "verification": None}
    if decision.verifier:
        verifier_adapter = adapters.get(decision.verifier)
        if not verifier_adapter:
            raise FederationError(f"Verifier adapter unavailable: {decision.verifier}")
        verification_prompt = "Independently verify this answer. Identify unsupported claims, contradictions and material omissions.\n\n" + primary_output
        verification = verifier_adapter(verification_prompt)
        if not verification or not verification.strip():
            raise FederationError("Verifier returned empty output")
        result["verification"] = verification
    return result
