"""Minimal provenance contract for auditable Zorvian intelligence outputs."""
from dataclasses import dataclass, field
from typing import Sequence


@dataclass(frozen=True)
class ProvenanceRecord:
    module: str
    task_id: str
    source_refs: Sequence[str] = field(default_factory=tuple)
    assumptions: Sequence[str] = field(default_factory=tuple)
    confidence: float = 0.0

    def validate(self):
        if not self.module or not self.task_id:
            raise ValueError("Module and task ID are required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0 and 1")
        return self

    @property
    def has_evidence(self) -> bool:
        return bool(self.source_refs)

    @property
    def needs_review(self) -> bool:
        self.validate()
        return self.confidence < 0.75 or bool(self.assumptions)
