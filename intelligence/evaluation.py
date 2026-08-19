"""Deterministic scoring primitives for Zorvian human/automated evaluations."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Evaluation:
    accuracy: int
    usefulness: int
    clarity: int
    speed: int
    unsupported_assumption: bool = False
    approval_failure: bool = False

    def validate(self):
        for value in (self.accuracy, self.usefulness, self.clarity, self.speed):
            if value < 1 or value > 5:
                raise ValueError("Evaluation scores must be between 1 and 5")
        return self

    @property
    def quality_score(self) -> float:
        self.validate()
        base = (self.accuracy * 0.4 + self.usefulness * 0.3 + self.clarity * 0.2 + self.speed * 0.1) * 20
        penalty = (25 if self.unsupported_assumption else 0) + (40 if self.approval_failure else 0)
        return round(max(0.0, base - penalty), 1)

    @property
    def passes(self) -> bool:
        return self.quality_score >= 80 and not self.unsupported_assumption and not self.approval_failure
