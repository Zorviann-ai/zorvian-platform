"""Tenant-bounded context envelope used by Zorvian intelligence calls."""
from dataclasses import dataclass, field
from typing import Mapping, Sequence


@dataclass(frozen=True)
class WorkspaceContext:
    tenant_id: str
    user_id: str
    role: str
    module: str
    instructions: Sequence[str] = field(default_factory=tuple)
    evidence: Sequence[str] = field(default_factory=tuple)
    facts: Mapping[str, str] = field(default_factory=dict)

    def validate(self):
        if not self.tenant_id or not self.user_id:
            raise ValueError("Tenant and user identity are required")
        if len(self.instructions) > 50 or len(self.evidence) > 100:
            raise ValueError("Context envelope exceeds bounded limits")
        return self

    def for_audit(self) -> dict:
        self.validate()
        return {
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "role": self.role,
            "module": self.module,
            "instruction_count": len(self.instructions),
            "evidence_count": len(self.evidence),
            "fact_keys": sorted(self.facts.keys()),
        }
