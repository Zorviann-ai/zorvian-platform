from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Iterable
import uuid


class ReserveEntryType(str, Enum):
    REVENUE = "revenue"
    ALLOCATION = "allocation"
    ADJUSTMENT = "adjustment"


class ProposalStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ReserveEntry:
    entry_id: str
    created_at: datetime
    entry_type: ReserveEntryType
    amount: Decimal
    currency: str
    source: str
    reference: str
    note: str = ""


@dataclass(frozen=True)
class ReinvestmentProposal:
    proposal_id: str
    created_at: datetime
    amount: Decimal
    currency: str
    purpose: str
    rationale: str
    requested_by: str
    status: ProposalStatus = ProposalStatus.PROPOSED
    approved_by: str | None = None


class SovereignReserve:
    """Internal accounting ledger only. It cannot access banks, cards or payment rails."""

    def __init__(self, entries: Iterable[ReserveEntry] = ()):
        self._entries = list(entries)
        self._proposals: dict[str, ReinvestmentProposal] = {}

    @property
    def entries(self) -> tuple[ReserveEntry, ...]:
        return tuple(self._entries)

    def record_revenue(
        self,
        *,
        amount: Decimal | str,
        currency: str,
        source: str,
        reference: str,
        note: str = "",
    ) -> ReserveEntry:
        value = Decimal(amount)
        if value <= 0:
            raise ValueError("revenue amount must be positive")
        entry = ReserveEntry(
            entry_id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            entry_type=ReserveEntryType.REVENUE,
            amount=value,
            currency=currency.upper(),
            source=source,
            reference=reference,
            note=note,
        )
        self._entries.append(entry)
        return entry

    def balance(self, currency: str) -> Decimal:
        target = currency.upper()
        return sum((entry.amount for entry in self._entries if entry.currency == target), Decimal("0"))

    def propose_reinvestment(
        self,
        *,
        amount: Decimal | str,
        currency: str,
        purpose: str,
        rationale: str,
        requested_by: str,
    ) -> ReinvestmentProposal:
        value = Decimal(amount)
        if value <= 0:
            raise ValueError("proposal amount must be positive")
        if value > self.balance(currency):
            raise ValueError("proposal exceeds recorded reserve balance")
        proposal = ReinvestmentProposal(
            proposal_id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            amount=value,
            currency=currency.upper(),
            purpose=purpose,
            rationale=rationale,
            requested_by=requested_by,
        )
        self._proposals[proposal.proposal_id] = proposal
        return proposal

    def approve_proposal(self, proposal_id: str, *, approved_by: str) -> ReinvestmentProposal:
        current = self._proposals[proposal_id]
        if current.status is not ProposalStatus.PROPOSED:
            raise ValueError("proposal is no longer pending")
        approved = ReinvestmentProposal(
            proposal_id=current.proposal_id,
            created_at=current.created_at,
            amount=current.amount,
            currency=current.currency,
            purpose=current.purpose,
            rationale=current.rationale,
            requested_by=current.requested_by,
            status=ProposalStatus.APPROVED,
            approved_by=approved_by,
        )
        self._proposals[proposal_id] = approved
        return approved

    def move_money(self, *_args, **_kwargs):
        raise PermissionError("Sovereign Reserve cannot move money; external financial execution is not implemented")

    def purchase(self, *_args, **_kwargs):
        raise PermissionError("Sovereign Reserve cannot purchase services or spend funds")
