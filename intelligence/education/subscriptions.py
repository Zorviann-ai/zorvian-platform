from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EducationPlan(str, Enum):
    HOME = "home"
    SCHOOL = "school"
    TUTOR = "tutor"
    PREMIUM_HOLOGRAPHIC = "premium_holographic"


class LicenceScope(str, Enum):
    FAMILY = "family"
    PER_STUDENT = "per_student"
    PER_CLASSROOM = "per_classroom"
    SCHOOL_WIDE = "school_wide"


@dataclass(frozen=True)
class EducationSubscription:
    subscription_id: str
    tenant_id: str
    plan: EducationPlan
    licence_scope: LicenceScope
    seats: int
    active: bool
    payment_connected: bool = False


class SubscriptionRegistry:
    def __init__(self) -> None:
        self._items: dict[str, EducationSubscription] = {}

    def register(self, sub: EducationSubscription) -> EducationSubscription:
        if sub.payment_connected:
            raise PermissionError("education subscriptions cannot connect payment rails in Stage 1")
        self._items[sub.subscription_id] = sub
        return sub

    def charge(self, *_a, **_k) -> None:
        raise PermissionError("education billing is not connected")
