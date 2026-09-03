from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TenantKind(str, Enum):
    SCHOOL = "school"
    HOME = "home"
    TUTOR = "tutor"


class IsolationDenied(PermissionError):
    pass


@dataclass(frozen=True)
class EducationTenant:
    tenant_id: str
    kind: TenantKind
    name: str


@dataclass(frozen=True)
class StudentAccount:
    account_id: str
    tenant_id: str
    school_id: str | None
    household_id: str | None
    classroom_id: str | None
    display_name: str


@dataclass
class EducationDirectory:
    tenants: dict[str, EducationTenant] = field(default_factory=dict)
    students: dict[str, StudentAccount] = field(default_factory=dict)

    def add_tenant(self, tenant: EducationTenant) -> None:
        self.tenants[tenant.tenant_id] = tenant

    def add_student(self, student: StudentAccount) -> None:
        if student.tenant_id not in self.tenants:
            raise IsolationDenied("unknown education tenant")
        self.students[student.account_id] = student

    def get_student(self, *, actor_tenant_id: str, student_id: str) -> StudentAccount:
        student = self.students[student_id]
        if student.tenant_id != actor_tenant_id:
            raise IsolationDenied("cross-tenant student access is denied")
        return student

    def get_student_for_household(self, *, household_id: str, student_id: str) -> StudentAccount:
        student = self.students[student_id]
        if student.household_id != household_id:
            raise IsolationDenied("cross-family student access is denied")
        return student
