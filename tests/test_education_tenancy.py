import pytest
from intelligence.education.subscriptions import EducationPlan, EducationSubscription, LicenceScope, SubscriptionRegistry
from intelligence.education.tenancy import EducationDirectory, EducationTenant, IsolationDenied, StudentAccount, TenantKind


def test_school_and_family_isolation():
    d = EducationDirectory()
    d.add_tenant(EducationTenant("school-a", TenantKind.SCHOOL, "A"))
    d.add_tenant(EducationTenant("school-b", TenantKind.SCHOOL, "B"))
    d.add_tenant(EducationTenant("home-a", TenantKind.HOME, "Family A"))
    d.add_student(StudentAccount("stu-a", "school-a", "sch-a", None, "c1", "Ada"))
    d.add_student(StudentAccount("stu-b", "school-b", "sch-b", None, "c2", "Bea"))
    d.add_student(StudentAccount("kid-a", "home-a", None, "house-a", None, "Kid"))
    d.add_student(StudentAccount("kid-b", "home-a", None, "house-b", None, "Other"))
    assert d.get_student(actor_tenant_id="school-a", student_id="stu-a").display_name == "Ada"
    with pytest.raises(IsolationDenied):
        d.get_student(actor_tenant_id="school-a", student_id="stu-b")
    with pytest.raises(IsolationDenied):
        d.get_student_for_household(household_id="house-a", student_id="kid-b")


def test_subscription_has_no_payment_rail():
    r = SubscriptionRegistry()
    r.register(EducationSubscription("sub1", "home-a", EducationPlan.HOME, LicenceScope.FAMILY, 3, True, False))
    with pytest.raises(PermissionError):
        r.charge("sub1")
