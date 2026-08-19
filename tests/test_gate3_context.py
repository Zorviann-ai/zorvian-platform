import pytest
from intelligence import WorkspaceContext


def test_context_requires_tenant_and_user():
    with pytest.raises(ValueError):
        WorkspaceContext(tenant_id="", user_id="u1", role="owner", module="freshx").validate()


def test_audit_projection_does_not_dump_evidence_content():
    c = WorkspaceContext(tenant_id="t1", user_id="u1", role="owner", module="tenders", evidence=("private evidence text",), facts={"region":"UK"})
    audit = c.for_audit()
    assert audit["tenant_id"] == "t1"
    assert audit["evidence_count"] == 1
    assert "private evidence text" not in str(audit)


def test_context_is_bounded():
    with pytest.raises(ValueError):
        WorkspaceContext(tenant_id="t1", user_id="u1", role="owner", module="freshx", evidence=tuple(str(i) for i in range(101))).validate()
