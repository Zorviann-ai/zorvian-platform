import pytest

from intelligence.context import WorkspaceContext
from intelligence.connected import ConnectedIntelligenceService, ConnectedRequest
from intelligence.providers import ProviderProfile, ProviderRegistry


def registry():
    return ProviderRegistry([
        ProviderProfile("provider-a", frozenset({"automotive", "communications", "fresh-produce", "contracts-tenders", "growth", "documents", "operations", "mobility"}), True, True, True, 10, 10),
        ProviderProfile("provider-b", frozenset({"general-business"}), False, False, False, 1, 1),
    ])


def executor(name, prompt, ctx):
    return {
        "task_id": "task-123",
        "output": f"Analysed by {name}: {prompt}",
        "confidence": 0.88,
        "source_refs": ("workspace://approved/test",),
        "assumptions": (),
    }


def test_connected_request_returns_provider_and_provenance():
    svc = ConnectedIntelligenceService(registry(), executor)
    ctx = WorkspaceContext("tenant-a", "user-a", "owner", "zai-auto")
    r = svc.run(ConnectedRequest("zai-auto", "compare", "Compare two vehicles", needs_retrieval=True), ctx)
    assert r.provider == "provider-a"
    assert r.capability == "automotive"
    assert r.confidence == 0.88
    assert r.provenance.has_evidence


def test_module_context_mismatch_is_blocked():
    svc = ConnectedIntelligenceService(registry(), executor)
    ctx = WorkspaceContext("tenant-a", "user-a", "owner", "freshx")
    with pytest.raises(PermissionError):
        svc.run(ConnectedRequest("zai-auto", "compare", "x"), ctx)


def test_unsupported_module_is_blocked():
    svc = ConnectedIntelligenceService(registry(), executor)
    ctx = WorkspaceContext("tenant-a", "user-a", "owner", "unknown")
    with pytest.raises(ValueError):
        svc.run(ConnectedRequest("unknown", "x", "x"), ctx)


def test_consequential_action_stays_human_gated():
    svc = ConnectedIntelligenceService(registry(), executor)
    ctx = WorkspaceContext("tenant-a", "user-a", "owner", "tenders")
    r = svc.run(ConnectedRequest("tenders", "submit", "Submit tender", needs_tools=True, consequential_action=True), ctx)
    assert r.human_approval_required is True
    assert r.tool_execution_allowed is False


def test_empty_provider_output_fails_closed():
    svc = ConnectedIntelligenceService(registry(), lambda *args: {"output": "", "confidence": 0.2, "task_id": "x"})
    ctx = WorkspaceContext("tenant-a", "user-a", "owner", "business-control")
    with pytest.raises(RuntimeError):
        svc.run(ConnectedRequest("business-control", "prioritise", "x"), ctx)
