from intelligence.connected import ConnectedIntelligenceService, ConnectedRequest, SUPPORTED_MODULES
from intelligence.context import WorkspaceContext
from intelligence.executor import SPECIALIST_INSTRUCTIONS
from intelligence.providers import ProviderProfile, ProviderRegistry
from intelligence.router import SPECIALISTS


PORTAL_MODULES = {
    "receptionist", "executive-assistant", "calendar-bookings", "reservations",
    "lead-intelligence", "social-ai", "marketing", "sales-quotes",
    "customer-support", "tasks-workflow", "business-intelligence",
    "route-intelligence", "freight-control", "document-studio", "tenders",
    "document-proof", "robotics", "video-ai", "legal-pathways",
    "finance-pathways", "freshx", "mailbox-communications", "guardian-security",
}


def test_every_portal_module_has_routing_and_specialist_instructions():
    assert PORTAL_MODULES <= SUPPORTED_MODULES
    assert PORTAL_MODULES <= set(SPECIALISTS)
    assert PORTAL_MODULES <= set(SPECIALIST_INSTRUCTIONS)


def test_connected_service_fails_over_to_next_approved_provider():
    capability = SPECIALISTS["executive-assistant"]
    registry = ProviderRegistry([
        ProviderProfile("primary", frozenset({capability}), True, True, True, 1, 1),
        ProviderProfile("secondary", frozenset({capability}), True, True, True, 2, 2),
    ])

    def executor(provider, prompt, ctx):
        if provider == "primary":
            raise RuntimeError("temporary failure")
        return {"task_id": "ok", "output": "Prepared", "confidence": 0.9}

    service = ConnectedIntelligenceService(registry, executor)
    result = service.run(
        ConnectedRequest("executive-assistant", "Prepare work", "Confirmed facts"),
        WorkspaceContext("tenant", "user", "owner", "executive-assistant"),
    )
    assert result.provider == "secondary"
    assert result.output == "Prepared"
