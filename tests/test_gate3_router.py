from intelligence import IntelligenceRequest, Risk, route


def test_specialist_routing():
    assert route(IntelligenceRequest(module="zai-auto", task="compare vehicles")).capability == "automotive"
    assert route(IntelligenceRequest(module="freshx", task="assess opportunity")).capability == "fresh-produce"
    assert route(IntelligenceRequest(module="tenders", task="analyse tender")).capability == "contracts-tenders"


def test_retrieval_requires_provenance():
    d = route(IntelligenceRequest(module="tenders", task="research requirement", needs_retrieval=True))
    assert d.provenance_required is True
    assert d.risk == Risk.LOW


def test_consequential_action_always_requires_human_approval():
    d = route(IntelligenceRequest(module="zai-auto", task="commit order", needs_tools=True, consequential_action=True, requested_by_role="owner"))
    assert d.risk == Risk.HIGH
    assert d.human_approval_required is True
    assert d.tool_execution_allowed is False


def test_staff_tool_request_is_gated():
    d = route(IntelligenceRequest(module="business-control", task="send external message", needs_tools=True, requested_by_role="staff"))
    assert d.human_approval_required is True
    assert d.tool_execution_allowed is False


def test_authorised_non_consequential_tool_use_can_execute():
    d = route(IntelligenceRequest(module="business-control", task="read permitted integration", needs_tools=True, requested_by_role="owner"))
    assert d.human_approval_required is False
    assert d.tool_execution_allowed is True
