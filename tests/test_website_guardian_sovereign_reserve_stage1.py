from decimal import Decimal

import pytest

from intelligence.website_guardian import (
    FindingSeverity,
    GuardianMode,
    ManagedWebsite,
    WebsiteClient,
    WebsiteFinding,
    WebsiteGuardian,
)
from intelligence.sovereign_reserve import ProposalStatus, SovereignReserve


def guardian():
    client = WebsiteClient(client_id="c1", name="Caelomere", subscription_active=True)
    site = ManagedWebsite(
        website_id="w1",
        client_id="c1",
        base_url="https://caelomere.com",
        mode=GuardianMode.MONITOR,
        approved_domains=("www.caelomere.com",),
    )
    return WebsiteGuardian([client], [site])


def test_guardian_only_scans_approved_domains():
    g = guardian()
    assert g.validate_scan_urls("w1", ["https://caelomere.com/about"]) == (
        "https://caelomere.com/about",
    )
    with pytest.raises(PermissionError):
        g.validate_scan_urls("w1", ["https://example.com/"])


def test_guardian_subscription_is_required():
    client = WebsiteClient(client_id="c1", name="Client", subscription_active=False)
    site = ManagedWebsite(website_id="w1", client_id="c1", base_url="https://example.com")
    g = WebsiteGuardian([client], [site])
    with pytest.raises(PermissionError):
        g.get_website("w1")


def test_stage1_report_is_read_only_and_fix_is_proposal_only():
    g = guardian()
    finding = WebsiteFinding(
        website_id="w1",
        url="https://caelomere.com/about",
        issue="missing meta description",
        severity=FindingSeverity.ATTENTION,
        evidence="meta[name=description] absent",
        recommendation="Add an accurate page description",
        auto_fix_eligible=True,
    )
    report = g.make_report("w1", [finding.url], [finding])
    assert report.health == "ATTENTION"
    assert report.external_changes_made is False
    proposal = g.propose_fix(finding)
    assert proposal.requires_human_approval is True
    assert proposal.executable is False
    with pytest.raises(PermissionError):
        g.publish(proposal)


def test_reserve_records_revenue_but_cannot_move_money():
    reserve = SovereignReserve()
    entry = reserve.record_revenue(
        amount="250.00",
        currency="gbp",
        source="website_guardian_subscription",
        reference="invoice-1001",
    )
    assert entry.amount == Decimal("250.00")
    assert reserve.balance("GBP") == Decimal("250.00")
    with pytest.raises(PermissionError):
        reserve.move_money("bank", "reserve")
    with pytest.raises(PermissionError):
        reserve.purchase("hosting")


def test_ai_can_propose_reinvestment_but_human_identity_must_approve():
    reserve = SovereignReserve()
    reserve.record_revenue(
        amount="500.00",
        currency="GBP",
        source="website_guardian_subscription",
        reference="invoice-1002",
    )
    proposal = reserve.propose_reinvestment(
        amount="100.00",
        currency="GBP",
        purpose="increase test compute capacity",
        rationale="CI queue is delaying controlled validation",
        requested_by="celestial-core",
    )
    assert proposal.status is ProposalStatus.PROPOSED
    approved = reserve.approve_proposal(proposal.proposal_id, approved_by="human-owner")
    assert approved.status is ProposalStatus.APPROVED
    assert approved.approved_by == "human-owner"
    assert reserve.balance("GBP") == Decimal("500.00")


def test_proposal_cannot_exceed_recorded_reserve():
    reserve = SovereignReserve()
    reserve.record_revenue(
        amount="50.00",
        currency="GBP",
        source="website_guardian_subscription",
        reference="invoice-1003",
    )
    with pytest.raises(ValueError):
        reserve.propose_reinvestment(
            amount="75.00",
            currency="GBP",
            purpose="compute",
            rationale="requested",
            requested_by="celestial-core",
        )
