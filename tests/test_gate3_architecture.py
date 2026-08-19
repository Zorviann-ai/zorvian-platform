from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_gate3_spec_exists_and_defines_core_layers():
    text = (ROOT / "GATE3_INTELLIGENCE.md").read_text(encoding="utf-8")
    for required in [
        "Zorvian Core", "Guardian", "Intelligence Router", "Workspace Context",
        "Specialist Agents", "Action Engine", "Evidence & Provenance", "Evaluation Layer"
    ]:
        assert required in text


def test_zai_auto_is_public_name_and_little_sis_is_private_persona():
    text = (ROOT / "GATE3_INTELLIGENCE.md").read_text(encoding="utf-8")
    assert "Zorvian Auto Intelligence (ZAI Auto)" in text
    assert "Little Sis" in text
    assert "private named agent/persona" in text


def test_beta_hub_exposes_required_controlled_modules():
    html = (ROOT / "beta" / "index.html").read_text(encoding="utf-8")
    for module in [
        "AI Receptionist", "ZAI Auto", "FreshX", "Contract & Tender Intelligence",
        "Lead Intelligence", "Document Studio", "Business Control", "Route Intelligence"
    ]:
        assert module in html
    assert "no confidential" in html
    assert "human review" in html


def test_gate3_spec_requires_quality_and_approval_controls():
    text = (ROOT / "GATE3_INTELLIGENCE.md").read_text(encoding="utf-8")
    for required in [
        "tenant isolation", "prompt-injection resistance", "hallucination resistance",
        "approval enforcement", "auditability", "human approval"
    ]:
        assert required in text
