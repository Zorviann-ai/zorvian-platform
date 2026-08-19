from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_beta_assets_contain_no_obvious_secret_material():
    text = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "beta").glob("*") if p.is_file())
    forbidden = ["sk-", "GUARDIAN_HASH_PEPPER=", "SMTP_PASSWORD=", "Authorization: Bearer"]
    assert all(item not in text for item in forbidden)


def test_feedback_is_local_not_remote_submission():
    html = (ROOT / "beta" / "feedback.html").read_text(encoding="utf-8")
    assert "event.preventDefault()" in html
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html


def test_beta_discloses_controlled_status_and_review_boundary():
    hub = (ROOT / "beta" / "index.html").read_text(encoding="utf-8")
    brief = (ROOT / "beta" / "TESTER_BRIEF.md").read_text(encoding="utf-8")
    assert "Controlled Beta" in hub
    assert "human review" in hub
    assert "human-reviewed" in brief
