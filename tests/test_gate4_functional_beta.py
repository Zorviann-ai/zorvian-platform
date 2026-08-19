from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOD = ROOT / "beta" / "modules"

PAGES = {
    "receptionist.html": "data-module=\"receptionist\"",
    "zai-auto.html": "data-module=\"auto\"",
    "freshx.html": "data-module=\"freshx\"",
    "tenders.html": "data-module=\"tenders\"",
    "leads.html": "data-module=\"leads\"",
    "document-studio.html": "data-module=\"documents\"",
    "business-control.html": "data-module=\"control\"",
    "route-intelligence.html": "data-module=\"route\"",
}


def test_all_functional_component_htmls_exist():
    for name, marker in PAGES.items():
        text = (MOD / name).read_text(encoding="utf-8")
        assert marker in text
        assert "demo.js" in text
        assert "Controlled Functional Beta" in text


def test_shared_demo_engine_covers_all_specialists_and_safety_boundaries():
    js = (MOD / "demo.js").read_text(encoding="utf-8")
    for key in ["receptionist", "auto", "freshx", "tenders", "leads", "documents", "control", "route"]:
        assert f"{key}:" in js
    for phrase in ["BLOCK", "human approval", "PREPARED ONLY"]:
        assert phrase in js


def test_beta_hub_links_every_component():
    html = (ROOT / "beta" / "index.html").read_text(encoding="utf-8")
    for name in PAGES:
        assert f"modules/{name}" in html


def test_connected_component_assets_keep_secrets_server_side_and_same_origin():
    text = "\n".join(p.read_text(encoding="utf-8") for p in MOD.glob("*") if p.is_file())
    forbidden = ["GUARDIAN_HASH_PEPPER=", "SMTP_PASSWORD=", "ZORVIAN_AI_ADAPTER_KEY", "sk-", "https://api.", "http://"]
    assert all(item not in text for item in forbidden)
    js = (MOD / "demo.js").read_text(encoding="utf-8")
    assert "fetch('/intelligence/run'" in js
    assert "sessionStorage" in js
