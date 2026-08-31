import json

from intelligence import executor


class Context:
    module = "tenders"

    def for_audit(self):
        return {"module": self.module}


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps({"id": "ox-task-1", "choices": [{"message": {"content": "Controlled analysis"}}]}).encode()


def test_ox_adapter_uses_server_key_and_expected_model(monkeypatch):
    captured = {}
    monkeypatch.setenv("OPENROUTER_API_KEY", "server-secret")

    def fake_open(req, timeout):
        captured["request"] = req
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(executor.urllib.request, "urlopen", fake_open)
    result = executor.execute_provider("ox-alpha", "Analyse this tender", Context())
    body = json.loads(captured["request"].data)
    assert body["model"] == "stealth/ox-alpha"
    assert captured["request"].get_header("Authorization") == "Bearer server-secret"
    assert result["output"] == "Controlled analysis"
    assert result["task_id"] == "ox-task-1"


def test_ox_adapter_fails_closed_without_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    try:
        executor.execute_provider("ox-alpha", "Analyse", Context())
    except RuntimeError as exc:
        assert "not configured" in str(exc)
    else:
        raise AssertionError("Expected missing-key failure")
