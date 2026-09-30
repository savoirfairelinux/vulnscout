import json
import os
import queue
import threading
import time
from types import SimpleNamespace

import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_AGENT_ENABLED", "1")
    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", str(tmp_path / "missing_server.py"))
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    from src.bin.webapp import create_app

    app = create_app()
    app.config.update(TESTING=True, SCAN_FILE=str(scan_file))
    return app.test_client()


def test_agent_is_opt_in(client, monkeypatch):
    monkeypatch.delenv("VULNSCOUT_AGENT_ENABLED")
    response = client.get("/api/agent")
    assert response.status_code == 404


def test_agent_rejects_remote_requests(client):
    response = client.get("/api/agent", environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
    assert response.status_code == 403


def test_agent_accepts_configured_trusted_client(client, monkeypatch):
    monkeypatch.setenv("VULNSCOUT_AGENT_TRUSTED_CLIENTS", "172.17.0.1, ")
    response = client.delete("/api/agent/conversation", environ_overrides={"REMOTE_ADDR": "172.17.0.1"})
    assert response.status_code == 200
    response = client.get("/api/agent", environ_overrides={"REMOTE_ADDR": "172.17.0.2"})
    assert response.status_code == 403


def test_agent_rejects_non_local_host(client):
    response = client.get("/api/agent", headers={"Host": "example.org"})
    assert response.status_code == 403
    response = client.delete("/api/agent/conversation", headers={"Host": "[::1]:7275"})
    assert response.status_code == 200


def test_agent_rejects_foreign_origin(client):
    response = client.post("/api/agent/messages", json={"message": "Hello"},
                           headers={"Origin": "https://example.org"})
    assert response.status_code == 403


def test_message_requires_text_and_configured_mcp(client):
    assert client.post("/api/agent/messages", json=["Hello"]).status_code == 400
    assert client.post("/api/agent/messages", json={"message": ""}).status_code == 400
    assert client.post("/api/agent/messages", json={"message": "Hello", "allow_writes": "yes"}).status_code == 400
    response = client.post("/api/agent/messages", json={"message": "Hello"})
    assert response.status_code == 503
    assert "VULNSCOUT_MCP_SERVER_PATH" in response.get_json()["error"]
    assert response.headers["Cache-Control"] == "no-store"


def test_context_rejects_malformed_and_unbounded_rows(client):
    for context in ({"page": "invalid"}, {"page": "vulnerabilities", "view": {"visibleVulnerabilityIds": ["CVE-1"] * 101}},
                    {"page": "review", "view": {"visibleCount": -1}}):
        response = client.post("/api/agent/messages", json={"message": "Assess", "context": context})
        assert response.status_code == 400


def test_page_selections_pass_validation_before_mcp_setup(client):
    context = {"page": "scans", "projectId": "project", "view": {
        "section": "scan history", "visibleScanIds": ["scan-id"],
        "selectedScanTypes": ["grype"], "selectedRefreshTypes": ["nvd"],
        "refreshMode": "custom", "hideEmptyScans": False,
        "excludeKernel": True, "excludeNative": True,
    }}
    response = client.post("/api/agent/messages", json={"message": "Review scans", "context": context})
    assert response.status_code == 503
    assert "VULNSCOUT_MCP_SERVER_PATH" in response.get_json()["error"]


def test_large_project_scope_uses_count_without_partial_ids(client):
    response = client.post("/api/agent/messages", json={
        "message": "Summarize", "context": {"page": "ai", "variantCount": 85, "view": {
            "selectedProjectName": "AgentDemo", "selectedVariantName": "Sample",
            "exportCategory": "all", "enabledExportDocuments": ["spdx2"],
        }},
    })
    assert response.status_code == 503
    assert "VULNSCOUT_MCP_SERVER_PATH" in response.get_json()["error"]
    invalid = client.post("/api/agent/messages", json={
        "message": "Summarize", "context": {"page": "ai", "variantCount": -1},
    })
    assert invalid.status_code == 400


def test_new_conversation_does_not_clear_authentication(client):
    result = client.delete("/api/agent/conversation").get_json()
    assert result["messages"] == []
    assert result["usage"]["cost"] is None


def test_device_login_without_client_id(client, monkeypatch):
    monkeypatch.delenv("VULNSCOUT_AGENT_GITHUB_CLIENT_ID", raising=False)
    assert client.get("/api/agent").get_json()["device_login"] is True
    assert client.post("/api/agent/auth/poll").status_code == 410
    response = client.post("/api/agent/auth")
    assert response.status_code == 200
    result = response.get_json()
    assert result["user_code"]
    assert result["verification_uri"] == "https://github.com/login/device"
    assert result["interval"] > 0
    assert "device_code" not in result
    assert "access_token" not in result
    response = client.post("/api/agent/auth/poll")
    assert response.status_code == 200
    assert response.get_json()["status"] == "pending"


def test_device_login_reports_unknown_github_client(client, monkeypatch):
    monkeypatch.setenv("VULNSCOUT_AGENT_GITHUB_CLIENT_ID", "Iv1.0000000000000000")
    assert client.get("/api/agent").get_json()["device_login"] is True
    response = client.post("/api/agent/auth")
    assert response.status_code == 503
    assert "device flow" in response.get_json()["error"]
    assert client.get("/api/agent").get_json()["token_connected"] is False


def test_status_uses_real_copilot_runtime(client):
    response = client.get("/api/agent")
    assert response.status_code == 200
    assert response.get_json()["configured"] is False
    assert isinstance(response.get_json()["authenticated"], bool)
    assert response.get_json()["token_connected"] is False
    assert response.get_json()["messages"] == []
    assert response.headers["Set-Cookie"].startswith("vulnscout_agent=")


def test_bundled_mcp_is_configured_by_default(client, monkeypatch):
    monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH")
    assert client.get("/api/agent").get_json()["configured"] is True


def test_unknown_route_context_is_supported(client):
    response = client.post("/api/agent/messages", json={"message": "Help", "context": {"page": "unknown"}})
    assert response.status_code == 503
    assert "Bundled MCP server" in response.get_json()["error"]


def test_models_use_signed_in_account(client):
    authenticated = client.get("/api/agent").get_json()["authenticated"]
    response = client.get("/api/agent/models")
    if authenticated:
        assert response.status_code == 200
        assert any(model["id"] == "auto" for model in response.get_json()["models"])
    else:
        assert response.status_code == 503
        assert response.get_json() == {"error": "Unable to load available Copilot models."}


def test_selected_model_persists_without_sending(client):
    authenticated = client.get("/api/agent").get_json()["authenticated"]
    response = client.post("/api/agent/model", json={"model": "nonexistent-model"})
    assert response.status_code == (400 if authenticated else 503)
    response = client.post("/api/agent/model", json={"model": "auto"})
    if authenticated:
        assert response.get_json()["model"] == "auto"
    else:
        assert response.status_code == 503
        assert response.get_json() == {"error": "Unable to verify this Copilot model."}
    assert client.get("/api/agent").get_json()["model"] == "auto"


def test_streaming_validation_still_returns_json(client):
    response = client.post("/api/agent/messages", json={"message": ""},
                           headers={"Accept": "application/x-ndjson"})
    assert response.status_code == 400
    assert response.is_json


def test_live_streaming_reply_and_conversation_lock(client, monkeypatch):
    if os.getenv("VULNSCOUT_TEST_MCP_SERVER_PATH"):
        monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", os.environ["VULNSCOUT_TEST_MCP_SERVER_PATH"])
    else:
        monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH")
    authenticated = client.get("/api/agent").get_json()["authenticated"]
    response = client.post("/api/agent/messages", json={
        "message": "Use get_vulnerability to retrieve CVE-2009-3555 and summarize it in one sentence. Do not make changes.",
        "allow_writes": False,
    }, headers={"Accept": "application/x-ndjson"}, buffered=False)
    try:
        assert response.status_code == 200
        assert response.mimetype == "application/x-ndjson"
        assert response.headers["X-Accel-Buffering"] == "no"
        assert response.headers["Cache-Control"] == "no-store"
        assert client.post("/api/agent/messages", json={"message": "Another request"}).status_code == 409
        events = [json.loads(chunk) for chunk in response.response]
        assert events[0]["type"] == "status"
        status = client.get("/api/agent").get_json()
        if authenticated:
            assert events[-1]["type"] == "done", events[-1]
            assert any(event["type"] == "delta" and event["text"] for event in events)
            assert any(event["type"] == "tool_start" for event in events)
            assert any(event["type"] == "tool_end" for event in events)
            assert {event["type"] for event in events} <= {"status", "heartbeat", "delta", "tool_start", "tool_end", "done"}
            assert status["messages"][-1]["content"] == events[-1]["reply"]
            assert status["usage"] == events[-1]["usage"]
        else:
            assert events[-1]["type"] == "error"
            assert "Agent request failed" in events[-1]["error"]
            assert status["messages"] == []
    finally:
        response.close()
        client.delete("/api/agent/conversation")


@pytest.mark.parametrize("method,path", [
    ("post", "/api/agent/auth"), ("delete", "/api/agent/auth"),
    ("post", "/api/agent/auth/poll"), ("get", "/api/agent/models"),
    ("post", "/api/agent/model"), ("delete", "/api/agent/conversation"),
    ("post", "/api/agent/messages"),
])
def test_every_agent_endpoint_requires_opt_in(client, monkeypatch, method, path):
    monkeypatch.delenv("VULNSCOUT_AGENT_ENABLED")
    response = getattr(client, method)(path)
    assert response.status_code == 404
    assert response.get_json()["error"] == "Agent chat is disabled on this server."


@pytest.mark.parametrize("context", [
    [], {"page": "metrics", "projectId": 42}, {"page": "metrics", "projectId": "x" * 101},
    {"page": "metrics", "variantIds": "variant"}, {"page": "metrics", "variantIds": [42]},
    {"page": "metrics", "variantIds": ["x"] * 51}, {"page": "metrics", "view": []},
    {"page": "metrics", "view": {"search": "x" * 201}},
    {"page": "metrics", "view": {"selectionCount": True}},
    {"page": "metrics", "view": {"visibleCount": 1000001}},
    {"page": "metrics", "view": {"hideEmptyScans": "true"}},
])
def test_context_boundaries_reject_invalid_values(client, context):
    response = client.post("/api/agent/messages", json={"message": "Review", "context": context})
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_context_retains_only_allowed_fields():
    from src.routes.agent import _validated_context

    context = {"page": "vulnerabilities", "projectId": "project", "variantId": "variant",
               "variantIds": ["variant"], "variantCount": 1, "secret": "not-for-the-agent",
               "view": {"search": "CVE", "selectedVariantIds": ["variant"], "selectionCount": 1,
                        "visibleCount": 0, "hideEmptyScans": False, "secret": "not-for-the-agent"}}
    result = _validated_context(context)
    assert "secret" not in result
    assert "secret" not in result["view"]
    assert result["variantIds"] == ["variant"]
    assert result["view"]["selectionCount"] == 1
    assert _validated_context(None) is None


@pytest.mark.parametrize("model", [None, "", "x" * 101, 42])
def test_message_rejects_invalid_model(client, model):
    response = client.post("/api/agent/messages", json={"message": "Review", "model": model})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Invalid model selection."


@pytest.mark.parametrize("body", [None, [], {}, {"model": 42}, {"model": "x" * 101}])
def test_model_selection_rejects_invalid_payload(client, body):
    assert client.post("/api/agent/model", json=body).status_code == 400


def test_conversation_expiry_and_busy_model_selection(client):
    from src.routes.agent import COOKIE, _conversations

    client.delete("/api/agent/conversation")
    key = client.get_cookie(COOKIE).value
    conversation = _conversations[key]
    with conversation.lock:
        response = client.post("/api/agent/model", json={"model": "auto"})
        assert response.status_code == 409
    conversation.last_used = time.monotonic() - 3601
    client.delete("/api/agent/conversation")
    assert client.get_cookie(COOKIE).value != key
    assert key not in _conversations


def test_reset_retains_identity_and_signout_clears_it(client):
    from src.routes.agent import COOKIE, _conversations

    client.delete("/api/agent/conversation")
    conversation = _conversations[client.get_cookie(COOKIE).value]
    conversation.token = "invalid-test-credential"
    conversation.device_code = "expired-code"
    conversation.model = "chosen-model"
    conversation.messages.append({"role": "user", "content": "Previous message"})
    conversation.usage["cost"] = 1
    response = client.delete("/api/agent/conversation")
    assert response.status_code == 200
    assert conversation.token == "invalid-test-credential"
    assert conversation.model == "chosen-model"
    assert conversation.messages == []
    assert conversation.usage["cost"] is None
    response = client.delete("/api/agent/auth")
    assert response.status_code == 200
    assert conversation.token is None
    assert conversation.device_code is None
    assert conversation.model == "auto"


def test_expired_device_code_is_cleared(client):
    from src.routes.agent import COOKIE, _conversations

    client.delete("/api/agent/conversation")
    conversation = _conversations[client.get_cookie(COOKIE).value]
    conversation.device_code = "expired-code"
    conversation.device_expires = time.monotonic() - 1
    assert client.post("/api/agent/auth/poll").status_code == 410
    assert conversation.device_code is None


def test_json_reply_failure_preserves_conversation_and_unlocks(client, monkeypatch):
    from src.routes.agent import COOKIE, _conversations

    monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH")
    client.delete("/api/agent/conversation")
    conversation = _conversations[client.get_cookie(COOKIE).value]
    conversation.token = "invalid-test-credential"
    response = client.post("/api/agent/messages", json={"message": "Review", "context": {"page": "metrics"}})
    assert response.status_code == 503
    assert "Agent request failed" in response.get_json()["error"]
    assert conversation.messages == []
    assert not conversation.lock.locked()


def test_stream_records_and_disconnect_cleanup():
    from src.routes.agent import _stream_events

    events = queue.Queue()
    disconnected = threading.Event()
    records = [{"type": "delta", "text": "First\nSecond"}, {"type": "done", "reply": "First\nSecond"}]
    for record in records:
        events.put(record)
    stream = _stream_events(events, disconnected)
    assert json.loads(next(stream))["type"] == "status"
    assert [json.loads(chunk) for chunk in stream] == records
    assert disconnected.is_set()
    disconnected.clear()
    stream = _stream_events(events, disconnected)
    next(stream)
    stream.close()
    assert disconnected.is_set()


def test_stream_heartbeat_and_terminal_error():
    from src.routes.agent import _stream_events

    events = queue.Queue()
    disconnected = threading.Event()
    stream = _stream_events(events, disconnected)
    assert json.loads(next(stream))["type"] == "status"
    assert json.loads(next(stream)) == {"type": "heartbeat"}
    events.put({"type": "error", "error": "Request failed"})
    assert [json.loads(chunk) for chunk in stream] == [{"type": "error", "error": "Request failed"}]
    assert disconnected.is_set()


def test_usage_aggregation_ignores_unreported_metrics():
    from copilot.session_events import AssistantUsageData
    from src.routes.agent import _add_usage, _session_usage

    events = [SimpleNamespace(data=AssistantUsageData.from_dict({"model": "auto", "cost": 1.5,
                                                               "inputTokens": 10, "outputTokens": 3})),
              SimpleNamespace(data=AssistantUsageData.from_dict({"model": "auto", "inputTokens": 2}))]
    usage = _session_usage(events)
    assert usage == {"cost": 1.5, "input_tokens": 12, "output_tokens": 3}
    empty = _session_usage([])
    assert empty == {"cost": None, "input_tokens": None, "output_tokens": None}
    assert _add_usage(usage, empty) == usage
    assert _add_usage(empty, usage) == usage


def test_public_event_projection_excludes_tool_payloads():
    from copilot.session_events import AssistantMessageDeltaData, ToolExecutionStartData, ToolExecutionCompleteData
    from src.routes.agent import _publish_event

    records = []
    payloads = [AssistantMessageDeltaData.from_dict({"messageId": "message", "deltaContent": "Answer"}),
                ToolExecutionStartData.from_dict({"toolCallId": "call", "toolName": "mcp-tool",
                                                   "mcpToolName": "get_vulnerability",
                                                   "arguments": {"private": "secret"}}),
                ToolExecutionCompleteData.from_dict({"toolCallId": "call", "success": True,
                                                      "result": {"content": "private tool result"}})]
    for payload in payloads:
        _publish_event(SimpleNamespace(data=payload), records.append)
    assert records == [{"type": "delta", "message_id": "message", "text": "Answer"},
                       {"type": "tool_start", "id": "call", "name": "get_vulnerability"},
                       {"type": "tool_end", "id": "call", "success": True}]
    _publish_event(SimpleNamespace(data={"private": "secret"}), records.append)
    _publish_event(SimpleNamespace(data=payloads[0]), None)
    assert len(records) == 3
