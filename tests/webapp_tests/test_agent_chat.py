import asyncio
import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest


USAGE = {"cost": 1, "input_tokens": 2, "output_tokens": 3}


async def _answer(call):
    """The AI queue's test runner: a reply that keeps its SDK session, as _reply does."""
    call.on_session(f"s-{call.request.id}")
    call.session.session_id, call.session.session_scope = f"s-{call.request.id}", call.scope
    return "answer", dict(USAGE)


def _queue():
    from src.controllers import agent_queue as aq

    return aq.agent_queue


def _main_session():
    return _queue()._conversations["main"].session


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", str(tmp_path / "missing_server.py"))
    monkeypatch.setenv("VULNSCOUT_CONFIG", str(tmp_path / "config.env"))
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_AUTH_CREDENTIALS", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)
    monkeypatch.delenv("AI_BASE_URL", raising=False)
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    from src.bin.webapp import create_app
    from src.controllers import agent_queue as aq
    from src.controllers.event_bus import EventBus
    from src.extensions import db
    from src.routes import agent

    # The agent connection and AI queue are process-wide; give each test fresh ones, as a fresh process would have.
    monkeypatch.setattr(agent, "_agent_connection", agent.Conversation())
    monkeypatch.setattr(aq, "agent_queue", aq.AgentQueue(runner=_answer, events=EventBus(), autostart=False))
    app = create_app()
    app.config.update(TESTING=True, SCAN_FILE=str(scan_file))
    with app.app_context():
        db.create_all()
    return app.test_client()


def test_agent_enabled_by_default(client):
    response = client.get("/api/agent")
    assert response.status_code == 200


def test_sdk_exposes_only_scoped_reference_and_dependency_tools(monkeypatch):
    import asyncio
    from src.routes import agent

    captured = {}

    class Session:
        session_id = "test-source-session"

        def on(self, callback):
            pass

        async def send_and_wait(self, message, *, timeout=60.0):
            return SimpleNamespace(data=SimpleNamespace(content="Source inspected"))

        async def disconnect(self):
            pass

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def list_models(self):
            return [SimpleNamespace(id="model", policy=None)]

        async def create_session(self, **options):
            captured.update(options)
            return Session()

    monkeypatch.setattr(agent, "_sdk_client", lambda token: Client())
    scope = json.dumps({"project_ids": ["p1"], "variant_ids": ["v1"]})
    response, _ = asyncio.run(agent._reply(
        agent.Conversation(), "Inspect uploaded source", agent._mcp_path(), "model", scope,
    ))
    assert response == "Source inspected"
    source_tools = {"list_codebase_files", "read_codebase_file", "search_codebase"}
    assert source_tools <= set(captured["mcp_servers"]["vulnscout"]["tools"])
    assert {f"mcp:vulnscout-{name}" for name in source_tools} <= set(captured["available_tools"])
    assert all(name.startswith("mcp:vulnscout-") for name in captured["available_tools"])
    assert captured["mcp_servers"]["vulnscout"]["env"]["VULNSCOUT_AGENT_SCOPE"] == scope
    assert captured["enable_skills"] is False
    assert captured["on_permission_request"].__name__ == "approve_all" and "custom_agents" not in captured
    assert "untrusted evidence" in captured["system_message"]["content"]
    dependency_tools = {"list_dependency_documents", "list_dependency_packages", "get_package_dependencies",
                        "get_package_source_files"}
    assert dependency_tools <= set(captured["mcp_servers"]["vulnscout"]["tools"])
    assert {f"mcp:vulnscout-{name}" for name in dependency_tools} <= set(captured["available_tools"])
    assert dependency_tools <= set(agent.READ_TOOLS)
    assert not dependency_tools & set(agent.WRITE_TOOLS)
    instructions = captured["system_message"]["content"]
    assert all(term in instructions for term in ("next_offset", "max_depth=0", "runtime usage",
                                                 "backports", "unknown", "no web research", "read-only"))
    assert all(term in instructions for term in ("STRIDE", "T# threats", "corroborates"))
    assert all(term in instructions for term in (
        "get_package_source_files", "build_targets", "path_edges", "BUILD/RUNTIME",
        "File presence does not prove compilation",
    ))
    assert "get_ai_context_form_guide" in agent.READ_TOOLS
    assert "get_ai_context_form_guide" not in agent.WRITE_TOOLS
    assert "mcp:vulnscout-get_ai_context_form_guide" in captured["available_tools"]
    assert all(term in instructions for term in (
        "get_ai_context_form_guide", "copy-ready", "view.section", "unsaved", "explicitly asks to save",
    ))


def test_agent_rejects_remote_requests(client):
    response = client.get("/api/agent", environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
    assert response.status_code == 403
    response = client.get("/api/agent", environ_overrides={"REMOTE_ADDR": None})
    assert response.status_code == 403


def test_agent_accepts_container_gateway(client):
    from src.routes.agent import _container_gateway

    gateway = _container_gateway()
    if gateway is None:
        pytest.skip("Container gateway not available")
    response = client.get("/api/agent", environ_overrides={"REMOTE_ADDR": gateway})
    assert response.status_code == 200


def test_agent_accepts_pasta_forwarded_host_but_rejects_remote(client, monkeypatch):
    from src.routes import agent

    monkeypatch.setattr(agent, "_container_gateway", lambda: "192.0.2.1")
    monkeypatch.setattr(agent, "_container_host_forward_ip", lambda gateway: "192.0.2.2")
    local = {"REMOTE_ADDR": "192.0.2.2"}
    assert client.get("/api/agent", environ_overrides=local).status_code == 200
    assert client.get("/api/agent", environ_overrides={"REMOTE_ADDR": "192.0.2.3"}).status_code == 403
    assert client.get("/api/agent", environ_overrides=local,
                      headers={"Host": "example.org"}).status_code == 403
    assert client.post("/api/agent/model", environ_overrides=local,
                       json={"model": "auto"}, headers={"Origin": "https://example.org"}).status_code == 403


def test_agent_rejects_non_local_host(client):
    response = client.get("/api/agent", headers={"Host": "example.org"})
    assert response.status_code == 403
    response = client.get("/api/agent", headers={"Host": "[::1]:7275"})
    assert response.status_code == 200


def test_agent_rejects_foreign_origin(client):
    response = client.post("/api/agent/model", json={"model": "auto"},
                           headers={"Origin": "https://example.org"})
    assert response.status_code == 403
    # Reads too: the connection is process-wide, so another site must not read it.
    response = client.get("/api/agent", headers={"Origin": "https://example.org"})
    assert response.status_code == 403
    assert client.get("/api/agent", headers={"Origin": "http://localhost"}).status_code == 200


def test_context_rejects_malformed_and_unbounded_rows():
    from src.routes.agent import _validated_context

    for context in ({"page": "invalid"}, {"page": "vulnerabilities", "view": {"visibleVulnerabilityIds": ["CVE-1"] * 101}},
                    {"page": "review", "view": {"visibleCount": -1}}):
        with pytest.raises(ValueError):
            _validated_context(context)


def test_page_selections_pass_validation():
    from src.routes.agent import _validated_context

    view = {
        "section": "scan history", "visibleScanIds": ["scan-id"],
        "selectedScanTypes": ["grype"], "selectedRefreshTypes": ["nvd"],
        "refreshMode": "custom", "hideEmptyScans": False,
        "excludeKernel": True, "excludeNative": True,
    }
    assert _validated_context({"page": "scans", "projectId": "project", "view": view}) == {
        "page": "scans", "projectId": "project", "view": view}


def test_large_variant_selection_keeps_full_scope_and_compacts_prompt(client):
    from src.models.project import Project
    from src.models.variant import Variant
    from src.routes.agent import MAX_PROMPT_VARIANTS, _prompt_context, _scope_for_context, _validated_context

    with client.application.app_context():
        project = Project.create("Large")
        variants = [str(Variant.create(f"Variant {index}", project.id).id)
                    for index in range(MAX_PROMPT_VARIANTS + 2)]
        selected = variants[1:]
        context = _validated_context({"page": "vulnerabilities", "projectId": str(project.id),
                                      "variantIds": selected})
        assert json.loads(_scope_for_context(context))["variant_ids"] == sorted(selected)
    prompt = _prompt_context(context)
    assert "variantIds" not in prompt
    assert prompt["variantCount"] == len(selected)
    assert context["variantIds"] == selected
    small = {"page": "metrics", "variantIds": ["variant"]}
    assert _prompt_context(small) is small
    with pytest.raises(ValueError, match="at most 1000 variants"):
        _validated_context({"page": "metrics", "variantIds": ["x"] * 1001})


def test_chat_prompt_appends_the_compacted_browser_view():
    from src.routes.agent import MAX_PROMPT_VARIANTS, chat_prompt

    assert chat_prompt("Hello", None) == "Hello"
    context = {"page": "metrics", "variantIds": ["v"] * (MAX_PROMPT_VARIANTS + 1)}
    text, view = chat_prompt("Summarize", context).split(
        "\n\nCurrent VulnScout browser view (selection only; verify facts with MCP): ")
    assert text == "Summarize"
    assert json.loads(view) == {"page": "metrics", "variantCount": MAX_PROMPT_VARIANTS + 1}
    assert chat_prompt("Help", {"page": "unknown"}).endswith(': {"page":"unknown"}')


def test_device_login_without_client_id(client, monkeypatch):
    from src.routes import agent

    calls = []

    def github_form(url, fields):
        calls.append((url, fields))
        if url == agent.GITHUB_DEVICE_URL:
            return {"device_code": "device-code", "user_code": "ABCD-1234",
                    "verification_uri": "https://github.com/login/device", "interval": 5, "expires_in": 900}
        return {"error": "authorization_pending"}

    monkeypatch.setattr(agent, "_github_form", github_form)
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
    assert calls == [
        (agent.GITHUB_DEVICE_URL, {"client_id": agent.GITHUB_COPILOT_CLIENT_ID, "scope": "read:user"}),
        (agent.GITHUB_TOKEN_URL, {"client_id": agent.GITHUB_COPILOT_CLIENT_ID, "device_code": "device-code",
                                  "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}),
    ]


def test_device_poll_interval_increases_when_github_omits_interval():
    from src.routes.agent import _device_poll_interval

    assert _device_poll_interval(5, {"error": "authorization_pending"}) == 5
    assert _device_poll_interval(5, {"error": "slow_down"}) == 10
    assert _device_poll_interval(10, {"error": "slow_down", "interval": 9}) == 15
    assert _device_poll_interval(15, {"error": "slow_down", "interval": 25}) == 25


def test_device_login_reports_unknown_github_client(client, monkeypatch):
    from src.routes import agent

    calls = []
    monkeypatch.setattr(agent, "_github_form", lambda url, fields: calls.append(fields) or {"error": "Not Found"})
    monkeypatch.setenv("VULNSCOUT_AGENT_GITHUB_CLIENT_ID", "Iv1.0000000000000000")
    assert client.get("/api/agent").get_json()["device_login"] is True
    response = client.post("/api/agent/auth")
    assert response.status_code == 503
    assert "device flow" in response.get_json()["error"]
    assert calls == [{"client_id": "Iv1.0000000000000000", "scope": "read:user"}]
    assert client.get("/api/agent").get_json()["token_connected"] is False


def test_status_uses_real_copilot_runtime(client):
    response = client.get("/api/agent")
    assert response.status_code == 200
    assert response.get_json()["configured"] is False
    assert isinstance(response.get_json()["authenticated"], bool)
    assert response.get_json()["token_connected"] is False
    assert response.get_json()["messages"] == []
    assert "Set-Cookie" not in response.headers


def test_connection_is_process_wide_without_cookies_or_threads(client):
    payload = {"provider": "local", "model": "qwen3:8b", "base_url": "http://localhost:11434/v1"}
    response = client.post("/api/agent/provider", json=payload)
    assert response.status_code == 200
    assert "Set-Cookie" not in response.headers
    other = client.application.test_client()
    for headers in ({}, {"X-Agent-Thread": "invalid"}, {"X-Agent-Thread": str(uuid4())}):
        response = other.get("/api/agent", headers=headers)
        assert response.status_code == 200
        assert response.get_json()["provider"] == "local"
        assert "Set-Cookie" not in response.headers
    assert other.delete("/api/agent/provider").status_code == 200
    assert client.get("/api/agent").get_json()["provider"] is None


@pytest.mark.parametrize("method,path", [("post", "/api/agent/messages"), ("delete", "/api/agent/conversation")])
def test_legacy_conversation_endpoints_are_removed(client, method, path):
    assert getattr(client, method)(path, json={"message": "Hello"}).status_code in (404, 405)


def test_bundled_mcp_is_configured_by_default(client, monkeypatch):
    monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH")
    assert client.get("/api/agent").get_json()["configured"] is True


def test_unknown_route_context_is_supported():
    from src.routes.agent import _validated_context

    assert _validated_context({"page": "unknown"}) == {"page": "unknown"}


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


@pytest.mark.parametrize("token_connected", [True, False])
def test_github_chatbox_model_survives_restart(client, monkeypatch, token_connected):
    from src.routes import agent

    async def auth_status(token):
        assert token == ("github-key" if token_connected else None)
        return {"authenticated": True, "login": "test-user"}

    async def models(token):
        return [{"id": "auto", "name": "Auto"}, {"id": "gpt-4o", "name": "GPT-4o"}]

    monkeypatch.setattr(agent, "_auth_status", auth_status)
    monkeypatch.setattr(agent, "_models", models)
    if token_connected:
        agent._persist_agent_credentials(token="github-key")
    assert client.get("/api/agent").get_json()["model"] == "auto"
    assert client.post("/api/agent/model", json={"model": "gpt-4o"}).status_code == 200
    assert "AI_MODEL=gpt-4o" in Path(os.environ["VULNSCOUT_CONFIG"]).read_text()
    monkeypatch.setattr(agent, "_agent_connection", agent.Conversation())
    status = client.get("/api/agent").get_json()
    assert status["model"] == "gpt-4o"
    assert status["token_connected"] is token_connected
    restarted = agent._connection()
    assert restarted.model == "gpt-4o"
    captured, _ = _assess_sdk(monkeypatch, models=("auto", "gpt-4o"))
    reply, _ = asyncio.run(agent._reply(restarted, "Hello", agent._mcp_path(), restarted.model, "{}"))
    assert reply == "Assessed"
    assert captured["model"] == "gpt-4o" and "provider" not in captured
    with pytest.raises(agent.UnavailableModelError, match="this account"):
        asyncio.run(agent._reply(restarted, "Hello", agent._mcp_path(), "removed-model", "{}"))


def test_github_model_write_failure_keeps_previous_selection(client, monkeypatch):
    from src.routes import agent

    async def models(token):
        return [{"id": "gpt-4o", "name": "GPT-4o"}]

    agent._persist_agent_credentials(token="github-key")
    monkeypatch.setattr(agent, "_models", models)
    monkeypatch.setattr(agent, "persist_env_keys", lambda updates: (False, "AI_MODEL"))
    response = client.post("/api/agent/model", json={"model": "gpt-4o"})
    assert response.status_code == 500
    assert response.get_json()["error"] == "Failed to persist model to config.env."
    assert agent._connection().model == "auto"
    assert "AI_MODEL" not in Path(os.environ["VULNSCOUT_CONFIG"]).read_text()


@pytest.mark.parametrize("provider,model,base_url", [
    ("openai", "gpt-4o", ""),
    ("azure", "my-deployment", "https://resource.openai.azure.com/openai/v1"),
    ("anthropic", "claude-sonnet-4-5", ""),
    ("local", "Qwen/Qwen3-Coder", "http://127.0.0.1:11434/v1"),
])
def test_provider_connection_keeps_credentials_private(client, provider, model, base_url):
    payload = {"provider": provider, "model": model, "base_url": base_url,
               "api_key": "private-credential" if provider != "local" else ""}
    response = client.post("/api/agent/provider", json=payload)
    assert response.status_code == 200
    assert response.get_json() == {"provider": provider, "model": model}
    status = client.get("/api/agent").get_json()
    assert status["authenticated"] is True
    assert status["provider"] == provider
    assert status["token_connected"] is False
    assert "private-credential" not in json.dumps(status)
    assert client.get("/api/agent/models").get_json() == {"models": [{"id": model, "name": model}]}
    assert client.post("/api/agent/model", json={"model": "unavailable"}).status_code == 400
    assert client.post("/api/agent/model", json={"model": model}).status_code == 200
    assert client.delete("/api/agent/provider").get_json() == {"provider": None, "model": "auto"}
    assert client.get("/api/agent").get_json()["provider"] is None


@pytest.mark.parametrize("payload", [
    {"provider": "unknown", "model": "gpt-4o", "api_key": "key"},
    {"provider": "openai", "model": "gpt-4o"},
    {"provider": "anthropic", "model": "gpt-4o", "api_key": "key", "base_url": "http://example.com"},
    {"provider": "azure", "model": "deployment", "api_key": "key"},
    {"provider": "local", "model": "qwen3:8b", "base_url": "http://example.com/v1"},
    {"provider": "local", "model": "qwen3:8b", "base_url": "http://127.0.0.1:11434/v1#fragment"},
])
def test_provider_connection_rejects_invalid_configuration(client, payload):
    assert client.post("/api/agent/provider", json=payload).status_code == 400
    assert client.get("/api/agent").get_json()["provider"] is None


def test_provider_credentials_do_not_require_a_model():
    from src.routes.agent import _provider_connection

    connection = _provider_connection({
        "provider": "local", "base_url": "http://127.0.0.1:11434/v1",
    })
    assert connection.model == ""


def test_provider_config_is_shell_safe_on_restart(client):
    config_file = Path(os.environ["VULNSCOUT_CONFIG"])
    model = "literal 'quoted' $(printf unsafe) `printf unsafe` $HOME"
    response = client.post("/api/agent/provider", json={
        "provider": "openai", "model": model, "api_key": "private'key$HOME",
    })
    assert response.status_code == 200
    restarted = subprocess.run(
        ["bash", "-ec", '. "$1"; printf "%s\\n%s" "$AI_MODEL" "$AI_AUTH_CREDENTIALS"',
         "restart", str(config_file)],
        env={key: value for key, value in os.environ.items() if not key.startswith("AI_")},
        check=True, capture_output=True, text=True,
    )
    assert restarted.stdout == model + "\nprivate'key$HOME"
    assert config_file.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("field", ["model", "api_key", "base_url"])
@pytest.mark.parametrize("control", ["\n", "\r", "\x00", "\x1b", "\x7f"])
def test_provider_rejects_control_characters(client, field, control):
    payload = {"provider": "openai", "model": "model", "api_key": "key"}
    payload[field] = ("https://example.org/" if field == "base_url" else "value") + control
    assert client.post("/api/agent/provider", json=payload).status_code == 400


def test_local_runtime_uses_writable_user_config(client, monkeypatch, tmp_path):
    monkeypatch.delenv("VULNSCOUT_CONFIG")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user-config"))
    response = client.post("/api/agent/provider", json={
        "provider": "openai", "model": "gpt-4o", "api_key": "local-key",
    })
    assert response.status_code == 200
    config_file = tmp_path / "user-config" / "vulnscout" / "config.env"
    assert "AI_PROVIDER=openai" in config_file.read_text()
    assert client.delete("/api/agent/provider").status_code == 200
    assert "AI_AUTH_CREDENTIALS" not in config_file.read_text()


def test_local_github_sign_in_uses_writable_user_config(client, monkeypatch, tmp_path):
    from src.routes import agent

    monkeypatch.delenv("VULNSCOUT_CONFIG")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "user-config"))
    monkeypatch.setattr(agent, "_github_form", lambda *args: {
        "device_code": "device", "user_code": "user", "access_token": "github-key",
    })

    async def token_status(token):
        return {"authenticated": True, "login": "test-user"}

    monkeypatch.setattr(agent, "_token_status", token_status)
    assert client.post("/api/agent/auth").status_code == 200
    assert client.post("/api/agent/auth/poll").status_code == 200
    config = tmp_path / "user-config" / "vulnscout" / "config.env"
    assert "AI_PROVIDER=github" in config.read_text()
    assert client.delete("/api/agent/auth").status_code == 200
    assert "AI_AUTH_CREDENTIALS" not in config.read_text()


def test_sign_out_survives_fresh_process_with_stale_environment(client, monkeypatch):
    from src.routes import agent

    assert client.post("/api/agent/provider", json={
        "provider": "openai", "model": "gpt-4o", "api_key": "old-key",
    }).status_code == 200
    assert client.delete("/api/agent/auth").status_code == 200
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("AI_AUTH_CREDENTIALS", "old-key")
    monkeypatch.setenv("AI_MODEL", "gpt-4o")
    fresh = agent.Conversation()
    assert agent._load_env_credentials(fresh) is None
    assert fresh.credentials.provider is None
    assert fresh.credentials.token is None


def test_connect_select_restart_send(client, monkeypatch):
    from src.routes import agent

    monkeypatch.setattr(agent, "_fetch_provider_models",
                        lambda *args: json.dumps({"data": [{"id": "gpt-4o"}]}))
    assert client.post("/api/agent/provider", json={
        "provider": "openai", "api_key": "key",
    }).get_json()["model"] == ""
    assert client.post("/api/agent/model", json={"model": "gpt-4o"}).status_code == 200
    for key in ("AI_PROVIDER", "AI_AUTH_CREDENTIALS", "AI_MODEL", "AI_BASE_URL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(agent, "_agent_connection", agent.Conversation())
    assert client.get("/api/agent").get_json()["model"] == "gpt-4o"
    restarted = agent._connection()
    captured, _ = _assess_sdk(monkeypatch)
    reply, _ = asyncio.run(agent._reply(restarted, "Hello", agent._mcp_path(), restarted.model, "{}"))
    assert reply == "Assessed"
    assert captured["model"] == "gpt-4o"
    assert captured["provider"] == {"type": "openai", "model_id": "gpt-4o", "wire_model": "gpt-4o",
                                    "api_key": "key"}
    with pytest.raises(agent.UnavailableModelError, match="this provider"):
        asyncio.run(agent._reply(restarted, "Hello", agent._mcp_path(), "model", "{}"))


@pytest.mark.parametrize("provider", ["github", "openai", "local"])
def test_environment_only_model_selection_preserves_connection(client, monkeypatch, provider):
    from src.routes import agent

    environment = {
        "AI_PROVIDER": provider,
        "AI_AUTH_CREDENTIALS": "environment-key",
        "AI_BASE_URL": "http://127.0.0.1:11434/v1" if provider == "local" else "",
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)

    async def models(token):
        return [{"id": "selected-model", "name": "Selected model"}]

    monkeypatch.setattr(agent, "_models", models)
    monkeypatch.setattr(agent, "_fetch_provider_models",
                        lambda *args: json.dumps({"data": [{"id": "selected-model"}]}))
    response = client.post("/api/agent/model", json={"model": "selected-model"})
    assert response.status_code == 200
    for key in agent.AGENT_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    expected = {key: value for key, value in environment.items() if value}
    assert agent._agent_environment() == {**expected, "AI_MODEL": "selected-model"}
    fresh = agent.Conversation()
    assert agent._load_env_credentials(fresh) is None
    assert fresh.model == "selected-model"
    if provider == "github":
        assert fresh.credentials.token == "environment-key"
    else:
        assert fresh.credentials.provider.kind == provider
        assert fresh.credentials.provider.api_key == "environment-key"
        assert fresh.credentials.provider.base_url == environment["AI_BASE_URL"]


@pytest.mark.parametrize("provider,model", [
    ("openai", "gpt-4o"), ("openai", ""), ("github", "gpt-4o"),
])
def test_fresh_connection_restores_saved_model(client, monkeypatch, provider, model):
    from src.routes import agent

    Path(os.environ["VULNSCOUT_CONFIG"]).write_text(
        f"AI_PROVIDER={provider}\nAI_AUTH_CREDENTIALS=saved-key\nAI_MODEL={model}\n"
    )
    monkeypatch.setattr(agent, "_fetch_provider_models",
                        lambda *args: json.dumps({"data": [{"id": "gpt-4o"}]}))

    async def auth_status(token):
        return {"authenticated": True, "login": "test-user"}

    monkeypatch.setattr(agent, "_auth_status", auth_status)
    response = client.get("/api/agent")
    assert response.status_code == 200
    assert response.get_json()["model"] == model


@pytest.mark.parametrize("value,expected", [
    ("abc#def", "abc#def"),
    ("#initial", "#initial"),
    ("org/model#revision # trailing comment", "org/model#revision"),
    ("'literal $HOME `command` # value'", "literal $HOME `command` # value"),
    (r"escaped\ value#suffix", "escaped value#suffix"),
    (r"escaped\ #suffix", "escaped #suffix"),
    (r"escaped\$literal", "escaped$literal"),
    ('"quoted#value" # trailing comment', "quoted#value"),
])
def test_direct_config_literals_match_shell_assignments(client, value, expected):
    from src.routes import agent

    config_file = Path(os.environ["VULNSCOUT_CONFIG"])
    config_file.write_text(
        f"AI_AUTH_CREDENTIALS={value}\nAI_MODEL={value}\n"
    )
    shell_value = subprocess.run(
        ["bash", "-ec", '. "$1"; printf "%s" "$AI_MODEL"', "config", str(config_file)],
        check=True, capture_output=True, text=True,
    )
    assert shell_value.stdout == expected
    assert agent._agent_environment() == {"AI_AUTH_CREDENTIALS": expected, "AI_MODEL": expected}


@pytest.mark.parametrize("value", [
    "$HOME", '"${MODEL}"', "`command`", "$(command)", "~", "model; command",
    r'"\$HOME"', r'"\`command\`"',
])
def test_direct_config_rejects_unsupported_shell_syntax(client, value):
    from src.routes import agent

    Path(os.environ["VULNSCOUT_CONFIG"]).write_text(f"AI_MODEL={value}\n")
    with pytest.raises(ValueError):
        agent._agent_environment()


def test_provider_restart_without_model_requires_selection(client, monkeypatch):
    from src.routes import agent

    monkeypatch.setattr(agent, "_fetch_provider_models",
                        lambda *args: json.dumps({"data": [{"id": "gpt-4o"}]}))
    assert client.post("/api/agent/provider", json={
        "provider": "openai", "api_key": "key",
    }).status_code == 200
    fresh = agent.Conversation()
    assert agent._load_env_credentials(fresh) is None
    assert fresh.model == ""
    assert fresh.credentials.provider.models == [{"id": "gpt-4o", "name": "gpt-4o"}]


@pytest.mark.parametrize("configured_provider", ["invalid-provider", "openai"])
@pytest.mark.parametrize("method,path", [
    ("post", "/api/agent/provider"), ("delete", "/api/agent/provider"),
    ("post", "/api/agent/auth"), ("delete", "/api/agent/auth"),
])
def test_broken_provider_can_be_replaced_or_removed(client, monkeypatch, method, path, configured_provider):
    from src.routes import agent

    monkeypatch.setenv("AI_PROVIDER", configured_provider)
    monkeypatch.setenv("AI_AUTH_CREDENTIALS", "broken-key")

    def unavailable(*args):
        raise ValueError("Could not reach the provider endpoint.")

    monkeypatch.setattr(agent, "_fetch_provider_models", unavailable)
    monkeypatch.setattr(agent, "_github_form", lambda *args: {
        "device_code": "device", "user_code": "user", "expires_in": 900,
    })
    response = getattr(client, method)(path, json={
        "provider": "openai", "model": "gpt-4o", "api_key": "replacement",
    })
    assert response.status_code == 200


def test_agent_loads_github_credentials_from_env(client, monkeypatch):
    from src.routes import agent

    monkeypatch.setenv("AI_PROVIDER", "github")
    monkeypatch.setenv("AI_AUTH_CREDENTIALS", "ghu_env_test_token")

    async def _fake_auth_status(token):
        assert token == "ghu_env_test_token"
        return {"authenticated": True, "login": "env-user"}

    monkeypatch.setattr(agent, "_auth_status", _fake_auth_status)
    status = client.get("/api/agent").get_json()
    assert status["authenticated"] is True
    assert status["token_connected"] is True
    assert status["provider"] is None
    assert status["config_error"] is None


def test_agent_rejects_invalid_env_provider_configuration(client, monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "invalid-provider")
    monkeypatch.setenv("AI_AUTH_CREDENTIALS", "unused")

    status = client.get("/api/agent").get_json()
    assert "Unsupported AI_PROVIDER value" in status["config_error"]

    models = client.get("/api/agent/models")
    assert models.status_code == 400
    assert "Invalid AI provider configuration" in models.get_json()["error"]


def test_provider_enrollment_requires_a_reachable_model_endpoint(client):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        response = client.post("/api/agent/provider", json={
            "provider": "local", "base_url": f"http://127.0.0.1:{port}/v1",
        })
    assert response.status_code == 400
    assert response.get_json()["error"] == "Could not reach the provider endpoint."
    assert client.get("/api/agent").get_json()["provider"] is None


def test_live_streaming_reply_resumes_its_session(client, monkeypatch):
    import asyncio
    from src.routes import agent

    if os.getenv("VULNSCOUT_TEST_MCP_SERVER_PATH"):
        monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", os.environ["VULNSCOUT_TEST_MCP_SERVER_PATH"])
    else:
        monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH")
    authenticated = client.get("/api/agent").get_json()["authenticated"]
    connection = agent._connection()
    with client.application.app_context():
        scope = agent._scope_for_context(None)
    events, sessions = [], []

    def turn(message):
        return asyncio.run(agent._reply(connection, message, agent._mcp_path(), connection.model, scope,
                                        events.append, on_session=sessions.append))

    prompt = "Use get_vulnerability to retrieve CVE-2009-3555 and summarize it in one sentence. Do not make changes."
    if not authenticated:
        with pytest.raises(Exception):
            turn(prompt)
        assert connection.session_id is None
        return
    try:
        reply, _ = turn(prompt)
        assert reply
        assert any(event["type"] == "delta" and event["text"] for event in events)
        assert any(event["type"] == "tool_start" for event in events)
        assert any(event["type"] == "tool_end" for event in events)
        assert {event["type"] for event in events} <= {"delta", "tool_start", "tool_end"}
        assert sessions == [connection.session_id]
        turn("Which vulnerability did we just discuss? Do not make changes.")
        assert sessions == [connection.session_id] * 2
    finally:
        if connection.session_id:
            asyncio.run(agent._delete_session(connection.credentials.token, connection.session_id))


@pytest.mark.parametrize("method,path", [
    ("post", "/api/agent/auth"), ("delete", "/api/agent/auth"),
    ("post", "/api/agent/provider"), ("delete", "/api/agent/provider"),
    ("post", "/api/agent/auth/poll"), ("get", "/api/agent/models"),
    ("post", "/api/agent/model"),
])
def test_every_agent_endpoint_rejects_remote_requests(client, method, path):
    response = getattr(client, method)(path, environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
    assert response.status_code == 403
    assert response.get_json()["error"] == "Agent chat is available only on localhost."


@pytest.mark.parametrize("context", [
    [], {"page": "metrics", "projectId": 42}, {"page": "metrics", "projectId": "x" * 101},
    {"page": "metrics", "variantIds": "variant"}, {"page": "metrics", "variantIds": [42]},
    {"page": "metrics", "variantIds": ["x"] * 1001}, {"page": "metrics", "view": []},
    {"page": "metrics", "view": {"search": "x" * 201}},
    {"page": "metrics", "view": {"selectionCount": True}},
    {"page": "metrics", "view": {"visibleCount": 1000001}},
    {"page": "metrics", "view": {"hideEmptyScans": "true"}},
])
def test_context_boundaries_reject_invalid_values(context):
    from src.routes.agent import _validated_context

    with pytest.raises(ValueError):
        _validated_context(context)


def test_context_retains_only_allowed_fields():
    from src.routes.agent import _validated_context

    context = {"page": "vulnerabilities", "projectId": "project", "variantId": "variant",
               "variantIds": ["variant"], "variantCount": 1, "secret": "not-for-the-agent",
               "view": {"search": "CVE", "selectedVariantIds": ["variant"], "selectionCount": 1,
                        "visibleCount": 0, "hideEmptyScans": False, "secret": "not-for-the-agent"}}
    result = _validated_context(context)
    assert "secret" not in result
    assert "variantCount" not in result
    assert "secret" not in result["view"]
    assert result["variantIds"] == ["variant"]
    assert result["view"]["selectionCount"] == 1
    assert _validated_context(None) is None


def test_agent_scope_verifies_membership_in_backend(client):
    from src.models.project import Project
    from src.models.variant import Variant
    from src.routes.agent import _scope_for_context

    with client.application.app_context():
        selected_project = Project.create("Selected")
        other_project = Project.create("Other")
        selected_variant = Variant.create("Selected variant", selected_project.id)
        other_variant = Variant.create("Other variant", other_project.id)
        scope = json.loads(_scope_for_context({"projectId": str(selected_project.id),
                                              "variantId": str(selected_variant.id)}))
        assert scope == {"project_ids": [str(selected_project.id)], "variant_ids": [str(selected_variant.id)]}
        with pytest.raises(ValueError, match="do not belong"):
            _scope_for_context({"projectId": str(selected_project.id), "variantId": str(other_variant.id)})


def test_ai_context_scope_uses_its_own_selection(client):
    from src.models.project import Project
    from src.models.variant import Variant
    from src.routes.agent import _scope_for_context

    with client.application.app_context():
        explorer = Project.create("Explorer")
        ai_project = Project.create("AI Context")
        explorer_variant = Variant.create("Explorer variant", explorer.id)
        ai_variant = Variant.create("AI variant", ai_project.id)
        context = {"page": "ai", "projectId": str(explorer.id), "variantId": str(explorer_variant.id),
                   "view": {"selectedProjectId": str(ai_project.id), "selectedVariantId": str(ai_variant.id)}}
        assert json.loads(_scope_for_context(context)) == {
            "project_ids": [str(ai_project.id)], "variant_ids": [str(ai_variant.id)]}
        context["view"]["selectedVariantId"] = str(explorer_variant.id)
        with pytest.raises(ValueError, match="do not belong"):
            _scope_for_context(context)
        context["view"] = {"selectedProjectId": "", "selectedVariantId": ""}
        assert json.loads(_scope_for_context(context)) == {"project_ids": [], "variant_ids": []}


@pytest.mark.parametrize("target_count", [1, 2])
def test_bulk_review_context_preserves_full_assessment_scope(client, target_count):
    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.package import Package
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability
    from src.routes import agent
    from vulnscout_mcp.client import ScopedVulnScoutClient

    with client.application.app_context():
        project = Project.create("Selected project")
        other = Project.create("Other project")
        first = Variant.create("Visible variant", project.id)
        second = Variant.create("Hidden target", project.id)
        excluded = Variant.create("Not a target", other.id)
        Vulnerability.create_record(id="CVE-2024-1234", description="Description")
        package = Package.find_or_create("example", "1.0", [], [], "")
        db.session.commit()
        finding = Finding.get_or_create(package.id, "CVE-2024-1234")
        assessment = Assessment.create(status="affected", origin="custom", targets=[
            (first.id, finding.id), (second.id, finding.id),
        ][:target_count])
        assessment_id = str(assessment.id)
        first_id = str(first.id)
        variant_ids = sorted([str(first.id), str(second.id)][:target_count])
        project_id = str(project.id)
        excluded_id = str(excluded.id)

    # The detail endpoint, unlike the visible table, returns the complete target set.
    full = client.get(f"/api/assessments/{assessment_id}").get_json()
    assert sorted(target["variant_id"] for target in full["targets"]) == variant_ids
    with client.application.app_context():
        with pytest.raises(ValueError, match="do not belong"):
            agent._scope_for_context(agent._validated_context({"page": "review", "variantId": first_id}))
        context = agent._validated_context({"page": "review", "projectId": project_id,
                                            "variantIds": variant_ids, "view": {"section": "assessments"}})
        scoped = json.loads(agent._scope_for_context(context))
    assert scoped["variant_ids"] == variant_ids
    assert scoped["project_ids"] == [project_id]
    assert excluded_id not in scoped["variant_ids"]
    result = ScopedVulnScoutClient("http://localhost", scoped)._assessment(full)
    assert result["targets"] == full["targets"]


def test_scoped_agent_mcp_reads_and_writes_against_live_backend(client, monkeypatch, tmp_path):
    from io import BytesIO
    from werkzeug.serving import make_server

    from src.extensions import db
    from src.models.assessment import Assessment
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.project import Project
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_observation import SBOMObservation
    from src.models.sbom_package import SBOMPackage
    from src.models.scan import Scan
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability
    from vulnscout_mcp.client import ScopedVulnScoutClient, VulnScoutError
    from vulnscout_mcp.tools.context import _codebase_source_impl

    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))

    with client.application.app_context():
        project_a = Project.create("Project A")
        project_b = Project.create("Project B")
        variant_a = Variant.create("Chosen", project_a.id)
        variant_other = Variant.create("Other", project_a.id)
        variant_b = Variant.create("Foreign", project_b.id)
        Vulnerability.create_record(id="CVE-2024-1234", description="Description", status="high")
        db.session.commit()
        findings = []
        documents = []
        for variant, name in ((variant_a, "allowed"), (variant_other, "other"), (variant_b, "foreign")):
            scan = Scan.create(name, variant.id)
            package = Package.find_or_create(name, "1.0", [], [], "")
            db.session.commit()
            finding = Finding.get_or_create(package.id, "CVE-2024-1234")
            Observation.create(finding.id, scan.id)
            document = SBOMDocument.create(path=f"/sbom/{name}.json", source_name="cdx", scan_id=scan.id)
            SBOMPackage.create(document.id, package.id)
            findings.append(finding)
            documents.append(document)
        unaffected_supplier = Package.find_or_create("allowed", "1.0", [], [], "", "VendorB")
        db.session.commit()
        SBOMPackage.create(documents[0].id, unaffected_supplier.id)
        SBOMObservation.create("CVE-2024-1234", documents[0].id, "current note", "Current evidence")
        historical = Scan.create("historical", variant_a.id)
        historical.timestamp = datetime(2000, 1, 1, tzinfo=timezone.utc)
        db.session.commit()
        historical_document = SBOMDocument.create(
            path="/sbom/historical.json", source_name="cdx", scan_id=historical.id)
        SBOMObservation.create("CVE-2024-1234", historical_document.id, "historical note", "Obsolete evidence")
        Vulnerability.create_record(id="CVE-2024-5678", description="Foreign only")
        foreign_only = Finding.get_or_create(package.id, "CVE-2024-5678")
        Observation.create(foreign_only.id, scan.id)
        shared = Assessment.create(status="affected", origin="ai", targets=[
            (variant_a.id, findings[0].id), (variant_other.id, findings[1].id),
        ])
        foreign = Assessment.create(status="affected", origin="ai", targets=[(variant_b.id, findings[2].id)])
        scope = {"project_ids": [str(project_a.id)], "variant_ids": [str(variant_a.id)]}
        shared_id, foreign_id = str(shared.id), str(foreign.id)
        chosen_id, other_id, foreign_variant_id = str(variant_a.id), str(variant_other.id), str(variant_b.id)
        project_id = str(project_a.id)

    uploaded = client.post(f"/api/variants/{chosen_id}/context/files", data={
        "file": (BytesIO(b"first\nunsafe_call();\n"), "main.c"),
    })
    assert uploaded.status_code == 201
    file_id = uploaded.get_json()["id"]
    other_upload = client.post(f"/api/variants/{other_id}/context/files", data={
        "file": (BytesIO(b"foreign code"), "other.c"),
    })
    assert other_upload.status_code == 201
    other_file_id = other_upload.get_json()["id"]

    server = make_server("127.0.0.1", 0, client.application, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        agent_client = ScopedVulnScoutClient(f"http://127.0.0.1:{server.server_port}", scope)
        assert [project["id"] for project in agent_client.list_projects()] == [project_id]
        assert [variant["id"] for variant in agent_client.list_variants()] == [chosen_id]
        context = agent_client.get_merged_context(project_id, chosen_id)
        assert context["files"][0]["id"] == file_id
        listing = json.loads(_codebase_source_impl(
            agent_client, chosen_id, file_id, {"operation": "list"},
        ))
        assert listing["files"] == [{"path": "main.c", "size": 21}]
        source = agent_client.get_codebase_source(
            chosen_id, file_id, {"operation": "read", "path": "main.c", "start_line": 2},
        )
        assert source["content"] == "unsafe_call();\n"
        matches = agent_client.get_codebase_source(
            chosen_id, file_id, {"operation": "search", "query": "unsafe_call"},
        )
        assert matches["matches"] == [{"path": "main.c", "line": 2, "text": "unsafe_call();"}]
        with pytest.raises(VulnScoutError, match="outside"):
            agent_client.get_codebase_source(other_id, other_file_id, {"operation": "list"})
        with pytest.raises(VulnScoutError, match="File not found"):
            agent_client.get_codebase_source(chosen_id, other_file_id, {"operation": "list"})
        assessments = agent_client.list_assessments_by_vuln("CVE-2024-1234")
        assert [assessment["id"] for assessment in assessments] == [shared_id]
        assert assessments[0]["variant_ids"] == [chosen_id]
        assert assessments[0]["packages"] == ["allowed@1.0"]
        assert agent_client.get_assessment(shared_id)["targets"][0]["variant_id"] == chosen_id
        with pytest.raises(VulnScoutError, match="outside"):
            agent_client.get_assessment(foreign_id)
        with pytest.raises(VulnScoutError, match="outside"):
            agent_client.update_assessment(shared_id, {"status": "fixed"})
        with pytest.raises(VulnScoutError, match="outside"):
            agent_client.write_assessment("CVE-2024-1234", {"targets": [
                {"variant_id": other_id, "package": "other@1.0"}], "status": "affected"})
        with pytest.raises(VulnScoutError, match="outside"):
            agent_client.update_variant_context(foreign_variant_id, {})
        with pytest.raises(VulnScoutError, match="entire project"):
            agent_client.update_project_context(project_id, "changed")
        vulnerability = agent_client.get_vulnerability_for_variant("CVE-2024-1234", chosen_id)
        assert vulnerability["packages"] == ["allowed@1.0"]
        assert "other@1.0" not in str(vulnerability)
        assert "foreign@1.0" not in str(vulnerability)
        assert "VendorB" not in str(vulnerability)
        texts = {text["content"] for text in vulnerability["texts"]}
        assert "Current evidence" in texts
        assert "Obsolete evidence" not in texts
        with pytest.raises(VulnScoutError, match="outside the current variant scope"):
            agent_client.get_vulnerability_for_variant("CVE-2024-5678", chosen_id)

        with client.application.app_context():
            extra = Variant.create("Another allowed variant", project_a.id)
            chosen = Assessment.create(status="affected", origin="custom", targets=[
                (variant_a.id, findings[0].id)])
            Assessment.create(status="affected", origin="custom", targets=[
                (variant_other.id, findings[1].id)])
            extra_id, chosen_assessment_id = str(extra.id), str(chosen.id)
        multi_client = ScopedVulnScoutClient(f"http://127.0.0.1:{server.server_port}", {
            "project_ids": [project_id], "variant_ids": [chosen_id, extra_id],
        })
        assert [row["id"] for row in multi_client.list_custom_assessments({"limit": 1})] == [
            chosen_assessment_id]

        with client.application.app_context():
            protected = Assessment.create(status="affected", origin="ai", targets=[
                (variant_a.id, findings[0].id)])
            protected_id = str(protected.id)
        assert agent_client.update_assessment(protected_id, {"status": "fixed"})["assessment"]["status"] == "fixed"
        from src.models.assessment_target import AssessmentTarget

        with client.application.app_context():
            db.session.add(AssessmentTarget(assessment_id=protected.id, variant_id=variant_other.id,
                                            finding_id=findings[1].id))
            db.session.commit()
        response = client.patch(f"/api/assessments/{protected_id}", json={
            "status": "affected", "allowed_variant_ids": [chosen_id],
        })
        assert response.status_code == 409
        assert client.get(f"/api/assessments/{protected_id}").get_json()["status"] == "fixed"

        saved = agent_client.write_assessment("CVE-2024-1234", {
            "targets": [{"variant_id": chosen_id, "package": "allowed@1.0"}],
            "status": "under_investigation", "ai_generated": False,
        })
        assert saved["assessment"]["status"] == "under_investigation"
        with client.application.app_context():
            persisted = Assessment.get_by_id(saved["assessment"]["id"])
            assert persisted.created_at is not None
            assert persisted.origin == "ai"
    finally:
        server.shutdown()
        server_thread.join(timeout=5)


@pytest.mark.parametrize("body", [None, [], {}, {"model": 42}, {"model": "x" * 101}])
def test_model_selection_rejects_invalid_payload(client, body):
    assert client.post("/api/agent/model", json=body).status_code == 400


def test_signout_clears_identity(client):
    from src.routes import agent

    connection = agent._connection()
    connection.credentials.token = "invalid-test-credential"
    connection.credentials.device_code = "expired-code"
    connection.model = "chosen-model"
    _main_session().usage["cost"] = 1
    response = client.delete("/api/agent/auth")
    assert response.status_code == 200
    assert response.get_json() == {"authenticated": False, "cleanup_error": None}
    assert connection.credentials.token is None
    assert connection.credentials.device_code is None
    assert connection.model == "auto"
    assert client.get("/api/agent").get_json()["usage"]["cost"] is None


def test_signout_clears_local_identity_when_remote_session_is_unavailable(client):
    from src.routes import agent

    connection = agent._connection()
    connection.credentials.token = "invalid-test-credential"
    session = _main_session()
    session.credentials.token = "invalid-test-credential"
    session.session_id = "missing-session"
    session.usage["cost"] = 1
    response = client.delete("/api/agent/auth")
    assert response.status_code == 200
    assert response.get_json()["cleanup_error"]
    assert connection.credentials.token is None
    assert _main_session().session_id is None
    assert client.get("/api/agent").get_json()["usage"]["cost"] is None


@pytest.mark.parametrize("method", ["post", "delete"])
def test_provider_change_keeps_connection_when_session_cleanup_fails(client, monkeypatch, method):
    from src.routes import agent

    async def unavailable(token, session_id):
        raise RuntimeError("Copilot unavailable")

    monkeypatch.setattr(agent, "_delete_session", unavailable)
    connection = agent._connection()
    connection.credentials.token = "github-key"
    _main_session().session_id = "stored-session"
    response = getattr(client, method)("/api/agent/provider", json={
        "provider": "openai", "model": "gpt-4o", "api_key": "key",
    })
    assert response.status_code == 503
    assert response.get_json()["error"] == "Could not clear the previous conversation."
    assert connection.credentials.token == "github-key" and connection.credentials.provider is None
    assert _main_session().session_id == "stored-session"
    assert not connection.lock.locked()


def test_provider_change_deletes_the_stored_session_and_respects_the_lock(client, monkeypatch):
    from src.routes import agent

    deleted = []

    async def delete(token, session_id):
        deleted.append(session_id)

    monkeypatch.setattr(agent, "_delete_session", delete)
    monkeypatch.setattr(agent, "_persist_agent_credentials", lambda **kwargs: None)
    connection = agent._connection()
    connection.credentials.token = "github-key"
    _main_session().session_id = "stored-session"
    with connection.lock:
        assert client.delete("/api/agent/provider").status_code == 409
    response = client.delete("/api/agent/provider")
    assert response.status_code == 200
    assert deleted == ["stored-session"]
    assert _main_session().session_id is None


def _configure_provider(monkeypatch):
    """A provider the queue can run turns with (the runner is faked; the MCP server only has to exist)."""
    from src.routes import agent

    async def delete(token, session_id):
        pass

    monkeypatch.setattr(agent, "_delete_session", delete)
    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", __file__)
    Path(os.environ["VULNSCOUT_CONFIG"]).write_text("AI_PROVIDER=openai\nAI_AUTH_CREDENTIALS=key\nAI_MODEL=gpt-4o\n")


def _run_blocked(monkeypatch):
    """Configure a provider and start a chat turn that runs until the returned event is set."""
    _configure_provider(monkeypatch)
    started, release = threading.Event(), threading.Event()

    async def blocked(call):
        started.set()
        while not release.is_set():
            await asyncio.sleep(0.01)
        return await _answer(call)

    queue = _queue()
    monkeypatch.setattr(queue, "_runner", blocked)
    [request], _ = queue.enqueue("main", "web", [{"kind": "message", "text": "Hello"}])
    thread = threading.Thread(target=queue.run_once, args=("chat",))
    thread.start()
    assert started.wait(10)
    return request, release, thread


def test_connection_changes_wait_for_the_running_request_but_model_selection_does_not(client, monkeypatch):
    from src.routes import agent

    monkeypatch.setattr(agent, "_persist_agent_credentials", lambda **kwargs: None)
    request, release, thread = _run_blocked(monkeypatch)
    connection = agent._connection()
    try:
        for method, path in (("post", "/api/agent/provider"), ("delete", "/api/agent/provider"),
                             ("delete", "/api/agent/auth")):
            response = getattr(client, method)(path, json={"provider": "local", "model": "m",
                                                           "base_url": "http://localhost:11434/v1"})
            assert response.status_code == 409
            assert response.get_json() == {"error": agent.BUSY_AGENT_ERROR}
        connection.credentials.device_code, connection.credentials.device_expires = "code", time.monotonic() + 60
        monkeypatch.setattr(agent, "_github_form", lambda *args: pytest.fail("the code must not be exchanged"))
        assert client.post("/api/agent/auth/poll").status_code == 409
        assert connection.credentials.device_code == "code"
        assert not connection.lock.locked()
        response = client.post("/api/agent/model", json={"model": "gpt-4o"})
        assert response.status_code == 200 and response.get_json() == {"model": "gpt-4o"}
    finally:
        release.set()
        thread.join(10)
    assert _queue().get_request(request["id"])["status"] == "done"
    assert connection.credentials.provider.kind == "openai"
    assert client.delete("/api/agent/provider").status_code == 200


def test_provider_change_fails_waiting_requests_of_conversations_with_history(client, monkeypatch):
    from src.routes import agent

    monkeypatch.setattr(agent, "_persist_agent_credentials", lambda **kwargs: None)
    _configure_provider(monkeypatch)
    queue = _queue()
    message = {"kind": "message", "text": "Hello"}
    queue.enqueue("main", "web", [message])
    queue.run_once("chat")
    status = client.get("/api/agent").get_json()
    assert [entry["role"] for entry in status["messages"]] == ["user", "assistant"]
    assert status["usage"]["cost"] == 1
    [waiting], _ = queue.enqueue("main", "web", [message])
    queue._pause("no_ai_config", "Paused.")
    assert client.post("/api/agent/model", json={"model": "gpt-4o"}).status_code == 200
    assert queue.paused is None
    assert client.delete("/api/agent/provider").status_code == 200
    assert queue.get_request(waiting["id"])["error_code"] == "connection_changed"
    status = client.get("/api/agent").get_json()
    assert status["messages"] == [] and status["usage"]["cost"] is None


def test_device_sign_in_wakes_the_paused_queue(client, monkeypatch):
    from src.routes import agent

    async def signed_in(token):
        return {"authenticated": True, "login": "octocat"}

    async def logged_out(token):
        return {"authenticated": False, "login": None}

    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", __file__)
    monkeypatch.setattr(agent, "_auth_status", logged_out)  # no Copilot user logged in on this machine
    queue = _queue()
    [request], _ = queue.enqueue("main", "web", [{"kind": "message", "text": "Hello"}], model="gpt-4o")
    assert queue.run_once("chat") is None and queue.paused["code"] == "no_ai_config"
    connection = agent._connection()
    connection.credentials.device_code, connection.credentials.device_expires = "code", time.monotonic() + 60
    answers = [{"error": "authorization_pending"}, {"access_token": "gho_new"}]
    monkeypatch.setattr(agent, "_github_form", lambda *args: answers.pop(0))
    monkeypatch.setattr(agent, "_token_status", signed_in)
    assert client.post("/api/agent/auth/poll").get_json()["status"] == "pending"
    assert queue.paused is not None
    assert client.post("/api/agent/auth/poll").get_json()["status"] == "connected"
    assert queue.paused is None
    assert queue.run_once("chat") == request["id"]
    assert queue.get_request(request["id"])["status"] == "done"


def test_copilot_model_lookup_failures_are_reported(client, monkeypatch):
    from src.routes import agent

    async def unavailable(token):
        raise RuntimeError("Copilot unavailable")

    monkeypatch.setattr(agent, "_auth_status", unavailable)
    monkeypatch.setattr(agent, "_models", unavailable)
    agent._connection().credentials.token = "github-key"
    assert client.get("/api/agent").get_json()["authenticated"] is False
    assert client.get("/api/agent/models").status_code == 503
    response = client.post("/api/agent/model", json={"model": "auto"})
    assert response.status_code == 503
    assert response.get_json()["error"] == "Unable to verify this Copilot model."


@pytest.mark.parametrize("context, error", [
    ({"page": "ai", "view": {"selectedProjectId": "invalid"}}, "Invalid project scope."),
    ({"page": "ai", "view": {"selectedProjectId": "00000000-0000-0000-0000-000000000000"}}, "Project not found."),
    ({"page": "metrics", "variantId": "invalid"}, "Invalid variant scope."),
])
def test_scope_rejects_unknown_projects_and_variants(client, context, error):
    from src.routes import agent

    with client.application.app_context():
        with pytest.raises(ValueError, match=error):
            agent._scope_for_context(context)


def test_expired_device_code_is_cleared(client):
    from src.routes import agent

    connection = agent._connection()
    connection.credentials.device_code = "expired-code"
    connection.credentials.device_expires = time.monotonic() - 1
    assert client.post("/api/agent/auth/poll").status_code == 410
    assert connection.credentials.device_code is None


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
    write_calls = set()
    payloads = [AssistantMessageDeltaData.from_dict({"messageId": "message", "deltaContent": "Answer"}),
                ToolExecutionStartData.from_dict({"toolCallId": "call", "toolName": "mcp-tool",
                                                   "mcpToolName": "get_vulnerability",
                                                   "arguments": {"private": "secret"}}),
                ToolExecutionCompleteData.from_dict({"toolCallId": "call", "success": True,
                                                      "result": {"content": "private tool result"}})]
    for payload in payloads:
        _publish_event(SimpleNamespace(data=payload), records.append, write_calls)
    assert records == [{"type": "delta", "message_id": "message", "text": "Answer"},
                       {"type": "tool_start", "id": "call", "name": "get_vulnerability"},
                       {"type": "tool_end", "id": "call", "success": True, "write": False}]
    for payload in (ToolExecutionStartData.from_dict({"toolCallId": "write", "toolName": "mcp-tool",
                                                      "mcpToolName": "write_assessment"}),
                    ToolExecutionCompleteData.from_dict({"toolCallId": "write", "success": True})):
        _publish_event(SimpleNamespace(data=payload), records.append, write_calls)
    assert records[-1] == {"type": "tool_end", "id": "write", "success": True, "write": True}
    _publish_event(SimpleNamespace(data={"private": "secret"}), records.append)
    _publish_event(SimpleNamespace(data=payloads[0]), None)
    assert len(records) == 5


def _assess_sdk(monkeypatch, *, delay=0.0, disconnect_error=None, models=("model",)):
    """Install a fake SDK client; return (captured create/resume options + sent message, deleted session ids)."""
    import asyncio
    from src.routes import agent

    captured, deleted = {}, []

    class Session:
        session_id = "assess-session"

        def on(self, callback):
            pass

        async def send_and_wait(self, message, *, timeout=60.0):
            # The SDK waits only `timeout` seconds (default 60) for the turn, whatever the caller's outer limit.
            captured["send_timeout"] = timeout
            captured["message"] = message
            await asyncio.sleep(delay)
            return SimpleNamespace(data=SimpleNamespace(content="Assessed"))

        async def disconnect(self):
            if disconnect_error:
                raise disconnect_error

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def list_models(self):
            return [SimpleNamespace(id=model, policy=None) for model in models]

        async def create_session(self, **options):
            captured.update(options)
            return Session()

        async def resume_session(self, session_id, **options):
            captured.update(options, resumed=session_id)
            return Session()

        async def delete_session(self, session_id):
            deleted.append(session_id)

    monkeypatch.setattr(agent, "_sdk_client", lambda token: Client())
    return captured, deleted


def test_ephemeral_assess_profile_turn_limits_tools_and_deletes_its_session(monkeypatch):
    import asyncio
    from src.routes import agent, agent_skills

    monkeypatch.delenv("VULNSCOUT_AGENT_WEB_ACCESS", raising=False)
    captured, deleted = _assess_sdk(monkeypatch)
    conversation = agent.Conversation(session_id="old", session_scope="{}")
    conversation.usage["cost"] = 5
    reply, usage = asyncio.run(agent._reply(
        conversation, "Assess", agent._mcp_path(), "model", "{}",
        profile=agent_skills.ASSESS, timeout=5, api_url="http://127.0.0.1:4321", ephemeral=True,
    ))

    assert reply == "Assessed" and "resumed" not in captured
    assert usage == agent._session_usage([])  # the turn's own usage, not the conversation's total
    assert captured["send_timeout"] == 5
    tools = agent.READ_TOOLS + agent_skills.ASSESS.write_tools
    server = captured["mcp_servers"]["vulnscout"]
    assert server["tools"] == list(tools)
    assert server["env"]["VULNSCOUT_BASE_URL"] == "http://127.0.0.1:4321"
    assert captured["available_tools"] == ([f"mcp:vulnscout-{tool}" for tool in tools]
                                           + ["builtin:skill", "builtin:view", "builtin:web_fetch"])
    assert not {"update_project_context", "update_variant_context", "write_assessment_review"} & set(tools)
    assert captured["enable_skills"] is True and captured["agent"] == "vulnscout-assess"
    assert captured["custom_agents"][0]["skills"] == ["cve-assessment"]
    assert captured["on_permission_request"](SimpleNamespace(kind="shell"), {}).kind == "reject"
    assert captured["system_message"]["content"] == agent_skills.PROFILE_SYSTEM_MESSAGE
    assert captured["message"] == "Use the cve-assessment skill.\n\nAssess"
    assert deleted == ["assess-session"]
    assert conversation.session_id == "old"


def test_profile_options_are_resupplied_on_resume(monkeypatch):
    import asyncio
    from src.routes import agent, agent_skills

    monkeypatch.setenv("VULNSCOUT_AGENT_WEB_ACCESS", "off")
    captured, _ = _assess_sdk(monkeypatch)
    conversation = agent.Conversation(session_id="thread-session", session_scope="{}")
    asyncio.run(agent._reply(conversation, "Is it fixed?", agent._mcp_path(), "model", "{}",
                             profile=agent_skills.REVIEW))
    assert captured["resumed"] == "thread-session"
    assert captured["agent"] == "vulnscout-review"
    assert "builtin:web_fetch" not in captured["available_tools"]
    assert "mcp:vulnscout-write_assessment" not in captured["available_tools"]
    assert "Web research is unavailable" in captured["message"]


@pytest.mark.parametrize("remove", ["root", "skill"])
def test_profile_turn_fails_when_skills_are_missing(monkeypatch, tmp_path, remove):
    import asyncio
    import re
    import shutil
    from src.routes import agent, agent_skills

    root = tmp_path / "skills"
    shutil.copytree(Path(agent_skills.__file__).resolve().parents[2] / ".github" / "skills", root)
    if remove == "root":
        shutil.rmtree(root)
    else:
        (root / "cve-assessment" / "SKILL.md").unlink()
    monkeypatch.setenv("VULNSCOUT_SKILLS_PATH", str(root))
    captured, _ = _assess_sdk(monkeypatch)
    expected = (agent_skills.SKILLS_MISSING_ERROR if remove == "root"
                else "Agent skill cve-assessment could not be loaded.")
    with pytest.raises(agent_skills.AgentSkillError, match=re.escape(expected)):
        asyncio.run(agent._reply(agent.Conversation(), "Review", agent._mcp_path(), "model", "{}",
                                 profile=agent_skills.REVIEW))
    assert captured == {}


def test_agent_turn_timeout_is_configurable(monkeypatch):
    import asyncio
    from src.routes import agent

    _, deleted = _assess_sdk(monkeypatch, delay=1)
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(agent._reply(
            agent.Conversation(), "Assess", agent._mcp_path(), "model", "{}",
            timeout=0.01, ephemeral=True,
        ))
    assert deleted == ["assess-session"]


def test_ephemeral_session_is_deleted_when_disconnect_fails(monkeypatch):
    import asyncio
    from src.routes import agent

    _, deleted = _assess_sdk(monkeypatch, disconnect_error=RuntimeError("disconnect failed"))
    with pytest.raises(RuntimeError, match="disconnect failed"):
        asyncio.run(agent._reply(
            agent.Conversation(), "Assess", agent._mcp_path(), "model", "{}", ephemeral=True,
        ))
    assert deleted == ["assess-session"]


@pytest.mark.parametrize("stored, resumed", [(None, False), ("thread-session", True)])
def test_on_session_receives_the_created_or_resumed_session(monkeypatch, stored, resumed):
    import asyncio
    from src.routes import agent

    captured, _ = _assess_sdk(monkeypatch)
    sessions = []

    def on_session(session_id):
        assert "message" not in captured  # before the turn is sent
        sessions.append(session_id)

    conversation = agent.Conversation(session_id=stored, session_scope="{}")
    asyncio.run(agent._reply(conversation, "Hi", agent._mcp_path(), "model", "{}", on_session=on_session))
    assert sessions == ["assess-session"]
    assert ("resumed" in captured) is resumed


def test_failed_on_session_still_disconnects_and_deletes_ephemeral_session(monkeypatch):
    import asyncio
    from src.routes import agent

    captured, deleted = _assess_sdk(monkeypatch)

    def on_session(session_id):
        raise RuntimeError("stopped")

    with pytest.raises(RuntimeError, match="stopped"):
        asyncio.run(agent._reply(agent.Conversation(), "Hi", agent._mcp_path(), "model", "{}",
                                 ephemeral=True, on_session=on_session))
    assert "message" not in captured
    assert deleted == ["assess-session"]
