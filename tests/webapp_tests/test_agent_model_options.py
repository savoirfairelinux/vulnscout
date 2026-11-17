"""Copilot model capabilities, persisted overrides and SDK propagation."""

import asyncio
import os
from pathlib import Path

import pytest
from copilot.client import ModelInfo

from src.routes import agent
from .test_agent_chat import _assess_sdk, client  # noqa: F401


def _model(*, efforts=True, long_context=True):
    return ModelInfo.from_dict({
        "id": "model", "name": "Model",
        "capabilities": {
            "supports": {"reasoningEffort": efforts},
            "limits": {"max_context_window_tokens": 1000000},
        },
        "supportedReasoningEfforts": ["low", "medium", "high", "xhigh", "max", "invented"],
        "defaultReasoningEffort": "high",
        "billing": {"tokenPrices": {
            **({"longContext": {"maxPromptTokens": 900000}} if long_context else {}),
        }},
    })


def test_copilot_model_metadata_controls_options(monkeypatch):
    _assess_sdk(monkeypatch, models=(_model(),))
    [choice] = asyncio.run(agent._models(None))
    assert choice == {
        "id": "model", "name": "Model", "context_tiers": ["default", "long_context"],
        "reasoning_efforts": ["low", "medium", "high", "xhigh", "max"],
        "default_reasoning_effort": "high",
    }
    choice = agent._model_choice(_model(efforts=False, long_context=False))
    assert choice == {"id": "model", "name": "Model"}  # a 1M limit alone is not a Copilot tier


@pytest.mark.parametrize("resume", [False, True])
@pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max"])
def test_persisted_options_reach_sdk_create_and_resume(client, monkeypatch, resume, effort):  # noqa: F811
    captured, _ = _assess_sdk(monkeypatch, models=(_model(),))
    agent._persist_agent_credentials(token="github-key")
    response = client.post("/api/agent/model", json={
        "model": "model", "context_tier": "long_context", "reasoning_effort": effort,
    })
    assert response.status_code == 200
    assert response.get_json() == {
        "model": "model", "context_tier": "long_context", "reasoning_effort": effort,
    }
    content = Path(os.environ["VULNSCOUT_CONFIG"]).read_text()
    assert "AI_CONTEXT_TIER=long_context" in content and f"AI_REASONING_EFFORT={effort}" in content
    restarted = agent.Conversation(session_id="previous" if resume else None, session_scope="{}")
    assert agent._load_env_credentials(restarted) is None
    asyncio.run(agent._reply(restarted, "Hello", agent._mcp_path(), restarted.model, "{}"))
    assert captured["context_tier"] == "long_context" and captured["reasoning_effort"] == effort
    assert ("resumed" in captured) is resume


@pytest.mark.parametrize("options", [
    {"context_tier": "1m"}, {"context_tier": None}, {"context_tier": []},
    {"reasoning_effort": "minimal"}, {"reasoning_effort": "none"},
    {"reasoning_effort": "invented"}, {"reasoning_effort": []},
])
def test_invalid_options_do_not_change_settings(client, monkeypatch, options):  # noqa: F811
    _assess_sdk(monkeypatch, models=(_model(),))
    assert client.post("/api/agent/model", json={"model": "model", **options}).status_code == 400
    assert not Path(os.environ["VULNSCOUT_CONFIG"]).exists()
    assert agent._connection().model == "auto"


@pytest.mark.parametrize("options", [{"context_tier": "long_context"}, {"reasoning_effort": "high"}])
def test_capability_absence_rejects_overrides(client, monkeypatch, options):  # noqa: F811
    _assess_sdk(monkeypatch, models=(_model(efforts=False, long_context=False),))
    assert client.post("/api/agent/model", json={"model": "model", **options}).status_code == 400
    provider = agent.ProviderConnection("openai", "model", "key", "", models=[{"id": "model", "name": "Model"}])
    agent._connection().credentials.provider = provider
    assert client.post("/api/agent/model", json={"model": "model", **options}).status_code == 400


def test_options_reset_on_model_selection_and_persistence_failure_is_atomic(client, monkeypatch):  # noqa: F811
    _assess_sdk(monkeypatch, models=(_model(), "other"))
    options = {"model": "model", "context_tier": "long_context", "reasoning_effort": "high"}
    assert client.post("/api/agent/model", json=options).status_code == 200
    with monkeypatch.context() as patch:
        patch.setattr(agent, "persist_env_keys", lambda updates: (False, "AI_CONTEXT_TIER"))
        assert client.post("/api/agent/model", json={"model": "other"}).status_code == 500
    assert agent._connection().credentials.context_tier == "long_context"
    assert client.post("/api/agent/model", json={"model": "other"}).get_json() == {
        "model": "other", "context_tier": "default", "reasoning_effort": None,
    }
    restarted = agent.Conversation()
    assert agent._load_env_credentials(restarted) is None
    assert restarted.credentials.context_tier == "default" and restarted.credentials.reasoning_effort is None


def test_sdk_rechecks_stale_capabilities_and_model_override_uses_defaults(monkeypatch):
    captured, _ = _assess_sdk(monkeypatch, models=(_model(efforts=False, long_context=False), "other"))
    credentials = agent.AgentCredentials(options_model="model", context_tier="long_context", reasoning_effort="high")
    conversation = agent.Conversation(credentials=credentials)
    with pytest.raises(agent.UnavailableModelError, match="context tier"):
        asyncio.run(agent._reply(conversation, "Hello", agent._mcp_path(), "model", "{}"))
    assert not captured
    asyncio.run(agent._reply(conversation, "Hello", agent._mcp_path(), "other", "{}"))
    assert captured["context_tier"] == "default" and "reasoning_effort" not in captured


def test_standalone_cli_loads_options_and_passes_them_to_ephemeral_sdk_turn(client, monkeypatch):  # noqa: F811
    from src.bin._ai_runner import load_agent

    captured, deleted = _assess_sdk(monkeypatch, models=(_model(),))
    agent._persist_agent_credentials(token="github-key")
    assert client.post("/api/agent/model", json={
        "model": "model", "context_tier": "long_context", "reasoning_effort": "high",
    }).status_code == 200
    monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH")
    credentials, model, path = load_agent(None)
    asyncio.run(agent._reply(
        agent.Conversation(credentials=credentials), "Hello", path, model, "{}", ephemeral=True,
    ))
    assert captured["context_tier"] == "long_context" and captured["reasoning_effort"] == "high"
    assert deleted == ["assess-session"]


def test_sign_out_clears_persisted_options(client, monkeypatch):  # noqa: F811
    _assess_sdk(monkeypatch, models=(_model(),))
    agent._persist_agent_credentials(token="github-key")
    assert client.post("/api/agent/model", json={
        "model": "model", "context_tier": "long_context", "reasoning_effort": "high",
    }).status_code == 200
    assert client.delete("/api/agent/auth").status_code == 200
    assert not any(key in agent._agent_environment() for key in ("AI_CONTEXT_TIER", "AI_REASONING_EFFORT"))
    assert agent._connection().credentials.context_tier == "default"
    assert agent._connection().credentials.reasoning_effort is None


@pytest.mark.parametrize("setting", [
    "AI_CONTEXT_TIER=1m", "AI_REASONING_EFFORT=minimal",
    "AI_PROVIDER=openai\nAI_CONTEXT_TIER=long_context",
])
def test_invalid_environment_options_fail_configuration(client, setting):  # noqa: F811
    Path(os.environ["VULNSCOUT_CONFIG"]).write_text(setting + "\n")
    assert agent._load_env_credentials(agent.Conversation()) is not None
