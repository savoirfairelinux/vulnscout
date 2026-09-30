import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_AGENT_ENABLED", "1")
    monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH", raising=False)
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


def test_new_conversation_does_not_clear_authentication(client):
    result = client.delete("/api/agent/conversation").get_json()
    assert result["messages"] == []


def test_status_uses_real_copilot_runtime(client):
    response = client.get("/api/agent")
    assert response.status_code == 200
    assert response.get_json()["configured"] is False
    assert isinstance(response.get_json()["authenticated"], bool)
    assert response.get_json()["messages"] == []
    assert response.headers["Set-Cookie"].startswith("vulnscout_agent=")
