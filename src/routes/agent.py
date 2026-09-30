"""Local, opt-in Copilot chat backed by the VulnScout stdio MCP server."""

import asyncio
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from flask import Blueprint, current_app, jsonify, request


READ_TOOLS = (
    "get_assessment", "list_assessments_by_vuln", "has_ai_assessment",
    "get_vulnerability", "find_project_id", "find_variant_id",
    "get_merged_context", "get_project_context", "get_custom_assessment",
    "list_custom_assessments",
)
WRITE_TOOLS = (
    "write_assessment", "update_ai_assessment", "update_project_context",
    "update_variant_context", "write_assessment_review",
)
COOKIE = "vulnscout_agent"
GITHUB_COPILOT_CLIENT_ID = "Iv1.b507a08c87ecfe98"
GITHUB_DEVICE_URL = "https://github.com/login/device/code"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_VERIFY_URL = "https://github.com/login/device"
agent_blueprint = Blueprint("agent", __name__)


@dataclass
class Conversation:
    token: str | None = None
    session_id: str | None = None
    messages: list[dict[str, str]] = field(default_factory=list)
    device_code: str | None = None
    device_expires: float = 0.0
    last_used: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock)


_conversations: dict[str, Conversation] = {}
_store_lock = threading.Lock()


def _conversation():
    key = request.cookies.get(COOKIE, "")
    with _store_lock:
        expired = [key for key, value in _conversations.items()
                   if time.monotonic() - value.last_used > 3600]
        for old_key in expired:
            del _conversations[old_key]
        if key not in _conversations:
            key = secrets.token_urlsafe(32)
            _conversations[key] = Conversation()
        conversation = _conversations[key]
        conversation.last_used = time.monotonic()
    return key, conversation


def _response(payload, key, status=200):
    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(COOKIE, key, httponly=True, samesite="Strict",
                        secure=request.is_secure, max_age=3600)
    return response


def _access_error():
    if os.getenv("VULNSCOUT_AGENT_ENABLED") != "1":
        return jsonify(error="Agent chat is disabled on this server."), 404
    extra_clients = os.getenv("VULNSCOUT_AGENT_TRUSTED_CLIENTS", "").split(",")
    trusted = {"127.0.0.1", "::1"} | {value.strip() for value in extra_clients if value.strip()}
    if request.remote_addr not in trusted:
        return jsonify(error="Agent chat is available only on localhost."), 403
    if urlsplit(request.host_url).hostname not in ("127.0.0.1", "localhost", "::1"):
        return jsonify(error="Agent chat requires a localhost host."), 403
    origin = request.headers.get("Origin")
    if request.method != "GET" and origin and origin.rstrip("/") != request.host_url.rstrip("/"):
        return jsonify(error="Invalid request origin."), 403
    return None


def _mcp_path():
    value = os.getenv("VULNSCOUT_MCP_SERVER_PATH", "")
    return Path(value).expanduser().resolve() if value else None


def _github_form(url, fields):
    github_request = urllib.request.Request(url, data=urlencode(fields).encode(),
                                            headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(github_request, timeout=15) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        return json.loads(error.read() or b"{}")


def _sdk_client(token):
    from copilot import CopilotClient

    return CopilotClient(github_token=token, use_logged_in_user=token is None,
                         working_directory=str(Path(__file__).resolve().parents[2]))


async def _auth_status(token):
    async with _sdk_client(token) as client:
        status = await client.get_auth_status()
        return {"authenticated": status.isAuthenticated, "login": status.login}


async def _token_status(token):
    async with _sdk_client(token) as client:
        status = await client.get_auth_status()
        auth = {"authenticated": status.isAuthenticated, "login": status.login}
        if status.isAuthenticated:
            try:
                await client.list_models()
            except Exception as error:
                # The SDK surfaces Copilot's HTTP denial only inside the JSON-RPC message.
                if '"status":401' not in str(error) and '"status":403' not in str(error):
                    raise
                auth["authenticated"] = False
        return auth


async def _delete_session(token, session_id):
    async with _sdk_client(token) as client:
        await client.delete_session(session_id)


async def _reply(conversation, message, allow_writes, path):
    from copilot.session import PermissionHandler

    tools = READ_TOOLS + WRITE_TOOLS if allow_writes else READ_TOOLS
    async with _sdk_client(conversation.token) as client:
        options = {
            "on_permission_request": PermissionHandler.approve_all,
            "available_tools": [f"mcp:vulnscout-{tool}" for tool in tools],
            "mcp_servers": {"vulnscout": {
                "type": "local", "command": sys.executable,
                "args": [str(path)], "cwd": str(path.parent),
                "env": {"VULNSCOUT_BASE_URL": os.getenv("VULNSCOUT_AGENT_API_URL", "http://localhost:7275")},
                "tools": list(tools),
            }},
            "system_message": {"mode": "append", "content": (
                "You are the VulnScout agent. Use only VulnScout MCP tools for facts and actions. "
                "Explain what you changed. If a tool returns an error, report it; do not invent results."
            )},
            "enable_config_discovery": False,
            "enable_host_git_operations": False,
            "enable_skills": False,
            "enable_file_hooks": False,
        }
        if conversation.session_id:
            session = await client.resume_session(conversation.session_id, **options)
        else:
            session = await client.create_session(**options)
        try:
            event = await asyncio.wait_for(session.send_and_wait(message), timeout=120)
            if event is None or not event.data.content:
                raise RuntimeError("The agent did not return a response.")
            conversation.session_id = session.session_id
            return event.data.content
        finally:
            await session.disconnect()


@agent_blueprint.route("/api/agent", methods=["GET"])
def agent_status():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    path = _mcp_path()
    configured = path is not None and path.is_file()
    try:
        auth = asyncio.run(_auth_status(conversation.token))
    except (ImportError, OSError, RuntimeError, ValueError):
        auth = {"authenticated": False, "login": None}
    return _response({**auth, "configured": configured,
                      "device_login": True,
                      "token_connected": conversation.token is not None,
                      "messages": conversation.messages}, key)


@agent_blueprint.route("/api/agent/auth", methods=["POST", "DELETE"])
def agent_auth():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    if request.method == "DELETE":
        with conversation.lock:
            if conversation.session_id:
                try:
                    asyncio.run(_delete_session(conversation.token, conversation.session_id))
                except Exception:
                    current_app.logger.exception("Could not delete agent session")
                    return _response({"error": "Could not delete the stored conversation."}, key, 503)
            conversation.token = None
            conversation.session_id = None
            conversation.device_code = None
            conversation.messages.clear()
        return _response({"authenticated": False}, key)
    client_id = os.getenv("VULNSCOUT_AGENT_GITHUB_CLIENT_ID") or GITHUB_COPILOT_CLIENT_ID
    try:
        result = _github_form(GITHUB_DEVICE_URL, {"client_id": client_id, "scope": "read:user"})
        interval = int(result.get("interval", 5))
        expires_in = int(result.get("expires_in", 900))
    except (OSError, ValueError):
        current_app.logger.exception("Could not start GitHub device sign-in")
        return _response({"error": "Could not reach GitHub."}, key, 503)
    if not isinstance(result.get("device_code"), str) or not isinstance(result.get("user_code"), str):
        return _response({"error": (
            "GitHub rejected the sign-in request. Check VULNSCOUT_AGENT_GITHUB_CLIENT_ID and that "
            "device flow is enabled for the OAuth App."
        )}, key, 503)
    verification_uri = result.get("verification_uri")
    if not isinstance(verification_uri, str) or not verification_uri.startswith("https://github.com/"):
        verification_uri = GITHUB_VERIFY_URL
    with conversation.lock:
        conversation.device_code = result["device_code"]
        conversation.device_expires = time.monotonic() + expires_in
    return _response({"user_code": result["user_code"], "verification_uri": verification_uri,
                      "interval": interval}, key)


@agent_blueprint.route("/api/agent/auth/poll", methods=["POST"])
def agent_auth_poll():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    with conversation.lock:
        if not conversation.device_code or time.monotonic() > conversation.device_expires:
            conversation.device_code = None
            return _response({"error": "The GitHub sign-in code expired. Start again."}, key, 410)
        try:
            result = _github_form(GITHUB_TOKEN_URL, {
                "client_id": os.getenv("VULNSCOUT_AGENT_GITHUB_CLIENT_ID") or GITHUB_COPILOT_CLIENT_ID,
                "device_code": conversation.device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            })
        except (OSError, ValueError):
            current_app.logger.exception("Could not poll GitHub device sign-in")
            return _response({"error": "Could not reach GitHub."}, key, 503)
        if result.get("error") in ("authorization_pending", "slow_down"):
            return _response({"status": "pending", "interval": result.get("interval")}, key)
        conversation.device_code = None
        token = result.get("access_token")
        if not isinstance(token, str):
            message = {"access_denied": "GitHub sign-in was cancelled.",
                       "expired_token": "The GitHub sign-in code expired. Start again."}
            return _response({"error": message.get(result.get("error"), "GitHub sign-in failed.")}, key, 401)
        try:
            auth = asyncio.run(_token_status(token))
        except Exception:
            current_app.logger.exception("Could not verify agent sign-in")
            return _response({"error": "Could not verify Copilot access."}, key, 503)
        if not auth["authenticated"]:
            return _response({"error": "This GitHub account does not have Copilot access."}, key, 401)
        conversation.token = token
        conversation.session_id = None
        conversation.messages.clear()
    return _response({"status": "connected", **auth}, key)


@agent_blueprint.route("/api/agent/conversation", methods=["DELETE"])
def agent_reset():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    with conversation.lock:
        if conversation.session_id:
            try:
                asyncio.run(_delete_session(conversation.token, conversation.session_id))
            except Exception:
                current_app.logger.exception("Could not delete agent session")
                return _response({"error": "Could not delete the stored conversation."}, key, 503)
        conversation.session_id = None
        conversation.messages.clear()
    return _response({"messages": []}, key)


@agent_blueprint.route("/api/agent/messages", methods=["POST"])
def agent_message():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _response({"error": "Expected a JSON object."}, key, 400)
    message = data.get("message")
    if not isinstance(message, str) or not message.strip() or len(message) > 8000:
        return _response({"error": "Enter a message of at most 8000 characters."}, key, 400)
    if not isinstance(data.get("allow_writes", False), bool):
        return _response({"error": "Invalid write permission."}, key, 400)
    user_message = message.strip()
    path = _mcp_path()
    if path is None or not path.is_file():
        return _response({"error": "Set VULNSCOUT_MCP_SERVER_PATH to the vulnscout-mcp run_server.py path."}, key, 503)
    if not conversation.lock.acquire(blocking=False):
        return _response({"error": "The agent is already responding."}, key, 409)
    try:
        try:
            reply = asyncio.run(_reply(conversation, user_message, data.get("allow_writes", False), path))
        except Exception:
            current_app.logger.exception("Agent request failed")
            return _response({
                "error": "Agent request failed. Check Copilot sign-in, MCP server, and backend logs.",
            }, key, 503)
        conversation.messages.extend(({"role": "user", "content": user_message},
                                      {"role": "assistant", "content": reply}))
        return _response({"reply": reply}, key)
    finally:
        conversation.lock.release()


def init_app(app):
    app.register_blueprint(agent_blueprint)
