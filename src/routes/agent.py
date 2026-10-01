"""Local Copilot chat backed by the VulnScout stdio MCP server."""

import asyncio
import ipaddress
import json
import os
import queue
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from flask import Blueprint, Response, current_app, jsonify, request

from ..models.project import Project
from ..models.variant import Variant


READ_TOOLS = (
    "get_assessment", "list_assessments_by_vuln", "has_ai_assessment",
    "get_vulnerability", "find_project_id", "find_variant_id", "list_variants",
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
PAGES = {"metrics", "packages", "vulnerabilities", "scans", "review", "exports", "settings", "ai", "unknown"}
agent_blueprint = Blueprint("agent", __name__)


@dataclass
class Conversation:
    token: str | None = None
    session_id: str | None = None
    session_scope: str | None = None
    session_writes: bool = False
    model: str = "auto"
    usage: dict = field(default_factory=lambda: {"cost": None, "input_tokens": None, "output_tokens": None})
    messages: list[dict[str, str]] = field(default_factory=list)
    device_code: str | None = None
    device_expires: float = 0.0
    device_interval: int = 5
    last_used: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock)


_conversations: dict[str, Conversation] = {}
_store_lock = threading.Lock()


def _container_gateway():
    if not (Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()):
        return None
    try:
        with Path("/proc/net/route").open(encoding="ascii") as routes:
            next(routes)
            for route in routes:
                fields = route.split()
                if fields[1] == "00000000" and int(fields[3], 16) & 0x3 == 0x3:
                    return str(ipaddress.IPv4Address(bytes.fromhex(fields[2])[::-1]))
    except (OSError, ValueError, IndexError, StopIteration):
        pass
    return None


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
    trusted = {"127.0.0.1", "::1"}
    gateway = _container_gateway()
    if gateway:
        trusted.add(gateway)
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
    if value:
        return Path(value).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "vulnscout_mcp" / "server.py"


def _github_form(url, fields):
    github_request = urllib.request.Request(url, data=urlencode(fields).encode(),
                                            headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(github_request, timeout=15) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        return json.loads(error.read() or b"{}")


def _device_poll_interval(current, result):
    return max(current + (5 if result.get("error") == "slow_down" else 0),
               int(result.get("interval") or 0))


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


async def _models(token):
    async with _sdk_client(token) as client:
        return [{"id": model.id, "name": model.name} for model in await client.list_models()
                if model.policy is None or model.policy.state == "enabled"]


async def _delete_session(token, session_id):
    async with _sdk_client(token) as client:
        await client.delete_session(session_id)


class UnavailableModelError(ValueError):
    pass


def _session_usage(events):
    from copilot.session_events import AssistantUsageData

    usage = [event.data for event in events if isinstance(event.data, AssistantUsageData)]
    costs = [event.cost for event in usage if event.cost is not None]
    inputs = [event.input_tokens for event in usage if event.input_tokens is not None]
    outputs = [event.output_tokens for event in usage if event.output_tokens is not None]
    return {
        "cost": sum(costs) if costs else None,
        "input_tokens": sum(inputs) if inputs else None,
        "output_tokens": sum(outputs) if outputs else None,
    }


def _add_usage(previous, current):
    return {key: previous[key] if current[key] is None else (previous[key] or 0) + current[key]
            for key in ("cost", "input_tokens", "output_tokens")}


def _bounded_string(value, limit, error):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(error)
    return value


def _bounded_strings(values, count, limit, error):
    if not isinstance(values, list) or len(values) > count or any(
        not isinstance(item, str) or len(item) > limit for item in values
    ):
        raise ValueError(error)
    return values


def _bounded_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1000000:
        raise ValueError("Invalid selection count.")
    return value


def _scan_option(value):
    if not isinstance(value, bool):
        raise ValueError("Invalid scan option.")
    return value


def _view_context(view):
    if not isinstance(view, dict):
        raise ValueError("Invalid view context.")
    filtered = {}
    for key in (
        "openVulnerabilityId", "search", "section", "selectedProjectId", "selectedProjectName",
        "selectedVariantId", "selectedVariantName", "openScanId", "exportType", "exportMode",
        "exportCategory", "refreshMode",
    ):
        if view.get(key) is not None:
            filtered[key] = _bounded_string(view[key], 200, "Invalid view selection.")
    for key in (
        "visibleVulnerabilityIds", "selectedVulnerabilityIds", "visiblePackageIds", "visibleScanIds",
        "matchingVariantIds", "selectedVariantIds", "selectedExportKeys", "enabledExportDocuments",
        "selectedScanTypes", "selectedRefreshTypes",
    ):
        if view.get(key) is not None:
            filtered[key] = _bounded_strings(
                view[key], 100, 200,
                "Filter the table to 100 vulnerabilities or fewer before sending all displayed IDs.",
            )
    for key in ("visibleCount", "selectionCount"):
        if key in view:
            filtered[key] = _bounded_count(view[key])
    for key in ("hideEmptyScans", "excludeKernel", "excludeNative"):
        if key in view:
            filtered[key] = _scan_option(view[key])
    return filtered


def _validated_context(value):
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("page") not in PAGES:
        raise ValueError("Invalid page context.")
    context = {"page": value["page"]}
    for key in ("projectId", "variantId", "baseVariantId", "compareOperation", "multiOperation"):
        if value.get(key) is not None:
            context[key] = _bounded_string(value[key], 100, "Invalid page scope.")
    if value.get("variantIds") is not None:
        context["variantIds"] = _bounded_strings(value["variantIds"], 50, 100, "Invalid variant selection.")
    if "variantCount" in value:
        context["variantCount"] = _bounded_count(value["variantCount"])
    if value.get("view") is not None:
        context["view"] = _view_context(value["view"])
    return context


def _scope_for_context(context):
    ai_page = context is not None and context.get("page") == "ai"
    view = (context.get("view") or {}) if ai_page else {}
    project_id = view.get("selectedProjectId") if ai_page else context.get("projectId") if context else None
    try:
        project = Project.get_by_id(UUID(project_id)) if project_id else None
    except ValueError as exc:
        raise ValueError("Invalid project scope.") from exc
    if project_id and project is None:
        raise ValueError("Project not found.")
    projects = [project] if project else [] if ai_page else Project.get_all()
    allowed = {str(variant.id) for item in projects for variant in Variant.get_by_project(item.id)}
    selected = []
    if ai_page:
        selected = [view["selectedVariantId"]] if view.get("selectedVariantId") else []
    elif context:
        selected = [value for value in (context.get("variantId"), context.get("baseVariantId")) if value]
        selected.extend(context.get("variantIds") or [])
    try:
        selected_ids = {str(UUID(value)) for value in selected}
    except ValueError as exc:
        raise ValueError("Invalid variant scope.") from exc
    if selected_ids and (not project or not selected_ids <= allowed):
        raise ValueError("Selected variants do not belong to the current project.")
    variants = sorted(selected_ids) if selected_ids else sorted(allowed)
    return json.dumps({"project_ids": [str(item.id) for item in projects], "variant_ids": variants},
                      separators=(",", ":"))


def _publish_event(event, publish):
    from copilot.session_events import AssistantMessageDeltaData, ToolExecutionStartData, ToolExecutionCompleteData

    if publish is None:
        return
    event_data = event.data
    if isinstance(event_data, AssistantMessageDeltaData):
        publish({"type": "delta", "message_id": event_data.message_id,
                 "text": event_data.delta_content})
    elif isinstance(event_data, ToolExecutionStartData):
        publish({"type": "tool_start", "id": event_data.tool_call_id,
                 "name": event_data.mcp_tool_name or event_data.tool_name})
    elif isinstance(event_data, ToolExecutionCompleteData):
        publish({"type": "tool_end", "id": event_data.tool_call_id, "success": event_data.success})


async def _reply(conversation, message, allow_writes, path, model, scope, publish=None):
    from copilot.session import PermissionHandler

    tools = READ_TOOLS + WRITE_TOOLS if allow_writes else READ_TOOLS
    async with _sdk_client(conversation.token) as client:
        models = await client.list_models()
        if model not in {choice.id for choice in models if choice.policy is None or choice.policy.state == "enabled"}:
            raise UnavailableModelError("Selected model is not available for this account.")
        options = {
            "model": model,
            "streaming": publish is not None,
            "on_permission_request": PermissionHandler.approve_all,
            "available_tools": [f"mcp:vulnscout-{tool}" for tool in tools],
            "mcp_servers": {"vulnscout": {
                "type": "local", "command": sys.executable,
                "args": [str(path)], "cwd": str(path.parent),
                "env": {
                    "VULNSCOUT_BASE_URL": os.getenv("VULNSCOUT_AGENT_API_URL", "http://localhost:7275"),
                    "VULNSCOUT_AGENT_SCOPE": scope,
                },
                "tools": list(READ_TOOLS + WRITE_TOOLS),
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
        if (
            conversation.session_id
            and conversation.session_scope == scope
        ):
            session = await client.resume_session(conversation.session_id, **options)
        else:
            session = await client.create_session(**options)
        try:
            live_events = []

            def on_event(event):
                live_events.append(event)
                _publish_event(event, publish)

            session.on(on_event)
            event = await asyncio.wait_for(session.send_and_wait(message), timeout=120)
            if event is None or not event.data.content:
                raise RuntimeError("The agent did not return a response.")
            conversation.session_id = session.session_id
            conversation.session_scope = scope
            conversation.session_writes = allow_writes
            usage = _add_usage(conversation.usage, _session_usage(live_events))
            return event.data.content, usage
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
                      "messages": conversation.messages,
                      "model": conversation.model, "usage": conversation.usage}, key)


@agent_blueprint.route("/api/agent/auth", methods=["POST", "DELETE"])
def agent_auth():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    if request.method == "DELETE":
        with conversation.lock:
            cleanup_error = None
            if conversation.session_id:
                try:
                    asyncio.run(_delete_session(conversation.token, conversation.session_id))
                except Exception:
                    current_app.logger.exception("Could not delete agent session")
                    cleanup_error = "Could not delete the stored conversation on the Copilot server."
            conversation.token = None
            conversation.session_id = None
            conversation.session_scope = None
            conversation.session_writes = False
            conversation.device_code = None
            conversation.device_expires = 0.0
            conversation.device_interval = 5
            conversation.messages.clear()
            conversation.model = "auto"
            conversation.usage = {"cost": None, "input_tokens": None, "output_tokens": None}
        return _response({"authenticated": False, "cleanup_error": cleanup_error}, key)
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
        conversation.device_interval = interval
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
            conversation.device_interval = _device_poll_interval(conversation.device_interval, result)
            return _response({"status": "pending", "interval": conversation.device_interval}, key)
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
        conversation.session_scope = None
        conversation.session_writes = False
        conversation.messages.clear()
        conversation.model = "auto"
        conversation.usage = {"cost": None, "input_tokens": None, "output_tokens": None}
    return _response({"status": "connected", **auth}, key)


@agent_blueprint.route("/api/agent/models", methods=["GET"])
def agent_models():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    try:
        models = asyncio.run(_models(conversation.token))
    except Exception:
        current_app.logger.exception("Could not list agent models")
        return _response({"error": "Unable to load available Copilot models."}, key, 503)
    return _response({"models": models}, key)


@agent_blueprint.route("/api/agent/model", methods=["POST"])
def agent_model():
    if error := _access_error():
        return error
    key, conversation = _conversation()
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("model"), str) or len(data["model"]) > 100:
        return _response({"error": "Invalid model selection."}, key, 400)
    if not conversation.lock.acquire(blocking=False):
        return _response({"error": "The agent is already responding."}, key, 409)
    try:
        try:
            choices = asyncio.run(_models(conversation.token))
        except Exception:
            current_app.logger.exception("Could not verify agent model")
            return _response({"error": "Unable to verify this Copilot model."}, key, 503)
        if data["model"] not in {choice["id"] for choice in choices}:
            return _response({"error": "Selected model is not available for this account."}, key, 400)
        conversation.model = data["model"]
        return _response({"model": conversation.model}, key)
    finally:
        conversation.lock.release()


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
        conversation.session_scope = None
        conversation.session_writes = False
        conversation.messages.clear()
        conversation.usage = {"cost": None, "input_tokens": None, "output_tokens": None}
    return _response({"messages": [], "usage": conversation.usage}, key)


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
    model = data.get("model", conversation.model)
    if not isinstance(model, str) or not model or len(model) > 100:
        return _response({"error": "Invalid model selection."}, key, 400)
    try:
        context = _validated_context(data.get("context"))
    except ValueError as exc:
        return _response({"error": str(exc)}, key, 400)
    user_message = message.strip()
    agent_prompt = user_message
    if context:
        agent_prompt = (f"{user_message}\n\nCurrent VulnScout browser view (selection only; verify facts with MCP): "
                        f"{json.dumps(context, separators=(',', ':'))}")
    path = _mcp_path()
    if path is None or not path.is_file():
        return _response({"error": (
            "Bundled MCP server not found. Check the installation or VULNSCOUT_MCP_SERVER_PATH override."
        )}, key, 503)
    try:
        scope = _scope_for_context(context)
    except ValueError as exc:
        return _response({"error": str(exc)}, key, 400)
    if not conversation.lock.acquire(blocking=False):
        return _response({"error": "The agent is already responding."}, key, 409)
    if request.headers.get("Accept") == "application/x-ndjson":
        return _stream_reply(key, conversation, agent_prompt, user_message,
                             data.get("allow_writes", False), path, model, scope)
    return _json_reply(key, conversation, agent_prompt, user_message,
                       data.get("allow_writes", False), path, model, scope)


def _json_reply(key, conversation, agent_prompt, user_message, allow_writes, path, model, scope):
    try:
        try:
            reply, usage = asyncio.run(_reply(conversation, agent_prompt, allow_writes, path, model, scope))
        except UnavailableModelError as exc:
            return _response({"error": str(exc)}, key, 400)
        except Exception:
            current_app.logger.exception("Agent request failed")
            return _response({
                "error": "Agent request failed. Check Copilot sign-in, MCP server, and backend logs.",
            }, key, 503)
        conversation.messages.extend(({"role": "user", "content": user_message},
                                      {"role": "assistant", "content": reply}))
        conversation.model = model
        conversation.usage = usage
        return _response({"reply": reply, "model": model, "usage": usage}, key)
    finally:
        conversation.lock.release()


def _stream_events(events, disconnected):
    try:
        yield json.dumps({"type": "status", "text": "Connecting to Copilot..."}) + "\n"
        while True:
            try:
                event = events.get(timeout=10)
            except queue.Empty:
                yield json.dumps({"type": "heartbeat"}) + "\n"
                continue
            yield json.dumps(event) + "\n"
            if event["type"] in ("done", "error"):
                break
    finally:
        disconnected.set()


def _stream_reply(key, conversation, agent_prompt, user_message, allow_writes, path, model, scope):
    events: queue.Queue = queue.Queue(maxsize=256)
    disconnected = threading.Event()
    logger = current_app.logger

    def publish(event):
        while not disconnected.is_set():
            try:
                events.put(event, timeout=0.1)
                return
            except queue.Full:
                continue

    def run():
        try:
            reply, usage = asyncio.run(_reply(conversation, agent_prompt, allow_writes, path, model, scope, publish))
            conversation.messages.extend(({"role": "user", "content": user_message},
                                          {"role": "assistant", "content": reply}))
            conversation.model = model
            conversation.usage = usage
            publish({"type": "done", "reply": reply, "model": model, "usage": usage})
        except UnavailableModelError as exc:
            publish({"type": "error", "error": str(exc)})
        except Exception:
            logger.exception("Agent streaming request failed")
            publish({"type": "error",
                     "error": "Agent request failed. Check Copilot sign-in, MCP server, and backend logs."})
        finally:
            conversation.last_used = time.monotonic()
            conversation.lock.release()

    response = Response(_stream_events(events, disconnected), mimetype="application/x-ndjson",
                        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
    response.set_cookie(COOKIE, key, httponly=True, samesite="Strict", secure=request.is_secure, max_age=3600)
    response.call_on_close(disconnected.set)
    try:
        threading.Thread(target=run, daemon=True).start()
    except Exception:
        conversation.lock.release()
        raise
    return response


def init_app(app):
    app.register_blueprint(agent_blueprint)
