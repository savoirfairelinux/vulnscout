# Agent chat (local MVP)

The **Agent** button opens a chat panel alongside VulnScout on desktop and a full-screen panel on smaller screens. Closing the panel preserves its draft and any response in progress until the page is reloaded. The Flask backend uses the GitHub Copilot SDK to launch the bundled `vulnscout_mcp/server.py` over stdio with the backend's Python interpreter. MCP dependencies are included in `requirements/base.txt` and the normal container image; no separate repository or bootstrap environment is required. The agent can read vulnerabilities, assessments, variants, and project context. Assessment and context write tools are available only when **Allow changes** is selected; the selection resets after each message.

This proof of concept is opt-in and **localhost-only**. It is intended for one developer running the backend and frontend on the same machine, not a shared or remotely accessible VulnScout deployment. Do not forward the agent port to other users: the server can access the local user's Copilot identity. Access tokens stay on the backend, in server memory until an hour of inactivity; they are not sent to the browser or persisted in browser storage. Copilot may keep session state in its own local directory.

## Start locally

From the demo worktree, with Python 3.11+ and Node.js installed:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements/base.txt
export VULNSCOUT_AGENT_ENABLED=1
export FLASK_SQLALCHEMY_DATABASE_URI="sqlite:///$PWD/instance/vulnscout.db"
export FLASK_SCAN_FILE="$(pwd)/instance/agent-demo-status.txt"
mkdir -p instance
printf '__END_OF_SCAN_SCRIPT__\n' > "$FLASK_SCAN_FILE"
.venv/bin/flask --app src.bin.webapp:create_app db upgrade
.venv/bin/flask --app src.bin.webapp:create_app run --host 127.0.0.1 --port 7275
```

The ignored `instance/vulnscout.db` in this worktree is an independent SQLite snapshot of the populated database under the original checkout's `.vulnscout/cache/`. It has been migrated to this branch's schema; running `db upgrade` above affects only the demo copy. Do not point the demo at the original checkout's database. In another terminal:

```sh
cd frontend
npm ci
VITE_API_URL=http://127.0.0.1:7275 npm run dev -- --host 127.0.0.1
```

Open the Vite URL and select **Agent** in the navbar. The Vite dev proxy forwards only `/api/agent` to the local Flask server. In production builds the browser uses the same origin as Flask. If the backend is on another port, set `VULNSCOUT_AGENT_API_URL` for both the backend's MCP connection and the Vite dev proxy.

`VULNSCOUT_MCP_SERVER_PATH` is an optional override for a custom stdio entrypoint. Remove old overrides pointing at a separate MCP checkout to use the bundled implementation. External MCP clients may still use the repository's `vulnscout_mcp/run_server.py` bootstrap launcher; the built-in agent does not need it.

## Run with `./vulnscout --serve --dev`

Build the normal image from this repository; it includes both the Copilot SDK and the MCP package:

```sh
docker build -t vulnscout:agent-demo .
```

Add these lines to `.vulnscout/cache/config.env`, run `./vulnscout --stop`, and then run `./vulnscout --serve --dev`:

```sh
VULNSCOUT_IMAGE=vulnscout:agent-demo
VULNSCOUT_AGENT_ENABLED=1
VULNSCOUT_AGENT_TRUSTED_CLIENTS=172.17.0.1
```

Remove any old `VULNSCOUT_MCP_SERVER_PATH` setting from `config.env`. Development mode mounts both `src/` and `vulnscout_mcp/`; rebuild the image when dependencies change. Requests from the host reach the container from the Docker bridge gateway (`docker network inspect bridge`), not loopback. `VULNSCOUT_AGENT_TRUSTED_CLIENTS` lists these extra client addresses. The container has no host Copilot sign-in. Select **Sign in with GitHub** in the panel; no token entry or OAuth App configuration is needed.

## Connect and chat

The panel detects an existing Copilot CLI or GitHub CLI sign-in on the backend host. Otherwise, select **Sign in with GitHub**, open the GitHub link, enter the short code shown in the panel, and approve access. The panel connects automatically after approval. The browser never receives the resulting access token. After a container restart, sign in again.

Device sign-in defaults to the public GitHub Copilot (VS Code) OAuth client ID, following the Virtual Engineer Copilot connector. This is a GitHub-owned application, not a VulnScout-owned registration; its availability and policies are outside VulnScout's control. GitHub's approval screen identifies that application. An operator can override the client ID using an OAuth App with device flow enabled (in `config.env` for the container):

```sh
VULNSCOUT_AGENT_GITHUB_CLIENT_ID=<OAuth App client ID>
```

The client ID is public; no client secret is needed. The app requests only the `read:user` scope. The backend exchanges the device code, so the resulting token does not reach the browser. A GitHub account with Copilot access (including the free tier) is required. Choose from the models available to that account in the toolbar selector; switching models keeps the current conversation. **Sign out** discards the in-memory token and deletes that agent session. The **+** button starts a **New conversation** after confirmation: it deletes the SDK session and resets messages, draft, write permission, and usage while retaining the connection and selected model. **Never ask again** remembers the confirmation preference in this browser. Earlier sessions created before starting a new conversation may still exist in the local Copilot directory.

Each message includes the active page and project/variant selection, including comparison modes. When a project is shown across all variants, its variant UUIDs are included in the scope; an open vulnerability also contributes its matching variant UUIDs. The vulnerability table sends its filtered, sorted vulnerability IDs (across pagination), search and selected IDs; the Review and Metrics views also share their displayed IDs and open vulnerability. The SBOM table shares filtered package IDs; Scans shares displayed scan IDs, the open result, and scan options; Export shares the wizard step, type, mode, enabled document groups, and selected variants/formats; Settings shares its active tab; AI Context shares its selected project and variant names and IDs. Unsaved form text and API keys are not sent automatically. The vulnerability modal has an Agent button in its header. Suggested actions, **Assess vulnerability**, and **Assess displayed** send immediately when selected; none turns on write access automatically. For lists over 100 items (50 at project scope), the request sends only the count, and the bulk action asks you to narrow the table. No partial list is silently presented as the full display.

Expand **Conversation usage** below the composer to see cumulative input/output tokens when supplied by the SDK and the sum of `assistant.usage.cost` across the current conversation. It does not infer a currency or a token price; when no cost is reported, it says **Cost not reported**. Each assistant response has a copy action. Sending keeps the user message visible while a response is pending; failures restore the draft for retry.

Responses stream as text arrives. Expand **Activity** to see tool names and running, completed, or failed status. This log does not expose internal reasoning, tool arguments, or raw tool results, and is retained only until the page reloads. Closing the panel keeps the stream running. If the connection is interrupted, the backend may still finish the turn; reload to check the stored reply before retrying, especially when writes were enabled.

The messages endpoint supports `Accept: application/x-ndjson` for status, text delta, tool activity, heartbeat, and terminal `done` or `error` records. Existing clients without this header still receive a single JSON response. Validation errors remain JSON HTTP errors. Proxies must not buffer streamed responses.

Read tools are available by default. Enabling writes for a message makes the MCP assessment and context write tools available for that turn, without a second approval prompt. Verify the requested target and scope before enabling writes. This MVP uses in-memory conversation state; it does not provide durable multi-user sessions or an OAuth app registration flow.
