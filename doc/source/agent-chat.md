# Agent chat (local MVP)

The **Agent** button opens a chat panel alongside VulnScout. The Flask backend uses the GitHub Copilot SDK to launch [vulnscout-mcp](https://github.com/savoirfairelinux/vulnscout-mcp) over stdio. The agent can read vulnerabilities, assessments, and project context. Assessment and context write tools are available only when **Allow assessment and context changes for the next message** is selected; the selection resets after each message.

This proof of concept is opt-in and **localhost-only**. It is intended for one developer running the backend and frontend on the same machine, not a shared or remotely accessible VulnScout deployment. Do not forward the agent port to other users: the server can access the local user's Copilot identity. Access tokens stay on the backend, in server memory until an hour of inactivity; they are not sent to the browser or persisted in browser storage. Copilot may keep session state in its own local directory.

## Start locally

From the demo worktree, with Python 3.11+ and Node.js installed:

```sh
git clone https://github.com/savoirfairelinux/vulnscout-mcp.git ../vulnscout-mcp
python3 -m venv .venv
.venv/bin/pip install -r requirements/base.txt
export VULNSCOUT_AGENT_ENABLED=1
export VULNSCOUT_MCP_SERVER_PATH="$(realpath ../vulnscout-mcp/run_server.py)"
export FLASK_SQLALCHEMY_DATABASE_URI="sqlite:///$PWD/instance/vulnscout.db"
export FLASK_SCAN_FILE="$(pwd)/instance/agent-demo-status.txt"
mkdir -p instance
printf '__END_OF_SCAN_SCRIPT__\n' > "$FLASK_SCAN_FILE"
.venv/bin/flask --app src.bin.webapp:create_app db upgrade
.venv/bin/flask --app src.bin.webapp:create_app run --host 127.0.0.1 --port 7275
```

The ignored `instance/vulnscout.db` in this worktree is an independent SQLite snapshot of the populated database under the original checkout's `.vulnscout/cache/`. It has been migrated to this branch's schema; running `db upgrade` above affects only the demo copy. Do not point the demo at the original checkout's database. The MCP launcher creates its own virtual environment on first use. In another terminal:

```sh
cd frontend
npm ci
VITE_API_URL=http://127.0.0.1:7275 npm run dev -- --host 127.0.0.1
```

Open the Vite URL and select **Agent** in the navbar. The Vite dev proxy forwards only `/api/agent` to the local Flask server. In production builds the browser uses the same origin as Flask. If the backend is on another port, set `VULNSCOUT_AGENT_API_URL` for both the backend's MCP connection and the Vite dev proxy.

## Run with `./vulnscout --serve --dev`

The container needs the SDK and vulnscout-mcp. Build a local image with both from the `vulnscout-mcp` checkout:

```sh
docker buildx build --builder default -t vulnscout:agent-demo -f - . <<'EOF'
FROM docker.io/sflinux/vulnscout:v0.22
RUN pip3 install --no-cache-dir --break-system-packages github-copilot-sdk==1.0.14 \
    && python3 -c "from copilot._cli_download import download_cli; download_cli()"
COPY requirements.txt run_server.py server.py client.py /opt/vulnscout-mcp/
COPY tools /opt/vulnscout-mcp/tools
RUN python3 -m venv /opt/vulnscout-mcp/venv \
    && /opt/vulnscout-mcp/venv/bin/pip install --no-cache-dir -r /opt/vulnscout-mcp/requirements.txt
EOF
```

Add these lines to `.vulnscout/cache/config.env`, run `./vulnscout --stop`, and then run `./vulnscout --serve --dev`:

```sh
VULNSCOUT_IMAGE=vulnscout:agent-demo
VULNSCOUT_AGENT_ENABLED=1
VULNSCOUT_MCP_SERVER_PATH=/opt/vulnscout-mcp/run_server.py
VULNSCOUT_AGENT_TRUSTED_CLIENTS=172.17.0.1
```

Requests from the host reach the container from the Docker bridge gateway (`docker network inspect bridge`), not loopback. `VULNSCOUT_AGENT_TRUSTED_CLIENTS` lists these extra client addresses. The container has no host Copilot sign-in. Select **Sign in with GitHub** in the panel; no token entry or OAuth App configuration is needed.

## Connect and chat

The panel detects an existing Copilot CLI or GitHub CLI sign-in on the backend host. Otherwise, select **Sign in with GitHub**, open the GitHub link, enter the short code shown in the panel, and approve access. The panel connects automatically after approval. The browser never receives the resulting access token. After a container restart, sign in again.

Device sign-in defaults to the public GitHub Copilot (VS Code) OAuth client ID, following the Virtual Engineer Copilot connector. This is a GitHub-owned application, not a VulnScout-owned registration; its availability and policies are outside VulnScout's control. GitHub's approval screen identifies that application. An operator can override the client ID using an OAuth App with device flow enabled (in `config.env` for the container):

```sh
VULNSCOUT_AGENT_GITHUB_CLIENT_ID=<OAuth App client ID>
```

The client ID is public; no client secret is needed. The app requests only the `read:user` scope. The backend exchanges the device code, so the resulting token does not reach the browser. A GitHub account with Copilot access (including the free tier) is required. Choose from the models available to that account in the **Model** selector; switching models keeps the current conversation. **Sign out** discards the in-memory token and deletes that agent session. **Clear chat** deletes the SDK session and resets its messages and usage while retaining the connection and selected model. Earlier sessions created before using Clear chat may still exist in the local Copilot directory.

The panel shows cumulative input/output tokens when supplied by the SDK, and sums `assistant.usage.cost` across the current conversation when the SDK supplies a cost value. It does not infer a currency or a token price; when no cost is reported, it says **Cost not reported**.

Read tools are available by default. Enabling writes for a message makes the MCP assessment and context write tools available for that turn, without a second approval prompt. Verify the requested target and scope before enabling writes. This MVP uses request/response chat and in-memory browser conversation state; it does not provide streaming, durable multi-user sessions, or an OAuth app registration flow.
