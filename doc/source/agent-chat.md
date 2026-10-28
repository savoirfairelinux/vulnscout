# AI Agent Development

This page covers the embedded Agent's architecture, configuration, and
development environment. For provider connection, chat usage, assessments,
and human review, see [AI Assessments](ai-assessments.md).
Normal use requires only the standard container, not the development setup below.

## Architecture and Access Boundaries

The Flask backend uses the GitHub Copilot SDK to launch the bundled
`vulnscout_mcp/server.py` over stdio with the backend's Python interpreter.
SDK and MCP dependencies are included in `requirements/base.txt` and the normal
container image; no separate repository or bootstrap environment is required.
External clients can use the repository's `vulnscout_mcp/run_server.py` launcher;
the embedded Agent does not need it.

The embedded Agent is **localhost-only**, including local host-to-container
forwarding through the gateway or rootless Podman pasta. It is intended for a
single user, not a shared or remotely accessible deployment. Do not forward it
to other users: the backend can access the local user's Copilot identity and
configured provider keys, and the agent can change assessments and context.
Conversation state is managed in memory; this is not a durable multi-user
session service.

The SDK session exposes only the allowed VulnScout MCP tools. External skill
discovery, shell tools, arbitrary filesystem access, and web research are not
enabled. Uploaded source is inspected through scoped codebase-reference tools,
without extraction or execution. **Codebase Path** is an external-client hint,
not a container mount. Dependency discovery does not establish runtime use or
exploitability.

`flask ai-assess` (`./vulnscout assess`) runs the same SDK turn without the web
session. Each turn is ephemeral (its SDK session is deleted) and exposes only the
read tools plus `write_assessment`. The command serves the app's API on an
ephemeral `127.0.0.1` port for the MCP server, because the CLI process does not
run the web server. It reads provider settings from the same `config.env`.

## Configuration and Credentials

Access tokens and API keys stay on the backend and are never returned to the
browser or stored in browser storage. Successful connector flows persist
`AI_PROVIDER`, `AI_AUTH_CREDENTIALS`, and optional `AI_MODEL` and `AI_BASE_URL`
in `config.env`. Copilot may also keep SDK session state in its local directory.

Without `VULNSCOUT_CONFIG`, standalone Flask stores configuration in
`$XDG_CONFIG_HOME/vulnscout/config.env` (default `~/.config/vulnscout/config.env`);
no root access is needed. Set `VULNSCOUT_CONFIG` to use another writable file.
The container entrypoint explicitly uses `/etc/vulnscout/config.env`, bind-mounted
from the host cache. Persisted configuration is owner-readable/writable only
(`0600`); both CLI `--config-list` paths redact `AI_AUTH_CREDENTIALS`.

AI settings are read from this file on restart, not copied into container
metadata. When the file exists it is authoritative, even if AI keys are absent,
so disconnecting cannot resurrect inherited credentials. Environment-only AI
settings are supported when no config file exists. Values written by the
dashboard are shell-quoted and control characters are rejected.
Selecting a model from an environment-only setup saves all current AI settings
with it, so the new authoritative file preserves the connection after restart.

Manually written AI assignments must be literal shell words: unquoted values
(including embedded `#`), single-quoted values, and simple double-quoted values
are supported, with optional whitespace-separated trailing comments.
Shell expansions, commands, and escaped dollar signs/backticks inside double
quotes are rejected rather than evaluated or silently treated as literals;
use single quotes for literal dollar signs and backticks.

Model selections are persisted as `AI_MODEL`, including GitHub Copilot
(device sign-in or an existing CLI identity), and restored on restart. After
restarting a non-GitHub provider that has no saved model, the toolbar requires
an explicit selection rather than sending Copilot's `auto` model ID to that
provider.
The **Model** selector above the chat stays visible in both conversation and
**Conversations** views and is disabled while any request is running.

### GitHub Device Sign-in

Device sign-in defaults to the public GitHub Copilot (VS Code) OAuth client ID.
This is a GitHub-owned application, not a VulnScout-owned registration; its
availability and policies are outside VulnScout's control. GitHub's approval
screen identifies that application.

An operator can override the client ID using an OAuth App with device flow
enabled, in `config.env` for the container:

```sh
VULNSCOUT_AGENT_GITHUB_CLIENT_ID='your-oauth-app-client-id'
```

The client ID is public; no client secret is needed. The app requests only the
`read:user` scope. The backend exchanges the device code, so the resulting token
does not reach the browser. VulnScout does not provide an OAuth application
registration flow.

## Start Locally Without the Container

From the repository root, with Python 3.11+ and Node.js 22 installed, create a
separate local database for development:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements/base.txt
export FLASK_SQLALCHEMY_DATABASE_URI="sqlite:///$PWD/instance/vulnscout.db"
export FLASK_SCAN_FILE="$(pwd)/instance/agent-demo-status.txt"
mkdir -p instance
printf '__END_OF_SCAN_SCRIPT__\n' > "$FLASK_SCAN_FILE"
.venv/bin/flask --app src.bin.webapp:create_app db upgrade
.venv/bin/flask --app src.bin.webapp:create_app run --host 127.0.0.1 --port 7275
```

This creates or upgrades `instance/vulnscout.db`; no populated snapshot is
shipped with the repository. Use a fresh path if that file already contains
data you want to preserve. Back up an existing database before upgrading it.
Import an SBOM through **Settings → project → variant → Import SBOM** to
populate the local instance. In another terminal, start the frontend:

```sh
cd frontend
npm ci
VITE_API_URL= npm run dev -- --host 127.0.0.1
```

Open the Vite URL. For connector setup, follow
[Connect an AI Provider](ai-assessments.md#connect-an-ai-provider).
The panel can detect an existing Copilot CLI or GitHub CLI sign-in on the backend
host; a container does not automatically inherit the host's identity.

### Proxy and MCP Overrides

The Vite dev proxy forwards `/api` to local Flask, with a separate `/api/agent`
target controlled by `VULNSCOUT_AGENT_API_URL`. In production builds the browser
uses the same origin as Flask. If the backend is on another port, set
`VITE_API_URL` for regular endpoints and `VULNSCOUT_AGENT_API_URL` for the agent
proxy and backend MCP connection.

`VULNSCOUT_MCP_SERVER_PATH` optionally overrides the stdio entrypoint. Remove old
overrides pointing at a separate MCP checkout to use the bundled implementation.

## Develop in the Container

Build the normal image from this repository; it includes the SDK and MCP package:

```sh
docker build -t vulnscout:agent-demo .
```

Set the locally built image in `.vulnscout/cache/config.env`:

```sh
VULNSCOUT_IMAGE=vulnscout:agent-demo
```

Run `./vulnscout stop`, then `./vulnscout serve --dev`. Remove any old
`VULNSCOUT_MCP_SERVER_PATH` setting from `config.env`. Development mode mounts
both `src/` and `vulnscout_mcp/`; rebuild the image when dependencies change.
Requests from the host reach the container through its default gateway, which
the agent recognizes automatically.

## Page Context and Target Resolution

Each message includes the active page and project/variant selection, including
comparison modes. All-variant project views include their variant UUIDs;
an open vulnerability contributes its matching variant UUIDs.

| View | Additional context |
| --- | --- |
| Vulnerabilities | Filtered, sorted vulnerability IDs across pagination, search and selection |
| Review and Metrics | Displayed IDs and open vulnerability |
| SBOM | Filtered package IDs |
| Scans | Displayed scan IDs, open result and scan options |
| Export | Wizard step, type, mode, enabled document groups and selected variants/formats |
| Settings | Active tab |
| AI Context | Selected project and variant names and IDs |

Unsaved form text and API keys are not included automatically.

Assessment requests are batched within the 8,000-character message limit without
splitting a variant across requests. If one variant's packages alone exceed the
limit, target resolution fails and asks the user to narrow the selection.
Displayed-list actions send only the count above 100 items (50 at project scope),
requiring narrowing rather than silently passing incomplete IDs.
In two-variant intersections, base-variant packages are checked against active
vulnerability observations, not just packages still installed in the SBOM.

Bulk custom-assessment reviews validate the complete target set before queuing.
A queued review succeeds only when every expected target has a freshly saved,
non-stale review; a text response is not proof of persistence.

## Streaming and Session Behavior

The messages endpoint supports `Accept: application/x-ndjson` for status, text
delta, tool activity, heartbeat, and terminal `done` or `error` records.
Clients without this header still receive a single JSON response. Validation
errors remain JSON HTTP errors. Proxies must not buffer streamed responses.

Activity events expose tool names and execution status, not internal reasoning,
tool arguments, or raw tool results. Usage displays sum `assistant.usage.cost`
across the current conversation without inferring a currency or token price.
Connector logos use Lobe Icons Static SVG (MIT).

One agent panel hosts the main conversation and separate action conversations,
all served by a shared FIFO queue. Hiding the panel, changing scope, or
navigating away does not cancel queued or running work. Reloading the browser
discards the in-memory queue and conversations, but does not guarantee
cancellation of a backend turn; inspect stored results before retrying writes
after an interruption. For user-facing
conversation lifetimes, queue controls, and retry behavior, see
[AI Assessments](ai-assessments.md#chat-scope-and-conversations).
