# Agent chat (local MVP)

The **Agent** button, to the left of the project/variant selector, opens the global chat panel alongside VulnScout on desktop and a full-screen panel on smaller screens. Closing the panel preserves its draft and any response in progress until the page is reloaded. The Flask backend uses the GitHub Copilot SDK to launch the bundled `vulnscout_mcp/server.py` over stdio with the backend's Python interpreter. MCP dependencies are included in `requirements/base.txt` and the normal container image; no separate repository or bootstrap environment is required. The agent can read vulnerabilities, assessments, variants, and project context. Assessment and context write tools are available when the user requests a change; there is no per-message write switch.

All four chat entry points (global, bulk assessment, review, and vulnerability
details) share one **AI queue**, opened with the clock button in any chat header.
It shows the originating chat, running request, pending requests, and failures.
Requests run one at a time in submission order, retaining their original
conversation and project/variant context. You can submit another message while
a response is running. Closing a chat, changing scope, or navigating away does
not cancel queued work; reloading the browser does discard the in-memory queue.
Failures pause the queue until you retry or remove the failed request. **Clear
all** removes waiting and failed requests, never the running request.
Connection changes require an empty queue. The AI queue is separate from the
navigation bar's scan/upload/export operation queue.

This proof of concept is **localhost-only** (including local host-to-container forwarding through the gateway or rootless Podman pasta). It is intended for one developer running the backend and frontend on the same machine, not a shared or remotely accessible VulnScout deployment. Do not forward the agent port to other users: the server can access the local user's Copilot identity and configured provider keys, and the agent can change assessments. Access tokens and API keys stay on the backend and are never sent back to the browser; browser storage is not used. Agent credentials are kept in memory and are also persisted in `config.env` (`AI_PROVIDER`, `AI_AUTH_CREDENTIALS`, optional `AI_MODEL` and `AI_BASE_URL`) when connector flows succeed, so they survive restarts and can later support CI-style AI execution. Copilot may keep session state in its own local directory.

## Start locally

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
Model selections made in the agent chatbox selector are also persisted as
`AI_MODEL`, including GitHub Copilot (device sign-in or an existing CLI identity),
and restored on restart. After restarting a non-GitHub provider that has no saved
model, the composer requires an explicit selection rather than sending Copilot's
`auto` model ID to that provider.

From the demo worktree, with Python 3.11+ and Node.js installed:

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

The ignored `instance/vulnscout.db` in this worktree is an independent SQLite snapshot of the populated database under the original checkout's `.vulnscout/cache/`. It has been migrated to this branch's schema; running `db upgrade` above affects only the demo copy. Do not point the demo at the original checkout's database. In another terminal:

If an older database is already stamped at revision `z2c3d4e5f6a7` but lacks `assessments.created_at`, run `db upgrade` after updating: the follow-up migration repairs the missing assessment and context timestamp columns.

```sh
cd frontend
npm ci
VITE_API_URL= npm run dev -- --host 127.0.0.1
```

Open the Vite URL and select **Agent** in the navbar. The Vite dev proxy forwards `/api` to the local Flask server, with a separate `/api/agent` target controlled by `VULNSCOUT_AGENT_API_URL`. In production builds the browser uses the same origin as Flask. If the backend is on another port, set `VITE_API_URL` for regular endpoints and `VULNSCOUT_AGENT_API_URL` for the agent proxy and backend MCP connection.

`VULNSCOUT_MCP_SERVER_PATH` is an optional override for a custom stdio entrypoint. Remove old overrides pointing at a separate MCP checkout to use the bundled implementation. External MCP clients may still use the repository's `vulnscout_mcp/run_server.py` bootstrap launcher; the built-in agent does not need it.

## Run with `./vulnscout serve --dev`

Build the normal image from this repository; it includes both the Copilot SDK and the MCP package:

```sh
docker build -t vulnscout:agent-demo .
```

Select the locally built image in `.vulnscout/cache/config.env`, run `./vulnscout stop`, and then run `./vulnscout serve --dev`:

```sh
VULNSCOUT_IMAGE=vulnscout:agent-demo
```

Remove any old `VULNSCOUT_MCP_SERVER_PATH` setting from `config.env`. Development mode mounts both `src/` and `vulnscout_mcp/`; rebuild the image when dependencies change. Requests from the host reach the container through its default gateway, which the agent recognizes automatically. The container has no host Copilot sign-in. Choose a connector in the agent setup panel.

## Connect and chat

The **AI** tab's **Codebase References** drop zone accepts source files and
ZIP/TAR/TAR.GZ/TGZ archives for the selected variant. The embedded Agent inspects
them using scoped `list_codebase_files`, `search_codebase` and
`read_codebase_file` MCP tools, without extraction, execution or arbitrary
filesystem access. **Codebase Path** is only a hint for external clients; it
does not mount host code into the container. See
[Codebase references](ai-assessments.md) for
upload limits, persistence and privacy considerations. The embedded Agent's
system instructions cover reference inspection; it does not enable external
skill discovery or filesystem tools.

The panel detects an existing Copilot CLI or GitHub CLI sign-in on the backend host. Otherwise, setup starts with **Select a connector**. Choose **GitHub Copilot**, **OpenAI**, **Microsoft Foundry**, **Anthropic**, or **Local model**, then select **Next**. Use **Back** to change connectors. For GitHub Copilot, select **Sign in with GitHub**, open the GitHub link, enter the short code shown in the panel, and approve access. Step 3 checks the connection and shows a confirmation before **Start using**. The browser never receives the resulting access token. When already connected, use the plug button to reopen connector setup.

Device sign-in defaults to the public GitHub Copilot (VS Code) OAuth client ID, following the Virtual Engineer Copilot connector. This is a GitHub-owned application, not a VulnScout-owned registration; its availability and policies are outside VulnScout's control. GitHub's approval screen identifies that application. An operator can override the client ID using an OAuth App with device flow enabled (in `config.env` for the container):

```sh
VULNSCOUT_AGENT_GITHUB_CLIENT_ID=<OAuth App client ID>
```

The client ID is public; no client secret is needed. The app requests only the `read:user` scope. The backend exchanges the device code, so the resulting token does not reach the browser. A GitHub account with Copilot access (including the free tier) is required for GitHub sign-in. Choose from the models available to that account at the bottom of the message box; switching models keeps the current conversation. Open the plug's connection panel to **Sign out**, clearing stored agent credentials and deleting that agent session. There is no separate logout icon in the chat header. The **+** button starts a **New conversation** after confirmation: it deletes the SDK session and resets messages, draft, and usage while retaining the connection and selected model. **Never ask again** remembers the confirmation preference in this browser. Earlier sessions created before starting a new conversation may still exist in the local Copilot directory.

For OpenAI, Microsoft Foundry (Azure), Anthropic, or a local OpenAI-compatible model, Step 2 asks for connector credentials, not a model. Hosted providers require an API key. **Use custom endpoint URL** reveals the URL field only when needed; it is required for Microsoft Foundry and local servers. Microsoft Foundry uses an HTTPS API base URL (for example `https://your-resource.openai.azure.com/openai/v1/`). A local Qwen server such as Ollama can use `http://127.0.0.1:11434/v1`; its API key is optional. When VulnScout runs in a container, point the local URL at a reachable container gateway or configured `host.docker.internal` instead of the container's own loopback. Local URLs are restricted to loopback or the container gateway; hosted URLs require HTTPS. Step 3 checks the provider's available models before confirming the connection. Select a model in the message box after **Start using**. **Disconnect provider**, in the plug's connection panel, forgets the key and conversation state. The selected provider is shared across all chats, while their messages remain separate. Connector logos come from Lobe Icons Static SVG (MIT).

Each message includes the active page and project/variant selection, including comparison modes. When a project is shown across all variants, its variant UUIDs are included in the scope; an open vulnerability also contributes its matching variant UUIDs. The vulnerability table sends its filtered, sorted vulnerability IDs (across pagination), search and selected IDs; the Review and Metrics views also share their displayed IDs and open vulnerability. The SBOM table shares filtered package IDs; Scans shares displayed scan IDs, the open result, and scan options; Export shares the wizard step, type, mode, enabled document groups, and selected variants/formats; Settings shares its active tab; AI Context shares its selected project and variant names and IDs. Unsaved form text and API keys are not sent automatically.

The **AI** button at the top of the vulnerability modal opens or closes a chat for that vulnerability over the modal. Opening the chat turns on Edit mode; closing it leaves the mode unchanged. Closing only hides the chat. Moving to another vulnerability gives it a separate conversation, without deleting the original session or cancelling its queued work. In Edit mode, **Assess with AI** next to **Add assessment** is enabled once at least one variant and one package are selected; it opens the chat and queues an assessment of exactly those variant/package targets. Large selections are split into requests within the 8,000-character message limit. A variant is never split across requests; if its packages alone exceed the limit, an error asks you to select fewer packages for it. A new AI assessment replaces a pending AI assessment only on the same variant and package, preserving other suggestions.

The **AI queue** button shows all chats' requests above the composer; remove waiting requests individually or use **Clear all**. While an action is queued or running, its button shows **Queued · #N** (position within that conversation) or **Running…** and is disabled to prevent duplicates. It can be requested again once it finishes. **Review with AI** after the **User** badge queues a review recording one review per target without changing the assessment. Conversations retain separate histories. Suggested actions, **Assess vulnerability**, and **Assess displayed** join the same FIFO queue. For view lists over 100 items, the request sends only the count, and bulk view actions ask you to narrow the table. No partial list is silently presented as the full display.

In the Review tab, **Review selected with AI** retrieves and validates each selected custom assessment's complete target set before opening the chat. Like the other tabs, the chat stays on the right alongside the content on desktop and fills the screen on smaller screens; closing and reopening it preserves its conversation and queue. Each queued request uses those targets' variants and projects, not just the variant currently displayed; unresolved targets prevent the entire selection from being queued. Scan assessments and pending AI suggestions are excluded. Queued reviews, including those started in the vulnerability modal, only succeed once every expected variant/package target has a freshly saved, non-stale review; an agent response alone is not proof of a saved review. If a request fails, the shared queue pauses with its error and failed action retained, and its action button stays disabled to prevent duplicates. Use **Retry failed action** in the **AI queue** to retry the same action and scope; remove it or clear waiting work to discard it without claiming success. Remaining requests resume after successful retry or removal. Selection is preserved.

Expand **Conversation usage** below the composer to see cumulative input/output tokens when supplied by the SDK and the sum of `assistant.usage.cost` across the current conversation. It does not infer a currency or a token price; when no cost is reported, it says **Cost not reported**. Each assistant response has a copy action. Sending keeps the user message visible while a response is pending; failures restore the draft for retry.

In the **Vulnerabilities** tab, select one or more rows and choose **Assess with AI**
in the selection bar. VulnScout resolves the active variant/package findings for
each selected vulnerability within the current project and variant selection
(including comparison and multi-variant modes), then queues the same assessment
workflow used by the vulnerability modal. Historical/outdated packages and
unselected vulnerabilities are not assessed. Every variant's packages stay
together, and large requests are batched within the agent message limit. If
targets cannot be loaded, no partial selection is queued; the error banner
explains what to retry.

The bulk assessment chat has its own conversation and opens automatically when
assessments are queued. Closing it with the chat's close button or resetting the
row selection preserves queued and running work; queuing another assessment
opens it again. A queued or running vulnerability cannot be queued again; selecting
additional rows queues only the new vulnerabilities. Clear or remove pending
items in the **AI queue**, or retry after an action finishes. If a provider or stream
request fails, its action stays in the **AI queue** and the queue pauses, preserving
the error and draft instead of starting the next vulnerability. Choose
**Retry failed action**, remove that action, or clear the queue to continue.
In two-variant intersections, base-variant packages are checked against active
vulnerability observations, not just packages still installed in its SBOM.
Changing the project or variant scope, or leaving the tab, starts a separate
conversation without cancelling requests already in the shared queue.
AI suggestions follow the normal approval workflow in **Review**; the
selection bar does not directly create user assessments.

Responses stream as text arrives. Expand **Activity** to see tool names and running, completed, or failed status. This log does not expose internal reasoning, tool arguments, or raw tool results, and is retained only until the page reloads. Closing the global panel keeps the stream running; closing a vulnerability assessment chat discards that chat. If the connection is interrupted, the backend may still finish the turn; reload to check the stored reply before retrying a write.

The messages endpoint supports `Accept: application/x-ndjson` for status, text delta, tool activity, heartbeat, and terminal `done` or `error` records. Existing clients without this header still receive a single JSON response. Validation errors remain JSON HTTP errors. Proxies must not buffer streamed responses.

MCP assessment and context write tools are available for explicit change requests without a second approval prompt. Verify the requested target and scope before asking for changes. This MVP uses in-memory conversation state; it does not provide durable multi-user sessions or an OAuth app registration flow.
