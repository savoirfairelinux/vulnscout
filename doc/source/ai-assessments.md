# AI Assessments

VulnScout can accept **AI-written vulnerability assessments**. An AI agent
evaluates a CVE against the available evidence and submits a VEX assessment to
VulnScout, where it is stored as **pending review**. A pending AI assessment is
never treated as official — it does **not** affect a vulnerability's status and
is **not** included in the exported VEX — until a human reviewer explicitly
**approves** it in the web interface.

This page describes how to set up and use that workflow, as well as how to
request an AI second opinion on existing user-authored assessments.

## Recommended Workflow: Built-in Agent

Use the **Agent** in VulnScout's web interface. The normal VulnScout container
includes the **GitHub Copilot SDK** and the bundled MCP tools used by the agent.
You do not need to install Python or Node.js on the host, configure an external
MCP client, or clone a separate MCP repository.

The SDK runs on the backend and connects your selected AI provider to VulnScout's
tools. MCP remains the internal tool interface; external MCP registration is an
alternative integration, not a prerequisite for using the built-in Agent.

The embedded Agent is currently **localhost-only** and intended for a local,
single-user setup. It is not a supported shared or remotely exposed AI service.
Do not forward it to other users.

### Connect an AI Provider

1. Start VulnScout with `./vulnscout serve` and open <http://localhost:7275>.
2. Select your project and variant, then click **Agent** in the navigation bar.
3. Choose a connector: **GitHub Copilot**, **OpenAI**, **Microsoft Foundry**,
   **Anthropic**, or **Local model**.
4. Follow the connector setup. GitHub Copilot uses GitHub sign-in; hosted
   providers require their credentials. A local OpenAI-compatible server needs
   an endpoint reachable from the VulnScout container.
5. Complete the connection check and select a model above the chat.

For GitHub Copilot, select **Sign in with GitHub**, open the displayed GitHub
link, enter the short code, and approve access. A GitHub account with Copilot
access is required. The approval screen identifies the GitHub-owned application
used for device sign-in. An existing Copilot CLI sign-in on your host is not
automatically available inside the container; connect through the Agent panel.
After the connection check, select **Start using**.

For other hosted providers, enter the API key. **Use custom endpoint URL**
reveals the endpoint field; Microsoft Foundry and local servers require it.
Microsoft Foundry uses an HTTPS API base URL such as
`https://your-resource.openai.azure.com/openai/v1/`. Hosted endpoints require
HTTPS. Local OpenAI-compatible endpoints are restricted to loopback or the
container gateway; their API key is optional.

A local server such as Ollama may use `http://127.0.0.1:11434/v1` when running
alongside a non-container backend. Inside the VulnScout container, that address
refers to the container itself. Use a reachable container gateway or a configured
`host.docker.internal` address for a server on the host.

Use the plug button to reopen connector setup. The provider is shared across
the main and action conversations, but their messages remain separate.
The **Model** selector stays visible in both conversation and **Conversations**
views and is disabled while any request is running. Switching models preserves
the current conversation. **Sign out** or **Disconnect provider** clears the
stored credentials and conversation state.
Actions queued before sign-in or the first connection wait until setup finishes.
Replacing or disconnecting an existing connection requires an empty queue;
finish or remove its requests first. Opening connection settings pauses waiting
work until you return to the chat. New actions submitted during a connection
change are retained. Follow-ups to a previous provider's conversation pause with
an explanation and require an explicit retry to start a fresh conversation.

Provider credentials are handled by the backend and persisted in the private
configuration file so the connection can survive restarts. They are not returned
to the browser. Only connect providers you are authorised to use with your data.
For configuration internals and development setup, see
[AI Agent Development](agent-chat.md).

### Prepare the Assessment Context

On the **AI Context** page, select the project and variant and provide relevant product,
deployment, environment, and threat-model context. Save your context before
requesting an assessment. Upload relevant source files using **Codebase
References**, as described below.

The agent receives the active page and project/variant scope. Keep that scope
aligned with the product and packages you want assessed; the same CVE can have
different impacts on different variants.

### Chat Scope and Conversations

The **Agent** button opens the only agent chat panel in VulnScout, alongside the
interface on desktop and full-screen on smaller displays. Messages you type go
to the **main conversation**. Every assessment or review action runs in its own
conversation inside that same panel. Each request keeps the active page,
project/variant scope, and relevant displayed or selected records captured when
it was queued. Unsaved form text and API keys are not sent automatically.

All requests share one **AI queue**, running one at a time in submission order.
The person button in the header switches to **Conversations**: the main
conversation first, then action conversations grouped into **Needs attention**,
**Running**, **Waiting**, and **Finished**. Each shows its origin, queue position,
and last activity. Selecting one opens its conversation; the back arrow returns
to the list, and Escape or the back arrow in the list returns to the conversation.

The person icon walks in place while work is active, with no horizontal movement
and at least one foot grounded. Reduced-motion preferences use a static walking
icon. An empty or paused queue shows a standing person; a warning mark identifies
a paused queue.

A waiting conversation displays its pending request and **Remove from queue**.
**Clear waiting** removes waiting and failed requests, never the running one.
Finished conversations can be deleted individually or with **Delete all**.
VulnScout keeps the 12 most recently used finished action conversations live;
older conversations are archived with their transcripts but cannot accept
follow-ups. This queue is separate from the navigation bar's scan/upload/export
operation queue.

Closing the panel, changing scope, or navigating away does not cancel queued or
running work. Reloading the browser discards the in-memory queue and
conversations. **+ → New conversation** deletes the main SDK session and resets
its messages, draft, and usage while keeping the connection, selected model,
and action conversations. **Never ask again** remembers the confirmation
preference in this browser. Older SDK session files may remain on the backend.

The **AI** button in a vulnerability modal opens this same panel beside the
modal and enables Edit mode. Moving to another vulnerability does not cancel
the previous one's queued work.

Assessment and context write tools are available for explicit change requests,
without a separate confirmation for each tool call. Check the target scope
before asking the agent to change data. Assessment approval remains a separate
human action.

### Request an Assessment

Open a vulnerability, enter **Edit** mode, select the target variants and
packages, and click **Assess with AI** next to **Add assessment**. VulnScout opens
the agent panel on a new action conversation for those exact targets.

For several vulnerabilities, select rows in **Vulnerabilities** and choose
**Assess with AI** in the selection bar. Each vulnerability gets its own
conversation; bulk assessments open **Conversations** so you can follow the
queue. If an action fails, retry it or remove it before the queue continues.
Narrow large selections when asked.
Historical/outdated packages and unselected vulnerabilities are excluded.
If targets cannot be resolved, VulnScout reports an error instead of queuing a
partial selection. Large requests are split within the message limit while
keeping each variant's packages together.

Closing the panel or resetting the row selection preserves queued and running
work. Additional selections queue only new vulnerabilities; a queued or running
vulnerability cannot be queued twice. Remove requests in **Conversations** or
use **Clear waiting** to discard waiting and failed actions.
Changing scope or leaving the Vulnerabilities tab does not cancel queued work.

Queued action buttons retain their labels and add **Queued · #N**, **Running...**,
or **Failed · view**. Clicking them opens the existing request rather than
queueing a duplicate. The status disappears when the request finishes.
A failed request shows its error, **Retry failed action**, and **Remove failed
action** in its conversation. The shared queue pauses until it is retried or
removed; other conversations show a banner linking to it.

Chat suggestions such as **Assess vulnerability** and **Assess displayed**
send immediately. Large displayed lists may require narrowing the table; a
partial display is never silently treated as the complete scope.

You can also ask in chat, for example:

```text
Assess CVE-2024-XXXXX for project "my-product", variant "production".
Use the saved context and uploaded codebase references, and explain any
missing evidence.
```

Assess and review actions follow the repository's `cve-assessment` and
`assessment-review` skills, so the built-in Agent and external clients use the
same methodology. The Agent can read VulnScout data, uploaded source references
and the skill files, and fetch public advisory pages such as NVD and GHSA
(disable with `VULNSCOUT_AGENT_WEB_ACCESS=off`). It has **no shell or host
filesystem access**, so a variant's `codebase_path` is not readable; upload the
source instead. Missing evidence remains an uncertainty, never proof that the
product is safe.

Submitted AI assessments remain pending until a human approves them.
A vulnerability has at most one pending AI assessment per variant and package.
A new submission replaces the pending assessment only on overlapping targets;
other targets and approved assessments are preserved.

### Responses, Activity, and Usage

Responses stream as text arrives. Expand **Activity** to inspect tool names and
their running, completed, or failed status. This log does not expose internal
reasoning, tool arguments, or raw tool results; it lasts until the page reloads.
Each assistant response has a copy action, and each code block in a response
has its own **Copy code block** button.

Expand **Conversation usage** below the composer to inspect cumulative
input/output tokens when provided by the SDK and reported usage cost. The UI
does not infer a currency or token price; missing cost is shown as **Cost not
reported**.

Failures restore the draft for retry. If a stream is interrupted, the backend
may still finish the request: reload and check the stored result before
retrying a write.

### Assess from the CLI or CI

`./vulnscout assess` runs the same embedded agent as **Assess with AI**, without a browser. Each result is a **pending AI assessment** to review as described in [Review AI Assessments](#review-ai-assessments). It uses the provider connected in the Agent panel, or `AI_PROVIDER`, `AI_AUTH_CREDENTIALS`, `AI_MODEL` and `AI_BASE_URL` set with `./vulnscout config set`.

```bash
./vulnscout assess -p demo --filter "pending and (cvss >= 9 or known_exploitable)"
./vulnscout assess -p demo -v x86 --cve CVE-2024-3094 --cve CVE-2023-4863 --json
./vulnscout assess -p demo -v x86 -v arm64 --filter "new and cvss >= 7" --dry-run
./vulnscout assess -p demo --filter "(id == CVE-2024-3094 or id == CVE-2023-4863) and pending"
```

- Select vulnerabilities with repeatable `--cve` **or** one `--filter` ([match-condition syntax](ci_conditions.md)); use exactly one, as they cannot be combined. To restrict specific IDs with other conditions, list them in the filter with `id == <id>`. Filters see each vulnerability's newest assessment, including pending AI ones.
- Scope follows `match-condition`: `-p` alone covers every variant, `-p -v` one variant (repeat `-v` to select several), and no scope means `default/default`. Each vulnerability is assessed on its active (variant, package) targets in scope: the package is in the variant's current SBOM and the vulnerability is found by the variant's current scans. Historical/outdated packages and findings are excluded, as in the web UI.
- As in the web UI, a new AI assessment replaces the earlier pending AI assessment on the same targets. Approved assessments are never changed.
- CLI runs may only read data and write AI assessments; they cannot change context or reviews, and they do not appear in the browser's **Conversations** queue.
- `--timeout` limits each agent turn (positive integer, default 600 s). `--model` overrides `AI_MODEL`. `--dry-run` lists the targets without calling the AI.
- Outcomes: `assessed`, `partial` (some targets written), `no_write`, `failed`, `timeout`, `not_found` (a `--cve` ID with no active target in scope; filter matches without one are skipped), `interrupted`, `planned` (dry run). The command exits **1** if any vulnerability has an outcome other than `assessed` or `planned`, and exits 0 when nothing matched.
- The summary lists each target under its vulnerability: after a run, `written` with the saved AI assessment IDs, or `not written`; with `--dry-run`, the packages per variant.
- `--json` prints `{"model", "scope", "results": [{"id", "outcome", "targets", "reply", "usage", "error"}]}` on stdout; progress goes to stderr. `scope` is `{"project", "variants"}`, where `variants` is `null` when every variant of the project is selected. Each `targets` entry is `{"variant_id", "variant", "package", "written", "assessment_ids"}`; `assessment_ids` lists the pending AI assessments saved for the target by this run.
- Ctrl-C, or a CI job cancellation (SIGTERM), stops the run inside the container after cancelling the current agent turn. The summary still lists what was written, and the exit code is 1. Press Ctrl-C a second time to stop immediately without a summary.

## AI Context page

The **AI Context** page uses a settings-style layout. The sidebar lists
**Project description** and the variants of the selected project. Variants that
are not ticked in the top-bar selector stay listed but locked. The page opens on
**Project description**, and returns to it when the open variant leaves the
scope. Selecting an item
opens its page; there is one **Save changes** button per page and no auto-save.
Leaving a page with unsaved changes asks to Save, Discard or Cancel.

A variant page has four tabs, **Context**, **System**, **Threat model** and
**Risks**. Edits are kept when you switch tabs. **Copy from...** replaces the
whole draft with another variant's context (any project); nothing is saved until
you save. Uploaded references are never copied.

**Context** holds the variant description, the **Codebase source** (uploaded
references, the default, or paths; only the selected one is shown, the other is
kept), environment and other information. The other tabs edit a STRIDE model:
system text fields with Components and Interactions tables (System), a Threats
table (Threat model) and a likelihood/impact/mitigation row per
threat (Risks). Required cells are marked with `*`: component name, interaction
source and destination (two different components), threat STRIDE category and
targets (at least one component or interaction), and risk threat. **Save changes** refuses to send a draft with a blank required
cell; it opens the tab and explains each missing value next to its cell.

Agents receive `threat_model` and `risks` as a plain-text rendering of these
tables, with the `C#`, `I#` and `T#` IDs kept; threats that have no rating,
mitigation or residual decision are left out of `risks`. `codebase_path` is
only sent when the source is paths, and uploaded references are only listed
when the source is references; `get_merged_context` also reports the
`codebase_source`. The MCP `update_variant_context` tool cannot change the
threat model, risks or codebase source; edit them in the page.

The assessment skills and the embedded Agent use the STRIDE model per variant.
They map the affected component to Components and Interactions, check
reachability against entry points and trust boundaries, match the CVE's impact
to Threats by STRIDE category, and cite the IDs. Mitigations and residual
decisions in Risks are treated as declarations: they can lower the impact, but
support `not_affected` only when source or configuration evidence confirms
them.

### Getting help from the agent

With the agent chat open on the AI Context page, **Help write project
description** (on the project page) or **Help fill this tab** (on a variant tab)
asks the embedded Agent to walk you through the open page. The Agent reads the
form guide (`get_ai_context_form_guide`), the variant's saved context, uploaded
references and SBOM dependencies, asks for missing facts, and replies with
copy-ready values: one code block per text field, and one entry per table row
naming the exact option to pick (for example `C1: OTA updater`). Each code block
has its own copy button. Unconfirmed values are marked `[confirm: ...]`. The
Agent does not save the form; paste the values and click **Save changes**. It
only sees saved context, not unsaved edits.

## Codebase references on the AI Context page

Open the **AI Context** page (top nav **AI**), select a variant in the sidebar and,
in its **Context** tab, keep **Codebase source** on **Codebase references** (the
default for a new variant). Then
drag source files or archives onto **Codebase References**, or use the file
picker. Multiple uploads are supported.
An optional description can identify the component/version and whether the
upload is a complete source tree or only selected files. References are saved
**immediately**, independently of **Save changes**; unsaved fields are kept.
Uploads and deletion mark older pending AI assessments for that variant outdated.
The UI asks before uploading when pending assessments exist and always confirms deletion.

Supported archives are **ZIP, TAR, TAR.GZ and TGZ**. Archives are limited to
**5,000 entries**, with a **10 MiB maximum per file** and **100 MiB maximum
expanded archive size**. Unsafe paths, duplicate file paths, encrypted ZIP files,
links, sparse files and special entries are rejected. Archives are read without
extraction or execution. Only UTF-8 text can be read as source; binary files
may be stored/listed but cannot provide text evidence. Other archive formats
are not unpacked.

**Codebase Path** remains available for an external Copilot/MCP client running
on the machine that owns the source. Add one row per local path with **Add path**
and remove rows with **Remove**; they are sent to agents joined by a semicolon.
A path entered here does **not** mount a directory into the container,
and the embedded Agent has no shell or arbitrary filesystem access.
Both embedded and external agents can inspect uploaded references through
`get_merged_context` (which supplies reference IDs), then `list_codebase_files`,
`search_codebase` and `read_codebase_file`. The embedded Agent and external
assessment skills use each variant's own uploads as additional evidence and
cite IDs, archive member paths and line numbers.

References are stored under `VULNSCOUT_CACHE_DIR/context-files` using opaque IDs
and persist with the cache volume. Delete removes the reference; deleting its
variant/project also cleans up the associated storage. Text context JSON
export lists each variant's uploads by name and description but does **not**
include their contents; importing text leaves existing uploads intact. Upload
references separately when moving to another instance.

Only upload code you are authorized to share with the selected AI provider,
and remove credentials, secrets and unrelated private files first. Uploaded
content is untrusted evidence, not agent instructions. Partial uploads,
unreadable files, conflicting versions or truncated searches must be reported
as evidence gaps, not used to claim a component is absent.

## Review AI Assessments

Pending AI assessments must be reviewed by a human before they become official.

1. Open the assessed vulnerability in the VulnScout web interface.
2. A pending AI assessment appears in a highlighted panel **above** the normal
   assessment timeline, labelled **"AI-generated · Pending review"**. It shows
   the same details as a normal assessment (status, justification, impact
   statement, notes, packages, and variant).
3. Click **Edit** on the vulnerability modal to enter editing mode — the
   **Approve** / **Reject** buttons only appear on the panel once editing mode
   is active.
4. Use the panel's action buttons:
   - **Approve** — promotes the assessment to an official (`custom`)
     assessment. It now affects the vulnerability's status and is included in
     the OpenVEX export.
   - **Reject** — deletes the pending AI assessment.

Until it is approved, a pending AI assessment has no effect on the
vulnerability's status, on scan history/diffs, or on any exported VEX.
You can also inspect pending suggestions in **Review → AI Assessments**.

## AI Review of Custom Assessments

This is a separate workflow from approving a pending AI assessment. It provides
an independent second opinion on an existing **user-authored** assessment
(`origin = "custom"`), not a scan-imported assessment or pending AI suggestion.
Use **Review with AI** on a custom assessment in the vulnerability
modal, or select assessments on the **Review** page and click **Review selected
with AI**. Requests run sequentially in the agent chat, one complete
assessment per request and per conversation; every target is reviewed even when the table is scoped
to one variant. You can close and reopen the chat while it works, inspect errors,
and remove queued requests without altering your selection.
Unresolved targets prevent the entire selection from being queued.
An agent reply alone is not proof of a saved review: queued reviews succeed only
once every expected target has a fresh, non-stale review. A failed action pauses
the queue; use **Retry failed action** in its conversation or remove the failed action
to continue.

The agent independently derives a conclusion for **each (variant, package)
target**, then saves a separate review for each one. An assessment covering multiple targets
can therefore have different review verdicts for different targets. Each
review is checked against the assessment content the agent read. If the
authored content changed meanwhile, the write is rejected: request a new review
of the updated assessment rather than reusing the old conclusion.
Re-reviewing a target replaces only that target's previous review; **no review
changes the underlying assessment**.

The **Review** page's **AI review** column and filter show which targets
agree (✓), differ (⚠), are stale (⚠ stale), or have no review (—).
Multi-target rows show counts for each state. Open the vulnerability detail
modal to read each target's AI review and rationale (`why:`). A stale review
warns that the assessment was edited after the review was generated; in edit
mode, **Discard review** removes a target's review without changing the
assessment.

## Dependencies and Evidence Limits

The Agent can also inspect SBOM dependencies using the selected project and
variant. For example, ask which libraries a package declares or which packages
depend on it. SBOM relationships describe declared dependencies, not proof of
runtime use or exploitability.

For lifecycle, LTS, or end-of-life questions, supply dated authoritative evidence.
Free chat cannot browse the web to verify current support policies;
missing release or support evidence must be reported as unknown. Upstream
support and vendor/distribution backports are separate questions.

## Troubleshooting

- **Agent access is refused** — use a local single-user deployment; remote
  access is not supported by the embedded Agent.
- **No model is available** — check the connector credentials and account
  access, then select an available model in the toolbar.
- **A local model cannot be reached** — the container's loopback is not the
  host's loopback. See [Connect an AI Provider](#connect-an-ai-provider).
- **The agent cannot read a host source directory** — upload codebase
  references; **Codebase Path** does not mount that directory.
- **A request failed** — inspect the error and **Activity** before retrying.
  For queued work, use **Retry failed action** in its conversation, or remove the
  failed action. If a stream was interrupted, check for a saved result before
  retrying a write.
- **`assess` reports `no_write` or `partial`** — the agent replied without recording every target. Read the `reply` in `--json` output, then rerun for those vulnerabilities; a rerun replaces any pending AI assessment it wrote.

## Optional: External AI Clients

Use an external client when you need your own agent environment, host-side
source access or web research in free chat. MCP integration and repository skills
remain supported, but are not required for the built-in Agent.

```{toctree}
:maxdepth: 1

ai-external-clients
```
