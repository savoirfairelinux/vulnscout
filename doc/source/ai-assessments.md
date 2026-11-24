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
For GitHub Copilot, **Context** selects the default tier (≤272K input, subject to
the model's limit) or **Copilot Long context** (>272K input) where Copilot advertises
support. Long context may increase usage charges. **Thinking** appears only when
Copilot advertises supported reasoning levels for the selected model; **Model
default** leaves reasoning to Copilot. These settings are saved with the model,
apply to chat, assessments, reviews and CLI turns, and are reset when choosing
another model or **Use model defaults**. Other connectors do not expose these
Copilot-specific controls.

The **Model** selector stays visible in both conversation and **Conversations**
views and is disabled while any request is running. Switching models preserves
the current conversation. Each request keeps the model selected when it was
queued, so a new selection applies only to later requests. Requests queued
before AI is configured, retried, or waiting across a connection change take
the model selected when they start.
**Sign out** or **Disconnect provider** clears the stored credentials and
conversation state.
While AI is not configured or GitHub is signed out, the queue is **paused**:
requests stay queued, a banner shows the reason, and they start once you sign in,
connect a provider or select a model.
Replacing or disconnecting a connection is refused while a request is running;
wait for it or stop it first. Waiting requests are kept: new conversations run
with the new connection, while follow-ups to a previous provider's conversation
fail with an explanation and need an explicit retry to start a fresh conversation.

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

All requests go to one **AI queue** kept by the VulnScout server and shared by
every browser tab and by `./vulnscout assess`/`review` (see
[Assess from the CLI or CI](#assess-from-the-cli-or-ci)). Every tab shows the
same requests and their live progress. Assessments, reviews and context imports
share five concurrent slots. Actions with conflicting targets wait. Chat messages run
in their own lane and never wait behind an action. The requests of one
conversation always run in order. A failed request does not block the queue:
later requests keep running, and the failed one stays listed until you retry or
remove it.
Agent writes refresh the current data in the background, so you can keep
working with vulnerabilities and reviews while assessments are queued or
running. The displayed data may briefly lag behind a write. If a Review
verdict refresh fails, the previous verdicts stay visible. The refresh warning
clears after a successful refresh without dismissing messages about your own
edits. Switching scope still waits for the new scope's data to load.
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
**Stop**, in a running conversation or next to it in **Conversations**, cancels
the running request; whatever it already saved is kept.
**Clear waiting** removes waiting and failed requests, never the running one.
Finished conversations can be deleted individually or with **Delete all**.
VulnScout keeps the 12 most recently used finished action conversations live;
older conversations are archived with their transcripts but cannot accept
follow-ups. This queue is separate from the navigation bar's scan/upload/export
operation queue.

Closing the panel, changing scope, navigating away, closing the tab or reloading
the page does not cancel queued or running work. The queue and the conversation
transcripts are kept in the server's memory: they survive a reload and are lost
when the server restarts. **+ → New conversation** deletes the main SDK session and resets
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
packages, choose **AI** under **Select how an assessment is added**, and click
**Start assessing**. VulnScout opens
the agent panel on a new action conversation for those exact targets.

For several vulnerabilities, select rows in **Vulnerabilities** and choose
**Assess with AI** in the selection bar. Each vulnerability gets its own
conversation; bulk assessments open **Conversations** so you can follow the
queue. Narrow large selections when asked.
Historical/outdated packages and unselected vulnerabilities are excluded.
If targets cannot be resolved, VulnScout reports an error instead of queuing a
partial selection. Large requests are split within the message limit while
keeping each variant's packages together; each batch is a fresh agent session in
the same conversation, and follow-up messages may save for any of its batches'
targets. These target restrictions are set when the action is queued and remain
in place if its waiting requests are removed before a follow-up runs.

Closing the panel or resetting the row selection preserves queued and running
work. The same vulnerability and target selection shares one action across the
selection bar, vulnerability modal, chat and CLI; different targets may queue
separate actions. Remove requests in **Conversations** or
use **Clear waiting** to discard waiting and failed actions.
Changing scope or leaving the Vulnerabilities tab does not cancel queued work.

Queued action buttons retain their labels and add **Queued · #N**, **Running...**,
or **Failed · view**. Clicking them opens the existing request rather than
queueing a duplicate. The status disappears when the request finishes.
A failed request shows its error, **Retry failed action**, and **Remove failed
action** in its conversation; other conversations show a banner linking to it.
Retrying moves the request to the end of the queue.

The **Assess vulnerability** chat suggestion sends immediately for the open
vulnerability. To assess several vulnerabilities, check the desired rows and
use **Assess with AI**; the chat does not offer a separate action to assess
every displayed row.

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
(disable with `VULNSCOUT_AGENT_WEB_ACCESS=off`). It has **no direct host
filesystem access**. Provision a **Codebase directory** or attach host folders
as described below to expose source through the bounded MCP tools or the isolated
read-only shell described in [AI Agent Development](agent-chat.md). Missing evidence remains an uncertainty, never proof that the
product is safe.

Submitted AI assessments remain pending until a human approves them.
A vulnerability has at most one pending AI assessment per variant and package.
A new submission replaces the pending assessment only on overlapping targets;
other targets and approved assessments are preserved.

### Responses, Activity, and Usage

Responses stream as text arrives. Expand **Activity** to inspect tool names and
their running, completed, or failed status. This log does not expose internal
reasoning, tool arguments, or raw tool results; it is kept with the transcript
until the server restarts.
Each assistant response has a copy action, and each code block in a response
has its own **Copy code block** button.

Expand **Conversation usage** below the composer to inspect cumulative
input/output tokens when provided by the SDK and reported usage cost. The UI
does not infer a currency or token price; missing cost is shown as **Cost not
reported**.

If a message cannot be queued, the draft is kept for retry. A request runs on
the server even when no tab follows it; if the page lost its connection, it
reconnects and shows the current state.

### Assess from the CLI or CI

`./vulnscout assess` runs the same embedded agent as **Assess with AI**, without a browser. Each result is a **pending AI assessment** to review as described in [Review AI Assessments](#review-ai-assessments). It uses the provider connected in the Agent panel, or `AI_PROVIDER`, `AI_AUTH_CREDENTIALS`, `AI_MODEL` and `AI_BASE_URL` set with `./vulnscout config set`.

```bash
./vulnscout assess -p demo --filter "pending and (cvss >= 9 or known_exploitable)"
./vulnscout assess -p demo -v x86 --cve CVE-2024-3094 --cve CVE-2023-4863 --json
./vulnscout assess -p demo -v x86 -v arm64 --filter "new and cvss >= 7" --dry-run
./vulnscout assess -p demo --filter "(id == CVE-2024-3094 or id == CVE-2023-4863) and pending"
```

When `./vulnscout serve` is running, `assess` and `review` submit their agent turns to the web server's [AI queue](#chat-scope-and-conversations) instead of running them in the command's process. The requests appear in every tab's **Conversations** with the origin `CLI`, wait behind the actions already queued, and use the server's AI connection; the command follows them and prints the same report and exit code. A server that is still starting is awaited for up to 60 s. An action that is already in the queue (for example a vulnerability queued from the web) is followed instead of being queued twice, and retried if it had failed; a review is followed only when it covers the same findings of the variant (a `--re-review` run selecting more findings is queued separately). Without a running server, the command runs the turns itself and prints `note: web server not running; this run is not visible in the web AI queue` on stderr.

- Select vulnerabilities with repeatable `--cve` **or** one `--filter` ([match-condition syntax](ci_conditions.md)); use exactly one, as they cannot be combined. To restrict specific IDs with other conditions, list them in the filter with `id == <id>`. Filters evaluate each active target with its own newest assessment, including pending AI ones, so an assessment of a removed version or of another package never hides an unassessed target.
- Scope follows `match-condition`: `-p` alone covers every variant, `-p -v` one variant (repeat `-v` to select several), and no scope means `default/default`. Each vulnerability is assessed on its active (variant, package) targets in scope: the exact package, supplier included, is in the variant's current SBOM and the vulnerability is found by the variant's current scans. Historical/outdated packages and findings are excluded, as in the web UI. With `--filter`, only the matching targets are assessed.
- As in the web UI, a new AI assessment replaces the earlier pending AI assessment on the same targets. Approved assessments are never changed.
- CLI runs may only read data and write AI assessments for the vulnerability and (variant, package) targets of each agent turn; any other write, including context and review changes, is rejected.
- `--timeout` limits each agent turn (positive integer, default 600 s). `--model` overrides `AI_MODEL`. `--dry-run` lists the targets without calling the AI. An expired or invalid GitHub Copilot token stops the run before the first assessment.
- Outcomes: `assessed`, `partial` (some targets written), `no_write`, `failed`, `timeout`, `not_found` (a `--cve` ID with no active target in scope; filter matches without one are skipped), `interrupted`, `planned` (dry run). The command exits **1** if any vulnerability has an outcome other than `assessed` or `planned`, and exits 0 when nothing matched.
- The summary lists each target under its vulnerability: after a run, `written` with the saved AI assessment IDs, or `not written`; with `--dry-run`, the packages per variant.
- `--json` prints `{"model", "scope", "results": [{"id", "outcome", "targets", "reply", "usage", "error"}]}` on stdout; progress, including container startup, goes to stderr. `scope` is `{"project", "variants"}`, where `variants` is `null` when every variant of the project is selected. Each `targets` entry is `{"variant_id", "variant", "package", "written", "assessment_ids"}`; `assessment_ids` lists the pending AI assessments this run's agent saved for the target; assessments written meanwhile by the web agent or another run are not counted.
- Ctrl-C, or a CI job cancellation (SIGTERM), stops the run after cancelling the current agent turn. Without `serve`, the run stops inside the container. With `serve`, only the requests this run created are stopped: the running one is cancelled and its waiting ones are removed, while other requests in the web AI queue continue, including one already queued (from the web UI or another run) that this run was only following. The summary still lists what was written, and the exit code is 1. Press Ctrl-C a second time to stop immediately without a summary. A request of the run stopped or removed from the web UI is reported as `interrupted`; if the web server stops during the run, the unfinished vulnerabilities are reported as `failed` (`web server stopped`).

### Reviewing custom assessments from the CLI

`./vulnscout review` runs the same embedded agent and `assessment-review` skill as **Review with AI** (see [AI Review of Custom Assessments](#ai-review-of-custom-assessments)), without a browser. It records one AI review per (variant, package) target of each **custom** (user-authored) assessment, and never modifies the assessment itself. Assessments from SBOM scans and pending AI suggestions are never reviewed. It uses the same provider settings as `assess`.

```bash
./vulnscout review -p demo --assessment-id 3f2b6c1e-0000-4000-8000-000000000001
./vulnscout review -p demo --cve CVE-2024-3094 --re-review
./vulnscout review -p demo -v x86 -v arm64 --cve CVE-2024-3094 --dry-run --json
```

- `-p` is always required, and `-p`/`-v` go after the verb. Select assessments in exactly one of two ways:
  - `--assessment-id <uuid>` (repeatable) reviews every target of that assessment in the project. Targets in other projects are left out and reported as `excluded_targets`. `-v` is rejected in this mode, and an assessment with no target in the project is an error.
  - `--cve <id>` (repeatable) reviews the custom assessments of that vulnerability: every target in the project, or only the variants given with `-v` (repeatable). Non-custom assessments of the CVE are ignored and counted in `ignored_non_custom`. A CVE with no custom assessment in scope is an error that says whether it has no assessment at all or only SBOM-scan or pending AI ones.
- All selection errors are listed together and the command exits 1 before any AI call.
- A target whose review is **fresh** is skipped (`skipped_fresh`); targets with no review or a **stale** one are always reviewed. `--re-review` also reviews fresh targets. When every target is fresh, no agent is loaded and the command exits 0.
- Each agent turn covers one variant of one assessment; many packages are split into batches shown as `(batch N of M)`. A turn may only save reviews for its own listed targets, against the assessment content selected at the start of the run: any other write, including changing the assessment, is rejected. After each turn the outcome is read back from the database, not from the agent's reply. With `serve` running, each turn is one request in the web AI queue, as described for [`assess`](#assess-from-the-cli-or-ci).
- `--timeout` limits each agent turn (positive integer, default 600 s). `--model` overrides `AI_MODEL`. `--dry-run` lists the targets without calling the AI. An expired or invalid GitHub Copilot token stops the run before the first review.
- Target outcomes: `reviewed` (a review for the pinned assessment content was saved), `skipped_fresh`, `planned` (dry run), and the failing ones `changed` (the assessment was edited, retargeted or deleted during the run; run it again), `no_write` (the agent saved no review), `failed`, `timeout`, `interrupted`.
- Assessment outcomes: `planned`, `skipped` (every target fresh), `reviewed`, `partial` (some targets reviewed) and `failed`.
- Exit codes: **0** when every selected target is reviewed, already fresh (skipped) or planned (`--dry-run`) and the run was not interrupted; **1** on any resolution or usage error (a missing `--project`, using both or neither of `--assessment-id` and `--cve`, a malformed ID, an invalid or missing option value such as `--timeout 0`, an unknown project or variant; with `--json` these errors go to stderr and stdout stays empty; the `vulnscout` wrapper and the `flask ai-review` command both exit 1 for these), any target with a failing outcome (`changed`, `no_write`, `failed`, `timeout`, `interrupted`), or an interrupted run.
- `--json` prints the report on stdout; progress, including container startup, goes to stderr. Its shape is:

  ```json
  {
    "model": "gpt-5",
    "scope": {"project": "demo", "variants": ["x86"]},
    "ignored_non_custom": 0,
    "interrupted": false,
    "results": [
      {
        "assessment_id": "3f2b6c1e-0000-4000-8000-000000000001",
        "vuln_id": "CVE-2024-3094",
        "outcome": "reviewed",
        "excluded_targets": 0,
        "targets": [
          {"variant_id": "...", "variant": "x86", "project_id": "...", "package": "xz@5.6.0",
           "outcome": "reviewed",
           "review": {"id": "...", "status": "not_affected", "verdict": "agrees"},
           "error": null}
        ],
        "reply": "...",
        "usage": {"cost": null, "input_tokens": null, "output_tokens": null}
      }
    ],
    "counts": {"reviewed": 1, "skipped": 0, "failed": 0}
  }
  ```

  `scope.variants` is `null` when every variant of the project is selected. `interrupted` is `true` when the run was stopped by Ctrl-C or SIGTERM. `counts` is per target: `failed` counts the failing outcomes above. `review` is `null` unless the target was reviewed; its `status` is the VEX status the agent concluded and `verdict` is `agrees` or `differs` relative to the assessment. `error` is the failure message of a failing target.
- Ctrl-C, or a CI job cancellation (SIGTERM), stops the run after cancelling the current agent turn, with or without `serve` as for `assess` (with `serve`, only this run's requests are stopped): reviews already saved stay `reviewed`, the remaining targets are reported as `interrupted` and the summary is still printed, with `Interrupted.` (`"interrupted": true` in `--json`) and exit code 1. Press Ctrl-C a second time to stop immediately without a summary.
- The web **Review with AI** button is unchanged; CLI and web reviews of a target replace each other.

## AI Context page

The **AI Context** page uses a settings-style layout. The sidebar lists
**Project description** and the variants of the selected project. Variants that
are not ticked in the top-bar selector stay listed but locked. The page opens on
**Project description**, and returns to it when the open variant leaves the
scope. Selecting an item
opens its page; there is one **Save changes** button per page and no auto-save.
Leaving a page with unsaved changes asks to Save, Discard or Cancel.

A variant page has four tabs, **Context**, **System**, **Threat model** and
**Risks**. You can save **Context** or **System** on its own and add threats and
risks later. Edits are kept when you switch tabs. **Copy from...** replaces the
whole draft with another variant's context (any project); nothing is saved until
you save. Uploaded references are never copied.

**Context** holds the variant description, the server codebase directory, the
attached host folders, environment and other information. Directory access is the only codebase method
shown on this page; legacy uploaded references and external paths remain stored
for API compatibility. The other tabs edit a STRIDE model:
system text fields with Components and Interactions tables (System), a Threats
table (Threat model) and a Risks table where each risk (`R#`) groups one or
more threats with an optional description, a likelihood, impact, mitigation and
residual decision (Risks). Required cells are marked with `*`: component name, interaction
source and destination (two different components), threat STRIDE category and
targets (at least one component or interaction), and risk threats (at least one). **Save changes** refuses to send a draft with a blank required
cell; it opens the tab and explains each missing value next to its cell.

Agents receive `threat_model` and `risks` as a plain-text rendering of these
tables, with the `C#`, `I#`, `T#` and `R#` IDs kept; risks that have no rating,
mitigation or residual decision are left out of `risks`.
`get_merged_context` exposes `codebase_directory` with its
server path and `file_id="directory"`, used with the same MCP browsing tools.
Merged context responses are limited to 12 KiB of UTF-8 content per tool call
to avoid Copilot's large-tool-output file offloading. Continue with the returned
`next_offset` until it is `null`, concatenating pages in order before analyzing
or assessing a variant. Offsets count characters, not bytes.
The MCP `update_variant_context` tool cannot change the
threat model, risks or directory. `get_merged_context` with
`include_model=true` and `update_variant_threat_model` read and edit the System
text and STRIDE tables as structured rows; an update given `expected_updated_at`
is rejected, without changes, when the variant's context was saved after that
read. A provisioned directory is exposed automatically without deleting legacy
uploads or paths, even when an older saved context still selected references or paths.

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
Agent does not save the form unless you explicitly ask it to; otherwise paste
the values and click **Save changes**. It only sees saved context, not unsaved
edits, and the page reloads after the Agent saves. The embedded Agent never
saves the System, Threat model and Risks tabs directly: it proposes a draft
with `propose_variant_threat_model`, which opens for review as described in
[Fill the threat model from a document](#fill-the-threat-model-from-a-document).

### Fill the threat model from a document

On a variant of the **AI Context** page, **Fill from document with AI…** sends
a local document (a Threagile `threagile.yaml`, `risks.json` or `report.pdf`,
another threat-model export, an architecture PDF, Markdown, YAML or JSON) to
the embedded agent. The agent follows the `ai-context-import` skill and
prepares a **draft** of the System, Threat model and Risks tabs (and, when the
document states them, the Context texts). It never saves.

- Documents, including the compressed archive itself, are limited to 10 MB.
  PDF extraction is limited to 2 MB of text, including page markers, and
  30 seconds. Exceeding a limit rejects the document with an error rather
  than importing incomplete text.
- The button is disabled while the variant has unsaved changes: save or
  discard them first.
- While the action is queued or running, the variant is read-only. A queued
  action can be cancelled.
- Each import reads and drafts against its uploaded document revision. If
  another upload replaces it, the old run is rejected; start a new import
  rather than combining content from different documents.
- The draft opens in the editor as **unsaved changes**, with a summary such
  as "+3 components, +5 threats". Review every tab, then **Save changes** to
  accept it or **Discard AI draft** to reject it.
- The document and the draft are kept in the cache only, never in the
  database, and are deleted when the draft is saved or discarded.
- If the context is saved after the draft was made, the draft is merged onto
  the saved context when it is opened. When both changed the same item, the
  draft is not loaded; the page lists the conflicts and offers to discard it.
  Successful rebases retain their row IDs in the cache, so reopening after
  failed cleanup does not duplicate already accepted rows.
- Saving or discarding only removes the draft revision you reviewed. If a
  newer draft replaced it, cleanup is refused; reload to review the new draft.
  Leaving with **Discard** waits for deletion and stays on the page if it fails.

## Legacy uploaded codebase references

Uploaded references remain supported through the
[codebase reference API](api.md#manage-codebase-references), but are no longer
shown or managed on the AI Context page.
An optional description can identify the component/version and whether the
upload is a complete source tree or only selected files. References are saved
**immediately**, independently of **Save changes**; unsaved fields are kept.
Uploads and deletion mark older pending AI assessments for that variant outdated.

Supported archives are **ZIP, TAR, TAR.GZ and TGZ**. Archives are limited to
**500,000 entries**, with a **10 MiB maximum per file** and **100 MiB maximum
expanded archive size**. Unsafe paths, duplicate file paths, encrypted ZIP files,
links, sparse files and special entries are rejected. Archives are read without
extraction or execution. Only UTF-8 text can be read as source; binary files
may be stored/listed but cannot provide text evidence. Other archive formats
are not unpacked.

There is no external source-path setting. Administrators populate or mount the
variant's provisioned directory; the embedded Agent has no direct host
filesystem access.
Both embedded and external agents can inspect uploaded references through
`get_merged_context` (which supplies reference IDs), then `list_codebase_files`,
`read_codebase_file` and `read_codebase_files`. The embedded Agent and external
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

### Administrator-provided codebase directories

CI pipelines can create or mount `context-<sanitized-project>-<sanitized-variant>`
directly under `VULNSCOUT_CACHE_DIR` and populate it with reviewed source.
Merged-context, directory-status and directory-source lookups automatically
register an existing readable directory and expose it to assessments and reviews.
No web interaction, provisioning request or editor save is required. These reads
never create filesystem paths. Automatic discovery rejects ambiguous names shared
by unregistered variants: use distinct names or explicitly provision the intended
owner instead of allowing an arbitrary reader to claim the source.

Alternatively, open the variant's **Context** tab and click **Create codebase
directory** to create a missing directory. Initial registration, whether automatic
or explicit, marks older pending assessments outdated without saving other
context fields. The page displays the **container path** and whether the directory
is available, empty, missing or unreadable.
**Refresh directory status** checks files or mounts added by an administrator;
it does not change the context draft. **Save changes** is not required for
directory discovery or source access.

Status includes **Files** and **Directories** counts after a complete scan,
including on refresh. Files count eligible regular files (even if binary or too
large to read); directories count eligible subdirectories, including empty ones,
but exclude the root. Hidden/sensitive names and linked entries are excluded.
Empty trees report zero files. Missing/unreadable directories and incomplete or
over-budget scans do not report counts; failed refreshes clear previous totals.

Directories live directly under `VULNSCOUT_CACHE_DIR` (normally
`/cache/vulnscout`), named
`context-<sanitized-project>-<sanitized-variant>`, without database IDs. Only ASCII
letters, digits, underscores and hyphens are used; each name segment is truncated
to 48 characters, with `unnamed` for an empty segment. If another variant already
owns the resulting name (including collisions from sanitization, truncation or
hyphen placement), creation returns HTTP 409 instead of sharing its files.
Choose distinct project/variant names in that case. The name is saved at first
provisioning: project/variant renames do **not** move it or break mounts. Existing
UUID-suffixed directories retain their saved paths; they are not automatically
renamed.
Deleting a variant/project revokes access through its IDs but **retains this
directory and its contents**, unlike uploaded references. An administrator must
unmount and remove retained directories manually. Recreating the same names
reuses the portable directory and its contents; remove or replace retained files
before recreating a variant if that evidence should not be reused.

To transport a source snapshot to another instance, use the same project/variant
names and place or mount the snapshot under the displayed cache directory.
For an older UUID-suffixed snapshot, use the destination's displayed directory
name rather than carrying over its old UUID suffix.

For the standard wrapper's cache volume, the displayed
`/cache/vulnscout/<directory-name>` maps to
`$VULNSCOUT_CACHE_DIR/<directory-name>` on the **server host** (by default
`.vulnscout/cache/<directory-name>`). Copy a reviewed, secret-free source snapshot
into the provisioned host directory, for example:

```bash
cp -R /srv/reviewed-source/. /srv/vulnscout-cache/<directory-name>/
```

Replace both example paths and `<directory-name>` with your deployment's values.
Do not copy an entire home directory. The server process needs read permission on
files and read/search permission on every directory. Provisioning uses mode
`0750`, owned by the API process; copy files as that owner or grant its group
read access (typically `0640` files, `0750` directories). With the standard
wrapper, check `USER_UID`/`USER_GID` in `config.env`; rootless Podman uses the
wrapper's keep-id mapping. Do not solve permission errors with world-writable
permissions. VulnScout does not recursively change ownership inside these
administrator-managed directories.

Alternatively, add a read-only bind mount to your existing container deployment.
For example, add this volume alongside its normal writable cache volume in
Compose, using the **exact displayed container path** as the target:

```yaml
services:
  vulnscout:
    volumes:
      - /srv/vulnscout-cache:/cache/vulnscout
      - /srv/reviewed-source:/cache/vulnscout/<directory-name>:ro
```

The equivalent Docker/Podman volume argument is
`--volume /srv/reviewed-source:/cache/vulnscout/<directory-name>:ro`.
Provision first, then recreate the container with the added mount. The wrapper
does not add container mounts from the Context form: customize your deployment
configuration for this option, or use [Attached host folders](#attached-host-folders),
which need no container change. On SELinux systems provide an appropriate
container-readable label (for example `:ro,Z` only when private relabeling is
appropriate), and account for rootless UID mapping. Keep the parent cache
writable for VulnScout's database and metadata; only the source mount is read-only.
**Remote workstation paths are not automatically accessible**: copy the snapshot
to the server or mount storage available to that server.

The embedded Agent has no direct host filesystem access. Its isolated read-only
shell can inspect a filtered snapshot of a directory or attached folder; see
[AI Agent Development](agent-chat.md). Merged
context returns `codebase_directory.file_id="directory"` for a provisioned
directory, and `list_codebase_children`, `list_codebase_files`, `read_codebase_file` and
`read_codebase_files` accept that ID within the variant's existing scope. Directory
availability takes precedence over uploads and external paths in merged source
evidence without deleting their stored data. An empty `files` list means there
are no active uploaded references, not that the directory is empty. Text context
exports/imports preserve the effective source, not
directory names, mounts or contents; provision the destination variant's own
directory separately. **Copy from...** does not copy server-side source.

Browsing rejects symbolic links (including the root and any replaced path
component), hard-linked files and special files. It excludes all hidden
files/directories and names matching `*secret*`, `*credential*`, `*password*`,
`*token*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.keystore`, `id_rsa*`,
`id_ed25519*`, `id_dsa*`, `id_ecdsa*`, `kubeconfig`, `*.kdbx`, `*.sqlite*`,
`*.db`, `*~` and `*.bak`
(case-insensitive). This is a filename safeguard, **not secret detection**;
administrators must remove sensitive content from otherwise eligible files.
Only UTF-8 source is readable. There is no aggregate directory/upload-size cap,
but each operation visits at most **500,000 entries** (excluded directories are not
traversed), each read is limited to **10 MiB/file**, listings/reads to
**64 KiB of serialized response**, and pages to **200 files/lines**. Oversized
responses fail explicitly; reduce the page size or line count. The embedded
agent's isolated shell has separate snapshot and output limits; see
[AI Agent Development](agent-chat.md). Excluded/binary/oversized files and partial inventories
cannot establish absence of vulnerable code.

Directory contents are live, not immutable evidence. Administrator edits and
mount changes outside VulnScout do **not** automatically mark pending assessments
outdated. Prefer versioned, read-only snapshots, identify their revision in the
context, and re-review assessments after source changes.

### Attached host folders

Attach several named folders from the **container host** to a variant, for
example the application source as `src` and a Yocto build tree as `build`,
without copying files, uploading archives or restarting the container. Agents
browse, read and search each one read-only with `file_id="mount:<alias>"`, so a
search of `src` never scans `build`. `get_merged_context` lists them under
`mounts` (`alias`, `file_id`); the provisioned codebase directory
keeps working unchanged alongside them.

**Image prerequisite:** The default `v0.25.1` release does not contain the
helper or the container-side attach command. Until a release includes them,
build this checkout with the same engine the launcher uses (Podman when
installed, otherwise Docker). Select it before starting the container:

```bash
podman build -t localhost/vulnscout:host-folders .  # or docker build
./vulnscout config set VULNSCOUT_IMAGE localhost/vulnscout:host-folders
./vulnscout start
```

`--dev` alone does not supply the host helper. Once the image is selected,
no per-folder setup is required.

**From the CLI** (use an existing project and variant; both default to `default`):

```bash
./vulnscout ai-context attach -p demo -v x86 src=/work/app build=/work/build/tmp/work
./vulnscout ai-context list -p demo -v x86          # alias, availability, host path
./vulnscout ai-context detach -p demo -v x86 build
./vulnscout ai-context helper status                # check helper reachability
```

`attach` approves exactly the named folder for that variant and alias. No
per-folder `config set` is required. The parent directory is not approved.
Relative paths are resolved on the host. Aliases are 1-32 lowercase letters,
digits, `_` or `-`, starting with a letter or digit, unique per variant;
re-attaching the same folder under the same alias is a no-op, and a different
folder needs `detach` first. A variant can have at most 32 attached folders.

Host-folder reads return whole lines within a 64 KiB JSON response. If even
one line cannot fit, `partial_line: true` marks its content as a prefix only;
`next_line`, when present, continues with the following line.

**From the web UI.** The variant's **Context** tab shows the host command to run,
each attached folder's availability, and actions to refresh status or detach.
Neither the browser nor the REST API can authorize a new host path. Folders
attached by a previous version without a host CLI approval must be approved
with the host command before they can be read. Attaching or detaching marks
older pending AI assessments outdated, like other source changes.

Open the UI on localhost and use its same-origin API. Host-folder endpoints
require a loopback peer (or the local container forwarder on a wrapper-created,
loopback-only publication), a localhost Host header and, when present, a matching
Origin. Do not expose the local service through an external reverse proxy.
On upgrade, use an updated backend image and run `./vulnscout restart` with the
updated wrapper to recreate the container: `serve` alone does not replace an
existing public port mapping or mark it as loopback-only.
If you set the wrapper's `VULNSCOUT_BIND_ADDRESS` to a LAN address or `0.0.0.0`,
ordinary UI/API access remains available, but the Agent and host-folder endpoints do not
trust container-forwarded requests. Use `./vulnscout ai-context` on the host
to manage attachments.

**How it works and security model.**

- The wrapper starts or reuses an **unprivileged helper process on the host, as
  the invoking user** (never root; it refuses to run as root). It needs `python3`
  3.9 or newer on the host and uses only its standard library. Even in dev mode
  the wrapper extracts the helper from the trusted configured image into host-only
  state, once per image ID; rebuild the image to test helper changes. `vulnscout stop`
  and `ai-context helper stop` stop it.
- It listens on a **private Unix socket** `host-helper/helper.sock` inside
  `VULNSCOUT_CACHE_DIR`, which the container already mounts at
  `/cache/vulnscout`: the directory is `0700`, the socket `0600`, both owned by
  the invoking user, and the helper also checks the peer's credentials (the same
  user, or root for rootful engines). Attaching folders later therefore needs no
  container restart, and no container ID, mount or engine option changes. Docker
  (rootful or rootless) and rootless Podman (with the wrapper's keep-id mapping)
  can open an owner-only socket under Unix permissions because the container's
  root maps to the invoking user or to host root. On SELinux hosts the wrapper
  reads the container's process label (including its MCS categories). The host
  helper uses `libselinux` to apply that label to its listening socket only.
  A recreated container with a different label gets a freshly bound socket.
  The launcher uses the host Python's `fcntl.flock` on a persistent file in
  the private host state directory so concurrent commands cannot stop or
  overwrite each other's replacement helper. No `flock` executable is needed.
  This requires matching launcher and image versions, not a host policy
  change, `--privileged`, or disabling SELinux.
- The **backend database is the source of truth** (variant, alias, host path,
  creation time) for the UI, API, CLI and agents; every request is checked
  against it before reaching the helper, so a detached alias is refused at once.
  The **helper is the enforcement point**: it keeps its own alias registry in the
  host-only `VULNSCOUT_HOST_HELPER_STATE_DIR` (default `.vulnscout/host-helper`,
  outside the cache mount). Before a database write, the helper checks the folder
  and signs a CLI approval for its attachment ID, variant, alias, path and the
  opened directory's identity. On Linux kernels and filesystems supporting
  exportable file handles and unique mount IDs (Linux 6.12+), that identity
  includes the directory generation. Approval survives a helper restart on
  the same mount within the same boot.
- A **host reboot** changes the boot ID; mount IDs from the previous boot
  no longer identify the current mounts. New approvals
  can survive it when the folder and the private approval key are on the host's
  **same ext4 root mount** and the kernel supplies its filesystem UUID and a
  generation-bearing directory handle. The helper verifies the filesystem UUID,
  key-file handle, directory handle, and membership in the *current* root mount;
  even a bind mount of the original directory is not interchangeable. Separate
  data mounts, bind mounts, and other filesystems do not get this guarantee.
  The trusted host and its private key must be preserved; these checks do not
  authenticate a host restored wholesale from a disk image.
- If only boot-scoped handles are available, run the host attach command again
  after a host reboot. Without suitable handles the helper holds the approved
  directory open: run the attach command again after a helper restart. At most
  128 session-only directory descriptors are kept; unactivated approvals
  expire after five minutes and detaching releases an active descriptor.
  Replacing the root directory requires fresh approval even if its inode is
  reused; editing files inside it does not. Older path-only or device/inode
  approvals require a fresh attach after upgrade. Older signed boot-scoped
  approvals still work where their exact identity matches, but cannot be upgraded
  from a path or refreshed automatically after reboot. Verify the host directories,
  then repeat the original host `ai-context attach` with the same project, variant,
  aliases and paths; there is no need to detach first. Use a matching wrapper
  and image: unconsumed permits from old helpers are not valid.
- **Rolling back the wrapper and image:** the previous helper reports the same
  protocol version but cannot read the new boot-scoped (`b`) or reboot-persistent
  (`d`) proofs. This affects folders first attached **or reapproved** with those
  proofs, even if the host has not rebooted. Check the directories and rerun
  `ai-context attach` with the rolled-back launcher and the original project,
  variant, aliases and paths. You do not need to detach first.
- The database saves the proof so activation can retry. If the CLI reports
  `activation pending`, the attachment
  was saved. Run `ai-context list` to retry and check availability. Keep the
  private helper state: if its signing key is
  lost, repeat the host command. An offline detach is recorded for retry and
  cannot revoke a later attachment using the same alias. Host-source reads use
  the exact path returned by the database lookup and validate/open it in the same
  helper request, rather than resolving the alias a second time.
- Requests are scoped by **variant ID and alias**. Paths are relative to the
  attached folder; absolute paths, `..`, empty components and hidden or sensitive
  names (the same list as codebase directories) are rejected, and every path
  component, including each ancestor of the attached folder, is opened relative to a
  verified directory descriptor without following symbolic links, so links
  (including a directory swapped for a link) cannot escape. Hard-linked regular
  files inside the folder are readable with the legacy read operation, but are not
  returned by shallow navigation or copied into shell snapshots.
- The helper is **read-only**: it can check status, stage
  and activate approvals, update its private registry, list or read source
  files, and run commands against a filtered snapshot in an isolated worker.
  No operation creates, writes or deletes
  anything under an attached folder.
- Bounds: recursive listings visit at most **500,000 entries** or **10 s**, return pages of
  200 files and report `truncated=true` (with `total` as a lower bound) when a
  budget stops them; reads are limited to **10 MiB/file**, 200 lines and
  **64 KiB**. File patterns are limited to 512 characters
  and **16** `*`/`?` wildcards, because a glob match cannot be interrupted by the
  time limits. At most 8 requests run at once.
- Large trees (for example a Yocto build directory):
  - Read known paths directly. An alias identifies an attachment, not its layout.
    From the target SBOM/build metadata, choose the nearest known folder and use
    `list_codebase_children` to discover immediate directories and files. It
    neither walks descendants nor creates a shell snapshot. An empty page with
    `next_cursor` is incomplete. Follow relevant branches, not a recursive root sample.
  - Attach the narrowest useful folder. `list_codebase_files` accepts `folder`, a sub-folder of the
    attachment. For the CLI example above, `build` is already rooted at the Yocto
    work directory: use `<tuple>/<recipe>` from discovered paths, not
    `build/tmp/work/<tuple>/<recipe>`. On an enclosing mount, retain the observed
    prefix instead. The walk starts at `folder`;
    `pattern` is relative to `folder`, while returned paths stay relative to the
    attached folder, so they can be passed to `read_codebase_file` unchanged.
    `folder` must be a plain relative path: `..`, absolute paths, hidden or
    sensitive names and links are rejected, and every component is opened without
    following links. Both provisioned directories and host folders support `folder`.
  - Without `folder`, start `pattern` with a literal path
    from metadata or the listing instead of `*curl*`: folders that cannot match the
    literal prefix are never opened and non-matching files are never stat'ed.
  - Listing uses a bounded Python walk (`engine="python"`).
    `visited_entries` includes nonmatching and excluded entries encountered during
    traversal.
  - A budget limit, I/O error or skipped path sets `truncated=true` with a message.
    `skipped_paths` counts files whose paths cannot be used in a read request.
    Narrow `folder` or `pattern` for a budget limit; check access and retry for an
    I/O error. An incomplete listing cannot establish absence.

**Unavailability is explicit.** When the helper is not running, the AI Context
page shows **Host folder helper unavailable** and each folder as
**Unavailable**. CLI attach fails if the helper cannot start. HTTP source reads
return 503 if the helper cannot be reached; agents must report that as missing evidence. Restart it
with `./vulnscout ai-context helper start` (or any `vulnscout` command). Its log
is `helper.log` in the state directory.

Limitations: the helper runs on the host that runs the container, so folders on
a remote workstation are not accessible. The socket is shared through a bind
mount, which requires a Linux container host (not Docker Desktop's VM), and an
engine that maps container root to the invoking user or to host root: setups
that remap it to another unprivileged UID (for example Docker `userns-remap`)
cannot connect. Approve only roots whose content you may
share with the selected AI provider; the filename exclusions are a safeguard,
not secret detection. On SELinux-enforcing hosts, policy may deny the container
from connecting to a socket created by a host process; check the audit log if
folders stay unavailable while the helper runs. Context exports, imports and
**Copy from...** do not carry attached folders.

## Review AI Assessments

Pending AI assessments must be reviewed by a human before they become official.

1. Open the assessed vulnerability in the VulnScout web interface.
2. A pending AI assessment appears in a highlighted panel **above** the normal
   assessment timeline, labelled **"AI-generated · Pending review"**. It shows
   the same details as a normal assessment (status, justification, impact
   statement, notes, packages, and variant).
3. Click **Edit** on the vulnerability modal to enter editing mode — the
   **Approve** / **Edit** / **Reject** buttons only appear on the panel once
   editing mode is active.
4. Use the panel's action buttons:
   - **Approve** — promotes the assessment to an official (`custom`)
     assessment. It now affects the vulnerability's status and is included in
     the OpenVEX export.
   - **Edit** — lets you amend the suggestion's notes, justification, impact
     statement and workaround before approving it. Its status, packages and
     variants are read-only. If the verdict is wrong, reject the suggestion
     rather than approving it with different wording. In edit mode the actions
     become:
     - **Confirm and approve** — saves your changes and approves the
       assessment in a single step, exactly like **Approve** but with the
       edited content. The message (notes, or the impact statement for
       *Not applicable* / *False positive*) cannot be empty. For *Not applicable*,
       the editor shows an inline error if both justification and impact
       statement are missing. If the save fails,
       the editor stays open with your changes and shows the error. While
       approval is in progress, the vulnerability modal cannot be closed
       or used to navigate to another vulnerability.
       When Notes displays an imported impact statement, editing it moves the
       corrected message to notes and clears the old impact statement so both
       OpenVEX and CycloneDX include the correction exactly once.
       If someone changed the suggestion while you were editing, reload and
       review their changes before approving.
       If a refresh removes the suggestion from the vulnerability modal, your
       draft stays visible for copying or cancellation and cannot be approved.
     - **Cancel changes** — discards your changes and restores the
       **Approve** / **Edit** / **Reject** buttons.
   - **Reject** — deletes the pending AI assessment.

Until it is approved, a pending AI assessment has no effect on the
vulnerability's status, on scan history/diffs, or on any exported VEX.
You can also inspect pending suggestions in **Review → AI Assessments**, where
each row offers the same **Approve**, **Edit** and **Reject** actions.
In that editor, pressing **Escape** or the close button asks before discarding
unsaved changes. **Cancel changes** discards the draft immediately.

## AI Review of Custom Assessments

This is a separate workflow from approving a pending AI assessment. It provides
an independent second opinion on an existing **user-authored** assessment
(`origin = "custom"`), not a scan-imported assessment or pending AI suggestion.
Use **Review with AI** on a custom assessment in the vulnerability
modal, or select assessments on the **Review** page and click **Review selected
with AI**. Up to five independent reviews can run at once,
one complete assessment per conversation; every target is reviewed even when the table is scoped
to one variant. You can close and reopen the chat while it works, inspect errors,
stop the running review, and remove queued requests without altering your selection.
Unresolved targets prevent the entire selection from being queued.
When a review starts, the server pins the assessment's current content by its
fingerprint; the agent may only save reviews of its own targets against that
fingerprint. Afterwards the server checks the database, not the agent's reply:
the request succeeds only once every expected target has a fresh, non-stale
review. A failed request does not block the queue; use **Retry failed action**
in its conversation or remove the failed action.

The agent independently derives a conclusion for **each (variant, package)
target**, then saves a separate review for each one. An assessment covering multiple targets
can therefore have different review verdicts for different targets. If the
authored content changed after the review started, the write is rejected (the
target is reported as changed): request a new review
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
- **The agent cannot read a host source directory** — provision a **Codebase directory**
  and have an administrator copy or mount source there.
- **A request failed** — inspect the error and **Activity** before retrying.
  For queued work, use **Retry failed action** in its conversation, or remove the
  failed action; other requests keep running meanwhile. Check for a saved
  result before retrying a write.
- **Requests stay queued** — the queue is paused while AI is not configured or
  GitHub is signed out; the banner shows why. Sign in, connect a provider or
  select a model to resume it.
- **`assess` reports `no_write` or `partial`** — the agent replied without recording every target. Read the `reply` in `--json` output, then rerun for those vulnerabilities; a rerun replaces any pending AI assessment it wrote.

## Optional: External AI Clients

Use an external client when you need your own agent environment, host-side
source access or web research in free chat. MCP integration and repository skills
remain supported, but are not required for the built-in Agent.

```{toctree}
:maxdepth: 1

ai-external-clients
```
