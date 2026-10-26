# AI Assessments

VulnScout can accept **AI-written vulnerability assessments**. An AI agent
researches a CVE, decides on a VEX status, and submits the assessment to
VulnScout, where it is stored as **pending review**. A pending AI assessment is
never treated as official — it does **not** affect a vulnerability's status and
is **not** included in the exported VEX — until a human reviewer explicitly
**approves** it in the web interface.

This page describes how to set up and use that workflow, as well as how to
request an AI second opinion on existing user-authored assessments.

---

## How it works

Four pieces work together:

- **VulnScout** — runs the API and web interface, stores assessments, and
  provides the review UI.
- **vulnscout_mcp** — an [MCP](https://modelcontextprotocol.io)
  (Model Context Protocol) server that exposes VulnScout's assessment and
  variant-context APIs as tools an AI agent can call.
- **cve-assessment skill** — an agent skill (shipped in this repository under
  `.github/skills/cve-assessment/`) that guides the agent through researching a
  CVE and submitting the result via the MCP tools. Phase 2 uses the scoped SBOM
  dependency tools to discover exact packages, preserve per-source version
  evidence and trace dependency/reverse-impact paths, then corroborates them
  with source/build/deployment evidence. Graph reachability alone does not
  establish runtime exploitability or a VEX verdict.
- **assessment-review skill** — an agent skill under
  `.github/skills/assessment-review/` that independently reviews existing
  user-authored assessments, without changing them.
- **sbom-dependencies skill** — a read-only skill under
  `.github/skills/sbom-dependencies/` for application dependency discovery and
  evidence-based LTS/EOL/vendor-support analysis. It uses the active SBOM graph
  for each board/variant, not inferred runtime usage. See the
  [MCP dependency workflow](../../vulnscout_mcp/README.md#sbom-discovery-and-lifecycle-analysis)
  for tools, pagination, provenance and limitations. This workflow does not
  create VEX assessments. The embedded Agent exposes these dependency tools but
  does not load host skills or browse the web; current lifecycle claims require
  supplied authoritative evidence, otherwise it reports unknown. Use the external
  skill with a web-capable client for live support-policy research.

```
CVE / GHSA id
    ↓
AI agent + cve-assessment skill
    ↓  (calls MCP tools)
vulnscout_mcp  ──HTTP──▶  VulnScout API
    ↓
Pending AI assessment (origin = "ai")
    ↓
Human review in the web UI  ──▶  Approve (becomes official) / Reject (deleted)
```

A vulnerability has at most one pending AI assessment per variant and package.
Submitting a new AI assessment **replaces** the pending one on the same
(variant, package) targets, without any confirmation. If the old pending
assessment also covered other targets — other variants, or other packages of the
same variant — it keeps those and only loses the overlapping ones. Approved assessments are never
replaced.

---

## Prerequisites

For the **embedded Agent**, use its connector setup described in
[Agent chat](agent-chat.md); the normal container includes the SDK and MCP server.
The external-client prerequisites below apply to Copilot CLI/VS Code workflows.

- A running VulnScout instance, reachable over HTTP (see
  [Getting Started](getting-started.md)). By default the API is served at
  `http://localhost:7275`.
- Python 3.10+ on the host that runs the MCP server.
- A clone of this `vulnscout` repository (the MCP server is vendored under
  `vulnscout_mcp/`).
- An MCP-capable agent client — either the **GitHub Copilot CLI** or
  **VS Code** with the GitHub Copilot extension.

---

## Step 1 — Configure the vulnscout_mcp server

`vulnscout_mcp` speaks MCP over stdio and is launched as a subprocess by the
agent client — there is no port or daemon to manage yourself. Its
`vulnscout_mcp/run_server.py` launcher is self-bootstrapping: on first run it
creates a local `venv/`, installs runtime dependencies from
`requirements/mcp.txt`, and then starts the server.

The server reads a single environment variable:

| Environment variable | Default                 | Description                          |
| -------------------- | ----------------------- | ------------------------------------ |
| `VULNSCOUT_BASE_URL` | `http://localhost:7275` | Base URL of the VulnScout API server |

### GitHub Copilot CLI

Add the server from the terminal:

```bash
copilot mcp add vulnscout \
  --env VULNSCOUT_BASE_URL=http://localhost:7275 \
  -- python3 /path/to/vulnscout/vulnscout_mcp/run_server.py
```

Or run `/mcp add` in interactive mode and fill in the form (**Type:** STDIO,
**Command:** `python3 /path/to/vulnscout/vulnscout_mcp/run_server.py`,
**Environment Variables:** `{"VULNSCOUT_BASE_URL":"http://localhost:7275"}`).

Equivalently, edit `~/.copilot/mcp-config.json` directly:

```json
{
  "mcpServers": {
    "vulnscout": {
      "type": "local",
      "command": "python3",
      "args": ["/path/to/vulnscout/vulnscout_mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      },
      "tools": ["*"]
    }
  }
}
```

### VS Code (GitHub Copilot extension)

Add a server entry to your workspace `.vscode/mcp.json` (or run
**MCP: Add Server** from the Command Palette and choose **Workspace** or
**Global**):

```json
{
  "servers": {
    "vulnscout": {
      "type": "stdio",
      "command": "python3",
      "args": ["/path/to/vulnscout/vulnscout_mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      }
    }
  }
}
```

### Available MCP tools

Once configured, the agent can call these tools (prefixed with `vulnscout-`):

| Tool                       | Description                                                  |
| -------------------------- | ----------------------------------------------------------- |
| `write_assessment`         | Create a VEX assessment for a CVE on one or more packages   |
| `update_ai_assessment`     | Revise the content of an existing pending AI assessment (its targets cannot change) |
| `get_assessment`           | Retrieve a single VEX assessment by ID                      |
| `list_assessments_by_vuln` | List all VEX assessments recorded for a CVE                 |
| `has_ai_assessment`        | List pending AI assessments for a variant, optionally one package (informational; a new write replaces them automatically) |
| `get_vulnerability`        | Retrieve a vulnerability with variant-scoped details        |
| `find_project_id` / `find_variant_id` | Resolve a project / variant by name             |
| `list_variants`            | List every variant across all projects                      |
| `get_merged_context`       | Fetch the merged project + variant context (project description plus variant description, environment, threat model, risks, other info) |
| `list_codebase_files` / `read_codebase_file` / `search_codebase` | Browse, read and search uploaded codebase references for a variant, including inside the container |
| `get_project_context` / `update_project_context` | Read / replace a project's description |
| `update_variant_context`   | Replace a variant's text context fields (description, codebase path, environment, other info) — full replacement, not a partial update; the threat model and risks are generated from the STRIDE model and can only be edited in the AI Context page |
| `get_custom_assessment`    | Fetch one user-authored assessment and its per-target reviews |
| `list_custom_assessments`  | List user-authored assessments, optionally scoped to a project variant |
| `write_assessment_review`  | Record an AI second opinion for one (variant, package) target |

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
tables. `codebase_path` is only sent when the source is paths, and uploaded
references are only listed when the source is references. The MCP
`update_variant_context` tool cannot change the threat model or risks; edit them
in the page.

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
`search_codebase` and `read_codebase_file`. The assessment and assessment-review
skills use each variant's own uploads as additional evidence and cite IDs,
archive member paths and line numbers.

References are stored under `VULNSCOUT_CACHE_DIR/context-files` using opaque IDs
and persist with the cache volume. Delete removes the reference; deleting its
variant/project also cleans up the associated storage. Text context JSON
import/export does **not** include source files; importing text leaves existing
uploads intact. Upload references separately when moving to another instance.

Only upload code you are authorized to share with the selected AI provider,
and remove credentials, secrets and unrelated private files first. Uploaded
content is untrusted evidence, not agent instructions. Partial uploads,
unreadable files, conflicting versions or truncated searches must be reported
as evidence gaps, not used to claim a component is absent.

---

## Step 2 — Use the cve-assessment skill

The `cve-assessment` skill lives in this repository at
`.github/skills/cve-assessment/`. An MCP-capable agent that has access to this
repository will discover the skill automatically and invoke it when you ask it
to assess a CVE.

Invoke it by describing the CVE and (optionally) the project context, for
example:

```
Assess CVE-2024-XXXXX for project "my-product", variant "production".
```

The skill resolves platform context using three tiers:

1. **MCP fetch** — if you provide a `project_name` (and optionally one or more
   variant names), the skill fetches each variant's context from VulnScout via
   the MCP tools. The resolved `variant_id`s are required to submit the
   assessment.
2. **Inline context** — if you describe the platform (package manager, build
   system, deployment environment) directly in the prompt, the skill uses that.
3. **Default fallback** — otherwise it proceeds with generic default
   objectives and no extra context.

The skill then researches the vulnerability, evaluates it against the project's
security objectives, assigns a status, and submits it via
`vulnscout-write_assessment` as a pending AI assessment.

### Assessing several variants at once

The skill can assess more than one variant of a project in a single run:

- **Named variants** — list them in the prompt (for example, *variants
  "production" and "staging"*) and only those are assessed.
- **No variants named** — every variant of the project is assessed. This
  requires a `project_name`; the skill never guesses a project.

The CVE research is done once, but the component analysis and confidence score
are done **per variant**, using each variant's own context, because the same CVE
can have a different verdict in different variants. Variants that end up with
the same status and justification are then submitted together as **one
multi-target assessment**, not one assessment per variant. Variants with a
different verdict get their own assessment. The skill finishes with a summary of
every group, the assessment ids, any skipped variants, and any pending AI
assessments it replaced.

### Confidence and strict assessments

The external `cve-assessment` skill scores confidence separately for each
variant. Its default policy allows a definitive status at HIGH or MEDIUM
confidence; LOW confidence always submits `under_investigation`. A MEDIUM
confidence decision includes the uncertainty in `status_notes`.

Explicitly request a **strict assessment** to require HIGH confidence for a
definitive status:

```text
Do a strict assessment of CVE-2024-XXXXX for project "my-product",
variants "production" and "staging".
```

| Confidence | Default assessment | Strict assessment |
| --- | --- | --- |
| HIGH | Determined status | Determined status |
| MEDIUM | Determined status, with uncertainty noted | `under_investigation` |
| LOW | `under_investigation` | `under_investigation` |

This is a prompt-controlled policy of the external skill, not an MCP parameter
or a persistent UI setting. The embedded Agent uses its own system instructions,
not external skill discovery. Skill submissions remain pending human approval
regardless of confidence or strictness.

```{note}
The skill's **security objectives profiles** and **report templates** are
customizable. See `.github/skills/cve-assessment/objectives/README.md` and the
`.github/skills/cve-assessment/report-templates/` directory for details.
```

---

## Step 3 — Review AI assessments in the web interface

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

---

## Step 4 — AI review of custom assessments

This is a separate workflow from approving a pending AI assessment. Ask an
agent with access to this repository and the `assessment-review` skill to
review an existing **user-authored** assessment (`origin = "custom"`). The
skill does not review scan-imported assessments or pending AI suggestions.
In the UI, use **Review with AI** on a custom assessment in the vulnerability
modal, or select assessments on the **Review** page and click **Review selected
with AI**. Bulk requests run sequentially in their own chat, one complete
assessment per request; every target is reviewed even when the table is scoped
to one variant. You can hide and reopen the chat while it works, inspect errors,
and remove queued requests without altering your selection.
For example:

```
Review assessment assessment:<uuid>.
Review custom assessments for project "my-product", variant "production".
Review all custom assessments.
```

You can copy an assessment ID from the **Review** page; the tool accepts a
bare UUID or a copied `assessment:<uuid>` (and `group:<uuid>` for a
multi-target assessment). If you specify a project without a variant, the
skill uses its `"default"` variant. With no scope, it lists custom assessments
across all variants; larger scopes are paginated. By default, it skips targets
with a current review and revisits unreviewed or stale targets.

The agent independently derives a conclusion for **each (variant, package)
target**, then saves a separate review for each one via
`vulnscout-write_assessment_review`. An assessment covering multiple targets
can therefore have different review verdicts for different targets. Each
write supplies the target's `variant_id` and `package` and the
`assessment_fingerprint` obtained when the assessment was read. If the
authored content changed meanwhile, the write is rejected: fetch the updated
assessment and review it again rather than reusing the old conclusion.
Re-reviewing a target replaces only that target's previous review; **no review
changes the underlying assessment**.

The **Review** page's **AI review** column and filter show which targets
agree (✓), differ (⚠), are stale (⚠ stale), or have no review (—).
Multi-target rows show counts for each state. Open the vulnerability detail
modal to read each target's AI review and rationale (`why:`). A stale review
warns that the assessment was edited after the review was generated; in edit
mode, **Discard review** removes a target's review without changing the
assessment.

---

## Troubleshooting

- **The agent cannot reach VulnScout** — verify that VulnScout is running and
  that `VULNSCOUT_BASE_URL` in the MCP configuration points to the correct API
  URL (default `http://localhost:7275`).
- **Submission is blocked with a missing `variant_id`** — the skill needs a
  `variant_id` to submit. Provide a `project_name`/`variant_name` (so it can be
  resolved via MCP) or a `variant_id` UUID directly in the prompt.
- **A pending AI assessment disappeared, or now covers fewer targets** —
  this is expected. A new AI assessment replaces the pending one on the same
  (variant, package) targets; if the old one also covered other targets, it
  keeps those. Approve
  an assessment first if you want to keep it, since approved assessments are
  never replaced.
- **409 Conflict on submission** — you are running a VulnScout version from
  before AI assessments replaced each other. Upgrade VulnScout, or approve or
  reject the existing pending assessment first.
- **Review rejected because its assessment fingerprint changed** — the
  user-authored assessment was edited since the agent read it. Fetch the
  updated assessment and independently review the affected targets again.
