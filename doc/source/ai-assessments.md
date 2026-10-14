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

Three pieces work together:

- **VulnScout** — runs the API and web interface, stores assessments, and
  provides the review UI.
- **vulnscout_mcp** — an [MCP](https://modelcontextprotocol.io)
  (Model Context Protocol) server that exposes VulnScout's assessment and
  variant-context APIs as tools an AI agent can call.
- **cve-assessment skill** — an agent skill (shipped in this repository under
  `.github/skills/cve-assessment/`) that guides the agent through researching a
  CVE and submitting the result via the MCP tools.
- **assessment-review skill** — an agent skill under
  `.github/skills/assessment-review/` that independently reviews existing
  user-authored assessments, without changing them.

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

## Fill in the AI context

Select a project in the **AI** tab. Each description, source path, environment
entry, system component, interaction, threat, risk and additional note has its
own **variants** selection. Shared entries are stored once: editing one updates
every selected recipient. Add another entry for variant-specific information,
or narrow an entry's scope. New entries initially select all currently loaded
variants; variants created later do **not** inherit existing entries.
Each saved entry must target at least one variant; this is checked on save.
Identical existing information is grouped where its ordering permits, without
overwriting the original per-variant content.

Use **Context** for descriptions,
source paths and the operating environment, **System** for architecture,
**Threat model** for threats, and **Risks** for their evaluation. **Summary**
provides a read-only STRIDE category overview and threat/risk tables, including
unsaved edits, incomplete entries, variant scopes and unavailable references.
Counts refer to shared entries, not summed per-variant copies, and do not
indicate completed review or safety. In Advanced free mode, Summary shows the
current text instead. Switching subtabs keeps unsaved edits. Each editable subtab
has its own **Save** button; other sections' drafts remain unsaved.
Save new system elements before threats that reference them, and new threats
before their risks. When removing references, save the risks or threats first.
System and threats share a text field, but their saves preserve the other
section's saved content. A reference must be available in every variant selected
for the referencing entry. Selecting a threat narrows a risk to compatible
variants. Save expanded dependency scopes before using them in another section,
and save reference changes before removing a dependency's scope.
In Advanced free mode, **Save Threat model** saves the
combined system/threat text; **Save Risks** saves only the risk text.

Use **Add Codebase Path** and **Remove Codebase Path** to list source directories
individually. Paths are context hints, not filesystem access or automatic mounts.
Container-based assessment tools need explicitly mounted directories and their
container paths. The embedded Agent currently exposes only VulnScout MCP tools,
not source-file read/search tools.

Choose **Editor mode** in **Context**; it applies to **System**, **Threat model**
and **Risks**, project-wide. The default is a guided **STRIDE template**.
Save other sections' drafts before changing mode, then save **Context** before
editing other sections in the new mode. A presentation-only mode change does
not outdate AI assessments. If legacy variants use mixed editors, the project
starts in Advanced free mode to retain all original text.
In **System**, describe assets, actors, entry points and trust boundaries.
Use **Add component** for security-relevant device parts, services, stores and
external actors. Use **Add interaction** for named, directed flows between
components, including their interface, exchanged data and crossed trust boundary.
This is a user-declared system model, not an inferred SBOM dependency graph.

In **Threat model**, record each threat's
description and select its category: **Spoofing**,
**Tampering**, **Repudiation**, **Information disclosure**, **Denial of service**
and **Elevation of privilege**. Use **Add threat** and **Add risk** to create
empty entries. The prompts are examples, not prefilled answers.
Several threats can share a category. Leave unknowns blank; the **Additional notes**
area can record assumptions or explain why a category does not apply.
Optionally select one or more **Affected system elements** from System.
Renaming an element updates its references; remove or reassign references before
deleting components or interactions. Existing threats need not acquire a target.

In the risk register, **select a threat from Threat model**, then record its
qualitative likelihood and impact, mitigations and residual-risk decisions.
A threat cannot be removed until its linked risks are reassigned or removed.
**Advanced free mode** remains available for your own format. Existing free-text
context opens in that mode;
switching to STRIDE retains it as additional notes. In free mode, system details
remain in the Threat Model text. Both modes save readable text
and work with existing AI tools and context imports/exports. Existing variant
API/MCP writes change only the requested recipient, splitting changed information
out of shared entries rather than editing other variants. Changing editor mode
is project-wide once shared context is saved.

Each save checks a project revision and keeps drafts on conflicts. Only variants
whose context changes have their pending AI assessments marked outdated;
changing the project description affects every project variant. Agent writes
and imports reload clean forms but retain dirty drafts with a warning.
**Reload saved context** asks before discarding unsaved drafts.

### Import and export

Exports contain **saved context only**. Projects using shared entries export
JSON format **3.0**, with one canonical `context` per project, a `variants` list
containing variant names, and `variant_names` on every scoped record. Portable
names replace database UUIDs. All projects in a 3.0 file use this shape; there
are no conflicting per-variant context copies.

The shared context contains one `editor_mode`, scoped text collections in
`fields` (`variant_description`, `codebase_path`, `environment`, `other_info`,
`scope`, `actors`, `entry_points`, `trust_boundaries`), and `components`,
`interactions`, `threats`, `risks`, `threat_notes`, `risk_notes`,
`free_threat_model` and `free_risks` arrays. Records have stable project-local
IDs (`C`, `I`, `T`, `R`, or `X` followed by a positive integer).
Text records have `id`, `value` and `variant_names`; structured records retain
their existing STRIDE fields and add a scope. Free mode uses the two free-text
arrays instead of structured system/threat/risk records.

Selecting export recipients intersects every entry's scope with that selection.
Imports replace only matching recipients, preserving unselected variants and
shared identities where content and ordering permit. Identifier collisions are remapped
together with their references; unavailable references remain unavailable.

Projects not yet using shared entries still export JSON format **2.0**.
Each variant has `editor_mode` (`stride` or `free`),
`codebase_paths` as an array, and its description, environment and other notes.
In STRIDE mode, `system` contains scope, actors, entry points, trust boundaries,
components and directed interactions. `threat_model` contains threats with stable
IDs, categories, descriptions, system `targetIds` and additional notes; `risks`
contains threat-linked risk entries and additional notes. Summary is derived,
not exported. Blank ratings and unavailable references remain explicit.

Advanced free-mode exports retain the original `threat_model` and `risks` text
instead of structured objects. **Legacy 1.0 and unversioned files still import,
always into Advanced free mode**, including files whose text happens to use a
STRIDE template. That choice survives reloads. Switching to STRIDE remains
explicit; save Context to persist an editor-mode change without saving other
drafts. Mode-only changes do not outdate AI assessments.

Formats 2.0 and 3.0 support partially completed contexts, including empty sections.
Malformed structured records, invalid IDs/categories/ratings and unknown format
versions are reported rather than silently discarded. Omit completely blank
editor-placeholder rows in 2.0; 3.0 retains scoped draft records explicitly.
Imports replace context for matching existing variants;
unknown projects/variants are ignored. Legacy imports retain their required
project-description and threat-model fields. The HTTP API and context CLI
commands use the same format.

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
| `update_variant_context`   | Replace a variant's context fields (description, environment, threat model, risks, other info) — full replacement, not a partial update |
| `get_custom_assessment`    | Fetch one user-authored assessment and its per-target reviews |
| `list_custom_assessments`  | List user-authored assessments, optionally scoped to a project variant |
| `write_assessment_review`  | Record an AI second opinion for one (variant, package) target |

## Codebase references in the AI tab

Select a project in **AI**, then choose **Codebase reference variant** in the
**Context** section and drag source files or archives onto **Codebase References**,
or use the file picker. Uploaded references belong only to that variant;
this selector is independent of the shared text entries' variant scopes.
Multiple uploads are supported.
An optional description can identify the component/version and whether the
upload is a complete source tree or only selected files. References are saved
**immediately**, independently of **Save context**; unsaved text fields are kept.
Uploads and deletion mark older pending AI assessments for that variant outdated.
The UI asks before uploading when pending assessments exist and always confirms deletion.

Supported archives are **ZIP, TAR, TAR.GZ and TGZ**. Each upload is limited to
**10 MB**, each member to **10 MB**, expanded archives to **100 MB**, and archives
to **5,000 entries**. Unsafe paths, duplicate file paths, encrypted ZIP files,
links, sparse files and special entries are rejected. Archives are read without
extraction or execution. Only UTF-8 text can be read as source; binary files
may be stored/listed but cannot provide text evidence. Other archive formats
are not unpacked.

**Codebase Path** remains available for an external Copilot/MCP client running
on the machine that owns the source. Separate multiple local paths with a
semicolon. A path entered here does **not** mount a directory into the container,
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
