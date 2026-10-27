# External AI Clients (MCP)

This optional workflow connects an external MCP-capable client to VulnScout.
For the recommended container-based workflow, use the built-in Agent described
in [AI Assessments](ai-assessments.md); no external MCP registration is needed.

The MCP implementation is bundled in this repository under `vulnscout_mcp/`.
There is no separate `vulnscout-mcp` repository to clone or install.
External clients can use this repository's assessment skills and their own
research capabilities; those skills are not loaded by the embedded Agent.

## Prerequisites

- A running VulnScout instance, reachable over HTTP (see
  [Getting Started](getting-started.md)). By default the API is served at
  `http://localhost:7275`.
- Python 3.10+ on the host that runs the MCP server.
- A clone of this `vulnscout` repository (the MCP server is vendored under
  `vulnscout_mcp/`).
- An MCP-capable agent client — either the **GitHub Copilot CLI** or
  **VS Code** with the GitHub Copilot extension.

## Configure the Bundled MCP Server

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

Once configured, the agent can call these assessment and context tools
(prefixed with `vulnscout-`):

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
| `get_merged_context`       | Fetch the merged project + variant context (project description plus variant description, codebase source, environment, STRIDE-rendered threat model and risks, other info) |
| `list_codebase_files` / `read_codebase_file` / `search_codebase` | Browse, read and search uploaded codebase references for a variant, including inside the container |
| `get_ai_context_form_guide` | Return the AI Context form guide: what each field and table expects, and the copy-ready reply format used to help fill it |
| `get_project_context` / `update_project_context` | Read / replace a project's description |
| `update_variant_context`   | Replace a variant's text context fields (description, codebase path, environment, other info) — full replacement, not a partial update; the threat model, risks and codebase source can only be edited on the AI Context page. A variant with no context yet is created with codebase source paths when a codebase path is given, otherwise references |
| `get_custom_assessment`    | Fetch one user-authored assessment and its per-target reviews |
| `list_custom_assessments`  | List user-authored assessments, optionally scoped to a project variant |
| `write_assessment_review`  | Record an AI second opinion for one (variant, package) target |
| `list_dependency_documents` / `list_dependency_packages` / `get_package_dependencies` | Inspect SBOM documents, package inventories and dependency relationships |

## Use the cve-assessment Skill

The `cve-assessment` skill lives in this repository at
`.github/skills/cve-assessment/`. Open the repository in a client that supports
these skills and enable skill discovery if required by that client. MCP support
alone does not load skills. Verify that the client has loaded the skill before
relying on its assessment policy.

Invoke it by describing the CVE and (optionally) the project context, for
example:

```
Assess CVE-2024-XXXXX for project "my-product", variant "production".
```

The skill resolves platform context using three tiers:

1. **MCP fetch** — if you provide a `project_name` (and optionally one or more
   variant names), the skill fetches each variant's context from VulnScout via
   the MCP tools, including its STRIDE threat model and risks. The resolved
   `variant_id`s are required to submit the assessment.
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

## Human Approval and Custom Assessment Reviews

External submissions follow the same [human approval workflow](ai-assessments.md#review-ai-assessments) as the embedded Agent.

The `assessment-review` skill in `.github/skills/assessment-review/` independently
reviews only user-authored (`custom`) assessments, never scan assessments or
pending AI suggestions. Ask it to review an assessment ID, a project and variant,
or all custom assessments. It stores one review per target without changing the
assessment; see [AI Review of Custom Assessments](ai-assessments.md#ai-review-of-custom-assessments).

For example:

```text
Review assessment assessment:<uuid>.
Review custom assessments for project "my-product", variant "production".
Review all custom assessments.
```

Copy an assessment ID from the **Review** page. The tool accepts a bare UUID,
`assessment:<uuid>`, or `group:<uuid>` for a multi-target assessment. If you name
a project without a variant, the skill uses its `"default"` variant. With no
scope, it lists custom assessments across all variants, following pagination.
By default, it skips targets with current reviews and revisits unreviewed or
stale targets. Review writes include the target's `variant_id`, `package`, and
the `assessment_fingerprint` obtained when reading the assessment.

## Dependency and Lifecycle Questions

The `.github/skills/sbom-dependencies/` skill uses the dependency tools to
discover direct/transitive dependencies and reverse dependents. It is
read-only: dependency discovery or lifecycle research does not create VEX
assessments. Follow pagination, keep per-document version evidence separate,
and do not infer runtime use from the SBOM graph alone.

For current lifecycle, LTS, and end-of-life research, use a client with web
research capabilities or supply authoritative dated evidence. Distinguish
upstream support from vendor/distribution backports and entitlement. MCP itself
does not provide web browsing.

## External Client Troubleshooting

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
- **Review rejected because its assessment fingerprint changed** — the
  user-authored assessment was edited since the agent read it. Fetch the
  updated assessment and independently review the affected targets again.
